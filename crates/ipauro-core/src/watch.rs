//! Event-driven(-ish) reconcile trigger on USB interface change.
//!
//! `@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — "Reconcile
//! triggers (event-driven first, poll as backstop)" and A002 §4's "Unplugging
//! ONE USB member destroys the whole bridge" incident, which is exactly why
//! this must react fast rather than wait out a slow poll.
//!
//! ## Mechanism chosen: fast [`UsbNcmSource`] polling, not PF_ROUTE/SCDynamicStore
//!
//! M1's spec named three acceptable mechanisms: a `PF_ROUTE` routing socket
//! (`RTM_IFINFO`/`RTM_NEWADDR`), `SCDynamicStore`, or a short-interval `ioreg`
//! poll. This module implements the third. Rationale:
//! - **Correctness with the least new surface.** A raw `PF_ROUTE` socket
//!   needs unsafe `libc` socket/read code parsing `rt_msghdr`/`ifa_msghdr`
//!   with sockaddr-alignment padding — real but easy-to-get-subtly-wrong
//!   parsing that would ship untested against real interface-change traffic
//!   (this crate's tests run in CI, no hardware). `SCDynamicStore` needs an
//!   Objective-C/CoreFoundation binding (this crate already carries one such
//!   binding, `xpc_helper.rs`/`ipauro-xpc`, but doubling that surface for a
//!   single watch is a heavier lift than the payoff here justifies).
//! - **It reuses [`UsbNcmSource`] as-is**, so the exact same discovery code
//!   path (and its [`crate::discovery::MockUsbNcmSource`] test double) drives
//!   both the reconciler's decisions AND the watch — one source of truth,
//!   trivially testable without hardware.
//! - **"~instant" is relative to a human replugging a cable.** A 2s poll
//!   reacts within 2s of a real detach — effectively instant next to the
//!   alternative (a 15s+ poll, or a person noticing silence and re-plugging).
//!
//! This is a documented trade-off, not a shortcut: true sub-second reaction
//! would need `PF_ROUTE` or IOKit notifications. If M1's hardware-verification
//! pass finds 2s too slow in practice, swap this module's mechanism — nothing
//! outside it needs to change, since it only ever calls the same
//! `reconcile`-kick `Notify` that a 15s poll or a `PF_ROUTE` socket would.
//!
//! ## Where the 15s "poll backstop regardless" (A001) lives
//!
//! Not here — [`crate::reconcile::run`]'s own `POLL_INTERVAL` (15s) is that
//! backstop. Keeping it there (rather than duplicating a second unconditional
//! timer in this module) means there is exactly one place that guarantees "a
//! reconcile pass happens at least this often no matter what", regardless of
//! which fast-path mechanism watches for changes.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, Notify};

use crate::discovery::UsbNcmSource;

/// Fast-path polling cadence — see module docs for why 2s and not a true
/// kernel-event mechanism.
const FAST_POLL: Duration = Duration::from_secs(2);

/// Pure comparison, split out so the "did the discovered set change" decision
/// is unit-testable without a runtime or a real clock.
fn discovered_set_changed(previous: Option<&[String]>, current: &[String]) -> bool {
    previous != Some(current)
}

/// Background task: polls `usb_source` every [`FAST_POLL`] and notifies
/// `kick` whenever the discovered interface set differs from the last poll
/// (including the very first poll, so a service that starts with USB already
/// plugged in kicks reconcile promptly instead of waiting for the 15s
/// backstop). Runs until `shutdown` fires.
pub async fn run(usb_source: Arc<dyn UsbNcmSource>, kick: Arc<Notify>, mut shutdown: broadcast::Receiver<()>) {
    let mut last: Option<Vec<String>> = None;
    loop {
        tokio::select! {
            _ = shutdown.recv() => return,
            _ = tokio::time::sleep(FAST_POLL) => {}
        }

        let source = usb_source.clone();
        let discovered = match tokio::task::spawn_blocking(move || source.discover()).await {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                log::warn!("usb watch: discovery failed, skipping this poll: {e}");
                continue;
            }
            Err(e) => {
                log::warn!("usb watch: discovery task panicked, skipping this poll: {e}");
                continue;
            }
        };
        let mut discovered = discovered;
        discovered.sort();

        if discovered_set_changed(last.as_deref(), &discovered) {
            log::debug!("usb watch: interface set changed -> {discovered:?}");
            last = Some(discovered);
            kick.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_poll_always_counts_as_a_change() {
        assert!(discovered_set_changed(None, &["en9".to_string()]));
        assert!(discovered_set_changed(None, &[]));
    }

    #[test]
    fn identical_sets_are_not_a_change() {
        let set = vec!["en9".to_string(), "en12".to_string()];
        assert!(!discovered_set_changed(Some(&set), &set));
    }

    #[test]
    fn a_detach_is_a_change() {
        let before = vec!["en9".to_string(), "en12".to_string()];
        let after = vec!["en9".to_string()];
        assert!(discovered_set_changed(Some(&before), &after));
    }

    #[test]
    fn an_attach_is_a_change() {
        let before = vec!["en9".to_string()];
        let after = vec!["en9".to_string(), "en12".to_string()];
        assert!(discovered_set_changed(Some(&before), &after));
    }
}
