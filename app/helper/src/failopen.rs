//! Fail-open state machine (ticket R002-F5).
//!
//! Keyed on the count of live *authenticated* connections from the brain
//! service — never on the UI client, which has no XPC relationship to the
//! helper at all. When the count drops to zero, a grace window
//! ([`ipauro_proto::helper::FAILOPEN_GRACE_SECS`]) starts; if no connection
//! returns before it elapses, the caller should destroy the bridge and return
//! to idle (stock networking). A reconnect at any point cancels the pending
//! grace window.
//!
//! Time-abstracted so it's unit-testable without sleeping: every method takes
//! the current [`Instant`] as an explicit parameter rather than reading the
//! clock itself, so tests can simulate elapsed time with plain
//! `Instant + Duration` arithmetic. The real-time driver (a background thread
//! that calls [`FailOpen::poll`] with `Instant::now()` on an interval) lives
//! in `main.rs`, not here.

use std::time::{Duration, Instant};

/// An action the caller must take in response to a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do.
    None,
    /// The grace window elapsed with zero live connections: destroy the
    /// bridge and return to idle.
    Destroy,
}

/// Pure fail-open state: a connection counter plus an optional grace-window
/// deadline. See module docs for the time-abstraction rationale.
#[derive(Debug)]
pub struct FailOpen {
    grace: Duration,
    connections: u32,
    deadline: Option<Instant>,
}

impl FailOpen {
    pub fn new(grace: Duration) -> Self {
        Self { grace, connections: 0, deadline: None }
    }

    /// A new authenticated connection was accepted. Cancels any pending
    /// grace window — this is the "cancel the timer on reconnect" gotcha.
    pub fn on_connect(&mut self) {
        self.connections += 1;
        self.deadline = None;
    }

    /// An authenticated connection was lost. If this was the last one,
    /// starts the grace window (idempotent: repeated calls while already at
    /// zero do not push the deadline back out).
    pub fn on_disconnect(&mut self, now: Instant) {
        self.connections = self.connections.saturating_sub(1);
        if self.connections == 0 && self.deadline.is_none() {
            self.deadline = Some(now + self.grace);
        }
    }

    /// Call periodically (e.g. once a second) with the current time. Returns
    /// [`Action::Destroy`] at most once per grace window — the deadline is
    /// cleared as soon as it fires, so subsequent polls return `None` until
    /// another disconnect starts a new window.
    pub fn poll(&mut self, now: Instant) -> Action {
        if self.connections == 0 {
            if let Some(deadline) = self.deadline {
                if now >= deadline {
                    self.deadline = None;
                    return Action::Destroy;
                }
            }
        }
        Action::None
    }

    /// Current count of live authenticated connections. Exposed for logging;
    /// production code should drive behavior off [`Self::poll`]'s return
    /// value, not this.
    pub fn live_connections(&self) -> u32 {
        self.connections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grace() -> Duration {
        Duration::from_secs(15)
    }

    #[test]
    fn idle_never_destroys() {
        let mut fo = FailOpen::new(grace());
        let t0 = Instant::now();
        assert_eq!(fo.poll(t0), Action::None);
        assert_eq!(fo.poll(t0 + Duration::from_secs(1_000)), Action::None);
    }

    #[test]
    fn disconnect_then_grace_elapses_destroys() {
        let mut fo = FailOpen::new(grace());
        fo.on_connect();
        let t0 = Instant::now();
        fo.on_disconnect(t0);

        // Still within grace: no destroy yet.
        assert_eq!(fo.poll(t0 + Duration::from_secs(5)), Action::None);
        assert_eq!(fo.poll(t0 + Duration::from_secs(14)), Action::None);

        // Grace elapsed: destroy fires exactly once.
        assert_eq!(fo.poll(t0 + Duration::from_secs(15)), Action::Destroy);
        assert_eq!(fo.poll(t0 + Duration::from_secs(16)), Action::None);
    }

    #[test]
    fn disconnect_then_reconnect_cancels_grace() {
        let mut fo = FailOpen::new(grace());
        fo.on_connect();
        let t0 = Instant::now();
        fo.on_disconnect(t0);
        assert_eq!(fo.poll(t0 + Duration::from_secs(5)), Action::None);

        // Reconnect before the grace window elapses.
        fo.on_connect();
        assert_eq!(fo.live_connections(), 1);

        // Even well past the original deadline, no destroy: the timer was
        // cancelled by the reconnect.
        assert_eq!(fo.poll(t0 + Duration::from_secs(30)), Action::None);
    }

    #[test]
    fn multiple_connections_only_disconnect_at_zero_starts_grace() {
        let mut fo = FailOpen::new(grace());
        fo.on_connect();
        fo.on_connect();
        let t0 = Instant::now();
        fo.on_disconnect(t0); // one left; grace must NOT start
        assert_eq!(fo.poll(t0 + Duration::from_secs(20)), Action::None);

        fo.on_disconnect(t0 + Duration::from_secs(1)); // now zero; grace starts here
        assert_eq!(fo.poll(t0 + Duration::from_secs(15)), Action::None); // 14s since real start
        assert_eq!(fo.poll(t0 + Duration::from_secs(16)), Action::Destroy); // 15s since real start
    }

    #[test]
    fn repeated_disconnect_at_zero_does_not_push_deadline_out() {
        let mut fo = FailOpen::new(grace());
        fo.on_connect();
        let t0 = Instant::now();
        fo.on_disconnect(t0); // deadline = t0 + 15s
        fo.on_disconnect(t0 + Duration::from_secs(10)); // spurious repeat; must not move deadline
        assert_eq!(fo.poll(t0 + Duration::from_secs(15)), Action::Destroy);
    }
}
