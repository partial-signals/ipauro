//! Fail-open state machine (ticket R002-F5).
//!
//! Keyed on the count of live *authenticated* connections from the brain
//! service — never on the UI client, which has no XPC relationship to the
//! helper at all. When the count drops to zero, a grace window
//! ([`ipauro_proto::helper::FAILOPEN_GRACE_SECS`]) starts; if no connection
//! returns before it elapses, the caller should run [`teardown`] and return
//! to idle (stock networking). A reconnect at any point cancels the pending
//! grace window.
//!
//! Time-abstracted so it's unit-testable without sleeping: every method takes
//! the current [`Instant`] as an explicit parameter rather than reading the
//! clock itself, so tests can simulate elapsed time with plain
//! `Instant + Duration` arithmetic. The real-time driver (a background thread
//! that calls [`FailOpen::poll`] with `Instant::now()` on an interval) lives
//! in `listener.rs`, not here.
//!
//! M1 widens what "fail open" means: restoring stock networking completely,
//! not just destroying the bridge. [`teardown`] is the ordered sequence —
//! see its own docs for why the order is load-bearing (the A002 "ordering
//! incident").

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

/// Full fail-open teardown, in the order the A002 findings doc's "pf
/// transport-scoping ... but pf is STATEFUL" section and the reconciler's
/// ordering note both demand: **scopes first**, then DHCP, then the bridge
/// LAST.
///
/// Why this order and not "destroy the bridge, then clean up": a pf scope
/// pinned to a bridge interface that's about to disappear does not
/// magically stop blocking that port — the block rule has no `on <iface>`
/// clause once the allow-list is gone (see `pf::generate_anchor_rules`), so
/// a scope left in place while its bridge dies blocks the port EVERYWHERE,
/// not just on the vanished bridge. The A002 findings doc hit exactly this
/// live ("had to `pf off` before rebuilding"). DHCP comes next (no point
/// serving leases on a bridge about to vanish); the bridge itself goes
/// last, once nothing still depends on it.
///
/// Every step runs even if an earlier one failed — a partial teardown must
/// never skip the final bridge destroy, since a half-torn-down state
/// (network still not fully stock) is exactly what fail-open exists to
/// prevent. Errors from every step are collected and returned together
/// rather than short-circuiting on the first one.
pub fn teardown(
    pf: &dyn crate::pf::PfExecutor,
    dhcp: &dyn crate::dhcp::DhcpExecutor,
    bridge: &dyn crate::executor::BridgeExecutor,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    if let Err(e) = pf.clear_scopes() {
        errors.push(format!("clear_scopes: {e:#}"));
    }
    if let Err(e) = dhcp.stop() {
        errors.push(format!("stop dhcp: {e:#}"));
    }
    if let Err(e) = bridge.destroy() {
        errors.push(format!("destroy bridge: {e:#}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "fail-open teardown had {} error(s): {}",
            errors.len(),
            errors.join("; ")
        ))
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

    // ---- teardown ordering (the A002 ordering incident) ----------------------

    use std::sync::Mutex;

    use ipauro_proto::state::BridgeInfo;

    use crate::dhcp::DhcpExecutor;
    use crate::executor::BridgeExecutor;
    use crate::pf::PfExecutor;

    /// Records which of the three teardown calls fired, in order, regardless
    /// of whether each one is configured to succeed or fail — the ordering
    /// must hold either way.
    #[derive(Default)]
    struct Spy {
        log: Mutex<Vec<&'static str>>,
        clear_scopes_err: Mutex<bool>,
        stop_dhcp_err: Mutex<bool>,
        destroy_bridge_err: Mutex<bool>,
    }

    impl PfExecutor for Spy {
        fn scope_udp(&self, _port: u16, _allowed_ifaces: &[String]) -> anyhow::Result<()> {
            unreachable!("teardown never scopes")
        }
        fn clear_scopes(&self) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("clear_scopes");
            if *self.clear_scopes_err.lock().unwrap() {
                anyhow::bail!("clear_scopes failed");
            }
            Ok(())
        }
        fn scoped_ports(&self) -> Vec<(u16, Vec<String>)> {
            Vec::new()
        }
    }

    impl DhcpExecutor for Spy {
        fn serve(
            &self,
            _: std::net::Ipv4Addr,
            _: std::net::Ipv4Addr,
            _: std::net::Ipv4Addr,
            _: std::net::Ipv4Addr,
        ) -> anyhow::Result<()> {
            unreachable!("teardown never serves")
        }
        fn stop(&self) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("stop_dhcp");
            if *self.stop_dhcp_err.lock().unwrap() {
                anyhow::bail!("stop_dhcp failed");
            }
            Ok(())
        }
        fn is_serving(&self) -> bool {
            false
        }
    }

    impl BridgeExecutor for Spy {
        fn create(&self) -> anyhow::Result<()> {
            unreachable!("teardown never creates")
        }
        fn destroy(&self) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("destroy_bridge");
            if *self.destroy_bridge_err.lock().unwrap() {
                anyhow::bail!("destroy_bridge failed");
            }
            Ok(())
        }
        fn status(&self) -> anyhow::Result<Option<BridgeInfo>> {
            unreachable!("teardown never queries status")
        }
        fn list_interfaces(&self) -> anyhow::Result<Vec<String>> {
            unreachable!("teardown never lists interfaces")
        }
        fn set_members(&self, _members: &[String]) -> anyhow::Result<()> {
            unreachable!("teardown never sets members")
        }
        fn set_address(&self, _ipv4: std::net::Ipv4Addr, _prefix: u8) -> anyhow::Result<()> {
            unreachable!("teardown never sets address")
        }
        fn address_prefix(&self) -> anyhow::Result<Option<u8>> {
            unreachable!("teardown never queries address_prefix")
        }
    }

    #[test]
    fn teardown_runs_scopes_then_dhcp_then_bridge_when_all_succeed() {
        let spy = Spy::default();
        assert!(teardown(&spy, &spy, &spy).is_ok());
        assert_eq!(*spy.log.lock().unwrap(), vec!["clear_scopes", "stop_dhcp", "destroy_bridge"]);
    }

    #[test]
    fn teardown_still_runs_dhcp_and_bridge_when_clear_scopes_fails() {
        let spy = Spy::default();
        *spy.clear_scopes_err.lock().unwrap() = true;
        let result = teardown(&spy, &spy, &spy);
        assert!(result.is_err(), "a failed step must surface, not be swallowed");
        assert_eq!(*spy.log.lock().unwrap(), vec!["clear_scopes", "stop_dhcp", "destroy_bridge"]);
    }

    #[test]
    fn teardown_still_runs_bridge_destroy_when_stop_dhcp_fails() {
        let spy = Spy::default();
        *spy.stop_dhcp_err.lock().unwrap() = true;
        let result = teardown(&spy, &spy, &spy);
        assert!(result.is_err());
        assert_eq!(*spy.log.lock().unwrap(), vec!["clear_scopes", "stop_dhcp", "destroy_bridge"]);
    }

    #[test]
    fn teardown_reports_every_failing_step_when_all_three_fail() {
        let spy = Spy::default();
        *spy.clear_scopes_err.lock().unwrap() = true;
        *spy.stop_dhcp_err.lock().unwrap() = true;
        *spy.destroy_bridge_err.lock().unwrap() = true;
        let err = teardown(&spy, &spy, &spy).unwrap_err();
        assert_eq!(*spy.log.lock().unwrap(), vec!["clear_scopes", "stop_dhcp", "destroy_bridge"]);
        let msg = err.to_string();
        assert!(
            msg.contains("clear_scopes")
                && msg.contains("stop dhcp")
                && msg.contains("destroy bridge")
        );
    }
}
