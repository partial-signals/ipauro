//! Connection-state reducer: pure, tested in isolation from both the IPC
//! thread and the egui event loop. `IpauroApp::logic` (`app.rs`) drains
//! `ipc_client` events and folds them through [`reduce`] — the only place a
//! [`Snapshot`] enters UI state, and the only place it leaves. Per the M0
//! ticket's binding requirement, the UI holds no state the service doesn't
//! have: a `Disconnected` event always clears the last snapshot rather than
//! leaving stale data on display.

use ipauro_proto::state::Snapshot;

/// Everything the background IPC thread can tell the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnEvent {
    /// The socket connected and `Hello` was sent; no snapshot yet.
    Connected,
    /// A snapshot arrived — from `Hello`'s reply, a pushed `Event`, or a
    /// command `Reply`. All three carry a full snapshot (protocol v0), so
    /// they fold into UI state identically.
    Snapshot(Snapshot),
    /// The socket dropped (EOF, error, or a fresh reconnect attempt failed).
    Disconnected,
    /// The reconnect loop can't connect and is trying to bring the core
    /// service up itself (SMAppService agent registration, and/or a
    /// dev-only sibling-binary spawn) rather than just waiting for it.
    StartingService,
    /// Nothing worked: the self-start attempt above failed outright (e.g.
    /// running outside a signed bundle with no dev-spawn fallback).
    ServiceStartFailed(String),
    /// A command's reply carried `ReplyOutcome::Err` — the connection and
    /// last-known snapshot are unaffected, but the user clicked something
    /// and the panel should say why it didn't work.
    CommandError(String),
}

/// Connection state as observed by the UI. There is deliberately no
/// "reconnecting" variant: the background thread's backoff is an
/// implementation detail invisible here — `Disconnected` covers first
/// launch, a dropped connection, and every backoff step alike, and the panel
/// renders the same "service not running" state for all of them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnState {
    #[default]
    Disconnected,
    /// Socket connected, `Hello` sent, no snapshot applied yet.
    Connected,
    /// A snapshot has been applied — the only state that has data to render.
    SnapshotApplied(Snapshot),
}

impl ConnState {
    /// The last-applied snapshot, if any. `None` whenever there is nothing
    /// live to show (disconnected, or connected but still awaiting `Hello`).
    pub fn snapshot(&self) -> Option<&Snapshot> {
        match self {
            ConnState::SnapshotApplied(snapshot) => Some(snapshot),
            ConnState::Disconnected | ConnState::Connected => None,
        }
    }
}

/// Fold one [`ConnEvent`] into the next [`ConnState`]. Every `ConnEvent`
/// variant is matched by name — no catch-all — so a new variant must be
/// handled here deliberately. `StartingService`/`ServiceStartFailed`/
/// `CommandError` say nothing about whether we have a socket and a snapshot
/// (that's what `ConnState` models), so they pass `current` through
/// unchanged; they're folded into [`StatusLine`] via [`reduce_status`]
/// instead.
pub fn reduce(current: &ConnState, event: ConnEvent) -> ConnState {
    match event {
        ConnEvent::Connected => ConnState::Connected,
        ConnEvent::Snapshot(snapshot) => ConnState::SnapshotApplied(snapshot),
        ConnEvent::Disconnected => ConnState::Disconnected,
        ConnEvent::StartingService | ConnEvent::ServiceStartFailed(_) | ConnEvent::CommandError(_) => {
            current.clone()
        }
    }
}

/// Transient, UI-only status line shown beneath the panel's rows: that the
/// reconnect loop is trying to bring the service up itself, that attempt
/// failing outright, or the most recent command's error. Never part of
/// [`ConnState`] — the service never reports any of this in a `Snapshot`, so
/// it would be dishonest to store it alongside data that actually came off
/// the wire (see this module's doc comment on the M0 ticket's "no state the
/// service doesn't have" rule — this is the one deliberate, clearly-labeled
/// exception, and it is UI-local by construction).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum StatusLine {
    #[default]
    None,
    StartingService,
    ServiceStartFailed(String),
    CommandError(String),
}

/// Fold one [`ConnEvent`] into the next [`StatusLine`]. Every variant
/// handled by name: a fresh `Connected` or a `Snapshot` both mean real data
/// is (about to be) on screen again, so they clear any stale status;
/// `Disconnected` alone leaves whatever was already showing, so a
/// `StartingService` message set moments before the socket drops doesn't
/// flicker away only to be set again on the very next loop iteration.
pub fn reduce_status(current: &StatusLine, event: &ConnEvent) -> StatusLine {
    match event {
        ConnEvent::StartingService => StatusLine::StartingService,
        ConnEvent::ServiceStartFailed(msg) => StatusLine::ServiceStartFailed(msg.clone()),
        ConnEvent::CommandError(msg) => StatusLine::CommandError(msg.clone()),
        ConnEvent::Snapshot(_) | ConnEvent::Connected => StatusLine::None,
        ConnEvent::Disconnected => current.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipauro_proto::state::*;

    fn snapshot(pid: u32) -> Snapshot {
        Snapshot {
            service: ServiceInfo {
                version: "0.0.1".into(),
                pid,
                started_unix: 1_700_000_000,
            },
            helper: HelperState::NotRegistered,
            bridge: BridgeState { desired_up: false, actual: None },
        }
    }

    #[test]
    fn disconnected_then_connected_then_snapshot_applied_then_disconnected() {
        let mut state = ConnState::default();
        assert_eq!(state, ConnState::Disconnected);
        assert_eq!(state.snapshot(), None);

        state = reduce(&state, ConnEvent::Connected);
        assert_eq!(state, ConnState::Connected);
        assert_eq!(state.snapshot(), None);

        let snap = snapshot(42);
        state = reduce(&state, ConnEvent::Snapshot(snap.clone()));
        assert_eq!(state, ConnState::SnapshotApplied(snap.clone()));
        assert_eq!(state.snapshot(), Some(&snap));

        state = reduce(&state, ConnEvent::Disconnected);
        assert_eq!(state, ConnState::Disconnected);
        assert_eq!(state.snapshot(), None);
    }

    #[test]
    fn reconnecting_clears_the_stale_snapshot_immediately() {
        // A second connect cycle must not leak the previous snapshot
        // forward: `Connected` always resets to "no data yet", even when we
        // had a snapshot applied a moment ago.
        let state = ConnState::SnapshotApplied(snapshot(1));
        let next = reduce(&state, ConnEvent::Connected);
        assert_eq!(next, ConnState::Connected);
        assert_eq!(next.snapshot(), None);
    }

    #[test]
    fn a_later_snapshot_replaces_an_earlier_one() {
        let state = reduce(&ConnState::default(), ConnEvent::Snapshot(snapshot(1)));
        let state = reduce(&state, ConnEvent::Snapshot(snapshot(2)));
        assert_eq!(state.snapshot().map(|s| s.service.pid), Some(2));
    }

    #[test]
    fn status_only_events_leave_conn_state_untouched() {
        let disconnected = ConnState::Disconnected;
        assert_eq!(
            reduce(&disconnected, ConnEvent::StartingService),
            ConnState::Disconnected
        );
        assert_eq!(
            reduce(&disconnected, ConnEvent::ServiceStartFailed("nope".into())),
            ConnState::Disconnected
        );
        assert_eq!(
            reduce(&disconnected, ConnEvent::CommandError("nope".into())),
            ConnState::Disconnected
        );

        let applied = ConnState::SnapshotApplied(snapshot(7));
        assert_eq!(reduce(&applied, ConnEvent::StartingService), applied);
        assert_eq!(
            reduce(&applied, ConnEvent::CommandError("boom".into())),
            applied
        );
    }

    #[test]
    fn reduce_status_sets_starting_service() {
        let status = reduce_status(&StatusLine::None, &ConnEvent::StartingService);
        assert_eq!(status, StatusLine::StartingService);
    }

    #[test]
    fn reduce_status_sets_service_start_failed_with_message() {
        let status = reduce_status(
            &StatusLine::None,
            &ConnEvent::ServiceStartFailed("no signed bundle".into()),
        );
        assert_eq!(status, StatusLine::ServiceStartFailed("no signed bundle".into()));
    }

    #[test]
    fn reduce_status_sets_command_error_with_message() {
        let status =
            reduce_status(&StatusLine::None, &ConnEvent::CommandError("helper busy".into()));
        assert_eq!(status, StatusLine::CommandError("helper busy".into()));
    }

    #[test]
    fn reduce_status_clears_on_connected_and_snapshot() {
        let stale = StatusLine::CommandError("stale".into());
        assert_eq!(reduce_status(&stale, &ConnEvent::Connected), StatusLine::None);
        assert_eq!(
            reduce_status(&stale, &ConnEvent::Snapshot(snapshot(1))),
            StatusLine::None
        );
    }

    #[test]
    fn reduce_status_preserves_current_on_disconnected() {
        let starting = StatusLine::StartingService;
        assert_eq!(reduce_status(&starting, &ConnEvent::Disconnected), starting);
    }
}
