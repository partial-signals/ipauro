//! Connection-state reducer: pure, tested in isolation from both the IPC
//! thread and the egui event loop. `IpauroApp::logic` (`app.rs`) drains
//! `ipc_client` events and folds them through [`reduce`] — the only place a
//! [`Snapshot`] enters UI state, and the only place it leaves. Per the M0
//! ticket's binding requirement, the UI holds no state the service doesn't
//! have: a `Disconnected` event always clears the last snapshot rather than
//! leaving stale data on display.
//!
//! That rule has exactly two deliberate, clearly-labelled exceptions, each
//! folded from the same `ConnEvent` stream by its own reducer and each
//! documented on its own type: [`StatusLine`] (transient — things the service
//! never reports at all, cleared by the next snapshot) and [`RebindWatch`]
//! (latched — a *past* value of `bridge.epoch` plus whether the operator has
//! acknowledged that it moved, which is by definition not in any single
//! snapshot).
//!
//! @yah:ticket(R005-F9, "UI surfaces the data-plane rebind signal (bridge generation) so the operator knows to restart their audio app")
//! @yah:status(review)
//! @yah:at(2026-07-26T03:13:32Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R005)
//! @yah:gotcha("Tier: Cleric — small surface, but the UI's 'no state the service doesn't have' rule makes the state-placement call a real design decision, not a mechanical add.")
//! @yah:gotcha("Do NOT bump on membership change or teardown; the service already encodes that rule in `reconcile::next_epoch`. The UI must only mirror `bridge.epoch`, never re-derive when a rebind is due.")
//! @yah:verify("cargo test -p ipauro-ui — 56 pass; the crate is `ipauro-ui`, not `dev-ui` as this ticket originally said. New reducer tests cover: first snapshot only seeds, bumped epoch latches, unchanged epoch does not, teardown alone does not, moved-epoch-with-no-bridge does not latch but still advances, service restart (epoch reset to 0) latches, latch survives Disconnected/Connected, a rebuild missed while disconnected latches on the reconnect snapshot, acknowledge clears without re-arming.")
//! @yah:handoff("State home decided: a NEW `RebindWatch` field in app/ui/src/state.rs, not an extended `StatusLine`. Justification (in the type's doc): `StatusLine` is transient and single-slot — every Snapshot/Connected clears it and each message replaces the last — whereas a rebind latch must survive both, and a CommandError landing a moment later would otherwise erase the notice. Module doc + `StatusLine`'s doc now both say there are exactly two labelled UI-local exceptions.")
//! @yah:handoff("Semantics mirror `ipauro_cli::format::rebind_notice` + `client::watch_loop` exactly: hold the last-seen epoch, compare against EVERY snapshot (Hello's included), `!=` not `>` so a service restart's epoch reset also flags, and the `bridge.actual.is_some()` guard so a moved epoch with no bridge to rejoin advances the tracker without latching. The UI never re-derives when a rebind is due — it only mirrors `bridge.epoch`.")
//! @yah:handoff("Rendered as an amber callout at the top of the panel (above the status rows, below the heading) with the generation, the recovery, and a Dismiss button. `panel::show` now returns a `PanelOutcome { rebind_dismissed }` rather than taking `&mut` — it stays a pure function of the state it's handed; `app.rs` calls `RebindWatch::acknowledge` on it. Dismiss only clears the latch, so the next rebuild flags again.")
//! @yah:handoff("Scope extended beyond the ticket's `panel.rs`: the compact always-on-top widget (widget.rs) also shows an amber dot + 'rebind' label with hover text. That is the mode an operator actually leaves open mid-session, so a panel-only callout would be invisible exactly when it matters. Dismissing stays panel-only (no room, and acknowledging deserves the full explanation).")
//! @yah:handoff("Discovered fixes: the ticket's verify named crate `dev-ui`, which does not exist — it is `ipauro-ui` (verify line corrected). `app.rs`'s module doc claimed the app owns 'nothing the service doesn't already have', which was already untrue of `StatusLine`; corrected to name both exceptions. `panel.rs`'s heading/separator hoisted from `show_status` into `show` so the callout sits between them — `show_status` is now snapshot rows only.")

use ipauro_proto::state::{BridgeState, Snapshot};

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
/// service doesn't have" rule — this is one of its two deliberate,
/// clearly-labeled exceptions, and it is UI-local by construction).
///
/// Contrast [`RebindWatch`], the other one: this is *transient* and single-slot
/// — every `Snapshot`/`Connected` clears it, and each new message replaces the
/// last. That's exactly why a rebind notice does not live here.
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

/// Latched "the data plane was rebuilt under you" notice — the UI's side of
/// `BridgeState::epoch`. The service tears the whole macOS bridge down and
/// rebuilds it under the same name, members and address when a single member
/// is unplugged (A002 §4), so *nothing else in the snapshot changes*: without
/// this, the panel shows a perfectly steady bridge while the operator's audio
/// app sits on a dead interface. Recovery is a restart of that app, which
/// only the operator can do — hence a notice rather than anything automatic.
///
/// Semantics are deliberately identical to the reference consumer,
/// `ipauro_cli::format::rebind_notice` + `client::watch_loop`: hold the epoch
/// last seen, compare it against *every* snapshot (`Hello`'s included), and
/// flag when it moves. Comparison is `!=`, not `>`, so a service restart —
/// which resets the epoch to 0 — also flags; per `BridgeState::epoch` that is
/// conservative in the safe direction.
///
/// This is UI-local by construction and one of the two exceptions to the "no
/// state the service doesn't have" rule (see this module's doc comment):
/// `bound_epoch` is a *previous* snapshot's value and `pending` is operator
/// acknowledgement, neither of which any single snapshot carries. It is NOT
/// part of [`StatusLine`], whose lifetime is the exact opposite — a
/// `StatusLine` is cleared by the next `Snapshot`/`Connected`, and a single
/// slot, so a command error moments later would erase the notice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RebindWatch {
    /// The generation folded in from the most recent snapshot, or `None`
    /// before this UI process has seen any snapshot at all. The first
    /// snapshot only seeds it: the UI has no idea which generation the
    /// operator's audio app bound at before launch, and guessing "a rebind is
    /// due" on startup would cry wolf on every single launch.
    bound_epoch: Option<u64>,
    /// `Some(generation)` once a rebind became due, until the operator
    /// dismisses it. Survives `Disconnected`/`Connected` on purpose: the
    /// epoch is level-triggered precisely so a consumer that was away across
    /// the rebuild still notices, and the notice is still true after the
    /// socket comes back.
    pending: Option<u64>,
}

impl RebindWatch {
    /// The generation the bridge was rebuilt at, while the operator hasn't
    /// dismissed the notice; `None` when nothing is outstanding.
    pub fn pending(&self) -> Option<u64> {
        self.pending
    }

    /// The operator says they've restarted their audio app. Clears only the
    /// latch — `bound_epoch` keeps tracking, so the *next* rebuild flags
    /// again.
    pub fn acknowledge(&mut self) {
        self.pending = None;
    }

    /// Fold one snapshot's bridge state in. `bound_epoch` always advances (so
    /// a generation is never re-reported), but the latch is only set when
    /// there is something to rejoin — mirroring `rebind_notice`'s
    /// `bridge.actual` guard. Teardown alone never advances the epoch
    /// (`reconcile::next_epoch`), so an epoch that moved with no bridge
    /// present is an out-of-order/reset generation, and telling the operator
    /// to rejoin a bridge that isn't there would be noise the panel's own
    /// "No bridge" row already covers.
    fn observe(&self, bridge: &BridgeState) -> RebindWatch {
        let moved = self.bound_epoch.is_some_and(|bound| bound != bridge.epoch);
        let pending = if moved && bridge.actual.is_some() {
            Some(bridge.epoch)
        } else {
            self.pending
        };
        RebindWatch { bound_epoch: Some(bridge.epoch), pending }
    }
}

/// Fold one [`ConnEvent`] into the next [`RebindWatch`]. Only `Snapshot`
/// carries a `bridge.epoch`; every other variant is matched by name and
/// passes `current` through untouched — notably `Disconnected`, which must
/// NOT reset the watch (see [`RebindWatch::pending`]).
pub fn reduce_rebind(current: &RebindWatch, event: &ConnEvent) -> RebindWatch {
    match event {
        ConnEvent::Snapshot(snapshot) => current.observe(&snapshot.bridge),
        ConnEvent::Connected
        | ConnEvent::Disconnected
        | ConnEvent::StartingService
        | ConnEvent::ServiceStartFailed(_)
        | ConnEvent::CommandError(_) => current.clone(),
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
            bridge: BridgeState { desired_up: false, actual: None, epoch: 0 },
            transport: Default::default(),
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

    /// A snapshot at generation `epoch`, with a bridge present iff `up`.
    fn bridge_snapshot(epoch: u64, up: bool) -> Snapshot {
        let mut snap = snapshot(1);
        snap.bridge = BridgeState {
            desired_up: up,
            actual: up.then(|| BridgeInfo {
                name: "bridge90".into(),
                members: vec!["en9".into()],
                ipv4: Some("10.69.0.1".into()),
                prefix: None,
            }),
            epoch,
        };
        snap
    }

    /// Fold a run of snapshots through `reduce_rebind` from a fresh watch.
    fn watch_over(snapshots: &[Snapshot]) -> RebindWatch {
        snapshots.iter().fold(RebindWatch::default(), |watch, snap| {
            reduce_rebind(&watch, &ConnEvent::Snapshot(snap.clone()))
        })
    }

    #[test]
    fn the_first_snapshot_only_seeds_the_generation() {
        // The UI can't know which generation the operator's app bound at
        // before launch — flagging here would cry wolf on every launch.
        let watch = watch_over(&[bridge_snapshot(7, true)]);
        assert_eq!(watch.pending(), None);
    }

    #[test]
    fn a_bumped_generation_latches_the_rebind_notice() {
        let watch = watch_over(&[bridge_snapshot(1, true), bridge_snapshot(2, true)]);
        assert_eq!(watch.pending(), Some(2));
    }

    #[test]
    fn an_unchanged_generation_does_not_latch() {
        let watch = watch_over(&[
            bridge_snapshot(1, true),
            bridge_snapshot(1, true),
            bridge_snapshot(1, true),
        ]);
        assert_eq!(watch.pending(), None);
    }

    #[test]
    fn the_notice_stays_latched_across_later_steady_snapshots() {
        // The operator may have the panel closed when the rebuild lands; the
        // notice must still be there when they open it.
        let watch = watch_over(&[
            bridge_snapshot(1, true),
            bridge_snapshot(2, true),
            bridge_snapshot(2, true),
        ]);
        assert_eq!(watch.pending(), Some(2));
    }

    #[test]
    fn a_teardown_alone_never_latches() {
        // `reconcile::next_epoch` holds the epoch across teardown, so this is
        // the honest steady case: bridge gone, generation unchanged. The
        // panel's own "No bridge" row already says what happened.
        let watch = watch_over(&[bridge_snapshot(3, true), bridge_snapshot(3, false)]);
        assert_eq!(watch.pending(), None);
    }

    #[test]
    fn a_moved_generation_with_no_bridge_to_rejoin_does_not_latch_but_still_advances() {
        // Mirrors `rebind_notice`'s `bridge.actual` guard: nowhere to rejoin,
        // so no notice — but the generation is consumed, so the bridge coming
        // back up at a new generation is what flags.
        let watch = watch_over(&[bridge_snapshot(3, true), bridge_snapshot(0, false)]);
        assert_eq!(watch.pending(), None);

        let after_rebuild =
            reduce_rebind(&watch, &ConnEvent::Snapshot(bridge_snapshot(1, true)));
        assert_eq!(after_rebuild.pending(), Some(1));
    }

    #[test]
    fn a_service_restart_that_resets_the_generation_latches() {
        // Comparison is `!=`, not `>` — an app outliving the service rebinds
        // once more than strictly needed, which `BridgeState::epoch` calls
        // conservative in the safe direction.
        let watch = watch_over(&[bridge_snapshot(5, true), bridge_snapshot(0, true)]);
        assert_eq!(watch.pending(), Some(0));
    }

    #[test]
    fn the_latch_survives_a_disconnect_and_reconnect() {
        // The whole point of a level-triggered epoch: a consumer that was
        // away across the rebuild still notices.
        let mut watch = watch_over(&[bridge_snapshot(1, true), bridge_snapshot(2, true)]);
        for event in [ConnEvent::Disconnected, ConnEvent::Connected] {
            watch = reduce_rebind(&watch, &event);
            assert_eq!(watch.pending(), Some(2), "{event:?} cleared the latch");
        }
    }

    #[test]
    fn a_rebuild_missed_while_disconnected_latches_on_the_reconnect_snapshot() {
        // The rebuild happens with the socket down; the epoch move is only
        // observable in the `Hello` snapshot after reconnecting.
        let watch = watch_over(&[bridge_snapshot(1, true)]);
        let watch = reduce_rebind(&watch, &ConnEvent::Disconnected);
        let watch = reduce_rebind(&watch, &ConnEvent::Connected);
        let watch = reduce_rebind(&watch, &ConnEvent::Snapshot(bridge_snapshot(2, true)));
        assert_eq!(watch.pending(), Some(2));
    }

    #[test]
    fn status_only_events_leave_the_rebind_watch_untouched() {
        let watch = watch_over(&[bridge_snapshot(1, true), bridge_snapshot(2, true)]);
        for event in [
            ConnEvent::StartingService,
            ConnEvent::ServiceStartFailed("nope".into()),
            ConnEvent::CommandError("nope".into()),
        ] {
            assert_eq!(reduce_rebind(&watch, &event), watch, "{event:?} moved the watch");
        }
    }

    #[test]
    fn acknowledging_clears_the_latch_but_keeps_tracking() {
        let mut watch = watch_over(&[bridge_snapshot(1, true), bridge_snapshot(2, true)]);
        watch.acknowledge();
        assert_eq!(watch.pending(), None);

        // Still steady at generation 2 — acknowledging must not re-arm.
        let watch = reduce_rebind(&watch, &ConnEvent::Snapshot(bridge_snapshot(2, true)));
        assert_eq!(watch.pending(), None);

        // The next real rebuild flags again.
        let watch = reduce_rebind(&watch, &ConnEvent::Snapshot(bridge_snapshot(3, true)));
        assert_eq!(watch.pending(), Some(3));
    }
}
