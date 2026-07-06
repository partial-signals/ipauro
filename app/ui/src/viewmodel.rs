//! Pure `Snapshot` → view-model mapping. No `egui` types here — this keeps
//! the mapping unit-testable without a graphics context, and keeps
//! `panel.rs`/`widget.rs` free of string formatting and enum-variant
//! matching.

use ipauro_proto::state::{BridgeState, HelperState, ServiceInfo, Snapshot, TransportState};

use crate::state::StatusLine;

/// Rows for the full Control-Center-style panel (`panel.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelViewModel {
    pub service_line: String,
    pub helper_line: String,
    /// Extra context shown above the helper action button — only non-`None`
    /// for `HelperState::RequiresApproval` ("Approve in System Settings…").
    pub helper_hint: Option<String>,
    /// Label for the helper install/re-check button, or `None` to hide it
    /// entirely (`Registered`/`Connected` need no user action here).
    pub helper_button_label: Option<String>,
    pub bridge_name_line: String,
    pub bridge_members_line: String,
    pub bridge_ipv4_line: String,
    /// Mirrors `desired_up`, not `actual` — the toggle button always reads
    /// "what will clicking this do", rather than lagging while the service
    /// converges actual → desired.
    pub bridge_desired_up: bool,
    /// Desired-vs-actual rendering for the Link transport scope: "on",
    /// "on (pending)", "off (pending)", "off" — mirrors `ipauro-cli`'s
    /// `scope_line` convention (`crates/ipauro-cli/src/format.rs`).
    pub link_scope_line: String,
    /// "serving" / "off" for the in-process DHCP responder.
    pub dhcp_line: String,
    /// Mirrors `link_scope_desired`, not `link_scoped` — same "what will
    /// clicking this do" convention as `bridge_desired_up`.
    pub link_scope_desired: bool,
}

/// The panel's transient status line (command errors, "starting
/// service…"), pre-formatted so `panel.rs` never matches a [`StatusLine`]
/// variant directly. `is_error` is the one bit of variant-derived shape
/// `panel.rs` needs (to pick a color) — a plain bool, not a re-exposed enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLineViewModel {
    pub text: String,
    pub is_error: bool,
}

/// Rows for the compact always-on-top widget (`widget.rs`): a status dot +
/// member count + a tiny link-scope dot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactViewModel {
    pub bridge_up: bool,
    pub member_count: usize,
    /// Whether Link's ports are actually pf-scoped right now (actual state,
    /// not desired — this is a glance-only display, no toggle here).
    pub link_scoped: bool,
}

pub fn panel_view_model(snapshot: &Snapshot, now_unix: u64) -> PanelViewModel {
    PanelViewModel {
        service_line: service_line(&snapshot.service, now_unix),
        helper_line: helper_line(&snapshot.helper),
        helper_hint: helper_hint(&snapshot.helper),
        helper_button_label: helper_button_label(&snapshot.helper),
        bridge_name_line: bridge_name_line(&snapshot.bridge),
        bridge_members_line: bridge_members_line(&snapshot.bridge),
        bridge_ipv4_line: bridge_ipv4_line(&snapshot.bridge),
        bridge_desired_up: snapshot.bridge.desired_up,
        link_scope_line: link_scope_line(&snapshot.transport),
        dhcp_line: dhcp_line(&snapshot.transport),
        link_scope_desired: snapshot.transport.link_scope_desired,
    }
}

/// [`StatusLine`] → [`StatusLineViewModel`], or `None` when there's nothing
/// to show. Every variant handled by name — no catch-all.
pub fn status_line_view_model(status: &StatusLine) -> Option<StatusLineViewModel> {
    match status {
        StatusLine::None => None,
        StatusLine::StartingService => Some(StatusLineViewModel {
            text: "Starting service…".to_string(),
            is_error: false,
        }),
        StatusLine::ServiceStartFailed(msg) => Some(StatusLineViewModel {
            text: format!("Couldn't start the service: {msg}"),
            is_error: true,
        }),
        StatusLine::CommandError(msg) => {
            Some(StatusLineViewModel { text: msg.clone(), is_error: true })
        }
    }
}

pub fn compact_view_model(snapshot: &Snapshot) -> CompactViewModel {
    CompactViewModel {
        bridge_up: snapshot.bridge.actual.is_some(),
        member_count: snapshot.bridge.actual.as_ref().map_or(0, |info| info.members.len()),
        link_scoped: snapshot.transport.link_scoped,
    }
}

fn service_line(service: &ServiceInfo, now_unix: u64) -> String {
    format!(
        "v{} · up {} · pid {}",
        service.version,
        format_uptime(now_unix, service.started_unix),
        service.pid
    )
}

/// `now_unix` is a parameter (rather than read from `SystemTime::now()`
/// internally) so this stays a pure, testable function.
pub fn format_uptime(now_unix: u64, started_unix: u64) -> String {
    let secs = now_unix.saturating_sub(started_unix);
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Every [`HelperState`] variant rendered explicitly by name — no catch-all,
/// so a new variant fails to compile here until someone decides its text.
fn helper_line(helper: &HelperState) -> String {
    match helper {
        HelperState::NotRegistered => "Not registered".to_string(),
        HelperState::Registered => "Registered (no XPC connection)".to_string(),
        HelperState::RequiresApproval => "Needs approval in System Settings".to_string(),
        HelperState::Connected { version } => format!("Connected (v{version})"),
    }
}

/// Extra hint text shown above the helper action button. Only
/// `RequiresApproval` has anything useful to say here — every other variant
/// explicit per house rule, not a catch-all.
fn helper_hint(helper: &HelperState) -> Option<String> {
    match helper {
        HelperState::RequiresApproval => Some("Approve in System Settings…".to_string()),
        HelperState::NotRegistered | HelperState::Registered | HelperState::Connected { .. } => None,
    }
}

/// Label for the helper install/re-check button, or `None` to hide it.
/// `NotRegistered` needs the user to kick off installation; `RequiresApproval`
/// needs a way to re-poll status after the user acts in System Settings
/// (clicking either button sends the same `Command::RegisterHelper` —
/// `registrar.register()` is idempotent, so "Re-check" is just another
/// registration attempt that also refreshes status). `Registered`/`Connected`
/// need no action here.
fn helper_button_label(helper: &HelperState) -> Option<String> {
    match helper {
        HelperState::NotRegistered => Some("Install Helper…".to_string()),
        HelperState::RequiresApproval => Some("Re-check".to_string()),
        HelperState::Registered | HelperState::Connected { .. } => None,
    }
}

fn bridge_name_line(bridge: &BridgeState) -> String {
    match &bridge.actual {
        Some(info) => info.name.clone(),
        None => "No bridge".to_string(),
    }
}

fn bridge_members_line(bridge: &BridgeState) -> String {
    match &bridge.actual {
        Some(info) if info.members.is_empty() => "No members".to_string(),
        Some(info) => info.members.join(", "),
        None => "—".to_string(),
    }
}

fn bridge_ipv4_line(bridge: &BridgeState) -> String {
    match &bridge.actual {
        Some(info) => info.ipv4.clone().unwrap_or_else(|| "No IPv4".to_string()),
        None => "—".to_string(),
    }
}

/// Desired-vs-actual rendering for the Link transport scope. Mirrors
/// `ipauro-cli`'s private `scope_line` (`crates/ipauro-cli/src/format.rs`):
/// all four `(desired, actual)` combinations rendered explicitly — no
/// catch-all — so "requested but not yet applied" and "cleared but not yet
/// torn down" are each their own distinct, honest label instead of collapsing
/// to a single ambiguous "on"/"off".
fn link_scope_line(transport: &TransportState) -> String {
    match (transport.link_scope_desired, transport.link_scoped) {
        (true, true) => "on".to_string(),
        (true, false) => "on (pending)".to_string(),
        (false, true) => "off (pending)".to_string(),
        (false, false) => "off".to_string(),
    }
}

/// Whether the in-process DHCP responder is serving on the bridge. This has
/// no separate "desired" bit in `TransportState` (it's driven implicitly by
/// the bridge's own desired/actual reconciliation), so — unlike the bridge
/// and link-scope rows — there's nothing to compare against and no
/// "(pending)" case here.
fn dhcp_line(transport: &TransportState) -> String {
    if transport.dhcp_serving { "serving".to_string() } else { "off".to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipauro_proto::state::BridgeInfo;

    fn snapshot_with(helper: HelperState, bridge: BridgeState) -> Snapshot {
        Snapshot {
            service: ServiceInfo { version: "1.2.3".into(), pid: 99, started_unix: 1_000 },
            helper,
            bridge,
            transport: Default::default(),
        }
    }

    fn snapshot_with_transport(transport: TransportState) -> Snapshot {
        Snapshot {
            service: ServiceInfo { version: "1.2.3".into(), pid: 99, started_unix: 1_000 },
            helper: HelperState::NotRegistered,
            bridge: BridgeState { desired_up: false, actual: None },
            transport,
        }
    }

    #[test]
    fn format_uptime_seconds_only() {
        assert_eq!(format_uptime(1_000 + 45, 1_000), "45s");
    }

    #[test]
    fn format_uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(1_000 + 125, 1_000), "2m 5s");
    }

    #[test]
    fn format_uptime_hours_and_minutes() {
        assert_eq!(format_uptime(1_000 + 3 * 3600 + 61, 1_000), "3h 1m");
    }

    #[test]
    fn every_helper_state_variant_has_distinct_text() {
        let texts = [
            helper_line(&HelperState::NotRegistered),
            helper_line(&HelperState::Registered),
            helper_line(&HelperState::RequiresApproval),
            helper_line(&HelperState::Connected { version: "9.9.9".into() }),
        ];
        for (i, a) in texts.iter().enumerate() {
            for (j, b) in texts.iter().enumerate() {
                assert!(i == j || a != b, "variants {i} and {j} render identically: {a:?}");
            }
        }
        assert!(texts[3].contains("9.9.9"));
    }

    #[test]
    fn panel_view_model_with_no_bridge() {
        let snapshot = snapshot_with(
            HelperState::NotRegistered,
            BridgeState { desired_up: false, actual: None },
        );
        let vm = panel_view_model(&snapshot, 1_000);
        assert_eq!(vm.bridge_name_line, "No bridge");
        assert_eq!(vm.bridge_members_line, "—");
        assert_eq!(vm.bridge_ipv4_line, "—");
        assert!(!vm.bridge_desired_up);
        // NotRegistered: a way to install, no approval hint needed yet.
        assert_eq!(vm.helper_button_label, Some("Install Helper…".to_string()));
        assert_eq!(vm.helper_hint, None);
    }

    #[test]
    fn panel_view_model_with_active_bridge() {
        let snapshot = snapshot_with(
            HelperState::Connected { version: "0.0.1".into() },
            BridgeState {
                desired_up: true,
                actual: Some(BridgeInfo {
                    name: "bridge90".into(),
                    members: vec!["en9".into(), "en12".into()],
                    ipv4: Some("10.69.0.1".into()),
                    prefix: None,
                }),
            },
        );
        let vm = panel_view_model(&snapshot, 1_000);
        assert_eq!(vm.bridge_name_line, "bridge90");
        assert_eq!(vm.bridge_members_line, "en9, en12");
        assert_eq!(vm.bridge_ipv4_line, "10.69.0.1");
        assert!(vm.bridge_desired_up);
        // Connected: nothing left for the user to do about the helper.
        assert_eq!(vm.helper_button_label, None);
        assert_eq!(vm.helper_hint, None);
    }

    #[test]
    fn helper_button_label_covers_every_variant() {
        assert_eq!(
            helper_button_label(&HelperState::NotRegistered),
            Some("Install Helper…".to_string())
        );
        assert_eq!(
            helper_button_label(&HelperState::RequiresApproval),
            Some("Re-check".to_string())
        );
        assert_eq!(helper_button_label(&HelperState::Registered), None);
        assert_eq!(
            helper_button_label(&HelperState::Connected { version: "1.0".into() }),
            None
        );
    }

    #[test]
    fn helper_hint_only_set_for_requires_approval() {
        assert_eq!(helper_hint(&HelperState::NotRegistered), None);
        assert_eq!(
            helper_hint(&HelperState::RequiresApproval),
            Some("Approve in System Settings…".to_string())
        );
        assert_eq!(helper_hint(&HelperState::Registered), None);
        assert_eq!(helper_hint(&HelperState::Connected { version: "1.0".into() }), None);
    }

    #[test]
    fn status_line_view_model_none_hides_the_line() {
        assert_eq!(status_line_view_model(&StatusLine::None), None);
    }

    #[test]
    fn status_line_view_model_starting_service_is_not_an_error() {
        let vm = status_line_view_model(&StatusLine::StartingService).unwrap();
        assert_eq!(vm.text, "Starting service…");
        assert!(!vm.is_error);
    }

    #[test]
    fn status_line_view_model_service_start_failed_is_an_error() {
        let vm =
            status_line_view_model(&StatusLine::ServiceStartFailed("no signed bundle".into()))
                .unwrap();
        assert!(vm.text.contains("no signed bundle"));
        assert!(vm.is_error);
    }

    #[test]
    fn status_line_view_model_command_error_is_an_error() {
        let vm = status_line_view_model(&StatusLine::CommandError("helper busy".into())).unwrap();
        assert_eq!(vm.text, "helper busy");
        assert!(vm.is_error);
    }

    #[test]
    fn panel_view_model_with_bridge_but_no_members() {
        let snapshot = snapshot_with(
            HelperState::NotRegistered,
            BridgeState {
                desired_up: true,
                actual: Some(BridgeInfo { name: "bridge90".into(), members: vec![], ipv4: None, prefix: None }),
            },
        );
        let vm = panel_view_model(&snapshot, 1_000);
        assert_eq!(vm.bridge_members_line, "No members");
        assert_eq!(vm.bridge_ipv4_line, "No IPv4");
    }

    #[test]
    fn compact_view_model_counts_members() {
        let snapshot = snapshot_with(
            HelperState::NotRegistered,
            BridgeState {
                desired_up: true,
                actual: Some(BridgeInfo {
                    name: "bridge90".into(),
                    members: vec!["en9".into(), "en12".into(), "en13".into()],
                    ipv4: None,
                    prefix: None,
                }),
            },
        );
        let vm = compact_view_model(&snapshot);
        assert!(vm.bridge_up);
        assert_eq!(vm.member_count, 3);
    }

    #[test]
    fn compact_view_model_with_no_bridge() {
        let snapshot = snapshot_with(
            HelperState::NotRegistered,
            BridgeState { desired_up: false, actual: None },
        );
        let vm = compact_view_model(&snapshot);
        assert!(!vm.bridge_up);
        assert_eq!(vm.member_count, 0);
    }

    /// All four `(desired, actual)` combinations rendered explicitly and
    /// correctly, matching `ipauro-cli`'s `scope_line` convention.
    #[test]
    fn link_scope_line_covers_every_desired_actual_combo() {
        let combos = [
            (true, true, "on"),
            (true, false, "on (pending)"),
            (false, true, "off (pending)"),
            (false, false, "off"),
        ];
        for (desired, actual, expected) in combos {
            let transport = TransportState {
                link_scope_desired: desired,
                link_scoped: actual,
                dhcp_serving: false,
            };
            assert_eq!(
                link_scope_line(&transport),
                expected,
                "desired={desired} actual={actual}"
            );
        }
    }

    #[test]
    fn dhcp_line_reflects_serving_state() {
        assert_eq!(
            dhcp_line(&TransportState {
                link_scope_desired: false,
                link_scoped: false,
                dhcp_serving: true
            }),
            "serving"
        );
        assert_eq!(
            dhcp_line(&TransportState {
                link_scope_desired: false,
                link_scoped: false,
                dhcp_serving: false
            }),
            "off"
        );
    }

    #[test]
    fn panel_view_model_wires_transport_fields_through() {
        let snapshot = snapshot_with_transport(TransportState {
            link_scope_desired: true,
            link_scoped: false,
            dhcp_serving: true,
        });
        let vm = panel_view_model(&snapshot, 1_000);
        assert_eq!(vm.link_scope_line, "on (pending)");
        assert_eq!(vm.dhcp_line, "serving");
        assert!(vm.link_scope_desired);
    }

    #[test]
    fn compact_view_model_reflects_link_scoped_actual_state() {
        let snapshot = snapshot_with_transport(TransportState {
            link_scope_desired: true,
            link_scoped: true,
            dhcp_serving: false,
        });
        let vm = compact_view_model(&snapshot);
        assert!(vm.link_scoped);

        let snapshot = snapshot_with_transport(TransportState {
            link_scope_desired: true,
            link_scoped: false,
            dhcp_serving: false,
        });
        let vm = compact_view_model(&snapshot);
        // Compact widget shows actual, not desired — pending scope isn't "on" yet.
        assert!(!vm.link_scoped);
    }
}
