//! Human-first pretty-printing for `Snapshot`, `EventBody`, and `ErrorInfo`.
//!
//! Kept separate from `client.rs` so the formatter is unit-testable against a
//! canned `Snapshot` without any socket plumbing.

use ipauro_proto::ipc::{ErrorCode, ErrorInfo, EventBody};
use ipauro_proto::state::{BridgeInfo, BridgeState, HelperState, Snapshot};

/// Render a whole-seconds duration as e.g. "1d 2h 3m 4s", dropping leading
/// zero units.
pub fn format_duration_secs(total: u64) -> String {
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let mins = (total % 3_600) / 60;
    let secs = total % 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m {secs}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {secs}s")
    } else if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

/// Human label for a `HelperState`. Every variant is named explicitly — no
/// catch-all — so a new variant fails to compile here instead of silently
/// rendering as blank.
pub fn helper_state_line(state: &HelperState) -> String {
    match state {
        HelperState::NotRegistered => "not registered".to_string(),
        HelperState::Registered => "registered (not connected)".to_string(),
        HelperState::RequiresApproval => "requires approval (check System Settings)".to_string(),
        HelperState::Connected { version } => format!("connected (v{version})"),
    }
}

/// Human label for the bridge's actual state (`None` = no bridge exists).
pub fn bridge_actual_line(actual: &Option<BridgeInfo>) -> String {
    match actual {
        None => "none".to_string(),
        Some(info) => format!(
            "{} [{}] {}",
            info.name,
            info.members.join(", "),
            info.ipv4.as_deref().unwrap_or("no ipv4")
        ),
    }
}

/// Flags a desired/actual mismatch on the bridge (e.g. "up" requested but not
/// yet actual, or vice versa) so operators notice convergence in progress.
fn bridge_pending_note(bridge: &BridgeState) -> &'static str {
    if bridge.desired_up == bridge.actual.is_some() {
        ""
    } else {
        "  (pending)"
    }
}

/// Multi-line status block: service version/pid/uptime, helper state, bridge
/// desired-vs-actual. Used by both `ipauro status` and any command reply.
pub fn pretty_snapshot(snapshot: &Snapshot) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(snapshot.service.started_unix);
    let uptime = format_duration_secs(now.saturating_sub(snapshot.service.started_unix));

    let lines = [
        "service:".to_string(),
        format!("  version   {}", snapshot.service.version),
        format!("  pid       {}", snapshot.service.pid),
        format!("  uptime    {uptime}"),
        String::new(),
        "helper:".to_string(),
        format!("  state     {}", helper_state_line(&snapshot.helper)),
        String::new(),
        "bridge:".to_string(),
        format!(
            "  desired   {}",
            if snapshot.bridge.desired_up { "up" } else { "down" }
        ),
        format!(
            "  actual    {}{}",
            bridge_actual_line(&snapshot.bridge.actual),
            bridge_pending_note(&snapshot.bridge)
        ),
        String::new(),
        "transport:".to_string(),
        format!("  link scope  {}", scope_line(&snapshot.transport)),
        format!(
            "  dhcp        {}",
            if snapshot.transport.dhcp_serving { "serving" } else { "off" }
        ),
    ];
    lines.join("\n")
}

/// Desired-vs-actual rendering for the Link transport scope, mirroring the
/// bridge's own pending convention.
fn scope_line(t: &ipauro_proto::state::TransportState) -> String {
    match (t.link_scope_desired, t.link_scoped) {
        (true, true) => "on".to_string(),
        (true, false) => "on  (pending)".to_string(),
        (false, true) => "off (pending)".to_string(),
        (false, false) => "off".to_string(),
    }
}

/// One-line rendering of an event for `ipauro watch`'s pretty mode.
pub fn pretty_event_line(seq: u64, event: &EventBody) -> String {
    match event {
        // v0 events only ever carry a full snapshot (see ipauro-proto docs on
        // EventBody); a future telemetry-stream variant would need an arm here.
        EventBody::Snapshot { snapshot } => format!(
            "#{seq}  helper={}  bridge_desired={}  bridge_actual={}",
            helper_state_line(&snapshot.helper),
            if snapshot.bridge.desired_up { "up" } else { "down" },
            bridge_actual_line(&snapshot.bridge.actual)
        ),
    }
}

/// Stable string for an `ErrorCode`, matched explicitly per variant.
pub fn error_code_str(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::VersionMismatch => "version_mismatch",
        ErrorCode::HelperNotConnected => "helper_not_connected",
        ErrorCode::HelperRejected => "helper_rejected",
        ErrorCode::InvalidCommand => "invalid_command",
        ErrorCode::Internal => "internal",
    }
}

/// Rendering for a failed command reply, printed to stderr.
pub fn pretty_error(err: &ErrorInfo) -> String {
    format!("error [{}]: {}", error_code_str(err.code), err.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipauro_proto::state::ServiceInfo;

    fn base_snapshot() -> Snapshot {
        Snapshot {
            service: ServiceInfo { version: "0.0.1".into(), pid: 42, started_unix: 1_700_000_000 },
            helper: HelperState::Connected { version: "0.0.1".into() },
            bridge: BridgeState {
                desired_up: true,
                actual: Some(BridgeInfo {
                    name: "bridge90".into(),
                    members: vec!["en9".into(), "en12".into()],
                    ipv4: Some("10.69.0.1".into()),
                    prefix: None,
                }),
            },
            transport: Default::default(),
        }
    }

    #[test]
    fn duration_formatting_drops_leading_zero_units() {
        assert_eq!(format_duration_secs(5), "5s");
        assert_eq!(format_duration_secs(65), "1m 5s");
        assert_eq!(format_duration_secs(3_723), "1h 2m 3s");
        assert_eq!(format_duration_secs(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn pretty_snapshot_includes_service_helper_bridge_fields() {
        let out = pretty_snapshot(&base_snapshot());
        assert!(out.contains("0.0.1"));
        assert!(out.contains("42"));
        assert!(out.contains("connected (v0.0.1)"));
        assert!(out.contains("desired   up"));
        assert!(out.contains("bridge90"));
        assert!(out.contains("en9, en12"));
        assert!(out.contains("10.69.0.1"));
        assert!(!out.contains("pending"));
    }

    #[test]
    fn pretty_snapshot_flags_desired_actual_mismatch() {
        let mut snap = base_snapshot();
        snap.bridge.actual = None; // desired_up stays true -> mismatch
        let out = pretty_snapshot(&snap);
        assert!(out.contains("(pending)"));
    }

    #[test]
    fn helper_state_line_covers_every_variant_distinctly() {
        let rendered: Vec<String> = [
            HelperState::NotRegistered,
            HelperState::Registered,
            HelperState::RequiresApproval,
            HelperState::Connected { version: "1.2.3".into() },
        ]
        .iter()
        .map(helper_state_line)
        .collect();
        // All four renderings must be distinct so a user can tell them apart.
        for i in 0..rendered.len() {
            for j in (i + 1)..rendered.len() {
                assert_ne!(rendered[i], rendered[j]);
            }
        }
        assert!(rendered[3].contains("1.2.3"));
    }

    #[test]
    fn bridge_actual_line_handles_none_and_missing_ipv4() {
        assert_eq!(bridge_actual_line(&None), "none");
        let info = BridgeInfo { name: "bridge90".into(), members: vec![], ipv4: None, prefix: None };
        assert_eq!(bridge_actual_line(&Some(info)), "bridge90 [] no ipv4");
    }

    #[test]
    fn error_code_str_covers_every_variant_distinctly() {
        let codes = [
            ErrorCode::VersionMismatch,
            ErrorCode::HelperNotConnected,
            ErrorCode::HelperRejected,
            ErrorCode::InvalidCommand,
            ErrorCode::Internal,
        ];
        let rendered: Vec<&str> = codes.iter().copied().map(error_code_str).collect();
        for i in 0..rendered.len() {
            for j in (i + 1)..rendered.len() {
                assert_ne!(rendered[i], rendered[j]);
            }
        }
    }

    #[test]
    fn pretty_event_line_includes_seq_and_bridge_state() {
        let line = pretty_event_line(7, &EventBody::Snapshot { snapshot: base_snapshot() });
        assert!(line.starts_with("#7"));
        assert!(line.contains("bridge90"));
    }
}
