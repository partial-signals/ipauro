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
        // Data-plane generation: an app bound to the bridge rebinds when this
        // moves (`BridgeState::epoch`). Surfaced so an operator chasing a
        // dropout can see at a glance that the bridge was rebuilt under them.
        format!("  gen       {}", snapshot.bridge.epoch),
        String::new(),
        "transport:".to_string(),
        format!("  link scope  {}", scope_line(&snapshot.transport)),
        format!(
            "  dhcp        {}",
            if snapshot.transport.dhcp_serving { "serving" } else { "off" }
        ),
        "mesh:".to_string(),
        format!("  {}", pretty_roles(&snapshot.mesh).replace('\n', "\n  ")),
    ];
    lines.join("\n")
}

/// `ipauro role get` / the status "mesh:" block.
pub fn pretty_roles(mesh: &ipauro_proto::state::MeshView) -> String {
    let name = |r: ipauro_proto::state::NodeRole| match r {
        ipauro_proto::state::NodeRole::Hub => "hub",
        ipauro_proto::state::NodeRole::Peer => "peer",
    };
    let mut lines = vec![format!("this node: {}", name(mesh.role))];
    for p in &mesh.peers {
        lines.push(format!("  {}  {}", p.node_id, name(p.role)));
    }
    lines.join("\n")
}

/// `ipauro status mesh`: members table, rate, bootstrap health, blockages.
pub fn pretty_mesh_status(mesh: &ipauro_proto::state::MeshView) -> String {
    use ipauro_proto::state::{BeaconStatus, EndpointStatus, Liveness, N0Status, NodeRole};
    let Some(st) = &mesh.status else {
        return "mesh status unavailable (service predates it or has not published one yet)".into();
    };
    let role = |r: NodeRole| match r {
        NodeRole::Hub => "hub",
        NodeRole::Peer => "peer",
    };
    let mut lines = Vec::new();
    if !st.is_supported() {
        lines.push(format!(
            "note: service reports mesh status v{} (this client knows v{}); showing what is understood",
            st.version,
            ipauro_proto::state::MESH_STATUS_VERSION
        ));
    }
    lines.push(match &st.self_node {
        Some(id) => format!("node: {} (endpoint {})", id.node_id, id.endpoint_id),
        None => "node: no mesh identity".to_string(),
    });
    lines.push(match &st.endpoint {
        EndpointStatus::Bound { addrs } => format!("endpoint: bound on {}", addrs.join(", ")),
        EndpointStatus::Failed { error } => format!("endpoint: FAILED ({error})"),
        EndpointStatus::NotStarted => "endpoint: not started".to_string(),
        EndpointStatus::Unknown => "endpoint: ?".to_string(),
    });
    lines.push(format!(
        "rate: {} Hz (epoch {}{})",
        st.rate.hz,
        st.rate.epoch,
        if st.rate.author.is_empty() { String::new() } else { format!(", proposed by {}", st.rate.author) }
    ));
    lines.push(match &st.bootstrap.beacon {
        BeaconStatus::NotRunning => "beacon: not running".to_string(),
        BeaconStatus::Up { iface } => format!("beacon: up on {iface}"),
        BeaconStatus::Down { iface, cause } => {
            let b = ipauro_proto::state::Blockage {
                cause: cause.clone(),
                remedy: ipauro_proto::state::Remedy::Unknown,
            };
            format!("beacon: down on {iface} ({})", b.cause_text())
        }
        BeaconStatus::Unknown => "beacon: ?".to_string(),
    });
    lines.push(format!(
        "n0 discovery: {}",
        match st.bootstrap.n0 {
            N0Status::Off => "off",
            N0Status::On => "on",
            N0Status::Unknown => "?",
        }
    ));
    lines.push(String::new());
    lines.push("members:".to_string());
    lines.push(format!("  {:<18} {:<5} {:<9} {:<8} {:<16} {}", "node", "role", "state", "seen", "ipv4", "ula"));
    for m in &st.members {
        let state = match m.liveness {
            Liveness::Alive => "alive",
            Liveness::Expiring => "expiring",
            Liveness::Expired => "expired",
            Liveness::Unknown => "?",
        };
        let seen = if m.is_self { "self".to_string() } else { format!("{}s+", m.last_seen_age_secs) };
        lines.push(format!(
            "  {:<18} {:<5} {:<9} {:<8} {:<16} {}",
            m.node_id,
            role(m.role),
            state,
            seen,
            m.ipv4.as_deref().unwrap_or("-"),
            m.ula.as_deref().unwrap_or("-"),
        ));
    }
    lines.push(String::new());
    if st.blockages.is_empty() {
        lines.push("blockages: none".to_string());
    } else {
        lines.push("blockages:".to_string());
        for b in &st.blockages {
            lines.push(format!("  - {}", b.cause_text()));
            lines.push(format!("      fix: {}", b.remedy_text()));
        }
    }
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
            "#{seq}  helper={}  bridge_desired={}  bridge_actual={}  gen={}",
            helper_state_line(&snapshot.helper),
            if snapshot.bridge.desired_up { "up" } else { "down" },
            bridge_actual_line(&snapshot.bridge.actual),
            snapshot.bridge.epoch
        ),
    }
}

/// The rebind notice an app must act on when the data-plane generation it
/// bound its sockets at has been superseded — A001's ordered-pass step 5
/// ("signal the audio app to rejoin the new bridge") rendered for a human.
/// `None` when no rebind is due.
///
/// This is the whole client-side protocol, and it is a two-line diff on
/// purpose: hold the `epoch` you last bound at, compare it against every
/// snapshot you see (`Hello`'s included, so a reconnect after the rebuild is
/// covered), and rejoin when it moves. See `BridgeState::epoch`.
pub fn rebind_notice(bound_epoch: u64, bridge: &BridgeState) -> Option<String> {
    if bridge.epoch == bound_epoch {
        return None;
    }
    // No bridge to bind to: `bridge_actual_line` already says "none" and
    // there is nowhere to rejoin, so a rebind notice would be noise. The
    // epoch never advances on teardown either (see `next_epoch`), so this
    // arm only fires on an out-of-order/reset generation.
    let info = bridge.actual.as_ref()?;
    Some(format!(
        "** rebind: {} is now generation {} ({}) — sockets bound at generation {} are on a dead interface **",
        info.name,
        bridge.epoch,
        info.ipv4.as_deref().unwrap_or("no ipv4"),
        bound_epoch
    ))
}

/// Stable string for an `ErrorCode`, matched explicitly per variant.
pub fn error_code_str(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::VersionMismatch => "version_mismatch",
        ErrorCode::HelperNotConnected => "helper_not_connected",
        ErrorCode::HelperRejected => "helper_rejected",
        ErrorCode::InvalidCommand => "invalid_command",
        ErrorCode::Internal => "internal",
        ErrorCode::MeshUnavailable => "mesh_unavailable",
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
                epoch: 1,
            },
            transport: Default::default(),
            mesh: Default::default(),
        }
    }

    #[test]
    fn pretty_roles_lists_self_then_peers() {
        use ipauro_proto::state::{MeshPeer, MeshView, NodeRole};
        let m = MeshView {
            role: NodeRole::Peer,
            peers: vec![MeshPeer { node_id: "0102030405060708".into(), role: NodeRole::Hub }],
            status: None,
        };
        assert_eq!(pretty_roles(&m), "this node: peer\n  0102030405060708  hub");
    }

    #[test]
    fn pretty_mesh_status_renders_members_rate_and_blockages() {
        use ipauro_proto::state::*;
        let mesh = MeshView {
            role: NodeRole::Hub,
            peers: vec![],
            status: Some(MeshStatus {
                version: MESH_STATUS_VERSION + 1,
                self_node: Some(MeshIdentity { node_id: "aa".into(), endpoint_id: "ep".into() }),
                members: vec![
                    MeshMember {
                        node_id: "aa".into(),
                        is_self: true,
                        role: NodeRole::Hub,
                        ula: Some("fd00::1".into()),
                        ipv4: Some("10.42.0.5".into()),
                        addr_salt: 0,
                        last_seen_age_secs: 0,
                        liveness: Liveness::Alive,
                        reachability: Reachability::Unknown,
                    },
                    MeshMember {
                        node_id: "bb".into(),
                        is_self: false,
                        role: NodeRole::Peer,
                        ula: None,
                        ipv4: None,
                        addr_salt: 0,
                        last_seen_age_secs: 120,
                        liveness: Liveness::Expired,
                        reachability: Reachability::Unknown,
                    },
                ],
                rate: MeshRateView { hz: 96_000, epoch: 3, author: "aa".into() },
                blockages: vec![Blockage {
                    cause: BlockCause::PeerExpired { node_id: "bb".into(), age_secs: 120 },
                    remedy: Remedy::CheckPeer { node_id: "bb".into() },
                }],
                ..Default::default()
            }),
        };
        let out = pretty_mesh_status(&mesh);
        assert!(out.contains("this client knows v1"), "newer-version note: {out}");
        assert!(out.contains("rate: 96000 Hz (epoch 3, proposed by aa)"));
        assert!(out.contains("10.42.0.5") && out.contains("expired") && out.contains("120s+"));
        assert!(out.contains("peer bb silent for 120s+") && out.contains("fix: check power"));
        assert!(pretty_mesh_status(&MeshView::default()).contains("unavailable"));
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
        assert!(line.contains("gen=1"));
    }

    #[test]
    fn pretty_snapshot_shows_the_data_plane_generation() {
        let mut snap = base_snapshot();
        snap.bridge.epoch = 4;
        assert!(pretty_snapshot(&snap).contains("gen       4"));
    }

    #[test]
    fn no_rebind_notice_while_the_generation_holds() {
        assert_eq!(rebind_notice(1, &base_snapshot().bridge), None);
    }

    #[test]
    fn rebind_notice_names_both_generations_and_where_to_rebind() {
        let mut bridge = base_snapshot().bridge;
        bridge.epoch = 2;
        let notice = rebind_notice(1, &bridge).expect("a superseded generation must be reported");
        assert!(notice.contains("bridge90"), "{notice}");
        assert!(notice.contains("generation 2"), "{notice}");
        assert!(notice.contains("generation 1"), "{notice}");
        assert!(notice.contains("10.69.0.1"), "{notice}");
    }

    #[test]
    fn no_rebind_notice_when_there_is_no_bridge_to_rebind_to() {
        // A bumped generation with no bridge would be a signal to nowhere;
        // `actual: none` already tells the operator what happened.
        let mut bridge = base_snapshot().bridge;
        bridge.actual = None;
        bridge.epoch = 9;
        assert_eq!(rebind_notice(1, &bridge), None);
    }
}
