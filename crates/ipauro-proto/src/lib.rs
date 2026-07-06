//! ipauro-proto — the shared protocol contract for IPAuRo.
//!
//! Three surfaces live here:
//! - [`ipc`]: the client ⇄ brain-service protocol (unix socket, NDJSON). Every
//!   client — the CLI, the egui tray UI, and external apps — speaks exactly
//!   this. Snapshot-on-connect + ordered event stream; the service's state
//!   store is the single source of truth (ticket R002-T7).
//! - [`helper`]: the brain-service ⇄ privileged-helper command set (XPC mach
//!   service). Narrow by construction: the helper exposes verbs, never
//!   parameters an attacker could aim (ticket R002-T3).
//! - [`state`]: the shared state types both surfaces carry.
//!
//! **This crate is manager-owned.** Implementation agents must not edit it;
//! request contract changes in your final report instead.
//!
//! Versioning: the server rejects clients whose [`PROTOCOL_VERSION`] it does
//! not know. Additive changes (new commands, defaulted snapshot fields) do
//! NOT bump the version — JSON tolerates unknown fields both ways; only
//! breaking reshapes bump it. v0 favors debuggability (NDJSON you can drive
//! with `nc`) over wire efficiency.
//!
//! Telemetry (metering) is deliberately NOT in the v0 control stream: per
//! R002-T7's gotcha, high-rate meter frames will arrive post-v0 as a separate
//! stream negotiated via a future `Command::SubscribeTelemetry`, so meters
//! never perturb control traffic.
//!
//! `@arch:see(.yah/docs/working/W001-ipauro-plan.md)`

pub const PROTOCOL_VERSION: u32 = 0;
// Version policy: additive changes (new commands, new optional snapshot
// fields with #[serde(default)]) do NOT bump the version — JSON tolerates
// unknown fields both ways. Only breaking reshapes bump it.

/// Prototype-proven defaults for the M1 data plane (mirrors `prototype/`'s
/// env defaults — the executable spec).
pub mod defaults {
    use std::net::Ipv4Addr;
    pub const BRIDGE_IPV4: Ipv4Addr = Ipv4Addr::new(10, 69, 0, 1);
    pub const BRIDGE_PREFIX: u8 = 24;
    pub const DHCP_POOL_START: Ipv4Addr = Ipv4Addr::new(10, 69, 0, 10);
    pub const DHCP_POOL_END: Ipv4Addr = Ipv4Addr::new(10, 69, 0, 200);
}

/// Seed of the M4 protocol registry (R004-F1): declarative protocol → ports
/// data, so transport scoping is data-driven from day one, never a
/// type-name match. M1 ships exactly one entry.
pub mod registry {
    pub struct ProtocolPorts {
        pub name: &'static str,
        pub udp_ports: &'static [u16],
        pub multicast_v4: &'static [&'static str],
        pub multicast_v6: &'static [&'static str],
    }
    /// Ableton Link (A002: udp/20808, 224.76.78.75, ff12::8080).
    pub const LINK: ProtocolPorts = ProtocolPorts {
        name: "ableton-link",
        udp_ports: &[20808],
        multicast_v4: &["224.76.78.75"],
        multicast_v6: &["ff12::8080"],
    };
}

/// Stable identifiers shared by packaging, the service, and the helper.
pub mod ids {
    /// The app bundle (main executable = the egui tray UI).
    pub const BUNDLE_ID: &str = "io.ipauro.app";
    /// launchd label for the brain service (SMAppService agent).
    pub const CORE_AGENT_LABEL: &str = "io.ipauro.core";
    /// launchd label AND mach service name of the privileged helper daemon.
    pub const HELPER_LABEL: &str = "io.ipauro.helper";

    /// Apple Developer Team ID used in code-signing requirements. Forks
    /// override at build time via the `IPAURO_TEAM_ID` env var.
    pub fn team_id() -> &'static str {
        option_env!("IPAURO_TEAM_ID").unwrap_or("7BW4R8G8Q6")
    }
}

/// Shared state types. The service owns the authoritative [`Snapshot`];
/// clients only ever render it.
pub mod state {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Snapshot {
        pub service: ServiceInfo,
        pub helper: HelperState,
        pub bridge: BridgeState,
        /// M1 data-plane state. `#[serde(default)]` so a new client tolerates
        /// an old server's snapshots (additive-change policy).
        #[serde(default)]
        pub transport: TransportState,
    }

    /// Data-plane posture beyond bare bridge existence (M1, R005).
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    pub struct TransportState {
        /// Whether scoping was REQUESTED (SetTransportScope) — desired state,
        /// so a reconnecting client can distinguish "never asked" from
        /// "asked, not applied yet". `#[serde(default)]`: additive.
        #[serde(default)]
        pub link_scope_desired: bool,
        /// Link's ports are pf-scoped to the bridge (prototype's pf-prefer).
        pub link_scoped: bool,
        /// The in-process DHCP responder is serving on the bridge.
        pub dhcp_serving: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct ServiceInfo {
        pub version: String,
        pub pid: u32,
        /// Unix seconds at service start (stamped by the service).
        pub started_unix: u64,
    }

    /// Where the privileged helper is in its lifecycle, as seen by the service.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "state", rename_all = "snake_case")]
    pub enum HelperState {
        /// SMAppService reports the daemon is not registered.
        NotRegistered,
        /// Registered but the service has no live XPC connection to it.
        Registered,
        /// Registration requires user approval in System Settings.
        RequiresApproval,
        /// Live XPC connection established.
        Connected { version: String },
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct BridgeState {
        /// What the user asked for (desired state).
        pub desired_up: bool,
        /// What actually exists right now, if anything.
        pub actual: Option<BridgeInfo>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct BridgeInfo {
        pub name: String,
        pub members: Vec<String>,
        pub ipv4: Option<String>,
        /// CIDR prefix of `ipv4`, when known. `#[serde(default)]`: additive.
        #[serde(default)]
        pub prefix: Option<u8>,
    }
}

/// Client ⇄ service IPC: unix socket, one JSON object per line (NDJSON).
///
/// Lifecycle: client connects → sends [`ClientMessage::Hello`] → server
/// replies [`ServerMessage::Hello`] carrying the full snapshot → server pushes
/// [`ServerMessage::Event`]s (monotonic `seq`) as state changes; commands get
/// a [`ServerMessage::Reply`] correlated by client-chosen `id`.
///
/// Version mismatch (pinned contract): the server ALWAYS sends its
/// [`ServerMessage::Hello`] — carrying its own `protocol_version` — before
/// acting on the client's version. If the client's version is unknown to the
/// server, the server closes the connection immediately after that Hello.
/// A client therefore detects rejection as "Hello with a foreign version,
/// then EOF", never as a bare EOF.
pub mod ipc {
    use crate::state::Snapshot;
    use serde::{Deserialize, Serialize};
    use std::io::{self, BufRead, Write};
    use std::path::PathBuf;

    /// Default socket path for the current user.
    /// macOS: `~/Library/Application Support/io.ipauro/core.sock`.
    /// Other unix (future): `$XDG_RUNTIME_DIR/ipauro/core.sock`.
    ///
    /// Note: unix socket paths are capped at ~104 bytes on macOS (`SUN_LEN`);
    /// a longer override fails at bind time, not silently.
    pub fn default_socket_path() -> PathBuf {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support/io.ipauro/core.sock")
        } else {
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or(home)
                .join("ipauro/core.sock")
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ClientMessage {
        Hello {
            protocol_version: u32,
            /// Human-readable, for logs/arbitration (e.g. "ipauro-cli 0.0.1").
            client_name: String,
            /// If false, the server sends Hello + Replies but no Events.
            subscribe_events: bool,
        },
        Command { id: u64, command: Command },
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "cmd", rename_all = "snake_case")]
    pub enum Command {
        /// Re-fetch the full snapshot (also delivered in Hello and on change).
        GetSnapshot,
        /// Set desired bridge state; the service drives actual → desired.
        BridgeUp,
        BridgeDown,
        /// Register/unregister the helper daemon via SMAppService (must be
        /// invoked from the installed app bundle context).
        RegisterHelper,
        UnregisterHelper,
        /// Pin Link's ports to the bridge via pf (block everywhere else) —
        /// the prototype's pf-prefer behavior, driven from
        /// `crate::registry::LINK`. The reconciler owns applying/clearing.
        SetTransportScope { enabled: bool },
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ServerMessage {
        Hello {
            protocol_version: u32,
            server_version: String,
            snapshot: Snapshot,
        },
        Event { seq: u64, event: EventBody },
        Reply {
            id: u64,
            #[serde(flatten)]
            outcome: ReplyOutcome,
        },
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "outcome", rename_all = "snake_case")]
    pub enum ReplyOutcome {
        Ok { snapshot: Snapshot },
        Err { error: ErrorInfo },
    }

    /// v0 events carry the full snapshot — state is small and this keeps every
    /// client trivially correct. Deltas are a post-v0 optimization.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "event", rename_all = "snake_case")]
    pub enum EventBody {
        Snapshot { snapshot: Snapshot },
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct ErrorInfo {
        pub code: ErrorCode,
        pub message: String,
    }

    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum ErrorCode {
        VersionMismatch,
        HelperNotConnected,
        HelperRejected,
        InvalidCommand,
        Internal,
    }

    /// Write one message as a JSON line. Callers flush.
    pub fn write_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
        serde_json::to_writer(&mut *w, msg)?;
        w.write_all(b"\n")
    }

    /// Read one message from a JSON line. `Ok(None)` = clean EOF.
    pub fn read_msg<T: for<'de> Deserialize<'de>>(
        r: &mut impl BufRead,
    ) -> io::Result<Option<T>> {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(line.trim_end())?))
    }
}

/// Service ⇄ privileged helper: XPC mach service (`ids::HELPER_LABEL`).
///
/// Wire convention: one xpc dictionary per message with a single `"msg"` key
/// holding the serde_json bytes of [`HelperRequest`]/[`HelperResponse`].
/// The helper MUST validate the peer's code signature before parsing anything
/// (team-ID requirement below); `IPAURO_INSECURE_DEV=1` disables validation
/// for unsigned dev builds and must never ship enabled.
pub mod helper {
    use crate::state::BridgeInfo;
    use serde::{Deserialize, Serialize};

    /// The only bridge the helper will ever touch. High unit number to avoid
    /// colliding with macOS's own Thunderbolt `bridge0` (see prototype).
    pub const BRIDGE_NAME: &str = "bridge90";

    /// Seconds the helper waits after losing its authenticated service
    /// connection before failing open (destroying the bridge, restoring
    /// stock networking). Tolerates service restarts/upgrades (R002-F5).
    pub const FAILOPEN_GRACE_SECS: u64 = 15;

    /// Env var that disables peer code-signing validation (dev only).
    pub const INSECURE_DEV_ENV: &str = "IPAURO_INSECURE_DEV";

    /// Code-signing requirement the helper applies to connecting peers.
    pub fn peer_requirement() -> String {
        format!(
            "anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
            crate::ids::team_id()
        )
    }

    /// Narrow verb set — no names, no paths, no rule text over the wire.
    ///
    /// Response pairing (pinned contract): `Ping` → `Pong`; `Status` →
    /// `Bridge`; `CreateBridge`/`DestroyBridge` → `Ok` **or** `Bridge` (a
    /// helper MAY answer with the resulting bridge state directly, saving the
    /// caller the follow-up `Status` round trip). Any request may be answered
    /// with `Err`. Other pairings are protocol violations the caller reports
    /// as internal errors.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "req", rename_all = "snake_case")]
    pub enum HelperRequest {
        Ping,
        Status,
        CreateBridge,
        DestroyBridge,
        /// Reconcile the bridge's member set to exactly this list (add
        /// missing, remove stale, flush any member-held IPv4s — addresses
        /// live on the bridge, A002 §4). The helper MUST validate every name
        /// (`^en[0-9]+$` and interface exists) before any exec — member names
        /// are the first attacker-aimable strings on this channel.
        /// `SetBridgeMembers` → `Ok` or `Bridge`.
        SetBridgeMembers { members: Vec<String> },
        /// Assign the bridge its IPv4 (idempotent). The helper MUST validate
        /// RFC1918 and 8..=30 prefix. → `Ok` or `Bridge`.
        SetBridgeAddress { ipv4: std::net::Ipv4Addr, prefix: u8 },
        /// Scope a UDP port to the allowed interfaces via a dedicated pf
        /// ANCHOR (allow there, block elsewhere, then selective state
        /// invalidation so live flows re-evaluate — stateful-pf trap, A002).
        /// Never whole-ruleset replace (R005-T5 gotcha). Iface names
        /// validated like members. → `Ok`.
        ScopeUdp { port: u16, allowed_ifaces: Vec<String> },
        /// Remove every scope this helper installed (flush the anchor). → `Ok`.
        ClearScopes,
        /// Serve DHCP on the bridge from an in-process responder — NEVER
        /// /etc/bootpd.plist (R005-T6 gotcha) — and NEVER emit a
        /// router/gateway option (the audio segment must not become a
        /// default route). Pool must lie in the bridge's subnet. → `Ok`.
        ServeDhcp {
            pool_start: std::net::Ipv4Addr,
            pool_end: std::net::Ipv4Addr,
            netmask: std::net::Ipv4Addr,
        },
        /// Stop the responder. → `Ok`.
        StopDhcp,
        /// Full data-plane report (bridge + scopes + DHCP). → `Report`.
        Report,
    }

    /// Answer to [`HelperRequest::Report`].
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct DataPlaneReport {
        pub bridge: Option<BridgeInfo>,
        /// Ports currently scoped by our anchor, with their allow-lists.
        pub scoped_ports: Vec<(u16, Vec<String>)>,
        pub dhcp_serving: bool,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "resp", rename_all = "snake_case")]
    pub enum HelperResponse {
        Pong { version: String },
        /// Current bridge state (None = no bridge exists).
        Bridge { info: Option<BridgeInfo> },
        /// Full data-plane report (answers `Report`).
        Report { report: DataPlaneReport },
        Ok,
        Err { message: String },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::*;
    use state::*;

    fn snapshot() -> Snapshot {
        Snapshot {
            service: ServiceInfo {
                version: "0.0.1".into(),
                pid: 42,
                started_unix: 1_700_000_000,
            },
            helper: HelperState::Connected { version: "0.0.1".into() },
            bridge: BridgeState {
                desired_up: true,
                actual: Some(BridgeInfo {
                    name: helper::BRIDGE_NAME.into(),
                    members: vec!["en9".into(), "en12".into()],
                    ipv4: Some("10.69.0.1".into()),
                    prefix: None,
                }),
            },
            transport: Default::default(),
        }
    }

    #[test]
    fn ipc_round_trips() {
        let msgs = vec![
            ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                client_name: "test".into(),
                subscribe_events: true,
            },
            ClientMessage::Command { id: 1, command: Command::BridgeUp },
            ClientMessage::Command { id: 2, command: Command::GetSnapshot },
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write_msg(&mut buf, m).unwrap();
        }
        let mut r = std::io::BufReader::new(buf.as_slice());
        for m in &msgs {
            let got: ClientMessage = read_msg(&mut r).unwrap().unwrap();
            assert_eq!(&got, m);
        }
        assert!(read_msg::<ClientMessage>(&mut r).unwrap().is_none());
    }

    #[test]
    fn server_messages_round_trip() {
        let msgs = vec![
            ServerMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                server_version: "0.0.1".into(),
                snapshot: snapshot(),
            },
            ServerMessage::Event {
                seq: 7,
                event: EventBody::Snapshot { snapshot: snapshot() },
            },
            ServerMessage::Reply { id: 1, outcome: ReplyOutcome::Ok { snapshot: snapshot() } },
            ServerMessage::Reply {
                id: 2,
                outcome: ReplyOutcome::Err {
                    error: ErrorInfo {
                        code: ErrorCode::HelperNotConnected,
                        message: "helper not connected".into(),
                    },
                },
            },
        ];
        for m in &msgs {
            let json = serde_json::to_string(m).unwrap();
            let back: ServerMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, m);
        }
    }

    #[test]
    fn m1_verbs_round_trip() {
        use std::net::Ipv4Addr;
        for req in [
            helper::HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "en12".into()] },
            helper::HelperRequest::SetBridgeAddress { ipv4: crate::defaults::BRIDGE_IPV4, prefix: 24 },
            helper::HelperRequest::ScopeUdp {
                port: registry::LINK.udp_ports[0],
                allowed_ifaces: vec![helper::BRIDGE_NAME.into()],
            },
            helper::HelperRequest::ClearScopes,
            helper::HelperRequest::ServeDhcp {
                pool_start: crate::defaults::DHCP_POOL_START,
                pool_end: crate::defaults::DHCP_POOL_END,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
            helper::HelperRequest::StopDhcp,
            helper::HelperRequest::Report,
        ] {
            let json = serde_json::to_string(&req).unwrap();
            assert_eq!(serde_json::from_str::<helper::HelperRequest>(&json).unwrap(), req);
        }
        let resp = helper::HelperResponse::Report {
            report: helper::DataPlaneReport {
                bridge: None,
                scoped_ports: vec![(20808, vec!["bridge90".into()])],
                dhcp_serving: true,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<helper::HelperResponse>(&json).unwrap(), resp);
    }

    #[test]
    fn old_snapshot_json_still_parses() {
        // Additive-change policy: a snapshot serialized WITHOUT the M1
        // `transport` field (an old server) must still parse via default.
        let old = r#"{"service":{"version":"0.0.1","pid":1,"started_unix":0},
            "helper":{"state":"not_registered"},
            "bridge":{"desired_up":false,"actual":null}}"#;
        let snap: Snapshot = serde_json::from_str(old).unwrap();
        assert_eq!(snap.transport, TransportState::default());
    }

    #[test]
    fn helper_messages_round_trip() {
        for req in [
            helper::HelperRequest::Ping,
            helper::HelperRequest::Status,
            helper::HelperRequest::CreateBridge,
            helper::HelperRequest::DestroyBridge,
        ] {
            let json = serde_json::to_string(&req).unwrap();
            assert_eq!(serde_json::from_str::<helper::HelperRequest>(&json).unwrap(), req);
        }
        let resp = helper::HelperResponse::Bridge { info: None };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<helper::HelperResponse>(&json).unwrap(), resp);
    }

    #[test]
    fn requirement_carries_team_id() {
        assert!(helper::peer_requirement().contains(ids::team_id()));
    }
}
