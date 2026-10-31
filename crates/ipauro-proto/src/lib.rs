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

pub mod stream;

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
    /// The ipauro LAN bootstrap beacon (R003-F9): signed node announcements
    /// on the bridge. Link-local scope IPv6 multicast (`ff02::6970:6175`, the
    /// ASCII of "ipau"), plus a subnet-directed IPv4 *broadcast* fallback for
    /// v4-only segments (broadcast has no group, so `multicast_v4` is empty).
    /// The one definition: `ipauro-iroh`'s beacon reads its group/port from
    /// here, and a pf scope generator must allow this entry on the bridge.
    pub const IPAURO_BEACON: ProtocolPorts = ProtocolPorts {
        name: "ipauro-beacon",
        udp_ports: &[20818],
        multicast_v4: &[],
        multicast_v6: &["ff02::6970:6175"],
    };
    /// Every registry entry, for data-driven consumers.
    pub const ALL: &[&ProtocolPorts] = &[&LINK, &IPAURO_BEACON];
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
        /// This node's elected role and the gossiped roles of the mesh
        /// (R003-F4). `#[serde(default)]`: additive.
        #[serde(default)]
        pub mesh: MeshView,
    }

    /// The per-machine role a USER elects. `Hub` bridges its member links (and
    /// still participates as a peer); `Peer` creates no bridge. Default `Hub`
    /// is M1's behavior. Mirrors `ipauro_mesh::topology::NodeRole` (proto
    /// does not depend on the mesh crate).
    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
    #[serde(rename_all = "snake_case")]
    pub enum NodeRole {
        #[default]
        Hub,
        Peer,
    }

    /// Mesh posture as this node sees it.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    pub struct MeshView {
        /// THIS node's elected role (settable via `Command::SetRole`).
        #[serde(default)]
        pub role: NodeRole,
        /// Every other live member's gossiped role. READ-ONLY here: a role
        /// changes only by its own machine's user (no remote-set exists).
        #[serde(default)]
        pub peers: Vec<MeshPeer>,
        /// The versioned mesh health/membership section (R003-T5). `None` =
        /// the server predates it or has not published one yet.
        #[serde(default)]
        pub status: Option<MeshStatus>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct MeshPeer {
        /// Hex of the 8-byte mesh NodeId.
        pub node_id: String,
        pub role: NodeRole,
    }

    /// Version of the [`MeshStatus`] section this crate writes. Bumped only
    /// when the section is reshaped incompatibly; additive fields and new
    /// enum variants (which decode as `Unknown`) do not bump it. A client
    /// seeing a LARGER version still renders what parsed
    /// ([`MeshStatus::is_supported`] lets it say so).
    pub const MESH_STATUS_VERSION: u32 = 1;

    /// Mesh health + membership as this node sees it (R003-T5). Everything
    /// here is change-only: the service republishes it through the ordinary
    /// snapshot event stream and never on a bare heartbeat, so continuous
    /// quantities are bucketed (`last_seen_age_secs`) or left to the client.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    pub struct MeshStatus {
        #[serde(default)]
        pub version: u32,
        /// This node's identity; `None` while the iroh endpoint is not up.
        #[serde(default)]
        pub self_node: Option<MeshIdentity>,
        /// Self first, then every other known member (live, expiring, or
        /// recently expired), sorted by NodeId.
        #[serde(default)]
        pub members: Vec<MeshMember>,
        /// The adopted whole-mesh sample rate.
        #[serde(default)]
        pub rate: MeshRateView,
        #[serde(default)]
        pub bootstrap: BootstrapStatus,
        #[serde(default)]
        pub endpoint: EndpointStatus,
        /// Every degraded state, each with a named cause and remedy.
        #[serde(default)]
        pub blockages: Vec<Blockage>,
        /// Foreign (non-IPAuRo) devices hubs advertise from their DHCP
        /// leases, sorted by leaf id (R003-F6).
        #[serde(default)]
        pub foreign_leaves: Vec<ForeignLeafView>,
    }

    /// A foreign device a hub terminates control for (R003-F6).
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct ForeignLeafView {
        /// Hex mesh id (hub NodeId + MAC derivation) — the control address.
        pub leaf_id: String,
        /// Hex NodeId of the advertising hub.
        pub hub: String,
        /// `aa:bb:cc:dd:ee:ff`.
        pub mac: String,
        #[serde(default)]
        pub ipv4: Option<String>,
        #[serde(default)]
        pub reachability: Reachability,
    }

    impl MeshStatus {
        /// Whether this client knows every part of the section's shape. When
        /// false the client should say the server is newer and render
        /// best-effort.
        pub fn is_supported(&self) -> bool {
            self.version <= MESH_STATUS_VERSION
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct MeshIdentity {
        /// Hex of the 8-byte mesh NodeId.
        pub node_id: String,
        /// The full iroh EndpointId (ed25519 public key), as iroh prints it.
        pub endpoint_id: String,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct MeshMember {
        pub node_id: String,
        #[serde(default)]
        pub is_self: bool,
        #[serde(default)]
        pub role: NodeRole,
        /// The ULA this node's NodeId maps to.
        #[serde(default)]
        pub ula: Option<String>,
        /// The IPv4 the deterministic assignment gives it over the current
        /// member set.
        #[serde(default)]
        pub ipv4: Option<String>,
        /// Hash salt that produced `ipv4` (0 = first choice; >0 = it lost a
        /// collision).
        #[serde(default)]
        pub addr_salt: u32,
        /// Seconds since last heard, BUCKETED (see [`bucket_age_secs`]) so a
        /// healthy heartbeat does not change the snapshot.
        #[serde(default)]
        pub last_seen_age_secs: u32,
        #[serde(default)]
        pub liveness: Liveness,
        /// How this node reaches the member for CONTROL (R003-F6).
        #[serde(default)]
        pub reachability: Reachability,
    }

    /// Control reachability of a member over the gossiped graph (R003-F6).
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    #[serde(tag = "via", rename_all = "snake_case")]
    pub enum Reachability {
        /// No link state from this node yet (or a server that predates this).
        #[default]
        Unknown,
        /// One hop (or self).
        Direct,
        /// Through relays; `hub` (hex NodeId) is the hub the member sits behind.
        ViaHub { hub: String },
        /// Only reachable through `hub`, which does not relay control.
        HubWontRelay { hub: String },
        Unreachable,
        #[serde(other)]
        Other,
    }

    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
    #[serde(rename_all = "snake_case")]
    pub enum Liveness {
        #[default]
        Alive,
        /// Silent for longer than half the expiry window.
        Expiring,
        /// Past the expiry window; kept visible for a while after.
        Expired,
        #[serde(other)]
        Unknown,
    }

    /// Quantize a last-seen age so it changes at most every few seconds
    /// while a peer is healthy (always bucket 0) and coarsely afterwards:
    /// 10 s steps to a minute, then minute steps.
    pub fn bucket_age_secs(secs: u64) -> u32 {
        let b = if secs < 60 { secs / 10 * 10 } else { secs / 60 * 60 };
        b.min(u32::MAX as u64) as u32
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct MeshRateView {
        pub hz: u32,
        /// Monotonic proposal epoch; a raise is a new epoch.
        pub epoch: u64,
        /// Hex NodeId of the proposer of this epoch.
        #[serde(default)]
        pub author: String,
    }

    impl Default for MeshRateView {
        /// The One Rate: 48 kHz at epoch 0.
        fn default() -> Self {
            Self { hz: 48_000, epoch: 0, author: String::new() }
        }
    }

    /// Sample rates a whole-mesh proposal may name.
    pub const ALLOWED_MESH_RATES_HZ: &[u32] = &[44_100, 48_000, 88_200, 96_000, 176_400, 192_000];

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    pub struct BootstrapStatus {
        #[serde(default)]
        pub beacon: BeaconStatus,
        /// Per-interface beacon health (R003-B10): a Hub announces on its
        /// bridge, a Peer on each uplink. `beacon` above is the aggregate
        /// (Up if any interface is). Empty = no beacon running.
        /// `#[serde(default)]`: additive.
        #[serde(default)]
        pub beacons: Vec<BeaconStatus>,
        #[serde(default)]
        pub n0: N0Status,
    }

    /// The LAN beacon (R003-F9) health. `Down` carries the typed why.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    #[serde(tag = "state", rename_all = "snake_case")]
    pub enum BeaconStatus {
        #[default]
        NotRunning,
        Up { iface: String },
        Down { iface: String, cause: BlockCause },
        #[serde(other)]
        Unknown,
    }

    /// n0 relay / DNS discovery over the internet (opt-in; air-gapped = off).
    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
    #[serde(rename_all = "snake_case")]
    pub enum N0Status {
        #[default]
        Off,
        On,
        #[serde(other)]
        Unknown,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
    #[serde(tag = "state", rename_all = "snake_case")]
    pub enum EndpointStatus {
        #[default]
        NotStarted,
        Bound { addrs: Vec<String> },
        Failed { error: String },
        #[serde(other)]
        Unknown,
    }

    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub enum IpFamily {
        V4,
        V6,
    }

    /// Why something is degraded. Typed, not a string: clients branch on it
    /// (icon, grouping, remedy button) and only render the data.
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum BlockCause {
        /// The iroh endpoint could not bind; there is no mesh identity.
        IrohBindFailed { error: String },
        /// The endpoint is up but the gossip layer failed to start.
        GossipUnavailable { error: String },
        /// The beacon polls for the bridge interface and it does not exist.
        BeaconWaitingForBridge { iface: String },
        /// A Peer has no uplink interface to announce on yet (R003-B10).
        BeaconWaitingForUplink,
        /// The beacon could not bind its socket on the bridge.
        BeaconBindFailed { iface: String, family: IpFamily, error: String },
        /// More members than hash-range slots; no IPv4 for this node.
        Ipv4Exhausted { members: u32, capacity: u32 },
        /// This node's first-choice IPv4 collided; `ipv4` is the re-resolved
        /// address (salt > 0).
        AddressCollision { ipv4: String, salt: u32 },
        /// A previously live member went silent past the expiry window.
        PeerExpired { node_id: String, age_secs: u32 },
        /// `node_id` is only reachable through `hub`, which bridges but does
        /// not relay control — the media-only-bridge failure (R003-F6).
        ControlRelayRefused { node_id: String, hub: String },
        #[serde(other)]
        Unknown,
    }

    /// What to do about a [`BlockCause`].
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    #[serde(tag = "action", rename_all = "snake_case")]
    pub enum Remedy {
        /// Free the UDP port / fix the permission named in the cause, then
        /// restart the ipauro service.
        RestartService,
        BringBridgeUp,
        /// Only a Hub has a bridge, so only a Hub runs the beacon.
        ElectHubRole,
        /// A Peer reaches the mesh through an uplink; plug one in.
        ConnectUplink,
        CheckInterface { iface: String },
        ReduceMembersOrWidenHashRange,
        /// Nothing to do: the deterministic re-resolution already ran.
        WaitForResolution,
        CheckPeer { node_id: String },
        /// Make `node_id` relay control (elect it Hub), or give the cut-off
        /// node another path.
        EnableControlRelay { node_id: String },
        #[serde(other)]
        Unknown,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    pub struct Blockage {
        pub cause: BlockCause,
        pub remedy: Remedy,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Severity {
        /// Self-resolving or purely informational.
        Info,
        /// A feature is degraded.
        Degraded,
        /// The mesh cannot work on this node.
        Blocked,
    }

    impl Blockage {
        pub fn severity(&self) -> Severity {
            match &self.cause {
                BlockCause::IrohBindFailed { .. } | BlockCause::GossipUnavailable { .. } => {
                    Severity::Blocked
                }
                BlockCause::BeaconBindFailed { .. }
                | BlockCause::Ipv4Exhausted { .. }
                | BlockCause::PeerExpired { .. }
                | BlockCause::ControlRelayRefused { .. } => Severity::Degraded,
                BlockCause::BeaconWaitingForBridge { .. }
                | BlockCause::BeaconWaitingForUplink
                | BlockCause::AddressCollision { .. }
                | BlockCause::Unknown => Severity::Info,
            }
        }

        /// One-line human rendering of the cause.
        pub fn cause_text(&self) -> String {
            match &self.cause {
                BlockCause::IrohBindFailed { error } => format!("mesh endpoint failed to bind: {error}"),
                BlockCause::GossipUnavailable { error } => format!("mesh gossip failed to start: {error}"),
                BlockCause::BeaconWaitingForBridge { iface } => {
                    format!("LAN beacon waiting for {iface} to exist")
                }
                BlockCause::BeaconWaitingForUplink => {
                    "LAN beacon waiting for an uplink interface to a hub".into()
                }
                BlockCause::BeaconBindFailed { iface, family, error } => {
                    let f = match family {
                        IpFamily::V4 => "IPv4 broadcast",
                        IpFamily::V6 => "IPv6 multicast",
                    };
                    format!("LAN beacon cannot bind {f} on {iface}: {error}")
                }
                BlockCause::Ipv4Exhausted { members, capacity } => {
                    format!("{members} members exceed the IPv4 hash range ({capacity} slots)")
                }
                BlockCause::AddressCollision { ipv4, salt } => {
                    format!("IPv4 first choice collided; re-resolved to {ipv4} (salt {salt})")
                }
                BlockCause::PeerExpired { node_id, age_secs } => {
                    format!("peer {node_id} silent for {age_secs}s+, expired")
                }
                BlockCause::ControlRelayRefused { node_id, hub } => {
                    format!("{node_id} is only reachable via {hub}, which does not relay control")
                }
                BlockCause::Unknown => "unrecognized condition (newer service?)".into(),
            }
        }

        /// One-line human rendering of the remedy.
        pub fn remedy_text(&self) -> String {
            match &self.remedy {
                Remedy::RestartService => "free the port / fix permissions, then restart the ipauro service".into(),
                Remedy::BringBridgeUp => "bring the bridge up (ipauro bridge up)".into(),
                Remedy::ElectHubRole => "only a Hub has a bridge; elect Hub (ipauro role set hub) if this machine should bridge".into(),
                Remedy::CheckInterface { iface } => {
                    format!("check {iface} is up with a link-local address and not blocked by pf / Local Network permission")
                }
                Remedy::ReduceMembersOrWidenHashRange => "reduce the mesh size or widen the IPv4 hash range".into(),
                Remedy::WaitForResolution => "none needed; the address was re-resolved deterministically".into(),
                Remedy::CheckPeer { node_id } => format!("check power, cable and the ipauro service on {node_id}"),
                Remedy::EnableControlRelay { node_id } => {
                    format!("elect {node_id} Hub so it relays control, or give the node another path")
                }
                Remedy::ConnectUplink => "connect an uplink (USB / Thunderbolt / Ethernet) to a hub".into(),
                Remedy::Unknown => "update this client".into(),
            }
        }
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
        /// **Data-plane generation.** Increments every time a *fresh* bridge
        /// interface comes into existence, or the existing one is
        /// re-addressed — i.e. every time an app holding a socket bound to
        /// the bridge must rebind (A001's ordered reconcile pass, step 5:
        /// "signal the audio app to rejoin the new bridge"). Starts at 0,
        /// meaning "no bridge has existed yet in this service instance".
        ///
        /// This exists because of A002 §4's live incident: unplugging ONE USB
        /// member tears down the WHOLE macOS bridge, and the hub's audio app
        /// is left with a multicast socket joined on a dead interface. The
        /// bridge is rebuilt under the same name (`bridge90`) with the same
        /// address, so *nothing else in the snapshot changes* — an app
        /// diffing name/members/ipv4 cannot tell a rebuild happened.
        ///
        /// Deliberately **level-triggered**: a consumer records the epoch it
        /// bound at and compares it against every snapshot it sees, so an app
        /// that was disconnected across the rebuild still notices on
        /// reconnect (`ServerMessage::Hello` carries the snapshot). An
        /// edge-triggered "rebind now" event would be missable exactly when
        /// it matters most.
        ///
        /// Membership changes alone do NOT bump it — the interface an app is
        /// bound to is unchanged, and a spurious rebind costs an audible
        /// dropout. Nor does teardown (`actual: None`): there is nothing to
        /// bind to, which the snapshot already says outright.
        ///
        /// Per **service instance**: it resets with the service's pid, so an
        /// app that outlives a service restart sees a lower/repeated epoch
        /// and rebinds once more than strictly needed — conservative in the
        /// safe direction. Pair with `ServiceInfo.pid` to tell instances
        /// apart. `#[serde(default)]`: additive.
        #[serde(default)]
        pub epoch: u64,
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
        /// Elect THIS machine's role (R003-F4). Persisted across service
        /// restarts; gossiped to the mesh; changing it re-runs the reconcile
        /// (Hub → Peer tears the bridge down in the usual order).
        SetRole { role: crate::state::NodeRole },
        /// Propose lifting the WHOLE mesh to `hz` (R003-F8/T5): a new
        /// `MeshRate` epoch authored by this node, gossiped to every member.
        /// `hz` must be one of `state::ALLOWED_MESH_RATES_HZ` and differ from
        /// the adopted rate; there is no per-node rate. Lowering uses the same
        /// verb (a new epoch), since a raise would otherwise be irreversible.
        ProposeMeshRate { hz: u32 },
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
        /// The command needs the mesh and this service has none running.
        MeshUnavailable,
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
        /// Add a mesh-derived address ALIAS on `iface` (R003-T3, generalised
        /// by R003-B10): a NodeId-derived IPv6 ULA or hashed IPv4, applied by
        /// the node to itself with no DHCP involved. `iface` is the bridge
        /// (`BRIDGE_NAME`, a Hub) or a managed UPLINK (a Peer has no bridge, so
        /// it addresses the interface through which it reaches a hub's
        /// segment). Idempotent: an alias already present is a no-op.
        /// The helper MUST validate `iface` before any exec — the bridge, or
        /// an `^en[0-9]+$` interface that exists, is not a bridge member and
        /// is not the host's default-route interface (never the user's
        /// primary internet NIC) — AND class + prefix: IPv6 must be a ULA
        /// (`fd00::/8`) at `/64`; IPv4 must be RFC1918 at 8..=30. → `Ok`.
        AddAlias { iface: String, addr: std::net::IpAddr, prefix: u8 },
        /// Remove one alias previously added by `AddAlias` (idempotent:
        /// absent, or the interface gone, is `Ok`). Same `iface` + class
        /// validation as the add — this verb can never strip link-local,
        /// public, or a primary address class, nor touch a non-uplink
        /// interface. → `Ok`.
        RemoveAlias { iface: String, addr: std::net::IpAddr },
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
        /// Non-primary, non-link-local addresses currently on the bridge —
        /// i.e. the mesh aliases `AddAlias` installed on the bridge (R003-T3).
        /// Absent from an older helper's report = none.
        #[serde(default)]
        pub bridge_aliases: Vec<std::net::IpAddr>,
        /// Mesh-class aliases (ULA, or RFC1918 beyond the interface's first
        /// IPv4) per candidate uplink interface (R003-B10), sorted by name,
        /// empty interfaces omitted. Reported for every `^en[0-9]+$`
        /// interface that is not a bridge member nor the default-route
        /// interface; the core only acts on the ones it classified as its
        /// uplinks. Absent from an older helper's report = none.
        #[serde(default)]
        pub uplink_aliases: Vec<(String, Vec<std::net::IpAddr>)>,
        /// Leases the in-process DHCP responder (R005-T6) currently holds,
        /// sorted by address — the foreign devices on the bridge a hub
        /// terminates control for (R003-F6). Empty while not serving. Absent
        /// from an older helper's report = none.
        #[serde(default)]
        pub dhcp_leases: Vec<DhcpLease>,
    }

    /// One DHCP lease: a client hardware (Ethernet) address and the address
    /// it holds.
    #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DhcpLease {
        pub mac: [u8; 6],
        pub ipv4: std::net::Ipv4Addr,
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
                epoch: 1,
            },
            transport: Default::default(),
            mesh: Default::default(),
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
            helper::HelperRequest::AddAlias {
                iface: "bridge90".into(),
                addr: "fd1b:5a70:a52::1".parse().unwrap(),
                prefix: 64,
            },
            helper::HelperRequest::AddAlias {
                iface: "en5".into(),
                addr: "10.42.3.4".parse().unwrap(),
                prefix: 16,
            },
            helper::HelperRequest::RemoveAlias { iface: "en5".into(), addr: "10.42.3.4".parse().unwrap() },
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
                bridge_aliases: vec!["fd1b:5a70:a52::1".parse().unwrap()],
                uplink_aliases: vec![("en5".into(), vec!["10.42.3.4".parse().unwrap()])],
                dhcp_leases: vec![helper::DhcpLease { mac: [2, 0, 0, 0, 0, 9], ipv4: "10.69.0.10".parse().unwrap() }],
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<helper::HelperResponse>(&json).unwrap(), resp);
    }

    #[test]
    fn old_report_without_aliases_still_parses() {
        let old = r#"{"bridge":null,"scoped_ports":[],"dhcp_serving":false}"#;
        let r: helper::DataPlaneReport = serde_json::from_str(old).unwrap();
        assert!(r.bridge_aliases.is_empty());
        assert!(r.uplink_aliases.is_empty());
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
    fn member_reachability_is_additive_and_tolerates_newer_variants() {
        let via = Reachability::ViaHub { hub: "05".into() };
        let j = serde_json::to_string(&via).unwrap();
        assert_eq!(j, r#"{"via":"via_hub","hub":"05"}"#);
        assert_eq!(serde_json::from_str::<Reachability>(&j).unwrap(), via);
        // An older server omits the field entirely.
        let old = r#"{"node_id":"aa"}"#;
        assert_eq!(serde_json::from_str::<MeshMember>(old).unwrap().reachability, Reachability::Unknown);
        // A newer server's variant decodes, not fails.
        let newer = r#"{"via":"satellite"}"#;
        assert_eq!(serde_json::from_str::<Reachability>(newer).unwrap(), Reachability::Other);
        let b = Blockage {
            cause: BlockCause::ControlRelayRefused { node_id: "cc".into(), hub: "05".into() },
            remedy: Remedy::EnableControlRelay { node_id: "05".into() },
        };
        assert_eq!(b.severity(), Severity::Degraded);
        assert!(b.cause_text().contains("does not relay control"));
    }

    fn sample_status() -> MeshStatus {
        MeshStatus {
            version: MESH_STATUS_VERSION,
            self_node: Some(MeshIdentity { node_id: "0102030405060708".into(), endpoint_id: "abcd".into() }),
            members: vec![MeshMember {
                node_id: "0102030405060708".into(),
                is_self: true,
                role: NodeRole::Hub,
                ula: Some("fd00::1".into()),
                ipv4: Some("10.42.1.1".into()),
                addr_salt: 0,
                last_seen_age_secs: 0,
                liveness: Liveness::Alive,
                reachability: Reachability::Direct,
            }],
            rate: MeshRateView { hz: 96_000, epoch: 2, author: "01".into() },
            bootstrap: BootstrapStatus {
                beacon: BeaconStatus::Down {
                    iface: "bridge90".into(),
                    cause: BlockCause::BeaconWaitingForBridge { iface: "bridge90".into() },
                },
                beacons: vec![
                    BeaconStatus::Up { iface: "en5".into() },
                    BeaconStatus::Up { iface: "en6".into() },
                ],
                n0: N0Status::On,
            },
            endpoint: EndpointStatus::Bound { addrs: vec!["127.0.0.1:1".into()] },
            blockages: vec![Blockage {
                cause: BlockCause::BeaconBindFailed {
                    iface: "bridge90".into(),
                    family: IpFamily::V6,
                    error: "denied".into(),
                },
                remedy: Remedy::CheckInterface { iface: "bridge90".into() },
            }],
            foreign_leaves: vec![ForeignLeafView {
                leaf_id: "0a0b0c0d0e0f1011".into(),
                hub: "0102030405060708".into(),
                mac: "02:00:00:00:00:07".into(),
                ipv4: Some("10.69.0.10".into()),
                reachability: Reachability::ViaHub { hub: "0102030405060708".into() },
            }],
        }
    }

    #[test]
    fn mesh_status_round_trips_in_snapshot_hello_and_event() {
        let mut snap = snapshot();
        snap.mesh.status = Some(sample_status());
        for m in [
            ServerMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                server_version: "x".into(),
                snapshot: snap.clone(),
            },
            ServerMessage::Event { seq: 3, event: EventBody::Snapshot { snapshot: snap.clone() } },
        ] {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ServerMessage>(&json).unwrap(), m);
        }
        for c in [Command::ProposeMeshRate { hz: 96_000 }, Command::SetRole { role: NodeRole::Peer }] {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Command>(&json).unwrap(), c);
        }
    }

    #[test]
    fn mesh_status_version_handling() {
        // Old server: no status at all -> None.
        let old = r#"{"service":{"version":"0.0.1","pid":1,"started_unix":0},
            "helper":{"state":"not_registered"},
            "bridge":{"desired_up":false,"actual":null},
            "mesh":{"role":"hub","peers":[]}}"#;
        assert_eq!(serde_json::from_str::<Snapshot>(old).unwrap().mesh.status, None);

        // Status without a version parses as version 0 (supported).
        let v0: MeshStatus = serde_json::from_str("{}").unwrap();
        assert_eq!(v0.version, 0);
        assert!(v0.is_supported());

        // Newer server: higher version, an unknown field, unknown enum
        // variants and a cause this client has never seen all still parse.
        let newer = r#"{"version":99,"brand_new_field":{"x":1},
            "bootstrap":{"beacon":{"state":"hovering"},"n0":"quantum"},
            "endpoint":{"state":"teleported"},
            "members":[{"node_id":"aa","liveness":"vibing"}],
            "blockages":[{"cause":{"kind":"solar_flare","intensity":9},"remedy":{"action":"hide"}}]}"#;
        let s: MeshStatus = serde_json::from_str(newer).unwrap();
        assert!(!s.is_supported());
        assert_eq!(s.bootstrap.beacon, BeaconStatus::Unknown);
        assert_eq!(s.bootstrap.n0, N0Status::Unknown);
        assert_eq!(s.endpoint, EndpointStatus::Unknown);
        assert_eq!(s.members[0].liveness, Liveness::Unknown);
        assert_eq!(s.blockages[0].cause, BlockCause::Unknown);
        assert_eq!(s.blockages[0].remedy, Remedy::Unknown);
        assert_eq!(s.blockages[0].severity(), Severity::Info);
    }

    #[test]
    fn age_buckets_are_coarse_and_monotone() {
        assert_eq!(
            [0, 9, 10, 59, 60, 119, 120, 3_599].map(bucket_age_secs),
            [0, 0, 10, 50, 60, 60, 120, 3_540]
        );
    }

    #[test]
    fn every_blockage_renders_cause_and_remedy_text() {
        for b in sample_status().blockages {
            assert!(!b.cause_text().is_empty() && !b.remedy_text().is_empty());
        }
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
