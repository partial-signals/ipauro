//! Mesh health + membership status (R003-T5): turns what the mesh layers
//! observe into the versioned [`MeshStatus`] section of the snapshot, and
//! keeps it fresh through the store's change-only broadcast.
//!
//! [`build`] is a pure function of [`MeshInputs`], so every blockage variant
//! can be produced from its cause in a test. The publisher
//! ([`sync_once`]) writes with `mutate_if_changed`: a heartbeat that changes
//! nothing visible emits no event (last-seen ages are bucketed by
//! `bucket_age_secs`; the continuous value is never stored).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use ipauro_iroh::{
    BeaconHealth, BeaconState, BeaconTargets, InterfaceBeacon, MemberObservation, MemberState, MeshMembership,
};
use ipauro_mesh::addressing::AddrError;
use ipauro_mesh::control::{ForeignLeaf, Reachability as ControlReach};
use ipauro_mesh::topology::Edge;
use ipauro_mesh::transport::{LinkQuality, TransportKind};
use ipauro_proto::helper::{DhcpLease, BRIDGE_NAME};
use ipauro_mesh::ids::NodeId;
use ipauro_mesh::rate::MeshRate;
use ipauro_proto::state::{
    bucket_age_secs, BeaconStatus, Blockage, BlockCause, BootstrapStatus, EndpointStatus, IpFamily,
    ForeignLeafView, Liveness, MeshIdentity, MeshMember, Reachability, MeshPeer, MeshRateView, MeshStatus, N0Status, NodeRole,
    Remedy, MESH_STATUS_VERSION,
};
use tokio::sync::{broadcast, Notify};

use crate::addressing::MeshAddressing;
use crate::discovery::LinkInventory;
use crate::role::{from_mesh, to_mesh};
use crate::state_store::StateStore;

const SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// What `main` knows about the mesh bring-up that no running component can
/// report afterwards (a failed start leaves nothing to ask).
#[derive(Clone, Default)]
pub struct MeshEnv {
    /// iroh EndpointId (hex/base32 as iroh prints it), when the endpoint is up.
    pub endpoint_id: Option<String>,
    pub endpoint: EndpointStatus,
    /// Set when the endpoint is up but gossip failed to start.
    pub gossip_error: Option<String>,
    pub internet_discovery: bool,
    pub beacon: Option<Arc<InterfaceBeacon>>,
    /// The interfaces `beacon` announces on, rewritten each sync from role +
    /// attached links ([`beacon_targets`]) (R003-B10).
    pub beacon_targets: Option<BeaconTargets>,
    /// Who this node hears directly, per interface (R003-F6 edge source).
    /// `None` = the `beacon` itself, which is what `main` runs; tests
    /// substitute a fixed table.
    pub segment_peers: Option<Arc<dyn SegmentPeers>>,
}

/// Peers heard directly on an interface: a verified beacon received on X
/// from N is a direct link self -> N over X (R003-F6).
pub trait SegmentPeers: Send + Sync {
    fn heard(&self) -> Vec<(String, NodeId)>;
}

impl SegmentPeers for InterfaceBeacon {
    fn heard(&self) -> Vec<(String, NodeId)> {
        InterfaceBeacon::heard(self).into_iter().map(|(i, k)| (i, ipauro_iroh::mesh_node_id(&k))).collect()
    }
}

/// This node's incident edges from what it hears (link-state: only its own
/// links). The transport class comes from link identification, never the
/// interface name: the bridge's members and every identified uplink are
/// USB-NCM links (the only class `discovery` identifies today). A peer heard
/// on an interface identification does not know is skipped, not guessed.
/// Quality is unmeasured (zeros); control routing ignores cost.
pub fn local_edges(heard: &[(String, NodeId)], inventory: &LinkInventory) -> Vec<Edge> {
    let class = |iface: &str| -> Option<TransportKind> {
        let identified = inventory.links.iter().any(|l| l.name == iface && l.uplink_eligible());
        (iface == BRIDGE_NAME || identified).then_some(TransportKind::UsbBridge)
    };
    let quality = LinkQuality { rtt_us: 0, jitter_us: 0, bandwidth_bps: 0, loss: 0.0 };
    let mut v: Vec<Edge> = heard
        .iter()
        .filter_map(|(iface, n)| class(iface).map(|kind| Edge { to: *n, kind, quality }))
        .collect();
    v.sort_by_key(|e| e.to);
    v.dedup_by_key(|e| e.to);
    v
}

/// The foreign leaves a hub advertises: one per DHCP lease (R005-T6), keyed
/// downstream by hub NodeId + MAC. Only a Hub serves DHCP on its bridge.
pub fn foreign_leaves(role: NodeRole, leases: &[DhcpLease]) -> Vec<ForeignLeaf> {
    match role {
        NodeRole::Hub => leases.iter().map(|l| ForeignLeaf { mac: l.mac, ipv4: Some(l.ipv4) }).collect(),
        NodeRole::Peer => Vec::new(),
    }
}

fn mac_text(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Everything [`build`] reads.
pub struct MeshInputs<'a> {
    pub env_endpoint_id: Option<&'a str>,
    pub endpoint: &'a EndpointStatus,
    pub gossip_error: Option<&'a str>,
    pub internet_discovery: bool,
    /// Per-interface beacon health; `None` = no beacon running at all.
    pub beacon: Option<Vec<BeaconHealth>>,
    pub role: NodeRole,
    /// Remote members as membership sees them (live, expiring, expired).
    pub members: &'a [MemberObservation],
    pub rate: MeshRate,
    pub addressing: Option<&'a MeshAddressing>,
    /// Control reachability per remote member and foreign leaf (R003-F6);
    /// absent = unknown.
    pub reachability: &'a BTreeMap<NodeId, ControlReach>,
    /// Foreign leaves advertised in the mesh, with their hub (R003-F6).
    pub foreign: &'a [(NodeId, ForeignLeaf)],
}

fn reachability(r: ControlReach) -> Reachability {
    match r {
        ControlReach::Unknown => Reachability::Unknown,
        ControlReach::Direct => Reachability::Direct,
        ControlReach::ViaHub { hub } => Reachability::ViaHub { hub: hex(&hub) },
        ControlReach::HubWontRelay { hub } => Reachability::HubWontRelay { hub: hex(&hub) },
        ControlReach::Unreachable => Reachability::Unreachable,
    }
}

pub fn hex(n: &NodeId) -> String {
    n.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn liveness(s: MemberState) -> Liveness {
    match s {
        MemberState::Alive => Liveness::Alive,
        MemberState::Expiring => Liveness::Expiring,
        MemberState::Expired => Liveness::Expired,
    }
}

pub fn rate_view(r: &MeshRate) -> MeshRateView {
    MeshRateView { hz: r.hz, epoch: r.epoch, author: hex(&r.author) }
}

/// Build the status section. Blockage order is deterministic: endpoint,
/// gossip, beacon, addressing, then expired peers by NodeId.
pub fn build(i: &MeshInputs<'_>) -> MeshStatus {
    let mut blockages = Vec::new();
    let me = i.addressing.map(|a| a.node());

    match i.endpoint {
        EndpointStatus::Failed { error } => blockages.push(Blockage {
            cause: BlockCause::IrohBindFailed { error: error.clone() },
            remedy: Remedy::RestartService,
        }),
        // Not failed: bound, not started (M1-only), or a newer variant the
        // service itself never produces.
        EndpointStatus::Bound { .. } | EndpointStatus::NotStarted | EndpointStatus::Unknown => {}
    }
    if let Some(error) = i.gossip_error {
        blockages.push(Blockage {
            cause: BlockCause::GossipUnavailable { error: error.to_string() },
            remedy: Remedy::RestartService,
        });
    }

    let beacons: Vec<BeaconStatus> = match &i.beacon {
        None => Vec::new(),
        Some(hs) => hs.iter().map(|h| beacon_status(h, i.role, &mut blockages)).collect(),
    };
    // A Peer with no uplink attached has nothing to announce on yet.
    if matches!(&i.beacon, Some(hs) if hs.is_empty()) && i.role == NodeRole::Peer {
        blockages.push(Blockage { cause: BlockCause::BeaconWaitingForUplink, remedy: Remedy::ConnectUplink });
    }
    // Aggregate: Up if any interface is, else the first Down, else not running.
    let beacon = beacons
        .iter()
        .find(|b| matches!(b, BeaconStatus::Up { .. }))
        .or_else(|| beacons.first())
        .cloned()
        .unwrap_or(BeaconStatus::NotRunning);

    // Addressing: claims over the live (non-expired) member set.
    let live: BTreeSet<NodeId> =
        i.members.iter().filter(|m| m.state != MemberState::Expired).map(|m| m.node).collect();
    let claims = i.addressing.map(|a| a.claims(&live));
    if let (Some(a), Some(claims)) = (i.addressing, &claims) {
        match claims {
            Ok(map) => {
                if let Some(mine) = map.get(&a.node()).filter(|c| c.salt > 0) {
                    blockages.push(Blockage {
                        cause: BlockCause::AddressCollision {
                            ipv4: mine.ipv4.to_string(),
                            salt: mine.salt,
                        },
                        remedy: Remedy::WaitForResolution,
                    });
                }
            }
            Err(AddrError::Exhausted { members, capacity }) => blockages.push(Blockage {
                cause: BlockCause::Ipv4Exhausted { members: *members as u32, capacity: *capacity },
                remedy: Remedy::ReduceMembersOrWidenHashRange,
            }),
            // Config-time variants: MeshAddressing::new refuses them before a
            // plan exists, and assign_ipv4 only ever returns Exhausted.
            Err(
                AddrError::BadPrefixLen(_)
                | AddrError::EmptyRange
                | AddrError::RangeOutsideSubnet
                | AddrError::OverlappingRanges,
            ) => {}
        }
    }

    let member_addrs = |n: &NodeId| -> (Option<String>, Option<String>, u32) {
        let Some(a) = i.addressing else { return (None, None, 0) };
        let ula = Some(a.ula_of(n).to_string());
        match &claims {
            Some(Ok(map)) => match map.get(n) {
                Some(c) => (ula, Some(c.ipv4.to_string()), c.salt),
                None => (ula, None, 0), // expired: not in the live set
            },
            Some(Err(_)) | None => (ula, None, 0),
        }
    };

    let mut members = Vec::new();
    if let Some(me) = me {
        let (ula, ipv4, addr_salt) = member_addrs(&me);
        members.push(MeshMember {
            node_id: hex(&me),
            is_self: true,
            role: i.role,
            ula,
            ipv4,
            addr_salt,
            last_seen_age_secs: 0,
            liveness: Liveness::Alive,
            reachability: Reachability::Direct,
        });
    }
    for m in i.members {
        let (ula, ipv4, addr_salt) = member_addrs(&m.node);
        let age = bucket_age_secs(m.last_seen.as_secs());
        members.push(MeshMember {
            node_id: hex(&m.node),
            is_self: false,
            role: from_mesh(m.role),
            ula,
            ipv4,
            addr_salt,
            last_seen_age_secs: age,
            liveness: liveness(m.state),
            reachability: reachability(i.reachability.get(&m.node).copied().unwrap_or(ControlReach::Unknown)),
        });
        // An expired member is already blocked as such; a live one cut off by
        // a hub that will not relay control is the media-only-bridge failure.
        if m.state != MemberState::Expired
            && let Some(ControlReach::HubWontRelay { hub }) = i.reachability.get(&m.node)
        {
            blockages.push(Blockage {
                cause: BlockCause::ControlRelayRefused { node_id: hex(&m.node), hub: hex(hub) },
                remedy: Remedy::EnableControlRelay { node_id: hex(hub) },
            });
        }
        if m.state == MemberState::Expired {
            blockages.push(Blockage {
                cause: BlockCause::PeerExpired { node_id: hex(&m.node), age_secs: age },
                remedy: Remedy::CheckPeer { node_id: hex(&m.node) },
            });
        }
    }

    MeshStatus {
        version: MESH_STATUS_VERSION,
        self_node: match (me, i.env_endpoint_id) {
            (Some(n), Some(e)) => Some(MeshIdentity { node_id: hex(&n), endpoint_id: e.to_string() }),
            _ => None,
        },
        members,
        rate: rate_view(&i.rate),
        bootstrap: BootstrapStatus {
            beacon,
            beacons,
            n0: if i.internet_discovery { N0Status::On } else { N0Status::Off },
        },
        endpoint: i.endpoint.clone(),
        blockages,
        foreign_leaves: i
            .foreign
            .iter()
            .map(|(hub, l)| {
                let id = l.id(*hub);
                ForeignLeafView {
                    leaf_id: hex(&id),
                    hub: hex(hub),
                    mac: mac_text(&l.mac),
                    ipv4: l.ipv4.map(|a| a.to_string()),
                    reachability: reachability(i.reachability.get(&id).copied().unwrap_or(ControlReach::Unknown)),
                }
            })
            .collect(),
    }
}

fn beacon_status(h: &BeaconHealth, role: NodeRole, blockages: &mut Vec<Blockage>) -> BeaconStatus {
    let bind_failed = |family: IpFamily, error: &str| BlockCause::BeaconBindFailed {
        iface: h.iface.clone(),
        family,
        error: error.to_string(),
    };
    let remedy = Remedy::CheckInterface { iface: h.iface.clone() };
    match &h.state {
        BeaconState::InterfaceAbsent => {
            // A Hub waits for its bridge; a Peer for its uplink to reappear
            // (a Peer never creates a bridge, so "bring it up" would be wrong).
            let (cause, remedy) = match role {
                NodeRole::Hub => {
                    (BlockCause::BeaconWaitingForBridge { iface: h.iface.clone() }, Remedy::BringBridgeUp)
                }
                NodeRole::Peer => (BlockCause::BeaconWaitingForUplink, Remedy::ConnectUplink),
            };
            blockages.push(Blockage { cause: cause.clone(), remedy });
            BeaconStatus::Down { iface: h.iface.clone(), cause }
        }
        BeaconState::Announcing { v6_error, v4_error, .. } => {
            for (family, e) in [(IpFamily::V6, v6_error), (IpFamily::V4, v4_error)] {
                if let Some(e) = e {
                    blockages.push(Blockage { cause: bind_failed(family, e), remedy: remedy.clone() });
                }
            }
            BeaconStatus::Up { iface: h.iface.clone() }
        }
        BeaconState::BindFailed { v6_error, v4_error, .. } => {
            blockages.push(Blockage { cause: bind_failed(IpFamily::V6, v6_error), remedy: remedy.clone() });
            blockages.push(Blockage { cause: bind_failed(IpFamily::V4, v4_error), remedy });
            BeaconStatus::Down { iface: h.iface.clone(), cause: bind_failed(IpFamily::V6, v6_error) }
        }
    }
}

/// Publish `status`; one snapshot event iff it differs from what is stored.
/// Returns whether an event was emitted.
pub async fn publish(store: &StateStore, status: MeshStatus) -> bool {
    store.mutate_if_changed(|s| s.mesh.status = Some(status)).await.is_some()
}

/// The interfaces the LAN beacon announces on (R003-B10): a Hub on its
/// bridge, a Peer — which creates none — on each uplink the link inventory
/// identified. Same uplink set the reconciler self-addresses.
pub fn beacon_targets(role: NodeRole, links: &crate::discovery::LinkInventory) -> Vec<String> {
    match role {
        NodeRole::Hub => vec![ipauro_proto::helper::BRIDGE_NAME.to_string()],
        NodeRole::Peer => links.uplinks(),
    }
}

/// One pull from the mesh layers into the store: advertise our role, publish
/// the live member set to the addressing seam, refresh the legacy
/// `mesh.peers` role list and the versioned status. Returns whether the
/// member set changed (IPv4 resolution may have moved — kick a reconcile).
pub async fn sync_once(
    store: &StateStore,
    env: &MeshEnv,
    membership: Option<&MeshMembership>,
) -> bool {
    let role = store.snapshot().await.mesh.role;
    let members: Vec<MemberObservation> = match membership {
        Some(m) => {
            m.set_local_role(to_mesh(role));
            // A hub is a transparent control relay, never a media-only
            // bridge (R003-F6): the role decides, there is no separate knob.
            m.set_relays_control(role == NodeRole::Hub);
            let heard = match (&env.segment_peers, &env.beacon) {
                (Some(s), _) => s.heard(),
                (None, Some(b)) => SegmentPeers::heard(b.as_ref()),
                (None, None) => Vec::new(),
            };
            m.set_local_edges(local_edges(&heard, &store.link_inventory()));
            m.set_foreign_leaves(foreign_leaves(role, &store.dhcp_leases()));
            m.members()
        }
        None => Vec::new(),
    };
    let foreign = membership.map(|m| m.foreign_leaves()).unwrap_or_default();
    let reach: BTreeMap<NodeId, ControlReach> = match membership {
        Some(m) => members
            .iter()
            .map(|o| o.node)
            .chain(foreign.iter().map(|(h, l)| l.id(*h)))
            .map(|n| (n, m.control_reachability(n)))
            .collect(),
        None => BTreeMap::new(),
    };
    let live: BTreeSet<NodeId> =
        members.iter().filter(|m| m.state != MemberState::Expired).map(|m| m.node).collect();
    let members_changed = store.set_mesh_members(live);
    let peers: Vec<MeshPeer> = members
        .iter()
        .filter(|m| m.state != MemberState::Expired)
        .map(|m| MeshPeer { node_id: hex(&m.node), role: from_mesh(m.role) })
        .collect();

    let addressing = store.mesh_addressing();
    let rate = match (membership, &addressing) {
        (Some(m), _) => m.mesh_rate(),
        (None, Some(a)) => MeshRate::new(a.node()),
        (None, None) => MeshRate::new(NodeId([0; 8])),
    };
    if let Some(targets) = &env.beacon_targets {
        targets.set(beacon_targets(role, &store.link_inventory()));
    }
    let status = build(&MeshInputs {
        env_endpoint_id: env.endpoint_id.as_deref(),
        endpoint: &env.endpoint,
        gossip_error: env.gossip_error.as_deref(),
        internet_discovery: env.internet_discovery,
        beacon: env.beacon.as_ref().map(|b| b.health()),
        role,
        members: &members,
        rate,
        addressing: addressing.as_ref(),
        reachability: &reach,
        foreign: &foreign,
    });
    store
        .mutate_if_changed(|s| {
            s.mesh.peers = peers;
            s.mesh.status = Some(status);
        })
        .await;
    members_changed
}

/// Background loop for [`sync_once`].
pub async fn run_sync(
    store: Arc<StateStore>,
    env: MeshEnv,
    membership: Option<Arc<MeshMembership>>,
    reconcile_kick: Arc<Notify>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut tick = tokio::time::interval(SYNC_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tick.tick() => {
                if sync_once(&store, &env, membership.as_deref()).await {
                    reconcile_kick.notify_one();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands;
    use crate::discovery::{MockUsbNcmSource, UsbNcmSource};
    use crate::helper_channel::MockHelper;
    use crate::registrar::StubHelperRegistrar;
    use crate::state_store::MeshControl;
    use ipauro_mesh::addressing::UlaPrefix;
    use ipauro_mesh::rate::RateError;
    use ipauro_mesh::topology::NodeRole as MeshRole;
    use ipauro_proto::ipc::{Command, ErrorCode, EventBody, ReplyOutcome};
    use std::sync::Mutex;

    fn n(b: u8) -> NodeId {
        NodeId([b, 1, 2, 3, 4, 5, 6, 7])
    }

    fn addressing() -> MeshAddressing {
        MeshAddressing::appliance(n(1), UlaPrefix::DEFAULT).unwrap()
    }

    fn obs(b: u8, secs: u64, state: MemberState) -> MemberObservation {
        MemberObservation {
            node: n(b),
            role: MeshRole::Hub,
            last_seen: Duration::from_secs(secs),
            state,
        }
    }

    const BOUND: EndpointStatus = EndpointStatus::NotStarted;

    fn inputs<'a>(
        endpoint: &'a EndpointStatus,
        members: &'a [MemberObservation],
        addressing: Option<&'a MeshAddressing>,
    ) -> MeshInputs<'a> {
        MeshInputs {
            env_endpoint_id: Some("endpoint-abc"),
            endpoint,
            gossip_error: None,
            internet_discovery: false,
            beacon: None,
            role: NodeRole::Hub,
            members,
            rate: MeshRate::new(n(1)),
            addressing,
            reachability: &NO_REACH,
            foreign: &[],
        }
    }

    static NO_REACH: BTreeMap<NodeId, ControlReach> = BTreeMap::new();

    #[test]
    fn member_reachability_is_reported_and_a_non_relaying_hub_is_a_blockage() {
        let a = addressing();
        let members = [obs(2, 0, MemberState::Alive), obs(3, 0, MemberState::Alive), obs(4, 0, MemberState::Expired)];
        let reach = BTreeMap::from([
            (n(2), ControlReach::Direct),
            (n(3), ControlReach::HubWontRelay { hub: n(2) }),
            (n(4), ControlReach::HubWontRelay { hub: n(2) }),
        ]);
        let s = build(&MeshInputs { reachability: &reach, ..inputs(&BOUND, &members, Some(&a)) });
        let by_id = |b: u8| s.members.iter().find(|m| m.node_id == hex(&n(b))).unwrap().reachability.clone();
        assert_eq!(s.members[0].reachability, Reachability::Direct, "self");
        assert_eq!(by_id(2), Reachability::Direct);
        assert_eq!(by_id(3), Reachability::HubWontRelay { hub: hex(&n(2)) });
        let relay: Vec<_> =
            s.blockages.iter().filter(|b| matches!(b.cause, BlockCause::ControlRelayRefused { .. })).collect();
        assert_eq!(relay.len(), 1, "expired members are not double-reported");
        assert_eq!(relay[0].cause, BlockCause::ControlRelayRefused { node_id: hex(&n(3)), hub: hex(&n(2)) });
        assert_eq!(relay[0].remedy, Remedy::EnableControlRelay { node_id: hex(&n(2)) });

        let via = BTreeMap::from([(n(3), ControlReach::ViaHub { hub: n(2) })]);
        let s = build(&MeshInputs { reachability: &via, ..inputs(&BOUND, &members, Some(&a)) });
        assert_eq!(by_id_of(&s, 3), Reachability::ViaHub { hub: hex(&n(2)) });
        assert_eq!(by_id_of(&s, 2), Reachability::Unknown, "no entry = unknown");
    }

    fn by_id_of(s: &MeshStatus, b: u8) -> Reachability {
        s.members.iter().find(|m| m.node_id == hex(&n(b))).unwrap().reachability.clone()
    }

    fn causes(s: &MeshStatus) -> Vec<&BlockCause> {
        s.blockages.iter().map(|b| &b.cause).collect()
    }

    #[test]
    fn healthy_mesh_has_self_first_addresses_and_no_blockages() {
        let a = addressing();
        let members = [obs(2, 0, MemberState::Alive), obs(3, 6, MemberState::Expiring)];
        let s = build(&inputs(&BOUND, &members, Some(&a)));
        assert_eq!(s.version, MESH_STATUS_VERSION);
        assert_eq!(s.members.len(), 3);
        assert!(s.members[0].is_self && s.members[0].ipv4.is_some() && s.members[0].ula.is_some());
        assert_eq!(s.members[2].liveness, Liveness::Expiring);
        assert_eq!(s.members[2].last_seen_age_secs, 0, "6s buckets to 0");
        assert_eq!(s.self_node.as_ref().unwrap().endpoint_id, "endpoint-abc");
        assert_eq!(s.rate, MeshRateView { hz: 48_000, epoch: 0, author: hex(&n(1)) });
        assert_eq!(s.bootstrap.n0, N0Status::Off);
        assert!(s.blockages.is_empty(), "{:?}", s.blockages);
    }

    #[test]
    fn iroh_bind_failure_is_a_typed_blockage_with_the_error() {
        let ep = EndpointStatus::Failed { error: "Address already in use".into() };
        let s = build(&inputs(&ep, &[], None));
        assert_eq!(
            s.blockages,
            vec![Blockage {
                cause: BlockCause::IrohBindFailed { error: "Address already in use".into() },
                remedy: Remedy::RestartService,
            }]
        );
        assert!(s.self_node.is_none() && s.members.is_empty());
        assert_eq!(s.endpoint, ep);
    }

    #[test]
    fn gossip_failure_is_a_blockage() {
        let mut i = inputs(&BOUND, &[], None);
        i.gossip_error = Some("subscribe: nope");
        assert_eq!(
            causes(&build(&i)),
            vec![&BlockCause::GossipUnavailable { error: "subscribe: nope".into() }]
        );
    }

    #[test]
    fn beacon_waiting_names_the_remedy_by_role() {
        let health = BeaconHealth { iface: "bridge90".into(), state: BeaconState::InterfaceAbsent };
        let mut i = inputs(&BOUND, &[], None);
        i.beacon = Some(vec![health.clone()]);
        let hub = build(&i);
        assert_eq!(hub.blockages[0].remedy, Remedy::BringBridgeUp);
        assert!(matches!(hub.bootstrap.beacon, BeaconStatus::Down { .. }));
        // A Peer waits on an UPLINK, never on a bridge it cannot create.
        i.role = NodeRole::Peer;
        let peer = build(&i);
        assert_eq!(peer.blockages[0].cause, BlockCause::BeaconWaitingForUplink);
        assert_eq!(peer.blockages[0].remedy, Remedy::ConnectUplink);
    }

    #[test]
    fn beacon_bind_failures_carry_family_and_error() {
        let mut i = inputs(&BOUND, &[], None);
        i.beacon = Some(vec![BeaconHealth {
            iface: "bridge90".into(),
            state: BeaconState::BindFailed { index: 9, v6_error: "e6".into(), v4_error: "e4".into() },
        }]);
        let s = build(&i);
        assert_eq!(s.blockages.len(), 2);
        assert!(matches!(&s.bootstrap.beacon, BeaconStatus::Down { cause: BlockCause::BeaconBindFailed { family: IpFamily::V6, .. }, .. }));

        // One family up: still Up, but the failed one is named.
        i.beacon = Some(vec![BeaconHealth {
            iface: "bridge90".into(),
            state: BeaconState::Announcing { index: 9, v6_error: None, v4_error: Some("e4".into()) },
        }]);
        let s = build(&i);
        assert_eq!(s.bootstrap.beacon, BeaconStatus::Up { iface: "bridge90".into() });
        assert_eq!(
            causes(&s),
            vec![&BlockCause::BeaconBindFailed {
                iface: "bridge90".into(),
                family: IpFamily::V4,
                error: "e4".into()
            }]
        );

        // Healthy beacon: Up, nothing blocked.
        i.beacon = Some(vec![BeaconHealth {
            iface: "bridge90".into(),
            state: BeaconState::Announcing { index: 9, v6_error: None, v4_error: None },
        }]);
        assert!(build(&i).blockages.is_empty());
    }

    fn announcing(iface: &str) -> BeaconHealth {
        BeaconHealth {
            iface: iface.into(),
            state: BeaconState::Announcing { index: 9, v6_error: None, v4_error: None },
        }
    }

    #[test]
    fn a_peer_reports_beacon_health_per_uplink() {
        let mut i = inputs(&BOUND, &[], None);
        i.role = NodeRole::Peer;
        i.beacon = Some(vec![
            BeaconHealth { iface: "en5".into(), state: BeaconState::InterfaceAbsent },
            announcing("en6"),
        ]);
        let s = build(&i);
        assert_eq!(
            s.bootstrap.beacons,
            vec![
                BeaconStatus::Down { iface: "en5".into(), cause: BlockCause::BeaconWaitingForUplink },
                BeaconStatus::Up { iface: "en6".into() },
            ]
        );
        assert_eq!(s.bootstrap.beacon, BeaconStatus::Up { iface: "en6".into() }, "aggregate: any Up is Up");
        // en5's absence is still named, with the Peer remedy.
        assert_eq!(s.blockages.len(), 1);
        assert_eq!(s.blockages[0].remedy, Remedy::ConnectUplink);
    }

    #[test]
    fn a_peer_with_no_uplink_says_so_and_a_hub_never_does() {
        let mut i = inputs(&BOUND, &[], None);
        i.beacon = Some(Vec::new());
        i.role = NodeRole::Peer;
        let s = build(&i);
        assert_eq!(s.bootstrap.beacon, BeaconStatus::NotRunning);
        assert!(s.bootstrap.beacons.is_empty());
        assert_eq!(causes(&s), vec![&BlockCause::BeaconWaitingForUplink]);
        i.role = NodeRole::Hub;
        assert!(build(&i).blockages.is_empty());
        // No beacon at all (iroh failed): nothing to report.
        i.beacon = None;
        assert!(build(&i).bootstrap.beacons.is_empty());
    }

    #[test]
    fn beacon_targets_follow_role_a_hub_its_bridge_a_peer_its_uplinks() {
        use crate::discovery::{classify, IfaceObservation};
        let o = |n: &str| IfaceObservation { name: n.into(), active: true, configured: true, input_packets: 1 };
        let inv = classify(
            &["en9".to_string()],
            &["en5".to_string(), "en1".to_string()],
            &[o("en9"), o("en5"), IfaceObservation { active: false, configured: false, ..o("en1") }],
            &[],
        );
        assert_eq!(beacon_targets(NodeRole::Hub, &inv), vec!["bridge90".to_string()]);
        assert_eq!(beacon_targets(NodeRole::Peer, &inv), vec!["en5".to_string(), "en9".to_string()]);
        assert!(beacon_targets(NodeRole::Peer, &Default::default()).is_empty());
    }

    #[test]
    fn exhausted_hash_range_is_a_blockage() {
        let a = addressing();
        let cap = ipauro_mesh::addressing::Ipv4Config::appliance_default().capacity();
        let many: Vec<MemberObservation> =
            (0..=cap).map(|i| MemberObservation {
                node: NodeId((i as u64 + 100).to_be_bytes()),
                role: MeshRole::Hub,
                last_seen: Duration::ZERO,
                state: MemberState::Alive,
            }).collect();
        let s = build(&inputs(&BOUND, &many, Some(&a)));
        assert!(
            s.blockages.iter().any(|b| matches!(
                b.cause,
                BlockCause::Ipv4Exhausted { capacity, .. } if capacity == cap
            ) && b.remedy == Remedy::ReduceMembersOrWidenHashRange),
            "{:?}",
            s.blockages.first()
        );
        // The ULA is still reported; the IPv4 is not.
        assert!(s.members[0].ula.is_some() && s.members[0].ipv4.is_none());
    }

    #[test]
    fn a_colliding_first_choice_is_reported_with_its_re_resolved_address() {
        // A peer that sorts BEFORE this node (assignment walks ids in order)
        // and hashes to the same first-choice slot makes this node lose it.
        let a = addressing();
        let mut found = None;
        for k in 0u32..4_000_000 {
            let k = k.to_be_bytes();
            let set: BTreeSet<NodeId> = [NodeId([0, k[0], k[1], k[2], k[3], 9, 9, 9])].into();
            if a.claims(&set).unwrap()[&a.node()].salt > 0 {
                found = Some(set);
                break;
            }
        }
        let set = found.expect("a colliding peer exists within 4M candidates");
        let members: Vec<_> = set
            .iter()
            .map(|id| MemberObservation { node: *id, role: MeshRole::Hub, last_seen: Duration::ZERO, state: MemberState::Alive })
            .collect();
        let s = build(&inputs(&BOUND, &members, Some(&a)));
        assert!(
            matches!(&s.blockages[0], Blockage { cause: BlockCause::AddressCollision { salt, .. }, remedy: Remedy::WaitForResolution } if *salt > 0),
            "{:?}",
            s.blockages
        );
    }

    #[test]
    fn expired_peer_is_visible_and_blocked_with_a_remedy_but_not_addressed() {
        let a = addressing();
        let members = [obs(2, 125, MemberState::Expired)];
        let s = build(&inputs(&BOUND, &members, Some(&a)));
        let m = &s.members[1];
        assert_eq!((m.liveness, m.last_seen_age_secs, m.ipv4.clone()), (Liveness::Expired, 120, None));
        assert_eq!(
            s.blockages,
            vec![Blockage {
                cause: BlockCause::PeerExpired { node_id: hex(&n(2)), age_secs: 120 },
                remedy: Remedy::CheckPeer { node_id: hex(&n(2)) },
            }]
        );
    }

    fn store_with_addressing() -> StateStore {
        let store = StateStore::new(crate::initial_snapshot());
        store.set_mesh_addressing(addressing());
        store
    }

    #[tokio::test]
    async fn membership_change_is_one_event_and_a_bare_heartbeat_is_none() {
        let store = store_with_addressing();
        let mut rx = store.subscribe();
        let env = MeshEnv::default();
        sync_once(&store, &env, None).await; // initial publish
        let _ = rx.try_recv();
        while rx.try_recv().is_ok() {}

        let publish = |members: Vec<MemberObservation>| {
            let a = addressing();
            let status = build(&inputs(&BOUND, &members, Some(&a)));
            let store = &store;
            async move { publish(store, status).await }
        };

        // First sighting of a peer: exactly one event.
        assert!(publish(vec![obs(2, 0, MemberState::Alive)]).await);
        assert!(matches!(rx.try_recv().unwrap().body, EventBody::Snapshot { .. }));
        assert!(rx.try_recv().is_err());

        // Heartbeats: ages wobble inside a bucket, state unchanged -> silence.
        for secs in [0, 1, 2, 3, 4, 5] {
            assert!(!publish(vec![obs(2, secs, MemberState::Alive)]).await, "age {secs}s");
        }
        assert!(rx.try_recv().is_err(), "no event for heartbeats");

        // Liveness transition: one event; expiry: one more.
        assert!(publish(vec![obs(2, 6, MemberState::Expiring)]).await);
        assert!(publish(vec![obs(2, 11, MemberState::Expired)]).await);
        assert!(rx.try_recv().is_ok() && rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());

        // Second peer joins: one event.
        assert!(publish(vec![obs(2, 12, MemberState::Expired), obs(3, 0, MemberState::Alive)]).await);
        assert!(rx.try_recv().is_ok() && rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn sync_once_without_a_mesh_publishes_status_once_then_nothing() {
        let store = store_with_addressing();
        let env = MeshEnv {
            endpoint: EndpointStatus::Failed { error: "boom".into() },
            ..Default::default()
        };
        sync_once(&store, &env, None).await;
        let snap = store.snapshot().await;
        let st = snap.mesh.status.expect("status published without a membership");
        assert!(matches!(st.blockages[0].cause, BlockCause::IrohBindFailed { .. }));
        let mut rx = store.subscribe();
        sync_once(&store, &env, None).await;
        assert!(rx.try_recv().is_err(), "unchanged status emits nothing");
    }

    struct FakeMesh(Mutex<MeshRate>);
    impl MeshControl for FakeMesh {
        fn propose_rate(&self, hz: u32) -> Result<MeshRate, RateError> {
            let mut r = self.0.lock().unwrap();
            *r = r.propose(hz, n(1))?;
            Ok(*r)
        }
    }

    async fn run(store: &StateStore, command: Command) -> ReplyOutcome {
        let helper = MockHelper::default();
        let usb: std::sync::Arc<dyn UsbNcmSource> = std::sync::Arc::new(MockUsbNcmSource::new([vec![]]));
        commands::handle(store, &helper, &usb, &StubHelperRegistrar, &Notify::new(), command).await
    }

    #[tokio::test]
    async fn propose_rate_validates_bumps_the_epoch_and_publishes_it() {
        let store = store_with_addressing();
        sync_once(&store, &MeshEnv::default(), None).await;

        // No mesh running: refused with a named code.
        match run(&store, Command::ProposeMeshRate { hz: 96_000 }).await {
            ReplyOutcome::Err { error } => assert_eq!(error.code, ErrorCode::MeshUnavailable),
            other => panic!("{other:?}"),
        }

        store.set_mesh_control(std::sync::Arc::new(FakeMesh(Mutex::new(MeshRate::new(n(1))))));
        for bad in [50_000, 48_000, 0] {
            match run(&store, Command::ProposeMeshRate { hz: bad }).await {
                ReplyOutcome::Err { error } => assert_eq!(error.code, ErrorCode::InvalidCommand, "{bad}"),
                other => panic!("{other:?}"),
            }
        }
        let mut rx = store.subscribe();
        match run(&store, Command::ProposeMeshRate { hz: 96_000 }).await {
            ReplyOutcome::Ok { snapshot } => {
                let r = snapshot.mesh.status.unwrap().rate;
                assert_eq!((r.hz, r.epoch), (96_000, 1));
            }
            other => panic!("{other:?}"),
        }
        assert!(rx.try_recv().is_ok(), "the raise is one event");
        match run(&store, Command::ProposeMeshRate { hz: 192_000 }).await {
            ReplyOutcome::Ok { snapshot } => assert_eq!(snapshot.mesh.status.unwrap().rate.epoch, 2),
            other => panic!("{other:?}"),
        }
    }

    struct FixedPeers(Mutex<Vec<(String, NodeId)>>);
    impl SegmentPeers for FixedPeers {
        fn heard(&self) -> Vec<(String, NodeId)> {
            self.0.lock().unwrap().clone()
        }
    }

    fn uplink_inventory(name: &str) -> LinkInventory {
        use crate::discovery::{LinkRole, UsbLink};
        LinkInventory { links: vec![UsbLink { name: name.into(), role: LinkRole::Device, evidence: vec![] }] }
    }

    #[test]
    fn edges_come_from_identified_links_only_and_leaves_only_on_a_hub() {
        use crate::discovery::{LinkRole, UsbLink};
        let inv = LinkInventory {
            links: vec![
                UsbLink { name: "en7".into(), role: LinkRole::Device, evidence: vec![] },
                UsbLink { name: "en9".into(), role: LinkRole::Internal, evidence: vec![] },
            ],
        };
        let heard = vec![
            (BRIDGE_NAME.to_string(), n(2)),
            ("en7".to_string(), n(3)),
            ("en9".to_string(), n(4)), // a rejected internal decoy
            ("en42".to_string(), n(5)), // not identified at all
            ("en7".to_string(), n(2)),  // same neighbour twice: one edge
        ];
        let e = local_edges(&heard, &inv);
        assert_eq!(e.iter().map(|e| e.to).collect::<Vec<_>>(), vec![n(2), n(3)]);
        assert!(e.iter().all(|e| e.kind == TransportKind::UsbBridge));

        let lease = DhcpLease { mac: [2, 0, 0, 0, 0, 7], ipv4: "10.69.0.10".parse().unwrap() };
        assert_eq!(foreign_leaves(NodeRole::Hub, &[lease]), vec![ForeignLeaf { mac: lease.mac, ipv4: Some(lease.ipv4) }]);
        assert!(foreign_leaves(NodeRole::Peer, &[lease]).is_empty());
    }

    /// R003-F6 end to end: three real memberships on 127.0.0.1 driven only
    /// by `sync_once`. A and C each hear hub H on a USB uplink; H hears both
    /// on its bridge and holds a DHCP lease for a foreign device. A's
    /// published status must show H Direct, C and the leaf ViaHub{H} — not
    /// Unknown.
    #[tokio::test(flavor = "multi_thread")]
    async fn beacon_heard_peers_and_dhcp_leases_drive_reachability_in_status() {
        use ipauro_iroh::{GossipConfig, IrohConfig, IrohNode, StaticBootstrap};
        let dir = std::env::temp_dir().join(format!("ipauro-f6-{}-{:?}", std::process::id(), std::time::SystemTime::now()));
        let start = |name: &'static str| {
            let mut c = IrohConfig::new(dir.join(name));
            c.bind_addrs = vec!["127.0.0.1:0".parse().unwrap()];
            IrohNode::start(c)
        };
        let (a, h, c) = (start("a").await.unwrap(), start("h").await.unwrap(), start("c").await.unwrap());
        let (ia, ih, ic) = (a.node_id(), h.node_id(), c.node_id());
        let gcfg = GossipConfig { mesh_id: "f6-core".into(), heartbeat: Duration::from_millis(100), expire_after_missed: 20 };
        let to_h = Arc::new(StaticBootstrap(vec![h.local_addr()]));
        let mh = MeshMembership::spawn(&h, Arc::new(StaticBootstrap::default()), gcfg.clone()).await.unwrap();
        let ma = MeshMembership::spawn(&a, to_h.clone(), gcfg.clone()).await.unwrap();
        let mc = MeshMembership::spawn(&c, to_h, gcfg).await.unwrap();

        let seat = |role: NodeRole, heard: Vec<(String, NodeId)>, inv: LinkInventory| {
            let store = StateStore::new(crate::initial_snapshot());
            store.set_identification(inv, vec![]);
            let env = MeshEnv { segment_peers: Some(Arc::new(FixedPeers(Mutex::new(heard)))), ..Default::default() };
            (store, env, role)
        };
        let (sa, ea, _) = seat(NodeRole::Peer, vec![("en7".into(), ih)], uplink_inventory("en7"));
        let (sc, ec, _) = seat(NodeRole::Peer, vec![("en8".into(), ih)], uplink_inventory("en8"));
        let (sh, eh, _) = seat(NodeRole::Hub, vec![(BRIDGE_NAME.into(), ia), (BRIDGE_NAME.into(), ic)], LinkInventory::default());
        for s in [&sa, &sc] {
            s.mutate(|s| s.mesh.role = NodeRole::Peer).await;
        }
        let lease = DhcpLease { mac: [2, 0, 0, 0, 0, 7], ipv4: "10.69.0.10".parse().unwrap() };
        sh.set_dhcp_leases(vec![lease]);
        let leaf = hex(&ForeignLeaf { mac: lease.mac, ipv4: None }.id(ih));

        let end = std::time::Instant::now() + Duration::from_secs(20);
        let st = loop {
            sync_once(&sh, &eh, Some(&mh)).await;
            sync_once(&sc, &ec, Some(&mc)).await;
            sync_once(&sa, &ea, Some(&ma)).await;
            let st = sa.snapshot().await.mesh.status.unwrap();
            let r = |id: &str| st.members.iter().find(|m| m.node_id == id).map(|m| m.reachability.clone());
            let lr = st.foreign_leaves.iter().find(|l| l.leaf_id == leaf).map(|l| l.reachability.clone());
            let via = Some(Reachability::ViaHub { hub: hex(&ih) });
            if r(&hex(&ih)) == Some(Reachability::Direct) && r(&hex(&ic)) == via && lr == via {
                break st;
            }
            assert!(std::time::Instant::now() < end, "reachability never converged: {st:#?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let l = st.foreign_leaves.iter().find(|l| l.leaf_id == leaf).unwrap();
        assert_eq!((l.hub.as_str(), l.mac.as_str(), l.ipv4.as_deref()), (hex(&ih).as_str(), "02:00:00:00:00:07", Some("10.69.0.10")));
        assert!(st.members.iter().all(|m| m.reachability != Reachability::Unknown), "{st:#?}");

        for m in [ma, mc, mh] {
            m.shutdown().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proto_and_mesh_agree_on_the_allowed_rates() {
        assert_eq!(ipauro_proto::state::ALLOWED_MESH_RATES_HZ, ipauro_mesh::rate::ALLOWED_RATES_HZ);
    }
}
