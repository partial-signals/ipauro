//! Mesh membership over an iroh-gossip topic (R003-F2).
//!
//! **Authentication.** iroh-gossip's `Message::delivered_from` is the previous
//! *hop*, not the author, and gossip messages are unsigned — on a multi-hop
//! tree the delivering key says nothing about who wrote the record. So each
//! record travels in a signed envelope:
//! `[ENVELOPE_VERSION][author ed25519 pubkey 32][signature 64][record bytes]`.
//! A receiver verifies the signature and requires
//! `record.author == mesh_node_id(pubkey)` — the property the key-derived
//! NodeId exists to give. Anything else is dropped and counted.
//!
//! **Seq across restarts.** Topology keeps "newest seq per author", so a
//! restarted node whose counter reset would be silent. Heartbeat seqs are
//! therefore seeded from wall-clock milliseconds (monotone across restarts).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_lite::StreamExt;
use ipauro_mesh::capability::ProtocolCaps;
use ipauro_mesh::gossip::{Gossip, Record};
use ipauro_mesh::ids::NodeId;
use ipauro_mesh::control::{self, ControlPlan, ForeignLeaf, Reachability};
use ipauro_mesh::topology::{Edge, NodeRole, PeerFacts, Topology};
use ipauro_mesh::policy::Policy;
use ipauro_mesh::rate::{MeshRate, RateError};
use ipauro_mesh::MeshNode;
use iroh::protocol::Router;
use iroh::{EndpointAddr, PublicKey, SecretKey};
use iroh_gossip::api::{Event, GossipSender};
use iroh_gossip::{ALPN, Gossip as IrohGossipProto, TopicId};
use tokio::sync::{mpsc, watch};

use crate::codec::{decode_record, encode_record};
use crate::control::{CONTROL_ALPN, ControlPlane, ControlView, IpPassthrough};
use crate::key::mesh_node_id;
use crate::node::IrohNode;

const ENVELOPE_VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"ipauro-gossip-record-v1";
const HEADER: usize = 1 + 32 + 64;

/// Why an inbound message was dropped.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Reject {
    #[error("unsupported envelope version {0}")]
    Version(u8),
    #[error("envelope too short")]
    Short,
    #[error("invalid author public key")]
    BadKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("record author does not match the signing key's NodeId")]
    SpoofedAuthor,
    #[error("undecodable record: {0}")]
    Decode(#[from] crate::codec::DecodeError),
}

/// Deterministic topic for a mesh/session identifier.
pub fn topic_for_mesh(mesh_id: &str) -> TopicId {
    let mut h = blake3::Hasher::new();
    h.update(b"ipauro-gossip-topic-v1");
    h.update(mesh_id.as_bytes());
    TopicId::from_bytes(*h.finalize().as_bytes())
}

/// Sign and frame `record` as `secret`'s message. The caller is trusted to set
/// `record.author` honestly; receivers check it ([`open_record`]).
pub fn seal_record(secret: &SecretKey, record: &Record) -> Vec<u8> {
    let body = encode_record(record);
    let mut signed = SIG_DOMAIN.to_vec();
    signed.extend_from_slice(&body);
    let sig = secret.sign(&signed);
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(secret.public().as_bytes());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&body);
    out
}

/// Verify and decode an envelope. Returns the record only if its signature is
/// valid and its `author` is the NodeId derived from the signing key.
pub fn open_record(bytes: &[u8]) -> Result<Record, Reject> {
    open_record_keyed(bytes).map(|(r, _)| r)
}

/// [`open_record`], also returning the verified signing key (the author's
/// iroh identity — what control forwarding dials).
fn open_record_keyed(bytes: &[u8]) -> Result<(Record, PublicKey), Reject> {
    if bytes.len() < HEADER {
        return Err(Reject::Short);
    }
    if bytes[0] != ENVELOPE_VERSION {
        return Err(Reject::Version(bytes[0]));
    }
    let pk_bytes: [u8; 32] = bytes[1..33].try_into().expect("slice is 32 bytes");
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| Reject::BadKey)?;
    let sig = iroh::Signature::try_from(&bytes[33..HEADER]).map_err(|_| Reject::BadSignature)?;
    let body = &bytes[HEADER..];
    let mut signed = SIG_DOMAIN.to_vec();
    signed.extend_from_slice(body);
    pk.verify(&signed, &sig).map_err(|_| Reject::BadSignature)?;
    let record = decode_record(body)?;
    if record.author != mesh_node_id(&pk) {
        return Err(Reject::SpoofedAuthor);
    }
    Ok((record, pk))
}

/// Where to find peers to dial. R003-F9's LAN beacon supplies another impl.
pub trait BootstrapSource: Send + Sync {
    fn peers(&self) -> Vec<EndpointAddr>;
}

/// Fixed peer list from configuration.
#[derive(Clone, Debug, Default)]
pub struct StaticBootstrap(pub Vec<EndpointAddr>);

impl BootstrapSource for StaticBootstrap {
    fn peers(&self) -> Vec<EndpointAddr> {
        self.0.clone()
    }
}

#[derive(Clone, Debug)]
pub struct GossipConfig {
    /// Mesh/session identifier; every node with the same id joins the same topic.
    pub mesh_id: String,
    pub heartbeat: Duration,
    /// A peer silent for this many heartbeat intervals is expired.
    pub expire_after_missed: u32,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self { mesh_id: "ipauro".into(), heartbeat: Duration::from_secs(2), expire_after_missed: 5 }
    }
}

/// `ipauro_mesh::gossip::Gossip` over an iroh-gossip topic.
pub struct IrohGossip {
    out: mpsc::UnboundedSender<Vec<u8>>,
    inbox: mpsc::UnboundedReceiver<Record>,
    secret: SecretKey,
    rejected: Arc<AtomicU64>,
}

impl IrohGossip {
    /// Broadcast an already-sealed envelope (the wire form).
    pub fn publish_sealed(&self, envelope: Vec<u8>) -> io::Result<()> {
        self.out.send(envelope).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "gossip task ended"))
    }
    /// Count of inbound messages dropped by authentication/decoding.
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

impl Gossip for IrohGossip {
    fn publish(&self, record: &Record) -> io::Result<()> {
        self.publish_sealed(seal_record(&self.secret, record))
    }
    fn drain(&mut self) -> Vec<Record> {
        let mut v = Vec::new();
        while let Ok(r) = self.inbox.try_recv() {
            v.push(r);
        }
        v
    }
}

/// Authenticated records and expiries waiting for the `MeshNode` owner.
#[derive(Default)]
struct Pending {
    records: Vec<Record>,
    expired: Vec<NodeId>,
    live: BTreeSet<NodeId>,
    /// Newest gossiped role per live peer (R003-F4): `(seq, role)` so a
    /// re-delivered older heartbeat cannot roll a role back.
    roles: HashMap<NodeId, (u64, NodeRole)>,
    /// When each live peer was last heard.
    heard: HashMap<NodeId, Instant>,
    /// Recently expired peers: `(last heard, last role)`, kept for
    /// [`TOMBSTONE_TTL`] so status can show "expired", not just vanish.
    gone: HashMap<NodeId, (Instant, NodeRole)>,
    /// The gossiped link-state graph, own record included (R003-F6): what
    /// control routing and reachability are planned over.
    topo: Topology,
    /// Verified iroh key per author, learned from signed envelopes and
    /// bootstrap addresses — how a NodeId next hop becomes dialable.
    keys: HashMap<NodeId, PublicKey>,
}

/// [`ControlView`] over the membership's own state.
struct MembershipView {
    me: NodeId,
    pending: Arc<Mutex<Pending>>,
    local_facts: Arc<Mutex<PeerFacts>>,
}

impl ControlView for MembershipView {
    fn plan(&self, dest: NodeId) -> ControlPlan {
        control::plan_control(&self.pending.lock().expect("pending lock poisoned").topo, self.me, dest)
    }
    fn key_of(&self, node: NodeId) -> Option<PublicKey> {
        self.pending.lock().expect("pending lock poisoned").keys.get(&node).copied()
    }
    fn relays_control(&self) -> bool {
        self.local_facts.lock().expect("local facts lock poisoned").relays_control
    }
}

/// How long an expired peer stays visible in [`MeshMembership::members`].
const TOMBSTONE_TTL: Duration = Duration::from_secs(300);

/// How healthy a member looks right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberState {
    Alive,
    /// Silent for more than half the expiry window.
    Expiring,
    Expired,
}

/// One remote member as membership sees it (R003-T5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberObservation {
    pub node: NodeId,
    pub role: NodeRole,
    pub last_seen: Duration,
    pub state: MemberState,
}

/// A running membership: gossip join + heartbeat + silence tracking.
///
/// `MeshNode` is not `Send` (its `Box<dyn Gateway>` has no `Send` bound), so
/// the background tasks cannot own one. They queue authenticated records and
/// expiries here; the `MeshNode` owner folds them in with
/// [`sync_into`](Self::sync_into) on its own thread.
pub struct MeshMembership {
    pending: Arc<Mutex<Pending>>,
    router: Router,
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    rejected: Arc<AtomicU64>,
    sealed_out: mpsc::UnboundedSender<Vec<u8>>,
    /// What this node's heartbeat advertises; mutated via [`set_local_role`](Self::set_local_role).
    local_facts: Arc<Mutex<PeerFacts>>,
    /// This node's own incident links, advertised in heartbeats (`None` =
    /// not measured yet, so the record carries no edge claim at all).
    local_edges: Arc<Mutex<Option<Vec<Edge>>>>,
    control: ControlPlane,
    me: NodeId,
    /// The adopted whole-mesh rate; gossiped in heartbeats once above epoch 0.
    rate: Arc<Mutex<MeshRate>>,
    /// Silence after which a peer is expired (`heartbeat * expire_after_missed`).
    expiry: Duration,
}

impl MeshMembership {
    pub async fn spawn(
        node: &IrohNode,
        bootstrap: Arc<dyn BootstrapSource>,
        cfg: GossipConfig,
    ) -> Result<Self, crate::node::NodeError> {
        let secret = node.endpoint().secret_key().clone();
        let me = node.node_id();
        for p in bootstrap.peers() {
            node.add_peer_addr(p);
        }
        let pending = Arc::new(Mutex::new(Pending::default()));
        let local_facts = Arc::new(Mutex::new(PeerFacts::default()));
        let keys_of = |peers: &[EndpointAddr], p: &Mutex<Pending>| {
            let mut p = p.lock().expect("pending lock poisoned");
            for a in peers {
                p.keys.insert(mesh_node_id(&a.id), a.id);
            }
        };
        keys_of(&bootstrap.peers(), &pending);
        let control = ControlPlane::new(
            node.endpoint().clone(),
            Arc::new(MembershipView { me, pending: pending.clone(), local_facts: local_facts.clone() }),
            Arc::new(IpPassthrough::default()),
        );
        let proto = IrohGossipProto::builder().spawn(node.endpoint().clone());
        let router = Router::builder(node.endpoint().clone())
            .accept(ALPN, proto.clone())
            .accept(CONTROL_ALPN, control.clone())
            .spawn();
        let ids = || bootstrap.peers().into_iter().map(|a| a.id).collect::<Vec<_>>();
        let topic = proto
            .subscribe(topic_for_mesh(&cfg.mesh_id), ids())
            .await
            .map_err(|e| crate::node::NodeError::Bind(format!("gossip subscribe: {e}")))?;
        let (sender, mut receiver): (GossipSender, _) = topic.split();

        let rejected = Arc::new(AtomicU64::new(0));
        let (in_tx, inbox) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (stop, stop_rx) = watch::channel(false);

        // Inbound: authenticate, then queue for the membership loop.
        let rej = rejected.clone();
        let rx_pending = pending.clone();
        let mut stop_in = stop_rx.clone();
        let rx_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_in.changed() => break,
                    ev = receiver.next() => match ev {
                        Some(Ok(Event::Received(m))) => match open_record_keyed(&m.content) {
                            Ok((r, pk)) => {
                                rx_pending.lock().expect("pending lock poisoned").keys.insert(r.author, pk);
                                let _ = in_tx.send(r);
                            }
                            Err(e) => {
                                rej.fetch_add(1, Ordering::Relaxed);
                                log::warn!("dropped gossip from {}: {e}", m.delivered_from.fmt_short());
                            }
                        },
                        Some(Ok(_)) => {} // NeighborUp/Down/Lagged: membership is heartbeat-driven, not neighbor-driven
                        Some(Err(_)) | None => break,
                    }
                }
            }
        });

        let gossip = IrohGossip { out: out_tx.clone(), inbox, secret, rejected: rejected.clone() };

        // Outbound pump: re-dial bootstrap each tick (peers may start later), then send.
        let mut stop_out = stop_rx.clone();
        let pump_bootstrap = bootstrap.clone();
        let pump_lookup = node.peer_lookup();
        let pump_pending = pending.clone();
        let tx_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_out.changed() => break,
                    msg = out_rx.recv() => match msg {
                        Some(bytes) => {
                            // Peers learned after start (beacon) must be dialable: feed the address book first.
                            let known = pump_bootstrap.peers();
                            for p in &known { pump_lookup.add_endpoint_info(p.clone()); }
                            keys_of(&known, &pump_pending);
                            let _ = sender.join_peers(known.into_iter().map(|a| a.id).collect()).await;
                            let _ = sender.broadcast(bytes.into()).await;
                        }
                        None => break,
                    }
                }
            }
        });

        let loop_pending = pending.clone();
        let local_edges = Arc::new(Mutex::new(None));
        let rate = Arc::new(Mutex::new(MeshRate::new(me)));
        let expiry = cfg.heartbeat * cfg.expire_after_missed;
        let hb_task = tokio::spawn(heartbeat_loop(
            me,
            gossip,
            loop_pending,
            local_facts.clone(),
            local_edges.clone(),
            rate.clone(),
            cfg,
            stop_rx,
        ));

        Ok(Self {
            pending,
            router,
            stop,
            tasks: vec![rx_task, tx_task, hb_task],
            rejected,
            sealed_out: out_tx,
            local_facts,
            local_edges,
            control,
            me,
            rate,
            expiry,
        })
    }

    /// Fold everything received since the last call into `mesh`: authenticated
    /// records via `apply_gossip`, silent peers via `forget_peer`. Returns
    /// whether the view changed.
    pub fn sync_into(&self, mesh: &mut MeshNode) -> bool {
        let (records, expired) = {
            let mut p = self.pending.lock().expect("pending lock poisoned");
            (std::mem::take(&mut p.records), std::mem::take(&mut p.expired))
        };
        let mut changed = false;
        for r in records {
            changed |= mesh.apply_gossip(r);
        }
        for n in expired {
            changed |= mesh.forget_peer(n);
        }
        changed
    }

    /// Peers heard from within the expiry window (excluding self), sorted.
    pub fn live_peers(&self) -> Vec<NodeId> {
        self.pending.lock().expect("pending lock poisoned").live.iter().copied().collect()
    }

    /// Set the role this node advertises; carried by the next heartbeat.
    pub fn set_local_role(&self, role: NodeRole) {
        self.local_facts.lock().expect("local facts lock poisoned").role = role;
    }

    /// Declare whether this node forwards control for others (R003-F6).
    /// Carried by the next heartbeat; also gates what [`control`](Self::control)
    /// relays.
    pub fn set_relays_control(&self, relays: bool) {
        self.local_facts.lock().expect("local facts lock poisoned").relays_control = relays;
    }

    /// Advertise the foreign (non-IPAuRo) leaves this node reaches on its own
    /// segment and terminates control for (R003-F6).
    pub fn set_foreign_leaves(&self, leaves: Vec<ForeignLeaf>) {
        self.local_facts.lock().expect("local facts lock poisoned").foreign = leaves;
    }

    /// Replace the protocol families this node advertises (`PeerFacts.protocols`):
    /// the caller's union of in-tree adapters and stream-socket sidecars
    /// (R003-F7). Carried by the next heartbeat, so a retraction (sidecar
    /// gone) reaches the mesh the same way an addition does.
    pub fn set_protocols(&self, caps: ProtocolCaps) {
        self.local_facts.lock().expect("local facts lock poisoned").protocols = caps;
    }

    /// Advertise this node's own incident links (link-state: never another
    /// node's). Carried by the next heartbeat.
    pub fn set_local_edges(&self, edges: Vec<Edge>) {
        *self.local_edges.lock().expect("local edges lock poisoned") = Some(edges);
    }

    /// The control-forwarding endpoint mounted on this node's router.
    pub fn control(&self) -> &ControlPlane {
        &self.control
    }

    /// Every foreign leaf advertised in the gossiped graph (own included),
    /// with its hub, sorted by leaf id.
    pub fn foreign_leaves(&self) -> Vec<(NodeId, ForeignLeaf)> {
        self.pending.lock().expect("pending lock poisoned").topo.foreign_leaves()
    }

    /// How this node reaches `dest` for control, over the gossiped graph.
    pub fn control_reachability(&self, dest: NodeId) -> Reachability {
        control::reachability(&self.pending.lock().expect("pending lock poisoned").topo, self.me, dest)
    }

    /// Gossiped roles of the peers currently live (excluding self). Read-only
    /// by construction: a peer's role changes only via its own signed record.
    pub fn peer_roles(&self) -> BTreeMap<NodeId, NodeRole> {
        let p = self.pending.lock().expect("pending lock poisoned");
        p.live.iter().map(|n| (*n, p.roles.get(n).map(|(_, r)| *r).unwrap_or_default())).collect()
    }

    /// Every remote member worth showing: live ones (alive / expiring) and
    /// recently expired ones, sorted by NodeId. Ages are measured now; callers
    /// that publish them must bucket (`ipauro_proto::state::bucket_age_secs`).
    pub fn members(&self) -> Vec<MemberObservation> {
        let now = Instant::now();
        let p = self.pending.lock().expect("pending lock poisoned");
        let mut out: Vec<MemberObservation> = p
            .live
            .iter()
            .map(|n| {
                let last_seen = p.heard.get(n).map(|t| now.duration_since(*t)).unwrap_or_default();
                let state = if last_seen * 2 > self.expiry { MemberState::Expiring } else { MemberState::Alive };
                let role = p.roles.get(n).map(|(_, r)| *r).unwrap_or_default();
                MemberObservation { node: *n, role, last_seen, state }
            })
            .collect();
        out.extend(p.gone.iter().filter(|(_, (t, _))| now.duration_since(*t) <= TOMBSTONE_TTL).map(
            |(n, (t, role))| MemberObservation {
                node: *n,
                role: *role,
                last_seen: now.duration_since(*t),
                state: MemberState::Expired,
            },
        ));
        out.sort_by_key(|m| m.node);
        out
    }

    /// The whole-mesh rate this node has adopted.
    pub fn mesh_rate(&self) -> MeshRate {
        *self.rate.lock().expect("rate lock poisoned")
    }

    /// Propose a whole-mesh rate (R003-T5): validate, take the next epoch as
    /// the author, adopt it locally and let heartbeats carry it to the rest.
    pub fn propose_rate(&self, hz: u32) -> Result<MeshRate, RateError> {
        let mut r = self.rate.lock().expect("rate lock poisoned");
        let next = r.propose(hz, self.me)?;
        *r = next;
        Ok(next)
    }

    /// Inbound messages dropped by authentication/decoding.
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Broadcast a pre-sealed envelope (tests inject forged ones this way).
    pub fn publish_sealed(&self, envelope: Vec<u8>) {
        let _ = self.sealed_out.send(envelope);
    }

    /// Stop the loops and close the router (and with it the endpoint).
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
        let _ = self.router.shutdown().await;
    }
}

// Each argument is a distinct shared handle owned by `spawn`; bundling them
// into a one-use struct would only rename the list.
#[allow(clippy::too_many_arguments)]
async fn heartbeat_loop(
    me: NodeId,
    mut gossip: IrohGossip,
    pending: Arc<Mutex<Pending>>,
    local_facts: Arc<Mutex<PeerFacts>>,
    local_edges: Arc<Mutex<Option<Vec<Edge>>>>,
    rate: Arc<Mutex<MeshRate>>,
    cfg: GossipConfig,
    mut stop: watch::Receiver<bool>,
) {
    let mut seq = now_millis();
    let deadline = cfg.heartbeat * cfg.expire_after_missed;
    let mut tick = tokio::time::interval(cfg.heartbeat);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Drain faster than we publish so convergence isn't gated on the heartbeat.
    let mut poll = tokio::time::interval((cfg.heartbeat / 4).max(Duration::from_millis(10)));
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = tick.tick() => {
                seq = (seq + 1).max(now_millis());
                // The default rate is implicit everywhere; only a raised one
                // (epoch > 0) rides the heartbeat, inside a Policy.
                let adopted = *rate.lock().expect("rate lock poisoned");
                let policy = (adopted.epoch > 0).then(|| {
                    let mut p = Policy::new(me);
                    p.rate = adopted;
                    p
                });
                let rec = Record {
                    author: me,
                    seq,
                    edges: local_edges.lock().expect("local edges lock poisoned").clone(),
                    facts: Some(local_facts.lock().expect("local facts lock poisoned").clone()),
                    policy,
                };
                // Our own record is part of the graph we plan control over.
                pending.lock().expect("pending lock poisoned").topo.apply(rec.clone());
                if let Err(e) = gossip.publish(&rec) {
                    log::warn!("heartbeat publish failed: {e}");
                }
            }
            _ = poll.tick() => {
                let now = Instant::now();
                let mut p = pending.lock().expect("pending lock poisoned");
                for r in gossip.drain() {
                    if r.author == me { continue; }
                    p.heard.insert(r.author, now);
                    p.gone.remove(&r.author);
                    p.live.insert(r.author);
                    rate.lock().expect("rate lock poisoned").observe(&r);
                    if let Some(f) = &r.facts {
                        let newer = p.roles.get(&r.author).is_none_or(|(s, _)| r.seq >= *s);
                        if newer {
                            p.roles.insert(r.author, (r.seq, f.role));
                        }
                    }
                    p.topo.apply(r.clone());
                    p.records.push(r);
                }
                let stale: Vec<NodeId> = p
                    .heard
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) > deadline)
                    .map(|(n, _)| *n)
                    .collect();
                p.gone.retain(|_, (t, _)| now.duration_since(*t) <= TOMBSTONE_TTL);
                for n in stale {
                    let heard = p.heard.remove(&n).unwrap_or(now);
                    let role = p.roles.get(&n).map(|(_, r)| *r).unwrap_or_default();
                    p.gone.insert(n, (heard, role));
                    p.live.remove(&n);
                    p.roles.remove(&n);
                    p.expired.push(n);
                    p.topo.forget(n);
                    log::info!("mesh peer {n:?} expired after {} silent heartbeats", cfg.expire_after_missed);
                }
            }
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(author: NodeId) -> Record {
        Record { author, seq: 7, edges: None, facts: None, policy: None }
    }

    #[test]
    fn honest_envelope_opens_spoof_tamper_and_version_rejected() {
        let sk = SecretKey::from_bytes(&[3; 32]);
        let me = mesh_node_id(&sk.public());
        let env = seal_record(&sk, &rec(me));
        assert_eq!(open_record(&env).unwrap().seq, 7);

        // Valid signature, wrong author.
        let spoof = seal_record(&sk, &rec(NodeId([0xEE; 8])));
        assert!(matches!(open_record(&spoof), Err(Reject::SpoofedAuthor)));

        // Tampered body.
        let mut t = env.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(matches!(open_record(&t), Err(Reject::BadSignature)));

        let mut v = env.clone();
        v[0] = 9;
        assert!(matches!(open_record(&v), Err(Reject::Version(9))));
        assert!(matches!(open_record(&env[..10]), Err(Reject::Short)));
    }

    #[test]
    fn topic_is_deterministic_and_mesh_specific() {
        assert_eq!(topic_for_mesh("x"), topic_for_mesh("x"));
        assert_ne!(topic_for_mesh("x"), topic_for_mesh("y"));
    }
}
