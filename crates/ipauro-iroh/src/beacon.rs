//! Air-gapped LAN bootstrap beacon (R003-F9).
//!
//! iroh-gossip needs one known peer; with no internet, n0 discovery is out and
//! iroh's mDNS is the very multicast class the Local Network gate polices. So
//! nodes announce themselves with a tiny UDP beacon on the bridge:
//! IPv6 link-local multicast (scoped to the interface index) and/or IPv4
//! subnet broadcast. Group and port come from one place,
//! `ipauro_proto::registry::IPAURO_BEACON`.
//!
//! Wire: `[BEACON_VERSION][author pubkey 32][ed25519 sig 64][body]`, body =
//! `NodeId(8) | mesh_id (u8 len + bytes) | n (u8) | n * (family u8 (4|6), ip, port u16 BE)`.
//! The signature is domain-separated; receivers require
//! `NodeId == mesh_node_id(pubkey)`, same property as the gossip envelope.
//! Replays only refresh a real peer's own advertised addresses and the table
//! TTL bounds how long a dead one lingers.
//!
//! A receiver dials the advertised addresses *and* `(datagram source ip,
//! advertised port)`: the source address is right by construction on the
//! segment the beacon arrived on, even if the sender advertised a wildcard.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ipauro_mesh::ids::NodeId;
use ipauro_proto::registry::IPAURO_BEACON;
use iroh::{EndpointAddr, PublicKey, SecretKey, TransportAddr};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::gossip::BootstrapSource;
use crate::key::mesh_node_id;

const BEACON_VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"ipauro-lan-beacon-v1";
const HEADER: usize = 1 + 32 + 64;
const MAX_ADDRS: usize = 8;
const MAX_DATAGRAM: usize = 1200;

/// UDP port of the beacon (from the registry).
pub fn beacon_port() -> u16 {
    IPAURO_BEACON.udp_ports[0]
}

/// The registry's IPv6 beacon group.
pub fn beacon_group_v6() -> Ipv6Addr {
    IPAURO_BEACON.multicast_v6[0].parse().expect("registry group is a valid IPv6 address")
}

/// Subnet-directed broadcast address of the appliance network
/// (`ipauro_mesh::addressing::Ipv4Config::appliance_default`).
pub fn appliance_broadcast_v4() -> Ipv4Addr {
    let cfg = ipauro_mesh::addressing::Ipv4Config::appliance_default();
    let mask = u32::MAX << (32 - cfg.prefix_len() as u32);
    Ipv4Addr::from(u32::from(cfg.network()) | !mask)
}

/// Interface index of `name`, if it exists right now.
pub fn iface_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum BeaconReject {
    #[error("datagram too short")]
    Short,
    #[error("unsupported beacon version {0}")]
    Version(u8),
    #[error("invalid public key")]
    BadKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("malformed body")]
    Malformed,
    #[error("NodeId does not match the signing key")]
    NodeIdMismatch,
}

/// A verified announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    pub id: PublicKey,
    pub mesh_id: String,
    pub addrs: Vec<SocketAddr>,
}

pub fn seal_beacon(secret: &SecretKey, mesh_id: &str, addrs: &[SocketAddr]) -> Vec<u8> {
    let addrs = &addrs[..addrs.len().min(MAX_ADDRS)];
    let mesh = &mesh_id.as_bytes()[..mesh_id.len().min(255)];
    let mut body = mesh_node_id(&secret.public()).0.to_vec();
    body.push(mesh.len() as u8);
    body.extend_from_slice(mesh);
    body.push(addrs.len() as u8);
    for a in addrs {
        match a.ip() {
            IpAddr::V4(ip) => {
                body.push(4);
                body.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                body.push(6);
                body.extend_from_slice(&ip.octets());
            }
        }
        body.extend_from_slice(&a.port().to_be_bytes());
    }
    let mut signed = SIG_DOMAIN.to_vec();
    signed.extend_from_slice(&body);
    let sig = secret.sign(&signed);
    let mut out = vec![BEACON_VERSION];
    out.extend_from_slice(secret.public().as_bytes());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&body);
    out
}

pub fn open_beacon(bytes: &[u8]) -> Result<Announcement, BeaconReject> {
    if bytes.len() < HEADER + 8 + 2 {
        return Err(BeaconReject::Short);
    }
    if bytes[0] != BEACON_VERSION {
        return Err(BeaconReject::Version(bytes[0]));
    }
    let pk_bytes: [u8; 32] = bytes[1..33].try_into().expect("32 bytes");
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| BeaconReject::BadKey)?;
    let sig = iroh::Signature::try_from(&bytes[33..HEADER]).map_err(|_| BeaconReject::BadSignature)?;
    let body = &bytes[HEADER..];
    let mut signed = SIG_DOMAIN.to_vec();
    signed.extend_from_slice(body);
    pk.verify(&signed, &sig).map_err(|_| BeaconReject::BadSignature)?;

    let mut r = body;
    let mut take = |n: usize| -> Result<&[u8], BeaconReject> {
        if r.len() < n {
            return Err(BeaconReject::Malformed);
        }
        let (a, b) = r.split_at(n);
        r = b;
        Ok(a)
    };
    let node = NodeId(take(8)?.try_into().expect("8 bytes"));
    if node != mesh_node_id(&pk) {
        return Err(BeaconReject::NodeIdMismatch);
    }
    let ml = take(1)?[0] as usize;
    let mesh_id = String::from_utf8(take(ml)?.to_vec()).map_err(|_| BeaconReject::Malformed)?;
    let n = take(1)?[0] as usize;
    if n > MAX_ADDRS {
        return Err(BeaconReject::Malformed);
    }
    let mut addrs = Vec::with_capacity(n);
    for _ in 0..n {
        let ip = match take(1)?[0] {
            4 => IpAddr::from(<[u8; 4]>::try_from(take(4)?).expect("4 bytes")),
            6 => IpAddr::from(<[u8; 16]>::try_from(take(16)?).expect("16 bytes")),
            _ => return Err(BeaconReject::Malformed),
        };
        let port = u16::from_be_bytes(take(2)?.try_into().expect("2 bytes"));
        addrs.push(SocketAddr::new(ip, port));
    }
    if !r.is_empty() {
        return Err(BeaconReject::Malformed);
    }
    Ok(Announcement { id: pk, mesh_id, addrs })
}

/// One bound UDP socket plus the destinations a beacon is sent to.
pub struct BeaconIo {
    sock: Arc<UdpSocket>,
    targets: Vec<SocketAddr>,
}

impl BeaconIo {
    fn reusable(domain: socket2::Domain) -> io::Result<socket2::Socket> {
        let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        s.set_nonblocking(true)?;
        Ok(s)
    }
    fn finish(s: socket2::Socket, targets: Vec<SocketAddr>) -> io::Result<Self> {
        Ok(Self { sock: Arc::new(UdpSocket::from_std(s.into())?), targets })
    }

    /// IPv6 link-local multicast on the interface with index `iface`.
    pub fn multicast_v6(iface: u32) -> io::Result<Self> {
        let group = beacon_group_v6();
        let s = Self::reusable(socket2::Domain::IPV6)?;
        s.set_only_v6(true)?;
        s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, beacon_port())).into())?;
        s.join_multicast_v6(&group, iface)?;
        s.set_multicast_if_v6(iface)?;
        s.set_multicast_hops_v6(1)?;
        Self::finish(s, vec![SocketAddr::V6(SocketAddrV6::new(group, beacon_port(), 0, iface))])
    }

    /// IPv4 subnet-directed broadcast (v4-only segments).
    pub fn broadcast_v4(broadcast: Ipv4Addr) -> io::Result<Self> {
        let s = Self::reusable(socket2::Domain::IPV4)?;
        s.set_broadcast(true)?;
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, beacon_port())).into())?;
        Self::finish(s, vec![SocketAddr::from((broadcast, beacon_port()))])
    }

    /// Plain UDP between explicit endpoints. This is the injectable form the
    /// protocol is tested over (multicast/broadcast on macOS loopback is not
    /// dependable); the framing, signing and table logic are identical.
    pub fn unicast(bind: SocketAddr, targets: Vec<SocketAddr>) -> io::Result<Self> {
        let s = Self::reusable(if bind.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 })?;
        s.bind(&bind.into())?;
        Self::finish(s, targets)
    }

    /// Replace the destinations (e.g. after learning ephemeral test ports).
    pub fn with_targets(mut self, targets: Vec<SocketAddr>) -> Self {
        self.targets = targets;
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }
}

#[derive(Clone, Debug)]
pub struct BeaconConfig {
    pub mesh_id: String,
    pub interval: Duration,
    /// Beacons sent in quick succession when started (interface up).
    pub burst: u32,
    pub burst_interval: Duration,
    /// A peer not re-announced within this long drops out of `peers()`.
    pub ttl: Duration,
    /// Hard cap on remembered peers.
    pub max_peers: usize,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            mesh_id: "ipauro".into(),
            interval: Duration::from_secs(3),
            burst: 4,
            burst_interval: Duration::from_millis(250),
            ttl: Duration::from_secs(15),
            max_peers: 256,
        }
    }
}

struct Entry {
    addr: EndpointAddr,
    last: Instant,
}

type Table = Arc<Mutex<HashMap<PublicKey, Entry>>>;

/// Sends our beacon and learns peers from theirs. A [`BootstrapSource`].
pub struct LanBeacon {
    table: Table,
    ttl: Duration,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl LanBeacon {
    /// `addrs` supplies our current direct addresses at each send.
    pub fn spawn(
        secret: SecretKey,
        ios: Vec<BeaconIo>,
        addrs: impl Fn() -> Vec<SocketAddr> + Send + Sync + 'static,
        cfg: BeaconConfig,
    ) -> Self {
        let table: Table = Arc::default();
        let me = secret.public();
        let kick = Arc::new(Notify::new());
        let addrs = Arc::new(addrs);
        let mut tasks = Vec::new();

        for io in &ios {
            let (sock, table, kick, cfg) = (io.sock.clone(), table.clone(), kick.clone(), cfg.clone());
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; MAX_DATAGRAM + 64];
                loop {
                    let Ok((n, src)) = sock.recv_from(&mut buf).await else { break };
                    match open_beacon(&buf[..n]) {
                        Ok(a) if a.id == me => {} // our own beacon (multicast loopback)
                        Ok(a) if a.mesh_id != cfg.mesh_id => {}
                        Ok(a) => {
                            if learn(&table, &cfg, a, src.ip()) {
                                kick.notify_one(); // answer a newcomer promptly
                            }
                        }
                        Err(e) => log::debug!("dropped beacon from {src}: {e}"),
                    }
                }
            }));
        }

        let sends: Vec<(Arc<UdpSocket>, Vec<SocketAddr>)> =
            ios.iter().map(|i| (i.sock.clone(), i.targets.clone())).collect();
        let cfgs = cfg.clone();
        tasks.push(tokio::spawn(async move {
            let mut sent_burst = 0;
            let mut last_send = Instant::now() - Duration::from_secs(60);
            loop {
                // Rate limit: never closer than the burst interval, whatever woke us.
                let since = last_send.elapsed();
                if since < cfgs.burst_interval {
                    tokio::time::sleep(cfgs.burst_interval - since).await;
                }
                let datagram = seal_beacon(&secret, &cfgs.mesh_id, &addrs());
                for (sock, targets) in &sends {
                    for t in targets {
                        if let Err(e) = sock.send_to(&datagram, t).await {
                            log::debug!("beacon send to {t} failed: {e}");
                        }
                    }
                }
                last_send = Instant::now();
                let wait = if sent_burst < cfgs.burst {
                    sent_burst += 1;
                    cfgs.burst_interval
                } else {
                    cfgs.interval + jitter(cfgs.interval / 4)
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = kick.notified() => {}
                }
            }
        }));
        Self { table, ttl: cfg.ttl, tasks }
    }

    /// Stop sending and receiving.
    pub fn shutdown(self) {
        for t in &self.tasks {
            t.abort();
        }
    }

    /// Keys of the peers heard within the ttl — each is a verified beacon
    /// received on this beacon's interface(s), i.e. a direct neighbour. The
    /// same ttl as [`BootstrapSource::peers`], so a silent peer drops out of
    /// both together.
    pub fn heard(&self) -> Vec<PublicKey> {
        let now = Instant::now();
        let mut v: Vec<PublicKey> = self
            .table
            .lock()
            .expect("beacon table poisoned")
            .iter()
            .filter(|(_, e)| now.duration_since(e.last) <= self.ttl)
            .map(|(k, _)| *k)
            .collect();
        v.sort();
        v
    }

    #[cfg(test)]
    fn table_len(&self) -> usize {
        self.table.lock().unwrap().len()
    }
}

impl Drop for LanBeacon {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Insert/refresh; returns true when the peer was previously unknown.
fn learn(table: &Table, cfg: &BeaconConfig, a: Announcement, src: IpAddr) -> bool {
    let mut addrs: Vec<SocketAddr> = a.addrs.iter().copied().filter(|s| !s.ip().is_unspecified()).collect();
    for s in &a.addrs {
        let via_src = SocketAddr::new(src, s.port());
        if !addrs.contains(&via_src) {
            addrs.push(via_src);
        }
    }
    let addr = EndpointAddr::from_parts(a.id, addrs.into_iter().map(TransportAddr::Ip));
    let mut t = table.lock().expect("beacon table poisoned");
    let now = Instant::now();
    t.retain(|_, e| now.duration_since(e.last) <= cfg.ttl);
    let new = !t.contains_key(&a.id);
    if new && t.len() >= cfg.max_peers {
        // Bounded: evict the stalest entry rather than grow without limit.
        if let Some(oldest) = t.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| *k) {
            t.remove(&oldest);
        }
    }
    t.insert(a.id, Entry { addr, last: now });
    new
}

fn jitter(max: Duration) -> Duration {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0) as u64;
    Duration::from_nanos(n % (max.as_nanos() as u64).max(1))
}

impl BootstrapSource for LanBeacon {
    fn peers(&self) -> Vec<EndpointAddr> {
        let now = Instant::now();
        self.table
            .lock()
            .expect("beacon table poisoned")
            .values()
            .filter(|e| now.duration_since(e.last) <= self.ttl)
            .map(|e| e.addr.clone())
            .collect()
    }
}

/// Composite bootstrap: the union of several sources (beacon ∪ static ∪ n0),
/// deduplicated by endpoint id, with addresses merged.
pub struct CompositeBootstrap(pub Vec<Arc<dyn BootstrapSource>>);

impl BootstrapSource for CompositeBootstrap {
    fn peers(&self) -> Vec<EndpointAddr> {
        let mut by_id: HashMap<PublicKey, EndpointAddr> = HashMap::new();
        for src in &self.0 {
            for p in src.peers() {
                by_id
                    .entry(p.id)
                    .and_modify(|e| e.addrs.extend(p.addrs.iter().cloned()))
                    .or_insert(p);
            }
        }
        by_id.into_values().collect()
    }
}

/// The interface names a beacon should announce on right now (R003-B10). A
/// shared handle: the owner of the beacon (`main`) creates it, the service
/// rewrites it as role and attached links change — a Hub names its bridge, a
/// Peer its uplink interface(s). Declarative: the beacon never decides WHICH
/// interfaces are eligible, only whether each named one exists yet.
#[derive(Clone, Default)]
pub struct BeaconTargets(Arc<Mutex<Vec<String>>>);

impl BeaconTargets {
    pub fn new(initial: Vec<String>) -> Self {
        let t = Self::default();
        t.set(initial);
        t
    }

    /// Replace the target set (sorted, deduplicated).
    pub fn set(&self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        *self.0.lock().expect("beacon targets poisoned") = names;
    }

    pub fn get(&self) -> Vec<String> {
        self.0.lock().expect("beacon targets poisoned").clone()
    }
}

/// A beacon over a changing set of named interfaces ([`BeaconTargets`]), each
/// of which may not exist yet (a bridge is created by the helper; an uplink
/// is plugged in) and may be rebuilt under the same name with a new index.
/// Polls the targets; per interface (re)binds multicast v6 + v4 broadcast on
/// change and drops that interface's beacon when it goes away or leaves the
/// target set. Peers learned on any interface are unioned. A [`BootstrapSource`].
pub struct InterfaceBeacon {
    current: Arc<Mutex<BTreeMap<String, LanBeacon>>>,
    health: Arc<Mutex<BTreeMap<String, BeaconState>>>,
    poller: tokio::task::JoinHandle<()>,
}

/// What a beacon is doing on one interface, and why not when it is not
/// (R003-T5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconHealth {
    pub iface: String,
    pub state: BeaconState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconState {
    /// The interface does not exist (bridge not created yet, or uplink not
    /// attached).
    InterfaceAbsent,
    /// Announcing; a family whose bind failed carries its error.
    Announcing { index: u32, v6_error: Option<String>, v4_error: Option<String> },
    /// Both binds failed; retried on the next poll.
    BindFailed { index: u32, v6_error: String, v4_error: String },
}

impl InterfaceBeacon {
    pub fn spawn(
        targets: BeaconTargets,
        secret: SecretKey,
        addrs: impl Fn() -> Vec<SocketAddr> + Send + Sync + Clone + 'static,
        cfg: BeaconConfig,
        poll: Duration,
    ) -> Self {
        let current: Arc<Mutex<BTreeMap<String, LanBeacon>>> = Arc::default();
        let cur = current.clone();
        let health: Arc<Mutex<BTreeMap<String, BeaconState>>> = Arc::default();
        let hl = health.clone();
        let poller = tokio::spawn(async move {
            // Per interface: the index we last acted on (`None` = absent or
            // bind failed, so retry next poll).
            let mut bound: HashMap<String, Option<u32>> = HashMap::new();
            loop {
                let want = targets.get();
                // Targets that left the set: stop announcing there and forget.
                bound.retain(|n, _| want.contains(n));
                cur.lock().expect("interface beacon poisoned").retain(|n, _| want.contains(n));
                hl.lock().expect("beacon health poisoned").retain(|n, _| want.contains(n));

                for iface in &want {
                    let idx = iface_index(iface);
                    if bound.get(iface) == Some(&idx) {
                        continue;
                    }
                    // Dropping the old LanBeacon aborts its tasks and closes its sockets.
                    cur.lock().expect("interface beacon poisoned").remove(iface);
                    bound.insert(iface.clone(), idx);
                    let set_health = |state: BeaconState| {
                        hl.lock().expect("beacon health poisoned").insert(iface.clone(), state);
                    };
                    let Some(i) = idx else {
                        set_health(BeaconState::InterfaceAbsent);
                        continue;
                    };
                    let mut ios = Vec::new();
                    let (mut v6_error, mut v4_error) = (None, None);
                    match BeaconIo::multicast_v6(i) {
                        Ok(io) => ios.push(io),
                        Err(e) => {
                            log::warn!("beacon: ipv6 multicast on {iface} (#{i}) unavailable: {e}");
                            v6_error = Some(e.to_string());
                        }
                    }
                    match BeaconIo::broadcast_v4(appliance_broadcast_v4()) {
                        Ok(io) => ios.push(io),
                        Err(e) => {
                            log::warn!("beacon: ipv4 broadcast unavailable: {e}");
                            v4_error = Some(e.to_string());
                        }
                    }
                    if ios.is_empty() {
                        bound.insert(iface.clone(), None); // retry next poll
                        set_health(BeaconState::BindFailed {
                            index: i,
                            v6_error: v6_error.unwrap_or_default(),
                            v4_error: v4_error.unwrap_or_default(),
                        });
                    } else {
                        set_health(BeaconState::Announcing { index: i, v6_error, v4_error });
                        log::info!("beacon: announcing on {iface} (#{i})");
                        cur.lock().expect("interface beacon poisoned").insert(
                            iface.clone(),
                            LanBeacon::spawn(secret.clone(), ios, addrs.clone(), cfg.clone()),
                        );
                    }
                }
                tokio::time::sleep(poll).await;
            }
        });
        Self { current, health, poller }
    }

    /// Peers currently heard, per interface (sorted by name, then key): the
    /// direct links R003-F6 advertises as this node's edges.
    pub fn heard(&self) -> Vec<(String, PublicKey)> {
        self.current
            .lock()
            .expect("interface beacon poisoned")
            .iter()
            .flat_map(|(iface, b)| b.heard().into_iter().map(move |k| (iface.clone(), k)))
            .collect()
    }

    /// Current health per target interface (sorted by name), for status
    /// reporting. Empty when no interface is targeted.
    pub fn health(&self) -> Vec<BeaconHealth> {
        self.health
            .lock()
            .expect("beacon health poisoned")
            .iter()
            .map(|(iface, state)| BeaconHealth { iface: iface.clone(), state: state.clone() })
            .collect()
    }
}

impl Drop for InterfaceBeacon {
    fn drop(&mut self) {
        self.poller.abort();
    }
}

impl BootstrapSource for InterfaceBeacon {
    fn peers(&self) -> Vec<EndpointAddr> {
        // The union over interfaces, deduplicated by endpoint id with
        // addresses merged (the same peer can be heard on two uplinks).
        let mut by_id: HashMap<PublicKey, EndpointAddr> = HashMap::new();
        for beacon in self.current.lock().expect("interface beacon poisoned").values() {
            for p in beacon.peers() {
                by_id.entry(p.id).and_modify(|e| e.addrs.extend(p.addrs.iter().cloned())).or_insert(p);
            }
        }
        by_id.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_bytes(&[b; 32])
    }
    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn targets_are_sorted_and_deduplicated() {
        let t = BeaconTargets::new(vec!["en6".into(), "en5".into(), "en6".into()]);
        assert_eq!(t.get(), vec!["en5".to_string(), "en6".to_string()]);
        t.set(Vec::new());
        assert!(t.get().is_empty());
    }

    #[tokio::test]
    async fn health_tracks_the_target_set_per_interface() {
        let targets = BeaconTargets::new(vec!["ipauro-nx-b".into(), "ipauro-nx-a".into()]);
        let b = InterfaceBeacon::spawn(
            targets.clone(),
            sk(5),
            Vec::new,
            BeaconConfig::default(),
            Duration::from_millis(10),
        );
        let b = &b;
        let until = |want: Vec<BeaconHealth>| async move {
            let end = Instant::now() + Duration::from_secs(3);
            while b.health() != want {
                assert!(Instant::now() < end, "health stuck at {:?}, wanted {want:?}", b.health());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let absent = |n: &str| BeaconHealth { iface: n.into(), state: BeaconState::InterfaceAbsent };
        // Neither exists: one entry each, sorted — a Peer with two unplugged uplinks.
        until(vec![absent("ipauro-nx-a"), absent("ipauro-nx-b")]).await;
        // An uplink leaves the target set (unplugged / role flip): its entry goes.
        targets.set(vec!["ipauro-nx-b".into()]);
        until(vec![absent("ipauro-nx-b")]).await;
        // No target at all (a Peer with no uplink): nothing reported, nothing announced.
        targets.set(Vec::new());
        until(Vec::new()).await;
        assert!(b.peers().is_empty());
    }

    #[test]
    fn registry_constants_parse() {
        assert!(beacon_group_v6().is_multicast());
        assert_eq!(beacon_port(), 20818);
        assert_eq!(appliance_broadcast_v4(), Ipv4Addr::new(10, 42, 255, 255));
    }

    #[test]
    fn roundtrip_and_rejections() {
        let k = sk(1);
        let addrs = [a("10.42.0.5:4000"), a("[fe80::1]:4001")];
        let b = seal_beacon(&k, "m", &addrs);
        let ann = open_beacon(&b).unwrap();
        assert_eq!((ann.id, ann.mesh_id.as_str(), ann.addrs.as_slice()), (k.public(), "m", &addrs[..]));

        let mut t = b.clone();
        *t.last_mut().unwrap() ^= 1;
        assert_eq!(open_beacon(&t), Err(BeaconReject::BadSignature));
        let mut v = b.clone();
        v[0] = 2;
        assert_eq!(open_beacon(&v), Err(BeaconReject::Version(2)));
        assert_eq!(open_beacon(&b[..20]), Err(BeaconReject::Short));
        // Truncated body with a signature that no longer matches.
        assert!(open_beacon(&b[..b.len() - 3]).is_err());
    }

    #[test]
    fn forged_node_id_rejected_even_with_valid_signature() {
        // Build a body claiming someone else's NodeId, signed by key 1.
        let k = sk(1);
        let mut body = mesh_node_id(&sk(2).public()).0.to_vec();
        body.extend_from_slice(&[0, 0]); // empty mesh id, zero addrs
        let mut signed = SIG_DOMAIN.to_vec();
        signed.extend_from_slice(&body);
        let mut out = vec![BEACON_VERSION];
        out.extend_from_slice(k.public().as_bytes());
        out.extend_from_slice(&k.sign(&signed).to_bytes());
        out.extend_from_slice(&body);
        assert_eq!(open_beacon(&out), Err(BeaconReject::NodeIdMismatch));
    }

    #[test]
    fn learn_bounds_table_and_adds_source_ip() {
        let table: Table = Arc::default();
        let cfg = BeaconConfig { max_peers: 2, ..BeaconConfig::default() };
        let ann = |b: u8| Announcement { id: sk(b).public(), mesh_id: "m".into(), addrs: vec![a("0.0.0.0:7000")] };
        assert!(learn(&table, &cfg, ann(1), "10.42.0.9".parse().unwrap()));
        assert!(!learn(&table, &cfg, ann(1), "10.42.0.9".parse().unwrap()));
        learn(&table, &cfg, ann(2), "10.42.0.8".parse().unwrap());
        learn(&table, &cfg, ann(3), "10.42.0.7".parse().unwrap());
        let t = table.lock().unwrap();
        assert_eq!(t.len(), 2, "bounded");
        let e = t.get(&sk(3).public()).unwrap();
        let ips: Vec<_> = e.addr.ip_addrs().copied().collect();
        assert_eq!(ips, vec![a("10.42.0.7:7000")], "wildcard dropped, source ip used");
    }

    #[tokio::test]
    async fn two_beacons_discover_each_other_and_ignore_self_and_junk() {
        // Plain-UDP form (see BeaconIo::unicast). Ports are ephemeral and
        // cross-wired after binding.
        let (la, lb) = (a("127.0.0.1:0"), a("127.0.0.1:0"));
        let (ia, ib) = (BeaconIo::unicast(la, vec![]).unwrap(), BeaconIo::unicast(lb, vec![]).unwrap());
        let (pa, pb) = (ia.local_addr().unwrap(), ib.local_addr().unwrap());
        let (ia, ib) = (
            ia.with_targets(vec![pb, pa]), // includes itself: own beacon must be ignored
            ib.with_targets(vec![pa]),
        );
        let cfg = BeaconConfig { interval: Duration::from_millis(100), burst_interval: Duration::from_millis(20), ..BeaconConfig::default() };
        let (ka, kb) = (sk(10), sk(11));
        let ba = LanBeacon::spawn(ka.clone(), vec![ia], move || vec![a("127.0.0.1:1111")], cfg.clone());
        let bb = LanBeacon::spawn(kb.clone(), vec![ib], move || vec![a("127.0.0.1:2222")], cfg);

        // Junk datagram at A: dropped, no panic, no table entry.
        let junk = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        junk.send_to(b"\x01nonsense", pa).await.unwrap();
        junk.send_to(&seal_beacon(&sk(12), "other-mesh", &[a("127.0.0.1:3")]), pa).await.unwrap();

        let end = Instant::now() + Duration::from_secs(5);
        while ba.peers().is_empty() || bb.peers().is_empty() {
            assert!(Instant::now() < end, "no discovery");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(ba.table_len(), 1, "self and other-mesh/junk excluded");
        assert_eq!(ba.peers()[0].id, kb.public());
        assert_eq!(bb.peers()[0].id, ka.public());
        assert_eq!(ba.heard(), vec![kb.public()], "heard = verified direct neighbours");
    }
}
