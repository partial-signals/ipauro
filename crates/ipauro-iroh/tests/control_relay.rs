//! R003-F6: control reaches a node A cannot dial, via the hub that advertises
//! it — three real iroh endpoints on 127.0.0.1.
//!
//! "A cannot dial C" is real, not simulated: relays and discovery are off, and
//! A's address book never learns C's sockets, so iroh has no path. A only
//! knows H; H knows A and C; C only knows H (C on H's single-port segment).

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipauro_iroh::{
    CONTROL_ALPN, ControlError, ControlPlane, ControlTarget, ControlView, IpPassthrough, IrohConfig, IrohNode,
    PassthroughPort, seal_frame,
};
use ipauro_mesh::control::{ControlPlan, ForeignLeaf, plan_control};
use ipauro_mesh::gossip::Record;
use ipauro_mesh::ids::NodeId;
use ipauro_mesh::topology::{Edge, PeerFacts, Topology};
use ipauro_mesh::transport::{LinkQuality, TransportKind};
use iroh::protocol::Router;
use iroh::{EndpointAddr, PublicKey};

struct View {
    me: NodeId,
    topo: Mutex<Topology>,
    keys: HashMap<NodeId, PublicKey>,
    relays: bool,
}

impl ControlView for View {
    fn plan(&self, dest: NodeId) -> ControlPlan {
        plan_control(&self.topo.lock().unwrap(), self.me, dest)
    }
    fn key_of(&self, node: NodeId) -> Option<PublicKey> {
        self.keys.get(&node).copied()
    }
    fn relays_control(&self) -> bool {
        self.relays
    }
}

fn rec(author: NodeId, to: &[NodeId], relays: bool, foreign: Vec<ForeignLeaf>) -> Record {
    let q = LinkQuality { rtt_us: 100, jitter_us: 10, bandwidth_bps: 0, loss: 0.0 };
    Record {
        author,
        seq: 1,
        edges: Some(to.iter().map(|t| Edge { to: *t, kind: TransportKind::Ethernet, quality: q }).collect()),
        facts: Some(PeerFacts { relays_control: relays, foreign, ..Default::default() }),
        policy: None,
    }
}

async fn node(dir: &std::path::Path, name: &str) -> IrohNode {
    let mut c = IrohConfig::new(dir.join(name));
    c.bind_addrs = vec!["127.0.0.1:0".parse().unwrap()];
    IrohNode::start(c).await.unwrap()
}

struct Seat {
    node: IrohNode,
    plane: ControlPlane,
    _router: Router,
}

struct Mesh {
    a: Seat,
    h: Seat,
    c: Seat,
}

/// Bring up A, H, C. `records(a, h, c)` is the gossiped graph; `views`
/// overrides one node's graph (to simulate a divergent view).
async fn mesh(
    dir: &std::path::Path,
    records: impl Fn(NodeId, NodeId, NodeId) -> Vec<Record>,
    h_records: Option<&dyn Fn(NodeId, NodeId, NodeId) -> Vec<Record>>,
) -> Mesh {
    let (a, h, c) = (node(dir, "a").await, node(dir, "h").await, node(dir, "c").await);
    a.add_peer_addr(h.local_addr());
    h.add_peer_addr(a.local_addr());
    h.add_peer_addr(c.local_addr());
    c.add_peer_addr(h.local_addr());
    let ids = (a.node_id(), h.node_id(), c.node_id());
    let keys: HashMap<NodeId, PublicKey> =
        [&a, &h, &c].iter().map(|n| (n.node_id(), n.public_key())).collect();
    let seat = |n: IrohNode, relays: bool, recs: Vec<Record>| {
        let mut t = Topology::new();
        for r in recs {
            t.apply(r);
        }
        let view = View { me: n.node_id(), topo: Mutex::new(t), keys: keys.clone(), relays };
        let plane = ControlPlane::new(n.endpoint().clone(), Arc::new(view), Arc::new(IpPassthrough::default()));
        let router = Router::builder(n.endpoint().clone()).accept(CONTROL_ALPN, plane.clone()).spawn();
        Seat { node: n, plane, _router: router }
    };
    let all = records(ids.0, ids.1, ids.2);
    let h_view = h_records.map(|f| f(ids.0, ids.1, ids.2)).unwrap_or_else(|| records(ids.0, ids.1, ids.2));
    Mesh { a: seat(a, false, all), h: seat(h, true, h_view), c: seat(c, false, records(ids.0, ids.1, ids.2)) }
}

fn leaf(port_last: u8) -> ForeignLeaf {
    ForeignLeaf { mac: [2, 0, 0, 0, 0, port_last], ipv4: Some(Ipv4Addr::LOCALHOST) }
}

/// A — H — C plus a foreign leaf on H's segment; H relays control.
fn segment(a: NodeId, h: NodeId, c: NodeId) -> Vec<Record> {
    vec![rec(a, &[h], false, vec![]), rec(h, &[a, c], true, vec![leaf(7)]), rec(c, &[h], false, vec![])]
}

async fn recv(p: &ControlPlane) -> Option<ipauro_iroh::ControlMessage> {
    tokio::time::timeout(Duration::from_secs(10), p.recv()).await.ok().flatten()
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(std::time::Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn control_reaches_an_undialable_node_via_its_hub_with_origin_verified() {
    let d = tempfile::tempdir().unwrap();
    let m = mesh(d.path(), segment, None).await;
    let (ia, ic) = (m.a.node.node_id(), m.c.node.node_id());

    // Precondition: A genuinely cannot reach C on its own.
    let direct = tokio::time::timeout(
        Duration::from_secs(3),
        m.a.node.endpoint().connect(EndpointAddr::from(m.c.node.public_key()), CONTROL_ALPN),
    )
    .await;
    assert!(!matches!(direct, Ok(Ok(_))), "A must not be able to dial C directly");

    let id = m.a.plane.send(ic, b"set-gain 3").await.unwrap();
    let got = recv(&m.c.plane).await.expect("C receives A's frame via H");
    assert_eq!(got.origin, ia, "origin is the signer, verified at C");
    assert_eq!(got.origin_key, m.a.node.public_key());
    assert_eq!((got.msg_id, got.payload.as_slice()), (id, &b"set-gain 3"[..]));
    // H counts a forward once C has acknowledged the stream, which can land
    // just after C's inbox sees the frame: await it, never sample it.
    eventually("H counted the forward", || m.h.plane.counts().forwarded == 1).await;
    assert_eq!(m.h.plane.counts().delivered, 0, "the hub is transparent");
    assert_eq!(m.c.plane.counts().delivered, 1);

    // And back: C replies to A through the same hub.
    m.c.plane.send(ia, b"ok").await.unwrap();
    assert_eq!(recv(&m.a.plane).await.unwrap().origin, ic);
    eventually("H counted the reply's forward", || m.h.plane.counts().forwarded == 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ttl_exhaustion_stops_a_frame_at_the_relay() {
    let d = tempfile::tempdir().unwrap();
    let m = mesh(d.path(), segment, None).await;
    let ic = m.c.node.node_id();

    // ttl 0: no relay may forward it. A's own send succeeds (one link to H).
    m.a.plane.send_with_ttl(ic, ControlTarget::Node, b"x", 0).await.unwrap();
    eventually("H counts the expiry", || m.h.plane.counts().ttl_expired == 1).await;
    assert_eq!(m.h.plane.counts().forwarded, 0);
    assert!(tokio::time::timeout(Duration::from_millis(300), m.c.plane.recv()).await.is_err());

    // ttl 1 is exactly enough for the one relay.
    m.a.plane.send_with_ttl(ic, ControlTarget::Node, b"y", 1).await.unwrap();
    assert_eq!(recv(&m.c.plane).await.unwrap().payload, b"y");
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_origin_is_rejected_at_the_destination() {
    let d = tempfile::tempdir().unwrap();
    let m = mesh(d.path(), segment, None).await;
    let ic = m.c.node.node_id();

    // A frame signed by A, then re-labelled with H's key as the origin: a relay
    // cannot do this undetected. It travels A -> H -> C (relays do not verify)
    // and C, the verification point, drops it.
    let sk = m.a.node.endpoint().secret_key().clone();
    let mut forged = seal_frame(&sk, 4, ic, ControlTarget::Node, 99, b"rm -rf");
    forged[2..34].copy_from_slice(m.h.node.public_key().as_bytes());
    m.a.plane.send_raw(m.h.node.public_key(), forged).await.unwrap();
    eventually("C rejects the forgery", || m.c.plane.counts().rejected == 1).await;
    eventually("the relay passed it on", || m.h.plane.counts().forwarded == 1).await;
    assert_eq!(m.c.plane.counts().delivered, 0);

    // A tampered payload under a genuine origin is rejected the same way.
    let mut tampered = seal_frame(&sk, 4, ic, ControlTarget::Node, 100, b"gain 1");
    *tampered.last_mut().unwrap() = b'9';
    m.a.plane.send_raw(m.h.node.public_key(), tampered).await.unwrap();
    eventually("C rejects the tampered frame", || m.c.plane.counts().rejected == 2).await;
    assert!(m.c.plane.try_recv().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn hub_terminates_control_for_a_foreign_leaf_as_plain_ip() {
    let d = tempfile::tempdir().unwrap();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (uport, tport) = (udp.local_addr().unwrap().port(), tcp.local_addr().unwrap().port());

    let m = mesh(d.path(), segment, None).await;
    let lid = leaf(7).id(m.h.node.node_id());

    m.a.plane.send_foreign(lid, PassthroughPort::Udp(uport), b"/mtrx/mute 1").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = udp.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"/mtrx/mute 1");

    let accept = std::thread::spawn(move || {
        use std::io::Read;
        let (mut s, _) = tcp.accept().unwrap();
        let mut v = Vec::new();
        s.read_to_end(&mut v).unwrap();
        v
    });
    m.a.plane.send_foreign(lid, PassthroughPort::Tcp(tport), b"PRESET 4\r\n").await.unwrap();
    assert_eq!(accept.join().unwrap(), b"PRESET 4\r\n");
    eventually("hub counted both terminations", || m.h.plane.counts().terminated == 2).await;
    assert_eq!(m.h.plane.counts().forwarded, 0, "terminated, not forwarded");
}

#[tokio::test(flavor = "multi_thread")]
async fn divergent_views_cannot_bounce_a_frame_back_to_its_previous_hop() {
    let d = tempfile::tempdir().unwrap();
    // H's (stale) view routes C through A — the hop the frame came from.
    let h_view = |a: NodeId, h: NodeId, c: NodeId| {
        vec![rec(a, &[h, c], true, vec![]), rec(h, &[a], true, vec![]), rec(c, &[a], false, vec![])]
    };
    let m = mesh(d.path(), segment, Some(&h_view)).await;
    m.a.plane.send(m.c.node.node_id(), b"z").await.unwrap();
    eventually("H drops instead of bouncing", || m.h.plane.counts().loop_dropped == 1).await;
    assert_eq!(m.h.plane.counts().forwarded, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hub_that_does_not_relay_control_cuts_the_node_off_with_a_named_cause() {
    let d = tempfile::tempdir().unwrap();
    // The AVB-D16 shape: H bridges (edges exist) but does not relay control.
    let avb_d16 = |a: NodeId, h: NodeId, c: NodeId| {
        vec![rec(a, &[h], false, vec![]), rec(h, &[a, c], false, vec![]), rec(c, &[h], false, vec![])]
    };
    let m = mesh(d.path(), avb_d16, None).await;
    let err = m.a.plane.send(m.c.node.node_id(), b"z").await.unwrap_err();
    match err {
        ControlError::NoRoute { refused_by, .. } => assert_eq!(refused_by, Some(m.h.node.node_id())),
        e => panic!("expected NoRoute naming the hub, got {e}"),
    }
}
