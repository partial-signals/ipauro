//! Control forwarding over iroh (R003-F6): a node reachable only through one
//! hub's audio segment stays addressable for control from anywhere in the
//! mesh, with no internet path.
//!
//! iroh would already relay through a peer that both ends can dial, but on an
//! air-gapped mesh A may have no address for C at all (C sits behind H on a
//! single port). So forwarding is explicit: A sends to the next hop that
//! `ipauro_mesh::control::plan_control` picks over the gossiped graph, and each
//! relay does the same until the frame lands.
//!
//! **Frame** (one QUIC uni stream per frame on [`CONTROL_ALPN`]):
//! `[FRAME_VERSION][ttl][origin ed25519 pubkey 32][signature 64][body]`, body =
//! `[dest NodeId 8][target tag][passthrough port, foreign only][msg_id u64][payload]`.
//! The signature covers the body under a domain tag; `ttl` sits outside it so
//! relays can decrement it.
//!
//! **Trust.** Relays forward without verifying — they are transparent. The
//! destination (or, for a foreign leaf, the terminating hub, which is the last
//! authenticated party on the path) verifies the signature end to end and
//! derives the origin NodeId from the signing key, so a relay can neither forge
//! an origin nor alter a payload undetected.
//!
//! **Loop safety.** `ttl` counts the relays a frame may still pass: a relay that
//! receives `ttl == 0` drops it, otherwise forwards with `ttl - 1`. A relay never
//! sends a frame back to the hop it came from. Every node plans from the same
//! gossiped graph, so a loop needs divergent views; these two rules bound it.
//!
//! **Foreign leaves** (no iroh) are terminated by the hub that advertises them:
//! the payload goes out as plain IP to the leaf's allocated address on the UDP
//! or TCP port the sender declared ([`ForeignDelivery`]). Nothing here knows any
//! leaf protocol; the port is the whole contract.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipauro_mesh::control::{ControlPlan, ForeignLeaf};
use ipauro_mesh::ids::NodeId;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey};
use tokio::sync::mpsc;

use crate::key::mesh_node_id;

/// ALPN of the control-forwarding protocol.
pub const CONTROL_ALPN: &[u8] = b"ipauro/control/1";
/// Relays a frame may pass by default — well above any mesh diameter we build.
pub const DEFAULT_CONTROL_TTL: u8 = 8;

const FRAME_VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"ipauro-control-frame-v1";
const HEADER: usize = 1 + 1 + 32 + 64;
/// Upper bound on one frame; control is small, and a hostile stream must not
/// make a relay buffer without limit.
pub const MAX_FRAME: usize = 64 * 1024;

/// Where a frame is going once it reaches `dest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlTarget {
    /// An IPAuRo node: delivered to its control inbox.
    Node,
    /// A foreign leaf: its hub sends the payload as plain IP to this port.
    Foreign(PassthroughPort),
}

/// The plain-IP port a foreign-leaf frame is delivered to, as the sender
/// declared it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassthroughPort {
    Udp(u16),
    Tcp(u16),
}

/// A verified control frame delivered to this node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlMessage {
    /// Derived from the signing key — not a claim the frame makes.
    pub origin: NodeId,
    pub origin_key: PublicKey,
    pub msg_id: u64,
    pub payload: Vec<u8>,
}

/// A verified frame: everything but the (mutable) ttl.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedFrame {
    pub dest: NodeId,
    pub target: ControlTarget,
    pub message: ControlMessage,
}

/// Why a frame was refused at its verification point.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameReject {
    #[error("unsupported control frame version {0}")]
    Version(u8),
    #[error("control frame truncated")]
    Truncated,
    #[error("invalid origin public key")]
    BadKey,
    #[error("origin signature does not verify")]
    BadSignature,
    #[error("invalid target tag {0}")]
    Target(u8),
    #[error("control frame exceeds {MAX_FRAME} bytes")]
    TooLarge,
}

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("no control route to {dest:?} (refused by {refused_by:?})")]
    NoRoute { dest: NodeId, refused_by: Option<NodeId> },
    #[error("no iroh key known for next hop {0:?}")]
    NoKey(NodeId),
    #[error("next hop is the previous hop; dropped to break a loop")]
    Loop,
    #[error("ttl exhausted")]
    TtlExpired,
    #[error("this node does not relay control")]
    RelayRefused,
    #[error("foreign leaf {0:?} has no allocated address")]
    LeafUnaddressed(NodeId),
    #[error("frame target does not match its destination")]
    TargetMismatch,
    #[error(transparent)]
    Reject(#[from] FrameReject),
    #[error("send to next hop failed: {0}")]
    Transport(String),
    #[error("foreign delivery failed: {0}")]
    Foreign(#[from] io::Error),
}

/// What the forwarding layer needs from the mesh: the shared control plan
/// over the gossiped graph, the iroh key behind a NodeId, and this node's own
/// relay declaration.
pub trait ControlView: Send + Sync + 'static {
    fn plan(&self, dest: NodeId) -> ControlPlan;
    fn key_of(&self, node: NodeId) -> Option<PublicKey>;
    /// Whether this node advertises `relays_control` — checked before it
    /// forwards or terminates anyone else's frame.
    fn relays_control(&self) -> bool;
}

/// Hub-side seam for delivering a verified frame to a foreign leaf.
pub trait ForeignDelivery: Send + Sync + 'static {
    fn deliver(&self, addr: Ipv4Addr, port: PassthroughPort, payload: &[u8]) -> io::Result<()>;
}

/// Plain UDP datagram / TCP connect-write-close passthrough. Protocol-agnostic
/// by design: the sender declares the port, the hub moves bytes.
#[derive(Clone, Copy, Debug)]
pub struct IpPassthrough {
    pub tcp_timeout: Duration,
}

impl Default for IpPassthrough {
    fn default() -> Self {
        Self { tcp_timeout: Duration::from_secs(3) }
    }
}

impl ForeignDelivery for IpPassthrough {
    fn deliver(&self, addr: Ipv4Addr, port: PassthroughPort, payload: &[u8]) -> io::Result<()> {
        match port {
            PassthroughPort::Udp(p) => {
                let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
                let n = s.send_to(payload, (addr, p))?;
                if n != payload.len() {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
                }
                Ok(())
            }
            PassthroughPort::Tcp(p) => {
                let mut s = TcpStream::connect_timeout(&SocketAddr::from((addr, p)), self.tcp_timeout)?;
                s.set_write_timeout(Some(self.tcp_timeout))?;
                s.write_all(payload)?;
                s.shutdown(std::net::Shutdown::Write)
            }
        }
    }
}

/// Per-outcome counters, so status and tests can see what a relay did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlCounts {
    /// Verified and delivered to this node's inbox.
    pub delivered: u64,
    /// Passed on toward another node.
    pub forwarded: u64,
    /// Verified and handed to a foreign leaf as plain IP.
    pub terminated: u64,
    pub ttl_expired: u64,
    /// Failed verification at this node (forged origin, tampered body, ...).
    pub rejected: u64,
    pub no_route: u64,
    pub loop_dropped: u64,
    /// Someone else's frame refused because this node does not relay control.
    pub relay_refused: u64,
    pub send_failed: u64,
}

#[derive(Default)]
struct Stats {
    delivered: AtomicU64,
    forwarded: AtomicU64,
    terminated: AtomicU64,
    ttl_expired: AtomicU64,
    rejected: AtomicU64,
    no_route: AtomicU64,
    loop_dropped: AtomicU64,
    relay_refused: AtomicU64,
    send_failed: AtomicU64,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// Sign and frame a control message from `secret`.
pub fn seal_frame(
    secret: &SecretKey,
    ttl: u8,
    dest: NodeId,
    target: ControlTarget,
    msg_id: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 4 + 8 + payload.len());
    body.extend_from_slice(&dest.0);
    match target {
        ControlTarget::Node => body.push(0),
        ControlTarget::Foreign(PassthroughPort::Udp(p)) => {
            body.push(1);
            body.extend_from_slice(&p.to_be_bytes());
        }
        ControlTarget::Foreign(PassthroughPort::Tcp(p)) => {
            body.push(2);
            body.extend_from_slice(&p.to_be_bytes());
        }
    }
    body.extend_from_slice(&msg_id.to_be_bytes());
    body.extend_from_slice(payload);
    let mut signed = SIG_DOMAIN.to_vec();
    signed.extend_from_slice(&body);
    let sig = secret.sign(&signed);
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.push(FRAME_VERSION);
    out.push(ttl);
    out.extend_from_slice(secret.public().as_bytes());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(&body);
    out
}

/// The unauthenticated routing fields a relay reads: `(dest, ttl)`.
fn peek(frame: &[u8]) -> Result<(NodeId, u8), FrameReject> {
    if frame.len() > MAX_FRAME {
        return Err(FrameReject::TooLarge);
    }
    if frame.len() < HEADER + 8 {
        return Err(FrameReject::Truncated);
    }
    if frame[0] != FRAME_VERSION {
        return Err(FrameReject::Version(frame[0]));
    }
    let dest = NodeId(frame[HEADER..HEADER + 8].try_into().expect("8 bytes"));
    Ok((dest, frame[1]))
}

/// Verify a frame end to end and decode it. The origin is the NodeId of the
/// signing key; a frame cannot name its own origin.
pub fn open_frame(frame: &[u8]) -> Result<OpenedFrame, FrameReject> {
    let (dest, _) = peek(frame)?;
    let pk = PublicKey::from_bytes(&frame[2..34].try_into().expect("32 bytes")).map_err(|_| FrameReject::BadKey)?;
    let sig = iroh::Signature::try_from(&frame[34..HEADER]).map_err(|_| FrameReject::BadSignature)?;
    let body = &frame[HEADER..];
    let mut signed = SIG_DOMAIN.to_vec();
    signed.extend_from_slice(body);
    pk.verify(&signed, &sig).map_err(|_| FrameReject::BadSignature)?;
    let mut rest = &body[8..];
    let mut take = |n: usize| -> Result<&[u8], FrameReject> {
        if rest.len() < n {
            return Err(FrameReject::Truncated);
        }
        let (a, b) = rest.split_at(n);
        rest = b;
        Ok(a)
    };
    let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    let target = match take(1)?[0] {
        0 => ControlTarget::Node,
        1 => ControlTarget::Foreign(PassthroughPort::Udp(port(take(2)?))),
        2 => ControlTarget::Foreign(PassthroughPort::Tcp(port(take(2)?))),
        t => return Err(FrameReject::Target(t)),
    };
    let msg_id = u64::from_be_bytes(take(8)?.try_into().expect("8 bytes"));
    Ok(OpenedFrame {
        dest,
        target,
        message: ControlMessage { origin: mesh_node_id(&pk), origin_key: pk, msg_id, payload: rest.to_vec() },
    })
}

struct Inner {
    endpoint: Endpoint,
    secret: SecretKey,
    view: Arc<dyn ControlView>,
    foreign: Arc<dyn ForeignDelivery>,
    inbox_tx: mpsc::UnboundedSender<ControlMessage>,
    inbox_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<ControlMessage>>,
    conns: Mutex<HashMap<PublicKey, Connection>>,
    stats: Stats,
    next_id: AtomicU64,
}

/// The control-forwarding endpoint: sends, relays, terminates and receives
/// control frames. Mount it on the endpoint's router under [`CONTROL_ALPN`]
/// (`MeshMembership` does).
#[derive(Clone)]
pub struct ControlPlane(Arc<Inner>);

impl std::fmt::Debug for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlane").field("me", &mesh_node_id(&self.0.secret.public())).finish()
    }
}

impl ControlPlane {
    pub fn new(endpoint: Endpoint, view: Arc<dyn ControlView>, foreign: Arc<dyn ForeignDelivery>) -> Self {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        Self(Arc::new(Inner {
            secret: endpoint.secret_key().clone(),
            endpoint,
            view,
            foreign,
            inbox_tx,
            inbox_rx: tokio::sync::Mutex::new(inbox_rx),
            conns: Mutex::new(HashMap::new()),
            stats: Stats::default(),
            next_id: AtomicU64::new(1),
        }))
    }

    /// Send `payload` to the IPAuRo node `dest`. Returns the message id.
    pub async fn send(&self, dest: NodeId, payload: &[u8]) -> Result<u64, ControlError> {
        self.send_with_ttl(dest, ControlTarget::Node, payload, DEFAULT_CONTROL_TTL).await
    }

    /// Send `payload` to a foreign leaf (by its mesh id); its hub delivers it
    /// as plain IP on `port`.
    pub async fn send_foreign(&self, leaf: NodeId, port: PassthroughPort, payload: &[u8]) -> Result<u64, ControlError> {
        self.send_with_ttl(leaf, ControlTarget::Foreign(port), payload, DEFAULT_CONTROL_TTL).await
    }

    /// Send with an explicit relay budget (`ttl` relays may forward it).
    pub async fn send_with_ttl(
        &self,
        dest: NodeId,
        target: ControlTarget,
        payload: &[u8],
        ttl: u8,
    ) -> Result<u64, ControlError> {
        let id = self.0.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = seal_frame(&self.0.secret, ttl, dest, target, id, payload);
        if frame.len() > MAX_FRAME {
            return Err(FrameReject::TooLarge.into());
        }
        self.route(frame, None).await.map(|_| id)
    }

    /// Next verified message delivered to this node.
    pub async fn recv(&self) -> Option<ControlMessage> {
        self.0.inbox_rx.lock().await.recv().await
    }

    /// A delivered message, if one is waiting.
    pub fn try_recv(&self) -> Option<ControlMessage> {
        self.0.inbox_rx.try_lock().ok()?.try_recv().ok()
    }

    pub fn counts(&self) -> ControlCounts {
        let s = &self.0.stats;
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        ControlCounts {
            delivered: g(&s.delivered),
            forwarded: g(&s.forwarded),
            terminated: g(&s.terminated),
            ttl_expired: g(&s.ttl_expired),
            rejected: g(&s.rejected),
            no_route: g(&s.no_route),
            loop_dropped: g(&s.loop_dropped),
            relay_refused: g(&s.relay_refused),
            send_failed: g(&s.send_failed),
        }
    }

    /// Put an already-built frame on the wire to `next` exactly as a relay
    /// would. Test hook for forged/tampered frames; not part of the API.
    #[doc(hidden)]
    pub async fn send_raw(&self, next: PublicKey, frame: Vec<u8>) -> Result<(), ControlError> {
        self.transmit(next, &frame).await
    }

    /// Route one frame. `prev` is the hop it arrived from (`None` = we are
    /// the origin).
    async fn route(&self, mut frame: Vec<u8>, prev: Option<PublicKey>) -> Result<(), ControlError> {
        let s = &self.0.stats;
        let (dest, ttl) = peek(&frame).inspect_err(|_| bump(&s.rejected))?;
        let relaying = prev.is_some();
        match self.0.view.plan(dest) {
            ControlPlan::Local => {
                let f = open_frame(&frame).inspect_err(|_| bump(&s.rejected))?;
                if f.target != ControlTarget::Node {
                    bump(&s.rejected);
                    return Err(ControlError::TargetMismatch);
                }
                bump(&s.delivered);
                let _ = self.0.inbox_tx.send(f.message);
                Ok(())
            }
            ControlPlan::Terminate { leaf } => {
                if relaying && !self.0.view.relays_control() {
                    bump(&s.relay_refused);
                    return Err(ControlError::RelayRefused);
                }
                let f = open_frame(&frame).inspect_err(|_| bump(&s.rejected))?;
                let ControlTarget::Foreign(port) = f.target else {
                    bump(&s.rejected);
                    return Err(ControlError::TargetMismatch);
                };
                self.terminate(dest, leaf, port, f.message.payload).await
            }
            ControlPlan::Forward { next, .. } => {
                if relaying {
                    if !self.0.view.relays_control() {
                        bump(&s.relay_refused);
                        return Err(ControlError::RelayRefused);
                    }
                    if ttl == 0 {
                        bump(&s.ttl_expired);
                        return Err(ControlError::TtlExpired);
                    }
                    frame[1] = ttl - 1;
                }
                let Some(key) = self.0.view.key_of(next) else {
                    bump(&s.no_route);
                    return Err(ControlError::NoKey(next));
                };
                if prev == Some(key) {
                    bump(&s.loop_dropped);
                    return Err(ControlError::Loop);
                }
                self.transmit(key, &frame).await?;
                if relaying {
                    bump(&s.forwarded);
                }
                Ok(())
            }
            ControlPlan::Unroutable { refused_by } => {
                bump(&s.no_route);
                Err(ControlError::NoRoute { dest, refused_by })
            }
        }
    }

    async fn terminate(
        &self,
        dest: NodeId,
        leaf: ForeignLeaf,
        port: PassthroughPort,
        payload: Vec<u8>,
    ) -> Result<(), ControlError> {
        let s = &self.0.stats;
        let Some(addr) = leaf.ipv4 else {
            bump(&s.no_route);
            return Err(ControlError::LeafUnaddressed(dest));
        };
        let foreign = self.0.foreign.clone();
        let res = tokio::task::spawn_blocking(move || foreign.deliver(addr, port, &payload))
            .await
            .map_err(|e| ControlError::Transport(format!("delivery task: {e}")))?;
        match res {
            Ok(()) => {
                bump(&s.terminated);
                Ok(())
            }
            Err(e) => {
                bump(&s.send_failed);
                Err(e.into())
            }
        }
    }

    async fn connection(&self, key: PublicKey, fresh: bool) -> Result<Connection, ControlError> {
        if !fresh
            && let Some(c) = self.0.conns.lock().expect("conns lock poisoned").get(&key)
            && c.close_reason().is_none()
        {
            return Ok(c.clone());
        }
        let c = self
            .0
            .endpoint
            .connect(EndpointAddr::from(key), CONTROL_ALPN)
            .await
            .map_err(|e| ControlError::Transport(e.to_string()))?;
        self.0.conns.lock().expect("conns lock poisoned").insert(key, c.clone());
        Ok(c)
    }

    async fn transmit(&self, key: PublicKey, frame: &[u8]) -> Result<(), ControlError> {
        // A cached connection may have died since; retry once on a fresh one.
        let mut last = None;
        for fresh in [false, true] {
            let conn = match self.connection(key, fresh).await {
                Ok(c) => c,
                Err(e) => {
                    last = Some(e);
                    continue;
                }
            };
            match write_frame(&conn, frame).await {
                Ok(()) => return Ok(()),
                Err(e) => last = Some(ControlError::Transport(e)),
            }
        }
        bump(&self.0.stats.send_failed);
        Err(last.expect("loop ran"))
    }
}

async fn write_frame(conn: &Connection, frame: &[u8]) -> Result<(), String> {
    let mut s = conn.open_uni().await.map_err(|e| e.to_string())?;
    s.write_all(frame).await.map_err(|e| e.to_string())?;
    s.finish().map_err(|e| e.to_string())?;
    // Resolves once the peer has the whole stream: the frame is handed over.
    s.stopped().await.map_err(|e| e.to_string())?;
    Ok(())
}

impl ProtocolHandler for ControlPlane {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let prev = conn.remote_id();
        loop {
            let mut rs = match conn.accept_uni().await {
                Ok(s) => s,
                // Peer closed: the normal end of a control connection.
                Err(_) => return Ok(()),
            };
            let frame = match rs.read_to_end(MAX_FRAME).await {
                Ok(f) => f,
                Err(e) => {
                    bump(&self.0.stats.rejected);
                    log::warn!("control frame from {} unreadable: {e}", prev.fmt_short());
                    continue;
                }
            };
            // Forwarding may dial onward; never stall this peer's reader on it.
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.route(frame, Some(prev)).await {
                    log::debug!("control frame from {} not delivered: {e}", prev.fmt_short());
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_tamper_rejected() {
        let sk = SecretKey::from_bytes(&[4; 32]);
        let dest = NodeId([9; 8]);
        let f = seal_frame(&sk, 3, dest, ControlTarget::Foreign(PassthroughPort::Tcp(7000)), 11, b"hi");
        assert_eq!(peek(&f).unwrap(), (dest, 3));
        let o = open_frame(&f).unwrap();
        assert_eq!(o.dest, dest);
        assert_eq!(o.target, ControlTarget::Foreign(PassthroughPort::Tcp(7000)));
        assert_eq!(o.message.origin, mesh_node_id(&sk.public()));
        assert_eq!((o.message.msg_id, o.message.payload.as_slice()), (11, &b"hi"[..]));

        // ttl is outside the signature: relays may decrement it.
        let mut t = f.clone();
        t[1] = 0;
        assert!(open_frame(&t).is_ok());
        // Anything inside is covered.
        let mut t = f.clone();
        *t.last_mut().unwrap() ^= 1;
        assert_eq!(open_frame(&t).unwrap_err(), FrameReject::BadSignature);
        let mut t = f.clone();
        t[HEADER] ^= 1; // dest
        assert_eq!(open_frame(&t).unwrap_err(), FrameReject::BadSignature);
        // Swapping in another key cannot claim another origin.
        let other = SecretKey::from_bytes(&[5; 32]);
        let mut t = f.clone();
        t[2..34].copy_from_slice(other.public().as_bytes());
        assert_eq!(open_frame(&t).unwrap_err(), FrameReject::BadSignature);

        let mut v = f.clone();
        v[0] = 9;
        assert_eq!(open_frame(&v).unwrap_err(), FrameReject::Version(9));
        assert_eq!(open_frame(&f[..HEADER]).unwrap_err(), FrameReject::Truncated);
    }
}
