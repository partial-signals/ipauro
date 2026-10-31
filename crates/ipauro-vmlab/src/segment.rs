//! One virtual L2 segment = one guest NIC = one unix socket this process
//! owns. Lima's vz driver attaches a `networks: - socket: <path>` entry by
//! dialing the socket and speaking the qemu stream protocol (`DialQemu` /
//! `qemuPacketConn` in limactl): each Ethernet frame is prefixed with its
//! length as a big-endian u32. So from the guest's side this is a cable;
//! from ours it is a tap that sees every frame the guest's kernel put on
//! that wire, and can put arbitrary frames back.
//!
//! On top of the tap sit emulated PEERS — hosts that exist only in this
//! process (a MAC, an IPv4 address, an ARP responder, an optional Link-shaped
//! beacon). Peers are the whole point of using sockets rather than a second
//! VM: the observation point is outside the kernel being tested, so a frame
//! the guest claims to send and the frame that reached the wire are never
//! confused (the same two-observation-point discipline as `ipauro-probe`).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::frame::{self, Frame, Mac, Parsed};

/// Ableton Link's IPv4 discovery group and port (A002 §"Ableton Link").
pub const LINK_GROUP: Ipv4Addr = Ipv4Addr::new(224, 76, 78, 75);
pub const LINK_PORT: u16 = 20808;
/// Every payload this harness originates starts with this, so a case can
/// tell harness traffic from the guest's own Link-port chatter.
pub const PEER_MAGIC: &[u8] = b"ipauro-vmlab-peer ";
pub const AGENT_MAGIC: &[u8] = b"ipauro-vmlab-agent ";

/// Read one qemu-stream frame. `Ok(None)` is a clean EOF (VM stopped).
pub fn read_qemu_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > 65_535 + 18 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("qemu frame length {len} is not a frame")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_qemu_frame(w: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(4 + frame.len());
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    w.write_all(&out)
}

#[derive(Clone, Debug)]
pub struct Captured {
    pub at: Instant,
    pub frame: Frame,
}

/// A host that exists only in this process, attached to one segment.
#[derive(Clone, Debug)]
pub struct Peer {
    pub name: String,
    pub mac: Mac,
    pub ip: Ipv4Addr,
    /// When set, the peer emits a Link-shaped beacon every tick: multicast to
    /// [`LINK_GROUP`] plus unicast to each listed address whose MAC has been
    /// learned (exactly Link's discover-by-multicast, sync-by-unicast shape).
    pub beacon: bool,
    pub unicast_to: Vec<Ipv4Addr>,
}

#[derive(Default)]
struct Inner {
    conn: Mutex<Option<UnixStream>>,
    connected_at: Mutex<Option<Instant>>,
    captured: Mutex<Vec<Captured>>,
    peers: Mutex<Vec<Peer>>,
    /// ip -> mac, learned from every frame the guest sends on this segment.
    arp: Mutex<HashMap<Ipv4Addr, Mac>>,
    seq: Mutex<u64>,
}

#[derive(Clone)]
pub struct Segment {
    pub name: String,
    pub path: PathBuf,
    inner: Arc<Inner>,
    stop: Arc<AtomicBool>,
}

impl Segment {
    /// Bind the socket and start accepting. Must happen BEFORE `limactl
    /// start`: lima dials unmanaged sockets once at boot and fails the start
    /// if nothing is listening. Re-accepts, so a VM restart re-attaches.
    pub fn listen(name: &str, path: &Path) -> Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).with_context(|| format!("binding segment socket {}", path.display()))?;
        let seg = Segment {
            name: name.to_string(),
            path: path.to_path_buf(),
            inner: Arc::new(Inner::default()),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let accept = seg.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let Ok(writer) = stream.try_clone() else { continue };
                *accept.inner.conn.lock().unwrap() = Some(writer);
                *accept.inner.connected_at.lock().unwrap() = Some(Instant::now());
                let reader = accept.clone();
                thread::spawn(move || reader.read_loop(stream));
            }
        });
        let ticker = seg.clone();
        thread::spawn(move || {
            while !ticker.stop.load(Ordering::Relaxed) {
                ticker.beacon_tick();
                thread::sleep(Duration::from_millis(100));
            }
        });
        Ok(seg)
    }

    pub fn is_connected(&self) -> bool {
        self.inner.conn.lock().unwrap().is_some()
    }

    fn read_loop(&self, mut stream: UnixStream) {
        // EOF or a broken stream both mean the guest detached.
        while let Ok(Some(raw)) = read_qemu_frame(&mut stream) {
            if let Some(f) = frame::parse(&raw) {
                self.on_frame(f);
            }
        }
        *self.inner.conn.lock().unwrap() = None;
    }

    fn on_frame(&self, f: Frame) {
        match &f.parsed {
            Parsed::Arp { op, sender_mac, sender_ip, target_ip } => {
                self.inner.arp.lock().unwrap().insert(*sender_ip, *sender_mac);
                if *op == 1 {
                    let reply = self
                        .inner
                        .peers
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|p| p.ip == *target_ip)
                        .map(|p| frame::arp_frame(2, p.mac, p.ip, *sender_mac, *sender_ip));
                    if let Some(reply) = reply {
                        let _ = self.inject(&reply);
                    }
                }
            }
            Parsed::Udp { src, .. } if !src.0.is_unspecified() => {
                self.inner.arp.lock().unwrap().insert(src.0, f.src_mac);
            }
            // DHCP-less guest chatter (src 0.0.0.0), IPv6, IGMP: nothing to
            // learn; still captured below for the cases that count frames.
            Parsed::Udp { .. } | Parsed::Other { .. } => {}
        }
        self.inner.captured.lock().unwrap().push(Captured { at: Instant::now(), frame: f });
    }

    /// Put a raw frame on the wire towards the guest.
    pub fn inject(&self, raw: &[u8]) -> Result<()> {
        let mut conn = self.inner.conn.lock().unwrap();
        let w = conn.as_mut().with_context(|| format!("segment {} has no guest attached", self.name))?;
        write_qemu_frame(w, raw).with_context(|| format!("writing to segment {}", self.name))
    }

    pub fn add_peer(&self, peer: Peer) {
        self.inner.peers.lock().unwrap().push(peer);
    }

    pub fn set_beacon(&self, peer: &str, on: bool) {
        for p in self.inner.peers.lock().unwrap().iter_mut().filter(|p| p.name == peer) {
            p.beacon = on;
        }
    }

    pub fn clear_peers(&self) {
        self.inner.peers.lock().unwrap().clear();
        self.inner.arp.lock().unwrap().clear();
    }

    pub fn learned_mac(&self, ip: Ipv4Addr) -> Option<Mac> {
        self.inner.arp.lock().unwrap().get(&ip).copied()
    }

    fn beacon_tick(&self) {
        let peers: Vec<Peer> = self.inner.peers.lock().unwrap().iter().filter(|p| p.beacon).cloned().collect();
        for p in peers {
            let seq = {
                let mut s = self.inner.seq.lock().unwrap();
                *s += 1;
                *s
            };
            let payload = peer_payload(&p.name, seq);
            let mcast = frame::udp_frame(
                p.mac,
                frame::multicast_mac(LINK_GROUP),
                (p.ip, LINK_PORT),
                (LINK_GROUP, LINK_PORT),
                1,
                &payload,
            );
            let _ = self.inject(&mcast);
            for dst in &p.unicast_to {
                match self.learned_mac(*dst) {
                    Some(mac) => {
                        let f = frame::udp_frame(p.mac, mac, (p.ip, LINK_PORT), (*dst, LINK_PORT), 64, &payload);
                        let _ = self.inject(&f);
                    }
                    // Not learned yet: ask, exactly as a real host would.
                    None => {
                        let _ = self.inject(&frame::arp_frame(1, p.mac, p.ip, [0; 6], *dst));
                    }
                }
            }
        }
    }

    /// Frames the guest put on this segment at or after `since`.
    pub fn captured_since(&self, since: Instant) -> Vec<Captured> {
        self.inner.captured.lock().unwrap().iter().filter(|c| c.at >= since).cloned().collect()
    }

    /// Link-port UDP frames on this wire at or after `since` matching `pred`.
    pub fn link_frames(&self, since: Instant, pred: impl Fn(&Frame, Ipv4Addr, Ipv4Addr, &[u8]) -> bool) -> usize {
        self.captured_since(since)
            .iter()
            .filter(|c| match &c.frame.parsed {
                Parsed::Udp { src, dst, payload } => {
                    (src.1 == LINK_PORT || dst.1 == LINK_PORT) && pred(&c.frame, src.0, dst.0, payload)
                }
                Parsed::Arp { .. } | Parsed::Other { .. } => false,
            })
            .count()
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(c) = self.inner.conn.lock().unwrap().take() {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn peer_payload(name: &str, seq: u64) -> Vec<u8> {
    let mut p = PEER_MAGIC.to_vec();
    p.extend_from_slice(format!("{name} {seq}").as_bytes());
    p
}

/// The peer name a harness payload carries, if it is one.
pub fn payload_peer(payload: &[u8]) -> Option<&str> {
    let rest = payload.strip_prefix(PEER_MAGIC)?;
    std::str::from_utf8(rest).ok()?.split(' ').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_framing_round_trips_and_reports_clean_eof() {
        let mut buf = Vec::new();
        write_qemu_frame(&mut buf, b"abc").unwrap();
        write_qemu_frame(&mut buf, b"").unwrap();
        assert_eq!(&buf[..4], &[0, 0, 0, 3]);
        let mut r = &buf[..];
        assert_eq!(read_qemu_frame(&mut r).unwrap().unwrap(), b"abc");
        assert_eq!(read_qemu_frame(&mut r).unwrap().unwrap(), b"");
        assert!(read_qemu_frame(&mut r).unwrap().is_none());
    }

    #[test]
    fn absurd_length_prefix_is_an_error_not_an_allocation() {
        let mut r = &[0xff, 0xff, 0xff, 0xff][..];
        assert!(read_qemu_frame(&mut r).is_err());
    }

    #[test]
    fn peer_payload_names_its_peer() {
        assert_eq!(payload_peer(&peer_payload("a", 7)), Some("a"));
        assert_eq!(payload_peer(b"something else"), None);
    }

    /// The whole segment over a real socketpair-backed unix socket: the
    /// "guest" ARPs for a peer and gets the peer's MAC back; the peer then
    /// learns the guest and starts its unicast leg.
    #[test]
    fn a_peer_answers_arp_and_beacons_unicast_once_it_learns_the_guest() {
        let dir = std::env::temp_dir().join(format!("ipauro-vmlab-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seg = Segment::listen("t", &dir.join("t.sock")).unwrap();
        let mut guest = UnixStream::connect(&seg.path).unwrap();
        let guest_mac: Mac = [2, 0, 0, 0, 0, 1];
        let (guest_ip, peer_ip) = (Ipv4Addr::new(10, 9, 0, 1), Ipv4Addr::new(10, 9, 0, 2));
        let peer_mac: Mac = [2, 0, 0, 0, 0, 2];
        seg.add_peer(Peer { name: "p".into(), mac: peer_mac, ip: peer_ip, beacon: true, unicast_to: vec![guest_ip] });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !seg.is_connected() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        write_qemu_frame(&mut guest, &frame::arp_frame(1, guest_mac, guest_ip, [0; 6], peer_ip)).unwrap();

        let (mut saw_reply, mut saw_unicast) = (false, false);
        guest.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        while !(saw_reply && saw_unicast) {
            let raw = read_qemu_frame(&mut guest).unwrap().expect("segment closed");
            match frame::parse(&raw).unwrap().parsed {
                Parsed::Arp { op: 2, sender_mac, sender_ip, .. } => {
                    assert_eq!((sender_mac, sender_ip), (peer_mac, peer_ip));
                    saw_reply = true;
                }
                Parsed::Udp { dst, payload, .. } if dst.0 == guest_ip => {
                    assert_eq!(payload_peer(&payload), Some("p"));
                    saw_unicast = true;
                }
                _ => {}
            }
        }
        seg.shutdown();
    }
}
