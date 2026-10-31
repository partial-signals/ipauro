//! Versioned binary codec for `ipauro_mesh::gossip::Record` (R003-F2).
//!
//! Mesh has no serde, so the wire format is hand-rolled here and pinned by
//! tests. Layout: leading version byte ([`RECORD_VERSION`]), then fields in
//! declaration order, integers big-endian, `Option` = 0/1 tag, `Vec` = u32
//! count. Unknown versions are rejected, never guessed at.
//!
//! Every mesh enum is matched *exhaustively* (no `_` arm), so adding a variant
//! to `ProtocolId`/`TransportKind`/... breaks the build here instead of
//! silently encoding it wrong. `MeshRate` (F8) travels inside `Policy.rate`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ipauro_mesh::addressing::AddrClaim;
use ipauro_mesh::capability::{
    ClockDomain, Codecs, FecSchemes, ProtocolCapability, ProtocolCaps, Tcap, Translation, Verbs,
};
use ipauro_mesh::control::ForeignLeaf;
use ipauro_mesh::gossip::Record;
use ipauro_mesh::ids::NodeId;
use ipauro_mesh::policy::{Policy, PolicyEpoch, ServiceOrder, Weights};
use ipauro_mesh::protocol::{
    Carrier, Channelization, ClockRef, Discovery, ExtProfile, ExtProtocolId, FanOut, Framing, LatencyClass,
    Packetization, ProtocolId, SampleFormats,
};
use ipauro_mesh::rate::MeshRate;
use ipauro_mesh::topology::{Edge, NodeRole, PeerFacts};
use ipauro_mesh::transport::{LinkQuality, TransportKind};

/// v2 (R003-F4) appends `PeerFacts.role` to the facts block; v3 (R003-F6)
/// appends `relays_control` and the `foreign` leaf list after it. The decoder
/// still accepts v1/v2 (role defaults to `Hub`, M1's behavior; an old peer
/// relays no control and advertises no leaves); v4 (R003-F7) opens
/// `ProtocolId` to extension families — a protocol is tag `0xFF` + a u8-length
/// name for `Ext`, and each `ProtocolCapability` gains an optional
/// `ExtProfile` row after its clock domains. An older record simply has no
/// extension families. The encoder always writes the current version.
pub const RECORD_VERSION: u8 = 4;
/// Oldest record version [`decode_record`] still understands.
const MIN_RECORD_VERSION: u8 = 1;
/// Upper bound on any decoded collection, so a hostile count cannot allocate.
const MAX_COUNT: u32 = 4096;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("unsupported record version {0}")]
    Version(u8),
    #[error("truncated record")]
    Truncated,
    #[error("invalid {0} tag {1}")]
    Tag(&'static str, u8),
    #[error("collection count {0} exceeds limit")]
    TooMany(u32),
    #[error("invalid extension protocol name")]
    ExtName,
    #[error("{0} trailing bytes")]
    Trailing(usize),
}

pub fn encode_record(r: &Record) -> Vec<u8> {
    encode_at(r, RECORD_VERSION)
}

/// Encode as wire version `ver` (tests pin backward decode against real
/// older-layout bytes). A pre-v4 record cannot carry an extension family.
fn encode_at(r: &Record, ver: u8) -> Vec<u8> {
    let mut w = W(vec![ver], ver);
    w.node(r.author);
    w.u64(r.seq);
    w.opt(&r.edges, |w, v| w.vec(v, W::edge));
    w.opt(&r.facts, W::facts);
    w.opt(&r.policy, W::policy);
    w.0
}

pub fn decode_record(buf: &[u8]) -> Result<Record, DecodeError> {
    let mut r = R { buf, ver: RECORD_VERSION };
    let v = r.u8()?;
    if !(MIN_RECORD_VERSION..=RECORD_VERSION).contains(&v) {
        return Err(DecodeError::Version(v));
    }
    r.ver = v;
    let rec = Record {
        author: r.node()?,
        seq: r.u64()?,
        edges: r.opt(|r| r.vec(R::edge))?,
        facts: r.opt(R::facts)?,
        policy: r.opt(R::policy)?,
    };
    if !r.buf.is_empty() {
        return Err(DecodeError::Trailing(r.buf.len()));
    }
    Ok(rec)
}

// ---- enum tables (exhaustive on encode; checked on decode) ------------------

fn proto_tag(p: ProtocolId) -> u8 {
    match p {
        ProtocolId::Link => 0,
        ProtocolId::LinkAudio => 1,
        ProtocolId::Dante => 2,
        ProtocolId::Aes67 => 3,
        ProtocolId::Avb => 4,
        ProtocolId::Madi => 5,
        ProtocolId::Ndi => 6,
        ProtocolId::JackTrip => 7,
        ProtocolId::UsbAudio => 8,
        // Followed by the name; see `W::proto`.
        ProtocolId::Ext(_) => EXT_TAG,
    }
}
/// v4: an extension family's tag; a u8-length name follows.
const EXT_TAG: u8 = 0xFF;
fn kind_tag(k: TransportKind) -> u8 {
    match k {
        TransportKind::LinkMulticast => 0,
        TransportKind::IrohOverlay => 1,
        TransportKind::Thunderbolt => 2,
        TransportKind::UsbBridge => 3,
        TransportKind::Ethernet => 4,
        TransportKind::Wifi => 5,
    }
}
fn kind_from(t: u8) -> Result<TransportKind, DecodeError> {
    Ok(match t {
        0 => TransportKind::LinkMulticast,
        1 => TransportKind::IrohOverlay,
        2 => TransportKind::Thunderbolt,
        3 => TransportKind::UsbBridge,
        4 => TransportKind::Ethernet,
        5 => TransportKind::Wifi,
        _ => return Err(DecodeError::Tag("transport", t)),
    })
}

// ---- writer -----------------------------------------------------------------

/// Output bytes + the version being written.
struct W(Vec<u8>, u8);
impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn bool(&mut self, v: bool) {
        self.0.push(v as u8);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn f32(&mut self, v: f32) {
        self.0.extend_from_slice(&v.to_bits().to_be_bytes());
    }
    fn f64(&mut self, v: f64) {
        self.0.extend_from_slice(&v.to_bits().to_be_bytes());
    }
    fn node(&mut self, n: NodeId) {
        self.0.extend_from_slice(&n.0);
    }
    fn opt<T>(&mut self, v: &Option<T>, f: impl FnOnce(&mut Self, &T)) {
        match v {
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
            None => self.u8(0),
        }
    }
    fn vec<T>(&mut self, v: &[T], mut f: impl FnMut(&mut Self, &T)) {
        self.u32(v.len() as u32);
        for x in v {
            f(self, x);
        }
    }
    fn edge(&mut self, e: &Edge) {
        self.node(e.to);
        self.u8(kind_tag(e.kind));
        self.u32(e.quality.rtt_us);
        self.u32(e.quality.jitter_us);
        self.u64(e.quality.bandwidth_bps);
        self.f32(e.quality.loss);
    }
    fn clock(&mut self, c: &ClockDomain) {
        match c {
            ClockDomain::Ptp(d) => {
                self.u8(0);
                self.u8(*d);
            }
            ClockDomain::TransportNative => self.u8(1),
        }
    }
    fn formats(&mut self, f: &SampleFormats) {
        self.u8(f.bits());
    }
    fn proto(&mut self, p: ProtocolId) {
        self.u8(proto_tag(p));
        if let ProtocolId::Ext(x) = p {
            debug_assert!(self.1 >= 4, "extension families need record v4");
            let name = x.as_str().as_bytes();
            self.u8(name.len() as u8);
            self.0.extend_from_slice(name);
        }
    }
    fn ext_row(&mut self, e: &ExtProfile) {
        self.proto(ProtocolId::Ext(e.id));
        self.u8(e.carrier.code());
        self.u8(e.discovery.code());
        self.u8(e.clock.code());
        let (c, n) = e.channelization.code();
        self.u8(c);
        self.u16(n);
        self.formats(&e.formats);
        self.vec(&e.rates_hz, |w, r| w.u32(*r));
        self.u8(e.packetization.framing.code());
        self.opt(&e.packetization.frames_per_packet, |w, v| w.u16(*v));
        self.bool(e.packetization.mux);
        self.u8(e.fan_out.code());
        self.u8(e.latency.code());
    }
    fn tcap(&mut self, t: &Tcap) {
        self.u16(t.version);
        let c = &t.codecs;
        let bits = [c.pcm_i16, c.pcm_i24, c.pcm_f32, c.flac, c.opus];
        self.u8(bits.iter().enumerate().fold(0, |a, (i, b)| a | ((*b as u8) << i)));
        self.opt(&t.max_chunk_frames, |w, v| w.u16(*v));
        self.bool(t.fec.xor_parity);
        self.bool(t.fec.raptorq);
        self.vec(&t.clock_domains, |w, c| w.clock(c));
        self.opt(&t.latency_target_ns, |w, v| w.u32(*v));
        self.opt(&t.multicast, |w, a| match a.ip() {
            IpAddr::V4(ip) => {
                w.u8(4);
                w.0.extend_from_slice(&ip.octets());
                w.u16(a.port());
            }
            IpAddr::V6(ip) => {
                w.u8(6);
                w.0.extend_from_slice(&ip.octets());
                w.u16(a.port());
            }
        });
    }
    fn protocols(&mut self, p: &ProtocolCaps) {
        self.vec(&p.speaks, |w, c| {
            w.proto(c.proto);
            let v = c.verbs;
            for b in [v.pass, v.sink, v.source, v.fan_in, v.fan_out] {
                w.bool(b);
            }
            w.formats(&c.formats);
            w.vec(&c.rates_hz, |w, r| w.u32(*r));
            w.vec(&c.clock_domains, |w, c| w.clock(c));
            if w.1 >= 4 {
                w.opt(&c.ext, W::ext_row);
            }
        });
        self.vec(&p.translates, |w, t| {
            w.proto(t.from);
            w.proto(t.to);
        });
    }
    fn facts(&mut self, f: &PeerFacts) {
        self.opt(&f.tcap, W::tcap);
        self.bool(f.can_relay);
        self.bool(f.can_transcode);
        self.protocols(&f.protocols);
        self.opt(&f.addr, |w, a| {
            w.0.extend_from_slice(&a.ipv4.octets());
            w.u32(a.salt);
        });
        self.u8(match f.role {
            NodeRole::Hub => 0,
            NodeRole::Peer => 1,
        });
        self.bool(f.relays_control);
        self.vec(&f.foreign, |w, l| {
            w.0.extend_from_slice(&l.mac);
            w.opt(&l.ipv4, |w, a| w.0.extend_from_slice(&a.octets()));
        });
    }
    fn policy(&mut self, p: &Policy) {
        for x in [p.weights.rtt, p.weights.jitter, p.weights.loss, p.weights.inv_bandwidth] {
            self.f64(x);
        }
        self.vec(&p.service_order.prefer, |w, k| w.u8(kind_tag(*k)));
        self.f64(p.service_order.override_margin);
        self.u64(p.epoch.epoch);
        self.node(p.epoch.author);
        self.u32(p.rate.hz);
        self.u64(p.rate.epoch);
        self.node(p.rate.author);
    }
}

// ---- reader -----------------------------------------------------------------

struct R<'a> {
    buf: &'a [u8],
    /// Record version being decoded; gates fields added after v1.
    ver: u8,
}
impl R<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("take(N) returns N bytes"))
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.arr::<1>()?[0])
    }
    fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(DecodeError::Tag("bool", t)),
        }
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    fn f32(&mut self) -> Result<f32, DecodeError> {
        Ok(f32::from_bits(self.u32()?))
    }
    fn f64(&mut self) -> Result<f64, DecodeError> {
        Ok(f64::from_bits(self.u64()?))
    }
    fn node(&mut self) -> Result<NodeId, DecodeError> {
        Ok(NodeId(self.arr()?))
    }
    fn opt<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, DecodeError>) -> Result<Option<T>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => f(self).map(Some),
            t => Err(DecodeError::Tag("option", t)),
        }
    }
    fn vec<T>(&mut self, mut f: impl FnMut(&mut Self) -> Result<T, DecodeError>) -> Result<Vec<T>, DecodeError> {
        let n = self.u32()?;
        if n > MAX_COUNT {
            return Err(DecodeError::TooMany(n));
        }
        (0..n).map(|_| f(self)).collect()
    }
    fn edge(&mut self) -> Result<Edge, DecodeError> {
        Ok(Edge {
            to: self.node()?,
            kind: kind_from(self.u8()?)?,
            quality: LinkQuality {
                rtt_us: self.u32()?,
                jitter_us: self.u32()?,
                bandwidth_bps: self.u64()?,
                loss: self.f32()?,
            },
        })
    }
    fn clock(&mut self) -> Result<ClockDomain, DecodeError> {
        match self.u8()? {
            0 => Ok(ClockDomain::Ptp(self.u8()?)),
            1 => Ok(ClockDomain::TransportNative),
            t => Err(DecodeError::Tag("clock", t)),
        }
    }
    fn formats(&mut self) -> Result<SampleFormats, DecodeError> {
        Ok(SampleFormats::from_bits(self.u8()?))
    }
    fn proto(&mut self) -> Result<ProtocolId, DecodeError> {
        let t = self.u8()?;
        if t == EXT_TAG && self.ver >= 4 {
            let n = self.u8()? as usize;
            if self.buf.len() < n {
                return Err(DecodeError::Truncated);
            }
            let (name, rest) = self.buf.split_at(n);
            self.buf = rest;
            let name = std::str::from_utf8(name).map_err(|_| DecodeError::ExtName)?;
            return ExtProtocolId::parse(name).map(ProtocolId::Ext).map_err(|_| DecodeError::ExtName);
        }
        ProtocolId::ALL.iter().copied().find(|p| proto_tag(*p) == t).ok_or(DecodeError::Tag("protocol", t))
    }
    fn ext_row(&mut self) -> Result<ExtProfile, DecodeError> {
        let id = match self.proto()? {
            ProtocolId::Ext(x) => x,
            // A row must name an extension family; in-tree rows never travel.
            _ => return Err(DecodeError::ExtName),
        };
        fn code<T>(t: Option<T>, what: &'static str, c: u8) -> Result<T, DecodeError> {
            t.ok_or(DecodeError::Tag(what, c))
        }
        let c = self.u8()?;
        let carrier = code(Carrier::from_code(c), "carrier", c)?;
        let c = self.u8()?;
        let discovery = code(Discovery::from_code(c), "discovery", c)?;
        let c = self.u8()?;
        let clock = code(ClockRef::from_code(c), "clock ref", c)?;
        let c = self.u8()?;
        let n = self.u16()?;
        let channelization = code(Channelization::from_code(c, n), "channelization", c)?;
        let formats = self.formats()?;
        let rates_hz = self.vec(R::u32)?;
        let c = self.u8()?;
        let framing = code(Framing::from_code(c), "framing", c)?;
        let frames_per_packet = self.opt(R::u16)?;
        let mux = self.bool()?;
        let c = self.u8()?;
        let fan_out = code(FanOut::from_code(c), "fan-out", c)?;
        let c = self.u8()?;
        let latency = code(LatencyClass::from_code(c), "latency", c)?;
        Ok(ExtProfile {
            id,
            carrier,
            discovery,
            clock,
            channelization,
            formats,
            rates_hz,
            packetization: Packetization { framing, frames_per_packet, mux },
            fan_out,
            latency,
        })
    }
    fn tcap(&mut self) -> Result<Tcap, DecodeError> {
        let version = self.u16()?;
        let b = self.u8()?;
        let bit = |i: u8| b & (1 << i) != 0;
        let codecs = Codecs { pcm_i16: bit(0), pcm_i24: bit(1), pcm_f32: bit(2), flac: bit(3), opus: bit(4) };
        let max_chunk_frames = self.opt(R::u16)?;
        let fec = FecSchemes { xor_parity: self.bool()?, raptorq: self.bool()? };
        let clock_domains = self.vec(R::clock)?;
        let latency_target_ns = self.opt(R::u32)?;
        let multicast = self.opt(|r| match r.u8()? {
            4 => Ok(SocketAddr::new(IpAddr::from(r.arr::<4>()?), r.u16()?)),
            6 => Ok(SocketAddr::new(IpAddr::from(r.arr::<16>()?), r.u16()?)),
            t => Err(DecodeError::Tag("ip family", t)),
        })?;
        Ok(Tcap { version, codecs, max_chunk_frames, fec, clock_domains, latency_target_ns, multicast })
    }
    fn protocols(&mut self) -> Result<ProtocolCaps, DecodeError> {
        let speaks = self.vec(|r| {
            Ok(ProtocolCapability {
                proto: r.proto()?,
                verbs: Verbs {
                    pass: r.bool()?,
                    sink: r.bool()?,
                    source: r.bool()?,
                    fan_in: r.bool()?,
                    fan_out: r.bool()?,
                },
                formats: r.formats()?,
                rates_hz: r.vec(R::u32)?,
                clock_domains: r.vec(R::clock)?,
                ext: if r.ver >= 4 { r.opt(R::ext_row)? } else { None },
            })
        })?;
        let translates = self.vec(|r| Ok(Translation { from: r.proto()?, to: r.proto()? }))?;
        Ok(ProtocolCaps { speaks, translates })
    }
    fn facts(&mut self) -> Result<PeerFacts, DecodeError> {
        Ok(PeerFacts {
            tcap: self.opt(R::tcap)?,
            can_relay: self.bool()?,
            can_transcode: self.bool()?,
            protocols: self.protocols()?,
            addr: self.opt(|r| Ok(AddrClaim { ipv4: Ipv4Addr::from(r.arr::<4>()?), salt: r.u32()? }))?,
            role: if self.ver >= 2 {
                match self.u8()? {
                    0 => NodeRole::Hub,
                    1 => NodeRole::Peer,
                    t => return Err(DecodeError::Tag("node role", t)),
                }
            } else {
                NodeRole::default()
            },
            relays_control: self.ver >= 3 && self.bool()?,
            foreign: if self.ver >= 3 {
                self.vec(|r| Ok(ForeignLeaf { mac: r.arr()?, ipv4: r.opt(|r| Ok(Ipv4Addr::from(r.arr::<4>()?)))? }))?
            } else {
                Vec::new()
            },
        })
    }
    fn policy(&mut self) -> Result<Policy, DecodeError> {
        Ok(Policy {
            weights: Weights {
                rtt: self.f64()?,
                jitter: self.f64()?,
                loss: self.f64()?,
                inv_bandwidth: self.f64()?,
            },
            service_order: ServiceOrder {
                prefer: self.vec(|r| kind_from(r.u8()?))?,
                override_margin: self.f64()?,
            },
            epoch: PolicyEpoch { epoch: self.u64()?, author: self.node()? },
            rate: MeshRate { hz: self.u32()?, epoch: self.u64()?, author: self.node()? },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Record {
        let a = NodeId([1; 8]);
        let mut caps = ProtocolCaps::default();
        caps.speaks.push(ProtocolCapability::full(ProtocolId::Dante, Verbs { pass: true, sink: true, ..Verbs::default() }));
        caps.speaks.push(ProtocolCapability::full(ProtocolId::Avb, Verbs::default()));
        caps.translates.push(Translation { from: ProtocolId::Dante, to: ProtocolId::Avb });
        Record {
            author: a,
            seq: 42,
            edges: Some(vec![Edge {
                to: NodeId([2; 8]),
                kind: TransportKind::Thunderbolt,
                quality: LinkQuality { rtt_us: 5, jitter_us: 1, bandwidth_bps: 40_000_000_000, loss: 0.25 },
            }]),
            facts: Some(PeerFacts {
                tcap: Some(Tcap {
                    version: 1,
                    codecs: Codecs { pcm_i24: true, opus: true, ..Codecs::default() },
                    max_chunk_frames: Some(256),
                    fec: FecSchemes { xor_parity: true, raptorq: false },
                    clock_domains: vec![ClockDomain::Ptp(3), ClockDomain::TransportNative],
                    latency_target_ns: Some(1_000_000),
                    multicast: Some("239.1.2.3:5000".parse().unwrap()),
                }),
                can_relay: true,
                can_transcode: false,
                protocols: caps,
                addr: Some(AddrClaim { ipv4: Ipv4Addr::new(169, 254, 7, 9), salt: 3 }),
                role: NodeRole::Peer,
                relays_control: true,
                foreign: vec![
                    ForeignLeaf { mac: [2, 0, 0, 0, 0, 7], ipv4: Some(Ipv4Addr::new(10, 42, 9, 7)) },
                    ForeignLeaf { mac: [2, 0, 0, 0, 0, 8], ipv4: None },
                ],
            }),
            policy: Some({
                let mut p = Policy::new(a);
                p.rate = p.rate.raise(96_000, a);
                p
            }),
        }
    }

    #[test]
    fn roundtrip_is_stable() {
        let r = full();
        let bytes = encode_record(&r);
        assert_eq!(bytes[0], RECORD_VERSION);
        let back = decode_record(&bytes).unwrap();
        // Record has no PartialEq (mesh is std-only): re-encoding must be byte-identical.
        assert_eq!(encode_record(&back), bytes);
        assert_eq!(back.author, r.author);
        assert_eq!(back.seq, 42);
        assert_eq!(back.facts.as_ref().unwrap().addr, r.facts.as_ref().unwrap().addr);
        assert_eq!(back.policy.as_ref().unwrap().rate, r.policy.as_ref().unwrap().rate);
        assert_eq!(back.edges.unwrap()[0].quality.loss, 0.25);
    }

    #[test]
    fn role_roundtrips_and_v1_records_default_to_hub() {
        let r = full();
        let back = decode_record(&encode_record(&r)).unwrap();
        assert_eq!(back.facts.unwrap().role, NodeRole::Peer);

        // A v1 record is the v2 bytes minus the trailing role byte (facts is
        // the last-but-policy block, so rebuild with policy absent and no v3
        // tail: relays_control=false (1 byte) + empty foreign list (4 bytes)).
        let mut v1 = Record { policy: None, ..full() };
        v1.facts.as_mut().unwrap().role = NodeRole::Hub;
        v1.facts.as_mut().unwrap().relays_control = false;
        v1.facts.as_mut().unwrap().foreign.clear();
        let mut bytes = encode_at(&v1, 3);
        // layout tail: ...facts(role u8, relays u8, foreign count u32) then policy tag 0
        let tail = bytes.pop().unwrap();
        assert_eq!(tail, 0, "policy None tag");
        bytes.truncate(bytes.len() - 5); // v3 tail
        bytes.pop(); // role byte
        bytes.push(tail);
        bytes[0] = 1;
        let old = decode_record(&bytes).unwrap();
        assert_eq!(old.facts.unwrap().role, NodeRole::Hub);

        // A bad role tag is rejected, not guessed.
        let mut bad = encode_at(&Record { policy: None, ..full() }, 3);
        bad[0] = 2;
        bad.pop(); // policy tag
        bad.truncate(bad.len() - 4 - 11 - 7); // foreign list: count + two leaves
        bad.pop(); // relays_control
        let n = bad.len();
        bad[n - 1] = 9;
        bad.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // relays, empty foreign, policy None
        assert_eq!(decode_record(&bad).err(), Some(DecodeError::Tag("node role", 9)));
    }

    #[test]
    fn control_relay_facts_roundtrip_and_v2_records_default_to_no_relay() {
        let r = full();
        let back = decode_record(&encode_record(&r)).unwrap();
        let (f, g) = (back.facts.unwrap(), r.facts.unwrap());
        assert!(f.relays_control);
        assert_eq!(f.foreign, g.foreign);

        // A v2 record is the v3 bytes minus relays_control + the foreign list.
        let mut v2 = Record { policy: None, ..full() };
        v2.facts.as_mut().unwrap().relays_control = false;
        v2.facts.as_mut().unwrap().foreign.clear();
        let mut bytes = encode_at(&v2, 3);
        let tail = bytes.pop().unwrap();
        bytes.truncate(bytes.len() - 5);
        bytes.push(tail);
        bytes[0] = 2;
        let old = decode_record(&bytes).unwrap().facts.unwrap();
        assert!(!old.relays_control);
        assert!(old.foreign.is_empty());
        assert_eq!(old.role, NodeRole::Peer, "v2 role still decoded");
    }

    fn ext_row(name: &str) -> ExtProfile {
        ExtProfile {
            id: ExtProtocolId::parse(name).unwrap(),
            carrier: Carrier::Udp,
            discovery: Discovery::Mdns,
            clock: ClockRef::PtpV2,
            channelization: Channelization::Muxed { channels: 32 },
            formats: SampleFormats { pcm_i24: true, pcm_f32: true, ..SampleFormats::NONE },
            rates_hz: vec![48_000, 96_000],
            packetization: Packetization { framing: Framing::Proprietary, frames_per_packet: Some(32), mux: true },
            fan_out: FanOut::Multicast,
            latency: LatencyClass::Ms,
        }
    }

    #[test]
    fn extension_families_roundtrip_in_v4() {
        let mut r = full();
        let caps = &mut r.facts.as_mut().unwrap().protocols;
        let row = ext_row("com.acme.netaudio");
        let x = ProtocolId::Ext(row.id);
        caps.speaks.push(ProtocolCapability::ext(row.clone(), Verbs { source: true, ..Verbs::default() }));
        caps.translates.push(Translation { from: x, to: ProtocolId::Dante });
        caps.translates.push(Translation { from: ProtocolId::Dante, to: x });
        let bytes = encode_record(&r);
        assert_eq!(bytes[0], 4);
        let back = decode_record(&bytes).unwrap();
        assert_eq!(encode_record(&back), bytes);
        let got = back.facts.unwrap().protocols;
        assert_eq!(got, r.facts.unwrap().protocols, "ext id, row and translations survive");
        assert_eq!(got.speaks(x).unwrap().ext.as_ref(), Some(&row));
        assert!(got.translates(x, ProtocolId::Dante));
    }

    #[test]
    fn v3_records_still_decode_without_extension_rows() {
        let r = full();
        let v3 = encode_at(&r, 3);
        assert_eq!(v3[0], 3);
        let back = decode_record(&v3).unwrap().facts.unwrap().protocols;
        assert_eq!(back, r.facts.unwrap().protocols, "in-tree caps identical, no ext rows");
        assert!(back.speaks.iter().all(|c| c.ext.is_none()));
        // The ext tag means nothing before v4.
        let mut b = encode_at(&Record { edges: None, facts: None, policy: None, ..full() }, 3);
        b.truncate(1 + 16);
        b.extend_from_slice(&[0, 1]); // edges None, facts Some
        b.push(0); // tcap None
        b.extend_from_slice(&[0, 0]); // can_relay, can_transcode
        b.extend_from_slice(&1u32.to_be_bytes());
        b.push(0xFF);
        assert_eq!(decode_record(&b).unwrap_err(), DecodeError::Tag("protocol", 0xFF));
    }

    #[test]
    fn bad_extension_names_are_rejected() {
        let mut r = full();
        let row = ext_row("com.acme.x");
        r.facts.as_mut().unwrap().protocols.speaks.push(ProtocolCapability::ext(row, Verbs::default()));
        let bytes = encode_record(&r);
        let at = bytes.windows(10).position(|w| w == b"com.acme.x").unwrap();
        let mut bad = bytes.clone();
        bad[at + 4] = b'.'; // "com..cme.x": empty label
        assert_eq!(decode_record(&bad).unwrap_err(), DecodeError::ExtName);
    }

    #[test]
    fn minimal_record_roundtrips() {
        let r = Record { author: NodeId([9; 8]), seq: 1, edges: None, facts: None, policy: None };
        let b = encode_record(&r);
        assert_eq!(b.len(), 1 + 8 + 8 + 3);
        assert_eq!(encode_record(&decode_record(&b).unwrap()), b);
    }

    #[test]
    fn unknown_version_truncation_and_trailing_rejected() {
        let mut b = encode_record(&full());
        assert_eq!(decode_record(&b[..b.len() - 1]).unwrap_err(), DecodeError::Truncated);
        let mut v = b.clone();
        v[0] = RECORD_VERSION + 1;
        assert_eq!(decode_record(&v).unwrap_err(), DecodeError::Version(RECORD_VERSION + 1));
        b.push(0);
        assert_eq!(decode_record(&b).unwrap_err(), DecodeError::Trailing(1));
        assert_eq!(decode_record(&[]).unwrap_err(), DecodeError::Truncated);
    }

    #[test]
    fn hostile_count_is_bounded() {
        // version, author, seq, edges=Some, count=u32::MAX
        let mut b = vec![RECORD_VERSION];
        b.extend_from_slice(&[0; 16]);
        b.push(1);
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode_record(&b).unwrap_err(), DecodeError::TooMany(u32::MAX));
    }
}
