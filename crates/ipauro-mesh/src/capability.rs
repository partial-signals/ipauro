//! Capability records — the mesh view of `tcap` (spec §4.2, §8).
//!
//! `tcap` is advertised on the wire in the tactus PeerAnnouncement (a payload
//! entry a v1 peer ignores — empirically verified, spec §1.1). This crate does
//! not *encode* the wire form (that is the spec's/tactus's job and the encoding
//! boundary is open question §10.6); it holds the decoded view the router and the
//! clock logic consume.

/// Codecs a peer will accept in native mode (spec §5).
#[derive(Clone, Copy, Default, Debug)]
pub struct Codecs {
    pub pcm_i16: bool,
    pub pcm_i24: bool,
    pub pcm_f32: bool,
    pub flac: bool,
    pub opus: bool,
}

/// Forward-error-correction schemes (spec §5 — the answer to the open-loop data
/// plane's lack of retransmit, §5.8).
#[derive(Clone, Copy, Default, Debug)]
pub struct FecSchemes {
    pub xor_parity: bool,
    pub raptorq: bool,
}

/// A peer's decoded capability set.
#[derive(Clone, Debug)]
pub struct Tcap {
    pub version: u16,
    pub codecs: Codecs,
    /// The peer's own render ceiling in frames/chunk. Answers the §5.9 hazard:
    /// a sender must not exceed the receiver's real buffer, and must never exceed
    /// 512 toward a *non*-tactus peer. `None` = unknown → assume the safe 512.
    pub max_chunk_frames: Option<u16>,
    pub fec: FecSchemes,
    /// Media-clock domains the peer is disciplined to (spec §6 type-5): PTP/gPTP
    /// domain numbers on a switched fabric, or a sentinel for transport-native
    /// recovery on a p2p link. Empty = ghost-time (musical) only.
    pub clock_domains: Vec<ClockDomain>,
    /// Negotiable latency target, ns (spec §6 type-6).
    pub latency_target_ns: Option<u32>,
    /// Multicast group the peer accepts native fan-out on, if any (spec §5).
    pub multicast: Option<std::net::SocketAddr>,
}

/// A media-clock reference a peer can share.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockDomain {
    /// IEEE-1588 / 802.1AS domain number on a switched fabric.
    Ptp(u8),
    /// Transport-native recovery on a dedicated p2p link (spec §7.2): no PTP,
    /// the talker is master by construction and the listener recovers rate.
    TransportNative,
}

impl Tcap {
    /// The safe per-chunk frame ceiling toward this peer (spec §5.9): the peer's
    /// advertised render ceiling, or 512 if unknown. A sender toward a peer with
    /// *no* `tcap` at all (a reference peer) is bound by 512 regardless — that is
    /// enforced by the router refusing native mode without a `tcap`.
    pub fn safe_chunk_frames(&self) -> u16 {
        self.max_chunk_frames.unwrap_or(512).max(1)
    }

    /// Intersection of two peers' capabilities — the native mode they can share.
    /// An empty intersection (e.g. no common codec) means fall back to v1.
    pub fn intersect(&self, other: &Tcap) -> Negotiated {
        Negotiated {
            codec: pick_codec(&self.codecs, &other.codecs),
            fec: pick_fec(&self.fec, &other.fec),
            clock: self
                .clock_domains
                .iter()
                .copied()
                .find(|d| other.clock_domains.contains(d)),
            max_chunk_frames: self.safe_chunk_frames().min(other.safe_chunk_frames()),
        }
    }
}

/// The concrete native mode two tactus peers will run for a channel.
#[derive(Clone, Copy, Debug)]
pub struct Negotiated {
    pub codec: Option<Codec>,
    pub fec: Option<Fec>,
    pub clock: Option<ClockDomain>,
    pub max_chunk_frames: u16,
}

impl Negotiated {
    /// A non-empty intersection means native mode is available; otherwise the
    /// channel falls back to conformant v1 (spec §4.3).
    pub fn is_native(&self) -> bool {
        self.codec.is_some()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Codec {
    PcmI16,
    PcmI24,
    PcmF32,
    Flac,
    Opus,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fec {
    XorParity,
    RaptorQ,
}

/// Prefer the richest common codec; PcmI16 is the guaranteed floor.
fn pick_codec(a: &Codecs, b: &Codecs) -> Option<Codec> {
    if a.opus && b.opus {
        Some(Codec::Opus)
    } else if a.flac && b.flac {
        Some(Codec::Flac)
    } else if a.pcm_f32 && b.pcm_f32 {
        Some(Codec::PcmF32)
    } else if a.pcm_i24 && b.pcm_i24 {
        Some(Codec::PcmI24)
    } else if a.pcm_i16 && b.pcm_i16 {
        Some(Codec::PcmI16)
    } else {
        None
    }
}

fn pick_fec(a: &FecSchemes, b: &FecSchemes) -> Option<Fec> {
    if a.raptorq && b.raptorq {
        Some(Fec::RaptorQ)
    } else if a.xor_parity && b.xor_parity {
        Some(Fec::XorParity)
    } else {
        None
    }
}
