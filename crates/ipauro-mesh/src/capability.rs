//! Capability records — two layers.
//!
//! - [`Tcap`]: the mesh view of tactus's `tcap` (spec §4.2, §8) — what a
//!   **tactus** peer negotiates for native mode. `tcap` is advertised on the wire
//!   in the tactus PeerAnnouncement (a payload entry a v1 peer ignores —
//!   empirically verified, spec §1.1). This crate does not *encode* the wire form
//!   (that is the spec's/tactus's job and the encoding boundary is open question
//!   §10.6); it holds the decoded view the router and the clock logic consume.
//! - [`ProtocolCaps`] (R010-F1): which **protocol families** a node speaks, with
//!   what verbs/formats/clock per protocol, and which pairs it can translate
//!   between. This is the cross-family discovery no predecessor has (A003 §4):
//!   it travels in the same gossip record as `tcap` ([`crate::topology::PeerFacts`])
//!   and is what makes a Protocol-NAT gateway *electable* (R010-F2) rather than
//!   hand-configured.
//!
//! The per-protocol vocabulary (formats, clock refs) is the registry's,
//! [`crate::protocol`]; a peer advertises a *subset* of its protocol's row.

use crate::protocol::{self, ExtProfile, ProtocolId, Profiles, Row, SampleFormats};

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

// --- protocol-family capability (R010-F1) -----------------------------------

/// The native verbs a peer offers *within* one protocol (A004 §2 adapter
/// contract: pass / sink / fan-in / fan-out; `transcode` is a protocol *pair*
/// property and lives in [`Translation`]). Fan-in here is routing discrete
/// streams onto one leg, never summing — this app does not mix (W001 §non-goals).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Verbs {
    /// Forward a stream of this protocol unchanged (a same-protocol relay hop).
    pub pass: bool,
    /// Terminate a stream of this protocol locally (the system-sound plugin,
    /// a DAC round-trip).
    pub sink: bool,
    /// Originate streams of this protocol (`can_originate` in A004).
    pub source: bool,
    /// Aggregate several incoming streams onto one outgoing leg, channel-discrete.
    pub fan_in: bool,
    /// Replicate one incoming stream to several legs.
    pub fan_out: bool,
}

/// One protocol a peer speaks, and how well: the subset of the registry row it
/// actually implements, plus the media-clock domains it is disciplined to for
/// that protocol (a Dante peer is in a PTPv1 domain *number*; an AVB peer in a
/// gPTP one — the same `ClockDomain::Ptp(n)` vocabulary as `tcap`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProtocolCapability {
    pub proto: ProtocolId,
    pub verbs: Verbs,
    /// Formats this peer handles for `proto`; must be ⊆ the registry row's.
    pub formats: SampleFormats,
    /// Sample rates this peer handles for `proto`; must be ⊆ the registry row's.
    /// Empty = every rate the protocol defines.
    pub rates_hz: Vec<u32>,
    pub clock_domains: Vec<ClockDomain>,
    /// The registry row for an extension family (R003-F7): `Some` iff `proto`
    /// is [`ProtocolId::Ext`] with the matching id ([`ProtocolCaps::validate`]).
    /// This is how every node learns an extension family's axes.
    pub ext: Option<ExtProfile>,
}

impl ProtocolCapability {
    /// A capability that claims the whole registry row (every format and rate)
    /// with the given verbs and no clock-domain membership. Tests and simple
    /// adapters start here and narrow.
    ///
    /// In-tree families only (panics on [`ProtocolId::Ext`]); an extension
    /// family is built with [`ProtocolCapability::ext`], which needs its row.
    #[track_caller]
    pub fn full(proto: ProtocolId, verbs: Verbs) -> Self {
        Self {
            proto,
            verbs,
            formats: protocol::profile(proto).formats,
            rates_hz: Vec::new(),
            clock_domains: Vec::new(),
            ext: None,
        }
    }

    /// A capability claiming the whole of an extension family's declared row.
    pub fn ext(row: ExtProfile, verbs: Verbs) -> Self {
        Self {
            proto: ProtocolId::Ext(row.id),
            verbs,
            formats: row.formats,
            rates_hz: Vec::new(),
            clock_domains: Vec::new(),
            ext: Some(row),
        }
    }
}

/// A transcode the peer offers: ingest `from` into the canonical stream, emit
/// as `to` (A004 §2). Directed — bridging Dante→AVB and AVB→Dante are two
/// translations, because an adapter may implement only ingest *or* emit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Translation {
    pub from: ProtocolId,
    pub to: ProtocolId,
}

/// Everything a node asserts about the protocol families it speaks. Gossiped
/// as part of `PeerFacts`; the author is the only one who may write it.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct ProtocolCaps {
    pub speaks: Vec<ProtocolCapability>,
    pub translates: Vec<Translation>,
}

/// Why a [`ProtocolCaps`] is not self-consistent. A publisher checks before it
/// gossips; a receiver never needs to, because the queries below only honour
/// translations whose endpoints are spoken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapsError {
    /// The same protocol appears twice in `speaks`.
    DuplicateProtocol(ProtocolId),
    /// A translation names a protocol the node does not speak.
    TranslatesUnspoken(Translation),
    /// A translation from a protocol to itself (that is `Verbs::pass`).
    SelfTranslation(ProtocolId),
    /// A translation endpoint carries no media (nothing to transcode).
    TranslatesNoMedia(Translation),
    /// A capability claims a format its protocol does not define.
    FormatOutsideProtocol(ProtocolId),
    /// A capability claims a rate its protocol does not define.
    RateOutsideProtocol(ProtocolId, u32),
    /// An extension family without its row, a row on an in-tree family, or a
    /// row whose id is not the capability's (R003-F7).
    ProfileMismatch(ProtocolId),
}

impl Profiles for ProtocolCaps {
    /// In-tree rows from the table; extension rows from this node's own
    /// capability for that family.
    fn row(&self, id: ProtocolId) -> Option<Row<'_>> {
        match id {
            ProtocolId::Ext(_) => self.speaks(id).and_then(|c| c.ext.as_ref()).map(Row::Ext),
            in_tree => protocol::in_tree(in_tree).map(Row::InTree),
        }
    }
}

impl ProtocolCaps {
    /// The capability this node advertises for `proto`, if it speaks it.
    pub fn speaks(&self, proto: ProtocolId) -> Option<&ProtocolCapability> {
        self.speaks.iter().find(|c| c.proto == proto)
    }

    /// Can this node bridge `from` → `to`? True only if it advertises the
    /// translation *and* speaks both ends — a translation whose endpoint is not
    /// spoken is ignored, so a malformed advertisement can never make a node
    /// look like a gateway it is not.
    pub fn translates(&self, from: ProtocolId, to: ProtocolId) -> bool {
        from != to
            && self.speaks(from).is_some()
            && self.speaks(to).is_some()
            && self.translates.contains(&Translation { from, to })
    }

    /// Every translation this node honours (see [`translates`](Self::translates)),
    /// sorted — the gateway election ranks candidates by it.
    pub fn honoured_translations(&self) -> Vec<Translation> {
        let mut v: Vec<Translation> = self
            .translates
            .iter()
            .copied()
            .filter(|t| self.translates(t.from, t.to))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Speaks more than one media-carrying protocol — the raw material of a
    /// Protocol-NAT gateway (R010-F2 elects among polyglots that also translate).
    pub fn is_polyglot(&self) -> bool {
        self.speaks
            .iter()
            .filter(|c| self.row(c.proto).is_some_and(|r| r.carries_media()))
            .count()
            > 1
    }

    /// What a node advertises when several sources contribute capabilities
    /// (its in-tree adapters plus its stream-socket sidecars, R003-F7):
    /// per family, verbs/formats/rates/clock domains are unioned (`self`'s
    /// extension row wins a disagreement); translations are unioned. Output is
    /// sorted, so equal inputs publish byte-identical records.
    pub fn union(&self, other: &ProtocolCaps) -> ProtocolCaps {
        let mut speaks: Vec<ProtocolCapability> = self.speaks.clone();
        for c in &other.speaks {
            match speaks.iter_mut().find(|d| d.proto == c.proto) {
                None => speaks.push(c.clone()),
                Some(d) => {
                    let (a, b) = (d.verbs, c.verbs);
                    d.verbs = Verbs {
                        pass: a.pass | b.pass,
                        sink: a.sink | b.sink,
                        source: a.source | b.source,
                        fan_in: a.fan_in | b.fan_in,
                        fan_out: a.fan_out | b.fan_out,
                    };
                    let f = SampleFormats::from_bits(d.formats.bits() | c.formats.bits());
                    d.formats = f;
                    // Empty = every rate the family defines, which absorbs any list.
                    if d.rates_hz.is_empty() || c.rates_hz.is_empty() {
                        d.rates_hz.clear();
                    } else {
                        d.rates_hz.extend(&c.rates_hz);
                        d.rates_hz.sort();
                        d.rates_hz.dedup();
                    }
                    for cd in &c.clock_domains {
                        if !d.clock_domains.contains(cd) {
                            d.clock_domains.push(*cd);
                        }
                    }
                    if d.ext.is_none() {
                        d.ext = c.ext.clone();
                    }
                }
            }
        }
        speaks.sort_by_key(|c| c.proto);
        let mut translates: Vec<Translation> = self.translates.iter().chain(&other.translates).copied().collect();
        translates.sort();
        translates.dedup();
        ProtocolCaps { speaks, translates }
    }

    /// Publisher-side consistency check against the registry.
    // `CapsError` carries the offending ids by value (Copy); with extension
    // ids inline (R003-F7) that is large, but this runs per publish, not per frame.
    #[allow(clippy::result_large_err)]
    pub fn validate(&self) -> Result<(), CapsError> {
        for (i, c) in self.speaks.iter().enumerate() {
            if self.speaks[..i].iter().any(|d| d.proto == c.proto) {
                return Err(CapsError::DuplicateProtocol(c.proto));
            }
            let consistent = match (c.proto, &c.ext) {
                (ProtocolId::Ext(id), Some(row)) => row.id == id,
                (ProtocolId::Ext(_), None) => false,
                (_, ext) => ext.is_none(),
            };
            if !consistent {
                return Err(CapsError::ProfileMismatch(c.proto));
            }
            let row = self.row(c.proto).ok_or(CapsError::ProfileMismatch(c.proto))?;
            if !row.formats().contains(&c.formats) {
                return Err(CapsError::FormatOutsideProtocol(c.proto));
            }
            if let Some(&r) = c.rates_hz.iter().find(|r| !row.rates_hz().contains(r)) {
                return Err(CapsError::RateOutsideProtocol(c.proto, r));
            }
        }
        for t in &self.translates {
            if t.from == t.to {
                return Err(CapsError::SelfTranslation(t.from));
            }
            if self.speaks(t.from).is_none() || self.speaks(t.to).is_none() {
                return Err(CapsError::TranslatesUnspoken(*t));
            }
            let media = |p| self.row(p).is_some_and(|r| r.carries_media());
            if !media(t.from) || !media(t.to) {
                return Err(CapsError::TranslatesNoMedia(*t));
            }
        }
        Ok(())
    }
}
