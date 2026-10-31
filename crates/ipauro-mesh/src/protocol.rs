//! Protocol registry — the control-plane half of R004-F1's registry, extended
//! per R010-F1 with the axes Protocol NAT needs: **media format, packetization,
//! and clock** per protocol (A004 §1 axes 3, 5, 6, 7, 9).
//!
//! Two halves, two crates, one registry:
//! - `ipauro_proto::registry` (manager-owned) holds the *network* half — ports and
//!   multicast groups the pf generator scopes (`ProtocolPorts`). M1 ships one row.
//! - this module holds the *media* half — what a protocol carries and how, which
//!   is what a node advertises over gossip ([`crate::capability::ProtocolCaps`])
//!   and what the gateway election (R010-F2) and the clock bridge (R010-F4) read.
//!
//! The two are joined by [`ProtocolProfile::name`], which equals the
//! `ProtocolPorts::name` of the same protocol (`"ableton-link"` today). Folding
//! this table into `ipauro-proto` is a proto request, not an edit this crate makes.
//!
//! **Design rule (R004-F1 gotcha, repo "no type-name sniffing"):** a new protocol
//! is one new [`ProtocolId`] variant plus one row in [`PROFILES`]. Nothing in this
//! crate matches on a `ProtocolId` to decide *behaviour*; consumers read the
//! profile's fields. [`clock_bridge`] is the model: it compares two profiles'
//! [`ClockRef`]s, it never asks "is this Dante?".
//!
//! Every row below is transcribed from A004 §1's table; where A004 is silent the
//! field says so (`None` / `Unknown`) rather than guessing.

/// Identity of a protocol family. Identity only — behaviour lives in the
/// [`ProtocolProfile`] row, looked up with [`profile`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum ProtocolId {
    /// Ableton Link: tempo/phase sync only, carries no samples.
    Link,
    /// LinkAudio v1 on the Link transport — PCM i16 big-endian, 1–2 ch, beat-time
    /// aligned, **no sample lock** (A004 §3 correction 2026-07-25).
    LinkAudio,
    /// Audinate Dante (native mode; AES67 mode classifies as [`ProtocolId::Aes67`]).
    Dante,
    /// AES67 / RAVENNA: RTP/UDP, PTPv2.
    Aes67,
    /// AVB / Milan: L2 AVTP with SRP reservations, gPTP.
    Avb,
    /// MADI: point-to-point coax/fiber, 64 channels muxed on one link.
    Madi,
    /// NDI audio: TCP/UDP, stream-timestamped.
    Ndi,
    /// JackTrip-family (NetJack2 / JackTrip / SonoBus): UDP, free-run + resample.
    JackTrip,
    /// USB Audio Class.
    UsbAudio,
    /// A family an out-of-process adapter declares (R003-F7): identity is its
    /// namespaced name; its row is gossiped data ([`ExtProfile`]), not a
    /// [`PROFILES`] entry. Orders after every in-tree variant, then by name.
    Ext(ExtProtocolId),
}

impl ProtocolId {
    /// Every **in-tree** protocol the registry knows, in a fixed order (so a
    /// table rendered from it is stable). Extension families are open-ended
    /// and never listed here.
    pub const ALL: [ProtocolId; 9] = [
        ProtocolId::Link,
        ProtocolId::LinkAudio,
        ProtocolId::Dante,
        ProtocolId::Aes67,
        ProtocolId::Avb,
        ProtocolId::Madi,
        ProtocolId::Ndi,
        ProtocolId::JackTrip,
        ProtocolId::UsbAudio,
    ];

    /// Resolve a family name, the join key shared with
    /// `ipauro_proto::registry` and the stream socket: an in-tree row's
    /// [`ProtocolProfile::name`], else (if it contains a `.`) an extension id.
    /// In-tree names carry no `.`, so the two spaces cannot collide.
    pub fn from_name(name: &str) -> Result<ProtocolId, ExtIdError> {
        if let Some(p) = PROFILES.iter().find(|p| p.name == name) {
            return Ok(p.id);
        }
        ExtProtocolId::parse(name).map(ProtocolId::Ext)
    }

    /// The family's name (inverse of [`from_name`](Self::from_name)).
    pub fn name(&self) -> &str {
        match self {
            ProtocolId::Ext(x) => x.as_str(),
            in_tree => profile(*in_tree).name,
        }
    }
}

/// Longest extension family name, in bytes.
pub const EXT_NAME_MAX: usize = 64;

/// Identity of an adapter-declared protocol family: a reverse-DNS name
/// (`com.acme.netaudio`) stored inline, so it is `Copy`, compares and orders
/// byte-wise (deterministic on every node, which the gateway tie-breaks need),
/// and two vendors collide only by claiming the same DNS namespace — the
/// identity *is* the name, there is no hash to collide.
///
/// Grammar: 2+ dot-separated labels, each 1–63 of `[a-z0-9-]` not starting or
/// ending with `-`; total ≤ [`EXT_NAME_MAX`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtProtocolId {
    /// Zero-padded; NUL never occurs in a valid name, so byte order = name order.
    bytes: [u8; EXT_NAME_MAX],
}

/// Why a name is not a valid extension id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtIdError {
    TooLong,
    /// Fewer than two labels: not namespaced (also every unknown in-tree-style name).
    NotNamespaced,
    BadLabel,
}

impl std::fmt::Display for ExtIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ExtIdError::TooLong => "extension family name longer than 64 bytes",
            ExtIdError::NotNamespaced => "not an in-tree family, and not a reverse-DNS extension name",
            ExtIdError::BadLabel => "extension name labels must be 1-63 of [a-z0-9-], no leading/trailing '-'",
        })
    }
}

impl std::error::Error for ExtIdError {}

impl ExtProtocolId {
    pub fn parse(name: &str) -> Result<Self, ExtIdError> {
        if name.len() > EXT_NAME_MAX {
            return Err(ExtIdError::TooLong);
        }
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() < 2 {
            return Err(ExtIdError::NotNamespaced);
        }
        for l in labels {
            let ok = (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-');
            if !ok {
                return Err(ExtIdError::BadLabel);
            }
        }
        let mut bytes = [0u8; EXT_NAME_MAX];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self { bytes })
    }

    pub fn as_str(&self) -> &str {
        let n = self.bytes.iter().position(|b| *b == 0).unwrap_or(EXT_NAME_MAX);
        std::str::from_utf8(&self.bytes[..n]).expect("validated ASCII at parse")
    }
}

impl std::fmt::Debug for ExtProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ext({})", self.as_str())
    }
}

/// A004 axis 1 — what the protocol rides on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Carrier {
    /// Raw L2 Ethernet frames (AVTP).
    L2Ethernet,
    /// IP/UDP (unicast and/or multicast per [`FanOut`]).
    Udp,
    /// TCP.
    Tcp,
    /// A dedicated point-to-point physical link (coax/fiber/USB).
    PointToPoint,
}

/// A004 axis 2 — how peers find each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Discovery {
    /// Multicast announce (Link).
    MulticastAnnounce,
    /// mDNS / DNS-SD.
    Mdns,
    /// SDP files handed around by hand ("sneakernet" AES67) and/or SAP.
    SdpSap,
    /// None — a cable is the session.
    Manual,
}

/// A004 axis 3 — the media-clock reference. **The hard axis.** Only the
/// disciplined references share a rate with anything; everything else is
/// receiver-side adaptive resampling (A003 §2, R010-F4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockRef {
    /// IEEE-1588 v1 (native Dante).
    PtpV1,
    /// IEEE-1588 v2 (AES67 / RAVENNA / ST 2110).
    PtpV2,
    /// 802.1AS generalized PTP (AVB / Milan).
    Gptp,
    /// Clock embedded in the physical link (MADI) — disciplined, but only to the
    /// device on the other end of the cable.
    Embedded,
    /// Link's musical beat clock: slope fixed at 1, offset re-measured every
    /// 30 s. Schedules samples, **disciplines no rate**.
    LinkBeat,
    /// Free-running sender; receiver resamples (JackTrip family, NDI timestamps).
    FreeRun,
    /// Carries no media, so no media clock (plain Link).
    None,
}

impl ClockRef {
    /// Whether two peers on this reference run at the *same* rate (ppm drift
    /// bounded by the reference) — i.e. a shared-domain leg needs only
    /// near-unity ASRC. `false` means divergence accumulates without bound and
    /// the leg needs adaptive resampling however nominal rates agree.
    pub fn disciplines_rate(&self) -> bool {
        matches!(self, ClockRef::PtpV1 | ClockRef::PtpV2 | ClockRef::Gptp | ClockRef::Embedded)
    }

    /// Whether the reference is a *network* clock two peers can both be slaved
    /// to. `Embedded` disciplines rate but only across one cable: two MADI links
    /// are two domains, so it never counts as shared.
    pub fn is_network_domain(&self) -> bool {
        matches!(self, ClockRef::PtpV1 | ClockRef::PtpV2 | ClockRef::Gptp)
    }
}

/// A004 axis 4 — how channels are identified on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Channelization {
    /// Discrete channels addressed by index (AES67, MADI slots, USB).
    DiscreteIndexed,
    /// Discrete channels/flows addressed by human name (Dante).
    DiscreteNamed,
    /// Many channels multiplexed on one stream, indexed (MADI: 64/link).
    Muxed { channels: u16 },
    /// Carries no channels (sync-only protocols).
    None,
}

impl Channelization {
    /// Named vs indexed — the A004 axis-8 semantic the degrade rule drops
    /// (named → indexed) when the sink cannot carry names.
    pub fn is_named(&self) -> bool {
        matches!(self, Channelization::DiscreteNamed)
    }
}

/// A004 axis 5 — the sample formats a protocol (or a peer, see
/// [`crate::capability::ProtocolCapability`]) can carry. A set, not an enum: a
/// protocol commonly offers several.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct SampleFormats {
    pub pcm_i16: bool,
    pub pcm_i24: bool,
    pub pcm_i32: bool,
    pub pcm_f32: bool,
    pub opus: bool,
    pub flac: bool,
}

impl SampleFormats {
    pub const NONE: SampleFormats = SampleFormats {
        pcm_i16: false,
        pcm_i24: false,
        pcm_i32: false,
        pcm_f32: false,
        opus: false,
        flac: false,
    };
    /// The uncompressed pro-AoIP set (L16/L24/L32).
    pub const PCM_INT: SampleFormats = SampleFormats { pcm_i16: true, pcm_i24: true, pcm_i32: true, ..Self::NONE };
    pub const PCM_I16_ONLY: SampleFormats = SampleFormats { pcm_i16: true, ..Self::NONE };

    /// Formats both sets carry — the passthrough set between two peers.
    pub fn intersect(&self, o: &SampleFormats) -> SampleFormats {
        SampleFormats {
            pcm_i16: self.pcm_i16 && o.pcm_i16,
            pcm_i24: self.pcm_i24 && o.pcm_i24,
            pcm_i32: self.pcm_i32 && o.pcm_i32,
            pcm_f32: self.pcm_f32 && o.pcm_f32,
            opus: self.opus && o.opus,
            flac: self.flac && o.flac,
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }

    /// Is `o` a subset of `self`? A peer may advertise only formats its
    /// protocol defines (`ProtocolCaps::validate`).
    pub fn contains(&self, o: &SampleFormats) -> bool {
        self.intersect(o) == *o
    }
}

/// A004 axis 6 — framing on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Framing {
    /// RTP (AES67, Dante-in-AES67-mode).
    Rtp,
    /// IEEE 1722 AVTP (AVB: AM824 / AAF).
    Avtp,
    /// Link's own chunk records (LinkAudio, link-wire-spec ch.03 §5).
    LinkChunk,
    /// MADI's fixed 64-slot frame.
    MadiFrame,
    /// USB isochronous transfers.
    UsbIsochronous,
    /// Vendor-proprietary headers (native Dante, NDI, JackTrip family).
    Proprietary,
    /// No media framing (sync-only).
    None,
}

/// A004 axis 6 (cont.) — packetization: frames per packet and mux vs discrete.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Packetization {
    pub framing: Framing,
    /// Frames (samples per channel) per packet, where the protocol fixes or
    /// customarily uses one. `None` = negotiated per stream / not applicable.
    pub frames_per_packet: Option<u16>,
    /// One stream carries many channels (mux) rather than one channel each.
    pub mux: bool,
}

/// A004 axis 9 — how a talker reaches more than one listener.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FanOut {
    /// Native IP multicast.
    Multicast,
    /// Listener subscribes to a talker's flow (Dante TX/RX).
    Subscription,
    /// Reserved streams on a TSN fabric (AVB SRP).
    ReservedStream,
    /// Unicast per listener.
    Unicast,
    /// Not applicable (one cable, one listener).
    None,
}

/// Rough latency class per A004 axis 7 — enough for policy to rank a leg, not a
/// measurement (that is `transport::LinkQuality`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LatencyClass {
    /// Sub-millisecond (AVB, MADI, USB).
    SubMs,
    /// Low single-digit ms (Dante, AES67).
    Ms,
    /// Tens to hundreds of ms (JackTrip family, NDI, LinkAudio's chunk schedule).
    Tens,
}

/// One registry row: a protocol as a point in A004's axis-space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtocolProfile {
    pub id: ProtocolId,
    /// Stable string identity shared with `ipauro_proto::registry::ProtocolPorts::name`.
    pub name: &'static str,
    pub carrier: Carrier,
    pub discovery: Discovery,
    pub clock: ClockRef,
    pub channelization: Channelization,
    /// Formats the *protocol* defines. A peer advertises a subset.
    pub formats: SampleFormats,
    /// Sample rates the protocol defines. Empty = carries no media.
    pub rates_hz: &'static [u32],
    pub packetization: Packetization,
    pub fan_out: FanOut,
    pub latency: LatencyClass,
}

impl ProtocolProfile {
    /// Carries samples at all (plain Link does not).
    pub fn carries_media(&self) -> bool {
        !self.formats.is_empty()
    }
}

const PRO_RATES: &[u32] = &[44_100, 48_000, 88_200, 96_000, 176_400, 192_000];
const STD_RATES: &[u32] = &[44_100, 48_000, 96_000];

/// The registry. One row per [`ProtocolId`]; [`ProtocolId::ALL`] order.
pub const PROFILES: [ProtocolProfile; 9] = [
    ProtocolProfile {
        id: ProtocolId::Link,
        name: "ableton-link",
        carrier: Carrier::Udp,
        discovery: Discovery::MulticastAnnounce,
        clock: ClockRef::None,
        channelization: Channelization::None,
        formats: SampleFormats::NONE,
        rates_hz: &[],
        packetization: Packetization { framing: Framing::None, frames_per_packet: None, mux: false },
        fan_out: FanOut::Multicast,
        latency: LatencyClass::Tens,
    },
    ProtocolProfile {
        id: ProtocolId::LinkAudio,
        name: "link-audio",
        carrier: Carrier::Udp,
        discovery: Discovery::MulticastAnnounce,
        clock: ClockRef::LinkBeat,
        channelization: Channelization::DiscreteIndexed,
        formats: SampleFormats::PCM_I16_ONLY,
        // Declared per stream and NOMINAL (no rate discipline); 48 k is the One Rate.
        rates_hz: STD_RATES,
        packetization: Packetization { framing: Framing::LinkChunk, frames_per_packet: None, mux: false },
        fan_out: FanOut::Multicast,
        latency: LatencyClass::Tens,
    },
    ProtocolProfile {
        id: ProtocolId::Dante,
        name: "dante",
        carrier: Carrier::Udp,
        discovery: Discovery::Mdns,
        clock: ClockRef::PtpV1,
        channelization: Channelization::DiscreteNamed,
        formats: SampleFormats::PCM_INT,
        rates_hz: PRO_RATES,
        packetization: Packetization { framing: Framing::Proprietary, frames_per_packet: None, mux: true },
        fan_out: FanOut::Subscription,
        latency: LatencyClass::Ms,
    },
    ProtocolProfile {
        id: ProtocolId::Aes67,
        name: "aes67",
        carrier: Carrier::Udp,
        discovery: Discovery::SdpSap,
        clock: ClockRef::PtpV2,
        channelization: Channelization::DiscreteIndexed,
        formats: SampleFormats { pcm_i16: true, pcm_i24: true, ..SampleFormats::NONE },
        rates_hz: &[48_000, 96_000],
        // AES67 fixes the 1 ms packet time: 48 frames at 48 kHz.
        packetization: Packetization { framing: Framing::Rtp, frames_per_packet: Some(48), mux: true },
        fan_out: FanOut::Multicast,
        latency: LatencyClass::Ms,
    },
    ProtocolProfile {
        id: ProtocolId::Avb,
        name: "avb",
        carrier: Carrier::L2Ethernet,
        discovery: Discovery::Mdns,
        clock: ClockRef::Gptp,
        channelization: Channelization::DiscreteIndexed,
        formats: SampleFormats::PCM_INT,
        rates_hz: PRO_RATES,
        // Class A: 8 kHz observation interval → 6 frames at 48 kHz.
        packetization: Packetization { framing: Framing::Avtp, frames_per_packet: Some(6), mux: true },
        fan_out: FanOut::ReservedStream,
        latency: LatencyClass::SubMs,
    },
    ProtocolProfile {
        id: ProtocolId::Madi,
        name: "madi",
        carrier: Carrier::PointToPoint,
        discovery: Discovery::Manual,
        clock: ClockRef::Embedded,
        channelization: Channelization::Muxed { channels: 64 },
        formats: SampleFormats { pcm_i24: true, ..SampleFormats::NONE },
        rates_hz: PRO_RATES,
        packetization: Packetization { framing: Framing::MadiFrame, frames_per_packet: Some(1), mux: true },
        fan_out: FanOut::None,
        latency: LatencyClass::SubMs,
    },
    ProtocolProfile {
        id: ProtocolId::Ndi,
        name: "ndi",
        carrier: Carrier::Tcp,
        discovery: Discovery::Mdns,
        clock: ClockRef::FreeRun,
        channelization: Channelization::DiscreteIndexed,
        formats: SampleFormats { pcm_i16: true, pcm_f32: true, ..SampleFormats::NONE },
        rates_hz: STD_RATES,
        packetization: Packetization { framing: Framing::Proprietary, frames_per_packet: None, mux: true },
        fan_out: FanOut::Unicast,
        latency: LatencyClass::Tens,
    },
    ProtocolProfile {
        id: ProtocolId::JackTrip,
        name: "jacktrip",
        carrier: Carrier::Udp,
        discovery: Discovery::Manual,
        clock: ClockRef::FreeRun,
        channelization: Channelization::DiscreteIndexed,
        formats: SampleFormats { pcm_i16: true, pcm_i24: true, pcm_i32: true, pcm_f32: true, opus: true, ..SampleFormats::NONE },
        rates_hz: STD_RATES,
        packetization: Packetization { framing: Framing::Proprietary, frames_per_packet: None, mux: true },
        fan_out: FanOut::Unicast,
        latency: LatencyClass::Tens,
    },
    ProtocolProfile {
        id: ProtocolId::UsbAudio,
        name: "usb-audio",
        carrier: Carrier::PointToPoint,
        discovery: Discovery::Manual,
        // Async feedback endpoint: the host disciplines to the device clock.
        clock: ClockRef::Embedded,
        channelization: Channelization::DiscreteIndexed,
        formats: SampleFormats { pcm_i16: true, pcm_i24: true, pcm_i32: true, ..SampleFormats::NONE },
        rates_hz: PRO_RATES,
        packetization: Packetization { framing: Framing::UsbIsochronous, frames_per_packet: None, mux: true },
        fan_out: FanOut::None,
        latency: LatencyClass::SubMs,
    },
];

/// The in-tree registry row for `id`, `None` for an extension family (whose
/// row is gossiped data — resolve it through a [`Profiles`] view).
pub fn in_tree(id: ProtocolId) -> Option<&'static ProtocolProfile> {
    PROFILES.iter().find(|p| p.id == id)
}

/// The in-tree registry row for `id`. Total over the in-tree variants
/// (`tests::every_protocol_has_exactly_one_profile`); **panics on
/// [`ProtocolId::Ext`]** — code that may meet an extension family resolves
/// rows through [`Profiles`] instead.
#[track_caller]
pub fn profile(id: ProtocolId) -> &'static ProtocolProfile {
    in_tree(id).expect("profile() is in-tree only; resolve extension families through `Profiles`")
}

/// An adapter-declared registry row (R003-F7): the same declarative axes as a
/// [`ProtocolProfile`], owned, so it can travel in gossip. Carried by the
/// declaring node's [`ProtocolCapability`](crate::capability::ProtocolCapability).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtProfile {
    pub id: ExtProtocolId,
    pub carrier: Carrier,
    pub discovery: Discovery,
    pub clock: ClockRef,
    pub channelization: Channelization,
    pub formats: SampleFormats,
    pub rates_hz: Vec<u32>,
    pub packetization: Packetization,
    pub fan_out: FanOut,
    pub latency: LatencyClass,
}

/// A registry row, wherever it came from. Consumers read axes through this,
/// so an extension family is indistinguishable from an in-tree one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Row<'a> {
    InTree(&'static ProtocolProfile),
    Ext(&'a ExtProfile),
}

impl Row<'_> {
    pub fn clock(&self) -> ClockRef {
        match self {
            Row::InTree(p) => p.clock,
            Row::Ext(p) => p.clock,
        }
    }
    pub fn formats(&self) -> SampleFormats {
        match self {
            Row::InTree(p) => p.formats,
            Row::Ext(p) => p.formats,
        }
    }
    pub fn rates_hz(&self) -> &[u32] {
        match self {
            Row::InTree(p) => p.rates_hz,
            Row::Ext(p) => &p.rates_hz,
        }
    }
    pub fn carries_media(&self) -> bool {
        !self.formats().is_empty()
    }
}

/// Something that can produce the row for a protocol id: the in-tree table
/// alone ([`InTree`]), one node's capabilities, or the whole gossiped view.
pub trait Profiles {
    fn row(&self, id: ProtocolId) -> Option<Row<'_>>;
}

/// The in-tree registry only; knows no extension family.
pub struct InTree;

impl Profiles for InTree {
    fn row(&self, id: ProtocolId) -> Option<Row<'_>> {
        in_tree(id).map(Row::InTree)
    }
}

/// Stable one-byte wire codes for the row axes — shared by the gossip codec
/// and the stream socket's family declaration, so the two never disagree.
/// Every table is an exhaustive `match` both ways' source of truth.
macro_rules! wire_codes {
    ($t:ident { $($v:ident = $c:literal),+ $(,)? }) => {
        impl $t {
            pub fn code(self) -> u8 {
                match self { $($t::$v => $c),+ }
            }
            pub fn from_code(c: u8) -> Option<Self> {
                match c { $($c => Some($t::$v),)+ _ => None }
            }
        }
    };
}

wire_codes!(Carrier { L2Ethernet = 0, Udp = 1, Tcp = 2, PointToPoint = 3 });
wire_codes!(Discovery { MulticastAnnounce = 0, Mdns = 1, SdpSap = 2, Manual = 3 });
wire_codes!(ClockRef { PtpV1 = 0, PtpV2 = 1, Gptp = 2, Embedded = 3, LinkBeat = 4, FreeRun = 5, None = 6 });
wire_codes!(Framing { Rtp = 0, Avtp = 1, LinkChunk = 2, MadiFrame = 3, UsbIsochronous = 4, Proprietary = 5, None = 6 });
wire_codes!(FanOut { Multicast = 0, Subscription = 1, ReservedStream = 2, Unicast = 3, None = 4 });
wire_codes!(LatencyClass { SubMs = 0, Ms = 1, Tens = 2 });

impl Channelization {
    /// `(code, muxed channel count)`; the count is 0 except for `Muxed`.
    pub fn code(self) -> (u8, u16) {
        match self {
            Channelization::DiscreteIndexed => (0, 0),
            Channelization::DiscreteNamed => (1, 0),
            Channelization::Muxed { channels } => (2, channels),
            Channelization::None => (3, 0),
        }
    }
    pub fn from_code(c: u8, channels: u16) -> Option<Self> {
        Some(match c {
            0 => Channelization::DiscreteIndexed,
            1 => Channelization::DiscreteNamed,
            2 => Channelization::Muxed { channels },
            3 => Channelization::None,
            _ => return None,
        })
    }
}

impl SampleFormats {
    /// Bitmask: i16, i24, i32, f32, opus, flac = bits 0..5.
    pub fn bits(&self) -> u8 {
        [self.pcm_i16, self.pcm_i24, self.pcm_i32, self.pcm_f32, self.opus, self.flac]
            .iter()
            .enumerate()
            .fold(0, |acc, (i, b)| acc | ((*b as u8) << i))
    }
    pub fn from_bits(b: u8) -> Self {
        let bit = |i: u8| b & (1 << i) != 0;
        SampleFormats { pcm_i16: bit(0), pcm_i24: bit(1), pcm_i32: bit(2), pcm_f32: bit(3), opus: bit(4), flac: bit(5) }
    }
}

/// What a transcode leg between two protocols must do about clock — the input
/// R010-F4 consumes, derived from profiles alone (never from protocol identity).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClockBridge {
    /// Same network reference both sides (PTPv2 ↔ PTPv2, …): rates agree to
    /// within the reference's ppm; near-unity ASRC only (A001 R005-T9 gotcha).
    /// Best case from profiles alone — whether the two peers sit in the same PTP
    /// *domain number* is the per-peer `capability::ClockDomain` check.
    SharedDomain,
    /// Two different disciplined references (PTPv1 vs gPTP, …): mutually
    /// incompatible, so either a boundary clock or ASRC between two steady rates.
    CrossDomain,
    /// At least one side disciplines no rate (LinkBeat, FreeRun): divergence is
    /// unbounded; adaptive resampling at the receiver is the only robust answer.
    Adaptive,
    /// At least one side carries no media; there is no leg to bridge.
    NoMedia,
    /// No row is visible for one side (an extension family nobody in view
    /// declares), so the relationship cannot be classified.
    Unknown,
}

/// Classify the clock relationship of a leg between two **in-tree** protocols.
/// Code that may meet an extension family uses [`clock_bridge_in`].
pub fn clock_bridge(from: ProtocolId, to: ProtocolId) -> ClockBridge {
    clock_bridge_in(&InTree, from, to)
}

/// Classify the clock relationship of a leg from `from`'s protocol into `to`'s,
/// reading both rows from `rows`.
pub fn clock_bridge_in(rows: &dyn Profiles, from: ProtocolId, to: ProtocolId) -> ClockBridge {
    let (Some(a), Some(b)) = (rows.row(from), rows.row(to)) else {
        return ClockBridge::Unknown;
    };
    if !a.carries_media() || !b.carries_media() {
        return ClockBridge::NoMedia;
    }
    let (ca, cb) = (a.clock(), b.clock());
    match (ca.disciplines_rate(), cb.disciplines_rate()) {
        (true, true) if ca == cb && ca.is_network_domain() => ClockBridge::SharedDomain,
        (true, true) => ClockBridge::CrossDomain,
        // One or both undisciplined.
        _ => ClockBridge::Adaptive,
    }
}
