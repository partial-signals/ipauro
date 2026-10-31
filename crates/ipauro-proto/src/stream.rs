//! The **stream facet** of the IPC surface (R003-F7): a binary, length-prefixed
//! framed protocol on a second unix socket, carrying canonical audio streams
//! between the brain service and out-of-process adapters / mixing apps.
//!
//! `@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)` —
//! §2 canonical stream model + two-tier adapter locus.
//! `@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — R002-T7:
//! the JSON control facet ([`crate::ipc`]) stays the place for discovery and
//! commands; **frames never travel through the JSON event stream**.
//!
//! # Licensing: IPC is not linking
//!
//! This socket is the sanctioned surface for **any-license sidecars** (A004 §2,
//! second tier). A closed-source vendor can add a protocol family, or consume
//! and publish streams, without linking IPAuRo's GPL core. The protocol is
//! therefore fully specified below; this comment is the normative spec and a
//! vendor must be able to implement it from this text alone.
//!
//! # Endpoint
//!
//! `<control socket path>.stream` (see [`stream_socket_path`]), same directory,
//! mode `0600`, same per-user trust model as the control socket.
//!
//! # Framing
//!
//! All integers are **little-endian**. Every message, both directions, is one
//! frame:
//!
//! | offset | size | field                                              |
//! |--------|------|----------------------------------------------------|
//! | 0      | 4    | `len: u32` = 1 + payload length (excludes itself)  |
//! | 4      | 1    | `kind: u8` (table below)                           |
//! | 5      | len-1| payload                                            |
//!
//! `len` must be in `1..=MAX_FRAME_LEN`; anything else is malformed. A
//! malformed frame closes **that** connection only (after a best-effort
//! [`Msg::Error`]); other clients are unaffected.
//!
//! Composite payload fields: `str16` = `u16 n` + `n` bytes UTF-8.
//!
//! # Handshake
//!
//! The client's first frame MUST be `Hello`; the server always answers
//! `HelloAck` (even on mismatch, so the client learns the server's version),
//! then closes if `accepted == 0`. Mirrors the control facet's client-identity
//! rule: every connection names itself.
//!
//! # Messages
//!
//! | kind | name        | dir | payload                                                        |
//! |------|-------------|-----|----------------------------------------------------------------|
//! | 0x01 | Hello       | c→s | `magic[4]="IPAS"`, `version u16`, `client str16`               |
//! | 0x02 | HelloAck    | s→c | `magic[4]`, `version u16`, `accepted u8`, `server str16`       |
//! | 0x10 | Register    | c→s | `request u32`, `Descriptor`                                    |
//! | 0x11 | Unregister  | c→s | `stream u32`                                                   |
//! | 0x12 | Subscribe   | c→s | `stream u32`, `queue_depth u16` (0 = server default)           |
//! | 0x13 | Unsubscribe | c→s | `stream u32`                                                   |
//! | 0x14 | List        | c→s | (empty)                                                        |
//! | 0x1A | DeclareFamily | c→s | `FamilyDecl`                                                 |
//! | 0x1B | FamilyDeclared| s→c | `name str16`                                                 |
//! | 0x15 | Registered  | s→c | `request u32`, `stream u32`, `StreamInfo`                      |
//! | 0x16 | StreamList  | s→c | `count u16`, `count ×` (`stream u32`, `StreamInfo`)            |
//! | 0x17 | Subscribed  | s→c | `stream u32`, `StreamInfo`                                     |
//! | 0x18 | Overrun     | s→c | `stream u32`, `dropped_total u64`                              |
//! | 0x19 | StreamEnded | s→c | `stream u32`                                                   |
//! | 0x20 | Data        | both| `stream u32`, `seq u64`, `timestamp u64`, `frames u32`, `pcm…` |
//! | 0x7F | Error       | s→c | `code u16`, `message str16`                                    |
//!
//! **Descriptor** (the canonical stream descriptor, A004 §2 `identity`/`signal`/`clock`):
//!
//! | size  | field                                                                |
//! |-------|----------------------------------------------------------------------|
//! | str16 | `name`                                                               |
//! | str16 | `protocol` — family this stream comes from / adds; `""` = none       |
//! | 1     | `payload`: 0 = sync-only (no samples), 1 = PCM                       |
//! | 2     | `channels u16`                                                       |
//! | 1     | `sample_format`: 1 = i16, 2 = i24 (3 bytes packed), 3 = i32, 4 = f32 |
//! | 4     | `nominal_rate_hz u32`                                                |
//! | 1     | `clock kind`: 0 FreeRun, 1 Ptp, 2 TransportNative, 3 LinkBeat, 4 Host|
//! | 1     | `clock arg` (PTP domain number for kind 1, else 0)                   |
//! | 1     | `role`: bit0 = source (client publishes), bit1 = sink (client consumes) |
//!
//! `protocol` is an in-tree family name (`dante`, `aes67`, …) or an extension
//! family this server currently knows from a `DeclareFamily`; anything else is
//! refused with error 5.
//!
//! **StreamInfo** = `Descriptor`, then `flags u8` (bit0 = rate mismatch: a PCM
//! stream whose nominal rate differs from the adopted mesh rate per R003-F8's
//! cascade — accepted, not resampled; R010-F4 owns ASRC; other bits reserved,
//! 0), then `mesh_rate_hz u32`.
//!
//! # Adding a protocol family (closed-source adapters)
//!
//! An adapter adds a family to the mesh by declaring its **registry row**; the
//! node then gossips it to every peer exactly as it does an in-tree family, so
//! the gateway planner treats it as an island or a translatable leg. The
//! declaration lives as long as the declaring connection: disconnect retracts
//! it on the node's next gossip record.
//!
//! The name is the family's permanent identity: a **reverse-DNS name** under a
//! domain the vendor controls (`com.acme.netaudio`) — 2+ dot-separated labels
//! of `[a-z0-9-]` (1–63 each, no leading/trailing `-`), at most 64 bytes.
//! In-tree names contain no `.`, so the spaces cannot collide. One connection
//! at a time may hold a name.
//!
//! **FamilyDecl**:
//!
//! | size  | field |
//! |-------|-------|
//! | str16 | `name` |
//! | 1     | `carrier`: 0 L2 Ethernet, 1 UDP, 2 TCP, 3 point-to-point |
//! | 1     | `discovery`: 0 multicast announce, 1 mDNS, 2 SDP/SAP, 3 manual |
//! | 1     | `clock_ref`: 0 PTPv1, 1 PTPv2, 2 gPTP, 3 embedded, 4 Link beat, 5 free-run, 6 none |
//! | 1     | `channelization`: 0 discrete indexed, 1 discrete named, 2 muxed, 3 none |
//! | 2     | `muxed_channels u16` (0 unless channelization = 2) |
//! | 1     | `formats` bitmask: bit0 i16, 1 i24, 2 i32, 3 f32, 4 opus, 5 flac (0 = sync-only) |
//! | 2+4n  | `rates`: `u16 n`, then `n × u32` Hz |
//! | 1     | `framing`: 0 RTP, 1 AVTP, 2 Link chunk, 3 MADI frame, 4 USB isochronous, 5 proprietary, 6 none |
//! | 2     | `frames_per_packet u16` (0 = negotiated / n.a.) |
//! | 1     | `mux` (0/1): one stream carries many channels |
//! | 1     | `fan_out`: 0 multicast, 1 subscription, 2 reserved stream, 3 unicast, 4 none |
//! | 1     | `latency`: 0 sub-ms, 1 ms, 2 tens of ms |
//! | 1     | `verbs` bitmask: bit0 pass, 1 sink, 2 source, 3 fan-in, 4 fan-out |
//! | 2+…   | `translates_to`: `u16 n`, then `n × str16` family names (this family → that) |
//! | 2+…   | `translates_from`: `u16 n`, then `n × str16` (that family → this) |
//!
//! A translation is only honoured mesh-wide if this node also speaks the other
//! end (an in-tree adapter, a stream registered for it, or another declared
//! family).
//!
//! **Data**: `pcm` is interleaved samples, `frames × channels × bytes(format)`
//! bytes exactly (a mismatch is malformed); for a sync-only stream `frames` may
//! be anything and `pcm` is empty. `seq` is the producer's monotonically
//! increasing sequence number; gaps seen by a subscriber are frames the server
//! dropped. `timestamp` is in the stream's own clock domain (opaque to the
//! server; e.g. sample time). A producer sends Data only for streams it
//! registered as source; the server forwards the identical frame to each
//! subscriber.
//!
//! # Delivery policy (live audio)
//!
//! The server never blocks a producer and never grows a queue without bound:
//! each subscriber connection has a bounded queue; when it is full the
//! **oldest** queued Data frame is dropped and counted against its stream, and
//! the subscriber receives an `Overrun` with the running total before its next
//! Data frame for that stream.
//!
//! Seam: v1 carries PCM in-band over this socket. A later version may negotiate
//! a shared-memory ring (a new Hello capability + a descriptor of the mapping),
//! leaving these frames as the control/fallback path. Not built.
//!
//! # Error codes
//!
//! `1` malformed frame (fatal), `2` version mismatch (fatal), `3` unknown
//! stream, `4` not the stream's owner (fatal), `5` invalid descriptor.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Handshake magic: ASCII "IPAS" (IPAuRo Stream).
pub const MAGIC: [u8; 4] = *b"IPAS";
/// Version of this stream protocol (independent of [`crate::PROTOCOL_VERSION`]).
pub const STREAM_PROTOCOL_VERSION: u16 = 1;
/// Largest legal `len` (kind byte + payload).
pub const MAX_FRAME_LEN: u32 = 1 << 20;
/// Server default per-subscriber queue depth, in frames.
pub const DEFAULT_QUEUE_DEPTH: u16 = 64;

pub const ERR_MALFORMED: u16 = 1;
pub const ERR_VERSION: u16 = 2;
pub const ERR_UNKNOWN_STREAM: u16 = 3;
pub const ERR_NOT_OWNER: u16 = 4;
pub const ERR_INVALID_DESCRIPTOR: u16 = 5;

pub const FLAG_RATE_MISMATCH: u8 = 1 << 0;

pub const ROLE_SOURCE: u8 = 1 << 0;
pub const ROLE_SINK: u8 = 1 << 1;

/// The stream socket that sits beside `control` (`<control>.stream`).
pub fn stream_socket_path(control: &Path) -> PathBuf {
    let mut s = control.as_os_str().to_owned();
    s.push(".stream");
    PathBuf::from(s)
}

/// What a stream carries — a declarative payload capability, mirroring
/// `ProtocolProfile::carries_media` (R003-F8): only PCM streams take part in
/// the rate policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Payload {
    SyncOnly,
    Pcm,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SampleFormat {
    I16,
    I24,
    I32,
    F32,
}

impl SampleFormat {
    pub fn bytes(self) -> usize {
        match self {
            SampleFormat::I16 => 2,
            SampleFormat::I24 => 3,
            SampleFormat::I32 | SampleFormat::F32 => 4,
        }
    }
}

/// The stream's media-clock domain (A004 §2 `clock`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clock {
    FreeRun,
    Ptp(u8),
    TransportNative,
    LinkBeat,
    Host,
}

/// The canonical stream descriptor as it crosses the wire.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descriptor {
    pub name: String,
    /// Protocol family name (joins `ProtocolProfile::name`); empty = none.
    pub protocol: String,
    pub payload: Payload,
    pub channels: u16,
    pub sample_format: SampleFormat,
    pub nominal_rate_hz: u32,
    pub clock: Clock,
    /// [`ROLE_SOURCE`] / [`ROLE_SINK`] bits.
    pub role: u8,
}

impl Descriptor {
    /// Exact PCM byte length of a Data frame carrying `frames` frames.
    pub fn pcm_len(&self, frames: u32) -> Option<usize> {
        match self.payload {
            Payload::SyncOnly => Some(0),
            Payload::Pcm => (frames as usize)
                .checked_mul(self.channels as usize)?
                .checked_mul(self.sample_format.bytes()),
        }
    }
}

/// A descriptor plus the server's verdict on it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StreamInfo {
    pub descriptor: Descriptor,
    pub flags: u8,
    pub mesh_rate_hz: u32,
}

impl StreamInfo {
    pub fn rate_mismatch(&self) -> bool {
        self.flags & FLAG_RATE_MISMATCH != 0
    }
}

/// An adapter's registry row for a family it adds (raw wire codes, tabled in
/// the module doc; the server maps them onto the mesh registry types).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FamilyDecl {
    pub name: String,
    pub carrier: u8,
    pub discovery: u8,
    pub clock_ref: u8,
    pub channelization: u8,
    pub muxed_channels: u16,
    pub formats: u8,
    pub rates_hz: Vec<u32>,
    pub framing: u8,
    pub frames_per_packet: u16,
    pub mux: bool,
    pub fan_out: u8,
    pub latency: u8,
    pub verbs: u8,
    pub translates_to: Vec<String>,
    pub translates_from: Vec<String>,
}

pub const VERB_PASS: u8 = 1 << 0;
pub const VERB_SINK: u8 = 1 << 1;
pub const VERB_SOURCE: u8 = 1 << 2;
pub const VERB_FAN_IN: u8 = 1 << 3;
pub const VERB_FAN_OUT: u8 = 1 << 4;

/// Every message on the stream socket.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Msg {
    Hello { version: u16, client: String },
    HelloAck { version: u16, accepted: bool, server: String },
    Register { request: u32, descriptor: Descriptor },
    Unregister { stream: u32 },
    Subscribe { stream: u32, queue_depth: u16 },
    Unsubscribe { stream: u32 },
    List,
    DeclareFamily(FamilyDecl),
    FamilyDeclared { name: String },
    Registered { request: u32, stream: u32, info: StreamInfo },
    StreamList { streams: Vec<(u32, StreamInfo)> },
    Subscribed { stream: u32, info: StreamInfo },
    Overrun { stream: u32, dropped_total: u64 },
    StreamEnded { stream: u32 },
    Data { stream: u32, seq: u64, timestamp: u64, frames: u32, pcm: Vec<u8> },
    Error { code: u16, message: String },
}

const K_HELLO: u8 = 0x01;
const K_HELLO_ACK: u8 = 0x02;
const K_REGISTER: u8 = 0x10;
const K_UNREGISTER: u8 = 0x11;
const K_SUBSCRIBE: u8 = 0x12;
const K_UNSUBSCRIBE: u8 = 0x13;
const K_LIST: u8 = 0x14;
const K_DECLARE_FAMILY: u8 = 0x1A;
const K_FAMILY_DECLARED: u8 = 0x1B;
const K_REGISTERED: u8 = 0x15;
const K_STREAM_LIST: u8 = 0x16;
const K_SUBSCRIBED: u8 = 0x17;
const K_OVERRUN: u8 = 0x18;
const K_STREAM_ENDED: u8 = 0x19;
/// Kind byte of a Data frame (exposed so a forwarder can route raw frames).
pub const K_DATA: u8 = 0x20;
const K_ERROR: u8 = 0x7F;

/// Why a frame failed to decode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("frame length {0} out of range")]
    BadLength(u32),
    #[error("truncated payload")]
    Truncated,
    #[error("trailing bytes after payload")]
    Trailing,
    #[error("unknown message kind 0x{0:02x}")]
    UnknownKind(u8),
    #[error("bad magic")]
    BadMagic,
    #[error("invalid {0} value {1}")]
    BadEnum(&'static str, u8),
    #[error("string is not UTF-8")]
    Utf8,
    #[error("string too long")]
    StringTooLong,
}

// ---- encoding ------------------------------------------------------------

fn put_str(b: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(u16::MAX as usize);
    b.extend_from_slice(&(n as u16).to_le_bytes());
    b.extend_from_slice(&bytes[..n]);
}

fn put_descriptor(b: &mut Vec<u8>, d: &Descriptor) {
    put_str(b, &d.name);
    put_str(b, &d.protocol);
    b.push(match d.payload {
        Payload::SyncOnly => 0,
        Payload::Pcm => 1,
    });
    b.extend_from_slice(&d.channels.to_le_bytes());
    b.push(match d.sample_format {
        SampleFormat::I16 => 1,
        SampleFormat::I24 => 2,
        SampleFormat::I32 => 3,
        SampleFormat::F32 => 4,
    });
    b.extend_from_slice(&d.nominal_rate_hz.to_le_bytes());
    let (k, a) = match d.clock {
        Clock::FreeRun => (0, 0),
        Clock::Ptp(n) => (1, n),
        Clock::TransportNative => (2, 0),
        Clock::LinkBeat => (3, 0),
        Clock::Host => (4, 0),
    };
    b.extend_from_slice(&[k, a, d.role]);
}

fn put_info(b: &mut Vec<u8>, i: &StreamInfo) {
    put_descriptor(b, &i.descriptor);
    b.push(i.flags);
    b.extend_from_slice(&i.mesh_rate_hz.to_le_bytes());
}

/// Encode `msg` as a complete frame (length prefix included).
pub fn encode(msg: &Msg) -> Vec<u8> {
    let mut b = vec![0u8; 4];
    match msg {
        Msg::Hello { version, client } => {
            b.push(K_HELLO);
            b.extend_from_slice(&MAGIC);
            b.extend_from_slice(&version.to_le_bytes());
            put_str(&mut b, client);
        }
        Msg::HelloAck { version, accepted, server } => {
            b.push(K_HELLO_ACK);
            b.extend_from_slice(&MAGIC);
            b.extend_from_slice(&version.to_le_bytes());
            b.push(*accepted as u8);
            put_str(&mut b, server);
        }
        Msg::Register { request, descriptor } => {
            b.push(K_REGISTER);
            b.extend_from_slice(&request.to_le_bytes());
            put_descriptor(&mut b, descriptor);
        }
        Msg::Unregister { stream } => {
            b.push(K_UNREGISTER);
            b.extend_from_slice(&stream.to_le_bytes());
        }
        Msg::Subscribe { stream, queue_depth } => {
            b.push(K_SUBSCRIBE);
            b.extend_from_slice(&stream.to_le_bytes());
            b.extend_from_slice(&queue_depth.to_le_bytes());
        }
        Msg::Unsubscribe { stream } => {
            b.push(K_UNSUBSCRIBE);
            b.extend_from_slice(&stream.to_le_bytes());
        }
        Msg::List => b.push(K_LIST),
        Msg::DeclareFamily(f) => {
            b.push(K_DECLARE_FAMILY);
            put_str(&mut b, &f.name);
            b.extend_from_slice(&[f.carrier, f.discovery, f.clock_ref, f.channelization]);
            b.extend_from_slice(&f.muxed_channels.to_le_bytes());
            b.push(f.formats);
            let n = f.rates_hz.len().min(u16::MAX as usize);
            b.extend_from_slice(&(n as u16).to_le_bytes());
            for r in &f.rates_hz[..n] {
                b.extend_from_slice(&r.to_le_bytes());
            }
            b.push(f.framing);
            b.extend_from_slice(&f.frames_per_packet.to_le_bytes());
            b.extend_from_slice(&[f.mux as u8, f.fan_out, f.latency, f.verbs]);
            for list in [&f.translates_to, &f.translates_from] {
                let n = list.len().min(u16::MAX as usize);
                b.extend_from_slice(&(n as u16).to_le_bytes());
                for name in &list[..n] {
                    put_str(&mut b, name);
                }
            }
        }
        Msg::FamilyDeclared { name } => {
            b.push(K_FAMILY_DECLARED);
            put_str(&mut b, name);
        }
        Msg::Registered { request, stream, info } => {
            b.push(K_REGISTERED);
            b.extend_from_slice(&request.to_le_bytes());
            b.extend_from_slice(&stream.to_le_bytes());
            put_info(&mut b, info);
        }
        Msg::StreamList { streams } => {
            b.push(K_STREAM_LIST);
            let n = streams.len().min(u16::MAX as usize);
            b.extend_from_slice(&(n as u16).to_le_bytes());
            for (id, info) in &streams[..n] {
                b.extend_from_slice(&id.to_le_bytes());
                put_info(&mut b, info);
            }
        }
        Msg::Subscribed { stream, info } => {
            b.push(K_SUBSCRIBED);
            b.extend_from_slice(&stream.to_le_bytes());
            put_info(&mut b, info);
        }
        Msg::Overrun { stream, dropped_total } => {
            b.push(K_OVERRUN);
            b.extend_from_slice(&stream.to_le_bytes());
            b.extend_from_slice(&dropped_total.to_le_bytes());
        }
        Msg::StreamEnded { stream } => {
            b.push(K_STREAM_ENDED);
            b.extend_from_slice(&stream.to_le_bytes());
        }
        Msg::Data { stream, seq, timestamp, frames, pcm } => {
            b.push(K_DATA);
            b.extend_from_slice(&stream.to_le_bytes());
            b.extend_from_slice(&seq.to_le_bytes());
            b.extend_from_slice(&timestamp.to_le_bytes());
            b.extend_from_slice(&frames.to_le_bytes());
            b.extend_from_slice(pcm);
        }
        Msg::Error { code, message } => {
            b.push(K_ERROR);
            b.extend_from_slice(&code.to_le_bytes());
            put_str(&mut b, message);
        }
    }
    let len = (b.len() - 4) as u32;
    b[..4].copy_from_slice(&len.to_le_bytes());
    b
}

// ---- decoding ------------------------------------------------------------

struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Truncated);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn str(&mut self) -> Result<String, WireError> {
        let n = self.u16()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| WireError::Utf8)
    }
    fn magic(&mut self) -> Result<(), WireError> {
        if self.take(4)? != MAGIC {
            return Err(WireError::BadMagic);
        }
        Ok(())
    }
    fn descriptor(&mut self) -> Result<Descriptor, WireError> {
        let name = self.str()?;
        let protocol = self.str()?;
        let payload = match self.u8()? {
            0 => Payload::SyncOnly,
            1 => Payload::Pcm,
            v => return Err(WireError::BadEnum("payload", v)),
        };
        let channels = self.u16()?;
        let sample_format = match self.u8()? {
            1 => SampleFormat::I16,
            2 => SampleFormat::I24,
            3 => SampleFormat::I32,
            4 => SampleFormat::F32,
            v => return Err(WireError::BadEnum("sample_format", v)),
        };
        let nominal_rate_hz = self.u32()?;
        let kind = self.u8()?;
        let arg = self.u8()?;
        let clock = match kind {
            0 => Clock::FreeRun,
            1 => Clock::Ptp(arg),
            2 => Clock::TransportNative,
            3 => Clock::LinkBeat,
            4 => Clock::Host,
            v => return Err(WireError::BadEnum("clock", v)),
        };
        let role = self.u8()?;
        Ok(Descriptor { name, protocol, payload, channels, sample_format, nominal_rate_hz, clock, role })
    }
    fn info(&mut self) -> Result<StreamInfo, WireError> {
        let descriptor = self.descriptor()?;
        let flags = self.u8()?;
        let mesh_rate_hz = self.u32()?;
        Ok(StreamInfo { descriptor, flags, mesh_rate_hz })
    }
    fn done(&self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

/// Decode one frame body (`kind` byte + payload, i.e. everything after the
/// length prefix).
pub fn decode(body: &[u8]) -> Result<Msg, WireError> {
    let mut c = Cur(body);
    let kind = c.u8()?;
    let msg = match kind {
        K_HELLO => {
            c.magic()?;
            Msg::Hello { version: c.u16()?, client: c.str()? }
        }
        K_HELLO_ACK => {
            c.magic()?;
            let version = c.u16()?;
            let accepted = c.u8()? != 0;
            Msg::HelloAck { version, accepted, server: c.str()? }
        }
        K_REGISTER => Msg::Register { request: c.u32()?, descriptor: c.descriptor()? },
        K_UNREGISTER => Msg::Unregister { stream: c.u32()? },
        K_SUBSCRIBE => Msg::Subscribe { stream: c.u32()?, queue_depth: c.u16()? },
        K_UNSUBSCRIBE => Msg::Unsubscribe { stream: c.u32()? },
        K_LIST => Msg::List,
        K_DECLARE_FAMILY => {
            let name = c.str()?;
            let (carrier, discovery, clock_ref, channelization) = (c.u8()?, c.u8()?, c.u8()?, c.u8()?);
            let muxed_channels = c.u16()?;
            let formats = c.u8()?;
            let n = c.u16()?;
            let rates_hz = (0..n).map(|_| c.u32()).collect::<Result<_, _>>()?;
            let framing = c.u8()?;
            let frames_per_packet = c.u16()?;
            let mux = c.u8()? != 0;
            let (fan_out, latency, verbs) = (c.u8()?, c.u8()?, c.u8()?);
            let mut names = || -> Result<Vec<String>, WireError> {
                let n = c.u16()?;
                (0..n).map(|_| c.str()).collect()
            };
            let translates_to = names()?;
            let translates_from = names()?;
            Msg::DeclareFamily(FamilyDecl {
                name,
                carrier,
                discovery,
                clock_ref,
                channelization,
                muxed_channels,
                formats,
                rates_hz,
                framing,
                frames_per_packet,
                mux,
                fan_out,
                latency,
                verbs,
                translates_to,
                translates_from,
            })
        }
        K_FAMILY_DECLARED => Msg::FamilyDeclared { name: c.str()? },
        K_REGISTERED => Msg::Registered { request: c.u32()?, stream: c.u32()?, info: c.info()? },
        K_STREAM_LIST => {
            let n = c.u16()?;
            let mut streams = Vec::with_capacity(n as usize);
            for _ in 0..n {
                streams.push((c.u32()?, c.info()?));
            }
            Msg::StreamList { streams }
        }
        K_SUBSCRIBED => Msg::Subscribed { stream: c.u32()?, info: c.info()? },
        K_OVERRUN => Msg::Overrun { stream: c.u32()?, dropped_total: c.u64()? },
        K_STREAM_ENDED => Msg::StreamEnded { stream: c.u32()? },
        K_DATA => {
            let stream = c.u32()?;
            let seq = c.u64()?;
            let timestamp = c.u64()?;
            let frames = c.u32()?;
            let pcm = std::mem::take(&mut c.0).to_vec();
            Msg::Data { stream, seq, timestamp, frames, pcm }
        }
        K_ERROR => Msg::Error { code: c.u16()?, message: c.str()? },
        k => return Err(WireError::UnknownKind(k)),
    };
    c.done()?;
    Ok(msg)
}

/// Validate a length prefix.
pub fn check_len(len: u32) -> Result<usize, WireError> {
    if len == 0 || len > MAX_FRAME_LEN {
        Err(WireError::BadLength(len))
    } else {
        Ok(len as usize)
    }
}

/// Blocking read of one frame body (for simple sync clients). `Ok(None)` on
/// clean EOF at a frame boundary.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = check_len(u32::from_le_bytes(len)).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Blocking read + decode of one message.
pub fn read_msg(r: &mut impl Read) -> io::Result<Option<Msg>> {
    match read_frame(r)? {
        None => Ok(None),
        Some(body) => decode(&body).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

/// Blocking encode + write of one message.
pub fn write_msg(w: &mut impl Write, msg: &Msg) -> io::Result<()> {
    w.write_all(&encode(msg))?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc() -> Descriptor {
        Descriptor {
            name: "mix-bus".into(),
            protocol: "dante".into(),
            payload: Payload::Pcm,
            channels: 2,
            sample_format: SampleFormat::I24,
            nominal_rate_hz: 48_000,
            clock: Clock::Ptp(3),
            role: ROLE_SOURCE,
        }
    }

    #[test]
    fn every_message_round_trips() {
        let info = StreamInfo { descriptor: desc(), flags: FLAG_RATE_MISMATCH, mesh_rate_hz: 48_000 };
        let msgs = vec![
            Msg::Hello { version: 1, client: "vendor".into() },
            Msg::HelloAck { version: 1, accepted: true, server: "core".into() },
            Msg::Register { request: 7, descriptor: desc() },
            Msg::Unregister { stream: 1 },
            Msg::Subscribe { stream: 1, queue_depth: 8 },
            Msg::Unsubscribe { stream: 1 },
            Msg::List,
            Msg::DeclareFamily(FamilyDecl {
                name: "com.acme.netaudio".into(),
                carrier: 1,
                discovery: 1,
                clock_ref: 1,
                channelization: 2,
                muxed_channels: 32,
                formats: 0b10,
                rates_hz: vec![48_000, 96_000],
                framing: 5,
                frames_per_packet: 32,
                mux: true,
                fan_out: 0,
                latency: 1,
                verbs: VERB_SOURCE | VERB_SINK,
                translates_to: vec!["dante".into()],
                translates_from: vec!["dante".into(), "aes67".into()],
            }),
            Msg::FamilyDeclared { name: "com.acme.netaudio".into() },
            Msg::Registered { request: 7, stream: 1, info: info.clone() },
            Msg::StreamList { streams: vec![(1, info.clone()), (2, info.clone())] },
            Msg::Subscribed { stream: 1, info },
            Msg::Overrun { stream: 1, dropped_total: 99 },
            Msg::StreamEnded { stream: 1 },
            Msg::Data { stream: 1, seq: 5, timestamp: 480, frames: 1, pcm: vec![1, 2, 3, 4, 5, 6] },
            Msg::Error { code: ERR_MALFORMED, message: "x".into() },
        ];
        for m in msgs {
            let f = encode(&m);
            assert_eq!(u32::from_le_bytes(f[..4].try_into().unwrap()) as usize, f.len() - 4);
            assert_eq!(decode(&f[4..]).unwrap(), m);
        }
    }

    #[test]
    fn hello_layout_is_as_documented() {
        let f = encode(&Msg::Hello { version: 1, client: "ab".into() });
        assert_eq!(f, [11, 0, 0, 0, 0x01, b'I', b'P', b'A', b'S', 1, 0, 2, 0, b'a', b'b']);
    }

    #[test]
    fn malformed_bodies_are_rejected() {
        assert_eq!(decode(&[0x55]), Err(WireError::UnknownKind(0x55)));
        assert_eq!(decode(&[K_HELLO, b'X', b'P', b'A', b'S', 1, 0, 0, 0]), Err(WireError::BadMagic));
        assert_eq!(decode(&[K_UNREGISTER, 1, 0]), Err(WireError::Truncated));
        assert_eq!(decode(&[K_LIST, 0]), Err(WireError::Trailing));
        assert_eq!(check_len(0), Err(WireError::BadLength(0)));
        assert_eq!(check_len(MAX_FRAME_LEN + 1), Err(WireError::BadLength(MAX_FRAME_LEN + 1)));
    }

    #[test]
    fn pcm_len_and_socket_path() {
        assert_eq!(desc().pcm_len(10), Some(60));
        let sync = Descriptor { payload: Payload::SyncOnly, ..desc() };
        assert_eq!(sync.pcm_len(10), Some(0));
        assert_eq!(stream_socket_path(Path::new("/a/core.sock")), PathBuf::from("/a/core.sock.stream"));
    }
}
