//! The stream-facet server (R003-F7): the binary canonical-stream socket that
//! sits beside the JSON control socket. The wire format is specified, byte for
//! byte, in [`ipauro_proto::stream`]; this module is its server.
//!
//! `@arch:see(.yah/docs/architecture/A004-ipauro-audio-protocol-taxonomy.md)` —
//! out-of-process adapters (A004 §2 second tier) register canonical streams
//! here; mixing apps subscribe/publish by id.
//!
//! Shape:
//! - one [`Registry`] of streams, each owned by the connection that registered
//!   it, with the subscriber connections it fans out to;
//! - per connection, one bounded [`Outbox`]: control replies are never dropped,
//!   Data frames are **drop-oldest** with a per-stream overrun count reported
//!   to the subscriber. A producer's Data is pushed into subscriber outboxes
//!   under a short std mutex and never awaits a subscriber, so a slow consumer
//!   cannot stall a producer;
//! - the rate verdict reuses R003-F8's capability-based participation
//!   ([`ipauro_mesh::rate`]): a PCM stream at a nominal rate other than the
//!   adopted mesh rate is accepted and flagged, never resampled here (R010-F4).
//!
//! Seam (not built): a shm ring negotiated at Hello would replace in-band PCM;
//! the Outbox is where that switch lands.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ipauro_mesh::capability::{CapsError, ProtocolCapability, ProtocolCaps, Translation, Verbs};
use ipauro_mesh::protocol::{
    self, Carrier, Channelization, ClockRef, Discovery, ExtIdError, ExtProfile, ExtProtocolId, FanOut, Framing,
    LatencyClass, Packetization, Profiles, ProtocolId, Row, SampleFormats,
};
use ipauro_mesh::rate::{self, Asrc, MeshRate, Role, StreamClock};
use ipauro_proto::stream::{
    self as wire, Descriptor, FamilyDecl, Msg, Payload, StreamInfo, WireError, DEFAULT_QUEUE_DEPTH,
    ERR_INVALID_DESCRIPTOR, ERR_MALFORMED, ERR_NOT_OWNER, ERR_UNKNOWN_STREAM, ERR_VERSION, FLAG_RATE_MISMATCH, K_DATA,
    ROLE_SINK, ROLE_SOURCE, STREAM_PROTOCOL_VERSION, VERB_FAN_IN, VERB_FAN_OUT, VERB_PASS, VERB_SINK, VERB_SOURCE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;

/// Where the adopted mesh rate comes from (the gossip membership in
/// production, a constant in tests).
pub type MeshRateSource = Arc<dyn Fn() -> MeshRate + Send + Sync>;

/// Bytes of a Data header after the kind byte: stream, seq, timestamp, frames.
const DATA_HEADER: usize = 4 + 8 + 8 + 4;

// ---- outbox ----------------------------------------------------------------

#[derive(Default)]
struct OutQ {
    control: VecDeque<Vec<u8>>,
    data: VecDeque<(u32, Arc<[u8]>)>,
    cap: usize,
    dropped: HashMap<u32, u64>,
    reported: HashMap<u32, u64>,
    /// Stop after flushing `control`.
    closing: bool,
}

/// One connection's outbound queue.
struct Outbox {
    q: Mutex<OutQ>,
    notify: Notify,
}

impl Outbox {
    fn new() -> Self {
        Self { q: Mutex::new(OutQ { cap: DEFAULT_QUEUE_DEPTH as usize, ..Default::default() }), notify: Notify::new() }
    }

    fn control(&self, msg: &Msg) {
        self.q.lock().unwrap().control.push_back(wire::encode(msg));
        self.notify.notify_one();
    }

    /// Never blocks: a full queue drops its oldest Data frame and counts it.
    fn data(&self, stream: u32, frame: Arc<[u8]>) {
        let mut q = self.q.lock().unwrap();
        if q.data.len() >= q.cap
            && let Some((old, _)) = q.data.pop_front()
        {
            *q.dropped.entry(old).or_default() += 1;
        }
        q.data.push_back((stream, frame));
        drop(q);
        self.notify.notify_one();
    }

    fn grow(&self, depth: u16) {
        let depth = if depth == 0 { DEFAULT_QUEUE_DEPTH } else { depth } as usize;
        let mut q = self.q.lock().unwrap();
        q.cap = q.cap.max(depth);
    }

    fn forget(&self, stream: u32) {
        let mut q = self.q.lock().unwrap();
        q.data.retain(|(s, _)| *s != stream);
    }

    fn close(&self) {
        self.q.lock().unwrap().closing = true;
        self.notify.notify_one();
    }

    /// Next bytes to write, or `None` when closed and drained.
    async fn next(&self) -> Option<Vec<u8>> {
        loop {
            {
                let mut q = self.q.lock().unwrap();
                if let Some(c) = q.control.pop_front() {
                    return Some(c);
                }
                if q.closing {
                    return None;
                }
                if let Some((s, frame)) = q.data.front().cloned() {
                    let dropped = q.dropped.get(&s).copied().unwrap_or(0);
                    if dropped > q.reported.get(&s).copied().unwrap_or(0) {
                        q.reported.insert(s, dropped);
                        return Some(wire::encode(&Msg::Overrun { stream: s, dropped_total: dropped }));
                    }
                    q.data.pop_front();
                    return Some(frame.to_vec());
                }
            }
            self.notify.notified().await;
        }
    }
}

// ---- registry --------------------------------------------------------------

struct Entry {
    info: StreamInfo,
    owner: u64,
    /// The family this stream's `protocol` resolved to (`None` = no family).
    family: Option<ProtocolId>,
    subs: Vec<(u64, Arc<Outbox>)>,
}

/// A family a sidecar declared: its capability row (carrying the
/// [`ExtProfile`]) and the translations it offers. Lives as long as `owner`.
struct Family {
    owner: u64,
    cap: ProtocolCapability,
    translates: Vec<Translation>,
}

#[derive(Default)]
struct Inner {
    next_id: u32,
    streams: BTreeMap<u32, Entry>,
    families: BTreeMap<ExtProtocolId, Family>,
}

impl Profiles for Inner {
    /// In-tree rows from the table; extension rows from live declarations.
    fn row(&self, id: ProtocolId) -> Option<Row<'_>> {
        match id {
            ProtocolId::Ext(x) => self.families.get(&x).and_then(|f| f.cap.ext.as_ref()).map(Row::Ext),
            in_tree => protocol::in_tree(in_tree).map(Row::InTree),
        }
    }
}

/// Receives this node's sidecar capabilities whenever they change; the
/// service unions them into the gossiped `PeerFacts.protocols`.
pub type CapsSink = Arc<dyn Fn(ProtocolCaps) + Send + Sync>;

/// All streams and sidecar families registered on this node's stream socket.
pub struct Registry {
    inner: Mutex<Inner>,
    mesh_rate: MeshRateSource,
    sink: Mutex<Option<CapsSink>>,
}

/// Why a Register was refused (non-fatal; the connection stays up).
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// PCM with zero channels, or neither source nor sink role.
    Shape(&'static str),
    /// PCM declared for a family whose registry row carries no media.
    PayloadOutsideProtocol(String),
    /// Neither an in-tree family nor a currently declared extension family.
    UnknownFamily(String),
}

/// Why a DeclareFamily was refused (non-fatal).
#[derive(Debug, PartialEq, Eq)]
pub enum DeclareError {
    /// Not a valid reverse-DNS extension name.
    Name(ExtIdError),
    /// The name is an in-tree family; those are not redeclared.
    InTree(String),
    /// Another live connection holds this name.
    Taken(String),
    /// A row code outside the documented table.
    Code(&'static str, u8),
    /// A translation names an unparseable family.
    Translation(String),
    /// The row is not self-consistent (e.g. a translation onto itself).
    Caps(Box<CapsError>),
}

impl Registry {
    pub fn new(mesh_rate: MeshRateSource) -> Self {
        Self { inner: Mutex::new(Inner::default()), mesh_rate, sink: Mutex::new(None) }
    }

    /// Install the capability sink and push the current capabilities to it.
    pub fn set_caps_sink(&self, sink: CapsSink) {
        *self.sink.lock().unwrap() = Some(sink);
        self.changed();
    }

    /// Re-publish capabilities after a change (outside the registry lock).
    fn changed(&self) {
        let sink = self.sink.lock().unwrap().clone();
        if let Some(sink) = sink {
            sink(self.protocol_caps());
        }
    }

    /// Resolve a descriptor into the server's verdict. Family lookup is by
    /// name (the identity join, A004/R004-F1); participation and the rate
    /// verdict come from the family's row — in-tree or declared — never from
    /// the name itself.
    pub fn assess(&self, d: &Descriptor) -> Result<(StreamInfo, Option<ProtocolId>), RegisterError> {
        self.assess_in(&self.inner.lock().unwrap(), d)
    }

    fn assess_in(&self, inner: &Inner, d: &Descriptor) -> Result<(StreamInfo, Option<ProtocolId>), RegisterError> {
        if d.role & (ROLE_SOURCE | ROLE_SINK) == 0 {
            return Err(RegisterError::Shape("role must include source or sink"));
        }
        if d.payload == Payload::Pcm && d.channels == 0 {
            return Err(RegisterError::Shape("pcm stream with zero channels"));
        }
        let family = if d.protocol.is_empty() {
            None
        } else {
            let p = ProtocolId::from_name(&d.protocol)
                .ok()
                .filter(|p| inner.row(*p).is_some())
                .ok_or_else(|| RegisterError::UnknownFamily(d.protocol.clone()))?;
            Some(p)
        };
        let mesh = (self.mesh_rate)();
        let mismatch = match (d.payload, family) {
            (Payload::SyncOnly, _) => false,
            (Payload::Pcm, Some(p)) => {
                if !rate::participates(inner, p) {
                    return Err(RegisterError::PayloadOutsideProtocol(p.name().to_string()));
                }
                // An adapter's stream arriving at the mesh is a generic
                // external input: cascade rule (c).
                let clock = StreamClock { proto: p, nominal_hz: d.nominal_rate_hz, role: Role::Input { partner: None } };
                matches!(rate::resolve(inner, &mesh, &clock), Some(r) if matches!(r.asrc, Asrc::Ratio { .. }))
            }
            // No family: participation is the declared payload; rule (c).
            (Payload::Pcm, None) => d.nominal_rate_hz != mesh.hz,
        };
        let flags = if mismatch { FLAG_RATE_MISMATCH } else { 0 };
        Ok((StreamInfo { descriptor: d.clone(), flags, mesh_rate_hz: mesh.hz }, family))
    }

    fn register(&self, owner: u64, d: &Descriptor) -> Result<(u32, StreamInfo), RegisterError> {
        let out = {
            let mut inner = self.inner.lock().unwrap();
            let (info, family) = self.assess_in(&inner, d)?;
            inner.next_id += 1;
            let id = inner.next_id;
            inner.streams.insert(id, Entry { info: info.clone(), owner, family, subs: Vec::new() });
            (id, info)
        };
        self.changed();
        Ok(out)
    }

    /// Map a declaration onto the mesh registry types. Pure: codes come from
    /// the mesh's shared wire tables, never from the family's name.
    pub fn family_from_decl(f: &FamilyDecl) -> Result<(ProtocolCapability, Vec<Translation>), DeclareError> {
        let id = match ProtocolId::from_name(&f.name).map_err(DeclareError::Name)? {
            ProtocolId::Ext(x) => x,
            in_tree => return Err(DeclareError::InTree(in_tree.name().to_string())),
        };
        fn code<T>(t: Option<T>, what: &'static str, c: u8) -> Result<T, DeclareError> {
            t.ok_or(DeclareError::Code(what, c))
        }
        let row = ExtProfile {
            id,
            carrier: code(Carrier::from_code(f.carrier), "carrier", f.carrier)?,
            discovery: code(Discovery::from_code(f.discovery), "discovery", f.discovery)?,
            clock: code(ClockRef::from_code(f.clock_ref), "clock_ref", f.clock_ref)?,
            channelization: code(
                Channelization::from_code(f.channelization, f.muxed_channels),
                "channelization",
                f.channelization,
            )?,
            formats: SampleFormats::from_bits(f.formats),
            rates_hz: f.rates_hz.clone(),
            packetization: Packetization {
                framing: code(Framing::from_code(f.framing), "framing", f.framing)?,
                frames_per_packet: (f.frames_per_packet != 0).then_some(f.frames_per_packet),
                mux: f.mux,
            },
            fan_out: code(FanOut::from_code(f.fan_out), "fan_out", f.fan_out)?,
            latency: code(LatencyClass::from_code(f.latency), "latency", f.latency)?,
        };
        let verbs = Verbs {
            pass: f.verbs & VERB_PASS != 0,
            sink: f.verbs & VERB_SINK != 0,
            source: f.verbs & VERB_SOURCE != 0,
            fan_in: f.verbs & VERB_FAN_IN != 0,
            fan_out: f.verbs & VERB_FAN_OUT != 0,
        };
        let me = ProtocolId::Ext(id);
        let other = |n: &String| ProtocolId::from_name(n).map_err(|_| DeclareError::Translation(n.clone()));
        let mut translates = Vec::new();
        for n in &f.translates_to {
            translates.push(Translation { from: me, to: other(n)? });
        }
        for n in &f.translates_from {
            translates.push(Translation { from: other(n)?, to: me });
        }
        if let Some(t) = translates.iter().find(|t| t.from == t.to) {
            return Err(DeclareError::Caps(Box::new(CapsError::SelfTranslation(t.from))));
        }
        let cap = ProtocolCapability::ext(row, verbs);
        ProtocolCaps { speaks: vec![cap.clone()], translates: Vec::new() }.validate().map_err(|e| DeclareError::Caps(Box::new(e)))?;
        Ok((cap, translates))
    }

    fn declare(&self, owner: u64, f: &FamilyDecl) -> Result<(), DeclareError> {
        let (cap, translates) = Self::family_from_decl(f)?;
        let ProtocolId::Ext(id) = cap.proto else { unreachable!("family_from_decl only yields Ext") };
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.families.get(&id).is_some_and(|fam| fam.owner != owner) {
                return Err(DeclareError::Taken(id.as_str().to_string()));
            }
            inner.families.insert(id, Family { owner, cap, translates });
        }
        self.changed();
        Ok(())
    }

    /// The registered streams, by id.
    pub fn list(&self) -> Vec<(u32, StreamInfo)> {
        self.inner.lock().unwrap().streams.iter().map(|(id, e)| (*id, e.info.clone())).collect()
    }

    /// What this node's sidecars add to its advertised `PeerFacts.protocols`
    /// (R010-F1 shape): every declared family with its row and translations,
    /// plus the in-tree families streams were registered for, with verbs from
    /// the declarations and the streams' roles. Gossiped exactly like an
    /// in-tree adapter's capability.
    pub fn protocol_caps(&self) -> ProtocolCaps {
        let inner = self.inner.lock().unwrap();
        let declared = ProtocolCaps {
            speaks: inner.families.values().map(|f| f.cap.clone()).collect(),
            translates: inner.families.values().flat_map(|f| f.translates.iter().copied()).collect(),
        };
        let mut verbs: BTreeMap<ProtocolId, Verbs> = BTreeMap::new();
        for e in inner.streams.values() {
            if let Some(p) = e.family {
                let v = verbs.entry(p).or_default();
                v.source |= e.info.descriptor.role & ROLE_SOURCE != 0;
                v.sink |= e.info.descriptor.role & ROLE_SINK != 0;
            }
        }
        let streams = ProtocolCaps {
            speaks: verbs
                .into_iter()
                .filter_map(|(p, v)| match (p, inner.row(p)?) {
                    (_, Row::InTree(_)) => Some(ProtocolCapability::full(p, v)),
                    (_, Row::Ext(row)) => Some(ProtocolCapability::ext(row.clone(), v)),
                })
                .collect(),
            translates: Vec::new(),
        };
        declared.union(&streams)
    }

    /// Drop everything `conn` owns or subscribes to, and retract its families.
    fn drop_conn(&self, conn: u64) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.families.retain(|_, f| f.owner != conn);
            inner.streams.retain(|id, e| {
                if e.owner == conn {
                    for (_, ob) in &e.subs {
                        ob.forget(*id);
                        ob.control(&Msg::StreamEnded { stream: *id });
                    }
                    false
                } else {
                    e.subs.retain(|(c, _)| *c != conn);
                    true
                }
            });
        }
        self.changed();
    }
}

// ---- server ----------------------------------------------------------------

/// A running stream socket. Dropping it stops the server (and every
/// connection) and removes the socket file.
pub struct StreamServer {
    path: PathBuf,
    registry: Arc<Registry>,
    task: tokio::task::JoinHandle<()>,
}

impl StreamServer {
    /// Bind `path` (0600, stale file removed) and start accepting.
    pub fn spawn(path: PathBuf, mesh_rate: MeshRateSource) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        log::info!("ipauro-core stream socket on {}", path.display());
        let registry = Arc::new(Registry::new(mesh_rate));
        let task = tokio::spawn(accept_loop(listener, registry.clone()));
        Ok(Self { path, registry, task })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }
}

impl Drop for StreamServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn accept_loop(listener: UnixListener, registry: Arc<Registry>) {
    // Owning the JoinSet means aborting this task aborts every connection.
    let mut conns = JoinSet::new();
    let next = AtomicU64::new(1);
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let id = next.fetch_add(1, Ordering::Relaxed);
                    conns.spawn(connection(stream, id, registry.clone()));
                }
                Err(e) => log::warn!("stream accept error: {e}"),
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

/// How a read ended.
enum ReadEnd {
    Eof,
    /// Protocol violation: send `Error{code}` then close this connection.
    Fatal(u16, String),
}

async fn read_body(r: &mut (impl AsyncReadExt + Unpin)) -> Result<Option<Vec<u8>>, ReadEnd> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(ReadEnd::Eof),
    }
    let n = wire::check_len(u32::from_le_bytes(len)).map_err(|e| ReadEnd::Fatal(ERR_MALFORMED, e.to_string()))?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await.map_err(|_| ReadEnd::Eof)?;
    Ok(Some(body))
}

async fn connection(stream: UnixStream, conn: u64, registry: Arc<Registry>) {
    let (mut rd, mut wr) = stream.into_split();
    let outbox = Arc::new(Outbox::new());
    let writer = {
        let outbox = outbox.clone();
        async move {
            while let Some(bytes) = outbox.next().await {
                if wr.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        }
    };
    let reader = {
        let outbox = outbox.clone();
        let registry = registry.clone();
        async move {
            let end = serve_reads(&mut rd, conn, &registry, &outbox).await;
            if let ReadEnd::Fatal(code, message) = end {
                log::warn!("stream client {conn}: closing ({message})");
                outbox.control(&Msg::Error { code, message });
            }
            registry.drop_conn(conn);
            outbox.close();
        }
    };
    tokio::join!(reader, writer);
}

async fn serve_reads(rd: &mut (impl AsyncReadExt + Unpin), conn: u64, reg: &Registry, ob: &Arc<Outbox>) -> ReadEnd {
    let malformed = |e: WireError| ReadEnd::Fatal(ERR_MALFORMED, e.to_string());

    // Handshake.
    let body = match read_body(rd).await {
        Ok(Some(b)) => b,
        Ok(None) => return ReadEnd::Eof,
        Err(e) => return e,
    };
    let (version, client) = match wire::decode(&body) {
        Ok(Msg::Hello { version, client }) => (version, client),
        Ok(other) => return ReadEnd::Fatal(ERR_MALFORMED, format!("expected Hello, got {other:?}")),
        Err(e) => return malformed(e),
    };
    let accepted = version == STREAM_PROTOCOL_VERSION;
    ob.control(&Msg::HelloAck {
        version: STREAM_PROTOCOL_VERSION,
        accepted,
        server: format!("ipauro-core {}", crate::build_version()),
    });
    if !accepted {
        return ReadEnd::Fatal(
            ERR_VERSION,
            format!("client '{client}' speaks stream v{version}, server is v{STREAM_PROTOCOL_VERSION}"),
        );
    }
    log::info!("stream client {conn} '{client}' connected");

    loop {
        let body = match read_body(rd).await {
            Ok(Some(b)) => b,
            Ok(None) => return ReadEnd::Eof,
            Err(e) => return e,
        };
        if body[0] == K_DATA {
            if let Err(e) = publish(reg, conn, &body) {
                return e;
            }
            continue;
        }
        match wire::decode(&body) {
            Err(e) => return malformed(e),
            Ok(Msg::Register { request, descriptor }) => match reg.register(conn, &descriptor) {
                Ok((stream, info)) => ob.control(&Msg::Registered { request, stream, info }),
                Err(e) => ob.control(&Msg::Error { code: ERR_INVALID_DESCRIPTOR, message: format!("{e:?}") }),
            },
            Ok(Msg::Unregister { stream }) => {
                let mut inner = reg.inner.lock().unwrap();
                match inner.streams.get(&stream) {
                    None => ob.control(&unknown(stream)),
                    Some(e) if e.owner != conn => {
                        return ReadEnd::Fatal(ERR_NOT_OWNER, format!("stream {stream} is not yours"))
                    }
                    Some(_) => {
                        let e = inner.streams.remove(&stream).expect("checked above");
                        for (_, sub) in e.subs {
                            sub.forget(stream);
                            sub.control(&Msg::StreamEnded { stream });
                        }
                        drop(inner);
                        reg.changed();
                    }
                }
            }
            Ok(Msg::Subscribe { stream, queue_depth }) => {
                let mut inner = reg.inner.lock().unwrap();
                match inner.streams.get_mut(&stream) {
                    None => ob.control(&unknown(stream)),
                    Some(e) => {
                        ob.grow(queue_depth);
                        if !e.subs.iter().any(|(c, _)| *c == conn) {
                            e.subs.push((conn, ob.clone()));
                        }
                        ob.control(&Msg::Subscribed { stream, info: e.info.clone() });
                    }
                }
            }
            Ok(Msg::Unsubscribe { stream }) => {
                if let Some(e) = reg.inner.lock().unwrap().streams.get_mut(&stream) {
                    e.subs.retain(|(c, _)| *c != conn);
                }
                ob.forget(stream);
            }
            Ok(Msg::List) => ob.control(&Msg::StreamList { streams: reg.list() }),
            Ok(Msg::DeclareFamily(f)) => match reg.declare(conn, &f) {
                Ok(()) => ob.control(&Msg::FamilyDeclared { name: f.name }),
                Err(e) => ob.control(&Msg::Error { code: ERR_INVALID_DESCRIPTOR, message: format!("{e:?}") }),
            },
            // Server-to-client kinds (and a second Hello) are protocol
            // violations from a client; Data was routed above.
            Ok(
                other @ (Msg::Hello { .. }
                | Msg::HelloAck { .. }
                | Msg::Registered { .. }
                | Msg::StreamList { .. }
                | Msg::Subscribed { .. }
                | Msg::Overrun { .. }
                | Msg::StreamEnded { .. }
                | Msg::FamilyDeclared { .. }
                | Msg::Error { .. }
                | Msg::Data { .. }),
            ) => return ReadEnd::Fatal(ERR_MALFORMED, format!("unexpected client message {other:?}")),
        }
    }
}

fn unknown(stream: u32) -> Msg {
    Msg::Error { code: ERR_UNKNOWN_STREAM, message: format!("no stream {stream}") }
}

/// Validate a producer's Data frame and fan the identical bytes out. Parses
/// only the fixed header — PCM is forwarded, never decoded or copied per
/// subscriber.
fn publish(reg: &Registry, conn: u64, body: &[u8]) -> Result<(), ReadEnd> {
    let h = body.get(1..1 + DATA_HEADER).ok_or_else(|| ReadEnd::Fatal(ERR_MALFORMED, "truncated Data".into()))?;
    let stream = u32::from_le_bytes(h[0..4].try_into().unwrap());
    let frames = u32::from_le_bytes(h[20..24].try_into().unwrap());
    let pcm = body.len() - 1 - DATA_HEADER;
    let inner = reg.inner.lock().unwrap();
    let Some(e) = inner.streams.get(&stream) else {
        // Not fatal: a frame can race the producer's own Unregister.
        return Ok(());
    };
    let d = &e.info.descriptor;
    if e.owner != conn || d.role & ROLE_SOURCE == 0 {
        return Err(ReadEnd::Fatal(ERR_NOT_OWNER, format!("Data for stream {stream} you do not source")));
    }
    if d.pcm_len(frames) != Some(pcm) {
        return Err(ReadEnd::Fatal(ERR_MALFORMED, format!("Data pcm is {pcm} bytes, descriptor implies {:?}", d.pcm_len(frames))));
    }
    if e.subs.is_empty() {
        return Ok(());
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(body);
    let frame: Arc<[u8]> = frame.into();
    for (_, sub) in &e.subs {
        sub.data(stream, frame.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipauro_mesh::ids::NodeId;
    use ipauro_proto::stream::{Clock, SampleFormat};
    use std::time::Duration;

    fn mesh48() -> MeshRateSource {
        Arc::new(|| MeshRate::new(NodeId([0; 8])))
    }

    fn sock(tag: &str) -> PathBuf {
        let n = std::process::id();
        std::env::temp_dir().join(format!("ipst-{n}-{tag}.sock"))
    }

    fn pcm_desc(protocol: &str, hz: u32, role: u8) -> Descriptor {
        Descriptor {
            name: "bus".into(),
            protocol: protocol.into(),
            payload: Payload::Pcm,
            channels: 2,
            sample_format: SampleFormat::I16,
            nominal_rate_hz: hz,
            clock: Clock::FreeRun,
            role,
        }
    }

    struct Client(UnixStream);

    impl Client {
        async fn raw(path: &Path) -> Self {
            Client(UnixStream::connect(path).await.unwrap())
        }
        async fn connect(path: &Path, name: &str) -> Self {
            let mut c = Self::raw(path).await;
            c.send(&Msg::Hello { version: STREAM_PROTOCOL_VERSION, client: name.into() }).await;
            match c.recv().await {
                Some(Msg::HelloAck { accepted: true, .. }) => c,
                other => panic!("handshake failed: {other:?}"),
            }
        }
        async fn send(&mut self, m: &Msg) {
            self.0.write_all(&wire::encode(m)).await.unwrap();
        }
        async fn recv(&mut self) -> Option<Msg> {
            let fut = async {
                match read_body(&mut self.0).await {
                    Ok(Some(b)) => Some(wire::decode(&b).unwrap()),
                    _ => None,
                }
            };
            tokio::time::timeout(Duration::from_secs(5), fut).await.expect("recv timed out")
        }
        async fn register(&mut self, d: Descriptor) -> (u32, StreamInfo) {
            self.send(&Msg::Register { request: 1, descriptor: d }).await;
            match self.recv().await {
                Some(Msg::Registered { request: 1, stream, info }) => (stream, info),
                other => panic!("register failed: {other:?}"),
            }
        }
        async fn declare(&mut self, f: FamilyDecl) {
            let name = f.name.clone();
            self.send(&Msg::DeclareFamily(f)).await;
            assert_eq!(self.recv().await, Some(Msg::FamilyDeclared { name }));
        }
        async fn subscribe(&mut self, stream: u32, depth: u16) -> StreamInfo {
            self.send(&Msg::Subscribe { stream, queue_depth: depth }).await;
            match self.recv().await {
                Some(Msg::Subscribed { info, .. }) => info,
                other => panic!("subscribe failed: {other:?}"),
            }
        }
    }

    /// A PCM family row (PTPv2, muxed, 48/96 k) translating to/from the names given.
    fn decl(name: &str, to: &[&str], from: &[&str]) -> FamilyDecl {
        FamilyDecl {
            name: name.into(),
            carrier: Carrier::Udp.code(),
            discovery: Discovery::Mdns.code(),
            clock_ref: ClockRef::PtpV2.code(),
            channelization: 2,
            muxed_channels: 32,
            formats: SampleFormats::PCM_INT.bits(),
            rates_hz: vec![48_000, 96_000],
            framing: Framing::Proprietary.code(),
            frames_per_packet: 0,
            mux: true,
            fan_out: FanOut::Multicast.code(),
            latency: LatencyClass::Ms.code(),
            verbs: VERB_SOURCE | VERB_SINK,
            translates_to: to.iter().map(|s| s.to_string()).collect(),
            translates_from: from.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn data(stream: u32, seq: u64) -> Msg {
        Msg::Data { stream, seq, timestamp: seq * 64, frames: 64, pcm: vec![seq as u8; 64 * 2 * 2] }
    }

    #[tokio::test]
    async fn handshake_accepts_v1_and_rejects_other_versions() {
        let srv = StreamServer::spawn(sock("hs"), mesh48()).unwrap();
        let _ok = Client::connect(srv.path(), "good").await;

        let mut bad = Client::raw(srv.path()).await;
        bad.send(&Msg::Hello { version: 99, client: "future".into() }).await;
        assert!(matches!(bad.recv().await, Some(Msg::HelloAck { version: 1, accepted: false, .. })));
        assert!(matches!(bad.recv().await, Some(Msg::Error { code: ERR_VERSION, .. })));
        assert_eq!(bad.recv().await, None, "rejected client is closed");

        // Wrong magic is malformed: Error then close, no HelloAck.
        let mut junk = Client::raw(srv.path()).await;
        junk.0.write_all(&[5, 0, 0, 0, 0x01, b'N', b'O', b'P', b'E']).await.unwrap();
        assert!(matches!(junk.recv().await, Some(Msg::Error { code: ERR_MALFORMED, .. })));
        assert_eq!(junk.recv().await, None);
    }

    #[tokio::test]
    async fn adapter_source_reaches_mixer_sink_in_order() {
        let srv = StreamServer::spawn(sock("e2e"), mesh48()).unwrap();
        let mut adapter = Client::connect(srv.path(), "dante-sidecar").await;
        let (id, info) = adapter.register(pcm_desc("dante", 48_000, ROLE_SOURCE)).await;
        assert!(!info.rate_mismatch());
        assert_eq!(info.flags, 0);

        let mut mixer = Client::connect(srv.path(), "mixer").await;
        mixer.send(&Msg::List).await;
        match mixer.recv().await {
            Some(Msg::StreamList { streams }) => assert_eq!(streams, vec![(id, info.clone())]),
            other => panic!("{other:?}"),
        }
        assert_eq!(mixer.subscribe(id, 0).await, info);

        for seq in 0..20 {
            adapter.send(&data(id, seq)).await;
        }
        for seq in 0..20 {
            assert_eq!(mixer.recv().await, Some(data(id, seq)));
        }

        // The sidecar's family is advertised as a capability row.
        let caps = srv.registry().protocol_caps();
        assert_eq!(caps.speaks.len(), 1);
        assert_eq!(caps.speaks[0].proto, ProtocolId::Dante);
        assert!(caps.speaks[0].verbs.source && !caps.speaks[0].verbs.sink);
        assert_eq!(caps.validate(), Ok(()));

        // Producer leaving ends the stream for its subscribers.
        drop(adapter);
        assert_eq!(mixer.recv().await, Some(Msg::StreamEnded { stream: id }));
        assert!(srv.registry().list().is_empty());
    }

    #[tokio::test]
    async fn slow_subscriber_drops_oldest_and_producer_never_blocks() {
        let srv = StreamServer::spawn(sock("slow"), mesh48()).unwrap();
        let mut producer = Client::connect(srv.path(), "producer").await;
        let (id, _) = producer.register(pcm_desc("", 48_000, ROLE_SOURCE)).await;
        let mut slow = Client::connect(srv.path(), "slow").await;
        slow.subscribe(id, 4).await;

        const N: u64 = 2_000;
        // 2000 × 280 B frames ≫ kernel socket buffers + 4-deep queue: if the
        // server blocked on the subscriber, this would never finish.
        tokio::time::timeout(Duration::from_secs(5), async {
            for seq in 0..N {
                producer.send(&data(id, seq)).await;
            }
        })
        .await
        .expect("producer blocked");
        // Round-trip a List so every Data above has been processed.
        producer.send(&Msg::List).await;
        assert!(matches!(producer.recv().await, Some(Msg::StreamList { .. })));

        let (mut seqs, mut overrun) = (Vec::new(), 0u64);
        while seqs.last() != Some(&(N - 1)) {
            match slow.recv().await {
                Some(Msg::Data { seq, .. }) => seqs.push(seq),
                Some(Msg::Overrun { stream, dropped_total }) => {
                    assert_eq!(stream, id);
                    assert!(dropped_total > overrun, "overrun total is monotonic");
                    overrun = dropped_total;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "order preserved across drops");
        assert!(overrun > 0, "drops were counted");
        assert_eq!(seqs.len() as u64 + overrun, N, "every frame delivered or counted");
    }

    #[tokio::test]
    async fn rate_mismatch_is_accepted_and_flagged() {
        let srv = StreamServer::spawn(sock("rate"), mesh48()).unwrap();
        let mut c = Client::connect(srv.path(), "c").await;
        let (_, info) = c.register(pcm_desc("dante", 44_100, ROLE_SOURCE)).await;
        assert!(info.rate_mismatch());
        assert_eq!(info.mesh_rate_hz, 48_000);
        // Without an in-tree family the declared payload decides participation.
        let (_, info) = c.register(pcm_desc("", 96_000, ROLE_SINK)).await;
        assert!(info.rate_mismatch());
        // Sync-only never participates, whatever its nominal rate.
        let sync = Descriptor { payload: Payload::SyncOnly, ..pcm_desc("ableton-link", 1, ROLE_SOURCE) };
        let (_, info) = c.register(sync).await;
        assert!(!info.rate_mismatch());
        // A family that is neither in-tree nor declared is refused, non-fatally.
        for name in ["acme-net", "com.acme.undeclared"] {
            c.send(&Msg::Register { request: 8, descriptor: pcm_desc(name, 48_000, ROLE_SOURCE) }).await;
            assert!(matches!(c.recv().await, Some(Msg::Error { code: ERR_INVALID_DESCRIPTOR, .. })), "{name}");
        }
        // A declared extension family's row decides participation, like an in-tree one.
        c.declare(decl("com.acme.netaudio", &[], &[])).await;
        let (_, info) = c.register(pcm_desc("com.acme.netaudio", 96_000, ROLE_SOURCE)).await;
        assert!(info.rate_mismatch());
        // PCM on a family whose row carries no media is refused, non-fatally.
        c.send(&Msg::Register { request: 9, descriptor: pcm_desc("ableton-link", 48_000, ROLE_SOURCE) }).await;
        assert!(matches!(c.recv().await, Some(Msg::Error { code: ERR_INVALID_DESCRIPTOR, .. })));
        c.send(&Msg::List).await;
        assert!(matches!(c.recv().await, Some(Msg::StreamList { streams }) if streams.len() == 4));
    }

    #[tokio::test]
    async fn malformed_frame_closes_only_that_client() {
        let srv = StreamServer::spawn(sock("bad"), mesh48()).unwrap();
        let mut producer = Client::connect(srv.path(), "producer").await;
        let (id, _) = producer.register(pcm_desc("", 48_000, ROLE_SOURCE)).await;
        let mut good = Client::connect(srv.path(), "good").await;
        good.subscribe(id, 0).await;

        // Oversized length prefix.
        let mut bad = Client::connect(srv.path(), "bad").await;
        bad.0.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
        assert!(matches!(bad.recv().await, Some(Msg::Error { code: ERR_MALFORMED, .. })));
        assert_eq!(bad.recv().await, None);

        // PCM length disagreeing with the descriptor.
        let mut liar = Client::connect(srv.path(), "liar").await;
        let (lid, _) = liar.register(pcm_desc("", 48_000, ROLE_SOURCE)).await;
        liar.send(&Msg::Data { stream: lid, seq: 0, timestamp: 0, frames: 10, pcm: vec![0; 3] }).await;
        assert!(matches!(liar.recv().await, Some(Msg::Error { code: ERR_MALFORMED, .. })));
        assert_eq!(liar.recv().await, None);

        // Publishing someone else's stream.
        let mut thief = Client::connect(srv.path(), "thief").await;
        thief.send(&data(id, 0)).await;
        assert!(matches!(thief.recv().await, Some(Msg::Error { code: ERR_NOT_OWNER, .. })));
        assert_eq!(thief.recv().await, None);

        // Everyone else is unaffected.
        producer.send(&data(id, 7)).await;
        assert_eq!(good.recv().await, Some(data(id, 7)));
        assert_eq!(srv.registry().list().len(), 1, "liar's stream went with it");
    }

    #[tokio::test]
    async fn declarations_are_validated_owned_and_retracted() {
        let srv = StreamServer::spawn(sock("decl"), mesh48()).unwrap();
        let seen: Arc<Mutex<Vec<ProtocolCaps>>> = Arc::default();
        let log = seen.clone();
        srv.registry().set_caps_sink(Arc::new(move |c| log.lock().unwrap().push(c)));
        let x = ProtocolId::from_name("com.acme.netaudio").unwrap();

        let mut a = Client::connect(srv.path(), "acme").await;
        a.declare(decl("com.acme.netaudio", &["dante"], &["dante"])).await;
        let caps = seen.lock().unwrap().last().cloned().unwrap();
        let cap = caps.speaks(x).expect("declared family advertised");
        assert_eq!(cap.ext.as_ref().unwrap().clock, ClockRef::PtpV2);
        assert_eq!(cap.ext.as_ref().unwrap().channelization, Channelization::Muxed { channels: 32 });
        assert!(caps.translates.contains(&Translation { from: x, to: ProtocolId::Dante }));
        assert!(caps.translates.contains(&Translation { from: ProtocolId::Dante, to: x }));

        // Refusals: in-tree name, bad name, bad code, someone else's name.
        let mut b = Client::connect(srv.path(), "rival").await;
        for f in [
            decl("dante", &[], &[]),
            decl("acme", &[], &[]),
            FamilyDecl { carrier: 99, ..decl("com.rival.y", &[], &[]) },
            decl("com.acme.netaudio", &[], &[]),
        ] {
            b.send(&Msg::DeclareFamily(f.clone())).await;
            assert!(matches!(b.recv().await, Some(Msg::Error { code: ERR_INVALID_DESCRIPTOR, .. })), "{f:?}");
        }

        // Disconnect retracts the family.
        drop(a);
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen.lock().unwrap().last().unwrap().speaks(x).is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("family retracted");
        assert!(srv.registry().protocol_caps().speaks.is_empty());
    }

    /// R003-F7 end to end: a sidecar adds family X on node A's stream socket;
    /// A's gossiped facts (through the real record codec) carry X; node B's
    /// view counts A as an X speaker and plans X exactly like an in-tree family.
    #[tokio::test]
    async fn sidecar_family_is_gossiped_and_planned_like_an_in_tree_one() {
        use ipauro_mesh::gossip::Record;
        use ipauro_mesh::ids::NodeId;
        use ipauro_mesh::policy::Policy;
        use ipauro_mesh::topology::PeerFacts;
        use ipauro_mesh::MeshNode;

        let (na, nb, nc) = (NodeId([1; 8]), NodeId([2; 8]), NodeId([3; 8]));
        let x = ProtocolId::from_name("com.acme.netaudio").unwrap();
        let y = ProtocolId::from_name("org.example.lonely").unwrap();

        // Each node's advertised caps, as its caps sink sees them.
        let node = |tag: &str| {
            let srv = StreamServer::spawn(sock(tag), mesh48()).unwrap();
            let caps: Arc<Mutex<ProtocolCaps>> = Arc::default();
            let c = caps.clone();
            srv.registry().set_caps_sink(Arc::new(move |p| *c.lock().unwrap() = p));
            (srv, caps)
        };
        let (srv_a, caps_a) = node("gA");
        let (srv_c, caps_c) = node("gC");

        // A: the sidecar adds X, translating both ways with Dante, and also
        // terminates Dante (a registered Dante stream).
        let mut sidecar = Client::connect(srv_a.path(), "acme-sidecar").await;
        sidecar.declare(decl("com.acme.netaudio", &["dante"], &["dante"])).await;
        sidecar.register(pcm_desc("dante", 48_000, ROLE_SOURCE | ROLE_SINK)).await;
        // C: an X-only island plus Y, which nothing translates.
        let mut island = Client::connect(srv_c.path(), "island").await;
        island.declare(decl("com.acme.netaudio", &[], &[])).await;
        island.declare(decl("org.example.lonely", &[], &[])).await;

        // Gossip: each node's facts through the real wire codec into B's view.
        let mut b = MeshNode::new(nb, Policy::new(nb));
        let mut seq = 0;
        let mut gossip = |b: &mut MeshNode, author: NodeId, caps: ProtocolCaps| {
            seq += 1;
            let facts = PeerFacts { protocols: caps, ..PeerFacts::default() };
            let rec = Record { author, seq, edges: None, facts: Some(facts), policy: None };
            let wire = ipauro_iroh::encode_record(&rec);
            b.apply_gossip(ipauro_iroh::decode_record(&wire).unwrap());
        };
        let mut dante_only = ProtocolCaps::default();
        dante_only.speaks.push(ProtocolCapability::full(ProtocolId::Dante, Verbs { sink: true, ..Verbs::default() }));
        gossip(&mut b, na, caps_a.lock().unwrap().clone());
        gossip(&mut b, nb, dante_only);
        gossip(&mut b, nc, caps_c.lock().unwrap().clone());

        assert_eq!(b.peers_speaking(x), vec![na, nc]);
        assert_eq!(b.peers_speaking(ProtocolId::Dante), vec![na, nb]);
        assert_eq!(b.translators(x, ProtocolId::Dante), vec![na]);
        let plan = b.gateway_plan();
        let leg = |f, t| plan.iter().find(|l| l.from == f && l.to == t).copied();
        assert_eq!(leg(x, ProtocolId::Dante).unwrap().gateway, Some(na), "X -> Dante is bridged by A");
        assert_eq!(leg(ProtocolId::Dante, x).unwrap().gateway, Some(na));
        assert_eq!(leg(y, ProtocolId::Dante).unwrap().gateway, None, "Y is an unbridged island");
        assert!(plan.windows(2).all(|w| (w[0].from, w[0].to) < (w[1].from, w[1].to)), "deterministic order");

        // The sidecar leaves: A's next record retracts X (and its Dante stream).
        drop(sidecar);
        tokio::time::timeout(Duration::from_secs(5), async {
            while caps_a.lock().unwrap().speaks(x).is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("retracted");
        gossip(&mut b, na, caps_a.lock().unwrap().clone());
        assert_eq!(b.peers_speaking(x), vec![nc]);
        assert!(b.translators(x, ProtocolId::Dante).is_empty());
        assert_eq!(b.gateway_plan().iter().find(|l| l.from == x && l.to == ProtocolId::Dante).unwrap().gateway, None);
    }
}
