//! Stream router core (R010-F3): the Protocol-NAT node as a **queueing/routing
//! node** — propagate streams 1:1, fan-in, or fan-out, where each leg is
//! independently **passthrough** (same protocol) or **transcode** (different
//! protocol), and **nothing is ever mixed**.
//!
//! This is the orchestration half. It decides, for one [`Demand`], a [`Flow`]:
//! which sink gets which sources, in what protocol, converted where, over which
//! route, and into which output channel. The media half — jitter buffer and
//! adaptive resampling on each leg — is a borrowed engine (zita-njbridge /
//! JackTrip, A003 §3; R010-F4) that consumes this plan; it never appears here.
//!
//! **No mixing, ever (W001 §non-goals, R010-F3 gotcha).** Fan-in is routing
//! several *discrete* streams onto one egress leg, kept channel-discrete. The
//! type system holds the line: a [`Slot`] maps exactly one source channel to
//! exactly one destination channel, and [`Leg::slots`] is built so no destination
//! channel is assigned twice (`tests::fan_in_keeps_every_channel_discrete`).
//! There is no field anywhere in this module where two samples could meet.
//!
//! **Deterministic.** Like routing and election, the plan is a pure function of
//! the gossiped view and the demand: the same `Flow` on every node, so the
//! source, the gateway and the sink each read their own part of one agreed plan
//! without a negotiation round (spec §8.3).
//!
//! **Every failure is a first-class outcome, not an absence.** A leg whose
//! protocols nobody translates is [`Mode::Unbridged`]; a leg whose nodes the
//! graph cannot connect is [`Path::Unroutable`]. Both stay in the plan so a status
//! surface can say *why* a sink is silent (W001 R007 philosophy).

use crate::gateway;
use crate::ids::{ChannelId, NodeId};
use crate::policy::Policy;
use crate::protocol::{self, ClockBridge, ProtocolId};
use crate::routing::{self, Constraints, Route, RouteRequest};
use crate::topology::Topology;

/// A stream entering the mesh: who originates it, in what protocol, how wide.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Source {
    pub stream: ChannelId,
    pub node: NodeId,
    pub proto: ProtocolId,
    /// Discrete channels in the stream. Each becomes one [`Slot`].
    pub channels: u16,
}

/// A consumer of streams: which node, and the protocol it must receive in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sink {
    pub node: NodeId,
    pub proto: ProtocolId,
}

/// What to propagate where. 1:1 is one source and one sink; fan-out is one
/// source to many sinks; fan-in is many sources to one sink; many-to-many is
/// simply fan-in at every sink.
#[derive(Clone, Debug)]
pub struct Demand {
    pub sources: Vec<Source>,
    pub sinks: Vec<Sink>,
    /// Applied to every route the plan needs (hop limit, forbidden transports…).
    pub constraints: Constraints,
}

/// The propagation shape of a demand, derived — never stated — so a caller
/// cannot ask for a shape the sources/sinks do not have.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    OneToOne,
    FanIn,
    FanOut,
    ManyToMany,
}

impl Demand {
    pub fn shape(&self) -> Shape {
        match (self.sources.len() > 1, self.sinks.len() > 1) {
            (false, false) => Shape::OneToOne,
            (true, false) => Shape::FanIn,
            (false, true) => Shape::FanOut,
            (true, true) => Shape::ManyToMany,
        }
    }
}

/// How one source reaches one sink, protocol-wise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Source and sink speak the same protocol: forward unchanged. The clock
    /// relationship still matters (LinkAudio→LinkAudio is `Adaptive`: no sample
    /// lock even within the protocol, A004 §3).
    Passthrough { clock: ClockBridge },
    /// Ingest `from` into the canonical stream and emit `to`, at node `at` —
    /// the source itself or the sink itself when either honours the translation
    /// (no extra hop), else the mesh's elected gateway for that leg
    /// ([`gateway::elect`]). `clock` is what R010-F4 must do on this leg.
    Transcode { from: ProtocolId, to: ProtocolId, at: NodeId, clock: ClockBridge },
    /// Nobody in the mesh translates `from` → `to`. The sink stays silent for
    /// this source, visibly.
    Unbridged { from: ProtocolId, to: ProtocolId },
}

/// The network path a source takes to its sink.
#[derive(Clone, PartialEq, Debug)]
pub enum Path {
    /// Source and sink (and any transcode) are on one node.
    Local,
    /// One route, source node → sink node (passthrough, or transcode at an end).
    Direct(Route),
    /// Two routes, through the transcoding node.
    ViaGateway { to_gateway: Route, to_sink: Route },
    /// The graph cannot connect the nodes under the demand's constraints. Which
    /// hop failed is named so the blockage is actionable.
    Unroutable { from: NodeId, to: NodeId },
}

/// One source's contribution to one egress leg.
#[derive(Clone, PartialEq, Debug)]
pub struct Input {
    pub source: Source,
    pub mode: Mode,
    pub path: Path,
}

/// One source channel landing on one destination channel. Exactly one each —
/// the whole no-mixing guarantee is that this is the only way samples move.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Slot {
    pub stream: ChannelId,
    pub src_channel: u16,
    pub dst_channel: u16,
}

/// The egress leg to one sink: every source feeding it, and the channel map.
#[derive(Clone, PartialEq, Debug)]
pub struct Leg {
    pub sink: Sink,
    pub inputs: Vec<Input>,
    /// Destination channels are assigned sequentially in source order, so the
    /// map is dense, deterministic and injective (one source channel per slot).
    pub slots: Vec<Slot>,
}

impl Leg {
    /// Total channels the sink receives — the sum of its sources' widths, never
    /// fewer (nothing is summed) and never more (nothing is duplicated).
    pub fn channel_count(&self) -> u16 {
        self.slots.len() as u16
    }

    /// Every input the leg can actually deliver (bridged *and* routable).
    pub fn live_inputs(&self) -> impl Iterator<Item = &Input> {
        self.inputs.iter().filter(|i| i.is_live())
    }
}

impl Input {
    pub fn is_live(&self) -> bool {
        !matches!(self.mode, Mode::Unbridged { .. }) && !matches!(self.path, Path::Unroutable { .. })
    }
}

/// The plan for one demand: one leg per sink.
#[derive(Clone, PartialEq, Debug)]
pub struct Flow {
    pub shape: Shape,
    pub legs: Vec<Leg>,
}

impl Flow {
    /// True when every source reaches every sink.
    pub fn is_complete(&self) -> bool {
        self.legs.iter().all(|l| l.inputs.iter().all(Input::is_live))
    }
}

/// Plan a demand against the gossiped view. Pure and deterministic.
pub fn plan(topo: &Topology, policy: &Policy, demand: &Demand) -> Flow {
    let legs = demand
        .sinks
        .iter()
        .map(|&sink| plan_leg(topo, policy, demand, sink))
        .collect();
    Flow { shape: demand.shape(), legs }
}

fn plan_leg(topo: &Topology, policy: &Policy, demand: &Demand, sink: Sink) -> Leg {
    let mut slots = Vec::new();
    let mut next_dst: u16 = 0;
    let inputs = demand
        .sources
        .iter()
        .map(|&source| {
            for c in 0..source.channels {
                slots.push(Slot { stream: source.stream, src_channel: c, dst_channel: next_dst });
                next_dst += 1;
            }
            plan_input(topo, policy, &demand.constraints, source, sink)
        })
        .collect();
    Leg { sink, inputs, slots }
}

fn plan_input(topo: &Topology, policy: &Policy, c: &Constraints, source: Source, sink: Sink) -> Input {
    let clock = protocol::clock_bridge_in(topo, source.proto, sink.proto);
    let (mode, via) = if source.proto == sink.proto {
        (Mode::Passthrough { clock }, None)
    } else {
        match transcode_site(topo, source, sink) {
            Some(at) => (
                Mode::Transcode { from: source.proto, to: sink.proto, at, clock },
                (at != source.node && at != sink.node).then_some(at),
            ),
            None => {
                return Input {
                    source,
                    mode: Mode::Unbridged { from: source.proto, to: sink.proto },
                    // No point routing a leg that cannot be bridged; the path
                    // is still computed so the operator sees both facts.
                    path: path_between(topo, policy, c, source.stream, source.node, sink.node),
                };
            }
        }
    };
    let path = match via {
        None => path_between(topo, policy, c, source.stream, source.node, sink.node),
        Some(gw) => match (
            path_between(topo, policy, c, source.stream, source.node, gw),
            path_between(topo, policy, c, source.stream, gw, sink.node),
        ) {
            (Path::Unroutable { from, to }, _) | (_, Path::Unroutable { from, to }) => Path::Unroutable { from, to },
            (a, b) => Path::ViaGateway { to_gateway: route_of(a), to_sink: route_of(b) },
        },
    };
    Input { source, mode, path }
}

/// Where a `source.proto → sink.proto` transcode happens: the source node if it
/// honours the translation (it emits the sink's protocol directly), else the
/// sink node (it ingests the source's), else the mesh-elected gateway. The
/// endpoint preference saves a hop *and* is still deterministic: both are facts
/// in the shared view.
fn transcode_site(topo: &Topology, source: Source, sink: Sink) -> Option<NodeId> {
    let honours = |n: NodeId| topo.facts(n).is_some_and(|f| f.protocols.translates(source.proto, sink.proto));
    if honours(source.node) {
        Some(source.node)
    } else if honours(sink.node) {
        Some(sink.node)
    } else {
        gateway::elect(topo, source.proto, sink.proto)
    }
}

fn path_between(topo: &Topology, policy: &Policy, c: &Constraints, ch: ChannelId, from: NodeId, to: NodeId) -> Path {
    if from == to {
        return Path::Local;
    }
    let req = RouteRequest { channel: ch, src: from, dst: to, constraints: c.clone() };
    match routing::plan(topo, policy, &req) {
        Some(r) => Path::Direct(r),
        None => Path::Unroutable { from, to },
    }
}

/// A `Local` or `Direct` path as the route it carries (a zero-hop route for
/// `Local`). Only called on paths already known not to be `Unroutable`.
fn route_of(p: Path) -> Route {
    match p {
        Path::Direct(r) => r,
        Path::Local => Route { hops: Vec::new(), cost: 0.0 },
        // `ViaGateway` is only ever built here from two single legs, and
        // `Unroutable` is filtered by the caller before this is reached.
        Path::ViaGateway { .. } | Path::Unroutable { .. } => unreachable!("route_of is only given single-hop-class paths"),
    }
}
