//! The mesh view: peers, the links between them, and their capabilities.
//!
//! Link-state, flooded by gossip (spec §8.3): each node advertises its own
//! incident links and its `tcap`; every node folds those into the same graph and
//! therefore computes the same routes. In production back this with `petgraph`;
//! the skeleton uses plain maps to stay dependency-free and obvious.

use std::collections::HashMap;

use crate::capability::Tcap;
use crate::gossip::Record;
use crate::ids::NodeId;
use crate::transport::{LinkQuality, TransportKind};

/// A directed link from one peer to another over one transport, with its measured
/// quality. Directed because quality (and even reachability) can be asymmetric.
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub to: NodeId,
    pub kind: TransportKind,
    pub quality: LinkQuality,
}

/// What a peer can do (capabilities) and whether it can transcode/relay — a hub
/// node satisfies the "fan-in/out/convert" routing constraints (spec §8.4).
#[derive(Clone, Debug, Default)]
pub struct PeerFacts {
    pub tcap: Option<Tcap>,
    /// This peer will relay/forward native flows (act as a routing hop).
    pub can_relay: bool,
    /// Codecs this peer can transcode *between* when acting as a hub.
    pub can_transcode: bool,
}

/// The whole gossiped graph. Eventually consistent; convergence of this graph
/// across nodes is what makes leaderless routing agree (spec §8.3).
#[derive(Default)]
pub struct Topology {
    edges: HashMap<NodeId, Vec<Edge>>,
    facts: HashMap<NodeId, PeerFacts>,
    /// Highest `seq` folded in per author — the dedup watermark. Flood
    /// dissemination delivers the same record by every path into a node, and a
    /// healing partition re-delivers a whole backlog in arbitrary order, so
    /// "newest per author wins" has to be enforced here rather than assumed of
    /// the transport.
    seen: HashMap<NodeId, u64>,
}

impl Topology {
    pub fn new() -> Self {
        Self::default()
    }

    /// Would this record advance the view — i.e. is its `seq` newer than the
    /// newest already folded in from that author?
    ///
    /// Separate from [`apply`](Self::apply) because a dissemination layer needs
    /// the answer *before* it pays to re-flood: a record that fails this is one
    /// every neighbour has already seen, and forwarding it is what turns a flood
    /// into a broadcast storm. [`apply`] re-checks, so `Topology` is safe to use
    /// without consulting this first.
    pub fn accepts(&self, record: &Record) -> bool {
        self.seen.get(&record.author).is_none_or(|&s| record.seq > s)
    }

    /// Fold one gossip record into the view. Returns whether anything changed
    /// (callers may re-plan on change).
    ///
    /// A record that does not [`accepts`](Self::accepts) is dropped whole and
    /// returns `false` without mutating anything — a duplicate flood arrival or
    /// a reordered straggler must not roll the view back to an older link state.
    /// The watermark advances even for a record that carries no `edges`/`facts`
    /// (a bare heartbeat or a policy-only relay), so a replay of the record it
    /// superseded stays rejected.
    ///
    /// Two things a real impl adds: ageing stale peers out on the Link ttl model
    /// (ch. 01 §7), and an incarnation number so an author that restarts and
    /// resets its `seq` is not mistaken for a replay of itself. Both are absent
    /// here; a restarted author is currently silent until its `seq` climbs back
    /// past the watermark.
    pub fn apply(&mut self, record: Record) -> bool {
        if !self.accepts(&record) {
            return false;
        }
        self.seen.insert(record.author, record.seq);
        let mut changed = false;
        if let Some(facts) = record.facts {
            self.facts.insert(record.author, facts);
            changed = true;
        }
        if let Some(edges) = record.edges {
            self.edges.insert(record.author, edges);
            changed = true;
        }
        changed
    }

    pub fn edges_from(&self, n: NodeId) -> &[Edge] {
        self.edges.get(&n).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn facts(&self, n: NodeId) -> Option<&PeerFacts> {
        self.facts.get(&n)
    }

    /// Every peer the view knows about, sorted for determinism (so a global
    /// recompute visits nodes in the same order everywhere).
    pub fn peers_sorted(&self) -> Vec<NodeId> {
        let mut ps: Vec<NodeId> = self
            .edges
            .keys()
            .chain(self.facts.keys())
            .copied()
            .collect();
        ps.sort();
        ps.dedup();
        ps
    }
}
