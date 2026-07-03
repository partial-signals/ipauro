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
}

impl Topology {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one gossip record into the view. Returns whether anything changed
    /// (callers may re-plan on change). A real impl also ages out stale peers on
    /// the Link ttl model (ch. 01 §7) — omitted here.
    pub fn apply(&mut self, record: Record) -> bool {
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
