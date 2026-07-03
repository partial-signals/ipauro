//! Route planning: **feasibility-first, preference-second** (spec §8.4).
//!
//! A demand is "carry channel X from `src` to `dst`, meeting these functional
//! constraints (codec, must pass a transcoding hub, bandwidth), preferring these
//! transports". The planner:
//!
//! 1. **filters** the graph to edges/paths that satisfy the constraints
//!    (reachability, required conversion available, capacity), then
//! 2. **ranks** the feasible paths by a cost that folds measured link cost
//!    (shared `Weights`) with service-order preference (`ServiceOrder`).
//!
//! Because every input (topology, weights, service order) is gossiped and every
//! node runs *this same deterministic function*, all nodes derive the same route
//! — consistency without consensus (spec §8.3). Ties break on the path's
//! node-id sequence so the determinism is total.

use crate::ids::{ChannelId, NodeId};
use crate::policy::Policy;
use crate::topology::{Edge, Topology};

/// A functional requirement a route MUST satisfy (the filter stage).
#[derive(Clone, Debug, Default)]
pub struct Constraints {
    /// The route must be able to deliver this codec end to end (directly or via a
    /// transcoding hop). `None` = any.
    pub require_codec: Option<crate::capability::Codec>,
    /// Minimum usable bandwidth along every hop, bits/s.
    pub min_bandwidth_bps: u64,
    /// The route must pass through a node that can transcode/fan (a hub). Set for
    /// "make it just work" flows that need conversion neither endpoint offers.
    pub require_hub: bool,
    /// Never route over these transports (e.g. exclude metered Wi-Fi).
    pub forbid: Vec<crate::transport::TransportKind>,
    /// Max hops (a relay chain longer than this is rejected).
    pub max_hops: u8,
}

/// A demand to plan.
#[derive(Clone, Debug)]
pub struct RouteRequest {
    pub channel: ChannelId,
    pub src: NodeId,
    pub dst: NodeId,
    pub constraints: Constraints,
}

/// A planned path: the node sequence and the transport used at each hop.
#[derive(Clone, Debug)]
pub struct Route {
    pub hops: Vec<Hop>,
    /// Total ranked cost (measured cost adjusted by service-order preference).
    pub cost: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct Hop {
    pub from: NodeId,
    pub edge: Edge,
}

/// Plan the best feasible route, or `None` if the constraints cannot be met.
///
/// Deterministic: same (topology, policy, request) → same route on every node.
pub fn plan(topo: &Topology, policy: &Policy, req: &RouteRequest) -> Option<Route> {
    // Dijkstra over the *ranked* edge cost, pruning edges that violate the
    // per-hop constraints. The hub requirement is a path-level predicate checked
    // on candidate completion, so we keep the best hub-satisfying and best
    // overall frontier together and accept the first that satisfies all
    // path-level constraints.
    use std::cmp::Ordering;
    use std::collections::BinaryHeap;

    // Min-heap via Reverse-ordered f64 wrapper.
    #[derive(Clone)]
    struct State {
        cost: f64,
        at: NodeId,
        hops: Vec<Hop>,
        saw_hub: bool,
    }
    impl PartialEq for State {
        fn eq(&self, o: &Self) -> bool {
            self.cost == o.cost
        }
    }
    impl Eq for State {}
    impl PartialOrd for State {
        fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
            Some(self.cmp(o))
        }
    }
    impl Ord for State {
        fn cmp(&self, o: &Self) -> Ordering {
            // Reverse for min-heap; tie-break on the node id at the frontier so
            // equal-cost expansions are deterministic across nodes.
            o.cost
                .partial_cmp(&self.cost)
                .unwrap_or(Ordering::Equal)
                .then_with(|| o.at.cmp(&self.at))
        }
    }

    let hub_ok = |n: NodeId| {
        topo.facts(n)
            .map(|f| f.can_transcode || f.can_relay)
            .unwrap_or(false)
    };

    let mut heap = BinaryHeap::new();
    heap.push(State {
        cost: 0.0,
        at: req.src,
        hops: Vec::new(),
        saw_hub: hub_ok(req.src),
    });
    // best cost seen per (node, saw_hub) — hub-ness is part of the state because a
    // costlier path that has passed a hub may be the only feasible one.
    let mut best: std::collections::HashMap<(NodeId, bool), f64> = Default::default();

    while let Some(st) = heap.pop() {
        if st.at == req.dst && (!req.constraints.require_hub || st.saw_hub) {
            return Some(Route {
                hops: st.hops,
                cost: st.cost,
            });
        }
        if st.hops.len() as u8 >= req.constraints.max_hops.max(1) {
            continue;
        }
        let key = (st.at, st.saw_hub);
        if best.get(&key).is_some_and(|&c| c <= st.cost) {
            continue;
        }
        best.insert(key, st.cost);

        for e in topo.edges_from(st.at) {
            if !edge_feasible(e, &req.constraints, topo, req.constraints.require_codec) {
                continue;
            }
            let step = e.quality.cost(&policy.weights);
            let ranked = apply_service_order(step, e.kind, policy);
            let mut hops = st.hops.clone();
            hops.push(Hop { from: st.at, edge: *e });
            heap.push(State {
                cost: st.cost + ranked,
                at: e.to,
                hops,
                saw_hub: st.saw_hub || hub_ok(e.to),
            });
        }
    }
    None
}

/// Per-hop feasibility (the filter stage). Codec is checked as "either endpoint
/// or a hub on the path can provide it" — here we admit the edge if the *next*
/// node advertises the codec or can transcode; full end-to-end codec proof is
/// completed by the hub predicate at path level.
fn edge_feasible(
    e: &Edge,
    c: &Constraints,
    topo: &Topology,
    require_codec: Option<crate::capability::Codec>,
) -> bool {
    if c.forbid.contains(&e.kind) {
        return false;
    }
    if c.min_bandwidth_bps > 0 && e.quality.bandwidth_bps < c.min_bandwidth_bps {
        return false;
    }
    if let Some(codec) = require_codec {
        let next_ok = topo
            .facts(e.to)
            .map(|f| f.can_transcode || peer_supports_codec(f, codec))
            .unwrap_or(false);
        if !next_ok {
            return false;
        }
    }
    true
}

fn peer_supports_codec(f: &crate::topology::PeerFacts, codec: crate::capability::Codec) -> bool {
    use crate::capability::Codec::*;
    let Some(t) = f.tcap.as_ref() else {
        return false;
    };
    match codec {
        PcmI16 => t.codecs.pcm_i16,
        PcmI24 => t.codecs.pcm_i24,
        PcmF32 => t.codecs.pcm_f32,
        Flac => t.codecs.flac,
        Opus => t.codecs.opus,
    }
}

/// Fold service-order preference into the measured cost (the rank stage).
/// A more-preferred transport gets its cost divided down, but only up to the
/// policy's `override_margin`, so preference biases without letting a bad link
/// win by an unbounded amount (spec §8.4).
fn apply_service_order(cost: f64, kind: crate::transport::TransportKind, policy: &Policy) -> f64 {
    let rank = policy.service_order.rank(kind);
    // rank 0 (most preferred) → divide by override_margin; falls to 1.0 as rank
    // grows, so preference never *inflates* a path, only discounts preferred ones.
    let n = policy.service_order.prefer.len().max(1) as f64;
    let discount = 1.0
        + (policy.service_order.override_margin - 1.0) * (1.0 - rank as f64 / n).clamp(0.0, 1.0);
    cost / discount
}
