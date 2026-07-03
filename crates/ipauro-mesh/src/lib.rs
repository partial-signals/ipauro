//! # ipauro-mesh
//!
//! Control plane for a **tactus-native** audio mesh: a routed, multi-transport
//! overlay that carries tactus sessions across subnets and over point-to-point
//! cables that Link's multicast discovery cannot reach, and that picks the best
//! of several transports to each peer.
//!
//! This crate implements the *wire-relevant mesh* described in
//! `link-wire-spec/spec/proposals/tactus-native-audio.md` §8 — modeled as the
//! algorithms above the wire. It:
//!
//! - treats every transport to a peer (Link multicast interface, iroh overlay
//!   connection, Thunderbolt/USB-C bridge) as a [`Gateway`](transport::Gateway),
//!   generalizing Link's per-gateway best-path model (§8.1);
//! - keeps a strict **control/media split** (§8.2): the reliable overlay carries
//!   control only; live audio stays on unreliable/timely datagrams;
//! - coordinates by **gossip + deterministic tie-break, not consensus** (§8.3):
//!   membership/topology/capabilities via gossip, single-owner roles (clock
//!   master, group owner) by the same lowest-id tie-break Link uses for session
//!   election, and flow optimization that converges on shared-objective *inputs*,
//!   never on consensus of outputs;
//! - selects paths **feasibility-first** (§8.4): constraints filter, preferences
//!   rank.
//!
//! ## Provenance
//!
//! GPL orchestration authored on the *dirty* side of the clean-room split. It
//! consumes the MIT `tactus` crate through its public API and never reaches
//! inside it, so tactus stays clean-room MIT and this crate's GPL status does
//! not propagate into it. Contains no Ableton Link source. The wire formats it
//! relies on come only from the released link-wire-spec.
//!
//! ## Status
//!
//! Design skeleton: type design and the three non-obvious algorithms (routing,
//! election, epoch/objective) are fleshed out; transport/gossip are traits for
//! the tactus and iroh adapters to implement. Not wired to a real build.

#[cfg(test)]
mod tests;

pub mod capability;
pub mod election;
pub mod gossip;
pub mod ids;
pub mod policy;
pub mod routing;
pub mod topology;
pub mod transport;

use std::collections::HashMap;

use ids::NodeId;
use policy::Policy;
use topology::Topology;
use transport::Gateway;

/// A node in the mesh: its identity, the transports it can reach peers over, the
/// gossiped view of the whole mesh, and the current routing policy.
///
/// The facade deliberately exposes *decisions* (routes, elected leaders), not
/// mechanism. Applications drive tactus from those decisions: which gateway to
/// send a channel over, whether this node is the clock master, and so on.
pub struct MeshNode {
    me: NodeId,
    /// Live transports this node can use, keyed by the peer they reach.
    gateways: HashMap<NodeId, Vec<Box<dyn Gateway>>>,
    /// Gossiped view of the mesh (peers, links, capabilities). Eventually
    /// consistent; every node converges to the same graph given the same gossip.
    topology: Topology,
    /// The shared objective/weights plus its monotonic epoch (§8.3).
    policy: Policy,
}

impl MeshNode {
    pub fn new(me: NodeId, policy: Policy) -> Self {
        Self {
            me,
            gateways: HashMap::new(),
            topology: Topology::new(),
            policy,
        }
    }

    pub fn id(&self) -> NodeId {
        self.me
    }

    /// Register a live transport to a peer (a Link multicast interface, an iroh
    /// connection whose direct path is up, a Thunderbolt bridge, …).
    pub fn add_gateway(&mut self, gw: Box<dyn Gateway>) {
        self.gateways.entry(gw.peer()).or_default().push(gw);
    }

    /// The gateway to `peer` a *direct* send should prefer right now: measured
    /// cost adjusted by service order (spec §8.4), lowest wins. This is the local,
    /// single-hop counterpart to [`plan_route`](Self::plan_route) (which plans
    /// multi-hop routes across the gossiped graph); use it when the peer is a
    /// direct neighbour and no relay/transcode is needed.
    pub fn best_gateway(&self, peer: NodeId) -> Option<&dyn Gateway> {
        self.gateways.get(&peer)?.iter().min_by(|a, b| {
            let ca = ranked_cost(a.as_ref(), &self.policy);
            let cb = ranked_cost(b.as_ref(), &self.policy);
            ca.partial_cmp(&cb).unwrap_or(std::cmp::Ordering::Equal)
        }).map(|b| b.as_ref())
    }

    /// Fold a received gossip record into the local view. Membership, link
    /// quality, capabilities, and policy-epoch updates all arrive this way.
    /// Returns whether the local view changed (a change may warrant a re-plan).
    pub fn apply_gossip(&mut self, record: gossip::Record) -> bool {
        self.policy.observe_epoch(&record);
        self.topology.apply(record)
    }

    /// Plan a route for one demand under the current policy. Feasibility-first:
    /// see [`routing::plan`].
    pub fn plan_route(&self, req: &routing::RouteRequest) -> Option<routing::Route> {
        routing::plan(&self.topology, &self.policy, req)
    }

    /// Who owns a single-owner role (clock master for a domain, multicast-group
    /// owner, …), by deterministic tie-break over the gossiped candidate set.
    /// No consensus round: every node computes the same winner from the same view.
    pub fn leader_for(&self, role: election::Role) -> Option<NodeId> {
        election::elect(self.me, &self.topology, role)
    }
}

/// Measured link cost adjusted by service-order preference — the same ranking the
/// multi-hop planner applies per edge (`routing`), reused for direct-neighbour
/// gateway selection.
fn ranked_cost(gw: &dyn Gateway, policy: &policy::Policy) -> f64 {
    let base = gw.quality().cost(&policy.weights);
    let rank = policy.service_order.rank(gw.kind());
    let n = policy.service_order.prefer.len().max(1) as f64;
    let discount = 1.0
        + (policy.service_order.override_margin - 1.0)
            * (1.0 - rank as f64 / n).clamp(0.0, 1.0);
    base / discount
}
