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
//!   connection, Thunderbolt/USB-C bridge) as a [`transport::Gateway`],
//!   generalizing Link's per-gateway best-path model (§8.1);
//! - keeps a strict **control/media split** (§8.2): the reliable overlay carries
//!   control only; live audio stays on unreliable/timely datagrams;
//! - coordinates by **gossip + deterministic tie-break, not consensus** (§8.3):
//!   membership/topology/capabilities via gossip, single-owner roles (clock
//!   master, group owner) by the same lowest-id tie-break Link uses for session
//!   election, and flow optimization that converges on shared-objective *inputs*,
//!   never on consensus of outputs;
//! - selects paths **feasibility-first** (§8.4): constraints filter, preferences
//!   rank;
//! - gossips **per-node protocol capability** (R010-F1, A004): which protocol
//!   families a node speaks, with what formats/packetization/clock, and which
//!   pairs it can translate between — the cross-family discovery that lets a
//!   Protocol-NAT gateway be *elected* instead of hand-configured. The registry
//!   of protocol rows is [`protocol`]; the advertisement is
//!   [`capability::ProtocolCaps`];
//! - **elects a Protocol-NAT gateway per translation leg** (R010-F2, [`gateway`]):
//!   which pairs of islands need bridging is derived from the census, who
//!   bridges each is the usual lowest-id tie-break over the nodes that honour
//!   that translation, and a pair nobody can bridge is reported, not dropped;
//! - **plans stream flows** (R010-F3, [`stream`]): 1:1 / fan-in / fan-out, each
//!   source→sink leg independently passthrough or transcode (at the source, the
//!   sink, or the elected gateway), routed over the graph, channel-discrete —
//!   **never mixed**.
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
//! Design skeleton: type design and the non-obvious algorithms (routing,
//! election, epoch/objective, gossip dedup) are fleshed out; transport/gossip
//! dissemination are traits for the tactus and iroh adapters to implement. Not
//! wired into the running product yet, but the algorithms are hardware-free and
//! run in the control-plane CI container (`scripts/ci-control-plane.sh`, R009-T1)
//! — so they are regression-checked before they have a first caller.

#[cfg(test)]
mod tests;

pub mod addressing;
pub mod capability;
pub mod control;
pub mod election;
pub mod gateway;
pub mod gossip;
pub mod ids;
pub mod policy;
pub mod protocol;
pub mod rate;
pub mod routing;
pub mod stream;
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

    /// Read-only view of the gossiped graph — membership, incident links, and
    /// per-peer facts. This is what a status surface renders and what a test
    /// compares across nodes to show two views have converged.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// Which objective is currently in force. The one strongly-ordered datum in
    /// the mesh (§8.3): two nodes on the same epoch are optimizing against
    /// identical weights, which is the precondition for their independently
    /// computed routes to agree.
    pub fn policy_epoch(&self) -> policy::PolicyEpoch {
        self.policy.epoch
    }

    /// The adopted mesh sample rate (R003-F8) and its epoch. A node never
    /// advertises any other rate.
    pub fn mesh_rate(&self) -> rate::MeshRate {
        self.policy.rate
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
    ///
    /// Stale records are rejected *before* the policy is inspected. Ordering
    /// matters: `PolicyEpoch` has its own monotonic ordering, but that only
    /// guards against an older *epoch*, not against a replayed record that
    /// carries a current one — and observing a policy off a record whose link
    /// state we are about to discard would adopt half of it.
    pub fn apply_gossip(&mut self, record: gossip::Record) -> bool {
        if !self.topology.accepts(&record) {
            return false;
        }
        self.policy.observe_epoch(&record);
        self.topology.apply(record)
    }

    /// Expire a peer that has gone silent: remove it from the topology view
    /// (R003-F2). Liveness timing is the dissemination layer's job (it knows
    /// the heartbeat clock); the mesh only owns the resulting view change.
    pub fn forget_peer(&mut self, peer: NodeId) -> bool {
        self.topology.forget(peer)
    }

    /// Plan a route for one demand under the current policy. Feasibility-first:
    /// see [`routing::plan`].
    pub fn plan_route(&self, req: &routing::RouteRequest) -> Option<routing::Route> {
        routing::plan(&self.topology, &self.policy, req)
    }

    /// Plan a control frame toward `dest` (R003-F6): local, terminate for a
    /// foreign leaf this node advertises, forward to a relay, or unroutable.
    pub fn plan_control(&self, dest: NodeId) -> control::ControlPlan {
        control::plan_control(&self.topology, self.me, dest)
    }

    /// How this node reaches `dest` for control (R003-F6).
    pub fn control_reachability(&self, dest: NodeId) -> control::Reachability {
        control::reachability(&self.topology, self.me, dest)
    }

    /// Who owns a single-owner role (clock master for a domain, multicast-group
    /// owner, …), by deterministic tie-break over the gossiped candidate set.
    /// No consensus round: every node computes the same winner from the same view.
    pub fn leader_for(&self, role: election::Role) -> Option<NodeId> {
        election::elect(self.me, &self.topology, role)
    }

    /// Peers that speak `proto`, from the gossiped view (R010-F1). A protocol
    /// whose speakers can reach no translator is a single-protocol island.
    pub fn peers_speaking(&self, proto: protocol::ProtocolId) -> Vec<NodeId> {
        self.topology.speakers_of(proto)
    }

    /// Peers that can bridge `from` → `to` — the candidate set a Protocol-NAT
    /// election (R010-F2) picks from by the usual lowest-id tie-break.
    pub fn translators(&self, from: protocol::ProtocolId, to: protocol::ProtocolId) -> Vec<NodeId> {
        self.topology.translators(from, to)
    }

    /// The mesh's Protocol-NAT assignment (R010-F2): every translation leg the
    /// census demands, with the elected gateway or `None` when no node can
    /// serve it. Same answer on every node from the same view.
    pub fn gateway_plan(&self) -> Vec<gateway::Leg> {
        gateway::plan(&self.topology)
    }

    /// Is this node the elected gateway for `from → to`? What an adapter host
    /// polls to decide whether to stand up that transcode leg.
    pub fn is_gateway_for(&self, from: protocol::ProtocolId, to: protocol::ProtocolId) -> bool {
        gateway::elect(&self.topology, from, to) == Some(self.me)
    }

    /// Plan how a set of streams reaches a set of sinks (R010-F3): one egress
    /// leg per sink, one passthrough-or-transcode input per source, a
    /// channel-discrete slot map, and every blockage named. Deterministic across
    /// nodes, so source, gateway and sink each act on their part of one plan.
    pub fn plan_flow(&self, demand: &stream::Demand) -> stream::Flow {
        stream::plan(&self.topology, &self.policy, demand)
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
