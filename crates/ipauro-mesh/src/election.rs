//! Leader election for single-owner roles — by **deterministic tie-break, not
//! consensus** (spec §8.3).
//!
//! The mesh needs exactly one owner for a few roles: the media-clock master of a
//! domain, the owner of a multicast group, the owner of a shared sink. Rather
//! than run Raft, every node computes the same winner from the same gossiped
//! candidate set, using the same lowest-id tie-break Link uses to elect a session
//! (link-wire-spec ch. 02 §7.2). No rounds, no quorum, no partition stall: during
//! a partition each side independently picks a leader from *its* view and they
//! reconcile deterministically when the views merge.

use crate::ids::NodeId;
use crate::topology::Topology;

/// A single-owner role.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Master of a media-clock domain (spec §6). On a dedicated p2p link the
    /// talker is master by construction (§7.2); on a shared domain the elected
    /// node fronts the PTP grandmaster.
    ClockMaster,
    /// Owner of a native multicast group (spec §5): the sink that allocates and
    /// announces it.
    MulticastOwner,
    /// Owner of a shared sink.
    SinkOwner,
}

/// Which peers are eligible for a role, from gossiped facts. Kept simple here;
/// a real impl scopes candidates per domain/channel.
fn eligible(topo: &Topology, role: Role) -> Vec<NodeId> {
    topo.peers_sorted()
        .into_iter()
        .filter(|n| match role {
            // A clock master must advertise at least one clock domain.
            Role::ClockMaster => topo
                .facts(*n)
                .and_then(|f| f.tcap.as_ref())
                .is_some_and(|t| !t.clock_domains.is_empty()),
            // A group/sink owner must be a tactus peer (has a tcap) and relay-able.
            Role::MulticastOwner | Role::SinkOwner => topo
                .facts(*n)
                .is_some_and(|f| f.tcap.is_some() && (f.can_relay || matches!(role, Role::SinkOwner))),
        })
        .collect()
}

/// Elect the owner of `role`: the eligible candidate that wins the lowest-id
/// tie-break. `me` is included implicitly if it appears in the topology. Returns
/// `None` if no candidate is eligible.
///
/// Deterministic across nodes given the same topology — that is the whole point.
pub fn elect(_me: NodeId, topo: &Topology, role: Role) -> Option<NodeId> {
    eligible(topo, role)
        .into_iter()
        .reduce(|a, b| if a.wins_tiebreak_over(&b) { a } else { b })
}

/// Convenience: is this node the leader for `role`?
pub fn is_leader(me: NodeId, topo: &Topology, role: Role) -> bool {
    elect(me, topo, role) == Some(me)
}
