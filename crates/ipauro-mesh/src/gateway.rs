//! Protocol-NAT gateway election (R010-F2) — the hub/peer election one level up.
//!
//! The mesh's census ([`Topology::protocols_spoken`]) tells every node which
//! protocol families are in play and who speaks each. From that alone, with no
//! configuration, each node derives:
//!
//! 1. **which legs need a gateway** ([`demands`]): a directed pair `from → to`
//!    is a demand when some `from`-speaker cannot be reached natively by some
//!    `to`-speaker — i.e. there is a `from`-speaker that does not speak `to` and
//!    a `to`-speaker that does not speak `from`. Two nodes that share any
//!    protocol talk natively and raise no demand;
//! 2. **who serves each leg** ([`elect`]): among the peers that honour the
//!    translation ([`ProtocolCaps::translates`](crate::capability::ProtocolCaps::translates)),
//!    the lowest id — the same deterministic tie-break as every other
//!    single-owner role ([`crate::election`]), so no consensus round and every
//!    node names the same gateway from the same view;
//! 3. **what is unbridged** ([`plan`]): a demand with no eligible translator is
//!    reported as a leg with `gateway: None`, never silently dropped — a blocked
//!    pair is a first-class, actionable state (W001 R007 philosophy), and it is
//!    exactly what a status surface should show ("Dante and AVB islands present,
//!    no node translates between them").
//!
//! Scope boundary: election is on gossiped *facts*, like the other roles —
//! whether the gateway is *reachable* from each island is the router's question
//! (R010-F3 plans the legs over [`crate::routing`]), and what the gateway does
//! about clock is R010-F4's ([`crate::protocol::clock_bridge`] is its input).

use crate::election::{self, Role};
use crate::ids::NodeId;
use crate::protocol::{ProtocolId, Profiles};
use crate::topology::Topology;

/// One directed translation leg the mesh needs, and who the mesh elected to
/// serve it (`None` = demanded but nobody can — unbridged).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leg {
    pub from: ProtocolId,
    pub to: ProtocolId,
    pub gateway: Option<NodeId>,
}

/// Directed protocol pairs that need a gateway, sorted (`ProtocolId` order on
/// `from`, then `to`). Sync-only protocols (no media) never raise a demand:
/// there is nothing to translate. An extension family (R003-F7) is read
/// through the same row view, so a sidecar's family is an island or a leg
/// exactly like an in-tree one.
pub fn demands(topo: &Topology) -> Vec<(ProtocolId, ProtocolId)> {
    let spoken: Vec<ProtocolId> = topo
        .protocols_spoken()
        .into_iter()
        .filter(|p| topo.row(*p).is_some_and(|r| r.carries_media()))
        .collect();
    let mut out = Vec::new();
    for &from in &spoken {
        for &to in &spoken {
            if from != to && needs_bridge(topo, from, to) {
                out.push((from, to));
            }
        }
    }
    out
}

/// Some `from`-speaker does not speak `to`, and some `to`-speaker does not speak
/// `from` — so a native path between those two does not exist.
fn needs_bridge(topo: &Topology, from: ProtocolId, to: ProtocolId) -> bool {
    let stranded = |speak: ProtocolId, lack: ProtocolId| {
        topo.speakers_of(speak)
            .into_iter()
            .any(|n| topo.facts(n).is_some_and(|f| f.protocols.speaks(lack).is_none()))
    };
    stranded(from, to) && stranded(to, from)
}

/// The gateway for `from → to`: the lowest-id peer honouring that translation.
/// `None` if no peer does. Pure function of the view — identical on every node.
pub fn elect(topo: &Topology, from: ProtocolId, to: ProtocolId) -> Option<NodeId> {
    election::elect(NodeId([0; 8]), topo, Role::ProtocolGateway { from, to })
}

/// Every demanded leg with its elected gateway (or `None`), sorted as
/// [`demands`]. The whole Protocol-NAT assignment for the mesh, derivable by
/// any node without a round-trip.
pub fn plan(topo: &Topology) -> Vec<Leg> {
    demands(topo)
        .into_iter()
        .map(|(from, to)| Leg { from, to, gateway: elect(topo, from, to) })
        .collect()
}
