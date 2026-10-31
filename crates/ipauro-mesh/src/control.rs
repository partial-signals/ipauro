//! Control reachability (R003-F6): every node — including one reachable only
//! over a single hub's audio segment, and including foreign (non-IPAuRo)
//! devices behind a hub — is addressable for **control** from any node in the
//! mesh.
//!
//! The failure designed against is MTRX ⇄ AVB-D16 ⇄ Apple: a box that bridges
//! media faithfully but drops plain IP severs control for everything behind
//! it. So a hub here is a *transparent control relay*:
//!
//! - **Presence** is ordinary link-state. A hub asserts its own incident edges
//!   (including edges to IPAuRo nodes only it can reach) and lists the foreign
//!   leaves on its segment in [`PeerFacts::foreign`]. It also declares
//!   [`PeerFacts::relays_control`]; only a declared relay is used as a hop.
//! - **Routing** ([`plan_control`]) is a deterministic fewest-hops search over
//!   the gossiped graph, so every node picks the same relay chain. Media
//!   planning ([`crate::routing::plan`]) is unrelated: control has no codec,
//!   bandwidth or transcoding constraint, only "can this hop forward control".
//! - **Foreign leaves** have no iroh identity. Each is keyed by
//!   [`foreign_leaf_id`] (hub NodeId + leaf MAC), and the advertising hub is
//!   the terminating relay that delivers the frame as plain IP.
//!
//! The wire half (signed envelope, TTL, forwarding ALPN) is `ipauro-iroh`'s.
//!
//! [`PeerFacts::foreign`]: crate::topology::PeerFacts::foreign
//! [`PeerFacts::relays_control`]: crate::topology::PeerFacts::relays_control

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;

use crate::ids::NodeId;
use crate::topology::Topology;

/// A foreign (non-IPAuRo, no iroh) device a hub reaches on its own segment,
/// e.g. one it leased an address to over DHCP (R005-T6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ForeignLeaf {
    /// The leaf's hardware address — the stable half of its identity.
    pub mac: [u8; 6],
    /// The control-plane-allocated address the hub delivers to. `None` = the
    /// hub sees the device but has no address for it yet (not deliverable).
    pub ipv4: Option<Ipv4Addr>,
}

impl ForeignLeaf {
    /// This leaf's mesh id when advertised by `hub` (see [`foreign_leaf_id`]).
    pub fn id(&self, hub: NodeId) -> NodeId {
        foreign_leaf_id(hub, self.mac)
    }
}

/// Stable mesh id for a foreign leaf: a 64-bit hash of a domain tag, the
/// advertising hub's NodeId and the leaf's MAC.
///
/// Folding in the hub makes the id *per attachment*: the same device moved to
/// another hub is a new entry, which is right — the old hub's route to it is
/// gone and must not be confused with the new one. It survives DHCP
/// re-leases (the address is not an input) and hub restarts (the NodeId is
/// key-derived). It cannot collide with an iroh node's id in practice: those
/// are derived from ed25519 keys through blake3, these from a different
/// domain-tagged hash.
pub fn foreign_leaf_id(hub: NodeId, mac: [u8; 6]) -> NodeId {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in b"ipauro-foreign-leaf-v1".iter().chain(hub.0.iter()).chain(mac.iter()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    NodeId((h ^ (h >> 31)).to_be_bytes())
}

/// What a node should do with a control frame addressed to `dest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlPlan {
    /// `dest` is this node.
    Local,
    /// `dest` is a foreign leaf this node advertises: deliver it as plain IP.
    Terminate { leaf: ForeignLeaf },
    /// Send to `next`; `path` is the whole chain from this node to `dest`.
    Forward { next: NodeId, path: Vec<NodeId> },
    /// No relay chain exists. `refused_by` names the first hub on a path that
    /// *would* work if it relayed control (the AVB-D16 case), if any.
    Unroutable { refused_by: Option<NodeId> },
}

/// How `me` reaches `dest` for control — the status view of [`plan_control`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// No gossiped link state from this node yet; nothing can be said.
    Unknown,
    /// One hop (or `dest` is this node).
    Direct,
    /// Through relays; `hub` is the last one — the hub `dest` sits behind.
    ViaHub { hub: NodeId },
    /// Only reachable through `hub`, which does not advertise control relay.
    HubWontRelay { hub: NodeId },
    Unreachable,
}

/// Plan a control frame from `me` toward `dest`. Deterministic: fewest hops,
/// ties broken by the lexicographically smallest node-id sequence, so every
/// node agrees on the chain.
///
/// An intermediate hop must declare `relays_control`, and so must the hub
/// terminating for a foreign leaf. `me` is exempt as the origin; a forwarding
/// layer that receives a frame from elsewhere must still check its own flag.
pub fn plan_control(topo: &Topology, me: NodeId, dest: NodeId) -> ControlPlan {
    if dest == me {
        return ControlPlan::Local;
    }
    if let Some((hub, leaf)) = topo.foreign_leaf(dest)
        && hub == me
    {
        return ControlPlan::Terminate { leaf: *leaf };
    }
    match search(topo, me, dest, true) {
        Some(path) => ControlPlan::Forward { next: path[1], path },
        None => ControlPlan::Unroutable { refused_by: refusing_hub(topo, me, dest) },
    }
}

/// Status view of how `me` reaches `dest` for control.
pub fn reachability(topo: &Topology, me: NodeId, dest: NodeId) -> Reachability {
    if dest == me {
        return Reachability::Direct;
    }
    if let Some(path) = search(topo, me, dest, true) {
        return match path.len() {
            2 => Reachability::Direct,
            n => Reachability::ViaHub { hub: path[n - 2] },
        };
    }
    if let Some(hub) = refusing_hub(topo, me, dest) {
        return Reachability::HubWontRelay { hub };
    }
    let knows_own_links =
        !topo.edges_from(me).is_empty() || topo.facts(me).is_some_and(|f| !f.foreign.is_empty());
    if knows_own_links { Reachability::Unreachable } else { Reachability::Unknown }
}

/// Every control destination this node knows (iroh peers and foreign leaves)
/// with its next hop — what a forwarding layer can cache between topology
/// changes. `Local`/`Unroutable` entries are omitted.
pub fn next_hops(topo: &Topology, me: NodeId) -> BTreeMap<NodeId, NodeId> {
    let mut dests = topo.peers_sorted();
    for p in topo.peers_sorted() {
        if let Some(f) = topo.facts(p) {
            dests.extend(f.foreign.iter().map(|l| l.id(p)));
        }
    }
    dests
        .into_iter()
        .filter_map(|d| match plan_control(topo, me, d) {
            ControlPlan::Forward { next, .. } => Some((d, next)),
            ControlPlan::Local | ControlPlan::Terminate { .. } | ControlPlan::Unroutable { .. } => None,
        })
        .collect()
}

/// The first non-relaying intermediate on the best path that ignores relay
/// declarations — the hub whose refusal cuts `dest` off.
fn refusing_hub(topo: &Topology, me: NodeId, dest: NodeId) -> Option<NodeId> {
    let path = search(topo, me, dest, false)?;
    // path[0] is me (exempt); the destination itself is not a relay, but a
    // foreign leaf's hub (path[len-2]) is, and is included in 1..len-1.
    path[1..path.len() - 1].iter().copied().find(|n| !relays(topo, *n))
}

fn relays(topo: &Topology, n: NodeId) -> bool {
    topo.facts(n).is_some_and(|f| f.relays_control)
}

/// Neighbours of `n`: its asserted edges plus the foreign leaves it
/// advertises, sorted and deduplicated for determinism.
fn neighbours(topo: &Topology, n: NodeId) -> Vec<NodeId> {
    let mut v: Vec<NodeId> = topo.edges_from(n).iter().map(|e| e.to).collect();
    if let Some(f) = topo.facts(n) {
        v.extend(f.foreign.iter().map(|l| l.id(n)));
    }
    v.sort();
    v.dedup();
    v
}

/// Breadth-first, neighbours in sorted order: the first path found is the
/// fewest-hops one with the smallest id sequence. With `require_relay`, only
/// `me` and declared relays are expanded.
fn search(topo: &Topology, me: NodeId, dest: NodeId, require_relay: bool) -> Option<Vec<NodeId>> {
    let mut parent: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    let mut queue = VecDeque::from([me]);
    while let Some(n) = queue.pop_front() {
        if n != me && require_relay && !relays(topo, n) {
            continue;
        }
        for m in neighbours(topo, n) {
            if m == me || parent.contains_key(&m) {
                continue;
            }
            parent.insert(m, n);
            if m == dest {
                let mut path = vec![dest];
                let mut at = dest;
                while let Some(&p) = parent.get(&at) {
                    path.push(p);
                    at = p;
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(m);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::Record;
    use crate::topology::{Edge, PeerFacts};
    use crate::transport::{LinkQuality, TransportKind};

    fn n(b: u8) -> NodeId {
        NodeId([b; 8])
    }
    fn e(to: NodeId) -> Edge {
        Edge {
            to,
            kind: TransportKind::Ethernet,
            quality: LinkQuality { rtt_us: 100, jitter_us: 10, bandwidth_bps: 0, loss: 0.0 },
        }
    }
    fn rec(author: NodeId, to: &[NodeId], relays: bool, foreign: Vec<ForeignLeaf>) -> Record {
        Record {
            author,
            seq: 1,
            edges: Some(to.iter().copied().map(e).collect()),
            facts: Some(PeerFacts { relays_control: relays, foreign, ..Default::default() }),
            policy: None,
        }
    }
    fn leaf(last: u8) -> ForeignLeaf {
        ForeignLeaf { mac: [2, 0, 0, 0, 0, last], ipv4: Some(Ipv4Addr::new(10, 42, 9, last)) }
    }

    /// A — H — C, plus a foreign leaf L on H's segment. A cannot reach C or L
    /// except through H (the single-port audio-segment shape).
    fn segment(hub_relays: bool) -> (Topology, NodeId, NodeId, NodeId, NodeId) {
        let (a, h, c) = (n(1), n(5), n(9));
        let l = leaf(7).id(h);
        let mut t = Topology::new();
        t.apply(rec(a, &[h], false, vec![]));
        t.apply(rec(h, &[a, c], hub_relays, vec![leaf(7)]));
        t.apply(rec(c, &[h], false, vec![]));
        (t, a, h, c, l)
    }

    #[test]
    fn leaf_id_is_stable_per_hub_and_mac() {
        let (h1, h2) = (n(1), n(2));
        let mac = [2, 0, 0, 0, 0, 1];
        assert_eq!(foreign_leaf_id(h1, mac), foreign_leaf_id(h1, mac));
        assert_ne!(foreign_leaf_id(h1, mac), foreign_leaf_id(h2, mac), "attachment-scoped");
        assert_ne!(foreign_leaf_id(h1, mac), foreign_leaf_id(h1, [2, 0, 0, 0, 0, 2]));
        // The address is not an input: a DHCP re-lease keeps the id.
        let a = ForeignLeaf { mac, ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)) };
        let b = ForeignLeaf { mac, ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)) };
        assert_eq!(a.id(h1), b.id(h1));
    }

    #[test]
    fn route_reaches_downstream_iroh_node_and_foreign_leaf_via_the_hub() {
        let (t, a, h, c, l) = segment(true);
        assert_eq!(plan_control(&t, a, c), ControlPlan::Forward { next: h, path: vec![a, h, c] });
        assert_eq!(plan_control(&t, a, l), ControlPlan::Forward { next: h, path: vec![a, h, l] });
        assert_eq!(plan_control(&t, h, l), ControlPlan::Terminate { leaf: leaf(7) });
        assert_eq!(plan_control(&t, h, c), ControlPlan::Forward { next: c, path: vec![h, c] });
        assert_eq!(plan_control(&t, c, c), ControlPlan::Local);
        assert_eq!(t.foreign_leaf(l), Some((h, &leaf(7))));
        // The table every node can cache agrees with the per-frame plan.
        let hops = next_hops(&t, a);
        assert_eq!(hops.get(&c), Some(&h));
        assert_eq!(hops.get(&l), Some(&h));
        assert_eq!(hops.get(&h), Some(&h));
    }

    #[test]
    fn reachability_variants() {
        let (t, a, h, c, l) = segment(true);
        assert_eq!(reachability(&t, a, h), Reachability::Direct);
        assert_eq!(reachability(&t, a, c), Reachability::ViaHub { hub: h });
        assert_eq!(reachability(&t, a, l), Reachability::ViaHub { hub: h });
        assert_eq!(reachability(&t, a, a), Reachability::Direct);

        // The AVB-D16 shape: the hub bridges but does not relay control.
        let (t, a, h, c, l) = segment(false);
        assert_eq!(reachability(&t, a, c), Reachability::HubWontRelay { hub: h });
        assert_eq!(reachability(&t, a, l), Reachability::HubWontRelay { hub: h });
        assert_eq!(plan_control(&t, a, c), ControlPlan::Unroutable { refused_by: Some(h) });

        // Known links but no path at all.
        let mut t = Topology::new();
        t.apply(rec(n(1), &[n(5)], false, vec![]));
        t.apply(rec(n(9), &[], false, vec![]));
        assert_eq!(reachability(&t, n(1), n(9)), Reachability::Unreachable);
        assert_eq!(plan_control(&t, n(1), n(9)), ControlPlan::Unroutable { refused_by: None });

        // No link state from this node at all: unknown, not "unreachable".
        let mut t = Topology::new();
        t.apply(rec(n(9), &[], false, vec![]));
        assert_eq!(reachability(&t, n(1), n(9)), Reachability::Unknown);
    }

    #[test]
    fn route_is_fewest_hops_then_smallest_ids_and_deterministic() {
        // a reaches d via h1 or h2 (both relay); h1 < h2 wins. A 3-hop path
        // via h3 is never preferred.
        let (a, h1, h2, h3, h4, d) = (n(1), n(3), n(4), n(5), n(6), n(9));
        let mut t = Topology::new();
        t.apply(rec(a, &[h2, h1, h3], false, vec![]));
        t.apply(rec(h1, &[d], true, vec![]));
        t.apply(rec(h2, &[d], true, vec![]));
        t.apply(rec(h3, &[h4], true, vec![]));
        t.apply(rec(h4, &[d], true, vec![]));
        assert_eq!(plan_control(&t, a, d), ControlPlan::Forward { next: h1, path: vec![a, h1, d] });
        // A non-relaying h1 shifts the route to h2 rather than failing.
        t.apply(Record { seq: 2, ..rec(h1, &[d], false, vec![]) });
        assert_eq!(plan_control(&t, a, d), ControlPlan::Forward { next: h2, path: vec![a, h2, d] });
    }

    #[test]
    fn a_leaf_is_only_reachable_through_its_own_hub() {
        // Two hubs; the leaf hangs off h2 only. Route must end at h2.
        let (a, h1, h2) = (n(1), n(3), n(4));
        let mut t = Topology::new();
        t.apply(rec(a, &[h1], false, vec![]));
        t.apply(rec(h1, &[a, h2], true, vec![]));
        t.apply(rec(h2, &[h1], true, vec![leaf(2)]));
        let l = leaf(2).id(h2);
        assert_eq!(plan_control(&t, a, l), ControlPlan::Forward { next: h1, path: vec![a, h1, h2, l] });
        assert_eq!(reachability(&t, a, l), Reachability::ViaHub { hub: h2 });
    }
}
