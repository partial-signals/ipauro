//! The mesh view: peers, the links between them, and their capabilities.
//!
//! Link-state, flooded by gossip (spec §8.3): each node advertises its own
//! incident links and its `tcap`; every node folds those into the same graph and
//! therefore computes the same routes. In production back this with `petgraph`;
//! the skeleton uses plain maps to stay dependency-free and obvious.

use std::collections::HashMap;

use crate::capability::{ProtocolCaps, Tcap};
use crate::gossip::Record;
use crate::ids::NodeId;
use crate::protocol::{self, ProtocolId, Profiles, Row};
use crate::transport::{LinkQuality, TransportKind};

/// A directed link from one peer to another over one transport, with its measured
/// quality. Directed because quality (and even reachability) can be asymmetric.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Edge {
    pub to: NodeId,
    pub kind: TransportKind,
    pub quality: LinkQuality,
}

/// The per-machine role a USER elects (R003-F4): a `Hub` bridges its member
/// links (and still participates as a peer); a `Peer` creates no bridge. This is
/// an operator choice gossiped as a fact — distinct from the automatic
/// single-owner elections in [`crate::election`]. Default = `Hub`, which is what
/// M1's manual bridge-up model already was.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeRole {
    #[default]
    Hub,
    Peer,
}

/// What a peer can do (capabilities) and whether it can transcode/relay — a hub
/// node satisfies the "fan-in/out/convert" routing constraints (spec §8.4).
#[derive(Clone, Debug, Default)]
pub struct PeerFacts {
    pub tcap: Option<Tcap>,
    /// This peer will relay/forward native flows (act as a routing hop).
    pub can_relay: bool,
    /// Codecs this peer can transcode *between* when acting as a tactus hub
    /// (codec-level, within the tactus protocol). Protocol-*family* translation
    /// (Dante → AVB) is [`ProtocolCaps::translates`], not this flag.
    pub can_transcode: bool,
    /// Which protocol families this peer speaks and can translate between
    /// (R010-F1). Default = speaks nothing beyond what `tcap` implies.
    pub protocols: ProtocolCaps,
    /// The IPv4 address this peer is using (R003-T3). Advertised as an
    /// observable for divergence detection, not an input — see
    /// [`crate::addressing`].
    pub addr: Option<crate::addressing::AddrClaim>,
    /// The role the machine's user elected (R003-F4). Read-only from every
    /// other node: only the author's record can change it.
    pub role: NodeRole,
    /// This peer forwards plain control frames for others (R003-F6): it is a
    /// transparent control relay, not a media-only bridge. A hub that bridges
    /// media but leaves this `false` is exactly the AVB-D16 failure, and
    /// status reports it as a blockage for every node only reachable via it.
    pub relays_control: bool,
    /// Foreign (non-IPAuRo, no iroh) devices this peer reaches on its own
    /// segment and terminates control for (R003-F6). Link-state: a hub asserts
    /// only its own downstream leaves; each becomes a routable topology entry
    /// keyed by [`crate::control::foreign_leaf_id`].
    pub foreign: Vec<crate::control::ForeignLeaf>,
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

impl Profiles for Topology {
    /// In-tree rows from the table. An extension family's row is the one
    /// declared by its **lowest-id** speaker that carries one — a pure function
    /// of the view, so every node reads the same axes (and elects the same
    /// gateway) even if two speakers' declarations differ.
    fn row(&self, id: ProtocolId) -> Option<Row<'_>> {
        match id {
            ProtocolId::Ext(_) => self
                .speakers_of(id)
                .into_iter()
                .find_map(|n| self.facts.get(&n)?.protocols.speaks(id)?.ext.as_ref())
                .map(Row::Ext),
            in_tree => protocol::in_tree(in_tree).map(Row::InTree),
        }
    }
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
    /// into a broadcast storm. [`apply`](Self::apply) re-checks, so `Topology` is safe to use
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

    /// Drop a silent peer's edges and facts (membership expiry, R003-F2). The
    /// `seen` watermark is deliberately kept: a replay of the record that
    /// introduced the peer must not resurrect it; only a record with a newer
    /// `seq` (the peer actually back) is accepted again. Returns whether the
    /// peer was known.
    pub fn forget(&mut self, n: NodeId) -> bool {
        let e = self.edges.remove(&n).is_some();
        let f = self.facts.remove(&n).is_some();
        e || f
    }

    pub fn edges_from(&self, n: NodeId) -> &[Edge] {
        self.edges.get(&n).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn facts(&self, n: NodeId) -> Option<&PeerFacts> {
        self.facts.get(&n)
    }

    /// Peers advertising that they speak `proto`, sorted. A protocol with
    /// speakers but no translator to anything else is an *island* — the
    /// condition R010-F2 elects a gateway for.
    pub fn speakers_of(&self, proto: ProtocolId) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .facts
            .iter()
            .filter(|(_, f)| f.protocols.speaks(proto).is_some())
            .map(|(n, _)| *n)
            .collect();
        v.sort();
        v
    }

    /// Peers that honour the translation `from` → `to` (see
    /// [`ProtocolCaps::translates`]), sorted — the gateway candidate set.
    pub fn translators(&self, from: ProtocolId, to: ProtocolId) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .facts
            .iter()
            .filter(|(_, f)| f.protocols.translates(from, to))
            .map(|(n, _)| *n)
            .collect();
        v.sort();
        v
    }

    /// Every protocol at least one peer speaks, sorted — the mesh's protocol
    /// census, from which islands and bridgeable pairs are read.
    pub fn protocols_spoken(&self) -> Vec<ProtocolId> {
        let mut v: Vec<ProtocolId> = self
            .facts
            .values()
            .flat_map(|f| f.protocols.speaks.iter().map(|c| c.proto))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// The foreign leaf with this id and the hub advertising it. Two hubs
    /// cannot both advertise one id (the id folds in the hub's NodeId), so the
    /// answer is unique.
    pub fn foreign_leaf(&self, id: NodeId) -> Option<(NodeId, &crate::control::ForeignLeaf)> {
        self.facts.iter().find_map(|(hub, f)| {
            f.foreign.iter().find(|l| l.id(*hub) == id).map(|l| (*hub, l))
        })
    }

    /// Every advertised foreign leaf with its hub, sorted by leaf id.
    pub fn foreign_leaves(&self) -> Vec<(NodeId, crate::control::ForeignLeaf)> {
        let mut v: Vec<(NodeId, crate::control::ForeignLeaf)> =
            self.facts.iter().flat_map(|(h, f)| f.foreign.iter().map(move |l| (*h, *l))).collect();
        v.sort_by_key(|(h, l)| l.id(*h));
        v
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
