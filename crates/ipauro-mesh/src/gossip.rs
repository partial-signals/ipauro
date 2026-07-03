//! Gossip: membership + link-state dissemination (spec §8.3).
//!
//! The mesh's soft state — who is alive, what transports they expose, link
//! quality, `tcap`, and the active policy epoch — spreads by gossip, exactly as
//! Link discovery already gossips peer state (ch. 01). This module defines the
//! record that travels and the transport-agnostic trait a SWIM-style membership
//! layer (or an iroh-backed flood) implements. The clean-room boundary: the
//! *encoding* of these records on the wire is fixed by the spec (open question
//! §10.6) so independent implementations interoperate; the dissemination policy
//! is this crate's.

use crate::ids::NodeId;
use crate::policy::Policy;
use crate::topology::{Edge, PeerFacts};

/// One gossiped record: what `author` asserts about itself. Link-state — a node
/// advertises only its *own* incident links and facts; the mesh graph is the
/// union of everyone's records.
#[derive(Clone, Debug)]
pub struct Record {
    pub author: NodeId,
    /// Monotonic per-author sequence; a receiver keeps only the newest.
    pub seq: u64,
    /// The author's incident links (`None` = no change this record).
    pub edges: Option<Vec<Edge>>,
    /// The author's capabilities / relay-ability (`None` = no change).
    pub facts: Option<PeerFacts>,
    /// The active policy, if the author is proposing/relaying one. Adopted iff it
    /// supersedes the receiver's epoch (`Policy::observe_epoch`).
    pub policy: Option<Policy>,
}

/// A membership/dissemination backend (SWIM over UDP, or iroh flood). Kept as a
/// trait so the tactus/iroh adapters supply it; the mesh logic above is
/// transport-agnostic.
pub trait Gossip {
    /// Broadcast this node's current record to the mesh.
    fn publish(&self, record: &Record) -> std::io::Result<()>;
    /// Drain records received since the last poll. A real impl delivers these via
    /// callback/stream; polling keeps the skeleton simple.
    fn drain(&mut self) -> Vec<Record>;
}
