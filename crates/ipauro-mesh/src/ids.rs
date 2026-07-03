//! Identifiers. The mesh keys everything on the peer's 8-byte Link NodeId, so a
//! mesh node and its Link/tactus peer are the same identity — the tie-break that
//! elects leaders (`election`) is byte-order on this value, exactly as Link's
//! session election is (link-wire-spec ch. 02 §7.2).

/// 8-byte node identity, shared with the underlying Link/tactus peer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodeId(pub [u8; 8]);

/// 8-byte channel identity (as published by a tactus sink).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ChannelId(pub [u8; 8]);

impl NodeId {
    /// Deterministic tie-break primitive: the byte-wise lesser id wins, matching
    /// Link's session-id tie-break so mesh and session elections never disagree.
    pub fn wins_tiebreak_over(&self, other: &NodeId) -> bool {
        self.0 < other.0
    }
}
