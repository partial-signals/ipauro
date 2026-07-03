//! Policy: the shared objective, its weights, and the monotonic epoch (spec §8.3).
//!
//! The mesh reaches agreement **without consensus** by agreeing on the
//! *objective*, not the *outcome*: given the same weights and the same gossiped
//! topology, every node's deterministic optimizer produces the same routes
//! (`routing`). The one strongly-ordered datum is the [`PolicyEpoch`] — which
//! objective is currently in force — gossiped with highest-epoch / lowest-id
//! wins. That is a monotonic counter, not a Raft log.

use crate::gossip::Record;
use crate::ids::NodeId;
use crate::transport::TransportKind;

/// Weights of the edge-cost objective. Shared mesh-wide; changing them is a new
/// [`PolicyEpoch`]. All nodes compute [`crate::transport::LinkQuality::cost`]
/// with the same weights, so edge costs are identical everywhere.
#[derive(Clone, Copy, Debug)]
pub struct Weights {
    pub rtt: f64,
    pub jitter: f64,
    pub loss: f64,
    /// Weight on inverse bandwidth (penalize narrow links).
    pub inv_bandwidth: f64,
}

impl Default for Weights {
    fn default() -> Self {
        // A latency-first default: jitter and loss dominate, bandwidth breaks ties.
        Self {
            rtt: 1.0,
            jitter: 2.0,
            loss: 4.0,
            inv_bandwidth: 0.5,
        }
    }
}

/// Explicit service-order preference applied *after* feasibility (spec §8.4).
/// A transport earlier in `prefer` is chosen over a later one even at somewhat
/// worse measured cost, up to `override_margin` (a cost ratio). This is how
/// "prefer Thunderbolt even at higher RTT" is expressed without letting
/// preference defeat a genuinely better path by an unbounded margin.
#[derive(Clone, Debug)]
pub struct ServiceOrder {
    pub prefer: Vec<TransportKind>,
    /// Max cost ratio by which a preferred transport may lose on measurement and
    /// still be chosen (e.g. 1.5 = accept 50% worse cost to honor preference).
    pub override_margin: f64,
}

impl Default for ServiceOrder {
    fn default() -> Self {
        Self {
            // Wired/dedicated first, wireless last.
            prefer: vec![
                TransportKind::Thunderbolt,
                TransportKind::Ethernet,
                TransportKind::UsbBridge,
                TransportKind::LinkMulticast,
                TransportKind::IrohOverlay,
                TransportKind::Wifi,
            ],
            override_margin: 1.5,
        }
    }
}

impl ServiceOrder {
    /// Preference rank of a transport (lower = more preferred). Unknown kinds
    /// sort last.
    pub fn rank(&self, kind: TransportKind) -> usize {
        self.prefer
            .iter()
            .position(|k| *k == kind)
            .unwrap_or(self.prefer.len())
    }
}

/// A monotonic identifier for the active objective. Ordered by `(epoch, author)`
/// with higher epoch winning and the lower author id breaking ties — the same
/// deterministic tie-break used everywhere in the mesh.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyEpoch {
    pub epoch: u64,
    pub author: NodeId,
}

impl PolicyEpoch {
    /// Does `other` supersede `self`? Higher epoch wins; equal epoch → lower id.
    pub fn superseded_by(&self, other: &PolicyEpoch) -> bool {
        other.epoch > self.epoch
            || (other.epoch == self.epoch && other.author.wins_tiebreak_over(&self.author))
    }
}

/// The active policy: objective weights, service order, and the epoch that
/// stamps them.
#[derive(Clone, Debug)]
pub struct Policy {
    pub weights: Weights,
    pub service_order: ServiceOrder,
    pub epoch: PolicyEpoch,
}

impl Policy {
    pub fn new(author: NodeId) -> Self {
        Self {
            weights: Weights::default(),
            service_order: ServiceOrder::default(),
            epoch: PolicyEpoch { epoch: 0, author },
        }
    }

    /// Adopt a policy carried in gossip if it supersedes the current one. This is
    /// the *only* place the objective changes; between changes every node
    /// optimizes against an identical objective, which is what lets independent
    /// optimizers converge without consensus.
    pub fn observe_epoch(&mut self, record: &Record) {
        if let Some(p) = record.policy.as_ref()
            && self.epoch.superseded_by(&p.epoch)
        {
            *self = p.clone();
        }
    }
}
