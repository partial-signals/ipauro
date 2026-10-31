//! Sample-rate policy (R003-F8): the One Rate, gossiped, plus the per-stream
//! clock cascade.
//!
//! **48 kHz is the mesh rate.** It is a mesh-consensus value modelled exactly
//! like [`PolicyEpoch`](crate::policy::PolicyEpoch): a [`MeshRate`] stamped with
//! a monotonic epoch, adopted iff it supersedes the local one (higher epoch
//! wins, equal epoch → lowest proposer id). It is raised only by a new epoch
//! that lifts the *whole* mesh; a node never advertises a rate other than the
//! one it has adopted, so divergent-rate conversion does not arise.
//!
//! The **cascade** ([`resolve`]) governs the exceptions, per stream:
//! (a) an input follows its corresponding output; (b) an output follows the host
//! hardware clock; (c) a generic external input, or a fan-out with no single
//! partner, takes the mesh rate. (a)+(b) chain, so authority lands at the
//! consuming hardware.
//!
//! **Nominal-rate agreement is not clock agreement.** Crystals drift ppm even at
//! a shared 48 kHz, so every participating stream still gets ASRC (R010-F4);
//! [`Asrc::NearUnity`] is the cheap ppm-correcting case, [`Asrc::Ratio`] a real
//! conversion.
//!
//! **Participation is capability-based**: a stream participates iff its protocol
//! carries PCM samples ([`participates`] reads
//! [`ProtocolProfile::carries_media`](crate::protocol::ProtocolProfile::carries_media)),
//! never the protocol's name. Pure tempo/phase sync does not.

use crate::gossip::Record;
use crate::ids::NodeId;
use crate::protocol::{ProtocolId, Profiles};

/// The default, evangelized mesh rate.
pub const DEFAULT_RATE_HZ: u32 = 48_000;

/// Rates a whole-mesh proposal may name (R003-T5). 48 kHz stays the default;
/// the rest are the standard audio families.
pub const ALLOWED_RATES_HZ: &[u32] = &[44_100, 48_000, 88_200, 96_000, 176_400, 192_000];

/// Why a rate proposal was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RateError {
    /// `hz` is not one of [`ALLOWED_RATES_HZ`].
    NotAllowed(u32),
    /// `hz` is already the adopted rate; a new epoch would change nothing.
    AlreadyAdopted(u32),
}

impl std::fmt::Display for RateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateError::NotAllowed(hz) => {
                write!(f, "{hz} Hz is not an allowed mesh rate (allowed: {ALLOWED_RATES_HZ:?})")
            }
            RateError::AlreadyAdopted(hz) => write!(f, "the mesh already runs at {hz} Hz"),
        }
    }
}

impl std::error::Error for RateError {}

/// The mesh-wide sample rate and the epoch that stamps it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MeshRate {
    pub hz: u32,
    pub epoch: u64,
    /// Proposer of this epoch; only used to break same-epoch conflicts.
    pub author: NodeId,
}

impl MeshRate {
    /// The default rate (48 kHz) at epoch 0.
    pub fn new(author: NodeId) -> Self {
        Self { hz: DEFAULT_RATE_HZ, epoch: 0, author }
    }

    /// Does `other` supersede `self`? Higher epoch wins; equal epoch → lower
    /// proposer id (the mesh-wide tie-break). Identical values do not supersede.
    pub fn superseded_by(&self, other: &MeshRate) -> bool {
        other.epoch > self.epoch
            || (other.epoch == self.epoch && other.author.wins_tiebreak_over(&self.author))
    }

    /// Propose lifting the whole mesh to `hz`: the next epoch, authored by
    /// `author`. Gossip it; it takes effect on a node only when adopted.
    pub fn raise(&self, hz: u32, author: NodeId) -> MeshRate {
        MeshRate { hz, epoch: self.epoch + 1, author }
    }

    /// [`raise`](Self::raise), validated: `hz` must be allowed and differ from
    /// the adopted rate. The only entry point a user-facing proposal should use.
    pub fn propose(&self, hz: u32, author: NodeId) -> Result<MeshRate, RateError> {
        if !ALLOWED_RATES_HZ.contains(&hz) {
            return Err(RateError::NotAllowed(hz));
        }
        if hz == self.hz {
            return Err(RateError::AlreadyAdopted(hz));
        }
        Ok(self.raise(hz, author))
    }

    /// Adopt the rate carried by `record` if it supersedes this one. Returns
    /// whether the mesh rate changed.
    pub fn observe(&mut self, record: &Record) -> bool {
        match record.policy.as_ref() {
            Some(p) if self.superseded_by(&p.rate) => {
                *self = p.rate;
                true
            }
            _ => false,
        }
    }
}

/// Whether a stream of `proto` takes part in the rate policy: iff it carries
/// PCM samples. Decided from the protocol's row (in-tree or an adapter's
/// declared one, read through `rows`), never its name. No row = no media.
pub fn participates(rows: &dyn Profiles, proto: ProtocolId) -> bool {
    rows.row(proto).is_some_and(|r| r.carries_media())
}

/// What a stream is, for clocking purposes.
#[derive(Clone, PartialEq, Debug)]
pub enum Role {
    /// A stream the host renders to hardware; follows the host clock. `None`
    /// means the host rate is unknown, which falls back to the mesh rate.
    Output { host_hz: Option<u32> },
    /// A stream arriving at the host. `partner` is its corresponding output
    /// (rule a); `None` is a generic external input or a fan-out with no single
    /// partner (rule c).
    Input { partner: Option<Box<StreamClock>> },
}

/// One stream's inputs to the cascade.
#[derive(Clone, PartialEq, Debug)]
pub struct StreamClock {
    pub proto: ProtocolId,
    /// The rate the stream itself declares (nominal, not disciplined).
    pub nominal_hz: u32,
    pub role: Role,
}

/// Which cascade rule decided the rate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RateSource {
    /// (a) matched the corresponding output.
    Partner,
    /// (b) matched the host hardware clock.
    Host,
    /// (c) the mesh rate.
    Mesh,
}

/// The conversion a participating stream needs. ASRC always runs (crystals
/// drift); the variant says how expensive it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Asrc {
    /// Same nominal rate: ppm drift correction only.
    NearUnity,
    /// A real rate ratio, `from` → `to`.
    Ratio { from: u32, to: u32 },
}

/// The cascade's verdict for one participating stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StreamRate {
    pub hz: u32,
    pub source: RateSource,
    pub asrc: Asrc,
}

/// Resolve the rate for one stream. `None` for a non-participating stream.
/// Pure: same inputs, same answer on every node.
pub fn resolve(rows: &dyn Profiles, mesh: &MeshRate, stream: &StreamClock) -> Option<StreamRate> {
    let (hz, source) = target(rows, mesh, stream)?;
    let asrc = if stream.nominal_hz == hz {
        Asrc::NearUnity
    } else {
        Asrc::Ratio { from: stream.nominal_hz, to: hz }
    };
    Some(StreamRate { hz, source, asrc })
}

/// The rate the cascade assigns, and by which rule.
fn target(rows: &dyn Profiles, mesh: &MeshRate, stream: &StreamClock) -> Option<(u32, RateSource)> {
    if !participates(rows, stream.proto) {
        return None;
    }
    match &stream.role {
        Role::Output { host_hz: Some(hz) } => Some((*hz, RateSource::Host)),
        Role::Output { host_hz: None } => Some((mesh.hz, RateSource::Mesh)),
        Role::Input { partner: Some(p) } => match target(rows, mesh, p) {
            Some((hz, _)) => Some((hz, RateSource::Partner)),
            // A partner that carries no samples cannot dictate a rate.
            None => Some((mesh.hz, RateSource::Mesh)),
        },
        Role::Input { partner: None } => Some((mesh.hz, RateSource::Mesh)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::InTree;
    use crate::policy::Policy;

    fn n(b: u8) -> NodeId {
        NodeId([b; 8])
    }
    fn rec(author: NodeId, p: Policy) -> Record {
        Record { author, seq: 1, edges: None, facts: None, policy: Some(p) }
    }
    fn policy_with(rate: MeshRate) -> Policy {
        let mut p = Policy::new(rate.author);
        p.rate = rate;
        p
    }
    #[test]
    fn propose_validates_and_bumps_the_epoch() {
        let base = MeshRate::new(n(1));
        let raised = base.propose(96_000, n(2)).unwrap();
        assert_eq!((raised.hz, raised.epoch, raised.author), (96_000, 1, n(2)));
        assert!(base.superseded_by(&raised));
        assert_eq!(base.propose(50_000, n(2)), Err(RateError::NotAllowed(50_000)));
        assert_eq!(base.propose(48_000, n(2)), Err(RateError::AlreadyAdopted(48_000)));
        // Lowering is a new epoch too (a raise must be reversible).
        assert_eq!(raised.propose(48_000, n(2)).unwrap().epoch, 2);
    }

    fn audio() -> ProtocolId {
        *ProtocolId::ALL.iter().find(|p| participates(&InTree, **p)).unwrap()
    }
    fn silent() -> ProtocolId {
        *ProtocolId::ALL.iter().find(|p| !participates(&InTree, **p)).unwrap()
    }
    fn out(host: Option<u32>, nominal: u32) -> StreamClock {
        StreamClock { proto: audio(), nominal_hz: nominal, role: Role::Output { host_hz: host } }
    }
    fn input(partner: Option<StreamClock>, nominal: u32) -> StreamClock {
        StreamClock { proto: audio(), nominal_hz: nominal, role: Role::Input { partner: partner.map(Box::new) } }
    }

    #[test]
    fn default_is_48k_epoch_zero() {
        let r = MeshRate::new(n(1));
        assert_eq!((r.hz, r.epoch), (48_000, 0));
        assert_eq!(Policy::new(n(1)).rate, r);
    }

    #[test]
    fn raise_adopted_mesh_wide() {
        let mut p = Policy::new(n(2));
        let raised = p.rate.raise(96_000, n(1));
        p.observe_epoch(&rec(n(1), policy_with(raised)));
        assert_eq!(p.rate.hz, 96_000);
        assert_eq!(p.rate.epoch, 1);
    }

    #[test]
    fn stale_epoch_rejected() {
        let mut r = MeshRate::new(n(1)).raise(96_000, n(1)); // epoch 1
        let stale = MeshRate { hz: 44_100, epoch: 0, author: n(1) };
        assert!(!r.observe(&rec(n(1), policy_with(stale))));
        assert_eq!(r.hz, 96_000);
    }

    #[test]
    fn same_epoch_tiebreak_is_deterministic() {
        let lo = MeshRate { hz: 96_000, epoch: 1, author: n(1) };
        let hi = MeshRate { hz: 88_200, epoch: 1, author: n(9) };
        for order in [[lo, hi], [hi, lo]] {
            let mut r = MeshRate::new(n(5));
            for x in order {
                r.observe(&rec(x.author, policy_with(x)));
            }
            assert_eq!(r, lo, "lowest proposer wins regardless of arrival order");
        }
    }

    #[test]
    fn rate_survives_policy_epoch_replacement() {
        // A newer policy epoch carrying an older rate must not roll the rate back.
        let mut p = Policy::new(n(3));
        let raised = p.rate.raise(96_000, n(3));
        p.rate = raised;
        let mut newer = Policy::new(n(1));
        newer.epoch.epoch = 5;
        p.observe_epoch(&rec(n(1), newer));
        assert_eq!(p.epoch.epoch, 5);
        assert_eq!(p.rate, raised);
    }

    #[test]
    fn rate_epoch_adopted_even_when_policy_epoch_is_not() {
        let mut p = Policy::new(n(3));
        p.epoch.epoch = 9;
        let mut carried = Policy::new(n(1));
        carried.rate = carried.rate.raise(96_000, n(1));
        p.observe_epoch(&rec(n(1), carried));
        assert_eq!(p.epoch.epoch, 9);
        assert_eq!(p.rate.hz, 96_000);
    }

    #[test]
    fn cascade_a_input_follows_output() {
        let mesh = MeshRate::new(n(1));
        let r = resolve(&InTree, &mesh, &input(Some(out(None, 44_100)), 48_000)).unwrap();
        assert_eq!((r.hz, r.source), (48_000, RateSource::Partner));
    }

    #[test]
    fn cascade_b_output_follows_host() {
        let mesh = MeshRate::new(n(1));
        let r = resolve(&InTree, &mesh, &out(Some(44_100), 48_000)).unwrap();
        assert_eq!((r.hz, r.source), (44_100, RateSource::Host));
    }

    #[test]
    fn cascade_c_generic_or_fanout_takes_mesh_rate() {
        let mesh = MeshRate::new(n(1)).raise(96_000, n(1));
        let r = resolve(&InTree, &mesh, &input(None, 48_000)).unwrap();
        assert_eq!((r.hz, r.source), (96_000, RateSource::Mesh));
    }

    #[test]
    fn cascade_chains_to_consuming_hardware() {
        let mesh = MeshRate::new(n(1));
        let chain = input(Some(input(Some(out(Some(44_100), 48_000)), 48_000)), 48_000);
        let r = resolve(&InTree, &mesh, &chain).unwrap();
        assert_eq!((r.hz, r.source), (44_100, RateSource::Partner));
    }

    #[test]
    fn pure_sync_stream_excluded() {
        let mesh = MeshRate::new(n(1));
        let s = StreamClock { proto: silent(), nominal_hz: 48_000, role: Role::Input { partner: None } };
        assert_eq!(resolve(&InTree, &mesh, &s), None);
    }

    #[test]
    fn near_unity_vs_ratio() {
        let mesh = MeshRate::new(n(1));
        let same = resolve(&InTree, &mesh, &input(None, 48_000)).unwrap();
        assert_eq!(same.asrc, Asrc::NearUnity);
        let diff = resolve(&InTree, &mesh, &input(None, 96_000)).unwrap();
        assert_eq!(diff.asrc, Asrc::Ratio { from: 96_000, to: 48_000 });
    }
}
