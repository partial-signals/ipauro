//! Skeleton tests: prove the non-obvious behaviors actually hold — routing is
//! feasibility-first and deterministic, election is a stable tie-break, and
//! gossip is idempotent under the two deliveries a flood actually produces
//! (duplicates, and a reordered backlog when a partition heals).
//!
//! These are the hardware-free half of the control plane and run in the Linux
//! container job — see `scripts/ci-control-plane.sh` (R009-T1).

use crate::capability::{Codec, Codecs, Tcap};
use crate::gossip::Record;
use crate::ids::NodeId;
use crate::policy::Policy;
use crate::routing::{Constraints, RouteRequest};
use crate::topology::{Edge, PeerFacts};
use crate::transport::{LinkQuality, TransportKind};
use crate::{election, MeshNode};

fn nid(b: u8) -> NodeId {
    NodeId([b; 8])
}

fn q(rtt: u32) -> LinkQuality {
    LinkQuality {
        rtt_us: rtt,
        jitter_us: rtt / 10,
        bandwidth_bps: 1_000_000_000,
        loss: 0.0,
    }
}

fn tcap_with(codecs: Codecs, clock: bool) -> Tcap {
    Tcap {
        version: 1,
        codecs,
        max_chunk_frames: Some(2048),
        fec: Default::default(),
        clock_domains: if clock {
            vec![crate::capability::ClockDomain::Ptp(0)]
        } else {
            vec![]
        },
        latency_target_ns: None,
        multicast: None,
    }
}

/// Direct low-RTT path A→B exists; a two-hop path via a hub also exists. Without
/// a hub requirement the direct path wins; *with* `require_hub` the planner is
/// forced through the hub even though it costs more — feasibility beats cost.
#[test]
fn routing_is_feasibility_first() {
    let (a, b, hub) = (nid(1), nid(2), nid(9));
    let mut node = MeshNode::new(a, Policy::new(a));

    // A → B direct (cheap), A → hub → B (dearer).
    node.apply_gossip(Record {
        author: a,
        seq: 1,
        edges: Some(vec![
            Edge { to: b, kind: TransportKind::Wifi, quality: q(1_000) },
            Edge { to: hub, kind: TransportKind::Ethernet, quality: q(2_000) },
        ]),
        facts: Some(PeerFacts { tcap: Some(tcap_with(all_codecs(), false)), ..Default::default() }),
        policy: None,
    });
    node.apply_gossip(Record {
        author: hub,
        seq: 1,
        edges: Some(vec![Edge { to: b, kind: TransportKind::Ethernet, quality: q(2_000) }]),
        facts: Some(PeerFacts { tcap: Some(tcap_with(all_codecs(), false)), can_relay: true, can_transcode: true }),
        policy: None,
    });
    node.apply_gossip(Record {
        author: b,
        seq: 1,
        edges: Some(vec![]),
        facts: Some(PeerFacts { tcap: Some(tcap_with(all_codecs(), false)), ..Default::default() }),
        policy: None,
    });

    let base = Constraints { max_hops: 4, ..Default::default() };

    // Unconstrained: shortest path is the 1-hop direct link.
    let r = node.plan_route(&RouteRequest { channel: chan(), src: a, dst: b, constraints: base.clone() }).unwrap();
    assert_eq!(r.hops.len(), 1, "direct path should win without a hub requirement");

    // Hub required: must route A→hub→B even though it is dearer.
    let r = node.plan_route(&RouteRequest {
        channel: chan(),
        src: a,
        dst: b,
        constraints: Constraints { require_hub: true, ..base },
    }).unwrap();
    assert_eq!(r.hops.len(), 2, "hub requirement must force the two-hop path");
    assert_eq!(r.hops[0].edge.to, hub);
}

/// Election is a stable lowest-id tie-break, identical from any node's view.
#[test]
fn election_is_deterministic_tiebreak() {
    let mut node = MeshNode::new(nid(5), Policy::new(nid(5)));
    for b in [nid(3), nid(7), nid(5)] {
        node.apply_gossip(Record {
            author: b,
            seq: 1,
            edges: Some(vec![]),
            facts: Some(PeerFacts { tcap: Some(tcap_with(all_codecs(), true)), can_relay: true, ..Default::default() }),
            policy: None,
        });
    }
    // Lowest id among clock-capable peers wins, regardless of who asks.
    assert_eq!(node.leader_for(election::Role::ClockMaster), Some(nid(3)));
}

fn all_codecs() -> Codecs {
    Codecs { pcm_i16: true, pcm_i24: true, pcm_f32: true, flac: true, opus: true }
}

fn chan() -> crate::ids::ChannelId {
    crate::ids::ChannelId([0xAB; 8])
}

// --- gossip dedup ------------------------------------------------------------
//
// `Record::seq` is the only thing standing between a flood and a broadcast storm,
// and between a reordered backlog and a view that rolls backwards. Every case
// below is a delivery a real dissemination layer produces on its own.

/// A record delivered twice — the ordinary outcome of a flood reaching a node by
/// two paths — must be folded once. The second delivery reports "no change" so a
/// caller does not re-plan, and re-flooding it is visibly unnecessary.
#[test]
fn a_duplicate_flood_arrival_is_folded_once() {
    let (a, b) = (nid(1), nid(2));
    let mut node = MeshNode::new(a, Policy::new(a));

    let rec = || Record {
        author: b,
        seq: 4,
        edges: Some(vec![Edge { to: a, kind: TransportKind::UsbBridge, quality: q(500) }]),
        facts: Some(PeerFacts { tcap: Some(tcap_with(all_codecs(), false)), ..Default::default() }),
        policy: None,
    };

    assert!(node.apply_gossip(rec()), "first delivery is new");
    assert!(!node.apply_gossip(rec()), "second delivery of the same seq must not re-fold");
    assert!(!node.topology().accepts(&rec()), "and must be recognizable as not worth re-flooding");
}

/// A straggler that arrives after a newer record from the same author must not
/// roll the view back. This is the failure a healing partition produces by the
/// dozen: both sides replay their backlog and arrival order is arbitrary.
#[test]
fn a_reordered_straggler_never_rolls_the_view_back() {
    let (a, b, c) = (nid(1), nid(2), nid(3));
    let mut node = MeshNode::new(a, Policy::new(a));

    // b's current state: reaches both a and c.
    node.apply_gossip(Record {
        author: b,
        seq: 9,
        edges: Some(vec![
            Edge { to: a, kind: TransportKind::UsbBridge, quality: q(500) },
            Edge { to: c, kind: TransportKind::UsbBridge, quality: q(500) },
        ]),
        facts: Some(PeerFacts { tcap: Some(tcap_with(all_codecs(), false)), ..Default::default() }),
        policy: None,
    });

    // An older record from b, describing a world where it only reached a.
    let changed = node.apply_gossip(Record {
        author: b,
        seq: 3,
        edges: Some(vec![Edge { to: a, kind: TransportKind::UsbBridge, quality: q(500) }]),
        facts: None,
        policy: None,
    });

    assert!(!changed, "an older seq must be dropped");
    assert_eq!(
        node.topology().edges_from(b).len(),
        2,
        "b's newer two-link state must survive the straggler"
    );
}

/// A record carrying neither edges nor facts still advances the watermark. A
/// bare heartbeat or a policy-only relay changes nothing observable, but if it
/// did not consume its sequence number the record it superseded could be
/// replayed straight back in.
#[test]
fn a_bare_heartbeat_still_consumes_its_sequence_number() {
    let (a, b) = (nid(1), nid(2));
    let mut node = MeshNode::new(a, Policy::new(a));

    node.apply_gossip(Record { author: b, seq: 7, edges: None, facts: None, policy: None });

    let replayed = Record {
        author: b,
        seq: 6,
        edges: Some(vec![Edge { to: a, kind: TransportKind::Wifi, quality: q(9_000) }]),
        facts: None,
        policy: None,
    };
    assert!(!node.apply_gossip(replayed), "seq 6 is behind the seq-7 heartbeat");
    assert!(node.topology().edges_from(b).is_empty(), "the replay must not have landed");
}

/// Dedup runs before the policy is inspected. `PolicyEpoch` ordering rejects an
/// *older* epoch, but it cannot tell that a record is a replay — so a stale
/// record carrying a live policy would otherwise get half-adopted: its objective
/// applied, its link state discarded.
#[test]
fn a_stale_record_cannot_smuggle_a_policy_in() {
    let (a, b) = (nid(1), nid(2));
    let mut node = MeshNode::new(a, Policy::new(a));
    let baseline = node.policy_epoch();

    node.apply_gossip(Record { author: b, seq: 5, edges: None, facts: None, policy: None });

    // Same author, older seq, but carrying a policy that *would* supersede.
    let mut newer = Policy::new(b);
    newer.epoch.epoch = 42;
    let changed = node.apply_gossip(Record {
        author: b,
        seq: 2,
        edges: None,
        facts: None,
        policy: Some(newer),
    });

    assert!(!changed);
    assert_eq!(node.policy_epoch(), baseline, "a dropped record must not move the epoch");
}

// --- partition heal ----------------------------------------------------------

/// Four clock-capable nodes in a line: a—b—c—d. The b—c link is the one that
/// partitions them into {a,b} and {c,d}.
fn line_edges(n: NodeId) -> Vec<Edge> {
    let e = |to| Edge { to, kind: TransportKind::UsbBridge, quality: q(1_000) };
    match n.0[0] {
        1 => vec![e(nid(2))],
        2 => vec![e(nid(1)), e(nid(3))],
        3 => vec![e(nid(2)), e(nid(4))],
        4 => vec![e(nid(3))],
        _ => unreachable!(),
    }
}

fn healed_record(n: NodeId, seq: u64) -> Record {
    Record {
        author: n,
        seq,
        edges: Some(line_edges(n)),
        facts: Some(PeerFacts {
            tcap: Some(tcap_with(all_codecs(), true)),
            can_relay: true,
            can_transcode: false,
        }),
        policy: None,
    }
}

/// The claim in `election`'s module docs — "during a partition each side
/// independently picks a leader from *its* view and they reconcile
/// deterministically when the views merge" — stated as a test.
///
/// Each side is fed only its own half, elects its own leader, then receives the
/// full record set in a *different* order with duplicates interleaved, as a real
/// backlog replay would deliver it. Both must land on one identical view: same
/// membership, same leader, same route for the same demand. No round-trip, no
/// quorum — just the same deterministic function over the same inputs.
#[test]
fn a_healed_partition_converges_to_one_view() {
    let (a, b, c, d) = (nid(1), nid(2), nid(3), nid(4));

    // Partitioned: each side sees only its own half, and each half's members
    // gossiped a different number of times before the heal.
    let mut left = MeshNode::new(a, Policy::new(a));
    for (n, seq) in [(a, 3), (b, 3)] {
        left.apply_gossip(healed_record(n, seq));
    }
    let mut right = MeshNode::new(c, Policy::new(c));
    for (n, seq) in [(c, 11), (d, 11)] {
        right.apply_gossip(healed_record(n, seq));
    }

    let role = election::Role::ClockMaster;
    assert_eq!(left.leader_for(role), Some(a), "left elects the lowest id it can see");
    assert_eq!(right.leader_for(role), Some(c), "right elects the lowest id it can see");
    assert_ne!(left.leader_for(role), right.leader_for(role), "partitioned views disagree");

    // Heal. Both sides receive every author's newest record, in different
    // orders, with re-deliveries mixed in — exactly what a backlog replay over a
    // flood looks like.
    let newest = [(a, 4u64), (b, 4), (c, 12), (d, 12)];
    for &(n, seq) in &[newest[2], newest[3], newest[0], newest[1], newest[2]] {
        left.apply_gossip(healed_record(n, seq));
    }
    for &(n, seq) in &[newest[1], newest[0], newest[3], newest[1], newest[2]] {
        right.apply_gossip(healed_record(n, seq));
    }

    assert_eq!(
        left.topology().peers_sorted(),
        right.topology().peers_sorted(),
        "membership must converge"
    );
    assert_eq!(left.topology().peers_sorted(), vec![a, b, c, d]);
    assert_eq!(left.leader_for(role), Some(a), "the global lowest id wins after the merge");
    assert_eq!(right.leader_for(role), Some(a), "and both sides agree on it");

    // The strongest form of convergence: both sides plan the same cross-partition
    // route, having never exchanged a route — only inputs.
    let req = RouteRequest {
        channel: chan(),
        src: a,
        dst: d,
        constraints: Constraints { max_hops: 6, ..Default::default() },
    };
    let lr = left.plan_route(&req).expect("a route exists once the line is whole");
    let rr = right.plan_route(&req).expect("and the far side must find it too");
    let path = |r: &crate::routing::Route| -> Vec<NodeId> {
        std::iter::once(r.hops[0].from).chain(r.hops.iter().map(|h| h.edge.to)).collect()
    };
    assert_eq!(path(&lr), vec![a, b, c, d]);
    assert_eq!(path(&lr), path(&rr), "both sides derive the identical path");
    assert_eq!(lr.cost, rr.cost, "and the identical cost");

    // Replaying the whole healed set changes nothing — convergence is stable, not
    // a state both sides oscillate through.
    for &(n, seq) in &newest {
        assert!(!left.apply_gossip(healed_record(n, seq)), "re-delivery must be inert");
        assert!(!right.apply_gossip(healed_record(n, seq)), "on both sides");
    }
}

/// Codec intersection prefers the richest common format and falls back cleanly.
#[test]
fn codec_intersection_prefers_richest() {
    let opus = tcap_with(Codecs { opus: true, pcm_i16: true, ..Default::default() }, false);
    let i16_only = tcap_with(Codecs { pcm_i16: true, ..Default::default() }, false);
    assert_eq!(opus.intersect(&opus).codec, Some(Codec::Opus));
    assert_eq!(opus.intersect(&i16_only).codec, Some(Codec::PcmI16));
    let none = tcap_with(Codecs::default(), false);
    assert!(!opus.intersect(&none).is_native(), "no common codec → fall back to v1");
}
