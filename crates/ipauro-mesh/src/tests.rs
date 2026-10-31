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
        facts: Some(PeerFacts {
            tcap: Some(tcap_with(all_codecs(), false)),
            can_relay: true,
            can_transcode: true,
            ..Default::default()
        }),
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
            ..Default::default()
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

// --- protocol capability advertisement (R010-F1) ------------------------------
//
// The R010-T5 exit shape, as gossip: three single-protocol islands (Link-only,
// AVB-only, Dante-only) and one polyglot that speaks all three and translates
// between them. Every node must read the same census, the same island set, and
// the same gateway candidate — from the same records, in any order.

mod protocol_caps {
    use super::{nid, tcap_with, all_codecs};
    use crate::capability::{CapsError, ProtocolCapability, ProtocolCaps, Translation, Verbs};
    use crate::gossip::Record;
    use crate::ids::NodeId;
    use crate::policy::Policy;
    use crate::protocol::{self, ClockBridge, ClockRef, ProtocolId, SampleFormats, PROFILES};
    use crate::topology::PeerFacts;
    use crate::MeshNode;

    const ENDPOINT: Verbs = Verbs { pass: false, sink: true, source: true, fan_in: false, fan_out: false };
    const GATEWAY: Verbs = Verbs { pass: true, sink: true, source: true, fan_in: true, fan_out: true };

    fn speaks_only(p: ProtocolId) -> ProtocolCaps {
        ProtocolCaps { speaks: vec![ProtocolCapability::full(p, ENDPOINT)], translates: vec![] }
    }

    /// Speaks every protocol in `ps` and translates every ordered pair.
    fn polyglot(ps: &[ProtocolId]) -> ProtocolCaps {
        let mut translates = Vec::new();
        for &from in ps {
            for &to in ps {
                if from != to {
                    translates.push(Translation { from, to });
                }
            }
        }
        ProtocolCaps { speaks: ps.iter().map(|&p| ProtocolCapability::full(p, GATEWAY)).collect(), translates }
    }

    fn record(n: NodeId, caps: ProtocolCaps) -> Record {
        Record {
            author: n,
            seq: 1,
            edges: Some(vec![]),
            facts: Some(PeerFacts {
                tcap: Some(tcap_with(all_codecs(), false)),
                protocols: caps,
                ..Default::default()
            }),
            policy: None,
        }
    }

    const ISLANDS: [ProtocolId; 3] = [ProtocolId::LinkAudio, ProtocolId::Avb, ProtocolId::Dante];

    /// The four R010-T5 nodes, as records.
    fn exit_mesh() -> Vec<Record> {
        vec![
            record(nid(1), speaks_only(ProtocolId::LinkAudio)),
            record(nid(2), speaks_only(ProtocolId::Avb)),
            record(nid(3), speaks_only(ProtocolId::Dante)),
            record(nid(4), polyglot(&ISLANDS)),
        ]
    }

    #[test]
    fn every_protocol_has_exactly_one_profile() {
        for id in ProtocolId::ALL {
            assert_eq!(PROFILES.iter().filter(|p| p.id == id).count(), 1, "{id:?}");
            assert_eq!(protocol::profile(id).id, id);
        }
        assert_eq!(PROFILES.len(), ProtocolId::ALL.len(), "a row without a variant, or vice versa");
        let mut names: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), PROFILES.len(), "profile names must be unique (they join ipauro_proto::registry)");
        // The one row the proto registry ships today must agree on its name.
        assert_eq!(protocol::profile(ProtocolId::Link).name, "ableton-link");
    }

    /// Rows must agree with themselves: media ⇔ formats ⇔ rates ⇔ a media clock.
    #[test]
    fn profiles_are_internally_consistent() {
        for p in PROFILES.iter() {
            let media = p.carries_media();
            assert_eq!(!p.rates_hz.is_empty(), media, "{:?}: rates iff media", p.id);
            assert_eq!(p.clock != ClockRef::None, media, "{:?}: a media clock iff media", p.id);
            assert_eq!(p.packetization.framing != protocol::Framing::None, media, "{:?}: framing iff media", p.id);
            assert_eq!(p.channelization != protocol::Channelization::None, media, "{:?}: channels iff media", p.id);
        }
        // The A004 §3 correction: LinkAudio carries samples but disciplines no rate.
        let la = protocol::profile(ProtocolId::LinkAudio);
        assert!(la.carries_media());
        assert!(!la.clock.disciplines_rate());
    }

    /// R010-F4's input: the clock relationship is read off two profiles, and the
    /// four classes are exactly the four A001/A003 cases.
    #[test]
    fn clock_bridge_is_derived_from_profiles() {
        use ProtocolId::*;
        assert_eq!(protocol::clock_bridge(Aes67, Aes67), ClockBridge::SharedDomain, "PTPv2 both sides");
        assert_eq!(protocol::clock_bridge(Dante, Avb), ClockBridge::CrossDomain, "PTPv1 vs gPTP");
        assert_eq!(protocol::clock_bridge(Dante, Aes67), ClockBridge::CrossDomain, "PTPv1 vs PTPv2");
        assert_eq!(protocol::clock_bridge(Madi, UsbAudio), ClockBridge::CrossDomain, "two cable clocks are two domains");
        assert_eq!(protocol::clock_bridge(Madi, Madi), ClockBridge::CrossDomain, "two MADI links are still two domains");
        assert_eq!(protocol::clock_bridge(LinkAudio, Dante), ClockBridge::Adaptive, "LinkBeat disciplines no rate");
        assert_eq!(protocol::clock_bridge(Dante, LinkAudio), ClockBridge::Adaptive, "…in either direction");
        assert_eq!(protocol::clock_bridge(JackTrip, Ndi), ClockBridge::Adaptive, "free-run both sides");
        assert_eq!(protocol::clock_bridge(Link, Dante), ClockBridge::NoMedia, "plain Link has no leg to bridge");
    }

    /// Every node folds the same four records (here in a different order on
    /// each) and reads the same census, speakers, and translator set.
    #[test]
    fn four_node_exit_mesh_converges_on_every_node() {
        let views: Vec<MeshNode> = (1..=4u8)
            .map(|me| {
                let mut node = MeshNode::new(nid(me), Policy::new(nid(me)));
                let mut recs = exit_mesh();
                recs.rotate_left(me as usize % 4);
                for r in recs {
                    assert!(node.apply_gossip(r));
                }
                node
            })
            .collect();

        for node in &views {
            let topo = node.topology();
            // Census in `ProtocolId` order (declaration order), independent of arrival order.
            assert_eq!(topo.protocols_spoken(), vec![ProtocolId::LinkAudio, ProtocolId::Dante, ProtocolId::Avb]);
            assert_eq!(node.peers_speaking(ProtocolId::LinkAudio), vec![nid(1), nid(4)]);
            assert_eq!(node.peers_speaking(ProtocolId::Avb), vec![nid(2), nid(4)]);
            assert_eq!(node.peers_speaking(ProtocolId::Dante), vec![nid(3), nid(4)]);
            assert_eq!(node.peers_speaking(ProtocolId::Aes67), Vec::<NodeId>::new(), "nobody speaks AES67");
            // Only the polyglot bridges anything, in every direction.
            for &from in &ISLANDS {
                for &to in &ISLANDS {
                    if from != to {
                        assert_eq!(node.translators(from, to), vec![nid(4)], "{from:?}→{to:?}");
                    }
                }
            }
            // Island endpoints are not gateways, however many verbs they claim.
            assert!(!topo.facts(nid(1)).unwrap().protocols.is_polyglot());
            assert!(topo.facts(nid(4)).unwrap().protocols.is_polyglot());
        }
    }

    /// A node that advertises a translation whose endpoint it does not speak,
    /// or that is not a protocol at all for media purposes, is never counted as
    /// a translator — a receiver needs no validation step for that to hold.
    #[test]
    fn a_translation_to_an_unspoken_protocol_is_not_honoured() {
        let mut caps = speaks_only(ProtocolId::Dante);
        caps.translates.push(Translation { from: ProtocolId::Dante, to: ProtocolId::Avb });
        assert!(!caps.translates(ProtocolId::Dante, ProtocolId::Avb));
        assert!(caps.honoured_translations().is_empty());
        assert_eq!(
            caps.validate(),
            Err(CapsError::TranslatesUnspoken(Translation { from: ProtocolId::Dante, to: ProtocolId::Avb }))
        );

        let mut node = MeshNode::new(nid(9), Policy::new(nid(9)));
        node.apply_gossip(record(nid(7), caps));
        assert!(node.translators(ProtocolId::Dante, ProtocolId::Avb).is_empty());
    }

    /// Translation is directed: an adapter that only ingests Dante and only
    /// emits AVB bridges one way.
    #[test]
    fn translation_is_directed() {
        let caps = ProtocolCaps {
            speaks: vec![
                ProtocolCapability::full(ProtocolId::Dante, GATEWAY),
                ProtocolCapability::full(ProtocolId::Avb, GATEWAY),
            ],
            translates: vec![Translation { from: ProtocolId::Dante, to: ProtocolId::Avb }],
        };
        assert_eq!(caps.validate(), Ok(()));
        assert!(caps.translates(ProtocolId::Dante, ProtocolId::Avb));
        assert!(!caps.translates(ProtocolId::Avb, ProtocolId::Dante));
    }

    /// The publisher-side check catches every way an advertisement can disagree
    /// with the registry row it claims.
    #[test]
    fn validate_rejects_claims_outside_the_registry_row() {
        // Format the protocol does not define: f32 on AES67.
        let mut c = ProtocolCapability::full(ProtocolId::Aes67, ENDPOINT);
        c.formats = SampleFormats { pcm_f32: true, ..SampleFormats::NONE };
        let caps = ProtocolCaps { speaks: vec![c], translates: vec![] };
        assert_eq!(caps.validate(), Err(CapsError::FormatOutsideProtocol(ProtocolId::Aes67)));

        // Rate the protocol does not define: 44.1 k on AES67.
        let mut c = ProtocolCapability::full(ProtocolId::Aes67, ENDPOINT);
        c.rates_hz = vec![44_100];
        let caps = ProtocolCaps { speaks: vec![c], translates: vec![] };
        assert_eq!(caps.validate(), Err(CapsError::RateOutsideProtocol(ProtocolId::Aes67, 44_100)));

        // Same protocol twice.
        let caps = ProtocolCaps {
            speaks: vec![
                ProtocolCapability::full(ProtocolId::Dante, ENDPOINT),
                ProtocolCapability::full(ProtocolId::Dante, GATEWAY),
            ],
            translates: vec![],
        };
        assert_eq!(caps.validate(), Err(CapsError::DuplicateProtocol(ProtocolId::Dante)));

        // Self-translation is `pass`, not a translation.
        let mut caps = speaks_only(ProtocolId::Dante);
        caps.translates.push(Translation { from: ProtocolId::Dante, to: ProtocolId::Dante });
        assert_eq!(caps.validate(), Err(CapsError::SelfTranslation(ProtocolId::Dante)));
        assert!(!caps.translates(ProtocolId::Dante, ProtocolId::Dante));

        // Plain Link carries nothing to transcode.
        let caps = polyglot(&[ProtocolId::Link, ProtocolId::Dante]);
        assert!(matches!(caps.validate(), Err(CapsError::TranslatesNoMedia(_))));
        assert!(!caps.is_polyglot(), "one media protocol + a sync protocol is not a polyglot");

        // And the well-formed polyglot passes.
        assert_eq!(polyglot(&ISLANDS).validate(), Ok(()));
    }

    /// A peer narrows its protocol's row; the passthrough set between two peers
    /// is the intersection of what each actually implements, not of the rows.
    #[test]
    fn peer_formats_narrow_the_registry_row() {
        let mut a = ProtocolCapability::full(ProtocolId::Dante, ENDPOINT);
        a.formats = SampleFormats { pcm_i24: true, ..SampleFormats::NONE };
        let b = ProtocolCapability::full(ProtocolId::Dante, GATEWAY);
        let shared = a.formats.intersect(&b.formats);
        assert_eq!(shared, SampleFormats { pcm_i24: true, ..SampleFormats::NONE });
        assert!(protocol::profile(ProtocolId::Dante).formats.contains(&shared));
    }
}

// --- gateway election (R010-F2) ------------------------------------------------

mod gateway_election {
    use super::nid;
    use crate::capability::{ProtocolCapability, ProtocolCaps, Translation, Verbs};
    use crate::gateway::{self, Leg};
    use crate::gossip::Record;
    use crate::ids::NodeId;
    use crate::policy::Policy;
    use crate::protocol::ProtocolId::{self, *};
    use crate::topology::PeerFacts;
    use crate::{election, MeshNode};

    const V: Verbs = Verbs { pass: true, sink: true, source: true, fan_in: true, fan_out: true };

    fn caps(speaks: &[ProtocolId], translates: &[(ProtocolId, ProtocolId)]) -> ProtocolCaps {
        ProtocolCaps {
            speaks: speaks.iter().map(|&p| ProtocolCapability::full(p, V)).collect(),
            translates: translates.iter().map(|&(from, to)| Translation { from, to }).collect(),
        }
    }

    fn all_pairs(ps: &[ProtocolId]) -> Vec<(ProtocolId, ProtocolId)> {
        let mut v = Vec::new();
        for &a in ps {
            for &b in ps {
                if a != b {
                    v.push((a, b));
                }
            }
        }
        v
    }

    fn rec(n: NodeId, c: ProtocolCaps) -> Record {
        Record {
            author: n,
            seq: 1,
            edges: Some(vec![]),
            facts: Some(PeerFacts { protocols: c, ..Default::default() }),
            policy: None,
        }
    }

    fn mesh(me: u8, recs: Vec<Record>) -> MeshNode {
        let mut node = MeshNode::new(nid(me), Policy::new(nid(me)));
        for r in recs {
            assert!(node.apply_gossip(r));
        }
        node
    }

    const ISLANDS: [ProtocolId; 3] = [LinkAudio, Dante, Avb];

    /// The R010-T5 shape: three monoglot islands and one polyglot. Every ordered
    /// pair is demanded and the polyglot wins every leg — and the plan is the
    /// same from every node's seat, including the islands'.
    #[test]
    fn exit_mesh_elects_the_polyglot_for_every_leg() {
        let recs = || {
            vec![
                rec(nid(1), caps(&[LinkAudio], &[])),
                rec(nid(2), caps(&[Avb], &[])),
                rec(nid(3), caps(&[Dante], &[])),
                rec(nid(4), caps(&ISLANDS, &all_pairs(&ISLANDS))),
            ]
        };
        let expected: Vec<Leg> = [
            (LinkAudio, Dante),
            (LinkAudio, Avb),
            (Dante, LinkAudio),
            (Dante, Avb),
            (Avb, LinkAudio),
            (Avb, Dante),
        ]
        .into_iter()
        .map(|(from, to)| Leg { from, to, gateway: Some(nid(4)) })
        .collect();

        for me in 1..=4u8 {
            let node = mesh(me, recs());
            assert_eq!(node.gateway_plan(), expected, "seat {me}");
            assert_eq!(node.is_gateway_for(Dante, Avb), me == 4);
        }
    }

    /// Two polyglots: the lowest id wins each leg it honours, exactly as every
    /// other role is elected; a leg only the higher-id node honours goes to it.
    #[test]
    fn lowest_id_translator_wins_each_leg_it_honours() {
        let node = mesh(
            1,
            vec![
                rec(nid(1), caps(&[Dante], &[])),
                rec(nid(2), caps(&[Avb], &[])),
                // nid(5): bridges both ways.
                rec(nid(5), caps(&[Dante, Avb], &all_pairs(&[Dante, Avb]))),
                // nid(3): lower id, but only ingests Dante → emits AVB.
                rec(nid(3), caps(&[Dante, Avb], &[(Dante, Avb)])),
            ],
        );
        assert_eq!(
            node.gateway_plan(),
            vec![
                Leg { from: Dante, to: Avb, gateway: Some(nid(3)) },
                Leg { from: Avb, to: Dante, gateway: Some(nid(5)) },
            ]
        );
        // Same answer through the generic election surface.
        assert_eq!(
            node.leader_for(election::Role::ProtocolGateway { from: Dante, to: Avb }),
            Some(nid(3))
        );
    }

    /// Islands with nobody to bridge them are reported as unbridged legs — a
    /// demand is never dropped because it cannot be met.
    #[test]
    fn an_unbridgeable_pair_is_reported_not_dropped() {
        let node = mesh(
            1,
            vec![
                rec(nid(1), caps(&[Dante], &[])),
                rec(nid(2), caps(&[Avb], &[])),
                // Speaks both but translates nothing: a polyglot endpoint, not a gateway.
                rec(nid(3), caps(&[Dante, Avb], &[])),
            ],
        );
        assert_eq!(
            node.gateway_plan(),
            vec![
                Leg { from: Dante, to: Avb, gateway: None },
                Leg { from: Avb, to: Dante, gateway: None },
            ]
        );
        assert!(gateway::elect(node.topology(), Dante, Avb).is_none());
    }

    /// No demand without an island: if every Dante speaker also speaks AVB, the
    /// AVB-only node reaches all of them natively and no gateway is needed.
    /// Likewise a sync-only protocol (plain Link) never raises a demand.
    #[test]
    fn no_demand_when_every_pair_shares_a_protocol() {
        let node = mesh(
            1,
            vec![
                rec(nid(1), caps(&[Dante, Avb], &all_pairs(&[Dante, Avb]))),
                rec(nid(2), caps(&[Avb], &[])),
                rec(nid(3), caps(&[Link], &[])),
            ],
        );
        assert!(gateway::demands(node.topology()).is_empty());
        assert!(node.gateway_plan().is_empty());
    }

    /// A gateway leaving (its record superseded by one that no longer translates)
    /// re-elects deterministically: the next-lowest translator takes the leg, or
    /// the leg goes unbridged.
    #[test]
    fn a_departing_gateway_is_replaced_by_the_next_translator() {
        let mut node = mesh(
            1,
            vec![
                rec(nid(1), caps(&[Dante], &[])),
                rec(nid(2), caps(&[Avb], &[])),
                rec(nid(3), caps(&[Dante, Avb], &all_pairs(&[Dante, Avb]))),
                rec(nid(4), caps(&[Dante, Avb], &all_pairs(&[Dante, Avb]))),
            ],
        );
        assert!(!node.is_gateway_for(Dante, Avb));
        assert_eq!(gateway::elect(node.topology(), Dante, Avb), Some(nid(3)));

        // nid(3) stops translating (adapter unloaded); newer record says so.
        let mut r = rec(nid(3), caps(&[Dante], &[]));
        r.seq = 2;
        assert!(node.apply_gossip(r));
        assert_eq!(gateway::elect(node.topology(), Dante, Avb), Some(nid(4)));

        let mut r = rec(nid(4), caps(&[Dante], &[]));
        r.seq = 2;
        assert!(node.apply_gossip(r));
        assert_eq!(
            node.gateway_plan(),
            vec![
                Leg { from: Dante, to: Avb, gateway: None },
                Leg { from: Avb, to: Dante, gateway: None },
            ]
        );
    }
}

// --- stream router (R010-F3) -----------------------------------------------------

mod stream_router {
    use super::{nid, q};
    use crate::capability::{ProtocolCapability, ProtocolCaps, Translation, Verbs};
    use crate::gossip::Record;
    use crate::ids::{ChannelId, NodeId};
    use crate::policy::Policy;
    use crate::protocol::ClockBridge;
    use crate::protocol::ProtocolId::{self, *};
    use crate::routing::Constraints;
    use crate::stream::{Demand, Mode, Path, Shape, Sink, Source};
    use crate::topology::{Edge, PeerFacts};
    use crate::transport::TransportKind;
    use crate::MeshNode;

    const V: Verbs = Verbs { pass: true, sink: true, source: true, fan_in: true, fan_out: true };

    fn caps(speaks: &[ProtocolId], translates: &[(ProtocolId, ProtocolId)]) -> ProtocolCaps {
        ProtocolCaps {
            speaks: speaks.iter().map(|&p| ProtocolCapability::full(p, V)).collect(),
            translates: translates.iter().map(|&(from, to)| Translation { from, to }).collect(),
        }
    }

    fn rec(n: NodeId, c: ProtocolCaps, edges: Vec<Edge>) -> Record {
        Record {
            author: n,
            seq: 1,
            edges: Some(edges),
            facts: Some(PeerFacts { protocols: c, ..Default::default() }),
            policy: None,
        }
    }

    fn e(to: NodeId) -> Edge {
        Edge { to, kind: TransportKind::Ethernet, quality: q(1_000) }
    }

    fn sid(b: u8) -> ChannelId {
        ChannelId([b; 8])
    }

    /// The R010-T5 star: islands 1 (LinkAudio), 2 (AVB), 3 (Dante) each wired
    /// only to the polyglot gateway 4 (100BASE-T everywhere).
    fn exit_mesh(me: u8) -> MeshNode {
        let mut node = MeshNode::new(nid(me), Policy::new(nid(me)));
        let all = [LinkAudio, Dante, Avb];
        let mut pairs = Vec::new();
        for &a in &all {
            for &b in &all {
                if a != b {
                    pairs.push((a, b));
                }
            }
        }
        for r in [
            rec(nid(1), caps(&[LinkAudio], &[]), vec![e(nid(4))]),
            rec(nid(2), caps(&[Avb], &[]), vec![e(nid(4))]),
            rec(nid(3), caps(&[Dante], &[]), vec![e(nid(4))]),
            rec(nid(4), caps(&all, &pairs), vec![e(nid(1)), e(nid(2)), e(nid(3))]),
        ] {
            assert!(node.apply_gossip(r));
        }
        node
    }

    fn c4() -> Constraints {
        Constraints { max_hops: 4, ..Default::default() }
    }

    /// Fan-out from the Dante island to every other node: the Dante→gateway leg
    /// is passthrough (the gateway speaks Dante), the AVB and LinkAudio legs
    /// transcode *at the gateway* with a two-route path, and each leg's clock
    /// class is the registry's. Identical from every seat.
    #[test]
    fn fan_out_legs_are_independently_passthrough_or_transcode() {
        let demand = Demand {
            sources: vec![Source { stream: sid(0xD), node: nid(3), proto: Dante, channels: 8 }],
            sinks: vec![
                Sink { node: nid(4), proto: Dante },
                Sink { node: nid(2), proto: Avb },
                Sink { node: nid(1), proto: LinkAudio },
            ],
            constraints: c4(),
        };
        let reference = exit_mesh(3).plan_flow(&demand);
        assert_eq!(reference.shape, Shape::FanOut);
        assert!(reference.is_complete(), "{reference:#?}");
        assert_eq!(reference.legs.len(), 3);

        // Leg to the gateway: passthrough, one direct hop, PTPv1 both sides.
        let gw = &reference.legs[0];
        assert_eq!(gw.inputs[0].mode, Mode::Passthrough { clock: ClockBridge::SharedDomain });
        assert!(matches!(&gw.inputs[0].path, Path::Direct(r) if r.hops.len() == 1));

        // Leg to AVB: transcode at 4, routed 3→4 then 4→2, cross-domain clock.
        let avb = &reference.legs[1];
        assert_eq!(avb.inputs[0].mode, Mode::Transcode { from: Dante, to: Avb, at: nid(4), clock: ClockBridge::CrossDomain });
        assert!(matches!(&avb.inputs[0].path, Path::ViaGateway { to_gateway, to_sink }
            if to_gateway.hops.len() == 1 && to_gateway.hops[0].edge.to == nid(4)
            && to_sink.hops.len() == 1 && to_sink.hops[0].edge.to == nid(2)));

        // Leg to LinkAudio: adaptive — LinkBeat disciplines no rate.
        let la = &reference.legs[2];
        assert_eq!(la.inputs[0].mode, Mode::Transcode { from: Dante, to: LinkAudio, at: nid(4), clock: ClockBridge::Adaptive });

        // Every leg carries all 8 channels, discretely.
        for leg in &reference.legs {
            assert_eq!(leg.channel_count(), 8);
        }

        // Same plan from the islands' and the gateway's seats.
        for me in [1, 2, 4] {
            assert_eq!(exit_mesh(me).plan_flow(&demand), reference, "seat {me}");
        }
    }

    /// Fan-in: three streams of different widths and protocols land on one AVB
    /// sink as 2+6+1 discrete channels in source order. No destination channel
    /// is assigned twice, none is skipped, each slot has exactly one source.
    #[test]
    fn fan_in_keeps_every_channel_discrete() {
        let node = exit_mesh(2);
        let flow = node.plan_flow(&Demand {
            sources: vec![
                Source { stream: sid(1), node: nid(1), proto: LinkAudio, channels: 2 },
                Source { stream: sid(3), node: nid(3), proto: Dante, channels: 6 },
                Source { stream: sid(4), node: nid(4), proto: Avb, channels: 1 },
            ],
            sinks: vec![Sink { node: nid(2), proto: Avb }],
            constraints: c4(),
        });
        assert_eq!(flow.shape, Shape::FanIn);
        assert!(flow.is_complete(), "{flow:#?}");
        let leg = &flow.legs[0];
        assert_eq!(leg.channel_count(), 9);

        let mut dsts: Vec<u16> = leg.slots.iter().map(|s| s.dst_channel).collect();
        dsts.sort();
        assert_eq!(dsts, (0..9).collect::<Vec<_>>(), "dense and injective");
        let per_stream = |id: ChannelId| leg.slots.iter().filter(|s| s.stream == id).count();
        assert_eq!((per_stream(sid(1)), per_stream(sid(3)), per_stream(sid(4))), (2, 6, 1));
        // Source order: LinkAudio's two channels first.
        assert_eq!(leg.slots[0], crate::stream::Slot { stream: sid(1), src_channel: 0, dst_channel: 0 });
        assert_eq!(leg.slots[2].stream, sid(3));

        // Each input's mode is its own: two transcodes (at the gateway) and one passthrough.
        assert!(matches!(leg.inputs[0].mode, Mode::Transcode { from: LinkAudio, to: Avb, at, .. } if at == nid(4)));
        assert!(matches!(leg.inputs[1].mode, Mode::Transcode { from: Dante, to: Avb, at, .. } if at == nid(4)));
        assert_eq!(leg.inputs[2].mode, Mode::Passthrough { clock: ClockBridge::SharedDomain });
    }

    /// A polyglot source emits the sink's protocol itself: transcode at the
    /// source, single direct route, no gateway hop.
    #[test]
    fn a_translating_endpoint_transcodes_in_place() {
        let node = exit_mesh(4);
        let flow = node.plan_flow(&Demand {
            sources: vec![Source { stream: sid(9), node: nid(4), proto: Dante, channels: 2 }],
            sinks: vec![Sink { node: nid(2), proto: Avb }],
            constraints: c4(),
        });
        let input = &flow.legs[0].inputs[0];
        assert!(matches!(input.mode, Mode::Transcode { at, .. } if at == nid(4)));
        assert!(matches!(&input.path, Path::Direct(r) if r.hops.len() == 1));

        // And a sink that translates ingests in place.
        let flow = node.plan_flow(&Demand {
            sources: vec![Source { stream: sid(9), node: nid(3), proto: Dante, channels: 2 }],
            sinks: vec![Sink { node: nid(4), proto: Avb }],
            constraints: c4(),
        });
        assert!(matches!(flow.legs[0].inputs[0].mode, Mode::Transcode { at, .. } if at == nid(4)));
        assert!(matches!(&flow.legs[0].inputs[0].path, Path::Direct(_)));
    }

    /// A protocol pair nobody translates stays in the plan as `Unbridged`, and a
    /// gateway the graph cannot reach stays as `Unroutable` — the sink is silent
    /// for a stated reason, and `is_complete` says so.
    #[test]
    fn blockages_are_named_not_dropped() {
        // AES67 sink: the gateway speaks no AES67.
        let node = exit_mesh(3);
        let flow = node.plan_flow(&Demand {
            sources: vec![Source { stream: sid(1), node: nid(3), proto: Dante, channels: 2 }],
            sinks: vec![Sink { node: nid(2), proto: Aes67 }],
            constraints: c4(),
        });
        assert!(!flow.is_complete());
        assert_eq!(flow.legs[0].inputs[0].mode, Mode::Unbridged { from: Dante, to: Aes67 });
        assert_eq!(flow.legs[0].live_inputs().count(), 0);

        // Gateway exists but the sink's only link is forbidden: unroutable 4→2.
        let flow = node.plan_flow(&Demand {
            sources: vec![Source { stream: sid(1), node: nid(3), proto: Dante, channels: 2 }],
            sinks: vec![Sink { node: nid(2), proto: Avb }],
            constraints: Constraints { forbid: vec![TransportKind::Ethernet], ..c4() },
        });
        assert!(!flow.is_complete());
        assert!(matches!(flow.legs[0].inputs[0].mode, Mode::Transcode { at, .. } if at == nid(4)));
        assert_eq!(flow.legs[0].inputs[0].path, Path::Unroutable { from: nid(3), to: nid(4) });
    }

    /// 1:1 on one node (the system-sound case: a stream terminating where it
    /// was ingested) needs no route at all.
    #[test]
    fn a_local_leg_has_no_route() {
        let node = exit_mesh(4);
        let flow = node.plan_flow(&Demand {
            sources: vec![Source { stream: sid(1), node: nid(4), proto: Dante, channels: 2 }],
            sinks: vec![Sink { node: nid(4), proto: LinkAudio }],
            constraints: c4(),
        });
        assert_eq!(flow.shape, Shape::OneToOne);
        assert_eq!(flow.legs[0].inputs[0].path, Path::Local);
        assert!(matches!(flow.legs[0].inputs[0].mode, Mode::Transcode { at, clock: ClockBridge::Adaptive, .. } if at == nid(4)));
    }
}
