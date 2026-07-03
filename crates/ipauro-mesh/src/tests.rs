//! Skeleton tests: prove the two non-obvious behaviors actually hold — routing is
//! feasibility-first and deterministic, and election is a stable tie-break.

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
