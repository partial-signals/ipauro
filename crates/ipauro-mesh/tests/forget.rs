//! Membership expiry hook (R003-F2). Lives outside src/tests.rs by design.
use ipauro_mesh::MeshNode;
use ipauro_mesh::gossip::Record;
use ipauro_mesh::ids::NodeId;
use ipauro_mesh::policy::Policy;
use ipauro_mesh::topology::PeerFacts;

fn rec(author: NodeId, seq: u64) -> Record {
    Record { author, seq, edges: None, facts: Some(PeerFacts::default()), policy: None }
}

#[test]
fn forget_removes_peer_and_replay_stays_rejected() {
    let me = NodeId([1; 8]);
    let peer = NodeId([2; 8]);
    let mut n = MeshNode::new(me, Policy::new(me));
    assert!(n.apply_gossip(rec(peer, 5)));
    assert_eq!(n.topology().peers_sorted(), vec![peer]);
    assert!(n.forget_peer(peer));
    assert!(n.topology().peers_sorted().is_empty());
    assert!(!n.forget_peer(peer));
    assert!(!n.apply_gossip(rec(peer, 5)), "replay must not resurrect");
    assert!(n.apply_gossip(rec(peer, 6)), "newer seq re-admits");
}
