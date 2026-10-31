use std::sync::Arc;
use std::time::{Duration, Instant};

use ipauro_iroh::{
    GossipConfig, IrohConfig, IrohNode, MeshMembership, StaticBootstrap, open_record, seal_record,
};
use ipauro_mesh::gossip::Record;
use ipauro_mesh::ids::NodeId;
use ipauro_mesh::MeshNode;
use ipauro_mesh::policy::Policy;

fn cfg() -> GossipConfig {
    GossipConfig { mesh_id: "test-mesh".into(), heartbeat: Duration::from_millis(100), expire_after_missed: 4 }
}

async fn node(dir: &std::path::Path, name: &str) -> IrohNode {
    let mut c = IrohConfig::new(dir.join(name));
    c.bind_addrs = vec!["127.0.0.1:0".parse().unwrap()];
    IrohNode::start(c).await.unwrap()
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Fold a membership's queue into its MeshNode and return the topology's peers.
fn view(ms: &MeshMembership, m: &mut MeshNode) -> Vec<NodeId> {
    ms.sync_into(m);
    m.topology().peers_sorted()
}

fn sorted(mut v: Vec<NodeId>) -> Vec<NodeId> {
    v.sort();
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn three_nodes_converge_spoof_rejected_and_silence_expires() {
    let d = tempfile::tempdir().unwrap();
    let a = node(d.path(), "a").await;
    let b = node(d.path(), "b").await;
    let c = node(d.path(), "c").await;
    let (ia, ib, ic) = (a.node_id(), b.node_id(), c.node_id());

    // a is the static bootstrap for b and c; c never dials b directly.
    let boot = Arc::new(StaticBootstrap(vec![a.local_addr()]));
    let ma = MeshMembership::spawn(&a, Arc::new(StaticBootstrap::default()), cfg()).await.unwrap();
    let mb = MeshMembership::spawn(&b, boot.clone(), cfg()).await.unwrap();
    let mc = MeshMembership::spawn(&c, boot, cfg()).await.unwrap();

    let mut na = MeshNode::new(ia, Policy::new(ia));
    let mut nb = MeshNode::new(ib, Policy::new(ib));
    let mut nc = MeshNode::new(ic, Policy::new(ic));

    until("full membership on all three", || {
        view(&ma, &mut na) == sorted(vec![ib, ic])
            && view(&mb, &mut nb) == sorted(vec![ia, ic])
            && view(&mc, &mut nc) == sorted(vec![ia, ib])
    })
    .await;

    // Spoof: c signs a record that claims to be authored by b's NodeId.
    let forged = Record { author: ib, seq: u64::MAX, edges: Some(vec![]), facts: None, policy: None };
    let secret_c = c.endpoint().secret_key().clone();
    let env = seal_record(&secret_c, &forged);
    assert!(open_record(&env).is_err(), "forged envelope must not open");
    let before = ma.rejected();
    mc.publish_sealed(env);
    until("a rejects the forgery", || ma.rejected() > before).await;
    // b's real heartbeats must not have been shadowed by the u64::MAX forgery.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(view(&ma, &mut na).contains(&ib));

    // Silence: shut b down; a and c expire it, and keep each other.
    mb.shutdown().await;
    b.shutdown().await;
    until("b expired on a and c", || {
        view(&ma, &mut na) == vec![ic] && view(&mc, &mut nc) == vec![ia]
    })
    .await;

    mc.shutdown().await;
    ma.shutdown().await;
    c.shutdown().await;
    a.shutdown().await;
}

/// R003-T5: the status inputs. A live peer is observed Alive with its role, a
/// silent one becomes an Expired tombstone (not a vanish), and a rate raised by
/// one node is adopted by the other through heartbeats alone.
#[tokio::test(flavor = "multi_thread")]
async fn members_observation_tombstones_and_rate_proposal_gossips() {
    use ipauro_iroh::MemberState;
    use ipauro_mesh::rate::RateError;

    let d = tempfile::tempdir().unwrap();
    let a = node(d.path(), "a").await;
    let b = node(d.path(), "b").await;
    let (ia, ib) = (a.node_id(), b.node_id());
    let boot = Arc::new(StaticBootstrap(vec![a.local_addr()]));
    let ma = MeshMembership::spawn(&a, Arc::new(StaticBootstrap::default()), cfg()).await.unwrap();
    let mb = MeshMembership::spawn(&b, boot, cfg()).await.unwrap();

    until("a observes b alive", || {
        ma.members().iter().any(|m| m.node == ib && m.state == MemberState::Alive)
    })
    .await;
    assert!(ma.members().iter().all(|m| m.node != ia), "self is never a remote member");

    // Rate: validated, epoch bumped, adopted by the peer.
    assert_eq!(ma.mesh_rate().epoch, 0);
    assert!(matches!(ma.propose_rate(50_000), Err(RateError::NotAllowed(_))));
    let raised = ma.propose_rate(96_000).unwrap();
    assert_eq!((raised.hz, raised.epoch, raised.author), (96_000, 1, ia));
    until("b adopts 96k", || mb.mesh_rate().hz == 96_000).await;
    assert_eq!(mb.mesh_rate().epoch, 1);

    // Silence: b goes away; a keeps it as an Expired tombstone.
    mb.shutdown().await;
    b.shutdown().await;
    until("b is an expired tombstone on a", || {
        ma.members().iter().any(|m| m.node == ib && m.state == MemberState::Expired)
    })
    .await;
    assert!(ma.live_peers().is_empty());

    ma.shutdown().await;
    a.shutdown().await;
}
