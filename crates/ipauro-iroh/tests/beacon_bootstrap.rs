//! Two nodes with NO static bootstrap find each other through the LAN beacon
//! and gossip-join. The beacon runs over plain UDP (BeaconIo::unicast): the
//! multicast/broadcast constructors need a real bridge interface.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipauro_iroh::{
    BeaconConfig, BeaconIo, CompositeBootstrap, GossipConfig, IrohConfig, IrohNode, LanBeacon,
    MeshMembership, StaticBootstrap,
};
use ipauro_mesh::MeshNode;
use ipauro_mesh::policy::Policy;

async fn node(dir: &std::path::Path, name: &str) -> IrohNode {
    let mut c = IrohConfig::new(dir.join(name));
    c.bind_addrs = vec!["127.0.0.1:0".parse().unwrap()];
    IrohNode::start(c).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn beacon_alone_bootstraps_gossip() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (node(d.path(), "a").await, node(d.path(), "b").await);
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (ioa, iob) = (BeaconIo::unicast(any, vec![]).unwrap(), BeaconIo::unicast(any, vec![]).unwrap());
    let (pa, pb) = (ioa.local_addr().unwrap(), iob.local_addr().unwrap());
    let ioa = ioa.with_targets(vec![pb]);
    let iob = iob.with_targets(vec![pa]);

    let bcfg = BeaconConfig {
        mesh_id: "beacon-test".into(),
        interval: Duration::from_millis(150),
        burst_interval: Duration::from_millis(30),
        ..BeaconConfig::default()
    };
    let addrs = |n: &IrohNode| {
        let addr = n.local_addr();
        move || addr.ip_addrs().copied().collect::<Vec<_>>()
    };
    let ba = Arc::new(LanBeacon::spawn(a.endpoint().secret_key().clone(), vec![ioa], addrs(&a), bcfg.clone()));
    let bb = Arc::new(LanBeacon::spawn(b.endpoint().secret_key().clone(), vec![iob], addrs(&b), bcfg));

    let gcfg = GossipConfig { mesh_id: "beacon-test".into(), heartbeat: Duration::from_millis(100), expire_after_missed: 20 };
    // Composite = beacon ∪ (empty) static, the shape core uses.
    let src = |bc: &Arc<LanBeacon>| {
        Arc::new(CompositeBootstrap(vec![bc.clone(), Arc::new(StaticBootstrap::default())]))
    };
    let ma = MeshMembership::spawn(&a, src(&ba), gcfg.clone()).await.unwrap();
    let mb = MeshMembership::spawn(&b, src(&bb), gcfg).await.unwrap();

    let (ia, ib) = (a.node_id(), b.node_id());
    let (mut na, mut nb) = (MeshNode::new(ia, Policy::new(ia)), MeshNode::new(ib, Policy::new(ib)));
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        ma.sync_into(&mut na);
        mb.sync_into(&mut nb);
        if na.topology().peers_sorted() == vec![ib] && nb.topology().peers_sorted() == vec![ia] {
            break;
        }
        assert!(Instant::now() < end, "beacon-only bootstrap did not converge");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ma.shutdown().await;
    mb.shutdown().await;
}
