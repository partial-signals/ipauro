use ipauro_iroh::{IrohConfig, IrohNode};

fn cfg(path: std::path::PathBuf) -> IrohConfig {
    let mut c = IrohConfig::new(path);
    c.bind_addrs = vec!["127.0.0.1:0".parse().unwrap()];
    c
}

#[tokio::test]
async fn distinct_nodes_stable_across_restart() {
    let d = tempfile::tempdir().unwrap();
    let (pa, pb) = (d.path().join("a.key"), d.path().join("b.key"));

    let a = IrohNode::start(cfg(pa.clone())).await.unwrap();
    let b = IrohNode::start(cfg(pb.clone())).await.unwrap();
    assert_ne!(a.node_id(), b.node_id());
    assert_ne!(a.public_key(), b.public_key());
    assert!(a.bound_addrs().iter().all(|s| s.ip().is_loopback() && s.port() != 0));
    assert!(!a.bound_addrs().is_empty());
    let (ida, ka) = (a.node_id(), a.public_key());
    a.shutdown().await;
    b.shutdown().await;

    let a2 = IrohNode::start(cfg(pa)).await.unwrap();
    assert_eq!(a2.node_id(), ida);
    assert_eq!(a2.public_key(), ka);
    a2.shutdown().await;
}

#[tokio::test]
async fn corrupt_key_refuses_to_start() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("n.key");
    std::fs::write(&p, b"junk").unwrap();
    assert!(IrohNode::start(cfg(p.clone())).await.is_err());
    assert_eq!(std::fs::read(&p).unwrap(), b"junk");
}
