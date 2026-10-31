//! R003-F4: the `SetRole` IPC command — round trip over the real socket,
//! reconcile consequences, and persistence across a service restart.

use std::io::{BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ipauro_core::discovery::MockUsbNcmSource;
use ipauro_core::helper_channel::MockHelper;
use ipauro_core::registrar::StubHelperRegistrar;
use ipauro_core::ServiceConfig;
use ipauro_proto::ipc::{read_msg, write_msg, ClientMessage, Command, ReplyOutcome, ServerMessage};
use ipauro_proto::state::{NodeRole, Snapshot};
use ipauro_proto::PROTOCOL_VERSION;

fn temp_socket_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("ipauro-rl-{}-{n}-{nanos}.sock", std::process::id()))
}

fn start(socket_path: PathBuf, helper: Arc<MockHelper>) -> tokio::task::JoinHandle<()> {
    let config = ServiceConfig {
        socket_path,
        helper,
        registrar: Arc::new(StubHelperRegistrar),
        usb_source: Arc::new(MockUsbNcmSource::new([vec!["en9".to_string()]])),
        mesh_node: None,
        membership: None,
    };
    tokio::spawn(async move {
        let _ = ipauro_core::serve(config, std::future::pending::<()>()).await;
    })
}

async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("service did not bind socket in time");
}

/// Hello, then run `commands` in order; returns each reply's snapshot plus the
/// Hello snapshot.
fn session(path: &PathBuf, commands: Vec<Command>) -> (Snapshot, Vec<ReplyOutcome>) {
    let stream = UnixStream::connect(path).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = BufWriter::new(stream);
    write_msg(
        &mut writer,
        &ClientMessage::Hello { protocol_version: PROTOCOL_VERSION, client_name: "role-test".into(), subscribe_events: false },
    )
    .unwrap();
    writer.flush().unwrap();
    let hello = match read_msg::<ServerMessage>(&mut reader).unwrap().unwrap() {
        ServerMessage::Hello { snapshot, .. } => snapshot,
        other => panic!("expected Hello, got {other:?}"),
    };
    let mut replies = Vec::new();
    for (i, command) in commands.into_iter().enumerate() {
        let id = i as u64 + 1;
        write_msg(&mut writer, &ClientMessage::Command { id, command }).unwrap();
        writer.flush().unwrap();
        match read_msg::<ServerMessage>(&mut reader).unwrap().unwrap() {
            ServerMessage::Reply { id: got, outcome } => {
                assert_eq!(got, id);
                replies.push(outcome);
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }
    (hello, replies)
}

fn snap(o: &ReplyOutcome) -> &Snapshot {
    match o {
        ReplyOutcome::Ok { snapshot } => snapshot,
        ReplyOutcome::Err { error } => panic!("command failed: {error:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_role_round_trips_tears_down_the_bridge_and_persists_across_restart() {
    let socket = temp_socket_path();
    let role_file = ipauro_core::role::role_path(&socket);
    let helper = Arc::new(MockHelper::new());
    let task = start(socket.clone(), helper.clone());
    wait_for_socket(&socket).await;

    let s = socket.clone();
    let (hello, replies) = tokio::task::spawn_blocking(move || {
        session(&s, vec![Command::BridgeUp, Command::SetRole { role: NodeRole::Peer }, Command::SetRole { role: NodeRole::Hub }])
    })
    .await
    .unwrap();
    assert_eq!(hello.mesh.role, NodeRole::Hub, "default role is M1's: hub");
    assert!(snap(&replies[0]).bridge.actual.is_some());
    // Hub -> Peer: bridge gone, role reflected, user's wish remembered.
    assert!(snap(&replies[1]).bridge.actual.is_none());
    assert_eq!(snap(&replies[1]).mesh.role, NodeRole::Peer);
    assert!(snap(&replies[1]).bridge.desired_up);
    // Peer -> Hub: rebuilt without another BridgeUp.
    assert!(snap(&replies[2]).bridge.actual.is_some());

    // Persist a Peer election, kill the service, restart on the same socket.
    let s = socket.clone();
    tokio::task::spawn_blocking(move || session(&s, vec![Command::SetRole { role: NodeRole::Peer }]))
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&role_file).unwrap(), "peer");
    task.abort();
    let _ = task.await;
    let _ = std::fs::remove_file(&socket);

    let task2 = start(socket.clone(), Arc::new(MockHelper::new()));
    wait_for_socket(&socket).await;
    let s = socket.clone();
    let (hello2, _) = tokio::task::spawn_blocking(move || session(&s, vec![])).await.unwrap();
    assert_eq!(hello2.mesh.role, NodeRole::Peer, "elected role survives a restart");

    task2.abort();
    let _ = task2.await;
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&role_file);
}
