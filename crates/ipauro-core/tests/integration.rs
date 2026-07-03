//! Integration tests for the brain service: boot it on a temp socket with
//! `MockHelper`, drive it with plain `std::os::unix::net::UnixStream` +
//! `ipauro_proto::ipc::{read_msg, write_msg}` — exactly what a real client
//! (CLI, tray UI, external app) would do.
//!
//! The client side is deliberately *blocking* std I/O (that's what real
//! clients use), so every client interaction runs inside
//! `tokio::task::spawn_blocking` — blocking a tokio worker thread directly
//! would starve the in-process server.

use std::io::{BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ipauro_core::helper_channel::MockHelper;
use ipauro_core::registrar::StubHelperRegistrar;
use ipauro_core::ServiceConfig;
use ipauro_proto::ipc::{read_msg, write_msg, ClientMessage, Command, EventBody, ReplyOutcome, ServerMessage};
use ipauro_proto::PROTOCOL_VERSION;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_socket_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("ipauro-core-test-{}-{n}-{nanos}.sock", std::process::id()))
}

/// A blocking IPC client connection, as the CLI would hold one.
struct Client {
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl Client {
    fn connect(socket_path: &PathBuf) -> Self {
        let stream = UnixStream::connect(socket_path).expect("connect to service socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");
        let write_stream = stream.try_clone().expect("clone socket for writer");
        Self { reader: BufReader::new(stream), writer: BufWriter::new(write_stream) }
    }

    fn send(&mut self, msg: &ClientMessage) {
        write_msg(&mut self.writer, msg).expect("write message");
        self.writer.flush().expect("flush message");
    }

    fn recv(&mut self) -> Option<ServerMessage> {
        read_msg(&mut self.reader).expect("read message")
    }

    /// Connect + handshake, asserting the server's Hello, and return the
    /// established connection.
    fn handshake(socket_path: &PathBuf, name: &str, subscribe_events: bool) -> Self {
        let mut client = Self::connect(socket_path);
        client.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_name: name.to_string(),
            subscribe_events,
        });
        match client.recv().expect("hello reply") {
            ServerMessage::Hello { protocol_version, .. } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Hello, got {other:?}"),
        }
        client
    }
}

/// Boots the service in the background on the given socket with a
/// `MockHelper`, and waits for the socket file to appear (accept loop is up)
/// before returning — avoids a connect-before-bind race.
async fn spawn_service(socket_path: PathBuf) {
    let config = ServiceConfig {
        socket_path: socket_path.clone(),
        helper: Arc::new(MockHelper::new()),
        registrar: Arc::new(StubHelperRegistrar),
    };
    tokio::spawn(async move {
        let _ = ipauro_core::serve(config, std::future::pending::<()>()).await;
    });
    for _ in 0..500 {
        if socket_path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("service did not bind socket in time");
}

/// Run blocking client-side I/O off the runtime workers.
async fn client_io<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("client task panicked")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_handshake_carries_snapshot() {
    let socket_path = temp_socket_path();
    spawn_service(socket_path.clone()).await;

    client_io(move || {
        let mut client = Client::connect(&socket_path);
        client.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_name: "test".to_string(),
            subscribe_events: false,
        });
        match client.recv().expect("hello reply") {
            ServerMessage::Hello { protocol_version, snapshot, .. } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert!(!snapshot.bridge.desired_up);
                assert!(snapshot.bridge.actual.is_none());
                assert_eq!(snapshot.service.version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_up_returns_actual_present() {
    let socket_path = temp_socket_path();
    spawn_service(socket_path.clone()).await;

    client_io(move || {
        let mut client = Client::handshake(&socket_path, "test", false);
        client.send(&ClientMessage::Command { id: 1, command: Command::BridgeUp });
        match client.recv().expect("command reply") {
            ServerMessage::Reply { id, outcome: ReplyOutcome::Ok { snapshot } } => {
                assert_eq!(id, 1);
                assert!(snapshot.bridge.desired_up);
                assert!(
                    snapshot.bridge.actual.is_some(),
                    "expected actual bridge present after BridgeUp"
                );
            }
            other => panic!("expected Ok reply, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribed_client_sees_events_with_increasing_seq() {
    let socket_path = temp_socket_path();
    spawn_service(socket_path.clone()).await;

    client_io(move || {
        // Client A issues commands; not subscribed, so its stream stays command-only.
        let mut a = Client::handshake(&socket_path, "a", false);
        // Client B subscribes to the event stream BEFORE A mutates anything.
        let mut b = Client::handshake(&socket_path, "b", true);

        // Synchronize: a Reply is served from the same server loop that owns
        // B's event subscription, so once it arrives the subscription is
        // definitely registered — no race with A's first mutation.
        b.send(&ClientMessage::Command { id: 100, command: Command::GetSnapshot });
        match b.recv().expect("b snapshot reply") {
            ServerMessage::Reply { id: 100, .. } => {}
            other => panic!("expected Reply id=100, got {other:?}"),
        }

        // A's BridgeUp mutates the store at least twice (desired, then
        // actual); BridgeDown likewise — B must observe events with strictly
        // increasing global seq.
        a.send(&ClientMessage::Command { id: 1, command: Command::BridgeUp });
        let _reply1 = a.recv().expect("reply 1");
        a.send(&ClientMessage::Command { id: 2, command: Command::BridgeDown });
        let _reply2 = a.recv().expect("reply 2");

        let seq_of = |msg: ServerMessage| match msg {
            ServerMessage::Event { seq, event: EventBody::Snapshot { .. } } => seq,
            other => panic!("expected Event, got {other:?}"),
        };
        let first = seq_of(b.recv().expect("event 1"));
        let second = seq_of(b.recv().expect("event 2"));
        assert!(second > first, "seq must be strictly increasing: {first} then {second}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_mismatch_gets_hello_then_disconnect() {
    let socket_path = temp_socket_path();
    spawn_service(socket_path.clone()).await;

    client_io(move || {
        let mut client = Client::connect(&socket_path);
        client.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION + 1,
            client_name: "future-client".to_string(),
            subscribe_events: true,
        });

        // The server still serves Hello (so the client can see the server's
        // version) ...
        match client.recv().expect("hello reply") {
            ServerMessage::Hello { protocol_version, .. } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Hello, got {other:?}"),
        }

        // ... then closes: the next read is a clean EOF, not another message.
        let next = client.recv();
        assert!(next.is_none(), "expected disconnect after version-mismatch Hello, got {next:?}");
    })
    .await;
}
