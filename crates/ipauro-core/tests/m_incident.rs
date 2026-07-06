//! The M-INCIDENT (ticket R005-T2, "Replug self-heal end-to-end: member
//! unplug -> rebuild + app-rebind") and the `SetTransportScope` round trip.
//!
//! `@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` §4:
//! "Unplugging ONE USB member destroys the whole bridge" — real macOS
//! `if_bridge` tears down the ENTIRE bridge on any member removal, not just
//! that member. `MockHelper` reproduces this exactly (see
//! `helper_channel.rs`'s doc comment). This test drives the real service —
//! `ipauro_core::serve` — with a scripted `MockUsbNcmSource`, so both
//! `watch::run`'s fast-path detection AND `reconcile::run`'s self-healing
//! rebuild are exercised end-to-end, not just the pure decision function
//! (see `reconcile.rs`'s `m_incident_two_pass_sequence_at_the_pure_fn_level`
//! for that lower-level companion test).

use std::io::{BufReader, BufWriter, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipauro_proto::helper::HelperRequest;
use ipauro_core::discovery::MockUsbNcmSource;
use ipauro_core::helper_channel::MockHelper;
use ipauro_core::registrar::StubHelperRegistrar;
use ipauro_core::ServiceConfig;
use ipauro_proto::ipc::{read_msg, write_msg, ClientMessage, Command, ReplyOutcome, ServerMessage};
use ipauro_proto::PROTOCOL_VERSION;

fn temp_socket_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    // Short prefix: macOS caps `sockaddr_un.sun_path` at ~104 bytes (SUN_LEN)
    // and `std::env::temp_dir()` is already a long per-user path there.
    std::env::temp_dir().join(format!("ipauro-mi-{}-{n}-{nanos}.sock", std::process::id()))
}

struct Client {
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
}

impl Client {
    fn connect(socket_path: &PathBuf) -> Self {
        let stream = UnixStream::connect(socket_path).expect("connect to service socket");
        stream.set_read_timeout(Some(Duration::from_secs(10))).expect("set read timeout");
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

    fn handshake(socket_path: &PathBuf) -> Self {
        let mut client = Self::connect(socket_path);
        client.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_name: "m-incident-test".to_string(),
            subscribe_events: false,
        });
        match client.recv().expect("hello reply") {
            ServerMessage::Hello { protocol_version, .. } => assert_eq!(protocol_version, PROTOCOL_VERSION),
            other => panic!("expected Hello, got {other:?}"),
        }
        client
    }

    fn command(&mut self, id: u64, command: Command) -> ReplyOutcome {
        self.send(&ClientMessage::Command { id, command });
        match self.recv().expect("command reply") {
            ServerMessage::Reply { id: got_id, outcome } => {
                assert_eq!(got_id, id);
                outcome
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }
}

async fn spawn_service(
    socket_path: PathBuf,
    helper: Arc<MockHelper>,
    usb_source: Arc<MockUsbNcmSource>,
) {
    let config = ServiceConfig {
        socket_path: socket_path.clone(),
        helper,
        registrar: Arc::new(StubHelperRegistrar),
        usb_source,
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

async fn client_io<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("client task panicked")
}

/// Polls `check` until it returns `true` or `timeout` elapses (buffer well
/// past `watch::run`'s 2s fast-poll interval); panics with `what` on timeout.
async fn wait_until(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    loop {
        if check() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m_incident_replug_self_heals_the_whole_bridge() {
    let socket_path = temp_socket_path();
    let helper = Arc::new(MockHelper::new());
    let usb_source = Arc::new(MockUsbNcmSource::new([vec!["en9".to_string(), "en12".to_string()]]));
    spawn_service(socket_path.clone(), helper.clone(), usb_source.clone()).await;

    // BridgeUp drives the FULL first ordered pass synchronously (commands.rs
    // calls reconcile::drive_once directly), so convergence here needs no
    // waiting: the reply already reflects the built bridge.
    let socket_path_for_client = socket_path.clone();
    let outcome = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        client.command(1, Command::BridgeUp)
    })
    .await;
    let snapshot = match outcome {
        ReplyOutcome::Ok { snapshot } => snapshot,
        ReplyOutcome::Err { error } => panic!("BridgeUp failed: {error:?}"),
    };
    let bridge = snapshot.bridge.actual.expect("bridge should exist after BridgeUp");
    assert_eq!(bridge.members, vec!["en9".to_string(), "en12".to_string()]);
    assert_eq!(bridge.ipv4.as_deref(), Some(ipauro_proto::defaults::BRIDGE_IPV4.to_string().as_str()));
    assert!(snapshot.transport.dhcp_serving);

    // Simulate the detach: en12's cable is pulled. Nothing in the test
    // touches the service directly from here — `watch::run`'s fast poll must
    // notice on its own and kick `reconcile::run`.
    usb_source.push(vec!["en9".to_string()]);

    // Wait for the watch+reconcile loop to self-heal, entirely in the
    // background (no client command at all): the mock's blast-radius
    // response to the member-shrink SetBridgeMembers destroys the whole
    // bridge, and the reconciler's self-kick-on-change (reconcile::run's doc)
    // drives the follow-up full rebuild.
    wait_until(
        "bridge rebuilt with only en9 after the en12 detach",
        Duration::from_secs(10),
        || helper.requests().iter().filter(|r| **r == HelperRequest::CreateBridge).count() >= 2,
    )
    .await;

    // Give the follow-up pass(es) a moment to fully settle (address/dhcp/scope
    // re-applied), then assert final state + exact ordering.
    let socket_path_for_client = socket_path.clone();
    let final_snapshot = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        match client.command(2, Command::GetSnapshot) {
            ReplyOutcome::Ok { snapshot } => snapshot,
            ReplyOutcome::Err { error } => panic!("GetSnapshot failed: {error:?}"),
        }
    })
    .await;
    let bridge = final_snapshot.bridge.actual.expect("bridge should exist again after self-heal");
    assert_eq!(bridge.members, vec!["en9".to_string()]);
    assert_eq!(bridge.ipv4.as_deref(), Some(ipauro_proto::defaults::BRIDGE_IPV4.to_string().as_str()));
    assert!(final_snapshot.transport.dhcp_serving);

    // Assert the ORDER of verbs the mock received: first-pass build, then the
    // member-shrink that blast-radiuses the bridge away, then the full
    // ordered rebuild — CreateBridge -> SetBridgeMembers -> SetBridgeAddress
    // -> ServeDhcp, in that relative order (Report calls interleave; ignored
    // here since ordering among the ACTING verbs is what R005-T2 pins).
    let requests = helper.requests();
    let acting: Vec<&HelperRequest> = requests
        .iter()
        .filter(|r| !matches!(r, HelperRequest::Report | HelperRequest::Ping | HelperRequest::Status))
        .collect();

    let create_positions: Vec<usize> =
        acting.iter().enumerate().filter(|(_, r)| ***r == HelperRequest::CreateBridge).map(|(i, _)| i).collect();
    assert_eq!(create_positions.len(), 2, "expected exactly two CreateBridge calls: initial + rebuild");
    let rebuild_start = create_positions[1];

    // From the rebuild's CreateBridge onward, the ordered pass must appear:
    // CreateBridge, SetBridgeMembers([en9]), SetBridgeAddress, ServeDhcp.
    let rebuild_tail = &acting[rebuild_start..];
    assert_eq!(rebuild_tail[0], &HelperRequest::CreateBridge);
    assert!(
        matches!(rebuild_tail.get(1), Some(HelperRequest::SetBridgeMembers { members }) if *members == vec!["en9".to_string()]),
        "expected SetBridgeMembers([en9]) right after the rebuild's CreateBridge, got {:?}",
        rebuild_tail.get(1)
    );
    assert!(
        rebuild_tail
            .iter()
            .skip(2)
            .any(|r| matches!(r, HelperRequest::SetBridgeAddress { .. })),
        "expected SetBridgeAddress somewhere in the rebuild tail"
    );
    assert!(
        rebuild_tail.iter().skip(2).any(|r| matches!(r, HelperRequest::ServeDhcp { .. })),
        "expected ServeDhcp somewhere in the rebuild tail"
    );
    // SetBridgeAddress must precede ServeDhcp (the ordered pass, R005-F3).
    let addr_pos = rebuild_tail.iter().position(|r| matches!(r, HelperRequest::SetBridgeAddress { .. })).unwrap();
    let dhcp_pos = rebuild_tail.iter().position(|r| matches!(r, HelperRequest::ServeDhcp { .. })).unwrap();
    assert!(addr_pos < dhcp_pos, "SetBridgeAddress must be issued before ServeDhcp");

    // Also confirm the member-shrink step that triggered the blast radius
    // really happened before the rebuild (the whole point of R005-T2).
    let shrink_pos = acting
        .iter()
        .position(|r| matches!(r, HelperRequest::SetBridgeMembers { members } if *members == vec!["en9".to_string()]))
        .expect("expected a SetBridgeMembers([en9]) step");
    assert!(shrink_pos < rebuild_start, "the member-shrink step must precede the rebuild's CreateBridge");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m_incident_clears_stale_scope_before_rebuilding() {
    // Same detach scenario, but with transport scoping enabled first — this
    // is the specific A002 §4 trap: a pf scope naming the dead bridge must be
    // cleared BEFORE the bridge is recreated, not after.
    let socket_path = temp_socket_path();
    let helper = Arc::new(MockHelper::new());
    let usb_source = Arc::new(MockUsbNcmSource::new([vec!["en9".to_string(), "en12".to_string()]]));
    spawn_service(socket_path.clone(), helper.clone(), usb_source.clone()).await;

    let socket_path_for_client = socket_path.clone();
    client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        let outcome = client.command(1, Command::BridgeUp);
        assert!(matches!(outcome, ReplyOutcome::Ok { .. }));
        let outcome = client.command(2, Command::SetTransportScope { enabled: true });
        match outcome {
            ReplyOutcome::Ok { snapshot } => assert!(snapshot.transport.link_scoped),
            ReplyOutcome::Err { error } => panic!("SetTransportScope failed: {error:?}"),
        }
    })
    .await;

    usb_source.push(vec!["en9".to_string()]);

    wait_until(
        "bridge rebuilt after the en12 detach with scope re-applied",
        Duration::from_secs(10),
        || helper_saw_second_create(&helper),
    )
    .await;

    let socket_path_for_client = socket_path.clone();
    let final_snapshot = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        match client.command(3, Command::GetSnapshot) {
            ReplyOutcome::Ok { snapshot } => snapshot,
            ReplyOutcome::Err { error } => panic!("GetSnapshot failed: {error:?}"),
        }
    })
    .await;
    assert!(final_snapshot.transport.link_scoped, "scope must be re-applied after the rebuild");

    let requests = helper.requests();
    let clear_positions: Vec<usize> =
        requests.iter().enumerate().filter(|(_, r)| **r == HelperRequest::ClearScopes).map(|(i, _)| i).collect();
    let create_positions: Vec<usize> = requests
        .iter()
        .enumerate()
        .filter(|(_, r)| **r == HelperRequest::CreateBridge)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(create_positions.len(), 2);
    let rebuild_create = create_positions[1];
    // The rebuild's ClearScopes (clearing the stale scope pinned to the dead
    // bridge) must come strictly before the rebuild's CreateBridge.
    assert!(
        clear_positions.iter().any(|&p| p < rebuild_create),
        "expected a ClearScopes before the rebuild's CreateBridge (positions: clears={clear_positions:?}, rebuild_create={rebuild_create})"
    );
}

fn helper_saw_second_create(helper: &MockHelper) -> bool {
    helper.requests().iter().filter(|r| **r == HelperRequest::CreateBridge).count() >= 2
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_transport_scope_round_trips() {
    let socket_path = temp_socket_path();
    let helper = Arc::new(MockHelper::new());
    let usb_source = Arc::new(MockUsbNcmSource::new([vec!["en9".to_string()]]));
    spawn_service(socket_path.clone(), helper, usb_source).await;

    client_io(move || {
        let mut client = Client::handshake(&socket_path);
        // Bridge must be up for a scope to make sense (can't scope traffic to
        // an interface that doesn't exist yet).
        assert!(matches!(client.command(1, Command::BridgeUp), ReplyOutcome::Ok { .. }));

        match client.command(2, Command::SetTransportScope { enabled: true }) {
            ReplyOutcome::Ok { snapshot } => assert!(snapshot.transport.link_scoped),
            ReplyOutcome::Err { error } => panic!("enable failed: {error:?}"),
        }

        match client.command(3, Command::SetTransportScope { enabled: false }) {
            ReplyOutcome::Ok { snapshot } => assert!(!snapshot.transport.link_scoped),
            ReplyOutcome::Err { error } => panic!("disable failed: {error:?}"),
        }
    })
    .await;
}
