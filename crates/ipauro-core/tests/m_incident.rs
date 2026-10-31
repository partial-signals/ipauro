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
use ipauro_proto::ipc::{read_msg, write_msg, ClientMessage, Command, EventBody, ReplyOutcome, ServerMessage};
use ipauro_proto::state::Snapshot;
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

    /// Like [`Client::recv`] but never panics: `None` on EOF, read timeout, or
    /// any other read error. For the background reader thread, which outlives
    /// the assertions it feeds and should just stop rather than blow up.
    fn try_recv(&mut self) -> Option<ServerMessage> {
        read_msg(&mut self.reader).ok().flatten()
    }

    /// Handle for unblocking a reader parked in [`Client::try_recv`] from
    /// another thread: `shutdown(Shutdown::Read)` on it makes that pending
    /// read return EOF at once, instead of sitting out the socket's read
    /// timeout.
    fn shutdown_handle(&self) -> UnixStream {
        self.reader.get_ref().try_clone().expect("clone socket for shutdown")
    }

    fn handshake(socket_path: &PathBuf) -> Self {
        Self::handshake_with(socket_path, false).0
    }

    /// Handshake, returning the `Hello` snapshot alongside the client — that
    /// snapshot is the baseline a connecting app binds at (its
    /// `bridge.epoch`), so the rebind test needs it, not just the connection.
    fn handshake_with(socket_path: &PathBuf, subscribe_events: bool) -> (Self, Snapshot) {
        let mut client = Self::connect(socket_path);
        client.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_name: "m-incident-test".to_string(),
            subscribe_events,
        });
        match client.recv().expect("hello reply") {
            ServerMessage::Hello { protocol_version, snapshot, .. } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                (client, snapshot)
            }
            other => panic!("expected Hello, got {other:?}"),
        }
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
        mesh_node: None,
        membership: None,
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
    // Sorted, not in the order the source happened to report them: R005-F7's
    // identification pass canonicalizes the member list, so a `SetBridgeMembers`
    // request is a function of WHICH interfaces are host-side links, never of
    // the order `ioreg` printed them.
    assert_eq!(bridge.members, vec!["en12".to_string(), "en9".to_string()]);
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

/// The OTHER half of R005-T2: "member unplug → rebuild **+ app-rebind**".
///
/// Rebuilding the bridge is not recovery on its own. A002 §4: the hub's audio
/// app still holds a multicast socket joined on the interface that just died,
/// and the rebuilt `bridge90` comes back under the same name with the same
/// address — so an app diffing the snapshot's name/members/ipv4 sees NOTHING
/// change and never rejoins. `BridgeState::epoch` is the one field that moves,
/// and this test drives it end to end: a subscribed client (standing in for
/// that audio app) must be TOLD, over the live event stream, that the
/// generation it bound at is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn m_incident_signals_app_rebind_over_the_event_stream() {
    let socket_path = temp_socket_path();
    let helper = Arc::new(MockHelper::new());
    let usb_source = Arc::new(MockUsbNcmSource::new([vec!["en9".to_string(), "en12".to_string()]]));
    spawn_service(socket_path.clone(), helper.clone(), usb_source.clone()).await;

    // The "audio app": subscribes to events and records the generation of
    // every snapshot pushed to it, in order. Its own thread with a plain
    // channel — this is the blocking-socket shape a real external app has.
    let socket_path_for_app = socket_path.clone();
    let (app_client, hello) =
        client_io(move || Client::handshake_with(&socket_path_for_app, true)).await;
    // The generation an app connecting right now would bind its sockets at.
    // No bridge exists yet, so this is the pre-bridge baseline.
    let bound_epoch = hello.bridge.epoch;
    assert_eq!(bound_epoch, 0, "no bridge existed when the app connected");

    let app_shutdown = app_client.shutdown_handle();
    let (tx, rx) = std::sync::mpsc::channel::<u64>();
    let app = std::thread::spawn(move || {
        let mut client = app_client;
        while let Some(msg) = client.try_recv() {
            if let ServerMessage::Event { event: EventBody::Snapshot { snapshot }, .. } = msg
                && tx.send(snapshot.bridge.epoch).is_err()
            {
                return; // test finished; stop reading
            }
        }
    });

    // Drive the same M-incident from a separate control connection: build,
    // then pull en12's cable.
    let socket_path_for_client = socket_path.clone();
    let built = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        match client.command(1, Command::BridgeUp) {
            ReplyOutcome::Ok { snapshot } => snapshot,
            ReplyOutcome::Err { error } => panic!("BridgeUp failed: {error:?}"),
        }
    })
    .await;
    assert_eq!(
        built.bridge.epoch, 1,
        "the first build is generation 1 — an app binding now records 1"
    );

    usb_source.push(vec!["en9".to_string()]);

    // Collect the generations the app was pushed, until one exceeds what it
    // bound at. THIS is the app-rebind signal arriving.
    let mut seen: Vec<u64> = Vec::new();
    wait_until("the bound app to be pushed a new bridge generation", Duration::from_secs(10), || {
        while let Ok(epoch) = rx.try_recv() {
            seen.push(epoch);
        }
        seen.iter().any(|&e| e > 1)
    })
    .await;

    let socket_path_for_client = socket_path.clone();
    let final_snapshot = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        match client.command(2, Command::GetSnapshot) {
            ReplyOutcome::Ok { snapshot } => snapshot,
            ReplyOutcome::Err { error } => panic!("GetSnapshot failed: {error:?}"),
        }
    })
    .await;

    // Exactly one rebind for one unplug. A generation per reconcile pass
    // (there are several) would make the signal useless — an app would drop
    // audio rejoining on every poll — so the count is the assertion, not just
    // "it moved". 1 = the initial build, 2 = the self-heal rebuild.
    assert_eq!(
        final_snapshot.bridge.epoch, 2,
        "one unplug must produce exactly one rebind signal (generations seen by the app: {seen:?})"
    );
    // And the bridge it names is the healed one, so the app has somewhere to
    // rebind TO — a generation bump pointing at `actual: None` would be a
    // signal to nowhere.
    let bridge = final_snapshot.bridge.actual.expect("bridge should exist again after self-heal");
    assert_eq!(bridge.members, vec!["en9".to_string()]);

    // Every generation the app was pushed is monotonic: an app that latches
    // "rebind when this differs from what I hold" must never be walked
    // backwards into rebinding to a bridge that already died.
    assert!(
        seen.windows(2).all(|w| w[1] >= w[0]),
        "generations pushed to a subscribed app must be monotonic, got {seen:?}"
    );

    // Unblock the app's parked read so the thread ends now rather than
    // sitting out the socket read timeout.
    let _ = app_shutdown.shutdown(std::net::Shutdown::Read);
    app.join().expect("app thread panicked");
}

/// The field shape of the same incident, and the one the snapshot alone
/// cannot express: the cable is pulled at an arbitrary moment, so a reconcile
/// pass OPENS with the bridge already gone and rebuilds it before anything is
/// reported. Members, name and address all come back identical — the rebuilt
/// interface is the only thing that changed, and an app diffing the snapshot
/// would see a perfectly steady bridge while its socket sits on a dead
/// ifindex. Only the generation moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebuild_within_one_pass_still_signals_a_rebind() {
    let socket_path = temp_socket_path();
    let helper = Arc::new(MockHelper::new());
    let usb_source = Arc::new(MockUsbNcmSource::new([vec!["en9".to_string(), "en12".to_string()]]));
    spawn_service(socket_path.clone(), helper.clone(), usb_source.clone()).await;

    let socket_path_for_client = socket_path.clone();
    let built = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        match client.command(1, Command::BridgeUp) {
            ReplyOutcome::Ok { snapshot } => snapshot,
            ReplyOutcome::Err { error } => panic!("BridgeUp failed: {error:?}"),
        }
    })
    .await;
    assert_eq!(built.bridge.epoch, 1);
    let before = built.bridge.actual.expect("bridge after BridgeUp");

    // The kernel takes the bridge with no membership change to notice — and
    // no reconcile pass observes the gap, because the very next pass both
    // sees it missing and rebuilds it.
    helper.destroy_out_of_band().await;

    // Drive the next pass. In the field this is `reconcile::run`'s 15s
    // backstop or an interface-change event; a repeat `BridgeUp` is the
    // same full ordered pass (`drive_bridge` → `drive_once`) without the
    // wall-clock wait, and is idempotent by construction.
    let socket_path_for_client = socket_path.clone();
    let healed = client_io(move || {
        let mut client = Client::handshake(&socket_path_for_client);
        match client.command(2, Command::BridgeUp) {
            ReplyOutcome::Ok { snapshot } => snapshot,
            ReplyOutcome::Err { error } => panic!("BridgeUp failed: {error:?}"),
        }
    })
    .await;

    let after = healed.bridge.actual.expect("bridge rebuilt within the pass");
    assert_eq!(after, before, "the rebuilt bridge is indistinguishable in the snapshot");
    assert_eq!(
        healed.bridge.epoch, 2,
        "the generation is the ONLY evidence the interface was replaced — without it \
         a bound app has nothing to key a rebind on"
    );
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
