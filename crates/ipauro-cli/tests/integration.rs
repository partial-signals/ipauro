//! Integration tests: drive the real `ipauro_cli::run` client logic against
//! an in-process fake server speaking `ipauro-proto`'s IPC protocol over a
//! temp unix socket. No subprocess — this calls the library function
//! directly so assertions can inspect exit codes plus captured stdout/stderr.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use ipauro_proto::ipc::{write_msg, ClientMessage, ErrorCode, ErrorInfo, EventBody, ReplyOutcome, ServerMessage};
use ipauro_proto::state::{BridgeInfo, BridgeState, HelperState, ServiceInfo, Snapshot};
use ipauro_proto::PROTOCOL_VERSION;

use ipauro_cli::{BridgeAction, Cli, Cmd, EXIT_COMMAND_ERR, EXIT_CONNECTION, EXIT_OK, EXIT_VERSION_MISMATCH};

fn temp_socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "ipauro-cli-test-{}-{tag}-{n}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn hello_snapshot() -> Snapshot {
    Snapshot {
        service: ServiceInfo { version: "9.9.9-fake".into(), pid: 4242, started_unix: 1_700_000_000 },
        helper: HelperState::Connected { version: "9.9.9-fake".into() },
        bridge: BridgeState { desired_up: false, actual: None, epoch: 0 },
        transport: Default::default(),
        // The fake server's Hello always carries this; `status mesh` reads it.
        mesh: ipauro_proto::state::MeshView { status: Some(mesh_status()), ..Default::default() },
    }
}

fn bridge_up_snapshot() -> Snapshot {
    Snapshot {
        bridge: BridgeState {
            desired_up: true,
            actual: Some(BridgeInfo {
                name: "bridge90".into(),
                members: vec!["en9".into(), "en12".into()],
                ipv4: Some("10.69.0.1".into()),
                prefix: None,
            }),
            epoch: 1,
        },
        transport: Default::default(),
        ..hello_snapshot()
    }
}

/// What the fake server does when the client sends a `Command`.
enum ReplyPlan {
    Ok(Snapshot),
    Err(ErrorInfo),
}

/// Serve exactly one connection:
/// - Hello handshake (advertising `hello_protocol_version`; a mismatched
///   version makes the real client bail right after Hello, so the server
///   just returns).
/// - Watch scenario (client subscribed to events): emit one `Event`, then
///   close the connection so the client's watch loop sees EOF and exits.
/// - Command scenario: for each `Command`, emit one interleaved `Event`
///   FIRST (the client must skip it while awaiting its Reply) and then the
///   `Reply` per `reply`; return on client disconnect.
fn spawn_fake_server(path: PathBuf, hello_protocol_version: u32, reply: ReplyPlan) -> JoinHandle<()> {
    let listener = UnixListener::bind(&path).expect("bind fake server socket");
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept connection");
        let mut writer = stream.try_clone().expect("clone stream for writing");
        let mut reader = BufReader::new(stream);

        let mut line = String::new();
        if reader.read_line(&mut line).expect("read hello line") == 0 {
            return;
        }
        let hello: ClientMessage = serde_json::from_str(line.trim_end()).expect("parse hello");
        let subscribe_events = match hello {
            ClientMessage::Hello { subscribe_events, .. } => subscribe_events,
            ClientMessage::Command { .. } => panic!("expected Hello as the first client message"),
        };

        write_msg(
            &mut writer,
            &ServerMessage::Hello {
                protocol_version: hello_protocol_version,
                server_version: "9.9.9-fake".into(),
                snapshot: hello_snapshot(),
            },
        )
        .expect("write hello reply");
        writer.flush().expect("flush hello reply");

        if hello_protocol_version != PROTOCOL_VERSION {
            // The client is expected to bail immediately without sending
            // anything further; nothing left for this fake server to do.
            return;
        }

        if subscribe_events {
            // Watch scenario: two events carrying the SAME snapshot, then hang
            // up (dropping the streams closes the socket) so the client's
            // watch loop ends on EOF. Two rather than one so a test can tell
            // a rebind notice that fires on a generation CHANGE from one that
            // fires on every event.
            let snapshot = match &reply {
                ReplyPlan::Ok(s) => s.clone(),
                ReplyPlan::Err(_) => hello_snapshot(),
            };
            for seq in 1..=2 {
                write_msg(
                    &mut writer,
                    &ServerMessage::Event { seq, event: EventBody::Snapshot { snapshot: snapshot.clone() } },
                )
                .expect("write event");
            }
            writer.flush().expect("flush events");
            return;
        }

        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).expect("read client message");
            if n == 0 {
                return;
            }
            let msg: ClientMessage = serde_json::from_str(line.trim_end()).expect("parse client message");
            match msg {
                ClientMessage::Command { id, command: _ } => {
                    // Interleave an Event before the Reply: the client must
                    // skip it while waiting for its correlated Reply.
                    write_msg(
                        &mut writer,
                        &ServerMessage::Event {
                            seq: 1,
                            event: EventBody::Snapshot { snapshot: hello_snapshot() },
                        },
                    )
                    .expect("write interleaved event");
                    let outcome = match &reply {
                        ReplyPlan::Ok(s) => ReplyOutcome::Ok { snapshot: s.clone() },
                        ReplyPlan::Err(e) => ReplyOutcome::Err { error: e.clone() },
                    };
                    write_msg(&mut writer, &ServerMessage::Reply { id, outcome }).expect("write reply");
                    writer.flush().expect("flush reply");
                }
                ClientMessage::Hello { .. } => panic!("unexpected second Hello from client"),
            }
        }
    })
}

fn run_cli(socket: PathBuf, json: bool, command: Cmd) -> (i32, String, String) {
    let cli = Cli { socket: Some(socket), json, command };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = ipauro_cli::run(cli, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn status_prints_pretty_snapshot_from_hello() {
    let path = temp_socket_path("status");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(hello_snapshot()));

    let (code, stdout, stderr) = run_cli(path.clone(), false, Cmd::Status { what: None });
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    assert!(stdout.contains("9.9.9-fake"), "stdout: {stdout}");
    assert!(stdout.contains("4242"));
    assert!(stdout.contains("connected (v9.9.9-fake)"));
    assert!(stdout.contains("desired   down"));
    assert!(stdout.contains("actual    none"));
}

#[test]
fn status_json_passes_raw_hello_line_through() {
    let path = temp_socket_path("status-json");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(hello_snapshot()));

    let (code, stdout, stderr) = run_cli(path.clone(), true, Cmd::Status { what: None });
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    let line = stdout.trim_end();
    let msg: ServerMessage = serde_json::from_str(line).expect("--json status output must be a raw ServerMessage line");
    match msg {
        ServerMessage::Hello { protocol_version, snapshot, .. } => {
            assert_eq!(protocol_version, PROTOCOL_VERSION);
            assert_eq!(snapshot, hello_snapshot());
        }
        other => panic!("expected Hello, got {other:?}"),
    }
}

#[test]
fn bridge_up_returns_ok_and_new_snapshot() {
    let path = temp_socket_path("bridge-up");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(bridge_up_snapshot()));

    let (code, stdout, stderr) =
        run_cli(path.clone(), false, Cmd::Bridge { action: BridgeAction::Up });
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    assert!(stdout.contains("desired   up"));
    assert!(stdout.contains("bridge90"));
    assert!(stdout.contains("en9, en12"));
    assert!(stdout.contains("10.69.0.1"));
}

#[test]
fn bridge_up_err_reply_exits_1_with_message_on_stderr() {
    let path = temp_socket_path("bridge-up-err");
    let error =
        ErrorInfo { code: ErrorCode::HelperNotConnected, message: "helper not connected".into() };
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Err(error));

    let (code, stdout, stderr) =
        run_cli(path.clone(), false, Cmd::Bridge { action: BridgeAction::Up });
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_COMMAND_ERR);
    assert!(stdout.is_empty(), "stdout should be empty on error: {stdout}");
    assert!(stderr.contains("helper_not_connected"));
    assert!(stderr.contains("helper not connected"));
}

#[test]
fn watch_prints_one_event_then_exits_on_eof() {
    let path = temp_socket_path("watch");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(bridge_up_snapshot()));

    let (code, stdout, stderr) = run_cli(path.clone(), false, Cmd::Watch);
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    assert!(stdout.contains("#1"), "stdout: {stdout}");
    assert!(stdout.contains("bridge90"));
    assert!(stdout.contains("bridge_desired=up"));
}

/// The client half of R005-T2's app-rebind contract, end to end through the
/// real CLI: `Hello` says generation 0, the pushed event says generation 1,
/// so `watch` must tell the operator their sockets are on a dead interface —
/// ONCE. The second event repeats generation 1 and must stay quiet, because a
/// notice on every event is a notice an app learns to ignore.
#[test]
fn watch_reports_a_rebind_once_per_generation_change() {
    let path = temp_socket_path("watch-rebind");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(bridge_up_snapshot()));

    let (code, stdout, stderr) = run_cli(path.clone(), false, Cmd::Watch);
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    assert_eq!(
        stdout.matches("** rebind:").count(),
        1,
        "exactly one rebind notice across two same-generation events: {stdout}"
    );
    assert!(stdout.contains("generation 1"), "stdout: {stdout}");
    // Both event lines carry the generation, so `--json`-less consumers can
    // still see it without waiting for a change.
    assert_eq!(stdout.matches("gen=1").count(), 2, "stdout: {stdout}");
}

/// `--json` is a machine surface: the raw NDJSON lines already carry
/// `bridge.epoch`, so the human-facing rebind notice must not be spliced into
/// the stream where it would break a line-oriented parser.
#[test]
fn watch_json_stays_machine_clean_across_a_rebind() {
    let path = temp_socket_path("watch-rebind-json");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(bridge_up_snapshot()));

    let (code, stdout, stderr) = run_cli(path.clone(), true, Cmd::Watch);
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    assert!(!stdout.contains("** rebind:"), "stdout: {stdout}");
    for line in stdout.lines() {
        let parsed: ServerMessage = serde_json::from_str(line).expect("every watch --json line parses");
        match parsed {
            ServerMessage::Event { event: EventBody::Snapshot { snapshot }, .. } => {
                assert_eq!(snapshot.bridge.epoch, 1, "the generation rides the raw line");
            }
            other => panic!("expected an Event, got {other:?}"),
        }
    }
}

#[test]
fn version_mismatch_exits_3() {
    let path = temp_socket_path("version-mismatch");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION + 1, ReplyPlan::Ok(hello_snapshot()));

    let (code, stdout, stderr) = run_cli(path.clone(), false, Cmd::Status { what: None });
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert_eq!(code, EXIT_VERSION_MISMATCH);
    assert!(stdout.is_empty());
    assert!(stderr.contains("mismatch"));
}

#[test]
fn connection_refused_exits_2_with_friendly_message() {
    // No server listening: exercise the "service not running" path directly.
    let path = temp_socket_path("no-server");

    let (code, stdout, stderr) = run_cli(path.clone(), false, Cmd::Status { what: None });

    assert_eq!(code, EXIT_CONNECTION);
    assert!(stdout.is_empty());
    assert!(stderr.contains("not running"), "stderr: {stderr}");
    assert!(stderr.contains(&path.display().to_string()));
}

#[test]
fn mesh_and_rate_subcommands_parse() {
    use clap::Parser;
    use ipauro_cli::{RateAction, StatusAction};
    let c = Cli::try_parse_from(["ipauro", "status", "mesh"]).unwrap();
    assert!(matches!(c.command, Cmd::Status { what: Some(StatusAction::Mesh) }));
    let c = Cli::try_parse_from(["ipauro", "status"]).unwrap();
    assert!(matches!(c.command, Cmd::Status { what: None }));
    let c = Cli::try_parse_from(["ipauro", "rate", "propose", "96000"]).unwrap();
    assert!(matches!(c.command, Cmd::Rate { action: RateAction::Propose { hz: 96_000 } }));
    assert!(Cli::try_parse_from(["ipauro", "rate", "propose"]).is_err());
    assert!(Cli::try_parse_from(["ipauro", "rate", "propose", "fast"]).is_err());
}

fn mesh_snapshot() -> Snapshot {
    hello_snapshot()
}

fn mesh_status() -> ipauro_proto::state::MeshStatus {
    use ipauro_proto::state::*;
    MeshStatus {
        version: MESH_STATUS_VERSION,
        rate: MeshRateView { hz: 96_000, epoch: 1, author: "aa".into() },
        blockages: vec![Blockage {
            cause: BlockCause::IrohBindFailed { error: "in use".into() },
            remedy: Remedy::RestartService,
        }],
        ..Default::default()
    }
}

#[test]
fn status_mesh_prints_rate_and_blockages() {
    let path = temp_socket_path("status-mesh");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(mesh_snapshot()));
    let (code, stdout, stderr) = run_cli(
        path.clone(),
        false,
        Cmd::Status { what: Some(ipauro_cli::StatusAction::Mesh) },
    );
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
    assert!(stdout.contains("rate: 96000 Hz (epoch 1"), "{stdout}");
    assert!(stdout.contains("mesh endpoint failed to bind: in use"), "{stdout}");
    assert!(stdout.contains("fix: free the port"), "{stdout}");
}

#[test]
fn rate_propose_sends_the_command_and_prints_the_reply() {
    let path = temp_socket_path("rate-propose");
    let server = spawn_fake_server(path.clone(), PROTOCOL_VERSION, ReplyPlan::Ok(mesh_snapshot()));
    let (code, _stdout, stderr) = run_cli(
        path.clone(),
        false,
        Cmd::Rate { action: ipauro_cli::RateAction::Propose { hz: 96_000 } },
    );
    server.join().unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, EXIT_OK, "stderr: {stderr}");
}
