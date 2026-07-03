//! Background IPC client: connects to the brain service over its unix
//! socket, completes the `Hello` handshake with `subscribe_events: true`,
//! and forwards every snapshot — from `Hello`'s reply, pushed `Event`s, and
//! command `Reply`s alike — to the UI as a [`ConnEvent`] over an mpsc
//! channel. Commands flow the other way over a second channel. Reconnects
//! forever with capped exponential backoff, resetting to the initial delay
//! whenever a connection is actually established.
//!
//! Two threads run per connection attempt: the caller of [`spawn`] owns a
//! single long-lived thread that drives the reconnect loop and writes
//! outgoing commands; each connection spawns a short-lived reader thread
//! that blocks on `read_msg` and forwards parsed messages back. Splitting
//! reader and writer avoids a read-timeout multiplexing loop, which would
//! risk silently dropping a message read partway through when a timeout
//! lands mid-line — `read_msg`'s buffer is not a valid unit of retry.
//! Blocking calls on two plain threads are simple and correct; a hand-rolled
//! poll loop would be "clever" for no benefit here.

use std::io::{self, BufReader, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use eframe::egui;
use ipauro_proto::ipc::{self, ClientMessage, Command, ReplyOutcome, ServerMessage};

use crate::state::ConnEvent;

const CLIENT_NAME: &str = "ipauro-ui";

/// Where to connect: the `IPAURO_SOCKET` env override (dev/test convenience,
/// honored client-side since `ipauro_proto::ipc::default_socket_path` is
/// pure), else the proto crate's default.
fn socket_path() -> PathBuf {
    std::env::var_os("IPAURO_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(ipauro_proto::ipc::default_socket_path)
}

/// Spawn the background IPC thread. Returns the receiver `IpauroApp::logic`
/// drains every frame for [`ConnEvent`]s, and the sender it uses to issue
/// [`Command`]s. `ctx` is cloned into both the writer and reader threads so
/// each can call `request_repaint()` right after producing an event, rather
/// than making the UI wait for its next scheduled poll.
pub fn spawn(ctx: egui::Context) -> (Receiver<ConnEvent>, Sender<Command>) {
    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();
    thread::spawn(move || reconnect_loop(ev_tx, cmd_rx, ctx));
    (ev_rx, cmd_tx)
}

fn reconnect_loop(ev_tx: Sender<ConnEvent>, cmd_rx: Receiver<Command>, ctx: egui::Context) {
    let mut backoff = Backoff::default();
    // Whether this outage episode has already gotten its one self-start
    // attempt (see `connected_this_attempt` below) — reset the moment a
    // connection actually lands, so the *next* outage gets a fresh attempt
    // rather than being silently skipped forever after the first one.
    let mut attempted_start = false;
    loop {
        let mut connected_this_attempt = false;
        if let Err(err) =
            run_connection(&ev_tx, &cmd_rx, &ctx, &mut backoff, &mut connected_this_attempt)
        {
            log::debug!("ipc: connection ended: {err}");
        }
        // Every exit path from `run_connection` means we no longer have a
        // live connection, whether it ever succeeded or not.
        let _ = ev_tx.send(ConnEvent::Disconnected);
        ctx.request_repaint();

        if connected_this_attempt {
            attempted_start = false;
        } else if !attempted_start {
            attempted_start = true;
            crate::service_bootstrap::attempt_start(&ev_tx, &ctx);
        }
        thread::sleep(backoff.next_delay());
    }
}

/// Run a single connection attempt to completion (until it drops or errors).
/// Resets `backoff` as soon as the handshake succeeds, so a connection that
/// lived a while before dropping retries quickly rather than inheriting a
/// maxed-out delay from earlier failed attempts.
fn run_connection(
    ev_tx: &Sender<ConnEvent>,
    cmd_rx: &Receiver<Command>,
    ctx: &egui::Context,
    backoff: &mut Backoff,
    connected_this_attempt: &mut bool,
) -> io::Result<()> {
    let mut writer = UnixStream::connect(socket_path())?;
    let reader_stream = writer.try_clone()?;

    ipc::write_msg(
        &mut writer,
        &ClientMessage::Hello {
            protocol_version: ipauro_proto::PROTOCOL_VERSION,
            client_name: CLIENT_NAME.to_string(),
            subscribe_events: true,
        },
    )?;
    writer.flush()?;

    backoff.reset();
    let _ = ev_tx.send(ConnEvent::Connected);
    ctx.request_repaint();
    *connected_this_attempt = true;

    let done = Arc::new(AtomicBool::new(false));
    let reader_handle = {
        let ev_tx = ev_tx.clone();
        let ctx = ctx.clone();
        let done = Arc::clone(&done);
        thread::spawn(move || read_loop(reader_stream, &ev_tx, &ctx, &done))
    };

    let mut next_id: u64 = 0;
    let result = loop {
        if done.load(Ordering::Acquire) {
            break Ok(());
        }
        match cmd_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(command) => {
                next_id += 1;
                let msg = ClientMessage::Command { id: next_id, command };
                if let Err(err) = ipc::write_msg(&mut writer, &msg).and_then(|()| writer.flush()) {
                    break Err(err);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            // The UI side dropped its sender, which only happens if
            // `IpauroApp` itself was torn down — quietly stop this
            // connection rather than treating it as an error.
            Err(RecvTimeoutError::Disconnected) => break Ok(()),
        }
    };

    // Force the reader's blocking read to unblock (EOF) even if we're the
    // side that noticed the problem first, so it can exit and be joined
    // instead of leaking a thread parked in a blocking read.
    let _ = writer.shutdown(Shutdown::Both);
    let _ = reader_handle.join();
    result
}

fn read_loop(stream: UnixStream, ev_tx: &Sender<ConnEvent>, ctx: &egui::Context, done: &AtomicBool) {
    let mut reader = BufReader::new(stream);
    loop {
        match ipc::read_msg::<ServerMessage>(&mut reader) {
            Ok(Some(msg)) => {
                if let Some(event) = translate(msg) {
                    let _ = ev_tx.send(event);
                    ctx.request_repaint();
                }
            }
            Ok(None) => break, // clean EOF
            Err(err) => {
                log::debug!("ipc: read error: {err}");
                break;
            }
        }
    }
    done.store(true, Ordering::Release);
}

/// `ServerMessage` → `ConnEvent`, matching every variant explicitly (`Hello`,
/// `Event`, `Reply`; `EventBody`'s one variant; `ReplyOutcome`'s two) — no
/// catch-all, so a protocol addition fails to compile here until handled.
/// `ReplyOutcome::Err` still yields an event (`CommandError`) rather than
/// `None`: the panel renders a transient status line from it (`state.rs`'s
/// `StatusLine`), so a failed `RegisterHelper`/`BridgeUp`/etc. is visible,
/// not just logged.
fn translate(msg: ServerMessage) -> Option<ConnEvent> {
    match msg {
        ServerMessage::Hello { snapshot, .. } => Some(ConnEvent::Snapshot(snapshot)),
        ServerMessage::Event { event: ipc::EventBody::Snapshot { snapshot }, .. } => {
            Some(ConnEvent::Snapshot(snapshot))
        }
        ServerMessage::Reply { outcome, .. } => match outcome {
            ReplyOutcome::Ok { snapshot } => Some(ConnEvent::Snapshot(snapshot)),
            ReplyOutcome::Err { error } => {
                log::warn!("ipc: command failed: {:?}: {}", error.code, error.message);
                Some(ConnEvent::CommandError(error.message))
            }
        },
    }
}

/// Capped exponential backoff for reconnect attempts.
struct Backoff {
    current: Duration,
}

impl Backoff {
    const INITIAL: Duration = Duration::from_millis(250);
    const MAX: Duration = Duration::from_secs(5);

    fn reset(&mut self) {
        self.current = Self::INITIAL;
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * 2).min(Self::MAX);
        delay
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self { current: Self::INITIAL }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipauro_proto::ipc::{ErrorCode, ErrorInfo};
    use ipauro_proto::state::{BridgeState, HelperState, ServiceInfo, Snapshot};

    fn snapshot() -> Snapshot {
        Snapshot {
            service: ServiceInfo { version: "0.0.1".into(), pid: 1, started_unix: 0 },
            helper: HelperState::NotRegistered,
            bridge: BridgeState { desired_up: false, actual: None },
        }
    }

    #[test]
    fn translates_hello_to_snapshot() {
        let msg = ServerMessage::Hello {
            protocol_version: ipauro_proto::PROTOCOL_VERSION,
            server_version: "0.0.1".into(),
            snapshot: snapshot(),
        };
        assert_eq!(translate(msg), Some(ConnEvent::Snapshot(snapshot())));
    }

    #[test]
    fn translates_event_to_snapshot() {
        let msg = ServerMessage::Event { seq: 3, event: ipc::EventBody::Snapshot { snapshot: snapshot() } };
        assert_eq!(translate(msg), Some(ConnEvent::Snapshot(snapshot())));
    }

    #[test]
    fn translates_ok_reply_to_snapshot() {
        let msg = ServerMessage::Reply { id: 1, outcome: ReplyOutcome::Ok { snapshot: snapshot() } };
        assert_eq!(translate(msg), Some(ConnEvent::Snapshot(snapshot())));
    }

    #[test]
    fn translates_err_reply_to_command_error() {
        let msg = ServerMessage::Reply {
            id: 1,
            outcome: ReplyOutcome::Err {
                error: ErrorInfo { code: ErrorCode::HelperNotConnected, message: "nope".into() },
            },
        };
        assert_eq!(translate(msg), Some(ConnEvent::CommandError("nope".into())));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut backoff = Backoff::default();
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
        assert_eq!(backoff.next_delay(), Duration::from_millis(500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(1_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(4_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(5_000)); // capped
        assert_eq!(backoff.next_delay(), Duration::from_millis(5_000)); // stays capped
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut backoff = Backoff::default();
        backoff.next_delay();
        backoff.next_delay();
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
    }

    #[test]
    fn socket_path_honors_env_override() {
        // SAFETY: test-only env mutation; this test does not run in
        // parallel with anything else that reads IPAURO_SOCKET.
        unsafe { std::env::set_var("IPAURO_SOCKET", "/tmp/ipauro-test.sock") };
        assert_eq!(socket_path(), PathBuf::from("/tmp/ipauro-test.sock"));
        unsafe { std::env::remove_var("IPAURO_SOCKET") };
    }
}
