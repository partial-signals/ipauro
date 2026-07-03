//! Connection + wire-level plumbing against `ipauro-proto`'s IPC surface.
//!
//! Kept independent of `clap` so it can be driven directly by tests (spawn a
//! fake server on a temp socket, call these functions) without subprocess
//! plumbing.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use ipauro_proto::ipc::{write_msg, ClientMessage, Command, ReplyOutcome, ServerMessage};

use crate::format;
use crate::{EXIT_COMMAND_ERR, EXIT_CONNECTION, EXIT_OK};

/// Why `connect` failed, distinguishing "nothing is listening" (the common,
/// friendly case) from other I/O trouble.
#[derive(Debug)]
pub enum ConnectError {
    /// No socket file, or a stale one nobody is listening on: the service
    /// just isn't running.
    NotRunning { path: PathBuf, source: io::Error },
    /// Some other I/O failure (permissions, etc).
    Io { path: PathBuf, source: io::Error },
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::NotRunning { path, .. } => {
                write!(f, "service not running (looked at {})", path.display())
            }
            ConnectError::Io { path, source } => {
                write!(f, "failed to connect to {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ConnectError {}

/// Connect to the brain-service's unix socket.
pub fn connect(socket: &Path) -> Result<UnixStream, ConnectError> {
    UnixStream::connect(socket).map_err(|source| {
        if matches!(source.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) {
            ConnectError::NotRunning { path: socket.to_path_buf(), source }
        } else {
            ConnectError::Io { path: socket.to_path_buf(), source }
        }
    })
}

/// Send `ClientMessage::Hello`.
pub fn send_hello(stream: &mut UnixStream, client_name: &str, subscribe_events: bool) -> io::Result<()> {
    write_msg(
        stream,
        &ClientMessage::Hello {
            protocol_version: ipauro_proto::PROTOCOL_VERSION,
            client_name: client_name.to_string(),
            subscribe_events,
        },
    )?;
    stream.flush()
}

/// Send `ClientMessage::Command` with the given correlation id.
fn send_command(stream: &mut UnixStream, id: u64, command: Command) -> io::Result<()> {
    write_msg(stream, &ClientMessage::Command { id, command })?;
    stream.flush()
}

/// Read one NDJSON line and parse it as a `ServerMessage`, returning both the
/// raw trimmed line (for `--json` passthrough) and the parsed value.
/// `Ok(None)` means clean EOF.
pub fn read_server_message(
    reader: &mut BufReader<UnixStream>,
) -> io::Result<Option<(String, ServerMessage)>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim_end().to_string();
    let msg = serde_json::from_str(&trimmed).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some((trimmed, msg)))
}

/// Send one `Command`, then read messages until the `Reply` correlated by
/// `id` arrives (interleaved `Event`s are skipped per the protocol's
/// lifecycle contract). Prints the outcome and returns the process exit code.
pub fn run_command(
    writer: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    command: Command,
    json: bool,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
) -> i32 {
    const WANT_ID: u64 = 1;
    if let Err(e) = send_command(writer, WANT_ID, command) {
        let _ = writeln!(err_out, "failed to send command: {e}");
        return EXIT_CONNECTION;
    }
    loop {
        match read_server_message(reader) {
            Ok(Some((raw, ServerMessage::Reply { id, outcome }))) => {
                if id != WANT_ID {
                    // Stale/mismatched reply id (shouldn't happen for a
                    // single in-flight command, but keep waiting for ours).
                    continue;
                }
                return match outcome {
                    ReplyOutcome::Ok { snapshot } => {
                        if json {
                            let _ = writeln!(out, "{raw}");
                        } else {
                            let _ = writeln!(out, "{}", format::pretty_snapshot(&snapshot));
                        }
                        EXIT_OK
                    }
                    ReplyOutcome::Err { error } => {
                        let _ = writeln!(err_out, "{}", format::pretty_error(&error));
                        EXIT_COMMAND_ERR
                    }
                };
            }
            Ok(Some((_, ServerMessage::Event { .. }))) => {
                // Interleaved events are skipped while awaiting a command reply.
            }
            Ok(Some((_, ServerMessage::Hello { .. }))) => {
                // The service sends Hello exactly once per connection, right
                // after it's established; ignore a stray repeat defensively.
            }
            Ok(None) => {
                let _ = writeln!(err_out, "service closed the connection before replying");
                return EXIT_CONNECTION;
            }
            Err(e) => {
                let _ = writeln!(err_out, "failed to read from service: {e}");
                return EXIT_CONNECTION;
            }
        }
    }
}

/// Print each `Event` as it arrives until EOF (or a read error). Used by
/// `ipauro watch`.
pub fn watch_loop(
    reader: &mut BufReader<UnixStream>,
    json: bool,
    out: &mut dyn Write,
    err_out: &mut dyn Write,
) -> i32 {
    loop {
        match read_server_message(reader) {
            Ok(Some((raw, ServerMessage::Event { seq, event }))) => {
                if json {
                    let _ = writeln!(out, "{raw}");
                } else {
                    let _ = writeln!(out, "{}", format::pretty_event_line(seq, &event));
                }
            }
            Ok(Some((_, ServerMessage::Hello { .. }))) => {
                // The service sends Hello exactly once per connection; ignore
                // a stray repeat defensively.
            }
            Ok(Some((_, ServerMessage::Reply { .. }))) => {
                // `watch` never sends a Command, so no Reply is expected;
                // ignore any stray one rather than crashing the client.
            }
            Ok(None) => return EXIT_OK, // clean EOF ends the watch
            Err(e) => {
                let _ = writeln!(err_out, "connection error while watching: {e}");
                return EXIT_CONNECTION;
            }
        }
    }
}
