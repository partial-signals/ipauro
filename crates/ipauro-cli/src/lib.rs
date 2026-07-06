//! ipauro — reference CLI client for IPAuRo's client<->brain-service IPC
//! protocol (`ipauro_proto::ipc`). Doubles as the M0 test harness (R002-T7):
//! anything the protocol can do, this CLI can drive from a terminal.
//!
//! The binary (`src/main.rs`) is a thin `clap` shell; all logic lives here so
//! integration tests can call [`run`] directly against an in-test fake server
//! instead of spawning a subprocess.

use std::io::{BufReader, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use ipauro_proto::ipc::{default_socket_path, Command, ServerMessage};
use ipauro_proto::PROTOCOL_VERSION;

pub mod client;
pub mod format;

/// Command succeeded.
pub const EXIT_OK: i32 = 0;
/// The service replied `ReplyOutcome::Err` to a command.
pub const EXIT_COMMAND_ERR: i32 = 1;
/// Couldn't establish or maintain a working connection to the service.
pub const EXIT_CONNECTION: i32 = 2;
/// The service speaks a different `PROTOCOL_VERSION` than this client.
pub const EXIT_VERSION_MISMATCH: i32 = 3;

#[derive(Parser, Debug, Clone)]
#[command(name = "ipauro", version, about = "IPAuRo reference IPC client")]
pub struct Cli {
    /// Path to the brain-service's unix socket.
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// Emit raw NDJSON protocol messages instead of pretty output.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Cmd {
    /// Print the service's current snapshot (version, helper, bridge).
    Status,
    /// Stream events as they happen until EOF/ctrl-C.
    Watch,
    /// Bring the USB-Ethernet bridge up or down.
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
    /// Register or unregister the privileged helper daemon.
    Helper {
        #[command(subcommand)]
        action: HelperAction,
    },
    /// Pin Link's ports to the bridge via pf (M1 transport scoping).
    Scope {
        #[command(subcommand)]
        action: ScopeAction,
    },
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeAction {
    Up,
    Down,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperAction {
    Register,
    Unregister,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeAction {
    On,
    Off,
}

/// Run the CLI's client logic end to end: connect, Hello handshake, dispatch
/// on `cli.command`, write human or `--json` output to `out`/`err_out`.
/// Returns the process exit code (see the `EXIT_*` constants).
pub fn run(cli: Cli, out: &mut dyn Write, err_out: &mut dyn Write) -> i32 {
    let socket = cli.socket.unwrap_or_else(default_socket_path);

    let stream = match client::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(err_out, "{e}");
            return EXIT_CONNECTION;
        }
    };

    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(err_out, "failed to prepare connection: {e}");
            return EXIT_CONNECTION;
        }
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;

    let client_name = format!("ipauro-cli {}", env!("CARGO_PKG_VERSION"));
    let subscribe_events = matches!(cli.command, Cmd::Watch);

    if let Err(e) = client::send_hello(&mut writer, &client_name, subscribe_events) {
        let _ = writeln!(err_out, "failed to send hello: {e}");
        return EXIT_CONNECTION;
    }

    let (raw_hello, hello_msg) = match client::read_server_message(&mut reader) {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            let _ = writeln!(err_out, "service closed the connection before completing handshake");
            return EXIT_CONNECTION;
        }
        Err(e) => {
            let _ = writeln!(err_out, "failed to read from service: {e}");
            return EXIT_CONNECTION;
        }
    };

    let (protocol_version, server_version, snapshot) = match hello_msg {
        ServerMessage::Hello { protocol_version, server_version, snapshot } => {
            (protocol_version, server_version, snapshot)
        }
        // The protocol's lifecycle contract guarantees Hello is the first
        // message on a connection; anything else here means the peer isn't
        // speaking ipauro-proto's IPC dialect.
        ServerMessage::Event { .. } | ServerMessage::Reply { .. } => {
            let _ = writeln!(err_out, "protocol error: expected Hello as the first message from the service");
            return EXIT_CONNECTION;
        }
    };

    if protocol_version != PROTOCOL_VERSION {
        let _ = writeln!(
            err_out,
            "protocol version mismatch: ipauro-cli speaks v{PROTOCOL_VERSION}, service speaks v{protocol_version} ({server_version}); upgrade one side"
        );
        return EXIT_VERSION_MISMATCH;
    }

    match cli.command {
        Cmd::Status => {
            if cli.json {
                let _ = writeln!(out, "{raw_hello}");
            } else {
                let _ = writeln!(out, "{}", format::pretty_snapshot(&snapshot));
            }
            EXIT_OK
        }
        Cmd::Watch => client::watch_loop(&mut reader, cli.json, out, err_out),
        Cmd::Bridge { action } => {
            let command = match action {
                BridgeAction::Up => Command::BridgeUp,
                BridgeAction::Down => Command::BridgeDown,
            };
            client::run_command(&mut writer, &mut reader, command, cli.json, out, err_out)
        }
        Cmd::Helper { action } => {
            let command = match action {
                HelperAction::Register => Command::RegisterHelper,
                HelperAction::Unregister => Command::UnregisterHelper,
            };
            client::run_command(&mut writer, &mut reader, command, cli.json, out, err_out)
        }
        Cmd::Scope { action } => {
            let command = match action {
                ScopeAction::On => Command::SetTransportScope { enabled: true },
                ScopeAction::Off => Command::SetTransportScope { enabled: false },
            };
            client::run_command(&mut writer, &mut reader, command, cli.json, out, err_out)
        }
    }
}
