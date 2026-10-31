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
pub mod stream;

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
    /// Print the service's current snapshot (version, helper, bridge);
    /// `status mesh` prints the mesh members, rate, bootstrap and blockages.
    Status {
        #[command(subcommand)]
        what: Option<StatusAction>,
    },
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
    /// Propose a whole-mesh sample rate (a new epoch gossiped to every node).
    Rate {
        #[command(subcommand)]
        action: RateAction,
    },
    /// Show or elect THIS machine's mesh role (hub bridges; peer does not).
    Role {
        #[command(subcommand)]
        action: RoleAction,
    },
    /// Canonical streams on the binary stream socket (`<socket>.stream`).
    Stream {
        #[command(subcommand)]
        action: StreamAction,
    },
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAction {
    /// List registered streams (descriptor + rate verdict).
    List,
    /// Subscribe to stream ID and print frame/overrun counts when it ends.
    Tap {
        id: u32,
        /// Stop after this many Data frames.
        #[arg(long)]
        frames: Option<u64>,
    },
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAction {
    /// Mesh membership, adopted rate, bootstrap sources and blockages.
    Mesh,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateAction {
    /// Lift (or change) the WHOLE mesh to HZ, e.g. 96000. The service
    /// validates it against the allowed rates; there is no per-node rate.
    Propose { hz: u32 },
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleAction {
    /// Print this node's role and every known member's gossiped role.
    Get,
    /// Elect this machine's role. Other machines' roles cannot be set.
    Set {
        #[arg(value_enum)]
        role: RoleArg,
    },
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleArg {
    Hub,
    Peer,
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

    // The stream facet is a separate socket and protocol; it never opens the
    // JSON control connection.
    if let Cmd::Stream { action } = cli.command {
        return match action {
            StreamAction::List => stream::list(&socket, out, err_out),
            StreamAction::Tap { id, frames } => stream::tap(&socket, id, frames, out, err_out),
        };
    }

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
    // `status` alone prints the whole snapshot; `status mesh` just the mesh.

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
        Cmd::Status { what } => {
            if cli.json {
                let _ = writeln!(out, "{raw_hello}");
            } else {
                match what {
                    None => {
                        let _ = writeln!(out, "{}", format::pretty_snapshot(&snapshot));
                    }
                    Some(StatusAction::Mesh) => {
                        let _ = writeln!(out, "{}", format::pretty_mesh_status(&snapshot.mesh));
                    }
                }
            }
            EXIT_OK
        }
        Cmd::Rate { action: RateAction::Propose { hz } } => client::run_command(
            &mut writer,
            &mut reader,
            Command::ProposeMeshRate { hz },
            cli.json,
            out,
            err_out,
        ),
        // The Hello snapshot's generation is the baseline: it is what an app
        // connecting right now would have bound its sockets at.
        Cmd::Watch => client::watch_loop(&mut reader, cli.json, snapshot.bridge.epoch, out, err_out),
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
        Cmd::Role { action: RoleAction::Get } => {
            if cli.json {
                let _ = writeln!(out, "{raw_hello}");
            } else {
                let _ = writeln!(out, "{}", format::pretty_roles(&snapshot.mesh));
            }
            EXIT_OK
        }
        Cmd::Role { action: RoleAction::Set { role } } => {
            let role = match role {
                RoleArg::Hub => ipauro_proto::state::NodeRole::Hub,
                RoleArg::Peer => ipauro_proto::state::NodeRole::Peer,
            };
            client::run_command(&mut writer, &mut reader, Command::SetRole { role }, cli.json, out, err_out)
        }
        Cmd::Scope { action } => {
            let command = match action {
                ScopeAction::On => Command::SetTransportScope { enabled: true },
                ScopeAction::Off => Command::SetTransportScope { enabled: false },
            };
            client::run_command(&mut writer, &mut reader, command, cli.json, out, err_out)
        }
        // Returned above, before the control connection was opened.
        Cmd::Stream { .. } => unreachable!("stream commands never reach the control socket"),
    }
}
