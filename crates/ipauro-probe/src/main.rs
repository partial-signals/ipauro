//! ipauro-probe — R002-T8 diagnostic: does this execution context hold macOS
//! 15+'s Local Network privacy grant for multicast (Ableton Link's own group
//! and port)?
//!
//! Empirical method (A002): join the group, send known-shaped beacons, and
//! watch two independent observation points at once — this process's own
//! socket, and `/dev/bpf` on the interface, which sits *below* the gate. A
//! datagram visible on the wire but absent from the socket is the gate's
//! silent-deny signature; a datagram absent from both, after `sendto` reported
//! success, is a denial on the send path instead. See RUNBOOK.md for the
//! execution-context matrix this tool exists to fill in.

mod cli;
mod commands;
mod grants;
mod iface;
mod net;
mod payload;
mod timestamp;
mod verdict;
mod wire;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    let result = match cli.command {
        cli::Command::Listen(args) => commands::listen::run(args).map(|()| ExitCode::SUCCESS),
        cli::Command::Beacon(args) => commands::beacon::run(args).map(|()| ExitCode::SUCCESS),
        cli::Command::Check(args) => commands::check::run(args),
        cli::Command::Grants(args) => commands::grants::run(args),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ipauro-probe: error: {err:#}");
            ExitCode::from(1)
        }
    }
}
