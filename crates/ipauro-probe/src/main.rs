//! ipauro-probe — R002-T8 diagnostic: does this execution context hold macOS
//! 15+'s Local Network privacy grant for multicast (Ableton Link's own group
//! and port)?
//!
//! Empirical method (A002): join the group, send known-shaped beacons, and
//! check whether our OWN socket receives them back via multicast loopback. If
//! `tcpdump` sees the datagram on the wire but this process's socket never
//! does, that is the gate's silent-deny signature. See RUNBOOK.md for the
//! execution-context matrix this tool exists to fill in.

mod cli;
mod commands;
mod iface;
mod net;
mod payload;
mod timestamp;
mod verdict;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    let result = match cli.command {
        cli::Command::Listen(args) => commands::listen::run(args).map(|()| ExitCode::SUCCESS),
        cli::Command::Beacon(args) => commands::beacon::run(args).map(|()| ExitCode::SUCCESS),
        cli::Command::Check(args) => commands::check::run(args),
    };

    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ipauro-probe: error: {err:#}");
            ExitCode::from(1)
        }
    }
}
