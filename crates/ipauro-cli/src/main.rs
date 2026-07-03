//! ipauro — reference CLI client for the IPAuRo brain-service IPC protocol.
//! See `ipauro_cli::run` for the actual client logic; this binary is a thin
//! `clap` shell around it.

use clap::Parser;
use ipauro_cli::Cli;

fn main() {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let code = ipauro_cli::run(cli, &mut stdout, &mut stderr);
    std::process::exit(code);
}
