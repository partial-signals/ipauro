//! `ipauro-probe listen` — join the multicast group and print one line per
//! datagram received: timestamp, source addr, payload summary. Never attempts
//! to parse unrecognized (foreign / real-Link) payloads — only labels them.

use anyhow::{Context, Result};

use crate::cli::ListenArgs;
use crate::payload::Beacon;
use crate::timestamp::now_ts;
use crate::{iface, net};

pub fn run(args: ListenArgs) -> Result<()> {
    let iface_addr = iface::resolve_optional(args.net.iface.as_deref())?;
    let socket = net::listen_socket(args.net.port, args.net.group, iface_addr)
        .context("setting up listen socket")?;

    eprintln!(
        "ipauro-probe listen: joined {}:{} on {}",
        args.net.group,
        args.net.port,
        args.net.iface.as_deref().unwrap_or("<system default>")
    );

    let mut buf = [0u8; 2048];
    loop {
        let (n, src) = socket.recv_from(&mut buf).context("receiving datagram")?;
        println!("{} {} {}", now_ts(), src, describe(&buf[..n]));
    }
}

/// One-line label for a received datagram: recognized probe beacon vs
/// unrecognized traffic. Real Ableton Link packets on this port will appear
/// here as foreign — they are deliberately never parsed as Link, only flagged.
fn describe(bytes: &[u8]) -> String {
    match Beacon::parse(bytes) {
        Some(b) => format!("probe beacon: {b}"),
        None => format!("foreign (Link?) {} bytes", bytes.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_probe_beacon_by_content() {
        let wire = "IPAURO-PROBE v0 host=x pid=1 seq=2";
        assert!(describe(wire.as_bytes()).starts_with("probe beacon:"));
    }

    #[test]
    fn describes_unrecognized_payload_as_foreign() {
        let binary = [0xff, 0x00, 0x10];
        assert_eq!(describe(&binary), "foreign (Link?) 3 bytes");
    }
}
