//! `ipauro-probe beacon` — send periodic datagrams to the multicast group with
//! an obviously-non-Link payload, so both humans (`tcpdump`) and this tool's
//! own `listen`/`check` can identify our traffic unambiguously.

use std::net::{SocketAddr, SocketAddrV4};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use gethostname::gethostname;

use crate::cli::BeaconArgs;
use crate::iface;
use crate::net;
use crate::payload::Beacon;
use crate::timestamp::now_ts;

pub fn run(args: BeaconArgs) -> Result<()> {
    let iface_addr = iface::resolve_optional(args.net.iface.as_deref())?;
    let socket = net::beacon_socket(iface_addr).context("setting up beacon socket")?;
    let target = SocketAddr::V4(SocketAddrV4::new(args.net.group, args.net.port));
    let host = gethostname().to_string_lossy().into_owned();
    let pid = std::process::id();
    let interval = Duration::from_millis(args.interval_ms.max(1));

    eprintln!(
        "ipauro-probe beacon: sending to {target} every {}ms (host={host} pid={pid})",
        args.interval_ms
    );

    let mut seq = 0u64;
    loop {
        let beacon = Beacon::new(&host, pid, seq);
        let wire = beacon.to_string();
        socket
            .send_to(wire.as_bytes(), target)
            .with_context(|| format!("sending beacon seq={seq}"))?;
        println!("{} sent seq={seq} -> {target}", now_ts());
        seq += 1;
        thread::sleep(interval);
    }
}
