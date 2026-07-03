//! `ipauro-probe check` — beacon and listen simultaneously for a fixed window,
//! then report sent/received-own/received-foreign counts and a verdict. This
//! is the R002-T8 empirical method in one shot: if our OWN beacon (sent via
//! multicast loopback, no network hop required) never comes back, that is the
//! Local Network privacy gate's silent-deny signature — packets can still be
//! visible on the wire (cross-check with `tcpdump`) while never reaching this
//! process's socket.

use std::net::{SocketAddr, SocketAddrV4};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use gethostname::gethostname;

use crate::cli::CheckArgs;
use crate::payload::Beacon;
use crate::verdict;
use crate::{iface, net};

/// How often the receive loop wakes to re-check the overall deadline.
const RECV_POLL_INTERVAL: Duration = Duration::from_millis(200);

pub fn run(args: CheckArgs) -> Result<ExitCode> {
    let iface_addr = iface::resolve_optional(args.net.iface.as_deref())?;
    let host = gethostname().to_string_lossy().into_owned();
    let pid = std::process::id();

    let listen_socket = net::listen_socket(args.net.port, args.net.group, iface_addr)
        .context("setting up listen socket")?;
    listen_socket
        .set_read_timeout(Some(RECV_POLL_INTERVAL))
        .context("setting listen socket read timeout")?;
    let beacon_socket = net::beacon_socket(iface_addr).context("setting up beacon socket")?;

    eprintln!(
        "ipauro-probe check: {}s on {}:{} via {}",
        args.seconds,
        args.net.group,
        args.net.port,
        args.net.iface.as_deref().unwrap_or("<system default>")
    );

    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));

    let sender = {
        let stop = Arc::clone(&stop);
        let sent = Arc::clone(&sent);
        let host = host.clone();
        let target = SocketAddr::V4(SocketAddrV4::new(args.net.group, args.net.port));
        let interval = Duration::from_millis(args.interval_ms.max(1));
        thread::spawn(move || {
            let mut seq = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let beacon = Beacon::new(&host, pid, seq);
                if beacon_socket.send_to(beacon.to_string().as_bytes(), target).is_ok() {
                    sent.fetch_add(1, Ordering::Relaxed);
                }
                seq += 1;
                thread::sleep(interval);
            }
        })
    };

    let mut received_own = 0u64;
    let mut received_foreign = 0u64;
    let deadline = Instant::now() + Duration::from_secs(args.seconds.max(1));
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match listen_socket.recv_from(&mut buf) {
            Ok((n, _src)) => match Beacon::parse(&buf[..n]) {
                Some(b) if b.is_own(&host, pid) => received_own += 1,
                _ => received_foreign += 1,
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                stop.store(true, Ordering::Relaxed);
                let _ = sender.join();
                return Err(e).context("receiving on listen socket");
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    sender.join().expect("beacon sender thread panicked");

    let sent = sent.load(Ordering::Relaxed);
    print_report(sent, received_own, received_foreign);

    Ok(ExitCode::from(verdict::compute(sent, received_own, received_foreign).exit_code()))
}

fn print_report(sent: u64, received_own: u64, received_foreign: u64) {
    println!("--- ipauro-probe check ---");
    println!("sent:              {sent}");
    println!("received-own:      {received_own}");
    println!("received-foreign:  {received_foreign}");
    println!("verdict: {}", verdict::describe(sent, received_own, received_foreign));
}
