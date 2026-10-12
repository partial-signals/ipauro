//! `ipauro-probe check` — beacon, listen, and tap the wire simultaneously for a
//! fixed window, then report the counts and a verdict. This is the R002-T8
//! empirical method in one shot.
//!
//! Two independent observations run against the same beacons:
//!
//! * the **socket** leg — did our own multicast datagrams come back to a
//!   socket in this process?
//! * the **wire** leg — did those same datagrams reach the interface at all,
//!   seen through `/dev/bpf` which sits *below* the Local Network privacy gate?
//!
//! Together they pin down which side of the socket layer a denial happens on,
//! and catch the case where in-kernel multicast loopback succeeds while nothing
//! actually leaves the machine. See `verdict` for the classification and
//! RUNBOOK.md for the execution-context matrix this fills in.

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
use crate::wire::{WireObservation, WireTap};
use crate::{iface, net, verdict};

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

    print_context(&args, &host, pid);

    // Start the wire tap before the first beacon so no send races ahead of it.
    let tap = start_tap(&args, &host, pid);

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
                let _ = tap.map(WireTap::stop);
                return Err(e).context("receiving on listen socket");
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    sender.join().expect("beacon sender thread panicked");
    let wire = match tap {
        Some(tap) => scope_to_egress(&args, tap.stop()),
        None => WireObservation::unavailable(tap_skip_reason(&args)),
    };

    let sent = sent.load(Ordering::Relaxed);
    print_report(sent, received_own, received_foreign, &wire);

    Ok(ExitCode::from(verdict::compute(sent, received_own, received_foreign, &wire).exit_code()))
}

/// The wire tap matches on the beacon's *identity* substring rather than the
/// protocol magic, so a probe running concurrently on another machine (or in
/// another context on this one) is never counted as ours.
fn wire_marker(host: &str, pid: u32) -> String {
    let beacon = Beacon::new(host, pid, 0);
    format!("host={} pid={}", beacon.host, beacon.pid)
}

/// Which interface the tap watches: `--tap-iface` when given, else the
/// multicast egress interface.
fn tap_iface(args: &CheckArgs) -> Option<&str> {
    args.tap_iface.as_deref().or(args.net.iface.as_deref())
}

/// A tap pointed somewhere other than the multicast egress interface cannot
/// answer "did our beacon leave the machine" — an off-path tap legitimately
/// sees zero. Downgrade such an observation to unavailable (carrying the count
/// it did see) so the verdict never reads a deliberate `--tap-iface lo0` as
/// suppressed egress.
fn scope_to_egress(args: &CheckArgs, observed: WireObservation) -> WireObservation {
    let tap = tap_iface(args);
    if tap.is_some() && tap == args.net.iface.as_deref() {
        return observed;
    }
    let where_ = tap.unwrap_or("<none>");
    let egress = args.net.iface.as_deref().unwrap_or("<system default>");
    match observed {
        WireObservation::Seen { count } => WireObservation::unavailable(format!(
            "tap watched {where_}, not the egress interface {egress} — \
             {count} own beacon(s) seen there, which says nothing about egress"
        )),
        unavailable => unavailable,
    }
}

/// Why no tap is running, when there isn't one — reported verbatim in the
/// verdict so a log-only launchd row still explains itself.
fn tap_skip_reason(args: &CheckArgs) -> String {
    if args.no_wire {
        "--no-wire".to_string()
    } else {
        "no --iface or --tap-iface given; the tap must be told which interface to watch".to_string()
    }
}

fn start_tap(args: &CheckArgs, host: &str, pid: u32) -> Option<WireTap> {
    if args.no_wire {
        return None;
    }
    let iface = tap_iface(args)?;
    match WireTap::start(iface, &wire_marker(host, pid)) {
        Ok(tap) => Some(tap),
        Err(err) => {
            // Not fatal: fall back to the socket-only verdict, which `verdict`
            // marks as unconfirmed rather than overclaiming.
            eprintln!("ipauro-probe: wire tap unavailable ({err:#}); socket-only verdict follows");
            None
        }
    }
}

/// Identify the execution context in the output itself. A launchd row leaves
/// nothing behind but a log file and an exit code, so the log has to say which
/// row it is.
fn print_context(args: &CheckArgs, host: &str, pid: u32) {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    // SAFETY: getuid/geteuid take no arguments and cannot fail.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };

    println!("--- context ---");
    println!("exe:      {exe}");
    println!("host:     {host}  pid: {pid}");
    println!("uid:      {uid}  euid: {euid}");
    println!(
        "launchd:  {}",
        std::env::var("XPC_SERVICE_NAME").unwrap_or_else(|_| "<none>".to_string())
    );
    println!(
        "ssh:      {}",
        if std::env::var_os("SSH_CONNECTION").is_some() { "yes" } else { "no" }
    );
    println!(
        "target:   {}:{} via {}",
        args.net.group,
        args.net.port,
        args.net.iface.as_deref().unwrap_or("<system default>")
    );
    println!("tap:      {}", tap_iface(args).unwrap_or("<none>"));
    println!("window:   {}s", args.seconds);
}

fn print_report(sent: u64, received_own: u64, received_foreign: u64, wire: &WireObservation) {
    println!("--- ipauro-probe check ---");
    println!("sent:              {sent}");
    println!("received-own:      {received_own}");
    println!("received-foreign:  {received_foreign}");
    println!("wire:              {wire}");
    let verdict = verdict::compute(sent, received_own, received_foreign, wire);
    println!(
        "verdict: {verdict} — {}",
        verdict::describe(sent, received_own, received_foreign, wire)
    );
    // The one bit the R002-T8 placement decision turns on, stated plainly so a
    // matrix row can be read off a log without interpreting the prose above.
    println!(
        "placement: this context {} carry the product's multicast traffic",
        if verdict.is_denied() { "CANNOT" } else { "can" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{DEFAULT_GROUP, DEFAULT_PORT, GroupArgs};

    fn args(iface: Option<&str>, no_wire: bool) -> CheckArgs {
        args_with_tap(iface, None, no_wire)
    }

    fn args_with_tap(iface: Option<&str>, tap: Option<&str>, no_wire: bool) -> CheckArgs {
        CheckArgs {
            net: GroupArgs {
                iface: iface.map(str::to_string),
                port: DEFAULT_PORT,
                group: DEFAULT_GROUP.parse().unwrap(),
            },
            seconds: 1,
            interval_ms: 100,
            tap_iface: tap.map(str::to_string),
            no_wire,
        }
    }

    #[test]
    fn tap_defaults_to_the_egress_interface() {
        assert_eq!(tap_iface(&args(Some("en0"), false)), Some("en0"));
        assert_eq!(tap_iface(&args(None, false)), None);
    }

    #[test]
    fn tap_iface_overrides_the_egress_interface() {
        // The discriminator between real egress and an in-kernel loopback
        // copy: beacon out en0, watch lo0.
        assert_eq!(tap_iface(&args_with_tap(Some("en0"), Some("lo0"), false)), Some("lo0"));
    }

    #[test]
    fn tap_iface_alone_is_enough_to_arm_the_tap() {
        assert_eq!(tap_iface(&args_with_tap(None, Some("lo0"), false)), Some("lo0"));
    }

    #[test]
    fn marker_carries_host_and_pid_and_appears_in_the_beacon() {
        let marker = wire_marker("relay-mbp", 4242);
        assert_eq!(marker, "host=relay-mbp pid=4242");
        assert!(Beacon::new("relay-mbp", 4242, 9).to_string().contains(&marker));
    }

    #[test]
    fn marker_uses_the_sanitized_hostname_the_beacon_actually_sends() {
        // Beacon::new collapses whitespace; the marker must match what goes on
        // the wire, not the raw hostname.
        let marker = wire_marker("weird host", 7);
        assert_eq!(marker, "host=weird_host pid=7");
        assert!(Beacon::new("weird host", 7, 0).to_string().contains(&marker));
    }

    #[test]
    fn marker_does_not_match_another_pid_on_the_same_host() {
        let ours = wire_marker("relay-mbp", 4242);
        let theirs = Beacon::new("relay-mbp", 9999, 3).to_string();
        assert!(!theirs.contains(&ours));
    }

    #[test]
    fn on_path_tap_observations_pass_through_unchanged() {
        let seen = WireObservation::Seen { count: 9 };
        assert_eq!(scope_to_egress(&args(Some("en0"), false), seen.clone()), seen);
    }

    #[test]
    fn off_path_tap_cannot_speak_to_egress() {
        // The awdl0/lo0 negative-control case: seeing zero on an interface the
        // traffic never traverses must not read as suppressed egress.
        let scoped = scope_to_egress(
            &args_with_tap(Some("en0"), Some("lo0"), false),
            WireObservation::Seen { count: 0 },
        );
        match scoped {
            WireObservation::Unavailable { reason } => {
                assert!(reason.contains("not the egress interface en0"));
            }
            other => panic!("expected an off-path downgrade, got {other:?}"),
        }
    }

    #[test]
    fn off_path_tap_keeps_its_count_in_the_reason() {
        let scoped = scope_to_egress(
            &args_with_tap(Some("en0"), Some("lo0"), false),
            WireObservation::Seen { count: 9 },
        );
        assert!(scoped.to_string().contains("9 own beacon(s) seen there"));
    }

    #[test]
    fn a_tap_with_no_named_egress_interface_is_also_off_path() {
        // Without --iface we don't know which interface the OS chose, so the
        // tap can't be asserted to be on the egress path.
        let scoped = scope_to_egress(
            &args_with_tap(None, Some("en0"), false),
            WireObservation::Seen { count: 4 },
        );
        assert!(matches!(scoped, WireObservation::Unavailable { .. }));
    }

    #[test]
    fn skip_reason_distinguishes_no_wire_from_no_iface() {
        assert_eq!(tap_skip_reason(&args(Some("en0"), true)), "--no-wire");
        assert!(tap_skip_reason(&args(None, false)).contains("no --iface"));
    }

    #[test]
    fn no_tap_without_an_interface_even_when_wire_is_wanted() {
        assert!(start_tap(&args(None, false), "h", 1).is_none());
        assert!(start_tap(&args(Some("en0"), true), "h", 1).is_none());
    }
}
