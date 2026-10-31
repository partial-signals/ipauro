//! The DHCP responder's raw-socket thread: binds `:67` on the bridge
//! interface only (`IP_BOUND_IF` — macOS's analogue of Linux's
//! `SO_BINDTODEVICE`, via `socket2::Socket::bind_device_by_index_v4`),
//! decodes each packet via `packet.rs`, answers via `responder.rs`, and
//! drives `lease.rs`.
//!
//! This is the one part of the DHCP subsystem that can't be unit-tested
//! without root + a real bridge interface to bind — see this lane's final
//! report. The codec/lease/responder logic feeding it is fully covered by
//! `packet.rs`/`lease.rs`/`responder.rs`'s own tests; this module just
//! wires them to a socket.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use ipauro_proto::helper::{BRIDGE_NAME, DhcpLease};
use socket2::{Domain, Protocol, Socket, Type};

use super::lease::LeaseTable;
use super::packet::Packet;
use super::responder::{self, DhcpConfig};
use crate::cmd;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
/// launchd label of macOS's own DHCP server — the daemon Internet Sharing
/// drives, and the one the prototype's `enable-dhcp.sh` enabled. Asked about
/// (never started or stopped) purely to name the holder of `:67`.
const BOOTPD_LABEL: &str = "com.apple.bootpd";
/// The launchd job that socket-activates `*:67` on bootpd's behalf. Named in
/// the diagnosis because unloading THIS is what frees the port.
const BOOTPS_PLIST: &str = "/System/Library/LaunchDaemons/bootps.plist";
/// ~1 hour, per `ipauro-proto`'s intent for the M1 pool (see
/// `defaults::DHCP_POOL_START`/`DHCP_POOL_END` neighbors) — not carried by
/// `HelperRequest::ServeDhcp` itself, so it's this responder's own fixed
/// policy rather than a wire parameter.
const DEFAULT_LEASE_SECS: u32 = 3600;
/// How often the receive loop wakes to check for a stop request — bounds
/// how long `stop()` can take to rejoin the thread.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The two DHCP operations the helper exposes over XPC. Real impl below;
/// tests use a mock (see `request.rs`'s tests).
pub trait DhcpExecutor: Send + Sync {
    fn serve(
        &self,
        pool_start: Ipv4Addr,
        pool_end: Ipv4Addr,
        netmask: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn is_serving(&self) -> bool;
    /// Leases currently held (empty while not serving), for the Report.
    fn leases(&self) -> Vec<DhcpLease>;
}

/// Real raw-socket-backed executor.
pub struct RawSocketDhcpResponder {
    /// Shared with the running thread: true while it should keep serving.
    /// The thread also clears this itself on a fatal (non-timeout) socket
    /// error, so `is_serving()` reflects reality even if nobody has called
    /// `stop()` yet.
    running: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
    /// The serving thread's lease table, shared so `leases()` can read it.
    leases: Arc<Mutex<Option<LeaseTable>>>,
}

impl Default for RawSocketDhcpResponder {
    fn default() -> Self {
        Self { running: Arc::new(AtomicBool::new(false)), handle: Mutex::new(None), leases: Arc::default() }
    }
}

impl RawSocketDhcpResponder {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DhcpExecutor for RawSocketDhcpResponder {
    fn serve(
        &self,
        pool_start: Ipv4Addr,
        pool_end: Ipv4Addr,
        netmask: Ipv4Addr,
        server_ip: Ipv4Addr,
    ) -> Result<()> {
        // Idempotent: replace any prior instance cleanly rather than
        // leaking a thread/socket if ServeDhcp is called again (e.g. a
        // pool/config change).
        self.stop()?;

        let socket = bind_bridge_socket()?;
        let config = DhcpConfig { server_ip, netmask, lease_secs: DEFAULT_LEASE_SECS };
        *self.leases.lock().expect("dhcp leases mutex poisoned") = Some(LeaseTable::new(pool_start, pool_end));
        let leases = Arc::clone(&self.leases);

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let join = std::thread::Builder::new()
            .name("ipauro-dhcp".into())
            .spawn(move || run_loop(&socket, &running, &config, &leases))
            .context("spawning DHCP responder thread")?;
        *self.handle.lock().expect("dhcp handle mutex poisoned") = Some(join);
        log::info!("DHCP responder serving {pool_start}-{pool_end} on {BRIDGE_NAME}");
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.lock().expect("dhcp handle mutex poisoned").take() {
            handle.join().map_err(|_| anyhow::anyhow!("DHCP responder thread panicked"))?;
            log::info!("DHCP responder stopped");
        }
        Ok(())
    }

    fn is_serving(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn leases(&self) -> Vec<DhcpLease> {
        if !self.is_serving() {
            return Vec::new();
        }
        self.leases.lock().expect("dhcp leases mutex poisoned").as_ref().map(LeaseTable::snapshot).unwrap_or_default()
    }
}

/// Resolve the bridge's interface index (`if_nametoindex`) and bind a UDP
/// socket to `:67`, restricted to receiving/sending on that interface only
/// (`IP_BOUND_IF`) — so this responder never answers DHCP traffic arriving
/// on Wi-Fi/Ethernet, and its broadcast replies egress the bridge, not
/// whatever the OS's default route happens to be.
fn bind_bridge_socket() -> Result<UdpSocket> {
    let ifindex = bridge_interface_index()?;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating DHCP socket")?;
    socket.set_reuse_address(true).context("SO_REUSEADDR")?;
    socket.set_broadcast(true).context("SO_BROADCAST")?;
    socket
        .bind_device_by_index_v4(Some(ifindex))
        .with_context(|| format!("IP_BOUND_IF (binding the DHCP socket to {BRIDGE_NAME})"))?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_SERVER_PORT);
    if let Err(e) = socket.bind(&bind_addr.into()) {
        // Only ask launchd who holds the port when the port is actually the
        // problem — the probe is a process spawn.
        let bootpd_loaded =
            e.kind() == std::io::ErrorKind::AddrInUse && cmd::job_is_loaded(BOOTPD_LABEL);
        anyhow::bail!("{}", describe_bind_failure(&e, bootpd_loaded));
    }
    socket.set_read_timeout(Some(POLL_INTERVAL)).context("setting DHCP socket recv timeout")?;
    Ok(socket.into())
}

/// Turn a failed `bind(:67)` into a sentence an operator can act on, rather
/// than the bare `binding :67: Address already in use` that M1 field
/// verification hit (R005-T10 finding 2).
///
/// The blockage this exists for: **launchd socket-activates `*:67` for
/// `bootps` whenever that job is loaded**, so the port is held even though no
/// `bootpd` process is running and `lsof` shows nothing — and the prototype's
/// `enable-dhcp.sh` left it loaded with `-w` (persistently). `SO_REUSEADDR`
/// does not get us past it. Naming the holder and the exact reversal is the
/// whole point; a generic "address in use" sends the operator hunting.
///
/// `bootpd_loaded` is launchd's answer for [`BOOTPD_LABEL`] ([`cmd::job_is_loaded`]),
/// which upgrades the wording from a suspicion to a statement. Pure so the
/// wording is testable without root, a bridge, or a real bind.
fn describe_bind_failure(e: &std::io::Error, bootpd_loaded: bool) -> String {
    match e.kind() {
        std::io::ErrorKind::AddrInUse if bootpd_loaded => format!(
            "another DHCP server holds UDP port {DHCP_SERVER_PORT}: launchd reports \
             {BOOTPD_LABEL} loaded (Internet Sharing, or an `enable-dhcp.sh`-style \
             `launchctl load -w {BOOTPS_PLIST}` left behind). launchd socket-activates \
             *:{DHCP_SERVER_PORT} while that job is loaded, so IPAuRo's in-process responder \
             cannot bind. Free the port with `sudo launchctl unload -w {BOOTPS_PLIST}`."
        ),
        std::io::ErrorKind::AddrInUse => format!(
            "another DHCP server holds UDP port {DHCP_SERVER_PORT} (bootpd / Internet Sharing?). \
             launchd reports {BOOTPD_LABEL} NOT loaded, so look for a third-party DHCP server \
             instead; `sudo lsof -nP -iUDP:{DHCP_SERVER_PORT}` names the process, and \
             `sudo launchctl print system/{BOOTPD_LABEL}` re-checks Apple's."
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "binding UDP port {DHCP_SERVER_PORT} was denied — a privileged port needs root; \
             the helper must be running as the launchd SYSTEM-domain daemon, not as a user agent."
        ),
        _ => format!("binding UDP port {DHCP_SERVER_PORT} on {BRIDGE_NAME} failed: {e}"),
    }
}

fn bridge_interface_index() -> Result<NonZeroU32> {
    let name = std::ffi::CString::new(BRIDGE_NAME).expect("BRIDGE_NAME has no interior NUL");
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    NonZeroU32::new(index).ok_or_else(|| {
        anyhow::anyhow!("if_nametoindex({BRIDGE_NAME}) returned 0 — does the bridge exist?")
    })
}

fn run_loop(
    socket: &UdpSocket,
    running: &AtomicBool,
    config: &DhcpConfig,
    leases: &Mutex<Option<LeaseTable>>,
) {
    let mut buf = [0u8; 1500];
    while running.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((n, _from)) => match Packet::decode(&buf[..n]) {
                Ok(pkt) => {
                    let reply = match leases.lock().expect("dhcp leases mutex poisoned").as_mut() {
                        Some(table) => responder::handle_packet(config, table, &pkt),
                        None => None, // stopped between recv and here
                    };
                    if let Some(reply) = reply {
                        send_reply(socket, &reply);
                    }
                }
                Err(e) => log::warn!("dropping malformed DHCP packet: {e}"),
            },
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                // Expected: the read timeout firing so we re-check `running`.
                continue;
            }
            Err(e) => {
                // A persistent, non-timeout socket error (e.g. the bridge
                // interface vanished — R002-T3's replug-blast-radius
                // scenario) isn't recoverable by retrying in a tight loop;
                // stop cleanly so `is_serving()` reflects reality instead of
                // spinning on a dead socket.
                log::error!("DHCP socket error, stopping responder: {e}");
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
}

fn send_reply(socket: &UdpSocket, reply: &Packet) {
    let bytes = reply.encode();
    let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT);
    if let Err(e) = socket.send_to(&bytes, dest) {
        log::warn!("DHCP send_to failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_responder_is_not_serving() {
        let responder = RawSocketDhcpResponder::new();
        assert!(!responder.is_serving());
    }

    #[test]
    fn stop_on_a_never_started_responder_is_a_harmless_no_op() {
        let responder = RawSocketDhcpResponder::new();
        assert!(responder.stop().is_ok());
        assert!(!responder.is_serving());
    }

    // ---- bind diagnosis (R005-T10 finding 2) ---------------------------------

    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "canned")
    }

    #[test]
    fn port_in_use_with_bootpd_loaded_names_the_holder_and_the_fix() {
        let msg = describe_bind_failure(&io(std::io::ErrorKind::AddrInUse), true);
        assert!(msg.contains(BOOTPD_LABEL), "{msg}");
        assert!(msg.contains("unload -w"), "the exact reversal must be spelled out: {msg}");
        assert!(msg.contains(BOOTPS_PLIST), "{msg}");
    }

    #[test]
    fn port_in_use_without_bootpd_points_elsewhere_instead_of_blaming_apple() {
        let msg = describe_bind_failure(&io(std::io::ErrorKind::AddrInUse), false);
        assert!(msg.contains("NOT loaded"), "{msg}");
        assert!(msg.contains("lsof"), "operator needs a way to name the real holder: {msg}");
        assert!(!msg.contains("unload -w"), "must not prescribe a fix for a job that isn't loaded: {msg}");
    }

    #[test]
    fn permission_denied_says_root_not_address_in_use() {
        let msg = describe_bind_failure(&io(std::io::ErrorKind::PermissionDenied), false);
        assert!(msg.contains("root"), "{msg}");
        assert!(!msg.contains("DHCP server holds"), "{msg}");
    }

    #[test]
    fn any_other_bind_error_still_surfaces_the_underlying_io_error() {
        let msg = describe_bind_failure(&io(std::io::ErrorKind::AddrNotAvailable), false);
        assert!(msg.contains("canned"), "the io::Error must not be swallowed: {msg}");
        assert!(msg.contains(BRIDGE_NAME), "{msg}");
    }

    /// Every diagnosis must name the port — the operator's search term.
    #[test]
    fn every_diagnosis_names_the_port() {
        for (kind, loaded) in [
            (std::io::ErrorKind::AddrInUse, true),
            (std::io::ErrorKind::AddrInUse, false),
            (std::io::ErrorKind::PermissionDenied, false),
            (std::io::ErrorKind::Other, false),
        ] {
            let msg = describe_bind_failure(&io(kind), loaded);
            assert!(msg.contains("67"), "{kind:?}: {msg}");
        }
    }
}
