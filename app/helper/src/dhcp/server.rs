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
use ipauro_proto::helper::BRIDGE_NAME;
use socket2::{Domain, Protocol, Socket, Type};

use super::lease::LeaseTable;
use super::packet::Packet;
use super::responder::{self, DhcpConfig};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
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
}

/// Real raw-socket-backed executor.
pub struct RawSocketDhcpResponder {
    /// Shared with the running thread: true while it should keep serving.
    /// The thread also clears this itself on a fatal (non-timeout) socket
    /// error, so `is_serving()` reflects reality even if nobody has called
    /// `stop()` yet.
    running: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Default for RawSocketDhcpResponder {
    fn default() -> Self {
        Self { running: Arc::new(AtomicBool::new(false)), handle: Mutex::new(None) }
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
        let mut leases = LeaseTable::new(pool_start, pool_end);

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let join = std::thread::Builder::new()
            .name("ipauro-dhcp".into())
            .spawn(move || run_loop(&socket, &running, &config, &mut leases))
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
    socket.bind(&bind_addr.into()).context("binding :67")?;
    socket.set_read_timeout(Some(POLL_INTERVAL)).context("setting DHCP socket recv timeout")?;
    Ok(socket.into())
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
    leases: &mut LeaseTable,
) {
    let mut buf = [0u8; 1500];
    while running.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((n, _from)) => match Packet::decode(&buf[..n]) {
                Ok(pkt) => {
                    if let Some(reply) = responder::handle_packet(config, leases, &pkt) {
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
}
