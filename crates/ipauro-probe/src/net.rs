//! Socket construction for the multicast group under test — the exact group
//! and port Ableton Link itself uses (224.76.78.75:20808 by default), so the
//! probe's empirical result generalizes to Link's real behavior in the same
//! execution context.
//!
//! Not unit-tested here: these functions bind real sockets and join real
//! multicast groups, which is exactly the OS/sandbox-dependent behavior this
//! tool exists to probe. See RUNBOOK.md for the manual verification matrix.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

/// Build a UDP socket bound to `port` on all interfaces and joined to `group`
/// on `iface` (or the system default interface if `None`).
///
/// Sets `SO_REUSEADDR` + `SO_REUSEPORT` so `listen`/`check` can run alongside
/// a real Link instance (which binds `*:20808` on every interface — A002) or
/// alongside each other, without "address already in use".
pub fn listen_socket(port: u16, group: Ipv4Addr, iface: Option<Ipv4Addr>) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating listen socket")?;
    socket.set_reuse_address(true).context("SO_REUSEADDR")?;
    // SO_REUSEPORT has no Windows equivalent in socket2; this tool targets
    // macOS (the whole point is macOS 15's Local Network gate), so the cfg
    // guard is defensive portability, not a supported-platform claim.
    #[cfg(unix)]
    socket.set_reuse_port(true).context("SO_REUSEPORT")?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket.bind(&bind_addr.into()).context("binding listen socket")?;

    let membership_iface = iface.unwrap_or(Ipv4Addr::UNSPECIFIED);
    socket
        .join_multicast_v4(&group, &membership_iface)
        .with_context(|| format!("joining multicast group {group} on {membership_iface}"))?;

    Ok(socket.into())
}

/// Build a UDP socket for sending beacons: bound to an ephemeral port, with
/// `IP_MULTICAST_IF` set to `iface` when given, and multicast loopback
/// enabled so a beacon we send can be received by our own `listen_socket` —
/// the loopback path `check` uses to prove app-layer reception works at all.
pub fn beacon_socket(iface: Option<Ipv4Addr>) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating beacon socket")?;
    socket.set_reuse_address(true).context("SO_REUSEADDR")?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    socket.bind(&bind_addr.into()).context("binding beacon socket")?;

    if let Some(addr) = iface {
        socket
            .set_multicast_if_v4(&addr)
            .with_context(|| format!("setting IP_MULTICAST_IF to {addr}"))?;
    }
    socket.set_multicast_loop_v4(true).context("enabling multicast loopback")?;

    Ok(socket.into())
}
