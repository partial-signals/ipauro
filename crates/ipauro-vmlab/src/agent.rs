//! The in-guest half: a Link-shaped endpoint that runs INSIDE the macOS VM.
//!
//! It does what Ableton Link does on the wire, and nothing more: one socket
//! per interface bound to that interface's address on `:20808`, multicast to
//! `224.76.78.75` out of each interface, unicast to known peers, and a
//! listener joined to the group on every interface. That is the shape pf
//! scoping has to bite on (A002: "Live binds *:20808 on ALL interfaces"), so
//! a scope that holds against this agent holds against the app.
//!
//! Every run is bounded by `--seconds` and exits on its own. That is the
//! teardown half of teardown-and-re-establish: a "session" is one agent
//! process, and a new session is a new process with fresh sockets and
//! therefore fresh pf state. Killing the `limactl shell` client instead would
//! leave the remote process running with its old state — the exact
//! "the old session survived" false positive A002 warns about.
//!
//! Output: one JSON line per 250 ms tick (`{"tick":n,"rx":{src:count}}`, the
//! counts since the previous tick), then a final summary line with
//! `"done":true`. The host stamps lines on arrival, so the cases can line up
//! what the guest's sockets saw with what the harness saw on the wire.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::num::NonZeroU32;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};

use crate::segment::{AGENT_MAGIC, LINK_GROUP, LINK_PORT, PEER_MAGIC, payload_peer};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tick {
    pub tick: u64,
    /// Harness-peer datagrams the agent's SOCKETS received this tick, keyed
    /// by peer name (from the payload — not the source IP, which a bridged
    /// segment shares across peers on one subnet).
    pub rx: BTreeMap<String, u64>,
    #[serde(default)]
    pub done: bool,
    /// Summary-only: datagrams sent per interface, and send errors per
    /// interface (a pf `block` on output surfaces here as EHOSTUNREACH).
    #[serde(default)]
    pub tx: BTreeMap<String, u64>,
    #[serde(default)]
    pub tx_err: BTreeMap<String, u64>,
}

struct Leg {
    name: String,
    addr: Ipv4Addr,
    netmask: Ipv4Addr,
    sock: UdpSocket,
}

fn iface_v4(name: &str) -> Result<(Ipv4Addr, Ipv4Addr)> {
    for ifa in if_addrs::get_if_addrs().context("listing interfaces")? {
        if ifa.name == name
            && let if_addrs::IfAddr::V4(v4) = ifa.addr
        {
            return Ok((v4.ip, v4.netmask));
        }
    }
    bail!("interface {name} has no IPv4 address")
}

fn reuse_socket() -> Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).context("socket")?;
    s.set_reuse_address(true).context("SO_REUSEADDR")?;
    s.set_reuse_port(true).context("SO_REUSEPORT")?;
    s.set_nonblocking(true).context("O_NONBLOCK")?;
    Ok(s)
}

fn leg(name: &str) -> Result<Leg> {
    let (addr, netmask) = iface_v4(name)?;
    let s = reuse_socket()?;
    // SAFETY: if_nametoindex reads a NUL-terminated string we own.
    let cname = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    let idx = NonZeroU32::new(idx).with_context(|| format!("if_nametoindex({name})"))?;
    s.bind_device_by_index_v4(Some(idx)).with_context(|| format!("IP_BOUND_IF {name}"))?;
    s.bind(&SocketAddrV4::new(addr, LINK_PORT).into()).with_context(|| format!("bind {addr}:{LINK_PORT}"))?;
    s.set_multicast_if_v4(&addr).context("IP_MULTICAST_IF")?;
    s.set_multicast_ttl_v4(1).context("IP_MULTICAST_TTL")?;
    // Our own beacons must not count as reception: the cases ask whether a
    // PEER got through, and the in-kernel loopback copy would answer yes
    // regardless of what pf did on the wire.
    s.set_multicast_loop_v4(false).context("IP_MULTICAST_LOOP")?;
    Ok(Leg { name: name.to_string(), addr, netmask, sock: s.into() })
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(a) & u32::from(mask) == u32::from(b) & u32::from(mask)
}

pub fn run(ifaces: &[String], unicast: &[Ipv4Addr], seconds: f64, interval: Duration) -> Result<()> {
    let legs = ifaces.iter().map(|i| leg(i)).collect::<Result<Vec<_>>>()?;
    let listen = reuse_socket()?;
    listen.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LINK_PORT).into()).context("bind *:20808")?;
    for l in &legs {
        listen.join_multicast_v4(&LINK_GROUP, &l.addr).with_context(|| format!("IP_ADD_MEMBERSHIP on {}", l.name))?;
    }
    let listen: UdpSocket = listen.into();

    let start = Instant::now();
    let end = start + Duration::from_secs_f64(seconds);
    let tick_len = Duration::from_millis(250);
    let mut next_send = start;
    let mut next_tick = start + tick_len;
    let mut seq = 0u64;
    let mut summary = Tick { done: true, ..Tick::default() };
    let mut tick = Tick::default();
    let mut buf = [0u8; 2048];
    let stdout = std::io::stdout();

    while Instant::now() < end {
        let now = Instant::now();
        if now >= next_send {
            seq += 1;
            for l in &legs {
                let payload = [AGENT_MAGIC, format!("{} {seq}", l.name).as_bytes()].concat();
                let mut dests = vec![SocketAddrV4::new(LINK_GROUP, LINK_PORT)];
                dests.extend(
                    unicast.iter().filter(|u| same_subnet(**u, l.addr, l.netmask)).map(|u| SocketAddrV4::new(*u, LINK_PORT)),
                );
                for d in dests {
                    let key = l.name.clone();
                    match l.sock.send_to(&payload, d) {
                        Ok(_) => *summary.tx.entry(key).or_default() += 1,
                        Err(_) => *summary.tx_err.entry(key).or_default() += 1,
                    }
                }
            }
            next_send += interval;
        }
        for sock in std::iter::once(&listen).chain(legs.iter().map(|l| &l.sock)) {
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        if buf[..n].starts_with(PEER_MAGIC)
                            && let Some(peer) = payload_peer(&buf[..n])
                        {
                            *tick.rx.entry(peer.to_string()).or_default() += 1;
                            *summary.rx.entry(peer.to_string()).or_default() += 1;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        if now >= next_tick {
            tick.tick += 1;
            let mut out = stdout.lock();
            writeln!(out, "{}", serde_json::to_string(&tick)?)?;
            out.flush()?;
            tick.rx.clear();
            next_tick += tick_len;
        }
        thread::sleep(Duration::from_millis(2));
    }
    let mut out = stdout.lock();
    writeln!(out, "{}", serde_json::to_string(&summary)?)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_match_picks_the_leg_for_a_unicast_peer() {
        let m = Ipv4Addr::new(255, 255, 255, 0);
        assert!(same_subnet(Ipv4Addr::new(10, 70, 1, 2), Ipv4Addr::new(10, 70, 1, 1), m));
        assert!(!same_subnet(Ipv4Addr::new(10, 70, 2, 2), Ipv4Addr::new(10, 70, 1, 1), m));
    }

    #[test]
    fn tick_lines_parse_with_summary_fields_absent() {
        let t: Tick = serde_json::from_str(r#"{"tick":3,"rx":{"a":4}}"#).unwrap();
        assert_eq!(t.rx["a"], 4);
        assert!(!t.done && t.tx.is_empty());
    }
}
