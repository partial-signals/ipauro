//! Transports and the control/media split (spec §8.1, §8.2).
//!
//! A [`Gateway`] is any way to reach a peer: a Link multicast interface, an iroh
//! overlay connection, a Thunderbolt/USB-C bridge. This generalizes Link's
//! per-gateway model — the mesh ranks a Thunderbolt path, a LAN path, and a relay
//! path against each other with the same best-path logic.
//!
//! The cardinal rule (§8.2): **the reliable overlay carries control, never live
//! audio.** That is enforced in the type system here — a [`Gateway`] exposes a
//! [`ControlChannel`] always, and a [`MediaChannel`] only when the transport can
//! deliver *timely* (unreliable) datagrams. You cannot accidentally send PCM down
//! a reliable stream because reliable transports simply do not hand you a
//! [`MediaChannel`].

use crate::ids::NodeId;

/// What kind of transport a gateway is. Feeds service-order policy (§8.4): e.g.
/// policy may prefer `Thunderbolt` over `Wifi` even at higher measured RTT.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportKind {
    /// Link/LinkAudio multicast on a shared L2 segment.
    LinkMulticast,
    /// iroh QUIC overlay (relay-bootstrapped, upgrades to a direct path).
    IrohOverlay,
    /// Thunderbolt IP bridge (PCIe/DMA — low jitter, preferred for p2p sync).
    Thunderbolt,
    /// USB-C / USB2 NCM bridge (cheap, 125 µs-polled — higher jitter than TB).
    UsbBridge,
    /// Wired Ethernet (possibly PTP-capable; see clock domains in `capability`).
    Ethernet,
    /// 802.11.
    Wifi,
}

impl TransportKind {
    /// Dedicated single-talker links need no reservation/shaping and can clock
    /// from the transport itself (spec §7.1, §7.2). Used by policy and by the
    /// clock-domain logic.
    pub fn is_dedicated_p2p(&self) -> bool {
        matches!(self, TransportKind::Thunderbolt | TransportKind::UsbBridge)
    }
}

/// Measured properties of a link, refreshed from keepalive RTTs (the ch. 03 §4.2
/// quality metric) and gossiped so every node can weight edges the same way.
#[derive(Clone, Copy, Debug)]
pub struct LinkQuality {
    pub rtt_us: u32,
    pub jitter_us: u32,
    /// Estimated usable bandwidth, bits/s (0 = unknown).
    pub bandwidth_bps: u64,
    /// Fraction of the measurement window lost, 0.0–1.0.
    pub loss: f32,
}

impl LinkQuality {
    /// A scalar cost for shortest-path, computed from the *shared* policy weights
    /// so every node ranks edges identically (spec §8.3). Kept here as the
    /// natural home of the measured inputs; the weights themselves live in
    /// `policy`.
    pub fn cost(&self, w: &crate::policy::Weights) -> f64 {
        w.rtt * self.rtt_us as f64
            + w.jitter * self.jitter_us as f64
            + w.loss * self.loss as f64 * 1e6
            + if self.bandwidth_bps == 0 {
                0.0
            } else {
                w.inv_bandwidth * (1e12 / self.bandwidth_bps as f64)
            }
    }
}

/// A reliable, ordered, authenticated channel — control plane only.
pub trait ControlChannel {
    fn send_reliable(&self, bytes: &[u8]) -> std::io::Result<()>;
}

/// A timely, *unreliable* channel — media plane only. May be raw UDP (dedicated
/// links, embedded) or congestion-aware QUIC datagrams (shared links, where
/// back-pressure fixes the §5.8 self-starvation *iff* the caller degrades
/// gracefully rather than merely dropping packets).
pub trait MediaChannel {
    /// Send one media datagram best-effort. Late data is never retransmitted.
    fn send_datagram(&self, bytes: &[u8]) -> std::io::Result<()>;
    /// True when the transport applies congestion control to datagrams, so the
    /// caller knows it must offer graceful degradation hooks.
    fn is_congestion_aware(&self) -> bool;
}

/// One transport to one peer.
pub trait Gateway {
    fn peer(&self) -> NodeId;
    fn kind(&self) -> TransportKind;
    fn quality(&self) -> LinkQuality;
    /// Always available.
    fn control(&self) -> &dyn ControlChannel;
    /// `Some` only for transports that can deliver timely/unreliable datagrams.
    /// Reliable-only transports (a plain QUIC stream) return `None`, making it a
    /// type error to stream audio over them.
    fn media(&self) -> Option<&dyn MediaChannel>;
}
