//! Just enough Ethernet / ARP / IPv4 / UDP to play a peer on a segment from
//! OUTSIDE the kernel under test: build the frames an emulated peer injects,
//! and parse the frames the guest puts on the wire. Deliberately not a
//! general stack — no fragmentation, no options, no IPv6 — because every
//! frame this harness cares about is a single small Link-shaped datagram.

use std::net::Ipv4Addr;

pub type Mac = [u8; 6];

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const IPPROTO_UDP: u8 = 17;
pub const BROADCAST: Mac = [0xff; 6];

/// The IPv4 multicast MAC for `group` (RFC 1112 §6.4: 01:00:5e + low 23 bits).
pub fn multicast_mac(group: Ipv4Addr) -> Mac {
    let o = group.octets();
    [0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]]
}

pub fn fmt_mac(m: &Mac) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Parse `aa:bb:cc:dd:ee:ff` — and ALSO macOS `ifconfig`'s zero-stripped
/// spelling (`52:55:55:a0:0:1`), which is what the guest reports.
pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split(':');
    for slot in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn ones_complement(mut sum: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        sum += u32::from(u16::from_be_bytes(*c));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A complete Ethernet+IPv4+UDP frame. The UDP checksum is filled in (macOS
/// accepts a zero checksum, but a real peer never sends one, and a frame the
/// guest silently dropped for a reason we introduced would read as a pf drop).
pub fn udp_frame(
    src_mac: Mac,
    dst_mac: Mac,
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut f = Vec::with_capacity(14 + ip_len);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let ip_start = f.len();
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&(ip_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0]); // id 0, DF
    f.extend_from_slice(&[ttl, IPPROTO_UDP, 0, 0]);
    f.extend_from_slice(&src.0.octets());
    f.extend_from_slice(&dst.0.octets());
    let ip_ck = fold(ones_complement(0, &f[ip_start..ip_start + 20]));
    f[ip_start + 10..ip_start + 12].copy_from_slice(&ip_ck.to_be_bytes());

    let udp_start = f.len();
    f.extend_from_slice(&src.1.to_be_bytes());
    f.extend_from_slice(&dst.1.to_be_bytes());
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.0.octets());
    pseudo.extend_from_slice(&dst.0.octets());
    pseudo.extend_from_slice(&[0, IPPROTO_UDP]);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    let mut ck = fold(ones_complement(ones_complement(0, &pseudo), &f[udp_start..]));
    if ck == 0 {
        ck = 0xffff;
    }
    f[udp_start + 6..udp_start + 8].copy_from_slice(&ck.to_be_bytes());
    f
}

/// ARP request (`op` 1) or reply (`op` 2), Ethernet/IPv4.
pub fn arp_frame(op: u16, src_mac: Mac, src_ip: Ipv4Addr, dst_mac: Mac, dst_ip: Ipv4Addr) -> Vec<u8> {
    let eth_dst = if op == 1 { BROADCAST } else { dst_mac };
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&eth_dst);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    f.extend_from_slice(&[0, 1, 0x08, 0, 6, 4]);
    f.extend_from_slice(&op.to_be_bytes());
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&src_ip.octets());
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&dst_ip.octets());
    f
}

/// What a captured frame IS, as far as the cases care.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    Arp { op: u16, sender_mac: Mac, sender_ip: Ipv4Addr, target_ip: Ipv4Addr },
    Udp { src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: Vec<u8> },
    /// Anything else (IPv6 ND, IGMP, mDNS-over-v6, TCP...). macOS guests
    /// chatter constantly; the cases filter it out rather than assert on it.
    Other { ethertype: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub dst_mac: Mac,
    pub src_mac: Mac,
    pub parsed: Parsed,
}

pub fn parse(f: &[u8]) -> Option<Frame> {
    if f.len() < 14 {
        return None;
    }
    let dst_mac: Mac = f[0..6].try_into().ok()?;
    let src_mac: Mac = f[6..12].try_into().ok()?;
    let ethertype = u16::from_be_bytes([f[12], f[13]]);
    let body = &f[14..];
    let ip4 = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let parsed = match ethertype {
        ETHERTYPE_ARP if body.len() >= 28 => Parsed::Arp {
            op: u16::from_be_bytes([body[6], body[7]]),
            sender_mac: body[8..14].try_into().ok()?,
            sender_ip: ip4(&body[14..18]),
            target_ip: ip4(&body[24..28]),
        },
        ETHERTYPE_IPV4 if body.len() >= 20 && body[9] == IPPROTO_UDP => {
            let ihl = usize::from(body[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([body[2], body[3]])).min(body.len());
            if total < ihl + 8 {
                return None;
            }
            let udp = &body[ihl..total];
            Parsed::Udp {
                src: (ip4(&body[12..16]), u16::from_be_bytes([udp[0], udp[1]])),
                dst: (ip4(&body[16..20]), u16::from_be_bytes([udp[2], udp[3]])),
                payload: udp[8..].to_vec(),
            }
        }
        other => Parsed::Other { ethertype: other },
    };
    Some(Frame { dst_mac, src_mac, parsed })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Mac = [0x52, 0x55, 0x55, 0xa0, 0, 2];

    #[test]
    fn udp_frame_round_trips_through_parse() {
        let g = Ipv4Addr::new(224, 76, 78, 75);
        let f = udp_frame(A, multicast_mac(g), (Ipv4Addr::new(10, 69, 0, 2), 20808), (g, 20808), 1, b"hi");
        let p = parse(&f).unwrap();
        assert_eq!(p.src_mac, A);
        assert_eq!(p.dst_mac, [0x01, 0x00, 0x5e, 0x4c, 0x4e, 0x4b]);
        assert_eq!(
            p.parsed,
            Parsed::Udp { src: (Ipv4Addr::new(10, 69, 0, 2), 20808), dst: (g, 20808), payload: b"hi".to_vec() }
        );
    }

    #[test]
    fn ip_and_udp_checksums_verify_to_zero() {
        let f = udp_frame(A, BROADCAST, (Ipv4Addr::new(10, 0, 0, 1), 1), (Ipv4Addr::new(10, 0, 0, 2), 2), 64, b"odd");
        assert_eq!(fold(ones_complement(0, &f[14..34])), 0, "IPv4 header checksum");
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&f[26..34]);
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&f[38..40]);
        assert_eq!(fold(ones_complement(ones_complement(0, &pseudo), &f[34..])), 0, "UDP checksum");
    }

    #[test]
    fn arp_request_is_broadcast_and_parses() {
        let f = arp_frame(1, A, Ipv4Addr::new(10, 69, 0, 2), [0; 6], Ipv4Addr::new(10, 69, 0, 1));
        let p = parse(&f).unwrap();
        assert_eq!(p.dst_mac, BROADCAST);
        assert_eq!(
            p.parsed,
            Parsed::Arp { op: 1, sender_mac: A, sender_ip: Ipv4Addr::new(10, 69, 0, 2), target_ip: Ipv4Addr::new(10, 69, 0, 1) }
        );
    }

    #[test]
    fn parse_mac_accepts_ifconfig_zero_stripped_form() {
        assert_eq!(parse_mac("52:55:55:a0:0:1"), Some([0x52, 0x55, 0x55, 0xa0, 0, 1]));
        assert_eq!(parse_mac("52:55:55:a0:00:01"), Some([0x52, 0x55, 0x55, 0xa0, 0, 1]));
        assert_eq!(parse_mac("52:55:55:a0:00"), None);
        assert_eq!(parse_mac("52:55:55:a0:00:01:02"), None);
    }

    #[test]
    fn short_or_truncated_frames_do_not_panic() {
        assert!(parse(&[0; 13]).is_none());
        let mut f = udp_frame(A, BROADCAST, (Ipv4Addr::LOCALHOST, 1), (Ipv4Addr::LOCALHOST, 2), 1, b"");
        f.truncate(14 + 24);
        f[16..18].copy_from_slice(&24u16.to_be_bytes());
        assert!(parse(&f).is_none());
    }
}
