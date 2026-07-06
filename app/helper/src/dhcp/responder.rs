//! Pure DHCP message logic: DISCOVER -> OFFER, REQUEST -> ACK. No sockets —
//! `server.rs` owns the raw UDP socket and calls [`handle_packet`] with each
//! decoded packet, sending whatever it returns.
//!
//! **Absolutely no option 3 (router).** This is pinned in
//! `ipauro-proto::helper::HelperRequest::ServeDhcp`'s doc comment (R005-T6:
//! the audio segment must not become a default route) and enforced here by
//! construction — [`build_options`] is the ONLY place this responder
//! assembles an outgoing option list, and it has no branch that could ever
//! push `opt::ROUTER`. [`options_never_contain_router`] asserts this
//! directly against every packet this module builds.

use std::net::Ipv4Addr;

use super::lease::LeaseTable;
use super::packet::{MessageType, Packet, RawOption, op, opt};

/// Static configuration for one `ServeDhcp` session (mirrors the
/// `HelperRequest::ServeDhcp` fields plus the bridge's own address, needed
/// for option 54).
#[derive(Debug, Clone, Copy)]
pub struct DhcpConfig {
    pub server_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    /// ~1 hour per ipauro-proto's `defaults` module intent; not hardcoded
    /// here — the caller (server.rs) supplies it from the request/registry.
    pub lease_secs: u32,
}

/// Handle one decoded incoming packet, returning the packet to send back (if
/// any). Every [`MessageType`] variant is matched by name — see the
/// house rule on enum discipline; unhandled types are explicitly listed with
/// the reason, not swallowed by a bare wildcard.
pub fn handle_packet(
    config: &DhcpConfig,
    leases: &mut LeaseTable,
    incoming: &Packet,
) -> Option<Packet> {
    // Only ever reply to a BOOTREQUEST — a BOOTREPLY reaching this socket
    // (e.g. our own broadcast reply looping back, or a malformed/hostile
    // packet) must never be answered.
    if incoming.op != op::BOOTREQUEST {
        return None;
    }
    match incoming.message_type() {
        Some(MessageType::Discover) => build_offer(config, leases, incoming),
        Some(MessageType::Request) => build_ack(config, leases, incoming),
        Some(MessageType::Release) => {
            leases.release(incoming.client_hw_addr());
            None // RFC 2131: RELEASE gets no reply.
        }
        // Scope is DISCOVER->OFFER / REQUEST->ACK (+ RELEASE, above) only
        // (HelperRequest::ServeDhcp's doc comment). DECLINE/INFORM are valid
        // RFC 2131 client messages this M1 responder doesn't yet act on (no
        // duplicate-address defense or host-configuration-only replies in
        // M1); OFFER/ACK/NAK are server-originated types a client would
        // never legitimately send us. All silently ignored, not protocol
        // errors.
        Some(MessageType::Decline)
        | Some(MessageType::Inform)
        | Some(MessageType::Offer)
        | Some(MessageType::Ack)
        | Some(MessageType::Nak) => None,
        // No (or unrecognized) option 53 message type: not a DHCP request
        // this responder understands.
        None => None,
    }
}

fn build_offer(config: &DhcpConfig, leases: &mut LeaseTable, incoming: &Packet) -> Option<Packet> {
    let client = incoming.client_hw_addr();
    let assigned = leases.allocate(client, incoming.requested_ip())?;
    Some(reply(config, incoming, assigned, MessageType::Offer))
}

fn build_ack(config: &DhcpConfig, leases: &mut LeaseTable, incoming: &Packet) -> Option<Packet> {
    let client = incoming.client_hw_addr();
    // REQUEST's requested-IP option (50) takes priority over ciaddr for a
    // fresh lease (RFC 2131 §4.3.2); an already-leased client just gets its
    // existing address back regardless of what it asked for.
    let requested = incoming.requested_ip().or_else(|| {
        if incoming.ciaddr != Ipv4Addr::UNSPECIFIED { Some(incoming.ciaddr) } else { None }
    });
    let assigned = leases.allocate(client, requested)?;
    Some(reply(config, incoming, assigned, MessageType::Ack))
}

fn reply(
    config: &DhcpConfig,
    incoming: &Packet,
    yiaddr: Ipv4Addr,
    message_type: MessageType,
) -> Packet {
    Packet {
        op: super::packet::op::BOOTREPLY,
        htype: incoming.htype,
        hlen: incoming.hlen,
        hops: 0,
        xid: incoming.xid,
        secs: 0,
        broadcast_flag: incoming.broadcast_flag,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr,
        siaddr: config.server_ip,
        giaddr: incoming.giaddr,
        chaddr: incoming.chaddr,
        sname: [0u8; 64],
        file: [0u8; 128],
        options: build_options(config, message_type),
    }
}

/// The ONLY place this responder assembles an outgoing option list.
/// Deliberately has no branch that could push `opt::ROUTER` — see module
/// docs. The `debug_assert` is a runtime belt-and-suspenders check of that
/// same invariant (on top of `options_never_contain_router`'s unit test),
/// since R005-T6 pins this as an absolute requirement, not just a default.
fn build_options(config: &DhcpConfig, message_type: MessageType) -> Vec<RawOption> {
    let options = vec![
        RawOption::message_type(message_type),
        RawOption::subnet_mask(config.netmask),
        RawOption::lease_time(config.lease_secs),
        RawOption::server_id(config.server_ip),
    ];
    debug_assert!(
        !options.iter().any(|o| o.code == opt::ROUTER),
        "responder must never emit a router/gateway option (R005-T6)"
    );
    options
}

#[cfg(test)]
mod tests {
    use super::super::packet::op;
    use super::*;

    fn config() -> DhcpConfig {
        DhcpConfig {
            server_ip: Ipv4Addr::new(10, 69, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            lease_secs: 3600,
        }
    }

    fn discover(xid: u32, mac: [u8; 6]) -> Packet {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&mac);
        Packet {
            op: op::BOOTREQUEST,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            broadcast_flag: true,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            options: vec![RawOption::message_type(MessageType::Discover)],
        }
    }

    fn request(xid: u32, mac: [u8; 6], requested_ip: Option<Ipv4Addr>) -> Packet {
        let mut pkt = discover(xid, mac);
        pkt.options = vec![RawOption::message_type(MessageType::Request)];
        if let Some(ip) = requested_ip {
            pkt.options.push(RawOption { code: opt::REQUESTED_IP, data: ip.octets().to_vec() });
        }
        pkt
    }

    fn pool() -> LeaseTable {
        LeaseTable::new(Ipv4Addr::new(10, 69, 0, 10), Ipv4Addr::new(10, 69, 0, 200))
    }

    #[test]
    fn discover_produces_an_offer_with_an_allocated_address() {
        let mut leases = pool();
        let resp = handle_packet(&config(), &mut leases, &discover(1, [1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(resp.message_type(), Some(MessageType::Offer));
        assert_eq!(resp.op, op::BOOTREPLY);
        assert_eq!(resp.xid, 1);
        assert!(
            (Ipv4Addr::new(10, 69, 0, 10)..=Ipv4Addr::new(10, 69, 0, 200)).contains(&resp.yiaddr)
        );
    }

    #[test]
    fn request_produces_an_ack_with_the_requested_address() {
        let mut leases = pool();
        // A real client DISCOVERs first, then REQUESTs the offered address.
        let offer =
            handle_packet(&config(), &mut leases, &discover(2, [1, 2, 3, 4, 5, 6])).unwrap();
        let req = request(2, [1, 2, 3, 4, 5, 6], Some(offer.yiaddr));
        let ack = handle_packet(&config(), &mut leases, &req).unwrap();
        assert_eq!(ack.message_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr, offer.yiaddr);
    }

    #[test]
    fn request_with_no_free_address_yields_no_reply() {
        let mut leases =
            LeaseTable::new(Ipv4Addr::new(10, 69, 0, 10), Ipv4Addr::new(10, 69, 0, 10));
        leases.allocate(&[9, 9, 9, 9, 9, 9], None); // exhaust the single-address pool
        let req = request(3, [1, 2, 3, 4, 5, 6], None);
        assert!(handle_packet(&config(), &mut leases, &req).is_none());
    }

    #[test]
    fn decline_inform_and_server_originated_types_produce_no_reply() {
        let mut leases = pool();
        for mt in [
            MessageType::Decline,
            MessageType::Inform,
            MessageType::Offer,
            MessageType::Ack,
            MessageType::Nak,
        ] {
            let mut pkt = discover(4, [1, 2, 3, 4, 5, 6]);
            pkt.options = vec![RawOption::message_type(mt)];
            assert!(
                handle_packet(&config(), &mut leases, &pkt).is_none(),
                "{mt:?} should produce no reply"
            );
        }
    }

    #[test]
    fn release_frees_the_lease_and_produces_no_reply() {
        let mut leases = pool();
        let mac = [1, 2, 3, 4, 5, 6];
        let offer = handle_packet(&config(), &mut leases, &discover(10, mac)).unwrap();

        let mut release_pkt = discover(11, mac);
        release_pkt.options = vec![RawOption::message_type(MessageType::Release)];
        assert!(handle_packet(&config(), &mut leases, &release_pkt).is_none());

        // The freed address is immediately available to a new client.
        let mut other = discover(12, [9, 9, 9, 9, 9, 9]);
        other
            .options
            .push(RawOption { code: opt::REQUESTED_IP, data: offer.yiaddr.octets().to_vec() });
        let reoffer = handle_packet(&config(), &mut leases, &other).unwrap();
        assert_eq!(reoffer.yiaddr, offer.yiaddr);
    }

    #[test]
    fn a_bootreply_packet_is_never_answered() {
        let mut leases = pool();
        let mut pkt = discover(6, [1, 2, 3, 4, 5, 6]);
        pkt.op = op::BOOTREPLY; // e.g. our own broadcast looping back
        assert!(handle_packet(&config(), &mut leases, &pkt).is_none());
    }

    #[test]
    fn packet_with_no_message_type_option_produces_no_reply() {
        let mut leases = pool();
        let mut pkt = discover(5, [1, 2, 3, 4, 5, 6]);
        pkt.options.clear();
        assert!(handle_packet(&config(), &mut leases, &pkt).is_none());
    }

    // ---- the hard requirement: never emit a router option ------------------

    #[test]
    fn options_never_contain_router() {
        let mut leases = pool();
        let offer =
            handle_packet(&config(), &mut leases, &discover(6, [1, 2, 3, 4, 5, 6])).unwrap();
        assert!(offer.option(opt::ROUTER).is_none(), "OFFER must never carry a router option");

        let req = request(6, [1, 2, 3, 4, 5, 6], Some(offer.yiaddr));
        let ack = handle_packet(&config(), &mut leases, &req).unwrap();
        assert!(ack.option(opt::ROUTER).is_none(), "ACK must never carry a router option");
    }

    #[test]
    fn offer_carries_the_pinned_option_set() {
        let mut leases = pool();
        let offer =
            handle_packet(&config(), &mut leases, &discover(7, [1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(offer.option(opt::SUBNET_MASK), Some([255, 255, 255, 0].as_slice()));
        assert_eq!(offer.option(opt::LEASE_TIME), Some(3600u32.to_be_bytes().as_slice()));
        assert_eq!(offer.option(opt::SERVER_ID), Some([10, 69, 0, 1].as_slice()));
        // Exactly 4 options: message-type, subnet-mask, lease-time, server-id.
        assert_eq!(offer.options.len(), 4);
    }

    #[test]
    fn same_client_discovering_twice_gets_the_same_offer() {
        let mut leases = pool();
        let first =
            handle_packet(&config(), &mut leases, &discover(8, [1, 2, 3, 4, 5, 6])).unwrap();
        let second =
            handle_packet(&config(), &mut leases, &discover(9, [1, 2, 3, 4, 5, 6])).unwrap();
        assert_eq!(first.yiaddr, second.yiaddr);
    }
}
