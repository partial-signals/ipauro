//! Hand-rolled RFC 2131 DHCP packet codec: fixed header + magic cookie +
//! TLV options. No external DHCP crate — the wire format is small and the
//! one hard requirement (never emit a router/gateway option, R005-T6) is
//! easiest to guarantee when we own every byte written.
//!
//! Layout (RFC 2131 §2, §3):
//! `op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2) ciaddr(4)
//! yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)` = 236 bytes,
//! then a 4-byte magic cookie (`99.130.83.99`), then options as
//! `code(1) len(1) data(len)` triples (`code` 0 = Pad, no len/data; `code`
//! 255 = End, terminates the list).

use std::net::Ipv4Addr;

pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Fixed-header length, NOT including the magic cookie.
pub const FIXED_HEADER_LEN: usize = 236;
/// Minimum valid packet: fixed header + magic cookie, zero options.
pub const MIN_PACKET_LEN: usize = FIXED_HEADER_LEN + 4;
/// BOOTP's historical minimum message size; padded to on encode for
/// compatibility with clients that assume it (RFC 1542 §2.1 background).
const MIN_ENCODED_LEN: usize = 300;

/// BOOTP `op` codes (RFC 951 / RFC 2131 §2).
pub mod op {
    pub const BOOTREQUEST: u8 = 1;
    pub const BOOTREPLY: u8 = 2;
}

/// DHCP option codes this codec/responder cares about (RFC 2132). Not
/// exhaustive — [`RawOption`] round-trips ANY option code/data, known or not.
pub mod opt {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    /// Router/gateway. NEVER emitted by this responder (R005-T6: the audio
    /// segment must not become a default route) — the codec can still
    /// decode it if present in a CLIENT packet; the ban is enforced in
    /// `responder.rs`, not here.
    pub const ROUTER: u8 = 3;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const END: u8 = 255;
}

/// DHCP message types (option 53's single data byte; RFC 2132 §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            // Anything else (0, 9+) isn't a message type this responder
            // understands — not a decode error, just "no known type."
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }
}

/// One raw `code, data` option TLV. Encode/decode round-trips ANY code —
/// typed accessors (`Packet::message_type`, etc.) build on top of this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOption {
    pub code: u8,
    pub data: Vec<u8>,
}

impl RawOption {
    pub fn message_type(mt: MessageType) -> Self {
        Self { code: opt::MESSAGE_TYPE, data: vec![mt.to_u8()] }
    }
    pub fn subnet_mask(mask: Ipv4Addr) -> Self {
        Self { code: opt::SUBNET_MASK, data: mask.octets().to_vec() }
    }
    pub fn lease_time(secs: u32) -> Self {
        Self { code: opt::LEASE_TIME, data: secs.to_be_bytes().to_vec() }
    }
    pub fn server_id(addr: Ipv4Addr) -> Self {
        Self { code: opt::SERVER_ID, data: addr.octets().to_vec() }
    }
}

/// A decoded (or to-be-encoded) DHCP/BOOTP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    /// The single flags bit this codec round-trips (RFC 2131 §2's
    /// "broadcast" bit, `0x8000`); the other 15 bits are reserved-must-be-
    /// zero in the RFC and carry no meaning we act on.
    pub broadcast_flag: bool,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<RawOption>,
}

impl Packet {
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options.iter().find(|o| o.code == code).map(|o| o.data.as_slice())
    }

    pub fn message_type(&self) -> Option<MessageType> {
        self.option(opt::MESSAGE_TYPE)
            .and_then(|d| d.first())
            .copied()
            .and_then(MessageType::from_u8)
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.option(opt::REQUESTED_IP).and_then(|d| <[u8; 4]>::try_from(d).ok()).map(Ipv4Addr::from)
    }

    /// Client hardware address, clamped to `hlen` (defensively capped at the
    /// 16-byte `chaddr` field width — a malformed/hostile `hlen` must never
    /// panic a slice).
    pub fn client_hw_addr(&self) -> &[u8] {
        &self.chaddr[..(self.hlen as usize).min(self.chaddr.len())]
    }

    /// Encode to wire bytes, padded to BOOTP's historical 300-byte minimum.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MIN_ENCODED_LEN);
        buf.push(self.op);
        buf.push(self.htype);
        buf.push(self.hlen);
        buf.push(self.hops);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        let flags: u16 = if self.broadcast_flag { 0x8000 } else { 0 };
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&self.ciaddr.octets());
        buf.extend_from_slice(&self.yiaddr.octets());
        buf.extend_from_slice(&self.siaddr.octets());
        buf.extend_from_slice(&self.giaddr.octets());
        buf.extend_from_slice(&self.chaddr);
        buf.extend_from_slice(&self.sname);
        buf.extend_from_slice(&self.file);
        debug_assert_eq!(buf.len(), FIXED_HEADER_LEN);
        buf.extend_from_slice(&MAGIC_COOKIE);
        for option in &self.options {
            buf.push(option.code);
            if option.code == opt::PAD || option.code == opt::END {
                continue; // Pad/End carry no length or data byte.
            }
            // Every option this codec builds is a handful of bytes (mask/
            // lease/server-id/message-type); a `data` longer than 255 bytes
            // would truncate here, which would be a bug in the CALLER, not
            // a wire-format concern this codec silently papers over.
            debug_assert!(
                option.data.len() <= u8::MAX as usize,
                "option {} data too long to encode",
                option.code
            );
            buf.push(option.data.len() as u8);
            buf.extend_from_slice(&option.data);
        }
        buf.push(opt::END);
        while buf.len() < MIN_ENCODED_LEN {
            buf.push(0);
        }
        buf
    }

    /// Decode wire bytes, rejecting anything malformed rather than guessing.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < MIN_PACKET_LEN {
            return Err(DecodeError::TooShort { len: bytes.len() });
        }
        if bytes[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4] != MAGIC_COOKIE {
            return Err(DecodeError::BadMagicCookie);
        }

        let xid = u32::from_be_bytes(bytes[4..8].try_into().expect("4-byte slice"));
        let secs = u16::from_be_bytes(bytes[8..10].try_into().expect("2-byte slice"));
        let flags = u16::from_be_bytes(bytes[10..12].try_into().expect("2-byte slice"));

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&bytes[28..44]);
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&bytes[44..108]);
        let mut file = [0u8; 128];
        file.copy_from_slice(&bytes[108..236]);

        let options = decode_options(&bytes[FIXED_HEADER_LEN + 4..])?;

        Ok(Packet {
            op: bytes[0],
            htype: bytes[1],
            hlen: bytes[2],
            hops: bytes[3],
            xid,
            secs,
            broadcast_flag: flags & 0x8000 != 0,
            ciaddr: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            yiaddr: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            siaddr: Ipv4Addr::new(bytes[20], bytes[21], bytes[22], bytes[23]),
            giaddr: Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]),
            chaddr,
            sname,
            file,
            options,
        })
    }
}

fn decode_options(bytes: &[u8]) -> Result<Vec<RawOption>, DecodeError> {
    let mut options = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let code = bytes[i];
        i += 1;
        if code == opt::PAD {
            continue;
        }
        if code == opt::END {
            break;
        }
        let len_byte = *bytes.get(i).ok_or(DecodeError::TruncatedOption { code })?;
        let len = len_byte as usize;
        i += 1;
        let data = bytes.get(i..i + len).ok_or(DecodeError::TruncatedOption { code })?.to_vec();
        i += len;
        options.push(RawOption { code, data });
    }
    Ok(options)
}

/// Why a byte buffer was rejected as not-a-valid-DHCP-packet. Every variant
/// is matched by name at call sites (no silent catch-all) — see
/// `dhcp::responder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Shorter than the fixed header + magic cookie (240 bytes).
    TooShort { len: usize },
    /// The 4 bytes at offset 236 aren't `99.130.83.99`.
    BadMagicCookie,
    /// An option's declared length ran past the end of the buffer (or the
    /// option's length byte itself was missing).
    TruncatedOption { code: u8 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { len } => {
                write!(f, "packet too short ({len} bytes, need >= {MIN_PACKET_LEN})")
            }
            Self::BadMagicCookie => write!(f, "bad magic cookie (not a DHCP packet)"),
            Self::TruncatedOption { code } => write!(f, "option {code} truncated"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet(op: u8, message_type: MessageType, options_tail: Vec<RawOption>) -> Packet {
        let mut options = vec![RawOption::message_type(message_type)];
        options.extend(options_tail);
        Packet {
            op,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0xdeadbeef,
            secs: 3,
            broadcast_flag: false,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: {
                let mut c = [0u8; 16];
                c[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
                c
            },
            sname: [0u8; 64],
            file: [0u8; 128],
            options,
        }
    }

    #[test]
    fn discover_round_trips() {
        let pkt = sample_packet(op::BOOTREQUEST, MessageType::Discover, vec![]);
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).expect("valid encode must decode");
        assert_eq!(decoded, pkt);
        assert_eq!(decoded.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn offer_round_trips_with_full_option_set() {
        let pkt = sample_packet(
            op::BOOTREPLY,
            MessageType::Offer,
            vec![
                RawOption::subnet_mask(Ipv4Addr::new(255, 255, 255, 0)),
                RawOption::lease_time(3600),
                RawOption::server_id(Ipv4Addr::new(10, 69, 0, 1)),
            ],
        );
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).expect("valid encode must decode");
        assert_eq!(decoded, pkt);
        assert_eq!(decoded.message_type(), Some(MessageType::Offer));
        assert_eq!(decoded.option(opt::SUBNET_MASK), Some([255, 255, 255, 0].as_slice()));
        assert_eq!(decoded.option(opt::LEASE_TIME), Some(3600u32.to_be_bytes().as_slice()));
        assert_eq!(decoded.option(opt::SERVER_ID), Some([10, 69, 0, 1].as_slice()));
    }

    #[test]
    fn request_round_trips_with_requested_ip() {
        let mut pkt = sample_packet(op::BOOTREQUEST, MessageType::Request, vec![]);
        pkt.options.push(RawOption { code: opt::REQUESTED_IP, data: vec![10, 69, 0, 42] });
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).expect("valid encode must decode");
        assert_eq!(decoded.requested_ip(), Some(Ipv4Addr::new(10, 69, 0, 42)));
    }

    #[test]
    fn ack_round_trips() {
        let pkt = sample_packet(
            op::BOOTREPLY,
            MessageType::Ack,
            vec![RawOption::server_id(Ipv4Addr::new(10, 69, 0, 1))],
        );
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).expect("valid encode must decode");
        assert_eq!(decoded.message_type(), Some(MessageType::Ack));
    }

    #[test]
    fn broadcast_flag_round_trips() {
        let mut pkt = sample_packet(op::BOOTREQUEST, MessageType::Discover, vec![]);
        pkt.broadcast_flag = true;
        let decoded = Packet::decode(&pkt.encode()).unwrap();
        assert!(decoded.broadcast_flag);

        pkt.broadcast_flag = false;
        let decoded = Packet::decode(&pkt.encode()).unwrap();
        assert!(!decoded.broadcast_flag);
    }

    #[test]
    fn client_hw_addr_reads_exactly_hlen_bytes() {
        let pkt = sample_packet(op::BOOTREQUEST, MessageType::Discover, vec![]);
        assert_eq!(pkt.client_hw_addr(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn client_hw_addr_clamps_a_bogus_oversized_hlen() {
        let mut pkt = sample_packet(op::BOOTREQUEST, MessageType::Discover, vec![]);
        pkt.hlen = 255; // hostile/malformed: must not panic on slicing chaddr
        assert_eq!(pkt.client_hw_addr().len(), 16);
    }

    #[test]
    fn a_client_packet_carrying_a_router_option_still_decodes_faithfully() {
        // The CODEC must round-trip any option (mechanism); the "never
        // EMIT a router option" rule is a responder-level (semantic)
        // invariant tested in `responder.rs`, not here.
        let mut pkt = sample_packet(op::BOOTREQUEST, MessageType::Inform, vec![]);
        pkt.options.push(RawOption { code: opt::ROUTER, data: vec![10, 0, 0, 1] });
        let decoded = Packet::decode(&pkt.encode()).unwrap();
        assert_eq!(decoded.option(opt::ROUTER), Some([10, 0, 0, 1].as_slice()));
    }

    #[test]
    fn unknown_message_type_byte_is_none_not_an_error() {
        let mut pkt = sample_packet(op::BOOTREQUEST, MessageType::Discover, vec![]);
        pkt.options[0] = RawOption { code: opt::MESSAGE_TYPE, data: vec![200] };
        let decoded = Packet::decode(&pkt.encode()).unwrap();
        assert_eq!(decoded.message_type(), None);
    }

    // ---- malformed-packet rejection ---------------------------------------

    #[test]
    fn empty_buffer_is_too_short() {
        assert_eq!(Packet::decode(&[]), Err(DecodeError::TooShort { len: 0 }));
    }

    #[test]
    fn buffer_one_byte_short_of_minimum_is_rejected() {
        let buf = vec![0u8; MIN_PACKET_LEN - 1];
        assert_eq!(Packet::decode(&buf), Err(DecodeError::TooShort { len: MIN_PACKET_LEN - 1 }));
    }

    #[test]
    fn minimum_length_with_correct_cookie_and_no_options_decodes() {
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        let decoded = Packet::decode(&buf).expect("minimal valid packet");
        assert!(decoded.options.is_empty());
    }

    #[test]
    fn bad_magic_cookie_is_rejected() {
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(Packet::decode(&buf), Err(DecodeError::BadMagicCookie));
    }

    #[test]
    fn option_length_byte_missing_is_rejected() {
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        buf.push(opt::SUBNET_MASK); // code with no following length byte at all
        assert_eq!(
            Packet::decode(&buf),
            Err(DecodeError::TruncatedOption { code: opt::SUBNET_MASK })
        );
    }

    #[test]
    fn option_length_overruns_buffer_is_rejected() {
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        buf.push(opt::SUBNET_MASK);
        buf.push(10); // claims 10 bytes of data
        buf.extend_from_slice(&[1, 2, 3]); // only 3 actually present
        assert_eq!(
            Packet::decode(&buf),
            Err(DecodeError::TruncatedOption { code: opt::SUBNET_MASK })
        );
    }

    #[test]
    fn cutting_mid_option_data_is_rejected() {
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        buf.push(opt::SUBNET_MASK);
        buf.push(4); // declares 4 data bytes
        buf.push(255); // only 1 present
        assert_eq!(
            Packet::decode(&buf),
            Err(DecodeError::TruncatedOption { code: opt::SUBNET_MASK })
        );
    }

    #[test]
    fn cutting_right_after_an_options_code_byte_is_rejected() {
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        buf.push(opt::SUBNET_MASK); // code present, length byte missing entirely
        assert_eq!(
            Packet::decode(&buf),
            Err(DecodeError::TruncatedOption { code: opt::SUBNET_MASK })
        );
    }

    #[test]
    fn a_complete_option_with_no_terminator_still_decodes_partially() {
        // No spurious rejection: a buffer that ends right after a fully-
        // present option (no END marker, no second option) is not
        // "truncated" by this codec's definition — RFC 2131 options run to
        // the end of the packet, END is a courtesy short-circuit, not a
        // requirement. This intentionally decodes to FEWER options than a
        // hypothetical fuller packet, never spuriously equal to one.
        let mut buf = vec![0u8; MIN_PACKET_LEN];
        buf[FIXED_HEADER_LEN..FIXED_HEADER_LEN + 4].copy_from_slice(&MAGIC_COOKIE);
        buf.push(opt::SUBNET_MASK);
        buf.push(4);
        buf.extend_from_slice(&[255, 255, 255, 0]);
        let decoded =
            Packet::decode(&buf).expect("a complete option with no terminator still decodes");
        assert_eq!(
            decoded.options,
            vec![RawOption { code: opt::SUBNET_MASK, data: vec![255, 255, 255, 0] }]
        );
    }
}
