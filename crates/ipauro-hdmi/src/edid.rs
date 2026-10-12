//! EDID base block + CTA-861 extension parsing, limited to what an audio
//! sink-capability probe needs: identity, audio data blocks, speaker
//! allocation, and the HDMI vendor block's physical address.
//!
//! With an AVR in the chain, the source sees the AVR's EDID: the TV's video
//! capabilities merged with the AVR's audio descriptors. That merged EDID
//! is what decides which bitstream formats a source may send.

use serde::Serialize;

use crate::sad::{self, Sad};

pub const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

#[derive(Debug, Clone, Serialize)]
pub struct Edid {
    pub manufacturer: String,
    pub product_code: u16,
    pub serial: u32,
    pub year: u16,
    pub version: String,
    pub monitor_name: Option<String>,
    pub extension_count: u8,
    pub base_checksum_ok: bool,
    pub cta: Vec<CtaExtension>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CtaExtension {
    pub revision: u8,
    pub checksum_ok: bool,
    pub basic_audio: bool,
    pub sads: Vec<Sad>,
    /// Raw speaker allocation payload (3 bytes when present).
    pub speaker_allocation: Option<Vec<u8>>,
    pub speakers: Vec<&'static str>,
    /// HDMI 1.x VSDB (OUI 00-0C-03) CEC physical address, as "a.b.c.d".
    pub hdmi_physical_address: Option<String>,
    /// HDMI Forum VSDB (OUI C4-5D-D8) present, i.e. an HDMI 2.x sink.
    pub hdmi_forum: bool,
    /// Data block tags seen, for anything this parser skips:
    /// `(tag, extended tag if tag 7, length)`.
    pub blocks: Vec<(u8, Option<u8>, u8)>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EdidError {
    #[error("EDID shorter than one 128-byte block ({0} bytes)")]
    Short(usize),
    #[error("missing EDID header 00 FF FF FF FF FF FF 00")]
    Header,
}

fn checksum_ok(block: &[u8]) -> bool {
    block.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

fn pnp_id(b: [u8; 2]) -> String {
    let v = u16::from_be_bytes(b);
    [(v >> 10) & 0x1f, (v >> 5) & 0x1f, v & 0x1f]
        .iter()
        .map(|c| {
            if (1..=26).contains(c) {
                (b'A' + *c as u8 - 1) as char
            } else {
                '?'
            }
        })
        .collect()
}

pub(crate) fn pnp_id_le(v: u16) -> String {
    pnp_id(v.to_be_bytes())
}

impl Edid {
    pub fn parse(data: &[u8]) -> Result<Edid, EdidError> {
        if data.len() < 128 {
            return Err(EdidError::Short(data.len()));
        }
        if data[..8] != HEADER {
            return Err(EdidError::Header);
        }
        let base = &data[..128];
        let mut monitor_name = None;
        for d in base[54..126].chunks_exact(18) {
            if d[0] == 0 && d[1] == 0 && d[3] == 0xFC {
                let s: String = d[5..18]
                    .iter()
                    .take_while(|c| **c != b'\n')
                    .map(|c| *c as char)
                    .collect();
                monitor_name = Some(s.trim_end().to_string());
            }
        }
        let mut cta = Vec::new();
        for block in data[128..].chunks_exact(128) {
            if block[0] == 0x02 {
                cta.push(parse_cta(block));
            }
        }
        Ok(Edid {
            manufacturer: pnp_id([base[8], base[9]]),
            product_code: u16::from_le_bytes([base[10], base[11]]),
            serial: u32::from_le_bytes([base[12], base[13], base[14], base[15]]),
            year: 1990 + u16::from(base[17]),
            version: format!("{}.{}", base[18], base[19]),
            monitor_name,
            extension_count: base[126],
            base_checksum_ok: checksum_ok(base),
            cta,
        })
    }

    pub fn sads(&self) -> impl Iterator<Item = &Sad> {
        self.cta.iter().flat_map(|c| c.sads.iter())
    }
}

fn parse_cta(block: &[u8]) -> CtaExtension {
    let mut ext = CtaExtension {
        revision: block[1],
        checksum_ok: checksum_ok(block),
        basic_audio: block[3] & 0x40 != 0,
        sads: Vec::new(),
        speaker_allocation: None,
        speakers: Vec::new(),
        hdmi_physical_address: None,
        hdmi_forum: false,
        blocks: Vec::new(),
    };
    let dtd_offset = usize::from(block[2]).clamp(4, 127);
    let mut i = 4;
    while i < dtd_offset {
        let tag = block[i] >> 5;
        let len = usize::from(block[i] & 0x1f);
        let Some(payload) = block.get(i + 1..i + 1 + len) else {
            break;
        };
        let ext_tag = (tag == 7 && len > 0).then(|| payload[0]);
        ext.blocks.push((tag, ext_tag, len as u8));
        match tag {
            1 => ext.sads.extend(Sad::parse_all(payload)),
            4 if len >= 1 => {
                ext.speakers = sad::speakers(payload);
                ext.speaker_allocation = Some(payload.to_vec());
            }
            3 if len >= 3 => match [payload[0], payload[1], payload[2]] {
                [0x03, 0x0C, 0x00] if len >= 5 => {
                    let (a, b) = (payload[3], payload[4]);
                    ext.hdmi_physical_address =
                        Some(format!("{}.{}.{}.{}", a >> 4, a & 0xf, b >> 4, b & 0xf));
                }
                [0xD8, 0x5D, 0xC4] => ext.hdmi_forum = true,
                _ => {}
            },
            _ => {}
        }
        i += 1 + len;
    }
    ext
}

/// Accepts raw binary EDID or a hex dump (whitespace/newlines/`0x`/colons
/// ignored), so EDIDs pasted from `ioreg`, `edid-decode` input, or a bug
/// report all work.
pub fn decode_input(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() >= 8 && bytes[..8] == HEADER {
        return bytes.to_vec();
    }
    let text = String::from_utf8_lossy(bytes).replace("0x", "");
    let digits: Vec<u8> = text.bytes().filter(|c| c.is_ascii_hexdigit()).collect();
    digits
        .chunks_exact(2)
        .filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}
