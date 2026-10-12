//! EMDF (Extensible Metadata Delivery Format, ETSI TS 102 366 Annex H)
//! container discovery inside AC-3/E-AC-3 sync frames.
//!
//! Dolby Atmos in DD+ ("E-AC-3 JOC") carries its object payloads in EMDF
//! containers inside otherwise ordinary E-AC-3 frames: Object Audio Metadata
//! (OAMD) and Joint Object Coding (JOC) parameters, both specified in ETSI
//! TS 103 420. This module only *finds* containers and lists their payload
//! IDs and sizes. It doesn't decode OAMD or JOC.
//!
//! Finding them is a search: a container starts with the 16-bit sync
//! `0x5838` followed by a 16-bit length, and it can sit at a non-byte-aligned
//! position (skip fields / auxdata). So every bit offset is tried, and a hit
//! only counts if the whole container parses: version, key, a payload loop
//! that ends in the terminator inside the declared length, and valid
//! protection length codes. A false positive would need a random bit pattern
//! to pass all of that. Treat a hit as strong evidence, not proof.

use serde::Serialize;

use crate::bits::BitReader;

pub const EMDF_SYNC: u32 = 0x5838;

/// Payload IDs assigned in ETSI TS 103 420 (V1.2.1, §4.x / Annex). These
/// are the two an Atmos-in-DD+ stream is expected to carry.
pub const PAYLOAD_ID_OAMD: u32 = 11;
pub const PAYLOAD_ID_JOC: u32 = 14;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmdfPayload {
    pub id: u32,
    pub name: &'static str,
    pub size_bytes: u32,
    /// Bit offset of the payload bytes within the frame.
    pub bit_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmdfContainer {
    /// Bit offset of the sync word within the frame.
    pub bit_offset: usize,
    pub container_length_bytes: u32,
    pub version: u32,
    pub key_id: u32,
    pub payloads: Vec<EmdfPayload>,
}

pub fn payload_name(id: u32) -> &'static str {
    match id {
        PAYLOAD_ID_OAMD => "OAMD (object audio metadata)",
        PAYLOAD_ID_JOC => "JOC (joint object coding)",
        _ => "unknown",
    }
}

fn variable_bits(r: &mut BitReader, n: u32) -> Option<u32> {
    let mut value: u32 = 0;
    // Bounded: a legitimate field never needs more than a few extensions.
    for _ in 0..8 {
        value = value.checked_add(r.read(n)?)?;
        if !r.flag()? {
            return Some(value);
        }
        value = value.checked_shl(n)?.checked_add(1 << n)?;
    }
    None
}

fn payload_config(r: &mut BitReader) -> Option<()> {
    let smploffste = r.flag()?;
    if smploffste {
        r.skip(11 + 1)?;
    }
    if r.flag()? {
        variable_bits(r, 11)?; // duration
    }
    if r.flag()? {
        variable_bits(r, 2)?; // groupid
    }
    if r.flag()? {
        r.skip(8)?; // codecdata (reserved)
    }
    let discard_unknown_payload = r.flag()?;
    if !discard_unknown_payload {
        let mut payload_frame_aligned = false;
        if !smploffste {
            payload_frame_aligned = r.flag()?;
            if payload_frame_aligned {
                r.skip(2)?; // create_duplicate, remove_duplicate
            }
        }
        if smploffste || payload_frame_aligned {
            r.skip(5 + 2)?; // priority, proc_allowed
        }
    }
    Some(())
}

/// Tries to parse a container whose sync word starts at `bit`.
fn parse_at(frame: &[u8], bit: usize) -> Option<EmdfContainer> {
    let mut r = BitReader::at_bit(frame, bit);
    if r.read(16)? != EMDF_SYNC {
        return None;
    }
    let len = r.read(16)?;
    if len == 0 || (len as usize) * 8 > r.remaining() {
        return None;
    }
    let body_start = r.position();
    let body_end = body_start + len as usize * 8;

    let mut version = r.read(2)?;
    if version == 3 {
        version += variable_bits(&mut r, 2)?;
    }
    let mut key_id = r.read(3)?;
    if key_id == 7 {
        key_id += variable_bits(&mut r, 3)?;
    }
    let mut payloads = Vec::new();
    loop {
        let mut id = r.read(5)?;
        if id == 0 {
            break;
        }
        if id == 0x1F {
            id += variable_bits(&mut r, 5)?;
        }
        payload_config(&mut r)?;
        let size = variable_bits(&mut r, 8)?;
        let at = r.position();
        r.skip(size as usize * 8)?;
        if r.position() > body_end {
            return None;
        }
        payloads.push(EmdfPayload {
            id,
            name: payload_name(id),
            size_bytes: size,
            bit_offset: at,
        });
        if payloads.len() > 32 {
            return None;
        }
    }
    // emdf_protection: primary length code 0 is reserved.
    let prot_primary = r.read(2)?;
    let prot_secondary = r.read(2)?;
    if prot_primary == 0 {
        return None;
    }
    let bits = |code: u32| match code {
        0 => 0,
        1 => 8,
        2 => 32,
        _ => 128,
    };
    r.skip(bits(prot_primary) + bits(prot_secondary))?;
    if r.position() > body_end || payloads.is_empty() {
        return None;
    }
    Some(EmdfContainer {
        bit_offset: bit,
        container_length_bytes: len,
        version,
        key_id,
        payloads,
    })
}

/// Finds every EMDF container in one sync frame (frame bytes in bitstream
/// order, starting at the 0x0B77 sync word).
pub fn find_containers(frame: &[u8]) -> Vec<EmdfContainer> {
    let mut found = Vec::new();
    let total = frame.len() * 8;
    let mut bit = 16; // never inside the sync word itself
    while bit + 32 <= total {
        if let Some(c) = parse_at(frame, bit) {
            bit += 32 + c.container_length_bytes as usize * 8;
            found.push(c);
        } else {
            bit += 1;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Packs (value, width) fields MSB-first.
    fn pack(fields: &[(u32, u32)]) -> Vec<u8> {
        let mut bits = Vec::new();
        for &(v, n) in fields {
            for i in (0..n).rev() {
                bits.push((v >> i) & 1);
            }
        }
        while bits.len() % 8 != 0 {
            bits.push(0);
        }
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b as u8))
            .collect()
    }

    #[test]
    fn finds_a_synthetic_container_at_an_odd_bit_offset() {
        // version 0, key 0, one OAMD payload of 2 bytes with the minimal
        // config (all optional flags off, discard_unknown_payload = 1),
        // terminator, protection (primary code 1 = 8 bits, secondary 0).
        let body = pack(&[
            (0, 2),
            (0, 3),
            (PAYLOAD_ID_OAMD, 5),
            (0, 1), // smploffste
            (0, 1), // duratione
            (0, 1), // groupide
            (0, 1), // codecdatae
            (1, 1), // discard_unknown_payload
            (2, 8), // size (variable_bits(8), no extension)
            (0, 1),
            (0xAB, 8),
            (0xCD, 8),
            (0, 5), // terminator
            (1, 2),
            (0, 2),
            (0x5A, 8),
        ]);
        let mut fields = vec![
            (0x0B77, 16),
            (0, 3),
            (EMDF_SYNC, 16),
            (body.len() as u32, 16),
        ];
        fields.extend(body.iter().map(|&b| (u32::from(b), 8)));
        let frame = pack(&fields);
        let found = find_containers(&frame);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bit_offset, 19);
        assert_eq!(found[0].payloads.len(), 1);
        assert_eq!(found[0].payloads[0].id, PAYLOAD_ID_OAMD);
        assert_eq!(found[0].payloads[0].size_bytes, 2);
    }

    #[test]
    fn plain_noise_yields_nothing() {
        let frame: Vec<u8> = (0..2048u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        assert!(find_containers(&frame).is_empty());
    }
}
