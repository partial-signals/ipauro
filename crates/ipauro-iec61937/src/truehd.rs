//! TrueHD (MLP) access units, as far as MAT framing and inspection need them.
//!
//! Every access unit starts with a 4-byte header: a 4-bit check nibble, a
//! 12-bit length in 16-bit words, and a 16-bit `input_timing` (the sample
//! clock at which the unit enters the decoder). Access units that open a
//! decodable point carry a *major sync* (`F8 72 6F BA` for TrueHD, `..BB` for
//! MLP) right after that header.
//!
//! Field layout follows FFmpeg's `ff_mlp_read_major_sync`
//! (libavcodec/mlp_parse.c), including how it detects the Atmos 16-channel
//! presentation (4 substreams and `substream_info` bit 7). That flag says a
//! TrueHD stream carries Atmos. It does not say anything about how the
//! objects are coded inside the 4th substream, which is undocumented.

use serde::Serialize;

use crate::bits::BitReader;

pub const MAJOR_SYNC_TRUEHD: u32 = 0xF872_6FBA;
pub const MAJOR_SYNC_MLP: u32 = 0xF872_6FBB;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AccessUnitHeader {
    pub check_nibble: u8,
    /// Total access-unit length in bytes.
    pub length_bytes: usize,
    pub input_timing: u16,
}

pub fn parse_au_header(buf: &[u8]) -> Option<AccessUnitHeader> {
    if buf.len() < 4 {
        return None;
    }
    let w0 = u16::from_be_bytes([buf[0], buf[1]]);
    let length_bytes = usize::from(w0 & 0x0fff) * 2;
    if length_bytes < 4 {
        return None;
    }
    Some(AccessUnitHeader {
        check_nibble: (w0 >> 12) as u8,
        length_bytes,
        input_timing: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// Splits a raw TrueHD elementary stream into access units.
pub fn access_units(stream: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let rest = stream.get(at..)?;
        let h = parse_au_header(rest)?;
        let au = rest.get(..h.length_bytes)?;
        at += h.length_bytes;
        Some(au)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MajorSync {
    /// 0xBA = TrueHD, 0xBB = MLP.
    pub stream_type: u8,
    pub ratebits: u8,
    pub sample_rate: u32,
    /// Samples per access unit at the base rate: 40 << (ratebits & 7).
    pub samples_per_au: u32,
    pub channel_arrangement: u16,
    pub is_vbr: bool,
    pub peak_data_rate_raw: u16,
    pub num_substreams: u8,
    pub extended_substream_info: u8,
    pub substream_info: u8,
    /// FFmpeg's Atmos test: TrueHD, 4 substreams, `substream_info` bit 7.
    pub atmos_16ch_presentation: bool,
}

fn mlp_samplerate(ratebits: u8) -> u32 {
    if ratebits == 0xF {
        return 0;
    }
    (if ratebits & 8 != 0 { 44100 } else { 48000 }) << (ratebits & 7)
}

/// Parses the major sync of an access unit (`au` starts at the AU header).
/// Returns `None` when the AU carries no major sync.
pub fn parse_major_sync(au: &[u8]) -> Option<MajorSync> {
    let ms = au.get(4..)?;
    if ms.len() < 28 {
        return None;
    }
    let sync = u32::from_be_bytes([ms[0], ms[1], ms[2], ms[3]]);
    if sync != MAJOR_SYNC_TRUEHD && sync != MAJOR_SYNC_MLP {
        return None;
    }
    let stream_type = ms[3];
    let mut r = BitReader::new(ms);
    r.skip(32)?;
    let (ratebits, channel_arrangement) = if stream_type == 0xBB {
        r.skip(8)?; // group1/group2 bits
        let rb = r.read(4)? as u8;
        r.skip(4 + 11)?;
        (rb, r.read(5)? as u16)
    } else {
        let rb = r.read(4)? as u8;
        r.skip(4 + 2 + 2)?;
        let ca = r.read(5)? as u16;
        r.skip(2 + 13)?;
        (rb, ca)
    };
    r.skip(48)?;
    let is_vbr = r.flag()?;
    let peak_data_rate_raw = r.read(15)? as u16;
    let num_substreams = r.read(4)? as u8;
    r.skip(2)?;
    let extended_substream_info = r.read(2)? as u8;
    let substream_info = r.read(8)? as u8;
    Some(MajorSync {
        stream_type,
        ratebits,
        sample_rate: mlp_samplerate(ratebits),
        samples_per_au: 40 << (ratebits & 7),
        channel_arrangement,
        is_vbr,
        peak_data_rate_raw,
        num_substreams,
        extended_substream_info,
        substream_info,
        atmos_16ch_presentation: stream_type == 0xBA
            && num_substreams == 4
            && substream_info >> 7 == 1,
    })
}
