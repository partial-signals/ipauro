//! AC-3 / E-AC-3 sync-frame headers (ETSI TS 102 366), as far as framing and
//! inspection need them.
//!
//! The bsid read-ahead picks the dialect: bsid ≤ 10 is AC-3, 11..=16 is
//! E-AC-3. E-AC-3 is the carrier for Dolby Atmos-in-DD+, where the object
//! payload (JOC + OAMD, ETSI TS 103 420) travels in EMDF containers inside
//! otherwise ordinary frames; see [`crate::emdf`].

use serde::Serialize;

use crate::bits::BitReader;

pub const SYNC_WORD: u16 = 0x0B77;
const SAMPLE_RATES: [u32; 3] = [48000, 44100, 32000];
const AC3_BITRATES_KBPS: [u32; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];
const EAC3_BLOCKS: [u8; 4] = [1, 2, 3, 6];
const ACMOD_CHANNELS: [u8; 8] = [2, 1, 2, 3, 3, 4, 4, 5];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Dialect {
    Ac3,
    Eac3,
}

/// E-AC-3 `strmtyp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StreamType {
    Independent,
    Dependent,
    /// AC-3 converted to E-AC-3 framing (strmtyp 2); treated as independent.
    Ac3Convert,
    Reserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncFrameHeader {
    pub dialect: Dialect,
    pub bsid: u8,
    /// Total sync-frame length in bytes, including the sync word.
    pub frame_bytes: usize,
    pub sample_rate: u32,
    /// Audio blocks of 256 samples in this frame (always 6 for AC-3).
    pub num_blocks: u8,
    pub acmod: u8,
    pub lfe: bool,
    /// Full-bandwidth channels + LFE.
    pub channels: u8,
    /// AC-3 only: bitstream mode (goes into IEC 61937 Pc bits 8..=10).
    pub bsmod: Option<u8>,
    /// E-AC-3 only.
    pub stream_type: Option<StreamType>,
    /// E-AC-3 only.
    pub substream_id: Option<u8>,
}

impl SyncFrameHeader {
    /// True for the frame that starts an E-AC-3 access unit (independent
    /// substream 0) and for every AC-3 frame.
    pub fn starts_access_unit(&self) -> bool {
        match self.dialect {
            Dialect::Ac3 => true,
            Dialect::Eac3 => {
                matches!(
                    self.stream_type,
                    Some(StreamType::Independent | StreamType::Ac3Convert)
                ) && self.substream_id == Some(0)
            }
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HeaderError {
    #[error("buffer too short for an AC-3/E-AC-3 header")]
    Truncated,
    #[error("no 0x0B77 sync word")]
    NoSync,
    #[error("unsupported bsid {0}")]
    Bsid(u8),
    #[error("reserved sample-rate code")]
    SampleRate,
    #[error("invalid frame size code")]
    FrameSize,
}

pub fn parse_header(buf: &[u8]) -> Result<SyncFrameHeader, HeaderError> {
    if buf.len() < 7 {
        return Err(HeaderError::Truncated);
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != SYNC_WORD {
        return Err(HeaderError::NoSync);
    }
    let bsid = buf[5] >> 3;
    let mut r = BitReader::new(buf);
    r.skip(16).ok_or(HeaderError::Truncated)?;
    match bsid {
        0..=10 => {
            r.skip(16).ok_or(HeaderError::Truncated)?; // crc1
            let fscod = r.read(2).ok_or(HeaderError::Truncated)? as usize;
            if fscod == 3 {
                return Err(HeaderError::SampleRate);
            }
            let frmsizecod = r.read(6).ok_or(HeaderError::Truncated)?;
            if frmsizecod > 37 {
                return Err(HeaderError::FrameSize);
            }
            r.skip(5).ok_or(HeaderError::Truncated)?; // bsid
            let bsmod = r.read(3).ok_or(HeaderError::Truncated)? as u8;
            let acmod = r.read(3).ok_or(HeaderError::Truncated)? as u8;
            if acmod == 2 {
                r.skip(2).ok_or(HeaderError::Truncated)?; // dsurmod
            } else {
                if acmod & 1 != 0 && acmod != 1 {
                    r.skip(2).ok_or(HeaderError::Truncated)?; // cmixlev
                }
                if acmod & 4 != 0 {
                    r.skip(2).ok_or(HeaderError::Truncated)?; // surmixlev
                }
            }
            let lfe = r.flag().ok_or(HeaderError::Truncated)?;
            let kbps = AC3_BITRATES_KBPS[(frmsizecod >> 1) as usize];
            let words = match fscod {
                0 => 2 * kbps,
                1 => 320 * kbps / 147 + (frmsizecod & 1),
                _ => 3 * kbps,
            };
            Ok(SyncFrameHeader {
                dialect: Dialect::Ac3,
                bsid,
                frame_bytes: words as usize * 2,
                sample_rate: SAMPLE_RATES[fscod] >> (bsid.max(8) - 8),
                num_blocks: 6,
                acmod,
                lfe,
                channels: ACMOD_CHANNELS[acmod as usize] + u8::from(lfe),
                bsmod: Some(bsmod),
                stream_type: None,
                substream_id: None,
            })
        }
        11..=16 => {
            let strmtyp = match r.read(2).ok_or(HeaderError::Truncated)? {
                0 => StreamType::Independent,
                1 => StreamType::Dependent,
                2 => StreamType::Ac3Convert,
                _ => StreamType::Reserved,
            };
            let substream_id = r.read(3).ok_or(HeaderError::Truncated)? as u8;
            let frmsiz = r.read(11).ok_or(HeaderError::Truncated)? as usize;
            let fscod = r.read(2).ok_or(HeaderError::Truncated)? as usize;
            let (sample_rate, num_blocks) = if fscod == 3 {
                let fscod2 = r.read(2).ok_or(HeaderError::Truncated)? as usize;
                if fscod2 == 3 {
                    return Err(HeaderError::SampleRate);
                }
                (SAMPLE_RATES[fscod2] / 2, 6)
            } else {
                let numblkscod = r.read(2).ok_or(HeaderError::Truncated)? as usize;
                (SAMPLE_RATES[fscod], EAC3_BLOCKS[numblkscod])
            };
            let acmod = r.read(3).ok_or(HeaderError::Truncated)? as u8;
            let lfe = r.flag().ok_or(HeaderError::Truncated)?;
            Ok(SyncFrameHeader {
                dialect: Dialect::Eac3,
                bsid,
                frame_bytes: (frmsiz + 1) * 2,
                sample_rate,
                num_blocks,
                acmod,
                lfe,
                channels: ACMOD_CHANNELS[acmod as usize] + u8::from(lfe),
                bsmod: None,
                stream_type: Some(strmtyp),
                substream_id: Some(substream_id),
            })
        }
        other => Err(HeaderError::Bsid(other)),
    }
}

/// Splits a concatenated AC-3/E-AC-3 elementary stream into sync frames.
/// Stops at the first byte that doesn't parse as a header, or at a truncated
/// final frame.
pub fn sync_frames(stream: &[u8]) -> impl Iterator<Item = (SyncFrameHeader, &[u8])> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let rest = stream.get(at..)?;
        let h = parse_header(rest).ok()?;
        let frame = rest.get(..h.frame_bytes)?;
        at += h.frame_bytes;
        Some((h, frame))
    })
}

/// Groups sync frames into access units: for E-AC-3, one independent
/// substream-0 frame plus the dependent/extra substreams that follow it;
/// for AC-3, one frame. This is the unit FFmpeg's parser hands the `spdif`
/// muxer, and the unit [`crate::packetize::Eac3Packetizer`] takes.
pub fn access_units(stream: &[u8]) -> impl Iterator<Item = &[u8]> {
    let frames: Vec<(SyncFrameHeader, std::ops::Range<usize>)> = {
        let mut v = Vec::new();
        let mut at = 0;
        for (h, f) in sync_frames(stream) {
            v.push((h, at..at + f.len()));
            at += f.len();
        }
        v
    };
    let mut i = 0;
    std::iter::from_fn(move || {
        if i >= frames.len() {
            return None;
        }
        let start = frames[i].1.start;
        let mut end = frames[i].1.end;
        i += 1;
        while i < frames.len() && !frames[i].0.starts_access_unit() {
            end = frames[i].1.end;
            i += 1;
        }
        Some(&stream[start..end])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ac3_frame_size_formula_matches_spec_table_corners() {
        // (fscod, frmsizecod) -> words, from ETSI TS 102 366 Table 4.13.
        let cases = [
            ((0, 0), 64),
            ((1, 0), 69),
            ((1, 1), 70),
            ((2, 0), 96),
            ((1, 37), 1394),
        ];
        for ((fscod, code), words) in cases {
            let kbps = AC3_BITRATES_KBPS[code >> 1];
            let got = match fscod {
                0 => 2 * kbps,
                1 => 320 * kbps / 147 + (code as u32 & 1),
                _ => 3 * kbps,
            };
            assert_eq!(got, words, "fscod {fscod} code {code}");
        }
    }
}
