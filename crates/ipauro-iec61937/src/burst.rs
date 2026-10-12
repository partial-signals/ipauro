//! The IEC 61937 data-burst preamble and a no-allocation burst writer.
//!
//! Preamble words (IEC 61937-1):
//! - `Pa` = 0xF872, `Pb` = 0x4E1F: sync.
//! - `Pc` = burst-info: data type (bits 0..=6), error flag (bit 7),
//!   data-type-dependent info (bits 8..=12), bitstream number (bits 13..=15).
//! - `Pd` = length code. The unit depends on the data type: **bits** for AC-3
//!   (and most legacy types), **bytes** for E-AC-3 and MAT.

use serde::Serialize;

pub const PA: u16 = 0xF872;
pub const PB: u16 = 0x4E1F;
pub const PREAMBLE_BYTES: usize = 8;

/// Byte order of the 16-bit words in the output byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WordOrder {
    /// Little-endian 16-bit words: the layout an S16LE PCM device buffer
    /// expects. This is FFmpeg's default `spdif` output.
    Le,
    /// Big-endian 16-bit words (FFmpeg `-spdif_flags be`).
    Be,
}

/// The `Pc` data-type field (bits 0..=6).
///
/// Only the types this project touches get names. Everything else round-trips
/// through [`DataType::Other`], so a scan never drops a burst it can't name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum DataType {
    /// 0: NULL data burst.
    Null,
    /// 1: AC-3 (IEC 61937-3). Pd in bits. Repetition period 1536 frames.
    Ac3,
    /// 3: Pause burst.
    Pause,
    /// 11/12/13: DTS type I/II/III.
    Dts(u8),
    /// 17: DTS type IV (DTS-HD).
    DtsHd,
    /// 21: E-AC-3 (IEC 61937-3). Pd in bytes. Repetition period 6144 frames
    /// (4× AC-3, so a 48 kHz stream rides a 192 kHz 2-ch link).
    Eac3,
    /// 22: MAT (IEC 61937-9). FFmpeg calls this `IEC61937_TRUEHD`; the
    /// payload is a MAT frame, which may carry TrueHD access units (MAT 1.0
    /// style, what FFmpeg emits) or, per CTA-861, MAT 2.0 PCM/object audio.
    /// Pd in bytes. Repetition period 15360 frames at the 768 kHz HBR rate.
    Mat,
    /// Any other value of bits 0..=6.
    Other(u8),
}

impl DataType {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x7f {
            0 => DataType::Null,
            1 => DataType::Ac3,
            3 => DataType::Pause,
            v @ (11..=13) => DataType::Dts(v),
            17 => DataType::DtsHd,
            21 => DataType::Eac3,
            22 => DataType::Mat,
            v => DataType::Other(v),
        }
    }

    pub fn bits(self) -> u8 {
        match self {
            DataType::Null => 0,
            DataType::Ac3 => 1,
            DataType::Pause => 3,
            DataType::Dts(v) => v,
            DataType::DtsHd => 17,
            DataType::Eac3 => 21,
            DataType::Mat => 22,
            DataType::Other(v) => v & 0x7f,
        }
    }

    /// Whether `Pd` counts bits (true) or bytes (false) for this type.
    pub fn length_in_bits(self) -> bool {
        !matches!(self, DataType::Eac3 | DataType::Mat | DataType::DtsHd)
    }

    /// Nominal burst repetition period in IEC 60958 frames (4 bytes each),
    /// where the type fixes one. DTS periods depend on the stream, so `None`.
    pub fn repetition_period_frames(self) -> Option<usize> {
        match self {
            DataType::Ac3 => Some(1536),
            DataType::Eac3 => Some(6144),
            DataType::Mat => Some(15360),
            _ => None,
        }
    }
}

/// A decoded burst preamble.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Preamble {
    pub pc: u16,
    pub pd: u16,
}

impl Preamble {
    pub fn data_type(&self) -> DataType {
        DataType::from_bits((self.pc & 0x7f) as u8)
    }
    pub fn error_flag(&self) -> bool {
        self.pc & 0x80 != 0
    }
    pub fn type_dependent(&self) -> u8 {
        ((self.pc >> 8) & 0x1f) as u8
    }
    pub fn bitstream_number(&self) -> u8 {
        (self.pc >> 13) as u8
    }
    /// Payload length in bytes, converting from bits where the type says so.
    pub fn payload_bytes(&self) -> usize {
        if self.data_type().length_in_bits() {
            (self.pd as usize).div_ceil(8)
        } else {
            self.pd as usize
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BurstError {
    #[error("payload of {payload} bytes does not fit a {period}-byte repetition period")]
    TooLarge { payload: usize, period: usize },
    #[error("repetition period {0} is not a positive multiple of 4 bytes")]
    BadPeriod(usize),
}

#[inline]
pub(crate) fn put16(out: &mut [u8], at: usize, v: u16, order: WordOrder) {
    let b = match order {
        WordOrder::Le => v.to_le_bytes(),
        WordOrder::Be => v.to_be_bytes(),
    };
    out[at] = b[0];
    out[at + 1] = b[1];
}

#[inline]
pub(crate) fn get16(buf: &[u8], at: usize, order: WordOrder) -> u16 {
    let b = [buf[at], buf[at + 1]];
    match order {
        WordOrder::Le => u16::from_le_bytes(b),
        WordOrder::Be => u16::from_be_bytes(b),
    }
}

/// Writes one complete data burst into `out`. `out.len()` is the repetition
/// period in bytes; whatever the payload doesn't use is zero stuffing.
///
/// `payload` is the big-endian bitstream as the codec produced it. An odd
/// final byte goes MSB-aligned into its own 16-bit word, as FFmpeg does.
/// Never allocates: this is the primitive a real-time callback calls.
pub fn write_burst(
    out: &mut [u8],
    pc: u16,
    pd: u16,
    payload: &[u8],
    order: WordOrder,
) -> Result<(), BurstError> {
    let period = out.len();
    if period == 0 || !period.is_multiple_of(4) {
        return Err(BurstError::BadPeriod(period));
    }
    let padded = payload.len().next_multiple_of(2);
    if PREAMBLE_BYTES + padded > period {
        return Err(BurstError::TooLarge {
            payload: payload.len(),
            period,
        });
    }
    put16(out, 0, PA, order);
    put16(out, 2, PB, order);
    put16(out, 4, pc, order);
    put16(out, 6, pd, order);

    let body = &mut out[PREAMBLE_BYTES..];
    let pairs = payload.len() / 2;
    match order {
        WordOrder::Be => body[..pairs * 2].copy_from_slice(&payload[..pairs * 2]),
        WordOrder::Le => {
            for i in 0..pairs {
                body[2 * i] = payload[2 * i + 1];
                body[2 * i + 1] = payload[2 * i];
            }
        }
    }
    let mut used = pairs * 2;
    if payload.len() % 2 == 1 {
        let last = u16::from(payload[payload.len() - 1]) << 8;
        put16(body, used, last, order);
        used += 2;
    }
    body[used..].fill(0);
    Ok(())
}

/// Reads a preamble at `at`, if the sync words are there.
pub fn read_preamble(buf: &[u8], at: usize, order: WordOrder) -> Option<Preamble> {
    if at + PREAMBLE_BYTES > buf.len() {
        return None;
    }
    if get16(buf, at, order) != PA || get16(buf, at + 2, order) != PB {
        return None;
    }
    Some(Preamble {
        pc: get16(buf, at + 4, order),
        pd: get16(buf, at + 6, order),
    })
}

/// Undoes the per-word swap of [`write_burst`]: copies a payload of `len`
/// bytes from burst-order `src` back into the codec's bitstream order.
pub fn unswap_payload(src: &[u8], len: usize, order: WordOrder, dst: &mut Vec<u8>) {
    dst.clear();
    let len = len.min(src.len());
    match order {
        WordOrder::Be => dst.extend_from_slice(&src[..len]),
        WordOrder::Le => {
            let words = len.div_ceil(2);
            for i in 0..words {
                let hi = src.get(2 * i + 1).copied().unwrap_or(0);
                let lo = src.get(2 * i).copied().unwrap_or(0);
                dst.push(hi);
                if dst.len() < len {
                    dst.push(lo);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_layout_le_matches_ffmpeg_convention() {
        let mut out = [0xAAu8; 16];
        write_burst(&mut out, 0x0001, 24, &[0x0B, 0x77, 0x12], WordOrder::Le).unwrap();
        assert_eq!(
            out,
            [
                0x72, 0xF8, 0x1F, 0x4E, 0x01, 0x00, 0x18, 0x00, // Pa Pb Pc Pd
                0x77, 0x0B, 0x00, 0x12, // swapped pair, lone byte MSB-aligned
                0, 0, 0, 0, // stuffing
            ]
        );
        let p = read_preamble(&out, 0, WordOrder::Le).unwrap();
        assert_eq!(p.data_type(), DataType::Ac3);
        assert_eq!(p.payload_bytes(), 3);
        let mut back = Vec::new();
        unswap_payload(&out[8..], 3, WordOrder::Le, &mut back);
        assert_eq!(back, [0x0B, 0x77, 0x12]);
    }

    #[test]
    fn burst_layout_be_is_unswapped() {
        let mut out = [0u8; 12];
        write_burst(&mut out, 0x0015, 2, &[0x0B, 0x77], WordOrder::Be).unwrap();
        assert_eq!(
            &out[..10],
            &[0xF8, 0x72, 0x4E, 0x1F, 0x00, 0x15, 0x00, 0x02, 0x0B, 0x77]
        );
    }

    #[test]
    fn oversize_payload_is_rejected() {
        let mut out = [0u8; 12];
        assert_eq!(
            write_burst(&mut out, 1, 0, &[0; 5], WordOrder::Le),
            Err(BurstError::TooLarge {
                payload: 5,
                period: 12
            })
        );
    }

    #[test]
    fn data_type_round_trips() {
        for v in 0..=0x7f {
            assert_eq!(DataType::from_bits(v).bits(), v);
        }
    }
}
