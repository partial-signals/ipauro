//! Elementary-stream → IEC 61937 packetizers.
//!
//! Each packetizer takes one access unit per [`Packetizer::push`] and returns
//! a complete burst (exactly one repetition period of bytes) when one is
//! ready. All buffers are allocated once in `new()`, so `push` never
//! allocates and can run on a real-time thread. One `push` completes at most
//! one burst (an access unit plus its timing padding is always less than one
//! MAT frame), which is why the return type is an `Option`.
//!
//! Output matches FFmpeg 6.1's `spdif` muxer byte-for-byte for AC-3, E-AC-3
//! and TrueHD (tests/ffmpeg_golden.rs). [`MatPacketizer`] is a port of
//! `spdif_header_truehd` from FFmpeg's libavformat/spdifenc.c
//! (LGPL-2.1-or-later, © 2010, 2020 Anssi Hannula et al.); LGPL-2.1 §3 allows
//! it to be carried under this crate's GPL-3.0-or-later.

use crate::ac3;
use crate::burst::{self, BurstError, DataType, WordOrder};
use crate::mat::{CODES, MAT_FRAME_SIZE, MAT_PKT_OFFSET};
use crate::truehd;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PacketizeError {
    #[error("access unit too short ({0} bytes)")]
    TooShort(usize),
    #[error("bad AC-3/E-AC-3 header: {0}")]
    Header(#[from] ac3::HeaderError),
    #[error("TrueHD stream has not yet carried a major sync; frame timing unknown")]
    NoMajorSync,
    #[error("TrueHD major sync has unknown stream type 0x{0:02x}")]
    MajorSyncType(u8),
    #[error("accumulated E-AC-3 payload {have} bytes exceeds burst capacity {cap}")]
    Overflow { have: usize, cap: usize },
    #[error(transparent)]
    Burst(#[from] BurstError),
}

pub trait Packetizer {
    fn data_type(&self) -> DataType;
    /// Repetition period of every emitted burst, in bytes.
    fn period_bytes(&self) -> usize;
    /// Feeds one access unit. Returns the completed burst, if this unit
    /// completed one. The slice borrows the packetizer's output buffer.
    fn push(&mut self, au: &[u8]) -> Result<Option<&[u8]>, PacketizeError>;
}

/// AC-3: one sync frame per burst, period 1536 frames (6144 bytes).
pub struct Ac3Packetizer {
    order: WordOrder,
    out: Vec<u8>,
}

impl Ac3Packetizer {
    pub const PERIOD: usize = 1536 * 4;

    pub fn new(order: WordOrder) -> Self {
        Self {
            order,
            out: vec![0; Self::PERIOD],
        }
    }
}

impl Packetizer for Ac3Packetizer {
    fn data_type(&self) -> DataType {
        DataType::Ac3
    }
    fn period_bytes(&self) -> usize {
        Self::PERIOD
    }
    fn push(&mut self, au: &[u8]) -> Result<Option<&[u8]>, PacketizeError> {
        if au.len() < 6 {
            return Err(PacketizeError::TooShort(au.len()));
        }
        let bsmod = u16::from(au[5] & 0x7);
        let pc = u16::from(DataType::Ac3.bits()) | (bsmod << 8);
        // Pd counts bits, rounded up to whole 16-bit words.
        let pd = (au.len().next_multiple_of(2) << 3) as u16;
        burst::write_burst(&mut self.out, pc, pd, au, self.order)?;
        Ok(Some(&self.out))
    }
}

/// E-AC-3: access units are concatenated until they add up to 6 audio blocks
/// (1536 samples), then sent as one burst, period 6144 frames (24576 bytes).
pub struct Eac3Packetizer {
    order: WordOrder,
    acc: Vec<u8>,
    acc_len: usize,
    acc_count: u8,
    out: Vec<u8>,
}

impl Eac3Packetizer {
    pub const PERIOD: usize = 6144 * 4;
    const CAP: usize = Self::PERIOD - burst::PREAMBLE_BYTES;

    pub fn new(order: WordOrder) -> Self {
        Self {
            order,
            acc: vec![0; Self::CAP],
            acc_len: 0,
            acc_count: 0,
            out: vec![0; Self::PERIOD],
        }
    }
}

impl Packetizer for Eac3Packetizer {
    fn data_type(&self) -> DataType {
        DataType::Eac3
    }
    fn period_bytes(&self) -> usize {
        Self::PERIOD
    }
    fn push(&mut self, au: &[u8]) -> Result<Option<&[u8]>, PacketizeError> {
        if au.len() < 6 {
            return Err(PacketizeError::TooShort(au.len()));
        }
        // Same rule as FFmpeg: E-AC-3 proper (bsid > 10) at a full sample
        // rate (fscod != 3) repeats 6/3/2/1 units per burst for
        // numblkscod 0/1/2/3. Everything else is one unit per burst.
        const REPEAT: [u8; 4] = [6, 3, 2, 1];
        let bsid = au[5] >> 3;
        let repeat = if bsid > 10 && au[4] & 0xC0 != 0xC0 {
            REPEAT[usize::from((au[4] & 0x30) >> 4)]
        } else {
            1
        };
        let have = self.acc_len + au.len();
        if have > Self::CAP {
            self.acc_len = 0;
            self.acc_count = 0;
            return Err(PacketizeError::Overflow {
                have,
                cap: Self::CAP,
            });
        }
        self.acc[self.acc_len..have].copy_from_slice(au);
        self.acc_len = have;
        self.acc_count += 1;
        if self.acc_count < repeat {
            return Ok(None);
        }
        let pc = u16::from(DataType::Eac3.bits());
        let pd = self.acc_len as u16; // bytes
        let len = self.acc_len;
        self.acc_len = 0;
        self.acc_count = 0;
        burst::write_burst(&mut self.out, pc, pd, &self.acc[..len], self.order)?;
        Ok(Some(&self.out))
    }
}

/// TrueHD access units → MAT frames → type-22 bursts, period 61440 bytes.
///
/// Padding comes from `input_timing`: a 1/1200 s access unit nominally owns
/// 2560 bytes of the 768 kHz × 4-byte link, so each unit is preceded by
/// enough zeros to keep data on schedule. The MAT codes count toward that
/// padding.
pub struct MatPacketizer {
    order: WordOrder,
    frame: Vec<u8>,
    filled: usize,
    prev_time: u16,
    /// Previous unit's size including any MAT codes it absorbed (0 = none yet).
    prev_size: usize,
    samples_per_au: u32,
    timing_anomalies: u64,
    out: Vec<u8>,
}

impl MatPacketizer {
    pub fn new(order: WordOrder) -> Self {
        Self {
            order,
            frame: vec![0; MAT_FRAME_SIZE],
            filled: 0,
            prev_time: 0,
            prev_size: 0,
            samples_per_au: 0,
            timing_anomalies: 0,
            out: vec![0; MAT_PKT_OFFSET],
        }
    }

    /// Count of units whose `input_timing` implied negative or excessive
    /// padding (FFmpeg logs "Unusual frame timing" and pads zero).
    pub fn timing_anomalies(&self) -> u64 {
        self.timing_anomalies
    }
}

impl Packetizer for MatPacketizer {
    fn data_type(&self) -> DataType {
        DataType::Mat
    }
    fn period_bytes(&self) -> usize {
        MAT_PKT_OFFSET
    }
    fn push(&mut self, au: &[u8]) -> Result<Option<&[u8]>, PacketizeError> {
        if au.len() < 10 {
            return Err(PacketizeError::TooShort(au.len()));
        }
        if u32::from_be_bytes([0, au[4], au[5], au[6]]) == 0x00F8_726F {
            let ratebits = match au[7] {
                0xBA => au[8] >> 4,
                0xBB => au[9] >> 4,
                t => return Err(PacketizeError::MajorSyncType(t)),
            };
            self.samples_per_au = 40 << (ratebits & 3);
        }
        if self.samples_per_au == 0 {
            return Err(PacketizeError::NoMajorSync);
        }
        let header = truehd::parse_au_header(au).ok_or(PacketizeError::TooShort(au.len()))?;
        let input_timing = header.input_timing;

        let mut padding = 0usize;
        if self.prev_size != 0 {
            let delta_samples = u32::from(input_timing.wrapping_sub(self.prev_time));
            let delta_bytes = (delta_samples * 2560 / self.samples_per_au) as i64;
            let p = delta_bytes - self.prev_size as i64;
            if p < 0 || p >= (MAT_FRAME_SIZE / 2) as i64 {
                self.timing_anomalies += 1;
            } else {
                padding = p as usize;
            }
        }

        let mut total_size = au.len();
        let mut data = au;
        let mut next = CODES
            .iter()
            .position(|(pos, _)| self.filled <= *pos)
            .expect("fill position never passes the end code");
        let mut emitted = false;

        while padding > 0 || !data.is_empty() || CODES[next].0 == self.filled {
            if CODES[next].0 == self.filled {
                let code = CODES[next].1;
                self.frame[self.filled..self.filled + code.len()].copy_from_slice(code);
                self.filled += code.len();
                let mut code_remaining = code.len();
                next += 1;
                if next == CODES.len() {
                    next = 0;
                    burst::write_burst(
                        &mut self.out,
                        u16::from(DataType::Mat.bits()),
                        MAT_FRAME_SIZE as u16,
                        &self.frame,
                        self.order,
                    )?;
                    emitted = true;
                    self.filled = 0;
                    // The inter-frame stuffing counts as well.
                    code_remaining += MAT_PKT_OFFSET - MAT_FRAME_SIZE;
                }
                if padding > 0 {
                    let as_padding = padding.min(code_remaining);
                    padding -= as_padding;
                    code_remaining -= as_padding;
                }
                total_size += code_remaining;
            }

            if padding > 0 {
                let n = (CODES[next].0 - self.filled).min(padding);
                self.frame[self.filled..self.filled + n].fill(0);
                self.filled += n;
                padding -= n;
                if padding > 0 {
                    continue; // reached a code slot
                }
            }

            if !data.is_empty() {
                let n = (CODES[next].0 - self.filled).min(data.len());
                self.frame[self.filled..self.filled + n].copy_from_slice(&data[..n]);
                self.filled += n;
                data = &data[n..];
            }
        }

        self.prev_size = total_size;
        self.prev_time = input_timing;
        Ok(emitted.then_some(&self.out[..]))
    }
}
