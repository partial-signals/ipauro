//! The object-encoder contract: scene → one carrier frame.
//!
//! Real-time shape: the caller owns every buffer. [`ObjectEncoder::encode`]
//! takes borrowed audio and a preallocated output slice and returns the
//! number of bytes written, so an implementation needs no allocation, no
//! locks and no blocking on the audio thread. A transport-agnostic burst is
//! the output (an E-AC-3 sync frame or a MAT frame). IEC 61937 wrapping and
//! device I/O live in `ipauro-iec61937` / `ipauro-hdmi`.
//!
//! No carrier is implemented. [`Unimplemented`] exists so a pipeline can be
//! wired end-to-end and fail loudly, with the reason, at the one stage
//! that's missing. It never emits bytes.

use serde::Serialize;

use crate::coords::Vec3;

/// The bitstreams that can carry objects to a Dolby Atmos sink over HDMI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Carrier {
    /// E-AC-3 core + JOC + OAMD in EMDF (ETSI TS 102 366 + TS 103 420).
    Eac3Joc,
    /// MAT frames carrying object audio PCM + metadata ("MAT 2.0").
    MatObjectPcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ObjectState {
    pub id: u32,
    pub position: Vec3,
    /// Linear gain, 1.0 = unity.
    pub gain: f32,
    /// Extent 0..1 (0 = point source).
    pub size: f32,
}

/// One encoder frame's worth of scene.
pub struct ObjectBlock<'a> {
    /// Sample index of the first sample in this block.
    pub timestamp: u64,
    pub sample_rate: u32,
    /// Metadata, one entry per object, sampled at the start of the block.
    pub objects: &'a [ObjectState],
    /// Mono audio per object, aligned with `objects`; every slice has
    /// `frame_samples()` samples.
    pub audio: &'a [&'a [f32]],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("{carrier:?} encoder is not implemented: {reason}")]
    Unimplemented {
        carrier: Carrier,
        reason: &'static str,
    },
    #[error("{got} objects, encoder supports at most {max}")]
    TooManyObjects { got: usize, max: usize },
    #[error("block has {got} samples per object, encoder frame is {want}")]
    BlockLength { got: usize, want: usize },
    #[error("output buffer too small: need {need} bytes")]
    OutputTooSmall { need: usize },
}

pub trait ObjectEncoder {
    fn carrier(&self) -> Carrier;
    /// Samples per object per call.
    fn frame_samples(&self) -> usize;
    fn max_objects(&self) -> usize;
    /// Upper bound on bytes written per call, for sizing `out` once.
    fn max_frame_bytes(&self) -> usize;
    /// Encodes one block into `out`, returning the bytes written.
    fn encode(&mut self, block: &ObjectBlock, out: &mut [u8]) -> Result<usize, EncodeError>;
}

/// Placeholder encoder for a carrier that doesn't exist yet. Always errors.
pub struct Unimplemented(pub Carrier);

impl Unimplemented {
    pub fn reason(carrier: Carrier) -> &'static str {
        match carrier {
            Carrier::Eac3Joc => {
                "needs an E-AC-3 core encoder, a JOC analysis stage and an OAMD/EMDF writer \
                 (all specified in public ETSI documents), and certified decoders reportedly reject \
                 EMDF without a valid keyed protection field; see W002 §2 (H-A1) before building it"
            }
            Carrier::MatObjectPcm => {
                "the MAT object-PCM payload is undocumented. It needs captures from a licensed source \
                 (W002 §6), and the sink may require a source-side hash (CTA-861 MAT SAD bit 1, W002 H-A2)"
            }
        }
    }
}

impl ObjectEncoder for Unimplemented {
    fn carrier(&self) -> Carrier {
        self.0
    }
    fn frame_samples(&self) -> usize {
        match self.0 {
            Carrier::Eac3Joc => 1536,
            Carrier::MatObjectPcm => 960,
        }
    }
    fn max_objects(&self) -> usize {
        0
    }
    fn max_frame_bytes(&self) -> usize {
        0
    }
    fn encode(&mut self, _block: &ObjectBlock, _out: &mut [u8]) -> Result<usize, EncodeError> {
        Err(EncodeError::Unimplemented {
            carrier: self.0,
            reason: Self::reason(self.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unimplemented_never_writes() {
        let mut out = [0xAAu8; 64];
        let silence = [0.0f32; 1536];
        let audio: [&[f32]; 1] = [&silence];
        let objects = [ObjectState {
            id: 1,
            position: Vec3::FRONT_CENTER,
            gain: 1.0,
            size: 0.0,
        }];
        let block = ObjectBlock {
            timestamp: 0,
            sample_rate: 48000,
            objects: &objects,
            audio: &audio,
        };
        for c in [Carrier::Eac3Joc, Carrier::MatObjectPcm] {
            let err = Unimplemented(c).encode(&block, &mut out).unwrap_err();
            assert!(matches!(err, EncodeError::Unimplemented { carrier, .. } if carrier == c));
        }
        assert!(out.iter().all(|b| *b == 0xAA));
    }
}
