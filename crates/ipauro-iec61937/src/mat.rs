//! MAT frame layout as FFmpeg's `spdif` muxer emits it for TrueHD.
//!
//! A MAT frame is 61424 bytes inside a 61440-byte burst (8-byte preamble and
//! 8 bytes of stuffing): 20 ms at the 768 kHz HBR rate, which is 24 TrueHD
//! access units at 48 kHz. Three fixed byte strings sit at fixed offsets:
//! a start code at 0, a middle code at 30708, and an end code in the last 16
//! bytes. TrueHD data fills the gaps, and zero padding fills whatever the
//! access units' `input_timing` leaves unused.
//!
//! **Provenance and limits.** The codes and offsets are constants copied from
//! FFmpeg (libavformat/spdifenc.c, LGPL-2.1-or-later; the comment there reads
//! "It seems Dolby TrueHD frames have to be encapsulated in MAT frames"). They
//! are empirical, not taken from a spec. Nothing public says which bits of the
//! start code encode the MAT version or the payload type, so this module does
//! **not** assume MAT 2.0 PCM/object frames use the same codes. Comparing
//! these constants against captured MAT 2.0 frames is experiment E-M2 in
//! W002.

use serde::Serialize;

/// Burst repetition period for MAT, in bytes (15360 IEC 60958 frames).
pub const MAT_PKT_OFFSET: usize = 61440;
/// MAT frame length (= IEC 61937 Pd for data type 22), in bytes.
pub const MAT_FRAME_SIZE: usize = 61424;

pub const START_CODE: [u8; 20] = [
    0x07, 0x9E, 0x00, 0x03, 0x84, 0x01, 0x01, 0x01, 0x80, 0x00, 0x56, 0xA5, 0x3B, 0xF4, 0x81, 0x83,
    0x49, 0x80, 0x77, 0xE0,
];
pub const MIDDLE_CODE: [u8; 12] = [
    0xC3, 0xC1, 0x42, 0x49, 0x3B, 0xFA, 0x82, 0x83, 0x49, 0x80, 0x77, 0xE0,
];
pub const END_CODE: [u8; 16] = [
    0xC3, 0xC2, 0xC0, 0xC4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x11,
];

pub const START_POS: usize = 0;
pub const MIDDLE_POS: usize = 30708;
pub const END_POS: usize = MAT_FRAME_SIZE - END_CODE.len();

/// The three codes in frame order: `(position, bytes)`.
pub const CODES: [(usize, &[u8]); 3] = [
    (START_POS, &START_CODE),
    (MIDDLE_POS, &MIDDLE_CODE),
    (END_POS, &END_CODE),
];

/// What a MAT frame's fixed code slots contain, compared to FFmpeg's constants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeCheck {
    pub start_matches: bool,
    pub middle_matches: bool,
    pub end_matches: bool,
    /// The bytes actually found in the start-code slot, hex. Kept even when
    /// they match, so captures from different encoders can be diffed.
    pub start_slot_hex: String,
}

/// Checks the three code slots of a MAT frame (payload already in bitstream
/// order, i.e. un-swapped).
pub fn check_codes(frame: &[u8]) -> Option<CodeCheck> {
    if frame.len() < MAT_FRAME_SIZE {
        return None;
    }
    let slot = |pos: usize, code: &[u8]| &frame[pos..pos + code.len()] == code;
    Some(CodeCheck {
        start_matches: slot(START_POS, &START_CODE),
        middle_matches: slot(MIDDLE_POS, &MIDDLE_CODE),
        end_matches: slot(END_POS, &END_CODE),
        start_slot_hex: hex(&frame[..START_CODE.len()]),
    })
}

/// Removes the code slots, returning the data area (TrueHD units + padding)
/// as one contiguous byte string. Only meaningful for FFmpeg-layout frames.
pub fn data_area(frame: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&frame[START_CODE.len()..MIDDLE_POS]);
    out.extend_from_slice(&frame[MIDDLE_POS + MIDDLE_CODE.len()..END_POS]);
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
