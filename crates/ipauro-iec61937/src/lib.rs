//! IEC 61937 framing for compressed audio over IEC 60958 / HDMI — the transport
//! layer under "Dolby Atmos over HDMI" (W002).
//!
//! An IEC 61937 stream is a sequence of *data bursts* laid into what the link
//! believes are 16-bit PCM samples: an 8-byte preamble (`Pa Pb Pc Pd`), the
//! payload, and zero stuffing up to a fixed *repetition period*. The sink finds
//! the `Pa`/`Pb` sync words, reads the data type from `Pc`, and hands the
//! payload to the matching decoder.
//!
//! What this crate is, and is not:
//! - [`burst`]: the preamble and a no-allocation burst writer.
//! - [`packetize`]: AC-3, E-AC-3 and MAT(TrueHD) packetizers that reproduce
//!   FFmpeg's `spdif` muxer byte-for-byte (verified in `tests/ffmpeg_golden.rs`).
//!   The MAT packetizer wraps **pre-encoded TrueHD** access units in MAT
//!   frames. It is not a MAT 2.0 object-PCM encoder; nobody has publicly
//!   specified that payload yet (see W002 §3).
//! - [`ac3`], [`truehd`], [`mat`]: header parsing for the payloads, used by the
//!   packetizers and by the inspector.
//! - [`scan`]: finds bursts in a captured byte stream; this is the core of the
//!   `mat-inspect` analysis tool.
//!
//! Byte order: [`WordOrder::Le`] is what a little-endian S16 PCM device
//! buffer expects (FFmpeg's default `spdif` output). The payload bitstream is
//! big-endian, so every 16-bit word gets swapped on the way in.

pub mod ac3;
mod bits;
pub mod burst;
pub mod emdf;
pub mod mat;
pub mod packetize;
pub mod scan;
pub mod truehd;

pub use burst::{DataType, WordOrder};
