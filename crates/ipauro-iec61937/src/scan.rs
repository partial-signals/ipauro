//! Burst discovery and per-burst decoding over a captured IEC 61937 byte stream.
//!
//! Input is the raw byte stream a device would play: interleaved 16-bit
//! "samples" for any channel count (2 ch at 48/192 kHz, or 8 ch at 192 kHz for
//! HDMI HBR). Bursts start on 16-bit word boundaries, and the channel count
//! only matters for timing, so the scan works on the flat stream.

use serde::Serialize;

use crate::ac3::{self, SyncFrameHeader};
use crate::burst::{self, DataType, PREAMBLE_BYTES, Preamble, WordOrder};
use crate::emdf::{self, EmdfContainer};
use crate::mat::{self, CodeCheck, MAT_FRAME_SIZE};
use crate::truehd::{self, MajorSync};

#[derive(Debug, Clone, Serialize)]
pub struct BurstRecord {
    /// Byte offset of `Pa` in the stream.
    pub offset: usize,
    pub pc: u16,
    pub pd: u16,
    pub data_type: DataType,
    pub error_flag: bool,
    pub type_dependent: u8,
    pub bitstream_number: u8,
    pub payload_bytes: usize,
    /// Distance in bytes to the next burst's `Pa` (the observed repetition
    /// period), if there is a next burst.
    pub period_bytes: Option<usize>,
    pub detail: Detail,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detail {
    None,
    /// Payload runs past the end of the capture.
    Truncated,
    Ac3Family {
        frames: Vec<FrameInfo>,
    },
    Mat(MatInfo),
}

#[derive(Debug, Clone, Serialize)]
pub struct FrameInfo {
    pub header: SyncFrameHeader,
    pub emdf: Vec<EmdfContainer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatInfo {
    pub codes: CodeCheck,
    /// Zero bytes in the data area (timing padding + unused space).
    pub padding_bytes: usize,
    pub truehd_units: usize,
    pub first_input_timing: Option<u16>,
    pub last_input_timing: Option<u16>,
    /// Major syncs found in this frame's TrueHD units.
    pub major_syncs: Vec<MajorSync>,
    /// True when the data area did not parse as a clean sequence of TrueHD
    /// units: some other payload (e.g. MAT 2.0 PCM) or a layout this
    /// parser doesn't know.
    pub data_area_unparsed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub word_order: WordOrder,
    pub stream_bytes: usize,
    pub bursts: Vec<BurstRecord>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// `(data type, count)`, in first-seen order.
    pub by_type: Vec<(DataType, usize)>,
    /// `(period in bytes, count)`, sorted by period.
    pub periods: Vec<(usize, usize)>,
    pub error_flags: usize,
    pub truncated: usize,
    pub mat_frames_with_foreign_codes: usize,
    pub mat_frames_unparsed: usize,
    pub frames_with_emdf: usize,
    pub emdf_payload_ids: Vec<(u32, usize)>,
    pub truehd_atmos_flag_seen: bool,
    /// Bytes before the first burst plus bytes between bursts not accounted
    /// for by payload + stuffing (non-zero junk).
    pub junk_bytes: usize,
}

/// Guesses the word order by looking for the sync pair both ways.
pub fn detect_word_order(stream: &[u8]) -> Option<WordOrder> {
    let probe = &stream[..stream.len().min(1 << 20)];
    for at in (0..probe.len().saturating_sub(PREAMBLE_BYTES)).step_by(2) {
        for order in [WordOrder::Le, WordOrder::Be] {
            if burst::read_preamble(probe, at, order).is_some() {
                return Some(order);
            }
        }
    }
    None
}

pub fn scan(stream: &[u8], order: WordOrder, decode: bool) -> ScanReport {
    let mut bursts: Vec<BurstRecord> = Vec::new();
    let mut at = 0;
    let mut junk = 0;
    let mut payload = Vec::new();
    while at + PREAMBLE_BYTES <= stream.len() {
        let Some(pre) = burst::read_preamble(stream, at, order) else {
            if stream[at] != 0 || stream[at + 1] != 0 {
                junk += 2;
            }
            at += 2;
            continue;
        };
        let start = at + PREAMBLE_BYTES;
        let len = pre.payload_bytes();
        let detail = if start + len > stream.len() {
            Detail::Truncated
        } else if decode {
            burst::unswap_payload(&stream[start..], len, order, &mut payload);
            decode_payload(&pre, &payload)
        } else {
            Detail::None
        };
        if let Some(prev) = bursts.last_mut() {
            prev.period_bytes = Some(at - prev.offset);
        }
        bursts.push(BurstRecord {
            offset: at,
            pc: pre.pc,
            pd: pre.pd,
            data_type: pre.data_type(),
            error_flag: pre.error_flag(),
            type_dependent: pre.type_dependent(),
            bitstream_number: pre.bitstream_number(),
            payload_bytes: len,
            period_bytes: None,
            detail,
        });
        at = start + len.next_multiple_of(2);
    }
    let summary = summarize(&bursts, junk);
    ScanReport {
        word_order: order,
        stream_bytes: stream.len(),
        bursts,
        summary,
    }
}

fn decode_payload(pre: &Preamble, payload: &[u8]) -> Detail {
    match pre.data_type() {
        DataType::Ac3 | DataType::Eac3 => Detail::Ac3Family {
            frames: ac3::sync_frames(payload)
                .map(|(header, frame)| FrameInfo {
                    emdf: emdf::find_containers(frame),
                    header,
                })
                .collect(),
        },
        DataType::Mat if payload.len() >= MAT_FRAME_SIZE => Detail::Mat(decode_mat(payload)),
        _ => Detail::None,
    }
}

fn decode_mat(frame: &[u8]) -> MatInfo {
    let codes = mat::check_codes(frame).expect("length checked by caller");
    let mut area = Vec::with_capacity(MAT_FRAME_SIZE);
    mat::data_area(frame, &mut area);

    let mut info = MatInfo {
        codes,
        padding_bytes: 0,
        truehd_units: 0,
        first_input_timing: None,
        last_input_timing: None,
        major_syncs: Vec::new(),
        data_area_unparsed: false,
    };
    // Units are separated by zero padding; a unit header is never 0x0000
    // because its length field is ≥ 2 words. A unit may run off the end of
    // the area (it continues in the next MAT frame); that's normal.
    let mut i = 0;
    while i < area.len() {
        if area[i] == 0 {
            info.padding_bytes += 1;
            i += 1;
            continue;
        }
        let Some(h) = truehd::parse_au_header(&area[i..]) else {
            info.data_area_unparsed = true;
            break;
        };
        // An implausible length means this isn't a TrueHD unit boundary.
        if h.length_bytes > 8190 {
            info.data_area_unparsed = true;
            break;
        }
        info.truehd_units += 1;
        info.first_input_timing.get_or_insert(h.input_timing);
        info.last_input_timing = Some(h.input_timing);
        if let Some(ms) = truehd::parse_major_sync(&area[i..]) {
            info.major_syncs.push(ms);
        }
        i += h.length_bytes;
    }
    info
}

fn bump<K: PartialEq + Copy>(v: &mut Vec<(K, usize)>, k: K) {
    match v.iter_mut().find(|(key, _)| *key == k) {
        Some((_, n)) => *n += 1,
        None => v.push((k, 1)),
    }
}

fn summarize(bursts: &[BurstRecord], junk: usize) -> Summary {
    let mut s = Summary {
        junk_bytes: junk,
        ..Default::default()
    };
    for b in bursts {
        bump(&mut s.by_type, b.data_type);
        if let Some(p) = b.period_bytes {
            bump(&mut s.periods, p);
        }
        s.error_flags += usize::from(b.error_flag);
        match &b.detail {
            Detail::Truncated => s.truncated += 1,
            Detail::Ac3Family { frames } => {
                for f in frames {
                    if !f.emdf.is_empty() {
                        s.frames_with_emdf += 1;
                    }
                    for c in &f.emdf {
                        for p in &c.payloads {
                            bump(&mut s.emdf_payload_ids, p.id);
                        }
                    }
                }
            }
            Detail::Mat(m) => {
                if !(m.codes.start_matches && m.codes.middle_matches && m.codes.end_matches) {
                    s.mat_frames_with_foreign_codes += 1;
                }
                s.mat_frames_unparsed += usize::from(m.data_area_unparsed);
                s.truehd_atmos_flag_seen |=
                    m.major_syncs.iter().any(|ms| ms.atmos_16ch_presentation);
            }
            Detail::None => {}
        }
    }
    s.periods.sort_unstable();
    s
}
