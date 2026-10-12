//! Golden tests: our packetizers vs FFmpeg 6.1.1's `spdif` muxer.
//!
//! The elementary-stream inputs are committed (tests/fixtures, regenerate with
//! gen.sh); FFmpeg's IEC 61937 outputs are pinned by SHA-256 in SHA256SUMS.
//! When `ffmpeg` is on PATH the reference is also regenerated live and diffed
//! byte-for-byte, which catches a stale hash file.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use ipauro_iec61937::burst::WordOrder;
use ipauro_iec61937::packetize::{Ac3Packetizer, Eac3Packetizer, MatPacketizer, Packetizer};
use ipauro_iec61937::scan::{self, Detail};
use ipauro_iec61937::{DataType, ac3, mat, truehd};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn pinned_sha(name: &str) -> String {
    let sums = std::fs::read_to_string(fixture("SHA256SUMS")).unwrap();
    sums.lines()
        .find_map(|l| {
            let (h, f) = l.split_once("  ")?;
            (f == name).then(|| h.to_string())
        })
        .unwrap_or_else(|| panic!("{name} not in SHA256SUMS"))
}

fn sha_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn run<'a>(p: &mut impl Packetizer, units: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let period = p.period_bytes();
    let mut out = Vec::new();
    for au in units {
        if let Some(b) = p.push(au).unwrap() {
            assert_eq!(b.len(), period);
            out.extend_from_slice(b);
        }
    }
    out
}

/// Regenerates FFmpeg's output live, if ffmpeg is installed.
fn ffmpeg_reference(demuxer: &str, input: &Path) -> Option<Vec<u8>> {
    let out = Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-f", demuxer, "-i"])
        .arg(input)
        .args(["-c", "copy", "-f", "spdif", "-"])
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn check(name: &str, demuxer: &str, ours: &[u8]) {
    let spdif = format!("{name}.spdif");
    assert_eq!(
        sha_hex(ours),
        pinned_sha(&spdif),
        "{spdif}: SHA-256 differs from pinned FFmpeg output"
    );
    if let Some(reference) = ffmpeg_reference(demuxer, &fixture(name)) {
        assert_eq!(
            ours.len(),
            reference.len(),
            "{spdif}: length differs from live FFmpeg"
        );
        if let Some(i) = ours.iter().zip(&reference).position(|(a, b)| a != b) {
            panic!("{spdif}: first byte difference vs live FFmpeg at offset {i}");
        }
    }
}

#[test]
fn truehd_mat_matches_ffmpeg() {
    let es = std::fs::read(fixture("tone.thd")).unwrap();
    let mut p = MatPacketizer::new(WordOrder::Le);
    let ours = run(&mut p, truehd::access_units(&es));
    assert_eq!(ours.len() % mat::MAT_PKT_OFFSET, 0);
    assert_eq!(p.timing_anomalies(), 0);
    check("tone.thd", "truehd", &ours);
}

#[test]
fn ac3_matches_ffmpeg() {
    let es = std::fs::read(fixture("tone.ac3")).unwrap();
    let ours = run(
        &mut Ac3Packetizer::new(WordOrder::Le),
        ac3::access_units(&es),
    );
    check("tone.ac3", "ac3", &ours);
}

#[test]
fn eac3_matches_ffmpeg() {
    let es = std::fs::read(fixture("tone.eac3")).unwrap();
    let ours = run(
        &mut Eac3Packetizer::new(WordOrder::Le),
        ac3::access_units(&es),
    );
    check("tone.eac3", "eac3", &ours);
}

#[test]
fn scan_round_trips_our_mat_output() {
    let es = std::fs::read(fixture("tone.thd")).unwrap();
    let stream = run(
        &mut MatPacketizer::new(WordOrder::Le),
        truehd::access_units(&es),
    );
    let report = scan::scan(&stream, WordOrder::Le, true);
    assert_eq!(report.bursts.len(), stream.len() / mat::MAT_PKT_OFFSET);
    assert_eq!(report.summary.junk_bytes, 0);
    assert_eq!(report.summary.mat_frames_unparsed, 0);
    assert_eq!(report.summary.mat_frames_with_foreign_codes, 0);
    let mut units = 0;
    for b in &report.bursts {
        assert_eq!(b.data_type, DataType::Mat);
        assert_eq!(b.payload_bytes, mat::MAT_FRAME_SIZE);
        if let Some(p) = b.period_bytes {
            assert_eq!(p, mat::MAT_PKT_OFFSET);
        }
        let Detail::Mat(m) = &b.detail else {
            panic!("not decoded as MAT")
        };
        units += m.truehd_units;
    }
    // 24 units per 20 ms frame, ± the unit straddling each frame boundary.
    let frames = report.bursts.len();
    assert!(
        units >= frames * 24 - frames && units <= frames * 25,
        "{units} units in {frames} frames"
    );
}

#[test]
fn scan_reads_eac3_headers() {
    let es = std::fs::read(fixture("tone.eac3")).unwrap();
    let stream = run(
        &mut Eac3Packetizer::new(WordOrder::Le),
        ac3::access_units(&es),
    );
    let report = scan::scan(&stream, scan::detect_word_order(&stream).unwrap(), true);
    assert!(!report.bursts.is_empty());
    for b in &report.bursts {
        assert_eq!(b.data_type, DataType::Eac3);
        let Detail::Ac3Family { frames } = &b.detail else {
            panic!()
        };
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].header.num_blocks, 6);
        assert_eq!(frames[0].header.channels, 6);
        // Plain FFmpeg E-AC-3 has no Atmos payloads.
        assert!(frames[0].emdf.is_empty());
    }
}

#[test]
fn big_endian_output_is_the_unswapped_twin() {
    let es = std::fs::read(fixture("tone.eac3")).unwrap();
    let le = run(
        &mut Eac3Packetizer::new(WordOrder::Le),
        ac3::access_units(&es),
    );
    let be = run(
        &mut Eac3Packetizer::new(WordOrder::Be),
        ac3::access_units(&es),
    );
    assert_eq!(le.len(), be.len());
    assert!(
        le.chunks(2)
            .zip(be.chunks(2))
            .all(|(l, b)| l[0] == b[1] && l[1] == b[0])
    );
}
