//! SAD flag decoding vs `edid-decode` (linuxtv), used as an oracle.
//!
//! The fixtures are synthetic (tests/fixtures/mk_edid.py). The assertions
//! on our parser always run. The oracle cross-check runs only when
//! `edid-decode` is on PATH (`apt install edid-decode`): for each fixture we
//! compare which Atmos-relevant flag strings it prints with what we decoded.

use std::path::{Path, PathBuf};
use std::process::Command;

use ipauro_hdmi::caps::{AtmosCarrier, SinkAudioCaps};
use ipauro_hdmi::edid::Edid;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn caps(name: &str) -> (Edid, SinkAudioCaps) {
    let e = Edid::parse(&std::fs::read(fixture(name)).unwrap()).unwrap();
    let c = SinkAudioCaps::from_sads(e.sads());
    (e, c)
}

fn oracle(name: &str) -> Option<String> {
    let out = Command::new("edid-decode")
        .arg(fixture(name))
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cross_check(name: &str, c: &SinkAudioCaps) {
    let Some(text) = oracle(name) else {
        eprintln!("edid-decode not installed; oracle cross-check skipped for {name}");
        return;
    };
    assert_eq!(
        text.contains("Supports Joint Object Coding\n"),
        c.eac3_joc,
        "{name}: JOC"
    );
    assert_eq!(
        text.contains("Supports Joint Object Coding with ACMOD28"),
        c.eac3_joc_acmod28,
        "{name}: ACMOD28"
    );
    assert_eq!(
        text.contains("object audio PCM and channel-based PCM"),
        c.mat_object_pcm,
        "{name}: MAT object PCM"
    );
    assert_eq!(
        text.contains("Supports only Dolby TrueHD"),
        c.mat && !c.mat_object_pcm,
        "{name}: TrueHD only"
    );
    match c.mat_hash_required {
        Some(true) => assert!(
            text.contains("Hash calculation required"),
            "{name}: hash required"
        ),
        Some(false) => assert!(
            text.contains("Hash calculation not required"),
            "{name}: hash not required"
        ),
        None => assert!(!text.contains("Hash calculation"), "{name}: no hash line"),
    }
}

#[test]
fn avr_requiring_hash() {
    let (e, c) = caps("synth-avr-hash.bin");
    assert_eq!(e.manufacturer, "YMH");
    assert_eq!(e.monitor_name.as_deref(), Some("SYNTH AVR H"));
    assert!(e.base_checksum_ok && e.cta[0].checksum_ok);
    assert!(c.eac3_joc && !c.eac3_joc_acmod28);
    assert!(c.mat_object_pcm);
    assert_eq!(c.mat_hash_required, Some(true));
    assert_eq!(
        c.atmos_carriers,
        [
            AtmosCarrier::Eac3Joc,
            AtmosCarrier::MatObjectPcm,
            AtmosCarrier::TrueHdAtmos
        ]
    );
    assert_eq!(
        e.cta[0].speakers,
        [
            "FL/FR",
            "LFE1",
            "FC",
            "BL/BR",
            "TpFL/TpFR",
            "LS/RS",
            "TpBL/TpBR"
        ]
    );
    cross_check("synth-avr-hash.bin", &c);
}

#[test]
fn avr_waiving_hash() {
    let (_, c) = caps("synth-avr-nohash.bin");
    assert!(c.eac3_joc && c.eac3_joc_acmod28);
    assert_eq!(c.mat_hash_required, Some(false));
    cross_check("synth-avr-nohash.bin", &c);
}

#[test]
fn legacy_receiver() {
    let (_, c) = caps("synth-legacy.bin");
    assert!(c.eac3 && !c.eac3_joc);
    assert!(c.mat && !c.mat_object_pcm);
    assert_eq!(c.mat_hash_required, None);
    assert_eq!(c.atmos_carriers, [AtmosCarrier::TrueHdAtmos]);
    cross_check("synth-legacy.bin", &c);
}

#[test]
fn hex_dump_input_round_trips() {
    let bin = std::fs::read(fixture("synth-legacy.bin")).unwrap();
    let hex: String = bin
        .chunks(16)
        .map(|row| row.iter().map(|b| format!("{b:02x} ")).collect::<String>() + "\n")
        .collect();
    assert_eq!(ipauro_hdmi::edid::decode_input(hex.as_bytes()), bin);
}
