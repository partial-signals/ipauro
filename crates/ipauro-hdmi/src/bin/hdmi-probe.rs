//! hdmi-probe — what does the HDMI sink accept, and what will this host let
//! us send it? (W002 milestone M0/M1 diagnostic.)

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;

use ipauro_hdmi::caps::{AtmosCarrier, SinkAudioCaps};
use ipauro_hdmi::edid::{self, Edid};

#[derive(Parser)]
#[command(
    name = "hdmi-probe",
    version,
    about = "Report HDMI sink audio capabilities (EDID/ELD, incl. Dolby Atmos carrier flags) and the host's encoded-output formats",
    long_about = "Report HDMI sink audio capabilities and the host's encoded-output formats.\n\n\
        Sink side: decodes the CTA-861 Short Audio Descriptors in every EDID/ELD it can find, \
        including E-AC-3 'Joint Object Coding' (DD+ Atmos) and MAT 'object audio PCM' plus its \
        'hash calculation required' bit.\n\n\
        Host side: macOS lists Core Audio devices, streams and physical formats (non-mixable / \
        encoded formats are what passthrough needs). Linux lists ALSA cards, PCM devices, ELDs and \
        DRM EDIDs.\n\n\
        Read-only by default. --try-formats (macOS) briefly takes hog mode on HDMI/DP devices, \
        tries each encoded physical format, and restores the original."
)]
struct Cli {
    /// Emit machine-readable JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Decode an EDID from a file (raw binary or hex dump). Repeatable.
    #[arg(long)]
    edid: Vec<PathBuf>,
    /// Skip system enumeration (only decode --edid files).
    #[arg(long)]
    no_system: bool,
    /// macOS: try switching HDMI/DP output streams to each encoded physical
    /// format and report the HAL's result codes (restores afterwards).
    #[arg(long)]
    try_formats: bool,
    /// With --try-formats: try every listed physical format, LPCM included.
    #[arg(long, requires = "try_formats")]
    try_all_formats: bool,
}

#[derive(Serialize)]
struct Report {
    tool: &'static str,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    sinks: Vec<SinkReport>,
    #[cfg(target_os = "linux")]
    linux: Option<ipauro_hdmi::platform::linux::LinuxReport>,
    #[cfg(target_os = "macos")]
    macos: Option<ipauro_hdmi::platform::macos::MacReport>,
    assessment: Vec<String>,
}

#[derive(Serialize)]
struct SinkReport {
    source: String,
    edid: Option<Edid>,
    error: Option<String>,
    caps: Option<SinkAudioCaps>,
}

fn sink_from_bytes(source: String, bytes: &[u8]) -> SinkReport {
    match Edid::parse(bytes) {
        Ok(e) => {
            let caps = SinkAudioCaps::from_sads(e.sads());
            SinkReport {
                source,
                edid: Some(e),
                error: None,
                caps: Some(caps),
            }
        }
        Err(err) => SinkReport {
            source,
            edid: None,
            error: Some(err.to_string()),
            caps: None,
        },
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hdmi-probe: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let mut report = Report {
        tool: "hdmi-probe",
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        sinks: Vec::new(),
        #[cfg(target_os = "linux")]
        linux: None,
        #[cfg(target_os = "macos")]
        macos: None,
        assessment: Vec::new(),
    };

    for path in &cli.edid {
        let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        report.sinks.push(sink_from_bytes(
            path.display().to_string(),
            &edid::decode_input(&raw),
        ));
    }

    if cli.try_formats && !cfg!(target_os = "macos") {
        report
            .assessment
            .push("--try-formats is macOS-only; ignored".into());
    }

    if !cli.no_system {
        #[cfg(target_os = "linux")]
        {
            let l = ipauro_hdmi::platform::linux::probe();
            for (conn, status, bytes) in &l.edids {
                report
                    .sinks
                    .push(sink_from_bytes(format!("drm:{conn} ({status})"), bytes));
            }
            report.linux = Some(l);
        }
        #[cfg(target_os = "macos")]
        {
            let m = ipauro_hdmi::platform::macos::probe(cli.try_formats, cli.try_all_formats);
            for (key, bytes) in &m.edids {
                report
                    .sinks
                    .push(sink_from_bytes(format!("ioreg:{key}"), bytes));
            }
            assess_macos(&m, &mut report.assessment);
            report.macos = Some(m);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        report
            .assessment
            .push("no system backend for this OS; use --edid".into());
    }

    assess_sinks(&report.sinks, &mut report.assessment);

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_text(&report);
    }
    Ok(())
}

fn assess_sinks(sinks: &[SinkReport], out: &mut Vec<String>) {
    for s in sinks {
        let Some(c) = &s.caps else { continue };
        let name = s
            .edid
            .as_ref()
            .and_then(|e| e.monitor_name.clone())
            .unwrap_or_else(|| s.source.clone());
        let carriers: Vec<&str> = c
            .atmos_carriers
            .iter()
            .map(|a| match a {
                AtmosCarrier::Eac3Joc => "DD+ JOC (E-AC-3, 2ch@192k non-audio)",
                AtmosCarrier::MatObjectPcm => "MAT object PCM (HBR 8ch@192k)",
                AtmosCarrier::TrueHdAtmos => "TrueHD-in-MAT (HBR)",
            })
            .collect();
        out.push(format!(
            "sink '{name}': Atmos carriers advertised: {}",
            if carriers.is_empty() {
                "none".into()
            } else {
                carriers.join("; ")
            }
        ));
        for n in &c.notes {
            out.push(format!("sink '{name}': {n}"));
        }
    }
}

#[cfg(target_os = "macos")]
fn assess_macos(m: &ipauro_hdmi::platform::macos::MacReport, out: &mut Vec<String>) {
    for d in m.devices.iter().filter(|d| d.is_hdmi_or_dp) {
        let name = d.name.clone().unwrap_or_else(|| d.id.to_string());
        let fmts: Vec<_> = d
            .output_streams
            .iter()
            .flat_map(|s| s.available_physical_formats.iter())
            .collect();
        let has_rate = |f: &&ipauro_hdmi::coreaudio::FormatDesc, rate: f64| match f.rate_range {
            Some((lo, hi)) => lo <= rate && rate <= hi,
            None => f.sample_rate == rate,
        };
        let enc = |ch: u32, rate: f64| {
            fmts.iter()
                .any(|f| f.encoded_candidate && f.channels == ch && has_rate(f, rate))
        };
        let pcm = |ch: u32, rate: f64| {
            fmts.iter()
                .any(|f| !f.encoded_candidate && f.channels >= ch && has_rate(f, rate))
        };
        // HBR = 768 kHz IEC 60958 frame rate: either 8 ch @ 192 kHz or, as
        // macOS 15 reportedly lists it, 2 ch @ 768 kHz ('mtct'/'mtc+').
        let hbr = enc(8, 192000.0) || enc(2, 768000.0);
        out.push(format!(
            "macOS '{name}': HAL lists encoded/non-mixable 2ch@48k: {}, 2ch@192k (E-AC-3 rate): {}, HBR-rate (MAT): {}; \
             LPCM 8ch@192k: {}. Listed ≠ demonstrated: confirm with hdmi-passthrough-test + the AVR's signal info.",
            enc(2, 48000.0), enc(2, 192000.0), hbr, pcm(8, 192000.0)
        ));
        let undocumented: Vec<String> = fmts
            .iter()
            .filter(|f| f.label.is_some_and(|l| l.contains("undocumented")))
            .map(|f| format!("{} ({})", f.format_id, f.label.unwrap_or("")))
            .collect();
        if !undocumented.is_empty() {
            out.push(format!(
                "macOS '{name}': undocumented IEC 61937 physical formats present: {} → try \
                 hdmi-passthrough-test --format <fourcc> --channels 2 --rate <192000|768000> (W002 E-T2)",
                undocumented.join(", ")
            ));
        }
    }
    for t in &m.format_trials {
        out.push(format!(
            "trial dev {} stream {}: {} {}ch @{} -> {} (took effect: {})",
            t.device,
            t.stream,
            t.requested.format_id,
            t.requested.channels,
            t.requested.sample_rate,
            t.set_status,
            t.took_effect
        ));
    }
}

fn print_text(r: &Report) {
    println!("hdmi-probe {} on {}/{}", r.version, r.os, r.arch);
    for s in &r.sinks {
        println!("\nSink: {}", s.source);
        if let Some(err) = &s.error {
            println!("  EDID error: {err}");
            continue;
        }
        let Some(e) = &s.edid else { continue };
        println!(
            "  {} product 0x{:04x} '{}' EDID {} ({}), {} CTA block(s){}",
            e.manufacturer,
            e.product_code,
            e.monitor_name.as_deref().unwrap_or("?"),
            e.version,
            e.year,
            e.cta.len(),
            if e.base_checksum_ok {
                ""
            } else {
                " [base checksum BAD]"
            }
        );
        for c in &e.cta {
            if let Some(pa) = &c.hdmi_physical_address {
                println!(
                    "  HDMI physical address {pa}{}",
                    if c.hdmi_forum {
                        ", HDMI Forum VSDB"
                    } else {
                        ""
                    }
                );
            }
            for sad in &c.sads {
                println!(
                    "  SAD {:02x}{:02x}{:02x}  {}",
                    sad.raw[0],
                    sad.raw[1],
                    sad.raw[2],
                    sad.describe()
                );
            }
            if !c.speakers.is_empty() {
                println!("  speakers: {}", c.speakers.join(" "));
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(l) = &r.linux {
        println!("\nALSA cards:");
        for c in &l.cards {
            println!("  {c}");
        }
        for p in l.pcm_devices.iter().filter(|p| {
            p.to_ascii_lowercase().contains("hdmi") || p.to_ascii_lowercase().contains("dp")
        }) {
            println!("  pcm {p}");
        }
        for e in &l.elds {
            println!(
                "  ELD {}: present={} valid={} name={:?} sads={:?}",
                e.path,
                e.eld.monitor_present,
                e.eld.eld_valid,
                e.eld.monitor_name,
                e.eld.sad_coding_types
            );
            if let Some(h) = &e.alsa_device_hint {
                println!("      device: {h}");
            }
        }
        for n in &l.notes {
            println!("  note: {n}");
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(m) = &r.macos {
        println!(
            "\nCore Audio devices (default output: {:?}):",
            m.default_output_device
        );
        for d in &m.devices {
            println!(
                "  [{}] {} ({}) transport {} uid {} rate {:?} hog {:?} mixing {:?}",
                d.id,
                d.name.as_deref().unwrap_or("?"),
                d.manufacturer.as_deref().unwrap_or("?"),
                d.transport.as_deref().unwrap_or("?"),
                d.uid.as_deref().unwrap_or("?"),
                d.nominal_rate,
                d.hog_pid,
                d.supports_mixing
            );
            for s in &d.output_streams {
                println!(
                    "    out stream {} term {} ch@{:?} physical {:?} (settable {:?})",
                    s.id,
                    s.terminal_type.as_deref().unwrap_or("?"),
                    s.starting_channel,
                    s.physical_format.as_ref().map(|f| format!(
                        "{} {}ch {}Hz {:?}",
                        f.format_id, f.channels, f.sample_rate, f.flags
                    )),
                    s.physical_format_settable
                );
                for f in &s.available_physical_formats {
                    println!(
                        "      avail {} {}ch {}b {:?} Hz {}B/{}fr {:?}{}{}",
                        f.format_id,
                        f.channels,
                        f.bits_per_channel,
                        f.rate_range,
                        f.bytes_per_packet,
                        f.frames_per_packet,
                        f.flags,
                        if f.encoded_candidate {
                            "  <- encoded candidate"
                        } else {
                            ""
                        },
                        f.label.map(|l| format!(" [{l}]")).unwrap_or_default()
                    );
                }
                for err in &s.errors {
                    println!("      error: {err}");
                }
            }
            for err in &d.errors {
                println!("    error: {err}");
            }
        }
        for n in &m.notes {
            println!("  note: {n}");
        }
    }
    if !r.assessment.is_empty() {
        println!("\nAssessment:");
        for a in &r.assessment {
            println!("  - {a}");
        }
    }
}
