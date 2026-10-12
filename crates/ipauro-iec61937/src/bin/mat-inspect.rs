//! mat-inspect — IEC 61937 / MAT / E-AC-3 stream inspection, differential
//! comparison, and packetization (W002 protocol-analysis harness).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

use ipauro_iec61937::burst::{self, WordOrder};
use ipauro_iec61937::packetize::{Ac3Packetizer, Eac3Packetizer, MatPacketizer, Packetizer};
use ipauro_iec61937::scan::{self, Detail, ScanReport};
use ipauro_iec61937::{ac3, truehd};

#[derive(Parser)]
#[command(
    name = "mat-inspect",
    version,
    about = "Inspect, diff, extract and build IEC 61937 bursts (AC-3, E-AC-3, MAT/TrueHD)",
    long_about = "Inspect, diff, extract and build IEC 61937 bursts (AC-3, E-AC-3, MAT/TrueHD).\n\n\
        Input captures are raw byte streams as a device would play them: interleaved S16 \
        'PCM' of any channel count (2 ch for AC-3/E-AC-3; 8 ch @ 192 kHz for HDMI HBR/MAT). \
        WAV headers are not parsed; strip them first (e.g. `ffmpeg -i in.wav -f s16le -c copy out.raw`).\n\n\
        Nothing here decodes audio, and nothing here claims to understand MAT 2.0 object payloads. \
        MAT frames are checked against the TrueHD-in-MAT layout FFmpeg emits, and anything else is \
        reported as unparsed rather than guessed at."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Order {
    Auto,
    Le,
    Be,
}

#[derive(Clone, Copy, ValueEnum)]
enum Codec {
    Ac3,
    Eac3,
    Truehd,
}

#[derive(Subcommand)]
enum Command {
    /// Find and decode every burst in a capture.
    Scan {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Order::Auto)]
        order: Order,
        /// Emit the full report as JSON on stdout.
        #[arg(long)]
        json: bool,
        /// Text mode: how many bursts to list individually.
        #[arg(long, default_value_t = 8)]
        bursts: usize,
        /// Only read preambles; skip payload decoding.
        #[arg(long)]
        no_decode: bool,
    },
    /// Compare two captures burst-by-burst and report which payload byte
    /// ranges differ (the core of the controlled A/B method in W002 §6).
    Diff {
        a: PathBuf,
        b: PathBuf,
        #[arg(long, value_enum, default_value_t = Order::Auto)]
        order: Order,
        #[arg(long)]
        json: bool,
        /// Report at most this many differing ranges.
        #[arg(long, default_value_t = 40)]
        ranges: usize,
    },
    /// Write the concatenated burst payloads (in bitstream order) to a file:
    /// recovers the E-AC-3/AC-3 elementary stream, or the raw MAT frames.
    Extract {
        file: PathBuf,
        out: PathBuf,
        #[arg(long, value_enum, default_value_t = Order::Auto)]
        order: Order,
    },
    /// Wrap an elementary stream in IEC 61937 bursts (no FFmpeg needed).
    /// Output is S16 'PCM' to play on a passthrough device: 2 ch @ 48 kHz for
    /// AC-3, 2 ch @ 192 kHz for E-AC-3, 8 ch @ 192 kHz (HBR) for TrueHD/MAT.
    Packetize {
        #[arg(long, value_enum)]
        codec: Codec,
        input: PathBuf,
        out: PathBuf,
        #[arg(long, value_enum, default_value_t = Order::Le)]
        order: Order,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mat-inspect: error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn read(path: &PathBuf) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn resolve_order(order: Order, data: &[u8], path: &Path) -> Result<WordOrder> {
    Ok(match order {
        Order::Le => WordOrder::Le,
        Order::Be => WordOrder::Be,
        Order::Auto => scan::detect_word_order(data).with_context(|| {
            format!(
                "no IEC 61937 sync (F872 4E1F) found in {} in either byte order",
                path.display()
            )
        })?,
    })
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Scan {
            file,
            order,
            json,
            bursts,
            no_decode,
        } => {
            let data = read(&file)?;
            let order = resolve_order(order, &data, &file)?;
            let report = scan::scan(&data, order, !no_decode);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_scan(&file, &report, bursts);
            }
            if report.bursts.is_empty() {
                bail!("no bursts found");
            }
        }
        Command::Diff {
            a,
            b,
            order,
            json,
            ranges,
        } => {
            let da = read(&a)?;
            let db = read(&b)?;
            let oa = resolve_order(order, &da, &a)?;
            let ob = resolve_order(order, &db, &b)?;
            let report = diff(&da, oa, &db, ob, ranges);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_diff(&a, &b, &report);
            }
        }
        Command::Extract { file, out, order } => {
            let data = read(&file)?;
            let order = resolve_order(order, &data, &file)?;
            let report = scan::scan(&data, order, false);
            let mut es = Vec::new();
            let mut payload = Vec::new();
            for b in &report.bursts {
                let start = b.offset + burst::PREAMBLE_BYTES;
                if start + b.payload_bytes > data.len() {
                    continue;
                }
                burst::unswap_payload(&data[start..], b.payload_bytes, order, &mut payload);
                es.extend_from_slice(&payload);
            }
            fs::write(&out, &es).with_context(|| format!("writing {}", out.display()))?;
            eprintln!(
                "extracted {} bursts, {} bytes -> {}",
                report.bursts.len(),
                es.len(),
                out.display()
            );
        }
        Command::Packetize {
            codec,
            input,
            out,
            order,
        } => {
            let es = read(&input)?;
            let order = match order {
                Order::Be => WordOrder::Be,
                _ => WordOrder::Le,
            };
            let mut stream = Vec::new();
            let (units, bursts) = match codec {
                Codec::Ac3 => pack(
                    &mut Ac3Packetizer::new(order),
                    ac3::access_units(&es),
                    &mut stream,
                )?,
                Codec::Eac3 => pack(
                    &mut Eac3Packetizer::new(order),
                    ac3::access_units(&es),
                    &mut stream,
                )?,
                Codec::Truehd => pack(
                    &mut MatPacketizer::new(order),
                    truehd::access_units(&es),
                    &mut stream,
                )?,
            };
            if units == 0 {
                bail!("no access units parsed from {}", input.display());
            }
            fs::write(&out, &stream).with_context(|| format!("writing {}", out.display()))?;
            let play_as = match codec {
                Codec::Ac3 => "2 ch S16 @ 48 kHz (IEC 958 non-audio)",
                Codec::Eac3 => "2 ch S16 @ 192 kHz (IEC 958 non-audio)",
                Codec::Truehd => "8 ch S16 @ 192 kHz (HDMI HBR, IEC 958 non-audio)",
            };
            eprintln!(
                "{units} access units -> {bursts} bursts, {} bytes -> {}\nplay as: {play_as}",
                stream.len(),
                out.display()
            );
        }
    }
    Ok(())
}

fn pack<'a>(
    p: &mut impl Packetizer,
    units: impl Iterator<Item = &'a [u8]>,
    out: &mut Vec<u8>,
) -> Result<(usize, usize)> {
    let (mut n_units, mut n_bursts) = (0, 0);
    for (i, au) in units.enumerate() {
        n_units += 1;
        if let Some(b) = p.push(au).with_context(|| format!("access unit {i}"))? {
            out.extend_from_slice(b);
            n_bursts += 1;
        }
    }
    Ok((n_units, n_bursts))
}

fn print_scan(path: &Path, r: &ScanReport, list: usize) {
    let s = &r.summary;
    println!(
        "{}: {} bytes, word order {:?}, {} bursts",
        path.display(),
        r.stream_bytes,
        r.word_order,
        r.bursts.len()
    );
    for (t, n) in &s.by_type {
        println!("  type {t:?}: {n}");
    }
    let periods: Vec<String> = s
        .periods
        .iter()
        .map(|(p, n)| format!("{p} B ×{n}"))
        .collect();
    println!(
        "  repetition periods: {}",
        if periods.is_empty() {
            "-".into()
        } else {
            periods.join(", ")
        }
    );
    if s.error_flags + s.truncated + s.junk_bytes > 0 {
        println!(
            "  anomalies: {} error flags, {} truncated, {} junk bytes",
            s.error_flags, s.truncated, s.junk_bytes
        );
    }
    if s.mat_frames_with_foreign_codes + s.mat_frames_unparsed > 0 {
        println!(
            "  MAT: {} frames with codes differing from FFmpeg's TrueHD layout, {} with unparsed data areas",
            s.mat_frames_with_foreign_codes, s.mat_frames_unparsed
        );
    }
    if s.truehd_atmos_flag_seen {
        println!(
            "  TrueHD major sync signals an Atmos 16-ch presentation (4 substreams, substream_info bit 7)"
        );
    }
    if s.frames_with_emdf > 0 {
        let ids: Vec<String> = s
            .emdf_payload_ids
            .iter()
            .map(|(id, n)| format!("{id} ({}) ×{n}", ipauro_iec61937::emdf::payload_name(*id)))
            .collect();
        println!(
            "  EMDF: {} frames carry containers; payload ids: {}",
            s.frames_with_emdf,
            ids.join(", ")
        );
    }
    for b in r.bursts.iter().take(list) {
        print!(
            "  @{:<9} Pc={:04x} {:?} Pd={} ({} B) period={}",
            b.offset,
            b.pc,
            b.data_type,
            b.pd,
            b.payload_bytes,
            b.period_bytes.map_or("-".into(), |p| p.to_string())
        );
        match &b.detail {
            Detail::Ac3Family { frames } => {
                for f in frames {
                    let h = &f.header;
                    print!(
                        "\n      {:?} bsid={} {} B {} Hz blocks={} acmod={} lfe={} strm={:?} sub={:?}",
                        h.dialect,
                        h.bsid,
                        h.frame_bytes,
                        h.sample_rate,
                        h.num_blocks,
                        h.acmod,
                        h.lfe,
                        h.stream_type,
                        h.substream_id
                    );
                    for c in &f.emdf {
                        let ids: Vec<String> = c
                            .payloads
                            .iter()
                            .map(|p| format!("{}:{}B", p.id, p.size_bytes))
                            .collect();
                        print!(
                            "\n        EMDF @bit {} len {} v{} key {} payloads [{}]",
                            c.bit_offset,
                            c.container_length_bytes,
                            c.version,
                            c.key_id,
                            ids.join(" ")
                        );
                    }
                }
            }
            Detail::Mat(m) => {
                print!(
                    "\n      codes start/mid/end={}/{}/{} units={} padding={} B timing {:?}..{:?}{}",
                    m.codes.start_matches,
                    m.codes.middle_matches,
                    m.codes.end_matches,
                    m.truehd_units,
                    m.padding_bytes,
                    m.first_input_timing,
                    m.last_input_timing,
                    if m.data_area_unparsed {
                        " [data area not TrueHD-parseable]"
                    } else {
                        ""
                    }
                );
                for ms in &m.major_syncs {
                    print!(
                        "\n      major sync 0x{:02x} {} Hz substreams={} substream_info=0x{:02x} atmos={}",
                        ms.stream_type,
                        ms.sample_rate,
                        ms.num_substreams,
                        ms.substream_info,
                        ms.atmos_16ch_presentation
                    );
                }
            }
            Detail::Truncated => print!("  [truncated]"),
            Detail::None => {}
        }
        println!();
    }
    if r.bursts.len() > list {
        println!(
            "  … {} more (use --bursts N or --json)",
            r.bursts.len() - list
        );
    }
}

#[derive(Serialize)]
struct DiffReport {
    bursts_a: usize,
    bursts_b: usize,
    compared: usize,
    type_mismatches: usize,
    length_mismatches: usize,
    period_mismatches: usize,
    identical_payloads: usize,
    /// Payload byte ranges (offset within the burst payload, bitstream
    /// order) that differ in at least one compared pair, with how many
    /// pairs differ there.
    differing_ranges: Vec<DiffRange>,
    ranges_truncated: bool,
}

#[derive(Serialize)]
struct DiffRange {
    start: usize,
    end: usize,
    max_pairs_differing: usize,
}

fn diff(da: &[u8], oa: WordOrder, db: &[u8], ob: WordOrder, max_ranges: usize) -> DiffReport {
    let ra = scan::scan(da, oa, false);
    let rb = scan::scan(db, ob, false);
    let n = ra.bursts.len().min(rb.bursts.len());
    let mut counts: Vec<usize> = Vec::new();
    let (mut tm, mut lm, mut pm, mut same) = (0, 0, 0, 0);
    let (mut pa, mut pb) = (Vec::new(), Vec::new());
    for i in 0..n {
        let (x, y) = (&ra.bursts[i], &rb.bursts[i]);
        tm += usize::from(x.data_type != y.data_type);
        lm += usize::from(x.payload_bytes != y.payload_bytes);
        pm += usize::from(x.period_bytes != y.period_bytes);
        let (sx, sy) = (
            x.offset + burst::PREAMBLE_BYTES,
            y.offset + burst::PREAMBLE_BYTES,
        );
        if sx + x.payload_bytes > da.len() || sy + y.payload_bytes > db.len() {
            continue;
        }
        burst::unswap_payload(&da[sx..], x.payload_bytes, oa, &mut pa);
        burst::unswap_payload(&db[sy..], y.payload_bytes, ob, &mut pb);
        let len = pa.len().max(pb.len());
        if counts.len() < len {
            counts.resize(len, 0);
        }
        let mut differs = false;
        for (k, count) in counts.iter_mut().enumerate().take(len) {
            if pa.get(k) != pb.get(k) {
                *count += 1;
                differs = true;
            }
        }
        same += usize::from(!differs);
    }
    let mut ranges = Vec::new();
    let mut k = 0;
    while k < counts.len() {
        if counts[k] == 0 {
            k += 1;
            continue;
        }
        let start = k;
        let mut max = 0;
        while k < counts.len() && counts[k] > 0 {
            max = max.max(counts[k]);
            k += 1;
        }
        ranges.push(DiffRange {
            start,
            end: k,
            max_pairs_differing: max,
        });
    }
    let truncated = ranges.len() > max_ranges;
    ranges.truncate(max_ranges);
    DiffReport {
        bursts_a: ra.bursts.len(),
        bursts_b: rb.bursts.len(),
        compared: n,
        type_mismatches: tm,
        length_mismatches: lm,
        period_mismatches: pm,
        identical_payloads: same,
        differing_ranges: ranges,
        ranges_truncated: truncated,
    }
}

fn print_diff(a: &Path, b: &Path, r: &DiffReport) {
    println!(
        "A = {} ({} bursts)\nB = {} ({} bursts)",
        a.display(),
        r.bursts_a,
        b.display(),
        r.bursts_b
    );
    println!(
        "compared {} pairs: {} identical payloads, {} type / {} length / {} period mismatches",
        r.compared,
        r.identical_payloads,
        r.type_mismatches,
        r.length_mismatches,
        r.period_mismatches
    );
    if r.differing_ranges.is_empty() {
        println!("no differing payload bytes");
        return;
    }
    println!("differing payload ranges (offset in payload, bitstream order):");
    for d in &r.differing_ranges {
        println!(
            "  [{:>6}, {:>6})  {:>5} B  in up to {} pairs",
            d.start,
            d.end,
            d.end - d.start,
            d.max_pairs_differing
        );
    }
    if r.ranges_truncated {
        println!("  … more ranges (raise --ranges or use --json)");
    }
}
