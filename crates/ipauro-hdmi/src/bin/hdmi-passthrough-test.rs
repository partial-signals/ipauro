//! hdmi-passthrough-test — M1 transport experiment: play a prepared IEC
//! 61937 stream (from `mat-inspect packetize` or `ffmpeg -f spdif`) to an
//! HDMI device through Core Audio's exclusive (hog-mode) path, logging every
//! HAL call and result code. Whether the AVR then reports Dolby Digital /
//! DD+ / TrueHD / Atmos is the observation this tool exists to enable.
//!
//! macOS only. On Linux the equivalent is a single `aplay` with the
//! IEC 958 non-audio bit (see `hdmi-probe` notes).

use std::process::ExitCode;

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::c_void;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail};
    use clap::Parser;

    use ipauro_hdmi::coreaudio::*;
    use ipauro_hdmi::platform::macos::{Hog, device_report};

    #[derive(Parser)]
    #[command(
        name = "hdmi-passthrough-test",
        version,
        about = "Play a raw IEC 61937 stream to an HDMI device via Core Audio hog mode, logging every HAL result",
        long_about = "Play a raw IEC 61937 stream to an HDMI device via Core Audio hog mode, logging every HAL result.\n\n\
            1. hdmi-probe: pick the device id and a physical format (e.g. 'cac3' 2ch @ 48000 for AC-3).\n\
            2. mat-inspect packetize --codec ac3 in.ac3 x.spdif\n\
            3. hdmi-passthrough-test --device ID --format cac3 --rate 48000 --channels 2 x.spdif\n\
            4. Read the AVR's signal-info screen while it plays.\n\n\
            The payload is copied bit-for-bit into the stream buffer. If the chosen physical format \
            is LPCM, the sink receives the bursts flagged as PCM (no IEC 958 non-audio bit): that is the \
            'PCM-carrier' experiment, which only works on sinks that sniff for IEC 61937 sync."
    )]
    struct Cli {
        /// Raw IEC 61937 byte stream (S16 words), e.g. from `mat-inspect packetize`.
        file: PathBuf,
        /// Core Audio device id (from hdmi-probe).
        #[arg(long)]
        device: u32,
        /// Physical format FourCC to select: cac3, ac-3, lpcm, ...
        #[arg(long, default_value = "cac3")]
        format: String,
        #[arg(long, default_value_t = 48000.0)]
        rate: f64,
        #[arg(long, default_value_t = 2)]
        channels: u32,
        /// Index of the output stream to drive (default: first).
        #[arg(long, default_value_t = 0)]
        stream_index: usize,
        /// Seconds to play (loops the file).
        #[arg(long, default_value_t = 20)]
        seconds: u64,
        /// Swap bytes of every 16-bit word before output (for devices whose
        /// selected format is big-endian when the file is LE, or vice versa).
        #[arg(long)]
        swap16: bool,
    }

    struct Shared {
        data: Vec<u8>,
        pos: AtomicUsize,
        calls: AtomicUsize,
        short_buffers: AtomicUsize,
        stream_index: usize,
        running: AtomicBool,
    }

    unsafe extern "C" fn io_proc(
        _device: AudioObjectID,
        _now: *const AudioTimeStamp,
        _in_data: *const AudioBufferList,
        _in_time: *const AudioTimeStamp,
        out_data: *mut AudioBufferList,
        _out_time: *const AudioTimeStamp,
        client: *mut c_void,
    ) -> OSStatus {
        // SAFETY: `client` is the `Shared` leaked for the lifetime of the
        // IOProc; `out_data` is the HAL's buffer list for this cycle.
        unsafe {
            let shared = &*(client as *const Shared);
            shared.calls.fetch_add(1, Ordering::Relaxed);
            let list = &mut *out_data;
            let n = list.number_buffers as usize;
            let bufs = std::slice::from_raw_parts_mut(list.buffers.as_mut_ptr(), n);
            for (i, b) in bufs.iter_mut().enumerate() {
                let out =
                    std::slice::from_raw_parts_mut(b.data as *mut u8, b.data_byte_size as usize);
                if i != shared.stream_index || !shared.running.load(Ordering::Relaxed) {
                    out.fill(0);
                    continue;
                }
                let len = shared.data.len();
                let mut pos = shared.pos.load(Ordering::Relaxed);
                let mut written = 0;
                while written < out.len() {
                    let n = (out.len() - written).min(len - pos);
                    out[written..written + n].copy_from_slice(&shared.data[pos..pos + n]);
                    written += n;
                    pos = (pos + n) % len;
                }
                shared.pos.store(pos, Ordering::Relaxed);
                if out.len() % 4 != 0 {
                    shared.short_buffers.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        0
    }

    fn log(step: &str, st: Result<(), OSStatus>) -> Result<()> {
        match st {
            Ok(()) => {
                println!("[ok]   {step}");
                Ok(())
            }
            Err(s) => {
                println!("[FAIL] {step}: {}", status_name(s));
                bail!("{step} failed: {}", status_name(s))
            }
        }
    }

    pub fn main() -> Result<()> {
        let cli = Cli::parse();
        let mut data =
            std::fs::read(&cli.file).with_context(|| format!("reading {}", cli.file.display()))?;
        if data.len() < 8 {
            bail!("input too short");
        }
        if cli.swap16 {
            for w in data.chunks_exact_mut(2) {
                w.swap(0, 1);
            }
        }
        let fmt: [u8; 4] = cli
            .format
            .as_bytes()
            .try_into()
            .context("--format must be exactly 4 characters")?;
        let want_id = fourcc(&fmt);

        let dev = device_report(cli.device);
        println!(
            "device {} '{}' transport {} ({} output streams)",
            cli.device,
            dev.name.as_deref().unwrap_or("?"),
            dev.transport.as_deref().unwrap_or("?"),
            dev.output_streams.len()
        );
        let stream = dev
            .output_streams
            .get(cli.stream_index)
            .context("no such output stream index")?;

        let pf_addr = addr(
            kAudioStreamPropertyPhysicalFormat,
            kAudioObjectPropertyScopeGlobal,
        );
        let list = get_vec::<AudioStreamRangedDescription>(
            stream.id,
            &addr(
                kAudioStreamPropertyAvailablePhysicalFormats,
                kAudioObjectPropertyScopeGlobal,
            ),
        )
        .map_err(|s| anyhow::anyhow!("available physical formats: {}", status_name(s)))?;
        let Some(choice) = list.iter().find(|r| {
            r.format.format_id == want_id
                && r.format.channels_per_frame == cli.channels
                && r.sample_rate_range.minimum <= cli.rate
                && cli.rate <= r.sample_rate_range.maximum
        }) else {
            println!("available physical formats on stream {}:", stream.id);
            for r in &list {
                println!(
                    "  {:?}",
                    FormatDesc::from_asbd(&r.format, Some(r.sample_rate_range))
                );
            }
            bail!(
                "no physical format {} {}ch @ {} on this stream",
                cli.format,
                cli.channels,
                cli.rate
            );
        };
        let mut asbd = choice.format;
        asbd.sample_rate = cli.rate;
        println!(
            "selected physical format: {:?}",
            FormatDesc::from_asbd(&asbd, None)
        );
        let original = get::<AudioStreamBasicDescription>(stream.id, &pf_addr).ok();

        let hog =
            Hog::take(cli.device).map_err(|s| anyhow::anyhow!("hog mode: {}", status_name(s)));
        log(
            "take hog mode",
            hog.as_ref().map(|_| ()).map_err(|_| fourcc(b"!hog") as i32),
        )?;
        let _hog = hog?;

        let mix = addr(
            kAudioDevicePropertySupportsMixing,
            kAudioObjectPropertyScopeGlobal,
        );
        if has(cli.device, &mix) && settable(cli.device, &mix).unwrap_or(false) {
            let _ = log("disable mixing", set(cli.device, &mix, &0u32));
        }
        log("set physical format", set(stream.id, &pf_addr, &asbd))?;
        std::thread::sleep(Duration::from_millis(300));
        let applied = get::<AudioStreamBasicDescription>(stream.id, &pf_addr).ok();
        println!(
            "physical format now: {:?}",
            applied.map(|f| FormatDesc::from_asbd(&f, None))
        );
        if applied.map(|f| f.format_id) != Some(want_id) {
            println!("[WARN] HAL did not apply the requested format id");
        }

        let shared: &'static Shared = Box::leak(Box::new(Shared {
            data,
            pos: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            short_buffers: AtomicUsize::new(0),
            stream_index: cli.stream_index,
            running: AtomicBool::new(true),
        }));
        let mut proc_id: AudioDeviceIOProcID = None;
        // SAFETY: `shared` lives forever (leaked); `proc_id` is a valid out-pointer.
        let st = unsafe {
            AudioDeviceCreateIOProcID(
                cli.device,
                io_proc,
                shared as *const Shared as *mut c_void,
                &mut proc_id,
            )
        };
        log(
            "AudioDeviceCreateIOProcID",
            if st == 0 { Ok(()) } else { Err(st) },
        )?;
        // SAFETY: proc_id came from AudioDeviceCreateIOProcID.
        let st = unsafe { AudioDeviceStart(cli.device, proc_id) };
        log("AudioDeviceStart", if st == 0 { Ok(()) } else { Err(st) })?;

        println!(
            "playing for {} s, now read the AVR's signal information display…",
            cli.seconds
        );
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(cli.seconds) {
            std::thread::sleep(Duration::from_secs(1));
            println!(
                "  t={:>3}s io callbacks={} position={}",
                t0.elapsed().as_secs(),
                shared.calls.load(Ordering::Relaxed),
                shared.pos.load(Ordering::Relaxed)
            );
        }
        shared.running.store(false, Ordering::Relaxed);
        // SAFETY: as above.
        unsafe {
            let _ = log(
                "AudioDeviceStop",
                match AudioDeviceStop(cli.device, proc_id) {
                    0 => Ok(()),
                    s => Err(s),
                },
            );
            let _ = AudioDeviceDestroyIOProcID(cli.device, proc_id);
        }
        if let Some(o) = original {
            let _ = log("restore physical format", set(stream.id, &pf_addr, &o));
        }
        if shared.short_buffers.load(Ordering::Relaxed) > 0 {
            println!("[WARN] some IO buffers were not a multiple of 4 bytes");
        }
        println!(
            "done. Record: macOS version, Mac model, device, format, AVR model/firmware, AVR signal info."
        );
        Ok(())
    }
}

fn main() -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        match imp::main() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("hdmi-passthrough-test: error: {e:#}");
                ExitCode::from(1)
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let args: Vec<String> = std::env::args().collect();
        let help = args.iter().any(|a| a == "--help" || a == "-h");
        eprintln!(
            "hdmi-passthrough-test drives Core Audio and is macOS-only.\n\
             On Linux, play the same stream with the IEC 958 non-audio bit set, e.g.:\n  \
             aplay -D 'hdmi:CARD=0,DEV=0,AES0=0x06' -t raw -f S16_LE -c 2 -r 48000  x.ac3.spdif   # AC-3\n  \
             aplay -D 'hdmi:CARD=0,DEV=0,AES0=0x06' -t raw -f S16_LE -c 2 -r 192000 x.eac3.spdif  # E-AC-3\n  \
             aplay -D 'hdmi:CARD=0,DEV=0,AES0=0x06' -t raw -f S16_LE -c 8 -r 192000 x.thd.spdif   # TrueHD/MAT (HBR)"
        );
        if help {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        }
    }
}
