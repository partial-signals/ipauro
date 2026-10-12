//! macOS probe backend: Core Audio HAL device/stream/format enumeration, an
//! opt-in physical-format switch trial, and EDID discovery via `ioreg`.

use std::process::Command;
use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::coreaudio::*;

#[derive(Debug, Clone, Serialize)]
pub struct MacReport {
    pub default_output_device: Option<u32>,
    pub devices: Vec<DeviceReport>,
    pub format_trials: Vec<FormatTrial>,
    /// EDID blobs found in the IORegistry: `(byte length, first key context)`.
    #[serde(skip)]
    pub edids: Vec<(String, Vec<u8>)>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceReport {
    pub id: u32,
    pub name: Option<String>,
    pub manufacturer: Option<String>,
    pub uid: Option<String>,
    pub model_uid: Option<String>,
    pub transport: Option<String>,
    pub is_hdmi_or_dp: bool,
    pub nominal_rate: Option<f64>,
    pub available_nominal_rates: Vec<(f64, f64)>,
    /// PID holding hog mode (-1 = free).
    pub hog_pid: Option<i32>,
    pub hog_settable: Option<bool>,
    pub supports_mixing: Option<u32>,
    pub latency_frames: Option<u32>,
    pub safety_offset_frames: Option<u32>,
    pub buffer_frames: Option<u32>,
    pub output_streams: Vec<StreamReport>,
    pub input_streams: Vec<StreamReport>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamReport {
    pub id: u32,
    pub direction: Option<u32>,
    pub terminal_type: Option<String>,
    pub starting_channel: Option<u32>,
    pub virtual_format: Option<FormatDesc>,
    pub physical_format: Option<FormatDesc>,
    pub physical_format_settable: Option<bool>,
    pub available_virtual_formats: Vec<FormatDesc>,
    pub available_physical_formats: Vec<FormatDesc>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormatTrial {
    pub device: u32,
    pub stream: u32,
    pub requested: FormatDesc,
    pub set_status: String,
    pub read_back: Option<FormatDesc>,
    pub took_effect: bool,
}

fn opt<T>(r: Result<T, OSStatus>, what: &str, errors: &mut Vec<String>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(s) => {
            // Unknown-property is routine (not every device has every
            // property); everything else is worth reporting.
            if s as u32 != fourcc(b"who?") {
                errors.push(format!("{what}: {}", status_name(s)));
            }
            None
        }
    }
}

fn stream_report(id: u32) -> StreamReport {
    let g = |sel| addr(sel, kAudioObjectPropertyScopeGlobal);
    let mut errors = Vec::new();
    let direction = opt(
        get::<u32>(id, &g(kAudioStreamPropertyDirection)),
        "direction",
        &mut errors,
    );
    let terminal_type = opt(
        get::<u32>(id, &g(kAudioStreamPropertyTerminalType)),
        "terminal type",
        &mut errors,
    )
    .map(fourcc_str);
    let starting_channel = opt(
        get::<u32>(id, &g(kAudioStreamPropertyStartingChannel)),
        "starting channel",
        &mut errors,
    );
    let virtual_format = opt(
        get::<AudioStreamBasicDescription>(id, &g(kAudioStreamPropertyVirtualFormat)),
        "virtual format",
        &mut errors,
    )
    .map(|f| FormatDesc::from_asbd(&f, None));
    let pf_addr = g(kAudioStreamPropertyPhysicalFormat);
    let physical_format = opt(
        get::<AudioStreamBasicDescription>(id, &pf_addr),
        "physical format",
        &mut errors,
    )
    .map(|f| FormatDesc::from_asbd(&f, None));
    let physical_format_settable = settable(id, &pf_addr).ok();
    let list = |sel, what: &str, errors: &mut Vec<String>| {
        opt(
            get_vec::<AudioStreamRangedDescription>(id, &g(sel)),
            what,
            errors,
        )
        .unwrap_or_default()
        .iter()
        .map(|r| FormatDesc::from_asbd(&r.format, Some(r.sample_rate_range)))
        .collect::<Vec<_>>()
    };
    let available_virtual_formats = list(
        kAudioStreamPropertyAvailableVirtualFormats,
        "available virtual formats",
        &mut errors,
    );
    let available_physical_formats = list(
        kAudioStreamPropertyAvailablePhysicalFormats,
        "available physical formats",
        &mut errors,
    );
    StreamReport {
        id,
        direction,
        terminal_type,
        starting_channel,
        virtual_format,
        physical_format,
        physical_format_settable,
        available_virtual_formats,
        available_physical_formats,
        errors,
    }
}

pub fn device_report(id: u32) -> DeviceReport {
    let g = |sel| addr(sel, kAudioObjectPropertyScopeGlobal);
    let mut errors = Vec::new();
    let transport_raw = opt(
        get::<u32>(id, &g(kAudioDevicePropertyTransportType)),
        "transport",
        &mut errors,
    );
    let streams = |scope, errors: &mut Vec<String>| {
        opt(
            get_vec::<u32>(id, &addr(kAudioDevicePropertyStreams, scope)),
            "streams",
            errors,
        )
        .unwrap_or_default()
        .into_iter()
        .map(stream_report)
        .collect::<Vec<_>>()
    };
    let hog = g(kAudioDevicePropertyHogMode);
    DeviceReport {
        id,
        name: opt(
            get_string(id, &g(kAudioObjectPropertyName)),
            "name",
            &mut errors,
        ),
        manufacturer: opt(
            get_string(id, &g(kAudioObjectPropertyManufacturer)),
            "manufacturer",
            &mut errors,
        ),
        uid: opt(
            get_string(id, &g(kAudioDevicePropertyDeviceUID)),
            "uid",
            &mut errors,
        ),
        model_uid: opt(
            get_string(id, &g(kAudioDevicePropertyModelUID)),
            "model uid",
            &mut errors,
        ),
        transport: transport_raw.map(fourcc_str),
        is_hdmi_or_dp: matches!(
            transport_raw,
            Some(t) if t == kAudioDeviceTransportTypeHDMI || t == kAudioDeviceTransportTypeDisplayPort
        ),
        nominal_rate: opt(
            get::<f64>(id, &g(kAudioDevicePropertyNominalSampleRate)),
            "nominal rate",
            &mut errors,
        ),
        available_nominal_rates: opt(
            get_vec::<AudioValueRange>(id, &g(kAudioDevicePropertyAvailableNominalSampleRates)),
            "available rates",
            &mut errors,
        )
        .unwrap_or_default()
        .iter()
        .map(|r| (r.minimum, r.maximum))
        .collect(),
        hog_pid: opt(get::<i32>(id, &hog), "hog mode", &mut errors),
        hog_settable: settable(id, &hog).ok(),
        supports_mixing: has(id, &g(kAudioDevicePropertySupportsMixing))
            .then(|| get::<u32>(id, &g(kAudioDevicePropertySupportsMixing)).ok())
            .flatten(),
        latency_frames: get::<u32>(
            id,
            &addr(kAudioDevicePropertyLatency, kAudioObjectPropertyScopeOutput),
        )
        .ok(),
        safety_offset_frames: get::<u32>(
            id,
            &addr(
                kAudioDevicePropertySafetyOffset,
                kAudioObjectPropertyScopeOutput,
            ),
        )
        .ok(),
        buffer_frames: get::<u32>(id, &g(kAudioDevicePropertyBufferFrameSize)).ok(),
        output_streams: streams(kAudioObjectPropertyScopeOutput, &mut errors),
        input_streams: streams(kAudioObjectPropertyScopeInput, &mut errors),
        errors,
    }
}

pub fn device_ids() -> Result<Vec<u32>, OSStatus> {
    get_vec::<u32>(
        kAudioObjectSystemObject,
        &addr(
            kAudioHardwarePropertyDevices,
            kAudioObjectPropertyScopeGlobal,
        ),
    )
}

/// Hog-mode guard: takes exclusive access, releases on drop.
pub struct Hog {
    device: u32,
}

impl Hog {
    pub fn take(device: u32) -> Result<Hog, OSStatus> {
        let a = addr(kAudioDevicePropertyHogMode, kAudioObjectPropertyScopeGlobal);
        let pid = std::process::id() as i32;
        set(device, &a, &pid)?;
        match get::<i32>(device, &a) {
            Ok(p) if p == pid => Ok(Hog { device }),
            Ok(_) => Err(fourcc(b"!hog") as i32),
            Err(s) => Err(s),
        }
    }
}

impl Drop for Hog {
    fn drop(&mut self) {
        let a = addr(kAudioDevicePropertyHogMode, kAudioObjectPropertyScopeGlobal);
        let _ = set(self.device, &a, &-1i32);
    }
}

/// For each HDMI/DP output stream: hog the device, try every "encoded
/// candidate" physical format (or every format, with `all`), read back what
/// the HAL actually applied, then restore the original format.
pub fn try_formats(
    devices: &[DeviceReport],
    all: bool,
    notes: &mut Vec<String>,
) -> Vec<FormatTrial> {
    let mut trials = Vec::new();
    for d in devices.iter().filter(|d| d.is_hdmi_or_dp) {
        let hog = match Hog::take(d.id) {
            Ok(h) => h,
            Err(s) => {
                notes.push(format!(
                    "device {}: could not take hog mode: {}",
                    d.id,
                    status_name(s)
                ));
                continue;
            }
        };
        for s in &d.output_streams {
            let pf = addr(
                kAudioStreamPropertyPhysicalFormat,
                kAudioObjectPropertyScopeGlobal,
            );
            let Ok(original) = get::<AudioStreamBasicDescription>(s.id, &pf) else {
                continue;
            };
            let Ok(list) = get_vec::<AudioStreamRangedDescription>(
                s.id,
                &addr(
                    kAudioStreamPropertyAvailablePhysicalFormats,
                    kAudioObjectPropertyScopeGlobal,
                ),
            ) else {
                continue;
            };
            for r in list {
                let mut want = r.format;
                if want.sample_rate == 0.0 {
                    want.sample_rate = r.sample_rate_range.maximum;
                }
                let desc = FormatDesc::from_asbd(&want, None);
                if !all && !desc.encoded_candidate {
                    continue;
                }
                let st = set(s.id, &pf, &want);
                // Format changes complete asynchronously on some drivers.
                thread::sleep(Duration::from_millis(250));
                let back = get::<AudioStreamBasicDescription>(s.id, &pf).ok();
                trials.push(FormatTrial {
                    device: d.id,
                    stream: s.id,
                    requested: desc,
                    set_status: status_name(st.err().unwrap_or(0)),
                    took_effect: back.is_some_and(|b| {
                        b.format_id == want.format_id
                            && b.sample_rate == want.sample_rate
                            && b.channels_per_frame == want.channels_per_frame
                    }),
                    read_back: back.map(|b| FormatDesc::from_asbd(&b, None)),
                });
            }
            let _ = set(s.id, &pf, &original);
            thread::sleep(Duration::from_millis(250));
        }
        drop(hog);
    }
    trials
}

/// Finds EDIDs anywhere in `ioreg -l -w0` output, whatever the key is
/// called (IODisplayEDID on Intel, EDID inside display attributes on Apple
/// Silicon, ...): every `<hex>` blob that starts with the EDID header and
/// is a whole number of 128-byte blocks.
pub fn ioreg_edids(notes: &mut Vec<String>) -> Vec<(String, Vec<u8>)> {
    let out = match Command::new("/usr/sbin/ioreg").args(["-l", "-w0"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => {
            notes.push(format!("could not run ioreg: {e}"));
            return Vec::new();
        }
    };
    let mut found: Vec<(String, Vec<u8>)> = Vec::new();
    for line in out.lines() {
        let mut rest = line;
        while let Some(open) = rest.find('<') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('>') else { break };
            let hex = &after[..close];
            rest = &after[close + 1..];
            if hex.len() < 256 || !hex.starts_with("00ffffffffffff00") {
                continue;
            }
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
                .collect();
            if !bytes.len().is_multiple_of(128) || found.iter().any(|(_, b)| *b == bytes) {
                continue;
            }
            let key = line[..line.find('<').unwrap_or(0)]
                .rsplit('"')
                .nth(1)
                .unwrap_or("?")
                .to_string();
            found.push((key, bytes));
        }
    }
    if found.is_empty() {
        notes.push("no EDID found in ioreg output; try `ioreg -l -w0 | grep -i edid` and pass it with --edid".into());
    }
    found
}

pub fn probe(try_formats_flag: bool, try_all: bool) -> MacReport {
    let mut notes = Vec::new();
    let default_output_device = get::<u32>(
        kAudioObjectSystemObject,
        &addr(
            kAudioHardwarePropertyDefaultOutputDevice,
            kAudioObjectPropertyScopeGlobal,
        ),
    )
    .ok();
    let devices: Vec<DeviceReport> = match device_ids() {
        Ok(ids) => ids.into_iter().map(device_report).collect(),
        Err(s) => {
            notes.push(format!(
                "kAudioHardwarePropertyDevices failed: {}",
                status_name(s)
            ));
            Vec::new()
        }
    };
    if !devices.iter().any(|d| d.is_hdmi_or_dp) {
        notes.push(
            "no HDMI/DisplayPort audio device present (is the AVR connected and powered?)".into(),
        );
    }
    let format_trials = if try_formats_flag {
        try_formats(&devices, try_all, &mut notes)
    } else {
        Vec::new()
    };
    let edids = ioreg_edids(&mut notes);
    MacReport {
        default_output_device,
        devices,
        format_trials,
        edids,
        notes,
    }
}
