//! Hand-written Core Audio HAL FFI: just the calls the probe and the
//! passthrough test make. These are public, documented C APIs
//! (CoreAudio/AudioHardware.h, AudioHardwareBase.h, CoreAudioTypes.h). The
//! bindings are written by hand so every selector and struct layout here can
//! be audited against the SDK headers, with no bindgen or SDK needed at
//! build time.

#![allow(non_upper_case_globals)]

use std::ffi::{c_char, c_void};
use std::ptr;

use serde::Serialize;

pub type OSStatus = i32;
pub type AudioObjectID = u32;

pub const fn fourcc(s: &[u8; 4]) -> u32 {
    ((s[0] as u32) << 24) | ((s[1] as u32) << 16) | ((s[2] as u32) << 8) | (s[3] as u32)
}

/// Renders a FourCC (or a small integer) for humans.
pub fn fourcc_str(v: u32) -> String {
    let b = v.to_be_bytes();
    if b.iter().all(|c| (0x20..0x7f).contains(c)) {
        format!("'{}'", String::from_utf8_lossy(&b))
    } else {
        format!("{v}")
    }
}

pub const kAudioObjectSystemObject: AudioObjectID = 1;
pub const kAudioObjectPropertyScopeGlobal: u32 = fourcc(b"glob");
pub const kAudioObjectPropertyScopeInput: u32 = fourcc(b"inpt");
pub const kAudioObjectPropertyScopeOutput: u32 = fourcc(b"outp");
pub const kAudioObjectPropertyElementMain: u32 = 0;

pub const kAudioHardwarePropertyDevices: u32 = fourcc(b"dev#");
pub const kAudioHardwarePropertyDefaultOutputDevice: u32 = fourcc(b"dOut");
pub const kAudioObjectPropertyName: u32 = fourcc(b"lnam");
pub const kAudioObjectPropertyManufacturer: u32 = fourcc(b"lmak");
pub const kAudioDevicePropertyDeviceUID: u32 = fourcc(b"uid ");
pub const kAudioDevicePropertyModelUID: u32 = fourcc(b"muid");
pub const kAudioDevicePropertyTransportType: u32 = fourcc(b"tran");
pub const kAudioDevicePropertyStreams: u32 = fourcc(b"stm#");
pub const kAudioDevicePropertyNominalSampleRate: u32 = fourcc(b"nsrt");
pub const kAudioDevicePropertyAvailableNominalSampleRates: u32 = fourcc(b"nsr#");
pub const kAudioDevicePropertyHogMode: u32 = fourcc(b"oink");
pub const kAudioDevicePropertySupportsMixing: u32 = fourcc(b"mix?");
pub const kAudioDevicePropertyLatency: u32 = fourcc(b"ltnc");
pub const kAudioDevicePropertySafetyOffset: u32 = fourcc(b"saft");
pub const kAudioDevicePropertyBufferFrameSize: u32 = fourcc(b"fsiz");

pub const kAudioStreamPropertyDirection: u32 = fourcc(b"sdir");
pub const kAudioStreamPropertyTerminalType: u32 = fourcc(b"term");
pub const kAudioStreamPropertyStartingChannel: u32 = fourcc(b"schn");
pub const kAudioStreamPropertyVirtualFormat: u32 = fourcc(b"sfmt");
pub const kAudioStreamPropertyAvailableVirtualFormats: u32 = fourcc(b"sfma");
pub const kAudioStreamPropertyPhysicalFormat: u32 = fourcc(b"pft ");
pub const kAudioStreamPropertyAvailablePhysicalFormats: u32 = fourcc(b"pfta");

pub const kAudioDeviceTransportTypeHDMI: u32 = fourcc(b"hdmi");
pub const kAudioDeviceTransportTypeDisplayPort: u32 = fourcc(b"dprt");

pub const kAudioFormatLinearPCM: u32 = fourcc(b"lpcm");
pub const kAudioFormatAC3: u32 = fourcc(b"ac-3");
pub const kAudioFormat60958AC3: u32 = fourcc(b"cac3");
pub const kAudioFormatEnhancedAC3: u32 = fourcc(b"ec-3");

// Undocumented physical formats reported on an Apple-silicon HDMI device
// under macOS 15.1.1 (mpv issue #15383 log; single source, W002 H-T2).
// None of them is in the public SDK headers. The packet geometry matches
// FFmpeg's IEC 61937 framing exactly: 'cec3'/'cc+3' = 24576-byte packets of
// 6144 frames (E-AC-3), 'mtct'/'mtc+' = 61440-byte packets of 15360 frames at
// 768 kHz (MAT, i.e. the HBR rate). The '+' variants plausibly track the
// sink's JOC / MAT-object-PCM SAD bits. That is a guess, not a fact.
pub const FMT_EAC3_IEC61937: u32 = fourcc(b"cec3");
pub const FMT_EAC3_JOC_IEC61937: u32 = fourcc(b"cc+3");
pub const FMT_MAT_IEC61937: u32 = fourcc(b"mtct");
pub const FMT_MAT_PLUS_IEC61937: u32 = fourcc(b"mtc+");

/// What a physical-format FourCC is (or is believed to be).
pub fn format_label(id: u32) -> Option<&'static str> {
    Some(match id {
        kAudioFormatLinearPCM => "linear PCM",
        kAudioFormat60958AC3 => "IEC 61937 AC-3 (documented)",
        kAudioFormatAC3 => "AC-3",
        kAudioFormatEnhancedAC3 => "E-AC-3",
        FMT_EAC3_IEC61937 => "IEC 61937 E-AC-3 (undocumented; inferred)",
        FMT_EAC3_JOC_IEC61937 => "IEC 61937 E-AC-3 JOC? (undocumented; inferred)",
        FMT_MAT_IEC61937 => "IEC 61937 MAT/TrueHD @768k = HBR (undocumented; inferred)",
        FMT_MAT_PLUS_IEC61937 => "IEC 61937 MAT object PCM? @768k = HBR (undocumented; inferred)",
        _ => return None,
    })
}

pub const kAudioFormatFlagIsFloat: u32 = 1 << 0;
pub const kAudioFormatFlagIsBigEndian: u32 = 1 << 1;
pub const kAudioFormatFlagIsSignedInteger: u32 = 1 << 2;
pub const kAudioFormatFlagIsPacked: u32 = 1 << 3;
pub const kAudioFormatFlagIsAlignedHigh: u32 = 1 << 4;
pub const kAudioFormatFlagIsNonInterleaved: u32 = 1 << 5;
pub const kAudioFormatFlagIsNonMixable: u32 = 1 << 6;

/// Errors from AudioHardwareBase.h, for readable reports.
pub fn status_name(s: OSStatus) -> String {
    let known = match s as u32 {
        0 => Some("noErr"),
        v if v == fourcc(b"stop") => Some("kAudioHardwareNotRunningError"),
        v if v == fourcc(b"what") => Some("kAudioHardwareUnspecifiedError"),
        v if v == fourcc(b"who?") => Some("kAudioHardwareUnknownPropertyError"),
        v if v == fourcc(b"!siz") => Some("kAudioHardwareBadPropertySizeError"),
        v if v == fourcc(b"nope") => Some("kAudioHardwareIllegalOperationError"),
        v if v == fourcc(b"!obj") => Some("kAudioHardwareBadObjectError"),
        v if v == fourcc(b"!dev") => Some("kAudioHardwareBadDeviceError"),
        v if v == fourcc(b"!str") => Some("kAudioHardwareBadStreamError"),
        v if v == fourcc(b"unop") => Some("kAudioHardwareUnsupportedOperationError"),
        v if v == fourcc(b"nrdy") => Some("kAudioHardwareNotReadyError"),
        v if v == fourcc(b"!dat") => Some("kAudioDeviceUnsupportedFormatError"),
        v if v == fourcc(b"!hog") => Some("kAudioDevicePermissionsError"),
        _ => None,
    };
    match known {
        Some(n) => format!("{n} ({s})"),
        None => format!("{} ({s})", fourcc_str(s as u32)),
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AudioObjectPropertyAddress {
    pub selector: u32,
    pub scope: u32,
    pub element: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AudioStreamBasicDescription {
    pub sample_rate: f64,
    pub format_id: u32,
    pub format_flags: u32,
    pub bytes_per_packet: u32,
    pub frames_per_packet: u32,
    pub bytes_per_frame: u32,
    pub channels_per_frame: u32,
    pub bits_per_channel: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AudioValueRange {
    pub minimum: f64,
    pub maximum: f64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AudioStreamRangedDescription {
    pub format: AudioStreamBasicDescription,
    pub sample_rate_range: AudioValueRange,
}

#[repr(C)]
pub struct AudioBuffer {
    pub number_channels: u32,
    pub data_byte_size: u32,
    pub data: *mut c_void,
}

/// Variable-length in C (`mBuffers[1]` is a flexible array).
#[repr(C)]
pub struct AudioBufferList {
    pub number_buffers: u32,
    pub buffers: [AudioBuffer; 1],
}

#[repr(C)]
pub struct SmpteTime {
    pub subframes: i16,
    pub subframe_divisor: i16,
    pub counter: u32,
    pub kind: u32,
    pub flags: u32,
    pub hours: i16,
    pub minutes: i16,
    pub seconds: i16,
    pub frames: i16,
}

#[repr(C)]
pub struct AudioTimeStamp {
    pub sample_time: f64,
    pub host_time: u64,
    pub rate_scalar: f64,
    pub word_clock_time: u64,
    pub smpte_time: SmpteTime,
    pub flags: u32,
    pub reserved: u32,
}

pub type AudioDeviceIOProc = unsafe extern "C" fn(
    device: AudioObjectID,
    now: *const AudioTimeStamp,
    input_data: *const AudioBufferList,
    input_time: *const AudioTimeStamp,
    output_data: *mut AudioBufferList,
    output_time: *const AudioTimeStamp,
    client_data: *mut c_void,
) -> OSStatus;
pub type AudioDeviceIOProcID = Option<AudioDeviceIOProc>;

#[link(name = "CoreAudio", kind = "framework")]
unsafe extern "C" {
    pub fn AudioObjectHasProperty(id: AudioObjectID, addr: *const AudioObjectPropertyAddress)
    -> u8;
    pub fn AudioObjectIsPropertySettable(
        id: AudioObjectID,
        addr: *const AudioObjectPropertyAddress,
        out_settable: *mut u8,
    ) -> OSStatus;
    pub fn AudioObjectGetPropertyDataSize(
        id: AudioObjectID,
        addr: *const AudioObjectPropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        out_size: *mut u32,
    ) -> OSStatus;
    pub fn AudioObjectGetPropertyData(
        id: AudioObjectID,
        addr: *const AudioObjectPropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        io_size: *mut u32,
        out_data: *mut c_void,
    ) -> OSStatus;
    pub fn AudioObjectSetPropertyData(
        id: AudioObjectID,
        addr: *const AudioObjectPropertyAddress,
        qualifier_size: u32,
        qualifier: *const c_void,
        size: u32,
        data: *const c_void,
    ) -> OSStatus;
    pub fn AudioDeviceCreateIOProcID(
        device: AudioObjectID,
        proc_: AudioDeviceIOProc,
        client_data: *mut c_void,
        out_id: *mut AudioDeviceIOProcID,
    ) -> OSStatus;
    pub fn AudioDeviceDestroyIOProcID(device: AudioObjectID, id: AudioDeviceIOProcID) -> OSStatus;
    pub fn AudioDeviceStart(device: AudioObjectID, id: AudioDeviceIOProcID) -> OSStatus;
    pub fn AudioDeviceStop(device: AudioObjectID, id: AudioDeviceIOProcID) -> OSStatus;
}

const kCFStringEncodingUTF8: u32 = 0x0800_0100;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringGetLength(s: *const c_void) -> isize;
    fn CFStringGetMaximumSizeForEncoding(len: isize, encoding: u32) -> isize;
    fn CFStringGetCString(s: *const c_void, buf: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFRelease(p: *const c_void);
}

pub fn addr(selector: u32, scope: u32) -> AudioObjectPropertyAddress {
    AudioObjectPropertyAddress {
        selector,
        scope,
        element: kAudioObjectPropertyElementMain,
    }
}

pub fn has(id: AudioObjectID, a: &AudioObjectPropertyAddress) -> bool {
    // SAFETY: plain C call with a valid pointer to a local struct.
    unsafe { AudioObjectHasProperty(id, a) != 0 }
}

pub fn settable(id: AudioObjectID, a: &AudioObjectPropertyAddress) -> Result<bool, OSStatus> {
    let mut s: u8 = 0;
    // SAFETY: valid pointers to locals.
    let st = unsafe { AudioObjectIsPropertySettable(id, a, &mut s) };
    if st != 0 { Err(st) } else { Ok(s != 0) }
}

/// Reads a fixed-size property.
pub fn get<T: Copy + Default>(
    id: AudioObjectID,
    a: &AudioObjectPropertyAddress,
) -> Result<T, OSStatus> {
    let mut v = T::default();
    let mut size = std::mem::size_of::<T>() as u32;
    // SAFETY: `v` is a valid, writable T of `size` bytes.
    let st = unsafe {
        AudioObjectGetPropertyData(id, a, 0, ptr::null(), &mut size, (&mut v as *mut T).cast())
    };
    if st != 0 { Err(st) } else { Ok(v) }
}

/// Reads an array property.
pub fn get_vec<T: Copy + Default>(
    id: AudioObjectID,
    a: &AudioObjectPropertyAddress,
) -> Result<Vec<T>, OSStatus> {
    let mut size: u32 = 0;
    // SAFETY: valid pointers to locals.
    let st = unsafe { AudioObjectGetPropertyDataSize(id, a, 0, ptr::null(), &mut size) };
    if st != 0 {
        return Err(st);
    }
    let n = size as usize / std::mem::size_of::<T>();
    let mut v = vec![T::default(); n];
    let mut size = (n * std::mem::size_of::<T>()) as u32;
    // SAFETY: `v` has room for `size` bytes.
    let st = unsafe {
        AudioObjectGetPropertyData(id, a, 0, ptr::null(), &mut size, v.as_mut_ptr().cast())
    };
    if st != 0 {
        return Err(st);
    }
    v.truncate(size as usize / std::mem::size_of::<T>());
    Ok(v)
}

/// Reads a CFString property and releases it.
pub fn get_string(id: AudioObjectID, a: &AudioObjectPropertyAddress) -> Result<String, OSStatus> {
    let mut s: *const c_void = ptr::null();
    let mut size = std::mem::size_of::<*const c_void>() as u32;
    // SAFETY: the HAL writes a retained CFStringRef into `s`.
    let st = unsafe {
        AudioObjectGetPropertyData(
            id,
            a,
            0,
            ptr::null(),
            &mut size,
            (&mut s as *mut *const c_void).cast(),
        )
    };
    if st != 0 {
        return Err(st);
    }
    if s.is_null() {
        return Ok(String::new());
    }
    // SAFETY: `s` is a valid CFString we own; released below.
    unsafe {
        let cap =
            CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
        let mut buf = vec![0u8; cap.max(1) as usize];
        let ok = CFStringGetCString(s, buf.as_mut_ptr().cast(), cap, kCFStringEncodingUTF8);
        CFRelease(s);
        if ok == 0 {
            return Ok(String::new());
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
    }
}

pub fn set<T: Copy>(
    id: AudioObjectID,
    a: &AudioObjectPropertyAddress,
    v: &T,
) -> Result<(), OSStatus> {
    // SAFETY: `v` is a valid T of the stated size.
    let st = unsafe {
        AudioObjectSetPropertyData(
            id,
            a,
            0,
            ptr::null(),
            std::mem::size_of::<T>() as u32,
            (v as *const T).cast(),
        )
    };
    if st != 0 { Err(st) } else { Ok(()) }
}

/// A serializable rendering of an ASBD.
#[derive(Debug, Clone, Serialize)]
pub struct FormatDesc {
    pub sample_rate: f64,
    pub format_id: String,
    pub label: Option<&'static str>,
    pub flags: Vec<&'static str>,
    pub channels: u32,
    pub bits_per_channel: u32,
    pub bytes_per_frame: u32,
    pub bytes_per_packet: u32,
    pub frames_per_packet: u32,
    pub non_mixable: bool,
    /// Not linear PCM, or flagged non-mixable: the "encoded" candidates.
    pub encoded_candidate: bool,
    /// Present for entries from an "available formats" list.
    pub rate_range: Option<(f64, f64)>,
}

impl FormatDesc {
    pub fn from_asbd(f: &AudioStreamBasicDescription, range: Option<AudioValueRange>) -> Self {
        let names = [
            (kAudioFormatFlagIsFloat, "float"),
            (kAudioFormatFlagIsBigEndian, "big-endian"),
            (kAudioFormatFlagIsSignedInteger, "signed-int"),
            (kAudioFormatFlagIsPacked, "packed"),
            (kAudioFormatFlagIsAlignedHigh, "aligned-high"),
            (kAudioFormatFlagIsNonInterleaved, "non-interleaved"),
            (kAudioFormatFlagIsNonMixable, "non-mixable"),
        ];
        let non_mixable = f.format_flags & kAudioFormatFlagIsNonMixable != 0;
        FormatDesc {
            sample_rate: f.sample_rate,
            format_id: fourcc_str(f.format_id),
            label: format_label(f.format_id),
            flags: names
                .iter()
                .filter(|(b, _)| f.format_flags & b != 0)
                .map(|(_, n)| *n)
                .collect(),
            channels: f.channels_per_frame,
            bits_per_channel: f.bits_per_channel,
            bytes_per_frame: f.bytes_per_frame,
            bytes_per_packet: f.bytes_per_packet,
            frames_per_packet: f.frames_per_packet,
            non_mixable,
            encoded_candidate: non_mixable || f.format_id != kAudioFormatLinearPCM,
            rate_range: range.map(|r| (r.minimum, r.maximum)),
        }
    }
}
