//! CTA-861 Short Audio Descriptors: the 3-byte records in which an HDMI sink
//! (TV/AVR) lists the audio formats it decodes. Both EDID and ELD carry them.
//!
//! The Atmos-relevant bits sit in byte 3 (index 2). Their meanings were
//! checked against `edid-decode` as an oracle (tests/edid_decode_oracle.rs):
//! - E-AC-3 (code 10): bit 0 = Joint Object Coding (DD+ Atmos), bit 1 =
//!   JOC with ACMOD 28.
//! - MAT (code 12): bit 0 = "Dolby TrueHD, object audio PCM and
//!   channel-based PCM" (clear = "only Dolby TrueHD"); bit 1, only meaningful
//!   when bit 0 is set, = hash calculation **not** required for object/
//!   channel-based PCM.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AudioFormat {
    Lpcm,
    Ac3,
    Mpeg1,
    Mp3,
    Mpeg2,
    AacLc,
    Dts,
    Atrac,
    OneBitAudio,
    /// Dolby Digital Plus.
    Eac3,
    DtsHd,
    /// Dolby MAT (TrueHD / MLP, and per CTA-861 MAT 2.0 object PCM).
    Mat,
    Dst,
    WmaPro,
    /// Code 15: the real format is in the extension type code.
    Extension(ExtensionType),
    Reserved(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExtensionType {
    HeAac,
    HeAacV2,
    Mpeg4AacLc,
    Dra,
    HeAacMpegSurround,
    AacLcMpegSurround,
    MpegH3d,
    Ac4,
    Lpcm3d,
    Other(u8),
}

impl AudioFormat {
    pub fn name(&self) -> String {
        match self {
            AudioFormat::Lpcm => "LPCM".into(),
            AudioFormat::Ac3 => "AC-3".into(),
            AudioFormat::Mpeg1 => "MPEG-1 L1/L2".into(),
            AudioFormat::Mp3 => "MP3".into(),
            AudioFormat::Mpeg2 => "MPEG-2 multichannel".into(),
            AudioFormat::AacLc => "AAC LC".into(),
            AudioFormat::Dts => "DTS".into(),
            AudioFormat::Atrac => "ATRAC".into(),
            AudioFormat::OneBitAudio => "One Bit Audio".into(),
            AudioFormat::Eac3 => "E-AC-3 (DD+)".into(),
            AudioFormat::DtsHd => "DTS-HD".into(),
            AudioFormat::Mat => "MAT (MLP/TrueHD)".into(),
            AudioFormat::Dst => "DST".into(),
            AudioFormat::WmaPro => "WMA Pro".into(),
            AudioFormat::Extension(e) => match e {
                ExtensionType::HeAac => "MPEG-4 HE-AAC".into(),
                ExtensionType::HeAacV2 => "MPEG-4 HE-AAC v2".into(),
                ExtensionType::Mpeg4AacLc => "MPEG-4 AAC LC".into(),
                ExtensionType::Dra => "DRA".into(),
                ExtensionType::HeAacMpegSurround => "MPEG-4 HE-AAC + MPEG Surround".into(),
                ExtensionType::AacLcMpegSurround => "MPEG-4 AAC LC + MPEG Surround".into(),
                ExtensionType::MpegH3d => "MPEG-H 3D Audio".into(),
                ExtensionType::Ac4 => "AC-4".into(),
                ExtensionType::Lpcm3d => "L-PCM 3D Audio".into(),
                ExtensionType::Other(v) => format!("extension type {v}"),
            },
            AudioFormat::Reserved(v) => format!("reserved format code {v}"),
        }
    }
}

/// Sample rates bitmap order (byte 2): 32, 44.1, 48, 88.2, 96, 176.4, 192 kHz.
const RATES: [u32; 7] = [32000, 44100, 48000, 88200, 96000, 176400, 192000];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sad {
    pub raw: [u8; 3],
    pub format: AudioFormat,
    pub format_name: String,
    /// Max channels (byte 1 bits 0..=2, plus one). Not meaningful for
    /// MPEG-H 3D or AC-4, which reuse those bits.
    pub max_channels: u8,
    pub sample_rates: Vec<u32>,
    /// LPCM only.
    pub lpcm_bit_depths: Vec<u8>,
    /// AC-3, MPEG-1/2, MP3, AAC, DTS, ATRAC: max bitrate in kbit/s.
    pub max_bitrate_kbps: Option<u32>,
    /// E-AC-3 byte 3 bit 0.
    pub eac3_joc: bool,
    /// E-AC-3 byte 3 bit 1.
    pub eac3_joc_acmod28: bool,
    /// MAT byte 3 bit 0: object audio PCM + channel-based PCM, beyond TrueHD.
    pub mat_object_pcm: bool,
    /// MAT byte 3 bit 1 (when bit 0 set): `Some(true)` = the sink requires
    /// a hash for object/channel PCM, `Some(false)` = it does not.
    pub mat_hash_required: Option<bool>,
}

impl Sad {
    pub fn parse(b: [u8; 3]) -> Sad {
        let code = (b[0] >> 3) & 0x0f;
        let format = match code {
            1 => AudioFormat::Lpcm,
            2 => AudioFormat::Ac3,
            3 => AudioFormat::Mpeg1,
            4 => AudioFormat::Mp3,
            5 => AudioFormat::Mpeg2,
            6 => AudioFormat::AacLc,
            7 => AudioFormat::Dts,
            8 => AudioFormat::Atrac,
            9 => AudioFormat::OneBitAudio,
            10 => AudioFormat::Eac3,
            11 => AudioFormat::DtsHd,
            12 => AudioFormat::Mat,
            13 => AudioFormat::Dst,
            14 => AudioFormat::WmaPro,
            15 => AudioFormat::Extension(match b[2] >> 3 {
                4 => ExtensionType::HeAac,
                5 => ExtensionType::HeAacV2,
                6 => ExtensionType::Mpeg4AacLc,
                7 => ExtensionType::Dra,
                8 => ExtensionType::HeAacMpegSurround,
                10 => ExtensionType::AacLcMpegSurround,
                11 => ExtensionType::MpegH3d,
                12 => ExtensionType::Ac4,
                13 => ExtensionType::Lpcm3d,
                v => ExtensionType::Other(v),
            }),
            v => AudioFormat::Reserved(v),
        };
        let sample_rates = RATES
            .iter()
            .enumerate()
            .filter(|(i, _)| b[1] & (1 << i) != 0)
            .map(|(_, r)| *r)
            .collect();
        let lpcm_bit_depths = if format == AudioFormat::Lpcm {
            [16u8, 20, 24]
                .iter()
                .enumerate()
                .filter(|(i, _)| b[2] & (1 << i) != 0)
                .map(|(_, d)| *d)
                .collect()
        } else {
            Vec::new()
        };
        let max_bitrate_kbps = (2..=8).contains(&code).then(|| u32::from(b[2]) * 8);
        let is_eac3 = format == AudioFormat::Eac3;
        let is_mat = format == AudioFormat::Mat;
        let mat_object_pcm = is_mat && b[2] & 0x01 != 0;
        Sad {
            raw: b,
            format_name: format.name(),
            format,
            max_channels: (b[0] & 0x07) + 1,
            sample_rates,
            lpcm_bit_depths,
            max_bitrate_kbps,
            eac3_joc: is_eac3 && b[2] & 0x01 != 0,
            eac3_joc_acmod28: is_eac3 && b[2] & 0x02 != 0,
            mat_object_pcm,
            mat_hash_required: mat_object_pcm.then_some(b[2] & 0x02 == 0),
        }
    }

    /// Parses a run of SADs (length a multiple of 3; any tail is ignored).
    pub fn parse_all(bytes: &[u8]) -> Vec<Sad> {
        bytes
            .chunks_exact(3)
            .map(|c| Sad::parse([c[0], c[1], c[2]]))
            .collect()
    }

    /// One-line human description, roughly in edid-decode's vocabulary.
    pub fn describe(&self) -> String {
        let rates: Vec<String> = self
            .sample_rates
            .iter()
            .map(|r| {
                if r % 1000 == 0 {
                    format!("{}", r / 1000)
                } else {
                    format!("{:.1}", f64::from(*r) / 1000.0)
                }
            })
            .collect();
        let mut s = format!(
            "{}: {} ch, {} kHz",
            self.format_name,
            self.max_channels,
            rates.join("/")
        );
        if !self.lpcm_bit_depths.is_empty() {
            let d: Vec<String> = self.lpcm_bit_depths.iter().map(|d| d.to_string()).collect();
            s += &format!(", {} bit", d.join("/"));
        }
        if let Some(k) = self.max_bitrate_kbps {
            s += &format!(", ≤{k} kbit/s");
        }
        if self.eac3_joc {
            s += ", JOC (Atmos)";
        }
        if self.eac3_joc_acmod28 {
            s += ", JOC ACMOD28";
        }
        if self.format == AudioFormat::Mat {
            s += if self.mat_object_pcm {
                ", TrueHD + object audio PCM + channel-based PCM"
            } else {
                ", TrueHD only"
            };
            match self.mat_hash_required {
                Some(true) => s += ", hash REQUIRED for PCM",
                Some(false) => s += ", hash not required",
                None => {}
            }
        }
        s
    }
}

/// Speaker Allocation (3 bytes; ELD carries only the first byte). Bit
/// names as edid-decode prints them.
pub const SPEAKER_BITS: [[&str; 8]; 3] = [
    [
        "FL/FR", "LFE1", "FC", "BL/BR", "BC", "FLc/FRc", "RLC/RRC", "FLw/FRw",
    ],
    [
        "TpFL/TpFR",
        "TpC",
        "TpFC",
        "LS/RS",
        "LFE2",
        "TpBC",
        "SiL/SiR",
        "TpSiL/TpSiR",
    ],
    [
        "TpBL/TpBR",
        "BtFC",
        "BtFL/BtFR",
        "TpLS/TpRS",
        "LSd/RSd",
        "",
        "",
        "",
    ],
];

pub fn speakers(bytes: &[u8]) -> Vec<&'static str> {
    let mut v = Vec::new();
    for (i, b) in bytes.iter().take(3).enumerate() {
        for (bit, name) in SPEAKER_BITS[i].iter().enumerate() {
            if b & (1 << bit) != 0 && !name.is_empty() {
                v.push(*name);
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atmos_bits() {
        let joc = Sad::parse([(10 << 3) | 7, 0x07, 0x01]);
        assert!(joc.eac3_joc && !joc.eac3_joc_acmod28);
        let mat_old = Sad::parse([(12 << 3) | 7, 0x54, 0x00]);
        assert!(!mat_old.mat_object_pcm);
        assert_eq!(mat_old.mat_hash_required, None);
        let mat_hash = Sad::parse([(12 << 3) | 7, 0x54, 0x01]);
        assert_eq!(mat_hash.mat_hash_required, Some(true));
        let mat_nohash = Sad::parse([(12 << 3) | 7, 0x54, 0x03]);
        assert_eq!(mat_nohash.mat_hash_required, Some(false));
        assert_eq!(mat_nohash.sample_rates, vec![48000, 96000, 192000]);
        // A bit-0 flag on another format means nothing.
        assert!(!Sad::parse([(2 << 3) | 5, 0x07, 0x01]).eac3_joc);
    }

    #[test]
    fn speaker_names() {
        assert_eq!(
            speakers(&[0x0f, 0x09, 0x01]),
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
    }
}
