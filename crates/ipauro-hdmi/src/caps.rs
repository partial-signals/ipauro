//! Sink audio capabilities, reduced to the questions W002 asks: which
//! Atmos-capable carriers will this sink accept, and what does each one need
//! from the source's transport?

use serde::Serialize;

use crate::sad::{AudioFormat, ExtensionType, Sad};

/// A way to get object audio to the sink's renderer, and what it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AtmosCarrier {
    /// Dolby Digital Plus with Joint Object Coding (ETSI TS 103 420). Needs
    /// IEC 61937 type 21 at 4× rate: a 2-ch 192 kHz non-audio link.
    Eac3Joc,
    /// Dolby MAT carrying object audio PCM ("MAT 2.0"). Needs IEC 61937
    /// type 22 over HDMI HBR (8-ch 192 kHz non-audio).
    MatObjectPcm,
    /// Dolby TrueHD with the Atmos extension, inside MAT. Same HBR transport;
    /// it needs a TrueHD+Atmos *encoder*, which nobody has in the open.
    TrueHdAtmos,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SinkAudioCaps {
    pub lpcm_max_channels: u8,
    pub lpcm_192k: bool,
    pub ac3: bool,
    pub eac3: bool,
    pub eac3_joc: bool,
    pub eac3_joc_acmod28: bool,
    pub mat: bool,
    pub mat_object_pcm: bool,
    /// Present when `mat_object_pcm`.
    pub mat_hash_required: Option<bool>,
    pub dts: bool,
    pub dts_hd: bool,
    pub mpegh_3d: bool,
    pub ac4: bool,
    /// Carriers this sink advertises, best-documented first.
    pub atmos_carriers: Vec<AtmosCarrier>,
    /// Plain-language observations for the report.
    pub notes: Vec<String>,
}

impl SinkAudioCaps {
    pub fn from_sads<'a>(sads: impl IntoIterator<Item = &'a Sad>) -> Self {
        let mut c = SinkAudioCaps::default();
        for s in sads {
            match s.format {
                AudioFormat::Lpcm => {
                    c.lpcm_max_channels = c.lpcm_max_channels.max(s.max_channels);
                    c.lpcm_192k |= s.sample_rates.contains(&192_000);
                }
                AudioFormat::Ac3 => c.ac3 = true,
                AudioFormat::Eac3 => {
                    c.eac3 = true;
                    c.eac3_joc |= s.eac3_joc;
                    c.eac3_joc_acmod28 |= s.eac3_joc_acmod28;
                }
                AudioFormat::Mat => {
                    c.mat = true;
                    if s.mat_object_pcm {
                        c.mat_object_pcm = true;
                        // If any MAT SAD waives the hash, record the waiver.
                        c.mat_hash_required = Some(
                            c.mat_hash_required.unwrap_or(true)
                                && s.mat_hash_required == Some(true),
                        );
                    }
                }
                AudioFormat::Dts => c.dts = true,
                AudioFormat::DtsHd => c.dts_hd = true,
                AudioFormat::Extension(ExtensionType::MpegH3d) => c.mpegh_3d = true,
                AudioFormat::Extension(ExtensionType::Ac4) => c.ac4 = true,
                _ => {}
            }
        }
        if c.eac3_joc {
            c.atmos_carriers.push(AtmosCarrier::Eac3Joc);
        }
        if c.mat_object_pcm {
            c.atmos_carriers.push(AtmosCarrier::MatObjectPcm);
        }
        if c.mat {
            c.atmos_carriers.push(AtmosCarrier::TrueHdAtmos);
            c.notes.push(
                "MAT/TrueHD advertised: TrueHD-Atmos decode is likely, but no SAD bit \
                 distinguishes TrueHD with vs without Atmos"
                    .into(),
            );
        }
        if c.eac3 && !c.eac3_joc {
            c.notes.push(
                "E-AC-3 advertised WITHOUT the JOC bit: DD+ Atmos may not be decoded as objects"
                    .into(),
            );
        }
        match c.mat_hash_required {
            Some(true) => c.notes.push(
                "MAT object PCM requires a source-side hash: an independent MAT 2.0 encoder must \
                 also reproduce that hash (unknown algorithm; W002 H-M3)"
                    .into(),
            ),
            Some(false) => c
                .notes
                .push("MAT object PCM accepted without a hash".into()),
            None => {}
        }
        if !c.eac3 && !c.mat {
            c.notes
                .push("No Dolby Atmos-capable carrier advertised".into());
        }
        c
    }
}
