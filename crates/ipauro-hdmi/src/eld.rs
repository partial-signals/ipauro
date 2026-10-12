//! ELD (EDID-Like Data): the HD Audio summary of a sink's audio
//! capabilities that the HDMI/DP transmitter hands the audio driver. The
//! binary layout follows the HDA specification as implemented by Linux
//! (sound/pci/hda/hda_eld.c, `snd_hdmi_parse_eld`).
//!
//! Linux's `/proc/asound/cardN/eld#D.P` text drops SAD byte 3, so it
//! **cannot** show the JOC / MAT-object-PCM flags. Use the binary ELD (ALSA
//! control `ELD`) or the DRM EDID for those. [`parse_proc_text`] reports
//! what the text does carry.

use serde::Serialize;

use crate::edid::pnp_id_le;
use crate::sad::{self, Sad};

#[derive(Debug, Clone, Serialize)]
pub struct Eld {
    pub eld_version: u8,
    pub cea_edid_version: u8,
    pub monitor_name: String,
    /// 0 = HDMI, 1 = DisplayPort.
    pub connection_type: u8,
    pub supports_hdcp: bool,
    pub supports_ai: bool,
    pub audio_sync_delay_ms: u16,
    pub speaker_allocation: u8,
    pub speakers: Vec<&'static str>,
    pub port_id: u64,
    pub manufacturer: String,
    pub product_id: u16,
    pub sads: Vec<Sad>,
}

const FIXED_BYTES: usize = 20;

pub fn parse(buf: &[u8]) -> Option<Eld> {
    if buf.len() < FIXED_BYTES {
        return None;
    }
    let mnl = usize::from(buf[4] & 0x1f);
    let sad_count = usize::from(buf[5] >> 4);
    let name = buf.get(FIXED_BYTES..FIXED_BYTES + mnl)?;
    let sads_at = FIXED_BYTES + mnl;
    let sads = Sad::parse_all(buf.get(sads_at..sads_at + 3 * sad_count)?);
    Some(Eld {
        eld_version: buf[0] >> 3,
        cea_edid_version: buf[4] >> 5,
        monitor_name: String::from_utf8_lossy(name)
            .trim_end_matches('\0')
            .to_string(),
        connection_type: (buf[5] >> 2) & 0x3,
        supports_hdcp: buf[5] & 0x1 != 0,
        supports_ai: buf[5] & 0x2 != 0,
        audio_sync_delay_ms: u16::from(buf[6]) * 2,
        speaker_allocation: buf[7] & 0x7f,
        speakers: sad::speakers(&[buf[7] & 0x7f]),
        port_id: u64::from_le_bytes(buf[8..16].try_into().ok()?),
        manufacturer: pnp_id_le(u16::from_le_bytes([buf[16], buf[17]])),
        product_id: u16::from_le_bytes([buf[18], buf[19]]),
        sads,
    })
}

/// The subset of `/proc/asound/cardN/eld#D.P` worth reporting.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProcEld {
    pub monitor_present: bool,
    pub eld_valid: bool,
    pub monitor_name: Option<String>,
    pub connection_type: Option<String>,
    pub speakers: Option<String>,
    /// `sadN_coding_type` values, e.g. `"[0xa] E-AC-3/DD+ (Dolby Digital Plus)"`.
    pub sad_coding_types: Vec<String>,
    /// `sadN_channels`, aligned with `sad_coding_types`.
    pub sad_channels: Vec<Option<u8>>,
}

pub fn parse_proc_text(text: &str) -> ProcEld {
    let mut e = ProcEld::default();
    for line in text.lines() {
        let mut parts = line.splitn(2, char::is_whitespace);
        let (Some(k), Some(v)) = (parts.next(), parts.next()) else {
            continue;
        };
        let v = v.trim();
        match k {
            "monitor_present" => e.monitor_present = v == "1",
            "eld_valid" => e.eld_valid = v == "1",
            "monitor_name" => e.monitor_name = Some(v.to_string()),
            "connection_type" => e.connection_type = Some(v.to_string()),
            "speakers" => e.speakers = Some(v.to_string()),
            _ => {
                if let Some(rest) = k.strip_prefix("sad") {
                    if let Some(idx) = rest
                        .strip_suffix("_coding_type")
                        .and_then(|n| n.parse::<usize>().ok())
                    {
                        if e.sad_coding_types.len() <= idx {
                            e.sad_coding_types.resize(idx + 1, String::new());
                            e.sad_channels.resize(idx + 1, None);
                        }
                        e.sad_coding_types[idx] = v.to_string();
                    } else if let Some(idx) = rest
                        .strip_suffix("_channels")
                        .and_then(|n| n.parse::<usize>().ok())
                    {
                        if e.sad_channels.len() <= idx {
                            e.sad_coding_types.resize(idx + 1, String::new());
                            e.sad_channels.resize(idx + 1, None);
                        }
                        e.sad_channels[idx] = v.parse().ok();
                    }
                }
            }
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_eld() {
        let mut b = vec![0u8; FIXED_BYTES];
        b[0] = 2 << 3;
        b[2] = 6;
        b[4] = (3 << 5) | 4; // CEA ver 3, name length 4
        b[5] = 2 << 4; // 2 SADs, HDMI
        b[7] = 0x0f;
        b[16..18].copy_from_slice(&0x4ca3u16.to_le_bytes());
        b.extend_from_slice(b"AVR1");
        b.extend_from_slice(&[(10 << 3) | 7, 0x07, 0x01, (12 << 3) | 7, 0x54, 0x03]);
        let e = parse(&b).unwrap();
        assert_eq!(e.monitor_name, "AVR1");
        assert_eq!(e.sads.len(), 2);
        assert!(e.sads[0].eac3_joc);
        assert_eq!(e.sads[1].mat_hash_required, Some(false));
        assert_eq!(e.speakers, ["FL/FR", "LFE1", "FC", "BL/BR"]);
    }

    #[test]
    fn parses_proc_text() {
        let t = "monitor_present\t\t1\neld_valid\t\t1\nmonitor_name\t\tRX-A8A\n\
                 connection_type\t\tHDMI\nsad_count\t\t2\nsad0_coding_type\t[0x1] LPCM\n\
                 sad0_channels\t\t8\nsad1_coding_type\t[0xc] MLP (Dolby TrueHD)\nsad1_channels\t\t8\n";
        let e = parse_proc_text(t);
        assert!(e.monitor_present && e.eld_valid);
        assert_eq!(e.monitor_name.as_deref(), Some("RX-A8A"));
        assert_eq!(e.sad_coding_types.len(), 2);
        assert_eq!(e.sad_channels[1], Some(8));
    }
}
