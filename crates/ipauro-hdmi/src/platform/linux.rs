//! Linux probe backend: ALSA's procfs view of HDMI/DP audio (cards, PCM
//! devices, ELD text) and DRM's raw EDIDs. Read-only and dependency-free
//! (no libasound), so it runs on any distro and inside containers.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::eld::{self, ProcEld};

#[derive(Debug, Clone, Serialize)]
pub struct LinuxReport {
    pub cards: Vec<String>,
    pub pcm_devices: Vec<String>,
    pub elds: Vec<EldEntry>,
    /// Raw EDIDs from `/sys/class/drm/*/edid`: `(connector, status, bytes)`.
    #[serde(skip)]
    pub edids: Vec<(String, String, Vec<u8>)>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EldEntry {
    pub path: String,
    /// The ALSA device string that plays to this ELD's pin, when derivable.
    pub alsa_device_hint: Option<String>,
    pub eld: ProcEld,
}

fn read_dir_sorted(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(p)
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    v.sort();
    v
}

pub fn probe() -> LinuxReport {
    let mut r = LinuxReport {
        cards: fs::read_to_string("/proc/asound/cards")
            .map(|s| {
                s.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        pcm_devices: fs::read_to_string("/proc/asound/pcm")
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default(),
        elds: Vec::new(),
        edids: Vec::new(),
        notes: Vec::new(),
    };
    if r.cards.is_empty() {
        r.notes.push(
            "no /proc/asound/cards: ALSA not present (container or non-Linux kernel?)".into(),
        );
    }

    for card in read_dir_sorted(Path::new("/proc/asound")) {
        let Some(name) = card
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Some(card_no) = name.strip_prefix("card") else {
            continue;
        };
        for f in read_dir_sorted(&card) {
            let Some(fname) = f.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(idx) = fname.strip_prefix("eld#") {
                let Ok(text) = fs::read_to_string(&f) else {
                    continue;
                };
                // eld#<codec>.<pin index>; the pin index usually matches the
                // HDMI PCM order (hdmi:CARD=x,DEV=<index>), but not always.
                let dev = idx.split('.').nth(1).and_then(|n| n.parse::<u32>().ok());
                r.elds.push(EldEntry {
                    path: f.display().to_string(),
                    alsa_device_hint: dev
                        .map(|d| format!("hdmi:CARD={card_no},DEV={d} (verify with `aplay -L`)")),
                    eld: eld::parse_proc_text(&text),
                });
            }
        }
    }
    if !r.elds.is_empty() {
        r.notes.push(
            "/proc ELD text omits SAD byte 3, so JOC / MAT-object-PCM flags come from the DRM EDID below \
             (or the binary ALSA 'ELD' control: `amixer -c N cget iface=PCM,name=ELD,device=D`)"
                .into(),
        );
    }

    for conn in read_dir_sorted(Path::new("/sys/class/drm")) {
        let edid_path = conn.join("edid");
        let Ok(bytes) = fs::read(&edid_path) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let status = fs::read_to_string(conn.join("status"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let name = conn
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        r.edids.push((name, status, bytes));
    }
    if r.edids.is_empty() {
        r.notes.push(
            "no non-empty /sys/class/drm/*/edid (no connected display, or no DRM driver)".into(),
        );
    }
    r.notes.push(
        "transport test: `mat-inspect packetize` then e.g. \
         `aplay -D 'hdmi:CARD=0,DEV=0,AES0=0x06' -c 2 -r 192000 -f S16_LE -t raw x.eac3.spdif` \
         (E-AC-3) or `-c 8 -r 192000` (TrueHD/MAT, HBR)"
            .into(),
    );
    r
}
