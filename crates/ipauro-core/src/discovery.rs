//! USB-NCM interface discovery — "which interface is the USB link?"
//! (`@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` §5). Ranked by
//! reliability, IOKit provenance on the HOST side (`AppleUSBNCMData` /
//! `AppleUSBECMData`) is the only signal this module feeds to bridging.
//!
//! This ports `prototype/usb-link-bridge.sh`'s `discover_usb_eth()` faithfully,
//! including its warnings:
//! - **Never `AppleUSBDeviceNCMData`.** On a host Mac that class is ALSO used
//!   by macOS's internal inter-processor NCM interfaces (the inactive
//!   `en1`..`en6`) — querying it here would try to bridge internal
//!   interfaces. Device-side peer detection is a different, diagnostic-only
//!   problem (traffic-based, per A002 §5.2) and is never fed to the bridge.
//! - **Never MAC-match, never `anpi*`.** Both are decoys (A002 §5.4, §3).
//!   This module never looks at MACs or link-local addresses at all — IOKit
//!   class provenance is the entire signal.
//! - A single Mac-to-Mac link can surface TWO host-side NCM interfaces (one
//!   live, one inert with no traffic). Bridging the inert one is harmless; a
//!   caller must not equate interface count with peer count.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Source of USB-NCM Ethernet interface (BSD `enN`) names. Behind a trait so
/// the reconciler and its tests never shell out to `ioreg` — see
/// [`MockUsbNcmSource`] for the scripted test double.
pub trait UsbNcmSource: Send + Sync {
    /// Sorted, deduped BSD names of every USB-NCM interface currently
    /// present. Empty is a valid answer ("no Mac plugged in right now"), not
    /// an error; `Err` is reserved for the discovery mechanism itself
    /// failing (e.g. `ioreg` not spawning).
    fn discover(&self) -> anyhow::Result<Vec<String>>;
}

/// The exact two `ioreg` classes `discover_usb_eth()` queries — HOST-side
/// USB-NCM gadget classes only. Order doesn't matter; results are merged and
/// deduped. Deliberately excludes `AppleUSBDeviceNCMData` (see module docs).
pub const NCM_HOST_CLASSES: [&str; 2] = ["AppleUSBNCMData", "AppleUSBECMData"];

/// Extract BSD Ethernet interface names (`enN`) from raw `ioreg -r -c <class>
/// -w0` text, matching tree lines of the shape `+-o enN  <class ...>`. Mirrors
/// the shell's `grep -oE '\+-o en[0-9]+' | grep -oE 'en[0-9]+'` exactly:
/// requires the literal `en` prefix immediately followed by one or more
/// digits, so lookalikes (`enclosure0`, an `anpi0` decoy, anything without
/// digits right after `en`) never match. Pure and unit-testable without a
/// real Mac — see the tests below for canned real output.
pub fn parse_ncm_bsd_names(ioreg_text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in ioreg_text.lines() {
        let Some(idx) = line.find("+-o en") else { continue };
        let rest = &line[idx + "+-o ".len()..]; // now starts with "en..."
        let digit_end = rest["en".len()..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|n| "en".len() + n)
            .unwrap_or(rest.len());
        if digit_end > "en".len() {
            names.push(rest[..digit_end].to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Real implementation: shells out to `ioreg` for each of [`NCM_HOST_CLASSES`]
/// and unions the parsed results. macOS-only — `ioreg` doesn't exist
/// elsewhere, and this whole discovery model is IOKit-specific.
#[cfg(target_os = "macos")]
pub struct IoregUsbNcmSource;

#[cfg(target_os = "macos")]
impl IoregUsbNcmSource {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl Default for IoregUsbNcmSource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl UsbNcmSource for IoregUsbNcmSource {
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        use anyhow::Context;
        use std::collections::BTreeSet;

        let mut names = BTreeSet::new();
        for class in NCM_HOST_CLASSES {
            let output = std::process::Command::new("ioreg")
                .args(["-r", "-c", class, "-w0"])
                .output()
                .with_context(|| format!("spawning `ioreg -r -c {class} -w0`"))?;
            // ioreg exits non-zero when nothing matches the class (no cable
            // plugged in right now) — that is a valid "nothing discovered"
            // result, not a discovery failure, so we don't check status: any
            // stdout it produced is still meaningful, and empty stdout parses
            // to no names either way.
            let text = String::from_utf8_lossy(&output.stdout);
            names.extend(parse_ncm_bsd_names(&text));
        }
        Ok(names.into_iter().collect())
    }
}

/// The non-macOS stand-in. There is no USB-NCM/IOKit discovery mechanism
/// outside macOS; "no interfaces found" is the honest answer, never an
/// error — this is a platform gap, not a fault.
#[cfg(not(target_os = "macos"))]
pub struct NoUsbNcmSource;

#[cfg(not(target_os = "macos"))]
impl UsbNcmSource for NoUsbNcmSource {
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// Scriptable test double: a queue of discovery results consumed one per
/// call, holding the last-returned result once the queue empties (so a test
/// doesn't have to over-provision calls whose exact count it can't predict —
/// e.g. the reconciler's own retry loop). [`MockUsbNcmSource::push`] appends
/// a new result at any time, letting a test simulate a live event (a replug)
/// happening mid-run, which the background watch task then picks up on its
/// own next poll — exactly the thing under test in the M-incident case.
pub struct MockUsbNcmSource {
    script: Mutex<VecDeque<Vec<String>>>,
    last: Mutex<Vec<String>>,
}

impl MockUsbNcmSource {
    pub fn new(script: impl IntoIterator<Item = Vec<String>>) -> Self {
        Self { script: Mutex::new(script.into_iter().collect()), last: Mutex::new(Vec::new()) }
    }

    /// Append another scripted result, to be returned once the queue reaches
    /// it (i.e. after every call already queued ahead of it).
    pub fn push(&self, next: Vec<String>) {
        self.script.lock().expect("script mutex poisoned").push_back(next);
    }
}

impl Default for MockUsbNcmSource {
    fn default() -> Self {
        Self::new([])
    }
}

impl UsbNcmSource for MockUsbNcmSource {
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        let mut script = self.script.lock().expect("script mutex poisoned");
        let mut last = self.last.lock().expect("last mutex poisoned");
        let result = script.pop_front().unwrap_or_else(|| last.clone());
        *last = result.clone();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic canned output for the HOST side of a healthy USB-C Mac-to-Mac
    /// link, shaped like `ioreg -r -c AppleUSBNCMData -w0` really prints
    /// (mirrors A002 §1's captured hierarchy). Includes a SECOND, inert
    /// host-side NCM interface (`en10`) per A002's "one link can surface two
    /// host-side interfaces" finding, plus an `anpi0` decoy line (wrong class
    /// entirely in real output, but included here as defense-in-depth: the
    /// `+-o en[0-9]+` pattern must not be fooled by it either way) to prove
    /// the parser is precise, not merely lucky.
    const REALISTIC_HOST_SIDE_IOREG: &str = r#"
+-o AppleT8142USBXHCI@02000000  <class AppleT8142USBXHCI, id 0x100000275, registered, matched, active, busy 0 (2 ms), retain 32>
  +-o Mac@02100000  <class IOUSBHostDevice, id 0x100000387, registered, matched, active, busy 0 (0 ms), retain 9>
    +-o NCM Control@0  <class AppleUSBNCMControl, id 0x10000038e, registered, matched, active, busy 0 (0 ms), retain 6>
    +-o NCM Data@1  <class AppleUSBNCMData, id 0x100000390, registered, matched, active, busy 0 (0 ms), retain 7>
      +-o en9  <class IOEthernetInterface, id 0x1000003a0, registered, matched, active, busy 0 (0 ms), retain 10>
  +-o anpi0  <class IO80211Interface, id 0x100000222, registered, matched, active, busy 0 (0 ms), retain 5>
  +-o Mac@02200000  <class IOUSBHostDevice, id 0x100000399, registered, matched, active, busy 0 (0 ms), retain 9>
    +-o NCM Data@1  <class AppleUSBNCMData, id 0x1000003a5, registered, matched, active, busy 0 (0 ms), retain 7>
      +-o en10  <class IOEthernetInterface, id 0x1000003b0, registered, matched, active, busy 0 (0 ms), retain 10>
"#;

    /// Canned output for a THIRD peer link (a fresh cable, e.g. the M-incident
    /// test's second member before the detach).
    const REALISTIC_HOST_SIDE_IOREG_SECOND_PEER: &str = r#"
+-o AppleT8142USBXHCI@03000000  <class AppleT8142USBXHCI, id 0x100000276, registered, matched, active, busy 0 (2 ms), retain 32>
  +-o Mac@03100000  <class IOUSBHostDevice, id 0x1000003c0, registered, matched, active, busy 0 (0 ms), retain 9>
    +-o NCM Data@1  <class AppleUSBNCMData, id 0x1000003c5, registered, matched, active, busy 0 (0 ms), retain 7>
      +-o en12  <class IOEthernetInterface, id 0x1000003d0, registered, matched, active, busy 0 (0 ms), retain 10>
"#;

    /// What the DEVICE side of a link shows for `AppleUSBDeviceNCMData` —
    /// macOS's internal inter-processor NCM interfaces (A002 §5, the
    /// `usb-link-bridge.sh` comment on `en1..en6`). This class is never
    /// queried by [`IoregUsbNcmSource`]; kept here only to prove that safety.
    const DEVICE_SIDE_DECOY_IOREG: &str = r#"
+-o AppleUSBDeviceNCMData@1  <class AppleUSBDeviceNCMData, id 0x100000410, registered, matched, active, busy 0 (0 ms), retain 4>
  +-o en1  <class IOEthernetInterface, id 0x100000411, registered, matched, active, busy 0 (0 ms), retain 6>
+-o AppleUSBDeviceNCMData@2  <class AppleUSBDeviceNCMData, id 0x100000412, registered, matched, active, busy 0 (0 ms), retain 4>
  +-o en2  <class IOEthernetInterface, id 0x100000413, registered, matched, active, busy 0 (0 ms), retain 6>
"#;

    #[test]
    fn parses_realistic_host_side_output_ignoring_the_anpi_decoy() {
        let names = parse_ncm_bsd_names(REALISTIC_HOST_SIDE_IOREG);
        assert_eq!(names, vec!["en10".to_string(), "en9".to_string()]);
    }

    #[test]
    fn merges_multiple_ioreg_invocations_like_the_real_source_does() {
        let mut names = parse_ncm_bsd_names(REALISTIC_HOST_SIDE_IOREG);
        names.extend(parse_ncm_bsd_names(REALISTIC_HOST_SIDE_IOREG_SECOND_PEER));
        names.sort();
        names.dedup();
        assert_eq!(names, vec!["en10".to_string(), "en12".to_string(), "en9".to_string()]);
    }

    #[test]
    fn ignores_lookalikes_without_a_digit_run() {
        let text = "  +-o enclosure0  <class IOService, id 0x1, registered>\n";
        assert!(parse_ncm_bsd_names(text).is_empty());
    }

    /// The parser alone is NOT the safety mechanism here — fed device-side
    /// text directly, it extracts `en1`/`en2` just like it would extract any
    /// other `enN` line. This is exactly why `IoregUsbNcmSource::discover`
    /// architecturally never invokes `ioreg -c AppleUSBDeviceNCMData`: see
    /// `device_side_class_is_never_queried` below for that guarantee.
    #[test]
    fn parser_would_extract_device_side_decoys_if_ever_fed_them() {
        let names = parse_ncm_bsd_names(DEVICE_SIDE_DECOY_IOREG);
        assert_eq!(names, vec!["en1".to_string(), "en2".to_string()]);
    }

    #[test]
    fn device_side_class_is_never_queried() {
        assert!(
            !NCM_HOST_CLASSES.contains(&"AppleUSBDeviceNCMData"),
            "AppleUSBDeviceNCMData surfaces macOS's internal inter-processor \
             NCM interfaces (en1..en6) on a host Mac — querying it would try \
             to bridge them (A002 §5)"
        );
    }

    #[test]
    fn mock_replays_script_then_holds_last() {
        let mock = MockUsbNcmSource::new([vec!["en9".to_string()], vec!["en9".to_string(), "en12".to_string()]]);
        assert_eq!(mock.discover().unwrap(), vec!["en9".to_string()]);
        assert_eq!(mock.discover().unwrap(), vec!["en9".to_string(), "en12".to_string()]);
        // Script exhausted: holds the last value indefinitely.
        assert_eq!(mock.discover().unwrap(), vec!["en9".to_string(), "en12".to_string()]);
        assert_eq!(mock.discover().unwrap(), vec!["en9".to_string(), "en12".to_string()]);
    }

    #[test]
    fn mock_push_appends_after_construction() {
        let mock = MockUsbNcmSource::new([vec!["en9".to_string(), "en12".to_string()]]);
        assert_eq!(mock.discover().unwrap(), vec!["en9".to_string(), "en12".to_string()]);
        // Simulate a live detach happening mid-test.
        mock.push(vec!["en9".to_string()]);
        assert_eq!(mock.discover().unwrap(), vec!["en9".to_string()]);
    }
}
