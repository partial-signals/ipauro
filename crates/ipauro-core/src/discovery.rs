//! USB-NCM interface identification — "which interface is the USB link?"
//! (`@arch:see(.yah/docs/architecture/A002-ipauro-findings.md)` §5, ticket
//! R005-F7). A002 §5 ranks the available signals by reliability; this module
//! implements that ranking as a type ([`Evidence`]) and a classifier
//! ([`classify`]) rather than as a convention, so a consumer states which
//! evidence it will act on instead of remembering which query it may run.
//!
//! Three signals are gathered, and they are NOT interchangeable:
//!
//! 1. **Host-side IOKit provenance** ([`NCM_HOST_CLASSES`] — `AppleUSBNCMData`
//!    / `AppleUSBECMData`). A002 §5.1, the strongest signal, and the ONLY one
//!    that ever produces a bridge member ([`LinkInventory::bridge_members`]).
//!    This is the relay's normal role: this Mac enumerated the peer.
//! 2. **Traffic** ([`Evidence::PeerTraffic`]). A002 §5.2 — an interface whose
//!    input packet counter is advancing is carrying somebody's frames. Cannot
//!    be fooled by MAC labels or by `anpi`. Used to corroborate and to break
//!    ties, never on its own to elect a bridge member.
//! 3. **Device-side IOKit** ([`NCM_DEVICE_CLASS`] — `AppleUSBDeviceNCMData`),
//!    narrowed by link state. This is how a Mac identifies the link when it is
//!    the DEVICE end of the cable rather than the host end.
//!
//! ## Why the device-side class needs narrowing
//!
//! `AppleUSBDeviceNCMData` is overloaded: on any Mac it is ALSO the class of
//! macOS's internal inter-processor NCM interfaces (the inactive `en1`..`en6`).
//! Feeding it straight to bridging would try to bridge internal interfaces —
//! the trap `prototype/usb-link-bridge.sh` calls out in `discover_usb_eth()`.
//! The prototype's `discover_device_side()` narrows by requiring `status:
//! active` AND a configured IPv4; [`classify`] ports that narrowing exactly and
//! records the outcome as a distinct role ([`LinkRole::Internal`]) rather than
//! discarding it, so an operator reading the inventory can see the decoys were
//! seen and rejected — not merely absent.
//!
//! ## The two things we never do
//!
//! - **Never MAC-match** (A002 §5.4 — the trap that cost the prototype
//!   session). NCM MACs are host-assigned and do not appear on the peer, so
//!   matching them across machines identifies the wrong interface with total
//!   confidence. Nothing in this module reads a MAC.
//! - **Never `anpi*`** (A002 §3). Interface names are gated through
//!   [`is_ncm_iface_name`] (`^en[0-9]+$`), so `anpi0`, `awdl0`, `llw0`,
//!   `bridge90` and friends cannot enter the inventory by any path, whatever
//!   IOKit or `netstat` said about them.
//!
//! ## What a caller must not conclude
//!
//! A single Mac-to-Mac link can surface TWO host-side NCM interfaces (one live,
//! one inert with no traffic). Bridging the inert one is harmless — it never
//! forwards — so both stay bridge-eligible; but interface count is NOT peer
//! count. [`Evidence::PeerTraffic`] is what distinguishes the live one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

/// The exact two `ioreg` classes that mean "this Mac is the HOST end of a USB
/// gadget link" (A002 §5.1). Order doesn't matter; results are merged and
/// deduped. Deliberately excludes [`NCM_DEVICE_CLASS`] — see module docs.
pub const NCM_HOST_CLASSES: [&str; 2] = ["AppleUSBNCMData", "AppleUSBECMData"];

/// The `ioreg` class that means "this Mac is the DEVICE end of a USB gadget
/// link" — and also, on every Mac, the class of macOS's internal
/// inter-processor NCM interfaces. Always narrowed by link state before it
/// means anything (module docs).
pub const NCM_DEVICE_CLASS: &str = "AppleUSBDeviceNCMData";

/// `^en[0-9]+$` — the only interface-name shape that may enter the inventory.
/// This is the `anpi`/`awdl`/`llw`/`bridge` decoy gate (A002 §3): a name that
/// fails here is dropped no matter which signal produced it.
pub fn is_ncm_iface_name(name: &str) -> bool {
    match name.strip_prefix("en") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Why we believe an interface is a USB link, ordered strongest-first so
/// `Vec<Evidence>` sorts into A002 §5's reliability ranking and
/// `evidence[0]` is the strongest signal available.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Evidence {
    /// A002 §5.1 — the interface hangs off a host-side gadget class in IOKit.
    /// Unambiguous and tied to the physical USB device.
    HostIokit,
    /// A002 §5.2 — the interface's input packet counter advanced between two
    /// samples, so it is actually carrying frames right now.
    PeerTraffic,
    /// The interface hangs off [`NCM_DEVICE_CLASS`]. Weakest on its own (the
    /// class is shared with macOS internals), which is why it is never
    /// bridge-eligible.
    DeviceIokit,
}

/// What an identified interface IS, which is what consumers switch on.
/// [`Evidence`] says why; this says what to do about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkRole {
    /// This Mac enumerated the peer: the relay/hub role. The only role that
    /// becomes a bridge member.
    Host,
    /// This Mac is the device end of somebody else's link. Diagnostic — a
    /// device-end interface is configured by the peer's DHCP, not bridged
    /// locally.
    Device,
    /// A [`NCM_DEVICE_CLASS`] interface that is not active and/or not
    /// configured: one of macOS's internal inter-processor NCM interfaces.
    /// Kept in the inventory as a *rejected* candidate so the decision is
    /// visible, never acted on.
    Internal,
}

/// One identified interface: its name, what it is, and every signal that
/// supports it (strongest-first, deduped).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsbLink {
    pub name: String,
    pub role: LinkRole,
    pub evidence: Vec<Evidence>,
}

impl UsbLink {
    /// Only [`LinkRole::Host`] may be handed to the kernel bridge. Enforced
    /// here rather than remembered at call sites — the whole reason the device
    /// class is safe to query at all (module docs).
    pub fn bridge_eligible(&self) -> bool {
        matches!(self.role, LinkRole::Host)
    }

    /// Whether a node may reach a hub's segment through this link (R003-B10):
    /// every identified link except [`LinkRole::Internal`], the rejected
    /// macOS-internal decoys. Both ends of a cable qualify — a Host-role link
    /// is a cable this Mac enumerated (a Peer still does not bridge it), a
    /// Device-role link is one it is the device end of. Distinct from
    /// [`Self::bridge_eligible`], which only a Hub's bridge membership uses.
    pub fn uplink_eligible(&self) -> bool {
        match self.role {
            LinkRole::Host | LinkRole::Device => true,
            LinkRole::Internal => false,
        }
    }

    /// The strongest signal supporting this link.
    pub fn strongest(&self) -> Evidence {
        self.evidence.first().copied().unwrap_or(Evidence::DeviceIokit)
    }

    /// Whether traffic was observed on this interface between the last two
    /// samples — A002 §5.2's "which enX actually carries the frames".
    pub fn carrying_traffic(&self) -> bool {
        self.evidence.contains(&Evidence::PeerTraffic)
    }
}

/// What the OS says about one candidate interface at one instant: enough to
/// apply the prototype's `discover_device_side()` narrowing (`active` +
/// `configured`) and to compute a traffic delta against a previous sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfaceObservation {
    pub name: String,
    /// `ifconfig` reported `status: active`.
    pub active: bool,
    /// `ifconfig` reported at least one IPv4 (`inet `) address. The prototype
    /// requires this because the real device-end link is configured (even if
    /// only self-assigned `169.254/16`) while the internal ones are not.
    pub configured: bool,
    /// Cumulative input packets (`netstat -ib`). Only ever meaningful as a
    /// delta between two samples — a lifetime counter says nothing about now.
    pub input_packets: u64,
}

/// The result of one identification pass: every interface any signal pointed
/// at, classified. Consumers ask this for what they need rather than
/// re-deriving it from raw names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkInventory {
    /// Sorted by interface name.
    pub links: Vec<UsbLink>,
}

impl LinkInventory {
    /// The bridge feed: host-side IOKit provenance only (A002 §5.1). Sorted
    /// and deduped, so it compares cleanly against a helper report's member
    /// list.
    pub fn bridge_members(&self) -> Vec<String> {
        self.links.iter().filter(|l| l.bridge_eligible()).map(|l| l.name.clone()).collect()
    }

    /// Interfaces a Peer self-addresses and announces on (R003-B10): every
    /// [`UsbLink::uplink_eligible`] link. Sorted by name (inventory order).
    /// Built from the same IOKit/link-state evidence as the bridge feed, never
    /// from interface-name shape; USB-NCM is the only attachment class
    /// identified today (Thunderbolt/plain Ethernet are not — a gap, see the
    /// ticket's handoff).
    pub fn uplinks(&self) -> Vec<String> {
        self.links.iter().filter(|l| l.uplink_eligible()).map(|l| l.name.clone()).collect()
    }

    /// This Mac's device-end link(s), if it is the device end of a cable.
    /// Diagnostic only — never fed to bridging (module docs).
    pub fn device_links(&self) -> Vec<&UsbLink> {
        self.links.iter().filter(|l| matches!(l.role, LinkRole::Device)).collect()
    }

    /// Device-class candidates rejected as macOS internals. Exposed so the
    /// rejection is auditable rather than silent.
    pub fn internal_links(&self) -> Vec<&UsbLink> {
        self.links.iter().filter(|l| matches!(l.role, LinkRole::Internal)).collect()
    }

    /// One line per link, for the service log. This is the operator's only
    /// view of the device-side and traffic signals today — the wire
    /// [`ipauro_proto::state::Snapshot`] has no field for them and
    /// `ipauro-proto` is manager-owned (flagged in R005-F7's report as a
    /// candidate proto addition).
    pub fn summary(&self) -> String {
        if self.links.is_empty() {
            return "no USB-NCM interfaces identified".to_string();
        }
        self.links
            .iter()
            .map(|l| {
                let role = match l.role {
                    LinkRole::Host => "host",
                    LinkRole::Device => "device",
                    LinkRole::Internal => "internal(rejected)",
                };
                let evidence = l
                    .evidence
                    .iter()
                    .map(|e| match e {
                        Evidence::HostIokit => "host-iokit",
                        Evidence::PeerTraffic => "traffic",
                        Evidence::DeviceIokit => "device-iokit",
                    })
                    .collect::<Vec<_>>()
                    .join("+");
                format!("{}={role}[{evidence}]", l.name)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Pure classification: raw signals → [`LinkInventory`]. Split out from every
/// `ioreg`/`ifconfig`/`netstat` spawn so the whole A002 §5 ranking is
/// unit-testable against canned real output, with no Mac and no cable.
///
/// - `host` / `device`: BSD names from the host and device IOKit classes.
/// - `now` / `previous`: interface observations from this pass and the one
///   before it. `previous` empty (first pass) simply means no traffic evidence
///   is available yet — never an error, and never a reason to withhold a link.
///
/// Precedence: a name in a host class is [`LinkRole::Host`] even if the device
/// class also lists it — §5.1 outranks everything, and the host classes are the
/// specific ones. Names failing [`is_ncm_iface_name`] are dropped outright.
pub fn classify(
    host: &[String],
    device: &[String],
    now: &[IfaceObservation],
    previous: &[IfaceObservation],
) -> LinkInventory {
    let observed: BTreeMap<&str, &IfaceObservation> =
        now.iter().map(|o| (o.name.as_str(), o)).collect();
    let before: BTreeMap<&str, u64> = previous.iter().map(|o| (o.name.as_str(), o.input_packets)).collect();

    let host_set: BTreeSet<&str> =
        host.iter().map(String::as_str).filter(|n| is_ncm_iface_name(n)).collect();
    let device_set: BTreeSet<&str> =
        device.iter().map(String::as_str).filter(|n| is_ncm_iface_name(n)).collect();

    let mut links = Vec::new();
    for name in host_set.iter().chain(device_set.iter()).copied().collect::<BTreeSet<_>>() {
        let role = if host_set.contains(name) {
            LinkRole::Host
        } else {
            // Device class: the prototype's narrowing decides whether this is
            // a real device-end link or one of macOS's internals. An
            // unobserved interface (ifconfig had nothing to say) fails the
            // narrowing — absence of evidence is not evidence of a link.
            match observed.get(name) {
                Some(o) if o.active && o.configured => LinkRole::Device,
                _ => LinkRole::Internal,
            }
        };

        let mut evidence = Vec::new();
        if host_set.contains(name) {
            evidence.push(Evidence::HostIokit);
        }
        if device_set.contains(name) {
            evidence.push(Evidence::DeviceIokit);
        }
        if traffic_advanced(name, &observed, &before) {
            evidence.push(Evidence::PeerTraffic);
        }
        evidence.sort();
        evidence.dedup();

        links.push(UsbLink { name: name.to_string(), role, evidence });
    }

    LinkInventory { links }
}

/// Whether `name`'s input packet counter moved between the previous sample and
/// this one. A missing previous sample (first pass, or the interface just
/// appeared) is "no evidence", not "no traffic" — the next pass decides. A
/// counter that went BACKWARDS means the interface was re-created and its
/// counters reset; that is a topology change, not traffic, so it does not
/// count.
fn traffic_advanced(
    name: &str,
    observed: &BTreeMap<&str, &IfaceObservation>,
    before: &BTreeMap<&str, u64>,
) -> bool {
    match (observed.get(name), before.get(name)) {
        (Some(now), Some(&then)) => now.input_packets > then,
        _ => false,
    }
}

/// Source of every raw identification signal. Behind a trait so the reconciler
/// and its tests never shell out — see [`MockUsbNcmSource`] for the scripted
/// double. Each method is one query family, parsed by a pure function that is
/// tested against canned real output.
pub trait UsbNcmSource: Send + Sync {
    /// Sorted, deduped BSD names from [`NCM_HOST_CLASSES`] (A002 §5.1). Empty
    /// is a valid answer ("no Mac plugged in right now"), not an error; `Err`
    /// is reserved for the discovery mechanism itself failing.
    fn discover(&self) -> anyhow::Result<Vec<String>>;

    /// Sorted, deduped BSD names from [`NCM_DEVICE_CLASS`]. Noisy by
    /// construction — [`classify`] narrows it. Same empty-vs-error contract as
    /// [`UsbNcmSource::discover`].
    fn discover_device_side(&self) -> anyhow::Result<Vec<String>>;

    /// Link state and input-packet counters for `names`. Interfaces that no
    /// longer exist are simply absent from the result (a cable pulled between
    /// the IOKit query and this one is normal, not an error).
    fn observe(&self, names: &[String]) -> anyhow::Result<Vec<IfaceObservation>>;
}

/// Run one full identification pass against `source`, carrying `previous`
/// observations in for traffic evidence. Returns the inventory alongside the
/// observations this pass took, which the caller keeps to feed the next pass.
pub fn identify(
    source: &dyn UsbNcmSource,
    previous: &[IfaceObservation],
) -> anyhow::Result<(LinkInventory, Vec<IfaceObservation>)> {
    let host = source.discover()?;
    let device = source.discover_device_side()?;
    let mut candidates: Vec<String> = host
        .iter()
        .chain(device.iter())
        .filter(|n| is_ncm_iface_name(n))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    candidates.sort();
    let now = source.observe(&candidates)?;
    Ok((classify(&host, &device, &now, previous), now))
}

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

/// Parse `ifconfig <iface>` output into the two bits the prototype's
/// `discover_device_side()` narrowing needs.
///
/// - `active`: a `status: active` line (macOS reports `inactive` for a port
///   with nothing plugged in).
/// - `configured`: at least one IPv4 line. The `inet ` prefix is checked WITH
///   its trailing space precisely so `inet6` does not satisfy it — a
///   device-end link always self-assigns an IPv6 link-local, so accepting
///   `inet6` would make every internal interface look configured.
pub fn parse_ifconfig_state(text: &str) -> (bool, bool) {
    let mut active = false;
    let mut configured = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "status: active" {
            active = true;
        }
        if line.starts_with("inet ") {
            configured = true;
        }
    }
    (active, configured)
}

/// Parse `netstat -ib` into per-interface cumulative input-packet counts.
///
/// `netstat -ib` prints several rows per interface — one per address family —
/// and only the `<Link#N>` row carries the link-level counters. Two shapes in
/// that row defeat a fixed-column parser, and both appear in real output:
///
/// - The **address column is optional**: Ethernet-like interfaces print a MAC,
///   `lo0` prints nothing at all. Taking the first all-digits field after the
///   `<Link#N>` token handles both — a MAC contains `:` so it is never
///   all-digits, and an absent address contributes no field.
/// - A **down interface's name carries a trailing `*`** (`gif0*`). The star is
///   status, not part of the BSD name, so it is stripped: leaving it on would
///   file the counters under a name no lookup ever matches, silently reporting
///   zero traffic for an interface that is merely down at this instant.
pub fn parse_netstat_input_packets(text: &str) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        // Skip past the `<Link#N>` marker; rows for other address families
        // (inet/inet6) repeat the same totals but are not the link row.
        if !fields.any(|f| f.starts_with("<Link#")) {
            continue;
        }
        let Some(ipkts) = line
            .split_whitespace()
            .skip_while(|f| !f.starts_with("<Link#"))
            .skip(1)
            .find_map(|f| f.parse::<u64>().ok())
        else {
            continue;
        };
        counts.insert(name.trim_end_matches('*').to_string(), ipkts);
    }
    counts
}

/// Real implementation: `ioreg` for provenance, `ifconfig` for link state,
/// `netstat -ib` for traffic counters. macOS-only — none of these exist
/// elsewhere, and this whole identification model is IOKit-specific.
#[cfg(target_os = "macos")]
pub struct IoregUsbNcmSource;

#[cfg(target_os = "macos")]
impl IoregUsbNcmSource {
    pub fn new() -> Self {
        Self
    }

    /// `ioreg -r -c <class> -w0` for each class, unioned. `ioreg` exits
    /// non-zero when nothing matches the class (no cable plugged in right
    /// now) — that is a valid "nothing discovered" result, not a discovery
    /// failure, so status is not checked: any stdout it produced is still
    /// meaningful, and empty stdout parses to no names either way.
    fn ioreg_classes(classes: &[&str]) -> anyhow::Result<Vec<String>> {
        use anyhow::Context;

        let mut names = BTreeSet::new();
        for class in classes {
            let output = std::process::Command::new("ioreg")
                .args(["-r", "-c", class, "-w0"])
                .output()
                .with_context(|| format!("spawning `ioreg -r -c {class} -w0`"))?;
            let text = String::from_utf8_lossy(&output.stdout);
            names.extend(parse_ncm_bsd_names(&text));
        }
        Ok(names.into_iter().collect())
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
        Self::ioreg_classes(&NCM_HOST_CLASSES)
    }

    fn discover_device_side(&self) -> anyhow::Result<Vec<String>> {
        Self::ioreg_classes(&[NCM_DEVICE_CLASS])
    }

    fn observe(&self, names: &[String]) -> anyhow::Result<Vec<IfaceObservation>> {
        use anyhow::Context;

        // One `netstat -ib` for every interface at once; per-interface
        // `ifconfig` because it is the only place `status:` is reported.
        let netstat = std::process::Command::new("netstat")
            .args(["-ib"])
            .output()
            .context("spawning `netstat -ib`")?;
        let counters = parse_netstat_input_packets(&String::from_utf8_lossy(&netstat.stdout));

        let mut out = Vec::new();
        for name in names {
            // Defense in depth: `name` reaches a process argument here, so the
            // decoy gate is re-applied at the exec boundary rather than
            // trusted from the caller.
            if !is_ncm_iface_name(name) {
                continue;
            }
            let output = std::process::Command::new("ifconfig")
                .arg(name)
                .output()
                .with_context(|| format!("spawning `ifconfig {name}`"))?;
            // A non-zero exit means the interface vanished between the IOKit
            // query and now (cable pulled mid-pass) — expected, so it is
            // omitted rather than reported as a failure.
            if !output.status.success() {
                continue;
            }
            let (active, configured) = parse_ifconfig_state(&String::from_utf8_lossy(&output.stdout));
            out.push(IfaceObservation {
                name: name.clone(),
                active,
                configured,
                input_packets: counters.get(name).copied().unwrap_or(0),
            });
        }
        Ok(out)
    }
}

/// The non-macOS stand-in. There is no USB-NCM/IOKit identification mechanism
/// outside macOS; "nothing identified" is the honest answer, never an error —
/// this is a platform gap, not a fault.
#[cfg(not(target_os = "macos"))]
pub struct NoUsbNcmSource;

#[cfg(not(target_os = "macos"))]
impl UsbNcmSource for NoUsbNcmSource {
    fn discover(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn discover_device_side(&self) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn observe(&self, _names: &[String]) -> anyhow::Result<Vec<IfaceObservation>> {
        Ok(Vec::new())
    }
}

/// Scriptable test double: a queue of host-side discovery results consumed one
/// per call, holding the last-returned result once the queue empties (so a test
/// doesn't have to over-provision calls whose exact count it can't predict —
/// e.g. the reconciler's own retry loop). [`MockUsbNcmSource::push`] appends
/// a new result at any time, letting a test simulate a live event (a replug)
/// happening mid-run, which the background watch task then picks up on its
/// own next poll — exactly the thing under test in the M-incident case.
///
/// The device-side and observation channels are separately settable and
/// default to empty, so a test that only cares about bridging says nothing
/// about them and gets today's host-only behaviour.
pub struct MockUsbNcmSource {
    script: Mutex<VecDeque<Vec<String>>>,
    last: Mutex<Vec<String>>,
    device: Mutex<Vec<String>>,
    observations: Mutex<Vec<IfaceObservation>>,
}

impl MockUsbNcmSource {
    pub fn new(script: impl IntoIterator<Item = Vec<String>>) -> Self {
        Self {
            script: Mutex::new(script.into_iter().collect()),
            last: Mutex::new(Vec::new()),
            device: Mutex::new(Vec::new()),
            observations: Mutex::new(Vec::new()),
        }
    }

    /// Append another scripted host-side result, to be returned once the queue
    /// reaches it (i.e. after every call already queued ahead of it).
    pub fn push(&self, next: Vec<String>) {
        self.script.lock().expect("script mutex poisoned").push_back(next);
    }

    /// Set what [`UsbNcmSource::discover_device_side`] returns from now on.
    pub fn set_device_side(&self, names: Vec<String>) {
        *self.device.lock().expect("device mutex poisoned") = names;
    }

    /// Set what [`UsbNcmSource::observe`] returns from now on (filtered to the
    /// requested names, like the real source).
    pub fn set_observations(&self, observations: Vec<IfaceObservation>) {
        *self.observations.lock().expect("observations mutex poisoned") = observations;
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

    fn discover_device_side(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.device.lock().expect("device mutex poisoned").clone())
    }

    fn observe(&self, names: &[String]) -> anyhow::Result<Vec<IfaceObservation>> {
        let wanted: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        Ok(self
            .observations
            .lock()
            .expect("observations mutex poisoned")
            .iter()
            .filter(|o| wanted.contains(o.name.as_str()))
            .cloned()
            .collect())
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

    /// VERBATIM `ioreg -r -c AppleUSBDeviceNCMData -w0` from a real Apple
    /// Silicon MacBook Pro with NOTHING plugged in (captured 2026-07-25 while
    /// working R005-F7), plus one hypothetical device-end link (`en8`, the
    /// clearly-marked final entry) in the same shape — this Mac has no peer
    /// cable, so the real capture alone could not exercise the accept path.
    ///
    /// Three things this real capture settles that an invented fixture would
    /// not:
    /// - **A quiet Mac already shows THREE `enN` children of this class**
    ///   (`en3`, `en4`, `en5`) with no cable anywhere. A002 §5 called them
    ///   `en1`..`en6`; the numbering varies by machine, which is exactly why
    ///   nothing may hardcode it.
    /// - **`anpi0`/`anpi1`/`anpi2` really are children of this class**, as
    ///   `AppleUSBDeviceNCMPrivateEthernetInterface`. A002 §3 called `anpi` a
    ///   decoy; this is the mechanism by which it would sneak in. It is kept
    ///   out only because [`parse_ncm_bsd_names`] requires `+-o en[0-9]+`.
    /// - **The interfaces nest deeper than one level** (`IONetworkStack` and
    ///   its user client hang off the `enN` node), so a parser keying on
    ///   indentation rather than the `+-o en` token would misread it.
    const DEVICE_SIDE_IOREG: &str = r#"
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000ce7, registered, matched, active, busy 0 (14 ms), retain 8>
  +-o en3  <class IOEthernetInterface, id 0x100000cf8, registered, matched, active, busy 0 (3 ms), retain 11>
    +-o IONetworkStack  <class IONetworkStack, id 0x100000b93, registered, matched, active, busy 0 (14 ms), retain 34>
      +-o IONetworkStackUserClient  <class IONetworkStackUserClient, id 0x1000013f1, !registered, !matched, active, busy 0, retain 5>
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000ce5, registered, matched, active, busy 0 (2 ms), retain 8>
  +-o anpi0  <class AppleUSBDeviceNCMPrivateEthernetInterface, id 0x100000d09, registered, matched, active, busy 0 (12 ms), retain 11>
    +-o IONetworkStack  <class IONetworkStack, id 0x100000b93, registered, matched, active, busy 0 (14 ms), retain 34>
      +-o IONetworkStackUserClient  <class IONetworkStackUserClient, id 0x1000013f1, !registered, !matched, active, busy 0, retain 5>
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000ca7, registered, matched, active, busy 0 (15 ms), retain 8>
  +-o en4  <class IOEthernetInterface, id 0x100000d0f, registered, matched, active, busy 0 (13 ms), retain 11>
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000ccf, registered, matched, active, busy 0 (15 ms), retain 8>
  +-o anpi1  <class AppleUSBDeviceNCMPrivateEthernetInterface, id 0x100000d0b, registered, matched, active, busy 0 (14 ms), retain 11>
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000d40, registered, matched, active, busy 0 (1 ms), retain 8>
  +-o en5  <class IOEthernetInterface, id 0x100000d56, registered, matched, active, busy 0 (1 ms), retain 11>
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000d42, registered, matched, active, busy 0 (1 ms), retain 8>
  +-o anpi2  <class AppleUSBDeviceNCMPrivateEthernetInterface, id 0x100000d51, registered, matched, active, busy 0 (1 ms), retain 11>
+-o AppleUSBDeviceNCMData  <class AppleUSBDeviceNCMData, id 0x100000d99, registered, matched, active, busy 0 (1 ms), retain 8>
  +-o en8  <class IOEthernetInterface, id 0x100000da1, registered, matched, active, busy 0 (1 ms), retain 11>
"#;

    /// Real `ifconfig en5` output for a configured device-end link — the one
    /// that passes the narrowing.
    const IFCONFIG_ACTIVE_CONFIGURED: &str = r#"en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6467<RXCSUM,TXCSUM,VLAN_MTU,TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether 36:1e:5f:8a:2b:c0
	inet6 fe80::14a3:9f2b:1c4d:5e6f%en5 prefixlen 64 secured scopeid 0xd
	inet 169.254.109.94 netmask 0xffff0000 broadcast 169.254.255.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
"#;

    /// Real `ifconfig en1` output for one of macOS's internal inter-processor
    /// NCM interfaces: active, an IPv6 link-local, and NO IPv4. This is the
    /// case that would slip through if the narrowing accepted `inet6`.
    const IFCONFIG_ACTIVE_UNCONFIGURED: &str = r#"en1: flags=8963<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=460<TSO4,TSO6,CHANNEL_IO>
	ether 36:1e:5f:8a:2b:c1
	inet6 fe80::341e:5fff:fe8a:2bc1%en1 prefixlen 64 scopeid 0x9
	media: autoselect <full-duplex>
	status: active
"#;

    /// VERBATIM `ifconfig en3` from the same real Mac as [`DEVICE_SIDE_IOREG`]:
    /// one of macOS's internal inter-processor NCM interfaces with no cable
    /// involved. `status: inactive`, no `inet`, and not even an `inet6` —
    /// which is what the narrowing actually meets in the field, and why
    /// `en3`/`en4` on this machine classify as [`LinkRole::Internal`].
    const IFCONFIG_INACTIVE: &str = r#"en3: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=400<CHANNEL_IO>
	ether ee:37:4f:9d:13:1f
	nd6 options=201<PERFORMNUD,DAD>
	media: none
	status: inactive
"#;

    /// VERBATIM `netstat -ib` from the same real Mac as [`DEVICE_SIDE_IOREG`],
    /// with an `en5` inet row appended to exercise the per-address-family
    /// duplicate. Every shape the parser has to survive is in here for real:
    /// `lo0`'s link row has an EMPTY address column while `anpi0`'s carries a
    /// MAC; `gif0*`/`stf0*` are DOWN and wear a trailing star; the `Network`
    /// column holds a name (`localhost`) as readily as a number.
    const NETSTAT_IB: &str = r#"Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                       1967183     0 2193300535  1967183     0 2193300535     0
lo0        16384 127           localhost        1967183     - 2193300535  1967183     - 2193300535     -
lo0        16384 macbook-pro fe80:1::1          1967183     - 2193300535  1967183     - 2193300535     -
gif0*      1280  <Link#2>                             0     0          0        0     0          0     0
stf0*      1280  <Link#3>                             0     0          0        0     0          0     0
anpi0      1500  <Link#4>    ee:37:4f:9d:13:3f        0     0          0        0     0          0     0
en3        1500  <Link#7>    ee:37:4f:9d:13:1f        0     0          0        0     0          0     0
en5        1500  <Link#13>   36:1e:5f:8a:2b:c0    45210     0   38102994    31877     0   22110043     0
en5        1500  169.254       169.254.109.94       45210     -   38102994    31877     -   22110043     -
"#;

    fn strs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn obs(name: &str, active: bool, configured: bool, input_packets: u64) -> IfaceObservation {
        IfaceObservation { name: name.to_string(), active, configured, input_packets }
    }

    fn link<'a>(inv: &'a LinkInventory, name: &str) -> &'a UsbLink {
        inv.links.iter().find(|l| l.name == name).unwrap_or_else(|| panic!("{name} not in inventory"))
    }

    // ---- ioreg parsing (A002 §5.1) ----------------------------------------

    #[test]
    fn parses_realistic_host_side_output_ignoring_the_anpi_decoy() {
        let names = parse_ncm_bsd_names(REALISTIC_HOST_SIDE_IOREG);
        assert_eq!(names, strs(&["en10", "en9"]));
    }

    #[test]
    fn merges_multiple_ioreg_invocations_like_the_real_source_does() {
        let mut names = parse_ncm_bsd_names(REALISTIC_HOST_SIDE_IOREG);
        names.extend(parse_ncm_bsd_names(REALISTIC_HOST_SIDE_IOREG_SECOND_PEER));
        names.sort();
        names.dedup();
        assert_eq!(names, strs(&["en10", "en12", "en9"]));
    }

    #[test]
    fn ignores_lookalikes_without_a_digit_run() {
        let text = "  +-o enclosure0  <class IOService, id 0x1, registered>\n";
        assert!(parse_ncm_bsd_names(text).is_empty());
    }

    #[test]
    fn device_side_class_is_not_a_host_class() {
        assert!(
            !NCM_HOST_CLASSES.contains(&NCM_DEVICE_CLASS),
            "AppleUSBDeviceNCMData surfaces macOS's internal inter-processor \
             NCM interfaces (en1..en6) on any Mac — treating it as a host \
             class would try to bridge them (A002 §5)"
        );
    }

    // ---- the decoy gate (A002 §3, §5.4) ------------------------------------

    #[test]
    fn iface_name_gate_accepts_only_en_digits() {
        for n in ["en0", "en9", "en12", "en999"] {
            assert!(is_ncm_iface_name(n), "{n} should pass");
        }
        for n in ["anpi0", "awdl0", "llw0", "bridge90", "utun3", "en", "en1a", "eth0", "", "en9;rm -rf /"] {
            assert!(!is_ncm_iface_name(n), "{n} should be rejected");
        }
    }

    #[test]
    fn decoys_cannot_enter_the_inventory_from_any_signal() {
        // Every signal simultaneously insists `anpi0` is a link. It must still
        // be absent — the gate is applied to names, not to sources.
        let inv = classify(
            &strs(&["anpi0", "en9"]),
            &strs(&["anpi0"]),
            &[obs("anpi0", true, true, 500), obs("en9", true, true, 10)],
            &[obs("anpi0", true, true, 1), obs("en9", true, true, 10)],
        );
        assert_eq!(inv.links.len(), 1);
        assert_eq!(inv.links[0].name, "en9");
        assert_eq!(inv.bridge_members(), strs(&["en9"]));
    }

    // ---- ifconfig / netstat parsing ----------------------------------------

    #[test]
    fn ifconfig_state_matrix() {
        assert_eq!(parse_ifconfig_state(IFCONFIG_ACTIVE_CONFIGURED), (true, true));
        assert_eq!(parse_ifconfig_state(IFCONFIG_ACTIVE_UNCONFIGURED), (true, false));
        assert_eq!(parse_ifconfig_state(IFCONFIG_INACTIVE), (false, false));
    }

    #[test]
    fn ifconfig_inet6_alone_is_not_configured() {
        // The exact trap the trailing space in `inet ` guards: every internal
        // NCM interface has an IPv6 link-local, so accepting `inet6` would
        // promote all of them to device-end links.
        assert!(IFCONFIG_ACTIVE_UNCONFIGURED.contains("inet6"));
        assert!(!parse_ifconfig_state(IFCONFIG_ACTIVE_UNCONFIGURED).1);
    }

    #[test]
    fn netstat_parses_both_link_row_shapes() {
        let counts = parse_netstat_input_packets(NETSTAT_IB);
        // MAC in the address column.
        assert_eq!(counts.get("en5"), Some(&45210));
        assert_eq!(counts.get("en3"), Some(&0));
        assert_eq!(counts.get("anpi0"), Some(&0));
        // Empty address column.
        assert_eq!(counts.get("lo0"), Some(&1_967_183));
    }

    #[test]
    fn netstat_strips_the_down_interface_star_from_the_name() {
        // `gif0*` is `gif0`, down. Filing it under the starred spelling would
        // make every lookup for the real name miss and report zero traffic.
        let counts = parse_netstat_input_packets(NETSTAT_IB);
        assert_eq!(counts.get("gif0"), Some(&0));
        assert!(!counts.keys().any(|k| k.contains('*')));
    }

    #[test]
    fn netstat_ignores_the_header_and_per_family_rows() {
        let counts = parse_netstat_input_packets(NETSTAT_IB);
        assert!(!counts.contains_key("Name"), "header row must not parse as an interface");
        // lo0's `localhost`/`fe80:1::1` rows and en5's `169.254` row repeat
        // totals the link row already carried: one entry per interface.
        assert_eq!(counts.len(), 6, "lo0 gif0 stf0 anpi0 en3 en5");
    }

    // ---- classification: host side (A002 §5.1) -----------------------------

    #[test]
    fn host_class_interfaces_are_bridge_eligible() {
        let inv = classify(&strs(&["en9", "en10"]), &[], &[], &[]);
        assert_eq!(inv.bridge_members(), strs(&["en10", "en9"]));
        assert_eq!(link(&inv, "en9").role, LinkRole::Host);
        assert_eq!(link(&inv, "en9").evidence, vec![Evidence::HostIokit]);
    }

    #[test]
    fn two_host_interfaces_for_one_cable_both_stay_eligible_but_only_one_carries_traffic() {
        // A002's "one link can surface TWO host-side NCM interfaces (one live,
        // one inert)". Bridging the inert one is harmless, so both remain
        // members — but a caller must not read 2 interfaces as 2 peers, and
        // traffic evidence is what tells them apart.
        let inv = classify(
            &strs(&["en9", "en10"]),
            &[],
            &[obs("en9", true, true, 5000), obs("en10", true, false, 0)],
            &[obs("en9", true, true, 4000), obs("en10", true, false, 0)],
        );
        assert_eq!(inv.bridge_members(), strs(&["en10", "en9"]));
        assert!(link(&inv, "en9").carrying_traffic());
        assert!(!link(&inv, "en10").carrying_traffic());
    }

    // ---- classification: device side (the narrowing) ------------------------

    #[test]
    fn device_side_narrowing_keeps_the_configured_link_and_rejects_internals() {
        let device = parse_ncm_bsd_names(DEVICE_SIDE_IOREG);
        assert_eq!(
            device,
            strs(&["en3", "en4", "en5", "en8"]),
            "class alone cannot tell the real link from macOS's internals — and \
             the three `anpi` children of this class must already be gone"
        );

        let inv = classify(
            &[],
            &device,
            &[
                // The device-end link: active AND holding an IPv4.
                obs("en8", true, true, 45210),
                // macOS internals, exactly as a quiet Mac reports them.
                obs("en3", false, false, 0),
                obs("en4", false, false, 0),
                obs("en5", false, false, 0),
            ],
            &[],
        );
        assert_eq!(inv.device_links().iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), vec!["en8"]);
        assert_eq!(
            inv.internal_links().iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
            vec!["en3", "en4", "en5"]
        );
    }

    #[test]
    fn the_anpi_decoys_really_are_children_of_the_device_class() {
        // Not hypothetical: [`DEVICE_SIDE_IOREG`] is verbatim from a real Mac,
        // and `anpi0`/`anpi1`/`anpi2` are in it as
        // `AppleUSBDeviceNCMPrivateEthernetInterface`s. Bridging one is the
        // A002 §3 decoy failure; the `+-o en[0-9]+` shape is what keeps them
        // out.
        assert_eq!(DEVICE_SIDE_IOREG.matches("+-o anpi").count(), 3);
        assert!(!parse_ncm_bsd_names(DEVICE_SIDE_IOREG).iter().any(|n| n.starts_with("anpi")));
    }

    #[test]
    fn device_side_links_are_never_bridge_eligible() {
        // The core safety property of querying the device class at all: no
        // matter how convincing the evidence, nothing from it becomes a bridge
        // member. `en5` here is active, configured, AND carrying traffic.
        let inv = classify(
            &[],
            &strs(&["en1", "en5"]),
            &[obs("en5", true, true, 45210), obs("en1", true, false, 0)],
            &[obs("en5", true, true, 40000), obs("en1", true, false, 0)],
        );
        assert!(link(&inv, "en5").carrying_traffic());
        assert_eq!(link(&inv, "en5").role, LinkRole::Device);
        assert!(
            inv.bridge_members().is_empty(),
            "AppleUSBDeviceNCMData must never feed bridging — it is also the \
             class of macOS's internal inter-processor interfaces (A002 §5)"
        );
    }

    #[test]
    fn uplinks_are_host_and_device_links_never_internals() {
        // en9: host end (cable this Mac enumerated); en5: device end (active +
        // configured); en1: macOS-internal decoy (inactive). Only the decoy is
        // excluded, and the answer comes from role, not from the `enN` shape
        // all three share.
        let inv = classify(
            &strs(&["en9"]),
            &strs(&["en1", "en5"]),
            &[obs("en9", true, true, 5), obs("en5", true, true, 5), obs("en1", false, false, 0)],
            &[],
        );
        assert_eq!(inv.uplinks(), strs(&["en5", "en9"]));
        assert_eq!(link(&inv, "en1").role, LinkRole::Internal);
        assert!(!link(&inv, "en1").uplink_eligible());
        assert_eq!(inv.bridge_members(), strs(&["en9"]), "bridge feed is unchanged");
    }

    #[test]
    fn an_unobserved_device_candidate_is_treated_as_internal() {
        // ifconfig had nothing to say (interface vanished mid-pass). Absence
        // of evidence must not promote it to a link.
        let inv = classify(&[], &strs(&["en5"]), &[], &[]);
        assert_eq!(link(&inv, "en5").role, LinkRole::Internal);
        assert!(inv.device_links().is_empty());
    }

    #[test]
    fn an_inactive_device_candidate_is_internal_even_when_configured() {
        let inv = classify(&[], &strs(&["en5"]), &[obs("en5", false, true, 0)], &[]);
        assert_eq!(link(&inv, "en5").role, LinkRole::Internal);
    }

    #[test]
    fn host_provenance_outranks_device_provenance_for_the_same_name() {
        // Both classes name en9. §5.1 is the specific, trustworthy signal, so
        // it wins the role — and both signals are recorded, strongest first.
        let inv = classify(&strs(&["en9"]), &strs(&["en9"]), &[obs("en9", true, true, 1)], &[]);
        assert_eq!(link(&inv, "en9").role, LinkRole::Host);
        assert_eq!(link(&inv, "en9").evidence, vec![Evidence::HostIokit, Evidence::DeviceIokit]);
        assert_eq!(link(&inv, "en9").strongest(), Evidence::HostIokit);
        assert_eq!(inv.bridge_members(), strs(&["en9"]));
    }

    // ---- classification: traffic evidence (A002 §5.2) -----------------------

    #[test]
    fn traffic_evidence_needs_two_samples() {
        let now = [obs("en9", true, true, 5000)];
        // First pass: no previous sample, so no traffic claim either way.
        let first = classify(&strs(&["en9"]), &[], &now, &[]);
        assert!(!link(&first, "en9").carrying_traffic());
        // Second pass with a lower previous count: the counter advanced.
        let second = classify(&strs(&["en9"]), &[], &now, &[obs("en9", true, true, 4999)]);
        assert!(link(&second, "en9").carrying_traffic());
    }

    #[test]
    fn a_static_counter_is_not_traffic() {
        let inv = classify(
            &strs(&["en9"]),
            &[],
            &[obs("en9", true, true, 5000)],
            &[obs("en9", true, true, 5000)],
        );
        assert!(!link(&inv, "en9").carrying_traffic());
    }

    #[test]
    fn a_counter_reset_is_not_traffic() {
        // The interface was re-created (replug): counters restart at ~0. That
        // is a topology change, not frames on the wire.
        let inv = classify(
            &strs(&["en9"]),
            &[],
            &[obs("en9", true, true, 12)],
            &[obs("en9", true, true, 90000)],
        );
        assert!(!link(&inv, "en9").carrying_traffic());
    }

    #[test]
    fn evidence_is_ranked_strongest_first() {
        assert!(Evidence::HostIokit < Evidence::PeerTraffic);
        assert!(Evidence::PeerTraffic < Evidence::DeviceIokit);
        let inv = classify(
            &strs(&["en9"]),
            &strs(&["en9"]),
            &[obs("en9", true, true, 10)],
            &[obs("en9", true, true, 1)],
        );
        assert_eq!(
            link(&inv, "en9").evidence,
            vec![Evidence::HostIokit, Evidence::PeerTraffic, Evidence::DeviceIokit]
        );
    }

    // ---- the full pass, end to end ------------------------------------------

    #[test]
    fn identify_runs_a_full_pass_and_returns_the_samples_for_the_next_one() {
        // A hub that is host to one cable (en9) and device on another (en5),
        // with macOS's internals (en1) in the device class alongside.
        let source = MockUsbNcmSource::new([strs(&["en9"])]);
        source.set_device_side(strs(&["en1", "en5"]));
        source.set_observations(vec![
            obs("en9", true, true, 100),
            obs("en5", true, true, 200),
            obs("en1", true, false, 0),
        ]);

        let (first, samples) = identify(&source, &[]).unwrap();
        assert_eq!(first.bridge_members(), strs(&["en9"]));
        assert_eq!(first.device_links().iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), vec!["en5"]);
        assert!(!link(&first, "en9").carrying_traffic(), "no previous sample yet");
        assert_eq!(samples.len(), 3, "observations feed the next pass's traffic delta");

        // Second pass: en9's counter advanced, en5's did not.
        source.set_observations(vec![
            obs("en9", true, true, 900),
            obs("en5", true, true, 200),
            obs("en1", true, false, 0),
        ]);
        let (second, _) = identify(&source, &samples).unwrap();
        assert!(link(&second, "en9").carrying_traffic());
        assert!(!link(&second, "en5").carrying_traffic());
    }

    #[test]
    fn identify_only_observes_gated_names() {
        let source = MockUsbNcmSource::new([strs(&["en9", "anpi0"])]);
        source.set_observations(vec![obs("en9", true, true, 1), obs("anpi0", true, true, 1)]);
        let (_, samples) = identify(&source, &[]).unwrap();
        assert_eq!(
            samples.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
            vec!["en9"],
            "a decoy must not even be handed to `ifconfig`"
        );
    }

    #[test]
    fn summary_names_role_and_evidence_for_each_link() {
        let inv = classify(
            &strs(&["en9"]),
            &strs(&["en1", "en5"]),
            &[obs("en9", true, true, 10), obs("en5", true, true, 5), obs("en1", true, false, 0)],
            &[obs("en9", true, true, 1), obs("en5", true, true, 5), obs("en1", true, false, 0)],
        );
        assert_eq!(
            inv.summary(),
            "en1=internal(rejected)[device-iokit] \
             en5=device[device-iokit] \
             en9=host[host-iokit+traffic]"
        );
    }

    #[test]
    fn summary_says_so_when_nothing_is_identified() {
        assert_eq!(LinkInventory::default().summary(), "no USB-NCM interfaces identified");
    }

    // ---- the test double ----------------------------------------------------

    #[test]
    fn mock_replays_script_then_holds_last() {
        let mock = MockUsbNcmSource::new([strs(&["en9"]), strs(&["en9", "en12"])]);
        assert_eq!(mock.discover().unwrap(), strs(&["en9"]));
        assert_eq!(mock.discover().unwrap(), strs(&["en9", "en12"]));
        // Script exhausted: holds the last value indefinitely.
        assert_eq!(mock.discover().unwrap(), strs(&["en9", "en12"]));
        assert_eq!(mock.discover().unwrap(), strs(&["en9", "en12"]));
    }

    #[test]
    fn mock_push_appends_after_construction() {
        let mock = MockUsbNcmSource::new([strs(&["en9", "en12"])]);
        assert_eq!(mock.discover().unwrap(), strs(&["en9", "en12"]));
        // Simulate a live detach happening mid-test.
        mock.push(strs(&["en9"]));
        assert_eq!(mock.discover().unwrap(), strs(&["en9"]));
    }

    #[test]
    fn mock_defaults_to_a_silent_device_side() {
        let mock = MockUsbNcmSource::new([strs(&["en9"])]);
        assert!(mock.discover_device_side().unwrap().is_empty());
        assert!(mock.observe(&strs(&["en9"])).unwrap().is_empty());
    }

    // ---- against the real machine -------------------------------------------

    /// Runs the REAL `ioreg`/`ifconfig`/`netstat` path on whatever Mac invokes
    /// it. `#[ignore]`d because it needs macOS and its result depends on what
    /// is plugged in — CI has neither — but the canned fixtures above are only
    /// as good as the shapes they were captured from, so this exists to
    /// re-check those shapes against a live machine after any macOS update:
    ///
    /// ```text
    /// cargo test -p ipauro-core --lib -- --ignored --nocapture real_machine
    /// ```
    ///
    /// The assertions are the invariants that must hold on ANY Mac, plugged in
    /// or not: every identified name passes the decoy gate, nothing from the
    /// device class is bridge-eligible, and `netstat` yielded counters for the
    /// interfaces we asked about. The inventory itself is printed for a human
    /// to compare against `ifconfig`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs a real Mac; result depends on what is plugged in"]
    fn real_machine_identification_holds_its_invariants() {
        let source = IoregUsbNcmSource::new();
        let (inventory, observations) = identify(&source, &[]).expect("identification pass");
        println!("inventory: {}", inventory.summary());
        println!("observations: {observations:#?}");

        for l in &inventory.links {
            assert!(is_ncm_iface_name(&l.name), "{} slipped past the decoy gate", l.name);
        }
        for l in inventory.device_links().iter().chain(inventory.internal_links().iter()) {
            assert!(!l.bridge_eligible(), "{} came from the device class", l.name);
        }
        for o in &observations {
            assert!(is_ncm_iface_name(&o.name), "{} was handed to ifconfig", o.name);
        }
        // A second pass proves the traffic delta path runs end to end; whether
        // it finds traffic depends on the cable, so only the mechanics are
        // asserted.
        let (second, _) = identify(&source, &observations).expect("second pass");
        println!("second pass: {}", second.summary());
    }
}
