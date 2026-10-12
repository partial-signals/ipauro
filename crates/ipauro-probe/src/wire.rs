//! BPF wire tap — the "packet on wire" half of the A002 diagnostic method.
//!
//! The macOS Local Network privacy gate sits **above** the kernel's packet
//! capture point, so `/dev/bpf*` observes traffic the gated application socket
//! never sees. Watching both halves at once is what makes a `check` verdict
//! falsifiable: a socket-only test cannot tell "the gate is open" apart from
//! "the gate is closed but multicast loopback isn't subject to it", and it
//! cannot tell "denied on the inbound path" apart from "denied on the outbound
//! path" (macOS suppresses egress silently — `sendto` still reports success).
//!
//! Deliberately does not parse `bpf_hdr`, Ethernet, IP or UDP. A BPF read
//! returns a concatenation of `[bpf_hdr][packet][pad]` records whose header
//! layout varies by platform and whose link-layer type varies by interface
//! (`DLT_EN10MB` on `en*`, `DLT_NULL` on `lo0`). Counting occurrences of the
//! beacon's own identity marker across the raw buffer is exact regardless of
//! either — BPF never splits one packet across two reads, so each captured
//! datagram carrying the marker contributes exactly one occurrence.
//!
//! Requires read access to `/dev/bpf*` (root, or membership of the
//! `access_bpf` group that Wireshark's ChmodBPF installs). Absent that, the
//! tap reports itself unavailable and `check` falls back to the weaker
//! socket-only verdict rather than failing.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use anyhow::{Result, anyhow};

/// How many `/dev/bpfN` clone devices to try before giving up. Each is
/// single-open; a busy one (Wireshark, another probe) returns `EBUSY`.
const MAX_BPF_MINOR: u32 = 32;

/// Requested kernel capture buffer. macOS clamps this to `debug.bpf_maxbufsize`
/// (512 KiB by default); the clamped value is what `BIOCSBLEN` reports back.
const REQUESTED_BUF_LEN: u32 = 1 << 20;

/// How long a single `poll` waits before the capture loop re-checks the stop
/// flag. Bounds how long `WireTap::stop` blocks.
const POLL_TIMEOUT_MS: i32 = 200;

// --- ioctl request encoding (macOS `sys/ioccom.h`) ---------------------------
const IOCPARM_MASK: u64 = 0x1fff;
const IOC_OUT: u64 = 0x4000_0000;
const IOC_IN: u64 = 0x8000_0000;
const IOC_INOUT: u64 = IOC_IN | IOC_OUT;

const fn ioc(inout: u64, group: u64, num: u64, len: u64) -> libc::c_ulong {
    (inout | ((len & IOCPARM_MASK) << 16) | (group << 8) | num) as libc::c_ulong
}

const BPF_GROUP: u64 = b'B' as u64;
/// `BIOCSBLEN` — `_IOWR('B', 102, u_int)`; must be set *before* `BIOCSETIF`.
const BIOCSBLEN: libc::c_ulong = ioc(IOC_INOUT, BPF_GROUP, 102, 4);
/// `BIOCSETIF` — `_IOW('B', 108, struct ifreq)`.
const BIOCSETIF: libc::c_ulong = ioc(IOC_IN, BPF_GROUP, 108, IFREQ_SIZE as u64);
/// `BIOCIMMEDIATE` — `_IOW('B', 112, u_int)`; deliver each packet as it
/// arrives instead of waiting for the buffer to fill.
const BIOCIMMEDIATE: libc::c_ulong = ioc(IOC_IN, BPF_GROUP, 112, 4);
/// `BIOCGSTATS` — `_IOR('B', 111, struct bpf_stat)` (two `u_int`s).
const BIOCGSTATS: libc::c_ulong = ioc(IOC_OUT, BPF_GROUP, 111, 8);

/// `struct ifreq` on macOS: a 16-byte interface name followed by a 16-byte
/// union. Declared locally rather than taken from `libc` because only the name
/// field is used here and the union's shape is irrelevant to `BIOCSETIF`.
const IFREQ_SIZE: usize = 32;
#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    _pad: [u8; 16],
}

/// `struct bpf_stat`: packets received by the filter, and packets dropped
/// because the kernel buffer was full.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct BpfStat {
    recv: libc::c_uint,
    drop: libc::c_uint,
}

/// What the wire tap was able to observe during a `check` window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireObservation {
    /// The tap ran and saw `count` of our own beacons pass the interface.
    Seen { count: u64 },
    /// No usable wire observation — no interface named, no permission to open
    /// `/dev/bpf*`, or the capture dropped packets and can no longer support a
    /// negative claim. Carries the reason for the report.
    Unavailable { reason: String },
}

impl WireObservation {
    /// Reason string for an unavailable tap.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        WireObservation::Unavailable { reason: reason.into() }
    }
}

impl fmt::Display for WireObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireObservation::Seen { count } => {
                write!(f, "{count} own beacon(s) observed on the wire")
            }
            WireObservation::Unavailable { reason } => write!(f, "unavailable ({reason})"),
        }
    }
}

/// A running BPF capture, counting occurrences of one marker.
pub struct WireTap {
    stop: Arc<AtomicBool>,
    worker: JoinHandle<WireObservation>,
}

impl WireTap {
    /// Attach to `iface` and start counting datagrams containing `marker`.
    ///
    /// `marker` must be the beacon's *identity* substring (host + pid), not
    /// just the protocol magic — otherwise a second probe instance running
    /// concurrently on another machine would be counted as ours.
    pub fn start(iface: &str, marker: &str) -> Result<WireTap> {
        let fd = open_bpf()?;
        set_buffer_len(&fd, REQUESTED_BUF_LEN)?;
        attach_interface(&fd, iface)?;
        set_immediate(&fd)?;

        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let stop = Arc::clone(&stop);
            let marker = marker.as_bytes().to_vec();
            std::thread::spawn(move || capture_loop(fd, &marker, &stop))
        };

        Ok(WireTap { stop, worker })
    }

    /// Stop the capture and return what it saw. Blocks for at most one poll
    /// interval plus the time to drain the final read.
    pub fn stop(self) -> WireObservation {
        self.stop.store(true, Ordering::Relaxed);
        self.worker
            .join()
            .unwrap_or_else(|_| WireObservation::unavailable("capture thread panicked"))
    }
}

/// Open the first free `/dev/bpfN` clone device.
fn open_bpf() -> Result<OwnedFd> {
    let mut last_err = None;
    for minor in 0..MAX_BPF_MINOR {
        let path = CString::new(format!("/dev/bpf{minor}")).expect("bpf path has no interior NUL");
        // SAFETY: `path` is a valid NUL-terminated C string that outlives the call.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        if fd >= 0 {
            // SAFETY: `open` returned a fresh, owned, valid descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        // EBUSY means that clone device is taken by another capture — keep
        // walking. Anything else (notably EACCES) is terminal and reported.
        if err.raw_os_error() != Some(libc::EBUSY) {
            return Err(anyhow!("opening /dev/bpf{minor}: {err}"));
        }
        last_err = Some(err);
    }
    Err(anyhow!(
        "no free /dev/bpf device in 0..{MAX_BPF_MINOR} (last: {})",
        last_err.map(|e| e.to_string()).unwrap_or_else(|| "none".into())
    ))
}

fn set_buffer_len(fd: &OwnedFd, len: u32) -> Result<()> {
    let mut len = len;
    // SAFETY: BIOCSBLEN reads and writes a single u_int through the pointer.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCSBLEN, &raw mut len) };
    if rc < 0 {
        return Err(anyhow!("BIOCSBLEN: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn attach_interface(fd: &OwnedFd, iface: &str) -> Result<()> {
    let bytes = iface.as_bytes();
    if bytes.len() >= 16 {
        return Err(anyhow!("interface name '{iface}' is too long for struct ifreq"));
    }
    let mut req = IfReq { name: [0; 16], _pad: [0; 16] };
    for (slot, byte) in req.name.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: BIOCSETIF reads a `struct ifreq`; `IfReq` is repr(C) and the
    // same 32-byte size, with the trailing union zeroed.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCSETIF, &raw mut req) };
    if rc < 0 {
        return Err(anyhow!("BIOCSETIF {iface}: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn set_immediate(fd: &OwnedFd) -> Result<()> {
    let mut on: libc::c_uint = 1;
    // SAFETY: BIOCIMMEDIATE reads a single u_int through the pointer.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), BIOCIMMEDIATE, &raw mut on) };
    if rc < 0 {
        return Err(anyhow!("BIOCIMMEDIATE: {}", io::Error::last_os_error()));
    }
    Ok(())
}

fn read_stats(fd: RawFd) -> Option<BpfStat> {
    let mut stats = BpfStat::default();
    // SAFETY: BIOCGSTATS writes two u_ints through the pointer.
    let rc = unsafe { libc::ioctl(fd, BIOCGSTATS, &raw mut stats) };
    (rc >= 0).then_some(stats)
}

/// Poll-read `/dev/bpf` until `stop`, counting `marker` occurrences.
fn capture_loop(fd: OwnedFd, marker: &[u8], stop: &AtomicBool) -> WireObservation {
    let raw = fd.as_raw_fd();
    let mut buf = vec![0u8; REQUESTED_BUF_LEN as usize];
    let mut count = 0u64;

    while !stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd { fd: raw, events: libc::POLLIN, revents: 0 };
        // SAFETY: single valid pollfd, count matches.
        let ready = unsafe { libc::poll(&raw mut pfd, 1, POLL_TIMEOUT_MS) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return WireObservation::unavailable(format!("poll: {err}"));
        }
        if ready == 0 {
            continue;
        }

        // SAFETY: `buf` is a valid writable allocation of exactly `buf.len()`.
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return WireObservation::unavailable(format!("read: {err}"));
        }
        count += count_occurrences(&buf[..n as usize], marker);
    }

    // A kernel-buffer overflow means the capture is no longer a sound basis
    // for "we saw nothing" — degrade to unavailable rather than report a
    // count that might be short.
    match read_stats(raw) {
        Some(stats) if stats.drop > 0 => WireObservation::unavailable(format!(
            "capture dropped {} packet(s) (kernel buffer overflow) — count {count} unreliable",
            stats.drop
        )),
        _ => WireObservation::Seen { count },
    }
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u64 {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_each_occurrence_once() {
        assert_eq!(count_occurrences(b"..X..X..X..", b"X"), 3);
    }

    #[test]
    fn counts_multi_byte_markers_without_overlap() {
        // "aaaa" contains "aa" twice non-overlapping, not three times.
        assert_eq!(count_occurrences(b"aaaa", b"aa"), 2);
    }

    #[test]
    fn finds_marker_embedded_in_binary_frame_padding() {
        // Stands in for a real BPF record: opaque header + link/IP/UDP bytes
        // around the payload we care about.
        let mut frame = vec![0x00, 0xff, 0x13, 0x37];
        frame.extend_from_slice(b"IPAURO-PROBE v0 host=mac pid=42 seq=1");
        frame.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(count_occurrences(&frame, b"host=mac pid=42"), 1);
    }

    #[test]
    fn absent_marker_counts_zero() {
        assert_eq!(count_occurrences(b"nothing to see here", b"host=mac pid=42"), 0);
    }

    #[test]
    fn empty_inputs_are_safe() {
        assert_eq!(count_occurrences(b"", b"x"), 0);
        assert_eq!(count_occurrences(b"x", b""), 0);
        assert_eq!(count_occurrences(b"x", b"xx"), 0);
    }

    #[test]
    fn ioctl_encoding_matches_macos_bpf_header() {
        // Values from <net/bpf.h> on macOS, computed by hand from
        // sys/ioccom.h's _IOWR/_IOW/_IOR macros. Pinning them here means a
        // typo in the encoder shows up as a unit-test failure rather than an
        // EINVAL at runtime in a launchd context with no terminal.
        assert_eq!(BIOCSBLEN, 0xC004_4266); // _IOWR('B', 102, u_int)
        assert_eq!(BIOCSETIF, 0x8020_426C); // _IOW('B', 108, struct ifreq)
        assert_eq!(BIOCIMMEDIATE, 0x8004_4270); // _IOW('B', 112, u_int)
        assert_eq!(BIOCGSTATS, 0x4008_426F); // _IOR('B', 111, struct bpf_stat)
    }

    #[test]
    fn ifreq_layout_matches_the_kernel_struct() {
        assert_eq!(std::mem::size_of::<IfReq>(), IFREQ_SIZE);
    }

    #[test]
    fn observation_displays_both_shapes() {
        assert!(WireObservation::Seen { count: 3 }.to_string().contains("3 own beacon"));
        assert!(WireObservation::unavailable("no --iface").to_string().contains("no --iface"));
    }
}
