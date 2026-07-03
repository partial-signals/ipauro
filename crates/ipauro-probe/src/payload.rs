//! Beacon payload: an obviously-non-Link probe datagram, distinguishable on sight
//! from real Ableton Link traffic (which is a compact binary format and will
//! never parse as this ASCII shape — see `listen`'s "foreign (Link?)" label).

use std::fmt;

/// Leading token identifying an IPAuRo probe beacon on the wire.
pub const MAGIC: &str = "IPAURO-PROBE";

/// Wire format version. `parse` only extracts the fields it knows about and
/// ignores the rest, so a future version can add fields without breaking older
/// probes' ability to recognize the beacon as "one of ours".
pub const PROTOCOL_VERSION: u32 = 0;

/// A single probe beacon: `IPAURO-PROBE v0 host=<hostname> pid=<pid> seq=<n>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub version: u32,
    pub host: String,
    pub pid: u32,
    pub seq: u64,
}

impl Beacon {
    pub fn new(host: &str, pid: u32, seq: u64) -> Self {
        // The wire format is whitespace-delimited, so a hostname containing
        // whitespace (unusual, but not guaranteed absent) would desync the
        // parser. Sanitize rather than reject.
        let sanitized = host.split_whitespace().collect::<Vec<_>>().join("_");
        let host = if sanitized.is_empty() { "unknown".to_string() } else { sanitized };
        Beacon { version: PROTOCOL_VERSION, host, pid, seq }
    }

    /// True if `host`/`pid` (typically this process's own identity) match this
    /// beacon's — i.e. this is one WE sent, not a foreign probe instance or
    /// real Link traffic. This is the loopback check `check` uses to determine
    /// whether app-layer multicast reception works at all in this context.
    pub fn is_own(&self, host: &str, pid: u32) -> bool {
        self.host == host && self.pid == pid
    }

    /// Parse a beacon out of a raw UDP payload. Returns `None` for anything
    /// that isn't a well-formed IPAURO-PROBE datagram — including real Link's
    /// binary payload (which usually isn't even valid UTF-8), and anything
    /// merely prefix-similar. Never attempts to parse Link's own wire format;
    /// unrecognized traffic is reported as opaque, not decoded.
    pub fn parse(bytes: &[u8]) -> Option<Beacon> {
        let text = std::str::from_utf8(bytes).ok()?;
        let rest = text.strip_prefix(MAGIC)?;
        // Require a word boundary right after MAGIC so "IPAURO-PROBE-DECOY..."
        // doesn't slip past the prefix check.
        if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
            return None;
        }

        let mut fields = rest.split_whitespace();
        let version = fields.next()?.strip_prefix('v')?.parse().ok()?;

        let (mut host, mut pid, mut seq) = (None, None, None);
        for field in fields {
            let (key, value) = field.split_once('=')?;
            match key {
                "host" => host = Some(value.to_string()),
                "pid" => pid = Some(value.parse().ok()?),
                "seq" => seq = Some(value.parse().ok()?),
                // Forward-compatible: ignore fields this build doesn't know
                // about rather than rejecting the whole beacon.
                _ => {}
            }
        }

        Some(Beacon { version, host: host?, pid: pid?, seq: seq? })
    }
}

impl fmt::Display for Beacon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{MAGIC} v{} host={} pid={} seq={}", self.version, self.host, self.pid, self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let b = Beacon::new("relay-mbp", 4242, 7);
        let wire = b.to_string();
        assert_eq!(wire, "IPAURO-PROBE v0 host=relay-mbp pid=4242 seq=7");
        let parsed = Beacon::parse(wire.as_bytes()).expect("parses back");
        assert_eq!(parsed, b);
    }

    #[test]
    fn parse_rejects_non_utf8_link_style_binary_payload() {
        // Real Ableton Link payloads are a compact binary format; this must
        // never be mistaken for a probe beacon.
        let binary = [0xff, 0x00, 0xfe, 0x02, 0x10, 0x20];
        assert_eq!(Beacon::parse(&binary), None);
    }

    #[test]
    fn parse_rejects_unrelated_text() {
        assert_eq!(Beacon::parse(b"just some udp payload"), None);
        assert_eq!(Beacon::parse(b""), None);
    }

    #[test]
    fn parse_rejects_prefix_lookalikes() {
        // Must not match on a mere string-prefix coincidence.
        assert_eq!(Beacon::parse(b"IPAURO-PROBE-DECOY v0 host=x pid=1 seq=1"), None);
    }

    #[test]
    fn parse_tolerates_unknown_future_fields() {
        let wire = "IPAURO-PROBE v0 host=x pid=1 seq=2 newfield=surprise";
        let parsed = Beacon::parse(wire.as_bytes()).expect("ignores unknown field");
        assert_eq!(parsed, Beacon::new("x", 1, 2));
    }

    #[test]
    fn parse_rejects_missing_fields() {
        assert_eq!(Beacon::parse(b"IPAURO-PROBE v0 host=x pid=1"), None); // no seq
        assert_eq!(Beacon::parse(b"IPAURO-PROBE v0 pid=1 seq=2"), None); // no host
        assert_eq!(Beacon::parse(b"IPAURO-PROBE v0 host=x seq=2"), None); // no pid
    }

    #[test]
    fn parse_rejects_malformed_version() {
        assert_eq!(Beacon::parse(b"IPAURO-PROBE 0 host=x pid=1 seq=2"), None); // missing 'v'
        assert_eq!(Beacon::parse(b"IPAURO-PROBE vX host=x pid=1 seq=2"), None); // non-numeric
    }

    #[test]
    fn is_own_matches_host_and_pid() {
        let b = Beacon::new("relay-mbp", 4242, 7);
        assert!(b.is_own("relay-mbp", 4242));
        assert!(!b.is_own("relay-mbp", 9999));
        assert!(!b.is_own("other-host", 4242));
    }

    #[test]
    fn sanitizes_whitespace_in_hostname() {
        let b = Beacon::new("weird host name", 1, 1);
        assert_eq!(b.host, "weird_host_name");
    }

    #[test]
    fn empty_hostname_falls_back_to_placeholder() {
        let b = Beacon::new("   ", 1, 1);
        assert_eq!(b.host, "unknown");
    }
}
