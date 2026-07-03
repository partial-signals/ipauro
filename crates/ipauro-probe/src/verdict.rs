//! Verdict logic for `check`: turn (sent, received-own, received-foreign)
//! counts into a human verdict + process exit code. Pure — no sockets, no I/O —
//! so it's exhaustively unit-testable independent of any real network stack.

use std::fmt;

/// Result of a `check` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// At least one of our own looped-back beacons was received: app-layer
    /// multicast reception works in this execution context.
    GateOpen,
    /// Beacons were sent but none of our own came back — the Local Network
    /// privacy gate's silent-deny signature (A002: packets can be visible on
    /// the wire yet never reach this app's socket).
    SilentDeny,
    /// Nothing was ever sent, so there is nothing to conclude from reception
    /// counts. Distinct from a hard setup error (socket/bind failure), which
    /// surfaces as an `Err` before a `Verdict` is ever computed — this variant
    /// covers the "ran, but the counts themselves are void" case.
    Inconclusive,
}

impl Verdict {
    /// Process exit code per the R002-T8 spec:
    /// 0 = gate open, 4 = silent deny (the gate's signature), 1 = setup
    /// error / inconclusive.
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::GateOpen => 0,
            Verdict::SilentDeny => 4,
            Verdict::Inconclusive => 1,
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Verdict::GateOpen => "GATE OPEN",
            Verdict::SilentDeny => "SILENT DENY",
            Verdict::Inconclusive => "INCONCLUSIVE",
        };
        f.write_str(s)
    }
}

/// Classify a `check` run from its counts.
pub fn compute(sent: u64, received_own: u64, received_foreign: u64) -> Verdict {
    // received_foreign never changes the verdict itself (own-beacon loopback
    // is the actual test) — it's surfaced only as color in `describe`.
    let _ = received_foreign;
    if received_own > 0 {
        Verdict::GateOpen
    } else if sent > 0 {
        Verdict::SilentDeny
    } else {
        Verdict::Inconclusive
    }
}

/// Human-readable verdict line for `check`'s report, in the exact words the
/// R002-T8 spec calls for.
pub fn describe(sent: u64, received_own: u64, received_foreign: u64) -> String {
    match compute(sent, received_own, received_foreign) {
        Verdict::GateOpen => format!(
            "app-layer multicast reception WORKS in this context \
             (received {received_own}/{sent} of our own beacons; {received_foreign} foreign)"
        ),
        Verdict::SilentDeny if received_foreign > 0 => format!(
            "packets likely dropped by Local Network privacy — cross-check with tcpdump \
             (sent {sent}, received-own 0, but saw {received_foreign} foreign datagram(s) — \
             gate may be per-flow, not blanket)"
        ),
        Verdict::SilentDeny => format!(
            "packets likely dropped by Local Network privacy — cross-check with tcpdump \
             (sent {sent}, received-own 0, received-foreign 0)"
        ),
        Verdict::Inconclusive => {
            "inconclusive — no beacons were sent; check setup/socket errors above".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_open_when_own_beacons_received() {
        assert_eq!(compute(10, 1, 0), Verdict::GateOpen);
        assert_eq!(compute(10, 1, 0).exit_code(), 0);
    }

    #[test]
    fn gate_open_takes_priority_even_with_foreign_traffic() {
        assert_eq!(compute(10, 3, 50), Verdict::GateOpen);
        assert_eq!(compute(10, 3, 50).exit_code(), 0);
    }

    #[test]
    fn silent_deny_when_sent_but_nothing_own_received() {
        assert_eq!(compute(10, 0, 0), Verdict::SilentDeny);
        assert_eq!(compute(10, 0, 0).exit_code(), 4);
    }

    #[test]
    fn silent_deny_even_if_foreign_traffic_visible() {
        // Foreign traffic being visible doesn't by itself prove reception of
        // OUR beacons works — own-beacon loopback is the actual test.
        assert_eq!(compute(10, 0, 5), Verdict::SilentDeny);
        assert_eq!(compute(10, 0, 5).exit_code(), 4);
    }

    #[test]
    fn inconclusive_when_nothing_was_sent() {
        assert_eq!(compute(0, 0, 0), Verdict::Inconclusive);
        assert_eq!(compute(0, 0, 0).exit_code(), 1);
    }

    #[test]
    fn inconclusive_even_if_foreign_traffic_somehow_seen_with_zero_sent() {
        assert_eq!(compute(0, 0, 3), Verdict::Inconclusive);
        assert_eq!(compute(0, 0, 3).exit_code(), 1);
    }

    #[test]
    fn describe_mentions_tcpdump_on_silent_deny() {
        assert!(describe(5, 0, 0).contains("tcpdump"));
        assert!(describe(5, 0, 2).contains("tcpdump"));
    }

    #[test]
    fn describe_flags_gate_open_in_words() {
        assert!(describe(5, 2, 0).contains("WORKS"));
    }

    #[test]
    fn describe_matches_spec_wording() {
        assert!(describe(5, 1, 0).contains("app-layer multicast reception WORKS in this context"));
        assert!(describe(5, 0, 0).contains("packets likely dropped by Local Network privacy"));
    }
}
