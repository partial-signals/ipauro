//! Verdict logic for `check`: turn the socket counts (sent, received-own,
//! received-foreign) plus the BPF wire observation into a human verdict and a
//! process exit code. Pure — no sockets, no I/O — so it's exhaustively
//! unit-testable independent of any real network stack.
//!
//! The wire leg is what makes the verdict falsifiable. Socket counts alone
//! cannot distinguish:
//!
//! * "the gate is open" from "the gate is shut but in-kernel multicast
//!   loopback isn't subject to it" (→ [`Verdict::LoopbackOnly`]), nor
//! * "denied on the inbound path" from "denied on the outbound path" — macOS
//!   suppresses a denied app's egress while `sendto` still reports success
//!   (→ [`Verdict::DeniedInbound`] vs [`Verdict::DeniedOutbound`]).
//!
//! When no wire observation is available the verdict degrades to the weaker
//! socket-only reading and says so, rather than overclaiming.

use std::fmt;

use crate::wire::WireObservation;

/// Result of a `check` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Our own beacons came back to our socket, and (where observed) also
    /// reached the wire: app-layer multicast works in this execution context.
    GateOpen,
    /// Our own beacons came back to our socket, but none of them reached the
    /// wire. In-process multicast loopback works while egress does not — the
    /// exact case a socket-only probe would misreport as `GateOpen`.
    LoopbackOnly,
    /// Beacons reached the wire but none came back to our socket: the packets
    /// exist and this process is not allowed to receive them.
    DeniedInbound,
    /// `sendto` reported success but nothing reached the wire and nothing came
    /// back: egress was suppressed beneath the socket layer.
    DeniedOutbound,
    /// Nothing was ever sent, so there is nothing to conclude from reception
    /// counts. Distinct from a hard setup error (socket/bind failure), which
    /// surfaces as an `Err` before a `Verdict` is ever computed — this variant
    /// covers the "ran, but the counts themselves are void" case.
    Inconclusive,
}

impl Verdict {
    /// Process exit code — the only channel a launchd job has for reporting a
    /// verdict, so each distinguishable outcome gets its own value.
    ///
    /// `0` gate open · `1` inconclusive/setup error · `4` denied inbound ·
    /// `5` denied outbound · `6` loopback-only.
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::GateOpen => 0,
            Verdict::Inconclusive => 1,
            Verdict::DeniedInbound => 4,
            Verdict::DeniedOutbound => 5,
            Verdict::LoopbackOnly => 6,
        }
    }

    /// True when this context cannot carry the product's multicast traffic —
    /// the single bit the R002-T8 placement decision actually turns on.
    pub fn is_denied(self) -> bool {
        matches!(self, Verdict::DeniedInbound | Verdict::DeniedOutbound | Verdict::LoopbackOnly)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Verdict::GateOpen => "GATE OPEN",
            Verdict::LoopbackOnly => "LOOPBACK ONLY",
            Verdict::DeniedInbound => "DENIED (inbound)",
            Verdict::DeniedOutbound => "DENIED (outbound)",
            Verdict::Inconclusive => "INCONCLUSIVE",
        };
        f.write_str(s)
    }
}

/// Classify a `check` run from its socket counts and wire observation.
pub fn compute(
    sent: u64,
    received_own: u64,
    received_foreign: u64,
    wire: &WireObservation,
) -> Verdict {
    // received_foreign never changes the verdict itself (own-beacon reception
    // is the actual test) — it's surfaced only as color in `describe`.
    let _ = received_foreign;

    // Nothing sent ⇒ the counts are void whatever the wire says.
    if sent == 0 {
        return Verdict::Inconclusive;
    }

    let wire_silent = matches!(wire, WireObservation::Seen { count: 0 });

    match (received_own > 0, wire_silent) {
        (true, false) => Verdict::GateOpen,
        (true, true) => Verdict::LoopbackOnly,
        // Beacons were observed on the wire (or the wire couldn't be observed
        // at all) yet none reached our socket: inbound denial. Without a wire
        // observation this is the honest default — `describe` marks it
        // unconfirmed.
        (false, false) => Verdict::DeniedInbound,
        (false, true) => Verdict::DeniedOutbound,
    }
}

/// Human-readable verdict line for `check`'s report.
pub fn describe(
    sent: u64,
    received_own: u64,
    received_foreign: u64,
    wire: &WireObservation,
) -> String {
    let verdict = compute(sent, received_own, received_foreign, wire);
    let unconfirmed = matches!(wire, WireObservation::Unavailable { .. });

    match verdict {
        Verdict::GateOpen if unconfirmed => format!(
            "app-layer multicast reception WORKS in this context \
             (received {received_own}/{sent} of our own beacons; {received_foreign} foreign). \
             NOT wire-confirmed — wire {wire}; rerun with --iface and /dev/bpf access to rule \
             out loopback-only reception"
        ),
        Verdict::GateOpen => format!(
            "app-layer multicast reception WORKS in this context \
             (received {received_own}/{sent} of our own beacons; {received_foreign} foreign), \
             wire-confirmed — {wire}"
        ),
        Verdict::LoopbackOnly => format!(
            "egress SUPPRESSED beneath the socket layer — our own beacons looped back in-process \
             ({received_own}/{sent}) but NONE reached the wire. A socket-only probe would have \
             called this context open; it is not"
        ),
        Verdict::DeniedInbound if unconfirmed => format!(
            "packets likely dropped by Local Network privacy — UNCONFIRMED, no wire observation \
             ({wire}). sent {sent}, received-own 0, received-foreign {received_foreign}. \
             Rerun with --iface and /dev/bpf access, or cross-check with tcpdump"
        ),
        Verdict::DeniedInbound => format!(
            "inbound DENIED by Local Network privacy — {wire}, but this process's socket received \
             0 of them (sent {sent}, received-foreign {received_foreign}). \
             Packets exist; this context may not receive them"
        ),
        Verdict::DeniedOutbound => format!(
            "outbound SUPPRESSED by Local Network privacy — sendto() reported success {sent} \
             time(s) but nothing reached the wire and nothing came back. \
             The denial is on the send path, not the receive path"
        ),
        Verdict::Inconclusive => {
            "inconclusive — no beacons were sent; check setup/socket errors above".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(count: u64) -> WireObservation {
        WireObservation::Seen { count }
    }

    fn no_wire() -> WireObservation {
        WireObservation::unavailable("no --iface")
    }

    #[test]
    fn gate_open_when_own_beacons_received_and_seen_on_wire() {
        assert_eq!(compute(10, 8, 0, &seen(8)), Verdict::GateOpen);
        assert_eq!(compute(10, 8, 0, &seen(8)).exit_code(), 0);
        assert!(!compute(10, 8, 0, &seen(8)).is_denied());
    }

    #[test]
    fn gate_open_takes_priority_even_with_foreign_traffic() {
        assert_eq!(compute(10, 3, 50, &seen(10)), Verdict::GateOpen);
    }

    #[test]
    fn wire_count_need_not_match_socket_count() {
        // The transmitted copy and the looped-back copy can both hit the BPF
        // tap, so the wire count routinely exceeds the socket count. Only
        // zero-vs-nonzero is load-bearing.
        assert_eq!(compute(10, 10, 0, &seen(20)), Verdict::GateOpen);
    }

    #[test]
    fn loopback_only_when_socket_receives_but_wire_is_silent() {
        // The false-positive a socket-only probe cannot catch.
        let v = compute(10, 10, 0, &seen(0));
        assert_eq!(v, Verdict::LoopbackOnly);
        assert_eq!(v.exit_code(), 6);
        assert!(v.is_denied());
    }

    #[test]
    fn denied_inbound_when_wire_shows_beacons_but_socket_gets_none() {
        let v = compute(10, 0, 0, &seen(10));
        assert_eq!(v, Verdict::DeniedInbound);
        assert_eq!(v.exit_code(), 4);
        assert!(v.is_denied());
    }

    #[test]
    fn denied_outbound_when_neither_wire_nor_socket_sees_anything() {
        let v = compute(10, 0, 0, &seen(0));
        assert_eq!(v, Verdict::DeniedOutbound);
        assert_eq!(v.exit_code(), 5);
        assert!(v.is_denied());
    }

    #[test]
    fn without_a_wire_observation_denial_defaults_to_inbound() {
        // Preserves the original socket-only contract (exit 4) so existing
        // runbook rows stay comparable; `describe` marks it unconfirmed.
        assert_eq!(compute(10, 0, 0, &no_wire()), Verdict::DeniedInbound);
        assert_eq!(compute(10, 0, 0, &no_wire()).exit_code(), 4);
    }

    #[test]
    fn without_a_wire_observation_reception_still_reads_as_open() {
        assert_eq!(compute(10, 5, 0, &no_wire()), Verdict::GateOpen);
    }

    #[test]
    fn inconclusive_when_nothing_was_sent_regardless_of_wire() {
        assert_eq!(compute(0, 0, 0, &seen(0)), Verdict::Inconclusive);
        assert_eq!(compute(0, 0, 3, &seen(7)), Verdict::Inconclusive);
        assert_eq!(compute(0, 0, 0, &no_wire()).exit_code(), 1);
    }

    #[test]
    fn every_verdict_has_a_distinct_exit_code() {
        let all = [
            Verdict::GateOpen,
            Verdict::LoopbackOnly,
            Verdict::DeniedInbound,
            Verdict::DeniedOutbound,
            Verdict::Inconclusive,
        ];
        let mut codes: Vec<u8> = all.iter().map(|v| v.exit_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "exit codes must be distinguishable by launchd");
    }

    #[test]
    fn describe_flags_unconfirmed_results_as_such() {
        assert!(describe(5, 0, 0, &no_wire()).contains("UNCONFIRMED"));
        assert!(describe(5, 2, 0, &no_wire()).contains("NOT wire-confirmed"));
    }

    #[test]
    fn describe_does_not_hedge_when_the_wire_confirms() {
        let open = describe(5, 5, 0, &seen(5));
        assert!(open.contains("wire-confirmed"));
        assert!(!open.contains("NOT wire-confirmed"));
        assert!(describe(5, 0, 0, &seen(5)).contains("inbound DENIED"));
    }

    #[test]
    fn describe_calls_out_the_loopback_only_false_positive() {
        let text = describe(5, 5, 0, &seen(0));
        assert!(text.contains("would have called this context open"));
    }

    #[test]
    fn describe_matches_spec_wording_for_the_open_case() {
        assert!(
            describe(5, 1, 0, &seen(1))
                .contains("app-layer multicast reception WORKS in this context")
        );
    }
}
