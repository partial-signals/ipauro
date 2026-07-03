//! Shared timestamp formatting for probe stdout lines.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Unix epoch seconds with millisecond precision, e.g. `1751476451.123`.
///
/// Deliberately epoch time rather than a hand-rolled calendar/timezone
/// conversion: it's unambiguous, needs no date-math correctness risk, and
/// matches `tcpdump -tt`'s output format exactly — see RUNBOOK.md's wire
/// cross-check, which relies on that for lining datagrams up by eye.
pub fn now_ts() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    format!("{}.{:03}", dur.as_secs(), dur.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_seconds_dot_millis() {
        let ts = now_ts();
        let (secs, millis) = ts.split_once('.').expect("has a decimal point");
        assert!(!secs.is_empty() && secs.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(millis.len(), 3);
        assert!(millis.chars().all(|c| c.is_ascii_digit()));
    }
}
