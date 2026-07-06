//! Pure validation and IPv4 math shared across the M1 data-plane verbs
//! (`SetBridgeMembers`, `SetBridgeAddress`, `ScopeUdp`, `ServeDhcp`). No
//! process spawn, no I/O — everything here is unit-testable in isolation,
//! which is where the "validate EVERY name before any exec" requirement
//! (ipauro-proto's `helper` module docs) actually gets enforced: reject the
//! whole request before `executor`/`pf`/`dhcp` ever see it.

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// `^en[0-9]+$` — the shape of a USB-NCM (or any real) Ethernet interface
/// name on macOS (A002 §5). Bridge members must match this; the bridge
/// itself is never a valid member of itself.
pub fn is_en_iface(name: &str) -> bool {
    match name.strip_prefix("en") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Validate a bridge-member candidate name: `^en[0-9]+$` only. Existence
/// (does this interface currently exist per `ifconfig`) is a separate,
/// system-dependent check the caller performs via `BridgeExecutor::
/// list_interfaces` — kept out of this pure function so it stays testable
/// without a process spawn.
pub fn is_valid_member_name(name: &str) -> bool {
    is_en_iface(name)
}

/// Validate a pf scope-target interface name: `^en[0-9]+$` OR exactly the
/// bridge itself (`ScopeUdp`'s allow-list legitimately names `bridge90` —
/// see the `m1_verbs_round_trip` proto test). Never any other literal.
pub fn is_valid_scope_iface_name(name: &str, bridge_name: &str) -> bool {
    is_en_iface(name) || name == bridge_name
}

/// Validate every name in `names` against `predicate`, returning the first
/// offender. Reject-the-whole-request-on-one-bad-name is enforced by the
/// caller treating any `Some` as "do not exec anything."
pub fn first_invalid_name<'a>(
    names: &'a [String],
    predicate: impl Fn(&str) -> bool,
) -> Option<&'a str> {
    names.iter().map(String::as_str).find(|n| !predicate(n))
}

/// Diff a desired bridge membership against the current one: names present
/// in `want` but not `have` must be `addm`'d; names present in `have` but
/// not `want` must be `deletem`'d. Set semantics (duplicates in either input
/// don't produce duplicate actions); order follows the input lists.
pub fn compute_membership_diff(want: &[String], have: &[String]) -> (Vec<String>, Vec<String>) {
    let want_set: HashSet<&str> = want.iter().map(String::as_str).collect();
    let have_set: HashSet<&str> = have.iter().map(String::as_str).collect();
    let to_add = want.iter().filter(|m| !have_set.contains(m.as_str())).cloned().collect();
    let to_remove = have.iter().filter(|m| !want_set.contains(m.as_str())).cloned().collect();
    (to_add, to_remove)
}

/// RFC1918 private address ranges: `10/8`, `172.16/12`, `192.168/16`.
pub fn is_rfc1918(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Validate a `SetBridgeAddress` request: RFC1918 + prefix in `8..=30`
/// (ipauro-proto's `helper` module docs).
pub fn validate_bridge_address(ipv4: Ipv4Addr, prefix: u8) -> Result<(), String> {
    if !is_rfc1918(ipv4) {
        return Err(format!("{ipv4} is not an RFC1918 private address"));
    }
    if !(8..=30).contains(&prefix) {
        return Err(format!("prefix /{prefix} is outside the accepted range 8..=30"));
    }
    Ok(())
}

/// Convert a CIDR prefix length to a dotted-decimal netmask.
/// `prefix == 0` yields `0.0.0.0`; out-of-range (`>32`) values saturate to
/// `/32` — callers that care about the accepted range validate separately
/// via [`validate_bridge_address`].
pub fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let prefix = prefix.min(32);
    let bits: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ipv4Addr::from(bits)
}

/// Convert a dotted-decimal netmask back to a prefix length. `None` if the
/// mask isn't a contiguous run of one-bits followed by zero-bits (a
/// malformed/unexpected mask — real `ifconfig` output never produces this,
/// but a parser must not silently misreport one that does).
pub fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.count_ones();
    let expected = if ones == 0 { 0 } else { u32::MAX << (32 - ones) };
    if bits == expected { Some(ones as u8) } else { None }
}

/// Parse an `ifconfig`-style hex netmask token (e.g. `0xffffff00`) into a
/// prefix length.
pub fn netmask_hex_to_prefix(hex: &str) -> Option<u8> {
    let digits = hex.strip_prefix("0x").unwrap_or(hex);
    let bits = u32::from_str_radix(digits, 16).ok()?;
    netmask_to_prefix(Ipv4Addr::from(bits))
}

/// Validate a `ServeDhcp` pool against the bridge's own subnet
/// (`bridge_ipv4`/`bridge_prefix`, from `BridgeExecutor::address_prefix`):
/// the caller-supplied `netmask` must match the bridge's actual netmask, and
/// both pool bounds must fall inside that subnet with `pool_start <=
/// pool_end` (R005-T6: "Pool must lie in the bridge's subnet").
pub fn validate_dhcp_pool(
    bridge_ipv4: Ipv4Addr,
    bridge_prefix: u8,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Result<(), String> {
    let expected_netmask = prefix_to_netmask(bridge_prefix);
    if netmask != expected_netmask {
        return Err(format!(
            "netmask {netmask} does not match the bridge's /{bridge_prefix} ({expected_netmask})"
        ));
    }
    let mask_bits = u32::from(netmask);
    let network = u32::from(bridge_ipv4) & mask_bits;
    for (label, addr) in [("pool_start", pool_start), ("pool_end", pool_end)] {
        if u32::from(addr) & mask_bits != network {
            return Err(format!(
                "{label} {addr} is not in the bridge's subnet ({network:#010x}/{bridge_prefix})"
            ));
        }
    }
    if u32::from(pool_start) > u32::from(pool_end) {
        return Err(format!("pool_start {pool_start} is after pool_end {pool_end}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- member/iface name validation matrix ------------------------------

    #[test]
    fn valid_member_names() {
        for n in ["en0", "en9", "en12", "en999", "en01"] {
            assert!(is_valid_member_name(n), "{n} should be valid");
        }
    }

    #[test]
    fn invalid_member_names() {
        for n in ["en", "eth0", "en1a", "bridge90", "en-1", "ENP0", "en 9", "", "en9;rm -rf /"] {
            assert!(!is_valid_member_name(n), "{n} should be invalid");
        }
    }

    #[test]
    fn scope_iface_allows_bridge_name_but_not_other_literals() {
        assert!(is_valid_scope_iface_name("bridge90", "bridge90"));
        assert!(is_valid_scope_iface_name("en9", "bridge90"));
        assert!(!is_valid_scope_iface_name("bridge1", "bridge90"));
        assert!(!is_valid_scope_iface_name("en0/../etc", "bridge90"));
    }

    #[test]
    fn first_invalid_name_reports_the_first_offender_and_stops_short() {
        let names = vec!["en9".to_string(), "bad name".to_string(), "en12".to_string()];
        assert_eq!(first_invalid_name(&names, is_valid_member_name), Some("bad name"));
        let all_good = vec!["en9".to_string(), "en12".to_string()];
        assert_eq!(first_invalid_name(&all_good, is_valid_member_name), None);
    }

    // ---- membership convergence decisions ---------------------------------

    #[test]
    fn diff_adds_missing_and_removes_stale() {
        let want = vec!["en9".to_string(), "en12".to_string()];
        let have = vec!["en12".to_string(), "en17".to_string()];
        let (add, remove) = compute_membership_diff(&want, &have);
        assert_eq!(add, vec!["en9".to_string()]);
        assert_eq!(remove, vec!["en17".to_string()]);
    }

    #[test]
    fn diff_identical_sets_is_empty() {
        let members = vec!["en9".to_string(), "en12".to_string()];
        let (add, remove) = compute_membership_diff(&members, &members);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    #[test]
    fn diff_empty_have_adds_everything() {
        let want = vec!["en9".to_string()];
        let (add, remove) = compute_membership_diff(&want, &[]);
        assert_eq!(add, want);
        assert!(remove.is_empty());
    }

    #[test]
    fn diff_empty_want_removes_everything() {
        let have = vec!["en9".to_string(), "en12".to_string()];
        let (add, remove) = compute_membership_diff(&[], &have);
        assert!(add.is_empty());
        assert_eq!(remove, have);
    }

    #[test]
    fn diff_tolerates_duplicates_in_inputs() {
        let want = vec!["en9".to_string(), "en9".to_string()];
        let have = vec!["en9".to_string()];
        let (add, remove) = compute_membership_diff(&want, &have);
        assert!(add.is_empty());
        assert!(remove.is_empty());
    }

    // ---- RFC1918 + prefix validation --------------------------------------

    #[test]
    fn rfc1918_ranges_accepted() {
        for a in ["10.0.0.1", "10.69.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1"] {
            let addr: Ipv4Addr = a.parse().unwrap();
            assert!(is_rfc1918(addr), "{a} should be RFC1918");
        }
    }

    #[test]
    fn non_rfc1918_ranges_rejected() {
        for a in ["8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.0.1", "1.2.3.4"] {
            let addr: Ipv4Addr = a.parse().unwrap();
            assert!(!is_rfc1918(addr), "{a} should not be RFC1918");
        }
    }

    #[test]
    fn validate_bridge_address_matrix() {
        let good = "10.69.0.1".parse().unwrap();
        assert!(validate_bridge_address(good, 24).is_ok());
        assert!(validate_bridge_address(good, 8).is_ok());
        assert!(validate_bridge_address(good, 30).is_ok());
        assert!(validate_bridge_address(good, 7).is_err());
        assert!(validate_bridge_address(good, 31).is_err());
        let public: Ipv4Addr = "8.8.8.8".parse().unwrap();
        assert!(validate_bridge_address(public, 24).is_err());
    }

    // ---- netmask <-> prefix ------------------------------------------------

    #[test]
    fn prefix_to_netmask_matrix() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(30), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn netmask_to_prefix_matrix() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), Some(8));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 252)), Some(30));
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
        // Non-contiguous mask: not a valid netmask, must not silently misreport.
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[test]
    fn netmask_hex_round_trips_prefix() {
        assert_eq!(netmask_hex_to_prefix("0xffffff00"), Some(24));
        assert_eq!(netmask_hex_to_prefix("ffffff00"), Some(24));
        assert_eq!(netmask_hex_to_prefix("0xff000000"), Some(8));
        assert_eq!(netmask_hex_to_prefix("not-hex"), None);
    }

    // ---- DHCP pool-in-subnet validation ------------------------------------

    #[test]
    fn dhcp_pool_inside_subnet_is_ok() {
        let bridge = "10.69.0.1".parse().unwrap();
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let start = "10.69.0.10".parse().unwrap();
        let end = "10.69.0.200".parse().unwrap();
        assert!(validate_dhcp_pool(bridge, 24, start, end, mask).is_ok());
    }

    #[test]
    fn dhcp_pool_outside_subnet_is_rejected() {
        let bridge = "10.69.0.1".parse().unwrap();
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let start = "10.70.0.10".parse().unwrap();
        let end = "10.70.0.200".parse().unwrap();
        assert!(validate_dhcp_pool(bridge, 24, start, end, mask).is_err());
    }

    #[test]
    fn dhcp_pool_mismatched_netmask_is_rejected() {
        let bridge = "10.69.0.1".parse().unwrap();
        let wrong_mask = Ipv4Addr::new(255, 255, 0, 0);
        let start = "10.69.0.10".parse().unwrap();
        let end = "10.69.0.200".parse().unwrap();
        assert!(validate_dhcp_pool(bridge, 24, start, end, wrong_mask).is_err());
    }

    #[test]
    fn dhcp_pool_start_after_end_is_rejected() {
        let bridge = "10.69.0.1".parse().unwrap();
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let start = "10.69.0.200".parse().unwrap();
        let end = "10.69.0.10".parse().unwrap();
        assert!(validate_dhcp_pool(bridge, 24, start, end, mask).is_err());
    }
}
