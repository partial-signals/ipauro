//! Resolve a human interface name (e.g. `en0`) to its IPv4 address — needed for
//! `IP_MULTICAST_IF` / multicast group membership scoping (`--iface`).

use std::net::Ipv4Addr;

use anyhow::{Context, Result};

/// Look up the IPv4 address bound to interface `name`.
pub fn resolve_ipv4(name: &str) -> Result<Ipv4Addr> {
    let interfaces = if_addrs::get_if_addrs().context("enumerating network interfaces")?;

    interfaces
        .into_iter()
        .filter(|iface| iface.name == name)
        .find_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) => Some(v4.ip),
            // This tool only speaks IPv4 multicast (matching Ableton Link's
            // 224.76.78.75 group); an interface with only an IPv6 address
            // isn't usable here.
            if_addrs::IfAddr::V6(_) => None,
        })
        .with_context(|| format!("interface '{name}' not found, or has no IPv4 address bound"))
}

/// `--iface` is optional everywhere it appears; `None` means "let the OS pick
/// the default membership/routing interface" and skips interface enumeration
/// entirely.
pub fn resolve_optional(name: Option<&str>) -> Result<Option<Ipv4Addr>> {
    name.map(resolve_ipv4).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_interface_name_is_an_error() {
        let err = resolve_ipv4("definitely-not-a-real-iface-zzz").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn none_resolves_to_none_without_touching_the_network_stack() {
        assert!(resolve_optional(None).unwrap().is_none());
    }
}
