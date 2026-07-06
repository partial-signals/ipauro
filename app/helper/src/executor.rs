//! Bridge lifecycle behind a trait (ticket R002-F4, extended for M1's
//! R005-T4 member/address reconcile), so request handling (`request.rs`) can
//! be unit-tested against a mock instead of shelling out.
//!
//! The real implementation shells out to `/sbin/ifconfig`. It is the ONLY
//! place in this crate that constructs an `ifconfig` command line, and the
//! bridge operations are hardcoded to [`ipauro_proto::helper::BRIDGE_NAME`]
//! — the request enum carries no interface name field for bridge identity
//! (see `ipauro-proto`'s `helper` module docs), so by construction no other
//! bridge can ever be created/destroyed/addressed here. Member names DO
//! travel over the wire (`SetBridgeMembers`); see `request.rs` for the
//! validate-before-any-exec gate ahead of every call into this module.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, Result, bail};
use ipauro_proto::helper::BRIDGE_NAME;
use ipauro_proto::state::BridgeInfo;

use crate::cmd::{self, IFCONFIG};
use crate::netutil;

/// The bridge operations the helper exposes over XPC. Real impl below;
/// tests use a mock (see `request.rs`'s tests).
pub trait BridgeExecutor: Send + Sync {
    fn create(&self) -> Result<()>;
    fn destroy(&self) -> Result<()>;
    fn status(&self) -> Result<Option<BridgeInfo>>;

    /// Every network interface name the system currently knows about
    /// (`ifconfig -l`). Used to validate that a caller-supplied member/scope
    /// name is real before any exec touches it (R002-T3: interface names are
    /// the first attacker-aimable strings on this channel).
    fn list_interfaces(&self) -> Result<Vec<String>>;

    /// Reconcile the bridge's member set to exactly `members` (already name-
    /// and existence-validated by the caller — see `request.rs`): add
    /// missing, remove stale, then flush any IPv4 alias each member
    /// self-assigned (A002 §4 — addresses live on the bridge, not the
    /// member; a member keeping a stray alias produces a split-brain
    /// subnet).
    fn set_members(&self, members: &[String]) -> Result<()>;

    /// Assign the bridge's IPv4 address (idempotent: a no-op if the bridge
    /// already holds this exact address/prefix).
    fn set_address(&self, ipv4: Ipv4Addr, prefix: u8) -> Result<()>;

    /// The bridge's current address prefix, parsed from `ifconfig`'s
    /// `netmask 0x........` token. Not carried by [`BridgeInfo`] today (see
    /// this lane's final report for a proto change request) — needed
    /// in-helper to validate a `ServeDhcp` pool falls inside the bridge's
    /// actual subnet (R005-T6).
    fn address_prefix(&self) -> Result<Option<u8>>;
}

/// Real `/sbin/ifconfig`-backed executor. Idempotent per ticket requirement:
/// create-on-existing and destroy-on-missing are `Ok(())`, not errors.
pub struct IfconfigExecutor;

impl BridgeExecutor for IfconfigExecutor {
    fn create(&self) -> Result<()> {
        // `ifconfig bridge90 create` fails ("already exists") if the bridge
        // is already there, so check first rather than ignoring the error —
        // ignoring it would mask a genuinely different failure.
        if self.status()?.is_none() {
            run(&[BRIDGE_NAME, "create"])?;
            log::info!("created {BRIDGE_NAME}");
        }
        run(&[BRIDGE_NAME, "up"])?;
        Ok(())
    }

    fn destroy(&self) -> Result<()> {
        match run(&[BRIDGE_NAME, "destroy"]) {
            Ok(_) => {
                log::info!("destroyed {BRIDGE_NAME}");
                Ok(())
            }
            Err(e) if stderr_indicates_absent(&e.to_string()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn status(&self) -> Result<Option<BridgeInfo>> {
        let output = Command::new(IFCONFIG)
            .arg(BRIDGE_NAME)
            .output()
            .with_context(|| format!("spawning {IFCONFIG} {BRIDGE_NAME}"))?;
        classify_ifconfig_output(
            output.status.success(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        )
    }

    fn list_interfaces(&self) -> Result<Vec<String>> {
        cmd::list_interfaces()
    }

    fn set_members(&self, members: &[String]) -> Result<()> {
        let have = self.status()?.map(|info| info.members).unwrap_or_default();
        let (to_add, to_remove) = netutil::compute_membership_diff(members, &have);

        for m in &to_add {
            run(&[BRIDGE_NAME, "addm", m]).with_context(|| format!("adding member {m}"))?;
            log::info!("added bridge member {m}");
        }
        for m in &to_remove {
            run(&[BRIDGE_NAME, "deletem", m])
                .with_context(|| format!("removing stale member {m}"))?;
            log::info!("removed stale bridge member {m}");
        }
        // Flush stray IPv4 aliases on every DESIRED member (not just newly
        // added ones) every pass — matches usb-link-bridge.sh's reconcile(),
        // and is cheap/idempotent when there's nothing to flush.
        for m in members {
            self.flush_member_aliases(m);
        }
        Ok(())
    }

    fn set_address(&self, ipv4: Ipv4Addr, prefix: u8) -> Result<()> {
        let current = self.status()?;
        let current_ipv4 = current.as_ref().and_then(|info| info.ipv4.as_deref());
        let current_prefix = self.address_prefix()?;
        if current_ipv4 == Some(ipv4.to_string().as_str()) && current_prefix == Some(prefix) {
            return Ok(()); // idempotent: already exactly this address/prefix
        }
        let netmask = netutil::prefix_to_netmask(prefix);
        run(&[BRIDGE_NAME, "inet", &ipv4.to_string(), "netmask", &netmask.to_string()])?;
        log::info!("set {BRIDGE_NAME} address -> {ipv4}/{prefix}");
        Ok(())
    }

    fn address_prefix(&self) -> Result<Option<u8>> {
        let output = Command::new(IFCONFIG)
            .arg(BRIDGE_NAME)
            .output()
            .with_context(|| format!("spawning {IFCONFIG} {BRIDGE_NAME}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr_indicates_absent(&stderr) {
                return Ok(None);
            }
            bail!("ifconfig {BRIDGE_NAME} failed: {}", stderr.trim());
        }
        Ok(parse_first_inet_netmask_prefix(&String::from_utf8_lossy(&output.stdout)))
    }
}

impl IfconfigExecutor {
    /// Query `member`'s own addresses and flush every one found — the
    /// address belongs on the bridge (A002 §4). Best-effort: a member that
    /// vanished mid-reconcile (replug race) or a flush that fails on an
    /// already-gone alias logs and continues rather than failing the whole
    /// `SetBridgeMembers` call over one stray alias.
    fn flush_member_aliases(&self, member: &str) {
        let output = match Command::new(IFCONFIG).arg(member).output() {
            Ok(o) => o,
            Err(e) => {
                log::warn!("could not spawn {IFCONFIG} {member} to flush aliases: {e:#}");
                return;
            }
        };
        if !output.status.success() {
            log::warn!(
                "could not query {member} to flush aliases: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return;
        }
        for addr in parse_inet_addresses(&String::from_utf8_lossy(&output.stdout)) {
            log::info!("flushing member {member} addr {addr} (belongs on the bridge, A002 §4)");
            if let Err(e) = run(&[member, "-alias", &addr]) {
                log::warn!("flushing {member} alias {addr} failed: {e:#}");
            }
        }
    }
}

fn run(args: &[&str]) -> Result<std::process::Output> {
    cmd::run_checked(IFCONFIG, args)
}

/// `ifconfig`'s stable error text when the interface doesn't exist (verified
/// against real `ifconfig` behavior; see the prototype's `usb-link-bridge.sh`
/// `bridge_exists()` which relies on the same nonzero-exit signal).
fn stderr_indicates_absent(stderr: &str) -> bool {
    stderr.contains("does not exist")
}

/// Pure classification of an `ifconfig <bridge>` invocation's result, split
/// out from `status()` so it can be exercised with canned output — no process
/// spawn, no root required — independent of whether `/sbin/ifconfig` is even
/// present on the test machine.
fn classify_ifconfig_output(
    success: bool,
    stdout: &str,
    stderr: &str,
) -> Result<Option<BridgeInfo>> {
    if !success {
        if stderr_indicates_absent(stderr) {
            return Ok(None);
        }
        bail!("ifconfig {BRIDGE_NAME} failed: {}", stderr.trim());
    }
    Ok(Some(parse_bridge_status(stdout)))
}

/// Parse every IPv4 (`inet `) address out of an `ifconfig <ifc>` stdout blob
/// — used both by [`parse_bridge_status`] (the bridge's own address) and by
/// [`IfconfigExecutor::flush_member_aliases`] (a member can carry zero, one,
/// or several stray IPv4 aliases it self-assigned before being bridged).
/// Deliberately matches "inet " (trailing space) so "inet6" lines are
/// excluded.
fn parse_inet_addresses(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Parse `ifconfig bridge90`'s stdout into a [`BridgeInfo`]. Only called once
/// the caller already knows the bridge exists (nonzero exit is handled by
/// [`classify_ifconfig_output`] before this is reached).
fn parse_bridge_status(stdout: &str) -> BridgeInfo {
    let mut members = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("member: ") {
            if let Some(name) = rest.split_whitespace().next() {
                members.push(name.to_string());
            }
        }
    }
    let ipv4 = parse_inet_addresses(stdout).into_iter().next();
    let prefix = parse_first_inet_netmask_prefix(stdout);
    BridgeInfo { name: BRIDGE_NAME.to_string(), members, ipv4, prefix }
}

/// Parse the netmask off the FIRST `inet ` line of an `ifconfig <ifc>`
/// stdout blob (e.g. `inet 10.69.0.1 netmask 0xffffff00 broadcast
/// 10.69.0.255`) into a CIDR prefix length. `None` if there's no `inet`
/// line, or its `netmask` token is missing/unparseable.
fn parse_first_inet_netmask_prefix(stdout: &str) -> Option<u8> {
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            let mask_pos = tokens.iter().position(|t| *t == "netmask")?;
            let hex = tokens.get(mask_pos + 1)?;
            return netutil::netmask_hex_to_prefix(hex);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canned, real-looking `ifconfig bridge90` output: two members + an
    /// assigned inet address, plus an inet6 line that must NOT be picked up
    /// as the ipv4 field.
    const BRIDGE_PRESENT_STDOUT: &str = "\
bridge90: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=3<RXCSUM,TXCSUM>
\tether 6e:1a:2b:3c:4d:5e
\tinet 10.69.0.1 netmask 0xffffff00 broadcast 10.69.0.255
\tinet6 fe80::1%bridge90 prefixlen 64 scopeid 0x1a
\tConfiguration:
\t\tid 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
\t\tmaxage 0 holdcnt 0 proto stp maxaddr 100 timeout 1200
\t\troot id 0:0:0:0:0:0 priority 0 ifcost 0 port 0
\t\tipfilter disabled flags 0x2
\tmember: en9 flags=3<LEARNING,DISCOVER>
\t        ifmaxaddr 0 port 9 priority 0 path cost 0
\tmember: en12 flags=3<LEARNING,DISCOVER>
\t        ifmaxaddr 0 port 10 priority 0 path cost 0
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: <unknown type>
\tstatus: active
";

    const BRIDGE_ABSENT_STDERR: &str = "ifconfig: interface bridge90 does not exist\n";

    #[test]
    fn parses_present_bridge_with_members_and_inet() {
        let result = classify_ifconfig_output(true, BRIDGE_PRESENT_STDOUT, "").unwrap();
        let info = result.expect("bridge should be present");
        assert_eq!(info.name, BRIDGE_NAME);
        assert_eq!(info.members, vec!["en9".to_string(), "en12".to_string()]);
        assert_eq!(info.ipv4.as_deref(), Some("10.69.0.1"));
    }

    #[test]
    fn absent_bridge_is_none_not_an_error() {
        let result = classify_ifconfig_output(false, "", BRIDGE_ABSENT_STDERR).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn other_failure_is_a_real_error() {
        let err = classify_ifconfig_output(false, "", "ifconfig: permission denied\n")
            .expect_err("non-absent failures must surface as errors");
        assert!(err.to_string().contains("permission denied"));
    }

    #[test]
    fn bridge_with_no_members_and_no_inet() {
        let stdout =
            "bridge90: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500\n\tstatus: active\n";
        let info = classify_ifconfig_output(true, stdout, "").unwrap().unwrap();
        assert!(info.members.is_empty());
        assert!(info.ipv4.is_none());
    }

    #[test]
    fn parses_netmask_prefix_from_bridge_output() {
        assert_eq!(parse_first_inet_netmask_prefix(BRIDGE_PRESENT_STDOUT), Some(24));
    }

    #[test]
    fn no_inet_line_has_no_prefix() {
        let stdout = "bridge90: flags=8802<BROADCAST> mtu 1500\n\tstatus: active\n";
        assert_eq!(parse_first_inet_netmask_prefix(stdout), None);
    }

    #[test]
    fn parses_multiple_stray_aliases_on_a_member() {
        let stdout = "\
en9: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
\tinet6 fe80::1%en9 prefixlen 64 scopeid 0x9
\tinet 169.254.84.1 netmask 0xffff0000 broadcast 169.254.255.255
\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
\tstatus: active
";
        assert_eq!(
            parse_inet_addresses(stdout),
            vec!["169.254.84.1".to_string(), "10.0.0.5".to_string()]
        );
    }

    #[test]
    fn member_with_no_aliases_parses_empty() {
        let stdout = "en9: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tstatus: active\n";
        assert!(parse_inet_addresses(stdout).is_empty());
    }
}
