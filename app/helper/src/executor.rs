//! Bridge lifecycle behind a trait (ticket R002-F4), so request handling
//! (`request.rs`) can be unit-tested against a mock instead of shelling out.
//!
//! The real implementation shells out to `/sbin/ifconfig`. It is the ONLY
//! place in this crate that constructs an `ifconfig` command line, and it is
//! hardcoded to [`ipauro_proto::helper::BRIDGE_NAME`] — the request enum
//! carries no interface name field (see `ipauro-proto`'s `helper` module
//! docs), so by construction no other interface can ever reach an exec call
//! here.

use anyhow::{bail, Context, Result};
use ipauro_proto::helper::BRIDGE_NAME;
use ipauro_proto::state::BridgeInfo;
use std::process::Command;

/// The three bridge operations the helper exposes over XPC. Real impl below;
/// tests use a mock (see `request.rs`'s tests).
pub trait BridgeExecutor: Send + Sync {
    fn create(&self) -> Result<()>;
    fn destroy(&self) -> Result<()>;
    fn status(&self) -> Result<Option<BridgeInfo>>;
}

const IFCONFIG: &str = "/sbin/ifconfig";

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
}

fn run(args: &[&str]) -> Result<std::process::Output> {
    log::debug!("+ {IFCONFIG} {}", args.join(" "));
    let output = Command::new(IFCONFIG)
        .args(args)
        .output()
        .with_context(|| format!("spawning {IFCONFIG} {args:?}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{IFCONFIG} {args:?} failed: {}", stderr.trim());
    }
    Ok(output)
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
fn classify_ifconfig_output(success: bool, stdout: &str, stderr: &str) -> Result<Option<BridgeInfo>> {
    if !success {
        if stderr_indicates_absent(stderr) {
            return Ok(None);
        }
        bail!("ifconfig {BRIDGE_NAME} failed: {}", stderr.trim());
    }
    Ok(Some(parse_bridge_status(stdout)))
}

/// Parse `ifconfig bridge90`'s stdout into a [`BridgeInfo`]. Only called once
/// the caller already knows the bridge exists (nonzero exit is handled by
/// [`classify_ifconfig_output`] before this is reached).
fn parse_bridge_status(stdout: &str) -> BridgeInfo {
    let mut members = Vec::new();
    let mut ipv4 = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("member: ") {
            if let Some(name) = rest.split_whitespace().next() {
                members.push(name.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("inet ") {
            // deliberately NOT "inet6" — the space after "inet" excludes it
            if let Some(addr) = rest.split_whitespace().next() {
                ipv4 = Some(addr.to_string());
            }
        }
    }
    BridgeInfo { name: BRIDGE_NAME.to_string(), members, ipv4 }
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
        let stdout = "bridge90: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500\n\tstatus: active\n";
        let info = classify_ifconfig_output(true, stdout, "").unwrap().unwrap();
        assert!(info.members.is_empty());
        assert!(info.ipv4.is_none());
    }
}
