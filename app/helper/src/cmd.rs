//! Shared subprocess-exec plumbing for the helper's `ifconfig`/`pfctl`
//! wrappers (`executor.rs`, `pf.rs`). One place that shells out and formats
//! errors, so both callers behave identically instead of drifting.

use std::io::Write;
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, bail};

/// `/sbin/ifconfig` — the single path both `executor.rs` (bridge) and this
/// module's [`list_interfaces`] use.
pub const IFCONFIG: &str = "/sbin/ifconfig";

/// `/sbin/pfctl` — used by `pf.rs` only, kept here for a single source of
/// truth on binary paths.
pub const PFCTL: &str = "/sbin/pfctl";

/// Run `program args...`, log the invocation at debug, and bail with stderr
/// on nonzero exit. Callers needing to distinguish a specific failure text
/// (e.g. ifconfig's "does not exist") should catch the `Result` and inspect
/// the message rather than pre-filtering here.
pub fn run_checked(program: &str, args: &[&str]) -> Result<Output> {
    log::debug!("+ {program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("spawning {program} {args:?}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{program} {args:?} failed: {}", stderr.trim());
    }
    Ok(output)
}

/// Like [`run_checked`], but pipes `stdin_text` to the child's standard
/// input — needed for `pfctl -f -` / `pfctl -a <anchor> -f -`, which read
/// the ruleset from stdin rather than a file argument (R005-T5: the helper
/// generates rule TEXT, never a file path or shell interpolation).
pub fn run_checked_with_stdin(program: &str, args: &[&str], stdin_text: &str) -> Result<Output> {
    log::debug!("+ {program} {} <<< ({} bytes on stdin)", args.join(" "), stdin_text.len());
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program} {args:?}"))?;
    child
        .stdin
        .take()
        .expect("Stdio::piped() guarantees a handle")
        .write_all(stdin_text.as_bytes())
        .with_context(|| format!("writing stdin to {program} {args:?}"))?;
    let output =
        child.wait_with_output().with_context(|| format!("waiting for {program} {args:?}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{program} {args:?} failed: {}", stderr.trim());
    }
    Ok(output)
}

/// List every network interface name currently known to the system
/// (`ifconfig -l`). Used to validate that a caller-supplied interface name
/// (bridge member or pf scope target) is real before any exec touches it —
/// per `ipauro-proto`'s `helper` module docs, interface names are the first
/// attacker-aimable strings on the XPC channel.
pub fn list_interfaces() -> Result<Vec<String>> {
    let output = run_checked(IFCONFIG, &["-l"])?;
    Ok(parse_interface_list(&String::from_utf8_lossy(&output.stdout)))
}

/// Pure parse of `ifconfig -l`'s stdout (a single space-separated line of
/// interface names) into a list. Split out for unit testing without a
/// process spawn.
pub fn parse_interface_list(stdout: &str) -> Vec<String> {
    stdout.split_whitespace().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interface_list() {
        let stdout = "lo0 en0 en1 bridge90 utun0\n";
        assert_eq!(parse_interface_list(stdout), vec!["lo0", "en0", "en1", "bridge90", "utun0"]);
    }

    #[test]
    fn parses_empty_interface_list() {
        assert!(parse_interface_list("").is_empty());
        assert!(parse_interface_list("\n").is_empty());
    }
}
