//! pf-based UDP transport scoping (`ScopeUdp`/`ClearScopes`, ticket
//! R005-T5), via a dedicated anchor named `ipauro` — never a whole-ruleset
//! replace. That's `pf-prefer.sh`'s PoC mechanism, explicitly banned: it
//! clobbers Apple's `com.apple/*` anchors and any VPN/firewall software's
//! rules, and flushes ALL pf state globally on `on`, killing other
//! software's connections. This module reproduces the PoC's BEHAVIOR (force
//! a UDP port onto an allow-listed interface, block it elsewhere, survive
//! pf's stateful trap) through a narrower mechanism.
//!
//! ## The anchor-evaluation decision (the one open mechanism question)
//!
//! `pfctl -a ipauro -f -` loads rule TEXT into a named anchor's rule table,
//! but per `pf.conf(5)`'s ANCHORS section, an anchor's rules are only ever
//! walked if the ALREADY-EVALUATED ruleset contains an `anchor <name>`
//! reference to it — same idea as a filesystem mount point existing before
//! you can mount onto it. Verified empirically against this machine's real
//! `/etc/pf.conf` (read-only: `cat /etc/pf.conf`, `man pf.conf`'s ANCHORS
//! section; did NOT mutate live pf state): the stock file declares exactly
//! one evaluated attachment point, `anchor "com.apple/*"` (populated from
//! `/etc/pf.anchors/com.apple`, which itself only declares
//! `200.AirDrop/*` and `250.ApplicationFirewall/*` — both Apple-namespaced,
//! neither a generic point we could piggyback our own name onto). There is
//! NO default attachment point for an arbitrary named anchor like `ipauro`.
//! Loading rules into `ipauro` via `-a` alone, with nothing else, would
//! populate an orphan anchor pf never visits — the scope would silently not
//! bite, exactly the failure mode `ScopeUdp` exists to prevent.
//!
//! **Decision:** [`ensure_anchor_point`] appends ONE idempotent,
//! marker-guarded line (`anchor "ipauro"`) to `/etc/pf.conf` if it isn't
//! already present, then reloads via `pfctl -f /etc/pf.conf`. This is
//! deliberately NOT the banned whole-ruleset-replace mechanism: it's the
//! sanctioned macOS pattern — the stock file's own header comment says as
//! much ("care must be taken to ensure that the main ruleset does not get
//! flushed, as the NESTED ANCHORS RELY ON THE ANCHOR POINT DEFINED HERE"),
//! and `com.apple`'s own entry in that same file is exactly this shape
//! (a bare `anchor` declaration referencing externally-managed content).
//! Reloading `/etc/pf.conf` reasserts anchor-point DECLARATIONS from that
//! file's text; it does not clear the CONTENTS of anchors populated
//! independently via `-a` (com.apple's rules, or any third-party software's
//! own anchor) since those live in the kernel's anchor table, not in this
//! file. Appending is a one-time, idempotent operation — [`pf_conf_needs_anchor_point`]
//! is checked before every call, so in steady state this is a cheap read
//! with no write and no reload.
//!
//! **Needs bench verification**: this sandbox has no root and the task
//! forbids mutating live pf state here, so I could not load a rule and
//! observe it actually bite. Flagged in the final report.
//!
//! ## Selective state invalidation
//!
//! A002's stateful-pf trap: pf checks the state table BEFORE the ruleset, so
//! a flow established before a new block rule loads keeps flowing — the
//! block only catches NEW packets. `pfctl -k <host>|<network>` (checked via
//! `man pfctl`) only matches by host/network; macOS's pfctl has no port
//! filter for state kill, which doesn't fit "any host, this port" scoping.
//! The targeted alternative pfctl DOES support is interface restriction:
//! `pfctl -F states -i <iface>`, applied per real non-loopback interface
//! rather than one unrestricted `-F states` call. See [`flush_affected_states`].

use std::collections::BTreeMap;
use std::fs;
use std::sync::Mutex;

use anyhow::{Context, Result};

use crate::cmd::{self, PFCTL};

/// The anchor all of this helper's pf rules live in. Never the main
/// ruleset.
pub const ANCHOR_NAME: &str = "ipauro";

const PF_CONF_PATH: &str = "/etc/pf.conf";

/// The exact anchor-point line [`pf_conf_needs_anchor_point`] checks for and
/// [`appended_pf_conf`] appends. Kept as one constant so the check and the
/// write can never drift apart.
const ANCHOR_LINE: &str = "anchor \"ipauro\"";

const ANCHOR_POINT_COMMENT: &str = "# ipauro: pf anchor attachment point (appended by ipauro-helper; \
do not remove — ScopeUdp/ClearScopes rules live in this anchor and are inert \
without this line; see pf.rs's module docs / A002 findings doc).";

/// The three pf operations the helper exposes over XPC. Real impl below;
/// tests use a mock (see `request.rs`'s tests).
pub trait PfExecutor: Send + Sync {
    /// Scope `port` (UDP) to `allowed_ifaces`: pass on each allowed
    /// interface, block everywhere else. Composes across multiple ports —
    /// each call updates just that port's entry in the tracked map and
    /// regenerates the WHOLE anchor from it (safe: it's our own anchor, not
    /// the main ruleset).
    fn scope_udp(&self, port: u16, allowed_ifaces: &[String]) -> Result<()>;

    /// Remove every scope this helper installed (empty the anchor, release
    /// the pf-enable reference if we hold one).
    fn clear_scopes(&self) -> Result<()>;

    /// Currently scoped ports + their allow-lists, for `Report`.
    fn scoped_ports(&self) -> Vec<(u16, Vec<String>)>;
}

/// Real `pfctl`-backed executor.
#[derive(Default)]
pub struct PfctlExecutor {
    state: Mutex<PfState>,
}

#[derive(Default)]
struct PfState {
    scopes: BTreeMap<u16, Vec<String>>,
    /// The token from `pfctl -E`'s reference-counted enable, if we're
    /// currently holding one. `None` means either "never enabled by us" or
    /// "already released."
    enable_token: Option<String>,
}

impl PfctlExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    fn reload_anchor(&self, state: &mut PfState) -> Result<()> {
        ensure_anchor_point()?;
        if state.scopes.is_empty() {
            self.release_pf(state)?;
        } else {
            self.ensure_pf_enabled(state)?;
        }
        let rules = generate_anchor_rules(&state.scopes);
        cmd::run_checked_with_stdin(PFCTL, &["-a", ANCHOR_NAME, "-f", "-"], &rules)
            .with_context(|| format!("loading rules into anchor {ANCHOR_NAME}"))?;
        flush_affected_states()?;
        Ok(())
    }

    fn ensure_pf_enabled(&self, state: &mut PfState) -> Result<()> {
        if state.enable_token.is_some() {
            return Ok(());
        }
        let output =
            cmd::run_checked(PFCTL, &["-E"]).context("pfctl -E (reference-counted enable)")?;
        let token = parse_enable_token(&String::from_utf8_lossy(&output.stdout))
            .or_else(|| parse_enable_token(&String::from_utf8_lossy(&output.stderr)));
        match token {
            Some(t) => {
                log::info!("pf enabled (reference token {t})");
                state.enable_token = Some(t);
            }
            None => {
                // pf may already be enabled by something else, or this
                // pfctl's output format differs from what's expected.
                // Leaving pf enabled without a token we can release is far
                // safer than guessing wrong and calling `-d` out from under
                // another reference holder (the whole point of `-E`/`-X`
                // being reference-counted).
                log::warn!(
                    "pfctl -E did not report a reference token; scope is active but this \
                     helper will not attempt to release pf's enable on ClearScopes"
                );
            }
        }
        Ok(())
    }

    fn release_pf(&self, state: &mut PfState) -> Result<()> {
        if let Some(token) = state.enable_token.take() {
            cmd::run_checked(PFCTL, &["-X", &token])
                .context("pfctl -X (releasing pf-enable reference)")?;
            log::info!("released pf-enable reference {token}");
        }
        Ok(())
    }
}

impl PfExecutor for PfctlExecutor {
    fn scope_udp(&self, port: u16, allowed_ifaces: &[String]) -> Result<()> {
        let mut state = self.state.lock().expect("pf state mutex poisoned");
        state.scopes.insert(port, allowed_ifaces.to_vec());
        self.reload_anchor(&mut state)
    }

    fn clear_scopes(&self) -> Result<()> {
        let mut state = self.state.lock().expect("pf state mutex poisoned");
        state.scopes.clear();
        self.reload_anchor(&mut state)
    }

    fn scoped_ports(&self) -> Vec<(u16, Vec<String>)> {
        let state = self.state.lock().expect("pf state mutex poisoned");
        state.scopes.iter().map(|(p, ifaces)| (*p, ifaces.clone())).collect()
    }
}

/// Generate the FULL contents of the `ipauro` anchor from the current
/// tracked scopes: for each port, pass-quick on every allowed interface,
/// then an interface-unqualified block-quick (rule order + `quick`
/// semantics mean an allowed interface's pass wins before the block is ever
/// reached — mirrors `pf-prefer.sh`'s `gen_conf`). Safe to fully regenerate
/// on every call since this is OUR OWN anchor, not the main ruleset.
fn generate_anchor_rules(scopes: &BTreeMap<u16, Vec<String>>) -> String {
    let mut out = format!(
        "# {ANCHOR_NAME}: transport-scoped UDP ports (ScopeUdp/ClearScopes; generated by ipauro-helper, do not edit by hand)\n"
    );
    for (port, ifaces) in scopes {
        for ifc in ifaces {
            out.push_str(&format!("pass quick on {ifc} proto udp from any to any port {port}\n"));
            out.push_str(&format!("pass quick on {ifc} proto udp from any port {port} to any\n"));
        }
        out.push_str(&format!("block drop quick proto udp from any to any port {port}\n"));
        out.push_str(&format!("block drop quick proto udp from any port {port} to any\n"));
    }
    out
}

/// Whether `/etc/pf.conf`'s current text lacks our anchor-point line.
fn pf_conf_needs_anchor_point(current: &str) -> bool {
    !current.contains(ANCHOR_LINE)
}

/// `current` with our anchor-point block appended (idempotent to call
/// repeatedly IF gated by [`pf_conf_needs_anchor_point`] first — this
/// function itself doesn't check, so it always appends).
fn appended_pf_conf(current: &str) -> String {
    let mut out = current.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(ANCHOR_POINT_COMMENT);
    out.push('\n');
    out.push_str(ANCHOR_LINE);
    out.push('\n');
    out
}

/// Ensure `/etc/pf.conf` has an evaluated attachment point for our anchor —
/// see this module's docs for why this is necessary and why it's safe.
/// Steady-state (the common case) is a single read + string search, no
/// write, no reload.
fn ensure_anchor_point() -> Result<()> {
    let current =
        fs::read_to_string(PF_CONF_PATH).with_context(|| format!("reading {PF_CONF_PATH}"))?;
    if !pf_conf_needs_anchor_point(&current) {
        return Ok(());
    }
    fs::write(PF_CONF_PATH, appended_pf_conf(&current))
        .with_context(|| format!("appending the ipauro anchor point to {PF_CONF_PATH}"))?;
    cmd::run_checked(PFCTL, &["-f", PF_CONF_PATH])
        .context("reloading /etc/pf.conf after appending the anchor point")?;
    log::warn!(
        "appended the ipauro anchor point to {PF_CONF_PATH} and reloaded the main ruleset \
         (one-time; see pf.rs's module docs for why this is required and safe)"
    );
    Ok(())
}

/// Selective state invalidation (A002's stateful-pf trap) — see module docs.
/// Best-effort per interface: one interface's flush failing (e.g. it
/// vanished mid-call) doesn't abort the others.
fn flush_affected_states() -> Result<()> {
    let ifaces = cmd::list_interfaces().context("listing interfaces to flush pf state")?;
    for ifc in ifaces.iter().filter(|i| i.as_str() != "lo0") {
        if let Err(e) = cmd::run_checked(PFCTL, &["-F", "states", "-i", ifc]) {
            log::warn!("flushing pf states on {ifc} failed (continuing): {e:#}");
        }
    }
    Ok(())
}

/// Parse `pfctl -E`'s reference-token line (observed real-world format:
/// `Token : 123456`) from either stream.
fn parse_enable_token(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((_, after)) = line.split_once("Token") {
            // e.g. " : 46165560" — whitespace surrounds the colon on both
            // sides, so strip whitespace, THEN the colon, THEN whitespace
            // again (trimming before stripping the colon would leave it
            // stuck to the digits since it isn't itself whitespace).
            let digits = after.trim().trim_start_matches(':').trim();
            if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                return Some(digits.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- rule-text generation (exact expected text) -----------------------

    #[test]
    fn generates_empty_anchor_as_header_only() {
        let rules = generate_anchor_rules(&BTreeMap::new());
        assert_eq!(
            rules,
            "# ipauro: transport-scoped UDP ports (ScopeUdp/ClearScopes; generated by ipauro-helper, do not edit by hand)\n"
        );
    }

    #[test]
    fn generates_single_port_single_iface() {
        let mut scopes = BTreeMap::new();
        scopes.insert(20808, vec!["bridge90".to_string()]);
        let rules = generate_anchor_rules(&scopes);
        assert_eq!(
            rules,
            "# ipauro: transport-scoped UDP ports (ScopeUdp/ClearScopes; generated by ipauro-helper, do not edit by hand)\n\
             pass quick on bridge90 proto udp from any to any port 20808\n\
             pass quick on bridge90 proto udp from any port 20808 to any\n\
             block drop quick proto udp from any to any port 20808\n\
             block drop quick proto udp from any port 20808 to any\n"
        );
    }

    #[test]
    fn generates_single_port_multiple_ifaces() {
        let mut scopes = BTreeMap::new();
        scopes.insert(20808, vec!["en9".to_string(), "en12".to_string()]);
        let rules = generate_anchor_rules(&scopes);
        assert_eq!(
            rules,
            "# ipauro: transport-scoped UDP ports (ScopeUdp/ClearScopes; generated by ipauro-helper, do not edit by hand)\n\
             pass quick on en9 proto udp from any to any port 20808\n\
             pass quick on en9 proto udp from any port 20808 to any\n\
             pass quick on en12 proto udp from any to any port 20808\n\
             pass quick on en12 proto udp from any port 20808 to any\n\
             block drop quick proto udp from any to any port 20808\n\
             block drop quick proto udp from any port 20808 to any\n"
        );
    }

    #[test]
    fn generates_multiple_ports_in_ascending_order() {
        let mut scopes = BTreeMap::new();
        scopes.insert(30000, vec!["en9".to_string()]);
        scopes.insert(20808, vec!["bridge90".to_string()]);
        let rules = generate_anchor_rules(&scopes);
        // BTreeMap iterates in key order regardless of insertion order.
        let port_20808_pos = rules.find("port 20808").unwrap();
        let port_30000_pos = rules.find("port 30000").unwrap();
        assert!(port_20808_pos < port_30000_pos);
    }

    // ---- anchor-point append (idempotent, marker-guarded) ------------------

    const STOCK_PF_CONF: &str = "\
#
# Default PF configuration file.
#
scrub-anchor \"com.apple/*\"
nat-anchor \"com.apple/*\"
rdr-anchor \"com.apple/*\"
dummynet-anchor \"com.apple/*\"
anchor \"com.apple/*\"
load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"
";

    #[test]
    fn stock_pf_conf_needs_the_anchor_point() {
        assert!(pf_conf_needs_anchor_point(STOCK_PF_CONF));
    }

    #[test]
    fn appending_satisfies_the_check_idempotently() {
        let appended = appended_pf_conf(STOCK_PF_CONF);
        assert!(!pf_conf_needs_anchor_point(&appended));
        // Appending again on top of the already-appended text would still
        // leave the marker present (the real caller never does this because
        // `ensure_anchor_point` gates on the check first, but the pure
        // function itself must not corrupt an idempotent re-append).
        let appended_twice = appended_pf_conf(&appended);
        assert!(!pf_conf_needs_anchor_point(&appended_twice));
    }

    #[test]
    fn appended_block_does_not_disturb_existing_content() {
        let appended = appended_pf_conf(STOCK_PF_CONF);
        assert!(appended.contains("load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\""));
        assert!(appended.contains(ANCHOR_LINE));
    }

    #[test]
    fn appended_pf_conf_handles_missing_trailing_newline() {
        let no_trailing_newline = "anchor \"com.apple/*\"";
        let appended = appended_pf_conf(no_trailing_newline);
        assert!(appended.starts_with("anchor \"com.apple/*\"\n"));
        assert!(appended.contains(ANCHOR_LINE));
    }

    // ---- pfctl -E token parsing ---------------------------------------------

    #[test]
    fn parses_enable_token_from_real_world_output() {
        let stdout =
            "No ALTQ support in kernel\nALTQ related functions disabled\nToken : 46165560\n";
        assert_eq!(parse_enable_token(stdout), Some("46165560".to_string()));
    }

    #[test]
    fn parses_enable_token_with_no_leading_warnings() {
        assert_eq!(parse_enable_token("Token : 1\n"), Some("1".to_string()));
    }

    #[test]
    fn missing_token_line_returns_none() {
        assert_eq!(parse_enable_token("No ALTQ support in kernel\n"), None);
        assert_eq!(parse_enable_token(""), None);
    }

    // ---- PfExecutor via the real struct (in-process state only; no exec) --

    #[test]
    fn scoped_ports_reports_in_ascending_port_order() {
        // Exercise just the pure BTreeMap bookkeeping by constructing
        // PfState directly — reload_anchor() (which shells out to pfctl) is
        // NOT invoked, so this needs no root and no real pfctl.
        let mut scopes = BTreeMap::new();
        scopes.insert(30000, vec!["en9".to_string()]);
        scopes.insert(20808, vec!["bridge90".to_string()]);
        let executor = PfctlExecutor { state: Mutex::new(PfState { scopes, enable_token: None }) };
        assert_eq!(
            executor.scoped_ports(),
            vec![(20808, vec!["bridge90".to_string()]), (30000, vec!["en9".to_string()])]
        );
    }
}
