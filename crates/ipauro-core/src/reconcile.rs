//! The desired-state reconciler (`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)`
//! "Controller / desired-state reconciler" and ticket R005-F3: "idempotent +
//! ordered actual->desired passes"). Drives the FULL M1 data-plane pass —
//! bridge existence/membership, addressing, DHCP, and transport scope — from
//! one pure decision function ([`reconcile_plan`]) executed by an async loop
//! that also owns backoff-on-failure and the A001-mandated 15s poll backstop.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ipauro_proto::defaults;
use ipauro_proto::helper::{BRIDGE_NAME, DataPlaneReport, HelperRequest, HelperResponse};
use ipauro_proto::ipc::{ErrorCode, ErrorInfo, ReplyOutcome};
use ipauro_proto::registry;
use ipauro_proto::state::{BridgeInfo, Snapshot};
use tokio::sync::{broadcast, Notify};

use crate::discovery::UsbNcmSource;
use crate::helper_channel::HelperChannel;
use crate::state_store::StateStore;

/// Backstop poll cadence when nothing has kicked the loop awake — A001's "15s
/// poll backstop regardless", independent of whichever fast-path mechanism
/// `watch.rs` uses to notice USB changes sooner. This is the ONE place that
/// guarantees a pass happens at least this often no matter what.
const POLL_INTERVAL: Duration = Duration::from_secs(15);
/// First retry delay after a failed drive attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Cap on the doubling backoff so a persistently-failing helper doesn't push
/// retries out arbitrarily far.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub(crate) fn err(code: ErrorCode, message: impl Into<String>) -> ReplyOutcome {
    ReplyOutcome::Err { error: ErrorInfo { code, message: message.into() } }
}

/// What the reconciler drives toward. `bridge_up` mirrors the wire-visible
/// `Snapshot.bridge.desired_up`; `scope_enabled` is `SetTransportScope`'s
/// flag, which is deliberately snapshot-ADJACENT rather than wire-visible —
/// `ipauro-proto` is manager-owned and its `TransportState` only carries
/// OBSERVED status (`link_scoped`/`dhcp_serving`), never a request. See
/// `StateStore::desired_scope_enabled` and this milestone's report (a
/// candidate future proto addition, not implemented here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Desired {
    pub bridge_up: bool,
    pub scope_enabled: bool,
}

/// Pure decision: (desired, discovered USB-NCM members, last known helper
/// report) → the ordered `HelperRequest`s needed to move actual toward
/// desired. Split out from the async executor so the ordering rules are
/// unit-testable without a runtime or a mock helper (ticket R005-F3).
///
/// **Ordering, `desired.bridge_up`** (the up pass):
/// 1. bridge exists + membership (`CreateBridge` if missing, then
///    `SetBridgeMembers`)
/// 2. bridge address (`SetBridgeAddress`)
/// 3. DHCP (`ServeDhcp`)
/// 4. transport scope (`ScopeUdp`), iff `scope_enabled`
///
/// A rebuild (bridge currently missing in `report`) ALWAYS clears any stale
/// scope FIRST, even though step 4 may reapply it moments later — A002 §4's
/// live incident: a pf scope pinned to a now-dead bridge blocks the audio
/// port EVERYWHERE, so a scope must never outlive the bridge interface it
/// names, not even for one pass.
///
/// **Ordering, `!desired.bridge_up`** (reverse — A001: "scope teardown
/// FIRST"): `ClearScopes` → `StopDhcp` → `DestroyBridge`.
///
/// Every step is gated on `report` already showing it unsatisfied, so a
/// steady-state call (nothing changed) returns an empty plan — this function
/// is safe to call on every reconcile wake, not just on detected drift, and a
/// membership change while up (replug) re-runs it idempotently.
pub fn reconcile_plan(desired: Desired, discovered: &[String], report: &DataPlaneReport) -> Vec<HelperRequest> {
    if !desired.bridge_up {
        let mut plan = Vec::new();
        if !report.scoped_ports.is_empty() {
            plan.push(HelperRequest::ClearScopes);
        }
        if report.dhcp_serving {
            plan.push(HelperRequest::StopDhcp);
        }
        if report.bridge.is_some() {
            plan.push(HelperRequest::DestroyBridge);
        }
        return plan;
    }

    let mut plan = Vec::new();
    let bridge_missing = report.bridge.is_none();
    // Simulated forward: tracks scope state AS IF the plan built so far had
    // already executed, so the trailing scope-enable/disable check below
    // never double-clears what the rebuild pre-step already cleared.
    let mut scope_active = link_is_scoped(report);

    if bridge_missing {
        if !report.scoped_ports.is_empty() {
            plan.push(HelperRequest::ClearScopes);
            scope_active = false;
        }
        plan.push(HelperRequest::CreateBridge);
    }

    let mut want_members = discovered.to_vec();
    want_members.sort();
    let mut have_members = report.bridge.as_ref().map(|b| b.members.clone()).unwrap_or_default();
    have_members.sort();
    if bridge_missing || have_members != want_members {
        plan.push(HelperRequest::SetBridgeMembers { members: discovered.to_vec() });
    }

    if bridge_missing || !bridge_address_matches(report.bridge.as_ref(), defaults::BRIDGE_IPV4) {
        plan.push(HelperRequest::SetBridgeAddress {
            ipv4: defaults::BRIDGE_IPV4,
            prefix: defaults::BRIDGE_PREFIX,
        });
    }

    if bridge_missing || !report.dhcp_serving {
        plan.push(HelperRequest::ServeDhcp {
            pool_start: defaults::DHCP_POOL_START,
            pool_end: defaults::DHCP_POOL_END,
            netmask: prefix_to_netmask(defaults::BRIDGE_PREFIX),
        });
    }

    if desired.scope_enabled {
        if bridge_missing || !scope_active {
            plan.push(HelperRequest::ScopeUdp {
                port: registry::LINK.udp_ports[0],
                allowed_ifaces: vec![BRIDGE_NAME.to_string()],
            });
        }
    } else if scope_active {
        plan.push(HelperRequest::ClearScopes);
    }

    plan
}

/// Whether `registry::LINK`'s port is currently scoped to the bridge, per a
/// helper `Report`. M1 ships exactly one registry entry, so "any scoped port"
/// and "Link's port is scoped" coincide today; this checks the specific
/// port+iface anyway so the logic stays correct once R004-F1 lands more
/// protocols and `ClearScopes`-flushes-everything stops being a safe proxy.
fn link_is_scoped(report: &DataPlaneReport) -> bool {
    report
        .scoped_ports
        .iter()
        .any(|(port, ifaces)| *port == registry::LINK.udp_ports[0] && ifaces.iter().any(|i| i == BRIDGE_NAME))
}

fn bridge_address_matches(info: Option<&BridgeInfo>, want: Ipv4Addr) -> bool {
    info.and_then(|b| b.ipv4.as_deref()) == Some(want.to_string().as_str())
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    // Guard the shift explicitly: `1u32 << 32` (prefix == 0) is UB in Rust.
    let bits: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
    Ipv4Addr::from(bits)
}

/// Discovers, fetches the helper's current [`DataPlaneReport`], computes one
/// [`reconcile_plan`], executes it in order, and — only if the plan wasn't
/// empty — refreshes the store from a fresh report afterward. Shared by the
/// command path (`commands.rs`, which reflects the result in its reply) and
/// `run`'s loop below. The returned `bool` is whether the plan actually ran
/// anything; `run` uses that to decide whether an immediate follow-up pass is
/// worth kicking (see `run`'s doc comment).
pub(crate) async fn drive_once(
    store: &StateStore,
    helper: &dyn HelperChannel,
    usb_source: &dyn UsbNcmSource,
) -> Result<(Snapshot, bool), ReplyOutcome> {
    let discovered =
        usb_source.discover().map_err(|e| err(ErrorCode::Internal, format!("USB discovery failed: {e}")))?;

    let report = fetch_report(helper).await?;
    let snapshot = store.snapshot().await;
    let desired =
        Desired { bridge_up: snapshot.bridge.desired_up, scope_enabled: store.desired_scope_enabled() };

    let plan = reconcile_plan(desired, &discovered, &report);
    let ran = !plan.is_empty();
    for verb in plan {
        execute_verb(helper, verb).await?;
    }

    let report = if ran { fetch_report(helper).await? } else { report };
    Ok((apply_report(store, report).await, ran))
}

/// Folds a [`DataPlaneReport`] into the store's wire-visible `bridge.actual`
/// and `transport` fields — the "refresh snapshot from Report after each
/// pass" step.
async fn apply_report(store: &StateStore, report: DataPlaneReport) -> Snapshot {
    let link_scoped = link_is_scoped(&report);
    let dhcp_serving = report.dhcp_serving;
    let bridge = report.bridge;
    let scope_desired = store.desired_scope_enabled();
    store
        .mutate(|s| {
            s.bridge.actual = bridge;
            s.transport.link_scope_desired = scope_desired;
            s.transport.link_scoped = link_scoped;
            s.transport.dhcp_serving = dhcp_serving;
        })
        .await
}

/// Executes one planned verb, per the pairing contract in
/// `ipauro_proto::helper`: `Ok` or `Bridge` are both success (the bridge-info
/// payload isn't folded in here — the pass's trailing `fetch_report` is the
/// single source of refreshed truth); `Err` is a rejection; anything else is a
/// protocol violation this caller reports as internal (Enum Variant
/// Discipline: every `HelperResponse` variant handled by name).
async fn execute_verb(helper: &dyn HelperChannel, verb: HelperRequest) -> Result<(), ReplyOutcome> {
    match helper.request(verb.clone()).await {
        Err(e) => Err(err(ErrorCode::HelperNotConnected, e.to_string())),
        Ok(HelperResponse::Ok) => Ok(()),
        Ok(HelperResponse::Bridge { .. }) => Ok(()),
        Ok(HelperResponse::Err { message }) => Err(err(ErrorCode::HelperRejected, message)),
        Ok(HelperResponse::Pong { .. }) => {
            Err(err(ErrorCode::Internal, format!("helper answered {verb:?} with Pong")))
        }
        Ok(HelperResponse::Report { .. }) => {
            Err(err(ErrorCode::Internal, format!("helper answered {verb:?} with Report")))
        }
    }
}

async fn fetch_report(helper: &dyn HelperChannel) -> Result<DataPlaneReport, ReplyOutcome> {
    match helper.request(HelperRequest::Report).await {
        Err(e) => Err(err(ErrorCode::HelperNotConnected, e.to_string())),
        Ok(HelperResponse::Report { report }) => Ok(report),
        Ok(HelperResponse::Err { message }) => Err(err(ErrorCode::HelperRejected, message)),
        Ok(HelperResponse::Ok) => Err(err(ErrorCode::Internal, "helper answered Report with Ok")),
        Ok(HelperResponse::Bridge { .. }) => {
            Err(err(ErrorCode::Internal, "helper answered Report with Bridge"))
        }
        Ok(HelperResponse::Pong { .. }) => Err(err(ErrorCode::Internal, "helper answered Report with Pong")),
    }
}

/// Capped exponential backoff, doubling each failed retry.
pub fn next_backoff(current: Duration) -> Duration {
    std::cmp::min(current * 2, MAX_BACKOFF)
}

/// Background task. Wakes on `kick` (a command, `watch::run` noticing a USB
/// change, or this loop's own follow-up below), its own poll interval, or
/// shutdown.
pub async fn run(
    store: Arc<StateStore>,
    helper: Arc<dyn HelperChannel>,
    usb_source: Arc<dyn UsbNcmSource>,
    kick: Arc<Notify>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        tokio::select! {
            _ = shutdown.recv() => return,
            _ = kick.notified() => {}
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }

        match drive_once(&store, helper.as_ref(), usb_source.as_ref()).await {
            Ok((_snapshot, ran)) => {
                backoff = INITIAL_BACKOFF;
                if ran {
                    // The pass changed something — re-verify promptly instead
                    // of waiting for the next external kick or the 15s
                    // backstop. This is what turns a single "shrink
                    // membership" step into the full A002 §4 rebuild when a
                    // member removal destroys the whole bridge out from under
                    // us: the NEXT pass sees `report.bridge = None` and
                    // rebuilds everything, in order. Converges in a small,
                    // bounded number of passes because every step is itself
                    // idempotent (a pass that truly changed nothing further
                    // returns an empty plan and stops re-kicking).
                    kick.notify_one();
                }
            }
            Err(outcome) => {
                log::warn!("reconcile attempt failed ({outcome:?}), retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
                kick.notify_one();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report() -> DataPlaneReport {
        DataPlaneReport { bridge: None, scoped_ports: Vec::new(), dhcp_serving: false }
    }

    fn full_report(members: &[&str]) -> DataPlaneReport {
        DataPlaneReport {
            bridge: Some(BridgeInfo {
                name: BRIDGE_NAME.to_string(),
                members: members.iter().map(|m| m.to_string()).collect(),
                ipv4: Some(defaults::BRIDGE_IPV4.to_string()),
                prefix: None,
            }),
            scoped_ports: vec![(registry::LINK.udp_ports[0], vec![BRIDGE_NAME.to_string()])],
            dhcp_serving: true,
        }
    }

    fn strs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn steady_state_up_needs_no_action() {
        let report = full_report(&["en9", "en12"]);
        let plan =
            reconcile_plan(Desired { bridge_up: true, scope_enabled: true }, &strs(&["en9", "en12"]), &report);
        assert_eq!(plan, Vec::new());
    }

    #[test]
    fn steady_state_down_needs_no_action() {
        let plan = reconcile_plan(Desired { bridge_up: false, scope_enabled: false }, &[], &empty_report());
        assert_eq!(plan, Vec::new());
    }

    #[test]
    fn cold_start_creates_full_ordered_pass_without_scope() {
        let plan =
            reconcile_plan(Desired { bridge_up: true, scope_enabled: false }, &strs(&["en9", "en12"]), &empty_report());
        assert_eq!(
            plan,
            vec![
                HelperRequest::CreateBridge,
                HelperRequest::SetBridgeMembers { members: strs(&["en9", "en12"]) },
                HelperRequest::SetBridgeAddress { ipv4: defaults::BRIDGE_IPV4, prefix: defaults::BRIDGE_PREFIX },
                HelperRequest::ServeDhcp {
                    pool_start: defaults::DHCP_POOL_START,
                    pool_end: defaults::DHCP_POOL_END,
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                },
            ]
        );
    }

    #[test]
    fn cold_start_with_scope_enabled_appends_scope_last() {
        let plan =
            reconcile_plan(Desired { bridge_up: true, scope_enabled: true }, &strs(&["en9"]), &empty_report());
        assert_eq!(
            plan.last(),
            Some(&HelperRequest::ScopeUdp {
                port: registry::LINK.udp_ports[0],
                allowed_ifaces: vec![BRIDGE_NAME.to_string()],
            })
        );
        assert_eq!(plan.first(), Some(&HelperRequest::CreateBridge));
    }

    #[test]
    fn membership_drift_while_bridge_present_only_updates_members() {
        // Bridge already exists with the right address/dhcp/scope; only the
        // member set drifted (a replug added/removed a peer without the
        // kernel destroying the bridge — the non-blast-radius case).
        let report = full_report(&["en9", "en12"]);
        let plan = reconcile_plan(Desired { bridge_up: true, scope_enabled: true }, &strs(&["en9"]), &report);
        assert_eq!(plan, vec![HelperRequest::SetBridgeMembers { members: strs(&["en9"]) }]);
    }

    #[test]
    fn stale_scope_is_cleared_before_rebuild_then_scope_is_reapplied() {
        // Bridge is gone (report.bridge = None) but a scope naming the dead
        // bridge is still active — the A002 §4 trap this ordering exists for.
        let mut report = empty_report();
        report.scoped_ports = vec![(registry::LINK.udp_ports[0], vec![BRIDGE_NAME.to_string()])];

        let plan = reconcile_plan(Desired { bridge_up: true, scope_enabled: true }, &strs(&["en9"]), &report);
        assert_eq!(
            plan,
            vec![
                HelperRequest::ClearScopes,
                HelperRequest::CreateBridge,
                HelperRequest::SetBridgeMembers { members: strs(&["en9"]) },
                HelperRequest::SetBridgeAddress { ipv4: defaults::BRIDGE_IPV4, prefix: defaults::BRIDGE_PREFIX },
                HelperRequest::ServeDhcp {
                    pool_start: defaults::DHCP_POOL_START,
                    pool_end: defaults::DHCP_POOL_END,
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                },
                HelperRequest::ScopeUdp {
                    port: registry::LINK.udp_ports[0],
                    allowed_ifaces: vec![BRIDGE_NAME.to_string()],
                },
            ],
            "ClearScopes must precede CreateBridge, and (since scope is still \
             desired) ScopeUdp must reappear at the end rather than being \
             skipped as already-satisfied"
        );
    }

    #[test]
    fn stale_scope_cleared_before_rebuild_and_not_reapplied_if_no_longer_desired() {
        let mut report = empty_report();
        report.scoped_ports = vec![(registry::LINK.udp_ports[0], vec![BRIDGE_NAME.to_string()])];

        let plan = reconcile_plan(Desired { bridge_up: true, scope_enabled: false }, &strs(&["en9"]), &report);
        // Exactly one ClearScopes (the rebuild pre-step) — the trailing
        // enable/disable check must not double-clear.
        assert_eq!(plan.iter().filter(|v| matches!(v, HelperRequest::ClearScopes)).count(), 1);
        assert_eq!(plan.first(), Some(&HelperRequest::ClearScopes));
        assert!(!plan.contains(&HelperRequest::ScopeUdp {
            port: registry::LINK.udp_ports[0],
            allowed_ifaces: vec![BRIDGE_NAME.to_string()],
        }));
    }

    #[test]
    fn disabling_scope_while_up_and_unchanged_otherwise_just_clears_it() {
        let report = full_report(&["en9"]);
        let plan = reconcile_plan(Desired { bridge_up: true, scope_enabled: false }, &strs(&["en9"]), &report);
        assert_eq!(plan, vec![HelperRequest::ClearScopes]);
    }

    #[test]
    fn desired_down_full_reverse_teardown_order() {
        let report = full_report(&["en9", "en12"]);
        let plan = reconcile_plan(Desired { bridge_up: false, scope_enabled: false }, &[], &report);
        assert_eq!(
            plan,
            vec![HelperRequest::ClearScopes, HelperRequest::StopDhcp, HelperRequest::DestroyBridge]
        );
    }

    #[test]
    fn desired_down_only_tears_down_what_is_actually_present() {
        let report = DataPlaneReport {
            bridge: Some(BridgeInfo { name: BRIDGE_NAME.to_string(), members: vec![], ipv4: None, prefix: None }),
            scoped_ports: Vec::new(),
            dhcp_serving: false,
        };
        let plan = reconcile_plan(Desired { bridge_up: false, scope_enabled: false }, &[], &report);
        assert_eq!(plan, vec![HelperRequest::DestroyBridge]);
    }

    /// The M-incident, at the pure decision-function level: pass 1 sees the
    /// detach as a plain membership shrink (bridge still reportedly present);
    /// pass 2 sees the mock's/macOS's blast radius (bridge now entirely gone)
    /// and issues the full ordered rebuild. `reconcile::run`'s self-kick
    /// (see `run`'s doc) is what drives pass 2 automatically in practice; the
    /// full async version of this scenario is `tests/m_incident.rs`.
    #[test]
    fn m_incident_two_pass_sequence_at_the_pure_fn_level() {
        let desired = Desired { bridge_up: true, scope_enabled: true };

        let steady = full_report(&["en9", "en12"]);
        let pass1 = reconcile_plan(desired, &strs(&["en9"]), &steady);
        assert_eq!(pass1, vec![HelperRequest::SetBridgeMembers { members: strs(&["en9"]) }]);

        // macOS's real (and the mock's simulated) blast radius: the WHOLE
        // bridge disappears, including its scope entry (pf state referencing
        // an interface that no longer exists doesn't clean itself up).
        let mut blasted = empty_report();
        blasted.scoped_ports = steady.scoped_ports.clone();
        let pass2 = reconcile_plan(desired, &strs(&["en9"]), &blasted);
        assert_eq!(
            pass2,
            vec![
                HelperRequest::ClearScopes,
                HelperRequest::CreateBridge,
                HelperRequest::SetBridgeMembers { members: strs(&["en9"]) },
                HelperRequest::SetBridgeAddress { ipv4: defaults::BRIDGE_IPV4, prefix: defaults::BRIDGE_PREFIX },
                HelperRequest::ServeDhcp {
                    pool_start: defaults::DHCP_POOL_START,
                    pool_end: defaults::DHCP_POOL_END,
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                },
                HelperRequest::ScopeUdp {
                    port: registry::LINK.udp_ports[0],
                    allowed_ifaces: vec![BRIDGE_NAME.to_string()],
                },
            ]
        );
    }

    #[test]
    fn prefix_to_netmask_common_prefixes() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut backoff = INITIAL_BACKOFF;
        for _ in 0..10 {
            backoff = next_backoff(backoff);
            assert!(backoff <= MAX_BACKOFF);
        }
        assert_eq!(backoff, MAX_BACKOFF);
    }

    #[test]
    fn backoff_starts_below_cap() {
        assert_eq!(next_backoff(INITIAL_BACKOFF), INITIAL_BACKOFF * 2);
    }
}
