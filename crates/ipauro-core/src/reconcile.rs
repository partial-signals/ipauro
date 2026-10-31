//! The desired-state reconciler (`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)`
//! "Controller / desired-state reconciler" and ticket R005-F3: "idempotent +
//! ordered actual->desired passes"). Drives the FULL M1 data-plane pass —
//! bridge existence/membership, addressing, DHCP, and transport scope — from
//! one pure decision function ([`reconcile_plan`]) executed by an async loop
//! that also owns backoff-on-failure and the A001-mandated 15s poll backstop.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use ipauro_proto::defaults;
use ipauro_proto::helper::{BRIDGE_NAME, DataPlaneReport, HelperRequest, HelperResponse};
use ipauro_proto::ipc::{ErrorCode, ErrorInfo, ReplyOutcome};
use ipauro_proto::registry;
use ipauro_proto::state::{BridgeInfo, NodeRole, Snapshot};
use tokio::sync::{broadcast, Notify};

use crate::addressing::PrimaryAddrs;
use crate::discovery::{identify, UsbNcmSource};
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
    ReplyOutcome::Err { error: error_info(code, message) }
}

fn error_info(code: ErrorCode, message: impl Into<String>) -> ErrorInfo {
    ErrorInfo { code, message: message.into() }
}

/// The independently-convergeable parts of the data plane.
///
/// M1 field verification (R005-T10 finding 3) hit the cost of not having
/// this: a `ServeDhcp` the helper refused aborted the whole pass, so the
/// transport scope — which needs nothing whatsoever from DHCP — was left
/// unapplied for as long as the DHCP problem persisted. A pass now attempts
/// every step whose prerequisites still hold and reports what didn't
/// converge, instead of stopping at the first refusal.
///
/// The facet a verb belongs to answers "what did this failure invalidate";
/// [`blocked_by`] answers the converse, "what must have worked for this verb
/// to be worth attempting".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Facet {
    /// The bridge interface itself: existence, membership, address.
    Bridge,
    /// The in-process DHCP responder.
    Dhcp,
    /// pf transport scoping.
    Scope,
    /// Mesh aliases on an uplink interface (R003-B10): the Peer's address,
    /// and the stripping of a Hub-to-be's soon-to-be-member interfaces. Kept
    /// apart from [`Facet::Bridge`] so an unplugged or refused uplink doesn't
    /// read as a bridge failure.
    Uplink,
}

/// Which facet a verb converges. Every [`HelperRequest`] variant by name (no
/// catch-all) per the house rule on enum discipline.
fn facet(verb: &HelperRequest) -> Facet {
    match verb {
        HelperRequest::CreateBridge
        | HelperRequest::DestroyBridge
        | HelperRequest::SetBridgeMembers { .. }
        | HelperRequest::SetBridgeAddress { .. } => Facet::Bridge,
        HelperRequest::AddAlias { iface, .. } | HelperRequest::RemoveAlias { iface, .. } => {
            if iface == BRIDGE_NAME { Facet::Bridge } else { Facet::Uplink }
        }
        HelperRequest::ServeDhcp { .. } | HelperRequest::StopDhcp => Facet::Dhcp,
        HelperRequest::ScopeUdp { .. } | HelperRequest::ClearScopes => Facet::Scope,
        // Read-only verbs are never planned — `reconcile_plan` only ever
        // emits mutations, and the pass's `Report`s are issued outside the
        // plan loop. Classified with the bridge so an unexpected one can't
        // silently gate anything narrower.
        HelperRequest::Ping | HelperRequest::Status | HelperRequest::Report => Facet::Bridge,
    }
}

/// Facets whose failure EARLIER IN THE SAME PASS makes `verb` futile or
/// unsafe to attempt.
///
/// Two rules, both load-bearing:
/// - Everything that names the bridge interface needs the bridge step to have
///   worked. The helper rejects `ScopeUdp`/`ServeDhcp` naming a `bridge90`
///   that doesn't exist anyway, so attempting them buys nothing but a second
///   error.
/// - `DestroyBridge` needs the scope teardown to have worked. A pf scope
///   naming a bridge that just vanished does not stop blocking — it blocks
///   that port EVERYWHERE (A002 §4, the live incident). Tearing the bridge
///   down under a scope we failed to clear turns one failed step into a
///   host-wide audio outage, so this is a skip for SAFETY, not futility.
fn blocked_by(verb: &HelperRequest) -> &'static [Facet] {
    match verb {
        HelperRequest::SetBridgeMembers { .. }
        | HelperRequest::SetBridgeAddress { .. }
        | HelperRequest::ServeDhcp { .. }
        | HelperRequest::ScopeUdp { .. } => &[Facet::Bridge],
        // An alias add — on the bridge OR an uplink — needs the bridge step to
        // have worked: on the bridge because it must exist; on an uplink
        // because a Hub->Peer flip adds only after `DestroyBridge` freed the
        // member, and a bridge that failed to go away still holds it (the
        // helper would refuse a member as an uplink).
        HelperRequest::AddAlias { .. } => &[Facet::Bridge],
        HelperRequest::DestroyBridge => &[Facet::Scope],
        // Nothing has to have succeeded for these: `CreateBridge` opens the
        // up-pass, and both teardown verbs are safe to attempt regardless.
        HelperRequest::CreateBridge
        | HelperRequest::ClearScopes
        | HelperRequest::RemoveAlias { .. }
        | HelperRequest::StopDhcp
        | HelperRequest::Ping
        | HelperRequest::Status
        | HelperRequest::Report => &[],
    }
}

/// Display name for a verb, for operator-facing failure summaries. Naming
/// only — nothing branches on it (see the house rule against type-name
/// dispatch); behavior keys on [`facet`]/[`blocked_by`].
fn verb_name(verb: &HelperRequest) -> &'static str {
    match verb {
        HelperRequest::Ping => "ping",
        HelperRequest::Status => "status",
        HelperRequest::CreateBridge => "create_bridge",
        HelperRequest::DestroyBridge => "destroy_bridge",
        HelperRequest::SetBridgeMembers { .. } => "set_bridge_members",
        HelperRequest::SetBridgeAddress { .. } => "set_bridge_address",
        HelperRequest::AddAlias { .. } => "add_alias",
        HelperRequest::RemoveAlias { .. } => "remove_alias",
        HelperRequest::ScopeUdp { .. } => "scope_udp",
        HelperRequest::ClearScopes => "clear_scopes",
        HelperRequest::ServeDhcp { .. } => "serve_dhcp",
        HelperRequest::StopDhcp => "stop_dhcp",
        HelperRequest::Report => "report",
    }
}

/// One planned step that did not converge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepFailure {
    /// Attempted; the helper refused it (or answered off-contract).
    Rejected { verb: HelperRequest, error: ErrorInfo },
    /// Never attempted — `blocked_by` failed earlier in this same pass.
    Skipped { verb: HelperRequest, blocked_by: Facet },
}

impl StepFailure {
    fn describe(&self) -> String {
        match self {
            Self::Rejected { verb, error } => {
                format!("{} rejected: {}", verb_name(verb), error.message)
            }
            Self::Skipped { verb, blocked_by } => {
                format!("{} skipped ({blocked_by:?} failed first)", verb_name(verb))
            }
        }
    }
}

/// The result of one reconcile pass.
///
/// A pass that failed *partway* is not the same thing as a pass that could
/// not run: `drive_once` returns `Err` only when nothing could be attempted
/// (discovery blew up, the helper channel is dead), and a `Pass` with
/// non-empty `failures` otherwise — carrying a snapshot refreshed from the
/// helper, so whatever DID converge is visible to every client immediately.
#[derive(Debug)]
pub(crate) struct Pass {
    pub snapshot: Snapshot,
    /// Whether the plan had anything in it (i.e. something was attempted).
    pub ran: bool,
    /// Steps that didn't converge. Empty = fully converged.
    pub failures: Vec<StepFailure>,
}

impl Pass {
    /// The reply this pass warrants — `None` when it fully converged.
    pub(crate) fn failure_outcome(&self) -> Option<ReplyOutcome> {
        if self.failures.is_empty() {
            return None;
        }
        Some(err(partial_failure_code(&self.failures), self.summary()))
    }

    /// Operator-facing one-liner naming every step that didn't converge.
    pub(crate) fn summary(&self) -> String {
        format!(
            "{} of the pass's steps did not converge: {}",
            self.failures.len(),
            self.failures.iter().map(StepFailure::describe).collect::<Vec<_>>().join("; ")
        )
    }
}

/// The code for a partially-converged pass: the first REJECTION's code (what
/// actually went wrong), since skips are only ever consequences of one.
fn partial_failure_code(failures: &[StepFailure]) -> ErrorCode {
    failures
        .iter()
        .find_map(|f| match f {
            StepFailure::Rejected { error, .. } => Some(error.code),
            StepFailure::Skipped { .. } => None,
        })
        .unwrap_or(ErrorCode::Internal)
}

/// What the reconciler drives toward. `bridge_up` mirrors the wire-visible
/// `Snapshot.bridge.desired_up`; `scope_enabled` is `SetTransportScope`'s
/// flag, which is deliberately snapshot-ADJACENT rather than wire-visible —
/// `ipauro-proto` is manager-owned and its `TransportState` only carries
/// OBSERVED status (`link_scoped`/`dhcp_serving`), never a request. See
/// `StateStore::desired_scope_enabled` and this milestone's report (a
/// candidate future proto addition, not implemented here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Desired<'a> {
    pub bridge_up: bool,
    pub scope_enabled: bool,
    /// This node's mesh-derived addresses (R003-T3); `None` = no mesh
    /// identity, in which case aliases are left untouched.
    pub primary: Option<PrimaryAddrs>,
    /// WHERE those addresses live (R003-B10). One address per node whatever
    /// its role — the address is the node's, not the interface's.
    pub site: AddrSite<'a>,
}

/// Where the node's primary mesh addresses are applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrSite<'a> {
    /// A Hub: aliases ride the bridge (R003-T3), planned in the up pass.
    Bridge,
    /// A Peer creates no bridge, so it self-applies on each of its uplink
    /// interfaces ([`crate::discovery::LinkInventory::uplinks`]). Only
    /// consulted on the `!bridge_up` branch — a Peer's `bridge_up` is always
    /// false (role gate in [`drive_once`]).
    Uplinks(&'a [String]),
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
/// 3. primary mesh addresses (`RemoveBridgeAlias` for stale ones FIRST, then
///    `AddBridgeAlias` for missing ones), iff `desired.primary`
/// 4. DHCP (`ServeDhcp`)
/// 5. transport scope (`ScopeUdp`), iff `scope_enabled`
///
/// A rebuild (bridge currently missing in `report`) ALWAYS clears any stale
/// scope FIRST, even though step 4 may reapply it moments later — A002 §4's
/// live incident: a pf scope pinned to a now-dead bridge blocks the audio
/// port EVERYWHERE, so a scope must never outlive the bridge interface it
/// names, not even for one pass.
///
/// **Ordering, `!desired.bridge_up`** (reverse — A001: "scope teardown
/// FIRST"): `ClearScopes` → `StopDhcp` → `RemoveBridgeAlias`* →
/// `DestroyBridge`.
///
/// Every step is gated on `report` already showing it unsatisfied, so a
/// steady-state call (nothing changed) returns an empty plan — this function
/// is safe to call on every reconcile wake, not just on detected drift, and a
/// membership change while up (replug) re-runs it idempotently.
pub fn reconcile_plan(desired: Desired<'_>, discovered: &[String], report: &DataPlaneReport) -> Vec<HelperRequest> {
    if !desired.bridge_up {
        let mut plan = Vec::new();
        if !report.scoped_ports.is_empty() {
            plan.push(HelperRequest::ClearScopes);
        }
        if report.dhcp_serving {
            plan.push(HelperRequest::StopDhcp);
        }
        if report.bridge.is_some() {
            plan.extend(report.bridge_aliases.iter().map(|&addr| HelperRequest::RemoveAlias {
                iface: BRIDGE_NAME.to_string(),
                addr,
            }));
            plan.push(HelperRequest::DestroyBridge);
        }
        // A Peer's address goes on its uplink(s). After the teardown above on
        // purpose (Hub -> Peer flip): the uplinks are bridge members until
        // `DestroyBridge` runs, and the helper refuses a member as an uplink.
        if let (Some(primary), AddrSite::Uplinks(uplinks)) = (desired.primary, desired.site) {
            plan.extend(uplink_alias_steps(&primary, uplinks, report));
        }
        return plan;
    }

    let mut plan = Vec::new();
    // Peer -> Hub flip: the interfaces about to be enslaved may still carry
    // the Peer's uplink aliases. Strip our own FIRST — once a member, the
    // address belongs on the bridge (A002 §4), and the helper no longer lists
    // (or lets us touch) a member as an uplink. The report only shows aliases
    // on non-members, so this is empty in steady state.
    if let Some(primary) = desired.primary {
        plan.extend(strip_owned_steps(&primary, discovered, report));
    }
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

    if let Some(primary) = desired.primary {
        // A rebuilt bridge starts with no aliases whatever a stale report says.
        let have: &[IpAddr] = if bridge_missing { &[] } else { &report.bridge_aliases };
        plan.extend(alias_steps(&primary, have));
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

/// Alias convergence: remove every alias on the bridge that is not wanted
/// (a collision re-hash moved us; the old address goes BEFORE the new one
/// arrives), then add the wanted ones not yet present. Already-converged =
/// empty, which is the idempotence replug relies on. Every non-primary,
/// non-link-local address on `bridge90` is ours by construction (the only
/// writer is `AddBridgeAlias`), so "not wanted" is safe to strip.
fn alias_steps(primary: &PrimaryAddrs, have: &[IpAddr]) -> Vec<HelperRequest> {
    let want = primary.addrs();
    let mut steps: Vec<HelperRequest> = have
        .iter()
        .filter(|a| !want.iter().any(|(w, _)| w == *a))
        .map(|&addr| HelperRequest::RemoveAlias { iface: BRIDGE_NAME.to_string(), addr })
        .collect();
    steps.extend(
        want.into_iter().filter(|(w, _)| !have.contains(w)).map(|(addr, prefix)| {
            HelperRequest::AddAlias { iface: BRIDGE_NAME.to_string(), addr, prefix }
        }),
    );
    steps
}

/// The helper's report of mesh-class aliases on `iface` (empty if none, or if
/// the interface is a bridge member / absent — the helper lists neither).
fn uplink_have<'r>(report: &'r DataPlaneReport, iface: &str) -> &'r [IpAddr] {
    report
        .uplink_aliases
        .iter()
        .find(|(name, _)| name == iface)
        .map(|(_, addrs)| addrs.as_slice())
        .unwrap_or(&[])
}

/// Peer addressing: on every uplink, strip OUR stale addresses (a collision
/// re-hash moved us — the old one goes BEFORE the new arrives), then add the
/// missing wanted ones. Unlike the bridge, an uplink carries the network's own
/// addresses too (the segment's DHCP lease, a user's static), so "stale" is
/// only what the plan OWNS ([`PrimaryAddrs::owns`]) and isn't wanted; the rest
/// is left alone. Converged = empty (replug idempotence); an unplugged uplink
/// is simply absent from `uplinks`, its aliases having gone with the interface.
fn uplink_alias_steps(primary: &PrimaryAddrs, uplinks: &[String], report: &DataPlaneReport) -> Vec<HelperRequest> {
    let want = primary.addrs();
    let mut steps = Vec::new();
    for iface in uplinks {
        let have = uplink_have(report, iface);
        steps.extend(
            have.iter()
                .filter(|a| primary.owns(**a) && !want.iter().any(|(w, _)| w == *a))
                .map(|&addr| HelperRequest::RemoveAlias { iface: iface.clone(), addr }),
        );
    }
    for iface in uplinks {
        let have = uplink_have(report, iface);
        steps.extend(want.iter().filter(|(w, _)| !have.contains(w)).map(|&(addr, prefix)| {
            HelperRequest::AddAlias { iface: iface.clone(), addr, prefix }
        }));
    }
    steps
}

/// `RemoveAlias` for every address the plan owns on each of `ifaces` — the
/// interfaces a Hub is about to enslave.
fn strip_owned_steps(primary: &PrimaryAddrs, ifaces: &[String], report: &DataPlaneReport) -> Vec<HelperRequest> {
    ifaces
        .iter()
        .flat_map(|iface| {
            uplink_have(report, iface)
                .iter()
                .filter(|a| primary.owns(**a))
                .map(move |&addr| HelperRequest::RemoveAlias { iface: iface.clone(), addr })
        })
        .collect()
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

/// Identifies, fetches the helper's current [`DataPlaneReport`], computes one
/// [`reconcile_plan`], executes it in order, and — only if the plan wasn't
/// empty — refreshes the store from a fresh report afterward. Shared by the
/// command path (`commands.rs`, which reflects the result in its reply) and
/// `run`'s loop below. [`Pass::ran`] is whether the plan actually had
/// anything in it; `run` uses that to decide whether an immediate follow-up
/// pass is worth kicking (see `run`'s doc comment).
///
/// **A refused step does not abort the pass** (R005-T10 finding 3). Each
/// planned verb is attempted unless a facet it [`blocked_by`] already failed
/// in this same pass; failures are collected into [`Pass::failures`] and the
/// store is still refreshed from a fresh report, so partial convergence is
/// both achieved and visible. The one exception is a channel-level failure
/// (`HelperNotConnected`): with no helper on the other end every remaining
/// verb fails identically and the trailing `Report` can't run either, so that
/// aborts the pass as before.
///
/// The identification step ([`identify`], ticket R005-F7) runs A002 §5's full
/// ranking — host IOKit provenance, device-side IOKit narrowed by link state,
/// and the traffic delta against the previous pass's observations — but only
/// [`crate::discovery::LinkInventory::bridge_members`] (host provenance) ever
/// reaches the plan. The device-side and traffic findings reach an operator
/// through the log line below; see `StateStore::links` for why they are not on
/// the wire snapshot.
pub(crate) async fn drive_once(
    store: &StateStore,
    helper: &dyn HelperChannel,
    usb_source: &Arc<dyn UsbNcmSource>,
) -> Result<Pass, ReplyOutcome> {
    let previous = store.last_observations();
    // `identify` spawns `ioreg` (which walks the whole IORegistry and can take
    // ~100ms), one `ifconfig` per candidate, and a `netstat` — all blocking.
    // This task shares a runtime with the IPC server, so it goes on the
    // blocking pool rather than stalling client replies behind a registry
    // walk. Same reasoning as `watch::run`'s `spawn_blocking`.
    let source = usb_source.clone();
    let identified = tokio::task::spawn_blocking(move || identify(source.as_ref(), &previous))
        .await
        .map_err(|e| err(ErrorCode::Internal, format!("USB discovery task panicked: {e}")))?;
    let (inventory, observations) =
        identified.map_err(|e| err(ErrorCode::Internal, format!("USB discovery failed: {e}")))?;
    let discovered = inventory.bridge_members();
    let uplinks = inventory.uplinks();
    if store.set_identification(inventory.clone(), observations) {
        log::info!("usb link identification: {}", inventory.summary());
    }

    let report = fetch_report(helper).await?;
    let snapshot = store.snapshot().await;
    let role = snapshot.mesh.role;
    let desired =
        Desired {
        // A Peer creates no bridge whatever the user asked of it (R003-F4);
        // `desired_up` is remembered, so Peer -> Hub resumes it.
        bridge_up: snapshot.bridge.desired_up && snapshot.mesh.role == NodeRole::Hub,
        scope_enabled: store.desired_scope_enabled(),
        primary: store.desired_primary(),
        // A Hub addresses its bridge; a Peer has none, so its uplinks (R003-B10).
        site: match role {
            NodeRole::Hub => AddrSite::Bridge,
            NodeRole::Peer => AddrSite::Uplinks(&uplinks),
        },
    };

    let plan = reconcile_plan(desired, &discovered, &report);
    let ran = !plan.is_empty();
    // A SUCCESSFUL `CreateBridge` in this pass means the interface apps bind
    // to is brand new even if it ends up looking identical in the report —
    // see `next_epoch`. A create that the helper refused must not bump the
    // epoch: nothing came into existence, and a spurious bump costs every
    // consumer a rebind (an audible dropout).
    let mut created = false;
    let mut failures: Vec<StepFailure> = Vec::new();
    let mut failed_facets: Vec<Facet> = Vec::new();

    for verb in plan {
        if let Some(&blocker) = blocked_by(&verb).iter().find(|f| failed_facets.contains(f)) {
            log::warn!(
                "reconcile: skipping {} — {blocker:?} failed earlier in this pass",
                verb_name(&verb)
            );
            failures.push(StepFailure::Skipped { verb, blocked_by: blocker });
            continue;
        }
        match execute_verb(helper, verb.clone()).await {
            Ok(()) => created |= verb == HelperRequest::CreateBridge,
            // Nothing is on the other end: every remaining verb — and the
            // trailing Report this pass needs to tell the truth afterward —
            // fails the same way. Abort rather than fabricate a report.
            Err(error) if error.code == ErrorCode::HelperNotConnected => {
                return Err(ReplyOutcome::Err { error });
            }
            Err(error) => {
                let facet = facet(&verb);
                log::warn!(
                    "reconcile: {} rejected ({}); {facet:?} stays unconverged — \
                     continuing with the rest of the pass",
                    verb_name(&verb),
                    error.message
                );
                if !failed_facets.contains(&facet) {
                    failed_facets.push(facet);
                }
                failures.push(StepFailure::Rejected { verb, error });
            }
        }
    }

    let report = if ran { fetch_report(helper).await? } else { report };
    let snapshot = apply_report(store, report, created).await;
    Ok(Pass { snapshot, ran, failures })
}

/// Folds a [`DataPlaneReport`] into the store's wire-visible `bridge.actual`
/// and `transport` fields — the "refresh snapshot from Report after each
/// pass" step — and advances `bridge.epoch` when this pass produced a bridge
/// apps must rebind to ([`next_epoch`]).
async fn apply_report(store: &StateStore, report: DataPlaneReport, created: bool) -> Snapshot {
    let link_scoped = link_is_scoped(&report);
    let dhcp_serving = report.dhcp_serving;
    store.set_dhcp_leases(report.dhcp_leases);
    let bridge = report.bridge;
    let scope_desired = store.desired_scope_enabled();
    store
        .mutate(|s| {
            s.bridge.epoch = next_epoch(s.bridge.epoch, s.bridge.actual.as_ref(), bridge.as_ref(), created);
            s.bridge.actual = bridge;
            s.transport.link_scope_desired = scope_desired;
            s.transport.link_scoped = link_scoped;
            s.transport.dhcp_serving = dhcp_serving;
        })
        .await
}

/// The rebind-relevant identity of a bridge: what an app's socket is actually
/// pinned to. Deliberately EXCLUDES the member set — adding or removing a USB
/// member does not move the interface an app is bound to, and a spurious
/// rebind costs an audible dropout.
fn rebind_identity(info: Option<&BridgeInfo>) -> Option<(&str, Option<&str>)> {
    info.map(|b| (b.name.as_str(), b.ipv4.as_deref()))
}

/// Pure rule for advancing `BridgeState::epoch` — A001's ordered-pass step 5
/// ("signal the audio app to rejoin the new bridge"), reduced to a number.
///
/// Bumps when the pass leaves a bridge in place that an app must (re)bind to:
///
/// - `created`: this pass issued `CreateBridge`, so the interface is fresh
///   regardless of how the report reads. This arm is load-bearing on its own:
///   in the A002 §4 blast-radius rebuild, the bridge comes back under the
///   SAME name with the SAME address, so identity alone shows no change
///   whenever the intermediate `bridge: None` never made it into the store
///   (destroy and rebuild landing inside one pass).
/// - identity change: name or address differs from what was stored — covers
///   re-addressing, and a bridge that appeared without us creating it (helper
///   restart, or a service that starts up next to an already-live bridge).
///
/// Does NOT bump when the bridge is gone (`next` is `None`): there is nothing
/// to bind to, and `bridge.actual = None` says so directly. The next build
/// bumps, so an app never sees the same epoch across a teardown/rebuild.
fn next_epoch(current: u64, prev: Option<&BridgeInfo>, next: Option<&BridgeInfo>, created: bool) -> u64 {
    if next.is_none() {
        return current;
    }
    if created || rebind_identity(prev) != rebind_identity(next) {
        return current + 1;
    }
    current
}

/// Executes one planned verb, per the pairing contract in
/// `ipauro_proto::helper`: `Ok` or `Bridge` are both success (the bridge-info
/// payload isn't folded in here — the pass's trailing `fetch_report` is the
/// single source of refreshed truth); `Err` is a rejection; anything else is a
/// protocol violation this caller reports as internal (Enum Variant
/// Discipline: every `HelperResponse` variant handled by name).
async fn execute_verb(helper: &dyn HelperChannel, verb: HelperRequest) -> Result<(), ErrorInfo> {
    match helper.request(verb.clone()).await {
        Err(e) => Err(error_info(ErrorCode::HelperNotConnected, e.to_string())),
        Ok(HelperResponse::Ok) => Ok(()),
        Ok(HelperResponse::Bridge { .. }) => Ok(()),
        Ok(HelperResponse::Err { message }) => Err(error_info(ErrorCode::HelperRejected, message)),
        Ok(HelperResponse::Pong { .. }) => {
            Err(error_info(ErrorCode::Internal, format!("helper answered {verb:?} with Pong")))
        }
        Ok(HelperResponse::Report { .. }) => {
            Err(error_info(ErrorCode::Internal, format!("helper answered {verb:?} with Report")))
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

        match drive_once(&store, helper.as_ref(), &usb_source).await {
            // Partial convergence: the steps that could run did, and the
            // store already reflects them. Retry the rest on the backoff
            // rather than the self-kick below — a helper that just refused a
            // step will refuse it again microseconds later.
            Ok(pass) if !pass.failures.is_empty() => {
                log::warn!("reconcile pass partially converged: {}", pass.summary());
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
                kick.notify_one();
            }
            Ok(pass) => {
                backoff = INITIAL_BACKOFF;
                if pass.ran {
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
        DataPlaneReport { bridge: None, scoped_ports: Vec::new(), dhcp_serving: false, bridge_aliases: Vec::new(), uplink_aliases: Vec::new(), dhcp_leases: Vec::new() }
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
            bridge_aliases: Vec::new(),
            uplink_aliases: Vec::new(),
            dhcp_leases: Vec::new(),
        }
    }

    fn strs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    // ---- primary mesh addresses (R003-T3) ----------------------------------

    fn primary(v4_last: u8) -> PrimaryAddrs {
        PrimaryAddrs {
            ula: "fd1b:5a70:a52::1".parse().unwrap(),
            ipv4: Some((Ipv4Addr::new(10, 42, 0, v4_last), 16)),
            owned: crate::addressing::Owned {
                ula48: [0xfd, 0x1b, 0x5a, 0x70, 0x0a, 0x52],
                v4_lo: Ipv4Addr::new(10, 42, 0, 1),
                v4_hi: Ipv4Addr::new(10, 42, 127, 255),
            },
        }
    }

    fn up_with(p: PrimaryAddrs) -> Desired<'static> {
        Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: Some(p) }
    }

    fn add(addr: &str, prefix: u8) -> HelperRequest {
        HelperRequest::AddAlias { iface: BRIDGE_NAME.to_string(), addr: addr.parse().unwrap(), prefix }
    }

    fn rm(addr: &str) -> HelperRequest {
        HelperRequest::RemoveAlias { iface: BRIDGE_NAME.to_string(), addr: addr.parse().unwrap() }
    }

    #[test]
    fn fresh_up_orders_bridge_then_address_then_aliases_then_dhcp() {
        let plan = reconcile_plan(up_with(primary(7)), &strs(&["en9"]), &empty_report());
        let pos = |v: &HelperRequest| plan.iter().position(|p| p == v).unwrap();
        let ula = add("fd1b:5a70:a52::1", 64);
        let v4 = add("10.42.0.7", 16);
        assert_eq!(plan.first(), Some(&HelperRequest::CreateBridge));
        let set_addr = plan.iter().position(|p| matches!(p, HelperRequest::SetBridgeAddress { .. })).unwrap();
        let dhcp = plan.iter().position(|p| matches!(p, HelperRequest::ServeDhcp { .. })).unwrap();
        assert!(set_addr < pos(&ula) && pos(&ula) < pos(&v4) && pos(&v4) < dhcp, "{plan:?}");
    }

    #[test]
    fn alias_steps_are_gated_on_the_bridge_facet() {
        assert_eq!(blocked_by(&add("fd00::1", 64)), &[Facet::Bridge]);
        assert!(blocked_by(&rm("fd00::1")).is_empty());
        assert_eq!(facet(&add("fd00::1", 64)), Facet::Bridge);
    }

    #[test]
    fn converged_aliases_are_a_no_op() {
        let mut report = full_report(&["en9"]);
        report.bridge_aliases = vec!["10.42.0.7".parse().unwrap(), "fd1b:5a70:a52::1".parse().unwrap()];
        let plan = reconcile_plan(up_with(primary(7)), &strs(&["en9"]), &report);
        assert_eq!(plan, Vec::new(), "re-applying the same address must plan nothing");
    }

    #[test]
    fn replug_rebuild_reapplies_the_same_addresses_despite_stale_report() {
        // Bridge gone (replug) but the last report still listed aliases: a
        // rebuilt bridge has none, so both are added again and nothing removed.
        let mut report = empty_report();
        report.bridge_aliases = vec!["10.42.0.7".parse().unwrap()];
        let plan = reconcile_plan(up_with(primary(7)), &strs(&["en9"]), &report);
        assert!(plan.contains(&add("fd1b:5a70:a52::1", 64)));
        assert!(plan.contains(&add("10.42.0.7", 16)));
        assert!(!plan.iter().any(|p| matches!(p, HelperRequest::RemoveAlias { .. })));
    }

    #[test]
    fn rehash_removes_the_old_address_before_adding_the_new() {
        let mut report = full_report(&["en9"]);
        report.bridge_aliases = vec!["fd1b:5a70:a52::1".parse().unwrap(), "10.42.0.7".parse().unwrap()];
        let plan = reconcile_plan(up_with(primary(9)), &strs(&["en9"]), &report);
        assert_eq!(plan, vec![rm("10.42.0.7"), add("10.42.0.9", 16)]);
    }

    #[test]
    fn teardown_removes_aliases_after_dhcp_before_destroy() {
        let mut report = full_report(&["en9"]);
        report.bridge_aliases = vec!["fd1b:5a70:a52::1".parse().unwrap(), "10.42.0.7".parse().unwrap()];
        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: false, scope_enabled: false, primary: None }, &[], &report);
        assert_eq!(
            plan,
            vec![
                HelperRequest::ClearScopes,
                HelperRequest::StopDhcp,
                rm("fd1b:5a70:a52::1"),
                rm("10.42.0.7"),
                HelperRequest::DestroyBridge,
            ]
        );
    }

    #[test]
    fn no_mesh_identity_leaves_aliases_alone() {
        let mut report = full_report(&["en9"]);
        report.bridge_aliases = vec!["10.42.0.7".parse().unwrap()];
        let plan = reconcile_plan(
            Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: None },
            &strs(&["en9"]),
            &report,
        );
        assert_eq!(plan, Vec::new());
    }

    #[test]
    fn store_feeds_desired_primary_from_the_member_seam() {
        use crate::addressing::MeshAddressing;
        use ipauro_mesh::addressing::UlaPrefix;
        use ipauro_mesh::ids::NodeId;
        let store = StateStore::new(crate::initial_snapshot());
        assert_eq!(store.desired_primary(), None, "no identity, no addresses");
        let me = NodeId([1, 2, 3, 4, 5, 6, 7, 8]);
        store.set_mesh_addressing(MeshAddressing::appliance(me, UlaPrefix::DEFAULT).unwrap());
        let alone = store.desired_primary().unwrap();
        store.set_mesh_members((0..30).map(|i| NodeId([i, 9, 9, 9, 9, 9, 9, 9])).collect());
        let crowded = store.desired_primary().unwrap();
        assert_eq!(alone.ula, crowded.ula, "ULA never depends on membership");
    }

    #[test]
    fn steady_state_up_needs_no_action() {
        let report = full_report(&["en9", "en12"]);
        let plan =
            reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: None }, &strs(&["en9", "en12"]), &report);
        assert_eq!(plan, Vec::new());
    }

    #[test]
    fn steady_state_down_needs_no_action() {
        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: false, scope_enabled: false, primary: None }, &[], &empty_report());
        assert_eq!(plan, Vec::new());
    }

    #[test]
    fn cold_start_creates_full_ordered_pass_without_scope() {
        let plan =
            reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: false, primary: None }, &strs(&["en9", "en12"]), &empty_report());
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
            reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: None }, &strs(&["en9"]), &empty_report());
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
        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: None }, &strs(&["en9"]), &report);
        assert_eq!(plan, vec![HelperRequest::SetBridgeMembers { members: strs(&["en9"]) }]);
    }

    #[test]
    fn stale_scope_is_cleared_before_rebuild_then_scope_is_reapplied() {
        // Bridge is gone (report.bridge = None) but a scope naming the dead
        // bridge is still active — the A002 §4 trap this ordering exists for.
        let mut report = empty_report();
        report.scoped_ports = vec![(registry::LINK.udp_ports[0], vec![BRIDGE_NAME.to_string()])];

        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: None }, &strs(&["en9"]), &report);
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

        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: false, primary: None }, &strs(&["en9"]), &report);
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
        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: false, primary: None }, &strs(&["en9"]), &report);
        assert_eq!(plan, vec![HelperRequest::ClearScopes]);
    }

    #[test]
    fn desired_down_full_reverse_teardown_order() {
        let report = full_report(&["en9", "en12"]);
        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: false, scope_enabled: false, primary: None }, &[], &report);
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
            bridge_aliases: Vec::new(),
            uplink_aliases: Vec::new(),
            dhcp_leases: Vec::new(),
        };
        let plan = reconcile_plan(Desired { site: AddrSite::Bridge, bridge_up: false, scope_enabled: false, primary: None }, &[], &report);
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
        let desired = Desired { site: AddrSite::Bridge, bridge_up: true, scope_enabled: true, primary: None };

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

    fn info(ipv4: Option<&str>, members: &[&str]) -> BridgeInfo {
        BridgeInfo {
            name: BRIDGE_NAME.to_string(),
            members: members.iter().map(|m| m.to_string()).collect(),
            ipv4: ipv4.map(|s| s.to_string()),
            prefix: None,
        }
    }

    #[test]
    fn epoch_bumps_on_first_build() {
        assert_eq!(next_epoch(0, None, Some(&info(Some("10.69.0.1"), &["en9"])), true), 1);
    }

    #[test]
    fn epoch_holds_in_steady_state() {
        let now = info(Some("10.69.0.1"), &["en9", "en12"]);
        assert_eq!(next_epoch(3, Some(&now), Some(&now), false), 3);
    }

    #[test]
    fn epoch_holds_across_a_membership_only_change() {
        // The A002 §4 NON-blast-radius case: a member left, the interface an
        // app is bound to did not. Bumping here would cost a needless rebind
        // (an audible dropout) on every peer plug/unplug.
        let before = info(Some("10.69.0.1"), &["en9", "en12"]);
        let after = info(Some("10.69.0.1"), &["en9"]);
        assert_eq!(next_epoch(3, Some(&before), Some(&after), false), 3);
    }

    #[test]
    fn epoch_bumps_when_the_bridge_is_re_addressed() {
        let before = info(Some("10.69.0.1"), &["en9"]);
        let after = info(Some("10.69.0.2"), &["en9"]);
        assert_eq!(next_epoch(3, Some(&before), Some(&after), false), 4);
    }

    #[test]
    fn epoch_holds_on_teardown_then_bumps_on_the_next_build() {
        let up = info(Some("10.69.0.1"), &["en9"]);
        let after_teardown = next_epoch(3, Some(&up), None, false);
        assert_eq!(after_teardown, 3, "nothing to bind to — no rebind is due");
        assert_eq!(next_epoch(after_teardown, None, Some(&up), true), 4);
    }

    #[test]
    fn epoch_bumps_on_an_identical_rebuild_within_one_pass() {
        // The trap `created` exists for: the blast-radius destroy AND the
        // rebuild both land inside one pass, so the store never observed the
        // intermediate `None` and the before/after reports are byte-identical
        // — yet the ifindex changed and every bound socket is dead.
        let same = info(Some("10.69.0.1"), &["en9"]);
        assert_eq!(next_epoch(7, Some(&same), Some(&same), true), 8);
    }

    #[test]
    fn epoch_bumps_for_a_bridge_that_appeared_without_us_creating_it() {
        // Service starts up next to an already-live bridge (or the helper
        // rebuilt on its own): no CreateBridge in our plan, but an app bound
        // to whatever came before must still rebind.
        assert_eq!(next_epoch(0, None, Some(&info(Some("10.69.0.1"), &["en9"])), false), 1);
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

    // ---- continue-on-error (R005-T10 finding 3) ------------------------------

    fn serve_dhcp() -> HelperRequest {
        HelperRequest::ServeDhcp {
            pool_start: defaults::DHCP_POOL_START,
            pool_end: defaults::DHCP_POOL_END,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
        }
    }

    fn scope_udp() -> HelperRequest {
        HelperRequest::ScopeUdp {
            port: registry::LINK.udp_ports[0],
            allowed_ifaces: vec![BRIDGE_NAME.to_string()],
        }
    }

    #[test]
    fn dhcp_needs_the_bridge_but_scope_never_needs_dhcp() {
        // The exact field shape: DHCP failing must not gate the scope.
        assert_eq!(blocked_by(&serve_dhcp()), &[Facet::Bridge]);
        assert_eq!(blocked_by(&scope_udp()), &[Facet::Bridge]);
        assert!(!blocked_by(&scope_udp()).contains(&Facet::Dhcp));
        assert_eq!(facet(&serve_dhcp()), Facet::Dhcp);
        assert_eq!(facet(&scope_udp()), Facet::Scope);
    }

    #[test]
    fn destroying_the_bridge_is_gated_on_the_scope_teardown() {
        // A002 §4: a scope naming a bridge that just vanished blocks the port
        // EVERYWHERE. Never tear the bridge down under a scope we couldn't
        // clear.
        assert_eq!(blocked_by(&HelperRequest::DestroyBridge), &[Facet::Scope]);
        assert!(blocked_by(&HelperRequest::ClearScopes).is_empty());
        assert!(blocked_by(&HelperRequest::StopDhcp).is_empty());
        assert!(blocked_by(&HelperRequest::CreateBridge).is_empty());
    }

    #[test]
    fn a_partial_pass_reports_the_rejection_code_not_a_skip() {
        let failures = vec![
            StepFailure::Rejected {
                verb: serve_dhcp(),
                error: error_info(ErrorCode::HelperRejected, "bootpd holds :67"),
            },
            StepFailure::Skipped { verb: scope_udp(), blocked_by: Facet::Bridge },
        ];
        assert_eq!(partial_failure_code(&failures), ErrorCode::HelperRejected);
        let pass = Pass { snapshot: crate::initial_snapshot(), ran: true, failures };
        let summary = pass.summary();
        assert!(summary.contains("serve_dhcp rejected: bootpd holds :67"), "{summary}");
        assert!(summary.contains("scope_udp skipped"), "{summary}");
        assert!(pass.failure_outcome().is_some());
    }

    #[test]
    fn a_fully_converged_pass_has_no_failure_reply() {
        let pass = Pass { snapshot: crate::initial_snapshot(), ran: true, failures: Vec::new() };
        assert!(pass.failure_outcome().is_none());
    }

    // ---- continue-on-error, end to end through a mock helper -----------------

    use crate::discovery::MockUsbNcmSource;
    use crate::helper_channel::MockHelper;

    fn source(members: &[&str]) -> Arc<dyn UsbNcmSource> {
        Arc::new(MockUsbNcmSource::new([strs(members)]))
    }

    async fn store_desiring(up: bool, scope: bool) -> StateStore {
        let store = StateStore::new(crate::initial_snapshot());
        store.mutate(|s| s.bridge.desired_up = up).await;
        store.set_desired_scope_enabled(scope);
        store
    }

    async fn store_with_mesh(role: NodeRole) -> StateStore {
        use crate::addressing::MeshAddressing;
        use ipauro_mesh::addressing::UlaPrefix;
        use ipauro_mesh::ids::NodeId;
        let store = store_desiring(true, false).await;
        store.set_mesh_addressing(
            MeshAddressing::appliance(NodeId([1, 2, 3, 4, 5, 6, 7, 8]), UlaPrefix::DEFAULT).unwrap(),
        );
        store.mutate(|s| s.mesh.role = role).await;
        store
    }

    #[tokio::test]
    async fn a_peer_creates_no_bridge_even_when_the_user_asked_for_one() {
        let store = store_with_mesh(NodeRole::Peer).await;
        let helper = MockHelper::new();
        let pass = drive_once(&store, &helper, &source(&["en9"])).await.expect("pass ran");
        assert!(!helper.requests().contains(&HelperRequest::CreateBridge), "{:?}", helper.requests());
        assert!(pass.snapshot.bridge.actual.is_none());
        assert!(pass.snapshot.bridge.desired_up, "the user's bridge wish is remembered");
    }

    #[tokio::test]
    async fn hub_to_peer_tears_down_aliases_before_the_bridge_and_peer_to_hub_rebuilds() {
        let store = store_with_mesh(NodeRole::Hub).await;
        let helper = MockHelper::new();
        let up = drive_once(&store, &helper, &source(&["en9"])).await.expect("up pass");
        assert!(up.snapshot.bridge.actual.is_some());
        let aliases_up =
            helper.requests().iter().filter(|r| matches!(r, HelperRequest::AddAlias { .. })).count();
        assert_eq!(aliases_up, 2, "ULA + hashed IPv4 applied");

        // Hub -> Peer. en9 is the cable this node reaches the hub through:
        // once the bridge is gone it is a plain uplink, and now carries the
        // address the bridge used to.
        helper.plug_uplink("en9").await;
        store.mutate(|s| s.mesh.role = NodeRole::Peer).await;
        let before = helper.requests().len();
        let down = drive_once(&store, &helper, &source(&["en9"])).await.expect("teardown pass");
        assert!(down.snapshot.bridge.actual.is_none());
        let reqs = helper.requests()[before..].to_vec();
        let last_rm = reqs.iter().rposition(|r| matches!(r, HelperRequest::RemoveAlias { .. })).unwrap();
        let destroy = reqs.iter().position(|r| *r == HelperRequest::DestroyBridge).unwrap();
        assert!(last_rm < destroy, "aliases go before the bridge: {reqs:?}");
        assert!(down.failures.is_empty(), "{:?}", down.failures);
        let first_uplink_add = reqs
            .iter()
            .position(|r| matches!(r, HelperRequest::AddAlias { iface, .. } if iface == "en9"))
            .expect("the peer addresses its uplink in the same pass");
        assert!(destroy < first_uplink_add, "uplink add only after the member is freed: {reqs:?}");
        assert_eq!(helper.aliases_on("en9").await.len(), 2, "ULA + IPv4 on the uplink");
        assert!(helper.aliases_on(BRIDGE_NAME).await.is_empty());

        // Peer -> Hub: the remembered wish rebuilds it, same addresses — and
        // the uplink's copy is stripped BEFORE en9 is enslaved.
        store.mutate(|s| s.mesh.role = NodeRole::Hub).await;
        let before = helper.requests().len();
        let again = drive_once(&store, &helper, &source(&["en9"])).await.expect("rebuild pass");
        assert!(again.snapshot.bridge.actual.is_some());
        let reqs = helper.requests()[before..].to_vec();
        let strip = reqs
            .iter()
            .rposition(|r| matches!(r, HelperRequest::RemoveAlias { iface, .. } if iface == "en9"))
            .expect("uplink aliases stripped on peer -> hub");
        let enslave = reqs.iter().position(|r| matches!(r, HelperRequest::SetBridgeMembers { .. })).unwrap();
        assert!(strip < enslave, "strip before enslave: {reqs:?}");
        assert!(again.failures.is_empty(), "{:?}", again.failures);
        assert!(helper.aliases_on("en9").await.is_empty());
        assert_eq!(helper.aliases_on(BRIDGE_NAME).await.len(), 2, "same two addresses, back on the bridge");
    }

    #[tokio::test]
    async fn member_set_change_re_resolves_this_nodes_ipv4() {
        use ipauro_mesh::ids::NodeId;
        let store = store_with_mesh(NodeRole::Hub).await;
        let alone = store.desired_primary().unwrap();
        // Find a crowd that forces this node off its salt-0 slot: any set where
        // a lower NodeId hashes to the same slot. Scan single peers until the
        // address moves (the hash range has 32k slots, so scan widely).
        let mut moved = None;
        for i in 0u32..200_000 {
            let peer = NodeId([0, 0, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0, 0, 1]);
            store.set_mesh_members([peer].into());
            let with = store.desired_primary().unwrap();
            if with.ipv4 != alone.ipv4 {
                moved = Some((peer, with));
                break;
            }
        }
        let (peer, with) = moved.expect("some lower-id peer collides with this node");
        assert_ne!(with.ipv4, alone.ipv4);
        assert_eq!(with.ula, alone.ula);
        // The peer leaves: resolution returns to the original, deterministically.
        store.set_mesh_members(Default::default());
        assert_eq!(store.desired_primary().unwrap(), alone);
        let _ = peer;
    }

    #[tokio::test]
    async fn a_refused_dhcp_step_does_not_cost_us_the_transport_scope() {
        // THE field finding, reproduced: bootpd holds :67, so ServeDhcp is
        // refused — and the pf scope, which needs nothing from DHCP, must
        // still land.
        let store = store_desiring(true, true).await;
        let helper = MockHelper::new();
        helper.reject(serve_dhcp());

        let pass = drive_once(&store, &helper, &source(&["en9"])).await.expect("pass ran");

        assert!(helper.requests().contains(&scope_udp()), "the scope must still be attempted");
        assert_eq!(pass.failures.len(), 1, "only DHCP failed: {:?}", pass.failures);
        assert!(matches!(pass.failures[0], StepFailure::Rejected { .. }));
        assert!(pass.snapshot.transport.link_scoped, "the snapshot must show what DID converge");
        assert!(!pass.snapshot.transport.dhcp_serving);
        assert!(pass.snapshot.bridge.actual.is_some());
    }

    #[tokio::test]
    async fn a_refused_bridge_step_skips_everything_that_needs_the_bridge() {
        let store = store_desiring(true, true).await;
        let helper = MockHelper::new();
        helper.reject(HelperRequest::CreateBridge);

        let pass = drive_once(&store, &helper, &source(&["en9"])).await.expect("pass ran");

        assert!(!helper.requests().contains(&serve_dhcp()), "futile without a bridge");
        assert!(!helper.requests().contains(&scope_udp()), "futile without a bridge");
        // 1 rejection (create) + 4 skips (members, address, dhcp, scope).
        assert_eq!(pass.failures.len(), 5, "{:?}", pass.failures);
        assert_eq!(
            pass.failures.iter().filter(|f| matches!(f, StepFailure::Skipped { .. })).count(),
            4
        );
        assert_eq!(pass.snapshot.bridge.epoch, 0, "a create that failed must not bump the epoch");
    }

    #[tokio::test]
    async fn a_refused_scope_teardown_leaves_the_bridge_standing() {
        // Safety skip: destroying the bridge under a live scope would block
        // Link's port on every interface on the host.
        let store = store_desiring(true, true).await;
        let helper = MockHelper::new();
        drive_once(&store, &helper, &source(&["en9"])).await.expect("bring it up");

        helper.reject(HelperRequest::ClearScopes);
        store.mutate(|s| s.bridge.desired_up = false).await;
        store.set_desired_scope_enabled(false);

        let pass = drive_once(&store, &helper, &source(&["en9"])).await.expect("pass ran");

        assert!(
            !helper.requests().contains(&HelperRequest::DestroyBridge),
            "never destroy a bridge a live scope still names"
        );
        assert!(
            helper.requests().contains(&HelperRequest::StopDhcp),
            "stopping DHCP needs nothing from the scope and must still run"
        );
        assert!(pass.snapshot.bridge.actual.is_some());
        assert_eq!(pass.failures.len(), 2, "1 rejection + 1 safety skip: {:?}", pass.failures);
    }

    #[tokio::test]
    async fn a_dead_channel_still_aborts_the_pass() {
        // Continue-on-error is for a helper that REFUSES a step, not for one
        // that isn't there: every remaining verb would fail identically.
        let store = store_desiring(true, true).await;
        let outcome = drive_once(&store, &crate::helper_channel::NullHelper, &source(&["en9"]))
            .await
            .expect_err("no helper, no pass");
        match outcome {
            ReplyOutcome::Err { error } => assert_eq!(error.code, ErrorCode::HelperNotConnected),
            ReplyOutcome::Ok { .. } => panic!("expected an error outcome"),
        }
    }

    #[tokio::test]
    async fn a_fully_converged_pass_reports_no_failures() {
        let store = store_desiring(true, true).await;
        let helper = MockHelper::new();
        let pass = drive_once(&store, &helper, &source(&["en9"])).await.expect("pass ran");
        assert!(pass.failures.is_empty(), "{:?}", pass.failures);
        assert!(pass.ran);
        assert_eq!(pass.snapshot.bridge.epoch, 1);
    }

    // ---- Peer addressing on uplinks (R003-B10) ------------------------------

    fn ups(names: &[&str]) -> Vec<String> {
        strs(names)
    }

    fn uplink_add(iface: &str, addr: &str, prefix: u8) -> HelperRequest {
        HelperRequest::AddAlias { iface: iface.into(), addr: addr.parse().unwrap(), prefix }
    }

    fn uplink_rm(iface: &str, addr: &str) -> HelperRequest {
        HelperRequest::RemoveAlias { iface: iface.into(), addr: addr.parse().unwrap() }
    }

    fn peer_desired(uplinks: &[String]) -> Desired<'_> {
        Desired {
            bridge_up: false,
            scope_enabled: false,
            primary: Some(primary(7)),
            site: AddrSite::Uplinks(uplinks),
        }
    }

    #[test]
    fn a_peer_with_an_uplink_and_no_bridge_gets_both_addresses_on_it() {
        let u = ups(&["en5"]);
        let plan = reconcile_plan(peer_desired(&u), &[], &empty_report());
        assert_eq!(
            plan,
            vec![uplink_add("en5", "fd1b:5a70:a52::1", 64), uplink_add("en5", "10.42.0.7", 16)],
            "no bridge verbs at all"
        );
    }

    #[test]
    fn a_converged_peer_plans_nothing() {
        let u = ups(&["en5"]);
        let mut report = empty_report();
        report.uplink_aliases = vec![(
            "en5".into(),
            vec!["fd1b:5a70:a52::1".parse().unwrap(), "10.42.0.7".parse().unwrap()],
        )];
        assert_eq!(reconcile_plan(peer_desired(&u), &[], &report), Vec::new());
    }

    #[test]
    fn a_peer_with_no_uplink_plans_nothing_and_replug_readds() {
        // Unplug: the alias went with the interface; the uplink set is empty.
        assert_eq!(reconcile_plan(peer_desired(&[]), &[], &empty_report()), Vec::new());
        // Replug (possibly under a new name): the same address, added again.
        let u = ups(&["en6"]);
        let plan = reconcile_plan(peer_desired(&u), &[], &empty_report());
        assert!(plan.contains(&uplink_add("en6", "10.42.0.7", 16)), "{plan:?}");
    }

    #[test]
    fn peer_uplink_rehash_strips_only_our_stale_address_first() {
        let u = ups(&["en5"]);
        let mut report = empty_report();
        report.uplink_aliases = vec![(
            "en5".into(),
            vec![
                "fd1b:5a70:a52::1".parse().unwrap(),
                "10.42.0.9".parse().unwrap(),  // ours, stale after a re-hash
                "10.69.0.55".parse().unwrap(), // the segment's DHCP lease: not ours
                "10.42.200.1".parse().unwrap(), // foreign pool half: not ours
            ],
        )];
        assert_eq!(
            reconcile_plan(peer_desired(&u), &[], &report),
            vec![uplink_rm("en5", "10.42.0.9"), uplink_add("en5", "10.42.0.7", 16)]
        );
    }

    #[test]
    fn peer_addresses_every_uplink_independently() {
        let u = ups(&["en5", "en6"]);
        let mut report = empty_report();
        report.uplink_aliases = vec![(
            "en5".into(),
            vec!["fd1b:5a70:a52::1".parse().unwrap(), "10.42.0.7".parse().unwrap()],
        )];
        assert_eq!(
            reconcile_plan(peer_desired(&u), &[], &report),
            vec![uplink_add("en6", "fd1b:5a70:a52::1", 64), uplink_add("en6", "10.42.0.7", 16)]
        );
    }

    #[test]
    fn hub_to_peer_destroys_the_bridge_before_addressing_the_uplink() {
        // The bridge still holds en5 (and the aliases): teardown order, then
        // the uplink add LAST — the helper refuses a bridge member.
        let u = ups(&["en5"]);
        let mut report = full_report(&["en5"]);
        report.bridge_aliases = vec!["fd1b:5a70:a52::1".parse().unwrap(), "10.42.0.7".parse().unwrap()];
        let plan = reconcile_plan(peer_desired(&u), &[], &report);
        let pos = |v: &HelperRequest| plan.iter().position(|p| p == v).unwrap();
        let destroy = pos(&HelperRequest::DestroyBridge);
        assert!(pos(&rm("10.42.0.7")) < destroy && pos(&rm("fd1b:5a70:a52::1")) < destroy, "{plan:?}");
        assert!(destroy < pos(&uplink_add("en5", "10.42.0.7", 16)), "{plan:?}");
        assert!(destroy < pos(&uplink_add("en5", "fd1b:5a70:a52::1", 64)), "{plan:?}");
    }

    #[test]
    fn peer_to_hub_strips_our_uplink_aliases_before_enslaving() {
        let mut report = empty_report();
        report.uplink_aliases = vec![(
            "en9".into(),
            vec![
                "fd1b:5a70:a52::1".parse().unwrap(),
                "10.42.0.7".parse().unwrap(),
                "10.69.0.55".parse().unwrap(),
            ],
        )];
        let plan = reconcile_plan(up_with(primary(7)), &strs(&["en9"]), &report);
        let strip_ula = plan.iter().position(|p| *p == uplink_rm("en9", "fd1b:5a70:a52::1")).unwrap();
        let strip_v4 = plan.iter().position(|p| *p == uplink_rm("en9", "10.42.0.7")).unwrap();
        let enslave = plan.iter().position(|p| matches!(p, HelperRequest::SetBridgeMembers { .. })).unwrap();
        assert!(strip_ula < enslave && strip_v4 < enslave, "{plan:?}");
        assert!(!plan.contains(&uplink_rm("en9", "10.69.0.55")), "the DHCP lease is not ours");
    }

    #[test]
    fn a_hub_with_its_bridge_down_does_not_address_uplinks() {
        let u = ups(&["en5"]);
        let d = Desired { site: AddrSite::Bridge, ..peer_desired(&u) };
        assert_eq!(reconcile_plan(d, &[], &empty_report()), Vec::new());
    }

    #[test]
    fn uplink_alias_verbs_are_their_own_facet_and_gated_on_the_bridge_step() {
        assert_eq!(facet(&uplink_add("en5", "10.42.0.7", 16)), Facet::Uplink);
        assert_eq!(facet(&add("10.42.0.7", 16)), Facet::Bridge);
        assert_eq!(blocked_by(&uplink_add("en5", "10.42.0.7", 16)), &[Facet::Bridge]);
        assert!(blocked_by(&uplink_rm("en5", "10.42.0.7")).is_empty());
    }

    #[tokio::test]
    async fn a_peer_self_addresses_through_the_real_pass_and_survives_replug() {
        let store = store_with_mesh(NodeRole::Peer).await;
        let helper = MockHelper::new();
        helper.plug_uplink("en9").await;
        let usb = source(&["en9"]); // host-side cable: an uplink for a Peer
        let first = drive_once(&store, &helper, &usb).await.expect("pass");
        assert!(first.failures.is_empty(), "{:?}", first.failures);
        assert!(!helper.requests().contains(&HelperRequest::CreateBridge));
        assert_eq!(helper.aliases_on("en9").await.len(), 2);

        // Converged: a second pass changes nothing.
        let n = helper.requests().len();
        let steady = drive_once(&store, &helper, &usb).await.expect("steady pass");
        assert!(!steady.ran, "no steps when converged");
        assert_eq!(helper.requests().iter().filter(|r| matches!(r, HelperRequest::AddAlias { .. })).count(), 2);
        let _ = n;

        // Unplug: the aliases went with the interface; nothing to do.
        helper.unplug_uplink("en9").await;
        let unplugged = source(&[]);
        let gone = drive_once(&store, &helper, &unplugged).await.expect("pass");
        assert!(!gone.ran && gone.failures.is_empty());

        // Replug: re-applied idempotently.
        helper.plug_uplink("en9").await;
        let back = drive_once(&store, &helper, &usb).await.expect("replug pass");
        assert!(back.failures.is_empty(), "{:?}", back.failures);
        assert_eq!(helper.aliases_on("en9").await.len(), 2);
    }
}
