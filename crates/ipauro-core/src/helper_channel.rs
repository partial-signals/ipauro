//! The seam between the brain service and the privileged helper.
//!
//! `HelperChannel` is the entire boundary: the real XPC-backed implementation
//! (mach service `ipauro_proto::ids::HELPER_LABEL`, peer code-signature
//! validation per `ipauro_proto::helper::peer_requirement()`) is wired in
//! later by constructing it and handing it to `ipauro_core::ServiceConfig` in
//! `main.rs` — nothing else in this crate needs to change.

use std::collections::HashSet;
use std::sync::Mutex as StdMutex;

use async_trait::async_trait;
use ipauro_proto::helper::{BRIDGE_NAME, DataPlaneReport, HelperRequest, HelperResponse};
use ipauro_proto::state::BridgeInfo;
use tokio::sync::Mutex;

/// Async request/response channel to the privileged helper. One method by
/// design — narrow by construction, mirroring `HelperRequest`'s own verb-only
/// shape (ticket R002-T3).
#[async_trait]
pub trait HelperChannel: Send + Sync {
    async fn request(&self, req: HelperRequest) -> anyhow::Result<HelperResponse>;
}

/// The default channel before a real helper connection exists (dev builds,
/// or any run where `RegisterHelper` hasn't succeeded yet). Every request
/// fails immediately; `commands.rs` turns that into `ErrorCode::HelperNotConnected`
/// and `HelperState` stays `NotRegistered`.
pub struct NullHelper;

#[async_trait]
impl HelperChannel for NullHelper {
    async fn request(&self, _req: HelperRequest) -> anyhow::Result<HelperResponse> {
        anyhow::bail!("helper not connected")
    }
}

/// In-memory stand-in for the XPC helper: tracks bridge existence + members +
/// address, scoped ports, and the DHCP flag realistically enough to exercise
/// the M1 reconciler end-to-end without touching any real network state.
///
/// The one deliberately-modeled real-world quirk (A002 §4): removing ANY
/// member from `SetBridgeMembers` (relative to the members it already holds)
/// destroys the WHOLE bridge, not just that member — mirroring macOS's real
/// `if_bridge` behavior on a USB-NCM member unplug. A pure addition (or a
/// no-op resend of the same set) does not.
///
/// `scoped_ports`/`dhcp_serving` are intentionally untouched by that
/// blast-radius destruction: in reality a pf scope naming the now-dead bridge
/// interface, and a DHCP responder bound to it, don't clean themselves up
/// either — that's exactly the A002 finding this crate's reconciler exists to
/// heal (`reconcile::reconcile_plan`'s "clear stale scope before rebuild").
///
/// Per-member IPv4 flushing (the shell prototype's `-alias` step) has no
/// state to model here: `ipauro_proto::state::BridgeInfo` only carries the
/// bridge's own address, never per-member addresses, so there is nothing
/// beyond the member-name set for this mock to track on that front.
pub struct MockHelper {
    bridge: Mutex<Option<BridgeInfo>>,
    scoped_ports: Mutex<Vec<(u16, Vec<String>)>>,
    dhcp_serving: Mutex<bool>,
    /// Mesh aliases per interface (R003-T3, R003-B10): the bridge's under
    /// `BRIDGE_NAME`, dropped with the bridge as on real macOS where
    /// destroying/tearing the bridge takes its addresses; an uplink's under
    /// its own name, dropped by [`MockHelper::unplug_uplink`].
    aliases: Mutex<std::collections::BTreeMap<String, Vec<std::net::IpAddr>>>,
    /// Uplink interfaces currently "plugged" — what the real helper's
    /// `uplink_candidates` would list absent bridge membership (and the
    /// default-route NIC, which the mock simply never plugs).
    uplinks: Mutex<std::collections::BTreeSet<String>>,
    /// Every request received, in order — lets tests assert verb ordering
    /// (the M-incident test's whole point). Plain `std::sync::Mutex`: pushed
    /// to synchronously at the top of `request`, never held across an
    /// `.await`.
    requests: StdMutex<Vec<HelperRequest>>,
    /// What this mock answers `Ping` with. Defaults to
    /// [`crate::build_version`] — i.e. a helper built from this same tree, the
    /// case every other test wants. Override to stand in for the STALE
    /// resident helper of R005-T10 finding 1.
    version: String,
    /// Requests to refuse with `HelperResponse::Err` instead of servicing.
    /// Exists for the continue-on-error pass (R005-T10 finding 3): a rejected
    /// step must not abort the steps that don't depend on it.
    rejected: StdMutex<Vec<HelperRequest>>,
}

impl MockHelper {
    pub fn new() -> Self {
        Self {
            bridge: Mutex::new(None),
            scoped_ports: Mutex::new(Vec::new()),
            dhcp_serving: Mutex::new(false),
            aliases: Mutex::new(Default::default()),
            uplinks: Mutex::new(Default::default()),
            requests: StdMutex::new(Vec::new()),
            version: crate::build_version(),
            rejected: StdMutex::new(Vec::new()),
        }
    }

    /// A mock answering `Ping` with someone else's build — the stale resident
    /// helper that launchd kept alive across a bundle replacement.
    pub fn with_version(version: impl Into<String>) -> Self {
        Self { version: version.into(), ..Self::new() }
    }

    /// Refuse `verb` (matched by exact equality, arguments included) with
    /// `HelperResponse::Err` from now on.
    pub fn reject(&self, verb: HelperRequest) {
        self.rejected.lock().expect("rejected mutex poisoned").push(verb);
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<HelperRequest> {
        self.requests.lock().expect("requests mutex poisoned").clone()
    }

    /// The kernel eating the bridge behind our back — A002 §4's blast radius
    /// as it ACTUALLY lands on macOS. The member-removal path above models
    /// the destruction as a response to our own `SetBridgeMembers`, which is
    /// the shape a poll-driven reconciler sees; in the field the cable is
    /// pulled at an arbitrary moment, so a pass can just as easily open with
    /// the bridge already gone and rebuild it inside that single pass. That
    /// variant leaves the before/after reports identical (same name, same
    /// address) even though every socket bound to the old interface is dead,
    /// and it is what `reconcile::next_epoch`'s `created` arm exists for.
    /// Records no request — nothing asked for it.
    pub async fn destroy_out_of_band(&self) {
        *self.bridge.lock().await = None;
        self.aliases.lock().await.remove(BRIDGE_NAME);
    }

    /// An uplink interface appears (cable plugged). Records no request.
    pub async fn plug_uplink(&self, name: &str) {
        self.uplinks.lock().await.insert(name.to_string());
    }

    /// The uplink disappears; its addresses go with it, as on real macOS.
    pub async fn unplug_uplink(&self, name: &str) {
        self.uplinks.lock().await.remove(name);
        self.aliases.lock().await.remove(name);
    }

    /// Aliases currently on `iface` (test inspection). Records no request.
    pub async fn aliases_on(&self, iface: &str) -> Vec<std::net::IpAddr> {
        self.aliases.lock().await.get(iface).cloned().unwrap_or_default()
    }
}

impl MockHelper {
    /// Why the real helper would refuse `iface` as an alias target, if it
    /// would: the bridge must exist; an uplink must be plugged and must not be
    /// a current bridge member.
    async fn alias_target_error(&self, iface: &str) -> Option<String> {
        let bridge = self.bridge.lock().await;
        if iface == BRIDGE_NAME {
            return bridge.is_none().then(|| "no such bridge".to_string());
        }
        if !self.uplinks.lock().await.contains(iface) {
            return Some(format!("{iface} is not a managed uplink"));
        }
        if bridge.as_ref().is_some_and(|b| b.members.iter().any(|m| m == iface)) {
            return Some(format!("{iface} is a bridge member"));
        }
        None
    }

    /// The report's per-uplink aliases: plugged, non-member, non-empty.
    async fn uplink_aliases(&self) -> Vec<(String, Vec<std::net::IpAddr>)> {
        let members = self.bridge.lock().await.as_ref().map(|b| b.members.clone()).unwrap_or_default();
        let plugged = self.uplinks.lock().await.clone();
        self.aliases
            .lock()
            .await
            .iter()
            .filter(|(name, a)| {
                name.as_str() != BRIDGE_NAME && plugged.contains(*name) && !members.contains(name) && !a.is_empty()
            })
            .map(|(n, a)| (n.clone(), a.clone()))
            .collect()
    }
}

impl Default for MockHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HelperChannel for MockHelper {
    async fn request(&self, req: HelperRequest) -> anyhow::Result<HelperResponse> {
        self.requests.lock().expect("requests mutex poisoned").push(req.clone());

        if self.rejected.lock().expect("rejected mutex poisoned").contains(&req) {
            return Ok(HelperResponse::Err { message: format!("mock refuses {req:?}") });
        }

        match req {
            HelperRequest::Ping => Ok(HelperResponse::Pong { version: self.version.clone() }),
            HelperRequest::Status => {
                let bridge = self.bridge.lock().await;
                Ok(HelperResponse::Bridge { info: bridge.clone() })
            }
            HelperRequest::CreateBridge => {
                let mut bridge = self.bridge.lock().await;
                // Idempotent: a bridge that already exists keeps its current
                // members/address (real `ifconfig bridge90 create` on an
                // existing bridge is a no-op/error, never a reset).
                if bridge.is_none() {
                    *bridge = Some(BridgeInfo {
                        name: BRIDGE_NAME.to_string(),
                        members: Vec::new(),
                        ipv4: None,
                        prefix: None,
                    });
                }
                Ok(HelperResponse::Bridge { info: bridge.clone() })
            }
            HelperRequest::DestroyBridge => {
                let mut bridge = self.bridge.lock().await;
                *bridge = None;
                self.aliases.lock().await.remove(BRIDGE_NAME);
                Ok(HelperResponse::Ok)
            }
            HelperRequest::SetBridgeMembers { members } => {
                let mut bridge = self.bridge.lock().await;
                let Some(current) = bridge.as_mut() else {
                    return Ok(HelperResponse::Err {
                        message: "SetBridgeMembers: no such bridge".to_string(),
                    });
                };
                let have: HashSet<&str> = current.members.iter().map(String::as_str).collect();
                let want: HashSet<&str> = members.iter().map(String::as_str).collect();
                let any_removed = have.difference(&want).next().is_some();
                if any_removed {
                    // A002 §4: unplugging (removing) ONE member tears down the
                    // ENTIRE bridge on real macOS, not just that member.
                    *bridge = None;
                    self.aliases.lock().await.remove(BRIDGE_NAME);
                    Ok(HelperResponse::Bridge { info: None })
                } else {
                    current.members = members;
                    Ok(HelperResponse::Bridge { info: bridge.clone() })
                }
            }
            HelperRequest::SetBridgeAddress { ipv4, prefix: _ } => {
                let mut bridge = self.bridge.lock().await;
                match bridge.as_mut() {
                    Some(info) => {
                        info.ipv4 = Some(ipv4.to_string());
                        Ok(HelperResponse::Bridge { info: Some(info.clone()) })
                    }
                    None => Ok(HelperResponse::Err {
                        message: "SetBridgeAddress: no such bridge".to_string(),
                    }),
                }
            }
            HelperRequest::AddAlias { iface, addr, prefix: _ } => {
                if let Some(err) = self.alias_target_error(&iface).await {
                    return Ok(HelperResponse::Err { message: format!("AddAlias: {err}") });
                }
                let mut aliases = self.aliases.lock().await;
                let on = aliases.entry(iface).or_default();
                if !on.contains(&addr) {
                    on.push(addr);
                }
                Ok(HelperResponse::Ok)
            }
            HelperRequest::RemoveAlias { iface, addr } => {
                // The real helper validates the target before ANY exec,
                // including a remove; absent aliases are Ok.
                if iface != BRIDGE_NAME && !self.uplinks.lock().await.contains(&iface) {
                    return Ok(HelperResponse::Err { message: format!("RemoveAlias: {iface} is not a managed uplink") });
                }
                if let Some(on) = self.aliases.lock().await.get_mut(&iface) {
                    on.retain(|a| *a != addr);
                }
                Ok(HelperResponse::Ok)
            }
            HelperRequest::ScopeUdp { port, allowed_ifaces } => {
                let mut scoped = self.scoped_ports.lock().await;
                scoped.retain(|(p, _)| *p != port);
                scoped.push((port, allowed_ifaces));
                Ok(HelperResponse::Ok)
            }
            HelperRequest::ClearScopes => {
                self.scoped_ports.lock().await.clear();
                Ok(HelperResponse::Ok)
            }
            HelperRequest::ServeDhcp { .. } => {
                *self.dhcp_serving.lock().await = true;
                Ok(HelperResponse::Ok)
            }
            HelperRequest::StopDhcp => {
                *self.dhcp_serving.lock().await = false;
                Ok(HelperResponse::Ok)
            }
            HelperRequest::Report => {
                let bridge = self.bridge.lock().await.clone();
                let scoped_ports = self.scoped_ports.lock().await.clone();
                let dhcp_serving = *self.dhcp_serving.lock().await;
                Ok(HelperResponse::Report { report: DataPlaneReport {
                    bridge,
                    scoped_ports,
                    dhcp_serving,
                    bridge_aliases: self.aliases_on(BRIDGE_NAME).await,
                    uplink_aliases: self.uplink_aliases().await,
                    dhcp_leases: Vec::new(),
                } })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn report(helper: &MockHelper) -> DataPlaneReport {
        match helper.request(HelperRequest::Report).await.unwrap() {
            HelperResponse::Report { report } => report,
            other => panic!("expected Report, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_bridge_is_idempotent_and_preserves_members() {
        let helper = MockHelper::new();
        helper.request(HelperRequest::CreateBridge).await.unwrap();
        helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into()] })
            .await
            .unwrap();
        // A second CreateBridge must not reset the members it just gained.
        helper.request(HelperRequest::CreateBridge).await.unwrap();
        let r = report(&helper).await;
        assert_eq!(r.bridge.unwrap().members, vec!["en9".to_string()]);
    }

    #[tokio::test]
    async fn adding_a_member_does_not_destroy_the_bridge() {
        let helper = MockHelper::new();
        helper.request(HelperRequest::CreateBridge).await.unwrap();
        helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into()] })
            .await
            .unwrap();
        helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "en12".into()] })
            .await
            .unwrap();
        let r = report(&helper).await;
        assert!(r.bridge.is_some());
        assert_eq!(r.bridge.unwrap().members, vec!["en9".to_string(), "en12".to_string()]);
    }

    #[tokio::test]
    async fn removing_a_member_destroys_the_whole_bridge() {
        let helper = MockHelper::new();
        helper.request(HelperRequest::CreateBridge).await.unwrap();
        helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "en12".into()] })
            .await
            .unwrap();
        let resp = helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into()] })
            .await
            .unwrap();
        assert_eq!(resp, HelperResponse::Bridge { info: None });
        let r = report(&helper).await;
        assert!(r.bridge.is_none(), "the whole bridge must be gone, not just the removed member");
    }

    #[tokio::test]
    async fn scope_and_dhcp_survive_the_blast_radius() {
        let helper = MockHelper::new();
        helper.request(HelperRequest::CreateBridge).await.unwrap();
        helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "en12".into()] })
            .await
            .unwrap();
        helper
            .request(HelperRequest::ScopeUdp { port: 20808, allowed_ifaces: vec![BRIDGE_NAME.into()] })
            .await
            .unwrap();
        helper
            .request(HelperRequest::ServeDhcp {
                pool_start: "10.69.0.10".parse().unwrap(),
                pool_end: "10.69.0.200".parse().unwrap(),
                netmask: "255.255.255.0".parse().unwrap(),
            })
            .await
            .unwrap();

        helper
            .request(HelperRequest::SetBridgeMembers { members: vec!["en9".into()] })
            .await
            .unwrap();

        let r = report(&helper).await;
        assert!(r.bridge.is_none());
        assert!(r.dhcp_serving, "DHCP flag isn't cleared by the blast radius alone");
        assert_eq!(r.scoped_ports, vec![(20808, vec![BRIDGE_NAME.to_string()])]);
    }

    #[tokio::test]
    async fn requests_are_captured_in_order() {
        let helper = MockHelper::new();
        helper.request(HelperRequest::CreateBridge).await.unwrap();
        helper.request(HelperRequest::ClearScopes).await.unwrap();
        assert_eq!(helper.requests(), vec![HelperRequest::CreateBridge, HelperRequest::ClearScopes]);
    }

    #[tokio::test]
    async fn scope_udp_replaces_any_existing_entry_for_the_same_port() {
        let helper = MockHelper::new();
        helper
            .request(HelperRequest::ScopeUdp { port: 20808, allowed_ifaces: vec!["bridge90".into()] })
            .await
            .unwrap();
        helper
            .request(HelperRequest::ScopeUdp { port: 20808, allowed_ifaces: vec!["en9".into()] })
            .await
            .unwrap();
        let r = report(&helper).await;
        assert_eq!(r.scoped_ports, vec![(20808, vec!["en9".to_string()])]);
    }
}
