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
    /// Every request received, in order — lets tests assert verb ordering
    /// (the M-incident test's whole point). Plain `std::sync::Mutex`: pushed
    /// to synchronously at the top of `request`, never held across an
    /// `.await`.
    requests: StdMutex<Vec<HelperRequest>>,
}

impl MockHelper {
    pub fn new() -> Self {
        Self {
            bridge: Mutex::new(None),
            scoped_ports: Mutex::new(Vec::new()),
            dhcp_serving: Mutex::new(false),
            requests: StdMutex::new(Vec::new()),
        }
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<HelperRequest> {
        self.requests.lock().expect("requests mutex poisoned").clone()
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

        match req {
            HelperRequest::Ping => {
                Ok(HelperResponse::Pong { version: env!("CARGO_PKG_VERSION").to_string() })
            }
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
                Ok(HelperResponse::Report { report: DataPlaneReport { bridge, scoped_ports, dhcp_serving } })
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
