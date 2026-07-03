//! The seam between the brain service and the privileged helper.
//!
//! `HelperChannel` is the entire boundary: the real XPC-backed implementation
//! (mach service `ipauro_proto::ids::HELPER_LABEL`, peer code-signature
//! validation per `ipauro_proto::helper::peer_requirement()`) is wired in
//! later by constructing it and handing it to `ipauro_core::ServiceConfig` in
//! `main.rs` — nothing else in this crate needs to change.

use async_trait::async_trait;
use ipauro_proto::helper::{HelperRequest, HelperResponse};
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

/// In-memory stand-in for the XPC helper: answers Create/Destroy/Status
/// realistically (tracks whether "the bridge" exists) without touching any
/// real network state. Used by tests, and any dev flow that wants a working
/// bridge command loop without the privileged daemon.
pub struct MockHelper {
    bridge: Mutex<Option<ipauro_proto::state::BridgeInfo>>,
}

impl MockHelper {
    pub fn new() -> Self {
        Self { bridge: Mutex::new(None) }
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
                *bridge = Some(ipauro_proto::state::BridgeInfo {
                    name: ipauro_proto::helper::BRIDGE_NAME.to_string(),
                    members: Vec::new(),
                    ipv4: Some("10.69.0.1".to_string()),
                });
                Ok(HelperResponse::Ok)
            }
            HelperRequest::DestroyBridge => {
                let mut bridge = self.bridge.lock().await;
                *bridge = None;
                Ok(HelperResponse::Ok)
            }
        }
    }
}
