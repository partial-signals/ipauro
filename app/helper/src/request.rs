//! [`HelperRequest`] -> [`HelperResponse`] handling, independent of the XPC
//! wire format. Kept separate from `listener.rs` specifically so it can be
//! unit-tested against a mock [`BridgeExecutor`] without any XPC machinery.

use crate::executor::BridgeExecutor;
use ipauro_proto::helper::{HelperRequest, HelperResponse};

/// Handle one already-deserialized [`HelperRequest`], using `executor` for
/// anything that touches the bridge. Every variant of the (closed, narrow —
/// see `ipauro-proto`) request enum is handled explicitly.
pub fn handle_request(executor: &dyn BridgeExecutor, request: HelperRequest) -> HelperResponse {
    match request {
        HelperRequest::Ping => {
            HelperResponse::Pong { version: env!("CARGO_PKG_VERSION").to_string() }
        }
        HelperRequest::Status => match executor.status() {
            Ok(info) => HelperResponse::Bridge { info },
            Err(e) => HelperResponse::Err { message: e.to_string() },
        },
        HelperRequest::CreateBridge => match executor.create() {
            Ok(()) => HelperResponse::Ok,
            Err(e) => HelperResponse::Err { message: e.to_string() },
        },
        HelperRequest::DestroyBridge => match executor.destroy() {
            Ok(()) => HelperResponse::Ok,
            Err(e) => HelperResponse::Err { message: e.to_string() },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipauro_proto::state::BridgeInfo;
    use std::sync::Mutex;

    /// A mock [`BridgeExecutor`] with programmable outcomes and a call log,
    /// so tests can assert both the returned [`HelperResponse`] and that the
    /// right (and only the right) executor method was invoked.
    struct MockExecutor {
        create_err: Mutex<Option<String>>,
        destroy_err: Mutex<Option<String>>,
        status: Mutex<Result<Option<BridgeInfo>, String>>,
        calls: Mutex<Vec<&'static str>>,
    }

    impl Default for MockExecutor {
        fn default() -> Self {
            Self {
                create_err: Mutex::new(None),
                destroy_err: Mutex::new(None),
                status: Mutex::new(Ok(None)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl BridgeExecutor for MockExecutor {
        fn create(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("create");
            match &*self.create_err.lock().unwrap() {
                Some(msg) => Err(anyhow::anyhow!(msg.clone())),
                None => Ok(()),
            }
        }

        fn destroy(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("destroy");
            match &*self.destroy_err.lock().unwrap() {
                Some(msg) => Err(anyhow::anyhow!(msg.clone())),
                None => Ok(()),
            }
        }

        fn status(&self) -> anyhow::Result<Option<BridgeInfo>> {
            self.calls.lock().unwrap().push("status");
            match &*self.status.lock().unwrap() {
                Ok(info) => Ok(info.clone()),
                Err(msg) => Err(anyhow::anyhow!(msg.clone())),
            }
        }
    }

    #[test]
    fn ping_reports_version_without_touching_the_executor() {
        let mock = MockExecutor::default();
        let resp = handle_request(&mock, HelperRequest::Ping);
        assert_eq!(resp, HelperResponse::Pong { version: env!("CARGO_PKG_VERSION").to_string() });
        assert!(mock.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn status_ok_reports_bridge_info() {
        let mock = MockExecutor::default();
        let info = BridgeInfo {
            name: "bridge90".into(),
            members: vec!["en9".into(), "en12".into()],
            ipv4: Some("10.69.0.1".into()),
        };
        *mock.status.lock().unwrap() = Ok(Some(info.clone()));

        let resp = handle_request(&mock, HelperRequest::Status);
        assert_eq!(resp, HelperResponse::Bridge { info: Some(info) });
        assert_eq!(*mock.calls.lock().unwrap(), vec!["status"]);
    }

    #[test]
    fn status_absent_bridge_reports_none_not_an_error() {
        let mock = MockExecutor::default(); // defaults to Ok(None)
        let resp = handle_request(&mock, HelperRequest::Status);
        assert_eq!(resp, HelperResponse::Bridge { info: None });
    }

    #[test]
    fn status_error_becomes_helper_err() {
        let mock = MockExecutor::default();
        *mock.status.lock().unwrap() = Err("ifconfig exploded".into());
        let resp = handle_request(&mock, HelperRequest::Status);
        assert_eq!(resp, HelperResponse::Err { message: "ifconfig exploded".into() });
    }

    #[test]
    fn create_bridge_ok() {
        let mock = MockExecutor::default();
        let resp = handle_request(&mock, HelperRequest::CreateBridge);
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(*mock.calls.lock().unwrap(), vec!["create"]);
    }

    #[test]
    fn create_bridge_error_becomes_helper_err() {
        let mock = MockExecutor::default();
        *mock.create_err.lock().unwrap() = Some("not root".into());
        let resp = handle_request(&mock, HelperRequest::CreateBridge);
        assert_eq!(resp, HelperResponse::Err { message: "not root".into() });
    }

    #[test]
    fn destroy_bridge_ok() {
        let mock = MockExecutor::default();
        let resp = handle_request(&mock, HelperRequest::DestroyBridge);
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(*mock.calls.lock().unwrap(), vec!["destroy"]);
    }

    #[test]
    fn destroy_bridge_error_becomes_helper_err() {
        let mock = MockExecutor::default();
        *mock.destroy_err.lock().unwrap() = Some("already gone".into());
        let resp = handle_request(&mock, HelperRequest::DestroyBridge);
        assert_eq!(resp, HelperResponse::Err { message: "already gone".into() });
    }
}
