//! [`HelperRequest`] -> [`HelperResponse`] handling, independent of the XPC
//! wire format. Kept separate from `listener.rs` specifically so it can be
//! unit-tested against mocks without any XPC machinery.
//!
//! Every M1 verb follows the same shape: validate EVERY caller-supplied name
//! (pattern, then existence via `BridgeExecutor::list_interfaces`) BEFORE
//! any exec — reject the whole request on the first bad name, per
//! `ipauro-proto`'s `helper` module docs (member/interface names are the
//! first attacker-aimable strings on this channel).

use std::net::Ipv4Addr;
use std::sync::Arc;

use ipauro_proto::helper::{BRIDGE_NAME, DataPlaneReport, HelperRequest, HelperResponse};

use crate::dhcp::DhcpExecutor;
use crate::executor::BridgeExecutor;
use crate::netutil;
use crate::pf::PfExecutor;

/// The three executor trait objects `handle_request` dispatches to. Bundled
/// so the fail-open teardown (`failopen::teardown`) and the listener's
/// per-connection state share one clonable handle instead of three.
#[derive(Clone)]
pub struct Executors {
    pub bridge: Arc<dyn BridgeExecutor>,
    pub pf: Arc<dyn PfExecutor>,
    pub dhcp: Arc<dyn DhcpExecutor>,
}

/// Handle one already-deserialized [`HelperRequest`]. Every variant of the
/// (closed, narrow — see `ipauro-proto`) request enum is handled explicitly.
pub fn handle_request(executors: &Executors, request: HelperRequest) -> HelperResponse {
    match &request {
        HelperRequest::Ping => {
            HelperResponse::Pong { version: env!("CARGO_PKG_VERSION").to_string() }
        }
        HelperRequest::Status => bridge_status_response(executors),
        HelperRequest::CreateBridge => result_to_ok(executors.bridge.create()),
        HelperRequest::DestroyBridge => result_to_ok(executors.bridge.destroy()),
        HelperRequest::SetBridgeMembers { members } => {
            handle_set_bridge_members(executors, members)
        }
        HelperRequest::SetBridgeAddress { ipv4, prefix } => {
            handle_set_bridge_address(executors, *ipv4, *prefix)
        }
        HelperRequest::ScopeUdp { port, allowed_ifaces } => {
            handle_scope_udp(executors, *port, allowed_ifaces)
        }
        HelperRequest::ClearScopes => result_to_ok(executors.pf.clear_scopes()),
        HelperRequest::ServeDhcp { pool_start, pool_end, netmask } => {
            handle_serve_dhcp(executors, *pool_start, *pool_end, *netmask)
        }
        HelperRequest::StopDhcp => result_to_ok(executors.dhcp.stop()),
        HelperRequest::Report => handle_report(executors),
    }
}

fn result_to_ok(result: anyhow::Result<()>) -> HelperResponse {
    match result {
        Ok(()) => HelperResponse::Ok,
        Err(e) => HelperResponse::Err { message: e.to_string() },
    }
}

fn bridge_status_response(executors: &Executors) -> HelperResponse {
    match executors.bridge.status() {
        Ok(info) => HelperResponse::Bridge { info },
        Err(e) => HelperResponse::Err { message: e.to_string() },
    }
}

/// Validate that every name in `names` currently exists per
/// `BridgeExecutor::list_interfaces` (the existence half of the "validate
/// before any exec" rule — pattern validation happens separately, before
/// this is even called).
fn check_interfaces_exist(executors: &Executors, names: &[String]) -> Result<(), String> {
    let existing = executors.bridge.list_interfaces().map_err(|e| e.to_string())?;
    if let Some(missing) = names.iter().find(|n| !existing.iter().any(|e| e == *n)) {
        return Err(format!("interface {missing} does not exist"));
    }
    Ok(())
}

fn handle_set_bridge_members(executors: &Executors, members: &[String]) -> HelperResponse {
    if let Some(bad) = netutil::first_invalid_name(members, netutil::is_valid_member_name) {
        return HelperResponse::Err { message: format!("invalid bridge member name: {bad}") };
    }
    if let Err(msg) = check_interfaces_exist(executors, members) {
        return HelperResponse::Err { message: msg };
    }
    match executors.bridge.set_members(members) {
        Ok(()) => bridge_status_response(executors),
        Err(e) => HelperResponse::Err { message: e.to_string() },
    }
}

fn handle_set_bridge_address(executors: &Executors, ipv4: Ipv4Addr, prefix: u8) -> HelperResponse {
    if let Err(msg) = netutil::validate_bridge_address(ipv4, prefix) {
        return HelperResponse::Err { message: msg };
    }
    match executors.bridge.set_address(ipv4, prefix) {
        Ok(()) => bridge_status_response(executors),
        Err(e) => HelperResponse::Err { message: e.to_string() },
    }
}

fn handle_scope_udp(executors: &Executors, port: u16, allowed_ifaces: &[String]) -> HelperResponse {
    if let Some(bad) = netutil::first_invalid_name(allowed_ifaces, |n| {
        netutil::is_valid_scope_iface_name(n, BRIDGE_NAME)
    }) {
        return HelperResponse::Err { message: format!("invalid scope interface name: {bad}") };
    }
    if let Err(msg) = check_interfaces_exist(executors, allowed_ifaces) {
        return HelperResponse::Err { message: msg };
    }
    result_to_ok(executors.pf.scope_udp(port, allowed_ifaces))
}

fn handle_serve_dhcp(
    executors: &Executors,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    netmask: Ipv4Addr,
) -> HelperResponse {
    let bridge_info = match executors.bridge.status() {
        Ok(Some(info)) => info,
        Ok(None) => {
            return HelperResponse::Err {
                message: "bridge does not exist; cannot serve DHCP".into(),
            };
        }
        Err(e) => return HelperResponse::Err { message: e.to_string() },
    };
    let bridge_ipv4: Ipv4Addr = match bridge_info.ipv4.as_deref().map(str::parse) {
        Some(Ok(addr)) => addr,
        _ => {
            return HelperResponse::Err {
                message: "bridge has no IPv4 address; call SetBridgeAddress first".into(),
            };
        }
    };
    let bridge_prefix = match executors.bridge.address_prefix() {
        Ok(Some(p)) => p,
        Ok(None) => {
            return HelperResponse::Err {
                message: "bridge has no address prefix; call SetBridgeAddress first".into(),
            };
        }
        Err(e) => return HelperResponse::Err { message: e.to_string() },
    };
    if let Err(msg) =
        netutil::validate_dhcp_pool(bridge_ipv4, bridge_prefix, pool_start, pool_end, netmask)
    {
        return HelperResponse::Err { message: msg };
    }
    result_to_ok(executors.dhcp.serve(pool_start, pool_end, netmask, bridge_ipv4))
}

fn handle_report(executors: &Executors) -> HelperResponse {
    let bridge = match executors.bridge.status() {
        Ok(info) => info,
        Err(e) => return HelperResponse::Err { message: e.to_string() },
    };
    HelperResponse::Report {
        report: DataPlaneReport {
            bridge,
            scoped_ports: executors.pf.scoped_ports(),
            dhcp_serving: executors.dhcp.is_serving(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ipauro_proto::state::BridgeInfo;

    use super::*;

    // ---- mocks --------------------------------------------------------------

    struct MockBridge {
        create_err: Mutex<Option<String>>,
        destroy_err: Mutex<Option<String>>,
        status: Mutex<Result<Option<BridgeInfo>, String>>,
        list_interfaces: Mutex<Result<Vec<String>, String>>,
        set_members_err: Mutex<Option<String>>,
        set_address_err: Mutex<Option<String>>,
        address_prefix: Mutex<Result<Option<u8>, String>>,
        calls: Mutex<Vec<String>>,
    }

    impl Default for MockBridge {
        fn default() -> Self {
            Self {
                create_err: Mutex::new(None),
                destroy_err: Mutex::new(None),
                status: Mutex::new(Ok(None)),
                list_interfaces: Mutex::new(Ok(Vec::new())),
                set_members_err: Mutex::new(None),
                set_address_err: Mutex::new(None),
                address_prefix: Mutex::new(Ok(None)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl BridgeExecutor for MockBridge {
        fn create(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("create".into());
            self.create_err.lock().unwrap().clone().map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
        }
        fn destroy(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("destroy".into());
            self.destroy_err.lock().unwrap().clone().map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
        }
        fn status(&self) -> anyhow::Result<Option<BridgeInfo>> {
            self.calls.lock().unwrap().push("status".into());
            self.status.lock().unwrap().clone().map_err(|m| anyhow::anyhow!(m))
        }
        fn list_interfaces(&self) -> anyhow::Result<Vec<String>> {
            self.calls.lock().unwrap().push("list_interfaces".into());
            self.list_interfaces.lock().unwrap().clone().map_err(|m| anyhow::anyhow!(m))
        }
        fn set_members(&self, members: &[String]) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push(format!("set_members({members:?})"));
            self.set_members_err.lock().unwrap().clone().map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
        }
        fn set_address(&self, ipv4: Ipv4Addr, prefix: u8) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push(format!("set_address({ipv4}/{prefix})"));
            self.set_address_err.lock().unwrap().clone().map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
        }
        fn address_prefix(&self) -> anyhow::Result<Option<u8>> {
            self.calls.lock().unwrap().push("address_prefix".into());
            self.address_prefix.lock().unwrap().clone().map_err(|m| anyhow::anyhow!(m))
        }
    }

    #[derive(Default)]
    struct MockPf {
        scope_err: Mutex<Option<String>>,
        clear_err: Mutex<Option<String>>,
        scoped: Mutex<Vec<(u16, Vec<String>)>>,
        calls: Mutex<Vec<String>>,
    }

    impl PfExecutor for MockPf {
        fn scope_udp(&self, port: u16, allowed_ifaces: &[String]) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push(format!("scope_udp({port}, {allowed_ifaces:?})"));
            self.scope_err.lock().unwrap().clone().map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
        }
        fn clear_scopes(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("clear_scopes".into());
            self.clear_err.lock().unwrap().clone().map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
        }
        fn scoped_ports(&self) -> Vec<(u16, Vec<String>)> {
            self.scoped.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct MockDhcp {
        serve_err: Mutex<Option<String>>,
        stop_err: Mutex<Option<String>>,
        serving: Mutex<bool>,
        calls: Mutex<Vec<String>>,
    }

    impl DhcpExecutor for MockDhcp {
        fn serve(
            &self,
            pool_start: Ipv4Addr,
            pool_end: Ipv4Addr,
            netmask: Ipv4Addr,
            server_ip: Ipv4Addr,
        ) -> anyhow::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("serve({pool_start}, {pool_end}, {netmask}, {server_ip})"));
            match self.serve_err.lock().unwrap().clone() {
                Some(m) => Err(anyhow::anyhow!(m)),
                None => {
                    *self.serving.lock().unwrap() = true;
                    Ok(())
                }
            }
        }
        fn stop(&self) -> anyhow::Result<()> {
            self.calls.lock().unwrap().push("stop".into());
            match self.stop_err.lock().unwrap().clone() {
                Some(m) => Err(anyhow::anyhow!(m)),
                None => {
                    *self.serving.lock().unwrap() = false;
                    Ok(())
                }
            }
        }
        fn is_serving(&self) -> bool {
            *self.serving.lock().unwrap()
        }
    }

    /// Bundle three fresh mocks into an [`Executors`], keeping typed `Arc`
    /// handles around so tests can inspect each mock's `.calls` log.
    fn mocks() -> (Arc<MockBridge>, Arc<MockPf>, Arc<MockDhcp>, Executors) {
        let bridge = Arc::new(MockBridge::default());
        let pf = Arc::new(MockPf::default());
        let dhcp = Arc::new(MockDhcp::default());
        let executors = Executors {
            bridge: bridge.clone() as Arc<dyn BridgeExecutor>,
            pf: pf.clone() as Arc<dyn PfExecutor>,
            dhcp: dhcp.clone() as Arc<dyn DhcpExecutor>,
        };
        (bridge, pf, dhcp, executors)
    }

    // ---- pre-existing verbs (unchanged behavior, new Executors shape) ------

    #[test]
    fn ping_reports_version_without_touching_any_executor() {
        let (bridge, pf, dhcp, executors) = mocks();
        let resp = handle_request(&executors, HelperRequest::Ping);
        assert_eq!(resp, HelperResponse::Pong { version: env!("CARGO_PKG_VERSION").to_string() });
        assert!(bridge.calls.lock().unwrap().is_empty());
        assert!(pf.calls.lock().unwrap().is_empty());
        assert!(dhcp.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn status_ok_reports_bridge_info() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        let info = BridgeInfo {
            name: "bridge90".into(),
            members: vec!["en9".into()],
            ipv4: Some("10.69.0.1".into()),
            prefix: None,
        };
        *bridge.status.lock().unwrap() = Ok(Some(info.clone()));
        let resp = handle_request(&executors, HelperRequest::Status);
        assert_eq!(resp, HelperResponse::Bridge { info: Some(info) });
    }

    #[test]
    fn create_bridge_ok() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        let resp = handle_request(&executors, HelperRequest::CreateBridge);
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(*bridge.calls.lock().unwrap(), vec!["create".to_string()]);
    }

    #[test]
    fn destroy_bridge_error_becomes_helper_err() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        *bridge.destroy_err.lock().unwrap() = Some("already gone".into());
        let resp = handle_request(&executors, HelperRequest::DestroyBridge);
        assert_eq!(resp, HelperResponse::Err { message: "already gone".into() });
    }

    // ---- SetBridgeMembers ----------------------------------------------------

    #[test]
    fn set_bridge_members_validates_then_converges_then_reports_status() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        *bridge.list_interfaces.lock().unwrap() = Ok(vec!["en9".into(), "en12".into()]);
        let info = BridgeInfo { name: "bridge90".into(), members: vec!["en9".into()], ipv4: None, prefix: None };
        *bridge.status.lock().unwrap() = Ok(Some(info.clone()));

        let resp = handle_request(
            &executors,
            HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "en12".into()] },
        );
        assert_eq!(resp, HelperResponse::Bridge { info: Some(info) });
        let calls = bridge.calls.lock().unwrap();
        assert!(calls.contains(&"list_interfaces".to_string()));
        assert!(calls.iter().any(|c| c.starts_with("set_members")));
    }

    #[test]
    fn set_bridge_members_rejects_the_whole_request_on_one_bad_name() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        let resp = handle_request(
            &executors,
            HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "bridge90".into()] },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        // No exec at all — not list_interfaces, not set_members.
        assert!(bridge.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn set_bridge_members_rejects_a_name_that_does_not_exist() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        *bridge.list_interfaces.lock().unwrap() = Ok(vec!["en9".into()]); // en12 not present
        let resp = handle_request(
            &executors,
            HelperRequest::SetBridgeMembers { members: vec!["en9".into(), "en12".into()] },
        );
        assert_eq!(resp, HelperResponse::Err { message: "interface en12 does not exist".into() });
        let calls = bridge.calls.lock().unwrap();
        assert!(
            !calls.iter().any(|c| c.starts_with("set_members")),
            "set_members must not run: {calls:?}"
        );
    }

    // ---- SetBridgeAddress ------------------------------------------------------

    #[test]
    fn set_bridge_address_valid_converges_and_reports_status() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        let info =
            BridgeInfo { name: "bridge90".into(), members: vec![], ipv4: Some("10.69.0.1".into()), prefix: None };
        *bridge.status.lock().unwrap() = Ok(Some(info.clone()));

        let resp = handle_request(
            &executors,
            HelperRequest::SetBridgeAddress { ipv4: Ipv4Addr::new(10, 69, 0, 1), prefix: 24 },
        );
        assert_eq!(resp, HelperResponse::Bridge { info: Some(info) });
        assert!(bridge.calls.lock().unwrap().iter().any(|c| c.starts_with("set_address")));
    }

    #[test]
    fn set_bridge_address_rejects_non_rfc1918_before_any_exec() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        let resp = handle_request(
            &executors,
            HelperRequest::SetBridgeAddress { ipv4: Ipv4Addr::new(8, 8, 8, 8), prefix: 24 },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        assert!(bridge.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn set_bridge_address_rejects_bad_prefix_before_any_exec() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        let resp = handle_request(
            &executors,
            HelperRequest::SetBridgeAddress { ipv4: Ipv4Addr::new(10, 69, 0, 1), prefix: 31 },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        assert!(bridge.calls.lock().unwrap().is_empty());
    }

    // ---- ScopeUdp / ClearScopes -------------------------------------------------

    #[test]
    fn scope_udp_allows_the_bridge_name_and_dispatches_to_pf() {
        let (bridge, pf, _dhcp, executors) = mocks();
        *bridge.list_interfaces.lock().unwrap() = Ok(vec!["bridge90".into()]);
        let resp = handle_request(
            &executors,
            HelperRequest::ScopeUdp { port: 20808, allowed_ifaces: vec!["bridge90".into()] },
        );
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(*pf.calls.lock().unwrap(), vec!["scope_udp(20808, [\"bridge90\"])".to_string()]);
    }

    #[test]
    fn scope_udp_rejects_an_invalid_iface_literal_before_any_exec() {
        let (bridge, pf, _dhcp, executors) = mocks();
        let resp = handle_request(
            &executors,
            HelperRequest::ScopeUdp { port: 20808, allowed_ifaces: vec!["bridge1".into()] },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        assert!(bridge.calls.lock().unwrap().is_empty());
        assert!(pf.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn scope_udp_rejects_a_nonexistent_interface() {
        let (bridge, pf, _dhcp, executors) = mocks();
        *bridge.list_interfaces.lock().unwrap() = Ok(vec![]); // bridge90 not present yet
        let resp = handle_request(
            &executors,
            HelperRequest::ScopeUdp { port: 20808, allowed_ifaces: vec!["bridge90".into()] },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        assert!(pf.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn clear_scopes_dispatches_to_pf() {
        let (_bridge, pf, _dhcp, executors) = mocks();
        let resp = handle_request(&executors, HelperRequest::ClearScopes);
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(*pf.calls.lock().unwrap(), vec!["clear_scopes".to_string()]);
    }

    #[test]
    fn clear_scopes_error_becomes_helper_err() {
        let (_bridge, pf, _dhcp, executors) = mocks();
        *pf.clear_err.lock().unwrap() = Some("pfctl exploded".into());
        let resp = handle_request(&executors, HelperRequest::ClearScopes);
        assert_eq!(resp, HelperResponse::Err { message: "pfctl exploded".into() });
    }

    // ---- ServeDhcp / StopDhcp ---------------------------------------------------

    #[test]
    fn serve_dhcp_requires_a_bridge_to_exist() {
        let (_bridge, _pf, dhcp, executors) = mocks(); // status defaults to Ok(None)
        let resp = handle_request(
            &executors,
            HelperRequest::ServeDhcp {
                pool_start: Ipv4Addr::new(10, 69, 0, 10),
                pool_end: Ipv4Addr::new(10, 69, 0, 200),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        assert!(dhcp.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn serve_dhcp_valid_pool_dispatches_with_the_bridge_address_as_server_id() {
        let (bridge, _pf, dhcp, executors) = mocks();
        *bridge.status.lock().unwrap() = Ok(Some(BridgeInfo {
            name: "bridge90".into(),
            members: vec![],
            ipv4: Some("10.69.0.1".into()),
            prefix: None,
        }));
        *bridge.address_prefix.lock().unwrap() = Ok(Some(24));

        let resp = handle_request(
            &executors,
            HelperRequest::ServeDhcp {
                pool_start: Ipv4Addr::new(10, 69, 0, 10),
                pool_end: Ipv4Addr::new(10, 69, 0, 200),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
        );
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(
            *dhcp.calls.lock().unwrap(),
            vec!["serve(10.69.0.10, 10.69.0.200, 255.255.255.0, 10.69.0.1)".to_string()]
        );
    }

    #[test]
    fn serve_dhcp_rejects_a_pool_outside_the_bridge_subnet() {
        let (bridge, _pf, dhcp, executors) = mocks();
        *bridge.status.lock().unwrap() = Ok(Some(BridgeInfo {
            name: "bridge90".into(),
            members: vec![],
            ipv4: Some("10.69.0.1".into()),
            prefix: None,
        }));
        *bridge.address_prefix.lock().unwrap() = Ok(Some(24));

        let resp = handle_request(
            &executors,
            HelperRequest::ServeDhcp {
                pool_start: Ipv4Addr::new(10, 70, 0, 10),
                pool_end: Ipv4Addr::new(10, 70, 0, 200),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            },
        );
        assert!(matches!(resp, HelperResponse::Err { .. }));
        assert!(dhcp.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn stop_dhcp_dispatches_and_reports_ok() {
        let (_bridge, _pf, dhcp, executors) = mocks();
        let resp = handle_request(&executors, HelperRequest::StopDhcp);
        assert_eq!(resp, HelperResponse::Ok);
        assert_eq!(*dhcp.calls.lock().unwrap(), vec!["stop".to_string()]);
    }

    // ---- Report ------------------------------------------------------------------

    #[test]
    fn report_assembles_bridge_scopes_and_dhcp_state() {
        let (bridge, pf, dhcp, executors) = mocks();
        let info = BridgeInfo {
            name: "bridge90".into(),
            members: vec!["en9".into()],
            ipv4: Some("10.69.0.1".into()),
            prefix: None,
        };
        *bridge.status.lock().unwrap() = Ok(Some(info.clone()));
        *pf.scoped.lock().unwrap() = vec![(20808, vec!["bridge90".to_string()])];
        *dhcp.serving.lock().unwrap() = true;

        let resp = handle_request(&executors, HelperRequest::Report);
        assert_eq!(
            resp,
            HelperResponse::Report {
                report: DataPlaneReport {
                    bridge: Some(info),
                    scoped_ports: vec![(20808, vec!["bridge90".to_string()])],
                    dhcp_serving: true,
                }
            }
        );
    }

    #[test]
    fn report_propagates_a_bridge_status_error() {
        let (bridge, _pf, _dhcp, executors) = mocks();
        *bridge.status.lock().unwrap() = Err("ifconfig exploded".into());
        let resp = handle_request(&executors, HelperRequest::Report);
        assert_eq!(resp, HelperResponse::Err { message: "ifconfig exploded".into() });
    }
}
