//! ipauro-helper — the privileged root daemon (ticket R002 M0 "privilege +
//! lifecycle spine", extended by M1's data plane — R005). Listens on the XPC
//! mach service named [`ipauro_proto::ids::HELPER_LABEL`] (registered by
//! launchd via this process's `MachServices` plist key — see
//! `app/helper/dev/*.plist`), authenticates every peer by code signature
//! before parsing any message, and drives three data-plane executors (see
//! `request::Executors`): the bridge (`executor.rs`, `/sbin/ifconfig`), pf
//! transport scoping (`pf.rs`, a dedicated `ipauro` anchor), and the
//! in-process DHCP responder (`dhcp/`). Fails open — full stock-networking
//! restoration via `failopen::teardown` (clear scopes, stop DHCP, destroy
//! the bridge, in that order) — if no authenticated connection is seen for
//! [`ipauro_proto::helper::FAILOPEN_GRACE_SECS`] after the last one drops.
//!
//! `IPAURO_INSECURE_DEV=1` disables peer authentication for unsigned dev
//! builds — see `app/helper/README.md`. Never set in a shipping build.

mod cmd;
mod dhcp;
mod executor;
mod failopen;
mod listener;
mod netutil;
mod pf;
mod request;
use std::sync::Arc;

use dhcp::RawSocketDhcpResponder;
use executor::IfconfigExecutor;
use ipauro_proto::helper::INSECURE_DEV_ENV;
/// The XPC FFI now lives in the shared `ipauro-xpc` crate (the brain
/// service's client side uses the same bindings); this alias keeps
/// `crate::xpc_sys::` paths working unchanged.
pub(crate) use ipauro_xpc as xpc_sys;
use listener::HelperState;
use pf::PfctlExecutor;
use request::Executors;

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let insecure_dev = std::env::var(INSECURE_DEV_ENV).map(|v| v == "1").unwrap_or(false);
    if insecure_dev {
        log::warn!("================================================================");
        log::warn!(" {INSECURE_DEV_ENV}=1 -- PEER CODE-SIGNING VALIDATION IS DISABLED.");
        log::warn!(" Any local process can drive this ROOT helper. Dev builds ONLY --");
        log::warn!(" never ship with this set.");
        log::warn!("================================================================");
    }

    let executors = Executors {
        bridge: Arc::new(IfconfigExecutor),
        pf: Arc::new(PfctlExecutor::new()),
        dhcp: Arc::new(RawSocketDhcpResponder::new()),
    };
    let state = Arc::new(HelperState::new(executors, insecure_dev));
    listener::run(&state)?;

    log::info!(
        "ipauro-helper {} (mach service {}) ready",
        env!("CARGO_PKG_VERSION"),
        ipauro_proto::ids::HELPER_LABEL
    );

    // Never returns: from here on, every XPC event (new connections,
    // messages, connection errors) is delivered to the blocks registered in
    // `listener::run` / `listener::accept_peer`, on GCD's default queue.
    unsafe { xpc_sys::dispatch_main() };
    #[allow(unreachable_code)]
    Ok(())
}
