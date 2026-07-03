//! ipauro-helper — the privileged root daemon (ticket R002, M0 "privilege +
//! lifecycle spine"). Listens on the XPC mach service named
//! [`ipauro_proto::ids::HELPER_LABEL`] (registered by launchd via this
//! process's `MachServices` plist key — see `app/helper/dev/*.plist`),
//! authenticates every peer by code signature before parsing any message,
//! and drives `bridge90` create/destroy/status via `/sbin/ifconfig`. Fails
//! open (destroys the bridge) if no authenticated connection is seen for
//! [`ipauro_proto::helper::FAILOPEN_GRACE_SECS`] after the last one drops.
//!
//! `IPAURO_INSECURE_DEV=1` disables peer authentication for unsigned dev
//! builds — see `app/helper/README.md`. Never set in a shipping build.

mod executor;
mod failopen;
mod listener;
mod request;
/// The XPC FFI now lives in the shared `ipauro-xpc` crate (the brain
/// service's client side uses the same bindings); this alias keeps
/// `crate::xpc_sys::` paths working unchanged.
pub(crate) use ipauro_xpc as xpc_sys;

use executor::IfconfigExecutor;
use ipauro_proto::helper::INSECURE_DEV_ENV;
use listener::HelperState;
use std::sync::Arc;

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

    let state = Arc::new(HelperState::new(Arc::new(IfconfigExecutor), insecure_dev));
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
