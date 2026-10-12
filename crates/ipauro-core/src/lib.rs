//! ipauro-core — the IPAuRo brain service: desired-state store, IPC server,
//! and the (pluggable) channel to the privileged helper.
//!
//! `@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — R002-T7:
//! the service's state store is the single source of truth; clients
//! (our tray UI, the CLI, external apps) are commanders/renderers kept in
//! sync via snapshot-on-connect + an ordered event stream.
//!
//! The privileged-helper boundary ([`helper_channel::HelperChannel`] /
//! [`registrar::HelperRegistrar`]) is injected via [`ServiceConfig`] — see
//! `main.rs` for the one-line seam where the real XPC implementation plugs in.

pub mod commands;
pub mod discovery;
pub mod helper_channel;
pub mod helper_link;
pub mod reconcile;
pub mod registrar;
#[cfg(target_os = "macos")]
pub mod registrar_smapp;
pub mod server;
pub mod state_store;
pub mod watch;
#[cfg(target_os = "macos")]
pub mod xpc_helper;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ipauro_proto::state::{BridgeState, HelperState, ServiceInfo, Snapshot};
use tokio::sync::{broadcast, Notify};

use discovery::UsbNcmSource;
use helper_channel::HelperChannel;
use registrar::HelperRegistrar;
use server::ServerHandles;
use state_store::StateStore;

/// Everything needed to boot the service. The helper channel/registrar/USB
/// source are the seam: swap `NullHelper`/`StubHelperRegistrar`/
/// `NoUsbNcmSource` for real XPC-backed, `SMAppService`-backed, and
/// `ioreg`-backed implementations here and nothing else in this crate changes.
pub struct ServiceConfig {
    pub socket_path: PathBuf,
    pub helper: Arc<dyn HelperChannel>,
    pub registrar: Arc<dyn HelperRegistrar>,
    pub usb_source: Arc<dyn UsbNcmSource>,
}

/// This build's full version identity — the workspace package version plus
/// the packaging build id, when `packaging/build-app.sh` stamped one in.
///
/// Two consumers: the wire-visible `ServiceInfo.version`, and
/// [`helper_link::SupervisedHelper`]'s staleness check, which compares this
/// against the version the helper answers `Ping` with. The helper computes
/// the same string the same way (`app/helper/src/main.rs`'s `build_version`),
/// so equality means "same build" — which the package version alone cannot
/// express, since it is `0.0.1` for every build of every milestone.
///
/// Deliberately duplicated in `ipauro-helper` instead of shared: the natural
/// home is `ipauro-proto`, which is manager-owned (flagged in R005-T10's
/// report). The two copies MUST produce byte-identical output for one build.
pub fn build_version() -> String {
    match option_env!("IPAURO_BUILD_ID") {
        Some(build) => format!("{}+{build}", env!("CARGO_PKG_VERSION")),
        None => env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// The snapshot every service instance boots with: no helper connection yet,
/// bridge not desired, stamped with this process's own identity.
pub fn initial_snapshot() -> Snapshot {
    let started_unix =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    Snapshot {
        service: ServiceInfo {
            version: build_version(),
            pid: std::process::id(),
            started_unix,
        },
        helper: HelperState::NotRegistered,
        bridge: BridgeState { desired_up: false, actual: None, epoch: 0 },
        transport: Default::default(),
    }
}

/// Boots the state store, reconcile loop, and IPC server, and runs until
/// `shutdown` resolves (SIGTERM/SIGINT in production; `std::future::pending()`
/// in tests that instead just let the runtime drop the task). Cleans up the
/// socket file on the way out.
pub async fn serve(config: ServiceConfig, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let store = Arc::new(StateStore::new(initial_snapshot()));
    let reconcile_kick = Arc::new(Notify::new());
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Every helper exchange in this process goes through the supervisor: it
    // keeps `Snapshot.helper` current off real traffic and cycles a stale
    // helper's registration (R005-T10 findings 1 + 4). Transparent to every
    // caller below — they still see a plain `HelperChannel`.
    let helper: Arc<dyn HelperChannel> = Arc::new(helper_link::SupervisedHelper::new(
        config.helper.clone(),
        store.clone(),
        config.registrar.clone(),
    ));

    let reconcile_task = tokio::spawn(reconcile::run(
        store.clone(),
        helper.clone(),
        config.usb_source.clone(),
        reconcile_kick.clone(),
        shutdown_tx.subscribe(),
    ));
    // Fast-path watch: kicks `reconcile_kick` on any USB-NCM interface change
    // (replug), well inside the 15s poll backstop `reconcile::run` already
    // provides on its own — see `watch`'s module docs for the mechanism
    // choice (ticket R005-F1).
    let watch_task = tokio::spawn(watch::run(
        config.usb_source.clone(),
        reconcile_kick.clone(),
        shutdown_tx.subscribe(),
    ));

    let handles = ServerHandles {
        store: store.clone(),
        helper: helper.clone(),
        usb_source: config.usb_source.clone(),
        registrar: config.registrar.clone(),
        reconcile_kick: reconcile_kick.clone(),
    };
    let mut server_task =
        tokio::spawn(server::run(config.socket_path.clone(), handles, shutdown_tx.subscribe()));

    // Boot probe: one Ping so the snapshot reflects the helper immediately
    // rather than at the first command. The supervisor above turns the answer
    // (or the failure) into `Snapshot.helper` and runs the stale-build check,
    // so this only has to make the call and log it. Best-effort by design —
    // a helper that becomes reachable, dies, or is replaced LATER is now
    // observed through ordinary traffic (R005-T10 finding 4), not here.
    {
        let helper = helper.clone();
        tokio::spawn(async move {
            match helper.request(ipauro_proto::helper::HelperRequest::Ping).await {
                Ok(ipauro_proto::helper::HelperResponse::Pong { version }) => {
                    log::info!("helper reachable (v{version})")
                }
                Ok(other) => log::warn!("helper answered Ping with {other:?}"),
                Err(e) => log::info!("helper not reachable at boot ({e})"),
            }
        });
    }

    // Wait for either an external shutdown request or the server task ending
    // on its own — the latter means it failed (bind error, accept-loop I/O
    // error) and the service must exit with that error now, not sit
    // listener-less until someone sends a signal.
    let server_result = tokio::select! {
        _ = shutdown => {
            log::info!("shutdown requested");
            let _ = shutdown_tx.send(());
            server_task.await
        }
        result = &mut server_task => result,
    };
    // Idempotent if already sent above; ensures the reconcile loop and the
    // watch task stop when the server died on its own.
    let _ = shutdown_tx.send(());
    let _ = reconcile_task.await;
    let _ = watch_task.await;

    match server_result {
        Ok(inner) => inner,
        Err(e) => Err(anyhow::anyhow!("server task panicked: {e}")),
    }
}
