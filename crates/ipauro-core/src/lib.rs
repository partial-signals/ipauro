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

/// The snapshot every service instance boots with: no helper connection yet,
/// bridge not desired, stamped with this process's own identity.
pub fn initial_snapshot() -> Snapshot {
    let started_unix =
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    Snapshot {
        service: ServiceInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            pid: std::process::id(),
            started_unix,
        },
        helper: HelperState::NotRegistered,
        bridge: BridgeState { desired_up: false, actual: None },
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

    let reconcile_task = tokio::spawn(reconcile::run(
        store.clone(),
        config.helper.clone(),
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
        helper: config.helper.clone(),
        usb_source: config.usb_source.clone(),
        registrar: config.registrar.clone(),
        reconcile_kick: reconcile_kick.clone(),
    };
    let mut server_task =
        tokio::spawn(server::run(config.socket_path.clone(), handles, shutdown_tx.subscribe()));

    // Boot probe: one Ping to discover whether the helper is reachable. On
    // Pong the snapshot reflects a live helper; on error we fall back to what
    // the OS says about registration (NotRegistered / RequiresApproval /
    // Registered-but-unreachable). Best-effort by design — the reconcile loop
    // re-drives state on real commands, and a helper that dies later is
    // observed through failed requests, not here.
    {
        let store = store.clone();
        let helper = config.helper.clone();
        let registrar = config.registrar.clone();
        tokio::spawn(async move {
            match helper.request(ipauro_proto::helper::HelperRequest::Ping).await {
                Ok(ipauro_proto::helper::HelperResponse::Pong { version }) => {
                    log::info!("helper reachable (v{version})");
                    store
                        .mutate(|s| s.helper = HelperState::Connected { version: version.clone() })
                        .await;
                }
                Ok(other) => log::warn!("helper answered Ping with {other:?}"),
                Err(e) => {
                    let status = registrar.status();
                    log::info!("helper not reachable at boot ({e}); registration status: {status:?}");
                    store.mutate(|s| s.helper = status.clone()).await;
                }
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
