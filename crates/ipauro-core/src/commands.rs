//! Command dispatch: turns a client [`Command`] into state-store mutations,
//! helper-channel calls, and a [`ReplyOutcome`].

use ipauro_proto::ipc::{Command, ErrorCode, ReplyOutcome};

use crate::discovery::UsbNcmSource;
use crate::helper_channel::HelperChannel;
use crate::reconcile::{self, err};
use crate::registrar::HelperRegistrar;
use crate::state_store::StateStore;
use tokio::sync::Notify;

/// Handle one command. Every [`Command`] variant is matched by name (no
/// catch-all) per house rule on enum discipline.
pub async fn handle(
    store: &StateStore,
    helper: &dyn HelperChannel,
    usb_source: &dyn UsbNcmSource,
    registrar: &dyn HelperRegistrar,
    reconcile_kick: &Notify,
    command: Command,
) -> ReplyOutcome {
    match command {
        Command::GetSnapshot => ReplyOutcome::Ok { snapshot: store.snapshot().await },
        Command::BridgeUp => drive_bridge(store, helper, usb_source, reconcile_kick, true).await,
        Command::BridgeDown => drive_bridge(store, helper, usb_source, reconcile_kick, false).await,
        Command::SetTransportScope { enabled } => {
            // Persisted in the snapshot-adjacent desired state (see
            // `StateStore::desired_scope_enabled`) BEFORE the helper is ever
            // touched, mirroring `drive_bridge`'s ordering: a failed drive
            // still leaves the store in a state `reconcile::run` will retry.
            store.set_desired_scope_enabled(enabled);
            // Reflect the desired flag in the wire snapshot immediately —
            // drive_once only refreshes transport state when its plan was
            // non-empty, and the flag must be visible even when nothing ran
            // (e.g. scoping toggled while the bridge is down).
            store.mutate(|s| s.transport.link_scope_desired = enabled).await;
            match reconcile::drive_once(store, helper, usb_source).await {
                Ok((snapshot, _ran)) => ReplyOutcome::Ok { snapshot },
                Err(outcome) => {
                    reconcile_kick.notify_one();
                    outcome
                }
            }
        }
        Command::RegisterHelper => match registrar.register().await {
            Ok(()) => {
                let status = registrar.status();
                let snapshot = store
                    .mutate(|s| {
                        // Never downgrade a live connection: the registrar only
                        // knows registration state, not liveness (its status()
                        // never returns Connected).
                        if !matches!(s.helper, ipauro_proto::state::HelperState::Connected { .. }) {
                            s.helper = status.clone();
                        }
                    })
                    .await;
                ReplyOutcome::Ok { snapshot }
            }
            Err(e) => err(ErrorCode::Internal, e.to_string()),
        },
        Command::UnregisterHelper => match registrar.unregister().await {
            Ok(()) => {
                let status = registrar.status();
                // Unconditional: an unregistered daemon's connection is dead
                // on the next request anyway.
                let snapshot = store.mutate(|s| s.helper = status.clone()).await;
                ReplyOutcome::Ok { snapshot }
            }
            Err(e) => err(ErrorCode::Internal, e.to_string()),
        },
    }
}

/// Set desired, then drive actual toward it via the FULL ordered reconcile
/// pass (`reconcile::drive_once`). Desired is persisted *before* the helper
/// is ever touched, so a failed drive still leaves the store in a state
/// `reconcile::run` will retry — and we kick it awake immediately rather than
/// waiting out its poll interval.
async fn drive_bridge(
    store: &StateStore,
    helper: &dyn HelperChannel,
    usb_source: &dyn UsbNcmSource,
    reconcile_kick: &Notify,
    up: bool,
) -> ReplyOutcome {
    store.mutate(|s| s.bridge.desired_up = up).await;

    match reconcile::drive_once(store, helper, usb_source).await {
        Ok((snapshot, _ran)) => ReplyOutcome::Ok { snapshot },
        Err(outcome) => {
            reconcile_kick.notify_one();
            outcome
        }
    }
}
