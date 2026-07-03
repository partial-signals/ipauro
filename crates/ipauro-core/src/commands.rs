//! Command dispatch: turns a client [`Command`] into state-store mutations,
//! helper-channel calls, and a [`ReplyOutcome`].

use ipauro_proto::helper::{HelperRequest, HelperResponse};
use ipauro_proto::ipc::{Command, ErrorCode, ErrorInfo, ReplyOutcome};
use ipauro_proto::state::Snapshot;
use tokio::sync::Notify;

use crate::helper_channel::HelperChannel;
use crate::registrar::HelperRegistrar;
use crate::state_store::StateStore;

fn err(code: ErrorCode, message: impl Into<String>) -> ReplyOutcome {
    ReplyOutcome::Err { error: ErrorInfo { code, message: message.into() } }
}

/// Handle one command. Every [`Command`] variant is matched by name (no
/// catch-all) per house rule on enum discipline.
pub async fn handle(
    store: &StateStore,
    helper: &dyn HelperChannel,
    registrar: &dyn HelperRegistrar,
    reconcile_kick: &Notify,
    command: Command,
) -> ReplyOutcome {
    match command {
        Command::GetSnapshot => ReplyOutcome::Ok { snapshot: store.snapshot().await },
        Command::BridgeUp => drive_bridge(store, helper, reconcile_kick, true).await,
        Command::BridgeDown => drive_bridge(store, helper, reconcile_kick, false).await,
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

/// Set desired, then drive actual toward it via the helper. Desired is
/// persisted *before* the helper is ever touched, so a failed drive still
/// leaves the store in a state `reconcile::run` will retry — and we kick it
/// awake immediately rather than waiting out its poll interval.
async fn drive_bridge(
    store: &StateStore,
    helper: &dyn HelperChannel,
    reconcile_kick: &Notify,
    up: bool,
) -> ReplyOutcome {
    store.mutate(|s| s.bridge.desired_up = up).await;

    match apply_bridge_action(store, helper, up).await {
        Ok(snapshot) => ReplyOutcome::Ok { snapshot },
        Err(outcome) => {
            reconcile_kick.notify_one();
            outcome
        }
    }
}

/// Issue Create/DestroyBridge then Status, folding the result into the
/// store. Shared by the command path (above) and `reconcile::run`'s retry
/// loop, which is why this returns a plain `Result` rather than a
/// `ReplyOutcome` directly wired to a client id.
pub(crate) async fn apply_bridge_action(
    store: &StateStore,
    helper: &dyn HelperChannel,
    up: bool,
) -> Result<Snapshot, ReplyOutcome> {
    let request = if up { HelperRequest::CreateBridge } else { HelperRequest::DestroyBridge };
    match helper.request(request).await {
        Err(e) => Err(err(ErrorCode::HelperNotConnected, e.to_string())),
        Ok(HelperResponse::Err { message }) => Err(err(ErrorCode::HelperRejected, message)),
        Ok(HelperResponse::Ok) => refresh_actual(store, helper).await,
        // Some helper impls may answer Create/Destroy with the bridge state
        // directly; accept it without the extra Status round trip.
        Ok(HelperResponse::Bridge { info }) => Ok(store.mutate(|s| s.bridge.actual = info).await),
        Ok(HelperResponse::Pong { .. }) => {
            Err(err(ErrorCode::Internal, "helper answered Create/DestroyBridge with Pong"))
        }
    }
}

async fn refresh_actual(store: &StateStore, helper: &dyn HelperChannel) -> Result<Snapshot, ReplyOutcome> {
    match helper.request(HelperRequest::Status).await {
        Err(e) => Err(err(ErrorCode::HelperNotConnected, e.to_string())),
        Ok(HelperResponse::Bridge { info }) => Ok(store.mutate(|s| s.bridge.actual = info).await),
        Ok(HelperResponse::Err { message }) => Err(err(ErrorCode::HelperRejected, message)),
        Ok(HelperResponse::Ok) => Err(err(ErrorCode::Internal, "helper answered Status with Ok")),
        Ok(HelperResponse::Pong { .. }) => Err(err(ErrorCode::Internal, "helper answered Status with Pong")),
    }
}
