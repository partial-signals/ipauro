//! Reconcile skeleton — the seed of the later desired-state reconciler
//! (`@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)`: "A
//! Kubernetes-style reconcile loop driving actual → desired network state
//! ... event-driven ... with a periodic poll backstop"). This crate only
//! owns the bridge desired/actual pair; the fuller reconciler (membership,
//! addressing, pf scope, spanning-tree pruning) lands with later milestones.

use std::sync::Arc;
use std::time::Duration;

use ipauro_proto::helper::HelperRequest;
use tokio::sync::{broadcast, Notify};

use crate::commands::apply_bridge_action;
use crate::helper_channel::HelperChannel;
use crate::state_store::StateStore;

/// Backstop poll cadence when nothing has kicked the loop awake.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// First retry delay after a failed drive attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Cap on the doubling backoff so a persistently-failing helper doesn't push
/// retries out arbitrarily far.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Pure decision: does actual need to move, and which way? Split out from
/// the async loop so it's unit-testable without a runtime.
pub fn reconcile_action(desired_up: bool, actual_present: bool) -> Option<HelperRequest> {
    match (desired_up, actual_present) {
        (true, false) => Some(HelperRequest::CreateBridge),
        (false, true) => Some(HelperRequest::DestroyBridge),
        (true, true) | (false, false) => None,
    }
}

/// Capped exponential backoff, doubling each failed retry.
pub fn next_backoff(current: Duration) -> Duration {
    std::cmp::min(current * 2, MAX_BACKOFF)
}

/// Background task. Wakes on `kick` (a failed command elsewhere wants a
/// faster retry than the poll backstop), its own poll interval, or shutdown.
/// Retries with capped backoff while actual != desired.
pub async fn run(
    store: Arc<StateStore>,
    helper: Arc<dyn HelperChannel>,
    kick: Arc<Notify>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        tokio::select! {
            _ = shutdown.recv() => return,
            _ = kick.notified() => {}
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }

        let snapshot = store.snapshot().await;
        let request = match reconcile_action(snapshot.bridge.desired_up, snapshot.bridge.actual.is_some()) {
            Some(request) => request,
            None => {
                backoff = INITIAL_BACKOFF;
                continue;
            }
        };

        let up = match request {
            HelperRequest::CreateBridge => true,
            HelperRequest::DestroyBridge => false,
            // reconcile_action's match arms above only ever produce
            // Create/DestroyBridge.
            HelperRequest::Ping | HelperRequest::Status => {
                unreachable!("reconcile_action never returns {request:?}")
            }
        };

        log::debug!("reconcile: driving actual toward desired (up={up})");
        match apply_bridge_action(&store, helper.as_ref(), up).await {
            Ok(_) => backoff = INITIAL_BACKOFF,
            Err(_outcome) => {
                log::warn!("reconcile attempt failed, retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_desired_needs_no_action() {
        assert_eq!(reconcile_action(true, true), None);
        assert_eq!(reconcile_action(false, false), None);
    }

    #[test]
    fn desired_up_but_absent_creates() {
        assert_eq!(reconcile_action(true, false), Some(HelperRequest::CreateBridge));
    }

    #[test]
    fn desired_down_but_present_destroys() {
        assert_eq!(reconcile_action(false, true), Some(HelperRequest::DestroyBridge));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut backoff = INITIAL_BACKOFF;
        for _ in 0..10 {
            backoff = next_backoff(backoff);
            assert!(backoff <= MAX_BACKOFF);
        }
        assert_eq!(backoff, MAX_BACKOFF);
    }

    #[test]
    fn backoff_starts_below_cap() {
        assert_eq!(next_backoff(INITIAL_BACKOFF), INITIAL_BACKOFF * 2);
    }
}
