//! Helper-liveness supervision: a [`HelperChannel`] decorator that keeps the
//! snapshot's `HelperState` honest and notices a helper that isn't the one
//! this build installed.
//!
//! Both behaviors come from the M1 single-Mac field verification (R005-T10):
//!
//! - **Freshness (finding 4).** `HelperState::Connected` was written exactly
//!   once, by `serve`'s boot ping. A helper that became reachable later — the
//!   user approving registration, launchd respawning the daemon — kept
//!   showing "registered (not connected)" in `ipauro status` while requests
//!   were flowing through it. Liveness is a property of *every* exchange, so
//!   it is observed here, at the one place every exchange passes through,
//!   rather than at one lifecycle moment.
//! - **Staleness (finding 1).** launchd keeps the resident helper process
//!   alive across a bundle replacement, so a newly-installed core talks to
//!   the PREVIOUS build until registration is cycled — observed as an M0
//!   helper answering `bad request: unknown variant` to M1 verbs. Every
//!   identification here compares the helper's reported build against
//!   [`crate::build_version`] and cycles registration on a mismatch.
//!
//! Identification is re-run on every reconnect, not just at boot: any failed
//! request clears the cached version, so the next success re-`Ping`s. That is
//! precisely the upgrade shape — the bundle swap kills the connection, and
//! the check lands on the very next request without waiting for a restart.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ipauro_proto::helper::{HelperRequest, HelperResponse};
use ipauro_proto::state::HelperState;

use crate::helper_channel::HelperChannel;
use crate::registrar::HelperRegistrar;
use crate::state_store::StateStore;

/// Wraps the real channel with liveness observation and the stale-helper
/// check. Transparent: it forwards every request and returns every response
/// unchanged, so callers (`reconcile`, `commands`) are unaware of it.
pub struct SupervisedHelper {
    inner: Arc<dyn HelperChannel>,
    store: Arc<StateStore>,
    registrar: Arc<dyn HelperRegistrar>,
    /// What a helper from THIS build answers `Ping` with.
    expected_version: String,
    identity: Mutex<Identity>,
}

/// What we currently know about the helper on the other end. Plain
/// `std::sync::Mutex`: only ever locked for a field read/write, never across
/// an `.await`.
#[derive(Default)]
struct Identity {
    /// Version from the most recent `Pong`. `None` before the first one, and
    /// again after any failed request — a cleared version is what re-arms the
    /// identity check on reconnect.
    version: Option<String>,
    /// Stale versions registration has already been cycled for. A bounce that
    /// doesn't fix the mismatch (two installs, a helper launchd refuses to
    /// reload) leaves the helper reporting the SAME string, so keying on it
    /// bounces once per distinct stale build instead of once per request.
    bounced: Vec<String>,
}

impl SupervisedHelper {
    pub fn new(
        inner: Arc<dyn HelperChannel>,
        store: Arc<StateStore>,
        registrar: Arc<dyn HelperRegistrar>,
    ) -> Self {
        Self {
            inner,
            store,
            registrar,
            expected_version: crate::build_version(),
            identity: Mutex::new(Identity::default()),
        }
    }

    fn known_version(&self) -> Option<String> {
        self.identity.lock().expect("identity mutex poisoned").version.clone()
    }

    /// Records that we are about to bounce for `version`; `false` if we
    /// already did.
    fn claim_bounce(&self, version: &str) -> bool {
        let mut identity = self.identity.lock().expect("identity mutex poisoned");
        if identity.bounced.iter().any(|v| v == version) {
            return false;
        }
        identity.bounced.push(version.to_string());
        true
    }

    fn forget_version(&self) {
        self.identity.lock().expect("identity mutex poisoned").version = None;
    }

    fn remember_version(&self, version: &str) {
        self.identity.lock().expect("identity mutex poisoned").version =
            Some(version.to_string());
    }

    /// A `Pong` arrived: check the helper's build against ours, then publish.
    async fn observe_identity(&self, version: String) {
        if version != self.expected_version {
            if self.claim_bounce(&version) {
                log::warn!(
                    "helper reports build {version} but this core is {} — launchd kept a stale \
                     helper across a bundle replacement; cycling its registration",
                    self.expected_version
                );
                self.bounce().await;
                // The daemon we were talking to is gone (or about to be):
                // drop the identity so the next successful request re-checks,
                // and report registration state rather than a connection that
                // no longer exists.
                self.forget_version();
                let status = self.registrar.status();
                self.publish(status).await;
                return;
            }
            // Already bounced for this one and it's still here. Say so
            // plainly and keep the wire-visible state honest: we ARE
            // connected, to the wrong build.
            log::warn!(
                "helper is still build {version} (expected {}) after a registration cycle — \
                 reinstall or `launchctl bootout system/{}` by hand",
                self.expected_version,
                ipauro_proto::ids::HELPER_LABEL
            );
        }
        self.remember_version(&version);
        self.publish(HelperState::Connected { version }).await;
    }

    /// A non-`Pong` request succeeded, so the helper is live by definition.
    async fn observe_success(&self) {
        if let Some(version) = self.known_version() {
            self.publish(HelperState::Connected { version }).await;
            return;
        }
        // Live, but unidentified — the first success after boot or after a
        // reconnect. One `Ping` settles both the version the snapshot shows
        // and the staleness check.
        match self.inner.request(HelperRequest::Ping).await {
            Ok(HelperResponse::Pong { version }) => self.observe_identity(version).await,
            Ok(other) => log::warn!("helper answered an identity Ping with {other:?}"),
            Err(e) => log::debug!("identity Ping after a successful request failed: {e}"),
        }
    }

    /// A request failed at the channel level: the connection is gone. Fall
    /// back to what the OS says about registration — the same answer
    /// `serve`'s boot probe used to produce on its own.
    async fn observe_failure(&self) {
        self.forget_version();
        let status = self.registrar.status();
        self.publish(status).await;
    }

    /// Unregister + re-register, which is what makes launchd drop the
    /// resident daemon and start the newly-installed binary.
    ///
    /// Both halves are best-effort: outside a signed bundle (a dev run) they
    /// fail by design, and the log line is the whole point there. Note the
    /// deliberate cost — unregistering kills the helper, whose fail-open
    /// grace window then restores stock networking. That is the right trade
    /// for a helper that cannot service current verbs anyway, but it does
    /// mean an automatic bounce briefly drops the data plane, and can leave
    /// registration in `RequiresApproval` (which the snapshot then shows).
    async fn bounce(&self) {
        if let Err(e) = self.registrar.unregister().await {
            log::warn!("stale-helper bounce: unregister failed: {e:#}");
        }
        if let Err(e) = self.registrar.register().await {
            log::warn!("stale-helper bounce: re-register failed: {e:#}");
        }
    }

    async fn publish(&self, state: HelperState) {
        self.store.mutate_if_changed(move |s| s.helper = state).await;
    }
}

#[async_trait]
impl HelperChannel for SupervisedHelper {
    async fn request(&self, req: HelperRequest) -> anyhow::Result<HelperResponse> {
        let response = self.inner.request(req).await;
        // Every `HelperResponse` variant by name (house rule): a `Pong`
        // identifies the peer, any other success only proves it is live, and
        // an `Err` is the HELPER talking — which still proves liveness, so it
        // is deliberately NOT treated as a disconnect. Only a channel-level
        // failure is.
        match &response {
            Ok(HelperResponse::Pong { version }) => self.observe_identity(version.clone()).await,
            Ok(HelperResponse::Ok)
            | Ok(HelperResponse::Bridge { .. })
            | Ok(HelperResponse::Report { .. })
            | Ok(HelperResponse::Err { .. }) => self.observe_success().await,
            Err(_) => self.observe_failure().await,
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use ipauro_proto::helper::BRIDGE_NAME;

    use crate::helper_channel::{MockHelper, NullHelper};

    /// Registrar that counts lifecycle calls and reports a scripted status —
    /// the stub registrar can't distinguish "was asked to re-register" from
    /// "was never asked".
    #[derive(Default)]
    struct CountingRegistrar {
        registers: AtomicUsize,
        unregisters: AtomicUsize,
    }

    #[async_trait]
    impl HelperRegistrar for CountingRegistrar {
        async fn register(&self) -> anyhow::Result<()> {
            self.registers.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn unregister(&self) -> anyhow::Result<()> {
            self.unregisters.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn status(&self) -> HelperState {
            HelperState::Registered
        }
    }

    fn supervised(
        inner: Arc<dyn HelperChannel>,
    ) -> (Arc<StateStore>, Arc<CountingRegistrar>, SupervisedHelper) {
        let store = Arc::new(StateStore::new(crate::initial_snapshot()));
        let registrar = Arc::new(CountingRegistrar::default());
        let helper = SupervisedHelper::new(
            inner,
            store.clone(),
            registrar.clone() as Arc<dyn HelperRegistrar>,
        );
        (store, registrar, helper)
    }

    async fn helper_state(store: &StateStore) -> HelperState {
        store.snapshot().await.helper
    }

    #[tokio::test]
    async fn a_plain_successful_request_marks_the_helper_connected() {
        // Finding 4: no Ping in sight — a CreateBridge that worked is proof
        // enough that the helper is live.
        let (store, _registrar, helper) = supervised(Arc::new(MockHelper::new()));
        assert_eq!(helper_state(&store).await, HelperState::NotRegistered);

        helper.request(HelperRequest::CreateBridge).await.unwrap();

        assert_eq!(
            helper_state(&store).await,
            HelperState::Connected { version: crate::build_version() }
        );
    }

    #[tokio::test]
    async fn an_unidentified_helper_is_pinged_exactly_once() {
        let mock = Arc::new(MockHelper::new());
        let (_store, _registrar, helper) = supervised(mock.clone());

        helper.request(HelperRequest::CreateBridge).await.unwrap();
        helper.request(HelperRequest::ClearScopes).await.unwrap();

        let pings =
            mock.requests().iter().filter(|r| **r == HelperRequest::Ping).count();
        assert_eq!(pings, 1, "the version is cached; only the first success pays for a Ping");
    }

    #[tokio::test]
    async fn a_helper_error_still_counts_as_live() {
        // The helper REFUSING something proves it is there — this is the M0
        // -vs-M1 shape ("bad request: unknown variant"), and treating it as a
        // disconnect would be the same lie finding 4 is about.
        let mock = Arc::new(MockHelper::new());
        mock.reject(HelperRequest::ClearScopes);
        let (store, _registrar, helper) = supervised(mock);

        helper.request(HelperRequest::ClearScopes).await.unwrap();

        assert!(matches!(helper_state(&store).await, HelperState::Connected { .. }));
    }

    #[tokio::test]
    async fn a_failed_request_falls_back_to_registration_status() {
        let (store, _registrar, helper) = supervised(Arc::new(NullHelper));
        assert!(helper.request(HelperRequest::Report).await.is_err());
        assert_eq!(helper_state(&store).await, HelperState::Registered);
    }

    #[tokio::test]
    async fn a_stale_helper_bounces_registration_once_not_once_per_request() {
        // Finding 1: the resident helper is from another build.
        let mock = Arc::new(MockHelper::with_version("0.0.1+an-older-build"));
        let (store, registrar, helper) = supervised(mock.clone());

        helper.request(HelperRequest::Ping).await.unwrap();
        assert_eq!(registrar.unregisters.load(Ordering::SeqCst), 1);
        assert_eq!(registrar.registers.load(Ordering::SeqCst), 1);
        assert_eq!(
            helper_state(&store).await,
            HelperState::Registered,
            "the connection we bounced is gone; report registration state, not Connected"
        );

        // A bounce that didn't take must not turn into a bounce-per-request
        // loop — but the state must then say plainly what we're talking to.
        helper.request(HelperRequest::Ping).await.unwrap();
        assert_eq!(registrar.unregisters.load(Ordering::SeqCst), 1, "bounced once per build");
        assert_eq!(
            helper_state(&store).await,
            HelperState::Connected { version: "0.0.1+an-older-build".into() }
        );
    }

    #[tokio::test]
    async fn a_matching_helper_is_never_bounced() {
        let (store, registrar, helper) = supervised(Arc::new(MockHelper::new()));
        helper.request(HelperRequest::Ping).await.unwrap();
        assert_eq!(registrar.unregisters.load(Ordering::SeqCst), 0);
        assert_eq!(
            helper_state(&store).await,
            HelperState::Connected { version: crate::build_version() }
        );
    }

    #[tokio::test]
    async fn a_reconnect_re_identifies_the_helper() {
        // The upgrade shape: requests fail while the bundle is swapped, then
        // succeed again against a helper nobody has identified yet.
        let mock = Arc::new(MockHelper::new());
        let (_store, _registrar, helper) = supervised(mock.clone());
        helper.request(HelperRequest::CreateBridge).await.unwrap();

        // Simulate the connection dropping: a channel-level failure clears
        // the cached identity.
        helper.observe_failure().await;

        helper
            .request(HelperRequest::ScopeUdp {
                port: 20808,
                allowed_ifaces: vec![BRIDGE_NAME.to_string()],
            })
            .await
            .unwrap();

        let pings = mock.requests().iter().filter(|r| **r == HelperRequest::Ping).count();
        assert_eq!(pings, 2, "identity must be re-checked after a reconnect, not assumed");
    }

    #[tokio::test]
    async fn responses_pass_through_untouched() {
        let (_store, _registrar, helper) = supervised(Arc::new(MockHelper::new()));
        let resp = helper.request(HelperRequest::Report).await.unwrap();
        assert!(matches!(resp, HelperResponse::Report { .. }));
    }
}
