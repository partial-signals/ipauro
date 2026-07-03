//! The second, smaller helper-lifecycle seam: `RegisterHelper`/`UnregisterHelper`
//! drive `SMAppService`, which requires an installed app-bundle context (an
//! Info.plist, a code-signed `.app`) that a bare `cargo run` binary doesn't
//! have. Kept as its own trait — separate from [`crate::helper_channel::HelperChannel`],
//! which talks to an *already-registered* helper over XPC — because
//! registration is a packaging concern, not a request/response protocol.

use async_trait::async_trait;
use ipauro_proto::state::HelperState;

#[async_trait]
pub trait HelperRegistrar: Send + Sync {
    async fn register(&self) -> anyhow::Result<()>;
    async fn unregister(&self) -> anyhow::Result<()>;
    /// Registration state as the OS reports it right now (never `Connected` —
    /// liveness is the HelperChannel's to observe, not the registrar's).
    fn status(&self) -> HelperState;
}

/// Stub used until packaging supplies the real `SMAppService`-backed
/// implementation. Logs the attempt and reports the reason plainly so it's
/// obvious in a dev build why `RegisterHelper`/`UnregisterHelper` never
/// succeed outside the installed app.
pub struct StubHelperRegistrar;

#[async_trait]
impl HelperRegistrar for StubHelperRegistrar {
    async fn register(&self) -> anyhow::Result<()> {
        log::info!("RegisterHelper requested; stub registrar cannot register a helper");
        anyhow::bail!("registering the helper requires an installed app bundle (SMAppService)")
    }

    async fn unregister(&self) -> anyhow::Result<()> {
        log::info!("UnregisterHelper requested; stub registrar cannot unregister a helper");
        anyhow::bail!("unregistering the helper requires an installed app bundle (SMAppService)")
    }

    fn status(&self) -> HelperState {
        // The stub can never have registered anything.
        HelperState::NotRegistered
    }
}
