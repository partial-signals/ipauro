//! The real, macOS-only [`HelperRegistrar`] backed by Apple's `SMAppService`
//! (ServiceManagement framework, macOS 13+). Drives registration of the
//! privileged helper daemon (`ipauro_proto::ids::HELPER_LABEL`), whose launchd
//! plist is embedded at `Contents/Library/LaunchDaemons/io.ipauro.helper.plist`
//! inside the running app bundle (see `packaging/build-app.sh` step 4 and
//! `packaging/README.md`).
//!
//! ## The signed-bundle requirement — read this before filing a bug
//!
//! `SMAppService::registerAndReturnError`/`unregisterAndReturnError` only
//! succeed when the *calling process itself* is the `CFBundleExecutable` of a
//! properly code-signed `.app` bundle that embeds the referenced plist next
//! to it. A bare `cargo run -p ipauro-core`, a `cargo test` binary, or an
//! unsigned/ad-hoc-signed dev build is not such a bundle, so `register()`/
//! `unregister()` are *expected* to fail there — typically with an `NSError`
//! whose code is 1 ("Operation not permitted") or similar. That failure is
//! not a bug in this module; it's Apple's API refusing to trust a caller it
//! can't attribute to an installed app. [`SmAppServiceRegistrar::register`]
//! and [`SmAppServiceRegistrar::unregister`] surface it as a plain,
//! non-panicking `anyhow::Error` carrying the `NSError`'s localized
//! description, so a dev running outside `dist/IPAuRo.app` sees *why*, rather
//! than a bare "Operation not permitted".
//!
//! `daemonServiceWithPlistName:` takes only the plist's **file name**
//! (`io.ipauro.helper.plist`) — SMAppService resolves it relative to
//! `Contents/Library/LaunchDaemons/` inside the running bundle itself, never
//! an absolute path.
//!
//! Verifying registration for real (the one-time OS approval dialog, the
//! System Settings > General > Login Items & Extensions entry, `launchctl
//! print system/io.ipauro.helper` showing the job loaded) requires running
//! from `dist/IPAuRo.app` assembled + signed by `packaging/build-app.sh` —
//! not reproducible from this crate's test suite. See this module's tests for
//! what *is* covered without a bundle.

use async_trait::async_trait;
use ipauro_proto::ids::HELPER_LABEL;
use ipauro_proto::state::HelperState;
use objc2::rc::Retained;
use objc2_foundation::{NSError, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};

use crate::registrar::HelperRegistrar;

/// `SMAppService`-backed [`HelperRegistrar`] for the privileged helper
/// daemon. Holds no FFI state between calls — each `register`/`unregister`/
/// `status` call builds its own `SMAppService` handle and drops it before
/// returning, so this struct is trivially `Send + Sync` even though
/// `SMAppService` itself is neither (it's a plain Objective-C object with no
/// thread-safety guarantees of its own).
pub struct SmAppServiceRegistrar;

impl SmAppServiceRegistrar {
    pub fn new() -> Self {
        Self
    }

    /// Fresh `SMAppService` handle for the helper daemon's plist. Cheap: this
    /// only wraps the plist name in an Objective-C object, it does not by
    /// itself talk to launchd (registration below does).
    fn service(&self) -> Retained<SMAppService> {
        let plist_name = NSString::from_str(&format!("{HELPER_LABEL}.plist"));
        // Safety: `daemonServiceWithPlistName:` per Apple's docs only reads
        // the given NSString; `plist_name` outlives the call.
        unsafe { SMAppService::daemonServiceWithPlistName(&plist_name) }
    }

    /// Current registration status, mapped to this service's `HelperState`
    /// model. Synchronous and fast — `status` is a local query against
    /// launchd's job table, not a round trip to the helper itself — so unlike
    /// `register`/`unregister` it is not part of the async `HelperRegistrar`
    /// trait. Deliberately kept off the trait entirely: only this concrete
    /// macOS type is meaningful to poll for it (see `registrar.rs`'s module
    /// docs on why registration-status and live-XPC-connection status are
    /// separate seams).
    pub fn status(&self) -> HelperState {
        // Safety: `status` per Apple's docs is a pure property read on a
        // live SMAppService instance; no preconditions beyond the object
        // being valid, which it is (just constructed above).
        map_status(unsafe { self.service().status() })
    }
}

impl Default for SmAppServiceRegistrar {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure mapping from `SMAppServiceStatus` to this service's `HelperState`.
/// Split out from `status()` so it's unit-testable without any FFI.
///
/// `SMAppServiceStatus` is an `NSInteger` newtype (`#[repr(transparent)]`
/// wrapping an integer, with four documented associated constants), not a
/// closed Rust enum — the compiler cannot prove these four constants are
/// exhaustive, and nothing stops a future macOS SDK from adding a fifth. The
/// wildcard arm below is required by the type, not laziness: it logs and
/// folds any value this crate doesn't recognize into `NotRegistered`, the
/// conservative choice that never claims a helper connection this code can't
/// back up.
fn map_status(status: SMAppServiceStatus) -> HelperState {
    match status {
        SMAppServiceStatus::NotRegistered => HelperState::NotRegistered,
        SMAppServiceStatus::Enabled => HelperState::Registered,
        SMAppServiceStatus::RequiresApproval => HelperState::RequiresApproval,
        // "An error occurred and no such service could be found" —
        // functionally indistinguishable from NotRegistered for our purposes.
        SMAppServiceStatus::NotFound => HelperState::NotRegistered,
        unknown => {
            log::warn!("unrecognized SMAppServiceStatus({}); treating as NotRegistered", unknown.0);
            HelperState::NotRegistered
        }
    }
}

/// Renders a failed `register`/`unregister` call's `NSError` into the message
/// this module surfaces. Centralized so both call sites read identically and
/// the "you're not in a signed bundle" framing (see module docs) is spelled
/// out exactly once.
fn bundle_error(verb: &str, e: Retained<NSError>) -> anyhow::Error {
    anyhow::anyhow!(
        "SMAppService {verb} requires running inside the signed IPAuRo.app bundle (got: {})",
        e.localizedDescription()
    )
}

#[async_trait]
impl HelperRegistrar for SmAppServiceRegistrar {
    async fn register(&self) -> anyhow::Result<()> {
        let service = self.service();
        // Safety: `registerAndReturnError:` per Apple's docs synchronously
        // registers the job or returns an NSError; no additional
        // preconditions beyond a valid `service` handle.
        match unsafe { service.registerAndReturnError() } {
            Ok(()) => {
                match map_status(unsafe { service.status() }) {
                    HelperState::RequiresApproval => log::info!(
                        "{HELPER_LABEL} registered; awaiting user approval in \
                         System Settings > General > Login Items & Extensions"
                    ),
                    HelperState::Registered => log::info!("{HELPER_LABEL} registered and enabled"),
                    HelperState::NotRegistered => log::warn!(
                        "{HELPER_LABEL} registerAndReturnError() reported success but status is \
                         still NotRegistered"
                    ),
                    // status() (via map_status) never produces Connected — that
                    // variant is populated from a live XPC ping elsewhere, not
                    // from SMAppService. Unreachable in practice; kept explicit
                    // per house rule on enum coverage rather than a catch-all.
                    HelperState::Connected { .. } => {
                        unreachable!("map_status never returns HelperState::Connected")
                    }
                }
                Ok(())
            }
            Err(e) => Err(bundle_error("registration", e)),
        }
    }

    async fn unregister(&self) -> anyhow::Result<()> {
        let service = self.service();
        // Safety: `unregisterAndReturnError:` per Apple's docs synchronously
        // unregisters the job or returns an NSError.
        match unsafe { service.unregisterAndReturnError() } {
            Ok(()) => {
                log::info!("{HELPER_LABEL} unregistered");
                Ok(())
            }
            Err(e) => Err(bundle_error("unregistration", e)),
        }
    }

    fn status(&self) -> HelperState {
        SmAppServiceRegistrar::status(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_status_covers_every_named_status() {
        assert_eq!(map_status(SMAppServiceStatus::NotRegistered), HelperState::NotRegistered);
        assert_eq!(map_status(SMAppServiceStatus::Enabled), HelperState::Registered);
        assert_eq!(map_status(SMAppServiceStatus::RequiresApproval), HelperState::RequiresApproval);
        assert_eq!(map_status(SMAppServiceStatus::NotFound), HelperState::NotRegistered);
    }

    #[test]
    fn map_status_folds_unrecognized_values_to_not_registered() {
        // Not one of Apple's four documented values — exercises the
        // future-proofing wildcard arm.
        assert_eq!(map_status(SMAppServiceStatus(99)), HelperState::NotRegistered);
    }

    /// Outside a signed app bundle this cannot register anything real (see
    /// module docs) — the point of this test is only that the FFI round trip
    /// through `daemonServiceWithPlistName:` + `status` completes without
    /// panicking, from a bare `cargo test` binary.
    #[test]
    fn status_does_not_panic_outside_a_bundle() {
        let registrar = SmAppServiceRegistrar::new();
        let status = registrar.status();
        match status {
            HelperState::NotRegistered
            | HelperState::Registered
            | HelperState::RequiresApproval
            | HelperState::Connected { .. } => {
                // Any of these is a valid, non-panicking outcome; a bare test
                // binary is expected to report NotRegistered in practice.
            }
        }
    }
}
