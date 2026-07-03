//! The real XPC-backed [`HelperChannel`]: connects to the privileged helper's
//! mach service (`ipauro_proto::ids::HELPER_LABEL`) and exchanges
//! `HelperRequest`/`HelperResponse` as serde_json bytes under the `"msg"`
//! dictionary key — the wire convention pinned in `ipauro_proto::helper` and
//! implemented by `app/helper`'s listener.
//!
//! Connection lifecycle: created lazily on first request. After
//! `ConnectionInterrupted` (helper crashed/restarted) the handle stays usable —
//! launchd owns the mach service name, so the next send respawns the helper on
//! demand. After `ConnectionInvalid` (name unregistered / peer requirement
//! problems) the handle is dropped and the next request reconnects from
//! scratch.

use async_trait::async_trait;
use ipauro_proto::helper::{HelperRequest, HelperResponse};
use ipauro_proto::ids::HELPER_LABEL;
use ipauro_xpc::{
    classify_event, xpc_connection_create_mach_service, xpc_connection_resume,
    xpc_connection_send_message_with_reply_sync, xpc_connection_set_event_handler,
    xpc_dictionary_create, xpc_dictionary_get_data, xpc_dictionary_set_data, xpc_release,
    SendableXpcObject, XpcEvent, XpcObject, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED,
};
use std::ffi::CString;
use std::ptr;
use std::sync::{Arc, Mutex};

use crate::helper_channel::HelperChannel;

/// Lazily-established connection; `None` until first use or after a
/// `ConnectionInvalid`. The `Mutex` also serializes requests — the helper
/// protocol is strictly request/reply, so concurrency buys nothing.
type SharedConn = Arc<Mutex<Option<SendableXpcObject>>>;

pub struct XpcHelper {
    conn: SharedConn,
}

impl XpcHelper {
    pub fn new() -> Self {
        Self { conn: Arc::new(Mutex::new(None)) }
    }

    fn connect() -> anyhow::Result<SendableXpcObject> {
        let name = CString::new(HELPER_LABEL).expect("label has no NUL");
        // Production: the helper is a launchd *daemon* (system domain), which
        // requires the PRIVILEGED lookup flag. Dev-only escape hatch: when
        // IPAURO_HELPER_USER_DOMAIN=1, look up in the caller's own domain so a
        // no-sudo dev loop can run the helper as a gui-domain agent (paired
        // with the helper's own IPAURO_INSECURE_DEV; never set in a real
        // install).
        let user_domain =
            std::env::var("IPAURO_HELPER_USER_DOMAIN").map(|v| v == "1").unwrap_or(false);
        let flags = if user_domain {
            log::warn!("IPAURO_HELPER_USER_DOMAIN=1 — looking up helper in the user domain (dev only)");
            0
        } else {
            XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
        };
        let conn = unsafe { xpc_connection_create_mach_service(name.as_ptr(), ptr::null_mut(), flags) };
        if conn.is_null() {
            anyhow::bail!("xpc_connection_create_mach_service returned null");
        }
        // A handler must be installed before resume. Replies flow through
        // send_message_with_reply_sync, so this only ever observes errors.
        let handler = block2::RcBlock::new(move |event: XpcObject| {
            match classify_event(event, false) {
                XpcEvent::ConnectionInterrupted => {
                    log::warn!("helper connection interrupted (helper restarted?)");
                }
                XpcEvent::ConnectionInvalid => {
                    log::warn!("helper connection invalid (helper not registered?)");
                }
                XpcEvent::PeerCodeSigningRequirementFailed
                | XpcEvent::TerminationImminent
                | XpcEvent::Message(_)
                | XpcEvent::NewConnection(_)
                | XpcEvent::Unknown => {
                    // Nothing actionable outside a request in flight; requests
                    // observe their own errors via the sync reply.
                    log::debug!("helper connection event: {:?}", classify_event(event, false));
                }
            }
        });
        unsafe {
            xpc_connection_set_event_handler(conn, &handler);
            xpc_connection_resume(conn);
        }
        Ok(SendableXpcObject(conn))
    }

    /// Blocking request/reply round trip. Runs on the blocking pool.
    fn request_sync(conn_slot: &SharedConn, req: &HelperRequest) -> anyhow::Result<HelperResponse> {
        let mut guard = conn_slot.lock().expect("xpc conn mutex poisoned");
        let conn = match *guard {
            Some(c) => c,
            None => {
                let c = Self::connect()?;
                *guard = Some(c);
                c
            }
        };

        let bytes = serde_json::to_vec(req)?;
        let reply = unsafe {
            let dict = xpc_dictionary_create(ptr::null(), ptr::null(), 0);
            xpc_dictionary_set_data(dict, c"msg".as_ptr(), bytes.as_ptr().cast(), bytes.len());
            let reply = xpc_connection_send_message_with_reply_sync(conn.0, dict);
            xpc_release(dict);
            reply
        };

        match classify_event(reply, false) {
            XpcEvent::Message(dict) => {
                let mut len: usize = 0;
                let data =
                    unsafe { xpc_dictionary_get_data(dict, c"msg".as_ptr(), &mut len as *mut usize) };
                let parsed = if data.is_null() {
                    Err(anyhow::anyhow!("helper reply missing \"msg\" key"))
                } else {
                    let slice = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
                    serde_json::from_slice::<HelperResponse>(slice).map_err(Into::into)
                };
                // Owned reply (+1 from the sync send); error singletons below
                // are immortal globals and are deliberately NOT released.
                unsafe { xpc_release(dict) };
                parsed
            }
            XpcEvent::ConnectionInterrupted => {
                // Connection stays usable; launchd respawns the helper on the
                // next send. Surface the failure so the reconcile loop retries.
                anyhow::bail!("helper request interrupted (helper restarting)")
            }
            XpcEvent::ConnectionInvalid => {
                *guard = None;
                anyhow::bail!("helper not reachable (service not registered?)")
            }
            XpcEvent::PeerCodeSigningRequirementFailed => {
                *guard = None;
                anyhow::bail!("helper rejected our code signature")
            }
            XpcEvent::TerminationImminent | XpcEvent::NewConnection(_) | XpcEvent::Unknown => {
                *guard = None;
                anyhow::bail!("unexpected XPC reply event")
            }
        }
    }
}

impl Default for XpcHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HelperChannel for XpcHelper {
    async fn request(&self, req: HelperRequest) -> anyhow::Result<HelperResponse> {
        let conn_slot = self.conn.clone();
        tokio::task::spawn_blocking(move || Self::request_sync(&conn_slot, &req))
            .await
            .map_err(|e| anyhow::anyhow!("helper request task panicked: {e}"))?
    }
}
