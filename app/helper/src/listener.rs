//! The XPC mach-service listener: accepts peer connections, authenticates
//! them BEFORE any message is parsed (ticket R002-T3), and speaks the wire
//! format (one dictionary, single key `"msg"` holding serde_json bytes of
//! [`HelperRequest`] / [`HelperResponse`]).
//!
//! Peer authentication: [`xpc_connection_set_peer_code_signing_requirement`]
//! is applied to every accepted peer connection immediately, before its own
//! event handler is even installed. Once applied, libxpc itself silently
//! drops any message that doesn't satisfy the requirement — our code never
//! sees the bytes of an unauthenticated message, satisfying "authenticate
//! the caller before parsing anything" structurally rather than by manual
//! checking. `IPAURO_INSECURE_DEV=1` skips this for unsigned dev builds (a
//! loud warning is logged at startup and on every connection while active).
//!
//! Block lifetime: every `RcBlock` handed to
//! `xpc_connection_set_event_handler` is dropped immediately after the
//! `set_event_handler` + `resume` pair. This is safe — libxpc keeps its own
//! retained copy of the block (standard Blocks-runtime copy-on-store
//! semantics), which was verified empirically before writing this module: a
//! block dropped on the Rust side immediately after being registered still
//! fired correctly when a real event arrived later.

use crate::executor::BridgeExecutor;
use crate::failopen::{Action, FailOpen};
use crate::request::handle_request;
use crate::xpc_sys::{self, classify_event, SendableXpcObject, XpcConnection, XpcEvent, XpcObject};
use anyhow::{anyhow, Context, Result};
use block2::RcBlock;
use ipauro_proto::helper::{HelperRequest, HelperResponse, FAILOPEN_GRACE_SECS, INSECURE_DEV_ENV};
use ipauro_proto::ids::HELPER_LABEL;
use std::ffi::CString;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shared daemon state: the bridge executor, the fail-open timer, and
/// whether peer authentication is disabled (dev builds only).
pub struct HelperState {
    executor: Arc<dyn BridgeExecutor>,
    failopen: Mutex<FailOpen>,
    insecure_dev: bool,
    requirement: CString,
}

impl HelperState {
    pub fn new(executor: Arc<dyn BridgeExecutor>, insecure_dev: bool) -> Self {
        Self {
            executor,
            failopen: Mutex::new(FailOpen::new(Duration::from_secs(FAILOPEN_GRACE_SECS))),
            insecure_dev,
            requirement: CString::new(ipauro_proto::helper::peer_requirement())
                .expect("peer_requirement() must not contain NUL bytes"),
        }
    }
}

/// Create the mach-service listener (named per [`HELPER_LABEL`]; the actual
/// mach service registration lives in launchd's plist, not here), accept
/// connections forever, and spawn the fail-open grace-window driver. Returns
/// once set up; the caller is expected to block on `dispatch_main()`
/// afterward so the process stays alive to service events.
pub fn run(state: &Arc<HelperState>) -> Result<()> {
    let label = CString::new(HELPER_LABEL).context("HELPER_LABEL must not contain NUL bytes")?;

    let listener: XpcConnection = unsafe {
        xpc_sys::xpc_connection_create_mach_service(
            label.as_ptr(),
            ptr::null_mut(),
            xpc_sys::XPC_CONNECTION_MACH_SERVICE_LISTENER,
        )
    };
    if listener.is_null() {
        return Err(anyhow!("xpc_connection_create_mach_service({HELPER_LABEL}) returned NULL"));
    }

    let accept_state = Arc::clone(state);
    let handler = RcBlock::new(move |event: XpcObject| {
        on_listener_event(&accept_state, event);
    });
    unsafe {
        xpc_sys::xpc_connection_set_event_handler(listener, &handler);
        xpc_sys::xpc_connection_resume(listener);
    }
    // See module docs: safe to drop here, libxpc retains its own copy. The
    // listener connection itself is intentionally never released — it lives
    // for the process's whole lifetime.
    drop(handler);

    spawn_failopen_driver(Arc::clone(state));

    log::info!("listening on mach service {HELPER_LABEL}");
    Ok(())
}

fn on_listener_event(state: &Arc<HelperState>, event: XpcObject) {
    match classify_event(event, true) {
        XpcEvent::NewConnection(peer) => accept_peer(state, peer),
        XpcEvent::ConnectionInvalid => {
            log::error!("listener's own mach-service connection went invalid");
        }
        XpcEvent::ConnectionInterrupted => log::warn!("listener connection interrupted"),
        XpcEvent::TerminationImminent => log::warn!("termination imminent (listener)"),
        XpcEvent::PeerCodeSigningRequirementFailed => {
            // Not expected here (the requirement is set per accepted peer
            // connection, not on the listener itself), but never silently
            // drop an enum variant — log if the runtime ever surfaces it.
            log::warn!("unexpected peer-code-signing-requirement event on the listener");
        }
        XpcEvent::Message(_) => log::warn!("listener received a message event (unexpected)"),
        XpcEvent::Unknown => log::warn!("unrecognized event on the listener connection"),
    }
}

fn accept_peer(state: &Arc<HelperState>, peer: XpcConnection) {
    if state.insecure_dev {
        log::warn!("{INSECURE_DEV_ENV}=1 — accepting peer WITHOUT code-signing validation");
    } else {
        let rc = unsafe {
            xpc_sys::xpc_connection_set_peer_code_signing_requirement(peer, state.requirement.as_ptr())
        };
        if rc != 0 {
            log::error!(
                "xpc_connection_set_peer_code_signing_requirement failed (rc={rc}); refusing peer"
            );
            unsafe { xpc_sys::xpc_connection_cancel(peer) };
            return;
        }
    }

    let pid = unsafe { xpc_sys::xpc_connection_get_pid(peer) };
    log::info!("accepted peer connection (pid {pid})");

    state.failopen.lock().expect("failopen mutex poisoned").on_connect();

    let peer_sendable = SendableXpcObject(peer);
    let disconnected = Arc::new(AtomicBool::new(false));
    let msg_state = Arc::clone(state);
    let msg_disconnected = Arc::clone(&disconnected);
    let handler = RcBlock::new(move |event: XpcObject| {
        on_peer_event(&msg_state, peer_sendable, &msg_disconnected, event);
    });
    unsafe {
        xpc_sys::xpc_connection_set_event_handler(peer, &handler);
        xpc_sys::xpc_connection_resume(peer);
    }
    drop(handler); // see module docs: libxpc retains its own copy
}

fn on_peer_event(
    state: &Arc<HelperState>,
    peer: SendableXpcObject,
    disconnected: &Arc<AtomicBool>,
    event: XpcObject,
) {
    match classify_event(event, false) {
        XpcEvent::Message(dict) => handle_message(state, peer.0, dict),
        XpcEvent::ConnectionInvalid | XpcEvent::ConnectionInterrupted => {
            mark_disconnected(state, disconnected);
        }
        XpcEvent::TerminationImminent => log::warn!("termination imminent (peer connection)"),
        XpcEvent::PeerCodeSigningRequirementFailed => {
            log::warn!("a message from this peer failed the code-signing requirement; dropped by libxpc");
        }
        XpcEvent::NewConnection(_) => {
            log::warn!("peer connection received a new-connection event (unexpected)");
        }
        XpcEvent::Unknown => log::warn!("unrecognized event on a peer connection"),
    }
}

fn mark_disconnected(state: &Arc<HelperState>, disconnected: &Arc<AtomicBool>) {
    // A connection can report both INTERRUPTED and INVALID over its
    // lifetime; only the first transition should count as a disconnect.
    if disconnected.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut failopen = state.failopen.lock().expect("failopen mutex poisoned");
    failopen.on_disconnect(Instant::now());
    log::info!("peer disconnected; {} authenticated connection(s) remain", failopen.live_connections());
}

fn handle_message(state: &Arc<HelperState>, peer: XpcConnection, dict: XpcObject) {
    let bytes = match get_data(dict, c"msg") {
        Some(b) => b,
        None => {
            log::warn!("message dictionary missing the \"msg\" key; dropping");
            return;
        }
    };
    let request: HelperRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("failed to parse HelperRequest: {e}");
            reply(peer, dict, &HelperResponse::Err { message: format!("bad request: {e}") });
            return;
        }
    };
    log::debug!("request: {request:?}");
    let response = handle_request(state.executor.as_ref(), request);
    reply(peer, dict, &response);
}

fn get_data(dict: XpcObject, key: &std::ffi::CStr) -> Option<Vec<u8>> {
    let mut len: usize = 0;
    let ptr = unsafe { xpc_sys::xpc_dictionary_get_data(dict, key.as_ptr(), &mut len as *mut usize) };
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
}

fn reply(peer: XpcConnection, original: XpcObject, response: &HelperResponse) {
    let bytes = match serde_json::to_vec(response) {
        Ok(b) => b,
        Err(e) => {
            log::error!("failed to serialize HelperResponse: {e}");
            return;
        }
    };
    let reply_dict = unsafe { xpc_sys::xpc_dictionary_create_reply(original) };
    if reply_dict.is_null() {
        log::error!("xpc_dictionary_create_reply returned NULL; cannot reply");
        return;
    }
    unsafe {
        xpc_sys::xpc_dictionary_set_data(
            reply_dict,
            c"msg".as_ptr(),
            bytes.as_ptr() as *const std::ffi::c_void,
            bytes.len(),
        );
        xpc_sys::xpc_connection_send_message(peer, reply_dict);
        xpc_sys::xpc_release(reply_dict);
    }
}

/// Background driver for the (pure, unit-tested) [`FailOpen`] state machine:
/// polls once a second and destroys the bridge if the grace window elapses
/// with no authenticated connection.
fn spawn_failopen_driver(state: Arc<HelperState>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let action = state.failopen.lock().expect("failopen mutex poisoned").poll(Instant::now());
        if action == Action::Destroy {
            log::warn!("fail-open: grace window elapsed with no authenticated connection — destroying bridge");
            if let Err(e) = state.executor.destroy() {
                log::error!("fail-open destroy failed: {e:#}");
            }
        }
    });
}
