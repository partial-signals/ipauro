//! Hand-rolled FFI over Apple's C XPC API (`<xpc/xpc.h>`, `<xpc/connection.h>`).
//!
//! No `xpc`-binding crate on crates.io fit this daemon's shape: the only
//! actively maintained one (`xpc-connection`, wrapping `xpc-connection-sys`)
//! is a CLIENT helper hard-coded to `XPC_CONNECTION_MACH_SERVICE_PRIVILEGED`
//! (see its `connect()`) — it has no path to become the LISTENER side of a
//! mach service, no `xpc_connection_set_peer_code_signing_requirement`, and no
//! dictionary get/set beyond what its own tiny `Message` enum covers. Since we
//! need to *be* the daemon (accept peer connections, authenticate them,
//! exchange raw dictionaries), hand-rolling the handful of C entry points we
//! actually use — per ticket R002-T3's explicitly sanctioned "your choice"
//! between a maintained crate and hand-rolled FFI — is the correct call here,
//! not a shortcut.
//!
//! ## Why `*mut c_void` for every XPC handle
//!
//! Apple's headers define these types via `XPC_DECL`, which — when NOT built
//! as Objective-C (`OS_OBJECT_USE_OBJC == 0`, the ABI a non-ObjC FFI caller
//! must target) — expands to (from `xpc/xpc.h`):
//! ```c
//! typedef void * xpc_object_t;
//! #define XPC_DECL(name) typedef struct _##name##_s * name##_t
//! ```
//! So `xpc_connection_t`, `xpc_endpoint_t`, etc. are *distinct nominal C
//! types*, but every one of them is pointer-sized and freely
//! implicitly-converts to/from `xpc_object_t` in C because `xpc_object_t` is
//! literally `void *` (C permits silent `void*` <-> any-object-pointer
//! conversion). There is no behavioral difference at the ABI level. Rust has
//! no such implicit conversion, so we collapse the whole family to one
//! `XpcObject = *mut c_void` alias and never fight the type checker over a
//! distinction C itself doesn't enforce. This was verified empirically
//! end-to-end (listener creation, block event handler invocation, dictionary
//! set/get round-trip, `xpc_connection_set_peer_code_signing_requirement`
//! returning 0) before committing to this approach.
//!
//! Verified available: macOS 26 (Darwin 25) SDK headers show
//! `xpc_connection_set_peer_code_signing_requirement` as
//! `API_AVAILABLE(macos(12.0))` — earlier than ticket R002-T3's "14.4+"
//! estimate — and it is a plain (non-block) C function, so the primary path
//! is used directly with no SecCode/audit-token fallback (see crate-level
//! docs).

use block2::Block;
use std::ffi::{c_char, c_int, c_void};
use std::ptr;

/// Every XPC handle (`xpc_object_t`, `xpc_connection_t`, ...) collapses to
/// this — see module docs for why that's correct, not sloppy.
pub type XpcObject = *mut c_void;

/// A connection handle. ABI-identical to [`XpcObject`] (see module docs);
/// kept as a distinct alias purely for call-site readability.
pub type XpcConnection = XpcObject;

/// `xpc_type_t` — `const struct _xpc_type_s *`. Only ever compared for
/// pointer identity against the `xpc_type_*()` accessors below.
pub type XpcType = *const c_void;

/// Passed to `xpc_connection_create_mach_service`: this connection is the
/// listener for a mach service already declared in the process's
/// `launchd.plist` (`MachServices` key) — never for ad-hoc registration.
pub const XPC_CONNECTION_MACH_SERVICE_LISTENER: u64 = 1 << 0;

/// Passed to `xpc_connection_create_mach_service` by a CLIENT connecting to a
/// mach service hosted by a launchd *daemon* (system domain) — exactly what
/// the brain service does to reach `ipauro-helper`.
pub const XPC_CONNECTION_MACH_SERVICE_PRIVILEGED: u64 = 1 << 1;

unsafe extern "C" {
    // -- well-known type singletons (compared via xpc_get_type) ------------
    #[link_name = "_xpc_type_connection"]
    static XPC_TYPE_CONNECTION_RAW: [u8; 0];
    #[link_name = "_xpc_type_dictionary"]
    static XPC_TYPE_DICTIONARY_RAW: [u8; 0];
    #[link_name = "_xpc_type_error"]
    static XPC_TYPE_ERROR_RAW: [u8; 0];

    // -- well-known error singletons (compared by identity against `event`) -
    #[link_name = "_xpc_error_connection_interrupted"]
    static XPC_ERROR_CONNECTION_INTERRUPTED_RAW: [u8; 0];
    #[link_name = "_xpc_error_connection_invalid"]
    static XPC_ERROR_CONNECTION_INVALID_RAW: [u8; 0];
    #[link_name = "_xpc_error_termination_imminent"]
    static XPC_ERROR_TERMINATION_IMMINENT_RAW: [u8; 0];
    #[link_name = "_xpc_error_peer_code_signing_requirement"]
    static XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT_RAW: [u8; 0];

    // -- connection lifecycle -----------------------------------------------
    pub fn xpc_connection_create_mach_service(
        name: *const c_char,
        targetq: *mut c_void,
        flags: u64,
    ) -> XpcConnection;
    pub fn xpc_connection_set_event_handler(
        connection: XpcConnection,
        handler: &Block<dyn Fn(XpcObject)>,
    );
    pub fn xpc_connection_resume(connection: XpcConnection);
    pub fn xpc_connection_cancel(connection: XpcConnection);
    pub fn xpc_connection_send_message(connection: XpcConnection, message: XpcObject);
    /// Client request/response: blocks the calling thread until the peer
    /// replies (or hands back an error singleton — classify with
    /// [`classify_event`]). Callers on an async runtime must wrap this in
    /// `spawn_blocking`. Returned object is owned by the caller: `xpc_release`.
    pub fn xpc_connection_send_message_with_reply_sync(
        connection: XpcConnection,
        message: XpcObject,
    ) -> XpcObject;
    pub fn xpc_connection_set_peer_code_signing_requirement(
        connection: XpcConnection,
        requirement: *const c_char,
    ) -> c_int;
    pub fn xpc_connection_get_pid(connection: XpcConnection) -> i32;

    // -- object introspection ------------------------------------------------
    pub fn xpc_get_type(object: XpcObject) -> XpcType;
    pub fn xpc_release(object: XpcObject);

    // -- dictionaries ---------------------------------------------------------
    /// Create a dictionary. Clients build outgoing messages with
    /// `xpc_dictionary_create(null, null, 0)` + the setters below.
    pub fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const XpcObject,
        count: usize,
    ) -> XpcObject;
    pub fn xpc_dictionary_create_reply(original: XpcObject) -> XpcObject;
    pub fn xpc_dictionary_get_data(
        xdict: XpcObject,
        key: *const c_char,
        length: *mut usize,
    ) -> *const c_void;
    pub fn xpc_dictionary_set_data(
        xdict: XpcObject,
        key: *const c_char,
        bytes: *const c_void,
        length: usize,
    );

    // -- libdispatch (same libSystem umbrella, no extra link needed) --------
    /// Runs the default dispatch queue's run loop forever. Never returns in
    /// practice; the daemon calls this once, at the very end of `main`, after
    /// the listener is set up and resumed.
    pub fn dispatch_main();
}

/// `XPC_TYPE_CONNECTION` — a listener's event handler receives objects of
/// this type for each newly-accepted peer connection.
pub fn xpc_type_connection() -> XpcType {
    ptr::addr_of!(XPC_TYPE_CONNECTION_RAW) as XpcType
}

/// `XPC_TYPE_DICTIONARY` — every application message on the wire is one.
pub fn xpc_type_dictionary() -> XpcType {
    ptr::addr_of!(XPC_TYPE_DICTIONARY_RAW) as XpcType
}

/// `XPC_TYPE_ERROR` — the type of the well-known `XPC_ERROR_*` singletons.
pub fn xpc_type_error() -> XpcType {
    ptr::addr_of!(XPC_TYPE_ERROR_RAW) as XpcType
}

/// `XPC_ERROR_CONNECTION_INTERRUPTED`.
pub fn xpc_error_connection_interrupted() -> XpcObject {
    ptr::addr_of!(XPC_ERROR_CONNECTION_INTERRUPTED_RAW) as XpcObject
}

/// `XPC_ERROR_CONNECTION_INVALID`.
pub fn xpc_error_connection_invalid() -> XpcObject {
    ptr::addr_of!(XPC_ERROR_CONNECTION_INVALID_RAW) as XpcObject
}

/// `XPC_ERROR_TERMINATION_IMMINENT`.
pub fn xpc_error_termination_imminent() -> XpcObject {
    ptr::addr_of!(XPC_ERROR_TERMINATION_IMMINENT_RAW) as XpcObject
}

/// `XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT` (macOS 12+).
pub fn xpc_error_peer_code_signing_requirement() -> XpcObject {
    ptr::addr_of!(XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT_RAW) as XpcObject
}

/// A raw XPC handle, wrapped so it can be captured by a `'static` block2
/// closure that GCD may invoke from any of its worker threads.
///
/// # Safety
/// Sound because libxpc documents its connection and object handles as safe
/// to use from multiple GCD queues/threads concurrently (see
/// `xpc_connection_send_message`: "This API is safe to call from multiple GCD
/// queues."). We never mutate through the pointer ourselves — we only ever
/// pass it back into libxpc entry points, which do their own synchronization.
#[derive(Clone, Copy)]
pub struct SendableXpcObject(pub XpcObject);

unsafe impl Send for SendableXpcObject {}
unsafe impl Sync for SendableXpcObject {}

/// The kind of event delivered to a connection's event handler, classified
/// from the raw `XpcObject` the C API hands us. Centralizing this dispatch
/// keeps every `match` on it exhaustive (no stringly-typed / ad-hoc pointer
/// comparisons scattered through the listener code).
#[derive(Debug, Clone, Copy)]
pub enum XpcEvent {
    /// A listener's handler received a new peer connection to accept.
    NewConnection(XpcConnection),
    /// A peer connection's handler received an application message.
    Message(XpcObject),
    ConnectionInterrupted,
    ConnectionInvalid,
    TerminationImminent,
    PeerCodeSigningRequirementFailed,
    /// A type/singleton we don't recognize. Always logged, never silently
    /// dropped — see the repo's enum-variant-discipline rule.
    Unknown,
}

/// Classify a raw event object delivered to a connection's event handler.
///
/// `on_listener` distinguishes the two contexts that share the exact same
/// `xpc_handler_t` signature: a listener's handler receives new connections
/// (`XPC_TYPE_CONNECTION`), while an accepted peer connection's handler
/// receives application dictionaries (`XPC_TYPE_DICTIONARY`). Both kinds of
/// handler can receive `XPC_TYPE_ERROR` singletons.
pub fn classify_event(event: XpcObject, on_listener: bool) -> XpcEvent {
    let ty = unsafe { xpc_get_type(event) };
    if ty == xpc_type_error() {
        if event == xpc_error_connection_invalid() {
            XpcEvent::ConnectionInvalid
        } else if event == xpc_error_connection_interrupted() {
            XpcEvent::ConnectionInterrupted
        } else if event == xpc_error_termination_imminent() {
            XpcEvent::TerminationImminent
        } else if event == xpc_error_peer_code_signing_requirement() {
            XpcEvent::PeerCodeSigningRequirementFailed
        } else {
            XpcEvent::Unknown
        }
    } else if on_listener && ty == xpc_type_connection() {
        XpcEvent::NewConnection(event)
    } else if !on_listener && ty == xpc_type_dictionary() {
        XpcEvent::Message(event)
    } else {
        XpcEvent::Unknown
    }
}
