//! Best-effort "make the brain service exist" bootstrap. Tried once per
//! outage episode by the background IPC thread (`ipc_client.rs`'s
//! `reconnect_loop`) whenever a connect attempt fails outright — this tray
//! UI ships inside the same signed bundle as `ipauro-core`, so registering
//! (and thereby starting) the `io.ipauro.core` SMAppService **agent** from
//! here is exactly as valid as the panel/tray driving `Command::RegisterHelper`
//! for the privileged helper daemon (`registrar_smapp.rs`, in `ipauro-core`).
//! The packaging README already anticipates this: "the running app is what
//! calls `SMAppService.agent(...).register()` — this packaging never does
//! that itself." Nothing did, until now.
//!
//! Mirrors `ipauro-core`'s `registrar_smapp.rs` in spirit: a fresh
//! `SMAppService` handle per call, no FFI state held between calls, and a
//! plain `Result<(), String>` instead of a panic when the caller isn't
//! running inside a signed bundle (a bare `cargo run -p ipauro-ui` dev
//! build hits exactly that case — see that module's doc comment for why).
//! For that dev case there's a second, cruder fallback: spawning the
//! sibling `ipauro-core` binary directly, gated behind `IPAURO_DEV_SPAWN=1`
//! so it can never fire by accident in the shipped app.

use std::sync::mpsc::Sender;

use eframe::egui;

use crate::state::ConnEvent;

/// Dev-only convenience: when set to `1`, a failed SMAppService agent
/// registration falls back to spawning the sibling `ipauro-core` binary
/// (found next to the running `ipauro-ui` executable) as a detached child
/// process. Never meaningful in the shipped bundle, where registration is
/// expected to succeed — see the module doc comment.
pub const DEV_SPAWN_ENV: &str = "IPAURO_DEV_SPAWN";

/// Try, once, to make the brain service exist and be starting up. Always
/// announces [`ConnEvent::StartingService`] first so the panel has
/// something to show while the (synchronous, expected-fast) OS call runs;
/// on total failure announces [`ConnEvent::ServiceStartFailed`] with the
/// reason. Success needs no event of its own — the reconnect loop's very
/// next connect attempt either lands or doesn't, and the status line clears
/// itself the moment a real `Snapshot` arrives (`state::reduce_status`).
pub fn attempt_start(ev_tx: &Sender<ConnEvent>, ctx: &egui::Context) {
    let _ = ev_tx.send(ConnEvent::StartingService);
    ctx.request_repaint();

    let Err(agent_err) = register_core_agent() else {
        // Registration succeeded, which per SMAppService's login-item-style
        // semantics also launches the agent — nothing further to do.
        return;
    };
    log::warn!("core agent self-registration failed: {agent_err}");

    let outcome = if dev_spawn_enabled() {
        spawn_sibling_core_dev()
            .map_err(|spawn_err| format!("{agent_err}; dev-spawn fallback also failed: {spawn_err}"))
    } else {
        Err(agent_err)
    };

    if let Err(message) = outcome {
        let _ = ev_tx.send(ConnEvent::ServiceStartFailed(message));
        ctx.request_repaint();
    }
}

fn dev_spawn_enabled() -> bool {
    std::env::var_os(DEV_SPAWN_ENV).is_some_and(|v| v == "1")
}

/// Spawn the sibling `ipauro-core` binary next to the currently running
/// executable, detached (not waited on). Dev-only fallback for running
/// outside a signed bundle — see module doc comment.
fn spawn_sibling_core_dev() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().ok_or_else(|| "current_exe has no parent directory".to_string())?;
    let sibling = dir.join("ipauro-core");
    std::process::Command::new(&sibling)
        .spawn()
        .map(|_child| ())
        .map_err(|e| format!("spawning {}: {e}", sibling.display()))
}

/// The real, macOS-only registration call: `SMAppService.agentServiceWithPlistName`
/// for `ipauro_proto::ids::CORE_AGENT_LABEL`. See `ipauro-core`'s
/// `registrar_smapp.rs` for the full explanation of the signed-bundle
/// requirement this inherits — the short version is that this only
/// succeeds when `ipauro-ui` itself is the `CFBundleExecutable` of a
/// properly signed, installed `.app` bundle (`dist/IPAuRo.app`).
#[cfg(target_os = "macos")]
fn register_core_agent() -> Result<(), String> {
    use ipauro_proto::ids::CORE_AGENT_LABEL;
    use objc2_foundation::NSString;
    use objc2_service_management::SMAppService;

    let plist_name = NSString::from_str(&format!("{CORE_AGENT_LABEL}.plist"));
    // Safety: `agentServiceWithPlistName:` per Apple's docs only reads the
    // given NSString for the duration of the call; `plist_name` outlives it.
    let service = unsafe { SMAppService::agentServiceWithPlistName(&plist_name) };
    // Safety: `registerAndReturnError:` per Apple's docs synchronously
    // registers (and, per SMAppService's login-item-style semantics,
    // launches) the job, or returns an NSError; no preconditions beyond a
    // valid `service` handle, which it is (just constructed above).
    unsafe { service.registerAndReturnError() }.map_err(|e| {
        format!(
            "SMAppService agent registration requires running inside the signed IPAuRo.app \
             bundle (got: {})",
            e.localizedDescription()
        )
    })
}

/// Non-macOS stub: there is no `SMAppService` here, so the only path left is
/// the dev-spawn fallback in [`attempt_start`].
#[cfg(not(target_os = "macos"))]
fn register_core_agent() -> Result<(), String> {
    Err("SMAppService agent registration is macOS-only".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_spawn_enabled_parses_env_var() {
        // SAFETY: test-only env mutation, all within one test function so
        // there is no risk of racing with itself — mirrors ipc_client.rs's
        // `socket_path_honors_env_override` in spirit.
        unsafe { std::env::remove_var(DEV_SPAWN_ENV) };
        assert!(!dev_spawn_enabled());
        unsafe { std::env::set_var(DEV_SPAWN_ENV, "true") };
        assert!(!dev_spawn_enabled(), "only the literal value \"1\" should enable dev-spawn");
        unsafe { std::env::set_var(DEV_SPAWN_ENV, "1") };
        assert!(dev_spawn_enabled());
        unsafe { std::env::remove_var(DEV_SPAWN_ENV) };
    }
}
