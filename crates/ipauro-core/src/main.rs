//! IPAuRo brain service entry point. Thin: parses CLI args, wires up the
//! (currently stub) helper boundary, and delegates to `ipauro_core::serve`.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(name = "ipauro-core", about = "IPAuRo brain service")]
struct Cli {
    /// Override the IPC socket path (default: ipauro_proto::ipc::default_socket_path()).
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Run without the privileged helper (all bridge commands fail with
    /// helper_not_connected). Dev/testing only.
    #[arg(long)]
    no_helper: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(ipauro_proto::ipc::default_socket_path);

    log::info!(
        "ipauro-core {} (protocol v{}) starting on {}",
        env!("CARGO_PKG_VERSION"),
        ipauro_proto::PROTOCOL_VERSION,
        socket_path.display(),
    );

    // --- The helper seam. ---
    // Real XPC channel on macOS unless --no-helper; NullHelper otherwise.
    let helper: Arc<dyn ipauro_core::helper_channel::HelperChannel> = if cli.no_helper {
        Arc::new(ipauro_core::helper_channel::NullHelper)
    } else {
        #[cfg(target_os = "macos")]
        {
            Arc::new(ipauro_core::xpc_helper::XpcHelper::new())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Arc::new(ipauro_core::helper_channel::NullHelper)
        }
    };
    // --no-helper only affects the request/response HelperChannel above: it
    // exists to let a dev run the service without a live helper connection.
    // Registration is a separate concern (whether SMAppService knows about
    // the daemon at all) and stays real on macOS regardless — there's no
    // installed-daemon state for --no-helper to usefully stub out here.
    let registrar: Arc<dyn ipauro_core::registrar::HelperRegistrar> = {
        #[cfg(target_os = "macos")]
        {
            Arc::new(ipauro_core::registrar_smapp::SmAppServiceRegistrar::new())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Arc::new(ipauro_core::registrar::StubHelperRegistrar)
        }
    };
    // --- The USB-NCM discovery seam. ---
    // Real `ioreg`-backed source on macOS (the only platform with IOKit/USB-
    // NCM); no discovery mechanism exists elsewhere.
    let usb_source: Arc<dyn ipauro_core::discovery::UsbNcmSource> = {
        #[cfg(target_os = "macos")]
        {
            Arc::new(ipauro_core::discovery::IoregUsbNcmSource::new())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Arc::new(ipauro_core::discovery::NoUsbNcmSource)
        }
    };

    let config = ipauro_core::ServiceConfig { socket_path, helper, registrar, usb_source };

    ipauro_core::serve(config, shutdown_signal()).await
}

/// Resolves on SIGTERM or SIGINT (Ctrl-C / `launchctl stop`).
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => log::info!("received SIGINT"),
        _ = sigterm.recv() => log::info!("received SIGTERM"),
    }
}
