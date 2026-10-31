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
        ipauro_core::build_version(),
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

    // --- The mesh identity seam (R003-F1). ---
    // Key lives next to the IPC socket so a `--socket` override (tests, dev)
    // also relocates the identity. Best-effort: a bind failure or corrupt key
    // is logged and the M1 control path runs without a mesh node.
    let key_path = socket_path
        .parent()
        .map(|d| d.join("node.key"))
        .unwrap_or_else(ipauro_iroh::default_key_path);
    let mut mesh_env = ipauro_core::mesh_status::MeshEnv::default();
    let iroh_node = match ipauro_iroh::IrohNode::start(ipauro_iroh::IrohConfig::new(key_path)).await
    {
        Ok(node) => {
            let id = node.node_id().0.iter().map(|b| format!("{b:02x}")).collect::<String>();
            log::info!("mesh node {id} (endpoint {}) bound on {:?}", node.public_key(), node.bound_addrs());
            mesh_env.endpoint_id = Some(node.public_key().to_string());
            mesh_env.endpoint = ipauro_proto::state::EndpointStatus::Bound {
                addrs: node.bound_addrs().iter().map(|a| a.to_string()).collect(),
            };
            mesh_env.internet_discovery = node.internet_discovery();
            Some(node)
        }
        Err(e) => {
            log::error!("mesh identity unavailable, continuing without iroh: {e}");
            mesh_env.endpoint = ipauro_proto::state::EndpointStatus::Failed { error: e.to_string() };
            None
        }
    };

    // Mesh membership over iroh-gossip (R003-F2), bootstrapped by the LAN
    // beacon (R003-F9). The beacon needs no internet; it binds once its
    // interface exists and rebinds if that is rebuilt.
    // Same degrade rule: failure is logged, the control path is unaffected.
    let mut gcfg = ipauro_iroh::GossipConfig::default();
    if let Ok(id) = std::env::var("IPAURO_MESH_ID") {
        gcfg.mesh_id = id;
    }
    // A Hub announces on its bridge, a Peer on its uplink(s) (R003-B10): the
    // service rewrites this target set as role and attached links change.
    let beacon_targets = ipauro_iroh::BeaconTargets::new(vec![ipauro_proto::helper::BRIDGE_NAME.to_string()]);
    let beacon = iroh_node.as_ref().map(|node| {
        let advertised: Vec<std::net::SocketAddr> = node.local_addr().ip_addrs().copied().collect();
        std::sync::Arc::new(ipauro_iroh::InterfaceBeacon::spawn(
            beacon_targets.clone(),
            node.endpoint().secret_key().clone(),
            move || advertised.clone(),
            ipauro_iroh::BeaconConfig { mesh_id: gcfg.mesh_id.clone(), ..Default::default() },
            std::time::Duration::from_secs(2),
        ))
    });
    let membership = match (&iroh_node, &beacon) {
        (Some(node), Some(beacon)) => {
            let bootstrap = ipauro_iroh::CompositeBootstrap(vec![
                beacon.clone(),
                std::sync::Arc::new(ipauro_iroh::StaticBootstrap::default()),
            ]);
            match ipauro_iroh::MeshMembership::spawn(node, std::sync::Arc::new(bootstrap), gcfg).await {
                Ok(m) => Some(std::sync::Arc::new(m)),
                Err(e) => {
                    log::error!("mesh gossip unavailable, continuing without it: {e}");
                    mesh_env.gossip_error = Some(e.to_string());
                    None
                }
            }
        }
        _ => None,
    };
    let membership_log = membership.clone().map(|m| {
        tokio::spawn(async move {
            let mut known = Vec::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let now = m.live_peers();
                if now != known {
                    log::info!("mesh membership: {} peer(s) {:?}", now.len(), now);
                    known = now;
                }
            }
        })
    });

    // Stream facet (R003-F7): binary canonical-stream socket beside the control
    // socket. Holds the membership weakly so `Arc::into_inner` below still works.
    let stream_server = {
        let weak = membership.as_ref().map(std::sync::Arc::downgrade);
        let rate: ipauro_core::stream_server::MeshRateSource = std::sync::Arc::new(move || {
            weak.as_ref()
                .and_then(|w| w.upgrade())
                .map(|m| m.mesh_rate())
                .unwrap_or_else(|| ipauro_mesh::rate::MeshRate::new(ipauro_mesh::ids::NodeId([0; 8])))
        });
        let path = ipauro_proto::stream::stream_socket_path(&socket_path);
        match ipauro_core::stream_server::StreamServer::spawn(path, rate) {
            Ok(s) => {
                // Advertised protocols = in-tree adapters (none yet) ∪ the
                // sidecars' families; every change rides the next heartbeat.
                let weak = membership.as_ref().map(std::sync::Arc::downgrade);
                s.registry().set_caps_sink(std::sync::Arc::new(move |sidecars| {
                    if let Some(m) = weak.as_ref().and_then(|w| w.upgrade()) {
                        let in_tree = ipauro_mesh::capability::ProtocolCaps::default();
                        m.set_protocols(in_tree.union(&sidecars));
                    }
                }));
                Some(s)
            }
            Err(e) => {
                log::error!("stream socket failed to bind: {e}");
                None
            }
        }
    };

    let mesh_node = iroh_node.as_ref().map(|n| n.node_id());
    let config = ipauro_core::ServiceConfig { socket_path, helper, registrar, usb_source, mesh_node, membership: membership.clone() };

    mesh_env.beacon = beacon.clone();
    mesh_env.beacon_targets = Some(beacon_targets);
    let result = ipauro_core::serve_with(config, mesh_env, shutdown_signal()).await;
    drop(stream_server);
    if let Some(t) = membership_log {
        t.abort();
    }
    drop(beacon);
    if let Some(m) = membership.and_then(std::sync::Arc::into_inner) {
        m.shutdown().await;
    }
    if let Some(node) = iroh_node {
        node.shutdown().await;
    }
    result
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
