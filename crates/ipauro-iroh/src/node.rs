//! The bound iroh endpoint for this machine.

use std::net::SocketAddr;
use std::path::PathBuf;

use ipauro_mesh::ids::NodeId;
use iroh::endpoint::{RelayMode, presets};
use iroh::address_lookup::MemoryLookup;
use iroh::{Endpoint, EndpointAddr, PublicKey};

use crate::key::{KeyError, load_or_create_secret_key, mesh_node_id};

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("invalid bind address {0}: {1}")]
    BindAddr(SocketAddr, String),
    #[error("failed to bind iroh endpoint: {0}")]
    Bind(String),
}

/// Bootstrap configuration. Defaults are air-gapped: no relay, no n0
/// DNS/pkarr discovery (LAN discovery is R003-F9's beacon).
#[derive(Clone, Debug)]
pub struct IrohConfig {
    /// Where the persistent ed25519 identity lives.
    pub key_path: PathBuf,
    /// Opt-in: use n0's relays and DNS/pkarr discovery over the internet.
    pub internet_discovery: bool,
    /// Explicit UDP bind addresses; empty = iroh's wildcard defaults (ephemeral port).
    pub bind_addrs: Vec<SocketAddr>,
}

impl IrohConfig {
    pub fn new(key_path: PathBuf) -> Self {
        Self { key_path, internet_discovery: false, bind_addrs: Vec::new() }
    }
}

/// A running iroh endpoint plus the identity it was bound with.
pub struct IrohNode {
    endpoint: Endpoint,
    node_id: NodeId,
    peers: MemoryLookup,
    internet_discovery: bool,
}

impl IrohNode {
    /// Load-or-create the machine key, then bind the endpoint with it.
    pub async fn start(config: IrohConfig) -> Result<Self, NodeError> {
        let secret = load_or_create_secret_key(&config.key_path)?;
        let node_id = mesh_node_id(&secret.public());
        let peers = MemoryLookup::new();

        let mut builder = if config.internet_discovery {
            Endpoint::builder(presets::N0)
        } else {
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled)
        }
        // Static peer addresses (bootstrap sources) resolve through this; it is
        // the only address lookup in the air-gapped default.
        .address_lookup(peers.clone())
        .secret_key(secret);
        if !config.bind_addrs.is_empty() {
            // Replace the default wildcard sockets with the explicit set.
            builder = builder.clear_ip_transports();
            for a in &config.bind_addrs {
                builder = builder
                    .bind_addr(*a)
                    .map_err(|e| NodeError::BindAddr(*a, e.to_string()))?;
            }
        }
        let endpoint = builder.bind().await.map_err(|e| NodeError::Bind(e.to_string()))?;
        Ok(Self { endpoint, node_id, peers, internet_discovery: config.internet_discovery })
    }

    /// Full ed25519 public key (iroh's endpoint id).
    pub fn public_key(&self) -> PublicKey {
        self.endpoint.id()
    }

    /// Whether n0 relay / DNS discovery over the internet is enabled.
    pub fn internet_discovery(&self) -> bool {
        self.internet_discovery
    }

    /// 8-byte mesh NodeId derived from the public key.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Local UDP addresses the endpoint is bound to.
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// The underlying endpoint, for the F2/F9 adapters.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Teach the endpoint how to dial `peer` (static bootstrap, F9 beacon).
    pub fn add_peer_addr(&self, peer: EndpointAddr) {
        self.peers.add_endpoint_info(peer);
    }

    /// Handle to the address book the endpoint dials through (cheap clone).
    pub fn peer_lookup(&self) -> MemoryLookup {
        self.peers.clone()
    }

    /// This node's own dialable address (id + bound sockets).
    pub fn local_addr(&self) -> EndpointAddr {
        EndpointAddr::from_parts(
            self.public_key(),
            self.bound_addrs().into_iter().map(iroh::TransportAddr::Ip),
        )
    }

    /// Graceful shutdown: closes connections and sockets.
    pub async fn shutdown(self) {
        self.endpoint.close().await;
    }
}
