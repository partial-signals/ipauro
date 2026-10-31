//! The iroh adapter for the IPAuRo mesh (R003-F1).
//!
//! `ipauro-mesh` stays std-only; everything that touches iroh lives here.
//! This crate owns the machine's root identity — one persistent ed25519
//! secret key — and the iroh `Endpoint` bound with it. Later tickets
//! (F2/F9) implement mesh's `Gossip` / `Gateway` traits on top of [`IrohNode`].

mod beacon;
mod codec;
mod control;
mod gossip;
mod key;
mod node;

pub use key::{KeyError, default_key_path, load_or_create_secret_key, mesh_node_id};
pub use node::{IrohConfig, IrohNode, NodeError};
pub use codec::{DecodeError, RECORD_VERSION, decode_record, encode_record};
pub use gossip::{
    BootstrapSource, GossipConfig, IrohGossip, MemberObservation, MemberState, MeshMembership, Reject, StaticBootstrap, open_record,
    seal_record, topic_for_mesh,
};
pub use beacon::{
    Announcement, BeaconConfig, BeaconHealth, BeaconState, BeaconIo, BeaconReject, BeaconTargets, CompositeBootstrap, InterfaceBeacon, LanBeacon,
    appliance_broadcast_v4, beacon_group_v6, beacon_port, iface_index, open_beacon, seal_beacon,
};
pub use control::{
    CONTROL_ALPN, ControlCounts, ControlError, ControlMessage, ControlPlane, ControlTarget, ControlView, DEFAULT_CONTROL_TTL,
    ForeignDelivery, FrameReject, IpPassthrough, MAX_FRAME, OpenedFrame, PassthroughPort, open_frame, seal_frame,
};
