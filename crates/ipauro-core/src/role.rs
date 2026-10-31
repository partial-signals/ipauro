//! The user-elected node role (R003-F4): persistence, and the pull-based sync
//! from the gossip layer into the store.
//!
//! Role is one tiny piece of desired state, so it persists as a one-word file
//! (`hub` / `peer`) next to the IPC socket, like the identity key. M1's other
//! desired state (bridge up/down, scope) is deliberately NOT persisted — a
//! restart returns to "down" — and this does not change that.
//!
//! Remote nodes' roles are read-only here: `mesh_status::sync_once` only WRITES the
//! local role into gossip and READS peers' roles out of it. Setting another
//! machine's role would need an authorization model nobody has decided.

use std::path::{Path, PathBuf};

use ipauro_mesh::topology::NodeRole as MeshRole;
use ipauro_proto::state::NodeRole;

/// Where the role lives, given the IPC socket path: the socket's own name
/// with a `.role` extension (`core.sock` -> `core.role`), so two services on
/// different sockets (every test) never share a role file.
pub fn role_path(socket_path: &Path) -> PathBuf {
    socket_path.with_extension("role")
}

pub fn encode(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Hub => "hub",
        NodeRole::Peer => "peer",
    }
}

pub fn decode(s: &str) -> Option<NodeRole> {
    match s.trim() {
        "hub" => Some(NodeRole::Hub),
        "peer" => Some(NodeRole::Peer),
        _ => None,
    }
}

/// Load the persisted role; absent or unreadable = the M1 default (`Hub`).
pub fn load(path: &Path) -> NodeRole {
    match std::fs::read_to_string(path) {
        Ok(s) => decode(&s).unwrap_or_else(|| {
            log::warn!("role file {} unparseable, defaulting to hub", path.display());
            NodeRole::default()
        }),
        Err(_) => NodeRole::default(),
    }
}

pub fn save(path: &Path, role: NodeRole) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Write-then-rename so a crash never leaves a torn file.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, encode(role))?;
    std::fs::rename(&tmp, path)
}

pub fn to_mesh(role: NodeRole) -> MeshRole {
    match role {
        NodeRole::Hub => MeshRole::Hub,
        NodeRole::Peer => MeshRole::Peer,
    }
}

pub fn from_mesh(role: MeshRole) -> NodeRole {
    match role {
        MeshRole::Hub => NodeRole::Hub,
        MeshRole::Peer => NodeRole::Peer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_roundtrips_through_the_file_and_defaults_to_hub() {
        let dir = std::env::temp_dir().join(format!("ipauro-role-{}", std::process::id()));
        let path = dir.join("role");
        assert_eq!(load(&path), NodeRole::Hub, "absent file = M1 default");
        save(&path, NodeRole::Peer).unwrap();
        assert_eq!(load(&path), NodeRole::Peer);
        save(&path, NodeRole::Hub).unwrap();
        assert_eq!(load(&path), NodeRole::Hub);
        std::fs::write(&path, "garbage").unwrap();
        assert_eq!(load(&path), NodeRole::Hub, "corrupt file falls back, never panics");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mesh_and_wire_roles_map_both_ways() {
        for r in [NodeRole::Hub, NodeRole::Peer] {
            assert_eq!(from_mesh(to_mesh(r)), r);
        }
    }
}
