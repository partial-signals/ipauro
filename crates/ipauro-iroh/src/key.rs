//! Persistent machine identity and the mesh `NodeId` derived from it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ipauro_mesh::ids::NodeId;
use iroh::{PublicKey, SecretKey};

/// Domain-separation tag for the mesh NodeId derivation. Versioned so a future
/// derivation cannot collide with this one.
const NODE_ID_DOMAIN: &[u8] = b"ipauro-mesh-nodeid-v1";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(
        "identity key file {path} is unreadable or corrupt ({reason}); refusing to regenerate \
         because a new key changes this machine's identity and mesh address. Restore the file \
         or delete it deliberately to mint a new identity"
    )]
    Corrupt { path: PathBuf, reason: String },
    #[error("cannot persist identity key at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
}

/// Mesh `NodeId` = first 8 bytes of `blake3(domain || ed25519 public key)`.
///
/// Lives here, not in `ipauro-mesh`: a domain-separated hash needs a hash
/// function, and mesh is deliberately dependency-free (std has no stable
/// cryptographic hash). Mesh only consumes the resulting 8 bytes.
pub fn mesh_node_id(public: &PublicKey) -> NodeId {
    let mut h = blake3::Hasher::new();
    h.update(NODE_ID_DOMAIN);
    h.update(public.as_bytes());
    let digest = h.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest.as_bytes()[..8]);
    NodeId(id)
}

/// Default key location: next to the core IPC socket
/// (`~/Library/Application Support/io.ipauro/` on macOS, `$XDG_RUNTIME_DIR/ipauro/`
/// elsewhere), mirroring `ipauro_proto::ipc::default_socket_path`'s layout.
pub fn default_key_path() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/io.ipauro/node.key")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("ipauro/node.key")
    }
}

/// Load the secret key at `path`, creating it (0600) on first boot.
///
/// A present-but-invalid file (wrong length, unreadable) is a hard
/// [`KeyError::Corrupt`] — never silently regenerated.
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey, KeyError> {
    match fs::read(path) {
        Ok(bytes) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| KeyError::Corrupt {
                path: path.into(),
                reason: format!("expected 32 bytes, found {}", bytes.len()),
            })?;
            Ok(SecretKey::from_bytes(&arr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create(path),
        Err(e) => Err(KeyError::Corrupt { path: path.into(), reason: e.to_string() }),
    }
}

fn create(path: &Path) -> Result<SecretKey, KeyError> {
    let io = |source| KeyError::Io { path: path.into(), source };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    let key = SecretKey::generate();
    let mut opts = fs::OpenOptions::new();
    // create_new: if a peer process raced us to create it, fail rather than overwrite.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).map_err(io)?;
    f.write_all(&key.to_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_fixed_vector_and_domain_separation() {
        let sk = SecretKey::from_bytes(&[7u8; 32]);
        let pk = sk.public();
        let id = mesh_node_id(&pk);
        assert_eq!(id, mesh_node_id(&pk), "deterministic");

        let mut h = blake3::Hasher::new();
        h.update(pk.as_bytes());
        let undomained = h.finalize();
        assert_ne!(&id.0[..], &undomained.as_bytes()[..8], "domain tag must change the hash");

        let other = SecretKey::from_bytes(&[8u8; 32]).public();
        assert_ne!(id, mesh_node_id(&other));
        // Pinned vector: changing the derivation changes every address mesh-wide.
        assert_eq!(id.0, EXPECTED, "NodeId derivation changed");
    }
    const EXPECTED: [u8; 8] = [167, 178, 119, 220, 99, 123, 100, 237];

    #[test]
    fn create_then_reload_same_key_with_0600() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/node.key");
        let a = load_or_create_secret_key(&p).unwrap();
        let b = load_or_create_secret_key(&p).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn corrupt_key_is_hard_error_and_untouched() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("node.key");
        fs::write(&p, b"short").unwrap();
        let err = load_or_create_secret_key(&p).unwrap_err();
        assert!(matches!(err, KeyError::Corrupt { .. }), "{err}");
        assert_eq!(fs::read(&p).unwrap(), b"short");
    }
}
