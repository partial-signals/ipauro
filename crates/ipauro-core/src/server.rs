//! The IPC server: one unix socket, NDJSON, per `ipauro_proto::ipc`.
//!
//! `@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — R002-T7:
//! snapshot-on-connect + ordered event stream; clients are commanders/renderers.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipauro_proto::ipc::{ClientMessage, ServerMessage};
use ipauro_proto::PROTOCOL_VERSION;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Notify};

use crate::commands;
use crate::helper_channel::HelperChannel;
use crate::registrar::HelperRegistrar;
use crate::state_store::StateStore;

/// Ensure the parent directory exists and any stale socket file from a prior
/// (crashed) run is removed before binding.
fn prepare_socket_path(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn restrict_socket_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Everything a connection handler needs; bundled so `run`'s accept loop only
/// clones one thing per connection.
#[derive(Clone)]
pub struct ServerHandles {
    pub store: Arc<StateStore>,
    pub helper: Arc<dyn HelperChannel>,
    pub registrar: Arc<dyn HelperRegistrar>,
    pub reconcile_kick: Arc<Notify>,
}

/// Runs the accept loop until `shutdown` fires, then removes the socket file.
pub async fn run(
    socket_path: PathBuf,
    handles: ServerHandles,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    prepare_socket_path(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    restrict_socket_permissions(&socket_path)?;
    log::info!("ipauro-core listening on {}", socket_path.display());

    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let handles = handles.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, handles).await {
                                log::warn!("connection error: {e}");
                            }
                        });
                    }
                    Err(e) => log::warn!("accept error: {e}"),
                }
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    log::info!("ipauro-core shut down, socket removed");
    Ok(())
}

async fn handle_connection(stream: UnixStream, handles: ServerHandles) -> anyhow::Result<()> {
    let ServerHandles { store, helper, registrar, reconcile_kick } = handles;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let (client_version, client_name, subscribe_events) = match read_client_message(&mut reader).await? {
        Some(ClientMessage::Hello { protocol_version, client_name, subscribe_events }) => {
            (protocol_version, client_name, subscribe_events)
        }
        Some(other) => {
            log::warn!("client sent {other:?} before Hello; closing");
            return Ok(());
        }
        None => return Ok(()), // disconnected before Hello
    };

    // Always reply Hello — even on a version mismatch — so the client can
    // see the server's version before the connection closes.
    let snapshot = store.snapshot().await;
    write_server_message(
        &mut write_half,
        &ServerMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            snapshot,
        },
    )
    .await?;

    if client_version != PROTOCOL_VERSION {
        log::warn!(
            "client '{client_name}' speaks protocol v{client_version}, server is v{PROTOCOL_VERSION}; closing"
        );
        return Ok(());
    }

    let mut events = store.subscribe();

    loop {
        tokio::select! {
            msg = read_client_message(&mut reader) => {
                match msg? {
                    None => break, // clean EOF
                    Some(ClientMessage::Command { id, command }) => {
                        let outcome = commands::handle(&store, helper.as_ref(), registrar.as_ref(), &reconcile_kick, command).await;
                        write_server_message(&mut write_half, &ServerMessage::Reply { id, outcome }).await?;
                    }
                    Some(ClientMessage::Hello { .. }) => {
                        log::warn!("client '{client_name}' sent a second Hello; ignoring");
                    }
                }
            }
            event = events.recv(), if subscribe_events => {
                match event {
                    Ok(crate::state_store::Event { seq, body }) => {
                        write_server_message(&mut write_half, &ServerMessage::Event { seq, event: body }).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("client '{client_name}' lagged; skipped {skipped} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Store dropped (service shutting down mid-connection).
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Mirrors `ipauro_proto::ipc::read_msg`, but over an async Tokio stream (the
/// proto helper is `std::io::BufRead`-based and can't be reused directly by
/// an async server).
async fn read_client_message(
    r: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> anyhow::Result<Option<ClientMessage>> {
    let mut line = String::new();
    let n = r.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(line.trim_end())?))
}

/// Mirrors `ipauro_proto::ipc::write_msg` for async Tokio streams.
async fn write_server_message(
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    msg: &ServerMessage,
) -> anyhow::Result<()> {
    let mut buf = serde_json::to_vec(msg)?;
    buf.push(b'\n');
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}
