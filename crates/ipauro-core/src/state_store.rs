//! The service's single authoritative state store.
//!
//! `@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — R002-T7:
//! "the service's desired-state store is the single source of truth; every
//! client ... is a commander/renderer kept in sync by snapshot+events."

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ipauro_proto::ipc::EventBody;
use ipauro_proto::state::Snapshot;
use tokio::sync::{broadcast, RwLock};

/// Backpressure buffer for the broadcast channel. State changes are rare and
/// small (whole-snapshot events per R002-T7); this is generous headroom, not
/// a tuned value.
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// One entry in the ordered event stream every subscribed client receives.
/// `seq` is global — one counter per [`StateStore`], never per-connection —
/// so two clients observing the same mutation see the same `seq`.
#[derive(Clone, Debug)]
pub struct Event {
    pub seq: u64,
    pub body: EventBody,
}

/// The service's authoritative [`Snapshot`] behind an async-aware lock. Every
/// mutation bumps the global event sequence and broadcasts the resulting
/// snapshot to subscribers.
pub struct StateStore {
    inner: RwLock<Snapshot>,
    seq: AtomicU64,
    tx: broadcast::Sender<Event>,
    /// `SetTransportScope`'s desired flag (M1, ticket R004-T2's precursor).
    /// Deliberately snapshot-ADJACENT rather than part of the wire
    /// [`Snapshot`]: `ipauro-proto` is manager-owned, and its
    /// `TransportState` carries only OBSERVED status (`link_scoped`,
    /// `dhcp_serving`) — never a request — so there is no wire field to put a
    /// "desired" bit in without a proto change (flagged in the M1 report as a
    /// candidate future addition). `reconcile::drive_once` reads this
    /// alongside `Snapshot.bridge.desired_up` to build a `reconcile::Desired`.
    desired_scope_enabled: AtomicBool,
}

impl StateStore {
    pub fn new(initial: Snapshot) -> Self {
        let (tx, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            inner: RwLock::new(initial),
            seq: AtomicU64::new(0),
            tx,
            desired_scope_enabled: AtomicBool::new(false),
        }
    }

    /// Current `SetTransportScope` desired flag. See the field doc for why
    /// this lives here instead of on the wire `Snapshot`.
    pub fn desired_scope_enabled(&self) -> bool {
        self.desired_scope_enabled.load(Ordering::SeqCst)
    }

    /// Sets the `SetTransportScope` desired flag. Does not itself touch the
    /// wire snapshot or broadcast an event — the reconciler's next pass is
    /// what makes the change observable, via `transport.link_scoped` once the
    /// helper confirms it (`commands::handle` kicks reconcile right after
    /// calling this).
    pub fn set_desired_scope_enabled(&self, enabled: bool) {
        self.desired_scope_enabled.store(enabled, Ordering::SeqCst);
    }

    /// A clone of the current state. Used for `Hello` (snapshot-on-connect)
    /// and `GetSnapshot`.
    pub async fn snapshot(&self) -> Snapshot {
        self.inner.read().await.clone()
    }

    /// Subscribe to the ordered event stream. New subscribers only observe
    /// events from this point forward; `Hello`'s snapshot covers everything
    /// before (snapshot-on-connect + ordered event stream, R002-T7).
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Apply `f` under the write lock, bump the global seq, and broadcast the
    /// resulting snapshot. Returns the new snapshot so callers building a
    /// `Reply` don't need a second read-lock round trip.
    ///
    /// Seq allocation and the broadcast happen while the write lock is still
    /// held: if they happened after release, two concurrent mutations could
    /// send out of order (seq 1 before seq 0) and a client rendering the
    /// last-received snapshot would show stale state. `broadcast::send` is
    /// synchronous, so nothing is awaited under the lock.
    pub async fn mutate(&self, f: impl FnOnce(&mut Snapshot)) -> Snapshot {
        let mut guard = self.inner.write().await;
        f(&mut guard);
        let snapshot = guard.clone();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        // Err(SendError) just means no subscribers are currently listening —
        // events are opt-in per-connection (`subscribe_events`), so that's
        // expected and not a failure.
        let _ = self.tx.send(Event { seq, body: EventBody::Snapshot { snapshot: snapshot.clone() } });
        drop(guard);
        snapshot
    }
}
