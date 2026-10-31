//! The service's single authoritative state store.
//!
//! `@arch:see(.yah/docs/architecture/A001-ipauro-architecture.md)` — R002-T7:
//! "the service's desired-state store is the single source of truth; every
//! client ... is a commander/renderer kept in sync by snapshot+events."

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use ipauro_mesh::ids::NodeId;
use ipauro_proto::ipc::EventBody;
use ipauro_proto::state::Snapshot;
use tokio::sync::{broadcast, RwLock};

use crate::addressing::{MeshAddressing, PrimaryAddrs};
use crate::discovery::{IfaceObservation, LinkInventory, LinkRole};

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
    /// This node's mesh addressing plan + the member set it is computed over
    /// (R003-T3). Snapshot-adjacent like `desired_scope_enabled`: the wire
    /// snapshot carries only OBSERVED state.
    mesh: Mutex<MeshState>,
    /// The latest USB-NCM identification pass (R005-F7) and the interface
    /// observations it took. Snapshot-ADJACENT for the same reason as
    /// `desired_scope_enabled`: the wire [`Snapshot`] has no field for link
    /// provenance and `ipauro-proto` is manager-owned, so the device-side and
    /// traffic signals reach an operator through the service log
    /// ([`LinkInventory::summary`]) until a `Snapshot.links` field is
    /// requested (flagged in R005-F7's report).
    ///
    /// The observations are kept because A002 §5.2's traffic signal is a
    /// DELTA — one pass's counters mean nothing without the previous pass's.
    links: Mutex<Identification>,
}

/// The mesh actions a command can drive (R003-T5), behind a trait so the
/// command path is testable without a live iroh node. `MeshMembership`
/// implements it.
pub trait MeshControl: Send + Sync {
    /// Propose lifting the whole mesh to `hz`; returns the new adopted rate.
    fn propose_rate(&self, hz: u32) -> Result<ipauro_mesh::rate::MeshRate, ipauro_mesh::rate::RateError>;
}

impl MeshControl for ipauro_iroh::MeshMembership {
    fn propose_rate(&self, hz: u32) -> Result<ipauro_mesh::rate::MeshRate, ipauro_mesh::rate::RateError> {
        ipauro_iroh::MeshMembership::propose_rate(self, hz)
    }
}

#[derive(Default)]
struct MeshState {
    control: Option<std::sync::Arc<dyn MeshControl>>,
    addressing: Option<MeshAddressing>,
    members: BTreeSet<NodeId>,
    role_path: Option<std::path::PathBuf>,
    /// The helper's DHCP leases as of the last Report (R003-F6).
    dhcp_leases: Vec<ipauro_proto::helper::DhcpLease>,
}

/// The identification state carried between reconcile passes.
#[derive(Default)]
struct Identification {
    inventory: LinkInventory,
    observations: Vec<IfaceObservation>,
}

/// The topology projection of an inventory: which interfaces exist and what
/// each one IS, with the (delta-derived, flickering) evidence dropped. See
/// [`StateStore::set_identification`].
fn classification(inventory: &LinkInventory) -> Vec<(&str, LinkRole)> {
    inventory.links.iter().map(|l| (l.name.as_str(), l.role)).collect()
}

impl StateStore {
    pub fn new(initial: Snapshot) -> Self {
        let (tx, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            inner: RwLock::new(initial),
            seq: AtomicU64::new(0),
            tx,
            desired_scope_enabled: AtomicBool::new(false),
            mesh: Mutex::new(MeshState::default()),
            links: Mutex::new(Identification::default()),
        }
    }

    /// The most recent USB link identification. See the `links` field doc for
    /// why this is not on the wire snapshot.
    pub fn link_inventory(&self) -> LinkInventory {
        self.links.lock().expect("links mutex poisoned").inventory.clone()
    }

    /// The previous pass's interface observations, to be fed to
    /// [`crate::discovery::identify`] as the baseline for its traffic delta.
    pub fn last_observations(&self) -> Vec<IfaceObservation> {
        self.links.lock().expect("links mutex poisoned").observations.clone()
    }

    /// Record an identification pass. Returns whether the CLASSIFICATION
    /// changed — an interface appeared, vanished, or changed role.
    ///
    /// Deliberately not full inventory equality: traffic evidence is a delta
    /// between consecutive passes, and passes are irregularly spaced (a
    /// converging reconcile self-kicks several times in a few milliseconds,
    /// then the backstop makes the next one 15s later). Over a
    /// millisecond-wide window even a busy link often shows no packets, so
    /// `Evidence::PeerTraffic` legitimately flickers and keying a log line on
    /// it would emit noise that says nothing about the topology. Traffic still
    /// appears in [`LinkInventory::summary`] when a real change does log.
    pub fn set_identification(
        &self,
        inventory: LinkInventory,
        observations: Vec<IfaceObservation>,
    ) -> bool {
        let mut guard = self.links.lock().expect("links mutex poisoned");
        let changed = classification(&guard.inventory) != classification(&inventory);
        guard.inventory = inventory;
        guard.observations = observations;
        changed
    }

    /// Install this node's addressing plan (once, at startup).
    pub fn set_mesh_addressing(&self, addressing: MeshAddressing) {
        self.mesh.lock().expect("mesh mutex poisoned").addressing = Some(addressing);
    }

    /// THE SEAM for gossip membership (R003-F2/F4): replace the known member
    /// set. IPv4 collision resolution is a function of this set, so a change
    /// can move this node's address; the reconciler then removes the old alias
    /// before adding the new one. Callers should kick a reconcile pass after.
    ///
    /// Returns whether the set actually changed.
    pub fn set_mesh_members(&self, members: BTreeSet<NodeId>) -> bool {
        let mut m = self.mesh.lock().expect("mesh mutex poisoned");
        let changed = m.members != members;
        m.members = members;
        changed
    }

    /// Record the DHCP leases from the latest helper Report (R003-F6): the
    /// foreign leaves this hub advertises and terminates control for.
    pub fn set_dhcp_leases(&self, leases: Vec<ipauro_proto::helper::DhcpLease>) {
        self.mesh.lock().expect("mesh mutex poisoned").dhcp_leases = leases;
    }

    /// The DHCP leases from the latest helper Report.
    pub fn dhcp_leases(&self) -> Vec<ipauro_proto::helper::DhcpLease> {
        self.mesh.lock().expect("mesh mutex poisoned").dhcp_leases.clone()
    }

    /// Install the mesh action handle (once, at startup).
    pub fn set_mesh_control(&self, control: std::sync::Arc<dyn MeshControl>) {
        self.mesh.lock().expect("mesh mutex poisoned").control = Some(control);
    }

    /// The mesh action handle, when a mesh is running.
    pub fn mesh_control(&self) -> Option<std::sync::Arc<dyn MeshControl>> {
        self.mesh.lock().expect("mesh mutex poisoned").control.clone()
    }

    /// The live (non-expired) member set the addressing plan is computed over.
    pub fn mesh_members(&self) -> BTreeSet<NodeId> {
        self.mesh.lock().expect("mesh mutex poisoned").members.clone()
    }

    /// This node's addressing plan, when it has a mesh identity.
    pub fn mesh_addressing(&self) -> Option<MeshAddressing> {
        self.mesh.lock().expect("mesh mutex poisoned").addressing
    }

    /// Where `persist_role` writes (R003-F4). Unset = not persisted (tests).
    pub fn set_role_path(&self, path: std::path::PathBuf) {
        self.mesh.lock().expect("mesh mutex poisoned").role_path = Some(path);
    }

    /// Persist the elected role if a path is configured.
    pub fn persist_role(&self, role: ipauro_proto::state::NodeRole) -> std::io::Result<()> {
        let path = self.mesh.lock().expect("mesh mutex poisoned").role_path.clone();
        match path {
            Some(p) => crate::role::save(&p, role),
            None => Ok(()),
        }
    }

    /// The addresses this node wants on the bridge now; `None` without a mesh
    /// identity (M1-only operation).
    pub fn desired_primary(&self) -> Option<PrimaryAddrs> {
        let m = self.mesh.lock().expect("mesh mutex poisoned");
        m.addressing.as_ref().map(|a| a.desired(&m.members))
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

    /// [`Self::mutate`], but only allocates a `seq` and broadcasts when `f`
    /// actually changed the snapshot; returns `None` when it didn't.
    ///
    /// For writers on a HOT path that mostly re-assert what is already true.
    /// [`crate::helper_link::SupervisedHelper`] refreshes `helper` after every
    /// successful helper request (R005-T10 finding 4: the boot ping was the
    /// only thing that ever set `Connected`, so a snapshot read "registered
    /// (not connected)" while requests were flowing) — through plain `mutate`
    /// that would push a redundant snapshot event to every client on every
    /// reconcile poll, forever.
    ///
    /// The comparison happens under the write lock, so a caller can't observe
    /// a change made between its own read and write.
    pub async fn mutate_if_changed(&self, f: impl FnOnce(&mut Snapshot)) -> Option<Snapshot> {
        let mut guard = self.inner.write().await;
        let before = guard.clone();
        f(&mut guard);
        if *guard == before {
            return None;
        }
        let snapshot = guard.clone();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let _ = self.tx.send(Event { seq, body: EventBody::Snapshot { snapshot: snapshot.clone() } });
        drop(guard);
        Some(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{classify, IfaceObservation};

    fn obs(name: &str, active: bool, configured: bool, input_packets: u64) -> IfaceObservation {
        IfaceObservation { name: name.to_string(), active, configured, input_packets }
    }

    fn store() -> StateStore {
        StateStore::new(crate::initial_snapshot())
    }

    #[test]
    fn first_identification_is_always_a_change() {
        let store = store();
        let inventory = classify(&["en9".to_string()], &[], &[], &[]);
        assert!(store.set_identification(inventory.clone(), Vec::new()));
        assert_eq!(store.link_inventory(), inventory);
    }

    #[test]
    fn a_repeat_of_the_same_classification_is_not_a_change() {
        let store = store();
        let inventory = classify(&["en9".to_string()], &[], &[], &[]);
        store.set_identification(inventory.clone(), Vec::new());
        assert!(!store.set_identification(inventory, Vec::new()));
    }

    #[test]
    fn traffic_flicker_alone_is_not_a_change() {
        // Two passes milliseconds apart: the counter didn't move, so
        // `PeerTraffic` drops off. The topology is identical and must not log.
        let store = store();
        let host = vec!["en9".to_string()];
        let now = [obs("en9", true, true, 500)];
        let with_traffic = classify(&host, &[], &now, &[obs("en9", true, true, 499)]);
        let without_traffic = classify(&host, &[], &now, &now);
        assert!(with_traffic != without_traffic, "the inventories really do differ");

        store.set_identification(with_traffic, now.to_vec());
        assert!(!store.set_identification(without_traffic, now.to_vec()));
    }

    #[test]
    fn a_role_change_is_a_change() {
        // The same interface reclassified from a rejected internal to a real
        // device-end link (its peer finally handed it an address).
        let store = store();
        let device = vec!["en5".to_string()];
        let internal = classify(&[], &device, &[obs("en5", true, false, 0)], &[]);
        let promoted = classify(&[], &device, &[obs("en5", true, true, 0)], &[]);
        store.set_identification(internal, Vec::new());
        assert!(store.set_identification(promoted, Vec::new()));
    }

    #[test]
    fn a_detach_is_a_change() {
        let store = store();
        store.set_identification(
            classify(&["en9".to_string(), "en12".to_string()], &[], &[], &[]),
            Vec::new(),
        );
        assert!(store.set_identification(classify(&["en9".to_string()], &[], &[], &[]), Vec::new()));
    }

    #[tokio::test]
    async fn mutate_if_changed_broadcasts_only_a_real_change() {
        use ipauro_proto::state::HelperState;
        let store = store();
        let mut rx = store.subscribe();

        let first = store
            .mutate_if_changed(|s| s.helper = HelperState::Connected { version: "0.0.1".into() })
            .await;
        assert!(first.is_some(), "a real change must broadcast");
        assert!(rx.try_recv().is_ok());

        // Re-asserting the same value: no seq, no event, no snapshot.
        let again = store
            .mutate_if_changed(|s| s.helper = HelperState::Connected { version: "0.0.1".into() })
            .await;
        assert!(again.is_none(), "a no-op mutation must not broadcast");
        assert!(rx.try_recv().is_err(), "no event may reach subscribers");
    }

    #[test]
    fn observations_round_trip_as_the_next_pass_baseline() {
        let store = store();
        assert!(store.last_observations().is_empty(), "no baseline before the first pass");
        let samples = vec![obs("en9", true, true, 42)];
        store.set_identification(LinkInventory::default(), samples.clone());
        assert_eq!(store.last_observations(), samples);
    }
}
