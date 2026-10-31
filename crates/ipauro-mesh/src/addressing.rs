//! Primary addressing (R003-T3): a node's address is a pure function of its
//! [`NodeId`] — no DHCP server, no addressing authority, nothing to lease or
//! re-lease on replug.
//!
//! Two families:
//!
//! - **IPv6 ULA** ([`ula_addr`]): `fdXX:XXXX:XXXX:SSSS:<iid>`. The 40-bit Global
//!   ID is mesh-wide and derived from a caller-supplied mesh/session identifier
//!   ([`UlaPrefix::from_mesh_id`]) or is the fixed ipauro constant
//!   ([`UlaPrefix::DEFAULT`]); every node of one mesh must use the same one. The
//!   64-bit IID is the 8-byte `NodeId` with the u/l bit (`0x02` of byte 0)
//!   flipped, the modified-EUI-64 convention of RFC 4291 App. A. Flipping is a
//!   bijection, so distinct NodeIds yield distinct addresses: **collision-free by
//!   construction**, nothing to resolve or gossip.
//! - **Hashed IPv4** ([`assign_ipv4`]): Dante/AES67 are IPv4-only, so this is the
//!   main path once those protocols arrive. 64 bits cannot fit in a /16, so
//!   collisions are real (birthday: ~20 nodes in a /24 pass 50%). Resolution is
//!   a deterministic, coordinator-free pure function of the *member set*:
//!   process members in ascending `NodeId`; each takes the first slot from
//!   `hash(id, salt)` for `salt = 0, 1, …` not already held by a lower id. So the
//!   lowest NodeId keeps a contested slot, losers re-hash with an incremented
//!   salt, and the result is independent of input order. After [`HASH_SALTS`]
//!   hashed attempts the probe continues linearly from the salt-0 slot, so
//!   exhaustion is exactly `members > capacity` and is reported
//!   ([`AddrError::Exhausted`]), never an overlap.
//!
//! ## Hash range vs foreign-DHCP pool
//!
//! Foreign (non-ipauro) devices are leased addresses by the control plane
//! (R005-T6) from a pool that must never overlap the hash range, or a leased
//! foreign device could take a node's hashed address. [`Ipv4Config::new`]
//! validates: both ranges inside the subnet, excluding network/broadcast,
//! non-empty, and disjoint.
//!
//! ## Gossip: inputs, not outputs
//!
//! The IPv4 assignment is a function of the membership set, which is already
//! gossiped; so each node *computes* the assignment from its own view rather
//! than trusting a peer's. Gossiping the computed result as authoritative would
//! be wrong under partition: two partitions assign independently, and a stale
//! "claim" would pin an address that the merged membership then reassigns —
//! turning a self-healing function into a state-reconciliation problem. Views
//! converge when membership does, and the assignment follows with no extra
//! protocol. The node still *advertises* its own [`AddrClaim`] (in
//! [`crate::topology::PeerFacts::addr`]) — not as an input, but as an
//! observable: [`diverging_claims`] compares what peers say they use against
//! what this node computed, so a transient divergence (a peer on a stale view)
//! is visible and a persistent one is a bug surfaced, not a silent overlap.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ids::NodeId;

/// Hashed attempts before the probe falls back to linear scan.
pub const HASH_SALTS: u32 = 32;

/// Why an address plan or assignment could not be produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddrError {
    /// Prefix length outside `1..=30` (need room for network + broadcast + hosts).
    BadPrefixLen(u8),
    /// A configured range is inverted or empty.
    EmptyRange,
    /// A configured range reaches outside the subnet or onto network/broadcast.
    RangeOutsideSubnet,
    /// The hash range and the foreign-DHCP pool overlap.
    OverlappingRanges,
    /// More members than hash-range slots.
    Exhausted { members: usize, capacity: u32 },
}

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrError::BadPrefixLen(p) => write!(f, "prefix length /{p} unusable (need 1..=30)"),
            AddrError::EmptyRange => write!(f, "address range is empty or inverted"),
            AddrError::RangeOutsideSubnet => {
                write!(f, "address range leaves the subnet or covers network/broadcast")
            }
            AddrError::OverlappingRanges => {
                write!(f, "hash range overlaps the foreign-DHCP pool")
            }
            AddrError::Exhausted { members, capacity } => {
                write!(f, "{members} members exceed hash range capacity {capacity}")
            }
        }
    }
}

impl std::error::Error for AddrError {}

// ---------------------------------------------------------------- IPv6 ULA

/// The mesh-wide ULA prefix: `fd` + 40-bit Global ID, plus a 16-bit Subnet ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UlaPrefix {
    global_id: [u8; 5],
    subnet_id: u16,
}

impl UlaPrefix {
    /// Fixed ipauro constant, for meshes that don't carry a session identifier.
    pub const DEFAULT: UlaPrefix = UlaPrefix { global_id: [0x1b, 0x5a, 0x70, 0x0a, 0x52], subnet_id: 0 };

    /// Global ID derived deterministically from a mesh/session identifier, so
    /// distinct meshes that later bridge are unlikely to share a prefix.
    pub fn from_mesh_id(mesh_id: &[u8]) -> Self {
        let h = hash64(mesh_id, 0).to_be_bytes();
        UlaPrefix { global_id: [h[0], h[1], h[2], h[3], h[4]], subnet_id: 0 }
    }

    pub fn with_subnet_id(mut self, subnet_id: u16) -> Self {
        self.subnet_id = subnet_id;
        self
    }
}

/// The node's ULA: `prefix ‖ subnet ‖ NodeId with u/l bit flipped`.
pub fn ula_addr(prefix: &UlaPrefix, node: &NodeId) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..6].copy_from_slice(&prefix.global_id);
    o[6..8].copy_from_slice(&prefix.subnet_id.to_be_bytes());
    o[8..16].copy_from_slice(&node.0);
    o[8] ^= 0x02;
    Ipv6Addr::from(o)
}

// ------------------------------------------------------------- IPv4 config

/// Validated IPv4 plan: subnet, hash range (nodes), foreign pool (DHCP).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4Config {
    network: u32,
    prefix_len: u8,
    hash_lo: u32,
    hash_hi: u32,
    foreign_lo: u32,
    foreign_hi: u32,
}

impl Ipv4Config {
    /// `hash` and `foreign` are inclusive `(first, last)` ranges.
    pub fn new(
        network: Ipv4Addr,
        prefix_len: u8,
        hash: (Ipv4Addr, Ipv4Addr),
        foreign: (Ipv4Addr, Ipv4Addr),
    ) -> Result<Self, AddrError> {
        if !(1..=30).contains(&prefix_len) {
            return Err(AddrError::BadPrefixLen(prefix_len));
        }
        let mask = u32::MAX << (32 - prefix_len);
        let net = u32::from(network) & mask;
        let bcast = net | !mask;
        let (hash_lo, hash_hi) = (u32::from(hash.0), u32::from(hash.1));
        let (foreign_lo, foreign_hi) = (u32::from(foreign.0), u32::from(foreign.1));
        for (lo, hi) in [(hash_lo, hash_hi), (foreign_lo, foreign_hi)] {
            if lo > hi {
                return Err(AddrError::EmptyRange);
            }
            if lo <= net || hi >= bcast {
                return Err(AddrError::RangeOutsideSubnet);
            }
        }
        if hash_lo <= foreign_hi && foreign_lo <= hash_hi {
            return Err(AddrError::OverlappingRanges);
        }
        Ok(Ipv4Config { network: net, prefix_len, hash_lo, hash_hi, foreign_lo, foreign_hi })
    }

    /// `10.42.0.0/16`: lower half hashed for nodes, upper half for foreign DHCP.
    pub fn appliance_default() -> Self {
        Self::new(
            Ipv4Addr::new(10, 42, 0, 0),
            16,
            (Ipv4Addr::new(10, 42, 0, 1), Ipv4Addr::new(10, 42, 127, 255)),
            (Ipv4Addr::new(10, 42, 128, 0), Ipv4Addr::new(10, 42, 255, 254)),
        )
        .expect("default plan is valid")
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
    /// Number of slots nodes can occupy.
    pub fn capacity(&self) -> u32 {
        self.hash_hi - self.hash_lo + 1
    }
    /// The range node addresses are hashed into (inclusive) — what makes an
    /// IPv4 on a shared interface "ours" rather than the network's own.
    pub fn hash_range(&self) -> (Ipv4Addr, Ipv4Addr) {
        (Ipv4Addr::from(self.hash_lo), Ipv4Addr::from(self.hash_hi))
    }
    /// The foreign-DHCP pool (inclusive), for the R005-T6 allocator.
    pub fn foreign_pool(&self) -> (Ipv4Addr, Ipv4Addr) {
        (Ipv4Addr::from(self.foreign_lo), Ipv4Addr::from(self.foreign_hi))
    }

    /// Refuse a DHCP pool (inclusive) that touches the hash range. The
    /// pool is configured outside this module (`ipauro_proto::defaults`), so
    /// the config-time gate is a check of an EXTERNAL range against the hash
    /// range: a lease inside it could hand a foreign device a node's address.
    pub fn check_pool_disjoint(&self, pool: (Ipv4Addr, Ipv4Addr)) -> Result<(), AddrError> {
        let (lo, hi) = (u32::from(pool.0), u32::from(pool.1));
        if lo > hi {
            return Err(AddrError::EmptyRange);
        }
        if self.hash_lo <= hi && lo <= self.hash_hi {
            return Err(AddrError::OverlappingRanges);
        }
        Ok(())
    }

    fn slot_addr(&self, slot: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.hash_lo + slot)
    }
}

/// A node's resolved IPv4 address and the salt that produced it (0 = first
/// choice; higher = it lost a collision, possibly repeatedly).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrClaim {
    pub ipv4: Ipv4Addr,
    pub salt: u32,
}

/// Stable 64-bit hash (FNV-1a then splitmix64 finalizer). Not `DefaultHasher`:
/// every node on every build must agree, forever.
fn hash64(bytes: &[u8], salt: u32) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes.iter().chain(salt.to_be_bytes().iter()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Slot index for `(node, salt)`: hashed for `salt < HASH_SALTS`, then a linear
/// walk from the salt-0 slot (guarantees every free slot is eventually reached).
fn slot_for(cfg: &Ipv4Config, node: &NodeId, salt: u32) -> u32 {
    let cap = u64::from(cfg.capacity());
    if salt < HASH_SALTS {
        (hash64(&node.0, salt) % cap) as u32
    } else {
        let base = hash64(&node.0, 0) % cap;
        ((base + u64::from(salt - HASH_SALTS) + 1) % cap) as u32
    }
}

/// Deterministic IPv4 assignment for a member set. Pure function of the *set*
/// (order and duplicates in `members` are irrelevant); every node that holds the
/// same view computes the same map.
pub fn assign_ipv4<I>(cfg: &Ipv4Config, members: I) -> Result<BTreeMap<NodeId, AddrClaim>, AddrError>
where
    I: IntoIterator<Item = NodeId>,
{
    let set: BTreeSet<NodeId> = members.into_iter().collect();
    if set.len() as u64 > u64::from(cfg.capacity()) {
        return Err(AddrError::Exhausted { members: set.len(), capacity: cfg.capacity() });
    }
    let mut taken: BTreeSet<u32> = BTreeSet::new();
    let mut out = BTreeMap::new();
    for node in set {
        // Terminates: salts >= HASH_SALTS walk every slot, and len <= capacity.
        let mut salt = 0u32;
        let slot = loop {
            let s = slot_for(cfg, &node, salt);
            if taken.insert(s) {
                break s;
            }
            salt += 1;
        };
        out.insert(node, AddrClaim { ipv4: cfg.slot_addr(slot), salt });
    }
    Ok(out)
}

/// Peers whose advertised claim differs from what we computed for them (a peer
/// absent from `computed` — one we don't know about yet — is also reported).
/// Transient under partition/stale views; persistent means a bug.
pub fn diverging_claims<'a, I>(
    computed: &BTreeMap<NodeId, AddrClaim>,
    advertised: I,
) -> Vec<NodeId>
where
    I: IntoIterator<Item = (&'a NodeId, &'a AddrClaim)>,
{
    let mut v: Vec<NodeId> = advertised
        .into_iter()
        .filter(|(n, c)| computed.get(*n).map(|m| m.ipv4) != Some(c.ipv4))
        .map(|(n, _)| *n)
        .collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(n: u64) -> NodeId {
        // Spread bits so ids aren't trivially adjacent.
        NodeId(hash64(&n.to_be_bytes(), 7).to_be_bytes())
    }

    fn small_cfg(slots: u8) -> Ipv4Config {
        // 10.0.0.0/24: hash 10.0.0.1..=slots, foreign above.
        Ipv4Config::new(
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, slots)),
            (Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::new(10, 0, 0, 250)),
        )
        .unwrap()
    }

    #[test]
    fn external_pool_must_be_disjoint_from_hash_range() {
        let cfg = Ipv4Config::appliance_default();
        let ip = |a, b, c, d| Ipv4Addr::new(a, b, c, d);
        // The prototype's bridge pool lives in a different /24 entirely.
        assert!(cfg.check_pool_disjoint((ip(10, 69, 0, 10), ip(10, 69, 0, 200))).is_ok());
        // Its own foreign pool is fine; a pool straddling/inside the hash range is not.
        assert!(cfg.check_pool_disjoint(cfg.foreign_pool()).is_ok());
        assert_eq!(
            cfg.check_pool_disjoint((ip(10, 42, 100, 0), ip(10, 42, 130, 0))),
            Err(AddrError::OverlappingRanges)
        );
        assert_eq!(
            cfg.check_pool_disjoint((ip(10, 42, 0, 5), ip(10, 42, 0, 9))),
            Err(AddrError::OverlappingRanges)
        );
        assert_eq!(
            cfg.check_pool_disjoint((ip(10, 69, 0, 9), ip(10, 69, 0, 1))),
            Err(AddrError::EmptyRange)
        );
    }

    #[test]
    fn ula_deterministic_and_formatted() {
        let n = NodeId([0x01, 2, 3, 4, 5, 6, 7, 8]);
        let a = ula_addr(&UlaPrefix::DEFAULT, &n);
        assert_eq!(a, ula_addr(&UlaPrefix::DEFAULT, &n));
        let o = a.octets();
        assert_eq!(o[0], 0xfd);
        assert_eq!(&o[1..6], &UlaPrefix::DEFAULT.global_id);
        assert_eq!(o[8], 0x01 ^ 0x02, "u/l bit flipped");
        assert_eq!(&o[9..], &n.0[1..]);
        // mesh-id derived prefix is stable and differs between meshes
        let p1 = UlaPrefix::from_mesh_id(b"session-a");
        assert_eq!(p1, UlaPrefix::from_mesh_id(b"session-a"));
        assert_ne!(p1, UlaPrefix::from_mesh_id(b"session-b"));
        assert_eq!(ula_addr(&p1.with_subnet_id(3), &n).segments()[3], 3);
        // distinct NodeIds -> distinct addresses
        let m = NodeId([0x03, 2, 3, 4, 5, 6, 7, 8]);
        assert_ne!(ula_addr(&p1, &n), ula_addr(&p1, &m));
    }

    #[test]
    fn config_validation() {
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let ip = |d| Ipv4Addr::new(10, 0, 0, d);
        let ok = |h: (u8, u8), f: (u8, u8)| {
            Ipv4Config::new(net, 24, (ip(h.0), ip(h.1)), (ip(f.0), ip(f.1)))
        };
        assert!(ok((1, 100), (101, 200)).is_ok());
        assert_eq!(ok((1, 100), (100, 200)), Err(AddrError::OverlappingRanges));
        assert_eq!(ok((50, 150), (10, 60)), Err(AddrError::OverlappingRanges));
        assert_eq!(ok((0, 100), (101, 200)), Err(AddrError::RangeOutsideSubnet)); // network
        assert_eq!(ok((1, 100), (101, 255)), Err(AddrError::RangeOutsideSubnet)); // broadcast
        assert_eq!(ok((9, 5), (101, 200)), Err(AddrError::EmptyRange));
        assert_eq!(
            Ipv4Config::new(net, 31, (ip(1), ip(2)), (ip(3), ip(4))),
            Err(AddrError::BadPrefixLen(31))
        );
        let d = Ipv4Config::appliance_default();
        assert_eq!(d.capacity(), 32767);
        assert!(d.foreign_pool().0 > Ipv4Addr::new(10, 42, 127, 255));
    }

    #[test]
    fn assigned_addrs_in_hash_range_and_unique() {
        let cfg = small_cfg(60);
        let m: Vec<NodeId> = (0..50).map(nid).collect();
        let a = assign_ipv4(&cfg, m.iter().copied()).unwrap();
        assert_eq!(a.len(), 50);
        let uniq: BTreeSet<_> = a.values().map(|c| c.ipv4).collect();
        assert_eq!(uniq.len(), 50);
        for c in a.values() {
            let l = c.ipv4.octets()[3];
            assert!((1..=60).contains(&l), "{} outside hash range", c.ipv4);
        }
        // 50 in 60 slots -> collisions certain -> some salt > 0
        assert!(a.values().any(|c| c.salt > 0));
    }

    fn permutations(v: &mut Vec<NodeId>, k: usize, out: &mut Vec<Vec<NodeId>>) {
        if k == v.len() {
            out.push(v.clone());
            return;
        }
        for i in k..v.len() {
            v.swap(k, i);
            permutations(v, k + 1, out);
            v.swap(k, i);
        }
    }

    #[test]
    fn collisions_resolve_identically_under_all_orders() {
        let cfg = small_cfg(6); // 7 members, 6 slots impossible; use 6 in 6 for dense collisions
        let mut members: Vec<NodeId> = (0..6).map(nid).collect();
        let want = assign_ipv4(&cfg, members.iter().copied()).unwrap();
        assert!(want.values().any(|c| c.salt > 0), "scenario must contain a collision");
        let mut perms = Vec::new();
        permutations(&mut members, 0, &mut perms);
        assert_eq!(perms.len(), 720);
        for p in perms {
            assert_eq!(assign_ipv4(&cfg, p).unwrap(), want);
        }
        // duplicates in input are irrelevant
        let dup = members.iter().chain(members.iter()).copied();
        assert_eq!(assign_ipv4(&cfg, dup).unwrap(), want);
    }

    #[test]
    fn lowest_node_id_keeps_contested_slot() {
        let cfg = small_cfg(2); // 2 slots: any 2+ nodes contest
        let a = assign_ipv4(&cfg, (0..2).map(nid)).unwrap();
        let (lo, hi) = (nid(0).min(nid(1)), nid(0).max(nid(1)));
        assert_eq!(a[&lo].salt, assign_ipv4(&cfg, [lo]).unwrap()[&lo].salt);
        assert_eq!(a[&lo], assign_ipv4(&cfg, [lo]).unwrap()[&lo], "lowest id is unaffected by others");
        assert_ne!(a[&lo].ipv4, a[&hi].ipv4);
    }

    #[test]
    fn replug_stable() {
        let cfg = Ipv4Config::appliance_default();
        let m: Vec<NodeId> = (0..40).map(nid).collect();
        let a = assign_ipv4(&cfg, m.iter().copied()).unwrap();
        // node leaves and returns: same member set, same addresses
        let without: Vec<NodeId> = m[1..].to_vec();
        let _ = assign_ipv4(&cfg, without).unwrap();
        assert_eq!(assign_ipv4(&cfg, m.iter().copied()).unwrap(), a);
    }

    #[test]
    fn adding_node_only_moves_colliders() {
        let cfg = small_cfg(120);
        let base: Vec<NodeId> = (0..60).map(nid).collect();
        let before = assign_ipv4(&cfg, base.iter().copied()).unwrap();
        for extra in 100..140u64 {
            let newcomer = nid(extra);
            let mut m = base.clone();
            m.push(newcomer);
            let after = assign_ipv4(&cfg, m).unwrap();
            let moved: Vec<NodeId> =
                base.iter().copied().filter(|n| before[n] != after[n]).collect();
            // A moved node must have lost a slot: either it sat on the newcomer's
            // hashed slot, or on one vacated by another moved node (cascade). So
            // every mover is a higher id than the newcomer ONLY IF newcomer < mover.
            for n in &moved {
                assert!(newcomer < *n, "{n:?} moved though lower id than newcomer");
            }
            // And newcomer bigger than everyone moves nobody.
            if base.iter().all(|n| *n < newcomer) {
                assert!(moved.is_empty());
            }
            // No overlap regardless.
            let u: BTreeSet<_> = after.values().map(|c| c.ipv4).collect();
            assert_eq!(u.len(), 61);
            // Moves are rare: far fewer than all nodes.
            assert!(moved.len() < 20, "too much churn: {}", moved.len());
        }
    }

    #[test]
    fn exhaustion_is_explicit_and_full_fit_works() {
        let cfg = small_cfg(10);
        let ok = assign_ipv4(&cfg, (0..10).map(nid)).unwrap();
        let u: BTreeSet<_> = ok.values().map(|c| c.ipv4).collect();
        assert_eq!(u.len(), 10, "full range packs with no overlap (linear fallback)");
        assert_eq!(
            assign_ipv4(&cfg, (0..11).map(nid)),
            Err(AddrError::Exhausted { members: 11, capacity: 10 })
        );
    }

    #[test]
    fn divergence_reporting() {
        let cfg = small_cfg(100);
        let a = assign_ipv4(&cfg, (0..5).map(nid)).unwrap();
        let mut adv: BTreeMap<NodeId, AddrClaim> = a.clone();
        assert!(diverging_claims(&a, adv.iter()).is_empty());
        let stale = nid(3);
        adv.get_mut(&stale).unwrap().ipv4 = Ipv4Addr::new(10, 0, 0, 99);
        adv.insert(nid(77), AddrClaim { ipv4: Ipv4Addr::new(10, 0, 0, 98), salt: 0 });
        let mut want = vec![stale, nid(77)];
        want.sort();
        assert_eq!(diverging_claims(&a, adv.iter()), want);
    }
}
