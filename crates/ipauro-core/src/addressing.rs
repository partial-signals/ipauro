//! This node's primary mesh addresses (R003-T3 application pass): the bridge
//! to the reconciler of `ipauro_mesh::addressing`'s pure functions.
//!
//! The address is `f(NodeId)` — no DHCP, no authority. The IPv6 ULA depends on
//! this node alone; the hashed IPv4 depends on the member SET (collisions are
//! resolved deterministically over it), so [`MeshAddressing::desired`] takes the
//! member set as a parameter. That parameter is the seam gossip membership
//! (R003-F2/F4) feeds through `StateStore::set_mesh_members`; until it does, the
//! set is `{self}`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipauro_mesh::addressing::{AddrClaim, AddrError, Ipv4Config, UlaPrefix, assign_ipv4, ula_addr};
use ipauro_mesh::ids::NodeId;
use ipauro_proto::helper::HelperRequest;

/// The ULA is installed as an on-link /64 (matches the helper's validation).
pub const ULA_PREFIX_LEN: u8 = 64;

/// The addresses this node wants on the bridge, as aliases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrimaryAddrs {
    pub ula: Ipv6Addr,
    /// `None` when the member set exhausted the hash range — the ULA still
    /// applies; the failure is logged by the caller, not silently swallowed.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// What counts as ours on an interface that also carries the network's own
    /// addresses (an uplink, R003-B10).
    pub owned: Owned,
}

/// The address space this node's plan allocates from: the mesh ULA /48 and the
/// IPv4 hash range. An address inside it on an uplink is a mesh address
/// (current or stale from a re-hash); anything outside — the segment's DHCP
/// lease, a user-configured address — is not ours to strip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    /// First 48 bits of the ULA (`fd` + 40-bit Global ID).
    pub ula48: [u8; 6],
    pub v4_lo: Ipv4Addr,
    pub v4_hi: Ipv4Addr,
}

impl PrimaryAddrs {
    /// Whether `addr` lies in this plan's allocation space ([`Owned`]).
    pub fn owns(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V6(a) => a.octets()[..6] == self.owned.ula48,
            IpAddr::V4(a) => (self.owned.v4_lo..=self.owned.v4_hi).contains(&a),
        }
    }

    /// The alias set as helper verbs' addresses, ULA first.
    pub fn addrs(&self) -> Vec<(std::net::IpAddr, u8)> {
        let mut v = vec![(self.ula.into(), ULA_PREFIX_LEN)];
        if let Some((a, p)) = self.ipv4 {
            v.push((a.into(), p));
        }
        v
    }

    /// `AddAlias` on `iface` for each wanted address.
    pub fn add_verbs(&self, iface: &str) -> Vec<HelperRequest> {
        self.addrs()
            .into_iter()
            .map(|(addr, prefix)| HelperRequest::AddAlias { iface: iface.to_string(), addr, prefix })
            .collect()
    }
}

/// Validated addressing plan for this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshAddressing {
    node: NodeId,
    ula: UlaPrefix,
    ipv4: Ipv4Config,
}

impl MeshAddressing {
    /// Config-time gate (R003-T3 decision 4): the foreign-DHCP pool the helper
    /// will serve must be disjoint from the hash range, or a leased foreign
    /// device could take a node's address. A misconfigured pool is refused
    /// here, before anything is applied.
    pub fn new(
        node: NodeId,
        ula: UlaPrefix,
        ipv4: Ipv4Config,
        dhcp_pool: (Ipv4Addr, Ipv4Addr),
    ) -> Result<Self, AddrError> {
        ipv4.check_pool_disjoint(dhcp_pool)?;
        Ok(Self { node, ula, ipv4 })
    }

    /// The appliance defaults, checked against the pool `reconcile` actually
    /// serves (`ipauro_proto::defaults`).
    pub fn appliance(node: NodeId, ula: UlaPrefix) -> Result<Self, AddrError> {
        use ipauro_proto::defaults::{DHCP_POOL_END, DHCP_POOL_START};
        Self::new(node, ula, Ipv4Config::appliance_default(), (DHCP_POOL_START, DHCP_POOL_END))
    }

    /// This node's id.
    pub fn node(&self) -> NodeId {
        self.node
    }

    /// Every member's resolved addresses over `members` (this node is always
    /// included) — what status reports (R003-T5). `Err` = the hash range is
    /// exhausted; every ULA is still computable, see [`Self::ula_of`].
    pub fn claims(
        &self,
        members: &BTreeSet<NodeId>,
    ) -> Result<BTreeMap<NodeId, AddrClaim>, AddrError> {
        let mut set = members.clone();
        set.insert(self.node);
        assign_ipv4(&self.ipv4, set)
    }

    /// The ULA `node` maps to (independent of the member set).
    pub fn ula_of(&self, node: &NodeId) -> Ipv6Addr {
        ula_addr(&self.ula, node)
    }

    /// Desired addresses for `members` (this node is always included).
    pub fn desired(&self, members: &BTreeSet<NodeId>) -> PrimaryAddrs {
        let ipv4 = match self.claims(members) {
            Ok(map) => map
                .get(&self.node)
                .map(|claim| (claim.ipv4, self.ipv4.prefix_len())),
            Err(e) => {
                log::error!("mesh IPv4 assignment failed, applying ULA only: {e}");
                None
            }
        };
        let ula = ula_addr(&self.ula, &self.node);
        let (v4_lo, v4_hi) = self.ipv4.hash_range();
        let mut ula48 = [0u8; 6];
        ula48.copy_from_slice(&ula.octets()[..6]);
        PrimaryAddrs { ula, ipv4, owned: Owned { ula48, v4_lo, v4_hi } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> NodeId {
        NodeId([b, 1, 2, 3, 4, 5, 6, 7])
    }

    #[test]
    fn desired_is_deterministic_and_includes_self() {
        let a = MeshAddressing::appliance(node(1), UlaPrefix::DEFAULT).unwrap();
        let alone = a.desired(&BTreeSet::new());
        assert_eq!(alone, a.desired(&BTreeSet::from([node(1)])));
        assert_eq!(alone.addrs().len(), 2);
        assert_eq!(alone.ula, ula_addr(&UlaPrefix::DEFAULT, &node(1)));
    }

    #[test]
    fn owns_the_plan_space_and_nothing_else() {
        let d = MeshAddressing::appliance(node(1), UlaPrefix::DEFAULT).unwrap().desired(&BTreeSet::new());
        let other_node_ula = ula_addr(&UlaPrefix::DEFAULT, &node(9));
        assert!(d.owns(d.ula.into()) && d.owns(other_node_ula.into()), "same /48 = mesh");
        assert!(d.owns(d.ipv4.unwrap().0.into()));
        assert!(d.owns("10.42.127.255".parse().unwrap()));
        for foreign in ["10.69.0.7", "10.42.128.1", "192.168.1.5", "fd00::1", "fe80::1", "2001:db8::1"] {
            assert!(!d.owns(foreign.parse().unwrap()), "{foreign} is not ours");
        }
    }

    #[test]
    fn peers_never_share_an_address() {
        let members: BTreeSet<_> = (1..=40).map(node).collect();
        let mut seen = BTreeSet::new();
        for n in &members {
            let d = MeshAddressing::appliance(*n, UlaPrefix::DEFAULT).unwrap().desired(&members);
            assert!(seen.insert(d.ipv4.unwrap().0), "duplicate v4 for {n:?}");
        }
    }

    #[test]
    fn overlapping_pool_is_refused_at_config_time() {
        let cfg = Ipv4Config::appliance_default();
        let bad = (Ipv4Addr::new(10, 42, 0, 10), Ipv4Addr::new(10, 42, 0, 200));
        assert_eq!(
            MeshAddressing::new(node(1), UlaPrefix::DEFAULT, cfg, bad),
            Err(AddrError::OverlappingRanges)
        );
    }
}
