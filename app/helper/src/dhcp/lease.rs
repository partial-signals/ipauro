//! A static in-memory lease table over a contiguous IPv4 pool, keyed by
//! client hardware address. No persistence across restarts — M1's scope is
//! "peers auto-acquire a same-subnet address" (R005-T6), not a durable
//! lease store; a helper restart re-serving a different address to a
//! previously-leased MAC is an accepted M1 limitation (see this lane's
//! final report).

use std::collections::HashMap;
use std::net::Ipv4Addr;

pub struct LeaseTable {
    pool_start: u32,
    pool_end: u32,
    leases: HashMap<Vec<u8>, Ipv4Addr>,
}

impl LeaseTable {
    pub fn new(pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> Self {
        Self {
            pool_start: u32::from(pool_start),
            pool_end: u32::from(pool_end),
            leases: HashMap::new(),
        }
    }

    /// Allocate (or return the existing lease for) `client`. A client that
    /// already holds a lease always gets it back unchanged (idempotent
    /// REQUEST/renew). Otherwise, `requested` is honored if it's in-pool
    /// and not already taken by a different client; failing that, the first
    /// free address in the pool is used. `None` if the pool is exhausted.
    pub fn allocate(&mut self, client: &[u8], requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(existing) = self.leases.get(client) {
            return Some(*existing);
        }
        if let Some(req) = requested {
            let req_bits = u32::from(req);
            if (self.pool_start..=self.pool_end).contains(&req_bits) && !self.is_taken(req_bits) {
                self.leases.insert(client.to_vec(), req);
                return Some(req);
            }
        }
        let free = (self.pool_start..=self.pool_end).find(|bits| !self.is_taken(*bits))?;
        let addr = Ipv4Addr::from(free);
        self.leases.insert(client.to_vec(), addr);
        Some(addr)
    }

    fn is_taken(&self, addr_bits: u32) -> bool {
        self.leases.values().any(|v| u32::from(*v) == addr_bits)
    }

    /// Free `client`'s lease, if any (DHCPRELEASE — `responder::handle_packet`).
    pub fn release(&mut self, client: &[u8]) {
        self.leases.remove(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> LeaseTable {
        LeaseTable::new(Ipv4Addr::new(10, 69, 0, 10), Ipv4Addr::new(10, 69, 0, 12))
    }

    #[test]
    fn distinct_clients_get_distinct_addresses() {
        let mut leases = pool();
        let a = leases.allocate(&[1], None).unwrap();
        let b = leases.allocate(&[2], None).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn same_client_gets_the_same_lease_on_renew() {
        let mut leases = pool();
        let first = leases.allocate(&[1], None).unwrap();
        let second = leases.allocate(&[1], None).unwrap();
        assert_eq!(first, second);
        // Renewing must not consume a second address from the pool: a third,
        // different client can still get one of the other two.
        let third = leases.allocate(&[2], None).unwrap();
        assert_ne!(third, first);
    }

    #[test]
    fn requested_ip_honored_when_free_and_in_pool() {
        let mut leases = pool();
        let addr = leases.allocate(&[1], Some(Ipv4Addr::new(10, 69, 0, 12))).unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 69, 0, 12));
    }

    #[test]
    fn requested_ip_out_of_pool_falls_back_to_first_free() {
        let mut leases = pool();
        let addr = leases.allocate(&[1], Some(Ipv4Addr::new(10, 70, 0, 5))).unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 69, 0, 10));
    }

    #[test]
    fn requested_ip_already_taken_by_another_client_falls_back() {
        let mut leases = pool();
        leases.allocate(&[1], Some(Ipv4Addr::new(10, 69, 0, 10))).unwrap();
        let addr = leases.allocate(&[2], Some(Ipv4Addr::new(10, 69, 0, 10))).unwrap();
        assert_ne!(addr, Ipv4Addr::new(10, 69, 0, 10));
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let mut leases = pool(); // pool of 3 addresses: .10, .11, .12
        assert!(leases.allocate(&[1], None).is_some());
        assert!(leases.allocate(&[2], None).is_some());
        assert!(leases.allocate(&[3], None).is_some());
        assert_eq!(leases.allocate(&[4], None), None);
    }

    #[test]
    fn release_frees_the_address_for_reuse() {
        let mut leases = pool();
        let addr = leases.allocate(&[1], None).unwrap();
        leases.release(&[1]);
        // A fresh client can now be handed that same address back.
        let reused = leases.allocate(&[2], Some(addr)).unwrap();
        assert_eq!(reused, addr);
    }

    #[test]
    fn single_address_pool_serves_exactly_one_client() {
        let mut leases =
            LeaseTable::new(Ipv4Addr::new(10, 69, 0, 10), Ipv4Addr::new(10, 69, 0, 10));
        assert_eq!(leases.allocate(&[1], None), Some(Ipv4Addr::new(10, 69, 0, 10)));
        assert_eq!(leases.allocate(&[2], None), None);
    }
}
