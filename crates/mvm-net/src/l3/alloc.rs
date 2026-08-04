//! Point-to-point address allocation for L3 tunnels.
//!
//! Each machine gets a /30 out of a host-configured pool: `.1` is the
//! gateway (which is also the synthetic resolver and the point-to-point
//! peer the guest sees), `.2` is the guest, `.3` is the subnet broadcast.
//! Nothing is hardcoded to a single global subnet — two machines on one
//! host must not share addresses, and the pool must be steerable away from
//! whatever the host already routes.
//!
//! The allocator is deliberately not a general IPAM: it hands out fixed
//! /30s from a contiguous pool and takes them back. That is the whole
//! requirement, and a smaller surface is a smaller thing to get wrong.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net};

/// Default pool. `10.201.0.0/16` is chosen to sit clear of the addresses
/// mvm already uses elsewhere — the dev bridge on `172.16.0.0/24` and
/// libkrun's shared network on `192.168.127.0/24` — and clear of the
/// `100.64.0.0/10` CGNAT block that `MANDATORY_DENY_RANGES` blackholes.
pub const DEFAULT_POOL: &str = "10.201.0.0/16";

/// Maximum concurrent leases the default pool supports. A /16 split into
/// /30s is 16384 subnets; index 0 is reserved so the pool's own network
/// address is never handed out.
pub const DEFAULT_POOL_CAPACITY: u32 = 16_383;

/// Which address family a packet is in.
///
/// An enum rather than the version nibble it comes from: the nibble has
/// values that are not families, and every caller here has already had one
/// validated for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

/// One machine's assigned point-to-point addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressLease {
    /// The /30 this lease occupies.
    pub subnet: Ipv4Net,
    /// Host-side address: point-to-point peer, default gateway, and
    /// synthetic DNS resolver, all the same address.
    pub gateway: Ipv4Addr,
    /// The address assigned to the guest. Anti-spoofing compares every
    /// outbound packet's source against exactly this.
    pub guest: Ipv4Addr,
    /// The same pair in IPv6, when this session was issued one.
    ///
    /// `None` is the ordinary case today, and it is what keeps IPv6 refused
    /// rather than carried unchecked: with no assigned address there is
    /// nothing for anti-spoofing to compare an IPv6 source against, so
    /// admission refuses the family outright instead of guessing.
    pub gateway_v6: Option<Ipv6Addr>,
    pub guest_v6: Option<Ipv6Addr>,
    /// Index within the pool, so release is O(log n) without re-deriving.
    index: u32,
}

impl AddressLease {
    /// The same lease with an IPv6 pair alongside the IPv4 one.
    pub fn with_v6(mut self, gateway: Ipv6Addr, guest: Ipv6Addr) -> Self {
        self.gateway_v6 = Some(gateway);
        self.guest_v6 = Some(guest);
        self
    }

    /// The address this lease assigned the guest in `family`, if any.
    pub fn guest_in(&self, family: AddressFamily) -> Option<IpAddr> {
        match family {
            AddressFamily::V4 => Some(IpAddr::V4(self.guest)),
            AddressFamily::V6 => self.guest_v6.map(IpAddr::V6),
        }
    }

    /// The gateway address in `family`, if any. Traffic to it is a host
    /// service rather than egress, in either family.
    pub fn gateway_in(&self, family: AddressFamily) -> Option<IpAddr> {
        match family {
            AddressFamily::V4 => Some(IpAddr::V4(self.gateway)),
            AddressFamily::V6 => self.gateway_v6.map(IpAddr::V6),
        }
    }
    /// The subnet's broadcast address. Packets to it are refused; a
    /// point-to-point link has no use for broadcast.
    pub fn broadcast(&self) -> Ipv4Addr {
        let base = u32::from(self.subnet.network());
        Ipv4Addr::from(base + 3)
    }

    /// Prefix length the guest configures on `mvm0`. A /30 keeps the
    /// guest's on-link set to exactly the gateway.
    pub fn prefix_len(&self) -> u8 {
        30
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// A lease over an explicit gateway/guest pair, for tests and for the
    /// privileged lane, which needs a lease matching a datapath it set up
    /// directly rather than one the allocator chose.
    pub fn for_test(gateway: std::net::Ipv4Addr, guest: std::net::Ipv4Addr) -> Self {
        let base = u32::from(gateway) & !3;
        Self {
            subnet: Ipv4Net::new(std::net::Ipv4Addr::from(base), 30)
                .expect("a /30 from an aligned base is valid"),
            gateway,
            guest,
            gateway_v6: None,
            guest_v6: None,
            index: 0,
        }
    }
}

/// Allocation refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocError {
    /// Every /30 in the pool is either leased or excluded.
    #[error("address pool {pool} is exhausted ({leased} leased, {excluded} excluded)")]
    PoolExhausted {
        pool: Ipv4Net,
        leased: usize,
        excluded: usize,
    },
    /// The configured pool is too small to carve a /30 out of.
    #[error("pool {0} is smaller than the /30 an L3 tunnel needs")]
    PoolTooSmall(Ipv4Net),
    /// The pool overlaps a range that must never be handed to a guest.
    #[error("pool {0} overlaps a mandatory-deny range")]
    PoolOverlapsMandatoryDeny(Ipv4Net),
}

/// Hands out and reclaims /30s from a pool.
#[derive(Debug, Clone)]
pub struct AddressAllocator {
    pool: Ipv4Net,
    capacity: u32,
    leased: BTreeSet<u32>,
    /// Indices withheld because they collide with something the host
    /// already routes.
    excluded: BTreeSet<u32>,
    /// Next index to try. Allocation sweeps forward from here so a
    /// released lease is not immediately reissued — a freshly restarted
    /// machine getting its predecessor's address would make stale
    /// in-flight packets look legitimate.
    cursor: u32,
}

impl AddressAllocator {
    /// Allocator over [`DEFAULT_POOL`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_POOL.parse().expect("DEFAULT_POOL is a valid /16"))
            .expect("DEFAULT_POOL is large enough and not mandatory-denied")
    }

    /// Allocator over an explicit pool.
    pub fn new(pool: Ipv4Net) -> Result<Self, AllocError> {
        if pool.prefix_len() > 30 {
            return Err(AllocError::PoolTooSmall(pool));
        }
        // Refuse a pool that would hand a guest an address the rest of the
        // stack blackholes — the tunnel would come up and then silently
        // drop everything.
        let pool_net = IpNet::V4(pool);
        for denied in mvm_core::network_policy::mandatory_deny_ranges() {
            if nets_overlap(&pool_net, &denied) {
                return Err(AllocError::PoolOverlapsMandatoryDeny(pool));
            }
        }
        let capacity = 1u32 << (30 - pool.prefix_len());
        Ok(Self {
            pool,
            capacity,
            leased: BTreeSet::new(),
            excluded: BTreeSet::new(),
            // Index 0 holds the pool's own network address; skip it.
            cursor: 1,
        })
    }

    /// Withhold every /30 that overlaps `net`. Call once per route the
    /// host already has, before the first allocation, so a tunnel cannot
    /// be handed a subnet that collides with host routing.
    pub fn exclude(&mut self, net: IpNet) {
        for index in 0..self.capacity {
            let Some(subnet) = self.subnet_at(index) else {
                continue;
            };
            if nets_overlap(&IpNet::V4(subnet), &net) {
                self.excluded.insert(index);
            }
        }
    }

    /// Take the next free /30.
    pub fn allocate(&mut self) -> Result<AddressLease, AllocError> {
        for step in 0..self.capacity {
            let index = (self.cursor.wrapping_add(step)) % self.capacity;
            if index == 0 || self.leased.contains(&index) || self.excluded.contains(&index) {
                continue;
            }
            let Some(subnet) = self.subnet_at(index) else {
                continue;
            };
            self.leased.insert(index);
            self.cursor = (index + 1) % self.capacity;
            let base = u32::from(subnet.network());
            return Ok(AddressLease {
                subnet,
                gateway: Ipv4Addr::from(base + 1),
                guest: Ipv4Addr::from(base + 2),
                gateway_v6: None,
                guest_v6: None,
                index,
            });
        }
        Err(AllocError::PoolExhausted {
            pool: self.pool,
            leased: self.leased.len(),
            excluded: self.excluded.len(),
        })
    }

    /// Give a lease back. Idempotent: releasing twice is not an error,
    /// because teardown runs on both the normal and the failed-startup
    /// path and must not care which got there first.
    pub fn release(&mut self, lease: &AddressLease) {
        self.leased.remove(&lease.index);
    }

    pub fn leased_count(&self) -> usize {
        self.leased.len()
    }

    pub fn pool(&self) -> Ipv4Net {
        self.pool
    }

    fn subnet_at(&self, index: u32) -> Option<Ipv4Net> {
        let base = u32::from(self.pool.network()).checked_add(index.checked_mul(4)?)?;
        Ipv4Net::new(Ipv4Addr::from(base), 30).ok()
    }
}

/// Whether two CIDRs share any address. `ipnet` has no direct predicate,
/// and the containment check has to run both ways: a /16 pool and a /8
/// deny range overlap even though neither contains the other's network
/// address in the direction you happen to test first.
fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_pool_hands_out_a_usable_point_to_point_lease() {
        let lease = AddressAllocator::with_defaults().allocate().unwrap();
        assert_eq!(lease.gateway, Ipv4Addr::new(10, 201, 0, 5));
        assert_eq!(lease.guest, Ipv4Addr::new(10, 201, 0, 6));
        assert_eq!(lease.broadcast(), Ipv4Addr::new(10, 201, 0, 7));
        assert_eq!(lease.prefix_len(), 30);
        assert_eq!(lease.subnet.prefix_len(), 30);
    }

    #[test]
    fn the_pools_own_network_address_is_never_handed_out() {
        let lease = AddressAllocator::with_defaults().allocate().unwrap();
        assert_ne!(lease.subnet.network(), Ipv4Addr::new(10, 201, 0, 0));
    }

    #[test]
    fn concurrent_machines_get_disjoint_subnets() {
        let mut alloc = AddressAllocator::with_defaults();
        let mut seen = BTreeSet::new();
        let leases: Vec<_> = (0..64).map(|_| alloc.allocate().unwrap()).collect();
        for lease in &leases {
            assert!(
                seen.insert(lease.subnet),
                "duplicate subnet {}",
                lease.subnet
            );
            assert!(seen.insert(Ipv4Net::new(lease.guest, 32).unwrap()));
        }
        // No two machines share a guest address — the anti-spoofing check
        // is only meaningful if this holds.
        let guests: BTreeSet<_> = leases.iter().map(|l| l.guest).collect();
        assert_eq!(guests.len(), leases.len());
    }

    #[test]
    fn a_released_lease_is_reusable_but_not_immediately_reissued() {
        let mut alloc = AddressAllocator::with_defaults();
        let first = alloc.allocate().unwrap();
        alloc.release(&first);
        assert_eq!(alloc.leased_count(), 0);
        let second = alloc.allocate().unwrap();
        assert_ne!(
            first.subnet, second.subnet,
            "a restarting machine must not inherit its own previous address"
        );
    }

    #[test]
    fn releasing_twice_is_not_an_error() {
        let mut alloc = AddressAllocator::with_defaults();
        let lease = alloc.allocate().unwrap();
        alloc.release(&lease);
        alloc.release(&lease);
        assert_eq!(alloc.leased_count(), 0);
    }

    #[test]
    fn exclusions_keep_the_allocator_off_host_routes() {
        let mut alloc = AddressAllocator::new("10.201.0.0/24".parse().unwrap()).unwrap();
        alloc.exclude("10.201.0.0/28".parse().unwrap());
        let lease = alloc.allocate().unwrap();
        assert!(
            u32::from(lease.subnet.network()) >= u32::from(Ipv4Addr::new(10, 201, 0, 16)),
            "allocated {} inside the excluded range",
            lease.subnet
        );
    }

    #[test]
    fn exhausting_a_small_pool_fails_closed() {
        // A /28 is four /30s; index 0 is reserved, so three are usable.
        let mut alloc = AddressAllocator::new("10.201.0.0/28".parse().unwrap()).unwrap();
        for _ in 0..3 {
            alloc.allocate().unwrap();
        }
        assert!(matches!(
            alloc.allocate(),
            Err(AllocError::PoolExhausted { .. })
        ));
    }

    #[test]
    fn a_pool_smaller_than_a_slash_30_is_refused() {
        assert!(matches!(
            AddressAllocator::new("10.201.0.0/31".parse().unwrap()),
            Err(AllocError::PoolTooSmall(_))
        ));
    }

    #[test]
    fn a_pool_overlapping_mandatory_deny_is_refused() {
        // CGNAT and link-local are both blackholed guest-side; a lease
        // from either would come up dead.
        for pool in ["100.64.0.0/24", "169.254.0.0/24", "127.0.0.0/24"] {
            assert!(
                matches!(
                    AddressAllocator::new(pool.parse().unwrap()),
                    Err(AllocError::PoolOverlapsMandatoryDeny(_))
                ),
                "{pool} should be refused as a tunnel pool"
            );
        }
    }

    #[test]
    fn a_pool_containing_a_deny_range_is_also_refused() {
        // The deny range is smaller than the pool here, so the overlap
        // check has to look both ways.
        assert!(matches!(
            AddressAllocator::new("100.0.0.0/8".parse().unwrap()),
            Err(AllocError::PoolOverlapsMandatoryDeny(_))
        ));
    }

    #[test]
    fn the_default_pool_capacity_matches_the_documented_number() {
        let mut alloc = AddressAllocator::new(DEFAULT_POOL.parse().unwrap()).unwrap();
        // Allocate the whole pool and count. 16384 /30s minus index 0.
        let mut n = 0u32;
        while alloc.allocate().is_ok() {
            n += 1;
        }
        assert_eq!(n, DEFAULT_POOL_CAPACITY);
    }
}
