//! Declared ingress mappings.
//!
//! An ingress mapping is the only way a new inbound flow reaches a guest.
//! Mappings come from the signed plan, are opened by the gateway, and are
//! closed when the machine stops — so no listener exists that the plan did
//! not declare, and a restart cannot inherit one.
//!
//! TCP and UDP are both declarable. Whether a mapping is *served* is a
//! property of the selected forwarding backend, not of this table: a
//! backend that forwards whole packets needs nothing bound, while one that
//! translates flows into host sockets has to open a listener per mapping
//! and reports so through its capabilities.

use std::collections::BTreeMap;
use std::net::IpAddr;

use mvm_contract::l3::proto;
use mvm_core::policy::projection::Proto;

/// Most mappings one machine may declare.
pub const DEFAULT_MAX_MAPPINGS: usize = 64;

/// One declared mapping: a host listener forwarding to a guest port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IngressMapping {
    pub proto: Proto,
    /// Address the host listener binds. `0.0.0.0` is a wildcard exposure
    /// and requires explicit admission.
    pub host_addr: IpAddr,
    pub host_port: u16,
    /// Guest port packets are delivered to.
    pub guest_port: u16,
}

impl IngressMapping {
    pub fn tcp(host_addr: IpAddr, host_port: u16, guest_port: u16) -> Self {
        Self {
            proto: Proto::Tcp,
            host_addr,
            host_port,
            guest_port,
        }
    }

    pub fn udp(host_addr: IpAddr, host_port: u16, guest_port: u16) -> Self {
        Self {
            proto: Proto::Udp,
            host_addr,
            host_port,
            guest_port,
        }
    }

    /// Whether this mapping exposes the guest on every host interface.
    pub fn is_wildcard(&self) -> bool {
        match self.host_addr {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }

    fn protocol_number(&self) -> u8 {
        match self.proto {
            Proto::Tcp => proto::TCP,
            Proto::Udp => proto::UDP,
        }
    }
}

/// Why a mapping was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IngressError {
    /// Another mapping already binds this host address and port. Reported
    /// by name rather than retried, because silently picking a different
    /// port would produce a machine reachable somewhere nobody declared.
    #[error("host {addr}:{port} is already bound by an existing mapping")]
    BindConflict { addr: IpAddr, port: u16 },
    /// A wildcard bind was declared without explicit admission.
    #[error("wildcard exposure on port {port} requires explicit admission")]
    WildcardNotAdmitted { port: u16 },
    /// The mapping table is full.
    #[error("ingress table full ({limit} mappings)")]
    TableFull { limit: usize },
    /// Port zero is not a listener.
    #[error("port 0 is not a valid ingress port")]
    ZeroPort,
}

/// One machine's declared mappings.
#[derive(Debug)]
pub struct IngressTable {
    /// Keyed by host (addr, port) so a bind conflict is a lookup.
    mappings: BTreeMap<(IpAddr, u16), IngressMapping>,
    max_mappings: usize,
    allow_wildcard: bool,
}

impl IngressTable {
    pub fn new(max_mappings: usize, allow_wildcard: bool) -> Self {
        Self {
            mappings: BTreeMap::new(),
            max_mappings,
            allow_wildcard,
        }
    }

    /// Table with the default cap and wildcard exposure permitted.
    ///
    /// Wildcard defaults to permitted because a plan that declares an
    /// ingress mapping at all has already made the decision to expose the
    /// guest; the flag exists for deployments that want to force an
    /// explicit bind address.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_MAPPINGS, true)
    }

    /// Table that refuses wildcard binds.
    pub fn without_wildcard() -> Self {
        Self::new(DEFAULT_MAX_MAPPINGS, false)
    }

    /// Declare a mapping.
    pub fn declare(&mut self, mapping: IngressMapping) -> Result<(), IngressError> {
        if mapping.host_port == 0 || mapping.guest_port == 0 {
            return Err(IngressError::ZeroPort);
        }
        if mapping.is_wildcard() && !self.allow_wildcard {
            return Err(IngressError::WildcardNotAdmitted {
                port: mapping.host_port,
            });
        }
        let key = (mapping.host_addr, mapping.host_port);
        if self.mappings.contains_key(&key) {
            return Err(IngressError::BindConflict {
                addr: mapping.host_addr,
                port: mapping.host_port,
            });
        }
        if self.mappings.len() >= self.max_mappings {
            return Err(IngressError::TableFull {
                limit: self.max_mappings,
            });
        }
        self.mappings.insert(key, mapping);
        Ok(())
    }

    /// Whether a new inbound flow to `guest_port` is declared.
    pub fn admits(&self, protocol: u8, guest_port: u16) -> bool {
        self.mappings
            .values()
            .any(|m| m.protocol_number() == protocol && m.guest_port == guest_port)
    }

    /// The mapping behind a host listener, if any.
    pub fn for_host(&self, addr: IpAddr, port: u16) -> Option<&IngressMapping> {
        self.mappings.get(&(addr, port))
    }

    /// Close one mapping.
    pub fn withdraw(&mut self, addr: IpAddr, port: u16) -> Option<IngressMapping> {
        self.mappings.remove(&(addr, port))
    }

    /// Close every mapping. Called on machine stop so nothing survives to
    /// be inherited by the next boot.
    pub fn clear(&mut self) -> Vec<IngressMapping> {
        let all: Vec<_> = self.mappings.values().copied().collect();
        self.mappings.clear();
        all
    }

    pub fn iter(&self) -> impl Iterator<Item = &IngressMapping> {
        self.mappings.values()
    }

    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

impl Default for IngressTable {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    const WILDCARD: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[test]
    fn a_declared_tcp_mapping_admits_its_guest_port() {
        let mut table = IngressTable::with_defaults();
        table
            .declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 80))
            .unwrap();
        assert!(table.admits(proto::TCP, 80));
        assert!(!table.admits(proto::TCP, 81), "no mapping, no admission");
        assert!(!table.admits(proto::UDP, 80), "protocol must match");
    }

    #[test]
    fn an_undeclared_port_is_never_admitted() {
        let table = IngressTable::with_defaults();
        assert!(!table.admits(proto::TCP, 80));
        assert!(table.is_empty());
    }

    #[test]
    fn a_bind_conflict_is_reported_by_address_and_port() {
        let mut table = IngressTable::with_defaults();
        table
            .declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 80))
            .unwrap();
        let err = table
            .declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 90))
            .unwrap_err();
        assert!(
            matches!(err, IngressError::BindConflict { addr: a, port: 8080 } if a == addr(127, 0, 0, 1))
        );
        assert_eq!(table.len(), 1, "the conflicting mapping must not land");
    }

    #[test]
    fn the_same_host_port_on_a_different_address_is_not_a_conflict() {
        let mut table = IngressTable::with_defaults();
        table
            .declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 80))
            .unwrap();
        table
            .declare(IngressMapping::tcp(addr(10, 0, 0, 1), 8080, 81))
            .unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn wildcard_exposure_can_be_refused() {
        let mut table = IngressTable::without_wildcard();
        assert!(matches!(
            table.declare(IngressMapping::tcp(WILDCARD, 8080, 80)),
            Err(IngressError::WildcardNotAdmitted { port: 8080 })
        ));
        // An explicit address is still fine.
        assert!(
            table
                .declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 80))
                .is_ok()
        );
    }

    #[test]
    fn wildcard_is_recognized_for_both_families() {
        assert!(IngressMapping::tcp(WILDCARD, 1, 1).is_wildcard());
        assert!(IngressMapping::tcp("::".parse().unwrap(), 1, 1).is_wildcard());
        assert!(!IngressMapping::tcp(addr(127, 0, 0, 1), 1, 1).is_wildcard());
    }

    /// A datagram mapping is a declaration like any other, and admission
    /// keys on the protocol as well as the port: a UDP mapping opens no
    /// TCP port and vice versa.
    #[test]
    fn a_declared_udp_mapping_admits_its_guest_port_and_only_its_protocol() {
        let mut table = IngressTable::with_defaults();
        table
            .declare(IngressMapping::udp(addr(127, 0, 0, 1), 5353, 53))
            .unwrap();
        assert!(table.admits(proto::UDP, 53));
        assert!(!table.admits(proto::TCP, 53), "protocol must match");
        assert!(!table.admits(proto::UDP, 54), "no mapping, no admission");
    }

    #[test]
    fn port_zero_is_refused_on_either_side() {
        let mut table = IngressTable::with_defaults();
        assert!(matches!(
            table.declare(IngressMapping::tcp(addr(127, 0, 0, 1), 0, 80)),
            Err(IngressError::ZeroPort)
        ));
        assert!(matches!(
            table.declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 0)),
            Err(IngressError::ZeroPort)
        ));
    }

    #[test]
    fn the_table_fails_closed_when_full() {
        let mut table = IngressTable::new(2, true);
        for port in 0..2u16 {
            table
                .declare(IngressMapping::tcp(
                    addr(127, 0, 0, 1),
                    8080 + port,
                    80 + port,
                ))
                .unwrap();
        }
        assert!(matches!(
            table.declare(IngressMapping::tcp(addr(127, 0, 0, 1), 9000, 90)),
            Err(IngressError::TableFull { limit: 2 })
        ));
    }

    #[test]
    fn withdrawing_a_mapping_closes_its_guest_port() {
        let mut table = IngressTable::with_defaults();
        table
            .declare(IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 80))
            .unwrap();
        assert!(table.withdraw(addr(127, 0, 0, 1), 8080).is_some());
        assert!(!table.admits(proto::TCP, 80));
        assert!(table.withdraw(addr(127, 0, 0, 1), 8080).is_none());
    }

    #[test]
    fn clearing_removes_every_mapping_so_a_restart_inherits_none() {
        let mut table = IngressTable::with_defaults();
        for port in 0..5u16 {
            table
                .declare(IngressMapping::tcp(
                    addr(127, 0, 0, 1),
                    8080 + port,
                    80 + port,
                ))
                .unwrap();
        }
        let closed = table.clear();
        assert_eq!(closed.len(), 5);
        assert!(table.is_empty());
        for port in 0..5u16 {
            assert!(!table.admits(proto::TCP, 80 + port));
        }
    }

    #[test]
    fn lookup_by_host_listener_finds_the_mapping() {
        let mut table = IngressTable::with_defaults();
        let mapping = IngressMapping::tcp(addr(127, 0, 0, 1), 8080, 80);
        table.declare(mapping).unwrap();
        assert_eq!(table.for_host(addr(127, 0, 0, 1), 8080), Some(&mapping));
        assert_eq!(table.for_host(addr(127, 0, 0, 1), 9999), None);
    }
}
