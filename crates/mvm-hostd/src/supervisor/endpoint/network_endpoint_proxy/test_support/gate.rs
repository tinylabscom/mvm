//! The claim-10 gate every endpoint test builds its service under.
//!
//! It lives in its own file, with no dependency on this crate's private
//! items, so the integration tests in `tests/` can include the same
//! definition by path instead of keeping a copy.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
use mvm_runtime::vmm::egress_gate::EgressGate;

/// A claim-10 gate admitting exactly `destinations`, each a `(host, port)`.
///
/// Every service needs a gate, and a test that is not about claim 10 must not
/// be able to pass because the gate refused. So a test gets a gate admitting
/// precisely the destinations it sends to, and its refusal can only come from
/// the thing it names. Claim-10 tests build their own gate.
///
/// No DNS is done. A numeric host pins to itself. Each distinct hostname pins
/// to its own address in TEST-NET-1 (`192.0.2.0/24`), which is outside the
/// mandatory-deny ranges, so the name is admitted on the ports listed and
/// nowhere else. An unrestricted gate is not a usable stand-in: it resolves
/// unpinned names through the host resolver, putting a live lookup inside the
/// test.
///
/// Loopback cannot be admitted. `127.0.0.0/8` and `::1` are mandatory-deny,
/// applied before any rule, so a pinned `127.0.0.1` is still refused. A test
/// that forwards to a local fixture server therefore sends to a public
/// address the gate admits and gives the service a forwarder that dials the
/// fixture instead, as `tests/wasm_egress_witness.rs` does.
pub(crate) fn gate_admitting(destinations: &[(&str, u16)]) -> Arc<EgressGate> {
    let now = chrono::Utc::now();
    let expires = (now + chrono::Duration::hours(1)).to_rfc3339();
    let now = now.to_rfc3339();
    let mut pins = DnsPinRegistry::new();
    let mut named = 0u8;
    for (host, _) in destinations {
        if pins.lookup(host).is_some() {
            continue;
        }
        let ip = host.parse::<IpAddr>().unwrap_or_else(|_| {
            named += 1;
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, named))
        });
        pins.add(DnsPin::at(*host, vec![ip], now.as_str(), expires.as_str()));
    }
    let policy = NetworkPolicy::allow_list(
        destinations
            .iter()
            .map(|(host, port)| HostPort::new(*host, *port))
            .collect(),
    );
    Arc::new(EgressGate::from_network_policy(&policy, &pins, &now))
}
