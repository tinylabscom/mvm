// The raw-L3 egress gate parses every guest IPv4 packet before any host
// forwarding decision — the first parse on the vsock-tunnel egress path, on
// attacker-influenced bytes. "Never panic on any input": the parser fails
// closed to `None` on malformed/short/non-IPv4 bytes, and the full gate
// decision never panics for any accepted or rejected packet.

#![no_main]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
use mvm_hostd::net_l3::{L3ForwardPolicy, parse_ipv4_dst_and_l4};

// One admitted host pinned to a fixed IPv4 so the decision path exercises the
// allow-set lookup for arbitrary parsed destinations, not just the drop path.
static GATE: LazyLock<L3ForwardPolicy> = LazyLock::new(|| {
    let policy = NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)]);
    let mut pins = DnsPinRegistry::new();
    pins.add(DnsPin::at(
        "example.com",
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))],
        "2030-01-01T00:00:00Z",
        "2030-01-01T01:00:00Z",
    ));
    L3ForwardPolicy::new(policy, pins)
});

fuzz_target!(|data: &[u8]| {
    // Raw destination/L4 parser on arbitrary bytes: fail closed, never panic.
    let _ = parse_ipv4_dst_and_l4(data);
    // Full gate decision on arbitrary bytes: never panic.
    let _ = GATE.decide_packet(data);
});
