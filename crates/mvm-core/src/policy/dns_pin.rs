//! DNS admission-time pin construction and `NetworkPolicy` resolution.
//! The [`DnsPin`]/[`DnsPinRegistry`] DTO and their pure parse/match
//! methods live in `mvm_contract::policy::dns_pin`, re-exported here so
//! every existing `crate::policy::dns_pin::{DnsPin, DnsPinRegistry}`
//! path keeps resolving unchanged.

use std::net::IpAddr;

use chrono::{Duration, Utc};

pub use mvm_contract::policy::dns_pin::{DnsPin, DnsPinRegistry};

/// Construct a pin from the canonical inputs. Computes
/// `resolved_at = Utc::now()` and `expires_at =
/// resolved_at + ttl`. The `ttl` is the operator-supplied
/// validity window — typically 1h, capped per tenant policy.
///
/// A free function rather than an inherent method on [`DnsPin`]:
/// that type now lives in `mvm-contract`, and the orphan rule
/// forbids `mvm-core` from adding inherent `impl`s to a foreign
/// type. `Utc::now()` also needs chrono's `clock` feature (std),
/// unavailable in the no_std `mvm-contract` crate.
pub fn new_pin(dest: impl Into<String>, ips: Vec<IpAddr>, ttl: Duration) -> DnsPin {
    let now = Utc::now();
    let expires = now + ttl;
    DnsPin {
        dest: dest.into(),
        ips,
        resolved_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
    }
}

/// Resolve a [`NetworkPolicy`]'s host-allowlist entries to their IP sets so
/// `host:port` rules gate on concrete addresses (the admission-time pin).
///
/// A literal IP needs no lookup and pins to itself; a hostname is resolved via
/// the host resolver once. An unresolvable host pins an **empty** IP set so the
/// downstream projection fails CLOSED (deny) rather than widening. An
/// unrestricted policy has no host rules and yields an empty registry — an
/// IP-pinning gate can only ever admit explicitly pinned destinations.
///
/// This performs blocking DNS I/O for hostname rules; call it once at admission
/// time, not on a hot path.
///
/// [`NetworkPolicy`]: crate::policy::network_policy::NetworkPolicy
pub fn resolve_network_policy_pins(
    policy: &crate::policy::network_policy::NetworkPolicy,
) -> DnsPinRegistry {
    use std::net::ToSocketAddrs;
    let mut reg = DnsPinRegistry::new();
    let Some(rules) = policy.resolve_rules() else {
        return reg; // unrestricted: no host rules to pin
    };
    for hp in rules {
        let mut ips: Vec<IpAddr> = if let Ok(ip) = hp.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (hp.host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|sa| sa.ip()).collect())
                .unwrap_or_default()
        };
        sort_ipv4_first(&mut ips);
        reg.add(new_pin(hp.host, ips, Duration::hours(24)));
    }
    reg
}

/// Order an address set IPv4-first, stable within each family. Host resolvers
/// commonly return IPv6 first (macOS `getaddrinfo` does), which strands an
/// admitted connect when the host has no IPv6 egress. Pinning IPv4-first makes
/// the downstream happy-eyeballs connect prefer the routable IPv4 address.
pub fn sort_ipv4_first(ips: &mut [IpAddr]) {
    ips.sort_by_key(|ip| ip.is_ipv6());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pin_new_uses_utc_now_and_sets_expires() {
        // `Utc::now()` makes the test wall-clock dependent —
        // we don't pin a specific timestamp, but we can assert
        // the relative invariant (ttl matches the supplied
        // Duration) and that the pin is_valid_at the same
        // resolved_at it just stamped.
        let pin = new_pin(
            "example.com",
            vec![ip("93.184.216.34")],
            Duration::seconds(3600),
        );
        assert_eq!(pin.ttl_secs(), 3600);
        assert!(pin.is_valid_at(&pin.resolved_at));
    }

    #[test]
    fn resolve_pins_literal_ip_allowlist_pins_to_itself() {
        use crate::policy::network_policy::{HostPort, NetworkPolicy};
        // A literal-IP allow-list needs no DNS: each host pins to itself.
        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("93.184.216.34", 443),
            HostPort::new("1.1.1.1", 53),
        ]);
        let reg = resolve_network_policy_pins(&policy);
        assert_eq!(reg.len(), 2);
        assert_eq!(
            reg.lookup("93.184.216.34").unwrap().ips,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            reg.lookup("1.1.1.1").unwrap().ips,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn sort_ipv4_first_orders_v4_before_v6_stably() {
        // Mirrors the macOS getaddrinfo order for a dual-stack host: IPv6 first.
        // After sorting, both IPv4 addresses lead and within-family order is
        // preserved so the connect prefers the routable IPv4 pin.
        let mut ips = vec![
            ip("2606:4700:10::6814:179a"),
            ip("2606:4700:10::ac42:93f3"),
            ip("172.66.147.243"),
            ip("104.20.23.154"),
        ];
        sort_ipv4_first(&mut ips);
        assert_eq!(
            ips,
            vec![
                ip("172.66.147.243"),
                ip("104.20.23.154"),
                ip("2606:4700:10::6814:179a"),
                ip("2606:4700:10::ac42:93f3"),
            ]
        );
    }

    #[test]
    fn resolve_pins_deny_all_and_unrestricted_yield_empty_registry() {
        use crate::policy::network_policy::NetworkPolicy;
        // deny-all has an empty rule set; unrestricted has no host rules at all.
        assert!(resolve_network_policy_pins(&NetworkPolicy::deny_all()).is_empty());
        assert!(resolve_network_policy_pins(&NetworkPolicy::unrestricted()).is_empty());
    }
}
