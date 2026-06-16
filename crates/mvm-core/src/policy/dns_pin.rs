//! DNS admission-time pin data model.
//!
//! When a workload's [`NetworkPolicy`] permits a host
//! destination (e.g. `api.openai.com:443`), the supervisor
//! resolves that host *once* at admission time and records the
//! resulting IP set in a `DnsPinRegistry` keyed by the
//! destination. The L7 egress proxy and the L4 substrate
//! consult the registry on every outbound flow:
//!
//! - Connection observed → `registry.lookup(host)?` returns the
//!   pin
//! - Pin still valid → `pin.is_valid_at(now)` checks TTL
//! - Observed IP matches → `pin.matches(observed_ip)` is the
//!   "permitted" gate
//!
//! A divergence between pinned and observed IPs is a DNS
//! rebinding signal and emits `LocalAuditKind::DnsPinReject`.
//!
//! This module is a **state-only slice**: types + tests, no
//! resolver, no enforcement, no audit emission. Those land in
//! mvmd's resolver and L7 proxy. Shipping the type now lets
//! emission sites and resolver impls land independently without
//! re-bumping the wire format.
//!
//! ## Wire format stability
//!
//! Time fields are RFC 3339 strings (matching the existing
//! audit-log convention in `mvm-core::policy::audit`).
//! `DnsPin`'s serde shape is the canonical contract between
//! `mvm-core` (producer of the type) and `mvmd`'s tenant audit
//! aggregation (consumer). Adding fields uses `#[serde(default)]`
//! to stay backward-compatible with old logs across the repo
//! boundary.
//!
//! [`NetworkPolicy`]: crate::policy::network_policy::NetworkPolicy

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// One admission-time DNS pin.
///
/// `dest` is the user-facing destination string the workload's
/// policy permits (typically a hostname, e.g. `api.openai.com`).
/// `ips` is the full resolved IP set — when the resolver returns
/// multiple A/AAAA records, every address is pinned and any one
/// is acceptable on a future flow (DNS round-robin and CDN
/// rotation are common; the pin set captures the snapshot the
/// admission-time resolver saw).
///
/// `resolved_at` + `expires_at` are RFC 3339 strings (UTC), the
/// same convention `LocalAuditEvent` uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPin {
    /// User-facing destination string. Typically a hostname,
    /// but a literal IP is also valid (in which case `ips`
    /// trivially contains that one IP and `matches` is a
    /// equality check).
    pub dest: String,
    /// Every IP the resolver returned at admission time. Pin
    /// matching is "observed ∈ ips" so multi-A / CDN-anycast
    /// destinations don't false-positive on a future flow that
    /// hits a different IP from the same set.
    pub ips: Vec<IpAddr>,
    /// RFC 3339 UTC timestamp of the admission-time resolve.
    pub resolved_at: String,
    /// RFC 3339 UTC timestamp after which the pin is stale and
    /// the resolver should refresh.
    pub expires_at: String,
}

impl DnsPin {
    /// Construct a pin from the canonical inputs. Computes
    /// `resolved_at = Utc::now()` and `expires_at =
    /// resolved_at + ttl`. The `ttl` is the operator-supplied
    /// validity window — typically 1h, capped per tenant policy.
    pub fn new(dest: impl Into<String>, ips: Vec<IpAddr>, ttl: Duration) -> Self {
        let now = Utc::now();
        let expires = now + ttl;
        Self {
            dest: dest.into(),
            ips,
            resolved_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        }
    }

    /// Pure-input constructor used by tests + deserializers
    /// that already have the timestamps in hand. Production
    /// callers prefer [`Self::new`].
    pub fn at(
        dest: impl Into<String>,
        ips: Vec<IpAddr>,
        resolved_at: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        Self {
            dest: dest.into(),
            ips,
            resolved_at: resolved_at.into(),
            expires_at: expires_at.into(),
        }
    }

    /// `true` when `observed` is in the pinned IP set.
    /// Equality on `IpAddr` handles both IPv4 + IPv6 cleanly.
    /// Pure — no I/O, no clock read.
    pub fn matches(&self, observed: &IpAddr) -> bool {
        self.ips.iter().any(|ip| ip == observed)
    }

    /// `true` when `now < expires_at`. Pure given the supplied
    /// `now` (RFC 3339 UTC). Test consumers pass a fixed string;
    /// production passes `Utc::now().to_rfc3339()`.
    ///
    /// Parse failures on either side return `false` (treat
    /// unparseable timestamps as expired) — fail-closed:
    /// rather emit a false `DnsPinReject` than let a malformed
    /// pin masquerade as valid.
    pub fn is_valid_at(&self, now: &str) -> bool {
        let Ok(now_dt) = DateTime::parse_from_rfc3339(now) else {
            return false;
        };
        let Ok(exp_dt) = DateTime::parse_from_rfc3339(&self.expires_at) else {
            return false;
        };
        now_dt < exp_dt
    }

    /// Derived TTL in seconds — `expires_at - resolved_at`.
    /// The audit detail format for `DnsPinSet` carries
    /// `ttl_s=<n>`; this helper produces it directly. Returns
    /// `0` if either timestamp fails to
    /// parse — defensive but a malformed pin wouldn't pass
    /// admission anyway.
    pub fn ttl_secs(&self) -> i64 {
        let (Ok(r), Ok(e)) = (
            DateTime::parse_from_rfc3339(&self.resolved_at),
            DateTime::parse_from_rfc3339(&self.expires_at),
        ) else {
            return 0;
        };
        (e - r).num_seconds()
    }
}

/// Pin store keyed by destination string.
///
/// Per-workload (or per-tenant, depending on the consumer's
/// scope choice). `mvmd`'s supervisor instantiates one per
/// admission and threads it through to the L7 proxy + the L4
/// substrate.
///
/// Internally a `BTreeMap` so iteration is sorted — that
/// makes audit logging deterministic. The map is the
/// load-bearing structure; lookups are O(log n) which is
/// fine for the typical per-workload allow-list size
/// (<50 entries).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPinRegistry {
    #[serde(default)]
    pub pins: BTreeMap<String, DnsPin>,
}

impl DnsPinRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a pin. A replace is a legitimate
    /// case — the resolver refreshes a pin at TTL/2 and the
    /// new IP set may differ; the registry holds the latest.
    pub fn add(&mut self, pin: DnsPin) {
        self.pins.insert(pin.dest.clone(), pin);
    }

    /// O(log n) lookup by destination string.
    pub fn lookup(&self, dest: &str) -> Option<&DnsPin> {
        self.pins.get(dest)
    }

    /// Number of pins currently in the registry.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// `true` when the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Iterator over every (dest, pin) pair. Sorted by dest.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &DnsPin)> {
        self.pins.iter()
    }

    /// Drop every pin whose `expires_at` is past `now`. Returns
    /// the number of pins removed. Used by the resolver's
    /// background sweep + by tests that pin a synthetic clock.
    pub fn prune_expired(&mut self, now: &str) -> usize {
        let before = self.pins.len();
        self.pins.retain(|_, pin| pin.is_valid_at(now));
        before - self.pins.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn fixed_pin(dest: &str, ips: &[&str]) -> DnsPin {
        DnsPin::at(
            dest,
            ips.iter().map(|s| ip(s)).collect(),
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        )
    }

    #[test]
    fn pin_matches_single_a_record() {
        let pin = fixed_pin("api.openai.com", &["104.18.7.42"]);
        assert!(pin.matches(&ip("104.18.7.42")));
        assert!(!pin.matches(&ip("104.18.7.43")));
    }

    #[test]
    fn pin_matches_multi_a_record_set_membership() {
        // A real CDN-anycast destination resolves to multiple
        // IPs; any of them on a future flow is permitted.
        let pin = fixed_pin(
            "api.openai.com",
            &["104.18.7.42", "104.18.32.1", "162.159.135.232"],
        );
        for ok in ["104.18.7.42", "104.18.32.1", "162.159.135.232"] {
            assert!(pin.matches(&ip(ok)), "{ok} must match");
        }
        // An IP outside the pinned set is rejected — this is
        // the DNS-rebinding signal that fires `DnsPinReject`.
        assert!(!pin.matches(&ip("169.254.169.254")));
    }

    #[test]
    fn pin_supports_ipv6() {
        let pin = DnsPin::at(
            "dns.google",
            vec![ip("2001:4860:4860::8888")],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        );
        assert!(pin.matches(&ip("2001:4860:4860::8888")));
        assert!(!pin.matches(&ip("2001:4860:4860::8844")));
    }

    #[test]
    fn pin_is_valid_before_expires_at() {
        let pin = fixed_pin("example.com", &["93.184.216.34"]);
        // expires at 13:00:00; check earlier.
        assert!(pin.is_valid_at("2026-05-15T12:30:00Z"));
        assert!(pin.is_valid_at("2026-05-15T12:59:59Z"));
    }

    #[test]
    fn pin_is_invalid_after_expires_at() {
        let pin = fixed_pin("example.com", &["93.184.216.34"]);
        assert!(!pin.is_valid_at("2026-05-15T13:00:00Z")); // boundary
        assert!(!pin.is_valid_at("2026-05-15T13:00:01Z"));
        assert!(!pin.is_valid_at("2026-06-01T00:00:00Z"));
    }

    #[test]
    fn pin_with_unparseable_now_fails_closed() {
        let pin = fixed_pin("example.com", &["93.184.216.34"]);
        // A garbage `now` shouldn't accidentally validate a
        // pin. The function returns false on parse failure.
        assert!(!pin.is_valid_at("not-a-timestamp"));
    }

    #[test]
    fn pin_with_unparseable_expires_at_fails_closed() {
        let pin = DnsPin::at(
            "example.com",
            vec![ip("93.184.216.34")],
            "2026-05-15T12:00:00Z",
            "garbage",
        );
        assert!(!pin.is_valid_at("2026-05-15T12:30:00Z"));
    }

    #[test]
    fn pin_ttl_secs_computes_from_timestamps() {
        let pin = fixed_pin("example.com", &["93.184.216.34"]);
        // 12:00:00 → 13:00:00 = 3600s.
        assert_eq!(pin.ttl_secs(), 3600);
    }

    #[test]
    fn pin_ttl_secs_returns_zero_on_malformed_timestamps() {
        let pin = DnsPin::at(
            "example.com",
            vec![ip("93.184.216.34")],
            "garbage",
            "garbage",
        );
        assert_eq!(pin.ttl_secs(), 0);
    }

    #[test]
    fn pin_new_uses_utc_now_and_sets_expires() {
        // `Utc::now()` makes the test wall-clock dependent —
        // we don't pin a specific timestamp, but we can assert
        // the relative invariant (ttl matches the supplied
        // Duration) and that the pin is_valid_at the same
        // resolved_at it just stamped.
        let pin = DnsPin::new(
            "example.com",
            vec![ip("93.184.216.34")],
            Duration::seconds(3600),
        );
        assert_eq!(pin.ttl_secs(), 3600);
        assert!(pin.is_valid_at(&pin.resolved_at));
    }

    #[test]
    fn pin_serde_roundtrip_preserves_every_field() {
        let pin = DnsPin::at(
            "api.openai.com",
            vec![ip("104.18.7.42"), ip("104.18.32.1")],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        );
        let json = serde_json::to_string(&pin).unwrap();
        let parsed: DnsPin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pin);
    }

    #[test]
    fn pin_serde_emits_stable_field_names() {
        // Pin the wire format. A future rename surfaces here
        // and forces a conscious decision about old-log readability.
        let pin = fixed_pin("example.com", &["93.184.216.34"]);
        let value = serde_json::to_value(&pin).unwrap();
        let obj = value.as_object().unwrap();
        for key in ["dest", "ips", "resolved_at", "expires_at"] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
    }

    // ────────────────────────────────────────────────────────
    // DnsPinRegistry
    // ────────────────────────────────────────────────────────

    #[test]
    fn registry_add_and_lookup_round_trip() {
        let mut reg = DnsPinRegistry::new();
        let pin = fixed_pin("example.com", &["93.184.216.34"]);
        reg.add(pin.clone());
        assert_eq!(reg.lookup("example.com"), Some(&pin));
        assert_eq!(reg.lookup("missing.example.com"), None);
    }

    #[test]
    fn registry_add_replaces_existing_pin_for_same_dest() {
        // Resolver refresh case: same dest, different IPs (CDN
        // rotated the answer). The registry holds the latest.
        let mut reg = DnsPinRegistry::new();
        let pin_v1 = fixed_pin("example.com", &["93.184.216.34"]);
        let pin_v2 = fixed_pin("example.com", &["104.18.7.42"]);
        reg.add(pin_v1);
        reg.add(pin_v2.clone());
        assert_eq!(reg.lookup("example.com"), Some(&pin_v2));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_iterates_sorted_by_dest() {
        // Deterministic iteration matters for audit-log
        // reproducibility — a tenant grep should see pins in a
        // stable order.
        let mut reg = DnsPinRegistry::new();
        for dest in ["zeta.com", "alpha.com", "mu.com"] {
            reg.add(fixed_pin(dest, &["1.2.3.4"]));
        }
        let collected: Vec<&str> = reg.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(collected, vec!["alpha.com", "mu.com", "zeta.com"]);
    }

    #[test]
    fn registry_prune_expired_drops_only_stale_pins() {
        let mut reg = DnsPinRegistry::new();
        // Active pin: expires 2026-05-15T13:00:00.
        reg.add(fixed_pin("active.example.com", &["1.2.3.4"]));
        // Stale pin: expires 2026-05-15T11:00:00.
        reg.add(DnsPin::at(
            "stale.example.com",
            vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))],
            "2026-05-15T10:00:00Z",
            "2026-05-15T11:00:00Z",
        ));
        let removed = reg.prune_expired("2026-05-15T12:30:00Z");
        assert_eq!(removed, 1);
        assert!(reg.lookup("active.example.com").is_some());
        assert!(reg.lookup("stale.example.com").is_none());
    }

    #[test]
    fn registry_prune_expired_returns_zero_when_no_pins_stale() {
        let mut reg = DnsPinRegistry::new();
        reg.add(fixed_pin("a.com", &["1.2.3.4"]));
        reg.add(fixed_pin("b.com", &["5.6.7.8"]));
        let removed = reg.prune_expired("2026-05-15T12:30:00Z");
        assert_eq!(removed, 0);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn registry_serde_roundtrip_preserves_pins() {
        let mut reg = DnsPinRegistry::new();
        reg.add(fixed_pin("a.com", &["1.2.3.4"]));
        reg.add(fixed_pin("b.com", &["5.6.7.8", "9.10.11.12"]));
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: DnsPinRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, reg);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = DnsPinRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }
}
