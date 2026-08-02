//! Host-controlled DNS bindings for L3 mode.
//!
//! A domain allowlist means nothing if the guest may resolve names itself
//! and then connect to whatever address it likes. So in L3 mode the guest
//! is pointed at a synthetic resolver on the gateway address, every other
//! DNS destination is refused, and an address only becomes reachable once
//! *this* store has bound it to an admitted name.
//!
//! The store is the bridge between "policy admitted `api.example.com:443`"
//! and "may this packet go to 93.184.216.34:443". It is bounded in names,
//! addresses per name, and total entries, and every binding expires.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

/// Most distinct names one machine may hold bindings for.
pub const DEFAULT_MAX_NAMES: usize = 256;

/// Most addresses a single name may bind. CDN round-robin answers are
/// commonly a handful; a resolver returning hundreds is either broken or
/// hostile.
pub const DEFAULT_MAX_ADDRS_PER_NAME: usize = 16;

/// Most bindings in total, across all names.
pub const DEFAULT_MAX_BINDINGS: usize = 1024;

/// Longest CNAME chain the resolver will follow before refusing.
pub const DEFAULT_MAX_ALIAS_DEPTH: usize = 8;

/// Most in-flight queries for one machine.
pub const DEFAULT_MAX_INFLIGHT_QUERIES: usize = 32;

/// Ceiling applied to an upstream TTL. A resolver that returns a
/// month-long TTL must not pin an address in this table for a month.
pub const DEFAULT_MAX_TTL_MILLIS: u64 = 300_000;

/// Floor applied to an upstream TTL, so a zero-TTL answer is still usable
/// long enough for the connection it was resolved for.
pub const DEFAULT_MIN_TTL_MILLIS: u64 = 5_000;

/// Bounds for one machine's DNS state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsLimits {
    pub max_names: usize,
    pub max_addrs_per_name: usize,
    pub max_bindings: usize,
    pub max_alias_depth: usize,
    pub max_inflight_queries: usize,
    pub max_ttl_millis: u64,
    pub min_ttl_millis: u64,
}

impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            max_names: DEFAULT_MAX_NAMES,
            max_addrs_per_name: DEFAULT_MAX_ADDRS_PER_NAME,
            max_bindings: DEFAULT_MAX_BINDINGS,
            max_alias_depth: DEFAULT_MAX_ALIAS_DEPTH,
            max_inflight_queries: DEFAULT_MAX_INFLIGHT_QUERIES,
            max_ttl_millis: DEFAULT_MAX_TTL_MILLIS,
            min_ttl_millis: DEFAULT_MIN_TTL_MILLIS,
        }
    }
}

/// One admitted address for one admitted name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsBinding {
    /// The name policy admitted, normalized to lowercase without a
    /// trailing dot.
    pub name: String,
    /// Ports the plan admits for this name. A binding never widens the
    /// port set the policy granted.
    pub ports: Vec<u16>,
    /// Milliseconds after which the binding is stale.
    pub expires_at_millis: u64,
    /// The policy epoch under which it was created. A plan revision
    /// invalidates every binding rather than letting a stale answer
    /// outlive the rules that approved it.
    pub policy_epoch: u64,
}

impl DnsBinding {
    pub fn is_valid_at(&self, now_millis: u64) -> bool {
        now_millis < self.expires_at_millis
    }

    /// Whether this binding covers `port`. An empty port list means the
    /// name was admitted without a port constraint.
    pub fn permits_port(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }
}

/// Why an answer or a binding was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsDeny {
    /// The plan does not admit this name.
    #[error("name {0:?} is not admitted by policy")]
    NameNotAdmitted(String),
    /// An answer pointed into a range a guest may not reach — the classic
    /// DNS rebinding move.
    #[error("answer {ip} for {name:?} rebinds into a prohibited range")]
    Rebinding { name: String, ip: IpAddr },
    /// Every answer for the name was filtered out.
    #[error("no admissible answer for {0:?}")]
    NoAdmissibleAnswer(String),
    /// The store is full.
    #[error("dns binding table full ({limit} entries)")]
    TableFull { limit: usize },
    /// Too many distinct names.
    #[error("dns name table full ({limit} names)")]
    NameTableFull { limit: usize },
    /// The alias chain was longer than the bound.
    #[error("alias chain for {name:?} exceeded depth {limit}")]
    AliasChainTooDeep { name: String, limit: usize },
    /// The query name was unusable.
    #[error("malformed query name")]
    MalformedName,
}

/// One machine's DNS bindings.
#[derive(Debug)]
pub struct DnsBindingStore {
    /// Keyed by address: the hot-path question is always "is this
    /// destination bound", never "what did this name resolve to".
    bindings: BTreeMap<IpAddr, DnsBinding>,
    limits: DnsLimits,
    /// Ranges the plan explicitly opened. An answer inside one of these is
    /// admissible even though it would otherwise be refused as private.
    admitted_private: Vec<IpNet>,
    denied: u64,
    admitted: u64,
}

impl DnsBindingStore {
    pub fn new(limits: DnsLimits, admitted_private: Vec<IpNet>) -> Self {
        Self {
            bindings: BTreeMap::new(),
            limits,
            admitted_private,
            denied: 0,
            admitted: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DnsLimits::default(), Vec::new())
    }

    /// Filter an upstream answer set down to the addresses a guest may be
    /// told about, then bind them.
    ///
    /// `ttl_millis` is the upstream TTL; it is clamped into the store's
    /// bounds. Returns the addresses actually bound — which is what the
    /// resolver should put in the response, so the guest is never handed
    /// an address it would then be refused for using.
    pub fn bind_answer(
        &mut self,
        name: &str,
        answers: &[IpAddr],
        ports: &[u16],
        ttl_millis: u64,
        policy_epoch: u64,
        now_millis: u64,
    ) -> Result<Vec<IpAddr>, DnsDeny> {
        let name = normalize_name(name).ok_or(DnsDeny::MalformedName)?;

        self.prune_expired(now_millis);

        let mut admissible = Vec::new();
        for ip in answers.iter().copied() {
            if self.answer_is_forbidden(ip) {
                self.denied += 1;
                return Err(DnsDeny::Rebinding {
                    name: name.clone(),
                    ip,
                });
            }
            if admissible.len() >= self.limits.max_addrs_per_name {
                break;
            }
            if !admissible.contains(&ip) {
                admissible.push(ip);
            }
        }
        if admissible.is_empty() {
            self.denied += 1;
            return Err(DnsDeny::NoAdmissibleAnswer(name));
        }

        let distinct_names = self.distinct_names();
        if !self.has_name(&name) && distinct_names >= self.limits.max_names {
            return Err(DnsDeny::NameTableFull {
                limit: self.limits.max_names,
            });
        }
        if self.bindings.len() + admissible.len() > self.limits.max_bindings {
            return Err(DnsDeny::TableFull {
                limit: self.limits.max_bindings,
            });
        }

        let ttl = ttl_millis.clamp(self.limits.min_ttl_millis, self.limits.max_ttl_millis);
        let expires_at_millis = now_millis.saturating_add(ttl);
        for ip in &admissible {
            self.bindings.insert(
                *ip,
                DnsBinding {
                    name: name.clone(),
                    ports: ports.to_vec(),
                    expires_at_millis,
                    policy_epoch,
                },
            );
        }
        self.admitted += 1;
        Ok(admissible)
    }

    /// The live binding for `ip`, if any.
    pub fn lookup(&self, ip: &IpAddr, now_millis: u64) -> Option<&DnsBinding> {
        self.bindings
            .get(ip)
            .filter(|binding| binding.is_valid_at(now_millis))
    }

    /// Whether a packet to `ip:port` is covered by a live binding under
    /// `policy_epoch`. A binding from a superseded epoch never counts.
    pub fn permits(&self, ip: &IpAddr, port: u16, policy_epoch: u64, now_millis: u64) -> bool {
        self.lookup(ip, now_millis)
            .is_some_and(|b| b.policy_epoch == policy_epoch && b.permits_port(port))
    }

    /// Drop expired bindings. Returns how many went.
    pub fn prune_expired(&mut self, now_millis: u64) -> usize {
        let before = self.bindings.len();
        self.bindings.retain(|_, b| b.is_valid_at(now_millis));
        before - self.bindings.len()
    }

    /// Drop everything. Called on session end and on policy-epoch change.
    pub fn clear(&mut self) {
        self.bindings.clear();
    }

    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn limits(&self) -> DnsLimits {
        self.limits
    }

    pub fn admitted_count(&self) -> u64 {
        self.admitted
    }

    pub fn denied_count(&self) -> u64 {
        self.denied
    }

    /// Whether an answer address must never be returned to a guest.
    ///
    /// Reuses `mvm-core`'s shared guard for the mandatory-deny set, then
    /// adds L3 mode's own private-range refusal: `MANDATORY_DENY_RANGES`
    /// does not include RFC1918, because on the socket-aware path the host
    /// resolver and connect logic bound the exposure. Here the guest emits
    /// packets, so private ranges are closed unless the plan opened them.
    fn answer_is_forbidden(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        // The shared guard refuses every RFC1918 / ULA answer outright,
        // which is right for the socket-aware path. L3 mode can open a
        // private range by explicit plan rule, so an answer inside an
        // admitted range short-circuits to allowed.
        //
        // This is safe because the guard's private clause is disjoint from
        // its others: `is_private()` covers 10/8, 172.16/12 and 192.168/16,
        // none of which overlap loopback, link-local, unspecified, or CGNAT
        // — and `fc00::/7` likewise overlaps none of the IPv6 clauses. So
        // an address that is private *and* admitted cannot also be one the
        // guard refuses for a different reason.
        if is_private_ip(ip) && self.admitted_private.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        mvm_core::policy::dns_guard::dns_answer_forbidden(ip)
    }

    fn distinct_names(&self) -> usize {
        let mut names: Vec<&str> = self.bindings.values().map(|b| b.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names.len()
    }

    fn has_name(&self, name: &str) -> bool {
        self.bindings.values().any(|b| b.name == name)
    }
}

/// Lowercase, strip a trailing dot, and refuse anything unusable as a
/// policy key.
pub fn normalize_name(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    if trimmed.contains(char::is_whitespace) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Walk a CNAME chain with a depth bound, returning the terminal name.
///
/// The resolver holds the chain; this is the bound applied to it. Split
/// out so the limit is testable without a resolver.
pub fn resolve_alias_chain(
    start: &str,
    chain: &BTreeMap<String, String>,
    limit: usize,
) -> Result<String, DnsDeny> {
    let mut current = normalize_name(start).ok_or(DnsDeny::MalformedName)?;
    for _ in 0..limit {
        match chain.get(&current) {
            Some(next) => {
                let next = normalize_name(next).ok_or(DnsDeny::MalformedName)?;
                if next == current {
                    // A self-referential alias would spin until the limit;
                    // treat it as terminal instead.
                    return Ok(current);
                }
                current = next;
            }
            None => return Ok(current),
        }
    }
    Err(DnsDeny::AliasChainTooDeep {
        name: current,
        limit,
    })
}

/// RFC1918 plus the IPv6 unique-local block.
fn is_private_ip(ip: IpAddr) -> bool {
    match normalize(ip) {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Collapse an IPv4-mapped IPv6 address so a `::ffff:10.0.0.1` answer
/// cannot slip past an IPv4-only range test.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const PUBLIC_2: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));

    fn fresh() -> DnsBindingStore {
        DnsBindingStore::with_defaults()
    }

    #[test]
    fn an_approved_answer_binds_and_then_permits_the_connection() {
        let mut store = fresh();
        let bound = store
            .bind_answer("api.example.com", &[PUBLIC], &[443], 60_000, 1, 0)
            .unwrap();
        assert_eq!(bound, vec![PUBLIC]);
        assert!(store.permits(&PUBLIC, 443, 1, 0));
    }

    #[test]
    fn a_bound_address_does_not_open_an_unadmitted_port() {
        let mut store = fresh();
        store
            .bind_answer("api.example.com", &[PUBLIC], &[443], 60_000, 1, 0)
            .unwrap();
        assert!(!store.permits(&PUBLIC, 8080, 1, 0));
    }

    #[test]
    fn a_binding_expires_at_its_ttl() {
        let mut store = fresh();
        store
            .bind_answer("api.example.com", &[PUBLIC], &[443], 30_000, 1, 0)
            .unwrap();
        assert!(store.permits(&PUBLIC, 443, 1, 29_999));
        assert!(!store.permits(&PUBLIC, 443, 1, 30_000));
    }

    #[test]
    fn an_upstream_ttl_is_clamped_into_the_stores_bounds() {
        let mut store = fresh();
        store
            .bind_answer("slow.example.com", &[PUBLIC], &[443], u64::MAX, 1, 0)
            .unwrap();
        assert!(!store.permits(&PUBLIC, 443, 1, DEFAULT_MAX_TTL_MILLIS));

        let mut store = fresh();
        store
            .bind_answer("fast.example.com", &[PUBLIC], &[443], 0, 1, 0)
            .unwrap();
        assert!(
            store.permits(&PUBLIC, 443, 1, DEFAULT_MIN_TTL_MILLIS - 1),
            "a zero-ttl answer must still last long enough to be used"
        );
    }

    #[test]
    fn a_binding_from_a_superseded_policy_epoch_does_not_count() {
        let mut store = fresh();
        store
            .bind_answer("api.example.com", &[PUBLIC], &[443], 60_000, 1, 0)
            .unwrap();
        assert!(store.permits(&PUBLIC, 443, 1, 0));
        assert!(
            !store.permits(&PUBLIC, 443, 2, 0),
            "a plan revision must not inherit the previous epoch's bindings"
        );
    }

    #[test]
    fn rebinding_into_loopback_is_refused() {
        let mut store = fresh();
        let err = store
            .bind_answer(
                "evil.example.com",
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                &[443],
                60_000,
                1,
                0,
            )
            .unwrap_err();
        assert!(matches!(err, DnsDeny::Rebinding { .. }));
    }

    #[test]
    fn rebinding_into_cloud_metadata_is_refused() {
        let mut store = fresh();
        assert!(matches!(
            store.bind_answer(
                "evil.example.com",
                &[IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
                &[80],
                60_000,
                1,
                0,
            ),
            Err(DnsDeny::Rebinding { .. })
        ));
    }

    #[test]
    fn rebinding_into_a_private_range_is_refused_by_default() {
        let mut store = fresh();
        for ip in [
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(172, 16, 0, 5),
            Ipv4Addr::new(192, 168, 1, 5),
        ] {
            assert!(
                matches!(
                    store.bind_answer("intra.example.com", &[IpAddr::V4(ip)], &[80], 60_000, 1, 0),
                    Err(DnsDeny::Rebinding { .. })
                ),
                "{ip} should be refused without an explicit rule"
            );
        }
    }

    #[test]
    fn an_explicitly_admitted_private_range_is_bindable() {
        let mut store = DnsBindingStore::new(
            DnsLimits::default(),
            vec!["10.42.0.0/16".parse::<IpNet>().unwrap()],
        );
        let ip = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 7));
        assert!(
            store
                .bind_answer("db.internal", &[ip], &[5432], 60_000, 1, 0)
                .is_ok()
        );
        assert!(store.permits(&ip, 5432, 1, 0));
        // A different private range stays closed.
        assert!(matches!(
            store.bind_answer(
                "other.internal",
                &[IpAddr::V4(Ipv4Addr::new(10, 43, 0, 1))],
                &[80],
                60_000,
                1,
                0
            ),
            Err(DnsDeny::Rebinding { .. })
        ));
    }

    #[test]
    fn an_ipv4_mapped_answer_cannot_smuggle_a_private_address() {
        let mut store = fresh();
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert!(matches!(
            store.bind_answer("evil.example.com", &[mapped], &[80], 60_000, 1, 0),
            Err(DnsDeny::Rebinding { .. })
        ));
    }

    #[test]
    fn an_ipv6_unique_local_answer_is_refused() {
        let mut store = fresh();
        let ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        assert!(matches!(
            store.bind_answer("evil.example.com", &[ula], &[80], 60_000, 1, 0),
            Err(DnsDeny::Rebinding { .. })
        ));
    }

    #[test]
    fn a_multi_address_answer_binds_every_address_up_to_the_cap() {
        let mut store = fresh();
        let answers: Vec<IpAddr> = (0..DEFAULT_MAX_ADDRS_PER_NAME as u8 + 10)
            .map(|i| IpAddr::V4(Ipv4Addr::new(93, 184, 216, i)))
            .collect();
        let bound = store
            .bind_answer("cdn.example.com", &answers, &[443], 60_000, 1, 0)
            .unwrap();
        assert_eq!(bound.len(), DEFAULT_MAX_ADDRS_PER_NAME);
    }

    #[test]
    fn duplicate_answers_bind_once() {
        let mut store = fresh();
        let bound = store
            .bind_answer(
                "api.example.com",
                &[PUBLIC, PUBLIC, PUBLIC],
                &[443],
                60_000,
                1,
                0,
            )
            .unwrap();
        assert_eq!(bound, vec![PUBLIC]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn the_binding_table_fails_closed_when_full() {
        let mut store = DnsBindingStore::new(
            DnsLimits {
                max_bindings: 2,
                ..DnsLimits::default()
            },
            Vec::new(),
        );
        store
            .bind_answer("a.example.com", &[PUBLIC, PUBLIC_2], &[443], 60_000, 1, 0)
            .unwrap();
        assert!(matches!(
            store.bind_answer(
                "b.example.com",
                &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                &[443],
                60_000,
                1,
                0
            ),
            Err(DnsDeny::TableFull { .. })
        ));
    }

    #[test]
    fn the_name_table_fails_closed_when_full() {
        let mut store = DnsBindingStore::new(
            DnsLimits {
                max_names: 1,
                ..DnsLimits::default()
            },
            Vec::new(),
        );
        store
            .bind_answer("a.example.com", &[PUBLIC], &[443], 60_000, 1, 0)
            .unwrap();
        assert!(matches!(
            store.bind_answer("b.example.com", &[PUBLIC_2], &[443], 60_000, 1, 0),
            Err(DnsDeny::NameTableFull { .. })
        ));
        // Re-binding the name already present is still fine.
        assert!(
            store
                .bind_answer("a.example.com", &[PUBLIC_2], &[443], 60_000, 1, 0)
                .is_ok()
        );
    }

    #[test]
    fn expired_bindings_are_pruned_and_free_their_slots() {
        let mut store = fresh();
        store
            .bind_answer("a.example.com", &[PUBLIC], &[443], 10_000, 1, 0)
            .unwrap();
        assert_eq!(store.prune_expired(9_999), 0);
        assert_eq!(store.prune_expired(10_000), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn clearing_removes_every_binding_so_none_outlives_the_session() {
        let mut store = fresh();
        store
            .bind_answer("a.example.com", &[PUBLIC], &[443], 60_000, 1, 0)
            .unwrap();
        store.clear();
        assert!(!store.permits(&PUBLIC, 443, 1, 0));
    }

    #[test]
    fn an_unbound_address_is_never_permitted() {
        let store = fresh();
        assert!(!store.permits(&PUBLIC, 443, 1, 0));
    }

    #[test]
    fn names_are_normalized_so_case_and_trailing_dots_do_not_fork_policy() {
        assert_eq!(
            normalize_name("API.Example.COM."),
            Some("api.example.com".into())
        );
        assert_eq!(
            normalize_name("  api.example.com  "),
            Some("api.example.com".into())
        );
        assert_eq!(normalize_name(""), None);
        assert_eq!(normalize_name("."), None);
        assert_eq!(normalize_name("bad name.com"), None);
        assert_eq!(normalize_name(&"a".repeat(254)), None);
    }

    #[test]
    fn a_cname_chain_resolves_to_its_terminal_name() {
        let mut chain = BTreeMap::new();
        chain.insert("www.example.com".to_string(), "cdn.example.net".to_string());
        chain.insert(
            "cdn.example.net".to_string(),
            "edge.example.org".to_string(),
        );
        assert_eq!(
            resolve_alias_chain("www.example.com", &chain, DEFAULT_MAX_ALIAS_DEPTH).unwrap(),
            "edge.example.org"
        );
    }

    #[test]
    fn an_overlong_cname_chain_is_refused() {
        let mut chain = BTreeMap::new();
        for i in 0..20 {
            chain.insert(
                format!("n{i}.example.com"),
                format!("n{}.example.com", i + 1),
            );
        }
        assert!(matches!(
            resolve_alias_chain("n0.example.com", &chain, DEFAULT_MAX_ALIAS_DEPTH),
            Err(DnsDeny::AliasChainTooDeep { .. })
        ));
    }

    #[test]
    fn a_self_referential_alias_terminates_instead_of_spinning() {
        let mut chain = BTreeMap::new();
        chain.insert(
            "loop.example.com".to_string(),
            "loop.example.com".to_string(),
        );
        assert_eq!(
            resolve_alias_chain("loop.example.com", &chain, DEFAULT_MAX_ALIAS_DEPTH).unwrap(),
            "loop.example.com"
        );
    }

    #[test]
    fn a_cyclic_alias_pair_is_refused_by_the_depth_bound() {
        let mut chain = BTreeMap::new();
        chain.insert("a.example.com".to_string(), "b.example.com".to_string());
        chain.insert("b.example.com".to_string(), "a.example.com".to_string());
        assert!(matches!(
            resolve_alias_chain("a.example.com", &chain, DEFAULT_MAX_ALIAS_DEPTH),
            Err(DnsDeny::AliasChainTooDeep { .. })
        ));
    }

    #[test]
    fn refusals_are_counted_for_metrics() {
        let mut store = fresh();
        let _ = store.bind_answer(
            "evil.example.com",
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &[80],
            60_000,
            1,
            0,
        );
        assert_eq!(store.denied_count(), 1);
        store
            .bind_answer("ok.example.com", &[PUBLIC], &[443], 60_000, 1, 0)
            .unwrap();
        assert_eq!(store.admitted_count(), 1);
    }
}
