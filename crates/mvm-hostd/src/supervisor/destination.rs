//! `DestinationPolicy` — explicit `(host, port)` allowlist.
//!
//! First-line defence: refuse outbound traffic to any destination
//! not on the workload's allowlist. The allowlist is sourced from
//! the workload's `EgressPolicy` once the resolver is wired; until
//! then the policy is constructed directly from a list of
//! (host, port) pairs.
//!
//! Match semantics:
//! - Exact host match (no wildcards). SNI-pin semantics where the
//!   cert SAN is what we match come later — for now `host` is the
//!   literal request host string.
//! - Port match exact. `0` in the allowlist means "any port for
//!   this host", which the caller opts into per entry.
//!
//! Threat shape addressed:
//! - SSRF that probes random ports of internal hosts.
//! - LLM-generated URLs to lookalike domains the workload was
//!   never authorised to call.
//! - Tool-call exfiltration over a side-channel host.

use std::collections::BTreeSet;

use async_trait::async_trait;

use crate::supervisor::inspector::{Inspector, InspectorVerdict, RequestCtx};

/// Allowed destination entry. `port = 0` is the explicit "any port
/// for this host" wildcard; we use `0` rather than `Option<u16>` so
/// the type is `Copy` and `Ord` (handy for the BTreeSet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Destination {
    pub host_hash: u64,
    pub port: u16,
}

/// Internal helper: stable hash of the host string. We can't store
/// `String` in a `Copy + Ord` type, so we hash the host once at
/// build-time and store only the (hash, port) pair. The original
/// host string lives alongside in a parallel `Vec<String>` for
/// audit-rendering.
fn host_hash(host: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    host.to_ascii_lowercase().hash(&mut hasher);
    hasher.finish()
}

/// Explicit (host, port) allowlist inspector. Constructed from the
/// workload's `EgressPolicy.allow_list` once the resolver is wired.
pub struct DestinationPolicy {
    allowed: BTreeSet<Destination>,
    /// Parallel store of original host strings (case preserved) so
    /// the deny-reason text is human-readable. Index aligns with the
    /// hash-based set is *not* preserved — we rebuild this set on
    /// every `new()` call from the input list. The set is small
    /// (typical workload allowlist is <50 entries), so storage is
    /// trivial.
    allowed_display: Vec<String>,
}

impl DestinationPolicy {
    /// Build from a list of `(host, port)` pairs. `port = 0` means
    /// "any port for this host". Duplicate entries are deduped.
    pub fn new<I, H>(entries: I) -> Self
    where
        I: IntoIterator<Item = (H, u16)>,
        H: AsRef<str>,
    {
        let mut allowed = BTreeSet::new();
        let mut display = Vec::new();
        for (host, port) in entries {
            let host_str = host.as_ref();
            allowed.insert(Destination {
                host_hash: host_hash(host_str),
                port,
            });
            let entry = if port == 0 {
                format!("{host_str}:*")
            } else {
                format!("{host_str}:{port}")
            };
            if !display.contains(&entry) {
                display.push(entry);
            }
        }
        Self {
            allowed,
            allowed_display: display,
        }
    }

    /// Deny-everything sentinel — useful when the workload has no
    /// `egress_policy` resolved yet, or when the policy bundle's
    /// allow-list is empty (a deliberate fail-closed configuration).
    pub fn deny_all() -> Self {
        Self::new::<_, &str>(std::iter::empty())
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        let h = host_hash(host);
        // Exact (host, port) match.
        if self.allowed.contains(&Destination { host_hash: h, port }) {
            return true;
        }
        // (host, *) wildcard match.
        self.allowed.contains(&Destination {
            host_hash: h,
            port: 0,
        })
    }

    /// Render the allowlist for inclusion in deny reasons.
    fn display_allowlist(&self) -> String {
        if self.allowed_display.is_empty() {
            "<empty allowlist — deny-all>".to_string()
        } else {
            self.allowed_display.join(", ")
        }
    }
}

#[async_trait]
impl Inspector for DestinationPolicy {
    fn name(&self) -> &'static str {
        "destination_policy"
    }

    async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
        if self.matches(&ctx.host, ctx.port) {
            InspectorVerdict::Allow
        } else {
            InspectorVerdict::Deny {
                reason: format!(
                    "destination {}:{} not in policy allowlist (allowed: {})",
                    ctx.host,
                    ctx.port,
                    self.display_allowlist()
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(host: &str, port: u16) -> RequestCtx {
        RequestCtx::new(host, port, "/")
    }

    #[tokio::test]
    async fn exact_host_port_match_allows() {
        let policy = DestinationPolicy::new([("api.openai.com", 443u16)]);
        let v = policy.inspect(&mut ctx("api.openai.com", 443)).await;
        assert!(v.is_allow());
    }

    #[tokio::test]
    async fn host_with_wrong_port_denies() {
        let policy = DestinationPolicy::new([("api.openai.com", 443u16)]);
        let v = policy.inspect(&mut ctx("api.openai.com", 8080)).await;
        match v {
            InspectorVerdict::Deny { reason } => {
                assert!(reason.contains("api.openai.com"));
                assert!(reason.contains("8080"));
                assert!(reason.contains("api.openai.com:443"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_host_denies() {
        let policy = DestinationPolicy::new([("api.openai.com", 443u16)]);
        let v = policy.inspect(&mut ctx("evil.com", 443)).await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn port_wildcard_zero_allows_any_port_for_that_host() {
        let policy = DestinationPolicy::new([("api.openai.com", 0u16)]);
        for port in [80u16, 443, 8080, 9999] {
            let v = policy.inspect(&mut ctx("api.openai.com", port)).await;
            assert!(v.is_allow(), "port {port} should be allowed");
        }
    }

    #[tokio::test]
    async fn port_wildcard_does_not_grant_other_hosts() {
        let policy = DestinationPolicy::new([("api.openai.com", 0u16)]);
        let v = policy.inspect(&mut ctx("evil.com", 443)).await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn case_insensitive_host_match() {
        let policy = DestinationPolicy::new([("Api.OpenAI.com", 443u16)]);
        let v = policy.inspect(&mut ctx("api.openai.com", 443)).await;
        assert!(v.is_allow());
    }

    #[tokio::test]
    async fn deny_all_refuses_every_destination() {
        let policy = DestinationPolicy::deny_all();
        for (host, port) in [("api.openai.com", 443u16), ("example.com", 80), ("a", 1)] {
            let v = policy.inspect(&mut ctx(host, port)).await;
            assert!(v.is_deny());
        }
    }

    #[tokio::test]
    async fn deny_reason_surfaces_the_attempted_destination() {
        // Operators read deny reasons in audit; the host + port
        // they got blocked on must be visible (the wording can
        // change but these substrings must remain).
        let policy = DestinationPolicy::new([("a.com", 443u16)]);
        let v = policy.inspect(&mut ctx("b.com", 80)).await;
        match v {
            InspectorVerdict::Deny { reason } => {
                assert!(reason.contains("b.com"));
                assert!(reason.contains("80"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }
}
