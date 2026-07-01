//! Host egress-broker decision logic.
//!
//! The closed-by-default enforcement core the host `mvm-egress-broker` runs for
//! each brokered egress request from a guest: resolve the workload's signed
//! network policy to an allowlist and decide allow/deny, carrying the
//! audit-relevant facts (the matched rule or the deny reason). Reuses
//! [`NetworkPolicy`] so the broker and the rest of the system share one policy
//! definition; this module only adds the per-request verdict.

use crate::policy::network_policy::{HostPort, NetworkPolicy};

/// A guest's brokered egress request, as the host egress broker sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRequest {
    pub host: String,
    pub port: u16,
}

impl EgressRequest {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// Why an egress request was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The policy is deny-all (no rules) — closed by default.
    DenyAll,
    /// The policy has an allowlist, but this host:port is not on it.
    NotInAllowlist,
}

impl DenyReason {
    /// Stable token for audit output.
    pub const fn label(self) -> &'static str {
        match self {
            DenyReason::DenyAll => "deny_all",
            DenyReason::NotInAllowlist => "not_in_allowlist",
        }
    }
}

/// The broker's verdict for one egress request, carrying the audit-relevant
/// facts (the matched allowlist rule, or the deny reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// Allowed. `matched` is the allowlist rule that permitted it, or `None`
    /// when the policy is unrestricted (no per-endpoint rule applied).
    Allowed { matched: Option<HostPort> },
    /// Denied, with the reason for the audit log.
    Denied { reason: DenyReason },
}

impl EgressVerdict {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, EgressVerdict::Allowed { .. })
    }
}

/// Decide whether a brokered egress request is permitted by the workload's
/// network policy. Closed by default: an empty/deny-all policy denies, an
/// allowlist permits only exact host+port matches, and only an explicitly
/// unrestricted policy allows everything.
pub fn decide_egress(policy: &NetworkPolicy, req: &EgressRequest) -> EgressVerdict {
    let Some(rules) = policy.resolve_rules() else {
        // `resolve_rules() == None` means unrestricted.
        return EgressVerdict::Allowed { matched: None };
    };
    if rules.is_empty() {
        return EgressVerdict::Denied {
            reason: DenyReason::DenyAll,
        };
    }
    match rules
        .into_iter()
        .find(|rule| rule.host == req.host && rule.port == req.port)
    {
        Some(matched) => EgressVerdict::Allowed {
            matched: Some(matched),
        },
        None => EgressVerdict::Denied {
            reason: DenyReason::NotInAllowlist,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_denies_everything() {
        let verdict = decide_egress(
            &NetworkPolicy::deny_all(),
            &EgressRequest::new("api.example.com", 443),
        );
        assert_eq!(
            verdict,
            EgressVerdict::Denied {
                reason: DenyReason::DenyAll
            }
        );
    }

    #[test]
    fn unrestricted_allows_with_no_specific_rule() {
        let verdict = decide_egress(
            &NetworkPolicy::unrestricted(),
            &EgressRequest::new("anything.example", 80),
        );
        assert_eq!(verdict, EgressVerdict::Allowed { matched: None });
    }

    #[test]
    fn allowlist_permits_only_exact_host_and_port() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);

        assert!(
            decide_egress(&policy, &EgressRequest::new("api.example.com", 443)).is_allowed(),
            "exact match allowed"
        );
        assert_eq!(
            decide_egress(&policy, &EgressRequest::new("evil.example.com", 443)),
            EgressVerdict::Denied {
                reason: DenyReason::NotInAllowlist
            },
            "other host denied"
        );
        assert_eq!(
            decide_egress(&policy, &EgressRequest::new("api.example.com", 80)),
            EgressVerdict::Denied {
                reason: DenyReason::NotInAllowlist
            },
            "wrong port denied"
        );
    }

    #[test]
    fn allowed_match_carries_the_rule_for_audit() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        let verdict = decide_egress(&policy, &EgressRequest::new("api.example.com", 443));
        assert_eq!(
            verdict,
            EgressVerdict::Allowed {
                matched: Some(HostPort::new("api.example.com", 443))
            }
        );
    }
}
