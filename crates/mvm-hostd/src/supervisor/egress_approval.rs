//! Where an `ask` route decision goes to be answered.
//!
//! A route rule can say `ask` instead of `allow` or `deny`: the request may
//! proceed if someone approves it. The approval backends — a terminal prompt,
//! a webhook — are a later workstream. Until one is configured, every `ask`
//! is answered by [`NoApprovalBackend`], which refuses with the fixed reason
//! `approval_unavailable`. An unanswered question is a refusal, never a pass.
//!
//! The pending decision carries only what the endpoint already records for
//! the route decision itself: the route, the rule, the destination and the
//! method. Nothing from the request body or headers reaches a backend through
//! this seam.

use async_trait::async_trait;

/// The reason an `ask` is refused when nothing can answer it.
pub const REASON_APPROVAL_UNAVAILABLE: &str = "approval_unavailable";

/// A request waiting on an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingEgressDecision<'a> {
    /// The route that asked.
    pub route_id: &'a str,
    /// The rule within it, as the audit record labels it.
    pub rule: &'a str,
    /// `host:port`.
    pub destination: &'a str,
    /// The request method, from a fixed set (`other` otherwise).
    pub method: &'a str,
}

/// An approval backend's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalVerdict {
    /// Proceed with this request.
    Approved,
    /// Refuse it, for this fixed audit reason.
    Denied {
        /// Host-chosen label recorded on the chain.
        reason: &'static str,
    },
}

/// Answers `ask` decisions. Implementations must fail closed: an error, a
/// timeout, or no one to ask is a [`ApprovalVerdict::Denied`].
#[async_trait]
pub trait EgressApprover: Send + Sync {
    async fn decide(&self, pending: &PendingEgressDecision<'_>) -> ApprovalVerdict;
}

/// The approver used until a backend is configured: refuses every `ask`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoApprovalBackend;

#[async_trait]
impl EgressApprover for NoApprovalBackend {
    async fn decide(&self, _pending: &PendingEgressDecision<'_>) -> ApprovalVerdict {
        ApprovalVerdict::Denied {
            reason: REASON_APPROVAL_UNAVAILABLE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn with_no_backend_an_ask_is_refused_as_approval_unavailable() {
        let pending = PendingEgressDecision {
            route_id: "github",
            rule: "rule-1",
            destination: "api.github.com:443",
            method: "POST",
        };
        assert_eq!(
            NoApprovalBackend.decide(&pending).await,
            ApprovalVerdict::Denied {
                reason: REASON_APPROVAL_UNAVAILABLE
            }
        );
    }
}
