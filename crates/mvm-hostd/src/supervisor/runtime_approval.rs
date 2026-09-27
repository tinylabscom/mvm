//! Runtime approvals: where an `ask` goes to be answered.
//!
//! A decision can be `ask` instead of allow or deny: an egress route rule, the
//! first use of a secret bound with `approve = "ask"`, or (once PS-13 gives
//! tool rules a live caller) a tool call. The flow is held **here, in the
//! host endpoint** — never in the guest — while an approval backend answers.
//!
//! [`RuntimeApprover`] is the seam every such decision goes through.
//! [`ApprovalSupervisor`] is the implementation the endpoint runs: it records
//! each request in the contract's [`ApprovalLedger`], asks an
//! [`ApprovalBroker`] (the operator's `mvmctl`, over a host-local socket),
//! waits at most its timeout, and chain-signs every step
//! (`approval.requested`, `approval.granted`, `approval.denied`,
//! `approval.timed_out`) with the request id. Anything that is not an explicit
//! approval — a timeout, no broker, a broker error, a mismatched answer — is a
//! denial.
//!
//! An approval scoped to the session is remembered in memory, keyed by the
//! question (route, rule, destination and method; or secret and destination;
//! or tool), until its TTL. Nothing is written to a profile, a manifest or the
//! plan.
//!
//! [`NoApprovalBackend`] answers every question with a denial and is the
//! approver a service starts with until one is configured.

mod broker;
mod limiter;
mod supervisor;

pub use broker::{ApprovalBroker, BrokerError, SocketBroker};
pub use supervisor::{ApprovalSupervisor, ApprovalSupervisorBuilder};

use async_trait::async_trait;
pub use mvm_contract::policy::approval_prompt::ApprovalSubject;

/// The reason an `ask` is refused when nothing can answer it.
pub const REASON_APPROVAL_UNAVAILABLE: &str = "approval_unavailable";

/// An approval decision.
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
///
/// Tool calls: the supervisor's `ToolGate` has no live caller today, so no
/// tool decision reaches this yet. When PS-13 wires tool rules, their `ask`
/// passes an [`ApprovalSubject::ToolCall`] here and needs nothing else.
#[async_trait]
pub trait RuntimeApprover: Send + Sync {
    async fn decide(&self, subject: &ApprovalSubject) -> ApprovalVerdict;
}

/// The approver used until a backend is configured: refuses every `ask`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoApprovalBackend;

#[async_trait]
impl RuntimeApprover for NoApprovalBackend {
    async fn decide(&self, _subject: &ApprovalSubject) -> ApprovalVerdict {
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
        let subject = ApprovalSubject::ToolCall {
            tool: "shell".into(),
        };
        assert_eq!(
            NoApprovalBackend.decide(&subject).await,
            ApprovalVerdict::Denied {
                reason: REASON_APPROVAL_UNAVAILABLE
            }
        );
    }
}
