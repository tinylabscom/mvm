//! Per-VM decisions for declared tool invocations.
//!
//! The endpoint receives resolved rules from the admitted plan. Only hashes
//! of the tool name and command line reach the audit chain; either input may
//! contain user data or a credential. A failed audit write refuses the call.

use std::sync::Arc;

use mvm_contract::policy::approval_prompt::ApprovalSubject;
use mvm_contract::policy::tool_rules::{ToolDecision, ToolRules};
use sha2::{Digest, Sha256};

use super::audit_recorder::{EventCategory, Recorder, RecorderError};
use super::runtime_approval::{ApprovalVerdict, RuntimeApprover};

/// Final decision after the signed rules and any operator answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolVerdict {
    /// The invocation may proceed.
    Allow,
    /// The invocation must be refused for this fixed, safe reason.
    Deny(&'static str),
}

/// Rules, approver and chain recorder for one VM. Constructed only from the
/// endpoint's admitted plan projection.
pub struct ToolDecisionGate {
    rules: ToolRules,
    approver: Arc<dyn RuntimeApprover>,
    recorder: Arc<Recorder>,
}

impl ToolDecisionGate {
    /// Bind one admitted rule set to the endpoint's approval and audit path.
    #[must_use]
    pub fn new(
        rules: ToolRules,
        approver: Arc<dyn RuntimeApprover>,
        recorder: Arc<Recorder>,
    ) -> Self {
        Self {
            rules,
            approver,
            recorder,
        }
    }

    /// Decide and record one invocation. A recorder failure is an error, so
    /// the caller cannot mistake an unaudited decision for an allow.
    pub async fn decide(&self, tool: &str, argv: &str) -> Result<ToolVerdict, RecorderError> {
        let verdict = match self.rules.decide(tool, Some(argv)) {
            ToolDecision::Allow => ToolVerdict::Allow,
            ToolDecision::Deny(reason) => ToolVerdict::Deny(reason),
            ToolDecision::Ask => {
                let subject = ApprovalSubject::ToolCall {
                    tool: tool.to_string(),
                };
                match self.approver.decide(&subject).await {
                    ApprovalVerdict::Approved => ToolVerdict::Allow,
                    ApprovalVerdict::Denied { reason } => ToolVerdict::Deny(reason),
                }
            }
        };
        let (outcome, reason) = match verdict {
            ToolVerdict::Allow => ("allow", "allowed"),
            ToolVerdict::Deny(reason) => ("deny", reason),
        };
        self.recorder
            .record_unbound(
                EventCategory::Host,
                "host.tool.decision",
                [
                    (
                        "tool_sha256".to_string(),
                        hex::encode(Sha256::digest(tool.as_bytes())),
                    ),
                    (
                        "argv_sha256".to_string(),
                        hex::encode(Sha256::digest(argv.as_bytes())),
                    ),
                    ("outcome".to_string(), outcome.to_string()),
                    ("reason".to_string(), reason.to_string()),
                ],
            )
            .await?;
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use mvm_core::plan::TenantId;

    use super::*;
    use crate::supervisor::audit::{CapturingAuditSigner, NoopAuditSigner};

    struct ScriptedApprover {
        calls: AtomicUsize,
        verdict: ApprovalVerdict,
    }

    #[async_trait]
    impl RuntimeApprover for ScriptedApprover {
        async fn decide(&self, subject: &ApprovalSubject) -> ApprovalVerdict {
            assert!(matches!(subject, ApprovalSubject::ToolCall { .. }));
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.verdict
        }
    }

    fn gate(
        rules: ToolRules,
        approver: Arc<ScriptedApprover>,
    ) -> (ToolDecisionGate, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".into())));
        (ToolDecisionGate::new(rules, approver, recorder), signer)
    }

    #[tokio::test]
    async fn deny_and_unlisted_refusals_never_prompt() {
        let approver = Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        });
        let (gate, signer) = gate(
            ToolRules {
                allow: vec!["read".into()],
                deny: vec!["write".into()],
                ..ToolRules::default()
            },
            Arc::clone(&approver),
        );
        assert!(matches!(
            gate.decide("write", "write x").await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert!(matches!(
            gate.decide("other", "other").await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert_eq!(approver.calls.load(Ordering::Relaxed), 0);
        assert_eq!(signer.entries().len(), 2);
    }

    #[tokio::test]
    async fn ask_uses_runtime_approver_and_records_the_result() {
        let approver = Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        });
        let (gate, signer) = gate(
            ToolRules {
                ask: vec!["shell".into()],
                ..ToolRules::default()
            },
            Arc::clone(&approver),
        );
        assert_eq!(
            gate.decide("shell", "echo ok").await.expect("audit"),
            ToolVerdict::Allow
        );
        assert_eq!(approver.calls.load(Ordering::Relaxed), 1);
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        let recorded = serde_json::to_string(&entries).expect("serialize audit entries");
        assert!(!recorded.contains("echo ok"));
    }

    #[tokio::test]
    async fn audit_failure_refuses_an_otherwise_allowed_call() {
        let approver = Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        });
        let recorder = Arc::new(Recorder::new(
            Arc::new(NoopAuditSigner),
            TenantId("local".into()),
        ));
        let gate = ToolDecisionGate::new(ToolRules::default(), approver, recorder);
        assert!(gate.decide("shell", "echo ok").await.is_err());
    }
}
