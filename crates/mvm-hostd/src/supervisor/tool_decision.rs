//! Per-VM decisions for declared tool invocations.
//!
//! The endpoint receives resolved rules from the admitted plan. Only hashes
//! of the tool name and command line reach the audit chain; either input may
//! contain user data or a credential. A failed audit write refuses the call.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use mvm_contract::policy::approval_prompt::ApprovalSubject;
use mvm_contract::policy::tool_rules::{ToolDecision, ToolRules};
use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;
use mvm_contract::protocol::network_flow::tool::{ToolCheckRequest, ToolOrigin};
use rand::Rng;
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

/// A decision for a host-started invocation, which may carry a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationVerdict {
    /// The invocation may proceed. When its tool owns routes or secrets, the
    /// binding its flows must carry to use them.
    Allow {
        binding: Option<ToolInvocationBinding>,
    },
    /// The invocation must be refused for this fixed, safe reason.
    Deny(&'static str),
}

/// How many bound invocations one VM keeps live. A binding is released when
/// its command finishes; past this many, the oldest is retired, so a caller
/// that never released cannot exhaust the table.
pub const MAX_LIVE_INVOCATIONS: usize = 256;

/// Rules, approver and chain recorder for one VM. Constructed only from the
/// endpoint's admitted plan projection.
pub struct ToolDecisionGate {
    rules: ToolRules,
    approver: Arc<dyn RuntimeApprover>,
    recorder: Arc<Recorder>,
    /// Live bindings and the tool each was minted for, oldest first.
    invocations: Mutex<VecDeque<(ToolInvocationBinding, String)>>,
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
            invocations: Mutex::new(VecDeque::new()),
        }
    }

    /// The admitted rules this gate decides.
    #[must_use]
    pub fn rules(&self) -> &ToolRules {
        &self.rules
    }

    /// Decide and record one invocation. A recorder failure is an error, so
    /// the caller cannot mistake an unaudited decision for an allow.
    pub async fn decide(
        &self,
        request: &ToolCheckRequest,
        origin: ToolOrigin,
    ) -> Result<ToolVerdict, RecorderError> {
        let verdict = self.verdict(request).await;
        self.record(request, verdict, None, origin).await?;
        Ok(verdict)
    }

    /// Decide and record one host-started invocation. An allowed invocation
    /// of a tool that owns routes or secrets gets a fresh binding, recorded
    /// with the decision and live until [`Self::release`].
    pub async fn decide_invocation(
        &self,
        request: &ToolCheckRequest,
        origin: ToolOrigin,
    ) -> Result<InvocationVerdict, RecorderError> {
        let verdict = self.verdict(request).await;
        let binding = match verdict {
            ToolVerdict::Allow if self.scopes_endpoint(&request.tool) => {
                Some(self.mint(&request.tool))
            }
            _ => None,
        };
        if let Err(error) = self
            .record(request, verdict, binding.as_ref(), origin)
            .await
        {
            if let Some(binding) = &binding {
                self.release(binding);
            }
            return Err(error);
        }
        Ok(match verdict {
            ToolVerdict::Allow => InvocationVerdict::Allow { binding },
            ToolVerdict::Deny(reason) => InvocationVerdict::Deny(reason),
        })
    }

    /// Retire a binding. Flows naming it afterwards belong to no tool.
    pub fn release(&self, binding: &ToolInvocationBinding) {
        self.live().retain(|(live, _)| live != binding);
    }

    /// The tool a live binding was minted for.
    #[must_use]
    pub fn tool_for(&self, binding: &ToolInvocationBinding) -> Option<String> {
        self.live()
            .iter()
            .find(|(live, _)| live == binding)
            .map(|(_, tool)| tool.clone())
    }

    fn scopes_endpoint(&self, tool: &str) -> bool {
        self.rules
            .detail
            .get(tool)
            .is_some_and(|detail| !detail.routes.is_empty() || !detail.secrets.is_empty())
    }

    fn live(&self) -> std::sync::MutexGuard<'_, VecDeque<(ToolInvocationBinding, String)>> {
        self.invocations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn mint(&self, tool: &str) -> ToolInvocationBinding {
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        let binding = ToolInvocationBinding::from_random(bytes);
        let mut live = self.live();
        if live.len() >= MAX_LIVE_INVOCATIONS {
            live.pop_front();
        }
        live.push_back((binding.clone(), tool.to_string()));
        binding
    }

    async fn verdict(&self, request: &ToolCheckRequest) -> ToolVerdict {
        let decision = match request.executable.as_deref() {
            Some(executable) => self
                .rules
                .decide_command(&request.tool, executable, &request.argv),
            None => ToolDecision::Deny("the invocation did not report an executable"),
        };
        match decision {
            ToolDecision::Allow => ToolVerdict::Allow,
            ToolDecision::Deny(reason) => ToolVerdict::Deny(reason),
            ToolDecision::Ask => {
                let subject = ApprovalSubject::ToolCall {
                    tool: request.tool.clone(),
                };
                match self.approver.decide(&subject).await {
                    ApprovalVerdict::Approved => ToolVerdict::Allow,
                    ApprovalVerdict::Denied { reason } => ToolVerdict::Deny(reason),
                }
            }
        }
    }

    async fn record(
        &self,
        request: &ToolCheckRequest,
        verdict: ToolVerdict,
        binding: Option<&ToolInvocationBinding>,
        origin: ToolOrigin,
    ) -> Result<(), RecorderError> {
        let (outcome, reason) = match verdict {
            ToolVerdict::Allow => ("allow", "allowed"),
            ToolVerdict::Deny(reason) => ("deny", reason),
        };
        let mut labels = vec![
            ("origin".to_string(), origin.audit_label().to_string()),
            (
                "tool_sha256".to_string(),
                hex::encode(Sha256::digest(request.tool.as_bytes())),
            ),
            (
                "argv_sha256".to_string(),
                hex::encode(Sha256::digest(request.argv.as_bytes())),
            ),
            ("outcome".to_string(), outcome.to_string()),
            ("reason".to_string(), reason.to_string()),
        ];
        if let Some(executable) = &request.executable {
            labels.push((
                "executable_sha256".to_string(),
                hex::encode(Sha256::digest(executable.as_bytes())),
            ));
        }
        if let Some(binding) = binding {
            labels.push(("binding_id".to_string(), binding.audit_id()));
        }
        self.recorder
            .record_unbound(EventCategory::Host, "host.tool.decision", labels)
            .await
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

    fn request(tool: &str, argv: &str) -> ToolCheckRequest {
        ToolCheckRequest {
            tool: tool.into(),
            executable: Some(format!("/bin/{tool}")),
            argv: argv.into(),
        }
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
            gate.decide(&request("write", "write x"), ToolOrigin::Host)
                .await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert!(matches!(
            gate.decide(&request("other", "other"), ToolOrigin::Host)
                .await,
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
                detail: [(
                    "shell".into(),
                    mvm_contract::policy::tool_rules::ToolRuleDetail {
                        executable: Some("/bin/shell".into()),
                        ..Default::default()
                    },
                )]
                .into(),
                ..ToolRules::default()
            },
            Arc::clone(&approver),
        );
        assert_eq!(
            gate.decide(&request("shell", "echo ok"), ToolOrigin::Host)
                .await
                .expect("audit"),
            ToolVerdict::Allow
        );
        assert_eq!(approver.calls.load(Ordering::Relaxed), 1);
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        let recorded = serde_json::to_string(&entries).expect("serialize audit entries");
        assert!(!recorded.contains("echo ok"));
    }

    #[tokio::test]
    async fn spoofed_or_unreported_executable_is_audited_and_never_prompts() {
        let approver = approving();
        let mut rules = ToolRules {
            ask: vec!["gh".into()],
            ..ToolRules::default()
        };
        rules.detail.insert(
            "gh".into(),
            mvm_contract::policy::tool_rules::ToolRuleDetail {
                executable: Some("/usr/bin/gh".into()),
                ..Default::default()
            },
        );
        let (gate, signer) = gate(rules, Arc::clone(&approver));
        let mut spoof = request("gh", "gh api");
        assert!(matches!(
            gate.decide(&spoof, ToolOrigin::Host).await,
            Ok(ToolVerdict::Deny(_))
        ));
        spoof.executable = None;
        assert!(matches!(
            gate.decide(&spoof, ToolOrigin::Host).await,
            Ok(ToolVerdict::Deny(_))
        ));
        assert_eq!(approver.calls.load(Ordering::Relaxed), 0);
        assert_eq!(signer.entries().len(), 2);
    }

    fn scoped_rules() -> ToolRules {
        let mut rules = ToolRules {
            allow: vec!["gh".into(), "plain".into()],
            ..ToolRules::default()
        };
        rules.detail.insert(
            "gh".into(),
            mvm_contract::policy::tool_rules::ToolRuleDetail {
                executable: Some("/bin/gh".into()),
                routes: vec!["api.github.com:443".into()],
                ..Default::default()
            },
        );
        rules.detail.insert(
            "plain".into(),
            mvm_contract::policy::tool_rules::ToolRuleDetail {
                executable: Some("/bin/plain".into()),
                ..Default::default()
            },
        );
        rules
    }

    fn approving() -> Arc<ScriptedApprover> {
        Arc::new(ScriptedApprover {
            calls: AtomicUsize::new(0),
            verdict: ApprovalVerdict::Approved,
        })
    }

    #[tokio::test]
    async fn an_allowed_scoped_invocation_gets_a_recorded_binding_until_released() {
        let (gate, signer) = gate(scoped_rules(), approving());
        let InvocationVerdict::Allow {
            binding: Some(binding),
        } = gate
            .decide_invocation(&request("gh", "gh api"), ToolOrigin::Host)
            .await
            .expect("audit")
        else {
            panic!("a scoped tool's allowed invocation is bound");
        };
        assert_eq!(gate.tool_for(&binding).as_deref(), Some("gh"));
        let recorded = serde_json::to_string(&signer.entries()).expect("entries");
        assert!(recorded.contains(&binding.audit_id()), "{recorded}");
        assert!(
            !recorded.contains(binding.as_str()),
            "the audit log must not carry a usable binding: {recorded}"
        );
        gate.release(&binding);
        assert_eq!(gate.tool_for(&binding), None);
    }

    #[tokio::test]
    async fn unscoped_and_refused_invocations_get_no_binding() {
        let (gate, _signer) = gate(scoped_rules(), approving());
        assert_eq!(
            gate.decide_invocation(&request("plain", "plain x"), ToolOrigin::Host)
                .await
                .expect("audit"),
            InvocationVerdict::Allow { binding: None }
        );
        assert!(matches!(
            gate.decide_invocation(&request("other", "other"), ToolOrigin::Host)
                .await
                .expect("audit"),
            InvocationVerdict::Deny(_)
        ));
        assert!(gate.live().is_empty());
    }

    #[tokio::test]
    async fn an_unaudited_scoped_allow_leaves_no_live_binding() {
        let recorder = Arc::new(Recorder::new(
            Arc::new(NoopAuditSigner),
            TenantId("local".into()),
        ));
        let gate = ToolDecisionGate::new(scoped_rules(), approving(), recorder);
        assert!(
            gate.decide_invocation(&request("gh", "gh api"), ToolOrigin::Host)
                .await
                .is_err()
        );
        assert!(gate.live().is_empty());
    }

    #[tokio::test]
    async fn past_the_bound_the_oldest_binding_is_retired() {
        let (gate, _signer) = gate(scoped_rules(), approving());
        let mut minted = Vec::new();
        for _ in 0..=MAX_LIVE_INVOCATIONS {
            match gate
                .decide_invocation(&request("gh", "gh api"), ToolOrigin::Host)
                .await
                .expect("audit")
            {
                InvocationVerdict::Allow {
                    binding: Some(binding),
                } => minted.push(binding),
                other => panic!("expected a bound allow, got {other:?}"),
            }
        }
        assert_eq!(gate.live().len(), MAX_LIVE_INVOCATIONS);
        assert_eq!(gate.tool_for(&minted[0]), None);
        assert_eq!(gate.tool_for(&minted[1]).as_deref(), Some("gh"));
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
        let gate = ToolDecisionGate::new(
            ToolRules {
                allow: vec!["shell".into()],
                detail: [(
                    "shell".into(),
                    mvm_contract::policy::tool_rules::ToolRuleDetail {
                        executable: Some("/bin/shell".into()),
                        ..Default::default()
                    },
                )]
                .into(),
                ..ToolRules::default()
            },
            approver,
            recorder,
        );
        assert!(
            gate.decide(&request("shell", "echo ok"), ToolOrigin::Host)
                .await
                .is_err()
        );
    }
}
