//! The MCP tool-call policy gate (PS-13 slice B).
//!
//! `mvmctl ops mcp` binds this gate over the resolved `[tools]` section of
//! the project's policy: every `tools/call` the server serves is authorized
//! here before any backend work. Whole-tool decisions (`deny` / `ask` /
//! `allow`) are enforced; `ask` is put to the terminal approver, fail-closed
//! when no terminal answers. Per-tool `argv`/`routes`/`secrets` detail
//! constrains workload egress and is enforced where those decisions live
//! (the slice C mediation), not here — MCP arguments are tool-specific JSON,
//! not command lines or destinations.
//!
//! Every decision is chain-signed before it can admit backend work. The
//! dimension is opt-in: a policy with no `[tools]` section
//! anywhere means no gate, and a policy that exists but does not resolve is
//! an error — half-applied policy must never silently widen to "no gate".

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use mvm_client::approval_broker::ApprovalBackend;
use mvm_client::policy_profiles::{
    Platform, PolicySelection, PolicyStore, ProjectPolicy, ResolvedPolicy, resolve,
};
use mvm_contract::policy::approval::ApprovalOutcome;
use mvm_contract::policy::approval_prompt::{
    ApprovalPrompt, ApprovalSubject, MAX_SUBJECT_FIELD_CHARS, display_safe,
};
use mvm_contract::policy::tool_rules::{ToolDecision, ToolRules};
use mvm_core::plan::TenantId;
use mvm_hostd::audit::active_signer::active_signer_for;
use mvm_hostd::supervisor::{EventCategory, Recorder};
use mvm_mcp::{ToolCallGate, ToolGateDenial};
use serde_json::Map;
use serde_json::Value;

use crate::approval::tty::TerminalBackend;

/// Authorize MCP tool calls against one resolved `[tools]` section.
pub struct McpToolGate {
    rules: ToolRules,
    approver: Arc<dyn ApprovalBackend>,
    recorder: Arc<Recorder>,
    sequence: AtomicU64,
}

impl McpToolGate {
    /// Resolve the project's policy and build a gate when the result carries
    /// a `[tools]` section. `None` when the dimension is not in use.
    ///
    /// # Errors
    ///
    /// The policy exists but does not resolve: starting an ungated server
    /// over a broken policy would silently drop the user's restrictions.
    pub fn resolve(project: Option<&Path>) -> Result<Option<Self>> {
        let policy = resolve_project_policy(project)?;
        if policy.tools.is_empty() {
            return Ok(None);
        }
        let audit_dir = mvm_hostd::audit::emitter::default_audit_dir()
            .context("locating the chain-signed tool audit")?;
        let recorder = recorder_for_active_signer(&audit_dir)?;
        Ok(Some(Self::new(
            policy.tools.to_tool_rules(),
            Arc::new(TerminalBackend::controlling(false)),
            recorder,
        )))
    }

    fn new(rules: ToolRules, approver: Arc<dyn ApprovalBackend>, recorder: Arc<Recorder>) -> Self {
        Self {
            rules,
            approver,
            recorder,
            sequence: AtomicU64::new(0),
        }
    }

    fn next_request_id(&self) -> mvm_contract::policy::approval::ApprovalRequestId {
        let n = self.sequence.fetch_add(1, Ordering::Relaxed);
        mvm_contract::policy::approval::ApprovalRequestId::parse(format!("appr-mcp-{n}"))
            .expect("request id is built from contract-legal characters")
    }

    async fn record(&self, tool: &str, outcome: &str, reason: &str) -> Result<(), ToolGateDenial> {
        self.recorder
            .record_unbound(
                EventCategory::Approval,
                format!("approval.tool_gate.{outcome}"),
                [
                    ("surface".to_string(), "mcp".to_string()),
                    (
                        "tool".to_string(),
                        display_safe(tool, MAX_SUBJECT_FIELD_CHARS),
                    ),
                    (
                        "reason".to_string(),
                        display_safe(reason, MAX_SUBJECT_FIELD_CHARS),
                    ),
                ],
            )
            .await
            .map_err(|_| ToolGateDenial::new("chain-signed tool audit unavailable"))
    }
}

fn recorder_for_active_signer(audit_dir: &Path) -> Result<Arc<Recorder>> {
    let signer = active_signer_for(audit_dir)
        .context("chain-signed tool audit unavailable; refusing MCP tool gate startup")?;
    Ok(Arc::new(Recorder::new(signer, TenantId("local".into()))))
}

#[async_trait::async_trait]
impl ToolCallGate for McpToolGate {
    async fn authorize(
        &self,
        tool: &str,
        _arguments: &Map<String, Value>,
    ) -> Result<(), ToolGateDenial> {
        // The MCP surface has no command line: the whole-tool decision from
        // the shared evaluator stands (an empty section admits everything).
        match self.rules.decide(tool, None) {
            ToolDecision::Allow => self.record(tool, "allowed", "policy_allow").await,
            ToolDecision::Deny(rule) => {
                let reason = format!("policy denies this tool ({rule})");
                self.record(tool, "denied", &reason).await?;
                Err(ToolGateDenial::new(reason))
            }
            ToolDecision::Ask => {
                self.record(tool, "requested", "policy_ask").await?;
                let prompt = ApprovalPrompt {
                    request_id: self.next_request_id(),
                    subject: ApprovalSubject::ToolCall {
                        tool: tool.to_string(),
                    },
                    expires_in_ms: 0,
                };
                let answer = self.approver.decide(&prompt);
                match answer.outcome {
                    ApprovalOutcome::Approved => {
                        self.record(tool, "granted", "terminal_approved").await?;
                        Ok(())
                    }
                    ApprovalOutcome::Denied => {
                        let reason = format!(
                            "the ask was denied{}",
                            answer
                                .reason
                                .as_deref()
                                .map(|label| format!(" ({label})"))
                                .unwrap_or_default()
                        );
                        self.record(tool, "ask_denied", &reason).await?;
                        Err(ToolGateDenial::new(reason))
                    }
                }
            }
        }
    }
}

/// The resolution `why` performs: project `[policy]` table (or an empty
/// policy when the project names none), resolved through the user store and
/// built-ins for this host's platform.
fn resolve_project_policy(
    project: Option<&Path>,
) -> Result<mvm_client::policy_profiles::PolicyBody> {
    let dir = project.unwrap_or_else(|| Path::new("."));
    let project = match mvm_core::manifest::manifest_in_dir(dir)? {
        Some(path) => {
            let manifest = mvm_core::manifest::Manifest::read_file(&path)?;
            Some(ProjectPolicy::from_manifest(&path, &manifest))
        }
        None => None,
    };
    let Some(selection) = PolicySelection::for_launch(&[], project)? else {
        return Ok(ResolvedPolicy::empty().policy);
    };
    let backend = mvm_client::backend_kind_for(&mvm_client::auto_selected_backend_name());
    Ok(resolve(
        &PolicyStore::from_config(),
        &selection,
        Platform::current(Some(backend)),
    )
    .context("resolving the project policy for the MCP tool gate")?
    .policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::approval_broker::{CallbackBackend, DenyBackend};
    use mvm_client::policy_profiles::model::{ToolDetail, ToolsSection};
    use mvm_contract::policy::approval_prompt::{ApprovalAnswer, ApprovalScope};
    use mvm_hostd::audit::active_signer::register_active_signer;
    use mvm_hostd::supervisor::{
        AuditError, AuditSigner, CapturingAuditSigner, FileAuditSigner, NoopAuditSigner,
        PlanAuditEntry, verify_audit_chain_entries,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn tools_section(allow: &[&str], ask: &[&str], deny: &[&str]) -> ToolsSection {
        ToolsSection {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ask: ask.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ..ToolsSection::default()
        }
    }

    fn gate(tools: ToolsSection) -> McpToolGate {
        McpToolGate::new(
            tools.to_tool_rules(),
            Arc::new(DenyBackend),
            Arc::new(Recorder::new(
                Arc::new(CapturingAuditSigner::new()),
                TenantId("local".into()),
            )),
        )
    }

    fn decide(gate: &McpToolGate, tool: &str) -> Result<(), ToolGateDenial> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(gate.authorize(tool, &Map::new()))
    }

    #[test]
    fn an_allowed_tool_is_admitted() {
        let gate = gate(tools_section(&["mvm.machine.list"], &[], &[]));
        decide(&gate, "mvm.machine.list").expect("allowed tool passes");
    }

    #[test]
    fn a_denied_tool_is_refused_with_the_policy_reason() {
        let gate = gate(tools_section(&[], &[], &["mvm.machine.stop"]));
        let denial = decide(&gate, "mvm.machine.stop").expect_err("denied tool refuses");
        assert!(denial.reason.contains("tools.deny"), "{}", denial.reason);
    }

    #[test]
    fn an_unlisted_tool_fails_closed() {
        let gate = gate(tools_section(&["mvm.machine.list"], &[], &[]));
        let denial = decide(&gate, "mvm.machine.rm").expect_err("unlisted tool refuses");
        assert!(denial.reason.contains("does not name"), "{}", denial.reason);
    }

    #[test]
    fn deny_beats_allow_and_ask() {
        let gate = gate(tools_section(
            &["mvm.machine.stop"],
            &["mvm.machine.stop"],
            &["mvm.machine.stop"],
        ));
        let denial = decide(&gate, "mvm.machine.stop").expect_err("deny wins");
        assert!(denial.reason.contains("tools.deny"), "{}", denial.reason);
    }

    #[test]
    fn an_ask_with_no_answering_terminal_is_refused() {
        // DenyBackend stands in for a terminal that cannot answer: the ask
        // must fail closed, not pass.
        let gate = gate(tools_section(&[], &["mvm.machine.stop"], &[]));
        let denial = decide(&gate, "mvm.machine.stop").expect_err("an unanswered ask refuses");
        assert!(denial.reason.contains("ask"), "{}", denial.reason);
    }

    #[test]
    fn detail_does_not_admit_a_tool_by_itself() {
        // Detail attaches to an allowed tool; it is not an allow.
        let mut tools = tools_section(&[], &[], &[]);
        tools.detail.insert(
            "mvm.machine.list".to_string(),
            ToolDetail {
                secrets: vec!["TOKEN".to_string()],
                ..ToolDetail::default()
            },
        );
        let gate = gate(tools);
        let denial = decide(&gate, "mvm.machine.list").expect_err("detail alone does not allow");
        assert!(denial.reason.contains("does not name"), "{}", denial.reason);
    }

    #[test]
    fn allowed_denied_and_asked_calls_are_chain_signed_without_arguments() {
        let dir = tempfile::tempdir().expect("audit dir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        let verifying = key.verifying_key();
        let signer = Arc::new(FileAuditSigner::open(key, dir.path()).expect("signer"));
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".into())));
        let gate = McpToolGate::new(
            tools_section(&["allowed"], &["asked"], &["denied"]).to_tool_rules(),
            Arc::new(DenyBackend),
            recorder,
        );
        decide(&gate, "allowed").expect("allow is audited");
        assert!(decide(&gate, "denied").is_err());
        assert!(decide(&gate, "asked").is_err());
        let entries = verify_audit_chain_entries(&signer.tenant_path("local"), &verifying)
            .expect("chain verifies");
        let events: Vec<_> = entries.iter().map(|entry| entry.event.as_str()).collect();
        assert_eq!(
            events,
            [
                "approval.tool_gate.allowed",
                "approval.tool_gate.denied",
                "approval.tool_gate.requested",
                "approval.tool_gate.ask_denied",
            ]
        );
        assert!(
            entries
                .iter()
                .all(|entry| !entry.labels.contains_key("arguments"))
        );
    }

    #[test]
    fn a_failed_audit_refuses_an_otherwise_allowed_tool() {
        let gate = McpToolGate::new(
            tools_section(&["allowed"], &[], &[]).to_tool_rules(),
            Arc::new(DenyBackend),
            Arc::new(Recorder::new(
                Arc::new(NoopAuditSigner),
                TenantId("local".into()),
            )),
        );
        let denial = decide(&gate, "allowed").expect_err("audit failure denies");
        assert!(denial.reason.contains("audit unavailable"));
    }

    #[test]
    fn a_missing_active_signer_refuses_gate_startup() {
        let dir = tempfile::tempdir().expect("audit dir");
        let err = recorder_for_active_signer(dir.path())
            .err()
            .expect("missing signer refuses");
        assert!(err.to_string().contains("audit unavailable"));
    }

    #[test]
    fn the_gate_reuses_the_process_signer_and_chain_signs_an_approved_ask() {
        let dir = tempfile::tempdir().expect("audit dir");
        let key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
        let verifying = key.verifying_key();
        let signer = Arc::new(FileAuditSigner::open(key, dir.path()).expect("signer"));
        let _registration = register_active_signer(dir.path(), &signer);
        let recorder = recorder_for_active_signer(dir.path()).expect("active signer");
        let approver = CallbackBackend::new(|prompt| {
            ApprovalAnswer::approved(prompt.request_id.clone(), ApprovalScope::Once, "operator")
        });
        let gate = McpToolGate::new(
            tools_section(&[], &["asked"], &[]).to_tool_rules(),
            Arc::new(approver),
            recorder,
        );
        decide(&gate, "asked").expect("an audited ask is approved");
        let entries = verify_audit_chain_entries(&signer.tenant_path("local"), &verifying)
            .expect("chain verifies");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event, "approval.tool_gate.requested");
        assert_eq!(entries[1].event, "approval.tool_gate.granted");
    }

    struct FailSecondSigner(AtomicUsize);

    #[async_trait::async_trait]
    impl AuditSigner for FailSecondSigner {
        async fn sign_and_emit(&self, _entry: &PlanAuditEntry) -> Result<(), AuditError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(AuditError::NotWired)
            }
        }
    }

    #[test]
    fn an_approved_ask_is_refused_if_its_grant_cannot_be_audited() {
        let approver = CallbackBackend::new(|prompt| {
            ApprovalAnswer::approved(prompt.request_id.clone(), ApprovalScope::Once, "operator")
        });
        let gate = McpToolGate::new(
            tools_section(&[], &["asked"], &[]).to_tool_rules(),
            Arc::new(approver),
            Arc::new(Recorder::new(
                Arc::new(FailSecondSigner(AtomicUsize::new(0))),
                TenantId("local".into()),
            )),
        );
        let denial = decide(&gate, "asked").expect_err("unsigned grant refuses");
        assert!(denial.reason.contains("audit unavailable"));
    }
}
