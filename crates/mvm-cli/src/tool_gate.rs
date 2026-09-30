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
//! Every non-allow decision is recorded as a `ToolGateDecision` local audit
//! entry. The dimension is opt-in: a policy with no `[tools]` section
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
use mvm_contract::policy::approval_prompt::{ApprovalPrompt, ApprovalSubject};
use mvm_contract::policy::tool_rules::{ToolDecision, ToolRules};
use mvm_core::policy::audit::LocalAuditKind;
use mvm_mcp::{ToolCallGate, ToolGateDenial};
use serde_json::Map;
use serde_json::Value;

use crate::approval::tty::TerminalBackend;

/// Authorize MCP tool calls against one resolved `[tools]` section.
pub struct McpToolGate {
    rules: ToolRules,
    approver: Arc<dyn ApprovalBackend>,
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
        Ok(Some(Self::new(
            policy.tools.to_tool_rules(),
            Arc::new(TerminalBackend::controlling(false)),
        )))
    }

    fn new(rules: ToolRules, approver: Arc<dyn ApprovalBackend>) -> Self {
        Self {
            rules,
            approver,
            sequence: AtomicU64::new(0),
        }
    }

    fn next_request_id(&self) -> mvm_contract::policy::approval::ApprovalRequestId {
        let n = self.sequence.fetch_add(1, Ordering::Relaxed);
        mvm_contract::policy::approval::ApprovalRequestId::parse(format!("appr-mcp-{n}"))
            .expect("request id is built from contract-legal characters")
    }

    fn record(&self, tool: &str, outcome: &str, reason: &str) {
        mvm_core::policy::audit::event(LocalAuditKind::ToolGateDecision)
            .detail(format!("tool={tool} outcome={outcome} reason={reason}"))
            .emit();
    }
}

impl ToolCallGate for McpToolGate {
    fn authorize(&self, tool: &str, _arguments: &Map<String, Value>) -> Result<(), ToolGateDenial> {
        // The MCP surface has no command line: the whole-tool decision from
        // the shared evaluator stands (an empty section admits everything).
        match self.rules.decide(tool, None) {
            ToolDecision::Allow => Ok(()),
            ToolDecision::Deny(rule) => {
                let reason = format!("policy denies this tool ({rule})");
                self.record(tool, "denied", &reason);
                Err(ToolGateDenial::new(reason))
            }
            ToolDecision::Ask => {
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
                        self.record(tool, "ask_granted", "the terminal approver granted the ask");
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
                        self.record(tool, "ask_denied", &reason);
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
    let Some(selection) = PolicySelection::for_launch(None, project)? else {
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
    use mvm_client::approval_broker::DenyBackend;
    use mvm_client::policy_profiles::model::{ToolDetail, ToolsSection};

    fn tools_section(allow: &[&str], ask: &[&str], deny: &[&str]) -> ToolsSection {
        ToolsSection {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            ask: ask.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ..ToolsSection::default()
        }
    }

    fn gate(tools: ToolsSection) -> McpToolGate {
        McpToolGate::new(tools.to_tool_rules(), Arc::new(DenyBackend))
    }

    #[test]
    fn an_allowed_tool_is_admitted() {
        let gate = gate(tools_section(&["mvm.machine.list"], &[], &[]));
        gate.authorize("mvm.machine.list", &Map::new())
            .expect("allowed tool passes");
    }

    #[test]
    fn a_denied_tool_is_refused_with_the_policy_reason() {
        let gate = gate(tools_section(&[], &[], &["mvm.machine.stop"]));
        let denial = gate
            .authorize("mvm.machine.stop", &Map::new())
            .expect_err("denied tool refuses");
        assert!(denial.reason.contains("tools.deny"), "{}", denial.reason);
    }

    #[test]
    fn an_unlisted_tool_fails_closed() {
        let gate = gate(tools_section(&["mvm.machine.list"], &[], &[]));
        let denial = gate
            .authorize("mvm.machine.rm", &Map::new())
            .expect_err("unlisted tool refuses");
        assert!(denial.reason.contains("does not name"), "{}", denial.reason);
    }

    #[test]
    fn deny_beats_allow_and_ask() {
        let gate = gate(tools_section(
            &["mvm.machine.stop"],
            &["mvm.machine.stop"],
            &["mvm.machine.stop"],
        ));
        let denial = gate
            .authorize("mvm.machine.stop", &Map::new())
            .expect_err("deny wins");
        assert!(denial.reason.contains("tools.deny"), "{}", denial.reason);
    }

    #[test]
    fn an_ask_with_no_answering_terminal_is_refused() {
        // DenyBackend stands in for a terminal that cannot answer: the ask
        // must fail closed, not pass.
        let gate = gate(tools_section(&[], &["mvm.machine.stop"], &[]));
        let denial = gate
            .authorize("mvm.machine.stop", &Map::new())
            .expect_err("an unanswered ask refuses");
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
        let denial = gate
            .authorize("mvm.machine.list", &Map::new())
            .expect_err("detail alone does not allow");
        assert!(denial.reason.contains("does not name"), "{}", denial.reason);
    }
}
