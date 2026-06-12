//! `PolicyToolGate` — replaces `NoopToolGate` with a real
//! allowlist check against `mvm-core::policy::ToolPolicy`.
//!
//! ## Phase 1 scope (this module)
//!
//! - Pure policy-decision logic: take a tool name, look it up in
//!   the plan's `ToolPolicy.allowed: Vec<String>` allowlist, return
//!   Allow / Deny.
//! - Audit-safe deny reasons: name the rejected tool and include
//!   the visible allowlist entries (operator sees both what was
//!   blocked AND what was permitted, in the same audit line).
//! - [`ToolAuditSink`] trait + capturing/noop sinks, mirroring the
//!   `EgressAuditSink` shape so the supervisor's audit fan-out
//!   stays uniform.
//! - `Supervisor::with_tool_gate` builder lands in `supervisor.rs`.
//!
//! ## Phase 2
//!
//! - Vsock listener loop: the workload talks to the supervisor via
//!   vsock RPC ("can I call tool `read_file`?"); the supervisor
//!   handles the request by calling `ToolGate::check(name)`.
//! - JSON-RPC framing on the vsock socket.
//!
//! Splitting like this keeps the policy decision testable without
//! the I/O surface, and lets Phase 2 layer on cleanly.
//!
//! ## Design notes
//!
//! - `PolicyToolGate` stores a `BTreeSet<String>` for O(log n)
//!   lookup. The bundle's policy carries a `Vec<String>` (preserves
//!   serialization order); we copy into a set at construction.
//! - The deny reason includes the allowlist contents so operators
//!   can answer "what would have been allowed?" in one read. For
//!   workloads with very long allowlists, callers can construct
//!   the gate with [`PolicyToolGate::quiet_deny_reasons`] to omit
//!   the listing — but the default is loud, because audit-time
//!   verbosity is a feature.
//! - The check method is `async` to match the trait. The lookup
//!   itself is synchronous; the async wrapper is free.

use std::collections::BTreeSet;
use std::sync::Mutex;

use async_trait::async_trait;
use mvm_core::policy::ToolPolicy;
use thiserror::Error;

use crate::supervisor::tool_gate::{ToolDecision, ToolError, ToolGate};

/// Audit record emitted per `ToolGate::check` call. Mirrors the
/// shape of [`crate::supervisor::l7_proxy::AuditFields`] so audit fan-out is
/// uniform across egress + tool-call paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAuditFields {
    pub outcome: ToolOutcome,
    pub tool_name: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    Allow,
    Deny,
}

#[derive(Debug, Error)]
pub enum ToolAuditError {
    #[error("tool audit sink not wired")]
    NotWired,
    #[error("io error writing tool audit: {0}")]
    Io(String),
}

#[async_trait]
pub trait ToolAuditSink: Send + Sync {
    async fn record(&self, fields: &ToolAuditFields) -> Result<(), ToolAuditError>;
}

/// In-memory sink for tests + dev mode.
pub struct CapturingToolAuditSink {
    entries: Mutex<Vec<ToolAuditFields>>,
}

impl CapturingToolAuditSink {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }
    pub fn entries(&self) -> Vec<ToolAuditFields> {
        self.entries
            .lock()
            .expect("CapturingToolAuditSink mutex poisoned")
            .clone()
    }
}
impl Default for CapturingToolAuditSink {
    fn default() -> Self {
        Self::new()
    }
}
#[async_trait]
impl ToolAuditSink for CapturingToolAuditSink {
    async fn record(&self, fields: &ToolAuditFields) -> Result<(), ToolAuditError> {
        self.entries
            .lock()
            .expect("CapturingToolAuditSink mutex poisoned")
            .push(fields.clone());
        Ok(())
    }
}

/// Sink that swallows tool-audit records. Default for callsites
/// that don't yet have a plan/bundle binding.
pub struct NoopToolAuditSink;
#[async_trait]
impl ToolAuditSink for NoopToolAuditSink {
    async fn record(&self, _fields: &ToolAuditFields) -> Result<(), ToolAuditError> {
        Ok(())
    }
}

/// Real `ToolGate` impl backed by a `ToolPolicy.allowed` allowlist.
pub struct PolicyToolGate {
    allowed: BTreeSet<String>,
    /// When false, deny reasons include the full allowlist. When
    /// true, the reason names the rejected tool only. Loud by
    /// default — audit verbosity is a feature.
    quiet: bool,
}

impl PolicyToolGate {
    /// Build from a `ToolPolicy`. The bundle's `Vec<String>` is
    /// deduplicated into a `BTreeSet` for O(log n) lookup.
    pub fn from_policy(policy: &ToolPolicy) -> Self {
        Self {
            allowed: policy.allowed.iter().cloned().collect(),
            quiet: false,
        }
    }

    /// Build from an iterator of allowed names (test convenience).
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: names.into_iter().map(Into::into).collect(),
            quiet: false,
        }
    }

    /// Deny-everything sentinel — useful when the workload has no
    /// `tool_policy` resolved yet, or when the policy bundle's
    /// allowed set is empty (a deliberate fail-closed
    /// configuration).
    pub fn deny_all() -> Self {
        Self::new::<_, &str>(std::iter::empty())
    }

    /// Set the deny-reason verbosity. Default = loud (false).
    pub fn quiet_deny_reasons(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// True iff `name` is on the allowlist. Synchronous helper
    /// exposed for non-trait callsites (e.g., a vsock RPC handler
    /// that already has its own async wrapper).
    pub fn is_allowed(&self, name: &str) -> bool {
        self.allowed.contains(name)
    }

    fn render_allowlist(&self) -> String {
        if self.allowed.is_empty() {
            "<empty allowlist — deny-all>".to_string()
        } else {
            // Stable ordering courtesy of BTreeSet.
            self.allowed.iter().cloned().collect::<Vec<_>>().join(", ")
        }
    }
}

#[async_trait]
impl ToolGate for PolicyToolGate {
    async fn check(&self, tool_name: &str) -> Result<ToolDecision, ToolError> {
        if self.is_allowed(tool_name) {
            return Ok(ToolDecision::Allow);
        }
        let reason = if self.quiet {
            format!("tool '{tool_name}' not in policy allowlist")
        } else {
            format!(
                "tool '{tool_name}' not in policy allowlist (allowed: {})",
                self.render_allowlist()
            )
        };
        Ok(ToolDecision::Deny { reason })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allowed_name_returns_allow() {
        let gate = PolicyToolGate::new(["read_file", "list_dir"]);
        let v = gate.check("read_file").await.expect("ok");
        assert_eq!(v, ToolDecision::Allow);
    }

    #[tokio::test]
    async fn unknown_name_denies_with_visible_allowlist() {
        let gate = PolicyToolGate::new(["read_file", "list_dir"]);
        let v = gate.check("rm_rf").await.expect("ok");
        match v {
            ToolDecision::Deny { reason } => {
                assert!(reason.contains("rm_rf"));
                // Loud by default — operator sees what WAS allowed.
                assert!(reason.contains("read_file"));
                assert!(reason.contains("list_dir"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn quiet_mode_omits_allowlist_from_reason() {
        let gate = PolicyToolGate::new(["read_file", "list_dir"]).quiet_deny_reasons(true);
        let v = gate.check("rm_rf").await.expect("ok");
        match v {
            ToolDecision::Deny { reason } => {
                assert!(reason.contains("rm_rf"));
                assert!(!reason.contains("read_file"));
                assert!(!reason.contains("list_dir"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deny_all_sentinel_blocks_every_call() {
        let gate = PolicyToolGate::deny_all();
        for name in ["read_file", "list_dir", "anything"] {
            let v = gate.check(name).await.expect("ok");
            assert!(matches!(v, ToolDecision::Deny { .. }));
        }
    }

    #[tokio::test]
    async fn empty_allowlist_renders_explicit_deny_all_reason() {
        let gate = PolicyToolGate::deny_all();
        let v = gate.check("read_file").await.expect("ok");
        if let ToolDecision::Deny { reason } = v {
            assert!(reason.contains("<empty allowlist"));
        } else {
            panic!("expected Deny");
        }
    }

    #[tokio::test]
    async fn from_policy_dedupes_input_vec() {
        // ToolPolicy.allowed is Vec; allow duplicate entries to
        // appear (perhaps from a hand-edited bundle) and confirm
        // PolicyToolGate dedupes via BTreeSet.
        let policy = ToolPolicy {
            allowed: vec![
                "read_file".to_string(),
                "read_file".to_string(),
                "list_dir".to_string(),
            ],
        };
        let gate = PolicyToolGate::from_policy(&policy);
        assert!(gate.is_allowed("read_file"));
        assert!(gate.is_allowed("list_dir"));
        assert!(!gate.is_allowed("rm_rf"));
    }

    #[tokio::test]
    async fn from_policy_preserves_stable_iteration_order() {
        // Audit reasons must be deterministic across runs — same
        // policy should produce the same listing every time.
        let policy = ToolPolicy {
            allowed: vec!["zzz".to_string(), "aaa".to_string(), "mmm".to_string()],
        };
        let gate = PolicyToolGate::from_policy(&policy);
        let v1 = gate.check("nope").await.expect("ok");
        let v2 = gate.check("nope").await.expect("ok");
        assert_eq!(v1, v2);
        // BTreeSet ordering: aaa, mmm, zzz.
        if let ToolDecision::Deny { reason } = v1 {
            assert!(reason.contains("aaa, mmm, zzz"));
        } else {
            panic!("expected Deny");
        }
    }

    #[tokio::test]
    async fn capturing_audit_sink_records_entries() {
        let sink = CapturingToolAuditSink::new();
        sink.record(&ToolAuditFields {
            outcome: ToolOutcome::Allow,
            tool_name: "read_file".to_string(),
            reason: None,
        })
        .await
        .expect("ok");
        sink.record(&ToolAuditFields {
            outcome: ToolOutcome::Deny,
            tool_name: "rm_rf".to_string(),
            reason: Some("not allowed".to_string()),
        })
        .await
        .expect("ok");
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].outcome, ToolOutcome::Allow);
        assert_eq!(entries[1].outcome, ToolOutcome::Deny);
    }

    #[tokio::test]
    async fn noop_sink_silently_succeeds() {
        let sink = NoopToolAuditSink;
        let r = sink
            .record(&ToolAuditFields {
                outcome: ToolOutcome::Allow,
                tool_name: "x".to_string(),
                reason: None,
            })
            .await;
        assert!(r.is_ok());
    }
}
