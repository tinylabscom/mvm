//! Host-mediated agent tools substrate.
//!
//! An LLM agent (Claude Code, opencode, future mvmforge clients)
//! calls into host-mediated tools — `mvm.web_search`,
//! `mvm.web_fetch`, `mvm.time_now`, `mvm.upload`/`download`, etc. The
//! agent doesn't reach these directly; every call routes through the
//! supervisor so:
//!
//! 1. **Allowlist enforcement** — the plan's
//!    `tool_policy: PolicyRef` gates which tools are reachable.
//!    Handled by [`crate::supervisor::tool_gate::ToolGate`] *before* calling
//!    [`ToolRegistry::invoke`]; this substrate trusts its caller did
//!    that.
//! 2. **Audit emission** — every successful or failed invoke fires
//!    a chain-signed entry through the
//!    [`Recorder`](crate::supervisor::Recorder) under `EventCategory::Cmd` with
//!    the canonical event name `cmd.tool.<name>.{completed,failed}`.
//!    The audit is best-effort: a chain-signer failure does not
//!    fail the tool call.
//! 3. **Uniform error rendering** — tool-side errors return
//!    [`ToolInvokeError`] so callers can surface a structured
//!    failure to the LLM client (MCP semantics: errors must reach
//!    the model, not the JSON-RPC error channel).
//!
//! ## What this module is NOT
//!
//! - Not a tool gate. [`crate::supervisor::tool_gate::ToolGate`] +
//!   [`crate::supervisor::policy_tool_gate::PolicyToolGate`] decide
//!   allow/deny; this module decides "given allow, what happens".
//! - Not a transport. The MCP server (`mvm-mcp/src/server.rs`) and
//!   the future agent vsock RPC are the
//!   two consumers; both call [`ToolRegistry::invoke`] after the
//!   gate clears.
//! - Not a place for per-tenant state. Tools are stateless from the
//!   registry's perspective; any per-tenant data (cached
//!   credentials, rate-limit buckets) lives inside each tool's own
//!   impl module.
//!
//! ## Adding a new tool
//!
//! 1. Add `pub mod <name>;` here.
//! 2. Implement [`HostMediatedTool`] in that submodule.
//! 3. Add a `register_<name>` helper if the tool needs construction
//!    args (credentials, allowlists) — keep `new() -> Self` for
//!    parameter-free tools so the registry can build a default
//!    bundle.
//! 4. Add the tool name to the canonical allowlist in
//!    `mvm-core::policy::ToolPolicy::DEFAULTS` (separate slice; this
//!    substrate does not pre-allowlist anything).

pub mod download;
pub mod http_hardening;
pub mod staging;
pub mod time_now;
pub mod upload;
pub mod web_fetch;
pub mod web_search;

use std::collections::BTreeMap;

use async_trait::async_trait;
use thiserror::Error;

use crate::supervisor::audit_recorder::{EventCategory, Recorder};

/// One tool the agent invokes through the supervisor. The trait is
/// JSON-shaped on both sides so any tool's signature flows through
/// the MCP wire format and the vsock RPC without bespoke encoding.
///
/// Implementors carry their own per-tool state (credentials,
/// upstream HTTP clients, rate-limit buckets) so the registry stays
/// stateless from the orchestration perspective.
#[async_trait]
pub trait HostMediatedTool: Send + Sync {
    /// Canonical tool name as exposed to the agent. Use the
    /// `mvm.<verb>` form (`mvm.time_now`, `mvm.web_search`,
    /// `mvm.web_fetch`, …) so allowlist entries are unambiguous
    /// across builtin and future-third-party tools.
    fn name(&self) -> &'static str;

    /// Invoke the tool. `params` is the raw JSON the agent sent;
    /// the impl deserializes into its own typed shape. Returns a
    /// JSON `Value` (the MCP wire result) or a structured
    /// [`ToolInvokeError`].
    async fn invoke(&self, params: serde_json::Value)
    -> Result<serde_json::Value, ToolInvokeError>;
}

/// Errors a tool surface can emit. Rendered to the MCP
/// `ToolResult { is_error: true, content: [Text { text: ... }] }`
/// shape by the dispatcher — they do NOT propagate as JSON-RPC
/// errors (clients tend to retry those instead of surfacing).
#[derive(Debug, Error)]
pub enum ToolInvokeError {
    /// The params didn't deserialize, or a required field is missing.
    #[error("invalid params for {tool}: {message}")]
    InvalidParams { tool: String, message: String },

    /// The named tool isn't registered. Caller chose a tool name
    /// that no impl serves — typically a typo in the agent's request,
    /// or a stale allowlist that names tools the supervisor has
    /// since dropped.
    #[error("unknown tool: {tool} (registered: {available:?})")]
    UnknownTool {
        tool: String,
        available: Vec<String>,
    },

    /// The upstream service (network, filesystem, etc.) refused or
    /// failed. The wrapped string is operator-readable; tools must
    /// take care to redact secrets before constructing this variant.
    #[error("upstream failure in {tool}: {message}")]
    Upstream { tool: String, message: String },
}

/// A bundle of available [`HostMediatedTool`] impls keyed by their
/// canonical name. Build once at supervisor start; share across
/// every dispatcher (MCP, agent vsock RPC).
///
/// The registry holds an optional [`Recorder`] for chain-signed
/// audit emission. When wired, every invoke fires
/// `cmd.tool.<name>.completed` (or `cmd.tool.<name>.failed`) under
/// [`EventCategory::Cmd`]. Audit failures degrade silently — a
/// tool call's success contract is independent of audit reachability.
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn HostMediatedTool>>,
    recorder: Option<Recorder>,
}

impl ToolRegistry {
    /// Build an empty registry. Tools are added via [`Self::register`];
    /// the audit recorder is attached via [`Self::with_recorder`].
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
            recorder: None,
        }
    }

    /// Build with the default tool set: every builtin is
    /// registered with its fail-closed `Default::default()` config.
    ///
    /// Today's registrations:
    ///
    /// - `mvm.time_now` — always reachable; no allowlist needed
    ///   (pure host-clock read with no upstream).
    /// - `mvm.web_fetch` — fail-closed by default (empty host
    ///   allowlist + [`web_fetch::NoopHttpFetcher`]). Operators
    ///   call [`Self::register`] with a configured
    ///   [`web_fetch::WebFetchTool`] to enable.
    /// - `mvm.web_search` — fail-closed by default (empty provider
    ///   allowlist + [`web_search::NoopSearchProvider`]).
    /// - `mvm.upload` / `mvm.download` — fail-closed by default
    ///   ([`staging::NoopStagingArea`]); operators wire a real
    ///   [`staging::FsStagingArea`] via the env-driven
    ///   `build_tool_registry` helper in `mvm-cli`.
    ///
    /// Future slices grow this list as `code_eval` lands.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Box::new(time_now::TimeNowTool));
        r.register(Box::new(web_fetch::WebFetchTool::default()));
        r.register(Box::new(web_search::WebSearchTool::default()));
        r.register(Box::new(upload::UploadTool::default()));
        r.register(Box::new(download::DownloadTool::default()));
        r
    }

    /// Attach a Recorder for chain-signed audit emission. Returns
    /// `self` for chaining.
    pub fn with_recorder(mut self, recorder: Recorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Register a tool. Replaces any previous entry with the same
    /// `name()` — useful for tests that want to override a builtin
    /// with a stub. Production callers should register each name
    /// exactly once.
    pub fn register(&mut self, tool: Box<dyn HostMediatedTool>) {
        let name = tool.name();
        self.tools.insert(name, tool);
    }

    /// The set of registered tool names, sorted (BTreeMap's keys are
    /// already in sort order). Operators see this in the error
    /// message on `UnknownTool` to debug allowlist drift.
    pub fn names(&self) -> Vec<&'static str> {
        self.tools.keys().copied().collect()
    }

    /// True if the named tool is registered. Used by the future
    /// MCP dispatcher to short-circuit before constructing the
    /// JSON-RPC response.
    pub fn is_registered(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Dispatch a tool call. The named tool's [`HostMediatedTool::invoke`]
    /// runs against `params`; the result (success or failure) emits
    /// a `cmd.tool.<name>.<phase>` audit entry through the wired
    /// Recorder.
    ///
    /// **Allowlist note**: This method does NOT consult any
    /// `ToolPolicy`. The caller (MCP dispatcher / agent vsock
    /// handler) MUST have already called
    /// [`crate::supervisor::tool_gate::ToolGate::check`] and seen
    /// `ToolDecision::Allow`. Skipping that step is a security bug
    /// — the registry trusts its caller to gate access.
    pub async fn invoke(
        &self,
        name: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ToolInvokeError> {
        let Some(tool) = self.tools.get(name) else {
            let err = ToolInvokeError::UnknownTool {
                tool: name.to_string(),
                available: self.names().into_iter().map(String::from).collect(),
            };
            self.emit_audit(name, "failed", Some(&err.to_string()))
                .await;
            return Err(err);
        };
        let result = tool.invoke(params).await;
        match &result {
            Ok(_) => self.emit_audit(name, "completed", None).await,
            Err(e) => self.emit_audit(name, "failed", Some(&e.to_string())).await,
        }
        result
    }

    async fn emit_audit(&self, name: &str, phase: &str, error: Option<&str>) {
        let Some(ref rec) = self.recorder else { return };
        let event = format!("cmd.tool.{name}.{phase}");
        let mut extras: Vec<(String, String)> = vec![
            ("tool".to_string(), name.to_string()),
            ("phase".to_string(), phase.to_string()),
        ];
        if let Some(err) = error {
            extras.push(("error".to_string(), err.to_string()));
        }
        if let Err(e) = rec.record_unbound(EventCategory::Cmd, event, extras).await {
            tracing::warn!(error = %e, tool = name, "tool audit emit failed");
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::audit::CapturingAuditSigner;
    use mvm_core::plan::TenantId;
    use std::sync::Arc;

    /// Test stub — records each invoke for assertions. Returns the
    /// params it received, echoed inside a `{ "got": ... }` envelope.
    struct EchoTool;

    #[async_trait]
    impl HostMediatedTool for EchoTool {
        fn name(&self) -> &'static str {
            "mvm.echo"
        }
        async fn invoke(
            &self,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, ToolInvokeError> {
            Ok(serde_json::json!({ "got": params }))
        }
    }

    /// Test stub — always fails with a fixed message.
    struct FailingTool;

    #[async_trait]
    impl HostMediatedTool for FailingTool {
        fn name(&self) -> &'static str {
            "mvm.failing"
        }
        async fn invoke(
            &self,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, ToolInvokeError> {
            Err(ToolInvokeError::Upstream {
                tool: "mvm.failing".to_string(),
                message: "boom".to_string(),
            })
        }
    }

    fn build_registry_with_recorder() -> (ToolRegistry, Arc<CapturingAuditSigner>) {
        let signer = Arc::new(CapturingAuditSigner::new());
        let rec = Recorder::new(signer.clone(), TenantId("local".to_string()));
        let mut reg = ToolRegistry::new().with_recorder(rec);
        reg.register(Box::new(EchoTool));
        reg.register(Box::new(FailingTool));
        (reg, signer)
    }

    // ──────────────────────────────────────────────────────────────
    // Construction
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn empty_registry_lists_no_tools() {
        let r = ToolRegistry::new();
        assert!(r.names().is_empty());
        assert!(!r.is_registered("mvm.anything"));
    }

    #[test]
    fn with_defaults_registers_all_phase_7_builtins() {
        // The substrate ships five tools out of the box.
        // `time_now` is reachable; the rest are wired with
        // fail-closed defaults so an operator who calls them
        // without configuring an allowlist / staging area gets a
        // clear "not wired" error.
        let r = ToolRegistry::with_defaults();
        for builtin in [
            "mvm.time_now",
            "mvm.web_fetch",
            "mvm.web_search",
            "mvm.upload",
            "mvm.download",
        ] {
            assert!(
                r.is_registered(builtin),
                "default registry must include {builtin}"
            );
        }
        assert_eq!(r.names().len(), 5);
    }

    #[tokio::test]
    async fn with_defaults_web_fetch_is_fail_closed() {
        // Sanity: a fresh registry hands out a `WebFetchTool` that
        // refuses every host. This is the contract that lets
        // operators ship the substrate with no per-tenant config and
        // not accidentally leak.
        let r = ToolRegistry::with_defaults();
        let err = r
            .invoke(
                "mvm.web_fetch",
                serde_json::json!({ "url": "https://x.example/" }),
            )
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { tool, message } => {
                assert_eq!(tool, "mvm.web_fetch");
                assert!(message.contains("not on per-tenant allowlist"), "{message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn with_defaults_web_search_is_fail_closed() {
        let r = ToolRegistry::with_defaults();
        let err = r
            .invoke("mvm.web_search", serde_json::json!({ "query": "x" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { tool, .. } => {
                assert_eq!(tool, "mvm.web_search");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn register_overrides_existing_entry() {
        // Useful in tests to swap a builtin for a stub.
        let mut r = ToolRegistry::with_defaults();
        assert!(r.is_registered("mvm.time_now"));
        struct OverrideTimeTool;
        #[async_trait]
        impl HostMediatedTool for OverrideTimeTool {
            fn name(&self) -> &'static str {
                "mvm.time_now"
            }
            async fn invoke(
                &self,
                _: serde_json::Value,
            ) -> Result<serde_json::Value, ToolInvokeError> {
                Ok(serde_json::json!({ "overridden": true }))
            }
        }
        r.register(Box::new(OverrideTimeTool));
        // Still exactly one entry under that name.
        assert_eq!(
            r.names().iter().filter(|n| **n == "mvm.time_now").count(),
            1
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Invoke happy path
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn invoke_routes_to_named_tool() {
        let (reg, _signer) = build_registry_with_recorder();
        let out = reg
            .invoke("mvm.echo", serde_json::json!({ "x": 1 }))
            .await
            .unwrap();
        assert_eq!(out, serde_json::json!({ "got": { "x": 1 } }));
    }

    #[tokio::test]
    async fn invoke_emits_completed_audit_on_success() {
        let (reg, signer) = build_registry_with_recorder();
        reg.invoke("mvm.echo", serde_json::json!({})).await.unwrap();
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "cmd.tool.mvm.echo.completed");
        assert_eq!(entries[0].labels.get("tool"), Some(&"mvm.echo".to_string()));
        assert_eq!(
            entries[0].labels.get("phase"),
            Some(&"completed".to_string())
        );
        assert!(!entries[0].labels.contains_key("error"));
    }

    // ──────────────────────────────────────────────────────────────
    // Invoke error paths
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn invoke_unknown_tool_names_available_tools_in_error() {
        let (reg, _) = build_registry_with_recorder();
        let err = reg
            .invoke("mvm.nope", serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = err.to_string();
        // The available-tools list shows up so an operator can spot
        // typos.
        assert!(msg.contains("mvm.echo"), "got: {msg}");
        assert!(msg.contains("mvm.failing"), "got: {msg}");
        assert!(msg.contains("mvm.nope"), "got: {msg}");
    }

    #[tokio::test]
    async fn invoke_unknown_tool_emits_failed_audit() {
        let (reg, signer) = build_registry_with_recorder();
        let _ = reg
            .invoke("mvm.nope", serde_json::json!({}))
            .await
            .unwrap_err();
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        // The audit event uses the requested name, not "unknown".
        assert_eq!(entries[0].event, "cmd.tool.mvm.nope.failed");
        assert!(entries[0].labels.contains_key("error"));
    }

    #[tokio::test]
    async fn invoke_propagates_upstream_failure() {
        let (reg, signer) = build_registry_with_recorder();
        let err = reg
            .invoke("mvm.failing", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::Upstream { .. }));
        // Audit captures the failure.
        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "cmd.tool.mvm.failing.failed");
        assert_eq!(
            entries[0].labels.get("error").map(String::as_str),
            Some("upstream failure in mvm.failing: boom")
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Recorder absent
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn invoke_without_recorder_returns_ok_and_skips_audit() {
        // Same EchoTool; no recorder attached. Tool call must
        // still succeed.
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(EchoTool));
        let out = reg
            .invoke("mvm.echo", serde_json::json!({ "x": 1 }))
            .await
            .unwrap();
        assert_eq!(out, serde_json::json!({ "got": { "x": 1 } }));
    }
}
