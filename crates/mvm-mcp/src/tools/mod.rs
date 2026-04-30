//! Tool definitions exposed via MCP.
//!
//! The schema (this module) is `protocol-only`; the dispatcher impl
//! that actually runs code in a microVM lives in
//! `mvm-cli::commands::ops::mcp`.
//!
//! Single-tool design ("borrow nix-sandbox-mcp's insight"): we expose
//! one parameterized tool (`run`) so the LLM context-window cost
//! stays flat at ~420 tokens regardless of how many templates the
//! user has built.

use serde::{Deserialize, Serialize};

/// Parameters for the `run` tool. Wire-compatible with
/// `nix-sandbox-mcp`'s `run` tool when names align (`env`, `code`,
/// `session`).
///
/// `deny_unknown_fields` is the same fail-closed hygiene applied to
/// every host-boundary type per ADR-002 §W4.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunParams {
    /// Name of a pre-built `mvmctl template`. Validated against the
    /// installed template registry; an unknown name returns an error
    /// with the list of valid envs.
    pub env: String,
    /// Program text. For `env=shell`/`env=bash`, evaluated via
    /// `bash -c <code>`. For `env=python`/`env=node`, written to a
    /// temp file and passed as the interpreter's first argv. The
    /// shell-env case is intentional and noted in ADR-003: there is
    /// no in-microVM interpreter sandbox beyond the microVM itself.
    pub code: String,
    /// Reserved for Proposal A.2 — session-pinned warm VMs. Ignored
    /// in v1; sending it does not error so clients can adopt the
    /// session API ahead of the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Reserved for Proposal A.2 — when paired with `session`, signals
    /// "this is the last call against this session, tear the VM down
    /// (snapshot first if the env was registered with
    /// `persist_on_close=true`)". Ignored in v1; the schema accepts
    /// it so clients can adopt the session lifecycle ahead of the
    /// server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close: Option<bool>,
    /// Per-call timeout in seconds. Bounded `[1, 600]`; out-of-range
    /// values are clamped (not errored) so an LLM that picks
    /// `timeout_secs: 0` still makes progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

/// JSON Schema for the `run` tool's input.
///
/// Hand-written instead of derived because we want the per-field
/// description text to bias the LLM toward sane defaults.
pub fn run_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["env", "code"],
        "properties": {
            "env": {
                "type": "string",
                "description": "Pre-built microVM template to execute in. Use 'shell' for filesystem/CLI work, 'python' for numeric/data work, 'node' for JS, or any user-defined template such as 'claude-code-vm'."
            },
            "code": {
                "type": "string",
                "description": "Program source. For shell/bash envs, executed via 'bash -c'. For python/node envs, written to a temp file and run by the interpreter."
            },
            "session": {
                "type": "string",
                "description": "Optional session ID for warm-VM persistence (reserved; v1 ignores)."
            },
            "close": {
                "type": "boolean",
                "description": "When paired with `session`, signals this is the last call against the session — server may snapshot + tear down (reserved; v1 ignores)."
            },
            "timeout_secs": {
                "type": "integer",
                "description": "Per-call timeout in seconds. Default 60. Clamped to [1, 600].",
                "minimum": 1,
                "maximum": 600
            }
        },
        "additionalProperties": false
    })
}

/// One tool in the registry. Returned by `tools/list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// All tools exposed by mvmctl mcp. v1 = exactly one.
pub fn all_tools() -> Vec<ToolSchema> {
    vec![ToolSchema {
        name: "run".to_string(),
        description:
            "Run code inside a fresh mvm microVM. Single tool; the `env` parameter selects which pre-built template to boot. Output is captured (stdout, stderr, exit_code). Each call boots and tears down a transient VM (session reuse is reserved). Use `mvmctl template list` on the host to discover available envs."
                .to_string(),
        input_schema: run_input_schema(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_params_serde_roundtrip() {
        let p = RunParams {
            env: "shell".to_string(),
            code: "echo hi".to_string(),
            session: None,
            close: None,
            timeout_secs: Some(30),
        };
        let s = serde_json::to_string(&p).unwrap();
        let parsed: RunParams = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.env, "shell");
        assert_eq!(parsed.timeout_secs, Some(30));
    }

    #[test]
    fn run_params_accepts_session_and_close() {
        // A.2 schema readiness: clients adopting session+close ahead
        // of server-side support must not get a parse error.
        let json = r#"{"env":"shell","code":"x","session":"s1","close":true}"#;
        let parsed: RunParams = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.session.as_deref(), Some("s1"));
        assert_eq!(parsed.close, Some(true));
    }

    #[test]
    fn run_params_rejects_unknown_fields() {
        let bad = r#"{"env":"shell","code":"x","unknown_field":1}"#;
        assert!(serde_json::from_str::<RunParams>(bad).is_err());
    }

    #[test]
    fn all_tools_returns_single_run_tool() {
        let tools = all_tools();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "run");
    }

    #[test]
    fn tools_list_token_budget_under_500() {
        // Byte-count heuristic where 1 token ≈ 4 bytes (well-known
        // approximation for Claude/GPT-4 family). The plan's target
        // is ≤ 500 tokens for `tools/list`. Guards against schema
        // bloat as we add description text over time.
        let serialized = serde_json::to_string(&all_tools()).unwrap();
        let approx_tokens = serialized.len() / 4;
        assert!(
            approx_tokens < 500,
            "tools/list too large: ~{} tokens ({} bytes); target < 500",
            approx_tokens,
            serialized.len()
        );
    }
}
