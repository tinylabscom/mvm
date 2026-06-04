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
    /// Name of a pre-built sandbox environment. Two forms accepted:
    ///
    /// - **Built-in preset name** — `shell`, `bash`, `python`, `node`.
    /// - **Manifest path** — an absolute path to a project directory
    ///   containing `mvm.toml`/`Mvmfile.toml`, or to the manifest file
    ///   itself. The slot for that manifest must already be built
    ///   (via `mvmctl build <PATH>`).
    ///
    /// An unknown value returns an error listing the valid built-ins
    /// and the user's currently-built slots.
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
                "description": "Pre-built microVM environment to execute in. Use 'shell' / 'bash' for filesystem/CLI work, 'python' for numeric/data work, 'node' for JS, or pass an absolute path to a project directory containing `mvm.toml` (the slot must have been built first via `mvmctl build <PATH>`). Run `mvmctl manifest ls` on the host to list available manifest-keyed slots."
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

/// JSON Schema for the `mvm.time_now` tool. Mirrors
/// `mvm_hostd::supervisor::tools::time_now::TimeNowParams`.
pub fn time_now_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "format": {
                "type": "string",
                "enum": ["rfc3339", "unix"],
                "description": "Output format. 'rfc3339' (default) returns an ISO-8601 string; 'unix' returns seconds-since-epoch as a decimal string."
            }
        },
        "additionalProperties": false
    })
}

/// JSON Schema for the `mvm.web_fetch` tool. Mirrors
/// `mvm_hostd::supervisor::tools::web_fetch::WebFetchParams`.
pub fn web_fetch_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {
                "type": "string",
                "description": "Absolute https:// URL to fetch. http:// and other schemes are rejected. The destination host must appear in the per-tenant allowlist."
            },
            "max_bytes": {
                "type": "integer",
                "description": "Cap on response body length, in bytes. Defaults to 1 MiB; values above 16 MiB are clamped.",
                "minimum": 1
            }
        },
        "additionalProperties": false
    })
}

/// JSON Schema for the `mvm.upload` tool. Mirrors
/// `mvm_hostd::supervisor::tools::upload::UploadParams`.
pub fn upload_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["path", "content_base64"],
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path under the per-tenant staging root. No absolute paths, no '..' components, no control characters; length capped at 512 bytes."
            },
            "content_base64": {
                "type": "string",
                "description": "URL-safe-no-pad base64 of the payload bytes. Binary content round-trips losslessly."
            },
            "max_bytes": {
                "type": "integer",
                "description": "Post-decode size cap, in bytes. Defaults to 16 MiB; values above 256 MiB are clamped.",
                "minimum": 1
            }
        },
        "additionalProperties": false
    })
}

/// JSON Schema for the `mvm.download` tool. Mirrors
/// `mvm_hostd::supervisor::tools::download::DownloadParams`.
pub fn download_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["path"],
        "properties": {
            "path": {
                "type": "string",
                "description": "Relative path under the per-tenant staging root. Same validation as mvm.upload."
            },
            "max_bytes": {
                "type": "integer",
                "description": "Cap on file size, in bytes. Defaults to 16 MiB; values above 256 MiB are clamped. Files larger than the cap return an error instead of a partial read.",
                "minimum": 1
            }
        },
        "additionalProperties": false
    })
}

/// JSON Schema for the `mvm.web_search` tool. Mirrors
/// `mvm_hostd::supervisor::tools::web_search::WebSearchParams`.
pub fn web_search_input_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "type": "string",
                "description": "Free-form search query. Non-empty, no control characters, length capped at 1024."
            },
            "provider": {
                "type": "string",
                "description": "Optional provider name (e.g. 'brave', 'google'). Falls back to the tool's default_provider. Must appear in the per-tenant allowlist."
            },
            "max_results": {
                "type": "integer",
                "description": "Cap on result count. Default 10; values above 50 are clamped.",
                "minimum": 1
            }
        },
        "additionalProperties": false
    })
}

/// All tools exposed by mvmctl mcp.
///
/// - `run` — legacy single-tool "boot a microVM and execute code".
/// - `mvm.time_now`, `mvm.web_fetch`, `mvm.web_search` — plan 60
///   Phase 7 host-mediated tools (implementations live in
///   `mvm-supervisor::tools`).
pub fn all_tools() -> Vec<ToolSchema> {
    vec![
        ToolSchema {
            name: "run".to_string(),
            description:
                "Run code inside a fresh mvm microVM. Single tool; the `env` parameter selects which pre-built environment to boot — either a built-in preset (`shell`, `bash`, `python`, `node`) or a path to a project directory whose `mvm.toml` has been built via `mvmctl build`. Output is captured (stdout, stderr, exit_code). Each call boots and tears down a transient VM (session reuse is reserved). Use `mvmctl manifest ls` on the host to discover available manifest-keyed environments."
                    .to_string(),
            input_schema: run_input_schema(),
        },
        ToolSchema {
            name: "mvm.time_now".to_string(),
            description:
                "Return the host wall-clock time as either RFC 3339 (default) or Unix seconds. No upstream call, no network — useful as a diagnostic that the agent → supervisor pipe is alive."
                    .to_string(),
            input_schema: time_now_input_schema(),
        },
        ToolSchema {
            name: "mvm.web_fetch".to_string(),
            description:
                "Fetch a single https:// URL. The destination host must appear in the per-tenant allowlist (operators grant per-host access). The response body comes back as URL-safe-no-pad base64 so binary content (images, gzip, etc.) round-trips losslessly; `bytes` carries the pre-encoding length."
                    .to_string(),
            input_schema: web_fetch_input_schema(),
        },
        ToolSchema {
            name: "mvm.web_search".to_string(),
            description:
                "Search the web through a per-tenant allowlisted provider (Brave / Google / DuckDuckGo / …). The agent does not see the provider's API key; the supervisor owns it. Returns up to `max_results` hits, each with title / url / snippet."
                    .to_string(),
            input_schema: web_search_input_schema(),
        },
        ToolSchema {
            name: "mvm.upload".to_string(),
            description:
                "Write a base64-encoded payload to a relative path under the per-tenant staging area on the host. Path validation rejects absolute paths, '..' components, control characters, and length > 512 bytes. The staging area is a host-side directory (~/.mvm/tool-staging/<tenant>/ by default; override via MVM_TOOL_STAGING_DIR) that the workload can read through a controlled channel."
                    .to_string(),
            input_schema: upload_input_schema(),
        },
        ToolSchema {
            name: "mvm.download".to_string(),
            description:
                "Read a relative path from the per-tenant staging area and return the bytes as URL-safe-no-pad base64. Same path validation + size caps as mvm.upload. Use the `bytes` field to learn the file size without decoding."
                    .to_string(),
            input_schema: download_input_schema(),
        },
    ]
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
    fn all_tools_returns_run_plus_phase_7_tools() {
        let tools = all_tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"run"));
        assert!(names.contains(&"mvm.time_now"));
        assert!(names.contains(&"mvm.web_fetch"));
        assert!(names.contains(&"mvm.web_search"));
        assert!(names.contains(&"mvm.upload"));
        assert!(names.contains(&"mvm.download"));
        assert_eq!(tools.len(), 6);
    }

    #[test]
    fn tools_list_token_budget_under_2000() {
        // Byte-count heuristic where 1 token ≈ 4 bytes (well-known
        // approximation for Claude/GPT-4 family). Plan 60 Phase 7
        // grows the tool count from 1 to 4; budget scales with it.
        // 2000 tokens (~8000 bytes) leaves headroom for the planned
        // `upload`/`download`/`code_eval` additions; tighten once
        // those land.
        let serialized = serde_json::to_string(&all_tools()).unwrap();
        let approx_tokens = serialized.len() / 4;
        assert!(
            approx_tokens < 2000,
            "tools/list too large: ~{} tokens ({} bytes); target < 2000",
            approx_tokens,
            serialized.len()
        );
    }
}
