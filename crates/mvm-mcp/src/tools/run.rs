//! Stdio-side handler for the `run` tool.
//!
//! Validates params, dispatches into a transient microVM via
//! `mvm-cli::exec::run_captured`, formats stdout/stderr/exit_code into
//! an MCP `tools/call` response, and audit-logs the invocation.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::dispatcher::Dispatcher;
use crate::protocol::{ContentBlock, ToolResult};
use crate::tools::RunParams;

/// stdout/stderr cap per call (cross-cutting consideration "A:
/// resource limits"). Truncated tail is replaced by an explicit
/// `[truncated, N more bytes]` marker so the LLM sees the failure
/// mode instead of a silently chopped payload.
const STREAM_CAP_BYTES: usize = 64 * 1024;

/// Default per-call timeout in seconds. Bounded `[1, 600]`; values
/// outside that range are clamped (not errored) so an LLM that picks
/// `timeout_secs: 0` still makes progress.
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const MIN_TIMEOUT_SECS: u64 = 1;
const MAX_TIMEOUT_SECS: u64 = 600;

/// Default concurrency cap. Configurable via `MVM_MCP_MAX_INFLIGHT`.
const DEFAULT_MAX_INFLIGHT: usize = 4;

/// Default memory ceiling in MiB. Configurable via
/// `MVM_MCP_MEM_CEILING_MIB`.
const DEFAULT_MEM_CEILING_MIB: u32 = 4096;

/// Default vCPUs handed to the transient microVM. Templates' vCPU
/// counts are not honored in v1 — every `tools/call run` uses the
/// same fixed shape so concurrency math stays predictable.
const DEFAULT_VM_CPUS: u32 = 2;
const DEFAULT_VM_MEM_MIB: u32 = 1024;

/// Concrete dispatcher backed by `mvm-cli::exec`.
pub struct ExecDispatcher {
    inflight: AtomicUsize,
    max_inflight: usize,
    mem_ceiling_mib: u32,
}

impl Default for ExecDispatcher {
    fn default() -> Self {
        Self {
            inflight: AtomicUsize::new(0),
            max_inflight: parse_env_usize("MVM_MCP_MAX_INFLIGHT", DEFAULT_MAX_INFLIGHT),
            mem_ceiling_mib: parse_env_u32("MVM_MCP_MEM_CEILING_MIB", DEFAULT_MEM_CEILING_MIB),
        }
    }
}

impl Dispatcher for ExecDispatcher {
    fn run(&self, params: RunParams) -> ToolResult {
        // Concurrency gate (cross-cutting "A: resource limits").
        let prev = self.inflight.fetch_add(1, Ordering::SeqCst);
        // Decrement no matter what path we take below.
        let _guard = InflightGuard(&self.inflight);
        if prev >= self.max_inflight {
            return error_result(format!(
                "MCP server busy: {} calls in flight (cap MVM_MCP_MAX_INFLIGHT={}). Retry shortly.",
                prev + 1,
                self.max_inflight
            ));
        }

        // Validate env against the local template registry.
        if let Err(e) = crate::env::validate_env(&params.env) {
            return error_result(format!("{e}"));
        }

        // Memory ceiling check: rejecting templates whose recorded
        // mem_mib exceeds MVM_MCP_MEM_CEILING_MIB. Look the spec up;
        // missing spec is a soft pass since we don't know the size.
        if let Ok(spec) = mvm_runtime::vm::template::lifecycle::template_load(&params.env)
            && spec.mem_mib > self.mem_ceiling_mib {
            return error_result(format!(
                "env '{}' requests {} MiB which exceeds MVM_MCP_MEM_CEILING_MIB={}",
                params.env, spec.mem_mib, self.mem_ceiling_mib
            ));
        }

        // Build the inline argv for the env. We don't have full
        // metadata about each template's "interpreter type" yet, so
        // v1 dispatches all envs through `bash -c`. Templates whose
        // service is `python`/`node`/etc. expose those interpreters
        // on PATH inside the VM, so `bash -c "python3 -c '<code>'"`
        // works for the curated envs documented in plan 32.
        let argv = bash_dash_c(&shell_escape(&params.code));
        let timeout = clamp_timeout(params.timeout_secs);

        let req = mvm_cli::exec::ExecRequest {
            image: mvm_cli::exec::ImageSource::Template(params.env.clone()),
            cpus: DEFAULT_VM_CPUS,
            memory_mib: DEFAULT_VM_MEM_MIB,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: mvm_cli::exec::ExecTarget::Inline { argv },
            timeout_secs: timeout,
        };

        let started = std::time::Instant::now();
        let result = mvm_cli::exec::run_captured(req);
        let elapsed = started.elapsed();

        match result {
            Ok(out) => {
                let stdout = truncate_with_marker(&out.stdout);
                let stderr = truncate_with_marker(&out.stderr);
                audit_call_complete(
                    &params.env,
                    params.code.len(),
                    out.exit_code,
                    elapsed.as_millis() as u64,
                    params.session.as_deref(),
                );
                ToolResult {
                    content: vec![
                        ContentBlock::Text { text: stdout },
                        ContentBlock::Text { text: format!("[stderr]\n{}", stderr) },
                        ContentBlock::Text { text: format!("exit_code={}", out.exit_code) },
                    ],
                    is_error: out.exit_code != 0,
                }
            }
            Err(e) => {
                audit_call_error(
                    &params.env,
                    params.code.len(),
                    elapsed.as_millis() as u64,
                    params.session.as_deref(),
                    &format!("{e:#}"),
                );
                error_result(format!("microVM exec failed: {e:#}"))
            }
        }
    }
}

struct InflightGuard<'a>(&'a AtomicUsize);
impl<'a> Drop for InflightGuard<'a> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn error_result(msg: impl Into<String>) -> ToolResult {
    ToolResult {
        content: vec![ContentBlock::Text { text: msg.into() }],
        is_error: true,
    }
}

fn clamp_timeout(t: Option<u64>) -> u64 {
    t.unwrap_or(DEFAULT_TIMEOUT_SECS)
        .clamp(MIN_TIMEOUT_SECS, MAX_TIMEOUT_SECS)
}

fn bash_dash_c(quoted_code: &str) -> Vec<String> {
    vec![
        "bash".to_string(),
        "-c".to_string(),
        quoted_code.to_string(),
    ]
}

/// Single-quote a string for safe inclusion in a `bash -c` invocation.
/// Single quotes can't appear inside single-quoted strings in bash, so
/// we close + concatenate the standard `'\''` workaround.
fn shell_escape(s: &str) -> String {
    let escaped: String = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// Cap `s` at [`STREAM_CAP_BYTES`] and append a marker reporting how
/// many bytes were dropped, so the LLM sees the truncation rather
/// than a silently truncated payload.
fn truncate_with_marker(s: &str) -> String {
    if s.len() <= STREAM_CAP_BYTES {
        return s.to_string();
    }
    // Truncate at a UTF-8 boundary at-or-before STREAM_CAP_BYTES.
    let mut end = STREAM_CAP_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = s.len() - end;
    format!("{}\n[truncated, {} more bytes]", &s[..end], dropped)
}

fn parse_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}
fn parse_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn audit_call_complete(
    env: &str,
    code_len: usize,
    exit_code: i32,
    elapsed_ms: u64,
    session: Option<&str>,
) {
    // `LocalAuditKind::McpToolsCallRun` is the v1 mvm-core kind. It
    // captures vm_name (the env name) and a JSON-encoded detail blob
    // with code_len/exit_code/elapsed_ms/session — the existing local
    // audit API doesn't take a structured payload, so we serialise
    // into the detail field. The audit call itself is best-effort;
    // failures land in `tracing::warn!` only.
    let detail = serde_json::json!({
        "code_len": code_len,
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "session": session,
    })
    .to_string();
    mvm_core::policy::audit::emit(
        mvm_core::policy::audit::LocalAuditKind::McpToolsCallRun,
        Some(env),
        Some(&detail),
    );
}

fn audit_call_error(
    env: &str,
    code_len: usize,
    elapsed_ms: u64,
    session: Option<&str>,
    error: &str,
) {
    let detail = serde_json::json!({
        "code_len": code_len,
        "elapsed_ms": elapsed_ms,
        "session": session,
        "error": error,
    })
    .to_string();
    mvm_core::policy::audit::emit(
        mvm_core::policy::audit::LocalAuditKind::McpToolsCallRunError,
        Some(env),
        Some(&detail),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_under_cap_passes_through() {
        let s = "hello world";
        assert_eq!(truncate_with_marker(s), s);
    }

    #[test]
    fn truncate_over_cap_appends_marker() {
        let s = "x".repeat(STREAM_CAP_BYTES + 100);
        let out = truncate_with_marker(&s);
        assert!(out.contains("[truncated, 100 more bytes]"));
        assert!(out.len() < STREAM_CAP_BYTES + 50, "marker is short");
    }

    #[test]
    fn truncate_respects_utf8_boundary() {
        // Build a string where byte STREAM_CAP_BYTES falls in the
        // middle of a multi-byte char.
        let prefix = "x".repeat(STREAM_CAP_BYTES - 1);
        let s = format!("{prefix}éééé");
        let out = truncate_with_marker(&s);
        // Truncated form must still parse as valid UTF-8 (Rust string
        // literal guarantees this) and contain the marker.
        assert!(out.contains("[truncated"));
    }

    #[test]
    fn timeout_clamps_to_bounds() {
        assert_eq!(clamp_timeout(None), DEFAULT_TIMEOUT_SECS);
        assert_eq!(clamp_timeout(Some(0)), MIN_TIMEOUT_SECS);
        assert_eq!(clamp_timeout(Some(99_999)), MAX_TIMEOUT_SECS);
        assert_eq!(clamp_timeout(Some(30)), 30);
    }

    #[test]
    fn shell_escape_handles_single_quotes() {
        let escaped = shell_escape("it's");
        assert_eq!(escaped, "'it'\\''s'");
    }

    #[test]
    fn shell_escape_no_quotes() {
        assert_eq!(shell_escape("plain"), "'plain'");
    }
}
