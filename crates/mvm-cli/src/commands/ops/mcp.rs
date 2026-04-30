//! `mvmctl mcp` — Model Context Protocol server entry point.
//!
//! Today: stdio-only transport. Reads JSON-RPC requests from stdin,
//! writes responses to stdout, dispatches `tools/call run` into
//! transient microVMs via [`crate::exec::run_captured`]. ADR-003 has
//! the threat model and design.
//!
//! Note: `mvmctl mcp` is *always* present in CLI builds (no Cargo
//! feature gate at the host level), matching `mvmctl exec`'s pattern.
//! The guest-side `Exec` handler is the actual gate per ADR-002 §W4.3
//! — production guest agents are built without `dev-shell`, so the
//! `tools/call run` dispatch returns "exec not available" instead of
//! executing. This composition is intentional: the MCP server is
//! useful when pointed at dev VMs, harmless when pointed at prod ones.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;
use mvm_mcp::{
    ContentBlock, Dispatcher, ReapReason, Reaper, RunParams, SessionConfig, SessionLookup,
    SessionMap, SessionState, ToolResult,
};

use super::Cli;

/// Per-session warm-VM handles, keyed by session ID. Locked
/// independently of [`SessionMap`] so a long-running dispatch
/// against one session doesn't block bookkeeping reads of others.
type WarmVms = Arc<Mutex<BTreeMap<String, Arc<Mutex<crate::exec::SessionVm>>>>>;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub transport: McpTransport,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum McpTransport {
    /// Speak MCP over stdio (the standard MCP transport for local
    /// developer tools). Reads JSON-RPC frames from stdin, writes
    /// responses to stdout. All non-protocol output goes to stderr —
    /// putting anything else on stdout corrupts the wire.
    Stdio,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.transport {
        McpTransport::Stdio => {
            mvm_mcp::init_stderr_tracing();
            let dispatcher = ExecDispatcher::default();
            // Spawn the session reaper. Drops out when the process exits;
            // sessions still in the map at shutdown get drained by the
            // dispatcher's Drop impl (RAII via Arc<Mutex<SessionMap>>
            // + the Drop on ExecDispatcher).
            dispatcher.spawn_reaper();
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            mvm_mcp::run_with_dispatcher(stdin.lock(), &mut stdout.lock(), &dispatcher)
        }
    }
}

// ---------------------------------------------------------------------------
// ExecDispatcher — bridges MCP protocol to crate::exec::run_captured
// ---------------------------------------------------------------------------

/// stdout/stderr cap per call (cross-cutting "A: resource limits").
/// Truncated tail is replaced by an explicit `[truncated, N more
/// bytes]` marker so the LLM sees the failure mode instead of a
/// silently chopped payload.
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

/// How often the reaper sweeps the session map. Smaller intervals
/// reap closer to the configured idle/max boundary at the cost of
/// extra wake-ups; the default is generous because session timeouts
/// are measured in minutes-to-hours.
const REAPER_TICK_SECS: u64 = 30;

/// Concrete dispatcher backed by [`crate::exec::run_captured`] (cold)
/// or [`crate::exec::dispatch_in_session`] (warm, when `session=ID`).
///
/// Plan 32 / Proposal A.2:
/// - **Bookkeeping (v1)**: the `SessionMap` records each session's
///   metadata, and a 30 s-tick reaper sweeps idle/expired entries.
/// - **Warm VM materialisation (v2)**: the per-session handle map
///   `warm_vms` keeps the booted [`crate::exec::SessionVm`] alive
///   across calls. First call in a session boots; subsequent calls
///   reuse. `close: true` and the reaper both tear down via
///   [`crate::exec::tear_down_session_vm`].
struct ExecDispatcher {
    inflight: AtomicUsize,
    max_inflight: usize,
    mem_ceiling_mib: u32,
    sessions: Arc<Mutex<SessionMap>>,
    warm_vms: WarmVms,
    reaper: Arc<DispatcherReaper>,
}

impl Default for ExecDispatcher {
    fn default() -> Self {
        let warm_vms: WarmVms = Arc::new(Mutex::new(BTreeMap::new()));
        Self {
            inflight: AtomicUsize::new(0),
            max_inflight: parse_env_usize("MVM_MCP_MAX_INFLIGHT", DEFAULT_MAX_INFLIGHT),
            mem_ceiling_mib: parse_env_u32("MVM_MCP_MEM_CEILING_MIB", DEFAULT_MEM_CEILING_MIB),
            sessions: Arc::new(Mutex::new(SessionMap::new(SessionConfig::from_env()))),
            reaper: Arc::new(DispatcherReaper {
                warm_vms: Arc::clone(&warm_vms),
            }),
            warm_vms,
        }
    }
}

impl ExecDispatcher {
    /// Cold-boot path: every call boots its own transient VM via
    /// [`crate::exec::run_captured`]. Used when the client did not
    /// supply a `session` parameter.
    fn run_cold(
        &self,
        env: &str,
        code: &str,
        timeout: u64,
    ) -> Result<crate::exec::ExecOutput, anyhow::Error> {
        let argv = bash_dash_c(&shell_escape(code));
        let req = crate::exec::ExecRequest {
            image: crate::exec::ImageSource::Template(env.to_string()),
            cpus: DEFAULT_VM_CPUS,
            memory_mib: DEFAULT_VM_MEM_MIB,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: crate::exec::ExecTarget::Inline { argv },
            timeout_secs: timeout,
        };
        crate::exec::run_captured(req)
    }

    /// Warm-VM path (A.2 v2): boot the session's VM on first call,
    /// reuse it on subsequent calls. The per-session lock serialises
    /// concurrent dispatches against the same session — stdout/stderr
    /// from the guest agent over a single vsock socket aren't
    /// interleave-safe.
    fn run_warm(
        &self,
        session_id: &str,
        env: &str,
        code: &str,
        timeout: u64,
    ) -> Result<crate::exec::ExecOutput, anyhow::Error> {
        let handle = self.get_or_boot_warm_vm(session_id, env)?;
        let vm = handle
            .lock()
            .map_err(|_| anyhow::anyhow!("warm-VM lock poisoned for session '{session_id}'"))?;
        crate::exec::dispatch_in_session(&vm, code.to_string(), timeout)
    }

    /// Look up an existing warm VM for the session, or boot a new one
    /// if none exists. Returns the per-session handle (an
    /// `Arc<Mutex<SessionVm>>` so concurrent dispatches serialise on
    /// the same VM).
    fn get_or_boot_warm_vm(
        &self,
        session_id: &str,
        env: &str,
    ) -> Result<Arc<Mutex<crate::exec::SessionVm>>, anyhow::Error> {
        // Fast path: handle already in the map.
        if let Ok(warm) = self.warm_vms.lock()
            && let Some(handle) = warm.get(session_id)
        {
            return Ok(Arc::clone(handle));
        }

        // Slow path: boot a new VM. Releasing the warm_vms lock
        // before booting avoids holding it across a multi-second
        // operation; the worst case is two concurrent first-calls
        // race to boot, the second discovers the first's handle and
        // tears down its own boot. That's correct (no leak) at the
        // cost of an extra VM start in pathological cases.
        let prefix = format!("mcp-session-{}", short_id(session_id));
        let booted =
            crate::exec::boot_session_vm(env, &prefix, DEFAULT_VM_CPUS, DEFAULT_VM_MEM_MIB)
                .with_context(|| format!("booting warm VM for session '{session_id}'"))?;
        let booted_name = booted.vm_name.clone();
        let handle = Arc::new(Mutex::new(booted));

        let race_winner: Option<Arc<Mutex<crate::exec::SessionVm>>> = {
            let mut warm = self
                .warm_vms
                .lock()
                .map_err(|_| anyhow::anyhow!("warm-VM map lock poisoned"))?;
            if let Some(existing) = warm.get(session_id) {
                Some(Arc::clone(existing))
            } else {
                warm.insert(session_id.to_string(), Arc::clone(&handle));
                None
            }
        };

        if let Some(existing) = race_winner {
            // Another thread booted in parallel. Tear down our VM and
            // return theirs.
            if let Ok(extra_mutex) = Arc::try_unwrap(handle)
                && let Ok(extra) = extra_mutex.into_inner()
            {
                tracing::debug!(vm = %extra.vm_name, "tearing down racing session VM");
                crate::exec::tear_down_session_vm(extra);
            }
            return Ok(existing);
        }

        // We won the boot race. Update the SessionMap's recorded
        // vm_name so the reaper and audit logs see it.
        if let Ok(mut map) = self.sessions.lock() {
            map.set_vm_name(session_id, booted_name);
        }
        Ok(handle)
    }

    /// Start a background thread that sweeps the session map every
    /// [`REAPER_TICK_SECS`]. Idempotent — safe to call once at
    /// startup. The thread is detached: it dies with the process.
    fn spawn_reaper(&self) {
        let sessions = Arc::clone(&self.sessions);
        let reaper = Arc::clone(&self.reaper);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(REAPER_TICK_SECS));
                let n = match sessions.lock() {
                    Ok(mut map) => map.reap_expired(reaper.as_ref()),
                    Err(_) => return, // poisoned mutex = process is unwinding
                };
                if n > 0 {
                    tracing::debug!(reaped = n, "MCP session reaper swept");
                }
            }
        });
    }
}

/// On Drop, drain the session map and audit-log every remaining
/// session as `Shutdown`. Kicks in when the stdio loop exits cleanly.
impl Drop for ExecDispatcher {
    fn drop(&mut self) {
        if let Ok(mut map) = self.sessions.lock() {
            let n = map.drain(self.reaper.as_ref());
            if n > 0 {
                tracing::info!(drained = n, "MCP server shutdown drained sessions");
            }
        }
    }
}

/// Reaper impl that audit-logs the close *and* tears down the warm
/// VM (A.2 v2). The trait-based design (per `mvm_mcp::session`) means
/// mvmd's hosted variant can plug in its own reaper that uses its
/// per-tenant orchestrator without changing the map contract.
struct DispatcherReaper {
    warm_vms: WarmVms,
}

impl Reaper for DispatcherReaper {
    fn on_reap(&self, session_id: &str, state: &SessionState, reason: ReapReason) {
        let detail = serde_json::json!({
            "session": session_id,
            "env": state.env,
            "reason": reason_str(reason),
            "vm_name": state.vm_name,
            "lifetime_secs": state.started_at.elapsed().as_secs(),
        })
        .to_string();
        mvm_core::policy::audit::emit(
            mvm_core::policy::audit::LocalAuditKind::McpSessionClosed,
            state.vm_name.as_deref(),
            Some(&detail),
        );

        // A.2 v2: actually tear down the warm VM. The handle lives in
        // `warm_vms`, which we own a strong ref to. Removing it drops
        // the Arc; if another Arc is still held by an in-flight
        // dispatch the VM survives until that completes — but the
        // dispatcher won't route new calls to it because the
        // SessionMap entry is already gone.
        if let Ok(mut warm) = self.warm_vms.lock()
            && let Some(handle) = warm.remove(session_id)
            && let Ok(vm_mutex) = Arc::try_unwrap(handle)
            && let Ok(vm) = vm_mutex.into_inner()
        {
            crate::exec::tear_down_session_vm(vm);
        }
        // If the handle had an outstanding dispatch (other Arc still
        // alive), the strong ref won't be sole. We rely on the
        // dispatch-side code path to clean up when it finishes — see
        // the `tear_down_orphaned_after_call` fallback in `run`.
    }
}

fn reason_str(r: ReapReason) -> &'static str {
    match r {
        ReapReason::Idle => "idle",
        ReapReason::MaxLifetime => "max_lifetime",
        ReapReason::Closed => "closed",
        ReapReason::Shutdown => "shutdown",
    }
}

/// Truncate a session id to the first 8 chars for use in VM names.
/// Keeps `mvmctl ls` readable when the LLM client sends a long UUID.
fn short_id(session_id: &str) -> String {
    session_id.chars().take(8).collect()
}

impl Dispatcher for ExecDispatcher {
    fn run(&self, params: RunParams) -> ToolResult {
        // Concurrency gate (cross-cutting "A: resource limits").
        let prev = self.inflight.fetch_add(1, Ordering::SeqCst);
        let _guard = InflightGuard(&self.inflight);
        if prev >= self.max_inflight {
            return error_result(format!(
                "MCP server busy: {} calls in flight (cap MVM_MCP_MAX_INFLIGHT={}). Retry shortly.",
                prev + 1,
                self.max_inflight
            ));
        }

        // Validate env against the local template registry.
        if let Err(e) = validate_env(&params.env) {
            return error_result(format!("{e}"));
        }

        // Session bookkeeping (A.2 v1). Touch the map before the
        // dispatch so audit logs see "session started" before
        // "tools/call ran".
        if let Some(session_id) = params.session.as_deref() {
            let lookup = self
                .sessions
                .lock()
                .map(|mut map| map.touch_or_insert(session_id, &params.env, None))
                .unwrap_or(SessionLookup::Created);
            if matches!(lookup, SessionLookup::Created) {
                let detail = serde_json::json!({
                    "session": session_id,
                    "env": params.env,
                })
                .to_string();
                mvm_core::policy::audit::emit(
                    mvm_core::policy::audit::LocalAuditKind::McpSessionStarted,
                    Some(&params.env),
                    Some(&detail),
                );
            }
        }

        // Memory ceiling check: reject envs whose recorded mem_mib
        // exceeds MVM_MCP_MEM_CEILING_MIB. Missing spec is a soft
        // pass since we don't know the size.
        if let Ok(spec) = mvm_runtime::vm::template::lifecycle::template_load(&params.env)
            && spec.mem_mib > self.mem_ceiling_mib
        {
            return error_result(format!(
                "env '{}' requests {} MiB which exceeds MVM_MCP_MEM_CEILING_MIB={}",
                params.env, spec.mem_mib, self.mem_ceiling_mib
            ));
        }

        let timeout = clamp_timeout(params.timeout_secs);

        let started = std::time::Instant::now();
        let result = match params.session.as_deref() {
            Some(session_id) => self.run_warm(session_id, &params.env, &params.code, timeout),
            None => self.run_cold(&params.env, &params.code, timeout),
        };
        let elapsed = started.elapsed();

        // After the dispatch completes (regardless of success), honour
        // an explicit close request so the reaper has nothing left to
        // do for this session — also tears down the warm VM via the
        // reaper impl.
        if let (Some(session_id), Some(true)) = (params.session.as_deref(), params.close)
            && let Ok(mut map) = self.sessions.lock()
        {
            map.remove(session_id, ReapReason::Closed, self.reaper.as_ref());
        }

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
                        ContentBlock::Text {
                            text: format!("[stderr]\n{stderr}"),
                        },
                        ContentBlock::Text {
                            text: format!("exit_code={}", out.exit_code),
                        },
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
impl Drop for InflightGuard<'_> {
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
/// Single quotes can't appear inside single-quoted strings, so we
/// close + concatenate the standard `'\''` workaround.
fn shell_escape(s: &str) -> String {
    let escaped: String = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// Cap `s` at [`STREAM_CAP_BYTES`] and append a marker reporting how
/// many bytes were dropped. UTF-8 boundary aware.
fn truncate_with_marker(s: &str) -> String {
    if s.len() <= STREAM_CAP_BYTES {
        return s.to_string();
    }
    let mut end = STREAM_CAP_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let dropped = s.len() - end;
    format!("{}\n[truncated, {} more bytes]", &s[..end], dropped)
}

fn parse_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
fn parse_env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn validate_env(env: &str) -> anyhow::Result<()> {
    let envs = mvm_runtime::vm::template::lifecycle::template_list()?;
    if envs.iter().any(|e| e == env) {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "env '{env}' is not a registered mvmctl template. Available envs: [{}]. \
         Build new ones via `mvmctl template create … && mvmctl template build <name>`.",
        envs.join(", ")
    ))
}

fn audit_call_complete(
    env: &str,
    code_len: usize,
    exit_code: i32,
    elapsed_ms: u64,
    session: Option<&str>,
) {
    // `LocalAuditKind::McpToolsCallRun` is the v1 mvm-core kind. The
    // existing local audit API takes a free-form `detail` string, so
    // we serialise the structured payload into JSON. Audit is
    // best-effort; failures land in `tracing::warn!` only.
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
