//! `mvmctl mcp` — Model Context Protocol server entry point.
//!
//! Today: stdio-only transport. Reads JSON-RPC requests from stdin,
//! writes responses to stdout, dispatches `tools/call run` into
//! transient microVMs via [`crate::exec::run_captured`].
//!
//! Note: `mvmctl mcp` is *always* present in CLI builds (no Cargo
//! feature gate at the host level), matching `mvmctl exec`'s pattern.
//! The guest-side `Exec` handler is the actual gate — production guest
//! agents are built without `dev-shell`, so the
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
use mvm_hostd::supervisor::ToolRegistry;
use mvm_hostd::supervisor::tools::{download, staging, upload, web_fetch, web_search};
use mvm_mcp::{
    ContentBlock, Dispatcher, ReapReason, Reaper, RunParams, SessionConfig, SessionLookup,
    SessionMap, SessionState, ToolResult,
};
use secrecy::SecretBox;

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
    /// Host-mediated tools (`mvm.time_now`,
    /// `mvm.web_fetch`, `mvm.web_search`). Built once at dispatcher
    /// construction; shared across every `tools/call` invocation.
    /// Default registry ships fail-closed for the web tools —
    /// operators wire per-tenant allowlists by replacing this with
    /// a configured registry in a follow-up slice.
    tool_registry: Arc<ToolRegistry>,
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
            tool_registry: Arc::new(build_tool_registry()),
        }
    }
}

/// Operator-rotatable provider credentials. When set,
/// the value names a secret stored via `mvmctl secret put` (default
/// tenant `local`). The supervisor fetches the value through
/// `mvm_core::crypto::secret_store::default_secret_store()` — OS
/// keyring on Mac/Linux with gnome-keyring, file fallback elsewhere
/// (mode 0600 under `~/.mvm/secrets/local/`).
///
/// Pattern: each provider gets *one* "from secret" env var paired
/// with the existing "direct value" env var. The direct value wins
/// when both are set (backward compatibility); operators rotating
/// from env-var to secret-store posture rm-and-rebuild their shell
/// init.
const BRAVE_API_KEY_FROM_SECRET_ENV_VAR: &str = "BRAVE_API_KEY_FROM_SECRET";
const TAVILY_API_KEY_FROM_SECRET_ENV_VAR: &str = "TAVILY_API_KEY_FROM_SECRET";
const GOOGLE_API_KEY_FROM_SECRET_ENV_VAR: &str = "GOOGLE_API_KEY_FROM_SECRET";
const GOOGLE_CSE_ID_FROM_SECRET_ENV_VAR: &str = "GOOGLE_CSE_ID_FROM_SECRET";

/// Tenant id under which provider credentials are stored. Matches
/// the default tenant `mvmctl secret put` uses, so an operator can
/// run `mvmctl secret put brave-api-key --value-file <(cat key)`
/// and reference it via `BRAVE_API_KEY_FROM_SECRET=brave-api-key`.
const PROVIDER_CREDENTIAL_TENANT: &str = "local";

/// Resolve a provider credential from either the
/// direct-value env var (v0 posture, visible to the calling user
/// via `/proc/<pid>/environ`) or a named secret in the secret store
/// (hardened posture, file mode 0600 or OS keyring).
///
/// Resolution order:
/// 1. `direct_env_var` — if set and non-empty, use it verbatim.
/// 2. `secret_ref_env_var` — if set, look up that name in the
///    secret store under the `local` tenant. If the lookup fails
///    (missing entry, permission error, store wedged), log a
///    `tracing::warn` and return `None` — the existing
///    "allowed-but-unregistered" config-drift error fires at
///    invoke time, which is the operator's downstream signal.
/// 3. Otherwise — `None` (caller treats as unconfigured).
///
/// The return type is `SecretBox<String>` (not a raw
/// `String`) so the bytes zeroize on drop — even if the provider
/// constructor that consumes it panics mid-build, the
/// SecretBox-wrapped value still gets cleaned up. Each provider's
/// `new()` accepts `SecretBox<String>` directly; this resolver
/// hands ownership through end-to-end.
fn resolve_provider_credential(
    direct_env_var: &str,
    secret_ref_env_var: &str,
    store: &dyn mvm_core::crypto::secret_store::SecretStore,
) -> Option<SecretBox<String>> {
    if let Ok(direct) = std::env::var(direct_env_var)
        && !direct.is_empty()
    {
        return Some(SecretBox::new(Box::new(direct)));
    }
    let secret_name = std::env::var(secret_ref_env_var).ok()?;
    if secret_name.is_empty() {
        return None;
    }
    match store.get(PROVIDER_CREDENTIAL_TENANT, &secret_name) {
        Ok(secret) => Some(secret),
        Err(e) => {
            tracing::warn!(
                env_var = secret_ref_env_var,
                secret_name = %secret_name,
                tenant = PROVIDER_CREDENTIAL_TENANT,
                error = %e,
                "could not resolve provider credential from secret_store"
            );
            None
        }
    }
}

/// Build the tool registry the MCP dispatcher hands out.
///
/// Today:
/// - `mvm.time_now` — always reachable.
/// - `mvm.web_fetch` — uses [`web_fetch::ReqwestHttpFetcher`] when
///   constructable; allowlist comes from
///   `$MVM_WEB_FETCH_ALLOWLIST` (comma-separated). When the env var
///   is unset, the allowlist is empty and every fetch fails closed.
/// - `mvm.web_search` — allowlist comes from
///   `$MVM_WEB_SEARCH_ALLOWLIST`; default provider comes from
///   `$MVM_WEB_SEARCH_DEFAULT` (or the first allowlist entry).
///   When `"brave"` is on the allowlist AND `$BRAVE_SEARCH_API_KEY`
///   is set, a [`web_search::BraveSearchProvider`] is registered.
///   Without the key, the existing "allowed but unregistered =
///   config drift" error fires on first invoke so the
///   misconfiguration is loud, not silent.
///
/// On `ReqwestHttpFetcher::new()` / `BraveSearchProvider::new()`
/// failure (extraordinarily rare), we log a `tracing::warn` and
/// fall back to the substrate's Noop default so the registry still
/// ships.
fn build_tool_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::with_defaults();

    // Every successful tool invocation
    // emits a `cmd.tool.<name>.{completed,failed}` chain-signed
    // entry through the host signer's FileAuditSigner. When the
    // signer isn't reachable (no $HOME, key not initialized, loose
    // perms) we log a warning in `build_cmd_recorder` and skip the
    // attachment — tool calls still succeed; the audit footprint
    // just doesn't land. Same posture as `cmd.*` envelopes.
    if let Some(rec) = crate::commands::cmd_audit::build_cmd_recorder() {
        registry = registry.with_recorder(rec);
    }

    // mvm.web_fetch
    let allow = web_fetch::allowlist_from_env_var(web_fetch::ALLOWLIST_ENV_VAR);
    let mut fetch_tool = web_fetch::WebFetchTool::with_allowlist(allow);
    match web_fetch::ReqwestHttpFetcher::new() {
        Ok(f) => {
            fetch_tool = fetch_tool.with_fetcher(Arc::new(f));
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "ReqwestHttpFetcher init failed; mvm.web_fetch will use Noop fallback"
            );
        }
    }
    registry.register(Box::new(fetch_tool));

    // mvm.web_search
    let search_allow = web_search::allowlist_from_env_var(web_search::ALLOWLIST_ENV_VAR);
    let default_provider = std::env::var(web_search::DEFAULT_PROVIDER_ENV_VAR)
        .ok()
        .or_else(|| search_allow.iter().next().cloned())
        .unwrap_or_else(|| "noop".to_string());
    let mut search_tool =
        web_search::WebSearchTool::with_allowlist(search_allow.iter().cloned(), default_provider);
    // Credentials resolve through env var OR named
    // secret-store entry. The secret_store backs `mvmctl secret`
    // (OS keyring on Mac/Linux with gnome-keyring, file fallback
    // elsewhere). Operators rotate by re-running `mvmctl secret
    // put`; the supervisor picks up the new value on next
    // `mvmctl mcp stdio` boot.
    let secret_store = mvm_core::crypto::secret_store::default_secret_store();
    if search_allow.contains("brave")
        && let Some(key) = resolve_provider_credential(
            web_search::BRAVE_API_KEY_ENV_VAR,
            BRAVE_API_KEY_FROM_SECRET_ENV_VAR,
            secret_store.as_ref(),
        )
    {
        match web_search::BraveSearchProvider::new(key) {
            Ok(p) => {
                search_tool = search_tool.register_provider(Arc::new(p));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "BraveSearchProvider init failed; mvm.web_search 'brave' provider will be \
                     allowlisted-but-unregistered"
                );
            }
        }
    }
    if search_allow.contains("tavily")
        && let Some(key) = resolve_provider_credential(
            web_search::TAVILY_API_KEY_ENV_VAR,
            TAVILY_API_KEY_FROM_SECRET_ENV_VAR,
            secret_store.as_ref(),
        )
    {
        match web_search::TavilySearchProvider::new(key) {
            Ok(p) => {
                search_tool = search_tool.register_provider(Arc::new(p));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "TavilySearchProvider init failed; mvm.web_search 'tavily' provider will be \
                     allowlisted-but-unregistered"
                );
            }
        }
    }
    if search_allow.contains("google") {
        let api_key = resolve_provider_credential(
            web_search::GOOGLE_API_KEY_ENV_VAR,
            GOOGLE_API_KEY_FROM_SECRET_ENV_VAR,
            secret_store.as_ref(),
        );
        let cse_id = resolve_provider_credential(
            web_search::GOOGLE_CSE_ID_ENV_VAR,
            GOOGLE_CSE_ID_FROM_SECRET_ENV_VAR,
            secret_store.as_ref(),
        );
        match (api_key, cse_id) {
            (Some(api_key), Some(cse_id)) => {
                match web_search::GoogleSearchProvider::new(api_key, cse_id) {
                    Ok(p) => {
                        search_tool = search_tool.register_provider(Arc::new(p));
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "GoogleSearchProvider init failed; mvm.web_search 'google' provider will \
                             be allowlisted-but-unregistered"
                        );
                    }
                }
            }
            _ => {
                // Helpful diagnostic — one or both of API key + CSE
                // ID isn't reachable via env var or secret store.
                // The existing "allowed-but-unregistered" config-
                // drift error fires at invoke time too, but this
                // warning surfaces the issue at supervisor boot.
                tracing::warn!(
                    "mvm.web_search 'google' is allowlisted but the API key and/or CSE ID is not \
                     reachable via env var ({}, {}) or secret_store ({}, {}); provider will be \
                     allowlisted-but-unregistered",
                    web_search::GOOGLE_API_KEY_ENV_VAR,
                    web_search::GOOGLE_CSE_ID_ENV_VAR,
                    GOOGLE_API_KEY_FROM_SECRET_ENV_VAR,
                    GOOGLE_CSE_ID_FROM_SECRET_ENV_VAR,
                );
            }
        }
    }
    registry.register(Box::new(search_tool));

    // mvm.upload + mvm.download — share one per-tenant FsStagingArea.
    // Default tenant matches the rest of the host-local scope ("local");
    // a future slice plumbs the per-call tenant once mvmctl mcp gains
    // the corresponding policy bundle.
    let staging_area = staging::default_for_tenant("local");
    registry.register(Box::new(upload::UploadTool::with_staging(
        staging_area.clone(),
    )));
    registry.register(Box::new(download::DownloadTool::with_staging(staging_area)));

    registry
}

/// The admission hook every MCP code-run boots under — cold and warm alike.
/// MCP runs untrusted AI code, so each VM is admitted as a deny-all transient
/// workload: the signed plan's `tenant_id` makes the libkrun/Vz supervisor
/// spawn the enforcing gateway bridge (Firecracker enforces the same policy
/// field via nftables). Without admission no bridge spawns and the deny-all is
/// inert on the bridge backends.
fn mcp_untrusted_admit()
-> impl Fn(&std::path::Path, &str) -> Result<Option<crate::exec::SessionAuditSubstrate>> {
    let backend = mvm_backend::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    crate::commands::vm::untrusted_transient_admit(
        backend,
        DEFAULT_VM_CPUS,
        u64::from(DEFAULT_VM_MEM_MIB),
    )
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
            name: None,
            image: crate::exec::ImageSource::Template(env.to_string()),
            // MCP sessions don't use the warm pool.
            warm_pool_size: 0,
            cpus: DEFAULT_VM_CPUS,
            memory_mib: DEFAULT_VM_MEM_MIB,
            mem_initial_mib: None,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: crate::exec::ExecTarget::Inline { argv },
            timeout_secs: Some(timeout),
            pty: false,
            // MCP runs untrusted code: deny egress by default.
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        };
        // Admit the run (see `mcp_untrusted_admit`): without it no bridge spawns
        // and the deny-all above is inert on the libkrun/Vz backends.
        let admit = mcp_untrusted_admit();
        crate::exec::run_captured(req, Some(&admit))
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
        crate::exec::dispatch_in_session(&vm, code.to_string(), Some(timeout))
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
        // Admit the session VM like the cold path so the gateway bridge spawns and
        // the deny-all is enforced (see `mcp_untrusted_admit`). A substrate forces
        // a cold boot — snapshot restore goes through `FlakeRunConfig`, which
        // carries `network_policy` but not the `tenant_id`/`plan_json` that trigger
        // the bridge — so the first call of a session pays a cold boot; every later
        // call reuses this running VM.
        let admit = mcp_untrusted_admit();
        let booted = crate::exec::boot_session_vm(
            env,
            &prefix,
            DEFAULT_VM_CPUS,
            DEFAULT_VM_MEM_MIB,
            Some(&admit),
        )
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
        if let Ok(spec) = mvm::vm::template::lifecycle::template_load(&params.env)
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

    /// Route registry tools through
    /// `mvm_hostd::supervisor::ToolRegistry`. The legacy `run` tool stays
    /// on its dedicated method; everything else (`mvm.time_now`,
    /// `mvm.web_fetch`, `mvm.web_search`, …) lands here.
    ///
    /// `ToolRegistry::invoke` is async; the MCP wire layer is sync,
    /// so we spin up a current-thread runtime per call (same pattern
    /// as `vm::audit_chain::AuditEmitter`'s `block_on`). Tool calls
    /// are infrequent relative to per-call cost, and the runtime
    /// build is dominated by everything else in the dispatch path.
    fn invoke_tool(&self, name: &str, params: serde_json::Value) -> ToolResult {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return error_result(format!(
                    "internal: building tokio runtime for tool {name:?}: {e}"
                ));
            }
        };
        match rt.block_on(self.tool_registry.invoke(name, params)) {
            Ok(value) => {
                // Render the JSON value as a single Text content
                // block. The LLM client parses the body; pretty-
                // printing keeps it human-readable when an operator
                // inspects audit logs.
                let text = serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|e| format!("(failed to serialize tool result: {e})"));
                ToolResult {
                    content: vec![ContentBlock::Text { text }],
                    is_error: false,
                }
            }
            Err(e) => error_result(e.to_string()),
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
    let envs = mvm::vm::template::lifecycle::template_list()?;
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
    use mvm_core::util::test_env::TestEnv;

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

    // ──────────────────────────────────────────────────────────────
    // invoke_tool routes through ToolRegistry
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn invoke_tool_routes_time_now_through_registry() {
        // The default ExecDispatcher carries a registry with the 3
        // host-mediated builtins. `mvm.time_now` is unconditionally
        // reachable (no allowlist needed), so this is the
        // simplest "the wiring works" smoke test.
        let dispatcher = ExecDispatcher::default();
        let result = dispatcher.invoke_tool("mvm.time_now", serde_json::json!({}));
        assert!(!result.is_error, "got error: {result:?}");
        let ContentBlock::Text { text } = &result.content[0];
        // The registry's TimeNowResult shape has `"time"` + `"format"` fields.
        assert!(text.contains("\"time\""), "got: {text}");
        assert!(text.contains("\"format\""), "got: {text}");
    }

    #[test]
    fn invoke_tool_renders_unknown_tool_as_is_error() {
        // The registry's `UnknownTool` error must surface as an
        // `is_error: true` ToolResult (NOT a JSON-RPC error), so
        // the LLM client sees the failure instead of retrying.
        let dispatcher = ExecDispatcher::default();
        let result = dispatcher.invoke_tool("mvm.does_not_exist", serde_json::json!({}));
        assert!(result.is_error);
        let ContentBlock::Text { text } = &result.content[0];
        assert!(text.contains("mvm.does_not_exist"), "got: {text}");
    }

    #[test]
    fn invoke_tool_web_fetch_fails_closed_with_clear_message() {
        // The default registry registers `mvm.web_fetch` with an
        // empty allowlist (Default::default() = fail_closed). The
        // operator sees a clear "not on allowlist" error rather
        // than a silent fall-through.
        let dispatcher = ExecDispatcher::default();
        let result = dispatcher.invoke_tool(
            "mvm.web_fetch",
            serde_json::json!({ "url": "https://example.com/" }),
        );
        assert!(result.is_error);
        let ContentBlock::Text { text } = &result.content[0];
        assert!(text.contains("not on per-tenant allowlist"), "got: {text}");
    }

    // ──────────────────────────────────────────────────────────────
    // resolve_provider_credential
    //
    // Env-var manipulation in tests is process-global, so each
    // test uses a unique env-var name to avoid races with parallel
    // tests touching the same key.
    // ──────────────────────────────────────────────────────────────

    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use secrecy::{ExposeSecret, SecretBox};

    /// Expose the inner string of a `SecretBox` for test
    /// assertions. The production path never does this — only
    /// `BraveSearchProvider::search` etc. expose at the wire
    /// boundary.
    fn exposed(opt: Option<SecretBox<String>>) -> Option<String> {
        opt.map(|s| s.expose_secret().clone())
    }

    fn tempdir_store() -> (tempfile::TempDir, FileSecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        (dir, store)
    }

    #[test]
    fn resolve_credential_returns_direct_env_var_when_set() {
        let direct = "MVM_TEST_CRED_DIRECT_RETURNED";
        let secret = "MVM_TEST_CRED_DIRECT_RETURNED_FROM_SECRET";
        let mut env = TestEnv::new();
        env.set(direct, "direct-value");
        let (_dir, store) = tempdir_store();
        let resolved = resolve_provider_credential(direct, secret, &store);
        assert_eq!(exposed(resolved).as_deref(), Some("direct-value"));
    }

    #[test]
    fn resolve_credential_returns_secret_store_value_when_direct_unset() {
        let direct = "MVM_TEST_CRED_FALLBACK_DIRECT";
        let secret_ref = "MVM_TEST_CRED_FALLBACK_FROM_SECRET";
        let mut env = TestEnv::new();
        env.set(secret_ref, "my-stored-key");
        let (_dir, store) = tempdir_store();
        store
            .put(
                PROVIDER_CREDENTIAL_TENANT,
                "my-stored-key",
                &SecretBox::new(Box::new("from-store".to_string())),
            )
            .unwrap();
        let resolved = resolve_provider_credential(direct, secret_ref, &store);
        assert_eq!(exposed(resolved).as_deref(), Some("from-store"));
    }

    #[test]
    fn resolve_credential_prefers_direct_when_both_set() {
        // Backward-compat invariant: the direct value wins when an
        // operator has both env vars set.
        let direct = "MVM_TEST_CRED_PRIORITY_DIRECT";
        let secret_ref = "MVM_TEST_CRED_PRIORITY_FROM_SECRET";
        let mut env = TestEnv::new();
        env.set(direct, "direct-wins");
        env.set(secret_ref, "stored-name");
        let (_dir, store) = tempdir_store();
        store
            .put(
                PROVIDER_CREDENTIAL_TENANT,
                "stored-name",
                &SecretBox::new(Box::new("stored-loses".to_string())),
            )
            .unwrap();
        let resolved = resolve_provider_credential(direct, secret_ref, &store);
        assert_eq!(exposed(resolved).as_deref(), Some("direct-wins"));
    }

    #[test]
    fn resolve_credential_returns_none_when_neither_env_var_set() {
        let (_dir, store) = tempdir_store();
        let resolved = resolve_provider_credential(
            "MVM_TEST_CRED_UNSET_DIRECT_DEFINITELY",
            "MVM_TEST_CRED_UNSET_REF_DEFINITELY",
            &store,
        );
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_credential_skips_empty_direct_value() {
        // An empty env var is functionally unset. Fall through to
        // the secret-store lookup.
        let direct = "MVM_TEST_CRED_EMPTY_DIRECT";
        let secret_ref = "MVM_TEST_CRED_EMPTY_FROM_SECRET";
        let mut env = TestEnv::new();
        env.set(direct, "");
        env.set(secret_ref, "actual-name");
        let (_dir, store) = tempdir_store();
        store
            .put(
                PROVIDER_CREDENTIAL_TENANT,
                "actual-name",
                &SecretBox::new(Box::new("from-store-fallback".to_string())),
            )
            .unwrap();
        let resolved = resolve_provider_credential(direct, secret_ref, &store);
        assert_eq!(exposed(resolved).as_deref(), Some("from-store-fallback"));
    }

    #[test]
    fn resolve_credential_returns_none_on_secret_store_miss() {
        // The secret-name env var is set but the named secret
        // doesn't exist in the store. The resolver returns None
        // so the caller's existing "allowed-but-unregistered"
        // config-drift path fires; a tracing::warn surfaces the
        // miss to the operator at boot time.
        let secret_ref = "MVM_TEST_CRED_MISS_FROM_SECRET";
        let mut env = TestEnv::new();
        env.set(secret_ref, "no-such-name");
        let (_dir, store) = tempdir_store();
        let resolved =
            resolve_provider_credential("MVM_TEST_CRED_MISS_DIRECT_UNSET", secret_ref, &store);
        assert!(resolved.is_none());
    }
}
