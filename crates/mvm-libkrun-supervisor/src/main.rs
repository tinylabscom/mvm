//! Plan 57 W4 / Plan 102 W6.A.5 — one-libkrun-guest-per-process supervisor.
//!
//! Reads a [`SupervisorConfig`] JSON document on stdin, ad-hoc
//! codesigns itself for `Hypervisor.framework` (macOS W2 gate),
//! creates the per-VM state directory, writes its own PID, then
//! either:
//!
//! 1. **Bridge path** (`cfg.tenant_id` is `Some`) — calls
//!    [`run_supervisor_with_bridge`] with a factory that spawns the
//!    per-VM gateway audit bridge (`mvm_hostd::supervisor::gateway_bridge::
//!    spawn_bridge_thread`). Every guest network byte transits the
//!    bridge, FlowOpened/FlowClosed entries chain-sign into
//!    `~/.mvm/audit/<tenant>.jsonl`, and `nc -U
//!    <gateway_audit_socket>` subscribers see the live NDJSON feed.
//!    This is the claim-10 substrate path.
//! 2. **Legacy path** (`cfg.tenant_id` is `None`) — falls back to
//!    the pre-W6.A.5 [`run_supervisor`] which boots libkrun without
//!    interposing a bridge. Used by Stage 0 builder VMs and any
//!    other dev-mode call site that doesn't synthesize an
//!    `ExecutionPlan`.
//!
//! Both paths block in `krun_start_enter` until the guest powers
//! off, at which point libkrun calls `exit()` on the process.
//!
//! ## Why one process per VM
//!
//! `krun_start_enter` calls `exit()` on the calling process when
//! the guest exits cleanly. An in-process registry (plan 57 W4
//! Option A) would tear down every other libkrun guest the parent
//! `mvmctl` is supervising. One process per VM scopes the `exit()`
//! to a single supervisor; the parent `mvmctl` returns immediately
//! after spawning and survives a guest's shutdown.
//!
//! ## Why this is its own crate
//!
//! Plan 102 W6.A.5 — the bin's bridge-factory branch depends on
//! `mvm-supervisor` (gateway audit substrate). Adding
//! `mvm-supervisor` to `mvm-libkrun`'s deps would close the cycle
//! `mvm-supervisor → mvm-backend → mvm-libkrun`. Splitting the bin
//! into a leaf crate breaks the cycle cleanly. The binary name is
//! preserved so `mvm-backend::libkrun::resolve_supervisor_path()`
//! keeps resolving it.

use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::SigningKey;
use libkrun_sys::{
    BridgeFds, LogLevel, SupervisorConfig, init_log, run_supervisor, run_supervisor_with_bridge,
    set_log_level,
};
use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
use mvm_core::policy::PolicyBundle;
use mvm_hostd::supervisor::audit::AuditSigner;
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
use mvm_hostd::supervisor::gateway_bridge::{
    AllowAll, BridgeConfig, BridgeEndpoints, spawn_bridge_thread,
};

fn main() -> ExitCode {
    // macOS Hypervisor.framework rejects any process without
    // `com.apple.security.hypervisor`. Plan 57 W2's ad-hoc signer
    // self-signs + re-spawns the binary on first run; subsequent
    // invocations are silent (`MVM_SIGNED=1`). Without this,
    // `krun_start_enter` fails at VM creation with rc -22.
    mvm_backend::providers::apple_container::ensure_signed();

    // Plan 88 W5 diagnostic: opt-in libkrun internal logger. Set
    // `MVM_KRUN_LOG={off,error,warn,info,debug,trace}` to surface
    // device-attach traces and virtio MMIO events that don't appear
    // via `krun_set_log_level` alone. Tried `krun_init_log` first
    // (full-featured); falls back to `krun_set_log_level` on older
    // libkrun builds that don't export it. Failures are non-fatal —
    // the supervisor still runs, just without verbose logging.
    if let Ok(level) = std::env::var("MVM_KRUN_LOG") {
        let parsed = match level.trim().to_ascii_lowercase().as_str() {
            "off" => Some(LogLevel::Off),
            "error" => Some(LogLevel::Error),
            "warn" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "trace" => Some(LogLevel::Trace),
            _ => None,
        };
        if let Some(lvl) = parsed
            && let Err(e) = init_log(2, lvl, 0, 0)
        {
            eprintln!(
                "mvm-libkrun-supervisor: krun_init_log failed ({e}); \
                 falling back to set_log_level"
            );
            if let Err(e2) = set_log_level(lvl) {
                eprintln!("mvm-libkrun-supervisor: krun_set_log_level failed: {e2}");
            }
        }
    }

    let mut json = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut json) {
        eprintln!("error: read SupervisorConfig JSON from stdin: {e}");
        return ExitCode::from(2);
    }

    let cfg: SupervisorConfig = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: parse SupervisorConfig JSON: {e}");
            return ExitCode::from(2);
        }
    };

    // Plan 102 W6.A.5 — route to the bridge path when the producer
    // populated the audit substrate, otherwise fall back to the
    // legacy direct-libkrun path (Stage 0 builder VMs, smoke tests,
    // etc. that haven't synthesized an ExecutionPlan).
    let outcome = if cfg.tenant_id.is_some() {
        run_with_bridge(cfg)
    } else {
        run_legacy(&cfg)
    };

    match outcome {
        // run_supervisor / run_supervisor_with_bridge return
        // `Result<Infallible, _>`. On success libkrun has already
        // called exit() on this process; we never get here.
        Err(e) => {
            eprintln!("supervisor failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// Legacy boot path — direct libkrun with no gateway audit bridge.
/// Returns `Result<Infallible, _>`, propagated up.
fn run_legacy(cfg: &SupervisorConfig) -> Result<std::convert::Infallible> {
    run_supervisor(cfg).map_err(|e| anyhow!("run_supervisor failed: {e}"))
}

/// Bridge boot path — sets up the per-VM gateway audit bridge
/// before calling libkrun's `start_enter`. Synthesizes the bridge
/// factory closure that converts `BridgeFds` (mvm-libkrun shape)
/// into `BridgeEndpoints` (mvm-supervisor shape), builds
/// `BridgeConfig` from the JSON-encoded plan + bundle and the
/// chain-signing `FileAuditSigner`, then calls
/// `spawn_bridge_thread`. The bridge thread runs concurrently with
/// `krun_start_enter` and is reaped by `exit()` on guest shutdown.
fn run_with_bridge(cfg: SupervisorConfig) -> Result<std::convert::Infallible> {
    // Pre-extract the audit-substrate paths + plan/bundle. The
    // factory closure needs them as owned values; the legacy
    // `&SupervisorConfig` reference path doesn't fit because
    // run_supervisor_with_bridge takes a `&SupervisorConfig` and
    // the factory captures these owned by move.
    let vm_name = cfg.krun.name.clone();
    let tenant_id = cfg
        .tenant_id
        .clone()
        .ok_or_else(|| anyhow!("run_with_bridge called without cfg.tenant_id"))?;
    let audit_dir = cfg.audit_dir.clone().ok_or_else(|| {
        anyhow!("cfg.audit_dir missing — validate_audit_substrate should have refused")
    })?;
    let audit_socket = cfg
        .gateway_audit_socket
        .clone()
        .ok_or_else(|| anyhow!("cfg.gateway_audit_socket missing"))?;
    let signing_key_path = cfg
        .signing_key_path
        .clone()
        .ok_or_else(|| anyhow!("cfg.signing_key_path missing"))?;
    let plan_value = cfg
        .plan
        .clone()
        .ok_or_else(|| anyhow!("cfg.plan missing on bridge path"))?;
    let bundle_value = cfg.bundle.clone();

    // Deserialize the JSON-Value-carrier into typed values. The
    // round-trip cost is trivial vs the bridge's IO budget.
    // cfg.plan carries the SignedExecutionPlan envelope the host admitted +
    // signed (plan_admission.rs serializes `admitted.signed`), not a bare
    // ExecutionPlan. Decode the envelope and read the inner plan from its
    // payload. The host already verified the signature + G4 window/nonce at
    // admit time and spawns this supervisor over a private channel, so under
    // ADR-002 (host is trusted) we extract rather than re-verify here.
    // Defense-in-depth re-verify via `mvm_core::plan::verify_plan` with the host
    // signer pubkey is a follow-up.
    let signed: SignedExecutionPlan =
        serde_json::from_value(plan_value).context("decode cfg.plan into SignedExecutionPlan")?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)
        .context("decode ExecutionPlan from signed plan payload")?;
    let bundle: Option<PolicyBundle> = match bundle_value {
        Some(v) => Some(serde_json::from_value(v).context("decode cfg.bundle into PolicyBundle")?),
        None => None,
    };

    // Load the host signer secret bytes. The file is mode 0600 and
    // written by mvm-cli's `host_signer::load_or_init_at` at admit
    // time; we re-read on each VM start. Path was already
    // canonicalized under `~/.mvm/keys/` by
    // `SupervisorConfig::validate_audit_substrate`.
    let key_bytes = std::fs::read(&signing_key_path)
        .with_context(|| format!("read signing key {}", signing_key_path.display()))?;
    let key_array: [u8; 32] = key_bytes.as_slice().try_into().with_context(|| {
        format!(
            "signing key {} is {} bytes, expected 32",
            signing_key_path.display(),
            key_bytes.len()
        )
    })?;
    let signing_key = SigningKey::from_bytes(&key_array);

    // FileAuditSigner is what mvm-supervisor's chain emitter wraps.
    // The cross-process flock (Plan 102 W6.A commit 2) serializes
    // writes from concurrent VM supervisors for the same tenant.
    let signer = FileAuditSigner::open(signing_key, &audit_dir)
        .with_context(|| format!("open FileAuditSigner at {}", audit_dir.display()))?;
    let signer: Arc<dyn AuditSigner> = Arc::new(signer);

    // Sanity log so operators tailing the bin's stderr can see the
    // bridge wired up.
    tracing::info!(
        vm = %vm_name,
        tenant = %tenant_id,
        audit_socket = %audit_socket.display(),
        audit_dir = %audit_dir.display(),
        "starting bridge-mode libkrun supervisor"
    );

    // Plan 113 §Task 4 — observer chain from admitted plan + host
    // allowlist. `resolve_observer_chain_from_plan` returns an empty
    // Vec for the `local-default` plan ref WITHOUT consulting the
    // allowlist; only non-default refs trigger the
    // `~/.mvm/observers/allowlist.toml` load. This preserves the
    // Stage 0 / dev-mode path (and the Plan 112 phase3c dispatch
    // smoke, which uses a placeholder plan that fails decode before
    // reaching this code).
    //
    // Leaf capabilities are fixed per backend: libkrun reports
    // `payload_tap: true`. The Vz drainer (Plan 113 §Task 10) will
    // set `payload_tap: false` from its own bin.
    let leaf_caps = mvm_hostd::supervisor::network::ProviderCapabilities {
        flow_events: true,
        payload_tap: true,
    };
    let observer_names = mvm_hostd::supervisor::network::resolve_observer_chain_from_plan(&plan)
        .context("resolve observer chain from admitted plan")?;
    let observers = if observer_names.is_empty() {
        Vec::new()
    } else {
        let allowlist = mvm_hostd::supervisor::network::ObserverAllowlist::load_from_host_config()
            .context("load ObserverAllowlist from ~/.mvm/observers/allowlist.toml")?;
        let mut pipe = mvm_hostd::supervisor::network::Pipeline::new();
        for name in observer_names {
            let obs = allowlist
                .resolve(&name)
                .context("resolve observer name in allowlist")?;
            pipe = pipe
                .observe(obs, leaf_caps)
                .context("observer capability gate")?;
        }
        pipe.build_observers()
    };

    let bridge_cfg = BridgeConfig {
        vm_name: vm_name.clone(),
        plan: Arc::new(plan),
        bundle: bundle.map(Arc::new),
        audit_socket,
        signer,
        policy: Arc::new(AllowAll),
        // Plan 113 / ADR-064 — observers resolved above from the
        // admitted plan's `network_policy` ref through the host
        // allowlist. Empty for `local-default` plans (preserves
        // pre-Plan-113 behavior); non-empty for tenant policies that
        // reference an allowlisted observer by name.
        observers,
    };

    run_supervisor_with_bridge(&cfg, move |bridge_fds| {
        let endpoints = match bridge_fds {
            BridgeFds::Passt {
                gateway_fd,
                supervisor_fd,
            } => BridgeEndpoints::Passt {
                gateway_fd,
                supervisor_fd,
            },
            BridgeFds::LibkrunGvproxy {
                gvproxy_socket_path,
                supervisor_listen_path,
            } => BridgeEndpoints::LibkrunGvproxy {
                gvproxy_socket_path,
                supervisor_listen_path,
            },
        };
        // Bridge thread JoinHandle is intentionally dropped — libkrun's
        // exit() on guest shutdown reaps the thread without graceful
        // join. The bridge's own `catch_unwind → exit(1)` provides the
        // fail-closed signal for the claim-10 substrate.
        let _join = spawn_bridge_thread(endpoints, bridge_cfg);
    })
    .map_err(|e| anyhow!("run_supervisor_with_bridge failed: {e}"))
}
