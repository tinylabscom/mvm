//! One-libkrun-guest-per-process supervisor.
//!
//! Reads a [`SupervisorConfig`] JSON document on stdin, ad-hoc
//! codesigns itself for `Hypervisor.framework` (macOS gate),
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
//!    [`run_supervisor`] which boots libkrun without
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
//! the guest exits cleanly. An in-process registry would tear down
//! every other libkrun guest the parent
//! `mvmctl` is supervising. One process per VM scopes the `exit()`
//! to a single supervisor; the parent `mvmctl` returns immediately
//! after spawning and survives a guest's shutdown.
//!
//! ## Why this is its own crate
//!
//! The bin's bridge-factory branch depends on
//! `mvm-supervisor` (gateway audit substrate). Adding
//! `mvm-supervisor` to `mvm-libkrun`'s deps would close the cycle
//! `mvm-supervisor → mvm-backend → mvm-libkrun`. Splitting the bin
//! into a leaf crate breaks the cycle cleanly. The binary name is
//! preserved so `mvm-backend::libkrun::resolve_supervisor_path()`
//! keeps resolving it.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use libkrun_sys::{
    BridgeFds, LogLevel, SupervisorBaseConfig, SupervisorConfig, init_log, run_supervisor,
    run_supervisor_with_bridge, set_log_level,
};
use mvm_core::plan::{ExecutionPlan, NonceStore, SignedExecutionPlan};
use mvm_core::policy::PolicyBundle;
use mvm_hostd::supervisor::audit::AuditSigner;
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
use mvm_hostd::supervisor::gateway_bridge::{
    AllowAll, BridgeConfig, BridgeEndpoints, spawn_bridge_thread,
};

/// Per-connection attach timeout. An abandoned connect must not wedge the
/// standby; pool size bounds the blast radius.
// A prelaunched **pool** standby legitimately blocks a long time waiting to be claimed —
// it's the warm pool's whole point. Its lifetime is bounded by the pool reaper TTL
// (`mvmctl cache prune`, ~30 min), NOT a short self-timeout; a 30s value
// made standbys self-exit before a later `up` could claim them. The per-conn read timeout
// (set on the accepted stream) still caps a connected-but-silent peer, so DoS protection is
// unaffected. Keep this aligned with the reaper TTL.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Cap on the attach frame — workload config is small; reject hostile prefixes.
const MAX_ATTACH_BYTES: usize = 1 << 20; // 1 MiB

/// Stdin dispatch. The prelaunched producer wraps the base
/// config under a unique `prelaunch_base` key; legacy callers emit a bare
/// `SupervisorConfig` (no wrapper) and are byte-for-byte unchanged. Probed
/// wrapper-first: a legacy config has no such key, so it falls through to the
/// unchanged whole-config path. `deny_unknown_fields` + the disjoint required
/// fields (`base_and_whole_configs_are_serde_disjoint` test in libkrun-sys)
/// make this unambiguous — a botched prelaunch can never silently boot via the
/// legacy arm (its `krun` is nested under `prelaunch_base`, so the bare-config
/// fallback fails its required `krun` field too).
///
/// NB: a serde-tagged enum is deliberately avoided — `deny_unknown_fields` is
/// unsupported on internally-tagged enums, and an `#[serde(untagged)]` fallback
/// would silently route a malformed prelaunch to the permissive legacy arm.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrelaunchEnvelope {
    prelaunch_base: SupervisorBaseConfig,
}

fn main() -> ExitCode {
    // macOS Hypervisor.framework rejects any process without
    // `com.apple.security.hypervisor`. The ad-hoc signer
    // self-signs + re-spawns the binary on first run; subsequent
    // invocations are silent (`MVM_SIGNED=1`). Without this,
    // `krun_start_enter` fails at VM creation with rc -22.
    mvm_backend::codesign::ensure_signed();

    // Diagnostic: opt-in libkrun internal logger. Set
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

    // Prelaunch (warm-pool standby) vs legacy/cold (bare
    // SupervisorConfig). The prelaunch producer wraps the base under a unique
    // `prelaunch_base` key; legacy callers emit a bare config and route below
    // unchanged.
    if let Ok(env) = serde_json::from_str::<PrelaunchEnvelope>(&json) {
        return run_prelaunched(env.prelaunch_base);
    }
    let cfg: SupervisorConfig = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: parse SupervisorConfig JSON: {e}");
            return ExitCode::from(2);
        }
    };
    dispatch_config(cfg)
}

/// Shared tail: given a finalized `SupervisorConfig` (from the legacy stdin
/// decode OR a verified prelaunch attach), bind the workload-exit control
/// listener and route to the bridge/legacy boot path. Extracted so both
/// entrypoints run identical post-config logic.
fn dispatch_config(cfg: SupervisorConfig) -> ExitCode {
    // Bind the workload-exit control listener and capture
    // the guest's exit code on a background thread. Must bind BEFORE the
    // run dispatch (libkrun's listen=false proxy needs a live socket
    // before start_enter). Best-effort: a bind failure must not block
    // boot — workload.exit simply stays absent and the host reads "unknown".
    if cfg
        .krun
        .host_listen_ports
        .contains(&mvm_guest::vsock::WORKLOAD_EXIT_PORT)
    {
        let state_dir = std::path::PathBuf::from(&cfg.vm_state_dir);
        let control_sock = cfg
            .krun
            .vsock_socket_path(mvm_guest::vsock::WORKLOAD_EXIT_PORT);
        let _ = std::fs::remove_file(&control_sock);
        match UnixListener::bind(&control_sock) {
            Ok(listener) => {
                std::thread::spawn(move || {
                    if let Err(e) = mvm_vm_host::exit_capture::capture_once(&listener, &state_dir) {
                        eprintln!("mvm-libkrun-supervisor: exit capture: {e}");
                    }
                });
            }
            Err(e) => eprintln!("mvm-libkrun-supervisor: bind control socket: {e}"),
        }
    }

    // Route to the bridge path when the producer
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

/// Prelaunched-standby flow. `ensure_signed()` + the libkrun
/// dylib are already warm (done in `main`). Bind the control UDS, accept ONE
/// connection (per-conn timeout), read the attach frame, re-verify+merge, then
/// hand the whole config to the existing bridge path. One-shot: any failure or
/// timeout exits non-zero WITHOUT `start_enter`.
fn run_prelaunched(base: SupervisorBaseConfig) -> ExitCode {
    let sock_path = base.control_socket_path.clone();
    let listener = match bind_control_socket(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "prelaunch: bind control socket {}: {e}",
                sock_path.display()
            );
            return ExitCode::from(3);
        }
    };
    let mut stream = match accept_one_with_timeout(&listener, ATTACH_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("prelaunch: attach accept failed: {e}");
            return ExitCode::from(4);
        }
    };
    // Best-effort cleanup of the control socket — the workload-exit socket the
    // bridge path binds is a different path under the state dir.
    let _ = std::fs::remove_file(&sock_path);

    // Read the length-prefixed attach frame, then re-encode to bytes for the
    // pure verifier (which owns the deny_unknown_fields decode + plan verify).
    let attach_value: serde_json::Value =
        match libkrun_sys::framing::read_json_frame_sync(&mut stream, MAX_ATTACH_BYTES) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("prelaunch: read attach frame: {e}");
                return ExitCode::from(5);
            }
        };
    let attach_bytes = match serde_json::to_vec(&attach_value) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("prelaunch: re-encode attach: {e}");
            return ExitCode::from(5);
        }
    };

    let mut nonce_store = NonceStore::new();
    let cfg = match mvm_vm_host::prelaunch::verify_and_merge_attach(
        base,
        &attach_bytes,
        Utc::now(),
        &mut nonce_store,
    ) {
        Ok(c) => c,
        Err(e) => {
            // SECURITY: refused — never start_enter.
            eprintln!("prelaunch: attach refused: {e}");
            return ExitCode::from(6);
        }
    };
    dispatch_config(cfg)
}

/// Bind the control UDS at `path` with mode 0700, inside a 0700 parent dir.
/// Mirrors the vsock-proxy posture: same-uid only.
fn bind_control_socket(path: &std::path::Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let _ = std::fs::remove_file(path); // clear a stale socket
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(listener)
}

/// Accept exactly one connection within `timeout`, else error. Sets a read
/// timeout on the accepted stream too, so a connected-but-silent peer can't
/// wedge the standby.
fn accept_one_with_timeout(
    listener: &UnixListener,
    timeout: Duration,
) -> std::io::Result<UnixStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "attach timeout",
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
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
fn run_with_bridge(mut cfg: SupervisorConfig) -> Result<std::convert::Infallible> {
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
    // admit time and spawns this supervisor over a private channel, so since
    // the host is trusted we extract rather than re-verify here.
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
    // Bare egress policy for the no-bundle path. The bridge derives the flow
    // gate + DNS allow-list from it when no bundle resolves (transient/dev).
    let network_policy: Option<mvm_core::network_policy::NetworkPolicy> =
        match cfg.network_policy.clone() {
            Some(v) => Some(
                serde_json::from_value(v)
                    .context("decode cfg.network_policy into NetworkPolicy")?,
            ),
            None => None,
        };

    // Native rvproxy gateway: when MVM_NETWORKING=native is in effect (the
    // supervisor inherits the launcher's env — the same channel that swaps the
    // gateway binary via MVM_GATEWAY_BIN), render the `run --config` TOML from
    // the admitted bundle into the per-VM scratch dir and point the gateway
    // spawn at it. The in-line splice still runs and shares the exact same
    // egress resolution, so this is additive belt-and-suspenders during the
    // transition off the splice.
    if matches!(
        mvm_build::libkrun_builder::resolve_networking_mode(),
        mvm_build::libkrun_builder::NetworkingPreference::Native
    ) && let libkrun_sys::NetworkingMode::Gvproxy { scratch_dir, .. } = &cfg.krun.networking
    {
        let scratch = std::path::PathBuf::from(scratch_dir);
        // Fail closed: a native gateway we can't configure must not silently
        // fall back to gvproxy-compat, which carries no policy.
        let config_path =
            mvm_hostd::supervisor::network::rvproxy_launch::write_native_gateway_config(
                bundle.as_ref(),
                &plan.tenant,
                &vm_name,
                &scratch,
                chrono::Utc::now(),
            )
            .context("render native rvproxy gateway config")?;
        tracing::info!(
            vm = %vm_name,
            config = %config_path.display(),
            "native rvproxy gateway: rendered run --config"
        );
        cfg.krun = cfg
            .krun
            .with_gvproxy_native_config(config_path.to_string_lossy().into_owned());
    }

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
    // The cross-process flock serializes writes from concurrent VM
    // supervisors for the same tenant.
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

    // Observer chain from admitted plan + host
    // allowlist. `resolve_observer_chain_from_plan` returns an empty
    // Vec for the `local-default` plan ref WITHOUT consulting the
    // allowlist; only non-default refs trigger the
    // `~/.mvm/observers/allowlist.toml` load. This preserves the
    // Stage 0 / dev-mode path (and the dispatch
    // smoke, which uses a placeholder plan that fails decode before
    // reaching this code).
    //
    // Leaf capabilities are fixed per backend: libkrun reports
    // `payload_tap: true`. The Vz drainer will
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
        // The flow-open gate. This `AllowAll` is only the
        // *no-bundle fallback*: when the admitted plan carries a resolvable
        // policy bundle, `run_bridge_inner` derives a per-tenant
        // `PlanFlowPolicy` (deny-by-default, the libkrun analogue of the
        // Firecracker `install_default_deny`) from the same resolved policy as
        // the packet scan, and that supersedes this field. Stage 0 builder VMs /
        // dev-mode carry no bundle, so they keep `AllowAll` (still gated by the
        // always-on mandatory-deny + placeholder-leak packet scans).
        policy: Arc::new(AllowAll),
        // Observers resolved above from the
        // admitted plan's `network_policy` ref through the host
        // allowlist. Empty for `local-default` plans (preserves
        // prior behavior); non-empty for tenant policies that
        // reference an allowlisted observer by name.
        observers,
        // Bare-policy enforcement seam for the no-bundle path, decoded from
        // SupervisorConfig.network_policy (which the libkrun backend fills from
        // VmStartConfig.network_policy).
        network_policy,
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
