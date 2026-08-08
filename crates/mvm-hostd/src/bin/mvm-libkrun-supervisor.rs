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
use ed25519_dalek::{SigningKey, VerifyingKey};
use libkrun_sys::{
    BridgeFds, LogLevel, SupervisorBaseConfig, SupervisorConfig, init_log, run_supervisor,
    run_supervisor_with_bridge, set_log_level,
};
use mvm_core::plan::{ExecutionPlan, NonceStore, SignedExecutionPlan, verify_plan, verify_plan_id};
use mvm_core::policy::PolicyBundle;
use mvm_hostd::supervisor::audit::AuditSigner;
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
use mvm_hostd::supervisor::gateway_bridge::{
    BridgeConfig, BridgeEndpoints, spawn_bridge_thread, spawn_native_audit_feed,
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
    mvm_runtime::codesign::ensure_signed();

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

/// When `cfg.egress_relay_socket` is set, pin the guest egress port's
/// host-side socket to that explicit UDS instead of the dir-derived
/// `vsock-<port>.sock` path. No-op when `None` (every construction
/// site today) — the derived path is unchanged.
fn apply_egress_relay_override(cfg: &mut SupervisorConfig) {
    if let Some(sock) = cfg.egress_relay_socket.clone() {
        cfg.krun.set_host_listen_socket_override(
            mvm_agentd::vsock::EGRESS_PORT,
            sock.to_string_lossy().into_owned(),
        );
    }
}

/// Shared tail: given a finalized `SupervisorConfig` (from the legacy stdin
/// decode OR a verified prelaunch attach), bind the workload-exit control
/// listener and route to the bridge/legacy boot path. Extracted so both
/// entrypoints run identical post-config logic.
fn dispatch_config(mut cfg: SupervisorConfig) -> ExitCode {
    apply_egress_relay_override(&mut cfg);

    append_supervisor_breadcrumb(
        std::path::Path::new(&cfg.vm_state_dir),
        "dispatch_config",
        format!(
            "tenant_id_present={} host_listen_ports={:?} networking={:?}",
            cfg.tenant_id.is_some(),
            cfg.krun.host_listen_ports,
            cfg.krun.networking
        ),
    );

    // Bind the workload-exit control listener and capture
    // the guest's exit code on a background thread. Must bind BEFORE the
    // run dispatch (libkrun's listen=false proxy needs a live socket
    // before start_enter). Best-effort: a bind failure must not block
    // boot — workload.exit simply stays absent and the host reads "unknown".
    if cfg
        .krun
        .host_listen_ports
        .contains(&mvm_agentd::vsock::WORKLOAD_EXIT_PORT)
    {
        let state_dir = std::path::PathBuf::from(&cfg.vm_state_dir);
        let control_sock = cfg
            .krun
            .vsock_socket_path(mvm_agentd::vsock::WORKLOAD_EXIT_PORT);
        let _ = std::fs::remove_file(&control_sock);
        match UnixListener::bind(&control_sock) {
            Ok(listener) => {
                std::thread::spawn(move || {
                    if let Err(e) = mvm_hostd::exit_capture::capture_once(&listener, &state_dir) {
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
    let outcome = if should_use_bridge_route(&cfg) {
        append_supervisor_breadcrumb(
            std::path::Path::new(&cfg.vm_state_dir),
            "dispatch_route",
            "bridge".to_string(),
        );
        run_with_bridge(cfg)
    } else {
        let route = if cfg.tenant_id.is_some() {
            "legacy_direct_vsock"
        } else {
            "legacy"
        };
        append_supervisor_breadcrumb(
            std::path::Path::new(&cfg.vm_state_dir),
            "dispatch_route",
            route.to_string(),
        );
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

fn should_use_bridge_route(cfg: &SupervisorConfig) -> bool {
    cfg.tenant_id.is_some()
        && !matches!(
            cfg.krun.networking,
            libkrun_sys::NetworkingMode::Tsi | libkrun_sys::NetworkingMode::VsockDirect
        )
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
    let cfg = match mvm_hostd::prelaunch::verify_and_merge_attach(
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
    let vm_state_dir = std::path::Path::new(&cfg.vm_state_dir);
    append_supervisor_breadcrumb(
        vm_state_dir,
        "run_legacy_enter",
        format!(
            "vm={} host_listen_ports={:?}",
            cfg.krun.name, cfg.krun.host_listen_ports
        ),
    );
    run_supervisor(cfg).map_err(|e| {
        append_supervisor_breadcrumb(vm_state_dir, "run_legacy_error", e.to_string());
        anyhow!("run_supervisor failed: {e}")
    })
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
    let vm_state_dir = std::path::PathBuf::from(&cfg.vm_state_dir);
    append_supervisor_breadcrumb(
        &vm_state_dir,
        "run_with_bridge_enter",
        format!(
            "vm={} tenant_id={}",
            cfg.krun.name,
            cfg.tenant_id.as_deref().unwrap_or("")
        ),
    );

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

    // Load the host signer secret bytes before trusting any field decoded from
    // cfg.plan. The file is mode 0600 and written by mvm-cli's
    // `host_signer::load_or_init_at` at admit time; the path was already
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
    let verifying_key = signing_key.verifying_key();

    // Deserialize the JSON-Value-carrier into the signed envelope, then verify
    // its signature and content-address before trusting the typed plan. The
    // round-trip cost is trivial versus the bridge's IO budget.
    let signed: SignedExecutionPlan =
        serde_json::from_value(plan_value).context("decode cfg.plan into SignedExecutionPlan")?;
    let signer_id = mvm_hostd::audit::host_keypair::host_signer_id();
    let plan = verify_signed_plan(&signed, &signer_id, &verifying_key)?;
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

    // Historical native-gateway hook: this now stays inert because the active
    // libkrun transport is direct-vsock only. Keep the surrounding
    // native-flow-audit plumbing in place so an eventual gateway-backed
    // transport reintroduction does not need a larger structural rewrite.
    let mut native_flow_audit_path: Option<std::path::PathBuf> = None;
    if matches!(
        mvm_build::libkrun_builder::resolve_networking_mode(),
        mvm_build::libkrun_builder::NetworkingPreference::VsockDirect
    ) && let libkrun_sys::NetworkingMode::NativeGateway { scratch_dir, .. } =
        &cfg.krun.networking
    {
        let scratch = std::path::PathBuf::from(scratch_dir);
        // Matches `write_native_gateway_config`'s `[audit]` export path.
        native_flow_audit_path = Some(scratch.join("flow-audit.jsonl"));
        // Fail closed: a native gateway we can't configure must not silently
        // fall back to gvproxy-compat, which carries no policy.
        let transparent = cfg.transparent_terminator_port.map(|terminator_port| {
            mvm_hostd::supervisor::network::rvproxy_config::RvproxyTransparentConfig {
                terminator_host: std::net::Ipv4Addr::new(127, 0, 0, 1),
                terminator_port,
            }
        });
        let config_path =
            mvm_hostd::supervisor::network::rvproxy_launch::write_native_gateway_config(
                bundle.as_ref(),
                &plan.tenant,
                &vm_name,
                &scratch,
                transparent,
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
            .with_native_gateway_config(config_path.to_string_lossy().into_owned());
    }

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
    // `payload_tap: true`. The drainer will
    // set `payload_tap: false` from its own bin.
    let leaf_caps = mvm_hostd::supervisor::network::ProviderCapabilities {
        flow_events: true,
        payload_tap: true,
    };
    let observer_names = mvm_hostd::supervisor::network::resolve_observer_chain_from_policy_source(
        &plan,
        bundle.as_ref(),
    )
    .context("resolve observer chain from admitted policy source")?;
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
        // Native rvproxy gateway: tail its flow-audit export into the chain
        // signer. `Some` only when the native gateway was rendered above; the
        // gvproxy/passt path leaves it `None` (splice is the sole audit source).
        native_flow_audit_path,
    };

    // Native rvproxy: libkrun attaches DIRECTLY to rvproxy (no splice in the
    // data path — interposing the splice in front of rvproxy breaks the vfkit
    // return path and would only mask rvproxy's own enforcement). rvproxy is the
    // sole egress enforcer; a standalone audit feed re-feeds its flow-audit
    // export into the chain signer so the claim-10 audit stays mvm's source of
    // truth. gvproxy/passt keep the in-line splice bridge.
    if bridge_cfg.native_flow_audit_path.is_some() {
        append_supervisor_breadcrumb(
            &vm_state_dir,
            "run_with_bridge_native",
            "native_flow_audit".to_string(),
        );
        // JoinHandle dropped — libkrun's exit() on guest shutdown reaps it;
        // the feed's own catch_unwind → exit(1) is the fail-closed signal.
        let _feed = spawn_native_audit_feed(bridge_cfg);
        return run_supervisor(&cfg).map_err(|e| {
            append_supervisor_breadcrumb(
                &vm_state_dir,
                "run_with_bridge_native_error",
                e.to_string(),
            );
            anyhow!("run_supervisor (native) failed: {e}")
        });
    }

    append_supervisor_breadcrumb(
        &vm_state_dir,
        "run_with_bridge_spawn_bridge",
        "inline_bridge".to_string(),
    );
    run_supervisor_with_bridge(&cfg, move |bridge_fds| {
        let endpoints = match bridge_fds {
            BridgeFds::Passt {
                gateway_fd,
                supervisor_fd,
            } => BridgeEndpoints::Passt {
                gateway_fd,
                supervisor_fd,
            },
            BridgeFds::LibkrunNativeGateway {
                gateway_socket_path,
                supervisor_listen_path,
            } => BridgeEndpoints::LibkrunNativeGateway {
                gateway_socket_path,
                supervisor_listen_path,
            },
        };
        // Bridge thread JoinHandle is intentionally dropped — libkrun's
        // exit() on guest shutdown reaps the thread without graceful
        // join. The bridge's own `catch_unwind → exit(1)` provides the
        // fail-closed signal for the claim-10 substrate.
        let _join = spawn_bridge_thread(endpoints, bridge_cfg);
    })
    .map_err(|e| {
        append_supervisor_breadcrumb(&vm_state_dir, "run_with_bridge_error", e.to_string());
        anyhow!("run_supervisor_with_bridge failed: {e}")
    })
}

/// Verify the plan envelope before exposing its payload to the bridge setup.
/// The supervisor receives the envelope over a private host channel, but the
/// channel is not a substitute for the plan's cryptographic invariants.
fn verify_signed_plan(
    signed: &SignedExecutionPlan,
    signer_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<ExecutionPlan> {
    let plan = verify_plan(signed, &[(signer_id, verifying_key)])
        .context("verifying SignedExecutionPlan envelope")?;
    verify_plan_id(&plan).context("verifying ExecutionPlan content address")?;
    Ok(plan)
}

fn append_supervisor_breadcrumb(vm_state_dir: &std::path::Path, stage: &str, detail: String) {
    let path = vm_state_dir.join("supervisor.lifecycle.log");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let timestamp = chrono::Utc::now().to_rfc3339();
    let line = format!("{timestamp} {stage}: {detail}\n");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = std::io::Write::write_all(&mut file, line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_supervisor_breadcrumb, apply_egress_relay_override, should_use_bridge_route,
        verify_signed_plan,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libkrun_sys::{BridgeRestartPolicy, KrunContext, NetworkingMode, SupervisorConfig};
    use mvm_core::plan::{SignedExecutionPlan, sign_plan};
    use mvm_core::protocol::signing::SignedPayload;

    fn sample_cfg(networking: NetworkingMode, tenant_id: Option<&str>) -> SupervisorConfig {
        let mut krun = KrunContext::new("vm-1", "/k", "/r");
        krun.networking = networking;
        SupervisorConfig {
            krun,
            vm_state_dir: "/run/state/vm-1".into(),
            pid_file_name: None,
            tenant_id: tenant_id.map(str::to_string),
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            network_policy: None,
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
            transparent_terminator_port: None,
            egress_relay_socket: None,
        }
    }

    #[test]
    fn append_supervisor_breadcrumb_writes_lifecycle_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        append_supervisor_breadcrumb(dir.path(), "dispatch_config", "detail".to_string());
        let body = std::fs::read_to_string(dir.path().join("supervisor.lifecycle.log"))
            .expect("read lifecycle log");
        assert!(body.contains("dispatch_config: detail"), "body: {body}");
    }

    #[test]
    fn bridge_route_skips_admitted_vsock_direct_workloads() {
        let cfg = sample_cfg(NetworkingMode::VsockDirect, Some("tenant-a"));
        assert!(
            !should_use_bridge_route(&cfg),
            "VsockDirect admitted workloads must stay on the legacy no-gateway route"
        );
    }

    #[test]
    fn bridge_route_keeps_gateway_backed_admitted_workloads() {
        let cfg = sample_cfg(
            NetworkingMode::Passt {
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                scratch_dir: "/tmp/passt".into(),
            },
            Some("tenant-a"),
        );
        assert!(
            should_use_bridge_route(&cfg),
            "gateway-backed admitted workloads must keep the bridge route"
        );
    }

    #[test]
    fn apply_egress_relay_override_pins_egress_port_when_set() {
        let mut cfg = sample_cfg(NetworkingMode::Tsi, None);
        cfg.krun = cfg
            .krun
            .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT);
        cfg.egress_relay_socket = Some(std::path::PathBuf::from(
            "/run/mvm/vm-1/substitution-endpoint.sock",
        ));
        apply_egress_relay_override(&mut cfg);
        assert_eq!(
            cfg.krun
                .host_listen_socket_path(mvm_agentd::vsock::EGRESS_PORT),
            std::path::PathBuf::from("/run/mvm/vm-1/substitution-endpoint.sock")
        );
    }

    #[test]
    fn apply_egress_relay_override_is_noop_when_unset() {
        let mut cfg = sample_cfg(NetworkingMode::Tsi, None);
        cfg.krun = cfg
            .krun
            .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT);
        let derived = cfg
            .krun
            .host_listen_socket_path(mvm_agentd::vsock::EGRESS_PORT);
        apply_egress_relay_override(&mut cfg);
        assert_eq!(
            cfg.krun
                .host_listen_socket_path(mvm_agentd::vsock::EGRESS_PORT),
            derived
        );
    }

    fn signed_fixture() -> (SignedExecutionPlan, SigningKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        (sign_plan(&plan, &key, "host:test"), key)
    }

    #[test]
    fn verify_signed_plan_accepts_valid_signature_and_content_address() {
        let (signed, key) = signed_fixture();
        let plan = verify_signed_plan(&signed, "host:test", &key.verifying_key())
            .expect("valid signed plan verifies");
        assert_eq!(plan.tenant.0, "local");
        assert!(mvm_core::plan::verify_plan_id(&plan).is_ok());
    }

    #[test]
    fn verify_signed_plan_rejects_tampered_payload() {
        let (mut signed, key) = signed_fixture();
        signed.0.payload[0] ^= 1;

        let err = verify_signed_plan(&signed, "host:test", &key.verifying_key())
            .expect_err("tampered payload must fail signature verification");
        assert!(
            err.to_string()
                .contains("verifying SignedExecutionPlan envelope")
        );
    }

    #[test]
    fn verify_signed_plan_rejects_signed_plan_with_wrong_content_address() {
        let (_, key) = signed_fixture();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.plan_id = mvm_core::plan::PlanId("sha256:wrong".to_string());
        let payload = serde_json::to_vec(&plan).expect("fixture plan serializes");
        let signature = key.sign(&payload);
        let signed = SignedExecutionPlan(SignedPayload {
            payload,
            signature: signature.to_bytes().to_vec(),
            signer_id: "host:test".to_string(),
        });

        let err = verify_signed_plan(&signed, "host:test", &key.verifying_key())
            .expect_err("wrong plan_id must fail content-address verification");
        assert!(
            err.to_string()
                .contains("verifying ExecutionPlan content address")
        );
    }
}
