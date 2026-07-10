//! One-libkrun-guest-per-process supervisor.
//!
//! Reads a [`SupervisorConfig`] JSON document on stdin, ad-hoc
//! codesigns itself for `Hypervisor.framework` (macOS gate),
//! creates the per-VM state directory, writes its own PID, then calls
//! [`run_supervisor`] on a vsock-only libkrun configuration. Used by Stage 0
//! builder VMs, by the vsock-only libkrun workload path, and by any other
//! dev-mode call site that doesn't synthesize a guest NIC.
//!
//! The supervisor blocks in `krun_start_enter` until the guest powers off, at
//! which point libkrun calls `exit()` on the process.
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
//! The binary name is preserved so
//! `mvm-backend::libkrun::resolve_supervisor_path()` keeps resolving it.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use chrono::Utc;
use libkrun_sys::{
    LogLevel, SupervisorBaseConfig, SupervisorConfig, init_log, run_supervisor, set_log_level,
};
use mvm_core::plan::NonceStore;

fn validate_vsock_only_networking(cfg: &SupervisorConfig) -> Result<()> {
    if matches!(
        cfg.krun.networking,
        libkrun_sys::NetworkingMode::Disconnected { .. }
    ) {
        return Ok(());
    }
    anyhow::bail!(
        "libkrun guest networking must stay on the disconnected sink/vsock-only path; \
         use the vsock egress transport"
    );
}

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
    if let Err(e) = validate_vsock_only_networking(&cfg) {
        eprintln!("supervisor failed: {e}");
        return ExitCode::from(1);
    }

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

    // Phase A: transparent-TCP vsock egress. When the host opted in and the
    // workload carries no bound secrets (so the substitution endpoint is NOT
    // binding EGRESS_PORT), bind the EGRESS_PORT UDS and run the claim-10 egress
    // server. The NIC is still attached (Phase A retains it); this is the opt-in
    // vsock path used to live-prove egress before the NIC is removed in Phase B.
    {
        let opt_in = mvm_build::libkrun_network_provider::vsock_egress_opt_in();
        let builder_policy_egress =
            cfg.tenant_id.is_none() && cfg.network_policy.as_ref().is_some();
        // Short-circuit on the opt-in flag so the default (flag-off) path does no
        // extra plan.json read. `should_serve_vsock_egress` also requires `opt_in`,
        // so passing `has_secrets = false` when opted out changes nothing.
        let has_secrets = (opt_in || builder_policy_egress)
            && mvm_backend::egress_shared::state_has_bound_secrets(std::path::Path::new(
                &cfg.vm_state_dir,
            ))
            .unwrap_or(false);
        let should_serve = mvm_vm_host::egress_server::should_serve_vsock_egress(
            &cfg.krun.host_listen_ports,
            opt_in || builder_policy_egress,
            has_secrets,
        );
        eprintln!(
            "mvm-libkrun-supervisor: egress startup: tenant_id_present={} host_listen_ports={:?} opt_in={} builder_policy_egress={} has_secrets={} should_serve={}",
            cfg.tenant_id.is_some(),
            cfg.krun.host_listen_ports,
            opt_in,
            builder_policy_egress,
            has_secrets,
            should_serve
        );
        if should_serve {
            let policy: mvm_core::network_policy::NetworkPolicy = cfg
                .network_policy
                .clone()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_else(mvm_core::network_policy::NetworkPolicy::deny_all);
            let gate = mvm_hostd::supervisor::substitution_endpoint::build_egress_gate(&policy);
            let egress_sock = cfg.krun.vsock_socket_path(mvm_guest::vsock::EGRESS_PORT);
            eprintln!(
                "mvm-libkrun-supervisor: egress startup: socket_path={}",
                egress_sock.display()
            );
            // Bind INSIDE the runtime context: `tokio::net::UnixListener::bind`
            // registers the fd with the reactor via `Handle::current()` and panics if
            // no runtime is entered. `dispatch_config` runs on a plain (non-tokio)
            // thread, so create + enter the runtime first, then remove_file + bind,
            // then serve — mirroring the runtime-first pattern in
            // `mvm_hostd::supervisor::gateway_bridge`.
            std::thread::spawn(move || {
                eprintln!("mvm-libkrun-supervisor: egress startup: spawn thread");
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("mvm-libkrun-supervisor: egress runtime: {e}");
                        return;
                    }
                };
                eprintln!("mvm-libkrun-supervisor: egress startup: runtime ready");
                let _guard = rt.enter();
                let _ = std::fs::remove_file(&egress_sock);
                let listener = match tokio::net::UnixListener::bind(&egress_sock) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("mvm-libkrun-supervisor: bind egress socket: {e}");
                        return;
                    }
                };
                eprintln!("mvm-libkrun-supervisor: egress startup: listener bound");
                if let Err(e) = rt.block_on(mvm_vm_host::egress_server::run(listener, gate)) {
                    eprintln!("mvm-libkrun-supervisor: egress server: {e}");
                }
            });
        }
    }

    let outcome = run_legacy(&cfg);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cfg() -> SupervisorConfig {
        SupervisorConfig {
            krun: libkrun_sys::KrunContext::new("vm", "/kernel", "/rootfs"),
            vm_state_dir: "/tmp/vm".into(),
            pid_file_name: None,
            tenant_id: None,
            audit_dir: None,
            gateway_audit_socket: None,
            gateway_events_socket: None,
            signing_key_path: None,
            plan: None,
            bundle: None,
            network_policy: None,
            bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
            transparent_terminator_port: None,
        }
    }

    #[test]
    fn validate_vsock_only_networking_accepts_disconnected_configs() {
        let mut cfg = sample_cfg();
        cfg.tenant_id = Some("tenant-a".into());
        cfg.krun = cfg.krun.with_disconnected_net([0x02, 0, 0, 0, 0, 1]);

        assert!(validate_vsock_only_networking(&cfg).is_ok());
    }

    #[test]
    fn validate_vsock_only_networking_rejects_guest_nic_configs() {
        let mut cfg = sample_cfg();
        cfg.tenant_id = Some("tenant-a".into());
        cfg.krun = cfg
            .krun
            .with_native_gateway([0x02, 0, 0, 0, 0, 1], "/tmp/scratch");

        let err = validate_vsock_only_networking(&cfg).expect_err("guest nic must be rejected");
        assert!(err.to_string().contains("disconnected sink"));
    }

    #[test]
    fn validate_vsock_only_networking_rejects_tsi_configs() {
        let cfg = sample_cfg();

        let err = validate_vsock_only_networking(&cfg).expect_err("tsi must be rejected");
        assert!(err.to_string().contains("disconnected sink"));
    }
}
