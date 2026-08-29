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
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use chrono::Utc;
use libkrun_sys::{
    LogLevel, SupervisorBaseConfig, SupervisorConfig, init_log, run_supervisor, set_log_level,
};
use mvm_core::plan::NonceStore;

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
    // First statement in the process: a panic before this line would
    // print its payload unredacted.
    mvm_hostd::panic_hook::install("libkrun-supervisor");
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

/// Take the exclusive store-image lock this config names, if any, and return
/// the guard whose lifetime is the lock's.
///
/// Only the persistent builder sets it: that VM outlives the command that
/// started it, so the lock has to be held by this process rather than by a CLI
/// that is about to exit. Every one-shot path leaves it `None` and keeps the
/// caller-held arrangement, which is correct there.
///
/// Failure is fatal. The guest is about to attach that image read-write, and
/// booting it while another VM holds the lock is the filesystem corruption the
/// lock exists to prevent.
fn hold_exclusive_image_lock(cfg: &SupervisorConfig) -> Result<Option<std::fs::File>, ExitCode> {
    let Some(lock_path) = cfg.exclusive_image_lock.as_ref() else {
        return Ok(None);
    };
    match mvm_build::builder_vm_runtime::hold_image_lock(
        lock_path,
        mvm_build::builder_vm_runtime::LockWait::from_env(),
    ) {
        Ok(file) => {
            append_supervisor_breadcrumb(
                std::path::Path::new(&cfg.vm_state_dir),
                "image_lock",
                format!("held {}", lock_path.display()),
            );
            Ok(Some(file))
        }
        Err(e) => {
            eprintln!(
                "error: mvm-libkrun-supervisor refusing to boot without the \
                 exclusive store-image lock at {}: {e}",
                lock_path.display()
            );
            Err(ExitCode::from(3))
        }
    }
}

/// Shared tail: given a finalized `SupervisorConfig` (from the legacy stdin
/// decode OR a verified prelaunch attach), bind the workload-exit control
/// listener and route to the bridge/legacy boot path. Extracted so both
/// entrypoints run identical post-config logic.
fn dispatch_config(mut cfg: SupervisorConfig) -> ExitCode {
    apply_egress_relay_override(&mut cfg);

    // Named binding, not `_`: `let _ = ...` would drop the file here and
    // silently unlock the image while the VM runs. This guard has to live as
    // long as this function, which is as long as the VM.
    let _image_lock = match hold_exclusive_image_lock(&cfg) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

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

    // One route. The bridge route existed to splice a packet-inspecting
    // sidecar between the guest's NIC and a userspace gateway; a workload
    // guest has no NIC, so there is nothing for it to sit between.
    let route = if cfg.tenant_id.is_some() {
        "direct_vsock"
    } else {
        "direct"
    };
    append_supervisor_breadcrumb(
        std::path::Path::new(&cfg.vm_state_dir),
        "dispatch_route",
        route.to_string(),
    );

    // The wall-clock bound the plan was admitted under. This process owns the
    // guest for its whole life — `krun_start_enter` blocks below and libkrun
    // exits the process when the guest powers off — so a timer here is the one
    // that can still fire when `mvmctl` is long gone. Held to the end of the
    // scope: dropping the guard stands the timer down.
    let _wall_clock = match mvm_hostd::supervisor::wall_clock::arm_for_supervisor(
        mvm_hostd::supervisor::wall_clock::SupervisorTimerInputs {
            plan_json: cfg.plan.as_ref(),
            audit_dir: cfg.audit_dir.as_deref(),
            signing_key_path: cfg.signing_key_path.as_deref(),
            vm_state_dir: std::path::Path::new(&cfg.vm_state_dir),
        },
    ) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("supervisor: refusing to boot a bounded workload it cannot audit: {e}");
            return ExitCode::from(7);
        }
    };

    // Registered here rather than at the top of `main`: everything above this
    // line refuses to boot, and a refusal has no consumption worth recording.
    // From here on the guest runs, so every way out of this process should
    // leave a reading.
    record_usage_at_exit(std::path::Path::new(&cfg.vm_state_dir));

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

/// Where the exit-time usage reading is written. Set once, immediately before
/// this process enters its VMM run loop, so the paths that refuse to boot leave
/// no record at all — an absent sidecar already reads as "nothing observed",
/// which is the honest answer for a machine that never started.
static USAGE_STATE_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// The `atexit` trampoline. Takes the reading against the directory the run loop
/// was entered for; does nothing if no run loop was ever entered.
///
/// The measurement itself lives in `mvm_hostd::supervisor::self_usage`, which is
/// feature-independent: this binary compiles only under `libkrun-sys`, and a
/// measurement tested only here would be tested in no lane at all.
extern "C" fn record_self_usage_at_exit() {
    if let Some(dir) = USAGE_STATE_DIR.get() {
        mvm_hostd::supervisor::self_usage::record_self_usage(dir);
    }
}

/// Arrange for a usage reading however this process ends.
///
/// There is no "after the run loop returns" here to hang this off: libkrun calls
/// `exit()` on this process from inside `krun_start_enter` when the guest powers
/// off, so no Rust statement following [`run_legacy`] executes on the ordinary
/// path. `atexit` is the hook that still fires there, and one registration also
/// covers the wall-clock kill — which exits `124` from the timer thread, and is
/// precisely the run whose consumption someone will want to read — and the
/// VMM-error return through `main`.
///
/// The SIGTERM handler libkrun installs is the one exit this does not reach: it
/// calls `_exit`, which skips `atexit` by design because nothing in this
/// function is safe to run from a signal handler.
fn record_usage_at_exit(vm_state_dir: &std::path::Path) {
    if USAGE_STATE_DIR.set(vm_state_dir.to_path_buf()).is_ok() {
        // SAFETY: `record_self_usage_at_exit` is an `extern "C"` function taking
        // no arguments and returning nothing, which is the signature `atexit`
        // requires.
        unsafe { libc::atexit(record_self_usage_at_exit) };
    }
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
        append_supervisor_breadcrumb, apply_egress_relay_override, hold_exclusive_image_lock,
    };
    use libkrun_sys::{BridgeRestartPolicy, KrunContext, NetworkingMode, SupervisorConfig};

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
            exclusive_image_lock: None,
        }
    }

    #[test]
    fn an_unset_image_lock_takes_nothing() {
        // Every one-shot path leaves it None: the caller outlives the VM, so
        // caller-held is already correct and the supervisor must not contend
        // for a lock the caller is holding.
        let cfg = sample_cfg(NetworkingMode::VsockDirect, None);
        let guard = hold_exclusive_image_lock(&cfg).expect("no lock named, no failure");
        assert!(guard.is_none());
    }

    #[test]
    fn a_named_image_lock_is_held_for_the_supervisors_life() {
        // The persistent-builder property: this process takes the lock, and
        // nothing else can while it runs.
        let scratch = tempfile::TempDir::new().expect("scratch");
        let lock_path = scratch.path().join("nix-store-aarch64.img.lock");
        let mut cfg = sample_cfg(NetworkingMode::VsockDirect, None);
        cfg.exclusive_image_lock = Some(lock_path.clone());

        let guard = hold_exclusive_image_lock(&cfg)
            .expect("the lock is free")
            .expect("a named lock yields a guard");
        assert!(
            mvm_build::builder_vm_runtime::hold_image_lock(
                &lock_path,
                mvm_build::builder_vm_runtime::LockWait::none()
            )
            .is_err(),
            "the supervisor's guard must exclude every other holder"
        );
        drop(guard);
    }

    #[test]
    fn a_contended_image_lock_refuses_to_boot() {
        // Booting anyway would attach the image read-write behind another VM
        // that is already writing it — the corruption the lock exists to stop.
        let scratch = tempfile::TempDir::new().expect("scratch");
        let lock_path = scratch.path().join("nix-store-aarch64.img.lock");
        let held = mvm_build::builder_vm_runtime::hold_image_lock(
            &lock_path,
            mvm_build::builder_vm_runtime::LockWait::none(),
        )
        .expect("pre-hold the lock");

        let mut cfg = sample_cfg(NetworkingMode::VsockDirect, None);
        cfg.exclusive_image_lock = Some(lock_path);
        // Under cfg(test) the wait budget is fail-fast, so this returns rather
        // than queueing for the hour a real supervisor would wait.
        assert!(
            hold_exclusive_image_lock(&cfg).is_err(),
            "a supervisor that cannot take the lock must refuse to boot"
        );
        drop(held);
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
}
