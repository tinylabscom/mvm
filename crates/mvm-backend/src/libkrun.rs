//! libkrun backend for mvm.
//!
//! Plan 53 §"Plan E" / Sprint 48: Tier 2 microVM backend that runs on
//! Linux KVM and macOS Apple Silicon. The lifecycle
//! delegates to a per-VM `mvm-libkrun-supervisor` subprocess (plan 57
//! W4) rather than calling libkrun in-process: `krun_start_enter` calls
//! `exit()` on the host process when the guest powers off, so any
//! in-process registry would tear down sibling guests. One process per
//! VM scopes the `exit()` to that supervisor and lets the parent
//! `mvmctl` survive a guest shutdown.
//!
//! ## Lifecycle
//!
//! - `start` writes `~/.mvm/vms/<name>/{rootfs.ref,kernel.ref}` runtime
//!   metadata (so `mvmctl console` can find the artifacts), serializes a
//!   [`SupervisorConfig`], spawns `mvm-libkrun-supervisor` with the JSON
//!   on stdin, and waits up to [`PID_FILE_TIMEOUT`] for the supervisor
//!   to write its PID file. Returns once the supervisor is running or
//!   exits with an error if the spawn fails or PID file never appears.
//! - `stop` reads `<vm_state_dir>/libkrun.pid`, sends `SIGTERM`, polls
//!   for the process to exit, and falls back to `SIGKILL` if it doesn't
//!   die within [`STOP_TIMEOUT`].
//! - `status` reads the PID file and probes with `kill(pid, 0)`.
//! - `list` walks `~/.mvm/vms/*/libkrun.pid`.

use anyhow::{Result, anyhow, bail};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage, StartMode, VmBackend,
    VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus,
};

use mvm_base::ui;
use mvm_libkrun::{KrunContext, SupervisorConfig};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// libkrun backend (Linux KVM / macOS Hypervisor.framework).
pub struct LibkrunBackend;

/// How long [`LibkrunBackend::start`] waits for the supervisor to
/// write its PID file before giving up and killing the child.
const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`LibkrunBackend::stop`] waits after `SIGTERM` before
/// escalating to `SIGKILL`. Tight because libkrun's signal handling
/// under `krun_start_enter` is empirically unreliable — when the
/// supervisor is spawned via `std::process::Command` (the production
/// `mvmctl up` path), SIGTERM often doesn't reach the in-supervisor
/// `sigaction` handler before we escalate. The in-supervisor handler
/// (see `mvm_libkrun::install_shutdown_handler`) still helps the
/// shell-stop case where SIGTERM is delivered cleanly (~200 ms); in
/// the always-escalate cargo-spawn / launchd path a shorter timeout
/// means `mvmctl stop` returns in 2 s instead of 5 s.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Default kernel cmdline for libkrun-launched guests.
/// `console=hvc0` matches libkrun's virtio-console wiring (plan 57 W3
/// finding); `root=/dev/vda rw init=/init` matches Apple Container's
/// boot for the same Nix-built rootfs layout.
const DEFAULT_CMDLINE: &str = "console=hvc0 root=/dev/vda rw init=/init";

/// Plan 112 Phase 3c — build the supervisor config for one VM, lifting
/// the audit-substrate resolution into the shared `audit_substrate`
/// module so libkrun and Vz share one source of truth (and the future
/// `NetworkProvider` trait extraction is mechanical).
///
/// **Do not log** `config.plan_json` or `config.bundle_json` — they
/// may carry secret bindings, env vars, or policy refs that resolve
/// to credentials. They're opaque transport bytes; the supervisor
/// re-verifies the signed envelope before trusting any decoded field.
fn build_supervisor_config(config: &VmStartConfig, state_dir: &Path) -> Result<SupervisorConfig> {
    let kernel = config
        .kernel_path
        .as_deref()
        .ok_or_else(|| anyhow!("libkrun backend requires a kernel path"))?;
    let vcpus = u8::try_from(config.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX);
    let krun = KrunContext::new(&config.name, kernel, &config.rootfs_path)
        .with_resources(vcpus, config.memory_mib)
        .with_cmdline(DEFAULT_CMDLINE)
        .with_vsock_socket_dir(state_dir.to_string_lossy().into_owned())
        .add_vsock_port(mvm_guest::vsock::GUEST_AGENT_PORT);
    // Plan 87/88 / ADR-058 — configure the per-OS virtio-net gateway
    // (macOS → gvproxy, Linux → passt), the same default the builder VM
    // uses. TSI was removed (Plan 102 W6.A): it bypasses virtio-net, so
    // the admitted gateway-audit bridge refuses it (claim-10 no-bypass).
    // KrunContext defaults to TSI, so an unconfigured workload would be
    // rejected by `run_supervisor_with_bridge`. The supervisor spawns the
    // gateway from this declared mode.
    let scratch = state_dir.to_string_lossy().into_owned();
    let krun = if cfg!(target_os = "macos") {
        krun.with_gvproxy(mvm_libkrun::gvproxy::DEFAULT_GUEST_MAC, scratch)
    } else {
        krun.with_passt(mvm_libkrun::passt::DEFAULT_GUEST_MAC, scratch)
    };

    // Plan 112 Phase 3c — resolve the audit substrate (paths + tenant
    // validation). When the producer threaded an AdmittedPlan in
    // (`tenant_id` Some), the AuditSubstrate carries the five resolved
    // paths; otherwise it's all-None and the supervisor takes the
    // legacy `run_supervisor` path.
    let substrate =
        crate::audit_substrate::compute_audit_substrate(&config.name, config.tenant_id.as_deref())?;

    // Parse the signed-plan + bundle envelopes from VmStartConfig.
    // mvm_libkrun::SupervisorConfig carries them as Option<serde_json::Value>
    // so the supervisor can re-verify the envelope without depending on
    // mvm-plan at the parse boundary.
    let plan = match config.plan_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| anyhow!("parse VmStartConfig.plan_json as JSON: {e}"))?,
        ),
        None => None,
    };
    let bundle = match config.bundle_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| anyhow!("parse VmStartConfig.bundle_json as JSON: {e}"))?,
        ),
        None => None,
    };

    Ok(SupervisorConfig {
        krun,
        vm_state_dir: state_dir.to_string_lossy().into_owned(),
        pid_file_name: None,
        tenant_id: substrate.tenant_id,
        audit_dir: substrate.audit_dir,
        gateway_audit_socket: substrate.gateway_audit_socket,
        gateway_events_socket: substrate.gateway_events_socket,
        signing_key_path: substrate.signing_key_path,
        plan,
        bundle,
        // Plan 113 §Task 14 / ADR-064 §Decision 6 — only `HardFail` is
        // implemented today. Defaulting here keeps the producer site
        // explicit while a future plan can change the default or
        // introduce policy-driven selection.
        bridge_restart_policy: mvm_libkrun::BridgeRestartPolicy::HardFail,
    })
}

impl VmBackend for LibkrunBackend {
    fn name(&self) -> &str {
        "libkrun"
    }

    fn capabilities(&self) -> VmCapabilities {
        // libkrun does not support memory snapshots (same trade as
        // Apple Container) — vsock and TAP are available; pause/resume
        // is theoretically possible but not exposed by libkrun's public
        // C API today.
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            vsock: true,
            tap_networking: false,
            // libkrun's C API doesn't expose virtio-balloon control
            // today; the upstream crate carries no `.balloon(...)`
            // builder. Declared `false` until wiring lands.
            balloon: false,
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        if !mvm_libkrun::is_available() {
            bail!(
                "libkrun is not installed on this host.\n  {}",
                mvm_libkrun::install_hint()
            );
        }

        // Plan 112 Phase 3c — early kernel-path check. `build_supervisor_config`
        // re-checks too, but this keeps the existing test contract
        // (`libkrun_start_errors_when_kernel_path_missing`) firing before
        // `admit_overlay_aware`'s sidecar check would mask it.
        let _ = config
            .kernel_path
            .as_deref()
            .ok_or_else(|| anyhow!("libkrun backend requires a kernel path"))?;
        let supervisor_path = resolve_supervisor_path()?;
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;

        // W6.2.1: thread the build-time sidecar into per-VM runtime
        // metadata so `mvmctl console` enforces the accessible/sealed
        // gate on libkrun-launched VMs the same way as on the
        // libkrun/Firecracker paths.
        let rootfs = Path::new(&config.rootfs_path);
        // Plan 74 W2 / ADR-051 admission gate — refuse pre-W1.4b
        // rootfs that lack the `/mvm/runtime` mount point. Fires
        // before the supervisor spawn so a refusal leaves no PID
        // file or krun handle behind.
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        mvm_base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;

        let vcpus = u8::try_from(config.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX);
        let cfg = build_supervisor_config(config, &state_dir)?;
        let pid_file = cfg.pid_file();
        // Remove any stale PID file from a previous crashed supervisor
        // so the wait-loop below can detect the new one unambiguously.
        let _ = std::fs::remove_file(&pid_file);

        let json =
            serde_json::to_string(&cfg).map_err(|e| anyhow!("serialize SupervisorConfig: {e}"))?;

        ui::info(&format!(
            "Starting libkrun VM '{}' (cpus={vcpus}, mem={}MiB) via {}...",
            config.name,
            config.memory_mib,
            supervisor_path.display(),
        ));

        // Capture the guest console (hvc0 → supervisor stdout) to a
        // per-VM log so a boot failure / kernel panic is diagnosable
        // (mirrors firecracker.log). Best-effort: fall back to null if
        // the file can't be created.
        let console_log = std::fs::File::create(state_dir.join("console.log"))
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        let mut child = Command::new(&supervisor_path)
            .stdin(Stdio::piped())
            .stdout(console_log)
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor_path.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe SupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file to appear; if the supervisor exits
        // first, surface its status instead of waiting the full
        // timeout.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        loop {
            if pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor child: {e}"))?
            {
                bail!(
                    "supervisor exited before writing PID file (status: {status}). \
                     Check stderr above for libkrun errors."
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "supervisor did not write {} within {:?}; killed",
                    pid_file.display(),
                    PID_FILE_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        ui::success(&format!(
            "libkrun VM '{}' started (pid file: {}).",
            config.name,
            pid_file.display()
        ));
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let pid_path = vm_state_dir(&id.0).join("libkrun.pid");
        let pid = match read_pid(&pid_path) {
            Some(p) => p,
            None => {
                // No PID file: nothing to do, but tell the user so it's
                // not silent. Matches `mvmctl stop` on a never-started
                // VM.
                ui::info(&format!(
                    "libkrun VM '{}' has no PID file at {}; nothing to stop.",
                    id.0,
                    pid_path.display()
                ));
                return Ok(());
            }
        };

        if !pid_alive(pid) {
            ui::info(&format!(
                "libkrun VM '{}' PID {pid} is not running; cleaning up state.",
                id.0
            ));
            let _ = std::fs::remove_file(&pid_path);
            return Ok(());
        }

        // SIGTERM first — gives libkrun a chance to clean up
        // virtio-blk file descriptors. Then SIGKILL if it ignores us.
        send_signal(pid, libc::SIGTERM);
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if !pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if pid_alive(pid) {
            ui::info(&format!(
                "libkrun VM '{}' PID {pid} did not exit after SIGTERM within {STOP_TIMEOUT:?}; sending SIGKILL.",
                id.0
            ));
            send_signal(pid, libc::SIGKILL);
        }

        let _ = std::fs::remove_file(&pid_path);
        ui::success(&format!("libkrun VM '{}' stopped.", id.0));
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let vms = self.list()?;
        let mut last_err = None;
        for vm in vms {
            if let Err(e) = self.stop(&VmId(vm.name.clone())) {
                tracing::warn!(name = vm.name, error = %e, "stop_all: stop failed");
                last_err = Some(e);
            }
        }
        if let Some(e) = last_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        bail!(
            "pause is not supported by the libkrun backend (upstream C API does not expose vCPU pause)"
        )
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        bail!(
            "resume is not supported by the libkrun backend (upstream C API does not expose vCPU pause)"
        )
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let pid_path = vm_state_dir(&id.0).join("libkrun.pid");
        match read_pid(&pid_path) {
            Some(pid) if pid_alive(pid) => Ok(VmStatus::Running),
            _ => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = vms_root();
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let pid_path = path.join("libkrun.pid");
            if !pid_path.exists() {
                // Not a libkrun-managed VM (e.g. Apple Container under
                // the same ~/.mvm/vms/ root).
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue, // skip non-UTF-8 dir names
            };
            let alive = read_pid(&pid_path).is_some_and(pid_alive);
            // The supervisor doesn't surface cpus/memory/ports back to
            // the parent today; W4.3 (the integration-test PR) reads
            // these out of the live VM via a status RPC over vsock.
            // Until then, `list` reports the name + running state and
            // leaves the discoverable-from-runtime fields empty.
            vms.push(VmInfo {
                id: VmId(name.clone()),
                name,
                status: if alive {
                    VmStatus::Running
                } else {
                    VmStatus::Stopped
                },
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            });
        }
        Ok(vms)
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        bail!("libkrun logs not yet implemented for VM '{}'", id.0)
    }

    fn is_available(&self) -> Result<bool> {
        Ok(mvm_libkrun::is_available())
    }

    fn install(&self) -> Result<()> {
        ui::info(&format!(
            "libkrun must be installed via the host's package manager.\n  {}",
            mvm_libkrun::install_hint()
        ));
        // Also surface where we look for the supervisor binary so
        // operators can pre-flight the install before hitting a
        // mid-`mvmctl up` failure.
        match resolve_supervisor_path() {
            Ok(path) => ui::info(&format!("Supervisor binary: {}", path.display())),
            Err(e) => ui::info(&format!("Supervisor binary: NOT FOUND ({e})")),
        }
        Ok(())
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // libkrun exposes vsock as a host-side abstract socket; the
        // guest agent listens on the shared `GUEST_AGENT_PORT` port,
        // identical to Firecracker and Apple Container, so callers can
        // share the same vsock client implementation across backends.
        Ok(GuestChannelInfo::Vsock {
            cid: 3, // standard guest CID
            port: mvm_guest::vsock::GUEST_AGENT_PORT,
        })
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 2: hardware isolation via KVM (Linux) or Hypervisor.framework
        // (macOS). Comparable VMM TCB to Firecracker — libkrun is rust-vmm
        // based, ~80K LOC, no Firecracker-excluded features (so it passes
        // the plan 53 §"fork test"). Claim 3 (verified boot) is partial
        // because the W3 dm-verity pipeline currently targets Firecracker;
        // libkrun support is a follow-up.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1 — host-fs isolation via KVM/HVF
                ClaimStatus::Holds,       // 2 — uid-0 protections same as FC
                ClaimStatus::DoesNotHold, // 3 — verified boot for libkrun rootfs not yet wired
                ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds,       // 5 — vsock framing is fuzzed
                ClaimStatus::Holds,       // 6 — image hash verification
                ClaimStatus::Holds,       // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "Hardware isolation via KVM (Linux) or Hypervisor.framework (macOS).",
                "Comparable VMM TCB to Firecracker; passes plan 53 §\"fork test\".",
                "Claim 3 (verified boot) is partial — dm-verity pipeline targets Firecracker today.",
                "Supported on Linux KVM and macOS Apple Silicon; macOS Intel is not a supported local host.",
            ],
        }
    }
}

// ─── helpers ───────────────────────────────────────────────────────

fn vms_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".mvm/vms")
}

fn vm_state_dir(name: &str) -> PathBuf {
    vms_root().join(name)
}

/// Resolve the absolute path to the `mvm-libkrun-supervisor` binary,
/// checking three sources in order:
///
/// 1. `MVM_LIBKRUN_SUPERVISOR_PATH` — explicit override, used by tests
///    and `cargo run` workflows.
/// 2. A binary named `mvm-libkrun-supervisor` adjacent to the current
///    executable — the layout produced by `cargo install mvm-libkrun`
///    or by a Homebrew bottle that ships `mvmctl` and
///    `mvm-libkrun-supervisor` side-by-side.
/// 3. `PATH` lookup.
///
/// Returns an actionable error if all three fail.
fn resolve_supervisor_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("MVM_LIBKRUN_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "MVM_LIBKRUN_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-libkrun-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Ok(path) = which::which("mvm-libkrun-supervisor") {
        return Ok(path);
    }
    bail!(
        "mvm-libkrun-supervisor binary not found. Looked for: \
         $MVM_LIBKRUN_SUPERVISOR_PATH, alongside the current exe, and on $PATH. \
         Install it via `cargo install --path crates/mvm-libkrun --features libkrun-sys` \
         or set MVM_LIBKRUN_SUPERVISOR_PATH=/abs/path/to/the/binary."
    )
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse::<libc::pid_t>().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    // `kill(pid, 0)` returns 0 if the process exists (and the caller
    // has permission to signal it), -1 with errno=ESRCH if not.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
    unsafe { libc::kill(pid, sig) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libkrun_backend_name() {
        assert_eq!(LibkrunBackend.name(), "libkrun");
    }

    #[test]
    fn libkrun_capabilities() {
        let caps = LibkrunBackend.capabilities();
        assert!(caps.vsock);
        assert!(!caps.snapshots);
        assert!(!caps.pause_resume);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn libkrun_security_profile_is_tier_2_with_partial_claim_3() {
        let profile = LibkrunBackend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        assert!(profile.layer_coverage.is_microvm());
        // Claim 3 (verified boot) is the only partial claim; everything
        // else holds because libkrun matches Firecracker's L2 properties.
        assert_eq!(profile.dropped_claims(), vec![3]);
        assert!(profile.na_claims().is_empty());
    }

    #[test]
    fn build_supervisor_config_maps_substrate_into_supervisor_config() {
        // Plan 112 Phase 3c — when the producer threaded an admitted plan,
        // build_supervisor_config maps the resolved AuditSubstrate fields
        // into SupervisorConfig + parses plan_json/bundle_json as JSON.
        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            tenant_id: Some("acme".into()),
            plan_json: Some("{\"k\":\"v\"}".into()),
            bundle_json: None,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert_eq!(cfg.tenant_id.as_deref(), Some("acme"));
        assert!(cfg.audit_dir.is_some());
        assert!(cfg.gateway_audit_socket.is_some());
        assert!(cfg.gateway_events_socket.is_some());
        assert!(cfg.signing_key_path.is_some());
        assert!(cfg.plan.is_some());
        assert!(cfg.bundle.is_none());
    }

    #[test]
    fn build_supervisor_config_no_tenant_keeps_substrate_none() {
        // Plan 112 Phase 3c — no admission ⇒ all five substrate fields
        // None ⇒ supervisor takes the legacy `run_supervisor` path.
        let config = VmStartConfig {
            name: "dev-vm".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert!(cfg.tenant_id.is_none());
        assert!(cfg.audit_dir.is_none());
        assert!(cfg.gateway_audit_socket.is_none());
        assert!(cfg.gateway_events_socket.is_none());
        assert!(cfg.signing_key_path.is_none());
        assert!(cfg.plan.is_none());
        assert!(cfg.bundle.is_none());
    }

    #[test]
    fn build_supervisor_config_refuses_unsafe_tenant() {
        // Plan 112 Phase 3c — defense-in-depth: tenant_id passes through
        // the DNS-label allowlist in audit_substrate; build_supervisor_config
        // propagates the error.
        let config = VmStartConfig {
            name: "evil-vm".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            tenant_id: Some("../escape".into()),
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        assert!(build_supervisor_config(&config, tmp.path()).is_err());
    }

    #[test]
    fn libkrun_install_message_is_actionable() {
        LibkrunBackend.install().expect("install hint never errors");
        let hint = mvm_libkrun::install_hint();
        assert!(!hint.is_empty());
    }

    #[test]
    fn libkrun_start_errors_when_kernel_path_missing() {
        let config = VmStartConfig {
            name: "libkrun-test".to_string(),
            rootfs_path: "/tmp/rootfs.ext4".to_string(),
            ..Default::default()
        };
        // No kernel_path set → start should fail with a precise message
        // before attempting to spawn the supervisor.
        let err = LibkrunBackend
            .start(&config)
            .expect_err("expected failure without kernel_path");
        let msg = err.to_string();
        assert!(
            msg.contains("kernel path") || msg.contains("not installed"),
            "unexpected error message: {msg}"
        );
    }

    /// A VM with no PID file is `Stopped`. Mirrors what `mvmctl status
    /// <name>` reports for a never-started VM.
    #[test]
    fn libkrun_status_is_stopped_when_no_pid_file() {
        let status = LibkrunBackend
            .status(&VmId("never-started-vm".to_string()))
            .expect("status should not error");
        assert_eq!(status, VmStatus::Stopped);
    }

    /// Serialise env-var mutations across tests in this module —
    /// cargo runs tests in parallel by default, and `std::env::set_var`
    /// is process-global. Without this, a sibling test can flip
    /// `HOME` (or `MVM_LIBKRUN_SUPERVISOR_PATH`) mid-call and corrupt
    /// our assertions. Matches the same pattern in
    /// `mvm_providers::apple_container::macos::tests::with_temp_home`.
    fn with_env<F: FnOnce()>(body: F) {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        // Poisoned guard is fine — earlier panic doesn't taint env
        // for us; we restore explicitly below.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        body();
    }

    /// `list` skips directories under `~/.mvm/vms/` that don't carry a
    /// `libkrun.pid` (e.g. Apple-Container-managed VMs sharing the
    /// same root). Returns an empty list when the root doesn't exist.
    #[test]
    fn libkrun_list_returns_empty_when_no_vms_dir() {
        with_env(|| {
            // Point HOME at a fresh temp dir so we get a known-empty
            // ~/.mvm/vms/ layout.
            let temp = tempfile::tempdir().expect("tempdir");
            let saved = std::env::var_os("HOME");
            // SAFETY: serialised by ENV_LOCK.
            unsafe { std::env::set_var("HOME", temp.path()) };
            let result = LibkrunBackend.list();
            unsafe {
                match saved {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
            let vms = result.expect("list should not error on missing root");
            assert!(vms.is_empty(), "expected empty list, got {vms:?}");
        });
    }

    #[test]
    fn resolve_supervisor_path_honors_env_override() {
        with_env(|| {
            let temp = tempfile::NamedTempFile::new().expect("tempfile");
            // SAFETY: serialised by ENV_LOCK.
            unsafe { std::env::set_var("MVM_LIBKRUN_SUPERVISOR_PATH", temp.path()) };
            let result = resolve_supervisor_path();
            unsafe { std::env::remove_var("MVM_LIBKRUN_SUPERVISOR_PATH") };
            let path = result.expect("env override resolves");
            assert_eq!(path, temp.path());
        });
    }

    #[test]
    fn resolve_supervisor_path_rejects_missing_env_target() {
        with_env(|| {
            // SAFETY: serialised by ENV_LOCK.
            unsafe {
                std::env::set_var(
                    "MVM_LIBKRUN_SUPERVISOR_PATH",
                    "/definitely/does/not/exist/mvm-libkrun-supervisor",
                )
            };
            let result = resolve_supervisor_path();
            unsafe { std::env::remove_var("MVM_LIBKRUN_SUPERVISOR_PATH") };
            let err = result.expect_err("expected missing-file error");
            assert!(err.to_string().contains("not a file"));
        });
    }
}
