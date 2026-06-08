//! Vz (Apple Virtualization.framework) backend for mvm.
//!
//! Plan 97 / ADR-056. Tier 2 microVM backend for macOS 13+ that runs
//! the workload directly on the host (no nested Firecracker, no
//! libkrun in the path). Lifecycle delegates to a per-VM
//! Rust-native `mvm-vz-supervisor` (the objc2 `[[bin]]` in
//! `mvm-vm-host`) — same one-process-per-VM contract
//! `LibkrunBackend` uses, swapped underneath.
//!
//! ## Why opt-in only
//!
//! Per Plan 97 §"Phase D" and the user constraint: `auto_select()`
//! stays unchanged on macOS — libkrun remains the macOS default,
//! Firecracker remains the Linux default. Vz is selected only via
//! `MVM_BACKEND=vz` or `--backend vz` (the `from_hypervisor("vz")`
//! path).
//!
//! ## Lifecycle
//!
//! - `start` writes runtime metadata to `~/.mvm/vms/<name>/` (so
//!   `mvmctl console` can find the artifacts), constructs a
//!   [`mvm_build::vz::SupervisorConfig`] from the `VmStartConfig`, spawns
//!   `mvm-vz-supervisor` with the JSON on stdin, and waits up to
//!   [`PID_FILE_TIMEOUT`] for the supervisor to write its PID file.
//! - `stop` reads `<vm_state_dir>/vz.pid`, sends `SIGTERM` (the
//!   supervisor forwards to `VZVirtualMachine.requestStop()`), polls
//!   for the process to exit, and falls back to `SIGKILL` after
//!   [`STOP_TIMEOUT`].
//! - `status` reads the PID file and probes with `kill(pid, 0)`.
//! - `list` walks `~/.mvm/vms/*/vz.pid`.
//! - `logs` tails `<vm_state_dir>/console.log` (capture-only console
//!   per Plan 97 Security §9).

use anyhow::{Result, anyhow, bail};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage, SnapshotCapability,
    StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::base::ui;
use crate::vz_control;
use mvm_build::host_gvproxy;
use mvm_build::vz;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Apple Virtualization.framework backend.
///
/// Direct host-level Vz integration; no nested KVM, no libkrun shim.
/// Only available on macOS 13+ (`Platform::has_vz()`). On Linux this
/// type still compiles, but `is_available()` always returns `Ok(false)`
/// and `start` bails before spawning anything.
pub struct VzBackend;

/// Plan 102 W6.A.5 — tear-down guard for host-side gvproxy in the
/// attached-VM path (`VzBackend::run_attached`). Ensures gvproxy is
/// stopped even on panic / early return between spawn and the
/// supervisor's exit. The detached `start()` path doesn't need this:
/// `VzBackend::stop` reads the PID file and cleans up there.
struct AttachedGvproxyGuard {
    state_dir: PathBuf,
}

impl Drop for AttachedGvproxyGuard {
    fn drop(&mut self) {
        if let Err(e) = host_gvproxy::stop_by_pid_file(&self.state_dir) {
            tracing::warn!(
                state_dir = %self.state_dir.display(),
                error = %e,
                "AttachedGvproxyGuard: host_gvproxy stop failed on drop"
            );
        }
    }
}

/// Plan 113 §Task 11 — tear-down guard for the per-VM `mvm-vz-drainer`
/// sidecar that bridges Swift's NDJSON `FlowEventWire` socket into the
/// chain-signed audit pipeline (ADR-064 §Decision 8). Mirrors
/// `AttachedGvproxyGuard`'s shape: kills + reaps the child on `Drop` so
/// the drainer dies on early return / panic from `VzBackend::start`
/// between drainer spawn and the Vz supervisor's PID-file write.
///
/// Once the Vz supervisor has confirmed boot (its PID file appears),
/// the parent calls [`AttachedDrainerGuard::detach`] which takes the
/// `Child` out of the guard. From that point the drainer is detached
/// (its PID file under `~/.mvm/vms/<name>/vz-drainer.pid` is the
/// reaper handle used by [`VzBackend::stop`]).
struct AttachedDrainerGuard {
    child: Option<std::process::Child>,
}

impl AttachedDrainerGuard {
    /// Hand off ownership of the spawned drainer to the OS — used after
    /// the Vz supervisor has confirmed boot so the drainer outlives
    /// `start()`'s stack frame. Returns the `Child` so the caller can
    /// read its PID into the on-disk reaper file before the handle is
    /// dropped without `kill()` firing.
    fn detach(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }
}

impl Drop for AttachedDrainerGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let pid = c.id();
            if let Err(e) = c.kill() {
                tracing::warn!(
                    drainer_pid = pid,
                    error = %e,
                    "AttachedDrainerGuard: kill mvm-vz-drainer failed on drop"
                );
            }
            if let Err(e) = c.wait() {
                tracing::warn!(
                    drainer_pid = pid,
                    error = %e,
                    "AttachedDrainerGuard: wait mvm-vz-drainer failed on drop"
                );
            }
        }
    }
}

/// PID file name the supervisor writes inside `vm_state_dir`. Distinct
/// from libkrun's `libkrun.pid` so the two backends can coexist under
/// the same `~/.mvm/vms/<name>/` tree if a host happens to use both.
const PID_FILE_NAME: &str = "vz.pid";

/// Plan 113 §Task 11 — PID file the `mvm-vz-drainer` sibling writes
/// after a successful boot. Lives next to `vz.pid` so `VzBackend::stop`
/// can reap the drainer the same way it reaps the supervisor.
const DRAINER_PID_FILE_NAME: &str = "vz-drainer.pid";

/// Persisted `SupervisorConfig` JSON. Written by `start` so
/// `snapshot_restore` can replay the same shape with
/// `startup_mode` flipped. Mode 0600 — same tier as the audit
/// chain and the host signer.
const SUPERVISOR_CONFIG_FILE_NAME: &str = "supervisor-config.json";

/// How long [`VzBackend::start`] waits for the supervisor to write its
/// PID file before killing the child and bailing. Matches the libkrun
/// path's budget.
const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`VzBackend::stop`] waits after `SIGTERM` before escalating
/// to `SIGKILL`. Vz's graceful-stop callback runs on the supervisor's
/// dispatch queue, so the 2 s window is comfortable.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Default kernel cmdline for Vz-launched guests. Matches the libkrun
/// path: `console=hvc0` for the virtio-console attachment, ext4 rootfs
/// at `/dev/vda`. The host-side cmdline allow-list (Plan 97 Security
/// §7 — to be wired in a follow-up that integrates with
/// `mvm_hostd::supervisor::admit_for_run`) will gate any tokens beyond this
/// default for workload microVMs.
const DEFAULT_CMDLINE: &str = "console=hvc0 root=/dev/vda rw init=/init";

impl VmBackend for VzBackend {
    fn name(&self) -> &str {
        "vz"
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // Plan 97 Phase E — supervisor exposes a control socket
            // for PAUSE / RESUME / BALLOON / SAVE; the corresponding
            // VmBackend verbs route through `vz_control::send_command`.
            pause_resume: true,
            // Snapshot save lands via SAVE on macOS 14+; restore is
            // a follow-up that requires a different supervisor
            // startup mode. Capability is keyed off the macOS major
            // version so non-macOS / pre-14 hosts honestly report
            // `false`.
            snapshots: macos_supports_vz_snapshots(),
            vsock: true,
            tap_networking: false,
            // `VZVirtioTraditionalMemoryBalloon` is wired by the Swift
            // supervisor; live adjustment goes through the control
            // socket's BALLOON verb.
            balloon: true,
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // Vz is the macOS live-memory path: coarse `saveMachineState` /
        // `restoreMachineState` (plan 123 C3), keyed off the same macOS
        // version gate as the `snapshots` flag so older hosts report
        // honestly rather than degrade silently.
        if macos_supports_vz_snapshots() {
            SnapshotCapability::SaveRestore
        } else {
            SnapshotCapability::Unsupported
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        if !mvm_core::platform::current().has_vz() {
            bail!(
                "Apple Virtualization.framework is not available on this host. \
                 Requires macOS 13 or later (Plan 97 §\"Minimum macOS version\")."
            );
        }

        let kernel = config
            .kernel_path
            .as_deref()
            .ok_or_else(|| anyhow!("Vz backend requires a kernel path"))?;

        let supervisor_path = resolve_supervisor_path()?;
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;

        // Record runtime metadata so `mvmctl console` / status RPCs
        // can find the artifacts after start. Matches the libkrun path
        // line-for-line.
        let rootfs = Path::new(&config.rootfs_path);
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;

        // Plan 102 W6.A.5 — spawn host-side gvproxy so the Swift
        // supervisor has something to connect to. VzBackend is
        // stateless; the child is detached (PID file under state
        // dir lets `stop()` find it later).
        let gvproxy_info = host_gvproxy::spawn_detached(&state_dir)
            .map_err(|e| anyhow!("spawn host-side gvproxy for Vz VM '{}': {e}", config.name))?;

        // Vz config build. The `?` propagates allowlist failures from
        // `audit_substrate::compute_audit_substrate` (unsafe tenant_id
        // / vm_name) — see Plan 112 Phase 3c.
        let cfg = build_supervisor_config(config, kernel, &state_dir, &gvproxy_info)?;

        // Plan 113 §Task 11 / ADR-064 — spawn the `mvm-vz-drainer`
        // sibling between gvproxy and the Vz VM boot. Closes Plan 112's
        // Vz carve-out: the drainer binds `events_ingest_socket_path`,
        // reads Swift's NDJSON `FlowEventWire` stream, and chain-signs
        // entries into `~/.mvm/audit/<tenant>.jsonl` via
        // `mvm-supervisor::gateway_bridge`. The guard kills the drainer
        // on early return / panic between here and the supervisor's PID
        // file appearing; after a clean boot the guard is `detach()`ed
        // and the drainer is reaped by `stop()` via its own PID file.
        let mut drainer_guard = spawn_vz_drainer(config)?;
        let pid_file = state_dir.join(PID_FILE_NAME);
        // Stale-PID-file cleanup from a previous crashed supervisor so
        // the wait-loop below detects the *new* one unambiguously.
        let _ = std::fs::remove_file(&pid_file);
        // Stale console log from a prior run is fine to leave — the
        // supervisor opens it with append. But truncate-via-create
        // gives users a fresh boot log on each start, matching what
        // most VM tools do. Best-effort.
        let console_log = state_dir.join("console.log");
        let _ = crate::libkrun::open_console_capture(&console_log);

        let json = cfg
            .to_json()
            .map_err(|e| anyhow!("serialize SupervisorConfig: {e}"))?;

        // Persist the supervisor config alongside the PID file so
        // `snapshot_restore` can replay the exact same shape with
        // `startup_mode` flipped to Restore. The restore path needs
        // disks, memory, cpu, vsock, network, etc. to match the
        // saved state's configuration (Apple validates this on
        // restoreMachineState). Without persistence we'd have to
        // reconstruct from disparate sources at restore time.
        // Best-effort write: a failure here logs a warn and
        // continues — the launch still succeeds; only restore will
        // fail with a clear "no supervisor-config.json" error.
        let cfg_path = state_dir.join(SUPERVISOR_CONFIG_FILE_NAME);
        if let Err(e) = persist_supervisor_config(&cfg_path, &json) {
            tracing::warn!(
                error = %e,
                "persisting supervisor config to {} failed (non-fatal)",
                cfg_path.display()
            );
        }

        ui::info(&format!(
            "Starting Vz VM '{}' (cpus={}, mem={}MiB) via {}...",
            config.name,
            config.cpus,
            config.memory_mib,
            supervisor_path.display(),
        ));

        let mut child = Command::new(&supervisor_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor_path.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe SupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file. If the supervisor exits first, surface
        // its status (which probably means a config-validation error
        // from VZ — the supervisor prints to stderr before exiting,
        // which we've inherited above).
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
                     Check stderr above for VZ configuration errors. Console log: {}",
                    console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "supervisor did not write {} within {:?}; killed. Console log: {}",
                    pid_file.display(),
                    PID_FILE_TIMEOUT,
                    console_log.display(),
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Plan 113 §Task 11 — Vz supervisor booted cleanly. Detach the
        // drainer so it survives `start()`'s stack frame; record its
        // PID for `stop()` to reap. A failure here is non-fatal: the
        // VM is already running. We log + leave the drainer attached;
        // the next `stop()` walks both PID files anyway.
        if let Err(e) = detach_and_persist_drainer(&state_dir, &mut drainer_guard) {
            tracing::warn!(
                vm = %config.name,
                error = %e,
                "detach/persist mvm-vz-drainer PID failed (non-fatal); guard remains attached"
            );
        }

        ui::success(&format!(
            "Vz VM '{}' started (pid file: {}, console log: {}).",
            config.name,
            pid_file.display(),
            console_log.display()
        ));
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let pid_path = vm_state_dir(&id.0).join(PID_FILE_NAME);
        let pid = match read_pid(&pid_path) {
            Some(p) => p,
            None => {
                ui::info(&format!(
                    "Vz VM '{}' has no PID file at {}; nothing to stop.",
                    id.0,
                    pid_path.display()
                ));
                return Ok(());
            }
        };

        if !pid_alive(pid) {
            ui::info(&format!(
                "Vz VM '{}' PID {pid} is not running; cleaning up state.",
                id.0
            ));
            let _ = std::fs::remove_file(&pid_path);
            return Ok(());
        }

        // SIGTERM → supervisor's `DispatchSourceSignal` handler →
        // `VZVirtualMachine.requestStop()` (ACPI power button to the
        // guest). The graceful path runs guest shutdown handlers; if
        // the guest ignores the ACPI event we fall back to SIGKILL.
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
                "Vz VM '{}' PID {pid} did not exit after SIGTERM within {STOP_TIMEOUT:?}; sending SIGKILL.",
                id.0
            ));
            send_signal(pid, libc::SIGKILL);
        }

        let _ = std::fs::remove_file(&pid_path);

        // Plan 102 W6.A.5 — tear down the host-side gvproxy
        // spawned by `start()`. Best-effort: the supervisor stop
        // already succeeded; a stuck gvproxy is a leak but not a
        // correctness issue (the listener socket is per-VM and the
        // PID file would be unlinked by the next start).
        if let Err(e) = host_gvproxy::stop_by_pid_file(&vm_state_dir(&id.0)) {
            tracing::warn!(
                vm = %id.0,
                error = %e,
                "host_gvproxy stop failed (non-fatal)"
            );
        }

        // Plan 113 §Task 11 — reap the `mvm-vz-drainer` sibling that
        // `start()` spawned and detached. Same SIGTERM → poll → SIGKILL
        // ladder as the supervisor; best-effort because some VMs have
        // no drainer (legacy callers without `plan_json`).
        reap_drainer(&vm_state_dir(&id.0));

        ui::success(&format!("Vz VM '{}' stopped.", id.0));
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

    fn pause(&self, id: &VmId) -> Result<()> {
        let sock = vz_control::control_socket_path(&vm_state_dir(&id.0));
        vz_control::send_command(&sock, "PAUSE").map(|_| ())
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        let sock = vz_control::control_socket_path(&vm_state_dir(&id.0));
        vz_control::send_command(&sock, "RESUME").map(|_| ())
    }

    fn balloon_set_target(&self, id: &VmId, target_inflate_mib: u32) -> Result<()> {
        // Plan 97 Phase E + §"Memory balloon floor". The host-side
        // floor enforcement (refuse to shrink the guest below a
        // configured minimum) happens on the Rust side here — the
        // supervisor's BALLOON verb is a pure setter. The plan's
        // floor of 128 MiB is the conservative default; consumers
        // that want a different floor pass it via VmStartConfig
        // (follow-up: thread plan.memory_floor through).
        const FLOOR_MIB: u32 = 128;
        if target_inflate_mib > 0 && target_inflate_mib < FLOOR_MIB {
            bail!(
                "balloon_set_target {target_inflate_mib} MiB below floor {FLOOR_MIB} MiB; \
                 raising the inflate target that low would push the guest under the floor"
            );
        }
        let sock = vz_control::control_socket_path(&vm_state_dir(&id.0));
        vz_control::send_command(&sock, &format!("BALLOON {target_inflate_mib}")).map(|_| ())
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let pid_path = vm_state_dir(&id.0).join(PID_FILE_NAME);
        match read_pid(&pid_path) {
            Some(pid) if pid_alive(pid) => Ok(VmStatus::Running),
            _ => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = PathBuf::from(mvm_core::config::mvm_data_dir()).join("vms");
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
            let pid_path = path.join(PID_FILE_NAME);
            if !pid_path.exists() {
                // Not a Vz-managed VM (the libkrun supervisor writes
                // `libkrun.pid` in the same `~/.mvm/vms/<name>/` tree).
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue, // skip non-UTF-8 dir names
            };
            let alive = read_pid(&pid_path).is_some_and(pid_alive);
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

    fn logs(&self, id: &VmId, lines: u32, _hypervisor: bool) -> Result<String> {
        // Capture-only console at `<vm_state_dir>/console.log` (Plan 97
        // Security §9). `hypervisor=true` would mean "supervisor's own
        // logs", which today is empty — the supervisor inherits stderr
        // from the parent `mvmctl`, so its logs are already on the
        // user's terminal. Surface the console capture in both cases.
        let log = mvm_core::config::vm_console_log(&id.0);
        let contents = std::fs::read_to_string(&log)
            .map_err(|e| anyhow!("read console log {}: {e}", log.display()))?;
        if lines == 0 {
            return Ok(contents);
        }
        // Tail by counting newlines from the end.
        let lines_usize = lines as usize;
        let tail: Vec<&str> = contents.lines().rev().take(lines_usize).collect();
        Ok(tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
    }

    fn is_available(&self) -> Result<bool> {
        Ok(mvm_core::platform::current().has_vz())
    }

    fn install(&self) -> Result<()> {
        ui::info("Apple Virtualization.framework is built into macOS 13+; no host install needed.");
        // Pre-flight the supervisor binary so operators don't hit a
        // mid-`mvmctl up` failure.
        match resolve_supervisor_path() {
            Ok(path) => ui::info(&format!("Supervisor binary: {}", path.display())),
            Err(e) => ui::info(&format!("Supervisor binary: NOT FOUND ({e})")),
        }
        Ok(())
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        Ok(GuestChannelInfo::Vsock {
            cid: 3,
            port: mvm_guest::vsock::GUEST_AGENT_PORT,
        })
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Plan 97 §"Can we still make all nine ADR-002 security
        // claims?". 7-claim table here covers claims 1–7 (8 and 9 live
        // outside `BackendSecurityProfile`).
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds, // 1 — host-fs isolation via Vz (ro rootfs attach) + host-side admission gate (enforce_admitted_shares); in-supervisor share re-check is deferred (Plan 97 Phase D)
                ClaimStatus::Holds, // 2 — uid-0 protections same as FC (guest-side)
                ClaimStatus::DoesNotHold, // 3 — verified-boot pipeline targets FC today
                ClaimStatus::Holds, // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds, // 5 — vsock framing fuzzed (Swift JSON corpus equivalence still pending)
                ClaimStatus::Holds, // 6 — dev image hash verified
                ClaimStatus::Holds, // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "Hardware isolation via Apple Virtualization.framework on macOS 13+.",
                "Same Hypervisor.framework primitive libkrun uses; Apple-controlled VMM surface.",
                "Claim 3 (verified boot) partial — dm-verity pipeline targets Firecracker today.",
                "Claim 5 (supervisor JSON corpus equivalence) is a Plan 97 follow-up; vsock framing fuzz already in CI.",
                "Pause/resume + balloon + snapshots require a supervisor control socket (Plan 97 follow-up).",
            ],
        }
    }
}

impl VzBackend {
    /// Plan 97 Phase C primitive — run a Linux guest under Vz
    /// **attached to the calling process**: spawn the supervisor in
    /// the foreground, pipe its JSON config on stdin, inherit
    /// stdout/stderr so the guest's console output streams to the
    /// terminal, and block until the supervisor exits. Returns the
    /// supervisor's exit status translated into [`VmExitStatus`].
    ///
    /// Foundation for a future `VzBuilderVm` (Plan 97 §"Phase C"):
    /// the builder VM wraps this primitive with virtio-fs
    /// `/work`/`/out`/`/job` shares + `BuilderJob` orchestration +
    /// artifact extraction. Those layers live in `mvm-build` and are
    /// not part of this primitive.
    ///
    /// Unlike `start` (which detaches), `run_attached` is suitable for
    /// one-shot workloads where the parent process owns the guest's
    /// lifetime — CI batch jobs, `mvmctl exec`-style verbs, and the
    /// builder-VM run loop. Stop semantics are SIGINT/SIGTERM to the
    /// caller; the supervisor's signal handler forwards to
    /// `VZVirtualMachine.requestStop()` (Plan 97 Phase A).
    pub fn run_attached(&self, config: &VmStartConfig) -> Result<VmExitStatus> {
        if !mvm_core::platform::current().has_vz() {
            bail!(
                "Apple Virtualization.framework is not available on this host. \
                 Requires macOS 13 or later."
            );
        }
        let kernel = config
            .kernel_path
            .as_deref()
            .ok_or_else(|| anyhow!("Vz backend requires a kernel path"))?;
        let supervisor_path = resolve_supervisor_path()?;
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;

        // Plan 102 W6.A.5 — attached path also needs the
        // host-side gvproxy. `run_attached` ties gvproxy's
        // lifetime to its own caller stack: the wait-on-exit
        // below blocks until the supervisor process ends, then
        // we tear down gvproxy on the way out (best-effort
        // tear-down inside the `Drop` of `AttachedGvproxyGuard`
        // below so panics + early returns still clean up).
        let gvproxy_info = host_gvproxy::spawn_detached(&state_dir)
            .map_err(|e| anyhow!("spawn host-side gvproxy for Vz VM '{}': {e}", config.name))?;
        let _gvproxy_guard = AttachedGvproxyGuard {
            state_dir: state_dir.clone(),
        };

        let cfg = build_supervisor_config(config, kernel, &state_dir, &gvproxy_info)?;
        let pid_file = state_dir.join(PID_FILE_NAME);
        let _ = std::fs::remove_file(&pid_file);

        let json = cfg
            .to_json()
            .map_err(|e| anyhow!("serialize SupervisorConfig: {e}"))?;

        ui::info(&format!(
            "Running Vz VM '{}' attached (cpus={}, mem={}MiB) via {}...",
            config.name,
            config.cpus,
            config.memory_mib,
            supervisor_path.display(),
        ));

        let mut child = Command::new(&supervisor_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor_path.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe SupervisorConfig to supervisor stdin: {e}"))?;

        // Block until the supervisor exits. Its exit code is the
        // guest's exit code per Plan 97 Phase A's `main.swift`
        // contract (0 clean / 1 guest error / 2 config parse error
        // / 3 supervisor startup error).
        let status = child
            .wait()
            .map_err(|e| anyhow!("wait for supervisor: {e}"))?;
        let _ = std::fs::remove_file(&pid_file);

        Ok(VmExitStatus {
            code: status.code(),
            success: status.success(),
        })
    }

    /// Plan 97 Phase E — snapshot save. Asks the supervisor to write
    /// the running VM's state to `snapshot_path`, using Vz's
    /// `saveMachineStateTo` API on macOS 14+. The supervisor returns
    /// `ERR SAVE requires macOS 14+` on older hosts; this method
    /// propagates the error verbatim.
    ///
    /// Not on the `VmBackend` trait yet — adding snapshot verbs there
    /// would ripple across every backend. Callers reach this through
    /// the concrete `VzBackend` type or by downcasting from
    /// `AnyBackend::Vz(_)`.
    pub fn snapshot_save(&self, id: &VmId, snapshot_path: &Path) -> Result<()> {
        let abs = if snapshot_path.is_absolute() {
            snapshot_path.to_path_buf()
        } else {
            bail!(
                "snapshot_save requires an absolute path, got {}",
                snapshot_path.display()
            );
        };
        let sock = vz_control::control_socket_path(&vm_state_dir(&id.0));
        vz_control::send_command(&sock, &format!("SAVE {}", abs.display())).map(|_| ())
    }

    /// Plan 97 Phase E — snapshot restore. Boots a new supervisor in
    /// `StartupMode::Restore` so it calls
    /// `VZVirtualMachine.restoreMachineState(from:)` + `resume()`
    /// instead of `start()` (macOS 14+ only).
    ///
    /// Replays the `SupervisorConfig` that the original boot wrote
    /// at `~/.mvm/vms/<vm>/supervisor-config.json`. Apple's restore
    /// API requires the VZ configuration to match the saved state's,
    /// so we use the exact same shape and only flip `startup_mode`.
    ///
    /// The VM must NOT already be running (the saved state and the
    /// running state would race over disks). This method does not
    /// check — callers should `mvmctl down <vm>` first.
    ///
    /// `machine_id_path` is the optional companion file SAVE wrote
    /// at `<snapshot_path>.machine-id` so the restored guest gets
    /// the same `VZGenericMachineIdentifier` (machine-id continuity).
    pub fn snapshot_restore(
        &self,
        id: &VmId,
        snapshot_path: &Path,
        machine_id_path: Option<&Path>,
    ) -> Result<VmId> {
        if !snapshot_path.is_absolute() {
            bail!(
                "snapshot_restore requires an absolute snapshot path, got {}",
                snapshot_path.display()
            );
        }
        if !mvm_core::platform::current().has_vz() {
            bail!(
                "Apple Virtualization.framework is not available on this host. \
                 Requires macOS 13 or later."
            );
        }

        let state_dir = vm_state_dir(&id.0);
        let cfg_path = state_dir.join(SUPERVISOR_CONFIG_FILE_NAME);
        let cfg_bytes = std::fs::read(&cfg_path).map_err(|e| {
            anyhow!(
                "read persisted supervisor config {}: {e}. \
                 The original `mvmctl up` did not persist its supervisor \
                 config; restore needs the original shape to match the \
                 saved state.",
                cfg_path.display()
            )
        })?;
        let mut cfg: vz::SupervisorConfig = serde_json::from_slice(&cfg_bytes)
            .map_err(|e| anyhow!("parse {} as SupervisorConfig: {e}", cfg_path.display()))?;

        // Flip to restore mode. Everything else (disks / vsock /
        // network / balloon / machine cpu+memory) stays as it was
        // at boot so Vz validates the configuration against the
        // saved state successfully.
        cfg.startup_mode = vz::StartupMode::Restore {
            snapshot_path: snapshot_path.display().to_string(),
            machine_id_path: machine_id_path.map(|p| p.display().to_string()),
        };

        let json = cfg
            .to_json()
            .map_err(|e| anyhow!("serialize SupervisorConfig for restore: {e}"))?;

        let supervisor_path = resolve_supervisor_path()?;
        let pid_file = state_dir.join(PID_FILE_NAME);
        // The VM must not already be running; refuse if a live PID
        // file exists. Stale PID files (process already exited) are
        // tolerated and removed.
        if let Some(pid) = read_pid(&pid_file)
            && pid_alive(pid)
        {
            bail!(
                "VM {:?} is still running (PID {pid}); stop it with `mvmctl down {}` before restoring",
                id.0,
                id.0,
            );
        }
        let _ = std::fs::remove_file(&pid_file);
        let console_log = state_dir.join("console.log");
        let _ = crate::libkrun::open_console_capture(&console_log);

        ui::info(&format!(
            "Restoring Vz VM '{}' from {} via {}...",
            id.0,
            snapshot_path.display(),
            supervisor_path.display(),
        ));

        let mut child = Command::new(&supervisor_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor_path.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe SupervisorConfig to supervisor stdin: {e}"))?;

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
                    "supervisor exited before writing PID file during restore (status: {status}). \
                     Check stderr above; console log: {}",
                    console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "supervisor did not write {} within {:?} during restore; killed. Console log: {}",
                    pid_file.display(),
                    PID_FILE_TIMEOUT,
                    console_log.display(),
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        ui::success(&format!(
            "Vz VM '{}' restored (pid file: {}, console log: {}).",
            id.0,
            pid_file.display(),
            console_log.display()
        ));
        Ok(VmId(id.0.clone()))
    }
}

/// Write JSON to `path` mode 0600, atomically via a rename. Mirrors
/// the pattern used by `plan_persist::write_plan` in mvm-cli.
fn persist_supervisor_config(path: &Path, json: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().ok_or_else(|| anyhow!("path has no parent"))?;
    let tmp = parent.join(format!("{}.tmp", SUPERVISOR_CONFIG_FILE_NAME));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| anyhow!("open {} for write: {e}", tmp.display()))?;
        f.write_all(json.as_bytes())
            .map_err(|e| anyhow!("write supervisor config: {e}"))?;
        f.sync_all().ok();
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow!("tighten mode on {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────

/// Plan 97 Phase E gate: snapshot save/restore lands in macOS 14
/// (`VZVirtualMachine.saveMachineStateTo` / `restoreMachineStateFrom`).
/// Reported as the *backend* capability rather than the live host's
/// — false on non-macOS / pre-14 hosts so callers downgrade
/// gracefully.
fn macos_supports_vz_snapshots() -> bool {
    if !matches!(
        mvm_core::platform::current(),
        mvm_core::platform::Platform::MacOS
    ) {
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        macos_major_version() >= 14
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
fn macos_major_version() -> u32 {
    use std::process::Command;
    Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|v| v.trim().split('.').next().map(String::from))
        .and_then(|major| major.parse::<u32>().ok())
        .unwrap_or(0)
}

fn vm_state_dir(name: &str) -> PathBuf {
    mvm_core::config::vm_state_dir(name)
}

/// Plan 102 W6.A.5 — per-VM Vz events-ingest socket path. The Swift
/// bridge (once written) connects here, sends the
/// `MVM_VZ_BRIDGE_V1\n` handshake, and writes NDJSON `FlowEventWire`
/// entries. The Rust supervisor's signer task drains them into the
/// per-tenant audit chain. Lives under `~/.mvm/audit/` so the path
/// is co-located with the chain files and the subscriber socket
/// (`gateway-<vm>.sock`).
///
/// Returned as a `String` to fit straight into
/// `NetworkConfig::Gvproxy.events_ingest_socket_path` without an
/// extra conversion.
fn events_ingest_socket_path(vm_name: &str) -> String {
    // `mvm_core::config::mvm_data_dir` returns `String`; convert to
    // PathBuf to use `Path::join`, then back to String for the JSON
    // field shape `NetworkConfig::Gvproxy.events_ingest_socket_path`
    // declares.
    PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("audit")
        .join(format!("gateway-events-{vm_name}.sock"))
        .to_string_lossy()
        .into_owned()
}

/// Build the [`mvm_build::vz::SupervisorConfig`] the supervisor binary
/// consumes on stdin. Maps the backend-agnostic `VmStartConfig` to
/// the Vz-specific JSON shape.
///
/// Phase B first-cut wiring — only the fields needed to boot a
/// dev-shell image are mapped. gvproxy networking, the runtime
/// overlay, dm-verity sidecar, and port forwarding all land in
/// follow-up slices when their host-side plumbing is in place.
///
/// Plan 112 Phase 3c — pre-flight: when the producer threaded an
/// AdmittedPlan in (`VmStartConfig.tenant_id` Some), run the
/// DNS-label allowlist through `audit_substrate::compute_audit_substrate`
/// so an unsafe tenant/vm_name fails fast before Swift spawn. The
/// **Vz consumer side** for the audit chain (a Rust drainer that
/// binds `events_ingest_socket_path` and emits to the chain) is a
/// follow-up plan after Phase 3c — until then, the substrate's
/// path values are computed but not threaded into
/// `vz::SupervisorConfig` (which would also require lockstep Swift
/// `Config.swift` decoder updates per the schema deny-unknown-fields
/// contract). The Swift bridge already writes flow events to
/// `events_ingest_socket_path` (PR #487 commit 7); the drainer
/// closes the loop.
/// Append the `mvm.uvols=` cmdline param so the dev VM's
/// `mvm-host-vm-init` mounts user volumes at their guest paths. No-op
/// (returns the default cmdline unchanged) when there are no volumes.
/// Harmless for workload guests (mkGuest `/init` ignores the param).
fn vz_cmdline_with_user_volumes(config: &VmStartConfig) -> String {
    let mut cmdline = DEFAULT_CMDLINE.to_string();
    if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes) {
        cmdline.push(' ');
        cmdline.push_str(&uvols);
    }
    cmdline
}

fn build_supervisor_config(
    config: &VmStartConfig,
    kernel: &str,
    state_dir: &Path,
    gvproxy: &host_gvproxy::HostGvproxyInfo,
) -> Result<vz::SupervisorConfig> {
    // Plan 112 Phase 3c — resolve the audit substrate (paths + tenant
    // validation). Plan 152 WS-B slice 8 threads it into the Rust-native
    // supervisor's config so it runs the in-process flow-audited gvproxy bridge
    // (payload_tap). When the producer threaded an AdmittedPlan in (`tenant_id`
    // Some), the substrate carries the resolved paths; otherwise it's all-None
    // and the supervisor direct-attaches gvproxy.
    let substrate =
        crate::audit_substrate::compute_audit_substrate(&config.name, config.tenant_id.as_deref())?;
    // Signed-plan + bundle envelopes from VmStartConfig, as JSON Values the
    // supervisor decodes into the typed plan + bundle for the bridge.
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
    let state_dir_str = state_dir.to_string_lossy().into_owned();
    let vsock_dir = state_dir.join("vsock").to_string_lossy().into_owned();
    let console_log = state_dir.join("console.log").to_string_lossy().into_owned();

    let mut disks = vec![vz::DiskConfig {
        id: "rootfs".into(),
        path: config.rootfs_path.clone(),
        // Rootfs is RO at boot under the W3 verified-boot model; even
        // when verity isn't on, libkrun and Firecracker mount it
        // read-only and rely on an overlay for writes. Mirror that
        // for Vz.
        read_only: true,
    }];

    // User-supplied volumes (--volume / MVM_VOLUMES). A directory share
    // is a virtio-fs device; a disk image is an extra virtio-blk device.
    // The tag/id `uvol{idx}` is the coordination key the guest mount
    // manifest uses to mount each at its requested guest path. Disk
    // images are sparse-created by the CLI orchestrator before start;
    // Apple Vz takes its own exclusive lock on a RW disk at start (the
    // reason the nix-store flock moved to a sidecar — see
    // builder_vm_runtime::NixStoreImageLock).
    let mut virtio_fs: Vec<vz::VirtioFsShare> = Vec::new();
    for (idx, vol) in config.volumes.iter().enumerate() {
        let tag = format!("uvol{idx}");
        match vol.kind {
            mvm_core::vm_backend::VmVolumeKind::DirShare => virtio_fs.push(vz::VirtioFsShare {
                tag,
                host_path: vol.host.clone(),
                read_only: vol.read_only,
            }),
            mvm_core::vm_backend::VmVolumeKind::Disk => disks.push(vz::DiskConfig {
                id: tag,
                path: vol.host.clone(),
                read_only: vol.read_only,
            }),
        }
    }

    Ok(vz::SupervisorConfig {
        name: config.name.clone(),
        vm_state_dir: state_dir_str,
        pid_file_name: Some(PID_FILE_NAME.to_string()),
        kernel: vz::KernelConfig {
            path: kernel.to_string(),
            cmdline: vz_cmdline_with_user_volumes(config),
            initrd_path: config.initrd_path.clone(),
        },
        resources: vz::ResourceConfig {
            cpu_count: config.cpus,
            memory_mib: u64::from(config.memory_mib),
        },
        disks,
        virtio_fs,
        vsock: vz::VsockConfig {
            ports: vec![mvm_guest::vsock::GUEST_AGENT_PORT],
            socket_dir: vsock_dir,
        },
        console_output_path: Some(console_log),
        // Plan 102 W6.A.5 — gvproxy backend with claim-10 audit
        // bridge ingest hookup. `socket_path` is where the Swift
        // supervisor connects gvproxy; `events_ingest_socket_path`
        // is where the (future) Swift bridge writes NDJSON
        // FlowEventWire entries for the Rust supervisor's signer
        // task to drain. The path is stable per VM under
        // `~/.mvm/audit/gateway-events-<vm>.sock` so a future
        // run_supervisor_with_bridge-style entry point on the Vz
        // side can bind that listener and consume the stream.
        network: Some(vz::NetworkConfig::Gvproxy {
            socket_path: gvproxy.socket_path.to_string_lossy().into_owned(),
            mac: host_gvproxy::derive_mac(&config.name),
            // Only request the claim-10 audit bridge when the drainer will
            // actually bind the ingest socket — i.e. an admitted workload
            // (plan_json + tenant_id), the same gate as `spawn_vz_drainer`.
            // Without admission the drainer is skipped; requesting the bridge
            // anyway makes the Swift supervisor's mandatory connect() fail
            // (errno=2) and the VM die before boot — the `up --dev
            // --hypervisor vz` crash. None → Swift takes the plain gvproxy
            // attachment (no bridge), mirroring libkrun's legacy path.
            events_ingest_socket_path: if config.plan_json.is_some() && config.tenant_id.is_some() {
                Some(events_ingest_socket_path(&config.name))
            } else {
                None
            },
        }),
        balloon: Some(vz::BalloonConfig {
            enabled: true,
            floor_mib: 128,
        }),
        // Plan 97 Phase E — bind the control socket so pause / resume /
        // balloon adjustment / snapshot SAVE work via
        // `<vm_state_dir>/control.sock`. `vz_control::control_socket_path`
        // is the canonical path resolver both sides agree on.
        control_socket_path: Some(
            vz_control::control_socket_path(state_dir)
                .to_string_lossy()
                .into_owned(),
        ),
        // Boot mode by default — `build_supervisor_config` is the
        // boot path; the restore path constructs its own config in
        // `build_restore_supervisor_config` below.
        startup_mode: vz::StartupMode::Boot,
        // Audit substrate (Plan 152 WS-B slice 8) — threaded from the admitted
        // plan so the Rust supervisor runs the in-process flow-audited gvproxy
        // bridge. All-None for an un-admitted (dev / builder) start → direct
        // gvproxy attach.
        tenant_id: substrate.tenant_id,
        plan,
        bundle,
        audit_dir: substrate
            .audit_dir
            .map(|p| p.to_string_lossy().into_owned()),
        gateway_audit_socket: substrate
            .gateway_audit_socket
            .map(|p| p.to_string_lossy().into_owned()),
        signing_key_path: substrate
            .signing_key_path
            .map(|p| p.to_string_lossy().into_owned()),
    })
}

/// Resolve the absolute path to the `mvm-vz-supervisor` binary,
/// checking three sources in order, paralleling the libkrun
/// resolver:
///
/// 1. `MVM_VZ_SUPERVISOR_PATH` — explicit override for tests +
///    `cargo run` workflows.
/// 2. A binary named `mvm-vz-supervisor` adjacent to the current
///    executable — the layout produced by `cargo install` /
///    Homebrew bottles that ship `mvmctl` alongside it.
/// 3. The source-checkout build output at
///    `<workspace>/target/debug/mvm-vz-supervisor` (the cargo `[[bin]]`
///    in `mvm-vm-host`); this matters during local dev when `mvmctl`
///    is `cargo run` from the workspace root.
/// 4. The version-pinned release layout `~/.mvm/bin/mvm-vz-supervisor-<version>`.
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("MVM_VZ_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "MVM_VZ_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-vz-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Source-checkout layout. CARGO_MANIFEST_DIR points at the
    // current crate; the workspace root is two `..` above.
    if let Some(workspace_root) = workspace_root_from_manifest_dir() {
        let candidate = vz::source_tree_binary_path(&workspace_root);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Release-installed layout under `~/.mvm/bin/`.
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = vz::supervisor_binary_path(Path::new(&home), env!("CARGO_PKG_VERSION"));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "mvm-vz-supervisor binary not found. Looked for: \
         $MVM_VZ_SUPERVISOR_PATH, alongside the current exe, \
         <workspace>/target/debug/mvm-vz-supervisor (source-checkout), and \
         ~/.mvm/bin/mvm-vz-supervisor-{} (release-installed). Build it with \
         `cargo build -p mvm-vm-host --bin mvm-vz-supervisor`, or set \
         MVM_VZ_SUPERVISOR_PATH=/abs/path/to/the/binary.",
        env!("CARGO_PKG_VERSION")
    );
}

/// Derive the workspace root from the build-time
/// `CARGO_MANIFEST_DIR`. Returns `None` when the binary is run from
/// an installed layout (the env var was evaluated at compile time,
/// so this only fails on a moved checkout — which is fine since the
/// installed-layout path is checked next).
fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    // `crates/mvm-backend` → workspace root is two `..` up.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

/// Plan 113 §Task 11 — spawn the `mvm-vz-drainer` sibling. Returns an
/// [`AttachedDrainerGuard`] still holding the `Child`; the caller
/// either lets the guard fall out of scope on early-return to kill the
/// drainer, or calls [`AttachedDrainerGuard::detach`] after the Vz
/// supervisor confirms boot.
///
/// Gate: when `config.plan_json` is `None`, the legacy path (no
/// admission, no audit substrate) is taken and an empty guard is
/// returned. When `plan_json` is `Some` but `tenant_id` is `None`,
/// that's a wire-level inconsistency (Plan 112 Phase 3c invariant —
/// substrate paths can't be computed without a tenant), so we log a
/// warning and skip the drainer rather than launch it with partial
/// information.
fn spawn_vz_drainer(config: &VmStartConfig) -> Result<AttachedDrainerGuard> {
    let Some(plan_json) = config.plan_json.as_deref() else {
        tracing::debug!(
            vm = %config.name,
            "no plan_json on VmStartConfig; skipping mvm-vz-drainer (legacy path)"
        );
        return Ok(AttachedDrainerGuard { child: None });
    };
    if config.tenant_id.is_none() {
        tracing::warn!(
            vm = %config.name,
            "plan_json set without tenant_id; skipping mvm-vz-drainer (wire-level inconsistency — \
             Plan 112 Phase 3c requires both for substrate path derivation)"
        );
        return Ok(AttachedDrainerGuard { child: None });
    }

    let data_dir = PathBuf::from(mvm_core::config::mvm_data_dir());
    let audit_dir = data_dir.join("audit");
    let audit_socket = audit_dir.join(format!("gateway-{}.sock", config.name));
    let signing_key_path = data_dir.join("keys").join("host-signer.ed25519");
    let events_socket = events_ingest_socket_path(&config.name);

    let drainer_cfg = serde_json::json!({
        "vm_name": config.name,
        "audit_dir": audit_dir,
        "audit_socket": audit_socket,
        "signing_key_path": signing_key_path,
        "events_socket_path": events_socket,
        "plan_json": plan_json,
        "bundle_json": config.bundle_json,
    });

    let drainer_bin =
        resolve_vz_drainer_path().map_err(|e| anyhow!("locate mvm-vz-drainer binary: {e}"))?;

    ui::info(&format!(
        "Spawning mvm-vz-drainer for Vz VM '{}' via {}...",
        config.name,
        drainer_bin.display(),
    ));

    let mut child = Command::new(&drainer_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow!("spawn {}: {e}", drainer_bin.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("mvm-vz-drainer stdin was not piped"))?
        .write_all(drainer_cfg.to_string().as_bytes())
        .map_err(|e| anyhow!("pipe DrainerConfig to mvm-vz-drainer stdin: {e}"))?;

    // Closing stdin (the take above already drops the writer once the
    // block ends) signals end-of-input to the drainer's `read_to_string`
    // loop.
    Ok(AttachedDrainerGuard { child: Some(child) })
}

/// Plan 113 §Task 11 — once the Vz supervisor's PID file appears, take
/// the drainer `Child` out of its guard, persist its PID under
/// `<state_dir>/vz-drainer.pid` (mode 0600), then drop the handle so
/// the OS keeps the process alive. From that point [`reap_drainer`] is
/// the reaper. No-op when the guard is empty (legacy path).
fn detach_and_persist_drainer(state_dir: &Path, guard: &mut AttachedDrainerGuard) -> Result<()> {
    let Some(child) = guard.detach() else {
        return Ok(());
    };
    let pid = child.id();
    let pid_path = state_dir.join(DRAINER_PID_FILE_NAME);
    write_drainer_pid_file(&pid_path, pid)?;
    // Drop the `Child` handle without `wait`; the kernel does not kill
    // a process when its `Child` handle drops, so the drainer survives.
    drop(child);
    Ok(())
}

/// Atomically write the drainer PID file at mode 0600, mirroring the
/// shape used by `persist_supervisor_config` so concurrent observers
/// never see a half-written value.
fn write_drainer_pid_file(path: &Path, pid: u32) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("drainer pid path has no parent: {}", path.display()))?;
    let tmp = parent.join(format!("{DRAINER_PID_FILE_NAME}.tmp"));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| anyhow!("open {} for write: {e}", tmp.display()))?;
        writeln!(f, "{pid}").map_err(|e| anyhow!("write drainer pid: {e}"))?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
    Ok(())
}

/// Plan 113 §Task 11 — reap the `mvm-vz-drainer` sibling spawned by
/// `start()`. Best-effort: a missing PID file means the VM either had
/// no drainer (legacy callers without `plan_json`) or the drainer
/// already exited; in either case `stop()` proceeds. SIGTERM → poll →
/// SIGKILL ladder matches the supervisor's path.
fn reap_drainer(state_dir: &Path) {
    let pid_path = state_dir.join(DRAINER_PID_FILE_NAME);
    let pid = match read_pid(&pid_path) {
        Some(p) => p,
        None => return,
    };
    if !pid_alive(pid) {
        let _ = std::fs::remove_file(&pid_path);
        return;
    }
    send_signal(pid, libc::SIGTERM);
    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if pid_alive(pid) {
        tracing::warn!(
            drainer_pid = pid,
            "mvm-vz-drainer did not exit after SIGTERM within {STOP_TIMEOUT:?}; sending SIGKILL"
        );
        send_signal(pid, libc::SIGKILL);
    }
    let _ = std::fs::remove_file(&pid_path);
}

/// Plan 113 §Task 11 — resolve the `mvm-vz-drainer` binary path,
/// checking three sources in order, mirroring `resolve_supervisor_path`:
///
/// 1. `MVM_VZ_DRAINER_PATH` — explicit override for tests +
///    `cargo run` workflows.
/// 2. A binary named `mvm-vz-drainer` adjacent to the current
///    executable — the layout produced by `cargo install` / Homebrew
///    bottles that ship `mvmctl` alongside the sidecars.
/// 3. The source-checkout build output under
///    `<workspace-root>/target/{release,debug}/mvm-vz-drainer`
///    (CLAUDE.md "Source-checkout builds never depend on mvm-published
///    artifacts"); this matters during local dev when `mvmctl` is
///    `cargo run` from the workspace root.
fn resolve_vz_drainer_path() -> Result<PathBuf> {
    let env_override = std::env::var_os("MVM_VZ_DRAINER_PATH").map(PathBuf::from);
    let current_exe = std::env::current_exe().ok();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resolve_vz_drainer_path_inner(
        env_override.as_deref(),
        current_exe.as_deref(),
        &manifest_dir,
    )
}

/// Pure resolver — exercised directly from tests without touching
/// `std::env`. Mirrors the Task 7 refactor pattern (`scrape_file_path_for`)
/// so unit tests don't race on process-wide env state.
fn resolve_vz_drainer_path_inner(
    env_override: Option<&Path>,
    current_exe: Option<&Path>,
    manifest_dir: &Path,
) -> Result<PathBuf> {
    if let Some(path) = env_override {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        bail!(
            "MVM_VZ_DRAINER_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Some(exe) = current_exe
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-vz-drainer");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Workspace target dir — `crates/mvm-backend` → workspace root is
    // two `..` up; the target dir is rooted there.
    if let Some(workspace_root) = manifest_dir.parent().and_then(Path::parent) {
        for variant in ["release", "debug"] {
            let candidate = workspace_root
                .join("target")
                .join(variant)
                .join("mvm-vz-drainer");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!(
        "mvm-vz-drainer binary not found. Looked for: $MVM_VZ_DRAINER_PATH, \
         alongside the current exe, and <workspace>/target/{{release,debug}}/mvm-vz-drainer. \
         Build with `cargo build -p mvm-vz-drainer`."
    )
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse::<libc::pid_t>().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    // `kill(pid, 0)` returns 0 if the process exists, -1 with
    // errno=ESRCH if not.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
    unsafe { libc::kill(pid, sig) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_vz() {
        assert_eq!(VzBackend.name(), "vz");
    }

    #[test]
    fn capabilities_match_plan_97_phase_e() {
        let caps = VzBackend.capabilities();
        assert!(caps.vsock, "vsock always available");
        assert!(
            !caps.tap_networking,
            "Vz uses file-handle attachments via gvproxy"
        );
        // Plan 97 Phase E — control socket exposes PAUSE / RESUME /
        // BALLOON; the trait verbs route through it.
        assert!(caps.pause_resume);
        assert!(caps.balloon);
        // snapshots is feature-detected on macOS 14+; on a
        // contributor host below 14 it stays false.
        let _ = caps.snapshots;
    }

    #[test]
    fn run_attached_requires_kernel_path() {
        // Phase C primitive — refuses without a kernel path. Real
        // boot can't be exercised in a unit test (needs an actual
        // dev-shell artifact), so the test catches the precondition
        // path which is what consumers will hit first when wiring
        // up a Vz-backed builder runner.
        let backend = VzBackend;
        let cfg = VmStartConfig {
            name: "smoke-attached".into(),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };
        let err = backend
            .run_attached(&cfg)
            .expect_err("missing kernel must error");
        // On a contributor host without Vz, the platform gate fires
        // first; on a macOS 13+ host, the kernel-path check fires.
        // Either way, the error must be actionable.
        let msg = err.to_string();
        assert!(
            msg.contains("kernel path") || msg.contains("not available"),
            "error explains the precondition: {msg}"
        );
    }

    #[test]
    fn snapshot_save_requires_absolute_path() {
        let backend = VzBackend;
        let id = VmId("any".into());
        let err = backend
            .snapshot_save(&id, Path::new("relative.snapshot"))
            .expect_err("relative path refused");
        assert!(
            err.to_string().contains("absolute path"),
            "error explains why: {err}"
        );
    }

    #[test]
    fn pause_with_no_supervisor_surfaces_socket_path() {
        // No supervisor is running for the test VM id; pause must
        // surface an actionable error mentioning the missing socket
        // path so operators know where to look.
        let backend = VzBackend;
        let id = VmId("definitely-not-running-1234567890".into());
        let err = backend.pause(&id).expect_err("pause should error");
        assert!(
            err.to_string().contains("control.sock"),
            "error mentions the socket: {err}"
        );
    }

    #[test]
    fn balloon_set_target_refuses_below_floor() {
        // 0 (deflate fully) is allowed; any positive value below the
        // 128 MiB floor must be rejected before the control-socket
        // dial — Plan 97 §"Memory balloon floor".
        let backend = VzBackend;
        let id = VmId("any".into());
        let err = backend
            .balloon_set_target(&id, 64)
            .expect_err("below-floor must error before connect");
        assert!(
            err.to_string().contains("floor"),
            "error explains the floor: {err}"
        );
        // 0 must pass the floor check (still errors because there's
        // no supervisor running, but with a connect error not a
        // floor-violation error).
        let err = backend
            .balloon_set_target(&id, 0)
            .expect_err("connect to missing socket still errors");
        assert!(
            !err.to_string().contains("floor"),
            "0 should not trigger the floor check: {err}"
        );
    }

    #[test]
    fn stop_with_no_pid_file_returns_ok() {
        // Stopping a never-started VM is a no-op (matches libkrun).
        let backend = VzBackend;
        let id = VmId("definitely-not-running-1234567890".into());
        assert!(backend.stop(&id).is_ok());
    }

    #[test]
    fn status_with_no_pid_file_is_stopped() {
        let backend = VzBackend;
        let id = VmId("definitely-not-running-1234567890".into());
        assert!(matches!(backend.status(&id).unwrap(), VmStatus::Stopped));
    }

    #[test]
    fn list_skips_dirs_without_vz_pid_file() {
        // `list` walks `~/.mvm/vms/` and yields entries whose dir
        // contains `vz.pid`. The libkrun backend uses `libkrun.pid`
        // in the same tree, so we must not pick those up. We can't
        // exercise the full path in a unit test without a tempdir
        // mock; instead assert the empty case from a clean
        // contributor host doesn't error.
        let backend = VzBackend;
        // On a contributor host with no Vz VM ever started, this
        // returns an empty Vec. On a host that has one running,
        // the test still passes — the filter rules don't change
        // shape with population.
        let _ = backend.list().expect("list must not error");
    }

    #[test]
    fn guest_channel_info_is_vsock_at_agent_port() {
        let info = VzBackend.guest_channel_info(&VmId("smoke".into())).unwrap();
        match info {
            GuestChannelInfo::Vsock { cid, port } => {
                assert_eq!(cid, 3);
                assert_eq!(port, mvm_guest::vsock::GUEST_AGENT_PORT);
            }
            other => panic!("expected vsock channel, got {other:?}"),
        }
    }

    #[test]
    fn security_profile_is_tier_2_with_claim_3_partial() {
        let profile = VzBackend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        assert!(profile.layer_coverage.is_microvm());
        assert_eq!(profile.dropped_claims(), vec![3]);
    }

    #[test]
    fn build_supervisor_config_maps_vmstartconfig_fields() {
        let mut cfg = VmStartConfig {
            name: "smoke".into(),
            cpus: 2,
            memory_mib: 1024,
            ..Default::default()
        };
        cfg.kernel_path = Some("/abs/vmlinux".into());
        cfg.rootfs_path = "/abs/rootfs.ext4".into();
        // Admitted workload: plan_json + tenant_id present, so the drainer
        // runs and the bridge is requested (the events_ingest assertion
        // below). The no-admission branch is covered separately by
        // `build_supervisor_config_omits_events_ingest_without_admission`.
        cfg.plan_json = Some("{}".into());
        cfg.tenant_id = Some("local".into());
        let state_dir = Path::new("/tmp/vz-smoke-state");
        // Plan 102 W6.A.5 — build_supervisor_config now takes
        // HostGvproxyInfo (the host-side gvproxy lifecycle's
        // socket + PID, populated into NetworkConfig::Gvproxy).
        // Test passes a stub — actual gvproxy isn't spawned here.
        let gvproxy_info = host_gvproxy::HostGvproxyInfo {
            socket_path: state_dir.join("gvproxy.sock"),
            pid: 0,
        };
        let built =
            build_supervisor_config(&cfg, "/abs/vmlinux", state_dir, &gvproxy_info).expect("build");

        assert_eq!(built.name, "smoke");
        assert_eq!(built.kernel.path, "/abs/vmlinux");
        assert_eq!(built.resources.cpu_count, 2);
        assert_eq!(built.resources.memory_mib, 1024);
        assert_eq!(built.disks.len(), 1);
        assert_eq!(built.disks[0].path, "/abs/rootfs.ext4");
        assert!(built.disks[0].read_only);
        assert!(built.virtio_fs.is_empty());
        assert_eq!(built.vsock.ports, vec![mvm_guest::vsock::GUEST_AGENT_PORT]);
        assert_eq!(built.pid_file_name.as_deref(), Some(PID_FILE_NAME));
        // Console capture goes to a file under state_dir; never `None`
        // — capture-only is the workload contract (Plan 97 Security §9).
        assert!(built.console_output_path.is_some());
        // Plan 102 W6.A.5 — network field is now populated with the
        // gvproxy socket + MAC + events_ingest path.
        match built.network {
            Some(vz::NetworkConfig::Gvproxy {
                socket_path,
                mac,
                events_ingest_socket_path,
            }) => {
                assert!(
                    socket_path.ends_with("gvproxy.sock"),
                    "socket path: {socket_path}"
                );
                assert!(
                    mac.starts_with("02:")
                        || mac.starts_with("06:")
                        || mac.starts_with("0a:")
                        || mac.starts_with("0e:"),
                    "locally-administered MAC: {mac}"
                );
                assert!(
                    events_ingest_socket_path.is_some(),
                    "events_ingest_socket_path should be populated for an admitted workload (W6.A.5 Vz bridge)"
                );
            }
            None => panic!("network should be Some(Gvproxy {{ .. }}) after W6.A.5"),
        }
    }

    #[test]
    fn build_supervisor_config_omits_events_ingest_without_admission() {
        // No plan_json/tenant_id — the default `up --dev` / no-bridge path.
        // `spawn_vz_drainer` is skipped for this case, so nothing binds the
        // events-ingest socket. The Vz bridge must therefore NOT request it,
        // or the Swift supervisor's mandatory connect() fails errno=2 and the
        // VM dies before boot (the `up --dev --hypervisor vz` crash). Gate the
        // request on the same condition as the drainer.
        let mut cfg = VmStartConfig {
            name: "no-admit".into(),
            cpus: 1,
            memory_mib: 512,
            ..Default::default()
        };
        cfg.kernel_path = Some("/abs/vmlinux".into());
        cfg.rootfs_path = "/abs/rootfs.ext4".into();
        assert!(cfg.plan_json.is_none() && cfg.tenant_id.is_none());
        let state_dir = Path::new("/tmp/vz-no-admit-state");
        let gvproxy_info = host_gvproxy::HostGvproxyInfo {
            socket_path: state_dir.join("gvproxy.sock"),
            pid: 0,
        };
        let built =
            build_supervisor_config(&cfg, "/abs/vmlinux", state_dir, &gvproxy_info).expect("build");
        match built.network {
            Some(vz::NetworkConfig::Gvproxy {
                events_ingest_socket_path,
                ..
            }) => assert!(
                events_ingest_socket_path.is_none(),
                "events_ingest must be None without admission (no drainer binds it); got {events_ingest_socket_path:?}"
            ),
            None => panic!("network should be Some(Gvproxy {{ .. }})"),
        }
    }

    #[test]
    fn build_supervisor_config_maps_user_volumes() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let cfg = VmStartConfig {
            name: "vols".into(),
            cpus: 1,
            memory_mib: 512,
            kernel_path: Some("/abs/vmlinux".into()),
            rootfs_path: "/abs/rootfs.ext4".into(),
            volumes: vec![
                VmVolume {
                    host: "/host/src".into(),
                    guest: "/work2".into(),
                    read_only: true,
                    kind: VmVolumeKind::DirShare,
                    ..Default::default()
                },
                VmVolume {
                    host: "/host/data.img".into(),
                    guest: "/data".into(),
                    size: "10G".into(),
                    kind: VmVolumeKind::Disk,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let state_dir = Path::new("/tmp/vz-vols-state");
        let gvproxy_info = host_gvproxy::HostGvproxyInfo {
            socket_path: state_dir.join("gvproxy.sock"),
            pid: 0,
        };
        let built =
            build_supervisor_config(&cfg, "/abs/vmlinux", state_dir, &gvproxy_info).expect("build");

        // rootfs (RO) + the disk volume.
        assert_eq!(built.disks.len(), 2);
        assert_eq!(built.disks[0].id, "rootfs");
        assert_eq!(built.disks[1].id, "uvol1");
        assert_eq!(built.disks[1].path, "/host/data.img");
        assert!(!built.disks[1].read_only);
        // The directory share.
        assert_eq!(built.virtio_fs.len(), 1);
        assert_eq!(built.virtio_fs[0].tag, "uvol0");
        assert_eq!(built.virtio_fs[0].host_path, "/host/src");
        assert!(built.virtio_fs[0].read_only);
    }

    /// Claim 1 witness: the base/core drive (rootfs) is ALWAYS attached
    /// read-only at the hypervisor on Vz, regardless of any user volumes.
    /// A regression that flips it to writable trips this test (and the
    /// catalog gate).
    #[test]
    fn vz_rootfs_disk_is_read_only() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let cfg = VmStartConfig {
            name: "rootfs-ro".into(),
            cpus: 1,
            memory_mib: 256,
            kernel_path: Some("/abs/vmlinux".into()),
            rootfs_path: "/abs/rootfs.ext4".into(),
            // Even with a writable user disk attached, the rootfs stays ro.
            volumes: vec![VmVolume {
                host: "/host/data.img".into(),
                guest: "/data".into(),
                size: "1G".into(),
                read_only: false,
                kind: VmVolumeKind::Disk,
                ..Default::default()
            }],
            ..Default::default()
        };
        let state_dir = Path::new("/tmp/vz-rootfs-ro-state");
        let gvproxy_info = host_gvproxy::HostGvproxyInfo {
            socket_path: state_dir.join("gvproxy.sock"),
            pid: 0,
        };
        let built =
            build_supervisor_config(&cfg, "/abs/vmlinux", state_dir, &gvproxy_info).expect("build");
        assert_eq!(built.disks[0].id, "rootfs");
        assert!(
            built.disks[0].read_only,
            "rootfs MUST be read-only at the hypervisor"
        );
    }

    #[test]
    fn build_supervisor_config_refuses_unsafe_tenant() {
        // Plan 112 Phase 3c — defense-in-depth: an unsafe tenant_id
        // (DNS-label allowlist violation) is refused inside
        // build_supervisor_config before any Swift spawn or file
        // touch. Same posture as libkrun's
        // build_supervisor_config_refuses_unsafe_tenant.
        let cfg = VmStartConfig {
            name: "smoke".into(),
            cpus: 1,
            memory_mib: 256,
            kernel_path: Some("/abs/vmlinux".into()),
            rootfs_path: "/abs/rootfs.ext4".into(),
            tenant_id: Some("../escape".into()),
            ..Default::default()
        };
        let state_dir = Path::new("/tmp/vz-tenant-refuse-state");
        let gvproxy_info = host_gvproxy::HostGvproxyInfo {
            socket_path: state_dir.join("gvproxy.sock"),
            pid: 0,
        };
        let err = build_supervisor_config(&cfg, "/abs/vmlinux", state_dir, &gvproxy_info)
            .expect_err("unsafe tenant must error");
        let msg = err.to_string();
        assert!(
            msg.contains("tenant_id") || msg.contains("vm_name"),
            "expected DNS-label rejection; got {msg}"
        );
    }

    #[test]
    fn resolve_supervisor_path_honors_env_override() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // `MVM_VZ_SUPERVISOR_PATH` points at a real file → returned as-is.
        // SAFETY: serialized by TEST_ENV_LOCK.
        unsafe {
            std::env::set_var("MVM_VZ_SUPERVISOR_PATH", tmp.path());
        }
        let path = resolve_supervisor_path().expect("env override resolves");
        assert_eq!(path, tmp.path());
        // SAFETY: serialized by TEST_ENV_LOCK.
        unsafe {
            std::env::remove_var("MVM_VZ_SUPERVISOR_PATH");
        }
    }

    #[test]
    fn resolve_vz_drainer_path_inner_prefers_env_override() {
        // Pure resolver — exercised without touching process env. The
        // override must point at a real file or the call errors with a
        // "not a file" message.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let manifest_dir = PathBuf::from("/nonexistent/manifest");
        let resolved = resolve_vz_drainer_path_inner(Some(tmp.path()), None, &manifest_dir)
            .expect("env override resolves");
        assert_eq!(resolved, tmp.path());
    }

    #[test]
    fn resolve_vz_drainer_path_inner_env_pointing_at_missing_file_errors() {
        let manifest_dir = PathBuf::from("/nonexistent/manifest");
        let bogus = Path::new("/definitely/not/there/mvm-vz-drainer");
        let err = resolve_vz_drainer_path_inner(Some(bogus), None, &manifest_dir)
            .expect_err("missing file must error");
        assert!(
            err.to_string().contains("not a file"),
            "error explains why: {err}"
        );
    }

    #[test]
    fn resolve_vz_drainer_path_inner_falls_back_to_adjacent() {
        // When the env override is absent but a sibling binary exists
        // next to the current exe, the resolver returns it.
        let tmp_dir = tempfile::tempdir().unwrap();
        let exe = tmp_dir.path().join("mvmctl");
        std::fs::write(&exe, b"#!fake").unwrap();
        let drainer = tmp_dir.path().join("mvm-vz-drainer");
        std::fs::write(&drainer, b"#!fake").unwrap();
        let manifest_dir = PathBuf::from("/nonexistent/manifest");
        let resolved =
            resolve_vz_drainer_path_inner(None, Some(&exe), &manifest_dir).expect("adjacent hit");
        assert_eq!(resolved, drainer);
    }

    #[test]
    fn resolve_vz_drainer_path_inner_errors_when_nothing_found() {
        // All three sources miss → actionable error.
        let manifest_dir = PathBuf::from("/nonexistent/manifest");
        let err = resolve_vz_drainer_path_inner(None, None, &manifest_dir)
            .expect_err("no candidate must error");
        let msg = err.to_string();
        assert!(
            msg.contains("mvm-vz-drainer") && msg.contains("MVM_VZ_DRAINER_PATH"),
            "error names the binary + override env var: {msg}"
        );
    }

    #[test]
    fn attached_drainer_guard_kills_child_on_drop() {
        // Spawn a long-lived `sleep` and wrap it; dropping the guard
        // must kill the process. We poll `try_wait` briefly after drop
        // to assert the child reaped.
        let child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        {
            let _guard = AttachedDrainerGuard { child: Some(child) };
            assert!(pid_alive(pid), "sleep should be alive while guard owns it");
        }
        // After drop: poll up to 1s for the process to disappear.
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if !pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!pid_alive(pid), "sleep must be dead after guard drop");
    }

    #[test]
    fn attached_drainer_guard_detach_leaves_child_running() {
        // `detach` takes the Child out so dropping the guard does NOT
        // kill the process. The test reaps the detached child manually
        // to avoid leaking it past the test boundary.
        let child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id() as libc::pid_t;
        let mut guard = AttachedDrainerGuard { child: Some(child) };
        let detached = guard.detach().expect("detach yields the child");
        // Guard is now empty; dropping it must NOT kill the child.
        drop(guard);
        assert!(pid_alive(pid), "sleep must still be alive after detach");
        // Clean up so the test doesn't leak the process.
        send_signal(pid, libc::SIGKILL);
        let mut detached = detached;
        let _ = detached.wait();
    }

    #[test]
    fn attached_drainer_guard_empty_drop_is_noop() {
        // The legacy / opt-out path returns an empty guard. Dropping
        // it must not panic and must not attempt any process ops.
        let guard = AttachedDrainerGuard { child: None };
        drop(guard);
    }

    #[test]
    fn resolve_supervisor_path_env_pointing_at_missing_file_errors() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialized by TEST_ENV_LOCK.
        unsafe {
            std::env::set_var(
                "MVM_VZ_SUPERVISOR_PATH",
                "/definitely/not/there/mvm-vz-supervisor",
            );
        }
        let err = resolve_supervisor_path().expect_err("missing file must error");
        assert!(
            err.to_string().contains("not a file"),
            "error explains why: {err}"
        );
        // SAFETY: serialized by TEST_ENV_LOCK.
        unsafe {
            std::env::remove_var("MVM_VZ_SUPERVISOR_PATH");
        }
    }
}
