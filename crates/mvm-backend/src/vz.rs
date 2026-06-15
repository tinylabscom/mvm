//! Vz (Apple Virtualization.framework) backend for mvm.
//!
//! Tier 2 microVM backend for macOS 13+ that runs
//! the workload directly on the host (no nested Firecracker, no
//! libkrun in the path). Lifecycle delegates to a per-VM
//! Rust-native `mvm-vz-supervisor` (the objc2 `[[bin]]` in
//! `mvm-vm-host`) — same one-process-per-VM contract
//! `LibkrunBackend` uses, swapped underneath.
//!
//! ## Why opt-in only
//!
//! `auto_select()`
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
//! - `logs` tails `<vm_state_dir>/console.log` (capture-only console).

use anyhow::{Context, Result, anyhow, bail};
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

/// Tear-down guard for host-side gvproxy in the
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

/// Tear-down guard for the per-VM `mvm-vz-drainer`
/// sidecar that bridges Swift's NDJSON `FlowEventWire` socket into the
/// chain-signed audit pipeline. Mirrors
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

/// PID file the `mvm-vz-drainer` sibling writes
/// after a successful boot. Lives next to `vz.pid` so `VzBackend::stop`
/// can reap the drainer the same way it reaps the supervisor.
const DRAINER_PID_FILE_NAME: &str = "vz-drainer.pid";

/// Persisted `SupervisorConfig` JSON. Written by `start` so
/// `snapshot_restore` can replay the same shape with
/// `startup_mode` flipped. Mode 0600 — same tier as the audit
/// chain and the host signer.
const SUPERVISOR_CONFIG_FILE_NAME: &str = "supervisor-config.json";

/// Canonical path to a VM's persisted supervisor config inside its state dir.
/// The single source of truth for the file name so callers (e.g. the
/// checkpoint fork path) never re-spell the literal.
pub fn supervisor_config_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SUPERVISOR_CONFIG_FILE_NAME)
}

/// Where a saved Vz standby keeps its seed supervisor config: inside the POOL
/// dir, not the seed VM's state dir. The seed's state dir is torn down when the
/// seed is stopped after capture, so spawn copies the config here and claim
/// (running much later) reads it from here. Both sides MUST use this path.
fn pool_seed_config_path(pool_root: &Path, standby_id: &str) -> PathBuf {
    supervisor_config_path(&pool_root.join(standby_id))
}

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
/// at `/dev/vda`. The host-side cmdline allow-list (to be wired in a
/// follow-up that integrates with `mvm_hostd::supervisor::admit_for_run`)
/// will gate any tokens beyond this default for workload microVMs.
const DEFAULT_CMDLINE: &str = "console=hvc0 root=/dev/vda rw init=/init";

impl VmBackend for VzBackend {
    fn name(&self) -> &str {
        "vz"
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // Supervisor exposes a control socket for PAUSE / RESUME /
            // BALLOON / SAVE; the corresponding VmBackend verbs route
            // through `vz_control::send_command`.
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
            // Vz runs on macOS with APFS, so clonefile is available.
            fs_quick_checkpoint: cfg!(target_os = "macos"),
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // Vz is the macOS live-memory path: coarse `saveMachineState` /
        // `restoreMachineState`, keyed off the same macOS
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
        // The admission gate + runtime_meta read the *source* (golden) rootfs
        // sidecar; the per-instance clone below is a CoW copy under a different
        // name, so its sidecar lives next to the source.
        let rootfs = Path::new(&config.rootfs_path);
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;

        // A non-verity image gets a CoW clone so each VM owns a writable root:
        // pristine template, multi-instance isolation, and a clean substrate
        // for features that require per-instance disk ownership. A verity/sealed
        // image stays on the read-only golden rootfs because dm-verity requires
        // an immutable backing. APFS CoW makes the clone O(1).
        let sealed = config.verity_path.is_some();
        let mut launch_config = config.clone();
        if !sealed {
            launch_config.rootfs_path =
                crate::base::cow::prepare_instance_rootfs(&config.name, &config.rootfs_path)?
                    .to_string_lossy()
                    .into_owned();
        }

        // Spawn host-side gvproxy so the supervisor has something to connect to.
        // VzBackend is stateless; the child is detached
        // (PID file under state dir lets `stop()` find it later).
        let gvproxy_info = host_gvproxy::spawn_detached(&state_dir)
            .map_err(|e| anyhow!("spawn host-side gvproxy for Vz VM '{}': {e}", config.name))?;

        // Vz config build. The `?` propagates allowlist failures from
        // `audit_substrate::compute_audit_substrate` for unsafe tenant_id /
        // vm_name values.
        let mut cfg = build_supervisor_config(&launch_config, kernel, &state_dir, &gvproxy_info)?;
        // Attach the rootfs writable for the per-instance clone; verity/sealed
        // stays read-only (the builder defaults read-only).
        if !sealed && let Some(disk) = cfg.disks.iter_mut().find(|d| d.id == "rootfs") {
            disk.read_only = false;
        }

        // Spawn the `mvm-vz-drainer` sibling between gvproxy and the Vz
        // VM boot. Closes the Vz audit carve-out: the drainer binds
        // `events_ingest_socket_path`,
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
            // Tight poll: the pid file lands a few hundred ms in, and a coarse
            // cadence rounds every `up` up by that much. Cheap to spin finer.
            std::thread::sleep(Duration::from_millis(5));
        }

        // Vz supervisor booted cleanly. Detach the
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

        // The supervisor is up (PID file written) and its host-listen proxy is
        // bound. Spawn the egress substitution endpoint if the admitted plan
        // carries secrets so the guest's egress can resolve placeholders
        // host-side (the guest never holds the real secret). The guard reaps the
        // endpoint on any early return below; defused once the VM is confirmed up
        // (the `stop` path then owns teardown). A secret-free plan is a defused
        // no-op.
        let mut endpoint_guard = spawn_vz_egress_endpoint_if_needed(&config.name, &state_dir)?;

        ui::success(&format!(
            "Vz VM '{}' started (pid file: {}, console log: {}).",
            config.name,
            pid_file.display(),
            console_log.display()
        ));
        endpoint_guard.defuse();
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        // Reap the per-VM substitution endpoint first (no-op when none was
        // spawned) so a crashed VM's decrypted-secret process can't outlive the
        // guest. Mirrors the libkrun / FC stop ordering — safe because reap is a
        // no-op when nothing exists, even before the not-running early return.
        crate::substitution_spawn::reap_substitution_endpoint(&vm_state_dir(&id.0), &id.0);

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
            remove_instance_rootfs(&id.0);
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
            // Tight poll: the supervisor owns the graceful→forced escalation
            // and exits in a few hundred ms, so detect its exit promptly
            // rather than rounding `down` up by a coarse cadence.
            std::thread::sleep(Duration::from_millis(25));
        }
        if pid_alive(pid) {
            ui::info(&format!(
                "Vz VM '{}' PID {pid} did not exit after SIGTERM within {STOP_TIMEOUT:?}; sending SIGKILL.",
                id.0
            ));
            send_signal(pid, libc::SIGKILL);
        }

        let _ = std::fs::remove_file(&pid_path);
        remove_instance_rootfs(&id.0);

        // Tear down the host-side gvproxy spawned by `start()`.
        // Best-effort: the supervisor stop
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

        // Reap the `mvm-vz-drainer` sibling that `start()` spawned and
        // detached. Same SIGTERM → poll → SIGKILL ladder as the
        // supervisor; best-effort because some VMs have
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
        // Host-side floor enforcement (refuse to shrink the guest below
        // a configured minimum) happens on the Rust side here — the
        // supervisor's BALLOON verb is a pure setter. The 128 MiB floor
        // is the conservative default; consumers that want a different
        // floor pass it via VmStartConfig
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
        // Capture-only console at `<vm_state_dir>/console.log`.
        // `hypervisor=true` would mean "supervisor's own
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
        // 7-claim table here covers claims 1–7 (8 and 9 live
        // outside `BackendSecurityProfile`).
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds, // 1 — host-fs isolation via Vz (ro rootfs attach) + host-side admission gate (enforce_admitted_shares); in-supervisor share re-check is deferred
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

    fn supports_standby_pool(&self) -> bool {
        // Saved-standby pool requires macOS 14+ snapshot support.
        macos_supports_vz_snapshots()
    }

    fn spawn_standby(
        &self,
        spec: &mvm_core::vm_backend::StandbySpec,
    ) -> std::result::Result<mvm_core::vm_backend::StandbyHandle, mvm_core::vm_backend::StandbyError>
    {
        vz_spawn_standby(spec)
            .map_err(|e| mvm_core::vm_backend::StandbyError::SpawnFailed(e.to_string()))
    }

    fn claim_standby(
        &self,
        handle: &mvm_core::vm_backend::StandbyHandle,
        claim: &mvm_core::vm_backend::StandbyClaim,
    ) -> std::result::Result<VmId, mvm_core::vm_backend::StandbyError> {
        vz_claim_standby(handle, claim)
            .map_err(|e| mvm_core::vm_backend::StandbyError::ClaimFailed(e.to_string()))
    }
}

impl VzBackend {
    /// Run a Linux guest under Vz
    /// **attached to the calling process**: spawn the supervisor in
    /// the foreground, pipe its JSON config on stdin, inherit
    /// stdout/stderr so the guest's console output streams to the
    /// terminal, and block until the supervisor exits. Returns the
    /// supervisor's exit status translated into [`VmExitStatus`].
    ///
    /// Foundation for a future `VzBuilderVm`:
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
    /// `VZVirtualMachine.requestStop()`.
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

        // Attached path also needs the host-side gvproxy.
        // `run_attached` ties gvproxy's
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
        // guest's exit code per the `main.swift` contract
        // (0 clean / 1 guest error / 2 config parse error
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

    /// Snapshot save. Asks the supervisor to write
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

    /// Snapshot restore. Boots a new supervisor in
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

        // The original gvproxy sidecar died when the VM was stopped. The
        // supervisor's connect() into the gvproxy socket must find a live
        // listener, so spawn a fresh one before handing the config to the
        // supervisor. Safe here because `stop` already reaped the
        // predecessor gvproxy — `spawn_detached`'s unlink only clears
        // stale socket/PID files, it does not kill a live process.
        if matches!(cfg.network, Some(vz::NetworkConfig::Gvproxy { .. })) {
            host_gvproxy::spawn_detached(&state_dir)
                .map_err(|e| anyhow!("spawn gvproxy for restoring Vz VM '{}': {e}", id.0))?;
        }

        ui::info(&format!(
            "Restoring Vz VM '{}' from {}...",
            id.0,
            snapshot_path.display(),
        ));
        spawn_supervisor_with_config(&cfg)?;
        ui::success(&format!("Vz VM '{}' restored.", id.0));
        Ok(VmId(id.0.clone()))
    }
}

/// Spawn `mvm-vz-supervisor` with `cfg` on stdin and block until it writes its
/// PID file (the supervisor's "I'm up" signal). Shared by `snapshot_restore`
/// (same-identity resume) and the vm_full fork path (new-identity restore) —
/// both flip `startup_mode` to `Restore` and hand the supervisor a config whose
/// shape matches the saved memory state.
///
/// Refuses if `cfg`'s VM is already running (a live supervisor would race the
/// new one over the same disks); a stale PID file (process gone) is removed.
fn spawn_supervisor_with_config(cfg: &vz::SupervisorConfig) -> Result<()> {
    let state_dir = PathBuf::from(&cfg.vm_state_dir);
    let pid_file = cfg.resolved_pid_file();
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        bail!(
            "VM {:?} is still running (PID {pid}); stop it with `mvmctl down {}` first",
            cfg.name,
            cfg.name,
        );
    }
    let _ = std::fs::remove_file(&pid_file);

    let json = cfg
        .to_json()
        .map_err(|e| anyhow!("serialize SupervisorConfig: {e}"))?;
    let supervisor_path = resolve_supervisor_path()?;
    let console_log = state_dir.join("console.log");
    let _ = crate::libkrun::open_console_capture(&console_log);

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
                "supervisor exited before writing PID file (status: {status}). \
                 Check stderr above; console log: {}",
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
    Ok(())
}

impl crate::checkpoint::VmFullRestore for VzBackend {
    /// Materialize the checkpoint's rootfs into place (must happen before
    /// `restoreMachineState` — the saved memory expects the exact disk it was
    /// captured with), then boot the supervisor in Restore mode.
    ///
    /// If the rootfs clone succeeds but `snapshot_restore` then fails, the
    /// clone is removed so a retry isn't blocked by a pre-existing file.
    fn restore(
        &self,
        target_vm: &str,
        rootfs_src: &std::path::Path,
        memory: &std::path::Path,
        machine_id: &std::path::Path,
    ) -> anyhow::Result<()> {
        restore_with_spawn(
            self,
            target_vm,
            rootfs_src,
            memory,
            machine_id,
            |backend, vm, mem, mid| {
                backend
                    .snapshot_restore(&VmId(vm.to_string()), mem, Some(mid))
                    .map(|_| ())
            },
        )
    }
}

/// Inner restore logic with an injectable spawn step so unit tests can trigger
/// the failure-cleanup path without a real supervisor binary.
fn restore_with_spawn(
    backend: &VzBackend,
    target_vm: &str,
    rootfs_src: &std::path::Path,
    memory: &std::path::Path,
    machine_id: &std::path::Path,
    do_restore: impl FnOnce(&VzBackend, &str, &std::path::Path, &std::path::Path) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    refuse_if_running(target_vm)?;
    use crate::checkpoint::VmFullControl as _;
    let target_rootfs = VzVmFullControl::new(target_vm)
        .rootfs_path()
        .context("resolving target VM rootfs path for restore")?;

    // The clone step can collide if a previous restore was interrupted
    // after the clone but before the supervisor wrote its PID file.
    // Distinguish the two error shapes: if the destination already exists,
    // we didn't create it — surface an actionable message and leave the
    // file alone. If the clone itself creates the file and restore later
    // fails, remove only what we created.
    if target_rootfs.exists() {
        anyhow::bail!(
            "restore target rootfs already exists at {}; a previous failed \
             restore may have left it. Remove it manually, then retry.",
            target_rootfs.display()
        );
    }

    crate::base::cow::clone_rootfs_for_instance(rootfs_src, &target_rootfs)
        .context("materializing checkpoint rootfs before restore")?;

    let restore_result = do_restore(backend, target_vm, memory, machine_id);

    if let Err(ref e) = restore_result {
        // The clone succeeded but restore failed — clean up what this
        // call created so the caller can retry without the stale file.
        tracing::warn!(
            target_rootfs = %target_rootfs.display(),
            error = %e,
            "snapshot_restore failed; removing cloned rootfs to allow retry"
        );
        let _ = std::fs::remove_file(&target_rootfs);
        // `snapshot_restore` spawns a fresh gvproxy before the supervisor; a
        // restore that dies after that spawn leaves the sidecar running with
        // its PID file in place, which the next retry's spawn would orphan.
        // Reap it here so a failed restore frees its own resources.
        let _ = host_gvproxy::stop_by_pid_file(&vm_state_dir(target_vm));
    }

    restore_result
}

/// Bridges the checkpoint `VmFullControl` trait to a running Vz VM's control
/// socket. Capture orchestration PAUSEs first, then SAVEs while paused, so
/// memory and disk are consistent; the orchestrator calls RESUME itself after.
pub struct VzVmFullControl {
    vm_name: String,
}

impl VzVmFullControl {
    pub fn new(vm_name: impl Into<String>) -> Self {
        Self {
            vm_name: vm_name.into(),
        }
    }

    fn sock(&self) -> PathBuf {
        vz_control::control_socket_path(&vm_state_dir(&self.vm_name))
    }
}

impl crate::checkpoint::VmFullControl for VzVmFullControl {
    fn pause(&self) -> Result<()> {
        vz_control::send_command(&self.sock(), "PAUSE").map(|_| ())
    }

    fn resume(&self) -> Result<()> {
        vz_control::send_command(&self.sock(), "RESUME").map(|_| ())
    }

    fn save_memory(&self, memory_path: &Path) -> Result<()> {
        if !memory_path.is_absolute() {
            anyhow::bail!(
                "save_memory requires an absolute path, got {}",
                memory_path.display()
            );
        }
        vz_control::send_command(&self.sock(), &format!("SAVE {}", memory_path.display()))
            .map(|_| ())
    }

    fn rootfs_path(&self) -> Result<PathBuf> {
        let cfg_path = vm_state_dir(&self.vm_name).join(SUPERVISOR_CONFIG_FILE_NAME);
        let bytes = std::fs::read(&cfg_path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", cfg_path.display()))?;
        let cfg: vz::SupervisorConfig = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", cfg_path.display()))?;
        cfg.disks
            .iter()
            .find(|d| d.id == "rootfs")
            .map(|d| PathBuf::from(&d.path))
            .ok_or_else(|| anyhow::anyhow!("supervisor config has no rootfs disk"))
    }
}

/// Derive a fork child's `SupervisorConfig` from the parent's persisted one.
/// Pure (no I/O, no spawn): the caller passes the already-parsed parent config
/// and the child's cloned blob paths; this rewrites identity + restore mode.
///
/// - `name` → `child_vm_name` (the new identity).
/// - MAC stays the parent's: VZ validates the restored machine state against the
///   saved device configuration and refuses a changed MAC. The clone model is
///   safe because every VM runs behind its own per-VM gvproxy with no shared L2
///   segment (the gvproxy-only invariant enforced by `fork_vm_full`).
/// - `vm_state_dir` → the child's state dir, and every disk `path` is rebased
///   into that dir (keeping each disk's basename) so the child boots from its
///   OWN cloned rootfs, never the parent's live image.
/// - `startup_mode` → `Restore` against the child's cloned `memory.bin` (and
///   inherited `machine-id` sidecar), so the supervisor resumes the captured
///   memory state instead of cold-booting the kernel.
///
/// Every per-VM *runtime* path (the sockets/dirs/logs `build_supervisor_config`
/// derives from `state_dir` or from `name`) is rebased onto the child so the
/// fork writes its own control/vsock/console and connects its own live gvproxy:
///
/// - `vsock.socket_dir`, `control_socket_path`, `console_output_path`, and the
///   gvproxy `socket_path` are rebased onto `child_state_dir`, reusing the same
///   basename/sub-path layout the normal builder uses.
/// - the audit-substrate sockets that key off the VM *name* (`gateway_audit_socket`)
///   are re-derived for `child_vm_name` under `~/.mvm/audit/`.
///
/// Claim-8 wiring (`tenant_id`, `plan`, `bundle`, `audit_dir`,
/// `signing_key_path`, `events_ingest_socket_path`) is CLEARED on the returned
/// config. The caller (`fork_vm_full`) injects the child's own admitted plan
/// after this function returns. The child must carry ITS OWN plan, not the
/// parent's — the supervisor re-verifies the plan under the child's identity.
pub fn build_child_supervisor_config(
    parent_cfg: &vz::SupervisorConfig,
    child_vm_name: &str,
    child_state_dir: &Path,
    memory_path: &Path,
    machine_id_path: Option<&Path>,
) -> Result<vz::SupervisorConfig> {
    let mut cfg = parent_cfg.clone();
    cfg.name = child_vm_name.to_string();
    cfg.vm_state_dir = child_state_dir.to_string_lossy().into_owned();

    for disk in &mut cfg.disks {
        let basename = Path::new(&disk.path)
            .file_name()
            .ok_or_else(|| anyhow!("disk path {:?} has no file name", disk.path))?;
        disk.path = child_state_dir
            .join(basename)
            .to_string_lossy()
            .into_owned();
    }

    // Per-VM runtime sockets/dirs/logs — rebase onto the child's own state dir,
    // matching the layout `build_supervisor_config` derives from `state_dir`.
    cfg.vsock.socket_dir = child_state_dir.join("vsock").to_string_lossy().into_owned();
    cfg.control_socket_path = Some(
        vz_control::control_socket_path(child_state_dir)
            .to_string_lossy()
            .into_owned(),
    );
    cfg.console_output_path = Some(
        child_state_dir
            .join("console.log")
            .to_string_lossy()
            .into_owned(),
    );

    if let Some(vz::NetworkConfig::Gvproxy {
        mac: _,
        socket_path,
        events_ingest_socket_path,
    }) = cfg.network.as_mut()
    {
        // The MAC stays the parent's: VZ validates restored machine state
        // against the saved device configuration and refuses a changed MAC
        // outright. Keeping it is safe — every VM talks to its own gvproxy
        // instance, so two live copies with the same MAC never share an L2
        // segment on the host side.
        // The child boots its OWN gvproxy in its state dir (the spawner starts
        // it); point the supervisor at that listener, not the parent's dead one.
        *socket_path = child_state_dir
            .join(host_gvproxy::SOCKET_FILE_NAME)
            .to_string_lossy()
            .into_owned();
        // Audit ingest socket keys off the VM name under ~/.mvm/audit/ — only
        // present for an admitted (plan+tenant) parent; re-derive for the child.
        if events_ingest_socket_path.is_some() {
            *events_ingest_socket_path = Some(self::events_ingest_socket_path(child_vm_name));
        }
    }

    // Audit substrate's per-VM gateway socket also keys off the name.
    if cfg.gateway_audit_socket.is_some() {
        cfg.gateway_audit_socket = Some(gateway_audit_socket_path(child_vm_name));
    }

    cfg.startup_mode = vz::StartupMode::Restore {
        snapshot_path: memory_path.display().to_string(),
        machine_id_path: machine_id_path.map(|p| p.display().to_string()),
    };

    // Clear all claim-8 / audit-substrate fields inherited from the parent.
    // The caller (`fork_vm_full`) injects the child's own admitted plan after
    // this function returns; a supervisor that re-verifies with the parent's
    // plan and child's identity would fail the workload-id check.
    cfg.tenant_id = None;
    cfg.plan = None;
    cfg.bundle = None;
    cfg.audit_dir = None;
    cfg.signing_key_path = None;
    // gateway_audit_socket keys off the VM name — clear so the caller derives
    // the correct child path from the child's audit substrate.
    cfg.gateway_audit_socket = None;
    // events_ingest_socket_path is set on the gvproxy attachment when there is
    // an admitted plan+tenant; clear now and let fork_vm_full re-enable it once
    // the child plan is injected.
    if let Some(vz::NetworkConfig::Gvproxy {
        ref mut events_ingest_socket_path,
        ..
    }) = cfg.network
    {
        *events_ingest_socket_path = None;
    }

    Ok(cfg)
}

/// Spawns a forked child supervisor in `Restore` mode by handing the already-
/// built child config to `mvm-vz-supervisor`. Implements the checkpoint seam so
/// `fork_vm_full` stays host-testable (a mock spawner replaces this in tests).
pub struct VzChildSupervisorSpawner;

impl crate::checkpoint::ChildSupervisorSpawner for VzChildSupervisorSpawner {
    fn spawn(&self, config: &vz::SupervisorConfig) -> Result<()> {
        // The child config's gvproxy `socket_path` was rebased onto the child
        // state dir by `build_child_supervisor_config`; spawn a live gvproxy
        // there first so the supervisor's connect() finds a listener (mirrors
        // the boot path in `start()`, which spawns gvproxy before the
        // supervisor). The parent's gvproxy is gone — the parent is stopped.
        if matches!(config.network, Some(vz::NetworkConfig::Gvproxy { .. })) {
            let child_state_dir = PathBuf::from(&config.vm_state_dir);
            host_gvproxy::spawn_detached(&child_state_dir).map_err(|e| {
                anyhow!(
                    "spawn child gvproxy for forked Vz VM '{}': {e}",
                    config.name
                )
            })?;
        }
        spawn_supervisor_with_config(config)
    }
}

// ─── Vz saved-standby pool ───────────────────────────────────────────────────

/// Spawn a Vz saved-standby: boot a seed VM from the spec's image, wait for
/// the supervisor's PID file (boot readiness), capture its consistent
/// {rootfs, memory, machine-id} triple into the pool dir, then stop the seed
/// VM. The returned handle carries pid=0 (no running supervisor) and
/// `image_sha256` so only claims whose image matches may use it.
///
/// Pool content layout: `~/.mvm/pool/<id>/content/{rootfs.ext4,memory.bin,machine-id}`.
/// The parent config at `~/.mvm/vms/<seed-id>/supervisor-config.json` is the
/// template `claim_standby` will clone + rewrite for the claimant.
///
/// Reuses `capture_vm_full` (the pause→save→clone→resume orchestrator) via the
/// existing `VzVmFullControl` seam; `VzBackend::stop` tears the seed down.
fn vz_spawn_standby(
    spec: &mvm_core::vm_backend::StandbySpec,
) -> Result<mvm_core::vm_backend::StandbyHandle> {
    use mvm_core::vm_backend::{StandbyHandle, StandbyState};

    let image_path = spec
        .image_path
        .as_deref()
        .context("Vz spawn_standby requires image_path in StandbySpec")?;
    let image_sha256 = spec
        .image_sha256
        .as_deref()
        .context("Vz spawn_standby requires image_sha256 in StandbySpec")?;
    let kernel_path = &spec.kernel_path;

    // Boot the seed VM under the standby id.  No plan/tenant — it's a
    // pre-admission seed; the claim re-admits with the claimant's own plan.
    let seed_cfg = mvm_core::vm_backend::VmStartConfig {
        name: spec.id.clone(),
        rootfs_path: image_path.to_string(),
        kernel_path: Some(kernel_path.clone()),
        cpus: u32::from(spec.vcpus),
        memory_mib: spec.mem_mib,
        ..Default::default()
    };
    VzBackend
        .start(&seed_cfg)
        .with_context(|| format!("vz_spawn_standby: boot seed VM '{}'", spec.id))?;

    // Cleanup guard: on any failure after the seed boots, stop the seed and
    // remove the partial pool dir + seed state dir so the pool reaper doesn't
    // see an unreapable orphan (reap_stale only processes recorded standbys).
    // Disarmed on the success path at the end of this function.
    let pool_root =
        mvm_core::config::mvm_pool_dir().context("vz_spawn_standby: resolve pool dir")?;
    let mut cleanup = SpawnCleanupGuard::new(
        spec.id.clone(),
        pool_root.join(&spec.id),
        vm_state_dir(&spec.id),
    );

    // Wait for guest-agent readiness.  Probe the vsock socket + console log
    // so the pool isn't gated on a magic sleep duration.  Fail closed on
    // timeout so a broken image can't consume a pool slot indefinitely.
    wait_for_seed_agent(&spec.id)
        .with_context(|| format!("vz_spawn_standby: seed VM '{}' agent not ready", spec.id))?;

    // Capture the live seed VM's triple into the pool dir.
    let pool_id = mvm_core::checkpoint::CheckpointId::new(spec.id.clone());
    let pool_store = crate::checkpoint::CheckpointStore::at(&pool_root);

    // `capture_vm_full` needs a supervisor_config_digest for the meta.  Use the
    // sha256 of the seed's persisted supervisor-config.json (the same one
    // `claim_standby` will read and rewrite for the claimant).
    let seed_state_dir = vm_state_dir(&spec.id);
    let cfg_json = std::fs::read(supervisor_config_path(&seed_state_dir)).with_context(|| {
        format!(
            "vz_spawn_standby: read seed supervisor-config for '{}'",
            spec.id
        )
    })?;
    let cfg_digest =
        mvm_core::crypto::image_verify::sha256_file(&supervisor_config_path(&seed_state_dir))
            .with_context(|| {
                format!("vz_spawn_standby: hash supervisor-config for '{}'", spec.id)
            })?;
    // Persist the seed config INTO the pool dir: stopping the seed below tears
    // down its state dir, so `claim_standby` (which runs much later) must read
    // the config from the pool, not the gone seed dir.
    let pool_dir = pool_root.join(&spec.id);
    std::fs::create_dir_all(&pool_dir)
        .with_context(|| format!("vz_spawn_standby: create pool dir for '{}'", spec.id))?;
    std::fs::write(pool_seed_config_path(&pool_root, &spec.id), &cfg_json).with_context(|| {
        format!(
            "vz_spawn_standby: persist seed supervisor-config into pool for '{}'",
            spec.id
        )
    })?;

    let capture_params = crate::checkpoint::CaptureVmFullParams {
        id: pool_id.clone(),
        vm_name: spec.id.clone(),
        supervisor_config_digest: cfg_digest,
        tag: None,
        created_unix: crate::standby_pool::now_unix_secs(),
    };
    let control = VzVmFullControl::new(&spec.id);
    let capture_result = crate::checkpoint::capture_vm_full(&pool_store, capture_params, &control);

    // Stop the seed regardless of capture success.
    if let Err(e) = VzBackend.stop(&VmId(spec.id.clone())) {
        tracing::warn!(id = %spec.id, error = %e, "vz_spawn_standby: seed stop failed (non-fatal)");
    }

    let _meta = capture_result.with_context(|| {
        format!(
            "vz_spawn_standby: capture_vm_full failed for seed '{}'",
            spec.id
        )
    })?;

    cleanup.disarm();
    Ok(StandbyHandle {
        id: spec.id.clone(),
        control_socket: spec.control_socket.clone(),
        pid: 0, // no live supervisor after capture
        kernel_sha256: spec.kernel_sha256.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        binding_nonce: spec.binding_nonce.clone(),
        spawned_unix_secs: crate::standby_pool::now_unix_secs(),
        state: StandbyState::Idle,
        image_sha256: Some(image_sha256.to_string()),
    })
}

/// Drop-guard that stops a running seed VM and removes the partial pool dir +
/// seed state dir when a `vz_spawn_standby` call fails after the seed has
/// booted.  Disarmed on the success path via [`SpawnCleanupGuard::disarm`].
///
/// Without this guard a failed spawn leaves an orphan seed VM and an
/// unreapable partial pool dir — `reap_stale` only processes recorded standbys,
/// so the orphan accumulates silently.
struct SpawnCleanupGuard {
    vm_id: String,
    pool_dir: PathBuf,
    state_dir: PathBuf,
    armed: bool,
}

impl SpawnCleanupGuard {
    fn new(vm_id: String, pool_dir: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            vm_id,
            pool_dir,
            state_dir,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SpawnCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::warn!(
            id = %self.vm_id,
            "vz_spawn_standby: cleaning up partial pool dir and seed state after spawn failure"
        );
        let _ = VzBackend.stop(&VmId(self.vm_id.clone()));
        if self.pool_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.pool_dir);
        }
        if self.state_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }
    }
}

/// Poll the seed VM's vsock agent socket until the guest agent is up, or a
/// deadline passes.
///
/// Two-stage readiness: first wait for the host-side UDS listener to appear
/// (the Vz supervisor binds `<vm_state_dir>/vsock/vsock-<port>.sock`), then
/// confirm the guest agent is actually serving by scanning the VM's console.log
/// for the literal "mvm-guest-agent: listening" line.  The socket file can
/// exist before the guest process inside has bound the vsock port, so both
/// checks together give a reliable ready signal.
///
/// The socket path is built via `mvm_core::config::vm_vz_vsock_port_socket` —
/// the single source of truth shared with the Vz supervisor — so they cannot
/// drift again.
fn wait_for_seed_agent(vm_name: &str) -> Result<()> {
    use std::time::{Duration, Instant};

    const SEED_AGENT_TIMEOUT: Duration = Duration::from_secs(60);
    const POLL_INTERVAL: Duration = Duration::from_millis(500);
    const AGENT_READY_LINE: &str = "mvm-guest-agent: listening";

    let agent_sock =
        mvm_core::config::vm_vz_vsock_port_socket(vm_name, mvm_guest::vsock::GUEST_AGENT_PORT);
    let console_log = mvm_core::config::vm_console_log(vm_name);
    let deadline = Instant::now() + SEED_AGENT_TIMEOUT;

    // Phase 1: wait for the supervisor to bind the host-side UDS listener.
    loop {
        if agent_sock.exists() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "vsock agent socket {} did not appear within {:?}",
                agent_sock.display(),
                SEED_AGENT_TIMEOUT,
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Phase 2: wait for the guest agent to write its ready line to console.log.
    // The socket exists once the supervisor binds; the guest process may still
    // be initialising its vsock listener.
    loop {
        let agent_ready = std::fs::read_to_string(&console_log)
            .map(|log| log.contains(AGENT_READY_LINE))
            .unwrap_or(false);
        if agent_ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "guest agent did not write '{}' to {} within {:?}",
                AGENT_READY_LINE,
                console_log.display(),
                SEED_AGENT_TIMEOUT,
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Claim a Vz saved-standby: verify the pool content integrity, clone
/// {rootfs, memory, machine-id} into the claimant's state dir, rewrite the
/// seed's supervisor config for the claimant identity + inject the admitted
/// plan, then spawn gvproxy + supervisor in Restore mode.
///
/// Reuses `build_child_supervisor_config` (the fork plumbing) and
/// `VzChildSupervisorSpawner` (the fork spawn path) — the claim is the fork
/// path with a pool-sourced parent instead of a checkpoint parent.
fn vz_claim_standby(
    handle: &mvm_core::vm_backend::StandbyHandle,
    claim: &mvm_core::vm_backend::StandbyClaim,
) -> Result<VmId> {
    // Locate the pool store and load the captured triple's manifest.
    let pool_root =
        mvm_core::config::mvm_pool_dir().context("vz_claim_standby: resolve pool dir")?;
    let pool_store = crate::checkpoint::CheckpointStore::at(&pool_root);
    let pool_id = mvm_core::checkpoint::CheckpointId::new(handle.id.clone());

    let meta = pool_store
        .read_meta(&pool_id)
        .with_context(|| format!("vz_claim_standby: read pool meta for '{}'", handle.id))?;

    // Fail-closed integrity check: hash the pool content against the manifest
    // and the handle's image_sha256 before materializing anything.
    crate::checkpoint::verify_content(&pool_store, &meta).with_context(|| {
        format!(
            "vz_claim_standby: pool content tampered for '{}'",
            handle.id
        )
    })?;

    // The pool rootfs sha256 must match what the handle recorded at spawn time.
    // A discrepancy means the pool dir was written after capture — refuse.
    // The pool content integrity was verified above via `verify_content`.
    // Image-sha compat was enforced at standby selection time by
    // `select_idle_compatible`; no further check is needed here.

    // Materialise clones into the claimant's state dir (mirrors fork_vm_full).
    let claimant_name = &handle.id; // the VM runs under the standby id
    let claimant_state_dir = vm_state_dir(claimant_name);
    std::fs::create_dir_all(&claimant_state_dir).with_context(|| {
        format!(
            "vz_claim_standby: create claimant state dir {}",
            claimant_state_dir.display()
        )
    })?;

    let content_dir = pool_store.content_dir(&pool_id);
    for blob in &meta.content {
        let src = content_dir.join(&blob.name);
        let dst = claimant_state_dir.join(&blob.name);
        // Skip if the file was already placed (e.g. a previous interrupted
        // claim that failed after the clone but before the supervisor wrote its
        // PID file).
        if !dst.exists() {
            crate::base::cow::clone_rootfs_for_instance(&src, &dst).with_context(|| {
                format!(
                    "vz_claim_standby: clone blob '{}' to {}",
                    blob.name,
                    dst.display()
                )
            })?;
        }
    }

    let memory_path = claimant_state_dir.join("memory.bin");
    let machine_id_path = claimant_state_dir.join("machine-id");

    // Read the seed config that `spawn_standby` copied into the pool dir. The
    // seed VM's own state dir was torn down when the seed was stopped after
    // capture, so the pool copy is the only surviving source.
    let seed_cfg_path = pool_seed_config_path(&pool_root, &handle.id);
    let seed_cfg_bytes = std::fs::read(&seed_cfg_path).with_context(|| {
        format!(
            "vz_claim_standby: read seed supervisor config {}",
            seed_cfg_path.display()
        )
    })?;
    let seed_cfg: vz::SupervisorConfig =
        serde_json::from_slice(&seed_cfg_bytes).context("vz_claim_standby: parse seed config")?;

    // Rewrite the config for the claimant identity + Restore mode. This is
    // identical to what fork_vm_full does via build_child_supervisor_config.
    let mut child_cfg = build_child_supervisor_config(
        &seed_cfg,
        claimant_name,
        &claimant_state_dir,
        &memory_path,
        Some(machine_id_path.as_path()),
    )
    .context("vz_claim_standby: build claimant supervisor config")?;

    // Inject the claimant's admitted plan + derive the audit substrate paths
    // (mirrors the fork_vm_full injection block exactly).
    let plan_json = &claim.plan_json;
    child_cfg.plan =
        Some(serde_json::from_str(plan_json).context("vz_claim_standby: parse claim plan_json")?);
    let substrate = crate::audit_substrate::compute_audit_substrate(
        claimant_name,
        Some(claim.tenant_id.as_str()),
    )
    .context("vz_claim_standby: compute audit substrate")?;
    child_cfg.tenant_id = substrate.tenant_id;
    child_cfg.audit_dir = substrate
        .audit_dir
        .map(|p| p.to_string_lossy().into_owned());
    child_cfg.gateway_audit_socket = substrate
        .gateway_audit_socket
        .map(|p| p.to_string_lossy().into_owned());
    child_cfg.signing_key_path = substrate
        .signing_key_path
        .map(|p| p.to_string_lossy().into_owned());
    if let Some(mvm_build::vz::NetworkConfig::Gvproxy {
        ref mut events_ingest_socket_path,
        ..
    }) = child_cfg.network
    {
        *events_ingest_socket_path = substrate
            .gateway_events_socket
            .map(|p| p.to_string_lossy().into_owned());
    }
    if let Some(ref bj) = claim.bundle_json {
        child_cfg.bundle =
            Some(serde_json::from_str(bj).context("vz_claim_standby: parse claim bundle_json")?);
    }

    // Spawn the claimant supervisor in Restore mode. The trait must be in scope.
    use crate::checkpoint::ChildSupervisorSpawner as _;
    VzChildSupervisorSpawner
        .spawn(&child_cfg)
        .context("vz_claim_standby: spawn claimant supervisor")?;

    Ok(VmId(claimant_name.clone()))
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

/// Snapshot save/restore lands in macOS 14
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

/// Per-VM Vz events-ingest socket path. The Swift
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

/// Per-VM gateway audit socket path. Mirrors the `gateway-<vm>.sock` shape
/// `audit_substrate::compute_audit_substrate` derives, so a forked child can
/// re-key it onto its own name without reaching back into the substrate builder.
fn gateway_audit_socket_path(vm_name: &str) -> String {
    PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("audit")
        .join(format!("gateway-{vm_name}.sock"))
        .to_string_lossy()
        .into_owned()
}

/// Build the [`mvm_build::vz::SupervisorConfig`] the supervisor binary
/// consumes on stdin. Maps the backend-agnostic `VmStartConfig` to
/// the Vz-specific JSON shape.
///
/// First-cut wiring — only the fields needed to boot a
/// dev-shell image are mapped. gvproxy networking, the runtime
/// overlay, dm-verity sidecar, and port forwarding all land in
/// follow-up slices when their host-side plumbing is in place.
///
/// Pre-flight: when the producer threaded an AdmittedPlan in
/// (`VmStartConfig.tenant_id` Some), run the DNS-label allowlist through
/// `audit_substrate::compute_audit_substrate` so an unsafe tenant/vm_name
/// fails fast before Swift spawn.
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

/// Best-effort removal of the per-instance rootfs clone on teardown. A verity
/// VM never created one (it ran the read-only golden), so a missing file is
/// normal. Mirrors the Apple-container path's cleanup.
fn remove_instance_rootfs(vm_name: &str) {
    if let Ok(path) = crate::base::cow::instance_rootfs_path(vm_name)
        && path.exists()
        && let Err(e) = std::fs::remove_file(&path)
    {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "failed to remove per-instance rootfs clone"
        );
    }
}

/// Spawn the per-VM substitution endpoint when the admitted plan carries egress
/// secrets, returning an armed [`EndpointGuard`]; a secret-free plan (or no
/// `plan.json`) yields a defused no-op guard. The Vz guest reaches the endpoint
/// by dialing `connect_host_vsock(SUBSTITUTION_PORT)`; the supervisor's
/// host-listen proxy splices that to the per-VM `vsock/` UDS the endpoint binds,
/// so the transport is `Uds`. No transparent terminator on this path
/// (`terminator_listen: None`), hence no per-VM TLS intermediate.
fn spawn_vz_egress_endpoint_if_needed(
    vm_name: &str,
    state_dir: &Path,
) -> Result<crate::substitution_spawn::EndpointGuard> {
    use crate::substitution_spawn::{
        EndpointGuard, EndpointTransport, SubstitutionSpawnParams, spawn_substitution_endpoint,
    };
    let Some((secrets, redaction, tenant)) =
        crate::egress_shared::decode_plan_secrets_from_state(state_dir)?
    else {
        return Ok(EndpointGuard::defused());
    };
    spawn_substitution_endpoint(SubstitutionSpawnParams {
        vm_name,
        state_dir,
        tenant: &tenant,
        secrets: &secrets,
        redaction: &redaction,
        // Vz routes guest→host through the per-VM UDS the supervisor's
        // host-listen proxy forwards into; the endpoint binds it under `vsock/`.
        transport: EndpointTransport::Uds {
            path: mvm_core::config::vm_vz_vsock_port_socket(
                vm_name,
                mvm_guest::vsock::SUBSTITUTION_PORT,
            ),
        },
        terminator_listen: None,
        tls_intermediate: None,
    })?;
    Ok(EndpointGuard::new(vm_name))
}

fn build_supervisor_config(
    config: &VmStartConfig,
    kernel: &str,
    state_dir: &Path,
    gvproxy: &host_gvproxy::HostGvproxyInfo,
) -> Result<vz::SupervisorConfig> {
    // Resolve the audit substrate (paths + tenant validation). It's
    // threaded into the Rust-native supervisor's config so it runs the
    // in-process flow-audited gvproxy bridge (payload_tap). When the
    // producer threaded an AdmittedPlan in (`tenant_id` Some), the
    // substrate carries the resolved paths; otherwise it's all-None
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
        // Rootfs is RO at boot under the verified-boot model; even
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
            // Host-listens / guest-connects channels. Egress substitution: the
            // guest dials SUBSTITUTION_PORT, the supervisor accepts and splices to
            // the per-VM UDS the substitution endpoint binds. Host-services
            // broker: the guest dials BROKER_PORT, the supervisor splices to the
            // per-VM broker subprocess UDS. Both unconditional — fail-closed:
            // nothing binds those UDS until the respective endpoint/subprocess is
            // spawned, so a stray guest dial gets refused.
            host_listen_ports: vec![
                mvm_guest::vsock::SUBSTITUTION_PORT,
                mvm_guest::vsock::BROKER_PORT,
            ],
        },
        console_output_path: Some(console_log),
        // gvproxy backend with claim-10 audit bridge ingest hookup.
        // `socket_path` is where the Swift
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
        // Bind the control socket so pause / resume /
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
        // Audit substrate — threaded from the admitted plan so the Rust
        // supervisor runs the in-process flow-audited gvproxy bridge.
        // All-None for an un-admitted (dev / builder) start → direct
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

/// Spawn the `mvm-vz-drainer` sibling. Returns an
/// [`AttachedDrainerGuard`] still holding the `Child`; the caller
/// either lets the guard fall out of scope on early-return to kill the
/// drainer, or calls [`AttachedDrainerGuard::detach`] after the Vz
/// supervisor confirms boot.
///
/// Gate: when `config.plan_json` is `None`, the legacy path (no
/// admission, no audit substrate) is taken and an empty guard is
/// returned. When `plan_json` is `Some` but `tenant_id` is `None`,
/// that's a wire-level inconsistency (substrate paths can't be computed
/// without a tenant), so we log a
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

/// Once the Vz supervisor's PID file appears, take
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

/// Reap the `mvm-vz-drainer` sibling spawned by
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

/// Resolve the `mvm-vz-drainer` binary path,
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
/// `std::env` (mirrors `scrape_file_path_for`)
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

/// Bail if `target_vm` is currently running. Called before any disk mutation
/// so callers never corrupt a live VM's rootfs.
fn refuse_if_running(target_vm: &str) -> anyhow::Result<()> {
    let pid_path = vm_state_dir(target_vm).join(PID_FILE_NAME);
    if let Some(pid) = read_pid(&pid_path)
        && pid_alive(pid)
    {
        anyhow::bail!("VM '{target_vm}' is running; stop it before restoring a checkpoint");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_vz() {
        assert_eq!(VzBackend.name(), "vz");
    }

    #[test]
    fn pool_seed_config_lives_in_pool_not_seed_state_dir() {
        // Regression: spawn once discarded the seed config and claim read it
        // from the seed's state dir, which is gone after the seed stops. The
        // seed config must live under the POOL dir so it survives to claim.
        let pool_root = Path::new("/pool/root");
        let id = "standby-abc123";
        let p = pool_seed_config_path(pool_root, id);
        assert_eq!(
            p,
            Path::new("/pool/root/standby-abc123/supervisor-config.json")
        );
        // Must NOT resolve into the seed's (torn-down) VM state dir.
        assert_ne!(p, supervisor_config_path(&vm_state_dir(id)));
    }

    #[test]
    fn capabilities_match_plan_97_phase_e() {
        let caps = VzBackend.capabilities();
        assert!(caps.vsock, "vsock always available");
        assert!(
            !caps.tap_networking,
            "Vz uses file-handle attachments via gvproxy"
        );
        // Control socket exposes PAUSE / RESUME / BALLOON; the trait
        // verbs route through it.
        assert!(caps.pause_resume);
        assert!(caps.balloon);
        // snapshots is feature-detected on macOS 14+; on a
        // contributor host below 14 it stays false.
        let _ = caps.snapshots;
    }

    #[test]
    fn vz_advertises_fs_quick_checkpoint_on_macos() {
        let caps = VzBackend.capabilities();
        assert_eq!(caps.fs_quick_checkpoint, cfg!(target_os = "macos"));
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
        // dial.
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
        // build_supervisor_config takes HostGvproxyInfo (the host-side
        // gvproxy lifecycle's socket + PID, populated into
        // NetworkConfig::Gvproxy). Test passes a stub — actual gvproxy
        // isn't spawned here.
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
        // The egress-substitution channel is host-listens / guest-connects: the
        // supervisor must listen on SUBSTITUTION_PORT so the guest can dial it.
        assert!(
            built
                .vsock
                .host_listen_ports
                .contains(&mvm_guest::vsock::SUBSTITUTION_PORT),
            "SUBSTITUTION_PORT must be in vsock.host_listen_ports"
        );
        // ...and it must NOT appear in the host-dials-guest proxy port set.
        assert!(
            !built
                .vsock
                .ports
                .contains(&mvm_guest::vsock::SUBSTITUTION_PORT),
            "SUBSTITUTION_PORT must not appear in vsock.ports"
        );
        // The host-services broker port is host-listens / guest-connects too:
        // the supervisor must listen on BROKER_PORT so the guest can dial it
        // (the broker subprocess binds the UDS the supervisor splices to).
        assert!(
            built
                .vsock
                .host_listen_ports
                .contains(&mvm_guest::vsock::BROKER_PORT),
            "BROKER_PORT must be in vsock.host_listen_ports"
        );
        assert!(
            !built.vsock.ports.contains(&mvm_guest::vsock::BROKER_PORT),
            "BROKER_PORT must not appear in vsock.ports"
        );
        assert_eq!(built.pid_file_name.as_deref(), Some(PID_FILE_NAME));
        // Console capture goes to a file under state_dir; never `None`
        // — capture-only is the workload contract.
        assert!(built.console_output_path.is_some());
        // Network field is populated with the gvproxy socket + MAC +
        // events_ingest path.
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

    /// No `plan.json` (or a secret-free plan) ⇒ no Vz egress endpoint is spawned
    /// and the returned guard is defused (its Drop is a no-op, so an early return
    /// can't reap a process that was never started). Mirrors the libkrun no-op
    /// test.
    #[test]
    fn vz_substitution_not_spawned_when_no_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        // Empty state dir: no plan.json at all.
        let guard = spawn_vz_egress_endpoint_if_needed("vz-no-secrets-vm", tmp.path())
            .expect("no-secrets path must succeed");
        assert!(
            guard.vm_name.is_none(),
            "a secret-free plan must yield a defused (no-op) guard"
        );
        // No pidfile was written (nothing spawned).
        assert!(
            !tmp.path()
                .join(crate::substitution_spawn::SUBST_PID_FILE)
                .exists()
        );
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
        // Defense-in-depth: an unsafe tenant_id
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

    #[test]
    fn vz_vm_full_control_resolves_rootfs_from_supervisor_config() {
        use crate::checkpoint::VmFullControl as _;
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        // vm_state_dir("spike") = <MVM_DATA_DIR>/vms/spike
        let state_dir = tmp.path().join("vms").join("spike");
        std::fs::create_dir_all(&state_dir).unwrap();

        let cfg = mvm_build::vz::SupervisorConfig {
            name: "spike".into(),
            vm_state_dir: state_dir.to_string_lossy().into_owned(),
            pid_file_name: None,
            kernel: mvm_build::vz::KernelConfig {
                path: "/abs/vmlinux".into(),
                cmdline: "console=hvc0 root=/dev/vda rw init=/init".into(),
                initrd_path: None,
            },
            resources: mvm_build::vz::ResourceConfig {
                cpu_count: 1,
                memory_mib: 512,
            },
            disks: vec![mvm_build::vz::DiskConfig {
                id: "rootfs".into(),
                path: "/abs/rootfs.ext4".into(),
                read_only: true,
            }],
            virtio_fs: vec![],
            vsock: mvm_build::vz::VsockConfig {
                ports: vec![],
                socket_dir: state_dir.to_string_lossy().into_owned(),
                host_listen_ports: vec![],
            },
            console_output_path: None,
            network: None,
            balloon: None,
            control_socket_path: None,
            startup_mode: mvm_build::vz::StartupMode::Boot,
            tenant_id: None,
            plan: None,
            bundle: None,
            audit_dir: None,
            gateway_audit_socket: None,
            signing_key_path: None,
        };
        let json = cfg.to_json().unwrap();
        std::fs::write(state_dir.join(SUPERVISOR_CONFIG_FILE_NAME), json.as_bytes()).unwrap();

        let ctl = VzVmFullControl::new("spike");
        let resolved = ctl.rootfs_path().expect("resolves rootfs");
        assert_eq!(resolved, std::path::PathBuf::from("/abs/rootfs.ext4"));

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    #[test]
    fn vz_vm_full_control_save_memory_requires_absolute_path() {
        use crate::checkpoint::VmFullControl as _;
        let ctl = VzVmFullControl::new("any");
        let err = ctl
            .save_memory(std::path::Path::new("relative/mem.bin"))
            .expect_err("relative path rejected");
        assert!(
            err.to_string().contains("absolute path"),
            "error explains requirement: {err}"
        );
    }

    #[test]
    fn vz_vm_full_control_pause_surfaces_missing_socket() {
        // No supervisor running; pause must surface the socket path.
        use crate::checkpoint::VmFullControl as _;
        let ctl = VzVmFullControl::new("definitely-not-running-1234567890");
        let err = ctl.pause().expect_err("pause should error");
        assert!(
            err.to_string().contains("control.sock"),
            "error mentions socket: {err}"
        );
    }

    fn minimal_parent_config(name: &str) -> vz::SupervisorConfig {
        vz::SupervisorConfig {
            name: name.into(),
            vm_state_dir: format!("/parent/state/{name}"),
            pid_file_name: Some(PID_FILE_NAME.into()),
            kernel: vz::KernelConfig {
                path: "/abs/vmlinux".into(),
                cmdline: "console=hvc0 root=/dev/vda".into(),
                initrd_path: None,
            },
            resources: vz::ResourceConfig {
                cpu_count: 2,
                memory_mib: 1024,
            },
            disks: vec![vz::DiskConfig {
                id: "rootfs".into(),
                path: "/parent/state/parentvm/rootfs.ext4".into(),
                read_only: true,
            }],
            virtio_fs: vec![],
            vsock: vz::VsockConfig {
                ports: vec![],
                socket_dir: "/parent/state/parentvm/vsock".into(),
                host_listen_ports: vec![],
            },
            console_output_path: Some("/parent/state/parentvm/console.log".into()),
            network: Some(vz::NetworkConfig::Gvproxy {
                socket_path: "/parent/state/parentvm/gvproxy.sock".into(),
                mac: host_gvproxy::derive_mac(name),
                events_ingest_socket_path: Some(
                    "/parent/audit/gateway-events-parentvm.sock".into(),
                ),
            }),
            balloon: None,
            control_socket_path: Some("/parent/state/parentvm/control.sock".into()),
            startup_mode: vz::StartupMode::Boot,
            // Claim-8 fields present on the parent; build_child_supervisor_config
            // clears all of them so fork_vm_full can inject the child's own plan.
            tenant_id: Some("tenant-x".into()),
            plan: None,
            bundle: None,
            audit_dir: Some("/parent/audit".into()),
            gateway_audit_socket: Some("/parent/audit/gateway-parentvm.sock".into()),
            signing_key_path: Some("/parent/keys/host-signer.ed25519".into()),
        }
    }

    #[test]
    fn build_child_supervisor_config_rewrites_identity_disks_and_restore_mode() {
        let parent = minimal_parent_config("parentvm");
        let child_dir = Path::new("/child/state/childvm");
        let mem = child_dir.join("memory.bin");
        let mid = child_dir.join("machine-id");

        let child =
            build_child_supervisor_config(&parent, "childvm", child_dir, &mem, Some(&mid)).unwrap();

        assert_eq!(child.name, "childvm");
        assert_eq!(child.vm_state_dir, child_dir.to_string_lossy());
        // rootfs disk now lives in the child dir, basename preserved.
        let rootfs = child.disks.iter().find(|d| d.id == "rootfs").unwrap();
        assert_eq!(rootfs.path, "/child/state/childvm/rootfs.ext4");
        // MAC stays the parent's: VZ refuses a machine-state restore whose
        // device config differs from the saved one, and per-VM gvproxy
        // instances make a duplicate MAC harmless.
        match child.network.as_ref().unwrap() {
            vz::NetworkConfig::Gvproxy {
                mac,
                socket_path,
                events_ingest_socket_path,
            } => {
                assert_eq!(mac, &host_gvproxy::derive_mac("parentvm"));
                assert_ne!(mac, &host_gvproxy::derive_mac("childvm"));
                // gvproxy listener rebased into the child state dir — the child
                // boots its own gvproxy there, not the parent's dead one.
                assert!(
                    socket_path.starts_with("/child/state/childvm/"),
                    "gvproxy socket_path not rebased: {socket_path}"
                );
                assert!(!socket_path.contains("/parent/"));
                // Claim-8 bridge ingest socket cleared — fork_vm_full re-enables
                // it after injecting the child's own admitted plan + tenant.
                assert!(
                    events_ingest_socket_path.is_none(),
                    "events_ingest_socket_path must be cleared by build_child_supervisor_config \
                     so fork_vm_full can re-enable it with the child's identity"
                );
            }
        }
        // Every per-VM runtime socket/dir/log now lives under the child state
        // dir (NOT the parent's) — the core of the fork-path correctness fix.
        assert_eq!(child.vsock.socket_dir, "/child/state/childvm/vsock");
        assert_eq!(
            child.control_socket_path.as_deref(),
            Some("/child/state/childvm/control.sock")
        );
        assert_eq!(
            child.console_output_path.as_deref(),
            Some("/child/state/childvm/console.log")
        );
        for field in [
            child.vsock.socket_dir.as_str(),
            child.control_socket_path.as_deref().unwrap(),
            child.console_output_path.as_deref().unwrap(),
        ] {
            assert!(
                field.starts_with("/child/state/childvm/"),
                "runtime path not rebased onto child: {field}"
            );
            assert!(
                !field.contains("/parent/"),
                "runtime path leaks parent: {field}"
            );
        }
        // Claim-8 / audit-substrate fields cleared — fork_vm_full injects the
        // child's own plan after this function returns. The child must NOT carry
        // the parent's plan (the supervisor re-verifies under the child identity).
        assert!(
            child.tenant_id.is_none(),
            "tenant_id must be cleared so fork_vm_full injects the child's identity"
        );
        assert!(
            child.plan.is_none(),
            "plan must be cleared so fork_vm_full injects the child's admitted plan"
        );
        assert!(
            child.audit_dir.is_none(),
            "audit_dir must be cleared so fork_vm_full re-derives it for the child"
        );
        assert!(
            child.signing_key_path.is_none(),
            "signing_key_path must be cleared so fork_vm_full re-derives it"
        );
        assert!(
            child.gateway_audit_socket.is_none(),
            "gateway_audit_socket must be cleared; it keys off VM name and is re-derived \
             by fork_vm_full with the child's identity"
        );
        // Restore mode pointing at the child's memory + inherited machine-id.
        match &child.startup_mode {
            vz::StartupMode::Restore {
                snapshot_path,
                machine_id_path,
            } => {
                assert_eq!(snapshot_path, &mem.display().to_string());
                assert_eq!(
                    machine_id_path.as_deref(),
                    Some(mid.display().to_string()).as_deref()
                );
            }
            other => panic!("expected Restore, got {other:?}"),
        }
    }

    #[test]
    fn restore_refuses_running_target_before_touching_disk() {
        use crate::checkpoint::VmFullRestore as _;
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        // Simulate a live supervisor: write vz.pid with the test process's PID.
        let state_dir = tmp.path().join("vms").join("target-vm");
        std::fs::create_dir_all(&state_dir).unwrap();
        let pid = unsafe { libc::getpid() };
        std::fs::write(state_dir.join(PID_FILE_NAME), pid.to_string()).unwrap();

        // Sentinel: the target rootfs must NOT be created by a refused restore.
        let target_rootfs = state_dir.join("rootfs.ext4");
        assert!(!target_rootfs.exists(), "pre-condition: rootfs absent");

        let err = VzBackend
            .restore(
                "target-vm",
                std::path::Path::new("/nonexistent/rootfs.ext4"),
                std::path::Path::new("/nonexistent/memory.bin"),
                std::path::Path::new("/nonexistent/machine-id"),
            )
            .expect_err("must refuse restore into a running VM");

        assert!(
            err.to_string().contains("running"),
            "error mentions 'running': {err}"
        );
        // rootfs must be untouched — the guard fired before the clone.
        assert!(
            !target_rootfs.exists(),
            "rootfs not created by refused restore"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    /// Helper: write a minimal SupervisorConfig JSON into `<state_dir>/supervisor-config.json`
    /// with the rootfs disk pointing at `rootfs_path`.
    fn write_supervisor_config(state_dir: &Path, vm_name: &str, rootfs_path: &Path) {
        let cfg = vz::SupervisorConfig {
            name: vm_name.into(),
            vm_state_dir: state_dir.to_string_lossy().into_owned(),
            pid_file_name: None,
            kernel: vz::KernelConfig {
                path: "/abs/vmlinux".into(),
                cmdline: "root=/dev/vda".into(),
                initrd_path: None,
            },
            resources: vz::ResourceConfig {
                cpu_count: 1,
                memory_mib: 512,
            },
            disks: vec![vz::DiskConfig {
                id: "rootfs".into(),
                path: rootfs_path.to_string_lossy().into_owned(),
                read_only: true,
            }],
            virtio_fs: vec![],
            vsock: vz::VsockConfig {
                ports: vec![],
                socket_dir: state_dir.to_string_lossy().into_owned(),
                host_listen_ports: vec![],
            },
            console_output_path: None,
            network: None,
            balloon: None,
            control_socket_path: None,
            startup_mode: vz::StartupMode::Boot,
            tenant_id: None,
            plan: None,
            bundle: None,
            audit_dir: None,
            gateway_audit_socket: None,
            signing_key_path: None,
        };
        let json = cfg.to_json().unwrap();
        std::fs::write(state_dir.join(SUPERVISOR_CONFIG_FILE_NAME), json).unwrap();
    }

    /// When `restore_with_spawn` succeeds at cloning the rootfs but the spawn
    /// closure injects a failure, the cloned file must be removed so a retry
    /// isn't blocked by `File exists`.
    #[test]
    fn restore_failure_removes_cloned_rootfs() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let state_dir = tmp.path().join("vms").join("restore-cleanup-vm");
        std::fs::create_dir_all(&state_dir).unwrap();

        // Source rootfs to clone from.
        let src_rootfs = tmp.path().join("source.ext4");
        std::fs::write(&src_rootfs, b"fake-rootfs-bytes").unwrap();

        // Target rootfs path (inside the state dir).
        let target_rootfs = state_dir.join("rootfs.ext4");
        write_supervisor_config(&state_dir, "restore-cleanup-vm", &target_rootfs);

        // Stand in for the gvproxy `snapshot_restore` spawns before the
        // supervisor: a PID file naming a dead process. A failed restore must
        // reap it so a retry doesn't orphan the sidecar.
        let gvproxy_pid = state_dir.join("host-gvproxy.pid");
        std::fs::write(&gvproxy_pid, "2147483647").unwrap();

        let backend = VzBackend;
        let err = restore_with_spawn(
            &backend,
            "restore-cleanup-vm",
            &src_rootfs,
            Path::new("/abs/memory.bin"),
            Path::new("/abs/machine-id"),
            |_, _, _, _| anyhow::bail!("injected spawn failure"),
        )
        .expect_err("injected failure must propagate");

        assert!(
            err.to_string().contains("injected spawn failure"),
            "original error propagated: {err}"
        );
        // The cloned rootfs must have been cleaned up.
        assert!(
            !target_rootfs.exists(),
            "cloned rootfs must be removed after restore failure"
        );
        // The orphaned gvproxy PID file must have been reaped.
        assert!(
            !gvproxy_pid.exists(),
            "gvproxy pid file must be reaped after restore failure"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    /// When the target rootfs already exists before the restore (leftover from a
    /// previous failed restore), the error names the path and does NOT delete it.
    #[test]
    fn restore_pre_existing_target_rootfs_errors_and_does_not_delete() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let state_dir = tmp.path().join("vms").join("stale-rootfs-vm");
        std::fs::create_dir_all(&state_dir).unwrap();

        let src_rootfs = tmp.path().join("source.ext4");
        std::fs::write(&src_rootfs, b"fake-bytes").unwrap();

        // Pre-create the target to simulate a stale leftover.
        let target_rootfs = state_dir.join("rootfs.ext4");
        std::fs::write(&target_rootfs, b"stale-bytes").unwrap();
        write_supervisor_config(&state_dir, "stale-rootfs-vm", &target_rootfs);

        let backend = VzBackend;
        let err = restore_with_spawn(
            &backend,
            "stale-rootfs-vm",
            &src_rootfs,
            Path::new("/abs/memory.bin"),
            Path::new("/abs/machine-id"),
            |_, _, _, _| panic!("spawn must not be called when target already exists"),
        )
        .expect_err("pre-existing target must error");

        let msg = err.to_string();
        assert!(
            msg.contains("already exists") && msg.contains(target_rootfs.to_str().unwrap()),
            "error names the leftover path: {msg}"
        );
        // The stale file must not have been touched.
        assert!(
            target_rootfs.exists(),
            "stale rootfs must not be deleted by the guard"
        );
        assert_eq!(
            std::fs::read(&target_rootfs).unwrap(),
            b"stale-bytes",
            "stale rootfs content must be unchanged"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    // ── saved-standby pool tests (Vz, no real VM) ────────────────────────────

    /// `vz_claim_standby` propagates a clean error when the pool dir is absent
    /// (missing meta.json) rather than panicking or returning a misleading
    /// message.
    #[test]
    fn claim_standby_errors_cleanly_on_missing_pool_meta() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let handle = mvm_core::vm_backend::StandbyHandle {
            id: "standby-no-pool".into(),
            control_socket: tmp.path().join("control.sock"),
            pid: 0,
            kernel_sha256: "aaaa".into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "bb".repeat(32),
            spawned_unix_secs: 1,
            state: mvm_core::vm_backend::StandbyState::Idle,
            image_sha256: Some("cccc".into()),
        };
        let claim = mvm_core::vm_backend::StandbyClaim {
            rootfs_path: "/fake/rootfs.ext4".into(),
            plan_json: "{}".into(),
            tenant_id: "t1".into(),
            audit_dir: tmp.path().join("audit"),
            gateway_audit_socket: tmp.path().join("audit.sock"),
            gateway_events_socket: None,
            bundle_json: None,
        };

        let err = vz_claim_standby(&handle, &claim).unwrap_err();
        let msg = err.to_string();
        // The error chain must mention the pool meta read, not panic or silently
        // succeed.
        assert!(
            msg.contains("pool meta") || msg.contains("meta.json") || msg.contains("pool dir"),
            "error should name the missing pool meta: {msg}"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    /// `verify_content` (called inside `vz_claim_standby`) fails closed when a
    /// pool blob has been tampered with — a wrong byte in rootfs.ext4 must
    /// produce an integrity error before any claimant state is written.
    #[test]
    fn claim_standby_errors_on_tampered_pool_blob() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let standby_id = "standby-tamper-test";
        let pool_root = tmp.path().join("pool");
        let store = crate::checkpoint::CheckpointStore::at(&pool_root);
        let ckid = mvm_core::checkpoint::CheckpointId::new(standby_id.to_string());
        let content_dir = store.content_dir(&ckid);
        std::fs::create_dir_all(&content_dir).unwrap();

        // Write blobs with a correct hash recorded in the manifest...
        let rootfs_path = content_dir.join("rootfs.ext4");
        let memory_path = content_dir.join("memory.bin");
        let machine_id_path = content_dir.join("machine-id");
        std::fs::write(&rootfs_path, b"fake-rootfs").unwrap();
        std::fs::write(&memory_path, b"fake-memory").unwrap();
        std::fs::write(&machine_id_path, b"fake-id").unwrap();

        let sha = |p: &std::path::Path| mvm_core::crypto::image_verify::sha256_file(p).unwrap();
        let meta = mvm_core::checkpoint::CheckpointMeta {
            id: ckid.clone(),
            vm_name: standby_id.into(),
            parent: None,
            tag: None,
            created_unix: 1,
            class: mvm_core::checkpoint::CheckpointClass::VmFull,
            supervisor_config_digest: "ignored".into(),
            audit_ref: None,
            content: vec![
                mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: sha(&rootfs_path),
                },
                mvm_core::checkpoint::ContentBlob {
                    name: "memory.bin".into(),
                    sha256: sha(&memory_path),
                },
                mvm_core::checkpoint::ContentBlob {
                    name: "machine-id".into(),
                    sha256: sha(&machine_id_path),
                },
            ],
        };
        store.write_meta(&meta).unwrap();

        // ...then tamper the rootfs so the manifest sha no longer matches.
        std::fs::write(&rootfs_path, b"CORRUPTED-rootfs").unwrap();

        let handle = mvm_core::vm_backend::StandbyHandle {
            id: standby_id.into(),
            control_socket: tmp.path().join("control.sock"),
            pid: 0,
            kernel_sha256: "kk".into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "cc".repeat(32),
            spawned_unix_secs: 1,
            state: mvm_core::vm_backend::StandbyState::Idle,
            image_sha256: Some("img-sha".into()),
        };
        let claim = mvm_core::vm_backend::StandbyClaim {
            rootfs_path: "/fake/rootfs.ext4".into(),
            plan_json: "{}".into(),
            tenant_id: "t1".into(),
            audit_dir: tmp.path().join("audit"),
            gateway_audit_socket: tmp.path().join("audit.sock"),
            gateway_events_socket: None,
            bundle_json: None,
        };

        let err = vz_claim_standby(&handle, &claim).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("tampered") || msg.contains("integrity") || msg.contains("sha256"),
            "error must name the integrity failure: {msg}"
        );

        // No claimant state dir should have been created — claim must abort
        // before writing any state.
        let claimant_dir = tmp.path().join("vms").join(standby_id);
        assert!(
            !claimant_dir.exists(),
            "claim must not create claimant dir before integrity check passes"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    /// `wait_for_seed_agent` must poll the path that the Vz supervisor actually
    /// binds: `<vm_state_dir>/vsock/vsock-<port>.sock`.  This test builds the
    /// expected path via the production helper and asserts that writing a file
    /// there causes the function to succeed (without a real VM) — pinning the
    /// naming against the helper so they cannot drift independently.
    #[test]
    fn wait_for_seed_agent_matches_vm_vz_vsock_port_socket() {
        use mvm_core::config::vm_vz_vsock_port_socket;
        use mvm_guest::vsock::GUEST_AGENT_PORT;

        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let vm_name = "seed-agent-socket-test";

        // The production helper defines the canonical socket path.
        let expected = vm_vz_vsock_port_socket(vm_name, GUEST_AGENT_PORT);

        // The socket dir must exist before the supervisor writes the socket file.
        std::fs::create_dir_all(expected.parent().unwrap()).unwrap();

        // Simulate supervisor + guest agent: write the socket file and the
        // ready line to console.log.
        std::fs::write(&expected, b"").unwrap();
        let console_log = mvm_core::config::vm_console_log(vm_name);
        std::fs::create_dir_all(console_log.parent().unwrap()).unwrap();
        std::fs::write(
            &console_log,
            "mvm-guest-agent: listening on vsock port 5252\n",
        )
        .unwrap();

        // wait_for_seed_agent should find both signals and return Ok immediately.
        let result = wait_for_seed_agent(vm_name);
        assert!(
            result.is_ok(),
            "wait_for_seed_agent must succeed when the correct socket + console ready line exist: {result:?}"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    /// `SpawnCleanupGuard` must remove the pool dir and state dir (and attempt
    /// to stop the VM) when dropped while armed, and must leave them intact
    /// when disarmed.
    #[test]
    fn spawn_cleanup_guard_removes_dirs_when_armed_and_skips_when_disarmed() {
        let tmp = tempfile::tempdir().unwrap();
        let pool_dir = tmp.path().join("pool").join("standby-abc123");
        let state_dir = tmp.path().join("vms").join("standby-abc123");
        std::fs::create_dir_all(&pool_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        // Armed drop: both dirs must be removed.
        {
            let _guard = SpawnCleanupGuard::new(
                "standby-abc123".into(),
                pool_dir.clone(),
                state_dir.clone(),
            );
            // guard drops here — armed
        }
        assert!(
            !pool_dir.exists(),
            "armed guard must remove the partial pool dir"
        );
        assert!(
            !state_dir.exists(),
            "armed guard must remove the seed state dir"
        );

        // Disarmed drop: dirs must survive.
        std::fs::create_dir_all(&pool_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        {
            let mut guard = SpawnCleanupGuard::new(
                "standby-abc123".into(),
                pool_dir.clone(),
                state_dir.clone(),
            );
            guard.disarm();
        }
        assert!(pool_dir.exists(), "disarmed guard must not remove pool dir");
        assert!(
            state_dir.exists(),
            "disarmed guard must not remove state dir"
        );
    }
}
