//! `HvfBackend` — the `VmBackend` impl for the raw-HVF macOS path (Plan 214).
//!
//! Lifecycle mirrors the other detached-supervisor backends (vz/libkrun): `start`
//! builds an [`HvfSupervisorConfig`] from the `VmStartConfig`, spawns
//! `mvm-hvf-supervisor` with the JSON on stdin, and waits for it to write its PID
//! file (boot confirmed). `stop` signals that PID; `status` probes it with
//! `kill(pid, 0)`; `list` walks `~/.mvm/vms/*/hvf.pid`; `logs` reads the captured
//! `console.log`. The guest boots through `boot_kernel` → the unified `vmm::run`
//! loop inside the supervisor.
//!
//! Transient by default (VM life = workload life): the guest runs its entrypoint
//! and reports its exit code over the workload-exit vsock port, which ends the run;
//! `wait` returns that code. A persistent (`-d`) VM instead runs until `stop`. With
//! vsock + optional virtio-blk. Not yet: pause/resume/snapshot, and vsock-mediated
//! networking/egress (ADR-100).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_build::hvf_supervisor::HvfSupervisorConfig;
use mvm_core::config::{mvm_data_dir, vm_state_dir};
use mvm_core::vm_backend::{
    VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::base::ui;

/// PID file the supervisor writes inside `vm_state_dir`. Distinct from the other
/// backends' markers so HVF VMs coexist under the same `~/.mvm/vms/` root.
const PID_FILE_NAME: &str = "hvf.pid";
/// How long `start` waits for the supervisor to confirm boot (PID file).
const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);

/// Raw HVF (`Hypervisor.framework`) backend. macOS / Apple-silicon only.
pub struct HvfBackend;

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 probes existence/permission without delivering a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Locate the per-VM supervisor binary: `$MVM_HVF_SUPERVISOR_PATH`, else
/// alongside the current executable (release + `cargo` layouts both put it there).
fn resolve_supervisor_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("MVM_HVF_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "MVM_HVF_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-hvf-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "mvm-hvf-supervisor binary not found (looked at $MVM_HVF_SUPERVISOR_PATH \
         and alongside the current exe)"
    )
}

fn vms_root() -> PathBuf {
    PathBuf::from(mvm_data_dir()).join("vms")
}

impl VmBackend for HvfBackend {
    fn name(&self) -> &str {
        "hvf"
    }

    fn capabilities(&self) -> VmCapabilities {
        // vsock is live-proven through the unified run loop; the rest land as
        // pause/snapshot/networking are wired onto the primitive.
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            vsock: true,
            tap_networking: false,
            balloon: false,
            fs_quick_checkpoint: false,
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        // No parent-entitlement gate here: the detached supervisor self-signs the
        // hypervisor entitlement and does the HVF work. The parent (CLI) only
        // spawns it, so it needn't be entitled. (`is_available` still probes for
        // selection/doctor.)
        let kernel = config
            .kernel_path
            .clone()
            .ok_or_else(|| anyhow!("hvf backend requires an arm64 kernel Image (kernel_path)"))?;

        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        let pid_file = state_dir.join(PID_FILE_NAME);
        let console_log = state_dir.join("console.log");
        // Create/truncate the console capture file up front.
        let _ = crate::libkrun::open_console_capture(&console_log);

        // Clear any prior run's exit code so `wait` reads only this launch's.
        let workload_exit = state_dir.join("workload.exit");
        let _ = std::fs::remove_file(&workload_exit);

        let disk = Some(config.rootfs_path.clone())
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        // A transient workload ends the VM by reporting its exit code over the
        // vsock exit port (the default — VM life = workload life); a persistent
        // (`-d`) VM ends on `stop`. MVM_HVF_TIMEOUT is only a backstop cap
        // (0 = none) against a guest that never reports + is never stopped.
        let timeout_secs = std::env::var("MVM_HVF_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let cfg = HvfSupervisorConfig {
            kernel: PathBuf::from(kernel),
            initramfs: config.initrd_path.clone().map(PathBuf::from),
            disk,
            vsock: true,
            console_log: console_log.clone(),
            pid_file: pid_file.clone(),
            workload_exit,
            timeout_secs,
        };
        let json = serde_json::to_string(&cfg)
            .map_err(|e| anyhow!("serialize HvfSupervisorConfig: {e}"))?;

        let supervisor = resolve_supervisor_path()?;
        ui::info(&format!(
            "Starting HVF VM '{}' via {}...",
            config.name,
            supervisor.display()
        ));

        let mut child = Command::new(&supervisor)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe HvfSupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file (boot confirmed). If the supervisor exits first,
        // surface that — its stderr (inherited) carries the actionable detail.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        loop {
            if pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor: {e}"))?
            {
                bail!(
                    "hvf supervisor exited before writing its PID file (status: {status}); \
                     see {}",
                    console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "hvf supervisor did not confirm boot within {PID_FILE_TIMEOUT:?}; see {}",
                    console_log.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Detach: dropping the `Child` does not kill the process, so the
        // supervisor outlives this CLI invocation (reaped via its PID file).
        drop(child);
        ui::success(&format!(
            "HVF VM '{}' started (pid file: {}, console: {}).",
            config.name,
            pid_file.display(),
            console_log.display()
        ));
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        // Transient run-to-exit: block until the supervisor persists the guest's
        // workload exit code to `<state>/workload.exit` (shared helper, same file
        // every backend writes).
        Ok(crate::workload_wait::wait_for_workload_exit(&vm_state_dir(
            &id.0,
        )))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let pid_path = vm_state_dir(&id.0).join(PID_FILE_NAME);
        if let Some(pid) = read_pid(&pid_path) {
            // SIGTERM (default action terminates — the supervisor installs no
            // handler), then SIGKILL if it lingers. The HVF VM dies with it.
            // SAFETY: signalling a pid we recorded.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while pid_alive(pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if pid_alive(pid) {
                // SAFETY: same pid.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let _ = std::fs::remove_file(&pid_path);
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        for vm in self.list()? {
            let _ = self.stop(&vm.id);
        }
        Ok(())
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        bail!("hvf pause/resume is not yet implemented (no snapshot/pause support)")
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        bail!("hvf pause/resume is not yet implemented (no snapshot/pause support)")
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let pid_path = vm_state_dir(&id.0).join(PID_FILE_NAME);
        Ok(match read_pid(&pid_path) {
            Some(pid) if pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
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
            let pid_path = entry.path().join(PID_FILE_NAME);
            if !pid_path.exists() {
                continue; // not an HVF-managed VM
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
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

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        // Capture-only console; one log (no separate hypervisor stream).
        let log = vm_state_dir(&id.0).join("console.log");
        std::fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))
    }

    fn is_available(&self) -> Result<bool> {
        Ok(hvf_probe())
    }

    fn install(&self) -> Result<()> {
        ui::info("Hypervisor.framework is built into macOS; no host install needed.");
        if !hvf_probe() {
            ui::info(
                "HVF unavailable — needs macOS / Apple silicon (and the binary \
                 codesigned with com.apple.security.hypervisor).",
            );
        }
        Ok(())
    }
}

/// Probe whether HVF can actually run here. The backend's lifecycle is
/// platform-agnostic (spawns a binary + tracks PID files), so it compiles
/// everywhere; only this probe is macOS/Apple-silicon-specific.
fn hvf_probe() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        crate::hvf::probe_available()
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_as_hvf() {
        assert_eq!(HvfBackend.name(), "hvf");
    }

    #[test]
    fn vsock_is_capable_pause_snapshot_are_not() {
        let c = HvfBackend.capabilities();
        assert!(c.vsock, "vsock is live-proven");
        assert!(!c.pause_resume);
        assert!(!c.snapshots);
        assert!(!c.tap_networking);
    }

    #[test]
    fn pause_resume_report_unimplemented() {
        let id = VmId("x".into());
        assert!(HvfBackend.pause(&id).is_err());
        assert!(HvfBackend.resume(&id).is_err());
    }

    #[test]
    fn unknown_vm_is_stopped_and_stop_is_idempotent() {
        let id = VmId("hvf-nonexistent-test-vm".into());
        assert_eq!(HvfBackend.status(&id).unwrap(), VmStatus::Stopped);
        assert!(HvfBackend.stop(&id).is_ok());
    }

    #[test]
    fn supervisor_path_env_must_point_at_a_file() {
        // SAFETY: single-threaded test mutation of a process env var.
        unsafe { std::env::set_var("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor") };
        let r = resolve_supervisor_path();
        unsafe { std::env::remove_var("MVM_HVF_SUPERVISOR_PATH") };
        assert!(r.is_err());
    }
}
