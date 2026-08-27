//! `HvfBackend` — the `VmBackend` impl for the raw-HVF macOS path.
//!
//! Lifecycle mirrors the other detached-supervisor backend (libkrun): `start`
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
//! networking/egress.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::config::vms_dir;
use mvm_core::vm_backend::VmStartConfig;
use mvm_vmm::host::hvf_supervisor::{HostDialSocket, HvfDisk};

use mvm_vmm::host::cmdline;

/// PID file the supervisor writes inside `vm_state_dir`. Distinct from the other
/// backends' markers so HVF VMs coexist under the same `~/.mvm/vms/` root.
pub(crate) const PID_FILE_NAME: &str = "hvf.pid";
/// How long `start` waits for the supervisor to confirm boot (PID file). Shared
/// with the hvf driver, which spawns the same supervisor binary.
pub(crate) const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);
pub const PAUSE_ACK_TIMEOUT: Duration = Duration::from_secs(2);

pub fn hvf_console_data_sockets(state_dir: &Path, dev_console: bool) -> Vec<HostDialSocket> {
    mvm_vmm::host::spec_map::console_data_sockets(state_dir, dev_console)
        .into_iter()
        .map(|(guest_port, host_socket)| HostDialSocket {
            guest_port,
            host_socket,
        })
        .collect()
}

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    mvm_vmm::host::process_liveness::pid_is_alive(pid)
}

pub fn wait_for_pid_exit(
    pid: libc::pid_t,
    timeout: Duration,
    observer: Option<&mvm_vmm::host::process_exit::ProcessExitObserver>,
) -> bool {
    mvm_vmm::host::process_exit::wait_for_pid_exit(pid, Instant::now() + timeout, observer)
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TerminationTiming {
    pub supervisor_signal: Duration,
    pub pid_disappearance: Duration,
    pub force_kill_wait: Duration,
}

/// SIGTERM a recorded pid, then SIGKILL if it lingers past a short grace. When
/// the supervisor is still this process's child, reap it with `waitpid` so an
/// already-exited zombie does not look alive for the full grace window.
/// Shared by the `VmBackend` stop path and the hvf driver's `kill`.
pub(crate) fn terminate_pid_timed(pid: libc::pid_t) -> Result<TerminationTiming> {
    let observer = mvm_vmm::host::process_exit::ProcessExitObserver::arm(pid).ok();
    let signal_started = Instant::now();
    // SAFETY: signalling a pid we recorded from our own supervisor.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let supervisor_signal = signal_started.elapsed();

    let wait_started = Instant::now();
    let exited = wait_for_pid_exit(pid, Duration::from_secs(5), observer.as_ref());
    let pid_disappearance = wait_started.elapsed();
    if exited {
        return Ok(TerminationTiming {
            supervisor_signal,
            pid_disappearance,
            force_kill_wait: Duration::ZERO,
        });
    }

    let force_started = Instant::now();
    let force_kill_wait = if pid_alive(pid) {
        // SAFETY: same pid.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        if !wait_for_pid_exit(pid, Duration::from_millis(500), observer.as_ref()) {
            return Err(anyhow!(
                "hvf supervisor pid {pid} could not be proven dead after SIGKILL"
            ));
        }
        force_started.elapsed()
    } else {
        Duration::ZERO
    };
    Ok(TerminationTiming {
        supervisor_signal,
        pid_disappearance,
        force_kill_wait,
    })
}

/// Ask a running HVF supervisor to change its vCPU execution state.
///
/// The supervisor owns the HVF VM and translates these signals into the
/// atomic controls consumed by the unified run loop. Keeping the signal
/// operation here gives both the legacy `VmBackend` surface and the driver
/// surface the same liveness and error handling.
pub(crate) fn signal_vm(pid_path: &Path, signal: libc::c_int, operation: &str) -> Result<()> {
    let pid = read_pid(pid_path)
        .with_context(|| format!("hvf {operation}: missing pid file {}", pid_path.display()))?;
    if !pid_alive(pid) {
        bail!(
            "hvf {operation}: supervisor pid {pid} from {} is not running",
            pid_path.display()
        );
    }
    // SAFETY: the pid came from the VM's own private state directory and was
    // verified live immediately before the signal. The supervisor installs
    // only async-signal-safe handlers for these controls.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(anyhow!(
            "hvf {operation}: signal supervisor pid {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(crate) fn wait_for_pause_state(path: &Path, paused: bool) -> Result<()> {
    let deadline = Instant::now() + PAUSE_ACK_TIMEOUT;
    loop {
        if path.exists() == paused {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "hvf pause state did not become {} at {}",
                if paused { "paused" } else { "resumed" },
                path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Locate the per-VM HVF supervisor binary. Compiled by mvmctl's build script;
/// see [`mvm_vmm::host::aux_bin`] for the search order.
pub fn resolve_supervisor_path() -> Result<PathBuf> {
    mvm_vmm::host::aux_bin::resolve(&mvm_vmm::host::aux_bin::AuxBin {
        bin: "mvm-hvf-supervisor",
        env_var: "MVM_HVF_SUPERVISOR_PATH",
    })
}

pub fn vms_root() -> PathBuf {
    vms_dir()
}

/// The per-VM gating endpoint is the sole egress gate on hvf (claim-10
/// default-deny plus optional secret substitution). It only needs to run for a
/// workload that can actually reach the network: an admitted egress policy, or a
/// bound-secret authority whose credentials are substituted on the egress path.
/// A deny-all run carrying no secrets has no reachable egress, so the endpoint is
/// skipped and `EGRESS_PORT` is left unwired — any guest dial then fails closed,
/// mirroring libkrun's no-secrets no-op.
pub fn hvf_endpoint_needed(
    network_policy: &mvm_core::policy::network_policy::NetworkPolicy,
    state_dir: &Path,
) -> bool {
    network_policy.allows_egress()
        || mvm_vmm::host::egress_shared::state_has_bound_secrets(state_dir).unwrap_or(false)
}

pub fn hvf_workload_disks(config: &VmStartConfig) -> Vec<HvfDisk> {
    if config.virtiofs_root.is_some() {
        return Vec::new();
    }

    if cmdline::verity_enabled(config) {
        let mut disks = vec![
            HvfDisk {
                path: PathBuf::from(&config.rootfs_path),
                read_only: true,
                ephemeral: false,
            },
            HvfDisk {
                path: PathBuf::from(
                    config
                        .verity_path
                        .as_deref()
                        .expect("verity-enabled boot must carry a verity sidecar"),
                ),
                read_only: true,
                ephemeral: false,
            },
        ];
        if let Some((overlay_path, overlay_verity_path, _)) = cmdline::runtime_overlay(config) {
            disks.push(HvfDisk {
                path: PathBuf::from(overlay_path),
                read_only: true,
                ephemeral: false,
            });
            disks.push(HvfDisk {
                path: PathBuf::from(overlay_verity_path),
                read_only: true,
                ephemeral: false,
            });
        }
        return disks;
    }

    let mut disks = Some(config.rootfs_path.clone())
        .filter(|p| !p.is_empty())
        .map(|p| {
            vec![HvfDisk {
                path: PathBuf::from(p),
                read_only: false,
                ephemeral: true,
            }]
        })
        .unwrap_or_default();
    // A non-verity dev boot has no initramfs to mount the runtime overlay, so
    // attach it as a plain read-only virtio-blk device immediately after the
    // rootfs (=> /dev/vdb). The guest `/init` mounts it from the matching
    // `mvm.runtime_data=` cmdline token. Only when the rootfs disk is present,
    // so the overlay never slides down to /dev/vda.
    if !disks.is_empty()
        && let Some(overlay) = mvm_vmm::host::boot_config::non_verity_overlay_ext4(config)
    {
        disks.push(HvfDisk {
            path: PathBuf::from(overlay),
            read_only: true,
            ephemeral: false,
        });
    }
    disks
}

pub fn ensure_hvf_runtime_source_supported(config: &VmStartConfig) -> Result<()> {
    // Two supported required-overlay shapes, keyed on whether the rootfs asks to
    // be sealed. A sealed boot (verity metadata present) must be fully verity
    // capable — a missing initrd fails closed rather than silently downgrading to
    // an unverified root — and carries the dm-verity overlay triple its initramfs
    // (mvm-verity-init) mounts. A non-verity dev boot instead mounts a plain
    // read-only overlay from `/dev/vdb` in its guest `/init`.
    let verity_intended = config.roothash.is_some() || config.verity_path.is_some();
    if verity_intended {
        if !cmdline::verity_enabled(config) {
            bail!(
                "required-overlay hvf boot requires verity metadata plus an initrd \
                 (`--initrd` or sibling rootfs.initrd)"
            );
        }
        if cmdline::runtime_overlay(config).is_none() {
            bail!("required-overlay hvf boot requires the runtime overlay artifact triple");
        }
    } else if mvm_vmm::host::boot_config::non_verity_overlay_ext4(config).is_none() {
        bail!(
            "required-overlay hvf boot requires the runtime overlay artifact triple \
             (a non-verity boot mounts it as a plain read-only /dev/vdb)"
        );
    }
    Ok(())
}

pub fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

pub fn hvf_supervisor_launch_support_available() -> bool {
    if let Some(path) = std::env::var_os("MVM_HVF_SUPERVISOR_PATH").map(PathBuf::from) {
        return path.is_file();
    }

    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        && dir.join("mvm-hvf-supervisor").is_file()
    {
        return true;
    }

    let Some(workspace_root) = workspace_root_from_manifest_dir() else {
        return false;
    };

    for variant in ["release", "debug"] {
        if workspace_root
            .join("target")
            .join(variant)
            .join("mvm-hvf-supervisor")
            .is_file()
        {
            return true;
        }
    }

    workspace_root.join("Cargo.toml").is_file()
}

pub(crate) fn hvf_workload_support_available() -> bool {
    hvf_platform_supported() && hvf_supervisor_launch_support_available()
}

/// Probe whether HVF can actually run here. The backend's lifecycle is
/// platform-agnostic (spawns a binary + tracks PID files), so it compiles
/// everywhere; only this probe is macOS/Apple-silicon-specific.
pub fn hvf_platform_supported() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        true
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}
