//! QEMU **workload** runtime backend.
//!
//! The dev/test counterpart to the QEMU *builder* (`mvm-build`'s
//! `qemu_builder`): this boots a user **workload** microVM via
//! `qemu-system-<arch>` so a workload can run for dev/test on a host
//! without `/dev/kvm` (TCG fallback) or where Firecracker isn't wanted.
//! **Firecracker stays the sole production runtime**; QEMU is opt-in
//! (`--hypervisor qemu` / `MVM_BACKEND=qemu`) and `auto_select` never
//! picks it.
//!
//! The selectable launch path is the unified workload runner over
//! [`crate::driver::QemuDriver`] — a QEMU boot attaches the universal
//! initramfs and receives `ActivateEnvironment` over vsock exactly like
//! Firecracker/libkrun/HVF. This raw backend remains as the driver's
//! identity delegate and owns the shared QEMU machinery both paths use:
//! guest-CID allocation, the AF_VSOCK↔UNIX bridge, and the pid-file
//! lifecycle.
//!
//! ## Tier
//!
//! Dev tier only, outside the security claims. `AnyBackend::tier()` reports
//! the **best-case** Tier 2 (KVM-accelerated, comparable to the
//! microvm.nix/qemu classification); when `/dev/kvm` is absent the boot
//! runs under TCG software emulation and `start` emits a loud Tier-3
//! banner. The static enum tier stays
//! Tier 2 because it's a compile-time classification consulted by the
//! tier-sync test + `doctor`; the live KVM-vs-TCG mode is a *runtime*
//! property surfaced through the banner and `doctor`, not the enum.
//!
//! ## Lifecycle
//!
//! - `start` boots `qemu-system` with `-daemonize -pidfile` (qemu forks
//!   and writes its own PID file), captures the guest serial console
//!   **write-only** to `console.log` (claim 15 — no host input fd), wires
//!   user-mode (slirp) networking, and attaches a virtio-vsock device on
//!   a per-VM guest CID. It then spawns a host-side AF_VSOCK↔UNIX bridge
//!   (a detached `mvmctl` subprocess) so the shared UNIX-socket agent
//!   client reaches the guest agent exactly as it does under
//!   libkrun/Firecracker — QEMU's `vhost-vsock` speaks real AF_VSOCK, not
//!   the per-port UNIX sockets those VMMs expose. The bridge is
//!   spec-driven ([`QemuBridgeSpec`]): the runner's driver additionally
//!   relays the guest-dialed channels (egress, broker) and captures the
//!   workload-exit report through the same process.
//! - `stop` SIGTERMs the qemu PID (then SIGKILL), reaps the bridge.
//! - `status` probes the qemu PID; `list` walks `~/.mvm/vms/*/qemu.pid`.

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::config::{vm_console_log, vm_state_dir, vms_dir};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    SnapshotCapability, StartMode, VmBackend, VmCapabilities, VmId, VmInfo, VmStartConfig,
    VmStatus,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use mvm_vmm::host::ui;

/// QEMU workload backend (Linux dev/test; KVM where present, TCG fallback).
pub struct QemuBackend;

/// How long a boot waits for qemu's `-pidfile` to appear
/// before declaring the boot failed.
pub(crate) const PID_FILE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the host AF_VSOCK↔UNIX bridge gets to bind its listening UNIX
/// socket before the boot returns. The socket existing means the agent
/// client has somewhere to connect; the guest agent coming up is raced by
/// the client's own retry, exactly as under libkrun.
pub(crate) const BRIDGE_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// SIGTERM→SIGKILL grace on `stop`.
pub(crate) const STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// QEMU's unprivileged user-mode network gives dev/test guests transparent
/// TCP and UDP without requiring a host TAP device or elevated setup.
fn qemu_user_network_args() -> [&'static str; 4] {
    [
        "-netdev",
        "user,id=n0",
        "-device",
        "virtio-net-pci,netdev=n0",
    ]
}

/// Per-VM file names under `vm_state_dir(name)`.
pub(crate) const QEMU_PID_FILE: &str = "qemu.pid";
pub(crate) const QEMU_LOG_FILE: &str = "qemu.log";
pub(crate) const QEMU_CID_FILE: &str = "qemu.cid";
pub(crate) const BRIDGE_PID_FILE: &str = "qemu-vsock-bridge.pid";
/// The JSON wiring plan the detached bridge process reads at startup.
pub(crate) const BRIDGE_SPEC_FILE: &str = "qemu-vsock-bridge.json";

/// Default workload kernel cmdline. `console=ttyS0` is QEMU's serial line
/// (vs libkrun's `hvc0`); `root=/dev/vda rw init=/init` matches the same
/// Nix-built workload rootfs the other backends boot. `mvm.backend=qemu`
/// marks the dev tier (parity with the builder marker).
const DEFAULT_CMDLINE: &str = "console=ttyS0 root=/dev/vda rw init=/init mvm.backend=qemu";
const VERITY_CMDLINE: &str = "console=ttyS0 mvm.backend=qemu";

fn qemu_verity_initrd_path(config: &VmStartConfig) -> Option<PathBuf> {
    config
        .verity_path
        .as_deref()
        .zip(config.roothash.as_deref())
        .and_then(|_| {
            Path::new(&config.rootfs_path)
                .parent()
                .map(|p| p.join("rootfs.initrd"))
        })
        .filter(|p| p.exists())
}

fn qemu_effective_initrd(config: &VmStartConfig) -> Option<PathBuf> {
    config
        .initrd_path
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| qemu_verity_initrd_path(config))
}

fn qemu_verity_enabled(config: &VmStartConfig) -> bool {
    config.verity_path.is_some()
        && config.roothash.is_some()
        && qemu_effective_initrd(config).is_some()
}

fn qemu_runtime_overlay(config: &VmStartConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

fn ensure_qemu_runtime_source_supported(config: &VmStartConfig) -> Result<()> {
    if config.runtime_source_policy != mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay {
        return Ok(());
    }
    // A sealed boot (verity metadata present) must be fully verity capable — a
    // missing initrd fails closed rather than downgrading to an unverified root —
    // and carries the dm-verity overlay triple its initramfs mounts. A non-verity
    // dev boot instead mounts a plain read-only overlay from `/dev/vdb`.
    let verity_intended = config.roothash.is_some() || config.verity_path.is_some();
    if verity_intended {
        if !qemu_verity_enabled(config) {
            bail!(
                "required-overlay qemu boot requires verity metadata plus an initrd \
                 (`--initrd` or sibling rootfs.initrd)"
            );
        }
        if qemu_runtime_overlay(config).is_none() {
            bail!("required-overlay qemu boot requires the runtime overlay artifact triple");
        }
    } else if mvm_vmm::host::boot_config::non_verity_overlay_ext4(config).is_none() {
        bail!(
            "required-overlay qemu boot requires the runtime overlay artifact triple \
             (a non-verity boot mounts it as a plain read-only /dev/vdb)"
        );
    }
    Ok(())
}

fn qemu_cmdline(config: &VmStartConfig) -> String {
    let mut cmdline = if qemu_verity_enabled(config) {
        VERITY_CMDLINE.to_string()
    } else {
        DEFAULT_CMDLINE.to_string()
    };
    if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes) {
        cmdline.push(' ');
        cmdline.push_str(&uvols);
    }
    if let Some(token) = mvm_vmm::host::egress_bridge::verb_grant_cmdline_token(&config.name) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    if let Some(token) = mvm_vmm::host::egress_bridge::require_grant_cmdline_token(&config.name) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    if let Some(verity_args) = mvm_vmm::host::boot_config::build_verity_cmdline_args(
        config.roothash.as_deref(),
        if qemu_verity_enabled(config) {
            qemu_runtime_overlay(config).map(|(_, _, roothash)| roothash)
        } else {
            None
        },
    ) {
        cmdline.push(' ');
        cmdline.push_str(&verity_args);
    }
    // Non-verity boots carry the runtime overlay as a plain read-only
    // `/dev/vdb`; emit the token its `/init` mounts from. Verity boots already
    // emitted the dm-verity variant above.
    if !qemu_verity_enabled(config)
        && let Some(overlay_args) = mvm_vmm::host::boot_config::build_runtime_overlay_cmdline_args(
            None,
            mvm_vmm::host::boot_config::non_verity_overlay_ext4(config).is_some(),
        )
    {
        cmdline.push(' ');
        cmdline.push_str(&overlay_args);
    }
    cmdline.push(' ');
    cmdline.push_str(&mvm_core::vm_backend::encode_runtime_source_policy_cmdline(
        config.runtime_source_policy,
    ));
    cmdline
}

fn qemu_drive_args(config: &VmStartConfig) -> Vec<String> {
    if qemu_verity_enabled(config) {
        let mut drives = vec![
            format!(
                "file={},if=virtio,format=raw,readonly=on",
                config.rootfs_path
            ),
            format!(
                "file={},if=virtio,format=raw,readonly=on",
                config
                    .verity_path
                    .as_deref()
                    .expect("verity-enabled qemu boot must carry a verity sidecar")
            ),
        ];
        if let Some((overlay_path, overlay_verity_path, _)) = qemu_runtime_overlay(config) {
            drives.push(format!(
                "file={overlay_path},if=virtio,format=raw,readonly=on"
            ));
            drives.push(format!(
                "file={overlay_verity_path},if=virtio,format=raw,readonly=on"
            ));
        }
        append_qemu_user_disks(&mut drives, config);
        return drives;
    }
    let mut drives = vec![format!("file={},if=virtio,format=raw", config.rootfs_path)];
    // A non-verity dev boot has no initramfs to mount the runtime overlay, so
    // attach it as a plain read-only virtio-blk device right after the rootfs
    // (=> /dev/vdb). The guest `/init` mounts it from the matching
    // `mvm.runtime_data=` cmdline token.
    if let Some(overlay) = mvm_vmm::host::boot_config::non_verity_overlay_ext4(config) {
        drives.push(format!("file={overlay},if=virtio,format=raw,readonly=on"));
    }
    append_qemu_user_disks(&mut drives, config);
    drives
}

fn append_qemu_user_disks(drives: &mut Vec<String>, config: &VmStartConfig) {
    drives.extend(
        config
            .volumes
            .iter()
            .filter(|volume| matches!(volume.kind, mvm_core::vm_backend::VmVolumeKind::Disk))
            .map(|volume| {
                let read_only = if volume.read_only { ",readonly=on" } else { "" };
                format!("file={},if=virtio,format=raw{read_only}", volume.host)
            }),
    );
}

fn ensure_qemu_volumes_supported(config: &VmStartConfig) -> Result<()> {
    if let Some(volume) = config
        .volumes
        .iter()
        .find(|volume| matches!(volume.kind, mvm_core::vm_backend::VmVolumeKind::DirShare))
    {
        bail!(
            "qemu directory-share volume '{}' -> '{}' is unsupported; use a disk-image volume",
            volume.host,
            volume.guest
        );
    }
    Ok(())
}

impl VmBackend for QemuBackend {
    fn name(&self) -> &str {
        "qemu"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Qemu
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // QEMU can pause/resume + snapshot via QMP, but mvm doesn't
            // wire a QMP monitor today. Declared false until the
            // monitor lands.
            pause_resume: false,
            snapshots: false,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            vsock: true,
            // User-mode (slirp) networking — no host TAP device.
            tap_networking: false,
            balloon: false,
            fs_quick_checkpoint: false,
            ..VmCapabilities::default()
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        ensure_qemu_volumes_supported(config)?;
        let qemu_bin = locate_qemu()?;
        let kernel = resolve_workload_kernel(config)?;
        ensure_qemu_runtime_source_supported(config)?;

        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;

        // Same admission gate + runtime-meta record as the libkrun path so
        // `mvmctl console`'s accessible/sealed gate (claim 15) and the
        // overlay-aware contract hold on QEMU-launched VMs too.
        let rootfs = Path::new(&config.rootfs_path);
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_vmm::host::runtime_meta::admit_runtime_overlay_contract(
            rootfs_dir,
            config.runtime_source_policy,
        )?;
        mvm_vmm::host::runtime_meta::record_from_start_config(
            &config.name,
            StartMode::Detached,
            config,
        )?;

        let kvm = kvm_available();
        if !kvm {
            // Loud Tier-3 banner for the unaccelerated TCG fallback.
            ui::warn(&format!(
                "QEMU workload '{}' is running UNACCELERATED (TCG — no /dev/kvm). \
                 This is a Tier-3 dev/test fallback: slow, and unaudited vs ADR-002. \
                 For production use a /dev/kvm host (Firecracker).",
                config.name
            ));
        }

        let cid = allocate_cid(&config.name)?;
        let pid_file = state_dir.join(QEMU_PID_FILE);
        let _ = std::fs::remove_file(&pid_file);
        let console_log = vm_console_log(&config.name);
        // Write-only console sink (claim 15): qemu opens `-serial file:`
        // for output only; there is no host fd from which the guest could
        // read console input. We pre-create the sink through the shared
        // write-only opener so the invariant + truncate-on-boot match the
        // other backends.
        drop(
            mvm_vmm::host::console_capture::open_console_capture(&console_log)
                .map_err(|e| anyhow!("open console sink {}: {e}", console_log.display()))?,
        );

        let cmdline = qemu_cmdline(config);

        let vcpus = config.cpus.clamp(1, u32::from(u8::MAX));

        ui::info(&format!(
            "Starting QEMU workload '{}' (cpus={vcpus}, mem={}MiB, {}) via {}...",
            config.name,
            config.memory_mib,
            if kvm { "KVM" } else { "TCG" },
            qemu_bin,
        ));

        let mut cmd = Command::new(&qemu_bin);
        cmd.args(["-m", &config.memory_mib.to_string()]);
        cmd.args(["-smp", &vcpus.to_string()]);
        if kvm {
            cmd.args(["-enable-kvm", "-cpu", "host"]);
        } else {
            cmd.args(["-cpu", "max"]);
        }
        cmd.arg("-kernel").arg(&kernel);
        if let Some(initrd) = qemu_effective_initrd(config) {
            cmd.arg("-initrd").arg(initrd);
        }
        cmd.arg("-append").arg(&cmdline);
        for drive in qemu_drive_args(config) {
            cmd.arg("-drive").arg(drive);
        }
        // virtio-vsock on the per-VM guest CID. The host reaches the agent
        // through the AF_VSOCK↔UNIX bridge spawned below.
        cmd.arg("-device")
            .arg(format!("vhost-vsock-pci,guest-cid={cid}"));
        // User-mode (slirp) networking — no root, no TAP.
        cmd.args(qemu_user_network_args());
        cmd.args(["-display", "none", "-monitor", "none", "-no-reboot"]);
        cmd.arg("-serial")
            .arg(format!("file:{}", console_log.display()));
        cmd.arg("-D").arg(state_dir.join(QEMU_LOG_FILE));
        // qemu forks into the background and writes its own pidfile.
        cmd.args(["-daemonize"]);
        cmd.arg("-pidfile").arg(&pid_file);

        let status = cmd
            .status()
            .map_err(|e| anyhow!("spawn qemu ({qemu_bin}): {e}"))?;
        if !status.success() {
            bail!(
                "qemu-system exited {} before daemonizing workload '{}'; see {}",
                status.code().unwrap_or(-1),
                config.name,
                state_dir.join(QEMU_LOG_FILE).display()
            );
        }

        // `-daemonize` returns only after the pidfile is written, but poll
        // defensively so a slow fork doesn't race the bridge spawn below.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        while !pid_file.exists() {
            if Instant::now() >= deadline {
                bail!(
                    "qemu did not write pidfile {} within {:?}",
                    pid_file.display(),
                    PID_FILE_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // If the bridge can't come up, the already-daemonized qemu would be
        // orphaned (a failed `start` won't be followed by `stop`). Roll back:
        // kill qemu + drop the pid/cid sidecars so a retry re-allocates a CID
        // instead of pinning the (possibly conflicting) one this attempt wrote.
        let bridge_spec = QemuBridgeSpec::agent_only(&config.name, cid, &state_dir);
        if let Err(e) = spawn_vsock_bridges(&config.name, &state_dir, &bridge_spec) {
            if let Some(pid) = read_pid(&pid_file) {
                send_signal(pid, libc::SIGTERM);
            }
            let _ = std::fs::remove_file(&pid_file);
            let _ = std::fs::remove_file(state_dir.join(QEMU_CID_FILE));
            return Err(e);
        }

        // No egress substitution moat here: QEMU is type-barred from carrying
        // an untrusted (secret-bearing) workload, so a signed plan with secrets
        // never reaches this backend.

        ui::success(&format!(
            "QEMU workload '{}' started (pid: {}).",
            config.name,
            pid_file.display()
        ));
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let state_dir = vm_state_dir(&id.0);
        // Reap the bridge first so it can't keep serving a half-dead VM.
        // Guard on liveness so a stale pidfile (crash without cleanup) whose
        // PID the OS has since recycled isn't signalled by mistake.
        if let Some(bpid) = read_pid(&state_dir.join(BRIDGE_PID_FILE))
            && pid_alive(bpid)
        {
            send_signal(bpid, libc::SIGTERM);
        }
        let _ = std::fs::remove_file(state_dir.join(BRIDGE_PID_FILE));

        let pid_path = state_dir.join(QEMU_PID_FILE);
        let Some(pid) = read_pid(&pid_path) else {
            ui::info(&format!(
                "QEMU VM '{}' has no PID file at {}; nothing to stop.",
                id.0,
                pid_path.display()
            ));
            return Ok(());
        };
        if !pid_alive(pid) {
            let _ = std::fs::remove_file(&pid_path);
            ui::info(&format!("QEMU VM '{}' was not running.", id.0));
            return Ok(());
        }
        send_signal(pid, libc::SIGTERM);
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline && pid_alive(pid) {
            std::thread::sleep(Duration::from_millis(100));
        }
        if pid_alive(pid) {
            ui::info(&format!(
                "QEMU VM '{}' PID {pid} ignored SIGTERM; sending SIGKILL.",
                id.0
            ));
            send_signal(pid, libc::SIGKILL);
        }
        let _ = std::fs::remove_file(&pid_path);
        ui::success(&format!("QEMU VM '{}' stopped.", id.0));
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let mut last_err = None;
        for vm in self.list()? {
            if let Err(e) = self.stop(&VmId(vm.name.clone())) {
                tracing::warn!(name = vm.name, error = %e, "qemu stop_all: stop failed");
                last_err = Some(e);
            }
        }
        last_err.map_or(Ok(()), Err)
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        bail!("pause is not supported by the qemu backend (QMP monitor not wired)")
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        bail!("resume is not supported by the qemu backend (QMP monitor not wired)")
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        match read_pid(&vm_state_dir(&id.0).join(QEMU_PID_FILE)) {
            Some(pid) if pid_alive(pid) => Ok(VmStatus::Running),
            _ => Ok(VmStatus::Stopped),
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = vms_dir();
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
            let pid_path = path.join(QEMU_PID_FILE);
            if !pid_path.exists() {
                // Not a QEMU-managed VM (other backends share ~/.mvm/vms/).
                continue;
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

    fn logs(&self, id: &VmId, lines: u32, hypervisor: bool) -> Result<String> {
        let state_dir = vm_state_dir(&id.0);
        let path = if hypervisor {
            state_dir.join(QEMU_LOG_FILE)
        } else {
            vm_console_log(&id.0)
        };
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        Ok(tail(&body, lines as usize))
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        // The shared agent client connects to the UNIX socket the bridge
        // binds (`vm_vsock_port_socket`); the `cid` here is the guest CID
        // the bridge dials over AF_VSOCK, surfaced for diagnostics.
        let cid = read_cid(&id.0).unwrap_or(3);
        Ok(GuestChannelInfo::Vsock {
            cid,
            port: mvm_agentd::vsock::GUEST_AGENT_PORT,
        })
    }

    fn is_available(&self) -> Result<bool> {
        Ok(locate_qemu().is_ok())
    }

    fn install(&self) -> Result<()> {
        ui::info(
            "QEMU must be installed via the host package manager \
             (`apt install qemu-system-x86 qemu-utils` / `dnf install qemu-system-x86`).",
        );
        Ok(())
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 2 best-case (KVM), the microvm.nix-lineage QEMU profile:
        // QEMU's device model is much larger than Firecracker's (higher L2
        // audit cost), and claim 3 (verified boot) targets Firecracker.
        // The TCG (no-KVM) mode is a runtime Tier-3 degradation surfaced by
        // the `start` banner + doctor, not by this compile-time tier.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1
                ClaimStatus::Holds,       // 2
                ClaimStatus::DoesNotHold, // 3 — verified boot targets Firecracker
                ClaimStatus::Holds,       // 4
                ClaimStatus::Holds,       // 5
                ClaimStatus::Holds,       // 6
                ClaimStatus::Holds,       // 7
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "QEMU workload runtime (Plan 166 / ADR-014); dev/test tier only.",
                "KVM-accelerated where /dev/kvm is present; TCG software-emulation fallback otherwise (runtime Tier-3, banner-flagged).",
                "Larger device model than Firecracker → higher L2 audit cost; outside ADR-002 claims. Never a production runtime.",
            ],
        }
    }
}

// ─── KVM / qemu probing ─────────────────────────────────────────────

fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// Resolve the kernel to boot the workload under QEMU from a start config:
/// the build's emitted `vmlinux` when there is one, else the cached builder
/// fallback. Thin wrapper over [`resolve_workload_kernel_path`] for the
/// config-carrying raw path.
fn resolve_workload_kernel(config: &VmStartConfig) -> Result<PathBuf> {
    resolve_workload_kernel_path(&config.name, config.kernel_path.as_deref().map(Path::new))
}

/// Resolve the kernel to boot the workload under QEMU.
///
/// `kernel_path` is the build's emitted `vmlinux` when there is one
/// (builder/interactive images). A plain `mkGuest` **workload** is a bare
/// rootfs with no kernel — libkrun boots it with libkrunfw's bundled
/// kernel, but QEMU has none. For the dev tier we fall back to the cached
/// builder VM kernel (`~/.mvm/cache/builder-vm/<arch>/vmlinux`), which has
/// virtio-blk/net/vsock + ext4 built-in and boots a workload rootfs
/// (`root=/dev/vda init=/init`) just fine — the Linux analog of
/// libkrunfw's bundled kernel. Production uses a workload kernel via
/// Firecracker; QEMU is dev/test only.
///
/// Shared by the raw backend (`VmStartConfig::kernel_path`) and the
/// `VmmDriver` (`KernelImage::Bundled` — QEMU has no libkrunfw, so the
/// cached-builder fallback IS its bundled kernel) so both boot paths
/// resolve the same file.
pub(crate) fn resolve_workload_kernel_path(
    name: &str,
    kernel_path: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(p) = kernel_path
        && p.is_file()
    {
        return Ok(p.to_path_buf());
    }
    // ~/.mvm/cache/builder-vm/<arch>/vmlinux — same layout
    // `mvm_build::libkrun_builder::ensure_builder_vm_image` promotes to.
    let builder_kernel = PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(host_arch())
        .join("vmlinux");
    if builder_kernel.is_file() {
        return Ok(builder_kernel);
    }
    bail!(
        "qemu workload '{name}' has no bootable kernel: the build produced no vmlinux \
         ({kernel_path:?}) and no cached builder kernel exists at {}. Run a build / `mvmctl bootstrap` \
         to populate the builder VM image first.",
        builder_kernel.display()
    )
}

/// `qemu-system-<host-arch>` on `$PATH`.
pub(crate) fn locate_qemu() -> Result<String> {
    let bin = match std::env::consts::ARCH {
        "x86_64" => "qemu-system-x86_64",
        "aarch64" => "qemu-system-aarch64",
        other => bail!("no qemu-system emulator mapped for host arch `{other}`"),
    };
    which::which(bin).map(|_| bin.to_string()).map_err(|_| {
        anyhow!(
            "`{bin}` not found on $PATH. Install QEMU \
             (`apt install qemu-system-x86 qemu-utils` / `dnf install qemu-system-x86`)."
        )
    })
}

/// `/dev/kvm` present + read-write for this process. Drives the KVM-vs-TCG
/// boot path and the Tier-3 banner.
pub(crate) fn kvm_available() -> bool {
    Path::new("/dev/kvm").exists()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

// ─── per-VM guest CID allocation ────────────────────────────────────

/// Allocate (or reuse) a unique guest CID for `name`. vhost-vsock refuses
/// duplicate CIDs across live VMs, so we pick the lowest CID ≥ 3 not
/// recorded by another VM's `qemu.cid` sidecar and persist it. Reuses the
/// VM's own recorded CID on restart.
pub(crate) fn allocate_cid(name: &str) -> Result<u32> {
    if let Some(existing) = read_cid(name) {
        return Ok(existing);
    }
    // Serialize the scan→pick→write across concurrent `mvmctl up
    // --hypervisor qemu` so two VMs can't pick the same CID in the window
    // before either qemu has daemonized (vhost-vsock refuses duplicate live
    // CIDs). A held `flock` on a shared lock file under the vms root is the
    // cheapest cross-process mutex; it's released when `_lock` (the open
    // file description) drops at function return.
    use std::os::fd::AsRawFd;
    let vms_root = vms_dir();
    std::fs::create_dir_all(&vms_root)
        .map_err(|e| anyhow!("create {}: {e}", vms_root.display()))?;
    let lock_path = vms_root.join(".qemu-cid-alloc.lock");
    let _lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| anyhow!("open cid lock {}: {e}", lock_path.display()))?;
    // SAFETY: flock(2) on a valid open fd; LOCK_EX blocks until acquired and
    // is released on close (when `_lock` drops).
    if unsafe { libc::flock(_lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(anyhow!(
            "flock cid alloc {}: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        ));
    }

    let in_use = used_cids();
    // CID 0/1 reserved (hypervisor/local), 2 = host. Guests start at 3.
    let cid = (3u32..).find(|c| !in_use.contains(c)).unwrap_or(3);
    let cid_file = vm_state_dir(name).join(QEMU_CID_FILE);
    std::fs::write(&cid_file, cid.to_string())
        .map_err(|e| anyhow!("write {}: {e}", cid_file.display()))?;
    Ok(cid)
}

/// CIDs recorded by VMs whose qemu process is still alive. A stale sidecar
/// from a crashed VM is ignored so its CID can be reclaimed.
fn used_cids() -> std::collections::HashSet<u32> {
    let mut set = std::collections::HashSet::new();
    let root = vms_dir();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return set;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let alive = read_pid(&dir.join(QEMU_PID_FILE)).is_some_and(pid_alive);
        if !alive {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(dir.join(QEMU_CID_FILE))
            && let Ok(c) = s.trim().parse::<u32>()
        {
            set.insert(c);
        }
    }
    set
}

pub(crate) fn read_cid(name: &str) -> Option<u32> {
    std::fs::read_to_string(vm_state_dir(name).join(QEMU_CID_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

// ─── host AF_VSOCK ↔ UNIX bridge ────────────────────────────────────

/// One host-dialed vsock channel the bridge serves: it listens on
/// `listen_uds` (the per-port UNIX socket the shared agent client connects
/// to, `vm_vsock_port_socket`) and splices each accepted connection to
/// `AF_VSOCK(cid, guest_port)`, so the client stays backend-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QemuBridgeHostDial {
    pub guest_port: u32,
    pub listen_uds: PathBuf,
}

/// One guest-dialed vsock channel the bridge serves: it listens on
/// `AF_VSOCK(VMADDR_CID_ANY, guest_port)` on the host and splices each
/// accepted connection to `target_uds` — the runner-bound listener (the
/// egress endpoint, the host-services broker) that owns the channel's
/// policy. QEMU's `vhost-vsock` exposes no per-port host sockets for the
/// guest's outbound dials, so the bridge terminates them here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QemuBridgeGuestDial {
    pub guest_port: u32,
    pub target_uds: PathBuf,
}

/// The detached bridge process's wiring plan for one VM, written as JSON
/// next to the VM's pid file and passed to `mvmctl __qemu-vsock-bridge
/// --spec`. QEMU's virtio-vsock speaks real AF_VSOCK, but the shared agent
/// client and the runner's channel set are expressed as per-port UNIX
/// sockets; the bridge is the translation layer between the two, in both
/// directions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QemuBridgeSpec {
    /// The VM's guest CID (host-dialed channels dial `AF_VSOCK(cid, port)`).
    pub cid: u32,
    /// Exit when this PID file's process is no longer alive (the VM is gone).
    pub watch_pid_file: PathBuf,
    /// Channels the host dials into the guest (agent RPC, dev console data).
    pub host_dials: Vec<QemuBridgeHostDial>,
    /// Channels the guest dials out to the host (egress, broker).
    pub guest_dials: Vec<QemuBridgeGuestDial>,
    /// When the spec carries the workload-exit port, the bridge accepts one
    /// connection on it and persists the guest's exit code under this state
    /// dir (`workload.exit`), mirroring the other drivers' capture.
    pub exit_capture_state_dir: Option<PathBuf>,
}

impl QemuBridgeSpec {
    /// The bridge plan for the raw (pre-runner) boot path: only the agent
    /// RPC channel, in the host-dialed direction — exactly what the legacy
    /// single-port bridge served.
    fn agent_only(name: &str, cid: u32, state_dir: &Path) -> Self {
        Self {
            cid,
            watch_pid_file: state_dir.join(QEMU_PID_FILE),
            host_dials: vec![QemuBridgeHostDial {
                guest_port: mvm_agentd::vsock::GUEST_AGENT_PORT,
                listen_uds: mvm_core::config::vm_vsock_port_socket(
                    name,
                    mvm_agentd::vsock::GUEST_AGENT_PORT,
                ),
            }],
            guest_dials: Vec::new(),
            exit_capture_state_dir: None,
        }
    }
}

/// Spawn the detached host-side AF_VSOCK↔UNIX bridge for this VM.
///
/// Writes `spec` as JSON next to the VM's pid file and launches a detached
/// `mvmctl __qemu-vsock-bridge` subprocess so it outlives the invoking
/// `mvmctl`, exactly as qemu (`-daemonize`) does. `stop` reaps it via
/// `BRIDGE_PID_FILE`. When the plan serves at least one host-dialed
/// channel, this waits for the first channel's UNIX socket to appear so an
/// immediately-following console/agent connect doesn't race a
/// not-yet-bound socket — the socket existing means the client has
/// somewhere to connect; the guest agent coming up is raced by the
/// client's own retry, exactly as under libkrun.
pub(crate) fn spawn_vsock_bridges(
    name: &str,
    state_dir: &Path,
    spec: &QemuBridgeSpec,
) -> Result<()> {
    let spec_path = state_dir.join(BRIDGE_SPEC_FILE);
    let json = serde_json::to_string(spec)
        .map_err(|e| anyhow!("serialize qemu bridge spec for '{name}': {e}"))?;
    std::fs::write(&spec_path, json).map_err(|e| anyhow!("write {}: {e}", spec_path.display()))?;
    for dial in &spec.host_dials {
        let _ = std::fs::remove_file(&dial.listen_uds);
    }
    let bridge_pid_file = state_dir.join(BRIDGE_PID_FILE);

    let exe =
        std::env::current_exe().map_err(|e| anyhow!("resolve current exe for bridge: {e}"))?;
    let mut cmd = Command::new(&exe);
    cmd.arg("__qemu-vsock-bridge")
        .arg("--spec")
        .arg(&spec_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Detach into its own session so it survives this process.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn vsock bridge ({}): {e}", exe.display()))?;
    std::fs::write(&bridge_pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", bridge_pid_file.display()))?;

    // Wait for the first host-dialed channel's socket (always the agent RPC
    // channel on every real plan) so a following connect doesn't race the
    // bind. A plan with no host-dialed channels has nothing to wait on.
    let Some(first) = spec.host_dials.first() else {
        return Ok(());
    };
    let deadline = Instant::now() + BRIDGE_SOCKET_TIMEOUT;
    while !first.listen_uds.exists() {
        if Instant::now() >= deadline {
            bail!(
                "qemu vsock bridge did not bind {} within {:?}",
                first.listen_uds.display(),
                BRIDGE_SOCKET_TIMEOUT
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Read a [`QemuBridgeSpec`] JSON file and run the bridge — the body of the
/// `mvmctl __qemu-vsock-bridge --spec <path>` subcommand.
///
/// Lives here (not in mvm-cli) so the AF_VSOCK plumbing sits beside the
/// backend that needs it; mvm-cli's hidden subcommand just forwards the path.
pub fn run_vsock_bridge_from_spec_file(spec_path: &Path) -> Result<()> {
    let json = std::fs::read_to_string(spec_path)
        .with_context(|| format!("read qemu bridge spec {}", spec_path.display()))?;
    let spec: QemuBridgeSpec = serde_json::from_str(&json)
        .with_context(|| format!("parse qemu bridge spec {}", spec_path.display()))?;
    run_vsock_bridge(&spec)
}

/// Body of the `mvmctl __qemu-vsock-bridge` subcommand: bind every channel
/// in the plan, then watch the VM's pid file and exit (cleaning up the
/// host-dialed sockets) when the VM is gone.
fn run_vsock_bridge(spec: &QemuBridgeSpec) -> Result<()> {
    // Host-dialed channels: one UNIX listener per channel; each accepted
    // connection is spliced to AF_VSOCK(cid, guest_port).
    for dial in &spec.host_dials {
        let listener = std::os::unix::net::UnixListener::bind(&dial.listen_uds)
            .with_context(|| format!("bind {}", dial.listen_uds.display()))?;
        let cid = spec.cid;
        let port = dial.guest_port;
        std::thread::spawn(move || serve_host_dial(listener, cid, port));
    }
    // Guest-dialed channels: one AF_VSOCK listener per channel; each
    // accepted connection is spliced to the runner-bound UNIX listener.
    for dial in &spec.guest_dials {
        let listener = VsockListener::bind(dial.guest_port)
            .with_context(|| format!("bind AF_VSOCK port {}", dial.guest_port))?;
        let target = dial.target_uds.clone();
        std::thread::spawn(move || serve_guest_dial(listener, target));
    }
    // Workload-exit capture: accept the guest's single exit report and
    // persist it where `wait_for_workload_exit` reads it.
    if let Some(state_dir) = &spec.exit_capture_state_dir {
        let listener = VsockListener::bind(mvm_agentd::vsock::WORKLOAD_EXIT_PORT)
            .context("bind AF_VSOCK workload-exit port")?;
        let state_dir = state_dir.clone();
        std::thread::spawn(move || {
            match listener
                .accept()
                .and_then(|stream| mvm_core::exit_capture::capture_stream(stream, &state_dir))
            {
                Ok(code) => tracing::info!(code, "qemu workload exit captured"),
                Err(e) => tracing::warn!("qemu workload exit capture failed: {e}"),
            }
        });
    }

    // Watch loop: stop when the watched VM is gone. Re-read the pidfile each
    // iteration so a transient partial read at startup doesn't latch
    // (the old read-once approach could loop forever on a one-off None).
    // Distinguish the cases: file *missing* or a *dead* pid → the VM is
    // torn down, exit; file present but momentarily unparseable → treat
    // as still-alive and retry (don't exit on a transient bad read).
    loop {
        let vm_gone = match std::fs::read_to_string(&spec.watch_pid_file) {
            Err(_) => true, // pidfile removed → VM torn down
            Ok(s) => match s.trim().parse::<libc::pid_t>() {
                Ok(pid) => !pid_alive(pid),
                Err(_) => false, // transient empty/partial read → keep serving
            },
        };
        if vm_gone {
            for dial in &spec.host_dials {
                let _ = std::fs::remove_file(&dial.listen_uds);
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Accept loop for one host-dialed channel: splice each UNIX connection to
/// `AF_VSOCK(cid, port)`. A failed guest dial (agent not up yet) drops the
/// client; the caller retries.
fn serve_host_dial(listener: std::os::unix::net::UnixListener, cid: u32, port: u32) {
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                if let Ok(guest) = dial_vsock(cid, port) {
                    std::thread::spawn(move || splice_bidirectional(client, guest));
                }
            }
            Err(e) => {
                tracing::warn!("qemu bridge accept on host-dial port {port} failed: {e}");
                return;
            }
        }
    }
}

/// Accept loop for one guest-dialed channel: splice each AF_VSOCK
/// connection to the runner-bound UNIX listener. A failed target connect
/// (endpoint not bound yet) drops the guest's dial; the guest retries.
fn serve_guest_dial(listener: VsockListener, target_uds: PathBuf) {
    loop {
        match listener.accept() {
            Ok(guest) => {
                if let Ok(host) = std::os::unix::net::UnixStream::connect(&target_uds) {
                    std::thread::spawn(move || splice_bidirectional(host, guest));
                }
            }
            Err(e) => {
                tracing::warn!("qemu bridge accept on guest-dial listener failed: {e}");
                return;
            }
        }
    }
}

/// The Linux `struct sockaddr_vm` wire layout, hoisted so the dial and the
/// listener share one definition. A field edit that desyncs the `socklen`
/// passed to connect(2)/bind(2) trips the layout contract below.
#[repr(C)]
struct SockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    /// `VMADDR_FLAG_TO_HOST` and friends. Zero for every address mvm
    /// builds; carried so the mirror matches the header field-for-field.
    svm_flags: u8,
    svm_zero: [u8; 3],
}

// Layout contract with the kernel's `struct sockaddr_vm`
// (linux/vm_sockets.h), derived on Linux 6.8 with cc
// sizeof/offsetof/_Alignof rather than read off the Rust definition.
// Bytes 12..16: the header gained `svm_flags` at offset 12 in Linux 6.0,
// shrinking `svm_zero` to three bytes. The total is 16 either way, which
// is why the pre-6.0 shape went unnoticed here.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};

    assert!(size_of::<SockaddrVm>() == 16);
    assert!(align_of::<SockaddrVm>() == 4);
    assert!(offset_of!(SockaddrVm, svm_family) == 0);
    assert!(offset_of!(SockaddrVm, svm_reserved1) == 2);
    assert!(offset_of!(SockaddrVm, svm_port) == 4);
    assert!(offset_of!(SockaddrVm, svm_cid) == 8);
    assert!(offset_of!(SockaddrVm, svm_flags) == 12);
    assert!(offset_of!(SockaddrVm, svm_zero) == 13);
};

const AF_VSOCK: libc::c_int = 40;

fn sockaddr_vm(cid: u32, port: u32) -> SockaddrVm {
    SockaddrVm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_flags: 0,
        svm_zero: [0; 3],
    }
}

fn vsock_socket() -> std::io::Result<libc::c_int> {
    // SAFETY: standard socket(2) on AF_VSOCK.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// A bound host-side AF_VSOCK listener: the host end of the channels the
/// guest dials out to (egress, broker, workload-exit). QEMU's
/// `vhost-vsock-pci` delivers a guest's `connect(cid=host, port)` to a host
/// process listening here, so the bridge terminates those dials and
/// splices them to the runner-bound UNIX listeners.
struct VsockListener {
    fd: libc::c_int,
}

impl VsockListener {
    /// Bind `AF_VSOCK(VMADDR_CID_ANY, port)` and start listening.
    fn bind(port: u32) -> std::io::Result<Self> {
        const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
        let fd = vsock_socket()?;
        let addr = sockaddr_vm(VMADDR_CID_ANY, port);
        // SAFETY: bind(2)/listen(2) on a valid fd; addr is fully initialized
        // and sized exactly. On failure the fd is closed before returning.
        unsafe {
            let rc = libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
            );
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            if libc::listen(fd, 16) < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
        }
        Ok(Self { fd })
    }

    /// Accept one guest connection, wrapped in a [`std::net::TcpStream`]
    /// (an owned fd with read/write + shutdown; no TCP methods are used).
    fn accept(&self) -> std::io::Result<std::net::TcpStream> {
        use std::os::fd::FromRawFd;
        // SAFETY: accept(2) on a listening fd; the returned fd is owned and
        // wrapped exactly once.
        let conn = unsafe { libc::accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `conn` is a fresh, owned descriptor from accept.
        Ok(unsafe { std::net::TcpStream::from_raw_fd(conn) })
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        // SAFETY: `fd` is owned by this listener and closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

/// Dial `AF_VSOCK(cid, port)` and wrap the fd in a [`std::net::TcpStream`]
/// for `splice_bidirectional` (TcpStream is just an owned fd with
/// read/write + shutdown; we never call TCP-specific methods).
fn dial_vsock(cid: u32, port: u32) -> std::io::Result<std::net::TcpStream> {
    use std::os::fd::FromRawFd;

    let fd = vsock_socket()?;
    let addr = sockaddr_vm(cid, port);
    // SAFETY: connect(2) on a valid fd; addr is fully initialized and sized
    // exactly. On failure the fd is closed before returning.
    unsafe {
        let rc = libc::connect(
            fd,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        );
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        Ok(std::net::TcpStream::from_raw_fd(fd))
    }
}

/// Splice two streams in both directions until either closes.
fn splice_bidirectional(a: std::os::unix::net::UnixStream, b: std::net::TcpStream) {
    use std::io::{Read, Write};
    let Ok(a2) = a.try_clone() else { return };
    let Ok(b2) = b.try_clone() else { return };
    let t = std::thread::spawn(move || {
        let mut r = a2;
        let mut w = b2;
        let mut buf = [0u8; 16 * 1024];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 || w.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = w.shutdown(std::net::Shutdown::Write);
    });
    let mut r = b;
    let mut w = a;
    let mut buf = [0u8; 16 * 1024];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 || w.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = w.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

// ─── pid helpers (local copies — libkrun's are private) ─────────────

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

pub(crate) fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
    unsafe {
        libc::kill(pid, sig);
    }
}

fn tail(s: &str, n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_backend_name_is_qemu() {
        assert_eq!(QemuBackend.name(), "qemu");
    }

    #[test]
    fn qemu_capabilities_vsock_only() {
        let c = QemuBackend.capabilities();
        assert!(c.vsock);
        assert!(!c.pause_resume);
        assert!(!c.snapshots);
        assert!(!c.tap_networking);
    }

    #[test]
    fn qemu_user_network_is_rootless_and_transparent() {
        assert_eq!(
            qemu_user_network_args(),
            [
                "-netdev",
                "user,id=n0",
                "-device",
                "virtio-net-pci,netdev=n0",
            ]
        );
    }

    #[test]
    fn qemu_security_profile_is_tier_2_partial_claim_3() {
        let p = QemuBackend.security_profile();
        assert!(p.tier.starts_with("Tier 2"));
        // Claim 3 (verified boot) targets Firecracker.
        assert_eq!(p.dropped_claims(), vec![3]);
    }

    #[test]
    fn pause_resume_unsupported() {
        assert!(QemuBackend.pause(&VmId("x".into())).is_err());
        assert!(QemuBackend.resume(&VmId("x".into())).is_err());
    }

    #[test]
    fn tail_returns_last_n_lines() {
        assert_eq!(tail("a\nb\nc\nd", 2), "c\nd");
        assert_eq!(tail("a\nb", 0), "");
        assert_eq!(tail("a\nb", 10), "a\nb");
    }

    #[test]
    fn qemu_cmdline_uses_verity_shape_and_runtime_overlay_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let cmdline = qemu_cmdline(&config);
        assert!(!cmdline.contains("root=/dev/vda"));
        assert!(!cmdline.contains("init=/init"));
        assert!(cmdline.contains("mvm.roothash="));
        assert!(cmdline.contains("mvm.data=/dev/vda"));
        assert!(cmdline.contains("mvm.hash=/dev/vdb"));
        assert!(cmdline.contains("mvm.runtime_roothash="));
        assert!(cmdline.contains("mvm.runtime_data=/dev/vdc"));
        assert!(cmdline.contains("mvm.runtime_hash=/dev/vdd"));
        assert!(cmdline.contains("mvm.runtime_source_policy=required_overlay"));
    }

    #[test]
    fn qemu_drive_args_use_read_only_verity_layout_with_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        let drives = qemu_drive_args(&config);
        assert_eq!(drives.len(), 4);
        assert!(drives.iter().all(|drive| drive.contains("readonly=on")));
        assert!(drives[0].contains(&config.rootfs_path));
        assert!(drives[1].contains(config.verity_path.as_deref().expect("verity path")));
        assert!(drives[2].contains("/tmp/runtime.ext4"));
        assert!(drives[3].contains("/tmp/runtime.verity"));
    }

    #[test]
    fn qemu_non_verity_boot_attaches_runtime_overlay_as_vdb() {
        // A plain dev rootfs (no verity) with a resolved overlay triple: the
        // rootfs keeps /dev/vda read-write, the overlay rides /dev/vdb
        // read-only, and the cmdline names the same device.
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            ..Default::default()
        };
        let drives = qemu_drive_args(&config);
        assert_eq!(drives.len(), 2);
        assert!(drives[0].contains("/tmp/rootfs.ext4"));
        assert!(!drives[0].contains("readonly=on"));
        assert!(drives[1].contains("/tmp/runtime.ext4"));
        assert!(drives[1].contains("readonly=on"));

        let cmdline = qemu_cmdline(&config);
        assert!(cmdline.contains("root=/dev/vda"), "got: {cmdline}");
        assert!(
            cmdline.contains("mvm.runtime_data=/dev/vdb"),
            "got: {cmdline}"
        );
        assert!(!cmdline.contains("mvm.runtime_hash="), "got: {cmdline}");
    }

    #[test]
    fn qemu_non_verity_boot_without_overlay_stays_single_disk() {
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            ..Default::default()
        };
        assert_eq!(qemu_drive_args(&config).len(), 1);
        assert!(!qemu_cmdline(&config).contains("mvm.runtime_data="));
    }

    #[test]
    fn qemu_attaches_disk_volumes_with_requested_access_mode() {
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            volumes: vec![
                mvm_core::vm_backend::VmVolume {
                    host: "/tmp/writable.ext4".into(),
                    guest: "/data/writable".into(),
                    kind: mvm_core::vm_backend::VmVolumeKind::Disk,
                    ..Default::default()
                },
                mvm_core::vm_backend::VmVolume {
                    host: "/tmp/readonly.ext4".into(),
                    guest: "/data/readonly".into(),
                    read_only: true,
                    kind: mvm_core::vm_backend::VmVolumeKind::Disk,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let drives = qemu_drive_args(&config);
        assert_eq!(drives.len(), 3);
        assert!(drives[1].contains("/tmp/writable.ext4"));
        assert!(!drives[1].contains("readonly=on"));
        assert!(drives[2].contains("/tmp/readonly.ext4"));
        assert!(drives[2].contains("readonly=on"));
    }

    #[test]
    fn qemu_refuses_directory_share_before_start() {
        let config = VmStartConfig {
            volumes: vec![mvm_core::vm_backend::VmVolume {
                host: "/tmp/share".into(),
                guest: "/data/share".into(),
                kind: mvm_core::vm_backend::VmVolumeKind::DirShare,
                ..Default::default()
            }],
            ..Default::default()
        };

        let err = ensure_qemu_volumes_supported(&config).unwrap_err();
        assert!(err.to_string().contains("directory-share"));
        assert!(err.to_string().contains("/data/share"));
    }

    #[test]
    fn required_overlay_qemu_support_rejects_missing_overlay_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let err = ensure_qemu_runtime_source_supported(&config).unwrap_err();
        assert!(err.to_string().contains("runtime overlay artifact triple"));
    }

    #[test]
    fn required_overlay_qemu_support_rejects_missing_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let err = ensure_qemu_runtime_source_supported(&config).unwrap_err();
        assert!(err.to_string().contains("rootfs.initrd"));
    }

    #[test]
    fn required_overlay_qemu_support_accepts_non_verity_block_overlay() {
        // A non-verity dev boot carrying the resolved overlay triple is served by
        // the plain read-only /dev/vdb mount — no verity metadata or initrd.
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        assert!(ensure_qemu_runtime_source_supported(&config).is_ok());
    }
}
