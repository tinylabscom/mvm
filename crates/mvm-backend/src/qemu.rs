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
//!   the per-port UNIX sockets those VMMs expose.
//! - `stop` SIGTERMs the qemu PID (then SIGKILL), reaps the bridge.
//! - `status` probes the qemu PID; `list` walks `~/.mvm/vms/*/qemu.pid`.

use anyhow::{Result, anyhow, bail};
use mvm_core::config::{mvm_data_dir, vm_console_log, vm_state_dir};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage, SnapshotCapability,
    StartMode, VmBackend, VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::base::ui;
use crate::libkrun::open_console_capture;
use crate::substitution_spawn::{reap_substitution_endpoint, spawn_substitution_endpoint};

/// QEMU workload backend (Linux dev/test; KVM where present, TCG fallback).
pub struct QemuBackend;

/// How long [`QemuBackend::start`] waits for qemu's `-pidfile` to appear
/// before declaring the boot failed.
const PID_FILE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the host AF_VSOCK↔UNIX bridge gets to bind its listening UNIX
/// socket before `start` returns. The socket existing means the agent
/// client has somewhere to connect; the guest agent coming up is raced by
/// the client's own retry, exactly as under libkrun.
const BRIDGE_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// SIGTERM→SIGKILL grace on `stop`.
const STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-VM file names under `vm_state_dir(name)`.
const QEMU_PID_FILE: &str = "qemu.pid";
const QEMU_LOG_FILE: &str = "qemu.log";
const QEMU_CID_FILE: &str = "qemu.cid";
const BRIDGE_PID_FILE: &str = "qemu-vsock-bridge.pid";

/// Default workload kernel cmdline. `console=ttyS0` is QEMU's serial line
/// (vs libkrun's `hvc0`); `root=/dev/vda rw init=/init` matches the same
/// Nix-built workload rootfs the other backends boot. `mvm.backend=qemu`
/// marks the dev tier (parity with the builder marker).
const DEFAULT_CMDLINE: &str = "console=ttyS0 root=/dev/vda rw init=/init mvm.backend=qemu";

impl VmBackend for QemuBackend {
    fn name(&self) -> &str {
        "qemu"
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // QEMU can pause/resume + snapshot via QMP, but mvm doesn't
            // wire a QMP monitor today. Declared false until the
            // monitor lands.
            pause_resume: false,
            snapshots: false,
            vsock: true,
            // User-mode (slirp) networking — no host TAP device.
            tap_networking: false,
            balloon: false,
            fs_quick_checkpoint: false,
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // No live-memory snapshot wired (no QMP). Warm-start would be a
        // fast reboot from the disk image, same posture as libkrun.
        SnapshotCapability::DiskOnly
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        let qemu_bin = locate_qemu()?;
        let kernel = resolve_workload_kernel(config)?;

        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;

        // Same admission gate + runtime-meta record as the libkrun path so
        // `mvmctl console`'s accessible/sealed gate (claim 15) and the
        // overlay-aware contract hold on QEMU-launched VMs too.
        let rootfs = Path::new(&config.rootfs_path);
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;

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
            open_console_capture(&console_log)
                .map_err(|e| anyhow!("open console sink {}: {e}", console_log.display()))?,
        );

        let mut cmdline = DEFAULT_CMDLINE.to_string();
        if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes) {
            cmdline.push(' ');
            cmdline.push_str(&uvols);
        }
        if let Some(roothash) = config.runtime_overlay_roothash.as_deref() {
            cmdline.push_str(" mvm.runtime_roothash=");
            cmdline.push_str(roothash);
        }

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
        if let Some(initrd) = config.initrd_path.as_deref() {
            cmd.arg("-initrd").arg(initrd);
        }
        cmd.arg("-append").arg(&cmdline);
        // Root disk (vda). Attached writable at the block level; the guest
        // mounts per the cmdline (`rw`).
        cmd.arg("-drive")
            .arg(format!("file={},if=virtio,format=raw", config.rootfs_path));
        // virtio-vsock on the per-VM guest CID. The host reaches the agent
        // through the AF_VSOCK↔UNIX bridge spawned below.
        cmd.arg("-device")
            .arg(format!("vhost-vsock-pci,guest-cid={cid}"));
        // User-mode (slirp) networking — no root, no TAP.
        cmd.args([
            "-netdev",
            "user,id=n0",
            "-device",
            "virtio-net-pci,netdev=n0",
        ]);
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
        if let Err(e) = spawn_vsock_bridge(&config.name, cid, &state_dir) {
            if let Some(pid) = read_pid(&pid_file) {
                send_signal(pid, libc::SIGTERM);
            }
            let _ = std::fs::remove_file(&pid_file);
            let _ = std::fs::remove_file(state_dir.join(QEMU_CID_FILE));
            return Err(e);
        }

        // When the admitted plan carries secret bindings, spawn the per-VM
        // substitution endpoint moat so the guest's egress can resolve
        // placeholders host-side (the guest never holds the real secret). Fail
        // closed: a secret-bearing workload whose endpoint can't come up is
        // rolled back rather than run with its secrets unavailable.
        if let (Some(tenant), Some(plan_json)) =
            (config.tenant_id.as_deref(), config.plan_json.as_deref())
        {
            match mvm_core::plan::secrets_from_signed_json(plan_json) {
                Ok(secrets) if !secrets.is_empty() => {
                    // Per-destination redaction rides the same signed plan; a
                    // parse hiccup defaults to all-off rather than failing the
                    // boot (secrets already gate that).
                    let redaction =
                        mvm_core::plan::redaction_from_signed_json(plan_json).unwrap_or_default();
                    // QEMU is slirp (no host TAP) — no transparent terminator
                    // to install, so `terminator_listen: None`. The vsock
                    // substitution channel alone is unchanged.
                    if let Err(e) = spawn_substitution_endpoint(
                        &config.name,
                        &state_dir,
                        tenant,
                        &secrets,
                        &redaction,
                        None,
                        // No transparent terminator on slirp ⇒ no TLS leg, so no
                        // per-VM intermediate (https termination is FC-scoped).
                        None,
                    ) {
                        rollback_qemu(&state_dir, &pid_file);
                        return Err(e);
                    }
                }
                Ok(_) => {} // plan has no egress secrets — no endpoint needed.
                Err(e) => {
                    // Not a decodable signed plan (legacy / test callers that
                    // pass a placeholder plan_json). No secrets ⇒ no endpoint.
                    tracing::warn!(error = %e, "plan_json not a decodable signed plan; skipping substitution endpoint");
                }
            }
        }

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

        // Reap the substitution endpoint moat (if this VM had one) so its
        // decrypted secrets don't outlive the guest.
        reap_substitution_endpoint(&state_dir, &id.0);

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
        let root = PathBuf::from(mvm_data_dir()).join("vms");
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
            port: mvm_guest::vsock::GUEST_AGENT_PORT,
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
                "QEMU workload runtime (Plan 166 / ADR-072); dev/test tier only.",
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

/// Resolve the kernel to boot the workload under QEMU.
///
/// `config.kernel_path` is the build's emitted `vmlinux` when there is one
/// (builder/dev-shell images). A plain `mkGuest` **workload** is a bare
/// rootfs with no kernel — libkrun boots it with libkrunfw's bundled
/// kernel, but QEMU has none. For the dev tier we fall back to the cached
/// builder VM kernel (`~/.cache/mvm/builder-vm/<arch>/vmlinux`), which has
/// virtio-blk/net/vsock + ext4 built-in and boots a workload rootfs
/// (`root=/dev/vda init=/init`) just fine — the Linux analog of
/// libkrunfw's bundled kernel. Production uses a workload kernel via
/// Firecracker; QEMU is dev/test only.
fn resolve_workload_kernel(config: &VmStartConfig) -> Result<PathBuf> {
    if let Some(k) = config.kernel_path.as_deref() {
        let p = PathBuf::from(k);
        if p.is_file() {
            return Ok(p);
        }
    }
    // ~/.cache/mvm/builder-vm/<arch>/vmlinux — same layout
    // `mvm_build::libkrun_builder::ensure_builder_vm_image` promotes to.
    let builder_kernel = PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(host_arch())
        .join("vmlinux");
    if builder_kernel.is_file() {
        return Ok(builder_kernel);
    }
    bail!(
        "qemu workload '{}' has no bootable kernel: the build produced no vmlinux \
         ({:?}) and no cached builder kernel exists at {}. Run a build / `mvmctl dev up` \
         to populate the builder VM image first.",
        config.name,
        config.kernel_path,
        builder_kernel.display()
    )
}

/// `qemu-system-<host-arch>` on `$PATH`.
fn locate_qemu() -> Result<String> {
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
fn allocate_cid(name: &str) -> Result<u32> {
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
    let vms_root = PathBuf::from(mvm_data_dir()).join("vms");
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
    let root = PathBuf::from(mvm_data_dir()).join("vms");
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

fn read_cid(name: &str) -> Option<u32> {
    std::fs::read_to_string(vm_state_dir(name).join(QEMU_CID_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
}

// ─── host AF_VSOCK ↔ UNIX bridge ────────────────────────────────────

/// Spawn the detached host-side AF_VSOCK↔UNIX bridge for this VM. QEMU's
/// virtio-vsock speaks real AF_VSOCK, but the shared agent client
/// (`mvm::vsock_transport`) connects to the per-port UNIX socket that
/// libkrun/Firecracker expose. The bridge listens on that UNIX socket
/// (`vm_vsock_port_socket`) and splices each connection to
/// `AF_VSOCK(cid, GUEST_AGENT_PORT)`, so the client is backend-agnostic.
///
/// It runs as a detached `mvmctl __qemu-vsock-bridge` subprocess so it
/// outlives the `mvmctl up` invocation, exactly as qemu (`-daemonize`)
/// does. `stop` reaps it via `BRIDGE_PID_FILE`.
fn spawn_vsock_bridge(name: &str, cid: u32, state_dir: &Path) -> Result<()> {
    let uds = mvm_core::config::vm_vsock_port_socket(name, mvm_guest::vsock::GUEST_AGENT_PORT);
    let _ = std::fs::remove_file(&uds);
    let bridge_pid_file = state_dir.join(BRIDGE_PID_FILE);

    let exe =
        std::env::current_exe().map_err(|e| anyhow!("resolve current exe for bridge: {e}"))?;
    let mut cmd = Command::new(&exe);
    cmd.arg("__qemu-vsock-bridge")
        .arg("--uds")
        .arg(&uds)
        .arg("--cid")
        .arg(cid.to_string())
        .arg("--port")
        .arg(mvm_guest::vsock::GUEST_AGENT_PORT.to_string())
        .arg("--watch-pid-file")
        .arg(state_dir.join(QEMU_PID_FILE))
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

    // Wait for the bridge to bind its UNIX socket so an immediately-
    // following console/agent connect doesn't race a not-yet-bound socket.
    let deadline = Instant::now() + BRIDGE_SOCKET_TIMEOUT;
    while !uds.exists() {
        if Instant::now() >= deadline {
            bail!(
                "qemu vsock bridge did not bind {} within {:?}",
                uds.display(),
                BRIDGE_SOCKET_TIMEOUT
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Kill the just-started qemu + bridge and drop their sidecars — used when a
/// later step of `start` fails so a failed `start` (not followed by `stop`)
/// doesn't orphan a daemonized qemu.
fn rollback_qemu(state_dir: &Path, pid_file: &Path) {
    if let Some(bpid) = read_pid(&state_dir.join(BRIDGE_PID_FILE)) {
        send_signal(bpid, libc::SIGTERM);
    }
    if let Some(pid) = read_pid(pid_file) {
        send_signal(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_file(state_dir.join(QEMU_CID_FILE));
    let _ = std::fs::remove_file(state_dir.join(BRIDGE_PID_FILE));
}

/// Body of the `mvmctl __qemu-vsock-bridge` subcommand. Listens on the
/// UNIX socket `uds` and, for each accepted connection, dials
/// `AF_VSOCK(cid, port)` and splices the two halves bidirectionally.
/// Exits when `watch_pid_file`'s process dies (the VM is gone).
///
/// Lives here (not in mvm-cli) so the AF_VSOCK plumbing sits beside the
/// backend that needs it; mvm-cli's hidden subcommand just forwards args.
pub fn run_vsock_bridge(uds: &Path, cid: u32, port: u32, watch_pid_file: &Path) -> Result<()> {
    use std::os::unix::net::UnixListener;

    let _ = std::fs::remove_file(uds);
    let listener = UnixListener::bind(uds).map_err(|e| anyhow!("bind {}: {e}", uds.display()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| anyhow!("set_nonblocking on {}: {e}", uds.display()))?;

    loop {
        // Stop when the watched VM is gone. Re-read the pidfile each
        // iteration so a transient partial read at startup doesn't latch
        // (the old read-once approach could loop forever on a one-off None).
        // Distinguish the cases: file *missing* or a *dead* pid → the VM is
        // torn down, exit; file present but momentarily unparseable → treat
        // as still-alive and retry (don't exit on a transient bad read).
        let vm_gone = match std::fs::read_to_string(watch_pid_file) {
            Err(_) => true, // pidfile removed → VM torn down
            Ok(s) => match s.trim().parse::<libc::pid_t>() {
                Ok(pid) => !pid_alive(pid),
                Err(_) => false, // transient empty/partial read → keep serving
            },
        };
        if vm_gone {
            let _ = std::fs::remove_file(uds);
            return Ok(());
        }
        match listener.accept() {
            Ok((client, _)) => {
                if let Ok(guest) = dial_vsock(cid, port) {
                    std::thread::spawn(move || splice_bidirectional(client, guest));
                }
                // If the guest dial fails (agent not up yet), drop the
                // client; the caller retries.
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(anyhow!("accept on {}: {e}", uds.display())),
        }
    }
}

/// Dial `AF_VSOCK(cid, port)` and wrap the fd in a [`std::net::TcpStream`]
/// for `splice_bidirectional` (TcpStream is just an owned fd with
/// read/write + shutdown; we never call TCP-specific methods).
fn dial_vsock(cid: u32, port: u32) -> std::io::Result<std::net::TcpStream> {
    use std::os::fd::FromRawFd;

    const AF_VSOCK: libc::c_int = 40;
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }
    // Pin the wire layout against the kernel uapi `struct sockaddr_vm`
    // (family u16 + reserved u16 + port u32 + cid u32 + 4-byte pad = 16,
    // == sizeof(struct sockaddr)). A future field edit that desyncs the
    // `socklen` passed to connect(2) trips this at compile time.
    const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

    // SAFETY: standard socket(2)/connect(2) on AF_VSOCK; addr is fully
    // initialized and sized exactly.
    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let addr = SockaddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        };
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

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
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
}
