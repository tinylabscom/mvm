//! `mvm-hvf-supervisor` — one process per raw-HVF guest.
//!
//! Reads an [`mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig`] JSON document on
//! stdin (written by `mvm_runtime::backends::hvf`), self-signs the `hypervisor`
//! entitlement, boots the guest via `mvm_runtime::backends::hvf::boot_kernel` (which drives
//! the unified `vmm::run` loop), captures its console to the configured log, and
//! writes/removes a PID file so the backend can confirm launch and stop/status
//! the VM. macOS / Apple-silicon only; a stub elsewhere so the workspace links.

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!(
        "mvm-hvf-supervisor runs only on macOS / Apple silicon (Hypervisor.framework); \
         this is a stub build"
    );
    std::process::exit(1);
}

/// Ad-hoc entitlement applied at first launch — `Hypervisor.framework` rejects an
/// unsigned process. Hypervisor-only — no virtualization entitlement.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HVF_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
    \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
    <plist version=\"1.0\"><dict>\n\
    <key>com.apple.security.hypervisor</key><true/>\n\
    </dict></plist>";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exe_has_hypervisor_entitlement(exe: &std::path::Path) -> bool {
    std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(exe)
        .output()
        .map(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout).contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn signed_marker_path(exe: &std::path::Path) -> std::path::PathBuf {
    let mut marker = exe.as_os_str().to_os_string();
    marker.push(".mvm-hvf-signed");
    std::path::PathBuf::from(marker)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn executable_fingerprint(exe: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(exe).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(format!(
        "{}:{}:{}:{}",
        metadata.ino(),
        metadata.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn signed_marker_matches(exe: &std::path::Path) -> bool {
    let Some(fingerprint) = executable_fingerprint(exe) else {
        return false;
    };
    std::fs::read_to_string(signed_marker_path(exe))
        .map(|cached| cached.trim() == fingerprint)
        .unwrap_or(false)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn record_signed_marker(exe: &std::path::Path) {
    if let Some(fingerprint) = executable_fingerprint(exe) {
        let _ = std::fs::write(signed_marker_path(exe), fingerprint);
    }
}

/// Self-sign ad-hoc with the hypervisor entitlement, then re-exec. We ship the
/// bin unsigned and HVF rejects it otherwise. `MVM_HVF_SIGNED` breaks the exec
/// loop; `exec()` preserves the pid + the stdin config pipe. A file lock
/// serializes concurrent launches (codesign --force rewrites the shared binary
/// in place). Mirrors the libkrun supervisor's `ensure_self_signed`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_self_signed() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if std::env::var("MVM_HVF_SIGNED").as_deref() == Ok("1") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    // The helper is stable between builds. Avoid spawning `codesign` for every
    // short-lived workload by caching only metadata observed after a successful
    // entitlement check or signing operation. Hypervisor.framework remains the
    // final authority and still rejects an unsigned helper.
    if signed_marker_matches(&exe) {
        return;
    }
    if exe_has_hypervisor_entitlement(&exe) {
        record_signed_marker(&exe);
        return;
    }

    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(std::env::temp_dir().join("mvm-hvf-supervisor.codesign.lock"))
        .ok();
    if let Some(f) = &lock {
        // SAFETY: flock on a valid fd; LOCK_EX blocks until exclusive.
        unsafe {
            libc::flock(f.as_raw_fd(), libc::LOCK_EX);
        }
    }

    if !exe_has_hypervisor_entitlement(&exe) {
        let ent = std::env::temp_dir().join("mvm-hvf-supervisor-entitlements.plist");
        if std::fs::write(&ent, HVF_ENTITLEMENTS_PLIST).is_err() {
            return;
        }
        let output = Command::new("codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&ent)
            .arg(&exe)
            .output();
        let signed = output.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !signed {
            eprintln!("mvm-hvf-supervisor: ad-hoc codesign failed; VM start may be rejected");
            if let Ok(o) = &output {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stderr = stderr.trim_end();
                if !stderr.is_empty() {
                    eprintln!("{stderr}");
                }
            }
            return;
        }
        record_signed_marker(&exe);
    }
    drop(lock);

    let err = Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("MVM_HVF_SIGNED", "1")
        .exec();
    eprintln!("mvm-hvf-supervisor: re-exec after signing failed: {err}");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::{record_signed_marker, signed_marker_matches};
    use std::io::Write;

    #[test]
    fn signed_marker_is_bound_to_the_executable_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("mvm-hvf-supervisor");
        let mut file = std::fs::File::create(&exe).expect("create executable");
        file.write_all(b"signed helper").expect("write executable");
        file.flush().expect("flush executable");

        assert!(!signed_marker_matches(&exe));
        record_signed_marker(&exe);
        assert!(signed_marker_matches(&exe));

        std::fs::write(&exe, b"replacement helper with different size")
            .expect("replace executable");
        assert!(!signed_marker_matches(&exe));
    }
}

/// Set by the SIGTERM/SIGINT handler; `boot_kernel_until`'s watchdog polls it and
/// force-exits the guest so a stop flushes the console + drops the PID file
/// cleanly (vs the kernel being killed mid-run).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set/cleared by the SIGUSR1/SIGUSR2 handlers; `boot_kernel_until` parks the
/// guest vCPU out of execution (RAM + devices intact) while this is true, so
/// `HvfBackend::pause`/`resume` freeze and thaw the guest in place.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_pause_signal(_: libc::c_int) {
    PAUSED.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_resume_signal(_: libc::c_int) {
    PAUSED.store(false, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::time::Duration;

    use anyhow::Context;
    use mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig;

    // Sign + re-exec before anything else (preserves the stdin config pipe).
    ensure_self_signed();

    // Graceful stop: SIGTERM/SIGINT set STOP, which the boot watchdog observes and
    // force-exits the guest (then we flush the console + drop the PID file).
    // Pause/resume: SIGUSR1 sets PAUSED (park the vCPU out of guest execution),
    // SIGUSR2 clears it (thaw and re-enter the guest).
    // SAFETY: installing trivial async-signal-safe handlers (each an atomic store).
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
        let pause_h = on_pause_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGUSR1, pause_h);
        let resume_h = on_resume_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGUSR2, resume_h);
    }

    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("read HvfSupervisorConfig from stdin")?;
    let cfg: HvfSupervisorConfig =
        serde_json::from_str(&raw).context("parse HvfSupervisorConfig JSON from stdin")?;

    // Announce launch: the backend polls for this PID file to confirm boot, then
    // reads it to stop/status the VM.
    std::fs::write(&cfg.pid_file, std::process::id().to_string())
        .with_context(|| format!("write pid file {}", cfg.pid_file.display()))?;
    if let Some(path) = &cfg.pause_state {
        let _ = std::fs::remove_file(path);
    }

    if !cfg.kernel.is_file() {
        anyhow::bail!("kernel {} is not a readable file", cfg.kernel.display());
    }
    let initramfs = cfg
        .initramfs
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read initramfs")?;
    // Build the virtio-blk backings in `/dev/vda`… order. A read-only disk is
    // file-served (hypervisor-enforced RO, no RAM cost); a read-write disk is
    // file-served and persists writes; an ephemeral disk is loaded into RAM and
    // its writes are dropped on exit (a workload rootfs that must not mutate its
    // shared base image).
    let mut disks = Vec::with_capacity(cfg.disks.len());
    for d in &cfg.disks {
        let img = if d.read_only {
            mvm_runtime::backends::hvf::DiskImage::open(&d.path, true)
                .with_context(|| format!("open read-only disk {}", d.path.display()))?
        } else if d.ephemeral {
            let bytes = std::fs::read(&d.path)
                .with_context(|| format!("read ephemeral disk {}", d.path.display()))?;
            mvm_runtime::backends::hvf::DiskImage::mem(bytes)
        } else {
            mvm_runtime::backends::hvf::DiskImage::open(&d.path, false)
                .with_context(|| format!("open read-write disk {}", d.path.display()))?
        };
        disks.push(img);
    }
    // timeout_secs == 0 ⇒ persistent: run until stopped (SIGTERM). A multi-year
    // cap backstops a stuck guest. Otherwise it's a bounded run.
    let timeout = if cfg.timeout_secs == 0 {
        Duration::from_secs(10 * 365 * 24 * 60 * 60)
    } else {
        Duration::from_secs(cfg.timeout_secs)
    };

    // Egress over vsock is a pure relay to the per-VM endpoint, which owns the
    // whole egress decision (claim-10 default-deny + secret substitution). The
    // supervisor only wires the relay socket paths through.
    let result = mvm_runtime::backends::hvf::boot_kernel_until(
        mvm_runtime::backends::hvf::KernelBootUntilParams::builder_file(&cfg.kernel, timeout)
            .initramfs(initramfs.as_deref())
            .disks(disks)
            .vsock(cfg.vsock)
            .stop(&STOP)
            .paused(&PAUSED)
            .channels(mvm_runtime::backends::hvf::HostChannels {
                agent_socket: cfg.agent_socket.clone(),
                substitution_socket: cfg.substitution_socket.clone(),
                egress_relay: cfg.egress_relay_socket.clone(),
                broker_socket: cfg.broker_socket.clone(),
                console_data_sockets: cfg
                    .console_data_sockets
                    .iter()
                    .map(|c| (c.guest_port, c.host_socket.clone()))
                    .collect(),
                cmdline: cfg.cmdline.clone(),
                mem_mib: cfg.memory_mib,
                // Dev hook: `MVM_HVF_VIRTIOFS_ROOT=<dir>` boots a virtiofs root without
                // the full run-path gate wiring, for live-mount iteration on HVF.
                virtiofs_root: cfg.virtiofs_root.clone().or_else(|| {
                    std::env::var_os("MVM_HVF_VIRTIOFS_ROOT").map(std::path::PathBuf::from)
                }),
                virtiofs_shares: cfg
                    .virtiofs_shares
                    .iter()
                    .map(|share| (share.tag.clone(), share.path.clone()))
                    .collect(),
                pause_state: cfg.pause_state.clone(),
                snapshot_request: cfg.snapshot_request.clone(),
                snapshot_ram: cfg.snapshot_ram.clone(),
                snapshot_frame: cfg.snapshot_frame.clone(),
                restore_ram: cfg.restore_ram.clone(),
                restore_frame: cfg.restore_frame.clone(),
                handoff_socket: cfg.handoff_socket.clone(),
                handoff_root: cfg.handoff_root.clone(),
                handoff_verify_key: cfg.handoff_verify_key.clone(),
            })
            .build(),
    );

    // The VM has stopped. Persist the outputs (console + workload exit code)
    // BEFORE removing the PID file: the backend keys "stopped" on the PID file via
    // status/wait, so dropping it first races a reader to an empty console.
    let r = result.map_err(|e| anyhow::anyhow!("hvf boot failed: {e:?}"))?;
    if let Ok(mut f) = std::fs::File::create(&cfg.console_log) {
        let _ = f.write_all(&r.console);
    }
    // Transient run-to-exit: persist the workload exit code (the backend's `wait`
    // reads this) so it is durable before "stopped" is observable.
    if let Some(code) = r.workload_exit_code {
        let _ = std::fs::write(&cfg.workload_exit, code.to_string());
    }
    let _ = std::fs::remove_file(&cfg.pid_file);
    if let Some(code) = r.workload_exit_code {
        std::process::exit(code);
    }
    Ok(())
}
