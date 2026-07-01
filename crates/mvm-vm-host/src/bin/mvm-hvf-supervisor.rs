//! `mvm-hvf-supervisor` — one process per raw-HVF guest (Plan 214 / ADR-098).
//!
//! Reads an [`mvm_build::hvf_supervisor::HvfSupervisorConfig`] JSON document on
//! stdin (written by `mvm_backend::hvf`), self-signs the `hypervisor`
//! entitlement, boots the guest via `mvm_backend::hvf::boot_kernel` (which drives
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
/// unsigned process. Hypervisor-only (vs the vz supervisor's virtualization key).
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

/// Self-sign ad-hoc with the hypervisor entitlement, then re-exec. We ship the
/// bin unsigned and HVF rejects it otherwise. `MVM_HVF_SIGNED` breaks the exec
/// loop; `exec()` preserves the pid + the stdin config pipe. A file lock
/// serializes concurrent launches (codesign --force rewrites the shared binary
/// in place). Mirrors `mvm-vz-supervisor`'s `ensure_self_signed`.
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
    if exe_has_hypervisor_entitlement(&exe) {
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
    }
    drop(lock);

    let err = Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("MVM_HVF_SIGNED", "1")
        .exec();
    eprintln!("mvm-hvf-supervisor: re-exec after signing failed: {err}");
    std::process::exit(1);
}

/// Set by the SIGTERM/SIGINT handler; `boot_kernel_until`'s watchdog polls it and
/// force-exits the guest so a stop flushes the console + drops the PID file
/// cleanly (vs the kernel being killed mid-run).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::time::Duration;

    use anyhow::Context;
    use mvm_build::hvf_supervisor::HvfSupervisorConfig;

    // Sign + re-exec before anything else (preserves the stdin config pipe).
    ensure_self_signed();

    // Graceful stop: SIGTERM/SIGINT set STOP, which the boot watchdog observes and
    // force-exits the guest (then we flush the console + drop the PID file).
    // SAFETY: installing a trivial async-signal-safe handler (an atomic store).
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
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

    let image = std::fs::read(&cfg.kernel)
        .with_context(|| format!("read kernel {}", cfg.kernel.display()))?;
    let initramfs = cfg
        .initramfs
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read initramfs")?;
    let disk = cfg
        .disk
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read disk")?;
    // timeout_secs == 0 ⇒ persistent: run until stopped (SIGTERM). A multi-year
    // cap backstops a stuck guest. Otherwise it's a bounded run.
    let timeout = if cfg.timeout_secs == 0 {
        Duration::from_secs(10 * 365 * 24 * 60 * 60)
    } else {
        Duration::from_secs(cfg.timeout_secs)
    };

    let result = mvm_backend::hvf::boot_kernel_until(
        &image,
        initramfs.as_deref(),
        disk.as_deref(),
        cfg.vsock,
        timeout,
        &STOP,
    );

    // The VM has stopped: drop the PID file and flush whatever console we
    // captured (capture-only console — written on exit, like the vz path).
    let _ = std::fs::remove_file(&cfg.pid_file);
    let r = result.map_err(|e| anyhow::anyhow!("hvf boot failed: {e:?}"))?;
    if let Ok(mut f) = std::fs::File::create(&cfg.console_log) {
        let _ = f.write_all(&r.console);
    }

    // Transient run-to-exit: if the guest reported a workload exit code over the
    // vsock exit port, persist it (the backend's `wait` reads this) and mirror it
    // as our own process exit code.
    if let Some(code) = r.workload_exit_code {
        let _ = std::fs::write(&cfg.workload_exit, code.to_string());
        std::process::exit(code);
    }
    Ok(())
}
