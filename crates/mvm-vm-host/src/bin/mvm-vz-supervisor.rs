//! Rust-native Vz supervisor — one process per Vz guest.
//!
//! Reads a [`mvm_build::vz::SupervisorConfig`] JSON document on stdin (the same
//! contract the Swift `mvm-vz-supervisor` consumed), builds the
//! `VZVirtualMachineConfiguration`, cold-boots the guest on its private serial
//! dispatch queue, forwards SIGTERM/SIGINT as a graceful ACPI shutdown, and
//! blocks until the guest stops. The process exit code mirrors the guest:
//! `0` on a clean power-off, `1` on a framework error stop.
//!
//! macOS-only — the objc2 Virtualization.framework stack lives behind a
//! `cfg(target_os = "macos")` gate (mirrored by the lib's `vz_objc` module).
//! On other targets this is a stub that fails closed, so a non-macOS workspace
//! build still links the bin without pulling the Apple frameworks.
//!
//! Spawned by `mvm_backend::vz` via `resolve_supervisor_path()`. This is the
//! production VZ path — the Swift supervisor is deleted. A
//! boot/vsock/control/save-restore correctness gate lives at
//! `crates/mvm-build/tests/vz_supervisor_parity.rs`.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!(
        "mvm-vz-supervisor runs only on macOS (Apple Virtualization.framework); \
         this is a non-macOS stub build"
    );
    std::process::exit(1);
}

/// Ad-hoc entitlements plist applied at first launch. Virtualization-only — the
/// `hypervisor` entitlement is libkrun's; the Vz supervisor only instantiates a
/// `VZVirtualMachine`, which `Hypervisor.framework` rejects from an unsigned
/// process. Mirrors the virtualization entitlement self-signed at launch.
#[cfg(target_os = "macos")]
const VZ_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
    \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
    <plist version=\"1.0\"><dict>\n\
    <key>com.apple.security.virtualization</key><true/>\n\
    </dict></plist>";

/// Does the on-disk binary already carry the virtualization entitlement?
#[cfg(target_os = "macos")]
fn exe_has_virtualization_entitlement(exe: &std::path::Path) -> bool {
    std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(exe)
        .output()
        .map(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .contains("com.apple.security.virtualization")
        })
        .unwrap_or(false)
}

/// Self-sign ad-hoc with the virtualization entitlement, then re-exec — we ship
/// the bin unsigned, and VZ start is rejected without it. Mirrors
/// `mvm_backend::codesign::ensure_signed` (virtualization-only). The `MVM_VZ_SIGNED`
/// guard prevents an exec loop; `exec()` preserves the pid and the stdin pipe
/// the spawner writes the config to, so this is transparent to `mvm_backend::vz`.
/// Best-effort: a signing failure logs and proceeds so the real entitlement
/// error from `start()` is what surfaces.
///
/// Serialized by a file lock: the warm pool prelaunches several
/// supervisors at once, and `codesign --force` rewrites the *shared* binary in
/// place — concurrent writes/execs of a half-rewritten Mach-O yield `ETXTBSY`
/// or "invalid signature". The lock makes exactly one launcher sign; the rest
/// re-check and skip straight to the re-exec.
#[cfg(target_os = "macos")]
fn ensure_self_signed() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if std::env::var("MVM_VZ_SIGNED").as_deref() == Ok("1") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if exe_has_virtualization_entitlement(&exe) {
        return;
    }

    // Best-effort exclusive lock; if it can't be taken, fall back to unlocked
    // (the pre-existing behaviour). Held until `lock` drops (function return or
    // the explicit drop before re-exec).
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false) // a lock file — never clobber its (empty) contents
        .open(std::env::temp_dir().join("mvm-vz-supervisor.codesign.lock"))
        .ok();
    if let Some(f) = &lock {
        // SAFETY: flock on a valid fd; LOCK_EX blocks until exclusive.
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    }

    // Re-check under the lock — another launcher may have signed it while we
    // waited, in which case we skip straight to the re-exec.
    if !exe_has_virtualization_entitlement(&exe) {
        let ent = std::env::temp_dir().join("mvm-vz-supervisor-entitlements.plist");
        if std::fs::write(&ent, VZ_ENTITLEMENTS_PLIST).is_err() {
            return;
        }
        let output = Command::new("codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&ent)
            .arg(&exe)
            .output();
        let signed = output.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !signed {
            eprintln!("mvm-vz-supervisor: ad-hoc codesign failed; VM start may be rejected");
            // On success codesign's "replacing existing signature" line is
            // discarded; on failure its stderr is the actionable detail.
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
    // Release the lock before re-exec: `exec` would otherwise leak the inherited
    // lock fd for the supervisor's whole life.
    drop(lock);

    let err = Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("MVM_VZ_SIGNED", "1")
        .exec();
    eprintln!("mvm-vz-supervisor: re-exec after signing failed: {err}");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use std::io::Read;
    use std::sync::Arc;

    use anyhow::Context;
    use tokio::signal::unix::{SignalKind, signal};

    use mvm_build::vz::SupervisorConfig;
    use mvm_vm_host::vz_objc::{VzSupervisor, remove_pid_file, write_pid_file};

    // Sign + re-exec before anything else (preserves the stdin pipe).
    ensure_self_signed();

    // Default to quiet (errors only); honor RUST_LOG when set.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .init();

    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("read SupervisorConfig from stdin")?;
    let config: SupervisorConfig =
        serde_json::from_str(&raw).context("parse SupervisorConfig JSON from stdin")?;

    // One VM per process; all VZ calls serialize on the VM's own dispatch
    // queue, so a current-thread runtime is enough and keeps the main thread
    // free for the control socket + vsock proxy.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    let code = rt.block_on(async move {
        let supervisor = Arc::new(VzSupervisor::boot(&config).await.context("boot vz guest")?);
        write_pid_file(&config).context("write supervisor pid file")?;

        let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;

        let mut waiter = {
            let s = Arc::clone(&supervisor);
            tokio::spawn(async move { s.wait().await })
        };

        // Race the guest's own terminal transition against a stop signal. On a
        // signal we ask for a graceful ACPI stop, then escalate to a forced
        // stop if the guest doesn't honor it within a short grace. Without the
        // escalation a guest that ignores ACPI (e.g. a minimal headless image
        // with no power-button handler) leaves `wait()` — and the caller's
        // `down` — hanging until an external SIGKILL.
        use std::time::Duration;
        // Ceiling on the graceful ACPI window before we force-stop. A guest
        // that honors ACPI returns the instant it stops (this is a ceiling,
        // not a floor); a headless image with no power-button handler never
        // moves, so keep it short so `down` stays well under a second. Tunable.
        const STOP_GRACE: Duration = Duration::from_millis(250);
        let code = tokio::select! {
            joined = &mut waiter => joined.context("supervisor wait task panicked")??,
            _ = async {
                tokio::select! {
                    _ = sigterm.recv() => {}
                    _ = sigint.recv() => {}
                }
            } => {
                tracing::info!("stop signal received — requesting graceful guest stop");
                let _ = supervisor.request_stop().await;
                match tokio::time::timeout(STOP_GRACE, &mut waiter).await {
                    Ok(joined) => joined.context("supervisor wait task panicked")??,
                    Err(_) => {
                        tracing::info!(
                            "guest did not honor ACPI stop within {STOP_GRACE:?} — forcing stop"
                        );
                        // A forced stop fires no `guestDidStop` delegate
                        // callback, so `waiter` would hang here — the
                        // `stopWithCompletionHandler` completion returning IS
                        // the "stopped" signal. Bound it so a wedged framework
                        // can't hold the process open; the subsequent
                        // `shutdown()` + process exit tears the VM down anyway.
                        if let Err(e) =
                            tokio::time::timeout(Duration::from_millis(500), supervisor.force_stop())
                                .await
                        {
                            tracing::warn!(error = %e, "forced stop did not complete in time");
                        }
                        0
                    }
                }
            }
        };

        supervisor.shutdown();
        remove_pid_file(&config);
        Ok::<i32, anyhow::Error>(code)
    })?;

    std::process::exit(code);
}
