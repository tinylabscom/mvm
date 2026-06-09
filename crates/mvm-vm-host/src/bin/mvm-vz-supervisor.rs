//! Rust-native Vz supervisor (Plan 152 WS-B) — one process per Vz guest.
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
//! Spawned by `mvm_backend::vz` via `resolve_supervisor_path()`. Behind the
//! Plan 152 WS-B parity gate the Swift supervisor still backs production until
//! the Rust path passes the boot/vsock/control/save-restore parity matrix.

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

/// Self-sign ad-hoc with the virtualization entitlement, then re-exec — we ship
/// the bin unsigned, and VZ start is rejected without it. Mirrors
/// `apple_container::ensure_signed` (virtualization-only). The `MVM_VZ_SIGNED`
/// guard prevents an exec loop; `exec()` preserves the pid and the stdin pipe
/// the spawner writes the config to, so this is transparent to `mvm_backend::vz`.
/// Best-effort: a signing failure logs and proceeds so the real entitlement
/// error from `start()` is what surfaces.
#[cfg(target_os = "macos")]
fn ensure_self_signed() {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if std::env::var("MVM_VZ_SIGNED").as_deref() == Ok("1") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if let Ok(out) = Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(&exe)
        .output()
        && out.status.success()
        && String::from_utf8_lossy(&out.stdout).contains("com.apple.security.virtualization")
    {
        return;
    }
    let ent = std::env::temp_dir().join("mvm-vz-supervisor-entitlements.plist");
    if std::fs::write(&ent, VZ_ENTITLEMENTS_PLIST).is_err() {
        return;
    }
    let signed = Command::new("codesign")
        .args(["--sign", "-", "--force", "--entitlements"])
        .arg(&ent)
        .arg(&exe)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !signed {
        eprintln!("mvm-vz-supervisor: ad-hoc codesign failed; VM start may be rejected");
        return;
    }
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

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("read SupervisorConfig from stdin")?;
    let config: SupervisorConfig =
        serde_json::from_str(&raw).context("parse SupervisorConfig JSON from stdin")?;

    // One VM per process; all VZ calls serialize on the VM's own dispatch
    // queue, so a current-thread runtime is enough and keeps the main thread
    // free for the (later-slice) control socket + vsock proxy.
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

        // Race the guest's terminal transition against a stop signal. A signal
        // requests a graceful shutdown and keeps waiting — the guest still
        // drives the exit code via the delegate.
        let code = loop {
            tokio::select! {
                joined = &mut waiter => {
                    break joined.context("supervisor wait task panicked")??;
                }
                _ = sigterm.recv() => {
                    tracing::info!("SIGTERM received — requesting graceful guest stop");
                    let _ = supervisor.request_stop().await;
                }
                _ = sigint.recv() => {
                    tracing::info!("SIGINT received — requesting graceful guest stop");
                    let _ = supervisor.request_stop().await;
                }
            }
        };

        supervisor.shutdown();
        remove_pid_file(&config);
        Ok::<i32, anyhow::Error>(code)
    })?;

    std::process::exit(code);
}
