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

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use std::io::Read;
    use std::sync::Arc;

    use anyhow::Context;
    use tokio::signal::unix::{SignalKind, signal};

    use mvm_build::vz::SupervisorConfig;
    use mvm_vm_host::vz_objc::{VzSupervisor, remove_pid_file, write_pid_file};

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

        remove_pid_file(&config);
        Ok::<i32, anyhow::Error>(code)
    })?;

    std::process::exit(code);
}
