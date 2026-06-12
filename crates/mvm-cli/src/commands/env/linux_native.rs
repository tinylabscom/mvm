//! `mvmctl dev` on Linux+KVM hosts.
//!
//! On hosts that can run Firecracker natively (Linux with `/dev/kvm`),
//! "dev mode" isn't a separate VM — the host *is* the dev environment.
//! The job of `mvmctl dev` here is bounded:
//!
//! 1. Verify (and install if missing) the Firecracker binary + jailer.
//! 2. Verify (and download if missing) the kernel + rootfs assets that
//!    `mvmctl up` and `mvmctl run` consume.
//! 3. Tell the user the host is ready.
//! 4. Optionally spawn a fresh interactive shell (`--shell`).
//!
//! This replaces the deleted Lima `dev_up`/`dev_down`/`dev_status`
//! helpers — those existed to manage a separate Lima VM. That VM is
//! gone; the asset pipeline now runs directly on the host via the
//! `mvm_backend::firecracker::*` functions.
//!
//! macOS 26+ Apple Silicon hosts use `super::dev_vz` instead; macOS
//! Intel / pre-26 / no-KVM-Linux hosts fall through to a "no dev
//! backend" error in `super::dev::run` — those need the
//! libkrun builder VM.

use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::ui;

use mvm_backend::firecracker;

/// `mvmctl dev up` on Linux+KVM.
///
/// Bootstraps the host-side Firecracker prerequisites and prints a
/// summary. With `open_shell`, spawns a fresh `bash -i` after setup
/// so the user lands in a shell with the dev environment ready.
pub(super) fn cmd_dev_linux_native(open_shell: bool) -> Result<()> {
    if !firecracker::is_installed()? {
        ui::info("Firecracker not installed — installing...");
        firecracker::install()?;
    } else {
        ui::info("Firecracker already installed.");
    }

    if !firecracker::has_base_assets()? {
        ui::info("Kernel/rootfs not present — downloading...");
        firecracker::download_assets()?;
        firecracker::prepare_rootfs()?;
        firecracker::write_state()?;
    } else {
        ui::info("Kernel + rootfs already present.");
    }

    ui::success(
        "Dev environment ready on host. Run `mvmctl up <flake>` to \
         launch a microVM.",
    );

    if open_shell {
        spawn_subshell()?;
    }
    Ok(())
}

/// `mvmctl dev down` on Linux+KVM.
///
/// On Linux there is no separate dev VM to stop — the host shell is
/// the environment. Function returns `Ok(())` so the caller's
/// gc-root cleanup (in `super::dev`) still runs unconditionally.
pub(super) fn cmd_dev_linux_native_down(json: bool) -> Result<bool> {
    if !json {
        ui::info(
            "Nothing to stop on Linux+KVM — the host is the dev environment. \
             (mvmctl-managed microVMs are still running; use `mvmctl down <name>` \
             to stop those individually or `mvmctl down --all`.)",
        );
    }
    // No managed dev VM on a native-KVM host; nothing was running.
    Ok(false)
}

/// `mvmctl dev shell` on Linux+KVM. Spawns an interactive `bash -i`.
///
/// Inherits stdin/stdout/stderr so the user gets a real TTY. Returns
/// after the user exits. The subshell inherits the parent's
/// environment; no `cd <project>` because on Linux+KVM there's no
/// VM-to-host path translation to do — `$PWD` already points at the
/// project the user invoked us from.
pub(super) fn cmd_dev_linux_native_shell() -> Result<()> {
    spawn_subshell()
}

/// `mvmctl dev status` on Linux+KVM. One-screen summary: KVM,
/// Firecracker binary, kernel/rootfs presence.
pub(super) fn cmd_dev_linux_native_status(json: bool) -> Result<()> {
    let has_kvm = std::path::Path::new("/dev/kvm").exists();
    let fc_installed = firecracker::is_installed().unwrap_or(false);
    let has_assets = firecracker::has_base_assets().unwrap_or(false);

    if json {
        // Host-native dev env: no managed VM. Collapse readiness into a
        // single state so the report shares the dev-status schema.
        let state = if !has_kvm {
            "no-kvm"
        } else if fc_installed && has_assets {
            "ready"
        } else {
            "not-ready"
        };
        return crate::json_out::emit_json(&super::dev_vz::build_dev_status_json_vmless(
            "linux-native",
            state,
        ));
    }

    ui::status_header();
    ui::status_line("Platform:", "Linux + KVM");
    ui::status_line("/dev/kvm:", if has_kvm { "present" } else { "Not present" });
    ui::status_line(
        "Firecracker:",
        if fc_installed {
            "Running"
        } else {
            "Not running"
        },
    );
    ui::status_line(
        "Kernel+rootfs:",
        if has_assets { "Running" } else { "Not present" },
    );

    if !has_kvm {
        ui::warn(
            "\n/dev/kvm is missing — Firecracker won't be able to launch \
             microVMs on this host. Check that the kvm kernel module is \
             loaded and your user is in the 'kvm' group.",
        );
    } else if !fc_installed || !has_assets {
        ui::info("\nRun `mvmctl dev up` to install Firecracker + download assets.");
    }
    Ok(())
}

fn spawn_subshell() -> Result<()> {
    // Honour $SHELL when set (the user's preferred shell); fall back
    // to `bash` since every supported Linux host carries it.
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "bash".to_string());
    ui::info(&format!("Launching {shell}; type `exit` to return."));
    let status = Command::new(&shell)
        .arg("-i")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawning interactive shell '{shell}'"))?;
    // A user exiting the subshell with non-zero code (e.g. Ctrl-D
    // after a failed command) is not an mvmctl failure — they're
    // back at the parent shell either way.
    if !status.success() {
        tracing::debug!(
            exit = ?status.code(),
            "subshell exited non-zero; returning to parent",
        );
    }
    Ok(())
}
