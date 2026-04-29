//! `mvmctl setup` and related rootfs/security helpers.

use anyhow::Result;
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::{firecracker, lima, microvm};

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Delete the existing rootfs and rebuild it from scratch
    #[arg(long)]
    pub recreate: bool,
    /// Re-run all setup steps even if already complete
    #[arg(long)]
    pub force: bool,
    /// Number of vCPUs for the Lima VM
    #[arg(long, default_value = "8")]
    pub lima_cpus: u32,
    /// Memory (GiB) for the Lima VM
    #[arg(long, default_value = "16")]
    pub lima_mem: u32,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    // CLI flag wins; otherwise fall back to per-user config defaults.
    let effective_cpus = if args.lima_cpus == 8 {
        cfg.lima_cpus
    } else {
        args.lima_cpus
    };
    let effective_mem = if args.lima_mem == 16 {
        cfg.lima_mem_gib
    } else {
        args.lima_mem
    };

    if args.recreate {
        recreate_rootfs()?;
        ui::success("\nRootfs recreated! Run 'mvmctl start' or 'mvmctl dev' to launch.");
        return Ok(());
    }

    if !bootstrap::is_lima_required() {
        // Native Linux — just install FC directly
        run_setup_steps(args.force, effective_cpus, effective_mem)?;
        ui::success("\nSetup complete! Run 'mvmctl start' to launch a microVM.");
        return Ok(());
    }

    which::which("limactl").map_err(|_| {
        anyhow::anyhow!(
            "'limactl' not found. Install Lima first: brew install lima\n\
             Or run 'mvmctl bootstrap' for full automatic setup."
        )
    })?;

    run_setup_steps(args.force, effective_cpus, effective_mem)?;

    ui::success("\nSetup complete! Run 'mvmctl start' to launch a microVM.");
    Ok(())
}

/// Stop the running microVM and rebuild the rootfs from the upstream squashfs.
pub(super) fn recreate_rootfs() -> Result<()> {
    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    // Stop Firecracker if running
    if firecracker::is_running()? {
        ui::info("Stopping running microVM...");
        microvm::stop()?;
    }

    ui::info("Removing existing rootfs...");
    shell::run_in_vm(&format!(
        "rm -f {dir}/ubuntu-*.ext4",
        dir = config::MICROVM_DIR,
    ))?;

    ui::info("Rebuilding rootfs...");
    firecracker::prepare_rootfs()?;
    firecracker::write_state()?;

    Ok(())
}

pub(super) fn run_setup_steps(force: bool, lima_cpus: u32, lima_mem: u32) -> Result<()> {
    let total = 5;

    // Step 1: Lima VM
    if bootstrap::is_lima_required() {
        let lima_status = lima::get_status()?;
        if !force && matches!(lima_status, lima::LimaStatus::Running) {
            ui::step(1, total, "Lima VM already running — skipping.");
        } else {
            let opts = config::LimaRenderOptions {
                cpus: Some(lima_cpus),
                memory_gib: Some(lima_mem),
                ..Default::default()
            };
            let lima_yaml = config::render_lima_yaml_with(&opts)?;
            ui::info(&format!(
                "Lima VM resources: {} vCPUs, {} GiB memory",
                lima_cpus, lima_mem,
            ));
            ui::step(1, total, "Setting up Lima VM...");
            lima::ensure_running(lima_yaml.path())?;
        }
    } else {
        ui::step(1, total, "Native Linux detected — skipping Lima VM setup.");
    }

    // Step 2: Firecracker (+ jailer from same release tarball)
    if !force && firecracker::is_installed()? {
        ui::step(2, total, "Firecracker already installed — skipping.");
    } else {
        ui::step(2, total, "Installing Firecracker...");
        firecracker::install()?;
    }

    // Step 3: Assets (kernel + squashfs)
    if !force && firecracker::has_base_assets()? {
        ui::step(
            3,
            total,
            "Kernel and rootfs already present \u{2014} skipping.",
        );
    } else {
        ui::step(3, total, "Downloading kernel and rootfs...");
        firecracker::download_assets()?;
    }

    if firecracker::has_squashfs()? && !firecracker::validate_rootfs_squashfs()? {
        ui::warn("Downloaded rootfs is corrupted. Re-downloading...");
        shell::run_in_vm(&format!(
            "rm -f {dir}/ubuntu-*.squashfs.upstream",
            dir = config::MICROVM_DIR,
        ))?;
        firecracker::download_assets()?;
    }

    // Step 4: Rootfs
    ui::step(4, total, "Preparing root filesystem...");
    firecracker::prepare_rootfs()?;

    firecracker::write_state()?;

    // Step 5: Security hardening
    ui::step(5, total, "Setting up security baseline...");
    setup_security_baseline()?;

    Ok(())
}

/// Deploy baseline security artifacts (seccomp profile, audit directory).
///
/// Idempotent — each step checks before acting.
pub(super) fn setup_security_baseline() -> Result<()> {
    use mvm_runtime::security::{jailer, seccomp};

    // Deploy strict seccomp filter profile
    seccomp::ensure_strict_profile()?;
    ui::info("  Seccomp strict profile deployed.");

    // Create audit log directory structure
    shell::run_in_vm("sudo mkdir -p /var/lib/mvm/tenants")?;
    ui::info("  Audit log directory created.");

    // Report jailer status (installed by firecracker::install() above)
    match jailer::jailer_available() {
        Ok(true) => ui::info("  Jailer binary available."),
        _ => ui::warn("  Jailer binary not found (may not be in this Firecracker release)."),
    }

    Ok(())
}
