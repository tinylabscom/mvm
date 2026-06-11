//! Setup helpers used by `bootstrap`. The standalone `mvmctl setup`
//! verb is gone — `bootstrap` runs the full flow idempotently, so the
//! separate subcommand was redundant. The helpers below
//! (`run_setup_steps`, `setup_security_baseline`) remain and are
//! imported by `bootstrap.rs`.

use anyhow::Result;

use crate::ui;

use mvm::config;
use mvm::shell;
use mvm_backend::firecracker;

pub(super) fn run_setup_steps(force: bool, _builder_cpus: u32, _builder_mem: u32) -> Result<()> {
    // Lima is gone; what remains here is the Firecracker asset
    // pipeline (kernel + rootfs + security baseline). The builder-VM
    // sizing args are kept on the signature so callers don't break,
    // but they're inert until direct-launch is wired up for the
    // macOS / no-KVM path.
    let total = 4;

    // Step 1: Firecracker (+ jailer from same release tarball)
    if !force && firecracker::is_installed()? {
        ui::step(1, total, "Firecracker already installed — skipping.");
    } else {
        ui::step(1, total, "Installing Firecracker...");
        firecracker::install()?;
    }

    // Step 2: Assets (kernel + squashfs)
    if !force && firecracker::has_base_assets()? {
        ui::step(
            2,
            total,
            "Kernel and rootfs already present \u{2014} skipping.",
        );
    } else {
        ui::step(2, total, "Downloading kernel and rootfs...");
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

    // Step 3: Rootfs
    ui::step(3, total, "Preparing root filesystem...");
    firecracker::prepare_rootfs()?;

    firecracker::write_state()?;

    // Step 4: Security hardening
    ui::step(4, total, "Setting up security baseline...");
    setup_security_baseline()?;

    Ok(())
}

/// Deploy baseline security artifacts (seccomp profile, audit directory).
///
/// Idempotent — each step checks before acting.
pub(super) fn setup_security_baseline() -> Result<()> {
    use mvm::security::{jailer, seccomp};

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
