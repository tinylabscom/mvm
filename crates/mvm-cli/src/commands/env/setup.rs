//! Setup helpers used by `bootstrap`. The standalone `mvmctl setup`
//! verb is gone — `bootstrap` runs the full flow idempotently, so the
//! separate subcommand was redundant. The helpers below
//! (`run_setup_steps`, `setup_security_baseline`) remain and are
//! imported by `bootstrap.rs`.

use anyhow::Result;

use crate::ui;

use mvm_runtime::config;
use mvm_runtime::firecracker;
use mvm_runtime::shell;

/// True when this host provisions Firecracker as its workload backend, so
/// `bootstrap` should install it, fetch its kernel/rootfs assets, and lay
/// down the jailer/seccomp security baseline. Firecracker only runs on
/// Linux KVM (see the workspace root docs' backend split); on macOS the
/// workload backend is libkrun/HVF and none of this step applies —
/// running it there previously crashed at the first Firecracker probe,
/// which shells through a VM that no longer exists on macOS 26+.
fn firecracker_provisioning_applies() -> bool {
    cfg!(target_os = "linux")
}

pub(super) fn run_setup_steps(force: bool, _builder_cpus: u32, _builder_mem: u32) -> Result<()> {
    if !firecracker_provisioning_applies() {
        ui::info(
            "Firecracker runs on Linux only \u{2014} skipping Firecracker asset provisioning.",
        );
        return Ok(());
    }

    // Lima is gone; what remains here is the Firecracker asset
    // pipeline (kernel + rootfs + security baseline). The builder-VM
    // sizing args are kept on the signature so callers don't break,
    // but they're inert until direct-launch is wired up for the
    // no-KVM Linux path.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn firecracker_provisioning_applies_on_linux() {
        assert!(firecracker_provisioning_applies());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn firecracker_provisioning_does_not_apply_off_linux() {
        assert!(!firecracker_provisioning_applies());
    }

    // Firecracker is fetched over the network and `setup_security_baseline`
    // mutates `/var/lib/mvm`, so this only runs for real off Linux, where
    // the gate must make it a no-op. This is the exact call `mvmctl
    // bootstrap` makes; before the platform gate it failed here on macOS
    // 26+ because the first Firecracker probe shelled through the removed
    // dev-VM path.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn run_setup_steps_is_a_no_op_off_linux() {
        run_setup_steps(false, 1, 1).expect("must not provision Firecracker off Linux");
    }
}
