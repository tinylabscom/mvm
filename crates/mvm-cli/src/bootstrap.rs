use anyhow::Result;

use crate::ui;
use mvm_core::platform::{self, Platform};

/// Check that a package manager is available for the current platform.
///
/// - macOS: requires Homebrew
/// - Linux: any of apt, dnf, pacman is accepted
/// - Windows: requires WSL2 (delegates to [`bootstrap_wsl2`])
pub fn check_package_manager() -> Result<()> {
    if cfg!(target_os = "macos") {
        check_homebrew()
    } else if cfg!(target_os = "windows") {
        bootstrap_wsl2()
    } else {
        check_linux_package_manager()
    }
}

/// Check that a Linux package manager is available.
///
/// Required for installing host-side prerequisites (Firecracker is
/// fetched as a binary; libkrun comes from distro packages or Homebrew).
/// The check is informational —
/// `mvmctl bootstrap` continues even if no manager is found, since
/// users may have installed prerequisites by other means.
fn check_linux_package_manager() -> Result<()> {
    for cmd in &["apt-get", "dnf", "pacman"] {
        if which::which(cmd).is_ok() {
            ui::info(&format!("Package manager found: {}", cmd));
            return Ok(());
        }
    }
    ui::warn(
        "No supported package manager found (apt-get, dnf, or pacman). \
         You may need to install prerequisites manually.",
    );
    Ok(())
}

/// WSL2 bootstrap path. On Windows, mvm runs
/// inside a WSL2 distro — the Windows-side `mvmctl.exe` is a launcher
/// that ensures WSL2 is configured and the Linux-side `mvmctl` is
/// installed inside the chosen distro.
///
/// The current implementation detects WSL2 readiness and surfaces an
/// install hint; full automation (running `wsl --install` + provisioning
/// the distro) happens in a follow-up once we've validated the user
/// flow on a real Windows host. See
/// `public/.../guides/windows-wsl2.md` for the manual walkthrough
/// users follow today.
#[cfg(target_os = "windows")]
pub fn bootstrap_wsl2() -> Result<()> {
    use std::process::Command;

    if which::which("wsl").is_err() {
        anyhow::bail!(
            "WSL is not installed on this Windows host.\n\
             Install it from an elevated PowerShell:\n  \
                 wsl --install\n\
             Then reboot and re-run `mvmctl bootstrap`. See\n  \
                 https://github.com/tinylabscom/mvm/blob/main/public/src/content/docs/install/windows.md"
        );
    }

    // `wsl --status` returns 0 if WSL2 is configured and at least one
    // distro is registered. We don't parse the output — exit code is
    // sufficient signal for the bootstrap path.
    let status = Command::new("wsl")
        .arg("--status")
        .status()
        .map_err(|e| anyhow::anyhow!("could not invoke wsl: {e}"))?;
    if !status.success() {
        anyhow::bail!(
            "WSL2 is not configured.\n\
             From an elevated PowerShell:\n  \
                 wsl --install\n  \
                 wsl --update\n\
             Then re-run `mvmctl bootstrap`."
        );
    }

    ui::info(
        "WSL2 detected. Install mvmctl inside your WSL2 distro and run\n  \
            wsl -d Ubuntu -- mvmctl bootstrap\n\
         to complete setup. See guides/windows-wsl2 for the full walkthrough.",
    );
    Ok(())
}

/// On non-Windows hosts, `bootstrap_wsl2` is a no-op so callers don't
/// have to cfg-gate at every call site.
#[cfg(not(target_os = "windows"))]
pub fn bootstrap_wsl2() -> Result<()> {
    Ok(())
}

/// Check if Homebrew is installed and accessible (macOS only).
pub fn check_homebrew() -> Result<()> {
    which::which("brew").map_err(|_| {
        anyhow::anyhow!(
            "Homebrew is not installed.\n\
             Install it first:\n\n  \
             /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"\n\n\
             Then run 'mvmctl bootstrap' again."
        )
    })?;
    ui::info("Homebrew found.");
    Ok(())
}

/// Print an informational hint about libkrun availability.
/// libkrun is optional — when it's available, `mvmctl run`
/// can use it as a Tier 2 backend on supported libkrun hosts: Linux
/// with KVM and macOS Apple Silicon. This function does *not* attempt
/// to install libkrun automatically since it lives in the host's
/// package manager (Homebrew on macOS, distro packages on Linux).
///
/// Idempotent and safe to call from any bootstrap path.
pub fn hint_libkrun_if_useful() {
    let plat = platform::current();
    // Skip on Linux+KVM (Firecracker is the right backend) and on
    // Windows (libkrun has no Windows port).
    if plat.has_kvm() || plat.is_windows() {
        return;
    }
    if libkrun_sys::is_available() {
        ui::info(
            "Detected libkrun on this host; you can opt in with `mvmctl run --hypervisor libkrun`.",
        );
        return;
    }
    // Only suggest the install on macOS Apple Silicon. libkrun does
    // not give us a supported Intel Mac or native Windows path.
    if matches!(plat, Platform::MacOS) && cfg!(target_arch = "aarch64") {
        ui::info(&format!(
            "Tip: install libkrun for the local builder/runtime path on this Apple Silicon Mac.\n  {}",
            libkrun_sys::install_hint()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_homebrew_error_message() {
        if which::which("brew").is_err() {
            let err = check_homebrew().unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("Homebrew is not installed"));
            assert!(msg.contains("curl -fsSL"));
            assert!(msg.contains("mvmctl bootstrap"));
        } else {
            assert!(check_homebrew().is_ok());
        }
    }
}
