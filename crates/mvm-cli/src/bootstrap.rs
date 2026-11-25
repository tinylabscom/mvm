use anyhow::Result;

use crate::ui;
use mvm_core::platform;

/// Check that a package manager is available for the current platform.
///
/// - macOS: reports whether Homebrew is present; never fails (see
///   [`homebrew_report`])
/// - Linux: any of apt, dnf, pacman is accepted
/// - Windows: requires WSL2 (delegates to [`bootstrap_wsl2`])
pub fn check_package_manager() -> Result<()> {
    if cfg!(target_os = "macos") {
        ui::info(homebrew_report(mvm_core::util::which("brew").is_some()));
        Ok(())
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
        if mvm_core::util::which(cmd).is_some() {
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
    if mvm_core::util::which("wsl").is_none() {
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
    let status = mvm_core::env_hygiene::helper_command("wsl")
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

/// What `bootstrap` says about Homebrew on macOS.
///
/// Homebrew is optional. The default backend on Apple Silicon is the in-house
/// HVF VMM, which needs nothing installed, and a release binary carries every
/// helper it spawns; only the opt-in libkrun backend is installed through
/// Homebrew. A
/// bootstrap that refused without Homebrew stopped before it prepared anything,
/// so a first run on a Mac without it printed an install error and then paid
/// the whole preparation itself.
fn homebrew_report(found: bool) -> &'static str {
    if found {
        "Homebrew found."
    } else {
        "Homebrew not found — not needed: the default HVF backend has no host \
         dependencies. Only the opt-in libkrun backend installs through it."
    }
}

/// Say that an installed libkrun can be opted into. libkrun is optional, and
/// no supported host needs it, so a host without it is told nothing.
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mac_without_homebrew_is_told_it_is_optional() {
        let report = homebrew_report(false);
        assert!(report.contains("not needed"), "{report}");
        assert!(report.contains("libkrun"), "{report}");
        for alarming in ["not installed", "Install it first", "curl -fsSL"] {
            assert!(
                !report.contains(alarming),
                "a missing optional tool must not read as a failure: {report}"
            );
        }
        assert_eq!(homebrew_report(true), "Homebrew found.");
    }

    /// The package-manager check is informational on every Unix host: a
    /// bootstrap that stops here prepares none of what the first run needs.
    #[cfg(unix)]
    #[test]
    fn the_package_manager_check_never_stops_a_bootstrap() {
        assert!(check_package_manager().is_ok());
    }
}
