use anyhow::Result;

use crate::ui;
use mvm_core::platform::{self, Platform};
use mvm_runtime::shell;

/// Check that a package manager is available for the current platform.
///
/// - macOS: requires Homebrew
/// - Linux: requires apt, dnf, or pacman
pub fn check_package_manager() -> Result<()> {
    if cfg!(target_os = "macos") {
        check_homebrew()
    } else {
        check_linux_package_manager()
    }
}

/// Check if Homebrew is installed and accessible (macOS only).
pub fn check_homebrew() -> Result<()> {
    which::which("brew").map_err(|_| {
        anyhow::anyhow!(
            "Homebrew is not installed.\n\
             Install it first:\n\n  \
             /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"\n\n\
             Then run 'mvm bootstrap' again."
        )
    })?;
    ui::info("Homebrew found.");
    Ok(())
}

/// Check that a Linux package manager is available.
fn check_linux_package_manager() -> Result<()> {
    for cmd in &["apt-get", "dnf", "pacman"] {
        if which::which(cmd).is_ok() {
            ui::info(&format!("Package manager found: {}", cmd));
            return Ok(());
        }
    }
    anyhow::bail!(
        "No supported package manager found (apt-get, dnf, or pacman).\n\
         Install Lima manually: https://lima-vm.io/docs/installation/"
    )
}

/// Install Lima if not already installed.
///
/// On native Linux with KVM, Lima is not required — this is a no-op.
/// On macOS or Linux without KVM: installs Lima via package manager.
pub fn ensure_lima() -> Result<()> {
    if platform::current() == Platform::LinuxNative {
        ui::info("Native Linux with KVM detected — Lima not required.");
        return Ok(());
    }

    if which::which("limactl").is_ok() {
        let output = shell::run_host("limactl", &["--version"])?;
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        ui::info(&format!("Lima already installed: {}", version));
        return Ok(());
    }

    if cfg!(target_os = "macos") {
        ui::info("Installing Lima via Homebrew...");
        shell::run_host_visible("brew", &["install", "lima"])?;
    } else {
        install_lima_linux()?;
    }

    which::which("limactl").map_err(|_| {
        anyhow::anyhow!("Lima installation completed but 'limactl' not found in PATH.")
    })?;

    ui::success("Lima installed successfully.");
    Ok(())
}

/// Install Lima on Linux via binary download from GitHub releases.
fn install_lima_linux() -> Result<()> {
    // Check for Homebrew first (works on Linux)
    if which::which("brew").is_ok() {
        ui::info("Installing Lima via Homebrew...");
        shell::run_host_visible("brew", &["install", "lima"])?;
        return Ok(());
    }

    // Check for Nix (cross-platform)
    if which::which("nix-env").is_ok() {
        ui::info("Installing Lima via Nix...");
        shell::run_host_visible("nix-env", &["-i", "lima"])?;
        return Ok(());
    }

    // Fallback: Download binary from GitHub releases
    ui::info("Installing Lima from GitHub releases...");
    let install_script = r#"
set -euo pipefail
LIMA_VERSION=$(curl -fsSL https://api.github.com/repos/lima-vm/lima/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
URL="https://github.com/lima-vm/lima/releases/download/v${LIMA_VERSION}/lima-${LIMA_VERSION}-Linux-${ARCH}.tar.gz"
echo "Downloading Lima ${LIMA_VERSION} for ${ARCH}..."
curl -fsSL "$URL" | sudo tar -xz -C /usr/local
sudo chmod +x /usr/local/bin/limactl
echo "Lima ${LIMA_VERSION} installed successfully"
"#;
    shell::run_host_visible("bash", &["-c", install_script])?;
    Ok(())
}

/// Check if the platform requires Lima.
pub fn is_lima_required() -> bool {
    platform::current().needs_lima()
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
            assert!(msg.contains("mvm bootstrap"));
        } else {
            assert!(check_homebrew().is_ok());
        }
    }

    #[test]
    fn test_ensure_lima_when_limactl_present() {
        if which::which("limactl").is_ok() {
            assert!(ensure_lima().is_ok());
        }
    }

    #[test]
    fn test_is_lima_required() {
        let _ = is_lima_required();
    }
}
