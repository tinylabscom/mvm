//! The host shell a support-artifact build step runs in.

use anyhow::{Context, Result};

/// Runs a support-artifact build step directly on this host: the initramfs
/// resolver's local build fallback and the warm-artifact worker's.
///
/// On Linux the host *is* the builder boundary. On macOS the nix-build
/// fallback is `#[cfg(target_os = "linux")]`, so nothing reaches it there.
pub(crate) struct HostShellEnvironment;

impl mvm_core::build_env::ShellEnvironment for HostShellEnvironment {
    fn shell_exec(&self, script: &str) -> Result<()> {
        let output = mvm_core::env_hygiene::helper_command("bash")
            .args(["-c", script])
            .output()
            .context("failed to run shell command")?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "shell command failed (exit {}): {stderr}",
                output.status.code().unwrap_or(-1)
            );
        }
    }

    fn shell_exec_stdout(&self, script: &str) -> Result<String> {
        let output = self.shell_exec_capture(script)?;
        Ok(output.0.trim().to_string())
    }

    fn shell_exec_visible(&self, script: &str) -> Result<()> {
        let status = mvm_core::env_hygiene::helper_command("bash")
            .args(["-c", script])
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .context("failed to run shell command")?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "shell command failed (exit {})",
                status.code().unwrap_or(-1)
            );
        }
    }

    fn log_info(&self, msg: &str) {
        tracing::info!("{msg}");
    }

    fn log_success(&self, msg: &str) {
        tracing::info!("{msg}");
    }

    fn shell_exec_capture(&self, script: &str) -> Result<(String, String)> {
        let output = mvm_core::env_hygiene::helper_command("bash")
            .args(["-c", script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .context("failed to run shell command")?;
        if output.status.success() {
            Ok((
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "shell command failed (exit {}): {stderr}",
                output.status.code().unwrap_or(-1)
            );
        }
    }
}
