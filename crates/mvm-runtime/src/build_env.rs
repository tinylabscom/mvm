use anyhow::{Result, anyhow};

use mvm_core::build_env::ShellEnvironment;

use crate::{shell, ui};

/// Shell environment implementation that delegates to the Lima VM.
///
/// Used by the CLI for dev-mode builds (`mvm build --flake`, `mvm run`,
/// `mvm template build`).
pub struct RuntimeBuildEnv;

impl ShellEnvironment for RuntimeBuildEnv {
    fn shell_exec(&self, script: &str) -> Result<()> {
        let out = shell::run_in_vm(script)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Command failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn shell_exec_stdout(&self, script: &str) -> Result<String> {
        let out = shell::run_in_vm(script)?;
        if !out.status.success() {
            return Err(anyhow!(
                "Command failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn shell_exec_visible(&self, script: &str) -> Result<()> {
        shell::run_in_vm_visible(script)
    }

    fn log_info(&self, msg: &str) {
        ui::info(msg);
    }

    fn log_success(&self, msg: &str) {
        ui::success(msg);
    }

    fn log_warn(&self, msg: &str) {
        ui::warn(msg);
    }

    fn shell_exec_capture(&self, script: &str) -> Result<(String, String)> {
        let out = shell::run_in_vm_capture(script)?;
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if !out.status.success() {
            // Include both stdout and stderr — callers may use 2>&1 which
            // merges all output into stdout, leaving stderr empty.
            let output = if stderr.is_empty() {
                stdout
            } else if stdout.is_empty() {
                stderr
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            return Err(anyhow!(
                "Command failed (exit {}):\n{}",
                out.status.code().unwrap_or(-1),
                output
            ));
        }
        Ok((stdout, stderr))
    }
}
