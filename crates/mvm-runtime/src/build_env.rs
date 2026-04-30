use anyhow::{Result, anyhow};

use mvm_core::build_env::ShellEnvironment;

use crate::{shell, ui};

/// Shell environment for the dev VM.
///
/// All build-related shell commands (`nix build`, file moves, scripted
/// setup, etc.) dispatch into the dev VM via `shell::run_in_vm`. The
/// dev VM is the only place mvmctl runs build tooling — the host never
/// invokes `nix` or other Linux tools directly. This is an isolation
/// invariant: the host's responsibility is limited to launching the dev
/// VM and ferrying artifacts in/out via vsock.
///
/// There is intentionally no `HostBuildEnv` alternative. Earlier code
/// had one as an "if host has nix, skip the VM" optimization, but that
/// erodes the isolation guarantee — anything that runs on the host is
/// outside the sandbox. If a future need to bypass the VM appears
/// (e.g. a tooling test that genuinely cannot wait for VM boot), add a
/// purpose-named impl with a narrowly scoped doc comment, not a generic
/// host-shell helper.
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

/// The build environment used by every mvmctl build invocation.
///
/// Always returns `RuntimeBuildEnv`. Builds happen inside the dev VM,
/// never on the host — see `RuntimeBuildEnv` for the isolation rationale.
pub fn default_build_env() -> Box<dyn ShellEnvironment> {
    Box::new(RuntimeBuildEnv)
}
