use anyhow::{Context, Result};
use std::io::Write as _;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use mvm_core::linux_env::LinuxEnv;
use mvm_core::platform;

use crate::config::VM_NAME;

/// Lima-backed Linux execution environment.
///
/// Routes all commands through `limactl shell <vm_name> bash -c "..."`.
/// Used on macOS and Linux without KVM.
pub struct LimaEnv {
    pub vm_name: String,
}

impl LimaEnv {
    pub fn new(vm_name: &str) -> Self {
        Self {
            vm_name: vm_name.to_string(),
        }
    }
}

impl LinuxEnv for LimaEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            return Ok(output);
        }

        Command::new("limactl")
            .args(["shell", &self.vm_name, "bash", "-c", script])
            .output()
            .with_context(|| format!("Failed to run command in Lima VM '{}'", self.vm_name))
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            if output.status.success() {
                return Ok(());
            }
            anyhow::bail!(
                "Command failed in Lima VM '{}' (exit {})",
                self.vm_name,
                output.status.code().unwrap_or(-1)
            );
        }

        let status = Command::new("limactl")
            .args(["shell", &self.vm_name, "bash", "-c", script])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("Failed to run command in Lima VM '{}'", self.vm_name))?;

        if !status.success() {
            anyhow::bail!(
                "Command failed in Lima VM '{}' (exit {})",
                self.vm_name,
                status.code().unwrap_or(-1)
            );
        }
        Ok(())
    }

    fn run_stdout(&self, script: &str) -> Result<String> {
        let output = self.run(script)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn run_capture(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            return Ok(output);
        }

        Command::new("limactl")
            .args(["shell", &self.vm_name, "bash", "-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("Failed to run command in Lima VM '{}'", self.vm_name))
    }
}

/// Native Linux execution environment.
///
/// Runs commands directly via `bash -c "..."`.
/// Used on Linux with KVM available.
pub struct NativeEnv;

impl LinuxEnv for NativeEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            return Ok(output);
        }

        Command::new("bash")
            .args(["-c", script])
            .output()
            .with_context(|| "Failed to run command on host")
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            if output.status.success() {
                return Ok(());
            }
            anyhow::bail!(
                "Command failed (exit {})",
                output.status.code().unwrap_or(-1)
            );
        }

        let status = Command::new("bash")
            .args(["-c", script])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| "Failed to run command on host")?;

        if !status.success() {
            anyhow::bail!("Command failed (exit {})", status.code().unwrap_or(-1));
        }
        Ok(())
    }

    fn run_stdout(&self, script: &str) -> Result<String> {
        let output = self.run(script)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn run_capture(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            return Ok(output);
        }

        Command::new("bash")
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "Failed to run command on host")
    }
}

/// Apple Container-backed Linux execution environment.
///
/// Routes commands through the guest agent's vsock `Exec` protocol.
/// Used on macOS 26+ when the Apple Container dev VM is running.
pub struct AppleContainerEnv {
    pub vm_id: String,
}

impl AppleContainerEnv {
    pub fn new(vm_id: &str) -> Self {
        Self {
            vm_id: vm_id.to_string(),
        }
    }

    /// Execute a command via the guest agent's vsock Exec protocol.
    fn exec_via_vsock(&self, script: &str, timeout_secs: u64) -> Result<Output> {
        let mut stream =
            mvm_apple_container::vsock_connect(&self.vm_id, mvm_guest::vsock::GUEST_AGENT_PORT)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to connect to dev VM '{}': {e}", self.vm_id)
                })?;

        let resp = mvm_guest::vsock::send_request(
            &mut stream,
            &mvm_guest::vsock::GuestRequest::Exec {
                command: script.to_string(),
                stdin: None,
                timeout_secs: Some(timeout_secs),
            },
        )
        .with_context(|| format!("Failed to execute command in dev VM '{}'", self.vm_id))?;

        match resp {
            mvm_guest::vsock::GuestResponse::ExecResult {
                exit_code,
                stdout,
                stderr,
            } => {
                use std::os::unix::process::ExitStatusExt;
                Ok(Output {
                    status: std::process::ExitStatus::from_raw(exit_code << 8),
                    stdout: stdout.into_bytes(),
                    stderr: stderr.into_bytes(),
                })
            }
            mvm_guest::vsock::GuestResponse::Error { message } => {
                anyhow::bail!("Dev VM exec error: {message}");
            }
            other => {
                anyhow::bail!("Unexpected response from dev VM: {other:?}");
            }
        }
    }
}

impl LinuxEnv for AppleContainerEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            return Ok(output);
        }
        self.exec_via_vsock(script, 60)
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            if output.status.success() {
                return Ok(());
            }
            anyhow::bail!(
                "Command failed in dev VM '{}' (exit {})",
                self.vm_id,
                output.status.code().unwrap_or(-1)
            );
        }

        let output = self.exec_via_vsock(script, 300)?;
        // Print stdout/stderr to the terminal (visible execution)
        if !output.stdout.is_empty() {
            std::io::stdout().write_all(&output.stdout).ok();
        }
        if !output.stderr.is_empty() {
            std::io::stderr().write_all(&output.stderr).ok();
        }
        if !output.status.success() {
            anyhow::bail!(
                "Command failed in dev VM '{}' (exit {})",
                self.vm_id,
                output.status.code().unwrap_or(-1)
            );
        }
        Ok(())
    }

    fn run_stdout(&self, script: &str) -> Result<String> {
        let output = self.run(script)?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn run_capture(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::shell_mock::intercept(script) {
            return Ok(output);
        }
        self.exec_via_vsock(script, 60)
    }
}

/// Create the appropriate `LinuxEnv` for the current platform.
pub fn create_linux_env() -> Box<dyn LinuxEnv> {
    let plat = platform::current();

    // Apple Container dev VM (macOS 26+)
    if plat.has_apple_containers() {
        return Box::new(AppleContainerEnv::new("mvm-dev"));
    }

    // Lima VM (macOS <26, Linux without KVM)
    if plat.needs_lima() {
        return Box::new(LimaEnv::new(VM_NAME));
    }

    // Native Linux with KVM
    Box::new(NativeEnv)
}

/// Global default environment used by `shell.rs` free functions.
static DEFAULT_ENV: OnceLock<Box<dyn LinuxEnv>> = OnceLock::new();

/// Get the default `LinuxEnv` for this process.
pub fn default_env() -> &'static dyn LinuxEnv {
    DEFAULT_ENV.get_or_init(create_linux_env).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lima_env_name() {
        let env = LimaEnv::new("test-vm");
        assert_eq!(env.vm_name, "test-vm");
    }

    #[test]
    fn test_create_linux_env_returns_env() {
        // Just verify the factory doesn't panic
        let env = create_linux_env();
        // The type depends on the platform, but it should implement LinuxEnv
        let _ = env;
    }

    #[test]
    fn test_default_env_is_consistent() {
        let a = default_env() as *const dyn LinuxEnv;
        let b = default_env() as *const dyn LinuxEnv;
        // Same pointer — OnceLock caches the result
        assert_eq!(a as *const (), b as *const ());
    }

    #[test]
    fn test_apple_container_env_name() {
        let env = AppleContainerEnv::new("mvm-dev");
        assert_eq!(env.vm_id, "mvm-dev");
    }
}
