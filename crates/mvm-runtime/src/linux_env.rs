use anyhow::{Context, Result};
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

/// Create the appropriate `LinuxEnv` for the current platform.
pub fn create_linux_env() -> Box<dyn LinuxEnv> {
    if platform::current().needs_lima() {
        Box::new(LimaEnv::new(VM_NAME))
    } else {
        Box::new(NativeEnv)
    }
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
}
