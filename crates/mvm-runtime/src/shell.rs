use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::config::VM_NAME;
use crate::linux_env;
use mvm_core::platform;

/// Run a command on the host, capturing output.
pub fn run_host(cmd: &str, args: &[&str]) -> Result<Output> {
    Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))
}

/// Run a command on the host, inheriting stdio (visible to user).
pub fn run_host_visible(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        anyhow::bail!(
            "Command failed (exit {}): {} {}",
            status.code().unwrap_or(-1),
            cmd,
            args.join(" ")
        );
    }
    Ok(())
}

/// Run a bash script in the Linux environment, capturing output.
///
/// On native Linux with KVM: runs `bash -c` directly on the host.
/// On macOS or Linux without KVM: runs via `limactl shell` inside a Lima VM.
///
/// When `vm_name` matches the default VM name, this delegates to the
/// [`LinuxEnv`](mvm_core::linux_env::LinuxEnv) abstraction. For custom
/// VM names, it uses the platform-specific command directly.
pub fn run_on_vm(vm_name: &str, script: &str) -> Result<Output> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run(script);
    }

    // Custom VM name — can't use the default LinuxEnv (it's bound to VM_NAME)
    if let Some(output) = crate::shell_mock::intercept(script) {
        return Ok(output);
    }

    if platform::current().needs_lima() {
        Command::new("limactl")
            .args(["shell", vm_name, "bash", "-c", script])
            .output()
            .with_context(|| format!("Failed to run command in Lima VM '{}'", vm_name))
    } else {
        Command::new("bash")
            .args(["-c", script])
            .output()
            .with_context(|| "Failed to run command on host")
    }
}

/// Run a bash script in the Linux environment, with output visible to user.
pub fn run_on_vm_visible(vm_name: &str, script: &str) -> Result<()> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run_visible(script);
    }

    let status = if platform::current().needs_lima() {
        Command::new("limactl")
            .args(["shell", vm_name, "bash", "-c", script])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("Failed to run command in Lima VM '{}'", vm_name))?
    } else {
        Command::new("bash")
            .args(["-c", script])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| "Failed to run command on host")?
    };

    if !status.success() {
        if platform::current().needs_lima() {
            anyhow::bail!(
                "Command failed in Lima VM '{}' (exit {})",
                vm_name,
                status.code().unwrap_or(-1)
            );
        } else {
            anyhow::bail!("Command failed (exit {})", status.code().unwrap_or(-1));
        }
    }
    Ok(())
}

/// Run a bash script in the Linux environment, returning stdout as String.
pub fn run_on_vm_stdout(vm_name: &str, script: &str) -> Result<String> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run_stdout(script);
    }
    let output = run_on_vm(vm_name, script)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a bash script in the default Linux environment, capturing output.
pub fn run_in_vm(script: &str) -> Result<Output> {
    linux_env::default_env().run(script)
}

/// Run a bash script in the default Linux environment, with output visible to user.
pub fn run_in_vm_visible(script: &str) -> Result<()> {
    linux_env::default_env().run_visible(script)
}

/// Run a bash script in the default Linux environment, returning stdout as String.
pub fn run_in_vm_stdout(script: &str) -> Result<String> {
    linux_env::default_env().run_stdout(script)
}

/// Run a bash script in the Linux environment, capturing stdout and stderr
/// into an `Output` struct (piped, not inherited).
///
/// Unlike `run_on_vm_visible`, the output is **not** shown to the user in real time.
/// Use this when you need to capture error messages (e.g., nix build failures) for
/// structured reporting.
pub fn run_on_vm_capture(vm_name: &str, script: &str) -> Result<Output> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run_capture(script);
    }

    if let Some(output) = crate::shell_mock::intercept(script) {
        return Ok(output);
    }

    if platform::current().needs_lima() {
        Command::new("limactl")
            .args(["shell", vm_name, "bash", "-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("Failed to run command in Lima VM '{}'", vm_name))
    } else {
        Command::new("bash")
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "Failed to run command on host")
    }
}

/// Run a bash script in the default Linux environment, capturing stdout and stderr.
pub fn run_in_vm_capture(script: &str) -> Result<Output> {
    linux_env::default_env().run_capture(script)
}

/// Heuristic: are we currently executing inside a Lima guest VM?
/// Checks common Lima environment markers.
pub fn inside_lima() -> bool {
    std::env::var("LIMA_INSTANCE").is_ok()
        || Path::new("/etc/lima-boot.conf").exists()
        || Path::new("/run/lima-guestagent.sock").exists()
}

/// Replace the current process with an interactive command (for SSH/TTY).
/// Uses Unix's process replacement — the Rust process is fully replaced, no return on success.
/// Note: This is safe because all arguments are passed as an array, not via shell interpolation.
#[cfg(unix)]
pub fn replace_process(cmd: &str, args: &[&str]) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let err = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();

    // exec() only returns on error
    Err(err).with_context(|| format!("Failed to replace process: {} {}", cmd, args.join(" ")))
}

/// Replace the current process with `cmd args...`, wrapped for the VM runtime.
///
/// On macOS (or Linux without KVM): exec `limactl shell <VM_NAME> <cmd> <args...>`
/// On native Linux with KVM: exec `<cmd> <args...>` directly
///
/// This mirrors [`run_in_vm`] but uses process replacement (Unix exec) instead
/// of spawning a child process. Needed for interactive TTY pass-through
/// (e.g., SSH sessions, interactive shells).
#[cfg(unix)]
pub fn replace_process_in_vm(cmd: &str, args: &[&str]) -> Result<()> {
    if platform::current().needs_lima() {
        let mut lima_args = vec!["shell", VM_NAME, cmd];
        lima_args.extend_from_slice(args);
        replace_process("limactl", &lima_args)
    } else {
        replace_process(cmd, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inside_lima_false_on_host() {
        // In CI/dev environments, we should NOT be inside Lima.
        // If LIMA_INSTANCE is not set and the marker files don't exist,
        // inside_lima() should return false.
        unsafe { std::env::remove_var("LIMA_INSTANCE") };
        // On a non-Lima machine, neither marker file exists.
        if !Path::new("/etc/lima-boot.conf").exists()
            && !Path::new("/run/lima-guestagent.sock").exists()
        {
            assert!(!inside_lima());
        }
    }

    #[test]
    fn test_run_host_echo() {
        let output = run_host("echo", &["hello"]).unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "hello");
    }

    #[test]
    fn test_run_host_failure() {
        let output = run_host("false", &[]).unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn test_run_host_nonexistent_command() {
        let result = run_host("definitely-not-a-real-command-12345", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_run_host_visible_success() {
        let result = run_host_visible("true", &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_host_visible_failure() {
        let result = run_host_visible("false", &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Command failed"));
    }
}
