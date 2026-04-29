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

/// Decide whether `AppleContainerEnv` may auto-start the dev daemon.
///
/// `MVM_NO_AUTO_DEV=1`             — opt-out (always wins).
/// `MVM_AUTO_DEV=1`                — opt-in even when stdin isn't a TTY.
/// `MVM_DEV_DAEMON=1`              — set inside the daemon itself; skip
///                                   auto-start to avoid recursion.
/// Otherwise: only when stdin is a TTY (best-effort interactivity check)
/// so headless CI doesn't silently boot a heavyweight VM.
fn auto_start_allowed() -> bool {
    if std::env::var("MVM_NO_AUTO_DEV").as_deref() == Ok("1") {
        return false;
    }
    if std::env::var("MVM_DEV_DAEMON").as_deref() == Ok("1") {
        return false;
    }
    if std::env::var("MVM_AUTO_DEV").as_deref() == Ok("1") {
        return true;
    }
    is_stdin_tty()
}

fn is_stdin_tty() -> bool {
    use std::os::unix::io::AsRawFd as _;
    unsafe { libc::isatty(std::io::stdin().as_raw_fd()) == 1 }
}

/// Boot the dev daemon by re-executing this binary as `<exe> dev up`.
///
/// Blocks until `mvmctl dev up` returns (it exits once the proxy socket
/// is reachable, which is exactly what callers need before retrying the
/// connection). Inherits stderr so progress messages reach the user.
fn start_dev_daemon(vm_id: &str) -> Result<()> {
    let exe = std::env::current_exe().context("locating mvmctl binary for dev auto-start")?;
    eprintln!("[mvm] dev VM '{vm_id}' is not running — auto-starting...");
    let status = Command::new(&exe)
        .args(["dev", "up"])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("spawning '{} dev up'", exe.display()))?;
    if !status.success() {
        anyhow::bail!(
            "'{} dev up' exited with {}",
            exe.display(),
            status.code().unwrap_or(-1),
        );
    }
    Ok(())
}

/// Shell prelude that defines a no-op `sudo` function when the script
/// already runs as root and `sudo` isn't installed.
///
/// The Apple Container dev VM uses a minimal Nix-built rootfs that runs
/// scripts as PID 1 (uid 0) with no sudo binary, while the shared
/// network / firecracker scripts in this crate are written for Lima's
/// non-root + passwordless-sudo model. Prepending this shim lets the
/// same scripts run unmodified on both backends.
const SUDO_SHIM: &str =
    "if [ \"$(id -u)\" = 0 ] && ! command -v sudo >/dev/null 2>&1; then sudo() { \"$@\"; }; fi";

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

    /// Connect to the dev VM, auto-starting the daemon when neither the
    /// in-process VM nor the cross-process proxy socket is available.
    ///
    /// Auto-start is skipped when `MVM_NO_AUTO_DEV=1` is set, when the
    /// current process is itself the dev daemon (avoids recursion), or
    /// when stdin is not a TTY *and* `MVM_AUTO_DEV` is not explicitly
    /// set (CI shouldn't silently boot a heavyweight VM).
    fn connect_with_auto_start(&self) -> Result<std::os::unix::net::UnixStream> {
        let port = mvm_guest::vsock::GUEST_AGENT_PORT;
        match mvm_apple_container::vsock_connect_any(&self.vm_id, port) {
            Ok(stream) => Ok(stream),
            Err(initial_err) => {
                if !auto_start_allowed() {
                    anyhow::bail!(
                        "Failed to connect to dev VM '{}': {initial_err}",
                        self.vm_id,
                    );
                }
                start_dev_daemon(&self.vm_id).with_context(|| {
                    format!(
                        "auto-starting dev VM '{}' after connect failure",
                        self.vm_id
                    )
                })?;
                mvm_apple_container::vsock_connect_any(&self.vm_id, port).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to connect to dev VM '{}' after auto-start: {e} (initial: {initial_err})",
                        self.vm_id,
                    )
                })
            }
        }
    }

    /// Execute a command via the guest agent's vsock Exec protocol.
    fn exec_via_vsock(&self, script: &str, timeout_secs: u64) -> Result<Output> {
        let mut stream = self.connect_with_auto_start()?;

        let wrapped = format!("{SUDO_SHIM}\n{script}");
        let resp = mvm_guest::vsock::send_request(
            &mut stream,
            &mvm_guest::vsock::GuestRequest::Exec {
                command: wrapped,
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

    /// `auto_start_allowed` is precedence-sensitive across env vars; a
    /// single mutex-guarded test exercises every branch in one process so
    /// parallel tests can't see partial state.
    #[test]
    fn test_auto_start_allowed_env_precedence() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");

        // Snapshot then clear so the test isn't perturbed by the runner.
        let saved: Vec<(&str, Option<String>)> =
            ["MVM_NO_AUTO_DEV", "MVM_AUTO_DEV", "MVM_DEV_DAEMON"]
                .iter()
                .map(|k| (*k, std::env::var(k).ok()))
                .collect();
        let restore = || {
            for (k, v) in &saved {
                // SAFETY: serialised via ENV_LOCK above.
                unsafe {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
        };

        let set = |k: &str, v: Option<&str>| {
            // SAFETY: serialised via ENV_LOCK above.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        };

        // Clear all three so each branch is exercised in isolation.
        set("MVM_NO_AUTO_DEV", None);
        set("MVM_AUTO_DEV", None);
        set("MVM_DEV_DAEMON", None);

        // Opt-out always wins, even alongside the explicit opt-in.
        set("MVM_NO_AUTO_DEV", Some("1"));
        set("MVM_AUTO_DEV", Some("1"));
        assert!(
            !auto_start_allowed(),
            "MVM_NO_AUTO_DEV must override opt-in"
        );

        // Daemon-self check prevents re-spawn recursion.
        set("MVM_NO_AUTO_DEV", None);
        set("MVM_AUTO_DEV", None);
        set("MVM_DEV_DAEMON", Some("1"));
        assert!(!auto_start_allowed(), "daemon must not auto-start itself");

        // Explicit opt-in overrides the TTY heuristic in headless runs.
        set("MVM_DEV_DAEMON", None);
        set("MVM_AUTO_DEV", Some("1"));
        assert!(
            auto_start_allowed(),
            "MVM_AUTO_DEV=1 must enable auto-start"
        );

        restore();
    }

    /// `SUDO_SHIM` must parse cleanly in POSIX `sh` (busybox ash on the
    /// dev rootfs) and behave as a no-op when running as a non-root user
    /// — which is the typical state for this test process.
    #[test]
    fn test_sudo_shim_is_valid_sh() {
        let out = Command::new("sh")
            .args(["-c", &format!("{SUDO_SHIM}\necho ok")])
            .output()
            .expect("sh");
        assert!(out.status.success(), "stderr: {:?}", out.stderr);
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
    }
}
