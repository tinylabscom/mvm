use anyhow::{Context, Result};
use std::io::Write as _;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use mvm_core::linux_env::LinuxEnv;
use mvm_core::platform;

/// Native Linux execution environment.
///
/// Runs commands directly via `bash -c "..."`.
/// Used on Linux with KVM available.
pub struct NativeEnv;

impl LinuxEnv for NativeEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::base::shell_mock::intercept(script) {
            return Ok(output);
        }

        Command::new("bash")
            .args(["-c", script])
            .output()
            .with_context(|| "Failed to run command on host")
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::base::shell_mock::intercept(script) {
            if output.status.success() {
                return Ok(());
            }
            anyhow::bail!(
                "Command failed (exit {})",
                output.status.code().unwrap_or(-1)
            );
        }

        let output = Command::new("bash")
            .args(["-c", script])
            .stdin(Stdio::inherit())
            .stdout(if crate::base::ui::is_chrome_routed_to_stderr() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .stderr(Stdio::inherit())
            .output()
            .with_context(|| "Failed to run command on host")?;

        if crate::base::ui::is_chrome_routed_to_stderr() && !output.stdout.is_empty() {
            std::io::stderr().write_all(&output.stdout).ok();
        }

        if !output.status.success() {
            anyhow::bail!(
                "Command failed (exit {})",
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
        if let Some(output) = crate::base::shell_mock::intercept(script) {
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

/// Decide whether `DevVmEnv` may auto-start the dev daemon.
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

/// Name of the dev VM. `mvmctl dev up` boots it as the libkrun dev VM
/// under `~/.mvm/vms/mvm-dev`; this is the display name the dev env carries.
const DEV_VM_NAME: &str = "mvm-dev";

/// Connect to the libkrun dev VM's guest-agent vsock through its per-port
/// Unix listener (`<vm_state_dir>/vsock-<port>.sock`) — the same path
/// `LibkrunTransport::for_vm` resolves. The libkrun supervisor is the
/// cross-process vsock server, so a plain connect to its listener is the
/// whole transport.
fn connect_dev_vsock(vm_id: &str, port: u32) -> std::io::Result<std::os::unix::net::UnixStream> {
    let sock = mvm_core::config::vm_vsock_port_socket(vm_id, port);
    std::os::unix::net::UnixStream::connect(sock)
}

/// Boot the dev daemon by re-executing this binary as `<exe> dev up`.
///
/// Blocks until `mvmctl dev up` returns (it exits once the proxy socket
/// is reachable, which is exactly what callers need before retrying the
/// connection). Inherits stderr so progress messages reach the user.
fn start_dev_daemon(vm_id: &str) -> Result<()> {
    let exe = std::env::current_exe().context("locating mvmctl binary for dev auto-start")?;
    crate::base::ui::progress(&format!(
        "dev VM '{vm_id}' is not running — auto-starting..."
    ));
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
/// The dev VM uses a minimal Nix-built rootfs that runs scripts as
/// PID 1 (uid 0) with no sudo binary, while the shared network /
/// firecracker scripts in this crate assume a non-root +
/// passwordless-sudo model. Prepending this shim lets the same scripts
/// run unmodified on both backends.
const SUDO_SHIM: &str =
    "if [ \"$(id -u)\" = 0 ] && ! command -v sudo >/dev/null 2>&1; then sudo() { \"$@\"; }; fi";

/// Dev-VM-backed Linux execution environment.
///
/// Routes commands through the guest agent's vsock `Exec` protocol.
/// Used on macOS 26+ when the libkrun dev VM is running.
pub struct DevVmEnv {
    pub vm_id: String,
}

impl DevVmEnv {
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
        match connect_dev_vsock(&self.vm_id, port) {
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
                connect_dev_vsock(&self.vm_id, port).map_err(|e| {
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
        let mut out_buf: Vec<u8> = Vec::new();
        let mut err_buf: Vec<u8> = Vec::new();
        // Accumulate streamed ExecEvent chunks.
        let terminal = mvm_guest::vsock::send_exec_streaming(
            &mut stream,
            &wrapped,
            None,
            Some(timeout_secs),
            |event| match event {
                mvm_guest::vsock::ExecEvent::Stdout { chunk } => out_buf.extend_from_slice(chunk),
                mvm_guest::vsock::ExecEvent::Stderr { chunk } => err_buf.extend_from_slice(chunk),
                _ => {}
            },
        )
        .with_context(|| format!("Failed to execute command in dev VM '{}'", self.vm_id))?;

        match terminal {
            mvm_guest::vsock::ExecEvent::Exit { code } => {
                use std::os::unix::process::ExitStatusExt;
                Ok(Output {
                    status: std::process::ExitStatus::from_raw(code << 8),
                    stdout: out_buf,
                    stderr: err_buf,
                })
            }
            mvm_guest::vsock::ExecEvent::TimedOut => anyhow::bail!(
                "command timed out after {timeout_secs}s in dev VM '{}'",
                self.vm_id
            ),
            other => anyhow::bail!("unexpected terminal exec event from dev VM: {other:?}"),
        }
    }
}

impl LinuxEnv for DevVmEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::base::shell_mock::intercept(script) {
            return Ok(output);
        }
        self.exec_via_vsock(script, 60)
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::base::shell_mock::intercept(script) {
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
            if crate::base::ui::is_chrome_routed_to_stderr() {
                std::io::stderr().write_all(&output.stdout).ok();
            } else {
                std::io::stdout().write_all(&output.stdout).ok();
            }
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
        if let Some(output) = crate::base::shell_mock::intercept(script) {
            return Ok(output);
        }
        self.exec_via_vsock(script, 60)
    }
}

/// Create the appropriate `LinuxEnv` for the current platform.
///
/// macOS 26+ Apple Silicon routes through the libkrun dev VM's guest-agent
/// vsock channel; native Linux runs on the host. macOS Intel, Linux without
/// KVM, WSL2, and native Windows are not supported local Linux execution
/// boundaries today; WSL2 nested KVM and a Hyper-V managed Linux builder are
/// future backend work.
pub fn create_linux_env() -> Box<dyn LinuxEnv> {
    let plat = platform::current();

    if plat.is_vz_default_tier() {
        return Box::new(DevVmEnv::new(DEV_VM_NAME));
    }

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
    fn test_dev_vm_env_name() {
        let env = DevVmEnv::new("mvm-dev");
        assert_eq!(env.vm_id, "mvm-dev");
    }

    #[test]
    fn dev_vm_connects_via_libkrun_per_port_socket() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("HOME", tmp.path());
        env.remove("MVM_DATA_DIR");

        // The dev env dials the libkrun dev VM's per-port vsock listener at
        // `<vm_state_dir>/vsock-<port>.sock` — the same path
        // `LibkrunTransport::for_vm` resolves, so the flake-build env and the
        // console can't drift onto different sockets.
        let port = mvm_guest::vsock::GUEST_AGENT_PORT;
        let sock = mvm_core::config::vm_vsock_port_socket(DEV_VM_NAME, port);
        assert!(
            sock.ends_with(mvm_core::config::vsock_socket_filename(port)),
            "dev VM socket must be the per-port libkrun listener: {sock:?}"
        );
        assert_eq!(
            sock,
            mvm_core::config::vm_state_dir(DEV_VM_NAME)
                .join(mvm_core::config::vsock_socket_filename(port))
        );
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
