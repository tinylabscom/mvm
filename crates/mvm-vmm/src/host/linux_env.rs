use anyhow::{Context, Result};
use std::io::Write as _;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

use mvm_core::linux_env::LinuxEnv;
use mvm_core::platform;
/// Builder VM name.
pub const VM_NAME: &str = "mvm-builder";

/// Native Linux execution environment.
///
/// Runs commands directly via `bash -c "..."`.
/// Used on Linux with KVM available.
pub struct NativeEnv;

impl LinuxEnv for NativeEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::host::shell::mock::intercept(script) {
            return Ok(output);
        }

        Command::new("bash")
            .args(["-c", script])
            .output()
            .with_context(|| "Failed to run command on host")
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::host::shell::mock::intercept(script) {
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
            .stdout(if crate::host::ui::is_chrome_routed_to_stderr() {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .stderr(Stdio::inherit())
            .output()
            .with_context(|| "Failed to run command on host")?;

        if crate::host::ui::is_chrome_routed_to_stderr() && !output.stdout.is_empty() {
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
        if let Some(output) = crate::host::shell::mock::intercept(script) {
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

/// Name of the dev VM: it runs as the libkrun dev VM under
/// `~/.mvm/vms/mvm-dev`; this is the display name the dev env carries.
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

/// Auto-starting the dev daemon used to re-exec this binary as `<exe> dev
/// up`. That command was removed along with the interactive dev-VM
/// surface, so there is no subprocess left to spawn here. This macOS
/// `run_in_vm` shell-ops path still needs a way to bring the Linux
/// execution environment up on demand, but that now has to go through the
/// headless builder VM instead of a dev-VM re-exec, and that wiring
/// doesn't exist yet — so fail closed with an explicit message instead of
/// attempting a spawn that can only fail.
fn start_dev_daemon(vm_id: &str) -> Result<()> {
    anyhow::bail!(
        "dev VM '{vm_id}' is not running and can no longer be auto-started: \
         the interactive dev-VM command that used to boot it on demand was \
         removed, and this macOS shell-ops path has not yet been migrated \
         to boot the headless builder VM instead. Start the builder VM \
         through another path first (for example a build that needs it), \
         then retry."
    )
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
        let port = mvm_agentd::vsock::GUEST_AGENT_PORT;
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
        let terminal = mvm_agentd::vsock::send_exec_streaming(
            &mut stream,
            &wrapped,
            None,
            Some(timeout_secs),
            |event| match event {
                mvm_agentd::vsock::ExecEvent::Stdout { chunk } => out_buf.extend_from_slice(chunk),
                mvm_agentd::vsock::ExecEvent::Stderr { chunk } => err_buf.extend_from_slice(chunk),
                _ => {}
            },
        )
        .with_context(|| format!("Failed to execute command in dev VM '{}'", self.vm_id))?;

        match terminal {
            mvm_agentd::vsock::ExecEvent::Exit { code } => {
                use std::os::unix::process::ExitStatusExt;
                Ok(Output {
                    status: std::process::ExitStatus::from_raw(code << 8),
                    stdout: out_buf,
                    stderr: err_buf,
                })
            }
            mvm_agentd::vsock::ExecEvent::TimedOut => anyhow::bail!(
                "command timed out after {timeout_secs}s in dev VM '{}'",
                self.vm_id
            ),
            other => anyhow::bail!("unexpected terminal exec event from dev VM: {other:?}"),
        }
    }
}

impl LinuxEnv for DevVmEnv {
    fn run(&self, script: &str) -> Result<Output> {
        if let Some(output) = crate::host::shell::mock::intercept(script) {
            return Ok(output);
        }
        self.exec_via_vsock(script, 60)
    }

    fn run_visible(&self, script: &str) -> Result<()> {
        if let Some(output) = crate::host::shell::mock::intercept(script) {
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
            if crate::host::ui::is_chrome_routed_to_stderr() {
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
        if let Some(output) = crate::host::shell::mock::intercept(script) {
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

    if plat.is_hvf_default_tier() {
        return Box::new(DevVmEnv::new(DEV_VM_NAME));
    }

    Box::new(NativeEnv)
}

/// Whether a `run_in_vm`-style guest op can reach a real Linux execution
/// environment today.
///
/// True on native Linux and macOS 13-25, both of which [`create_linux_env`]
/// resolves to [`NativeEnv`]. False only on macOS 26+ Apple Silicon, where
/// [`create_linux_env`] hands back [`DevVmEnv`] and — since the dev-VM
/// auto-start path was retired (see [`start_dev_daemon`]) — a `run_in_vm`
/// call has nothing left to dispatch to. Guest ops that still need a Linux
/// builder on that tier should check this and fail closed via
/// [`require_guest_exec_available`] instead of attempting the doomed call.
pub fn guest_exec_via_vm_available() -> bool {
    !platform::current().is_hvf_default_tier()
}

/// Fails closed with an actionable error naming `limitation` when
/// [`guest_exec_via_vm_available`] is false; otherwise a no-op.
///
/// Callers hold a `run_in_vm`-backed op that has no builder to run against
/// on the current tier; this lets them return an upfront, honest error
/// instead of letting the call fail deep inside the vsock exec path.
pub fn require_guest_exec_available(limitation: &str) -> Result<()> {
    guest_exec_gate(guest_exec_via_vm_available(), limitation)
}

/// Pure decision behind [`require_guest_exec_available`], taking the
/// availability bool directly so it (and callers' gates) can be
/// unit-tested by forcing both branches, without faking the host's OS tier.
fn guest_exec_gate(available: bool, limitation: &str) -> Result<()> {
    if available {
        return Ok(());
    }
    Err(guest_exec_unavailable_error(limitation))
}

/// Build the actionable error a gated guest op returns once
/// [`guest_exec_via_vm_available`] is false. `limitation` is a short clause
/// naming what the op needs (e.g. "needs an ext4 reader, which doesn't
/// exist yet"); the workaround text is centralized here so it can't drift
/// between call sites.
pub fn guest_exec_unavailable_error(limitation: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{limitation}. This macOS tier has no Linux builder to run it against \
         — run it on Linux or in CI."
    )
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
    use mvm_core::util::test_env::TestEnv;

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
    fn start_dev_daemon_fails_honestly_without_spawning() {
        let err = start_dev_daemon("test-vm").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("test-vm"), "expected vm_id in message: {msg}");
        assert!(
            !msg.contains("dev up"),
            "must not point callers at the removed dev-up command: {msg}"
        );
    }

    #[test]
    fn dev_vm_connects_via_libkrun_per_port_socket() {
        let _guard = crate::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("HOME", tmp.path());
        env.remove("MVM_HOME");

        // The dev env dials the libkrun dev VM's per-port vsock listener in
        // the canonical socket directory. That directory is normally the VM
        // state directory and becomes the hashed short namespace when any
        // socket path would exceed the platform limit.
        let port = mvm_agentd::vsock::GUEST_AGENT_PORT;
        let sock = mvm_core::config::vm_vsock_port_socket(DEV_VM_NAME, port);
        assert!(
            sock.ends_with(mvm_core::config::vsock_socket_filename(port)),
            "dev VM socket must be the per-port libkrun listener: {sock:?}"
        );
        assert_eq!(
            sock,
            mvm_core::config::vm_socket_dir(DEV_VM_NAME)
                .join(mvm_core::config::vsock_socket_filename(port))
        );
    }

    /// `auto_start_allowed` is precedence-sensitive across env vars; a
    /// single mutex-guarded test exercises every branch in one process so
    /// parallel tests can't see partial state.
    #[test]
    fn test_auto_start_allowed_env_precedence() {
        let mut env = TestEnv::new();

        // Clear all three so each branch is exercised in isolation.
        env.remove("MVM_NO_AUTO_DEV");
        env.remove("MVM_AUTO_DEV");
        env.remove("MVM_DEV_DAEMON");

        // Opt-out always wins, even alongside the explicit opt-in.
        env.set("MVM_NO_AUTO_DEV", "1");
        env.set("MVM_AUTO_DEV", "1");
        assert!(
            !auto_start_allowed(),
            "MVM_NO_AUTO_DEV must override opt-in"
        );

        // Daemon-self check prevents re-spawn recursion.
        env.remove("MVM_NO_AUTO_DEV");
        env.remove("MVM_AUTO_DEV");
        env.set("MVM_DEV_DAEMON", "1");
        assert!(!auto_start_allowed(), "daemon must not auto-start itself");

        // Explicit opt-in overrides the TTY heuristic in headless runs.
        env.remove("MVM_DEV_DAEMON");
        env.set("MVM_AUTO_DEV", "1");
        assert!(
            auto_start_allowed(),
            "MVM_AUTO_DEV=1 must enable auto-start"
        );
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

    // ── guest_exec gating ───────────────────────────────────────────

    #[test]
    fn guest_exec_via_vm_available_is_negation_of_hvf_default_tier() {
        assert_eq!(
            guest_exec_via_vm_available(),
            !platform::current().is_hvf_default_tier()
        );
    }

    /// The gate's decision is forced through the same bool
    /// [`guest_exec_via_vm_available`] feeds, so both branches are
    /// covered without needing to fake the host's OS tier.
    #[test]
    fn guest_exec_gate_passes_when_available() {
        assert!(guest_exec_gate(true, "irrelevant").is_ok());
    }

    #[test]
    fn guest_exec_gate_fails_closed_naming_limitation_and_workaround() {
        let err = guest_exec_gate(false, "needs an ext4 reader, which doesn't exist yet")
            .expect_err("must fail closed when unavailable");
        let msg = err.to_string();
        assert!(msg.contains("ext4 reader"), "missing limitation: {msg}");
        assert!(msg.contains("Linux"), "missing Linux workaround: {msg}");
    }

    #[test]
    fn require_guest_exec_available_matches_gate() {
        let available = guest_exec_via_vm_available();
        let result = require_guest_exec_available("doing a thing");
        assert_eq!(result.is_ok(), available);
    }
}
