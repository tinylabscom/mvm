//! Internal `mvmctl __ssh-agent-proxy` subcommand.
//!
//! Hidden helper spawned detached by `machine start` for dev-tier SSH-agent
//! forwarding. It accepts exactly one host capability: the Unix socket named by
//! `SSH_AUTH_SOCK`. It never reads, copies, or mounts key files or `~/.ssh`.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use std::io::BufRead;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const SSH_AGENT_PROXY_PID_FILE: &str = "ssh-agent-proxy.pid";
pub(crate) const SSH_AGENT_GUEST_SOCKET: &str = "/run/mvm/ssh-agent.sock";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Host SSH agent Unix socket. Usually `$SSH_AUTH_SOCK`.
    #[arg(long)]
    host_sock: PathBuf,
    /// Host-side Unix socket that the VMM's guest→host vsock proxy dials.
    #[arg(long, conflicts_with = "listen_vsock_port")]
    listen_uds: Option<PathBuf>,
    /// Host AF_VSOCK port for backends that expose guest→host directly.
    #[arg(long, conflicts_with = "listen_uds")]
    listen_vsock_port: Option<u32>,
}

#[derive(Debug, Clone)]
pub(crate) enum SshAgentProxyListen {
    Uds(PathBuf),
    Vsock(u32),
}

pub(crate) fn proxy_pid_path(vm_name: &str) -> PathBuf {
    mvm_core::config::vm_state_dir(vm_name).join(SSH_AGENT_PROXY_PID_FILE)
}

pub(crate) fn validate_host_ssh_auth_sock(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading SSH_AUTH_SOCK metadata {}", path.display()))?;
    if !meta.file_type().is_socket() {
        bail!("SSH_AUTH_SOCK {} is not a Unix socket", path.display());
    }
    Ok(())
}

pub(crate) fn ssh_auth_sock_from_env() -> Result<PathBuf> {
    let value = std::env::var_os("SSH_AUTH_SOCK").ok_or_else(|| {
        anyhow::anyhow!("ssh-agent forwarding requested but SSH_AUTH_SOCK is unset")
    })?;
    let path = PathBuf::from(value);
    validate_host_ssh_auth_sock(&path)?;
    Ok(path)
}

pub(crate) fn spawn_proxy(
    vm_name: &str,
    host_sock: &Path,
    listen: SshAgentProxyListen,
) -> Result<()> {
    validate_host_ssh_auth_sock(host_sock)?;
    reap_proxy(vm_name);
    if let SshAgentProxyListen::Uds(path) = &listen {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let _ = std::fs::remove_file(path);
    }

    let exe = std::env::current_exe().context("resolving current executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg("__ssh-agent-proxy")
        .arg("--host-sock")
        .arg(host_sock)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    match &listen {
        SshAgentProxyListen::Uds(path) => {
            cmd.arg("--listen-uds").arg(path);
        }
        SshAgentProxyListen::Vsock(port) => {
            cmd.arg("--listen-vsock-port").arg(port.to_string());
        }
    }
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("spawning ssh-agent proxy")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("ssh-agent proxy stdout was not piped"))?;
    let mut reader = std::io::BufReader::new(stdout);
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                if let Some(status) = child.try_wait().context("polling ssh-agent proxy")? {
                    bail!("ssh-agent proxy exited before ready (status: {status})");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(_) if line.trim() == "READY" => {
                std::fs::write(proxy_pid_path(vm_name), child.id().to_string())
                    .context("writing ssh-agent proxy pid file")?;
                return Ok(());
            }
            Ok(_) => bail!("unexpected ssh-agent proxy readiness line: {}", line.trim()),
            Err(err) => return Err(err.into()),
        }
    }
    let _ = child.kill();
    bail!("ssh-agent proxy did not become ready within {READY_TIMEOUT:?}");
}

pub(crate) fn reap_proxy(vm_name: &str) {
    let pid_path = proxy_pid_path(vm_name);
    let Ok(pid_text) = std::fs::read_to_string(&pid_path) else {
        cleanup_proxy_files(vm_name);
        return;
    };
    if let Ok(pid) = pid_text.trim().parse::<libc::pid_t>() {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if !alive {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if alive {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    let _ = std::fs::remove_file(pid_path);
    cleanup_proxy_files(vm_name);
}

fn cleanup_proxy_files(vm_name: &str) {
    let _ = std::fs::remove_file(mvm_core::config::vm_vsock_port_socket(
        vm_name,
        mvm_guest::vsock::SSH_AGENT_PORT,
    ));
    let _ = std::fs::remove_file(mvm_core::config::vm_vz_vsock_port_socket(
        vm_name,
        mvm_guest::vsock::SSH_AGENT_PORT,
    ));
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    validate_host_ssh_auth_sock(&args.host_sock)?;
    match (&args.listen_uds, args.listen_vsock_port) {
        (Some(path), None) => {
            crate::commands::shared::run_ssh_agent_proxy_uds(path, &args.host_sock)
        }
        (None, Some(port)) => {
            crate::commands::shared::run_ssh_agent_proxy_vsock(port, &args.host_sock)
        }
        _ => bail!("exactly one of --listen-uds or --listen-vsock-port is required"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn validates_host_sock_is_socket() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-socket");
        std::fs::write(&file, b"x").unwrap();
        let err = validate_host_ssh_auth_sock(&file).expect_err("plain file rejected");
        assert!(err.to_string().contains("not a Unix socket"));
    }

    #[test]
    fn proxy_pid_path_honors_mvm_data_dir() {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.set("MVM_DATA_DIR", dir.path());
        assert_eq!(
            proxy_pid_path("web"),
            dir.path()
                .join("vms")
                .join("web")
                .join(SSH_AGENT_PROXY_PID_FILE)
        );
    }
}
