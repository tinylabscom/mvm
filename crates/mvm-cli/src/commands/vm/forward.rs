//! `mvmctl forward` — forward a port from a running microVM to localhost.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;

use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::config;
use mvm_runtime::vm::{lima, microvm};

use super::Cli;
use super::shared::{
    CHILD_PIDS, clap_port_spec, clap_vm_name, parse_port_spec, resolve_running_vm,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Port mapping(s): GUEST_PORT or LOCAL_PORT:GUEST_PORT
    #[arg(short, long, value_name = "PORT", value_parser = clap_port_spec)]
    pub port: Vec<String>,
    /// Port mapping(s) (positional, same as --port)
    #[arg(trailing_var_arg = true, hide = true)]
    pub ports: Vec<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let mut all_ports = args.port;
    all_ports.extend(args.ports);
    forward_ports(&args.name, &all_ports)
}

/// Forward a port from a running microVM to localhost.
///
/// On macOS this tunnels through Lima's SSH connection; on native Linux
/// it spawns a local socat proxy.
///
/// Each `port_spec` is either `GUEST_PORT` (binds to same local port) or
/// `LOCAL_PORT:GUEST_PORT`.  Multiple ports are forwarded concurrently —
/// background children handle all but the last, and Ctrl-C kills the group.
pub(super) fn forward_ports(name: &str, port_specs: &[String]) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    // Verify the VM is actually running.
    let _abs_dir = resolve_running_vm(name)?;

    // Read the VM's guest IP from run-info.json.
    let info = microvm::read_vm_run_info(name)?;

    // Use CLI port specs if provided, otherwise fall back to persisted ports.
    let parsed: Vec<(u16, u16)> = if port_specs.is_empty() {
        if info.ports.is_empty() {
            anyhow::bail!(
                "VM '{}' has no port mappings configured.\n\
                 Specify ports: mvmctl forward {} <PORT>...\n\
                 Or declare ports in mvm.toml.",
                name,
                name,
            );
        }
        ui::info("Using port mappings from VM config.");
        info.ports.iter().map(|p| (p.host, p.guest)).collect()
    } else {
        port_specs
            .iter()
            .map(|s| parse_port_spec(s))
            .collect::<Result<_>>()?
    };
    let guest_ip = info
        .guest_ip
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "VM '{}' has no guest_ip in run-info. Was it started with 'mvmctl run'?",
                name,
            )
        })?;

    for &(local_port, guest_port) in &parsed {
        ui::info(&format!(
            "Forwarding localhost:{} -> {}:{} (VM '{}')",
            local_port, guest_ip, guest_port, name,
        ));
    }
    ui::info("Press Ctrl-C to stop forwarding.");

    if bootstrap::is_lima_required() {
        // macOS: SSH port-forward through Lima's SSH connection.
        // SSH -L supports multiple -L flags in a single session.
        lima::require_running()?;
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        let ssh_config = format!("{}/.lima/{}/ssh.config", home, config::VM_NAME);

        let mut cmd = std::process::Command::new("ssh");
        cmd.arg("-F").arg(&ssh_config).arg("-N"); // no remote command
        for &(local_port, guest_port) in &parsed {
            cmd.arg("-L")
                .arg(format!("{}:{}:{}", local_port, guest_ip, guest_port));
        }
        cmd.arg(format!("lima-{}", config::VM_NAME));

        let status = cmd
            .status()
            .context("Failed to start SSH port forward. Is Lima running?")?;

        if !status.success() {
            anyhow::bail!("SSH port forward exited with status {}", status);
        }
    } else {
        // Native Linux: socat proxy (microVM is directly reachable).
        // Spawn a child for each port; wait on all.
        let mut children: Vec<std::process::Child> = Vec::new();
        for &(local_port, guest_port) in &parsed {
            let child = std::process::Command::new("socat")
                .arg(format!("TCP-LISTEN:{},fork,reuseaddr", local_port))
                .arg(format!("TCP:{}:{}", guest_ip, guest_port))
                .spawn()
                .context("Failed to start socat. Install it with: sudo apt install socat")?;
            // Register PID so the signal handler can clean it up.
            if let Ok(mut pids) = CHILD_PIDS.lock() {
                pids.push(child.id());
            }
            children.push(child);
        }
        // Wait for all children to exit (Ctrl-C triggers the signal handler
        // which sends SIGTERM to each tracked child).
        for mut child in children {
            if let Err(e) = child.wait() {
                tracing::warn!("failed to wait on socat child: {e}");
            }
        }
        // Clear tracked PIDs after children exit.
        if let Ok(mut pids) = CHILD_PIDS.lock() {
            pids.clear();
        }
    }

    Ok(())
}
