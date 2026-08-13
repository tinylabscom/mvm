//! `mvmctl forward` — forward a port from a running microVM to localhost.

use std::{
    collections::BTreeMap,
    io,
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::ui;

use super::Cli;
use super::shared::{clap_port_spec, clap_vm_name, parse_port_spec, resolve_running_vm};
use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;

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
/// The host listener reaches the guest through the VM's authenticated control
/// channel and a dedicated vsock data port. Guests have no host-reachable NIC,
/// so forwarding must never depend on a legacy dev VM, guest IP, or `socat`.
///
/// Each `port_spec` is either `GUEST_PORT` (binds to same local port) or
/// `LOCAL_PORT:GUEST_PORT`.  Multiple ports are forwarded concurrently —
/// background children handle all but the last, and Ctrl-C kills the group.
pub(in crate::commands) fn forward_ports(name: &str, port_specs: &[String]) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    // Verify the VM is actually running.
    let _abs_dir = resolve_running_vm(name)?;

    // Use CLI port specs if provided, otherwise fall back to persisted ports.
    let parsed: Vec<(u16, u16)> = if port_specs.is_empty() {
        let spec = mvm_runtime::machine::persist::load_machine_spec(name)?;
        if spec.ports.is_empty() {
            anyhow::bail!(
                "VM '{}' has no port mappings configured.\n\
                 Specify ports: mvmctl forward {} <PORT>...\n\
                 Or declare ports in mvm.toml.",
                name,
                name,
            );
        }
        ui::info("Using port mappings from VM config.");
        spec.ports
            .iter()
            .map(|port| parse_port_spec(port))
            .collect::<Result<_>>()?
    } else {
        port_specs
            .iter()
            .map(|s| parse_port_spec(s))
            .collect::<Result<_>>()?
    };
    let mut listeners = Vec::with_capacity(parsed.len());
    let mut guest_channels = BTreeMap::new();
    for &(local_port, guest_port) in &parsed {
        let vsock_port = if let Some(port) = guest_channels.get(&guest_port) {
            *port
        } else {
            let mut agent = mvm_runtime::vsock_transport::for_vm(name)?
                .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
                .with_context(|| format!("connect to guest agent for port {guest_port}"))?;
            let port = mvm_agentd::vsock::start_port_forward_on(&mut agent, guest_port)
                .with_context(|| format!("request guest port forward for TCP {guest_port}"))?;
            wait_for_forward_channel(name, port)?;
            guest_channels.insert(guest_port, port);
            port
        };
        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .with_context(|| format!("bind forwarding listener 127.0.0.1:{local_port}"))?;
        ui::info(&format!(
            "Forwarding localhost:{} -> vsock:{} -> tcp://localhost:{} (VM '{}')",
            local_port, vsock_port, guest_port, name,
        ));
        listeners.push((listener, vsock_port));
    }
    ui::info("Press Ctrl-C to stop forwarding.");

    let mut workers = Vec::with_capacity(listeners.len());
    for (listener, vsock_port) in listeners {
        let name = name.to_string();
        workers.push(thread::spawn(move || {
            serve_listener(&name, listener, vsock_port)
        }));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("port-forward listener thread panicked"))??;
    }

    Ok(())
}

fn wait_for_forward_channel(name: &str, vsock_port: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if mvm_runtime::vsock_transport::for_vm(name)
            .and_then(|transport| transport.connect(vsock_port))
            .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "guest forward channel vsock:{vsock_port} was not ready within 5 seconds"
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn serve_listener(name: &str, listener: TcpListener, vsock_port: u32) -> Result<()> {
    for incoming in listener.incoming() {
        let tcp = incoming.context("accept forwarded TCP connection")?;
        let name = name.to_string();
        thread::spawn(move || {
            let result = mvm_runtime::vsock_transport::for_vm(&name)
                .and_then(|transport| transport.connect(vsock_port))
                .and_then(|guest| proxy(tcp, guest).map_err(Into::into));
            if let Err(error) = result {
                tracing::warn!(vm = %name, vsock_port, %error, "forwarded connection failed");
            }
        });
    }
    Ok(())
}

fn proxy(mut tcp: TcpStream, mut guest: UnixStream) -> io::Result<()> {
    let mut tcp_reader = tcp.try_clone()?;
    let mut guest_writer = guest.try_clone()?;
    let upload = thread::spawn(move || {
        let result = io::copy(&mut tcp_reader, &mut guest_writer);
        let _ = guest_writer.shutdown(Shutdown::Write);
        result
    });
    let download = io::copy(&mut guest, &mut tcp);
    let _ = tcp.shutdown(Shutdown::Write);
    let upload = upload
        .join()
        .map_err(|_| io::Error::other("forward upload thread panicked"))?;
    upload?;
    download?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn forwarding_vsock_port_is_stable() {
        assert_eq!(mvm_agentd::vsock::PORT_FORWARD_BASE + 8080, 18080);
    }
}
