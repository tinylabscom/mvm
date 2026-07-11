//! `mvm-network-tunnel-worker` — per-VM host-owned packet-tunnel worker.
//!
//! The backend hands this process one JSON config on stdin, then the process:
//! - binds the per-VM host UDS the guest reaches over virtio-vsock,
//! - accepts exactly one stream,
//! - validates the guest's tunnel identity against host-owned session state,
//! - sends the host-authored `mvm-net0` config,
//! - enforces the default-deny packet policy and audit trail.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use mvm_hostd::network_tunnel::HostTunPacketPath;
use mvm_hostd::network_tunnel::{
    HostTunnelWorker, TunnelAuditEvent, TunnelAuditSink, TunnelPacketPolicy, TunnelWorkerConfig,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubprocessConfig {
    listener: ListenerConfig,
    audit_jsonl_path: PathBuf,
    worker: TunnelWorkerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ListenerConfig {
    Uds { path: PathBuf },
    Vsock { port: u32 },
}

// The forwarding loops poll the session fd alongside the TUN fd, so the stream
// must expose its raw fd. Both concrete streams (`UnixStream` and the vsock
// `File`) are `AsRawFd`; thread that through the boxed trait object.
trait ReadWrite: Read + Write + AsRawFd {}

impl<T> ReadWrite for T where T: Read + Write + AsRawFd {}

impl AsRawFd for Box<dyn ReadWrite> {
    fn as_raw_fd(&self) -> RawFd {
        (**self).as_raw_fd()
    }
}

struct JsonlAuditSink {
    writer: BufWriter<File>,
}

impl JsonlAuditSink {
    fn open(path: &PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create tunnel audit dir {}", parent.display()))?;
        }
        let file = File::create(path)
            .with_context(|| format!("create tunnel audit log {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }
}

impl TunnelAuditSink for JsonlAuditSink {
    type Error = std::io::Error;

    fn record(&mut self, event: TunnelAuditEvent) -> std::result::Result<(), Self::Error> {
        serde_json::to_writer(&mut self.writer, &event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

fn read_config() -> Result<SubprocessConfig> {
    let mut raw = Vec::with_capacity(4096);
    std::io::stdin()
        .lock()
        .read_to_end(&mut raw)
        .context("mvm-network-tunnel-worker stdin read failed")?;
    let config: SubprocessConfig =
        serde_json::from_slice(&raw).context("parse tunnel worker config")?;
    config.worker.validate()?;
    Ok(config)
}

enum BoundListener {
    Uds {
        path: PathBuf,
        listener: UnixListener,
    },
    #[cfg(target_os = "linux")]
    Vsock(mvm_hostd::supervisor::substitution_proxy::vsock::VsockListener),
}

impl BoundListener {
    fn accept(self) -> Result<(Box<dyn ReadWrite>, Option<PathBuf>)> {
        match self {
            Self::Uds { path, listener } => {
                let (stream, _addr) = listener
                    .accept()
                    .with_context(|| format!("accept tunnel worker UDS {}", path.display()))?;
                Ok((Box::new(stream), Some(path)))
            }
            #[cfg(target_os = "linux")]
            Self::Vsock(listener) => {
                let conn_fd =
                    mvm_hostd::supervisor::substitution_proxy::vsock::accept(listener.raw_fd())
                        .context("accept tunnel worker vsock")?;
                let stream = unsafe { File::from_raw_fd(conn_fd) };
                Ok((Box::new(stream), None))
            }
        }
    }
}

fn bind_listener(config: &ListenerConfig) -> Result<BoundListener> {
    match config {
        ListenerConfig::Uds { path } => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create tunnel socket dir {}", parent.display()))?;
            }
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path)
                .with_context(|| format!("bind tunnel worker UDS {}", path.display()))?;
            Ok(BoundListener::Uds {
                path: path.clone(),
                listener,
            })
        }
        ListenerConfig::Vsock { port } => {
            #[cfg(target_os = "linux")]
            {
                let listener =
                    mvm_hostd::supervisor::substitution_proxy::vsock::VsockListener::bind(*port)
                        .with_context(|| format!("bind tunnel worker vsock port {port}"))?;
                Ok(BoundListener::Vsock(listener))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = port;
                anyhow::bail!("vsock network tunnel worker transport is linux-only");
            }
        }
    }
}

fn main() -> Result<()> {
    mvm_hostd::parent_death::exit_when_orphaned();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let config = read_config()?;
    let listener = bind_listener(&config.listener)?;
    let audit = JsonlAuditSink::open(&config.audit_jsonl_path)?;
    let (stream, cleanup_uds_path) = listener.accept()?;
    let packet_policy = config.worker.packet_policy.clone();
    let mut worker = HostTunnelWorker::new(stream, audit, config.worker)
        .context("create host network tunnel worker")?;
    worker
        .bootstrap(1, 2, 3)
        .context("bootstrap host network tunnel worker")?;
    match packet_policy {
        TunnelPacketPolicy::DropAll => {
            worker
                .run_until_shutdown()
                .context("run host network tunnel worker")?;
        }
        TunnelPacketPolicy::L3Forward {
            interface_name: Some(interface_name),
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                let device = mvm_hostd::host_tun::HostTunDevice::open_named(&interface_name)
                    .with_context(|| {
                        format!("open host tunnel device for interface {interface_name}")
                    })?;
                mvm_hostd::host_tun::setup_host_tun_egress(&interface_name).with_context(|| {
                    format!("set up host TUN egress + NAT for {interface_name}")
                })?;
                // Graceful-stop defense in depth: a caught SIGTERM/SIGINT tears
                // down NAT before exit. A hard SIGKILL is uncatchable and is
                // reaped by the backend's spawn-side sweep instead.
                mvm_hostd::host_tun::install_egress_teardown_on_stop_signal(interface_name.clone());
                let mut packet_path = HostTunPacketPath::new(device);
                let result = worker.run_blocking_l3_relay_loop(&mut packet_path, 0, 4);
                // Tear down NAT + the gateway address regardless of loop outcome.
                if let Err(err) = mvm_hostd::host_tun::teardown_host_tun_egress(&interface_name) {
                    tracing::warn!(%interface_name, error = %err, "host TUN egress teardown failed");
                }
                result.context("run host network tunnel L3 forward")?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = interface_name;
                anyhow::bail!("l3_forward host TUN egress is only supported on Linux");
            }
        }
        TunnelPacketPolicy::L3Forward {
            interface_name: None,
            ..
        } => {
            worker
                .run_until_shutdown_l3_gate()
                .context("run host network tunnel L3 gate")?;
        }
        TunnelPacketPolicy::HostTun { interface_name } => {
            #[cfg(target_os = "linux")]
            {
                let device = mvm_hostd::host_tun::HostTunDevice::open_named(&interface_name)
                    .with_context(|| {
                        format!("open host tunnel device for interface {interface_name}")
                    })?;
                let mut packet_path = HostTunPacketPath::new(device);
                worker
                    .run_blocking_tun_relay_loop(&mut packet_path, 0, 4)
                    .context("run host tunnel relay loop")?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = interface_name;
                anyhow::bail!("host_tun packet policy is only supported on Linux");
            }
        }
    }
    if let Some(path) = cleanup_uds_path {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use mvm_hostd::net_l3::L3Decision;

    /// The exact wire shape `network_tunnel_spawn` emits for an admitted
    /// allow-list: the packet policy is `l3_forward` carrying the policy + pins
    /// nested under `gate`, plus a per-VM host TUN interface name.
    fn l3_forward_worker_config_json() -> serde_json::Value {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "api.example.com",
            vec!["93.184.216.34".parse().unwrap()],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        serde_json::json!({
            "listener": { "kind": "uds", "path": "/run/mvm/tunnel.sock" },
            "audit_jsonl_path": "/run/mvm/network-tunnel.audit.jsonl",
            "worker": {
                "expected_session": {
                    "tenant_id": "tenant-a",
                    "vm_id": "vm-1",
                    "boot_id": "boot-1",
                    "session_nonce": "nonce-1",
                    "maximum_frame_size": 4096,
                    "accepted_features": { "ipv4": true, "audit_stream": true }
                },
                "network_config": {
                    "interface_name": "mvm-net0",
                    "guest_ipv4": "10.240.0.2",
                    "prefix_len": 30,
                    "gateway_ipv4": "10.240.0.1",
                    "dns_servers": ["10.240.0.1"],
                    "mtu": 1500
                },
                "initial_credit": { "flow_id": 0, "bytes": 4096, "packets": 1024 },
                "packet_policy": {
                    "kind": "l3_forward",
                    "gate": { "policy": policy, "pins": pins },
                    "interface_name": "mvmt0123456789"
                },
                "limits": { "max_packets": 1024, "max_bytes": 8388608 }
            }
        })
    }

    #[test]
    fn worker_parses_l3_forward_config_into_gate() {
        let config: SubprocessConfig =
            serde_json::from_value(l3_forward_worker_config_json()).expect("l3_forward parses");
        config.worker.validate().expect("valid worker config");

        let TunnelPacketPolicy::L3Forward {
            gate,
            interface_name,
        } = config.worker.packet_policy
        else {
            panic!("an l3_forward config must parse into a TunnelPacketPolicy::L3Forward");
        };
        assert_eq!(interface_name.as_deref(), Some("mvmt0123456789"));

        // The reconstructed gate admits the pinned destination and drops an
        // unpinned one — the admission decision survives the wire round-trip.
        assert_eq!(
            gate.decide("93.184.216.34".parse().unwrap(), 6, Some(443)),
            L3Decision::Allow
        );
        assert!(matches!(
            gate.decide("203.0.113.7".parse().unwrap(), 6, Some(443)),
            L3Decision::Drop(_)
        ));
    }
}
