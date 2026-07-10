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
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_hostd::network_tunnel::{
    HostTunPacketPath, HostTunnelWorker, TunnelAuditEvent, TunnelAuditSink, TunnelPacketPolicy,
    TunnelWorkerConfig,
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

trait ReadWrite: Read + Write {}

impl<T> ReadWrite for T where T: Read + Write {}

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
