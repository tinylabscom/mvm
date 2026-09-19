//! Minimal virtio-vsock (virtio-mmio v2) device — the host↔guest transport.
//!
//! Enough of the device for a guest to detect `virtio_vsock`, get `AF_VSOCK`,
//! connect to the host (CID 2), and exchange stream bytes. The host acts as a
//! listener that accepts any connection and captures what the guest sends (the
//! shape `mvm-init` lifecycle markers + the agent will use). Three queues:
//! rx (host→guest), tx (guest→host), event. Requests are serviced synchronously
//! in the guest's `QueueNotify` MMIO exit and completed by the backend raising
//! the device's SPI line.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::hvf_handoff::HvfHandoffRequest;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::device_state::{
    DeviceKind, DeviceStateError, SnapshotDeviceState, StateReader, StateWriter,
};
use super::vsock_handlers::{
    HostPortCursor, VsockHandlerContext, VsockHandlerRegistry, VsockLifecycleState,
};
#[cfg(test)]
use super::vsock_transport::{
    GUEST_CID, HOST_BUF_ALLOC, HOST_CID, OP_SHUTDOWN, TYPE_STREAM, VIRTIO_ID_VSOCK, VIRTIO_MAGIC,
    VIRTIO_VERSION,
};
use super::vsock_transport::{
    NUM_QUEUES, OP_CREDIT_UPDATE, OP_REQUEST, OP_RESPONSE, OP_RST, OP_RW, Queue, RegisterWrite,
    VsockHdr, VsockTransportCore,
};

/// A guest interrupt line the host-I/O thread can assert on its own — the seam
/// that lets host→guest vsock delivery raise the device's IRQ **off** the vCPU
/// exit path (the fix for the poll-starvation reachability bug). The backend
/// injects an impl wrapping its interrupt primitive (HVF's process-global GIC SPI
/// today). `Send + Sync` because the I/O thread holds it.
pub trait IrqLine: Send + Sync {
    /// Assert the device's SPI to the guest (level-high; the guest acks via
    /// `INTERRUPT_ACK`). Called after the I/O thread delivers an rx packet.
    fn signal(&self, spi: u32);
}

/// Fresh host-owned paths supplied when a restored child reconnects its vsock
/// channels. These bindings are deliberately external to snapshot bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VsockHostBindings {
    /// Host agent RPC listener path.
    pub agent_socket: Option<PathBuf>,
    /// Host egress endpoint path.
    pub network_endpoint: Option<PathBuf>,
    /// Host broker endpoint path.
    pub broker_endpoint: Option<PathBuf>,
    /// Host view-only display frame sink path.
    pub display_endpoint: Option<PathBuf>,
    /// Additional host-dial listeners (telemetry and admitted console ports).
    pub console_sockets: Vec<(u32, PathBuf)>,
}

#[derive(Clone, Default)]
struct VsockHostRuntimeConfig {
    bindings: VsockHostBindings,
    agent_activity: Option<Arc<std::sync::atomic::AtomicUsize>>,
    substitution_activity: Option<Arc<std::sync::atomic::AtomicUsize>>,
    broker_activity: Option<Arc<std::sync::atomic::AtomicUsize>>,
    display_activity: Option<Arc<std::sync::atomic::AtomicUsize>>,
    host_dial_activity: Option<Arc<std::sync::atomic::AtomicUsize>>,
    workload_exit_stop: Option<&'static AtomicBool>,
    trusted_builder_egress: bool,
}

impl VsockHostBindings {
    fn paths(&self) -> Vec<&Path> {
        self.agent_socket
            .iter()
            .map(PathBuf::as_path)
            .chain(self.network_endpoint.iter().map(PathBuf::as_path))
            .chain(self.broker_endpoint.iter().map(PathBuf::as_path))
            .chain(self.display_endpoint.iter().map(PathBuf::as_path))
            .chain(self.console_sockets.iter().map(|(_, path)| path.as_path()))
            .collect()
    }
}

const HANDOFF_AGENT: u8 = 1 << 0;
const HANDOFF_EGRESS: u8 = 1 << 1;
const HANDOFF_BROKER: u8 = 1 << 2;
const HANDOFF_CONSOLE: u8 = 1 << 3;

fn valid_handoff_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
}

fn canonical_child_bindings(
    name: &str,
    state_dir: &Path,
    mask: u8,
) -> std::io::Result<VsockHostBindings> {
    let agent_socket =
        (mask & HANDOFF_AGENT != 0).then(|| mvm_core::config::vm_hvf_agent_socket_at(state_dir));
    let network_endpoint =
        (mask & HANDOFF_EGRESS != 0).then(|| mvm_core::config::vm_network_endpoint_socket(name));
    let broker_path =
        mvm_core::config::vm_vsock_port_socket_at(state_dir, mvm_agentd::vsock::BROKER_PORT);
    let broker_endpoint = (mask & HANDOFF_BROKER != 0).then_some(broker_path);
    let display_path =
        mvm_core::config::vm_vsock_port_socket_at(state_dir, mvm_agentd::vsock::DISPLAY_PORT);
    let display_endpoint =
        (mask & crate::hvf_handoff::HANDOFF_DISPLAY != 0).then_some(display_path);
    let mut console_sockets = if mask & HANDOFF_CONSOLE != 0 {
        mvm_agentd::vsock::dev_console_data_ports()
            .map(|port| {
                (
                    port,
                    mvm_core::config::vm_hvf_vsock_port_socket_at(state_dir, port),
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    if mask & crate::hvf_handoff::HANDOFF_TELEMETRY != 0 {
        let port = mvm_core::protocol::telemetry::TELEMETRY_PORT;
        console_sockets.push((
            port,
            mvm_core::config::vm_hvf_vsock_port_socket_at(state_dir, port),
        ));
    }
    Ok(VsockHostBindings {
        agent_socket,
        network_endpoint,
        broker_endpoint,
        display_endpoint,
        console_sockets,
    })
}

fn validate_handoff_endpoint(path: &Path, root: &Path, socket_dir: &Path) -> std::io::Result<()> {
    let socket_dir = std::fs::canonicalize(socket_dir)?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "endpoint has no parent")
    })?;
    let parent = std::fs::canonicalize(parent)?;
    if !parent.starts_with(root) && !parent.starts_with(&socket_dir) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "handoff endpoint is outside the trusted VM root",
        ));
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff endpoint is a directory",
            ));
        }
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(path)?;
            let target = if target.is_absolute() {
                target
            } else {
                parent.join(target)
            };
            let target = std::fs::canonicalize(target)?;
            if !target.starts_with(root) && !target.starts_with(&socket_dir) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "handoff endpoint symlink escapes the trusted VM root",
                ));
            }
        } else if !metadata.file_type().is_socket() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff endpoint is not an owned socket",
            ));
        }
    }
    Ok(())
}

fn handoff_debug(message: &str) {
    if let Some(path) = std::env::var_os("MVM_HVF_AGENT_DEBUG")
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(file, "[vsock] {message}");
    }
}

const R_CONFIG: u64 = 0x100; // guest_cid (u64) at +0
const MMIO_LEN: u64 = 0x200;

/// The lockable inner state of the virtio-vsock device. Shared (behind `Mutex`)
/// between the vCPU thread (MMIO dispatch) and the host-I/O thread
/// ([`super::vsock_io`]); every field is touched only while the lock is held, so
/// guest RAM and the virtqueues are never accessed concurrently.
pub(super) struct VsockShared {
    transport: VsockTransportCore,
    lifecycle: VsockLifecycleState,
    handlers: VsockHandlerRegistry,
}

impl VsockShared {
    /// # Safety
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`.
    unsafe fn new(irq: u32, ram: *mut u8, ram_base: u64, ram_size: usize) -> Self {
        let _ = irq;
        Self {
            // SAFETY: forwarded from this fn's contract.
            transport: unsafe { VsockTransportCore::new(ram, ram_base, ram_size) },
            lifecycle: VsockLifecycleState::new(),
            handlers: VsockHandlerRegistry::new(),
        }
    }

    pub fn set_agent_socket(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        self.handlers.set_agent_socket(path)
    }

    pub fn set_agent_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.handlers.set_agent_activity(counter);
    }

    pub fn set_network_endpoint(&mut self, path: &std::path::Path) {
        self.handlers.set_network_endpoint(path);
    }

    pub fn set_trusted_builder_egress(&mut self) {
        self.handlers.set_trusted_builder_egress();
    }

    pub fn set_substitution_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.handlers.set_substitution_activity(counter);
    }

    pub fn set_broker_endpoint(&mut self, path: &std::path::Path) {
        self.handlers.set_broker_endpoint(path);
    }

    pub fn set_broker_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.handlers.set_broker_activity(counter);
    }

    pub fn set_display_endpoint(&mut self, path: &std::path::Path) {
        self.handlers.set_display_endpoint(path);
    }

    pub fn set_display_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.handlers.set_display_activity(counter);
    }

    pub fn capture_workload_exit(&mut self, stop: &'static std::sync::atomic::AtomicBool) {
        self.lifecycle.exit_stop = Some(self.handlers.capture_workload_exit(stop));
    }

    pub fn set_host_dial_sockets<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a std::path::Path)>,
    ) -> std::io::Result<()> {
        self.handlers.set_host_dial_sockets(ports)
    }

    /// Exempt these guest ports from idle eviction in **both** layers that can
    /// reclaim a quiet stream: the host-dial bridge, which closes the host
    /// socket, and the transport's credit table, which sends the guest an
    /// `OP_RST`. Fixing only one leaves the other to sever the connection.
    pub fn set_long_lived_host_dial_ports(&mut self, ports: impl IntoIterator<Item = u32>) {
        let ports: Vec<u32> = ports.into_iter().collect();
        self.handlers
            .set_long_lived_host_dial_ports(ports.iter().copied());
        self.transport.set_long_lived_ports(ports);
    }

    pub fn set_host_dial_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.handlers.set_host_dial_activity(counter);
    }

    pub fn read(&self, offset: u64) -> u64 {
        self.transport.read(offset, R_CONFIG)
    }

    pub fn write(&mut self, offset: u64, value: u64) -> bool {
        match self.transport.write_register(offset, value) {
            RegisterWrite::None => false,
            RegisterWrite::Notify(queue) => self.on_notify(queue),
        }
    }

    fn on_notify(&mut self, queue: u32) -> bool {
        if queue == 1 {
            let packets = self.transport.take_tx_packets();
            for (hdr, payload) in packets {
                self.handle_packet(hdr, &payload);
            }
        }
        let flushed = self.transport.flush_rx();
        let drained = self.transport.interrupt_status & 1 != 0;
        drained || flushed
    }

    fn handle_packet(&mut self, hdr: VsockHdr, payload: &[u8]) {
        if !self.transport.record_tx_credit(&hdr) {
            let mut ctx = VsockHandlerContext::new(&mut self.transport, &mut self.lifecycle);
            ctx.queue_reply(&hdr, OP_RST, &[]);
            return;
        }
        let mut ctx = VsockHandlerContext::new(&mut self.transport, &mut self.lifecycle);
        if self.handlers.dispatch_packet(&mut ctx, hdr, payload) {
            return;
        }

        match hdr.op {
            OP_REQUEST => ctx.queue_reply(&hdr, OP_RESPONSE, &[]),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                ctx.record_received(&payload[..n]);
                if ctx.try_add_recv(&hdr, n as u32) {
                    ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
                } else {
                    ctx.queue_reply(&hdr, OP_RST, &[]);
                }
            }
            super::vsock_transport::OP_CREDIT_REQUEST => {
                ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[])
            }
            super::vsock_transport::OP_SHUTDOWN => {
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }

    pub(super) fn service_host_io(&mut self) -> bool {
        let mut ctx = VsockHandlerContext::new(&mut self.transport, &mut self.lifecycle);
        self.handlers.service_host_io(&mut ctx)
    }

    pub(super) fn cancel(&mut self) {
        self.handlers.cancel();
        self.transport.recv_cnt.clear();
        self.transport.clear_tx_credit();
        self.transport.pending_rx.clear();
    }

    pub(super) fn poll_fds(&self) -> Vec<std::os::fd::RawFd> {
        self.handlers.poll_fds()
    }
}

/// The virtio-vsock device the run loop drives (a [`RunDevice`](super::run::RunDevice)).
///
/// A thin handle over the lockable [`VsockShared`] plus the dedicated host-I/O
/// thread. The vCPU thread reaches guest→host work through the MMIO delegators
/// ([`Self::read`]/[`Self::write`]); the host→guest direction (accepting the agent
/// socket, draining sockets, framing rx packets, raising the IRQ) runs on the I/O
/// thread so it is never starved by the vCPU's MMIO cadence. `base`/`irq` are
/// immutable and kept out of the lock so address matching needs no lock.
pub struct VirtioVsock {
    base: u64,
    irq: u32,
    shared: Arc<Mutex<VsockShared>>,
    io: Option<super::vsock_io::IoHandle>,
    irq_line: Option<Arc<dyn IrqLine>>,
    host_runtime: VsockHostRuntimeConfig,
    handoff_listener: Option<UnixListener>,
    handoff_root: Option<PathBuf>,
    handoff_verify_key: Option<VerifyingKey>,
    handoff_stop: Option<&'static AtomicBool>,
    handoff_used: bool,
    /// Whether host I/O is parked for a pause. The device is shared by every
    /// vCPU of an SMP machine and each one that parks calls the snapshot hooks,
    /// so this is what makes the transition happen once per pause rather than
    /// once per vCPU.
    snapshot_parked: bool,
}

impl VirtioVsock {
    /// # Safety
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`,
    /// valid until the device (and its joined I/O thread) are dropped.
    pub unsafe fn new(base: u64, irq: u32, ram: *mut u8, ram_base: u64, ram_size: usize) -> Self {
        // SAFETY: forwarded from this fn's contract.
        let shared = unsafe { VsockShared::new(irq, ram, ram_base, ram_size) };
        Self {
            base,
            irq,
            shared: Arc::new(Mutex::new(shared)),
            io: None,
            irq_line: None,
            host_runtime: VsockHostRuntimeConfig::default(),
            handoff_listener: None,
            handoff_root: None,
            handoff_verify_key: None,
            handoff_stop: None,
            handoff_used: false,
            snapshot_parked: false,
        }
    }

    fn lock(&self) -> MutexGuard<'_, VsockShared> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify_io(&self) {
        if let Some(io) = &self.io {
            io.wake();
        }
    }

    pub fn set_agent_socket(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let result = self.lock().set_agent_socket(path);
        if result.is_ok() {
            self.host_runtime.bindings.agent_socket = Some(path.to_path_buf());
        }
        self.notify_io();
        result
    }

    pub fn set_agent_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_agent_activity(Arc::clone(&counter));
        self.host_runtime.agent_activity = Some(counter);
        self.notify_io();
    }

    pub fn set_network_endpoint(&mut self, path: &std::path::Path) {
        self.lock().set_network_endpoint(path);
        self.host_runtime.bindings.network_endpoint = Some(path.to_path_buf());
        self.notify_io();
    }

    pub fn set_trusted_builder_egress(&mut self) {
        self.lock().set_trusted_builder_egress();
        self.host_runtime.trusted_builder_egress = true;
        self.notify_io();
    }

    pub fn set_substitution_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_substitution_activity(Arc::clone(&counter));
        self.host_runtime.substitution_activity = Some(counter);
        self.notify_io();
    }

    pub fn set_broker_endpoint(&mut self, path: &std::path::Path) {
        self.lock().set_broker_endpoint(path);
        self.host_runtime.bindings.broker_endpoint = Some(path.to_path_buf());
        self.notify_io();
    }

    pub fn set_broker_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_broker_activity(Arc::clone(&counter));
        self.host_runtime.broker_activity = Some(counter);
        self.notify_io();
    }

    pub fn set_display_endpoint(&mut self, path: &std::path::Path) {
        self.lock().set_display_endpoint(path);
        self.host_runtime.bindings.display_endpoint = Some(path.to_path_buf());
        self.notify_io();
    }

    pub fn set_display_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_display_activity(Arc::clone(&counter));
        self.host_runtime.display_activity = Some(counter);
        self.notify_io();
    }

    pub fn capture_workload_exit(&mut self, stop: &'static std::sync::atomic::AtomicBool) {
        self.lock().capture_workload_exit(stop);
        self.host_runtime.workload_exit_stop = Some(stop);
        self.notify_io();
    }

    pub fn set_long_lived_host_dial_ports(&mut self, ports: impl IntoIterator<Item = u32>) {
        self.lock().set_long_lived_host_dial_ports(ports);
        self.notify_io();
    }

    pub fn set_host_dial_sockets<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a std::path::Path)>,
    ) -> std::io::Result<()> {
        let ports = ports
            .into_iter()
            .map(|(port, path)| (port, path.to_path_buf()))
            .collect::<Vec<_>>();
        let result = self
            .lock()
            .set_host_dial_sockets(ports.iter().map(|(port, path)| (*port, path.as_path())));
        if result.is_ok() {
            self.host_runtime.bindings.console_sockets = ports;
        }
        self.notify_io();
        result
    }

    pub fn set_host_dial_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_host_dial_activity(Arc::clone(&counter));
        self.host_runtime.host_dial_activity = Some(counter);
        self.notify_io();
    }

    fn restore_host_runtime(&mut self, irq_line: Arc<dyn IrqLine>) -> std::io::Result<()> {
        let config = self.host_runtime.clone();
        self.lock().handlers.clear_host_bindings();
        self.host_runtime = VsockHostRuntimeConfig::default();
        self.rebind_host_channels(&config.bindings, Arc::clone(&irq_line))?;
        if config.trusted_builder_egress {
            self.set_trusted_builder_egress();
        }
        if let Some(counter) = config.agent_activity {
            self.set_agent_activity(counter);
        }
        if let Some(counter) = config.substitution_activity {
            self.set_substitution_activity(counter);
        }
        if let Some(counter) = config.broker_activity {
            self.set_broker_activity(counter);
        }
        if let Some(counter) = config.display_activity {
            self.set_display_activity(counter);
        }
        if let Some(counter) = config.host_dial_activity {
            self.set_host_dial_activity(counter);
        }
        if let Some(stop) = config.workload_exit_stop {
            self.capture_workload_exit(stop);
        }
        Ok(())
    }

    /// Rebind host channels after a child restores guest state.
    ///
    /// Existing listeners and I/O are stopped before the caller-supplied paths
    /// are bound. The paths are never read from snapshot bytes; the caller must
    /// derive and authorize them for the child identity first.
    pub fn rebind_host_channels(
        &mut self,
        bindings: &VsockHostBindings,
        irq_line: Arc<dyn IrqLine>,
    ) -> std::io::Result<()> {
        handoff_debug("rebind begin");
        self.shutdown();
        self.lock().handlers.clear_host_bindings();
        let result = (|| {
            if let Some(path) = &bindings.agent_socket {
                self.set_agent_socket(path)?;
            }
            if let Some(path) = &bindings.network_endpoint {
                self.set_network_endpoint(path);
            }
            if let Some(path) = &bindings.broker_endpoint {
                self.set_broker_endpoint(path);
            }
            if let Some(path) = &bindings.display_endpoint {
                self.set_display_endpoint(path);
            }
            if !bindings.console_sockets.is_empty() {
                self.set_host_dial_sockets(
                    bindings
                        .console_sockets
                        .iter()
                        .map(|(port, path)| (*port, path.as_path())),
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            handoff_debug("rebind bind failed");
            self.shutdown();
            return result;
        }
        handoff_debug("rebind bindings installed");
        self.start_io(irq_line);
        handoff_debug("rebind io started");
        Ok(())
    }

    /// Bind the fixed, supervisor-owned control socket used to authorize one
    /// live standby handoff. The request contains only a child identity and is
    /// authenticated by the host key pinned in the supervisor config.
    pub fn set_handoff_control(
        &mut self,
        socket: Option<&Path>,
        root: Option<&Path>,
        verify_key: Option<&str>,
        stop: &'static AtomicBool,
    ) -> std::io::Result<()> {
        let (Some(socket), Some(root), Some(verify_key)) = (socket, root, verify_key) else {
            return Ok(());
        };
        let root = std::fs::canonicalize(root)?;
        let parent = socket.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "handoff socket has no parent",
            )
        })?;
        let parent = std::fs::canonicalize(parent)?;
        if !parent.starts_with(&root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff socket is outside the trusted VM root",
            ));
        }
        if let Ok(metadata) = std::fs::symlink_metadata(socket) {
            if metadata.file_type().is_dir()
                || metadata.file_type().is_symlink()
                || !metadata.file_type().is_socket()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "handoff socket path is not an owned socket",
                ));
            }
            std::fs::remove_file(socket)?;
        }
        let listener = UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let mut permissions = std::fs::metadata(socket)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
        }
        std::fs::set_permissions(socket, permissions)?;
        let key_bytes = hex::decode(verify_key).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handoff public key",
            )
        })?;
        let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handoff public key length",
            )
        })?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid handoff public key",
            )
        })?;
        self.handoff_listener = Some(listener);
        self.handoff_root = Some(root);
        self.handoff_verify_key = Some(verifying_key);
        self.handoff_stop = Some(stop);
        Ok(())
    }

    pub fn start_io(&mut self, irq_line: Arc<dyn IrqLine>) {
        handoff_debug("start_io");
        if let Some(io) = self.io.take() {
            io.stop();
        }
        self.irq_line = Some(Arc::clone(&irq_line));
        self.io = Some(super::vsock_io::spawn(
            Arc::clone(&self.shared),
            irq_line,
            self.irq,
        ));
    }

    pub fn shutdown(&mut self) {
        handoff_debug("shutdown");
        if let Some(io) = self.io.take() {
            io.stop();
        }
        self.lock().cancel();
    }

    /// Stop host I/O before serializing a paused parent.
    ///
    /// The manual device codec never serializes listeners or handler objects,
    /// so the parent keeps its binding configuration in memory for
    /// [`Self::resume_after_snapshot`]. A restored child starts with a newly
    /// constructed handler registry and binds fresh authorized channels.
    ///
    /// Once per pause: every vCPU that parks calls this, and only the first has
    /// anything to stop.
    pub fn prepare_snapshot(&mut self) {
        if self.snapshot_parked {
            return;
        }
        self.snapshot_parked = true;
        let queue = self.lock().transport.queues[0];
        handoff_debug(&format!(
            "prepare_snapshot before ready={} size={} pending={}",
            queue.ready,
            queue.num,
            self.lock().transport.pending_rx.len()
        ));
        self.shutdown();
        self.lock().handlers.clear_host_bindings();
        let queue = self.lock().transport.queues[0];
        handoff_debug(&format!(
            "prepare_snapshot after ready={} size={} pending={}",
            queue.ready,
            queue.num,
            self.lock().transport.pending_rx.len()
        ));
    }

    /// Restart the live parent's host-I/O owner after a snapshot pause.
    ///
    /// Once per pause, and that is load-bearing rather than tidy. Every vCPU
    /// leaving the hold calls this, but the first one to leave runs guest code
    /// straight away — so by the time a second vCPU gets here the guest agent
    /// may already be serving a host connection. Rebinding then runs
    /// `shutdown`, which cancels every live stream. That is how a warm claim's
    /// post-restore session died with `Broken pipe` on the host while the guest
    /// logged a peer that hung up mid-handshake, and only on machines with more
    /// than one vCPU, and only when the second vCPU lost the race.
    pub fn resume_after_snapshot(&mut self) {
        if !std::mem::take(&mut self.snapshot_parked) {
            return;
        }
        if let Some(irq_line) = self.irq_line.clone()
            && let Err(error) = self.restore_host_runtime(irq_line)
        {
            handoff_debug(&format!("resume after snapshot failed: {error}"));
        }
    }

    pub fn received(&self) -> Vec<u8> {
        self.lock().lifecycle.received.clone()
    }

    pub fn workload_exit_code(&self) -> Option<i32> {
        self.lock().lifecycle.workload_exit_code
    }

    #[cfg(test)]
    pub(crate) fn queued_host_packets(&self) -> usize {
        self.lock().transport.pending_rx.len()
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + MMIO_LEN
    }
    pub fn irq(&self) -> u32 {
        self.irq
    }

    pub fn read(&self, offset: u64) -> u64 {
        self.lock().read(offset)
    }

    pub fn write(&self, offset: u64, value: u64) -> bool {
        let result = self.lock().write(offset, value);
        self.notify_io();
        result
    }

    pub fn poll(&mut self) -> Option<u32> {
        let handoff = self.poll_handoff();
        if handoff || self.lock().service_host_io() {
            Some(self.irq)
        } else {
            None
        }
    }

    fn poll_handoff(&mut self) -> bool {
        if self.handoff_used {
            return false;
        }
        let Some(listener) = &self.handoff_listener else {
            return false;
        };
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return false,
            Err(error) => {
                self.fail_handoff(None, error);
                return false;
            }
        };
        let result = self.accept_handoff(&mut stream);
        match result {
            Ok(()) => {
                let _ = stream.write_all(crate::hvf_handoff::HANDOFF_ACCEPTED);
                self.handoff_used = true;
                true
            }
            Err(error) => {
                let _ = stream.write_all(&crate::hvf_handoff::refusal_line(&error.to_string()));
                self.fail_handoff(Some(&mut stream), error);
                false
            }
        }
    }

    fn accept_handoff(&mut self, stream: &mut UnixStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        let request: HvfHandoffRequest = serde_json::from_str(line.trim_end()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid handoff request")
        })?;
        if request.parent_pid != std::process::id() || !valid_handoff_name(&request.child_vm_name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff identity is not bound to this supervisor",
            ));
        }
        let signature_bytes = hex::decode(&request.signature).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid handoff signature")
        })?;
        let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid handoff signature length",
            )
        })?;
        let signature = Signature::from_bytes(&signature_bytes);
        let key = self.handoff_verify_key.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff verifier unavailable",
            )
        })?;
        key.verify(
            &HvfHandoffRequest::signing_message(
                request.parent_pid,
                &request.child_vm_name,
                request.channel_mask,
            ),
            &signature,
        )
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff signature rejected",
            )
        })?;

        let root = self.handoff_root.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "handoff root unavailable",
            )
        })?;
        let child_dir = mvm_core::config::vm_state_dir(&request.child_vm_name);
        let canonical_child_dir = std::fs::canonicalize(&child_dir)?;
        if !canonical_child_dir.starts_with(root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "child state is outside the trusted VM root",
            ));
        }
        let bindings =
            canonical_child_bindings(&request.child_vm_name, &child_dir, request.channel_mask)?;
        let socket_dir = mvm_core::config::vm_socket_dir_at(&child_dir);
        std::fs::create_dir_all(&socket_dir)?;
        for path in bindings.paths() {
            if let Err(error) = validate_handoff_endpoint(path, root, &socket_dir) {
                if let Some(debug_path) = std::env::var_os("MVM_HVF_AGENT_DEBUG")
                    && let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(debug_path)
                {
                    let _ = writeln!(
                        file,
                        "[handoff] endpoint={} root={} socket_dir={} error={error}",
                        path.display(),
                        root.display(),
                        socket_dir.display()
                    );
                }
                return Err(error);
            }
        }
        let irq_line = self.irq_line.clone().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "handoff IRQ line unavailable",
            )
        })?;
        self.rebind_host_channels(&bindings, irq_line)
    }

    fn fail_handoff(&self, _stream: Option<&mut UnixStream>, error: std::io::Error) {
        if let Some(path) = std::env::var_os("MVM_HVF_AGENT_DEBUG")
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(file, "[handoff] rejected: {error}");
        }
        if let Some(stop) = self.handoff_stop {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

impl VsockShared {
    fn reject_snapshot_if_live(&self) -> Result<(), DeviceStateError> {
        let kind = DeviceKind::VirtioVsock;
        if self.handlers.has_host_bindings() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "host_endpoints_bound",
            });
        }
        if !self.handlers.poll_fds().is_empty() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "host_io_fds",
            });
        }
        if !self.transport.recv_cnt.is_empty() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "receive_credit_sessions",
            });
        }
        if self.transport.has_tx_credit() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "transmit_credit_sessions",
            });
        }
        if !self.transport.pending_rx.is_empty() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "pending_rx_packets",
            });
        }
        if !self.lifecycle.received.is_empty() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "lifecycle_transcript",
            });
        }
        if self.lifecycle.workload_exit_code.is_some() {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "workload_exit",
            });
        }
        Ok(())
    }
}

impl SnapshotDeviceState for VirtioVsock {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::VirtioVsock
    }

    fn snapshot_state(&self) -> Result<Vec<u8>, DeviceStateError> {
        if self.io.is_some() {
            return Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "host_io_active",
            });
        }
        let mut shared = self.lock();
        shared.reject_snapshot_if_live()?;
        let cursor = shared.handlers.host_port_cursor();
        let mut writer = StateWriter::new(1);
        writer.u32(shared.transport.device_features_sel);
        writer.u32(shared.transport.status);
        writer.u32(shared.transport.queue_sel);
        writer.u32(shared.transport.interrupt_status);
        for queue in shared.transport.queues {
            write_queue_state(&mut writer, queue);
        }
        // Host port numbering is guest-visible state: the resumed guest may
        // still hold connections under ports the parent handed out, so a
        // restored device must carry on past them rather than start again.
        writer.u32(cursor.agent);
        writer.u32(cursor.host_dial);
        Ok(writer.finish())
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), DeviceStateError> {
        if self.io.is_some() {
            return Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "host_io_active",
            });
        }

        let kind = DeviceKind::VirtioVsock;
        let mut reader = StateReader::new(bytes);
        let version = reader.version(kind)?;
        if version != 1 {
            return Err(DeviceStateError::UnsupportedVersion(version));
        }
        let device_features_sel = reader.u32(kind, "device_features_sel")?;
        let status = reader.u32(kind, "status")?;
        let queue_sel = reader.u32(kind, "queue_sel")?;
        let interrupt_status = reader.u32(kind, "interrupt_status")?;
        let mut queues = [Queue::default(); NUM_QUEUES];
        for queue in &mut queues {
            queue.num = reader.u32(kind, "queue_num")?;
            queue.ready = reader.u32(kind, "queue_ready")?;
            queue.desc = reader.u64(kind, "desc")?;
            queue.avail = reader.u64(kind, "avail")?;
            queue.used = reader.u64(kind, "used")?;
            queue.last_avail = reader.u16(kind, "last_avail")?;
            queue.next_used = reader.u16(kind, "next_used")?;
        }
        let cursor = HostPortCursor {
            agent: reader.u32(kind, "agent_host_port_cursor")?,
            host_dial: reader.u32(kind, "host_dial_port_cursor")?,
        };
        reader.finish()?;

        if cursor.agent < super::agent_bridge::FIRST_HOST_PORT {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "agent_host_port_cursor",
            });
        }
        if cursor.host_dial < super::host_dial_bridge::FIRST_HOST_DIAL_PORT {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "host_dial_port_cursor",
            });
        }

        if device_features_sel > 1 {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "device_features_sel",
            });
        }
        if usize::try_from(queue_sel).map_or(true, |index| index >= NUM_QUEUES) {
            return Err(DeviceStateError::InvalidValue {
                kind,
                field: "queue_sel",
            });
        }
        for queue in &queues {
            if queue.ready > 1 {
                return Err(DeviceStateError::InvalidValue {
                    kind,
                    field: "queue_ready",
                });
            }
            if queue.num != 0 && super::validated_queue_size(queue.num).is_none() {
                return Err(DeviceStateError::InvalidValue {
                    kind,
                    field: "queue_num",
                });
            }
        }

        let mut shared = self.lock();
        shared.reject_snapshot_if_live()?;
        shared.transport.device_features_sel = device_features_sel;
        shared.transport.status = status;
        shared.transport.queue_sel = queue_sel;
        shared.transport.queues = queues;
        shared.transport.interrupt_status = interrupt_status;
        shared.handlers.continue_host_ports(cursor);
        Ok(())
    }
}

fn write_queue_state(writer: &mut StateWriter, queue: Queue) {
    writer.u32(queue.num);
    writer.u32(queue.ready);
    writer.u64(queue.desc);
    writer.u64(queue.avail);
    writer.u64(queue.used);
    writer.u16(queue.last_avail);
    writer.u16(queue.next_used);
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Fuzz-only driver over the vsock [`VsockTransportCore`].
///
/// Exposes exactly the untrusted-guest entry points — MMIO register programming
/// and the queue-notify service paths — so a fuzz harness can drive hostile
/// virtqueue geometry and descriptor tables against the device without a live
/// hypervisor or the host-I/O handlers. It is not part of the device's supported
/// API: hidden from docs, and only reachable by the workspace-excluded fuzz
/// crate. Everything it wraps stays crate-private.
#[doc(hidden)]
pub struct FuzzTransportDriver(VsockTransportCore);

#[doc(hidden)]
impl FuzzTransportDriver {
    /// # Safety
    /// `ram` must point to `ram_size` writable bytes mapped at `ram_base` and
    /// stay valid (unmoved, unfreed) for the lifetime of the returned driver.
    pub unsafe fn new(ram: *mut u8, ram_base: u64, ram_size: usize) -> Self {
        // SAFETY: forwarded to the caller's contract.
        Self(unsafe { VsockTransportCore::new(ram, ram_base, ram_size) })
    }

    /// Apply one MMIO register write. A write to the queue-notify register drives
    /// the same TX/RX service dispatch the vCPU MMIO exit path runs.
    pub fn write_register(&mut self, offset: u64, value: u64) {
        match self.0.write_register(offset, value) {
            RegisterWrite::None => {}
            RegisterWrite::Notify(queue) => self.notify(queue),
        }
    }

    /// Drive the queue-notify service paths directly (queue `1` is TX). Mirrors
    /// the device's on-notify dispatch minus the packet handlers, which are out
    /// of scope for the queue-geometry / descriptor-table surface.
    pub fn notify(&mut self, queue: u32) {
        if queue == 1 {
            let _ = self.0.take_tx_packets();
        }
        let _ = self.0.flush_rx();
    }

    /// Pre-queue a host→guest packet so the RX flush path has work to service
    /// (the RX arm of the queue-geometry divide-by-zero only runs with a
    /// non-empty pending-RX buffer).
    pub fn queue_host_packet(&mut self, src_port: u32, dst_port: u32, op: u16, payload: &[u8]) {
        self.0.queue_host_packet(src_port, dst_port, op, payload);
    }

    /// Number of host→guest packets still queued — the accumulating buffer the
    /// fuzz target observes to prove RX servicing never grows it without bound.
    pub fn pending_rx_len(&self) -> usize {
        self.0.pending_rx.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bind_unix_listener, error_chain_has_permission_denied};
    use crate::vmm::vsock_transport::MAX_CONNECTIONS;

    fn dev() -> VsockShared {
        let ram = crate::test_support::page_aligned_ram(0x1000);
        // SAFETY: page-aligned, zeroed, leaked for the test process lifetime.
        unsafe { VsockShared::new(49, ram.as_mut_ptr(), 0x4000_0000, ram.len()) }
    }

    fn virtio_dev() -> VirtioVsock {
        let ram = crate::test_support::page_aligned_ram(0x1000);
        // SAFETY: page-aligned, zeroed, leaked for the test process lifetime.
        unsafe { VirtioVsock::new(0x0a00_0000, 49, ram.as_mut_ptr(), 0x4000_0000, ram.len()) }
    }

    struct TestIrqLine;

    impl IrqLine for TestIrqLine {
        fn signal(&self, _spi: u32) {}
    }

    /// Wait for the device to pick up a host connection and return the host
    /// port it assigned, read off the `OP_REQUEST` it queued for the guest.
    fn next_queued_request_port(device: &VirtioVsock) -> u32 {
        let started = std::time::Instant::now();
        loop {
            if let Some(port) = device
                .lock()
                .transport
                .pending_rx
                .iter()
                .find(|(hdr, _)| hdr.op == OP_REQUEST)
                .map(|(hdr, _)| hdr.src_port)
            {
                return port;
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(2),
                "the device never picked up the host connection"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// A rebind must not hand out a host port a guest may still hold.
    ///
    /// Host ports are the guest's connection identity. A guest restored from a
    /// snapshot can still believe a port is connected: the parent's last
    /// session closes just before capture, its `OP_RST` is still queued when
    /// the pause cancels host I/O, and the guest is frozen holding the socket.
    /// Reissuing that port gets the new connection reset by the guest kernel on
    /// sight. Starting every rebind back at the first host port is what made a
    /// warm claim's post-restore session collide with the parent's activation
    /// session, one claim in a few, depending only on which connection drew the
    /// stale number.
    #[test]
    fn a_rebind_never_reissues_a_host_port() {
        let dir = tempfile::Builder::new()
            .prefix("vsk")
            .tempdir_in("/tmp")
            .unwrap();
        let agent_socket = dir.path().join("agent.sock");
        let bindings = VsockHostBindings {
            agent_socket: Some(agent_socket.clone()),
            ..VsockHostBindings::default()
        };
        let mut device = virtio_dev();
        if device
            .rebind_host_channels(&bindings, Arc::new(TestIrqLine))
            .is_err()
        {
            return;
        }
        let _first_client = std::os::unix::net::UnixStream::connect(&agent_socket).unwrap();
        let first = next_queued_request_port(&device);

        device
            .rebind_host_channels(&bindings, Arc::new(TestIrqLine))
            .unwrap();
        let _second_client = std::os::unix::net::UnixStream::connect(&agent_socket).unwrap();
        let second = next_queued_request_port(&device);

        assert!(
            second > first,
            "a rebind reissued host port {second} after {first} had already been handed out"
        );
        device.shutdown();
    }

    /// A child restored into a new process gets a newly constructed device, so
    /// the rebind guarantee above only reaches it if the numbering travels in
    /// the snapshot. The guest it resumes holds whatever the parent held.
    #[test]
    fn a_restored_device_continues_host_port_numbering_from_its_snapshot() {
        let dir = tempfile::Builder::new()
            .prefix("vsk")
            .tempdir_in("/tmp")
            .unwrap();
        let agent_socket = dir.path().join("agent.sock");
        let mut source = virtio_dev();
        if source
            .rebind_host_channels(
                &VsockHostBindings {
                    agent_socket: Some(agent_socket.clone()),
                    ..VsockHostBindings::default()
                },
                Arc::new(TestIrqLine),
            )
            .is_err()
        {
            return;
        }
        let _client = std::os::unix::net::UnixStream::connect(&agent_socket).unwrap();
        let handed_out = next_queued_request_port(&source);

        source.prepare_snapshot();
        let bytes = source.snapshot_state().unwrap();

        let mut restored = virtio_dev();
        restored.restore_state(&bytes).unwrap();
        let cursor = restored.lock().handlers.host_port_cursor();
        assert!(
            cursor.agent > handed_out,
            "a restored device would reissue host port {} after the parent had handed out \
             {handed_out}",
            cursor.agent
        );
    }

    /// A snapshot is read back through `restore_state`, so a cursor that points
    /// into another bridge's range, or below the first host port, is refused
    /// rather than trusted.
    #[test]
    fn a_snapshot_with_a_host_port_cursor_out_of_range_is_refused() {
        let mut source = virtio_dev();
        source.prepare_snapshot();
        let mut bytes = source.snapshot_state().unwrap();
        // The cursor is the last eight bytes: agent then host-dial, both u32 LE.
        let agent_at = bytes.len() - 8;
        bytes[agent_at..agent_at + 4].copy_from_slice(&7u32.to_le_bytes());
        let error = virtio_dev().restore_state(&bytes).unwrap_err();
        assert!(matches!(
            error,
            DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "agent_host_port_cursor"
            }
        ));
    }

    /// Every vCPU of an SMP machine runs its own copy of the run loop, and each
    /// one that parks for a pause calls `prepare_snapshot` and then
    /// `resume_after_snapshot` on the one shared device. The second vCPU to
    /// leave the hold must not tear down what the first already brought back:
    /// by then the guest is running, and the host may be mid-handshake with it.
    ///
    /// Checked on the connection rather than on `io.is_some()`, because a
    /// second rebind also leaves I/O running — it just drops every live stream
    /// on the way. That was the warm-claim failure: the host's post-restore
    /// session died with `Broken pipe` while the guest logged a peer that hung
    /// up mid-handshake.
    #[test]
    fn a_second_vcpu_leaving_the_pause_hold_keeps_the_first_ones_connections() {
        // Short root: macOS caps a socket path at 104 bytes, and the default
        // temp dir alone eats most of that.
        let dir = tempfile::Builder::new()
            .prefix("vsk")
            .tempdir_in("/tmp")
            .unwrap();
        let agent_socket = dir.path().join("agent.sock");
        let mut device = virtio_dev();
        device.irq_line = Some(Arc::new(TestIrqLine));
        if device.set_agent_socket(&agent_socket).is_err() {
            return;
        }
        device.start_io(Arc::new(TestIrqLine));

        // Two vCPUs park.
        device.prepare_snapshot();
        device.prepare_snapshot();

        // The first leaves the hold, restoring host I/O; the host connects.
        device.resume_after_snapshot();
        let mut client = std::os::unix::net::UnixStream::connect(&agent_socket).unwrap();
        // Set while the stream is healthy. macOS refuses `setsockopt` with
        // EINVAL on a socket whose connection has already been torn down, which
        // would report the bug as an unexplained unwrap.
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .unwrap();
        let accepted = std::time::Instant::now();
        while device.queued_host_packets() == 0
            && accepted.elapsed() < std::time::Duration::from_secs(2)
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            device.queued_host_packets() > 0,
            "the device never picked up the host connection, so the rest of this \
             test would pass without exercising anything"
        );

        // The second leaves the hold.
        device.resume_after_snapshot();

        let mut byte = [0u8; 1];
        match std::io::Read::read(&mut client, &mut byte) {
            Ok(0) => panic!("the second vCPU's resume closed a connection the first one served"),
            Ok(_) => {}
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "the second vCPU's resume broke a live connection: {error}"
            ),
        }
        assert!(
            device.queued_host_packets() > 0,
            "the second vCPU's resume discarded the pending connection request"
        );
        device.shutdown();
    }

    #[test]
    fn idle_control_state_roundtrips_without_host_state() {
        let source = virtio_dev();
        {
            let mut shared = source.lock();
            shared.transport.device_features_sel = 1;
            shared.transport.status = 4;
            shared.transport.queue_sel = 2;
            shared.transport.interrupt_status = 1;
            shared.transport.queues[0] = Queue {
                num: 128,
                ready: 1,
                desc: 0x1000,
                avail: 0x2000,
                used: 0x3000,
                last_avail: 7,
                next_used: 9,
            };
        }

        let encoded = source.snapshot_state().expect("idle vsock state captures");
        let mut target = virtio_dev();
        target
            .restore_state(&encoded)
            .expect("idle vsock state restores");
        assert_eq!(target.snapshot_state().unwrap(), encoded);
    }

    #[test]
    fn active_vsock_state_is_rejected_before_capture() {
        let source = virtio_dev();
        {
            let mut shared = source.lock();
            let hdr = VsockHdr {
                src_port: 1000,
                dst_port: 2000,
                ..Default::default()
            };
            assert!(shared.transport.try_add_recv(&hdr, 1));
            shared.transport.pending_rx.clear();
        }
        assert!(matches!(
            source.snapshot_state(),
            Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "receive_credit_sessions"
            })
        ));
    }

    #[test]
    fn transmit_credit_state_is_rejected_before_capture() {
        let source = virtio_dev();
        {
            let mut shared = source.lock();
            shared.handle_packet(
                VsockHdr {
                    src_cid: GUEST_CID,
                    dst_cid: HOST_CID,
                    src_port: 1000,
                    dst_port: mvm_agentd::vsock::EGRESS_PORT,
                    op: OP_CREDIT_UPDATE,
                    typ: TYPE_STREAM,
                    buf_alloc: 64,
                    ..Default::default()
                },
                &[],
            );
            shared.transport.pending_rx.clear();
        }
        assert!(matches!(
            source.snapshot_state(),
            Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "transmit_credit_sessions"
            })
        ));
    }

    #[test]
    fn host_endpoint_binding_is_rejected_before_capture() {
        let dir = tempfile::tempdir().unwrap();
        let source = virtio_dev();
        source
            .lock()
            .set_network_endpoint(&dir.path().join("egress.sock"));
        assert!(matches!(
            source.snapshot_state(),
            Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "host_endpoints_bound"
            })
        ));
    }

    #[test]
    fn snapshot_pause_rebinds_the_live_parents_host_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = dir.path().join("egress.sock");
        let mut source = virtio_dev();
        source.set_network_endpoint(&endpoint);
        source.irq_line = Some(Arc::new(TestIrqLine));

        source.prepare_snapshot();
        source
            .snapshot_state()
            .expect("paused device contains no host-owned handles");
        assert_eq!(
            source.host_runtime.bindings.network_endpoint.as_deref(),
            Some(endpoint.as_path())
        );

        source.resume_after_snapshot();
        assert!(source.io.is_some(), "live parent host I/O must restart");
        assert!(matches!(
            source.snapshot_state(),
            Err(DeviceStateError::InvalidValue {
                kind: DeviceKind::VirtioVsock,
                field: "host_io_active"
            })
        ));
        source.shutdown();
    }

    #[test]
    fn identity_and_config() {
        let d = dev();
        assert_eq!(d.read(0x000) as u32, VIRTIO_MAGIC);
        assert_eq!(d.read(0x008) as u32, VIRTIO_ID_VSOCK);
        assert_eq!(d.read(R_CONFIG) as u32, GUEST_CID as u32);
        assert_eq!(d.read(0x004) as u32, VIRTIO_VERSION);
    }

    #[test]
    fn hdr_round_trips() {
        let h = VsockHdr {
            src_cid: 3,
            dst_cid: 2,
            src_port: 1234,
            dst_port: 5678,
            len: 9,
            typ: TYPE_STREAM,
            op: OP_RW,
            flags: 0,
            buf_alloc: 4096,
            fwd_cnt: 7,
        };
        let b = h.to_bytes();
        let h2 = VsockHdr::from_bytes(&b);
        assert_eq!(h2.src_port, 1234);
        assert_eq!(h2.dst_port, 5678);
        assert_eq!(h2.op, OP_RW);
        assert_eq!(h2.len, 9);
        assert_eq!(h2.buf_alloc, 4096);
    }

    #[test]
    fn request_queues_a_response_and_rw_is_captured() {
        let mut d = dev();
        let req = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1000,
            dst_port: 2000,
            op: OP_REQUEST,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(req, &[]);
        assert_eq!(d.transport.pending_rx.len(), 1);
        assert_eq!(d.transport.pending_rx[0].0.op, OP_RESPONSE);
        assert_eq!(d.transport.pending_rx[0].0.src_port, 2000);
        assert_eq!(d.transport.pending_rx[0].0.dst_port, 1000);

        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1000,
            dst_port: 2000,
            len: 5,
            op: OP_RW,
            typ: TYPE_STREAM,
            buf_alloc: HOST_BUF_ALLOC,
            ..Default::default()
        };
        d.handle_packet(rw, b"hello");
        assert_eq!(d.lifecycle.received, b"hello");
    }

    #[test]
    fn guest_stream_cap_returns_reset_for_a_new_identity() {
        let mut d = dev();
        for src_port in 0..MAX_CONNECTIONS as u32 {
            d.handle_packet(
                VsockHdr {
                    src_cid: GUEST_CID,
                    dst_cid: HOST_CID,
                    src_port,
                    dst_port: mvm_agentd::vsock::WORKLOAD_EXIT_PORT,
                    len: 1,
                    typ: TYPE_STREAM,
                    op: OP_RW,
                    ..Default::default()
                },
                b"x",
            );
        }

        d.handle_packet(
            VsockHdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: MAX_CONNECTIONS as u32,
                dst_port: mvm_agentd::vsock::WORKLOAD_EXIT_PORT,
                len: 1,
                typ: TYPE_STREAM,
                op: OP_RW,
                ..Default::default()
            },
            b"x",
        );

        assert_eq!(d.transport.pending_rx.len(), MAX_CONNECTIONS + 1);
        assert_eq!(
            d.transport.pending_rx.back().map(|(hdr, _)| hdr.op),
            Some(OP_RST)
        );
    }

    #[test]
    fn egress_port_relays_frame_to_endpoint_and_back() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");

        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            let mut reply = b"OK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            c.write_all(&reply).unwrap();
            buf[..n].to_vec()
        });

        let mut d = dev();
        d.set_network_endpoint(&sock);

        let raw = b"1.2.3.4:80\n".to_vec();
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1500,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: raw.len() as u32,
            op: OP_RW,
            typ: TYPE_STREAM,
            buf_alloc: HOST_BUF_ALLOC,
            ..Default::default()
        };
        d.handle_packet(rw, &raw);

        assert!(d.lifecycle.received.is_empty());
        assert!(
            d.transport
                .pending_rx
                .iter()
                .any(|(h, _)| h.op == OP_CREDIT_UPDATE)
        );

        let got_by_endpoint = server.join().unwrap();
        assert_eq!(got_by_endpoint, raw);

        let mut reply = None;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if let Some((h, payload)) = d
                .transport
                .pending_rx
                .iter()
                .find(|(h, _)| h.op == OP_RW && h.dst_port == 1500)
            {
                reply = Some((*h, payload.clone()));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (h, payload) = reply.expect("endpoint reply framed back to the guest");
        assert_eq!(h.src_port, mvm_agentd::vsock::EGRESS_PORT);
        assert!(payload.starts_with(b"OK:"));
    }

    #[test]
    fn egress_port_resets_without_endpoint() {
        let mut d = dev();
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 2000,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: 16,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(rw, b"93.184.216.34:80");
        assert!(d.lifecycle.received.is_empty());
        assert!(d.transport.pending_rx.iter().any(|(h, _)| h.op == OP_RST));
    }

    /// The regression a FlowMux launch died on: the session handshake opens
    /// with the *host's* `SessionHello`, so the guest connects and reads. A
    /// bridge that dials the endpoint only on the first guest payload leaves
    /// the endpoint with no socket to greet on, and both halves wait — which
    /// surfaced as "no guest authenticated" with a guest that had connected.
    #[test]
    fn egress_port_delivers_a_host_first_greeting_after_only_a_connect() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");

        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.write_all(b"HELLO").unwrap();
            // The real endpoint holds the session open waiting for the guest's
            // reply; dropping here would close the socket before the drain.
            std::thread::sleep(std::time::Duration::from_millis(500));
        });

        let mut d = dev();
        d.set_network_endpoint(&sock);

        let request = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1600,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: 0,
            op: OP_REQUEST,
            typ: TYPE_STREAM,
            buf_alloc: HOST_BUF_ALLOC,
            ..Default::default()
        };
        d.handle_packet(request, &[]);
        assert!(
            d.transport
                .pending_rx
                .iter()
                .any(|(h, _)| h.op == OP_RESPONSE),
            "the connect itself must still be accepted"
        );

        let mut greeting = None;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if let Some((h, payload)) = d
                .transport
                .pending_rx
                .iter()
                .find(|(h, _)| h.op == OP_RW && h.dst_port == 1600)
            {
                greeting = Some((*h, payload.clone()));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (h, payload) =
            greeting.expect("the endpoint's greeting reaches a guest that has only connected");
        assert_eq!(h.src_port, mvm_agentd::vsock::EGRESS_PORT);
        assert_eq!(payload, b"HELLO");
        server.join().unwrap();
    }

    /// With nothing bound the refusal now lands on the connect rather than on
    /// the first payload, so a guest waiting to be greeted learns immediately
    /// instead of blocking until its own timeout.
    #[test]
    fn egress_port_resets_a_connect_without_endpoint() {
        let mut d = dev();
        let request = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 2100,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: 0,
            op: OP_REQUEST,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(request, &[]);
        assert!(d.transport.pending_rx.iter().any(|(h, _)| h.op == OP_RST));
        assert!(
            !d.transport
                .pending_rx
                .iter()
                .any(|(h, _)| h.op == OP_RESPONSE),
            "a connect with no endpoint must not read as accepted"
        );
    }

    #[test]
    fn teardown_cancellation_clears_vsock_state() {
        let mut d = dev();
        d.handle_packet(
            VsockHdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: 2000,
                dst_port: mvm_agentd::vsock::WORKLOAD_EXIT_PORT,
                len: 1,
                op: OP_RW,
                typ: TYPE_STREAM,
                ..Default::default()
            },
            b"x",
        );
        assert!(!d.transport.recv_cnt.is_empty());
        assert!(!d.transport.pending_rx.is_empty());

        d.cancel();

        assert!(d.transport.recv_cnt.is_empty());
        assert!(d.transport.pending_rx.is_empty());
    }

    #[test]
    fn broker_port_relays_frame_to_endpoint_and_back() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("hvf-broker.sock");

        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            let mut reply = b"OK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            c.write_all(&reply).unwrap();
            buf[..n].to_vec()
        });

        let mut d = dev();
        d.set_broker_endpoint(&sock);

        let raw = b"host.audit.v1 request\n".to_vec();
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1600,
            dst_port: mvm_agentd::vsock::BROKER_PORT,
            len: raw.len() as u32,
            op: OP_RW,
            typ: TYPE_STREAM,
            buf_alloc: HOST_BUF_ALLOC,
            ..Default::default()
        };
        d.handle_packet(rw, &raw);

        assert!(d.lifecycle.received.is_empty());
        assert!(
            d.transport
                .pending_rx
                .iter()
                .any(|(h, _)| h.op == OP_CREDIT_UPDATE)
        );

        let got_by_broker = server.join().unwrap();
        assert_eq!(got_by_broker, raw);

        let mut reply = None;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if let Some((h, payload)) = d
                .transport
                .pending_rx
                .iter()
                .find(|(h, _)| h.op == OP_RW && h.dst_port == 1600)
            {
                reply = Some((*h, payload.clone()));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (h, payload) = reply.expect("broker reply framed back to the guest");
        assert_eq!(h.src_port, mvm_agentd::vsock::BROKER_PORT);
        assert!(payload.starts_with(b"OK:"));
    }

    #[test]
    fn broker_port_resets_without_endpoint() {
        let mut d = dev();
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 2100,
            dst_port: mvm_agentd::vsock::BROKER_PORT,
            len: 8,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(rw, b"audit v1");
        assert!(d.lifecycle.received.is_empty());
        assert!(d.transport.pending_rx.iter().any(|(h, _)| h.op == OP_RST));
    }

    #[test]
    fn host_agent_request_advertises_zero_credit_so_guest_does_not_reset() {
        let mut d = dev();
        let cap = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 7000,
            dst_port: 9000,
            len: 5,
            op: OP_RW,
            typ: TYPE_STREAM,
            buf_alloc: HOST_BUF_ALLOC,
            ..Default::default()
        };
        d.handle_packet(cap, b"hello");
        let credit = d
            .transport
            .pending_rx
            .iter()
            .find(|(h, _)| h.op == OP_CREDIT_UPDATE && h.dst_port == 7000)
            .expect("capture stream acked");
        assert_eq!(credit.0.fwd_cnt, 5);
        d.transport.pending_rx.clear();

        d.transport.queue_host_packet(
            1 << 20,
            mvm_agentd::vsock::GUEST_AGENT_PORT,
            OP_REQUEST,
            &[],
        );
        let req = &d.transport.pending_rx[0].0;
        assert_eq!(req.op, OP_REQUEST);
        assert_eq!(req.dst_port, mvm_agentd::vsock::GUEST_AGENT_PORT);
        assert_eq!(req.fwd_cnt, 0);
        assert_eq!(req.buf_alloc, HOST_BUF_ALLOC);
    }

    #[test]
    fn receive_credit_is_tracked_per_connection() {
        let mut d = dev();
        let a = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 7000,
            dst_port: 9000,
            len: 3,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(a, b"abc");
        let b = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 8000,
            dst_port: 9000,
            len: 10,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(b, b"0123456789");
        let ca = d
            .transport
            .pending_rx
            .iter()
            .find(|(h, _)| h.op == OP_CREDIT_UPDATE && h.dst_port == 7000)
            .expect("stream A credit");
        let cb = d
            .transport
            .pending_rx
            .iter()
            .find(|(h, _)| h.op == OP_CREDIT_UPDATE && h.dst_port == 8000)
            .expect("stream B credit");
        assert_eq!(ca.0.fwd_cnt, 3);
        assert_eq!(cb.0.fwd_cnt, 10);
    }

    #[test]
    fn service_host_io_drains_egress_replies() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            c.write_all(b"OK").unwrap();
            buf[..n].to_vec()
        });

        let mut d = dev();
        d.set_network_endpoint(&sock);
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1500,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: 5,
            op: OP_RW,
            typ: TYPE_STREAM,
            buf_alloc: HOST_BUF_ALLOC,
            ..Default::default()
        };
        d.handle_packet(rw, b"1.2.3");
        server.join().unwrap();
        d.transport.pending_rx.clear();

        let mut framed = false;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if d.transport
                .pending_rx
                .iter()
                .any(|(h, _)| h.op == OP_RW && h.dst_port == 1500)
            {
                framed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(framed);
    }

    #[test]
    fn host_honors_guest_transmit_credit_and_resumes_after_update() {
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("credit.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut request = [0u8; 64];
            let _ = connection.read(&mut request).unwrap();
            connection.write_all(&[b'x'; 200]).unwrap();
            connection.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        });

        let mut device = dev();
        device.set_network_endpoint(&sock);
        let target = b"files.pythonhosted.org:443\n";
        device.handle_packet(
            VsockHdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: 1700,
                dst_port: mvm_agentd::vsock::EGRESS_PORT,
                len: target.len() as u32,
                op: OP_RW,
                typ: TYPE_STREAM,
                buf_alloc: 64,
                ..Default::default()
            },
            target,
        );

        let mut received = Vec::new();
        for _ in 0..100 {
            let _ = device.service_host_io();
            for (header, payload) in device.transport.pending_rx.drain(..) {
                if header.op == OP_RW && header.dst_port == 1700 {
                    received.extend_from_slice(&payload);
                }
            }
            if !received.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let first_window = received.len();

        device.handle_packet(
            VsockHdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: 1700,
                dst_port: mvm_agentd::vsock::EGRESS_PORT,
                op: OP_CREDIT_UPDATE,
                typ: TYPE_STREAM,
                buf_alloc: 64,
                fwd_cnt: 64,
                ..Default::default()
            },
            &[],
        );
        for _ in 0..100 {
            let _ = device.service_host_io();
            for (header, payload) in device.transport.pending_rx.drain(..) {
                if header.op == OP_RW && header.dst_port == 1700 {
                    received.extend_from_slice(&payload);
                }
            }
            if received.len() >= 128 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        server.join().unwrap();
        assert_eq!(first_window, 64, "host exceeded the guest's first window");
        assert_eq!(
            received.len(),
            128,
            "host did not stop at or resume for the second window"
        );
    }

    #[test]
    fn large_egress_reply_obeys_credit_and_arrives_without_loss() {
        use std::io::{Read, Write};

        const PAYLOAD_LEN: usize = 32 * 1024 * 1024;
        const GUEST_WINDOW: usize = 64 * 1024;
        const SERVER_CHUNK: usize = 16 * 1024;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("large-credit.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            loop {
                connection.read_exact(&mut byte).unwrap();
                if byte[0] == b'\n' {
                    break;
                }
            }
            let mut offset = 0usize;
            let mut chunk = [0u8; SERVER_CHUNK];
            while offset < PAYLOAD_LEN {
                let len = SERVER_CHUNK.min(PAYLOAD_LEN - offset);
                for (index, byte) in chunk[..len].iter_mut().enumerate() {
                    *byte = ((offset + index) % 251) as u8;
                }
                connection.write_all(&chunk[..len])?;
                offset += len;
            }
            Ok::<(), std::io::Error>(())
        });

        let mut device = dev();
        device.set_network_endpoint(&sock);
        let target = b"files.pythonhosted.org:443\n";
        device.handle_packet(
            VsockHdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: 1800,
                dst_port: mvm_agentd::vsock::EGRESS_PORT,
                len: target.len() as u32,
                op: OP_RW,
                typ: TYPE_STREAM,
                buf_alloc: GUEST_WINDOW as u32,
                ..Default::default()
            },
            target,
        );

        let mut received = Vec::with_capacity(PAYLOAD_LEN);
        let mut largest_window = 0usize;
        let mut shutdown_seen = false;
        for _ in 0..40_000 {
            let _ = device.service_host_io();
            let mut window_bytes = 0usize;
            for (header, payload) in device.transport.pending_rx.drain(..) {
                if header.op == OP_RW && header.dst_port == 1800 {
                    window_bytes += payload.len();
                    received.extend_from_slice(&payload);
                } else if header.op == OP_SHUTDOWN && header.dst_port == 1800 {
                    shutdown_seen = true;
                }
            }
            largest_window = largest_window.max(window_bytes);
            if window_bytes > 0 {
                device.handle_packet(
                    VsockHdr {
                        src_cid: GUEST_CID,
                        dst_cid: HOST_CID,
                        src_port: 1800,
                        dst_port: mvm_agentd::vsock::EGRESS_PORT,
                        op: OP_CREDIT_UPDATE,
                        typ: TYPE_STREAM,
                        buf_alloc: GUEST_WINDOW as u32,
                        fwd_cnt: received.len() as u32,
                        ..Default::default()
                    },
                    &[],
                );
            }
            if !shutdown_seen {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            if shutdown_seen {
                break;
            }
        }

        drop(device);
        let server_result = server.join().unwrap();
        assert!(
            shutdown_seen,
            "large egress stream did not close gracefully"
        );
        assert!(server_result.is_ok(), "large egress writer was cut off");
        assert!(
            largest_window <= GUEST_WINDOW,
            "host queued {largest_window} bytes into an {GUEST_WINDOW}-byte guest window"
        );
        assert_eq!(received.len(), PAYLOAD_LEN);
        assert!(
            received
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == (index % 251) as u8),
            "large egress stream was corrupted"
        );
    }

    #[test]
    fn cancel_clears_transmit_credit_state() {
        let mut device = dev();
        device.handle_packet(
            VsockHdr {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: 1900,
                dst_port: mvm_agentd::vsock::EGRESS_PORT,
                op: OP_CREDIT_UPDATE,
                typ: TYPE_STREAM,
                buf_alloc: 64,
                ..Default::default()
            },
            &[],
        );
        assert_eq!(
            device
                .transport
                .tx_credit_available(mvm_agentd::vsock::EGRESS_PORT, 1900),
            64
        );

        device.cancel();

        assert_eq!(
            device
                .transport
                .tx_credit_available(mvm_agentd::vsock::EGRESS_PORT, 1900),
            0
        );
    }

    #[test]
    fn host_agent_connection_frames_op_request_and_routes_replies() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let mut d = dev();
        if let Err(err) = d.set_agent_socket(&sock) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied agent socket setup at {}: {err}",
                    sock.display()
                );
                return;
            }
            panic!("agent socket setup failed at {}: {err}", sock.display());
        }

        let _client = std::os::unix::net::UnixStream::connect(&sock).unwrap();

        let mut hdr = None;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if let Some((h, _)) = d.transport.pending_rx.front() {
                hdr = Some(*h);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let hdr = hdr.expect("OP_REQUEST framed for the host connection");
        assert_eq!(hdr.op, OP_REQUEST);
        assert_eq!(hdr.dst_port, mvm_agentd::vsock::GUEST_AGENT_PORT);
        assert_eq!(hdr.src_cid, HOST_CID);
        assert_eq!(hdr.dst_cid, GUEST_CID);
        let conn_id = hdr.src_port;
        assert!(d.handlers.is_agent_stream(conn_id));

        let reply = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: mvm_agentd::vsock::GUEST_AGENT_PORT,
            dst_port: conn_id,
            len: 5,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(reply, b"world");
        assert!(d.lifecycle.received.is_empty());
    }

    #[test]
    fn host_console_connection_frames_op_request_on_the_console_port() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let port = 20005u32;
        let sock = dir.path().join("vsock-20005.sock");
        let mut d = dev();
        if let Err(err) = d.set_host_dial_sockets([(port, sock.as_path())]) {
            if error_chain_has_permission_denied(&err) {
                eprintln!(
                    "skipping test: sandbox denied console socket setup at {}: {err}",
                    sock.display()
                );
                return;
            }
            panic!("console socket setup failed at {}: {err}", sock.display());
        }
        if !sock.exists() {
            eprintln!(
                "skipping test: console socket was not created at {}",
                sock.display()
            );
            return;
        }

        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        client.write_all(b"ls\n").unwrap();
        client.set_nonblocking(true).unwrap();

        let mut hdr = None;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if let Some((h, _)) = d.transport.pending_rx.front() {
                hdr = Some(*h);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let hdr = hdr.expect("OP_REQUEST framed for the host console connection");
        assert_eq!(hdr.op, OP_REQUEST);
        assert_eq!(hdr.dst_port, port);
        assert_ne!(hdr.dst_port, mvm_agentd::vsock::GUEST_AGENT_PORT);
        assert_eq!(hdr.src_cid, HOST_CID);
        assert_eq!(hdr.dst_cid, GUEST_CID);
        let conn_id = hdr.src_port;
        assert!(d.handlers.is_host_dial_stream(conn_id));
        assert!(!d.handlers.is_agent_stream(conn_id));

        let accept = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: port,
            dst_port: conn_id,
            op: OP_RESPONSE,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(accept, &[]);
        d.transport.pending_rx.clear();
        let mut relayed = false;
        for _ in 0..200 {
            let _ = d.service_host_io();
            if d.transport
                .pending_rx
                .iter()
                .any(|(h, p)| h.op == OP_RW && h.dst_port == port && p == b"ls\n")
            {
                relayed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(relayed);

        let out = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: port,
            dst_port: conn_id,
            len: 2,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(out, b"# ");
        assert!(d.lifecycle.received.is_empty());
        let mut buf = [0u8; 16];
        let mut n = 0;
        for _ in 0..200 {
            match client.read(&mut buf) {
                Ok(k) if k > 0 => {
                    n = k;
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        assert_eq!(&buf[..n], b"# ");
    }

    #[test]
    fn telemetry_handoff_is_independent_and_rebinds_the_child_listener() {
        let dir = tempfile::tempdir().unwrap();
        let bindings = canonical_child_bindings(
            "telemetry-child",
            dir.path(),
            crate::hvf_handoff::HANDOFF_TELEMETRY,
        )
        .unwrap();
        assert!(bindings.agent_socket.is_none());
        assert!(bindings.network_endpoint.is_none());
        assert!(bindings.broker_endpoint.is_none());
        let port = mvm_core::protocol::telemetry::TELEMETRY_PORT;
        let socket = mvm_core::config::vm_hvf_vsock_port_socket_at(dir.path(), port);
        assert_eq!(bindings.console_sockets, vec![(port, socket.clone())]);
        assert!(
            canonical_child_bindings("telemetry-child", dir.path(), 0)
                .unwrap()
                .console_sockets
                .is_empty()
        );
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let mut device = virtio_dev();
        device
            .rebind_host_channels(&bindings, Arc::new(TestIrqLine))
            .unwrap();
        assert!(socket.exists());
        let _client = UnixStream::connect(&socket).unwrap();
        device.shutdown();
        assert!(device.io.is_none());
        assert_ne!(
            HvfHandoffRequest::signing_message(42, "telemetry-child", 0),
            HvfHandoffRequest::signing_message(
                42,
                "telemetry-child",
                crate::hvf_handoff::HANDOFF_TELEMETRY
            ),
        );
    }

    #[test]
    fn empty_console_sockets_bind_nothing() {
        let mut d = dev();
        d.set_host_dial_sockets([]).unwrap();
        assert!(!d.service_host_io());
        assert!(d.transport.pending_rx.is_empty());
    }

    #[test]
    fn host_channel_rebind_starts_a_fresh_io_owner_without_dropping_bindings() {
        struct NoopIrq;
        impl IrqLine for NoopIrq {
            fn signal(&self, _spi: u32) {}
        }

        let dir = tempfile::tempdir().unwrap();
        let agent_socket = dir.path().join("agent.sock");
        let mut device = virtio_dev();
        device
            .rebind_host_channels(
                &VsockHostBindings {
                    agent_socket: Some(agent_socket.clone()),
                    ..VsockHostBindings::default()
                },
                Arc::new(NoopIrq),
            )
            .unwrap();
        assert!(device.io.is_some());
        assert!(agent_socket.exists());
        let _client = std::os::unix::net::UnixStream::connect(agent_socket).unwrap();
        device.shutdown();
        assert!(device.io.is_none());
    }

    /// The refusal a claiming host reads back names what the parent refused.
    ///
    /// Driven through the real handoff socket and `poll`, not the line encoder,
    /// because the encoder being right says nothing about whether the refusal
    /// path calls it. It used to write a bare `ERR`.
    #[test]
    fn a_refused_handoff_tells_the_host_why() {
        let dir = tempfile::Builder::new()
            .prefix("vsk")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("hvf-handoff.sock");
        let verify_key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        let mut device = virtio_dev();
        if device
            .set_handoff_control(Some(&socket), Some(dir.path()), Some(&verify_key), stop)
            .is_err()
        {
            return;
        }

        let client_socket = socket.clone();
        let host = std::thread::spawn(move || {
            let mut stream = std::os::unix::net::UnixStream::connect(client_socket).unwrap();
            stream.write_all(b"not a handoff request\n").unwrap();
            let mut reply = String::new();
            BufReader::new(stream).read_line(&mut reply).unwrap();
            reply
        });

        let started = std::time::Instant::now();
        while !stop.load(Ordering::Relaxed) {
            device.poll();
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "the parent never answered the handoff attempt"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(host.join().unwrap(), "ERR invalid handoff request\n");
    }

    #[test]
    fn handoff_names_cannot_escape_the_state_root() {
        assert!(valid_handoff_name("child-123"));
        assert!(!valid_handoff_name("../child"));
        assert!(!valid_handoff_name("child/name"));
        assert!(!valid_handoff_name(""));
    }

    #[test]
    fn handoff_endpoint_rejects_symlink_outside_state_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("vms");
        let child = root.join("child");
        std::fs::create_dir_all(&child).expect("child state dir");
        let outside = dir.path().join("outside.sock");
        let listener = UnixListener::bind(&outside).expect("outside listener");
        let escape = child.join("escape.sock");
        std::os::unix::fs::symlink(&outside, &escape).expect("escape symlink");
        let result = validate_handoff_endpoint(&escape, &root, &child);
        drop(listener);
        assert!(result.is_err());
    }
}
