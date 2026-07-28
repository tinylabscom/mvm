//! Minimal virtio-vsock (virtio-mmio v2) device — the host↔guest transport.
//!
//! Enough of the device for a guest to detect `virtio_vsock`, get `AF_VSOCK`,
//! connect to the host (CID 2), and exchange stream bytes. The host acts as a
//! listener that accepts any connection and captures what the guest sends (the
//! shape `mvm-init` lifecycle markers + the agent will use). Three queues:
//! rx (host→guest), tx (guest→host), event. Requests are serviced synchronously
//! in the guest's `QueueNotify` MMIO exit and completed by the backend raising
//! the device's SPI line.

use std::sync::{Arc, Mutex, MutexGuard};

use super::vsock_handlers::{VsockHandlerContext, VsockHandlerRegistry, VsockLifecycleState};
#[cfg(test)]
use super::vsock_transport::{
    GUEST_CID, HOST_BUF_ALLOC, HOST_CID, TYPE_STREAM, VIRTIO_ID_VSOCK, VIRTIO_MAGIC, VIRTIO_VERSION,
};
use super::vsock_transport::{
    OP_CREDIT_UPDATE, OP_REQUEST, OP_RESPONSE, OP_RST, OP_RW, RegisterWrite, VsockHdr,
    VsockTransportCore,
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

    pub fn set_substitution_endpoint(&mut self, path: &std::path::Path) {
        self.handlers.set_substitution_endpoint(path);
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

    pub fn capture_workload_exit(&mut self, stop: &'static std::sync::atomic::AtomicBool) {
        self.lifecycle.exit_stop = Some(self.handlers.capture_workload_exit(stop));
    }

    pub fn set_console_sockets<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a std::path::Path)>,
    ) -> std::io::Result<()> {
        self.handlers.set_console_sockets(ports)
    }

    pub fn set_console_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.handlers.set_console_activity(counter);
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
        self.notify_io();
        result
    }

    pub fn set_agent_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_agent_activity(counter);
        self.notify_io();
    }

    pub fn set_substitution_endpoint(&mut self, path: &std::path::Path) {
        self.lock().set_substitution_endpoint(path);
        self.notify_io();
    }

    pub fn set_substitution_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_substitution_activity(counter);
        self.notify_io();
    }

    pub fn set_broker_endpoint(&mut self, path: &std::path::Path) {
        self.lock().set_broker_endpoint(path);
        self.notify_io();
    }

    pub fn set_broker_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_broker_activity(counter);
        self.notify_io();
    }

    pub fn capture_workload_exit(&mut self, stop: &'static std::sync::atomic::AtomicBool) {
        self.lock().capture_workload_exit(stop);
        self.notify_io();
    }

    pub fn set_console_sockets<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a std::path::Path)>,
    ) -> std::io::Result<()> {
        let result = self.lock().set_console_sockets(ports);
        self.notify_io();
        result
    }

    pub fn set_console_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.lock().set_console_activity(counter);
        self.notify_io();
    }

    pub fn start_io(&mut self, irq_line: Arc<dyn IrqLine>) {
        self.shutdown();
        self.io = Some(super::vsock_io::spawn(
            Arc::clone(&self.shared),
            irq_line,
            self.irq,
        ));
    }

    pub fn shutdown(&mut self) {
        if let Some(io) = self.io.take() {
            io.stop();
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

    pub fn poll(&self) -> Option<u32> {
        if self.lock().service_host_io() {
            Some(self.irq)
        } else {
            None
        }
    }
}

impl Drop for VirtioVsock {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bind_unix_listener, error_chain_has_permission_denied};
    use crate::vmm::vsock_transport::MAX_CONNECTIONS;

    fn dev() -> VsockShared {
        let ram = vec![0u8; 0x1000].leak();
        // SAFETY: leaked for the test.
        unsafe { VsockShared::new(49, ram.as_mut_ptr(), 0x4000_0000, ram.len()) }
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
        d.set_substitution_endpoint(&sock);

        let raw = b"1.2.3.4:80\n".to_vec();
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1500,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: raw.len() as u32,
            op: OP_RW,
            typ: TYPE_STREAM,
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
        d.set_substitution_endpoint(&sock);
        let rw = VsockHdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1500,
            dst_port: mvm_agentd::vsock::EGRESS_PORT,
            len: 5,
            op: OP_RW,
            typ: TYPE_STREAM,
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
        if let Err(err) = d.set_console_sockets([(port, sock.as_path())]) {
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
        assert!(d.handlers.is_console_stream(conn_id));
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
    fn empty_console_sockets_bind_nothing() {
        let mut d = dev();
        d.set_console_sockets([]).unwrap();
        assert!(!d.service_host_io());
        assert!(d.transport.pending_rx.is_empty());
    }
}
