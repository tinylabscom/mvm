//! Minimal virtio-vsock (virtio-mmio v2) device — the host↔guest transport.
//!
//! Enough of the device for a guest to detect `virtio_vsock`, get `AF_VSOCK`,
//! connect to the host (CID 2), and exchange stream bytes. The host acts as a
//! listener that accepts any connection and captures what the guest sends (the
//! shape `mvm-init` lifecycle markers + the agent will use). Three queues:
//! rx (host→guest), tx (guest→host), event. Requests are serviced synchronously
//! in the guest's `QueueNotify` MMIO exit and completed by the backend raising
//! the device's SPI line.

use super::guest_mem::GuestMem;

const VIRTIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_VERSION: u32 = 2;
const VIRTIO_ID_VSOCK: u32 = 19;
const VIRTIO_VENDOR: u32 = 0x4d56_4d76;

const R_MAGIC: u64 = 0x000;
const R_VERSION: u64 = 0x004;
const R_DEVICE_ID: u64 = 0x008;
const R_VENDOR_ID: u64 = 0x00c;
const R_DEVICE_FEATURES: u64 = 0x010;
const R_DEVICE_FEATURES_SEL: u64 = 0x014;
const R_DRIVER_FEATURES: u64 = 0x020;
const R_DRIVER_FEATURES_SEL: u64 = 0x024;
const R_QUEUE_SEL: u64 = 0x030;
const R_QUEUE_NUM_MAX: u64 = 0x034;
const R_QUEUE_NUM: u64 = 0x038;
const R_QUEUE_READY: u64 = 0x044;
const R_QUEUE_NOTIFY: u64 = 0x050;
const R_INTERRUPT_STATUS: u64 = 0x060;
const R_INTERRUPT_ACK: u64 = 0x064;
const R_STATUS: u64 = 0x070;
const R_QUEUE_DESC_LO: u64 = 0x080;
const R_QUEUE_DESC_HI: u64 = 0x084;
const R_QUEUE_DRIVER_LO: u64 = 0x090;
const R_QUEUE_DRIVER_HI: u64 = 0x094;
const R_QUEUE_DEVICE_LO: u64 = 0x0a0;
const R_QUEUE_DEVICE_HI: u64 = 0x0a4;
const R_CONFIG: u64 = 0x100; // guest_cid (u64) at +0

const MMIO_LEN: u64 = 0x200;
const QUEUE_SIZE_MAX: u32 = 256;
const NUM_QUEUES: usize = 3;
const RX: usize = 0;
const TX: usize = 1;

const VIRTQ_DESC_F_NEXT: u16 = 1;

const HDR_LEN: usize = 44;
const HOST_CID: u64 = 2;
const GUEST_CID: u64 = 3;
const HOST_BUF_ALLOC: u32 = 256 * 1024;

// vsock packet ops.
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;
const TYPE_STREAM: u16 = 1;

/// A split virtqueue's driver-programmed layout + our consume cursor.
#[derive(Default, Clone, Copy)]
struct Queue {
    num: u32,
    ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
}

/// The vsock packet header (little-endian, 44 bytes).
#[derive(Default, Clone, Copy)]
struct Hdr {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    typ: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

impl Hdr {
    fn to_bytes(self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.typ.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }
    fn from_bytes(b: &[u8]) -> Hdr {
        let u64a = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32a = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u16a = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        Hdr {
            src_cid: u64a(0),
            dst_cid: u64a(8),
            src_port: u32a(16),
            dst_port: u32a(20),
            len: u32a(24),
            typ: u16a(28),
            op: u16a(30),
            flags: u32a(32),
            buf_alloc: u32a(36),
            fwd_cnt: u32a(40),
        }
    }
}

/// virtio-vsock device: host-side listener that accepts any connection and
/// records the stream bytes the guest sends.
pub struct VirtioVsock {
    base: u64,
    irq: u32,
    mem: GuestMem,
    device_features_sel: u32,
    status: u32,
    queue_sel: u32,
    queues: [Queue; NUM_QUEUES],
    interrupt_status: u32,
    /// Bytes received from the guest over an accepted stream (for the host).
    pub received: Vec<u8>,
    fwd_cnt: u32,
    /// Pending packets to deliver to the guest on its rx queue.
    pending_rx: Vec<(Hdr, Vec<u8>)>,
    /// Workload exit code captured from a guest write to
    /// [`WORKLOAD_EXIT_PORT`](mvm_guest::vsock::WORKLOAD_EXIT_PORT) (4-byte LE
    /// i32) — the transient run-to-exit signal. `Some` once the guest reports.
    pub workload_exit_code: Option<i32>,
    /// Set when the workload-exit code arrives, so the run loop's watchdog ends a
    /// transient VM (the same flag the SIGTERM/stop path uses).
    exit_stop: Option<&'static std::sync::atomic::AtomicBool>,
    /// Host vsock egress gateway: policy + open connections. Drives the
    /// claim-10 decision + the TCP proxy; the device only frames its replies onto
    /// the rx queue. The proxy core is transport-agnostic (keyed by stream id), so
    /// the device keeps the inbound header per stream to frame async replies back.
    egress: super::egress_proxy::EgressProxy,
    /// Inbound vsock header per egress stream (keyed by guest `src_port`), so a
    /// reply the header-agnostic proxy produces can be framed on the right stream.
    egress_hdrs: std::collections::HashMap<u32, Hdr>,
    /// Host→guest agent stream bridge — the inbound counterpart of `egress`. Host
    /// RPC clients connect to its Unix socket and reach the guest agent on
    /// [`GUEST_AGENT_PORT`](mvm_guest::vsock::GUEST_AGENT_PORT); the device frames
    /// its `OP_REQUEST`/`OP_RW` onto the rx queue and routes the guest's replies
    /// back to the host socket.
    agent: super::agent_bridge::AgentBridge,
    /// Per-VM substitution gateway. When a substitution endpoint UDS is
    /// configured, `EGRESS_PORT` carries the WireRequest substitution protocol and
    /// routes here instead of the raw-TCP `egress` proxy. The bridge makes the
    /// claim-10 decision on the first frame (reusing the egress gate), then relays
    /// admitted streams to the endpoint subprocess that enforces claims 12/13.
    substitution: super::substitution_bridge::SubstitutionBridge,
    /// Inbound vsock header per substitution stream (keyed by guest `src_port`), so
    /// an endpoint reply can be framed back on the right stream.
    substitution_hdrs: std::collections::HashMap<u32, Hdr>,
}

impl VirtioVsock {
    /// # Safety
    /// `ram` must point to `ram_size` bytes mapped as guest RAM at `ram_base`.
    pub unsafe fn new(base: u64, irq: u32, ram: *mut u8, ram_base: u64, ram_size: usize) -> Self {
        Self {
            base,
            irq,
            // SAFETY: forwarded from this fn's contract.
            mem: unsafe { GuestMem::new(ram, ram_base, ram_size) },
            device_features_sel: 0,
            status: 0,
            queue_sel: 0,
            queues: [Queue::default(); NUM_QUEUES],
            interrupt_status: 0,
            received: Vec::new(),
            fwd_cnt: 0,
            pending_rx: Vec::new(),
            workload_exit_code: None,
            exit_stop: None,
            egress: super::egress_proxy::EgressProxy::new(),
            egress_hdrs: std::collections::HashMap::new(),
            agent: super::agent_bridge::AgentBridge::new(),
            substitution: super::substitution_bridge::SubstitutionBridge::new(),
            substitution_hdrs: std::collections::HashMap::new(),
        }
    }

    /// Expose the host-side agent listener at `path` (host→guest). Host RPC
    /// clients connect here; the bridge opens a vsock stream to the guest agent on
    /// [`GUEST_AGENT_PORT`](mvm_guest::vsock::GUEST_AGENT_PORT). The inbound
    /// counterpart of [`set_egress_gate`](Self::set_egress_gate).
    pub fn set_agent_socket(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        self.agent.bind(path)
    }

    /// Share the heartbeat activity counter with the agent bridge so an open agent
    /// stream keeps the run loop waking an idle guest (the same counter the egress
    /// proxy uses).
    pub fn set_agent_activity(&mut self, counter: std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        self.agent.set_activity(counter);
    }

    /// Install the host egress gateway policy. A guest connect request
    /// to the egress port is then decided against `gate` (claim-10 default-deny)
    /// before any host connection is opened.
    pub fn set_egress_gate(&mut self, gate: super::egress_gate::EgressGate) {
        self.egress.set_gate(gate);
    }

    /// Share the open-egress-connection counter with the host run loop so its
    /// heartbeat can be gated on there being host→guest work to deliver.
    pub fn set_egress_activity(&mut self, counter: std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        self.egress.set_activity(counter);
    }

    /// Point the substitution gateway at this VM's `mvm-substitution-endpoint`
    /// Unix socket. Once set, a guest connect to `EGRESS_PORT` is relayed
    /// to the endpoint (WireRequest substitution; claims 10/12/13) rather than the
    /// raw-TCP egress proxy. Without it, `EGRESS_PORT` keeps the legacy egress path.
    pub fn set_substitution_endpoint(&mut self, path: &std::path::Path) {
        self.substitution.set_endpoint(path);
    }

    /// Install the claim-10 policy on the substitution gateway — the same
    /// [`EgressGate`](super::egress_gate::EgressGate) the raw-egress path uses, so
    /// a destination the network policy forbids is refused at the bridge before the
    /// secrets endpoint is contacted.
    pub fn set_substitution_gate(&mut self, gate: super::egress_gate::EgressGate) {
        self.substitution.set_gate(gate);
    }

    /// Share the heartbeat activity counter with the substitution gateway so an
    /// open substitution stream awaiting an endpoint reply keeps the run loop waking
    /// an idle guest (the same counter the egress proxy + agent bridge use).
    pub fn set_substitution_activity(
        &mut self,
        counter: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.substitution.set_activity(counter);
    }

    /// Egress targets the gateway refused (claim-10) — for audit / verification.
    pub fn egress_denied(&self) -> &[String] {
        &self.egress.denied
    }

    /// Egress targets the gateway admitted + connected — for audit / verification.
    pub fn egress_allowed(&self) -> &[String] {
        &self.egress.allowed
    }

    /// Capture the transient workload-exit code: a guest write of a 4-byte LE i32
    /// to [`WORKLOAD_EXIT_PORT`](mvm_guest::vsock::WORKLOAD_EXIT_PORT) records the
    /// code and sets `stop` so the run loop ends (VM life = workload life).
    pub fn capture_workload_exit(&mut self, stop: &'static std::sync::atomic::AtomicBool) {
        self.exit_stop = Some(stop);
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + MMIO_LEN
    }

    pub fn read(&self, offset: u64) -> u64 {
        u64::from(match offset {
            R_MAGIC => VIRTIO_MAGIC,
            R_VERSION => VIRTIO_VERSION,
            R_DEVICE_ID => VIRTIO_ID_VSOCK,
            R_VENDOR_ID => VIRTIO_VENDOR,
            R_DEVICE_FEATURES if self.device_features_sel == 1 => 1, // VIRTIO_F_VERSION_1
            R_DEVICE_FEATURES => 0,
            R_QUEUE_NUM_MAX => QUEUE_SIZE_MAX,
            R_QUEUE_READY => self.cur().ready,
            R_INTERRUPT_STATUS => self.interrupt_status,
            R_STATUS => self.status,
            R_CONFIG => GUEST_CID as u32, // guest_cid low
            o if o == R_CONFIG + 4 => (GUEST_CID >> 32) as u32, // guest_cid high
            _ => 0,
        })
    }

    fn cur(&self) -> &Queue {
        &self.queues[(self.queue_sel as usize).min(NUM_QUEUES - 1)]
    }
    fn cur_mut(&mut self) -> &mut Queue {
        let i = (self.queue_sel as usize).min(NUM_QUEUES - 1);
        &mut self.queues[i]
    }

    /// Handle an MMIO write. Returns `true` if the guest needs an interrupt.
    pub fn write(&mut self, offset: u64, value: u64) -> bool {
        let v = value as u32;
        match offset {
            R_DEVICE_FEATURES_SEL => self.device_features_sel = v,
            R_DRIVER_FEATURES_SEL | R_DRIVER_FEATURES => {}
            R_QUEUE_SEL => self.queue_sel = v,
            R_QUEUE_NUM => self.cur_mut().num = v,
            R_QUEUE_READY => self.cur_mut().ready = v,
            R_STATUS => self.status = v,
            R_INTERRUPT_ACK => self.interrupt_status &= !v,
            R_QUEUE_DESC_LO => set_lo(&mut self.cur_mut().desc, v),
            R_QUEUE_DESC_HI => set_hi(&mut self.cur_mut().desc, v),
            R_QUEUE_DRIVER_LO => set_lo(&mut self.cur_mut().avail, v),
            R_QUEUE_DRIVER_HI => set_hi(&mut self.cur_mut().avail, v),
            R_QUEUE_DEVICE_LO => set_lo(&mut self.cur_mut().used, v),
            R_QUEUE_DEVICE_HI => set_hi(&mut self.cur_mut().used, v),
            R_QUEUE_NOTIFY => return self.on_notify(v),
            _ => {}
        }
        false
    }

    fn on_notify(&mut self, queue: u32) -> bool {
        // The guest notifies tx (new packets) or rx (new buffers posted). Either
        // way, drain tx then try to flush queued rx packets to the guest.
        if queue as usize == TX {
            self.drain_tx();
        }
        let flushed = self.flush_rx();
        let drained = self.interrupt_status & 1 != 0;
        drained || flushed
    }

    /// Process guest→host packets on the tx queue.
    fn drain_tx(&mut self) {
        let q = self.queues[TX];
        if q.ready == 0 || q.num == 0 {
            return;
        }
        let qsz = q.num as u16;
        let avail_idx = self.mem.rd_u16(q.avail + 2);
        let mut last = q.last_avail;
        while last != avail_idx {
            let slot = last % qsz;
            let head = self.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            let buf = self.read_chain(q.desc, head, qsz);
            if buf.len() >= HDR_LEN {
                let hdr = Hdr::from_bytes(&buf[..HDR_LEN]);
                self.handle_packet(hdr, &buf[HDR_LEN..]);
            }
            self.complete(TX, head, 0);
            last = last.wrapping_add(1);
        }
        self.queues[TX].last_avail = last;
    }

    /// Read a (readable) descriptor chain into one contiguous buffer.
    fn read_chain(&self, desc: u64, head: u16, qsz: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let mut idx = head;
        let mut guard = 0u32;
        loop {
            let da = desc + u64::from(idx) * 16;
            let addr = self.mem.rd_u64(da);
            let len = self.mem.rd_u32(da + 8) as usize;
            let flags = self.mem.rd_u16(da + 12);
            out.extend_from_slice(&self.mem.read_bytes(addr, len));
            guard += 1;
            if flags & VIRTQ_DESC_F_NEXT == 0 || guard > u32::from(qsz) {
                break;
            }
            idx = self.mem.rd_u16(da + 14);
        }
        out
    }

    fn handle_packet(&mut self, hdr: Hdr, payload: &[u8]) {
        // Guest→host packet on a host-initiated agent stream: the host opened it,
        // so the guest agent's reply is addressed to our host-assigned src_port
        // (dst_port here). Route to the agent bridge, not the listener paths.
        if self.agent.is_agent_stream(hdr.dst_port) {
            agent_dbg(&format!(
                "guest op={} ({} bytes) for agent stream {}",
                hdr.op,
                payload.len(),
                hdr.dst_port
            ));
            match hdr.op {
                OP_RESPONSE => self.agent.on_established(hdr.dst_port),
                OP_RW => {
                    let n = (hdr.len as usize).min(payload.len());
                    self.agent.write_to_host(hdr.dst_port, &payload[..n]);
                    self.fwd_cnt = self.fwd_cnt.wrapping_add(n as u32);
                    self.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
                }
                OP_SHUTDOWN | OP_RST => {
                    self.agent.close(hdr.dst_port);
                    self.queue_reply(&hdr, OP_RST, &[]);
                }
                _ => {}
            }
            return;
        }
        match hdr.op {
            OP_REQUEST => {
                // Accept the connection: reply RESPONSE with our credit.
                self.queue_reply(&hdr, OP_RESPONSE, &[]);
            }
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                if hdr.dst_port == mvm_guest::vsock::WORKLOAD_EXIT_PORT {
                    // Transient workload-exit signal: a 4-byte LE i32 exit code.
                    // Record it and request stop (VM life = workload life).
                    if n >= 4 {
                        self.workload_exit_code =
                            Some(i32::from_le_bytes(payload[..4].try_into().unwrap()));
                    } else {
                        self.workload_exit_code = Some(0);
                    }
                    if let Some(stop) = self.exit_stop {
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                } else if hdr.dst_port == mvm_guest::vsock::EGRESS_PORT {
                    // The egress port carries one of two protocols, chosen at
                    // configuration time (not by peeking the bytes): if a
                    // substitution endpoint is wired for this VM, the stream speaks
                    // the WireRequest substitution protocol and is relayed to the
                    // endpoint, which makes the whole egress decision. Otherwise it
                    // is the legacy raw-TCP egress request — payload "ip:port",
                    // decided against the default-deny gate before any host socket
                    // is opened.
                    if self.substitution.has_endpoint() {
                        self.handle_substitution_request(&hdr, &payload[..n]);
                    } else {
                        self.handle_egress_request(&hdr, &payload[..n]);
                    }
                    self.fwd_cnt = self.fwd_cnt.wrapping_add(n as u32);
                    return;
                } else {
                    self.received.extend_from_slice(&payload[..n]);
                }
                self.fwd_cnt = self.fwd_cnt.wrapping_add(n as u32);
                // Acknowledge consumed bytes so the guest's credit recovers.
                self.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
            }
            OP_CREDIT_REQUEST => self.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]),
            OP_SHUTDOWN => {
                // A substitution stream the guest is done with: tear down its
                // endpoint connection so the endpoint sees EOF on the request.
                if self.substitution_hdrs.remove(&hdr.src_port).is_some() {
                    self.substitution.close(hdr.src_port);
                }
                self.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }

    /// Frame an inbound egress request to the [`EgressProxy`] and map its action to
    /// a vsock control reply. The decision + TCP proxy live in the proxy;
    /// the device owns the rx framing and the per-stream header.
    fn handle_egress_request(&mut self, hdr: &Hdr, payload: &[u8]) {
        use super::egress_proxy::EgressAction;
        match self.egress.handle_frame(hdr.src_port, payload) {
            EgressAction::Opened => {
                self.egress_hdrs.insert(hdr.src_port, *hdr);
                self.queue_reply(hdr, OP_CREDIT_UPDATE, &[]); // ack the established stream
            }
            EgressAction::Refused => self.queue_reply(hdr, OP_RST, &[]),
            EgressAction::Wrote => {}
        }
    }

    /// Frame an inbound substitution request to the [`SubstitutionBridge`] and map
    /// its action to a vsock control reply. The bridge enforces claim-10 on the
    /// first frame and relays admitted streams to the per-VM endpoint (claims
    /// 12/13); the device owns only the rx framing and the per-stream header.
    fn handle_substitution_request(&mut self, hdr: &Hdr, payload: &[u8]) {
        use super::substitution_bridge::SubstitutionAction;
        match self.substitution.handle_frame(hdr.src_port, payload) {
            // Relayed (admitted) or Pending (buffering the first frame): ack the
            // bytes so the guest's credit recovers, and keep the stream's header
            // for framing replies / a later reset.
            SubstitutionAction::Relayed | SubstitutionAction::Pending => {
                self.substitution_hdrs.insert(hdr.src_port, *hdr);
                self.queue_reply(hdr, OP_CREDIT_UPDATE, &[]);
            }
            // Fail-closed: no endpoint, a claim-10 deny, or a malformed frame →
            // reset the stream (no egress).
            SubstitutionAction::Refused => {
                self.substitution_hdrs.remove(&hdr.src_port);
                self.queue_reply(hdr, OP_RST, &[]);
            }
        }
    }

    /// Drain endpoint replies into the guest's rx queue — the host→guest half of
    /// the substitution relay, called on every timer tick (via [`RunDevice::poll`])
    /// so a `WireResponse` reaches a guest blocked in `recv`. Returns `Some(irq)`
    /// if a reply was delivered into a posted rx buffer.
    pub fn drain_substitution(&mut self) -> Option<u32> {
        if !self.substitution.has_active() {
            return None;
        }
        let drained = self.substitution.drain();
        for (conn_id, bytes) in drained.ready {
            if let Some(h) = self.substitution_hdrs.get(&conn_id).copied() {
                self.queue_reply(&h, OP_RW, &bytes);
            }
        }
        for conn_id in drained.closed {
            self.substitution_hdrs.remove(&conn_id);
        }
        if self.flush_rx() {
            Some(self.irq)
        } else {
            None
        }
    }

    /// Drain admitted egress sockets into the guest's rx queue — the host→guest
    /// half of the proxy, called on every timer tick (via [`RunDevice::poll`]) so
    /// replies + streamed bytes reach the guest even when it is idle in WFI.
    /// Returns `Some(irq)` if a reply was delivered into a posted rx buffer.
    pub fn drain_egress(&mut self) -> Option<u32> {
        if !self.egress.has_active() {
            return None;
        }
        let drained = self.egress.drain();
        for (conn_id, bytes) in drained.ready {
            if let Some(h) = self.egress_hdrs.get(&conn_id).copied() {
                self.queue_reply(&h, OP_RW, &bytes);
            }
        }
        for conn_id in drained.closed {
            self.egress_hdrs.remove(&conn_id);
        }
        // Always attempt to flush: a reply queued on an earlier tick (before the
        // guest posted an rx buffer) must still deliver now. `flush_rx` is a cheap
        // no-op when nothing is pending.
        if self.flush_rx() {
            Some(self.irq)
        } else {
            None
        }
    }

    /// Drive the host→guest agent bridge each tick: open a vsock stream for each new
    /// host connection (`OP_REQUEST` to the guest agent on
    /// [`GUEST_AGENT_PORT`](mvm_guest::vsock::GUEST_AGENT_PORT)) and relay host→guest
    /// request bytes (`OP_RW`). The guest's replies are routed back to the host
    /// socket in [`handle_packet`](Self::handle_packet). Returns `Some(irq)` when a
    /// packet was delivered into a posted rx buffer.
    pub fn drain_agent(&mut self) -> Option<u32> {
        let opened = self.agent.accept_new();
        if !opened.is_empty() {
            agent_dbg(&format!(
                "accepted {} host conn(s) → OP_REQUEST to:{}",
                opened.len(),
                mvm_guest::vsock::GUEST_AGENT_PORT
            ));
        }
        for conn_id in opened {
            self.queue_host_packet(conn_id, mvm_guest::vsock::GUEST_AGENT_PORT, OP_REQUEST, &[]);
        }
        for (conn_id, bytes) in self.agent.drain_host() {
            agent_dbg(&format!(
                "host→guest {} bytes on stream {conn_id}",
                bytes.len()
            ));
            self.queue_host_packet(conn_id, mvm_guest::vsock::GUEST_AGENT_PORT, OP_RW, &bytes);
        }
        if self.flush_rx() {
            Some(self.irq)
        } else {
            None
        }
    }

    /// Frame a host-*initiated* host→guest packet for an agent stream. Unlike
    /// [`queue_reply`](Self::queue_reply) (which swaps an inbound header), this
    /// builds a fresh header for a stream the host opened: `src_port` is the
    /// host-assigned conn id, `dst_port` the guest's listener.
    fn queue_host_packet(&mut self, src_port: u32, dst_port: u32, op: u16, payload: &[u8]) {
        let hdr = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port,
            dst_port,
            len: payload.len() as u32,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: self.fwd_cnt,
        };
        self.pending_rx.push((hdr, payload.to_vec()));
    }

    /// Queue a host→guest reply (src/dst swapped from the inbound header).
    fn queue_reply(&mut self, inbound: &Hdr, op: u16, payload: &[u8]) {
        let reply = Hdr {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: inbound.dst_port,
            dst_port: inbound.src_port,
            len: payload.len() as u32,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: self.fwd_cnt,
        };
        self.pending_rx.push((reply, payload.to_vec()));
    }

    /// Deliver queued packets into guest-posted rx buffers. Returns whether any
    /// were delivered (the guest then needs an interrupt).
    fn flush_rx(&mut self) -> bool {
        let q = self.queues[RX];
        if q.ready == 0 || q.num == 0 || self.pending_rx.is_empty() {
            return false;
        }
        let qsz = q.num as u16;
        let mut last = q.last_avail;
        let mut delivered = false;
        while !self.pending_rx.is_empty() {
            let avail_idx = self.mem.rd_u16(q.avail + 2);
            if last == avail_idx {
                break; // no rx buffer available
            }
            let (hdr, payload) = self.pending_rx.remove(0);
            let slot = last % qsz;
            let head = self.mem.rd_u16(q.avail + 4 + u64::from(slot) * 2);
            // rx buffer: first writable descriptor (vsock posts single buffers).
            let da = q.desc + u64::from(head) * 16;
            let addr = self.mem.rd_u64(da);
            let cap = self.mem.rd_u32(da + 8) as usize;
            let mut bytes = hdr.to_bytes().to_vec();
            bytes.extend_from_slice(&payload);
            let n = bytes.len().min(cap);
            self.mem.write_bytes(addr, &bytes[..n]);
            self.complete(RX, head, n as u32);
            last = last.wrapping_add(1);
            delivered = true;
        }
        self.queues[RX].last_avail = last;
        delivered
    }

    /// Push a completed buffer onto a queue's used ring.
    fn complete(&mut self, q: usize, head: u16, written: u32) {
        let used = self.queues[q].used;
        let qsz = self.queues[q].num as u16;
        let used_idx = self.mem.rd_u16(used + 2);
        let slot = u64::from(used_idx % qsz);
        self.mem.wr_u16(used + 4 + slot * 8, head);
        self.mem.wr_u16(used + 6 + slot * 8, 0);
        self.mem.wr_u16(used + 8 + slot * 8, written as u16);
        self.mem
            .wr_u16(used + 10 + slot * 8, (written >> 16) as u16);
        self.mem.wr_u16(used + 2, used_idx.wrapping_add(1));
        self.interrupt_status |= 1;
    }

    /// The device's SPI INTID — raised by the platform run loop on completion.
    pub fn irq(&self) -> u32 {
        self.irq
    }
}

/// Debug trace for the host↔guest agent relay, gated on `MVM_HVF_AGENT_DEBUG` so
/// it is silent in normal operation. Goes to stderr (the supervisor inherits it).
fn agent_dbg(msg: &str) {
    if let Some(path) = std::env::var_os("MVM_HVF_AGENT_DEBUG") {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "[agent-bridge] {msg}");
        }
    }
}

fn set_lo(v: &mut u64, lo: u32) {
    *v = (*v & !0xffff_ffff) | u64::from(lo);
}
fn set_hi(v: &mut u64, hi: u32) {
    *v = (*v & 0xffff_ffff) | (u64::from(hi) << 32);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> VirtioVsock {
        let mut ram = vec![0u8; 0x1000];
        // SAFETY: leaked for the test.
        unsafe { VirtioVsock::new(0x0a00_0200, 49, ram.as_mut_ptr(), 0x4000_0000, ram.len()) }
    }

    #[test]
    fn identity_and_config() {
        let d = dev();
        assert_eq!(d.read(R_MAGIC) as u32, VIRTIO_MAGIC);
        assert_eq!(d.read(R_DEVICE_ID) as u32, VIRTIO_ID_VSOCK);
        assert_eq!(d.read(R_CONFIG) as u32, GUEST_CID as u32);
    }

    #[test]
    fn hdr_round_trips() {
        let h = Hdr {
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
        let h2 = Hdr::from_bytes(&b);
        assert_eq!(h2.src_port, 1234);
        assert_eq!(h2.dst_port, 5678);
        assert_eq!(h2.op, OP_RW);
        assert_eq!(h2.len, 9);
        assert_eq!(h2.buf_alloc, 4096);
    }

    #[test]
    fn request_queues_a_response_and_rw_is_captured() {
        let mut d = dev();
        let req = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1000,
            dst_port: 2000,
            op: OP_REQUEST,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(req, &[]);
        assert_eq!(d.pending_rx.len(), 1);
        assert_eq!(d.pending_rx[0].0.op, OP_RESPONSE);
        assert_eq!(d.pending_rx[0].0.src_port, 2000); // swapped
        assert_eq!(d.pending_rx[0].0.dst_port, 1000);

        let rw = Hdr {
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
        assert_eq!(d.received, b"hello");
    }

    /// Build a `(gate-admitting-the-host, framed-WireRequest)` pair for the
    /// substitution device tests: the gate self-pins `host:port`, the frame targets
    /// `https://<host>/v1`.
    #[cfg(test)]
    fn subst_gate_and_frame(
        host: &str,
        port: u16,
    ) -> (crate::vmm::egress_gate::EgressGate, Vec<u8>) {
        use base64::Engine;
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::substitution_wire::WireRequest;

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            host,
            vec!["93.184.216.34".parse().unwrap()],
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
        ));
        let gate = crate::vmm::egress_gate::EgressGate::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort {
                host: host.into(),
                port,
            }]),
            &pins,
            "2026-01-01T00:00:00Z",
        );
        let req = WireRequest {
            method: "POST".into(),
            url: format!("https://{host}/v1"),
            headers: vec![("authorization".into(), "Bearer mvm-secret-abc".into())],
            body_b64: base64::engine::general_purpose::STANDARD.encode(b"{}"),
        };
        let body = serde_json::to_vec(&req).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        (gate, frame)
    }

    /// With a substitution endpoint wired, a guest OP_RW to `EGRESS_PORT` carrying a
    /// WireRequest to an *admitted* destination is relayed to the endpoint (not
    /// captured as raw bytes, not handed to the raw-TCP egress proxy), and the
    /// endpoint's reply frames back to the guest as OP_RW on the same stream.
    #[test]
    fn egress_port_routes_admitted_request_to_substitution_endpoint() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");

        // Mock endpoint: read the relayed frame, reply "REPLY:" + it.
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let n = c.read(&mut buf).unwrap();
            let mut reply = b"REPLY:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            c.write_all(&reply).unwrap();
        });

        let (gate, frame) = subst_gate_and_frame("api.openai.com", 443);
        let mut d = dev();
        d.set_substitution_endpoint(&sock);
        d.set_substitution_gate(gate);

        let rw = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1000,
            dst_port: mvm_guest::vsock::EGRESS_PORT,
            len: frame.len() as u32,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(rw, &frame);

        // Routed to the endpoint, NOT the raw capture buffer; the stream is acked.
        assert!(
            d.received.is_empty(),
            "substitution bytes must not hit the capture path"
        );
        assert!(
            d.pending_rx.iter().any(|(h, _)| h.op == OP_CREDIT_UPDATE),
            "relayed stream must be acked"
        );

        // host → guest: poll until the endpoint's reply frames back as OP_RW.
        let mut reply = None;
        for _ in 0..200 {
            let _ = d.drain_substitution();
            if let Some((h, payload)) = d
                .pending_rx
                .iter()
                .find(|(h, _)| h.op == OP_RW && h.dst_port == 1000)
            {
                reply = Some((*h, payload.clone()));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let (h, payload) = reply.expect("endpoint reply framed back to the guest");
        assert_eq!(h.src_port, mvm_guest::vsock::EGRESS_PORT); // swapped from inbound
        assert!(
            payload.starts_with(b"REPLY:"),
            "reply must be the endpoint's echoed frame"
        );
        server.join().unwrap();
    }

    /// Claim-10 at the device: a WireRequest to a destination the gate does NOT
    /// admit is reset (OP_RST), never relayed — the endpoint (here a live socket
    /// that would accept) is never contacted, so nothing reaches the wire.
    #[test]
    fn egress_port_resets_unadmitted_substitution_request() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("subst.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let contacted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let contacted_w = contacted.clone();
        let server = std::thread::spawn(move || {
            // If the bridge wrongly relayed, the endpoint would accept a connection.
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            for _ in 0..40 {
                if let Ok((mut c, _)) = listener.accept() {
                    let mut b = [0u8; 8];
                    let _ = c.read(&mut b);
                    contacted_w.store(true, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });

        // Gate admits api.openai.com; the request targets a different host.
        let (gate, _admitted) = subst_gate_and_frame("api.openai.com", 443);
        let (_g2, denied_frame) = subst_gate_and_frame("evil.example.com", 443);
        let mut d = dev();
        d.set_substitution_endpoint(&sock);
        d.set_substitution_gate(gate);

        let rw = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 1234,
            dst_port: mvm_guest::vsock::EGRESS_PORT,
            len: denied_frame.len() as u32,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(rw, &denied_frame);

        // The stream was reset, not acked/relayed.
        assert!(
            d.pending_rx.iter().any(|(h, _)| h.op == OP_RST),
            "a claim-10-denied request must be reset"
        );
        assert!(d.received.is_empty());
        let _ = server.join();
        assert!(
            !contacted.load(std::sync::atomic::Ordering::Relaxed),
            "the secrets endpoint must not be contacted for a denied destination"
        );
    }

    /// Without a substitution endpoint, `EGRESS_PORT` keeps the legacy raw-TCP
    /// egress path: a connect target that no gate admits is refused (default-deny),
    /// and nothing is relayed to a substitution endpoint.
    #[test]
    fn egress_port_uses_legacy_egress_proxy_without_endpoint() {
        let mut d = dev();
        // No substitution endpoint, no egress gate → default-deny.
        let rw = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 2000,
            dst_port: mvm_guest::vsock::EGRESS_PORT,
            len: 16,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(rw, b"93.184.216.34:80");
        // The legacy egress proxy refused it (recorded as denied), and it was not
        // captured as raw bytes.
        assert!(d.received.is_empty());
        assert_eq!(d.egress_denied(), &["93.184.216.34:80".to_string()]);
    }

    #[test]
    fn host_agent_connection_frames_op_request_and_routes_replies() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let mut d = dev();
        d.set_agent_socket(&sock).unwrap();

        // A host RPC client connects to the agent socket.
        let _client = std::os::unix::net::UnixStream::connect(&sock).unwrap();

        // drain_agent accepts it and frames an OP_REQUEST to the guest agent port.
        let mut hdr = None;
        for _ in 0..200 {
            let _ = d.drain_agent();
            if let Some((h, _)) = d.pending_rx.first() {
                hdr = Some(*h);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let hdr = hdr.expect("OP_REQUEST framed for the host connection");
        assert_eq!(hdr.op, OP_REQUEST);
        assert_eq!(hdr.dst_port, mvm_guest::vsock::GUEST_AGENT_PORT);
        assert_eq!(hdr.src_cid, HOST_CID);
        assert_eq!(hdr.dst_cid, GUEST_CID);
        // The host-assigned src_port is now an agent stream, so a guest reply
        // addressed to it routes to the bridge rather than the capture path.
        let conn_id = hdr.src_port;
        assert!(d.agent.is_agent_stream(conn_id));

        let reply = Hdr {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: mvm_guest::vsock::GUEST_AGENT_PORT,
            dst_port: conn_id,
            len: 5,
            op: OP_RW,
            typ: TYPE_STREAM,
            ..Default::default()
        };
        d.handle_packet(reply, b"world");
        // Routed to the bridge (host socket), NOT appended to the guest-capture buf.
        assert!(
            d.received.is_empty(),
            "agent-stream bytes must not hit the capture path"
        );
    }
}
