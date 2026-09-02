use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use super::agent_bridge::AgentBridge;
use super::host_dial_bridge::HostDialBridge;
use super::substitution_bridge::{
    EgressBudget, EndpointRelayAction, GuestEndpointRelay, READ_CHUNK, SubstitutionBridge,
};
use super::vsock_transport::{
    OP_CREDIT_REQUEST, OP_CREDIT_UPDATE, OP_REQUEST, OP_RESPONSE, OP_RST, OP_RW, OP_SHUTDOWN,
    VsockHdr, VsockTransportCore,
};

pub(crate) struct VsockLifecycleState {
    pub(crate) received: Vec<u8>,
    pub(crate) workload_exit_code: Option<i32>,
    pub(crate) exit_stop: Option<&'static AtomicBool>,
}

impl VsockLifecycleState {
    pub(crate) fn new() -> Self {
        Self {
            received: Vec::new(),
            workload_exit_code: None,
            exit_stop: None,
        }
    }
}

pub(crate) struct VsockHandlerContext<'a> {
    transport: &'a mut VsockTransportCore,
    lifecycle: &'a mut VsockLifecycleState,
}

impl<'a> VsockHandlerContext<'a> {
    pub(crate) fn new(
        transport: &'a mut VsockTransportCore,
        lifecycle: &'a mut VsockLifecycleState,
    ) -> Self {
        Self {
            transport,
            lifecycle,
        }
    }

    pub(crate) fn try_add_recv(&mut self, inbound: &VsockHdr, n: u32) -> bool {
        self.transport.try_add_recv(inbound, n)
    }

    pub(crate) fn remove_recv(&mut self, host_port: u32, guest_port: u32) {
        self.transport.remove_recv(host_port, guest_port);
        self.transport.remove_tx_credit(host_port, guest_port);
    }

    pub(crate) fn tx_credit_available(&self, host_port: u32, guest_port: u32) -> u32 {
        self.transport.tx_credit_available(host_port, guest_port)
    }

    pub(crate) fn consume_tx_credit(&mut self, host_port: u32, guest_port: u32, n: u32) {
        self.transport.consume_tx_credit(host_port, guest_port, n);
    }

    pub(crate) fn evict_idle_connections(&mut self) -> Vec<(u32, u32)> {
        self.transport
            .evict_idle_connections()
            .into_iter()
            .map(|key| (key.host_port, key.guest_port))
            .collect()
    }

    pub(crate) fn queue_reply(&mut self, inbound: &VsockHdr, op: u16, payload: &[u8]) {
        self.transport.queue_reply(inbound, op, payload);
    }

    pub(crate) fn queue_host_packet(
        &mut self,
        src_port: u32,
        dst_port: u32,
        op: u16,
        payload: &[u8],
    ) {
        self.transport
            .queue_host_packet(src_port, dst_port, op, payload);
    }

    pub(crate) fn flush_rx(&mut self) -> bool {
        self.transport.flush_rx()
    }

    pub(crate) fn rx_queue_state(&self) -> (u32, u32, usize) {
        let queue = self.transport.queues[0];
        (queue.ready, queue.num, self.transport.pending_rx.len())
    }

    pub(crate) fn record_received(&mut self, payload: &[u8]) {
        self.lifecycle.received.extend_from_slice(payload);
    }

    pub(crate) fn record_workload_exit(&mut self, payload: &[u8]) {
        self.lifecycle.workload_exit_code = Some(if payload.len() >= 4 {
            i32::from_le_bytes(payload[..4].try_into().expect("i32 exit code"))
        } else {
            0
        });
        if let Some(stop) = self.lifecycle.exit_stop {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

pub(crate) trait GuestPortHandler: Any + Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]);
    fn has_host_binding(&self) -> bool {
        false
    }
    fn drain(&mut self, _ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        None
    }
    fn cancel(&mut self) {}
    fn poll_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
}

pub(crate) trait HostInitiatedHandler: Any + Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn accepts_stream(&self, conn_id: u32) -> bool;
    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]);
    fn has_host_binding(&self) -> bool {
        false
    }
    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32>;
    fn cancel(&mut self) {}
    fn poll_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
}

pub(crate) struct VsockHandlerRegistry {
    guest_ports: BTreeMap<u32, Box<dyn GuestPortHandler>>,
    host_initiated: Vec<Box<dyn HostInitiatedHandler>>,
}

impl VsockHandlerRegistry {
    pub(crate) fn new() -> Self {
        let mut guest_ports: BTreeMap<u32, Box<dyn GuestPortHandler>> = BTreeMap::new();
        guest_ports.insert(
            mvm_agentd::vsock::WORKLOAD_EXIT_PORT,
            Box::new(WorkloadExitHandler::new()),
        );
        let egress_budget = EgressBudget::new();
        guest_ports.insert(
            mvm_agentd::vsock::EGRESS_PORT,
            Box::new(StreamRelayHandler::with_budget(
                mvm_agentd::vsock::EGRESS_PORT,
                egress_budget.clone(),
            )),
        );
        guest_ports.insert(
            mvm_agentd::vsock::BROKER_PORT,
            Box::new(StreamRelayHandler::with_budget(
                mvm_agentd::vsock::BROKER_PORT,
                egress_budget,
            )),
        );

        let host_initiated: Vec<Box<dyn HostInitiatedHandler>> = vec![
            Box::new(AgentVsockHandler::new()),
            Box::new(HostDialVsockHandler::new()),
        ];

        Self {
            guest_ports,
            host_initiated,
        }
    }

    pub(crate) fn set_agent_socket(&mut self, path: &Path) -> std::io::Result<()> {
        self.host_handler_mut::<AgentVsockHandler>()
            .expect("agent handler present")
            .bridge
            .bind(path)
    }

    pub(crate) fn set_agent_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.host_handler_mut::<AgentVsockHandler>()
            .expect("agent handler present")
            .bridge
            .set_activity(counter);
    }

    pub(crate) fn set_network_endpoint(&mut self, path: &Path) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_agentd::vsock::EGRESS_PORT)
            .expect("egress handler present")
            .bridge
            .set_endpoint(path);
    }

    /// Drop the workload egress ceilings for a trusted-builder VM. Both ports
    /// keep sharing one budget.
    pub(crate) fn set_trusted_builder_egress(&mut self) {
        let budget = EgressBudget::trusted_builder();
        for port in [
            mvm_agentd::vsock::EGRESS_PORT,
            mvm_agentd::vsock::BROKER_PORT,
        ] {
            self.guest_handler_mut::<StreamRelayHandler>(port)
                .expect("relay handler present")
                .bridge
                .set_budget(budget.clone());
        }
    }

    pub(crate) fn set_substitution_activity(
        &mut self,
        counter: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_agentd::vsock::EGRESS_PORT)
            .expect("egress handler present")
            .bridge
            .set_activity(counter);
    }

    pub(crate) fn set_broker_endpoint(&mut self, path: &Path) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_agentd::vsock::BROKER_PORT)
            .expect("broker handler present")
            .bridge
            .set_endpoint(path);
    }

    pub(crate) fn set_broker_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_agentd::vsock::BROKER_PORT)
            .expect("broker handler present")
            .bridge
            .set_activity(counter);
    }

    pub(crate) fn set_host_dial_sockets<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a Path)>,
    ) -> std::io::Result<()> {
        self.host_handler_mut::<HostDialVsockHandler>()
            .expect("console handler present")
            .bridge
            .bind_ports(ports)
    }

    pub(crate) fn set_long_lived_host_dial_ports(&mut self, ports: impl IntoIterator<Item = u32>) {
        self.host_handler_mut::<HostDialVsockHandler>()
            .expect("console handler present")
            .bridge
            .set_long_lived_ports(ports);
    }

    pub(crate) fn set_host_dial_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.host_handler_mut::<HostDialVsockHandler>()
            .expect("console handler present")
            .bridge
            .set_activity(counter);
    }

    pub(crate) fn capture_workload_exit(
        &mut self,
        stop: &'static AtomicBool,
    ) -> &'static AtomicBool {
        stop
    }

    pub(crate) fn dispatch_packet(
        &mut self,
        ctx: &mut VsockHandlerContext<'_>,
        hdr: VsockHdr,
        payload: &[u8],
    ) -> bool {
        if let Some(handler) = self
            .host_initiated
            .iter_mut()
            .find(|handler| handler.accepts_stream(hdr.dst_port))
        {
            handler.on_packet(ctx, hdr, payload);
            return true;
        }

        if let Some(handler) = self.guest_ports.get_mut(&hdr.dst_port) {
            handler.on_packet(ctx, hdr, payload);
            return true;
        }

        false
    }

    pub(crate) fn service_host_io(&mut self, ctx: &mut VsockHandlerContext<'_>) -> bool {
        let mut delivered = false;
        for handler in &mut self.host_initiated {
            delivered |= handler.drain(ctx).is_some();
        }
        for handler in self.guest_ports.values_mut() {
            delivered |= handler.drain(ctx).is_some();
        }
        for (host_port, guest_port) in ctx.evict_idle_connections() {
            ctx.queue_host_packet(host_port, guest_port, OP_RST, &[]);
            delivered = true;
        }
        delivered
    }

    pub(crate) fn cancel(&mut self) {
        for handler in &mut self.host_initiated {
            handler.cancel();
        }
        for handler in self.guest_ports.values_mut() {
            handler.cancel();
        }
    }

    pub(crate) fn clear_host_bindings(&mut self) {
        *self = Self::new();
    }

    pub(crate) fn poll_fds(&self) -> Vec<RawFd> {
        let mut fds = Vec::new();
        for handler in &self.host_initiated {
            fds.extend(handler.poll_fds());
        }
        for handler in self.guest_ports.values() {
            fds.extend(handler.poll_fds());
        }
        fds
    }

    pub(crate) fn has_host_bindings(&self) -> bool {
        self.host_initiated
            .iter()
            .any(|handler| handler.has_host_binding())
            || self
                .guest_ports
                .values()
                .any(|handler| handler.has_host_binding())
    }

    #[cfg(test)]
    pub(crate) fn is_agent_stream(&mut self, conn_id: u32) -> bool {
        self.host_handler_mut::<AgentVsockHandler>()
            .expect("agent handler present")
            .bridge
            .is_agent_stream(conn_id)
    }

    #[cfg(test)]
    pub(crate) fn is_host_dial_stream(&mut self, conn_id: u32) -> bool {
        self.host_handler_mut::<HostDialVsockHandler>()
            .expect("console handler present")
            .bridge
            .is_host_dial_stream(conn_id)
    }

    fn guest_handler_mut<T: Any>(&mut self, port: u32) -> Option<&mut T> {
        self.guest_ports
            .get_mut(&port)
            .and_then(|handler| handler.as_any_mut().downcast_mut::<T>())
    }

    fn host_handler_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.host_initiated
            .iter_mut()
            .find_map(|handler| handler.as_any_mut().downcast_mut::<T>())
    }
}

struct WorkloadExitHandler {}

impl WorkloadExitHandler {
    fn new() -> Self {
        Self {}
    }
}

impl GuestPortHandler for WorkloadExitHandler {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            OP_REQUEST => ctx.queue_reply(&hdr, OP_RESPONSE, &[]),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                ctx.record_workload_exit(&payload[..n]);
                if ctx.try_add_recv(&hdr, n as u32) {
                    ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
                } else {
                    ctx.queue_reply(&hdr, OP_RST, &[]);
                }
            }
            OP_CREDIT_REQUEST => ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]),
            OP_SHUTDOWN => {
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }
}

struct StreamRelayHandler {
    guest_port: u32,
    bridge: SubstitutionBridge,
    headers: HashMap<u32, VsockHdr>,
    tx_pending: HashMap<u32, Vec<u8>>,
}

impl StreamRelayHandler {
    fn with_budget(guest_port: u32, budget: EgressBudget) -> Self {
        Self {
            guest_port,
            bridge: SubstitutionBridge::with_budget(budget),
            headers: HashMap::new(),
            tx_pending: HashMap::new(),
        }
    }

    fn flush_tx_pending(&mut self, ctx: &mut VsockHandlerContext<'_>, conn_id: u32) {
        if let Some(bytes) = self.tx_pending.remove(&conn_id) {
            if let Some(hdr) = self.headers.get(&conn_id).copied() {
                self.queue_up_to_credit(ctx, conn_id, hdr, bytes);
            } else {
                // No remembered header yet; keep the bytes buffered.
                self.tx_pending.insert(conn_id, bytes);
            }
        }
    }

    fn queue_up_to_credit(
        &mut self,
        ctx: &mut VsockHandlerContext<'_>,
        conn_id: u32,
        hdr: VsockHdr,
        bytes: Vec<u8>,
    ) {
        let avail = ctx.tx_credit_available(self.guest_port, conn_id) as usize;
        if avail == 0 {
            self.tx_pending.insert(conn_id, bytes);
            return;
        }
        let send_len = bytes.len().min(avail);
        ctx.queue_reply(&hdr, OP_RW, &bytes[..send_len]);
        ctx.consume_tx_credit(self.guest_port, conn_id, send_len as u32);
        if send_len < bytes.len() {
            self.tx_pending.insert(conn_id, bytes[send_len..].to_vec());
        }
    }
}

impl GuestPortHandler for StreamRelayHandler {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn has_host_binding(&self) -> bool {
        self.bridge.has_binding()
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            // Open the endpoint side now, not on the guest's first payload.
            // The endpoint speaks first here — a FlowMux session opens with the
            // host's `SessionHello` — so a guest that connects goes straight
            // into a read. Dialing lazily leaves nothing on the host end to
            // send it, and both sides wait forever. Remembering the header is
            // the other half: `drain` can only push endpoint bytes at a
            // connection it has a header for.
            OP_REQUEST => {
                if self.bridge.open_connection(hdr.src_port) {
                    self.headers.insert(hdr.src_port, hdr);
                    ctx.queue_reply(&hdr, OP_RESPONSE, &[]);
                } else {
                    self.headers.remove(&hdr.src_port);
                    ctx.queue_reply(&hdr, OP_RST, &[]);
                }
            }
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                if !ctx.try_add_recv(&hdr, n as u32) {
                    self.bridge.close_connection(hdr.src_port);
                    self.headers.remove(&hdr.src_port);
                    ctx.queue_reply(&hdr, OP_RST, &[]);
                    return;
                }
                match self.bridge.relay_guest_bytes(hdr.src_port, &payload[..n]) {
                    EndpointRelayAction::Relayed => {
                        self.headers.insert(hdr.src_port, hdr);
                        ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
                    }
                    EndpointRelayAction::Refused => {
                        self.bridge.close_connection(hdr.src_port);
                        ctx.remove_recv(hdr.dst_port, hdr.src_port);
                        self.headers.remove(&hdr.src_port);
                        ctx.queue_reply(&hdr, OP_RST, &[]);
                    }
                }
            }
            OP_CREDIT_REQUEST => ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]),
            OP_SHUTDOWN | OP_RST => {
                if self.headers.remove(&hdr.src_port).is_some() {
                    self.bridge.close_connection(hdr.src_port);
                }
                self.tx_pending.remove(&hdr.src_port);
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }

    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        if !self.bridge.is_active() && self.tx_pending.is_empty() {
            return None;
        }

        // First, try to push any buffered egress bytes that previously lacked
        // guest receive credit. This lets progress resume as soon as the guest
        // sends a credit update, even if the endpoint has no new data yet.
        let pending_conn_ids: Vec<u32> = self.tx_pending.keys().copied().collect();
        for conn_id in pending_conn_ids {
            self.flush_tx_pending(ctx, conn_id);
        }

        // Only pull more bytes from the endpoint when we have credit for them.
        // This keeps the in-memory pending queue bounded and preserves stream
        // ordering for each connection.
        let guest_port = self.guest_port;
        let tx_pending = &self.tx_pending;
        let mut limit = |conn_id: u32| -> usize {
            if tx_pending.contains_key(&conn_id) {
                return 0;
            }
            let avail = ctx.tx_credit_available(guest_port, conn_id) as usize;
            READ_CHUNK.min(avail)
        };
        let drained = self.bridge.drain_endpoint_bytes_limited(&mut limit);
        for (conn_id, mut bytes) in drained.ready {
            if let Some(pending) = self.tx_pending.remove(&conn_id) {
                let mut combined = pending;
                combined.append(&mut bytes);
                bytes = combined;
            }
            if let Some(hdr) = self.headers.get(&conn_id).copied() {
                self.queue_up_to_credit(ctx, conn_id, hdr, bytes);
            }
        }
        for conn_id in drained.closed {
            self.flush_tx_pending(ctx, conn_id);
            self.tx_pending.remove(&conn_id);
            if let Some(hdr) = self.headers.remove(&conn_id) {
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_SHUTDOWN, &[]);
                if let Some((h, _)) = ctx.transport.pending_rx.back_mut() {
                    h.flags = 3;
                }
            }
        }
        if ctx.flush_rx() { Some(0) } else { None }
    }

    fn cancel(&mut self) {
        self.bridge.close_all();
        self.headers.clear();
    }

    fn poll_fds(&self) -> Vec<RawFd> {
        self.bridge.poll_fds()
    }
}

struct AgentVsockHandler {
    bridge: AgentBridge,
}

impl AgentVsockHandler {
    fn new() -> Self {
        Self {
            bridge: AgentBridge::new(),
        }
    }
}

impl HostInitiatedHandler for AgentVsockHandler {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn has_host_binding(&self) -> bool {
        self.bridge.has_binding()
    }

    fn accepts_stream(&self, conn_id: u32) -> bool {
        self.bridge.is_agent_stream(conn_id)
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            OP_RESPONSE => self.bridge.on_established(hdr.dst_port),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                if !ctx.try_add_recv(&hdr, n as u32) {
                    self.bridge.close(hdr.dst_port);
                    ctx.queue_reply(&hdr, OP_RST, &[]);
                    return;
                }
                self.bridge.write_to_host(hdr.dst_port, &payload[..n]);
                ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
            }
            OP_SHUTDOWN | OP_RST => {
                self.bridge.close(hdr.dst_port);
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }

    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        let opened = self.bridge.accept_new();
        if !opened.is_empty() {
            agent_dbg(&format!(
                "accepted {} host conn(s) → OP_REQUEST to:{}",
                opened.len(),
                mvm_agentd::vsock::GUEST_AGENT_PORT
            ));
        }
        for conn_id in opened {
            ctx.queue_host_packet(
                conn_id,
                mvm_agentd::vsock::GUEST_AGENT_PORT,
                OP_REQUEST,
                &[],
            );
        }
        for (conn_id, bytes) in self.bridge.drain_host() {
            agent_dbg(&format!(
                "host→guest {} bytes on stream {conn_id}",
                bytes.len()
            ));
            ctx.queue_host_packet(conn_id, mvm_agentd::vsock::GUEST_AGENT_PORT, OP_RW, &bytes);
        }
        for conn_id in self.bridge.take_host_closed() {
            agent_dbg(&format!("host closed stream {conn_id} → OP_RST to guest"));
            ctx.remove_recv(conn_id, mvm_agentd::vsock::GUEST_AGENT_PORT);
            ctx.queue_host_packet(conn_id, mvm_agentd::vsock::GUEST_AGENT_PORT, OP_RST, &[]);
        }
        let delivered = ctx.flush_rx();
        let (ready, size, pending) = ctx.rx_queue_state();
        agent_dbg(&format!(
            "agent rx delivered={delivered} ready={ready} size={size} pending={pending}"
        ));
        if delivered { Some(0) } else { None }
    }

    fn cancel(&mut self) {
        self.bridge.close_all();
    }

    fn poll_fds(&self) -> Vec<RawFd> {
        self.bridge.poll_fds()
    }
}

struct HostDialVsockHandler {
    bridge: HostDialBridge,
}

impl HostDialVsockHandler {
    fn new() -> Self {
        Self {
            bridge: HostDialBridge::new(),
        }
    }
}

impl HostInitiatedHandler for HostDialVsockHandler {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn has_host_binding(&self) -> bool {
        self.bridge.has_binding()
    }

    fn accepts_stream(&self, conn_id: u32) -> bool {
        self.bridge.is_host_dial_stream(conn_id)
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            OP_RESPONSE => self.bridge.on_established(hdr.dst_port),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                if !ctx.try_add_recv(&hdr, n as u32) {
                    self.bridge.close(hdr.dst_port);
                    ctx.queue_reply(&hdr, OP_RST, &[]);
                    return;
                }
                self.bridge.write_to_host(hdr.dst_port, &payload[..n]);
                ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
            }
            OP_SHUTDOWN | OP_RST => {
                self.bridge.close(hdr.dst_port);
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }

    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        for (conn_id, guest_port) in self.bridge.accept_new() {
            ctx.queue_host_packet(conn_id, guest_port, OP_REQUEST, &[]);
        }
        for (conn_id, guest_port, bytes) in self.bridge.drain_host() {
            ctx.queue_host_packet(conn_id, guest_port, OP_RW, &bytes);
        }
        for (conn_id, guest_port) in self.bridge.take_host_closed() {
            ctx.remove_recv(conn_id, guest_port);
            ctx.queue_host_packet(conn_id, guest_port, OP_RST, &[]);
        }
        if ctx.flush_rx() { Some(0) } else { None }
    }

    fn cancel(&mut self) {
        self.bridge.close_all();
    }

    fn poll_fds(&self) -> Vec<RawFd> {
        self.bridge.poll_fds()
    }
}

/// Resolved `MVM_HVF_AGENT_DEBUG` trace-file path, read from the environment once
/// and cached — the per-packet drain path must not take the process-global env
/// lock on every call.
fn agent_debug_path() -> Option<&'static Path> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| std::env::var_os("MVM_HVF_AGENT_DEBUG").map(PathBuf::from))
        .as_deref()
}

fn agent_dbg(msg: &str) {
    let Some(path) = agent_debug_path() else {
        return;
    };
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "[agent-bridge] {msg}");
    }
}
