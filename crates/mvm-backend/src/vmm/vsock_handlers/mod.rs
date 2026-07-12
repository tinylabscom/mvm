use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::agent_bridge::AgentBridge;
use super::console_bridge::ConsoleBridge;
use super::substitution_bridge::{EndpointRelayAction, GuestEndpointRelay, SubstitutionBridge};
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

    pub(crate) fn add_recv(&mut self, inbound: &VsockHdr, n: u32) {
        self.transport.add_recv(inbound, n);
    }

    pub(crate) fn remove_recv(&mut self, host_port: u32, guest_port: u32) {
        self.transport.remove_recv(host_port, guest_port);
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
    fn drain(&mut self, _ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        None
    }
    fn poll_fds(&self) -> Vec<RawFd> {
        Vec::new()
    }
}

pub(crate) trait HostInitiatedHandler: Any + Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn accepts_stream(&self, conn_id: u32) -> bool;
    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]);
    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32>;
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
            mvm_guest::vsock::WORKLOAD_EXIT_PORT,
            Box::new(WorkloadExitHandler::new()),
        );
        guest_ports.insert(
            mvm_guest::vsock::EGRESS_PORT,
            Box::new(StreamRelayHandler::new(mvm_guest::vsock::EGRESS_PORT)),
        );
        guest_ports.insert(
            mvm_guest::vsock::BROKER_PORT,
            Box::new(StreamRelayHandler::new(mvm_guest::vsock::BROKER_PORT)),
        );

        let host_initiated: Vec<Box<dyn HostInitiatedHandler>> = vec![
            Box::new(AgentVsockHandler::new()),
            Box::new(ConsoleVsockHandler::new()),
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

    pub(crate) fn set_substitution_endpoint(&mut self, path: &Path) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_guest::vsock::EGRESS_PORT)
            .expect("egress handler present")
            .bridge
            .set_endpoint(path);
    }

    pub(crate) fn set_substitution_activity(
        &mut self,
        counter: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_guest::vsock::EGRESS_PORT)
            .expect("egress handler present")
            .bridge
            .set_activity(counter);
    }

    pub(crate) fn set_broker_endpoint(&mut self, path: &Path) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_guest::vsock::BROKER_PORT)
            .expect("broker handler present")
            .bridge
            .set_endpoint(path);
    }

    pub(crate) fn set_broker_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.guest_handler_mut::<StreamRelayHandler>(mvm_guest::vsock::BROKER_PORT)
            .expect("broker handler present")
            .bridge
            .set_activity(counter);
    }

    pub(crate) fn set_console_sockets<'a>(
        &mut self,
        ports: impl IntoIterator<Item = (u32, &'a Path)>,
    ) -> std::io::Result<()> {
        self.host_handler_mut::<ConsoleVsockHandler>()
            .expect("console handler present")
            .bridge
            .bind_ports(ports)
    }

    pub(crate) fn set_console_activity(&mut self, counter: Arc<std::sync::atomic::AtomicUsize>) {
        self.host_handler_mut::<ConsoleVsockHandler>()
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
        delivered
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

    #[cfg(test)]
    pub(crate) fn is_agent_stream(&mut self, conn_id: u32) -> bool {
        self.host_handler_mut::<AgentVsockHandler>()
            .expect("agent handler present")
            .bridge
            .is_agent_stream(conn_id)
    }

    #[cfg(test)]
    pub(crate) fn is_console_stream(&mut self, conn_id: u32) -> bool {
        self.host_handler_mut::<ConsoleVsockHandler>()
            .expect("console handler present")
            .bridge
            .is_console_stream(conn_id)
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
                ctx.add_recv(&hdr, n as u32);
                ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
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
    bridge: SubstitutionBridge,
    headers: HashMap<u32, VsockHdr>,
}

impl StreamRelayHandler {
    fn new(_guest_port: u32) -> Self {
        Self {
            bridge: SubstitutionBridge::new(),
            headers: HashMap::new(),
        }
    }
}

impl GuestPortHandler for StreamRelayHandler {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            OP_REQUEST => ctx.queue_reply(&hdr, OP_RESPONSE, &[]),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                match self.bridge.relay_guest_bytes(hdr.src_port, &payload[..n]) {
                    EndpointRelayAction::Relayed => {
                        self.headers.insert(hdr.src_port, hdr);
                        ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]);
                    }
                    EndpointRelayAction::Refused => {
                        self.headers.remove(&hdr.src_port);
                        ctx.queue_reply(&hdr, OP_RST, &[]);
                    }
                }
                ctx.add_recv(&hdr, n as u32);
            }
            OP_CREDIT_REQUEST => ctx.queue_reply(&hdr, OP_CREDIT_UPDATE, &[]),
            OP_SHUTDOWN => {
                if self.headers.remove(&hdr.src_port).is_some() {
                    self.bridge.close_connection(hdr.src_port);
                }
                ctx.remove_recv(hdr.dst_port, hdr.src_port);
                ctx.queue_reply(&hdr, OP_RST, &[]);
            }
            _ => {}
        }
    }

    fn drain(&mut self, ctx: &mut VsockHandlerContext<'_>) -> Option<u32> {
        if !self.bridge.is_active() {
            return None;
        }
        let drained = self.bridge.drain_endpoint_bytes();
        for (conn_id, bytes) in drained.ready {
            if let Some(hdr) = self.headers.get(&conn_id).copied() {
                ctx.queue_reply(&hdr, OP_RW, &bytes);
            }
        }
        for conn_id in drained.closed {
            self.headers.remove(&conn_id);
        }
        if ctx.flush_rx() { Some(0) } else { None }
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

    fn accepts_stream(&self, conn_id: u32) -> bool {
        self.bridge.is_agent_stream(conn_id)
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            OP_RESPONSE => self.bridge.on_established(hdr.dst_port),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                self.bridge.write_to_host(hdr.dst_port, &payload[..n]);
                ctx.add_recv(&hdr, n as u32);
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
                mvm_guest::vsock::GUEST_AGENT_PORT
            ));
        }
        for conn_id in opened {
            ctx.queue_host_packet(conn_id, mvm_guest::vsock::GUEST_AGENT_PORT, OP_REQUEST, &[]);
        }
        for (conn_id, bytes) in self.bridge.drain_host() {
            agent_dbg(&format!(
                "host→guest {} bytes on stream {conn_id}",
                bytes.len()
            ));
            ctx.queue_host_packet(conn_id, mvm_guest::vsock::GUEST_AGENT_PORT, OP_RW, &bytes);
        }
        for conn_id in self.bridge.take_host_closed() {
            agent_dbg(&format!("host closed stream {conn_id} → OP_RST to guest"));
            ctx.queue_host_packet(conn_id, mvm_guest::vsock::GUEST_AGENT_PORT, OP_RST, &[]);
        }
        if ctx.flush_rx() { Some(0) } else { None }
    }

    fn poll_fds(&self) -> Vec<RawFd> {
        self.bridge.poll_fds()
    }
}

struct ConsoleVsockHandler {
    bridge: ConsoleBridge,
}

impl ConsoleVsockHandler {
    fn new() -> Self {
        Self {
            bridge: ConsoleBridge::new(),
        }
    }
}

impl HostInitiatedHandler for ConsoleVsockHandler {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn accepts_stream(&self, conn_id: u32) -> bool {
        self.bridge.is_console_stream(conn_id)
    }

    fn on_packet(&mut self, ctx: &mut VsockHandlerContext<'_>, hdr: VsockHdr, payload: &[u8]) {
        match hdr.op {
            OP_RESPONSE => self.bridge.on_established(hdr.dst_port),
            OP_RW => {
                let n = (hdr.len as usize).min(payload.len());
                self.bridge.write_to_host(hdr.dst_port, &payload[..n]);
                ctx.add_recv(&hdr, n as u32);
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
        if ctx.flush_rx() { Some(0) } else { None }
    }

    fn poll_fds(&self) -> Vec<RawFd> {
        self.bridge.poll_fds()
    }
}

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
