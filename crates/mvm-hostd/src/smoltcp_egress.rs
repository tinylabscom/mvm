//! macOS userspace TCP/IP egress for the host-forwarded packet tunnel.
//!
//! The guest hands the host raw IPv4 packets over the network tunnel. On Linux
//! admitted packets are injected into a kernel TUN + NAT. macOS has no
//! unprivileged kernel NAT, so the host instead terminates the guest's TCP
//! flows in an in-process `smoltcp` stack and bridges each admitted flow to an
//! ordinary host socket — no root, no utun.
//!
//! Admission is unchanged: every guest packet is gated by
//! [`L3ForwardPolicy::decide_packet`] before it reaches the stack, exactly like
//! the raw-L3 decision gate. Only admitted packets are fed to `smoltcp`; a
//! denied destination is audited and dropped and never opens a socket. The
//! stack's gateway address mirrors the Linux TUN path (`10.240.0.1/30`, guest
//! `10.240.0.2`).
//!
//! Scope: TCP only. DNS already works via the guest `/etc/hosts` injection
//! (the tunnel hands the guest pin-consistent entries), so no resolver is
//! needed here. UDP and ICMP are dropped + audited for now — see the
//! `follow-up:` notes below.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::tcp::State;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::net_l3::{L3Decision, L3DropReason, L3ForwardPolicy};
use crate::network_tunnel::{
    GuestSessionEvent, HostTunnelWorker, TunnelAuditEvent, TunnelAuditSink, TunnelWorkerError,
    TunnelWorkerOutcome,
};

/// IPv4 protocol number for TCP.
const IP_PROTO_TCP: u8 = 6;
/// Userspace-stack gateway address + prefix, matching the Linux TUN gateway so
/// the guest sees identical addressing on both host platforms. The guest lives
/// at `10.240.0.2` inside the same `/30`.
const GATEWAY_OCTETS: [u8; 4] = [10, 240, 0, 1];
const GATEWAY_PREFIX_LEN: u8 = 30;
/// Read/write scratch used when splicing between a guest socket and its host
/// stream.
const SPLICE_CHUNK: usize = 8192;

/// Host-internal knobs for the userspace egress stack. Not a wire type — it is
/// constructed by the worker binary, never deserialized from an untrusted
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressConfig {
    /// Maximum concurrent bridged flows (also caps live `smoltcp` sockets).
    pub max_flows: usize,
    /// Per-flow cap on bytes buffered in each direction. Splicing stops filling
    /// a direction once its buffer reaches this, applying backpressure.
    pub max_flow_buffer_bytes: usize,
    /// IP MTU for the stack. Clamp to the negotiated tunnel frame size so a
    /// single stack packet always fits one tunnel frame.
    pub mtu: usize,
    /// Per-flow `smoltcp` receive-ring size.
    pub tcp_rx_buffer_bytes: usize,
    /// Per-flow `smoltcp` transmit-ring size.
    pub tcp_tx_buffer_bytes: usize,
    /// Bound on the blocking host `connect()` for a newly admitted flow.
    pub host_connect_timeout: Duration,
    /// Upper bound on how long a loop iteration waits for a guest frame, so the
    /// stack's own timers still fire under an idle session.
    pub idle_poll_timeout: Duration,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            max_flows: 64,
            max_flow_buffer_bytes: 256 * 1024,
            mtu: 1500,
            tcp_rx_buffer_bytes: 64 * 1024,
            tcp_tx_buffer_bytes: 64 * 1024,
            host_connect_timeout: Duration::from_secs(10),
            idle_poll_timeout: Duration::from_millis(100),
        }
    }
}

/// In-memory L3 device: its RX queue is fed guest packets, its TX queue is
/// drained back to the guest. No OS device — `smoltcp` is poll-driven over
/// these two queues.
struct TunnelDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TunnelDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    /// Enqueue one raw IPv4 packet from the guest for the stack to ingest.
    fn push_guest_packet(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    /// Dequeue one raw IPv4 packet the stack emitted toward the guest.
    fn pop_host_packet(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }
}

impl Device for TunnelDevice {
    type RxToken<'a> = TunnelRxToken;
    type TxToken<'a> = TunnelTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn receive(&mut self, _now: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        let rx = TunnelRxToken { buffer };
        let tx = TunnelTxToken {
            tx: &mut self.tx,
            mtu: self.mtu,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunnelTxToken {
            tx: &mut self.tx,
            mtu: self.mtu,
        })
    }
}

struct TunnelRxToken {
    buffer: Vec<u8>,
}

impl RxToken for TunnelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct TunnelTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TxToken for TunnelTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0_u8; len];
        let result = f(&mut buffer);
        // Fail closed on an oversize emit rather than framing a packet the
        // guest can't accept; a well-behaved stack never exceeds the MTU.
        if len <= self.mtu {
            self.tx.push_back(buffer);
        }
        result
    }
}

/// One admitted guest TCP flow bridged to a host socket. `to_host` carries
/// guest→host bytes awaiting the host stream; `to_guest` carries host→guest
/// bytes awaiting the guest socket.
struct HostBridge {
    stream: TcpStream,
    dst: Ipv4Addr,
    dst_port: u16,
    flow_id: u32,
    to_host: VecDeque<u8>,
    to_guest: VecDeque<u8>,
    host_eof: bool,
    host_write_shut: bool,
    guest_to_host_bytes: u64,
    host_to_guest_bytes: u64,
}

/// Userspace TCP egress stack: terminates admitted guest flows and bridges each
/// to a host socket.
pub struct SmoltcpEgress {
    gate: L3ForwardPolicy,
    config: EgressConfig,
    device: TunnelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Listening sockets, keyed by handle → the port they listen on.
    listeners: HashMap<SocketHandle, u16>,
    /// Established bridged flows, keyed by their `smoltcp` socket handle.
    flows: HashMap<SocketHandle, HostBridge>,
    /// Distinct admitted destination ports the stack listens on.
    listen_ports: Vec<u16>,
    next_flow_id: u32,
    next_tx_sequence: u64,
    stop: Option<Arc<AtomicBool>>,
}

impl SmoltcpEgress {
    /// Build the stack from the admitted gate. Assigns the gateway address,
    /// enables any-destination termination (safe because only gate-admitted
    /// packets are ever fed in), and opens one listener per admitted port.
    pub fn new(gate: &L3ForwardPolicy, config: EgressConfig) -> Result<Self, TunnelWorkerError> {
        if config.max_flows == 0 {
            return Err(TunnelWorkerError::InvalidConfig(
                "smoltcp egress max_flows must be non-zero",
            ));
        }
        let mtu = config.mtu.max(576);
        let mut device = TunnelDevice::new(mtu);

        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = random_seed();
        let mut iface = Interface::new(iface_config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            let gw = IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(
                    GATEWAY_OCTETS[0],
                    GATEWAY_OCTETS[1],
                    GATEWAY_OCTETS[2],
                    GATEWAY_OCTETS[3],
                )),
                GATEWAY_PREFIX_LEN,
            );
            // Single address; the heapless address list has ample room.
            let _ = addrs.push(gw);
        });
        // Terminate flows to any destination the gate already admitted. Non-
        // admitted packets are dropped at ingest and never reach the stack.
        iface.set_any_ip(true);

        // Distinct admitted ports, sorted for deterministic listener setup.
        let mut ports: Vec<u16> = gate
            .admitted_ipv4_endpoints()
            .map(|(_ip, port)| port)
            .collect();
        ports.sort_unstable();
        ports.dedup();

        let mut egress = Self {
            gate: gate.clone(),
            config,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            listeners: HashMap::new(),
            flows: HashMap::new(),
            listen_ports: ports,
            next_flow_id: 0,
            next_tx_sequence: 0,
            stop: None,
        };
        egress.replenish_listeners();
        Ok(egress)
    }

    /// Attach a shared stop flag; when set, the loop tells the guest to stop and
    /// returns fail-closed.
    pub fn with_stop_flag(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Drive the stack until the guest shuts down, a quota is spent, or the stop
    /// flag fires. Reuses the worker's session (guest packet in/out), its audit
    /// sink, and its per-session quota; the gate gates every packet at ingest.
    pub fn run<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
    ) -> Result<TunnelWorkerOutcome, TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        loop {
            if self.stop_requested() {
                let outcome = worker.close_for_host_error("smoltcp egress stopped".to_string())?;
                worker.record_session_closed(outcome.clone())?;
                return Ok(outcome);
            }

            let timeout_ms = self.iteration_timeout_ms();
            if worker.poll_guest_readable(timeout_ms)? {
                match worker.read_guest_session_event()? {
                    GuestSessionEvent::Packet {
                        flow_id,
                        sequence,
                        payload,
                    } => self.ingest_guest_packet(worker, flow_id, sequence, payload)?,
                    GuestSessionEvent::Closed(outcome) => {
                        worker.record_session_closed(outcome.clone())?;
                        return Ok(outcome);
                    }
                    GuestSessionEvent::Control => {}
                }
            }

            // Ingest freshly-queued guest packets and run stack timers.
            self.iface
                .poll(Instant::now(), &mut self.device, &mut self.sockets);

            // Accept new flows and splice bytes on established ones.
            self.service_flows(worker)?;

            // Flush socket writes into the device TX queue.
            self.iface
                .poll(Instant::now(), &mut self.device, &mut self.sockets);

            // Deliver stack output back to the guest.
            if let Some(outcome) = self.drain_tx_to_guest(worker)? {
                worker.record_session_closed(outcome.clone())?;
                return Ok(outcome);
            }
        }
    }

    fn stop_requested(&self) -> bool {
        self.stop
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    /// Wait a short slice when flows are active (to move bytes promptly) and up
    /// to the idle timeout otherwise (so timers still fire).
    fn iteration_timeout_ms(&self) -> i32 {
        let timeout = if self.flows.is_empty() {
            self.config.idle_poll_timeout
        } else {
            Duration::from_millis(5)
        };
        i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX)
    }

    /// Gate one guest packet and, if admitted, hand it to the stack. A denied
    /// destination is audited and dropped — no socket is opened.
    ///
    /// follow-up: UDP and ICMP to an admitted destination are dropped + audited
    /// here (TCP-only first slice); they must never be silently forwarded.
    fn ingest_guest_packet<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        let bytes = payload.len();
        match self.gate.decide_packet(&payload) {
            L3Decision::Allow => {
                self.device.push_guest_packet(payload);
                Ok(())
            }
            L3Decision::Drop(reason) => {
                worker.record_tunnel_audit(TunnelAuditEvent::PacketL3Dropped {
                    flow_id,
                    sequence,
                    bytes,
                    reason,
                })
            }
        }
    }

    /// Promote accepted listeners into bridges and splice established flows.
    fn service_flows<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        self.promote_accepted_listeners(worker)?;
        self.pump_established_flows(worker)?;
        self.replenish_listeners();
        Ok(())
    }

    /// A listener that left the `Listen` state received a SYN. Read its intended
    /// destination, re-check the gate (defence in depth — ingest already
    /// admitted it), open a host stream, and register a bridge; on deny or a
    /// failed host connect, reset the guest socket.
    fn promote_accepted_listeners<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        let handles: Vec<SocketHandle> = self.listeners.keys().copied().collect();
        for handle in handles {
            let target = {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if socket.is_listening() {
                    continue;
                }
                accepted_target(socket)
            };
            self.listeners.remove(&handle);
            let Some((dst, dst_port)) = target else {
                // Left Listen without a peer (aborted/closed); reclaim it.
                self.sockets.remove(handle);
                continue;
            };

            match self.gate.decide(dst, IP_PROTO_TCP, Some(dst_port)) {
                L3Decision::Allow => {
                    self.open_admitted_flow(worker, handle, dst, dst_port)?;
                }
                L3Decision::Drop(reason) => {
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.sockets.remove(handle);
                    worker.record_tunnel_audit(TunnelAuditEvent::TcpFlowDenied {
                        dst,
                        dst_port,
                        reason,
                    })?;
                }
            }
        }
        Ok(())
    }

    fn open_admitted_flow<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
        handle: SocketHandle,
        dst: Ipv4Addr,
        dst_port: u16,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        if self.flows.len() >= self.config.max_flows {
            // At the flow cap: reset rather than exceed the bound.
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
            self.sockets.remove(handle);
            worker.record_tunnel_audit(TunnelAuditEvent::TcpFlowDenied {
                dst,
                dst_port,
                reason: L3DropReason::PortNotAllowed,
            })?;
            return Ok(());
        }

        let target = SocketAddr::new(IpAddr::V4(dst), dst_port);
        match TcpStream::connect_timeout(&target, self.config.host_connect_timeout) {
            Ok(stream) => {
                stream
                    .set_nonblocking(true)
                    .map_err(|e| TunnelWorkerError::PacketPath(e.to_string()))?;
                let flow_id = self.next_flow_id;
                self.next_flow_id = self.next_flow_id.wrapping_add(1);
                self.flows.insert(
                    handle,
                    HostBridge {
                        stream,
                        dst,
                        dst_port,
                        flow_id,
                        to_host: VecDeque::new(),
                        to_guest: VecDeque::new(),
                        host_eof: false,
                        host_write_shut: false,
                        guest_to_host_bytes: 0,
                        host_to_guest_bytes: 0,
                    },
                );
                worker.record_tunnel_audit(TunnelAuditEvent::TcpFlowOpened {
                    flow_id,
                    dst,
                    dst_port,
                })?;
            }
            Err(err) => {
                // Host unreachable: RST the guest flow. Not a gate denial, so no
                // TcpFlowDenied — record a drop for observability.
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
                self.sockets.remove(handle);
                tracing::warn!(%dst, dst_port, error = %err, "smoltcp egress host connect failed");
            }
        }
        Ok(())
    }

    /// Splice every established bridge in both directions, retiring finished
    /// flows with a `TcpFlowClosed` audit.
    fn pump_established_flows<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        let cap = self.config.max_flow_buffer_bytes;
        let handles: Vec<SocketHandle> = self.flows.keys().copied().collect();
        for handle in handles {
            let finished = {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                let bridge = self.flows.get_mut(&handle).expect("bridge for handle");
                pump_flow(socket, bridge, cap);
                !socket.is_open()
            };
            if finished {
                let bridge = self.flows.remove(&handle).expect("bridge for handle");
                self.sockets.remove(handle);
                worker.record_tunnel_audit(TunnelAuditEvent::TcpFlowClosed {
                    flow_id: bridge.flow_id,
                    dst: bridge.dst,
                    dst_port: bridge.dst_port,
                    guest_to_host_bytes: bridge.guest_to_host_bytes,
                    host_to_guest_bytes: bridge.host_to_guest_bytes,
                })?;
            }
        }
        Ok(())
    }

    /// Ensure each admitted port has one live listener, up to the flow cap.
    fn replenish_listeners(&mut self) {
        let total = self.sockets.iter().count();
        if total >= self.config.max_flows {
            return;
        }
        let mut budget = self.config.max_flows - total;
        let ports = self.listen_ports.clone();
        for port in ports {
            if budget == 0 {
                break;
            }
            if self.listeners.values().any(|&p| p == port) {
                continue;
            }
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0_u8; self.config.tcp_rx_buffer_bytes]),
                tcp::SocketBuffer::new(vec![0_u8; self.config.tcp_tx_buffer_bytes]),
            );
            // Any local address on this port; `any_ip` accepts the concrete dst.
            if socket.listen(port).is_err() {
                continue;
            }
            let handle = self.sockets.add(socket);
            self.listeners.insert(handle, port);
            budget -= 1;
        }
    }

    fn drain_tx_to_guest<S, A>(
        &mut self,
        worker: &mut HostTunnelWorker<S, A>,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        while let Some(packet) = self.device.pop_host_packet() {
            let sequence = self.next_tx_sequence;
            self.next_tx_sequence = self.next_tx_sequence.wrapping_add(1);
            if let Some(outcome) = worker.send_guest_packet(0, sequence, packet)? {
                return Ok(Some(outcome));
            }
        }
        Ok(None)
    }
}

/// The concrete `(dst, port)` a just-accepted listener socket targets, or
/// `None` if it left `Listen` without an established peer.
fn accepted_target(socket: &tcp::Socket) -> Option<(Ipv4Addr, u16)> {
    let local = socket.local_endpoint()?;
    socket.remote_endpoint()?;
    let dst = ipv4_of(local.addr)?;
    Some((dst, local.port))
}

fn ipv4_of(addr: IpAddress) -> Option<Ipv4Addr> {
    match IpAddr::from(addr) {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Splice one bridged flow both ways: guest socket ⇄ host stream. Bounded by
/// `cap` per direction; drops nothing — backpressure falls out of the caps.
fn pump_flow(socket: &mut tcp::Socket, bridge: &mut HostBridge, cap: usize) {
    // guest → host buffer
    while socket.can_recv() && bridge.to_host.len() < cap {
        let mut chunk = [0_u8; SPLICE_CHUNK];
        match socket.recv_slice(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bridge.to_host.extend(&chunk[..n]),
            Err(_) => break,
        }
    }
    // host buffer → host stream
    while !bridge.to_host.is_empty() {
        let written = {
            let (head, _) = bridge.to_host.as_slices();
            bridge.stream.write(head)
        };
        match written {
            Ok(0) => break,
            Ok(n) => {
                bridge.guest_to_host_bytes += n as u64;
                bridge.to_host.drain(..n);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                bridge.host_eof = true;
                break;
            }
        }
    }
    // Guest closed its send side and everything drained → shut host write so
    // the server sees EOF. Keyed on a genuine peer-FIN state: `may_recv()` is
    // also false pre-handshake (SynReceived), which must not be mistaken for a
    // close.
    let guest_sent_fin = matches!(
        socket.state(),
        State::CloseWait | State::Closing | State::LastAck | State::TimeWait | State::Closed
    );
    if guest_sent_fin && bridge.to_host.is_empty() && !bridge.host_write_shut {
        let _ = bridge.stream.shutdown(Shutdown::Write);
        bridge.host_write_shut = true;
    }
    // host stream → guest buffer
    if !bridge.host_eof && bridge.to_guest.len() < cap {
        let mut chunk = [0_u8; SPLICE_CHUNK];
        match bridge.stream.read(&mut chunk) {
            Ok(0) => bridge.host_eof = true,
            Ok(n) => bridge.to_guest.extend(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => bridge.host_eof = true,
        }
    }
    // guest buffer → guest socket
    while socket.can_send() && !bridge.to_guest.is_empty() {
        let sent = {
            let (head, _) = bridge.to_guest.as_slices();
            socket.send_slice(head)
        };
        match sent {
            Ok(0) => break,
            Ok(n) => {
                bridge.host_to_guest_bytes += n as u64;
                bridge.to_guest.drain(..n);
            }
            Err(_) => break,
        }
    }
    // Host closed and everything forwarded → close the guest send side.
    if bridge.host_eof && bridge.to_guest.is_empty() && socket.may_send() {
        socket.close();
    }
}

fn random_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_l3::L3ForwardPolicy;
    use crate::network_tunnel::{
        ExpectedTunnelSession, HostTunnelWorker, NoopTunnelAuditSink, TunnelPacketPolicy,
        TunnelWorkerConfig, TunnelWorkerLimits,
    };
    use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::protocol::network_tunnel::{
        NETWORK_TUNNEL_VERSION, TunnelControlMessage, TunnelCreditUpdate, TunnelFeatures,
        TunnelHello, TunnelNetworkConfig, TunnelShutdownReason,
    };
    use smoltcp::iface::{
        Config as IfaceConfig, Interface as GuestIface, SocketSet as GuestSockets,
    };
    use smoltcp::socket::tcp as gtcp;
    use smoltcp::wire::{IpCidr as WireCidr, Ipv4Address as WireV4};
    use std::net::TcpListener;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicBool;

    fn gate_for(host: &str, port: u16, pinned: &[&str]) -> L3ForwardPolicy {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new(host, port)]);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            host,
            pinned.iter().map(|s| s.parse().expect("ip")).collect(),
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        L3ForwardPolicy::new(policy, pins)
    }

    #[test]
    fn new_opens_one_listener_per_distinct_admitted_port() {
        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("a.test", 443),
            HostPort::new("b.test", 443),
            HostPort::new("c.test", 8443),
        ]);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "a.test",
            vec!["10.0.0.1".parse().unwrap()],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        pins.add(DnsPin::at(
            "b.test",
            vec!["10.0.0.2".parse().unwrap()],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        pins.add(DnsPin::at(
            "c.test",
            vec!["10.0.0.3".parse().unwrap()],
            "2026-05-15T12:00:00Z",
            "2026-05-15T13:00:00Z",
        ));
        let gate = L3ForwardPolicy::new(policy, pins);
        let egress = SmoltcpEgress::new(&gate, EgressConfig::default()).unwrap();
        // Two distinct ports (443, 8443) → two listeners.
        assert_eq!(egress.listen_ports, vec![443, 8443]);
        assert_eq!(egress.listeners.len(), 2);
    }

    #[test]
    fn new_rejects_zero_max_flows() {
        let gate = gate_for("api.test", 443, &["10.0.0.9"]);
        match SmoltcpEgress::new(
            &gate,
            EgressConfig {
                max_flows: 0,
                ..EgressConfig::default()
            },
        ) {
            Err(TunnelWorkerError::InvalidConfig(_)) => {}
            other => panic!(
                "zero max_flows must be rejected, got {:?}",
                other.map(|_| ())
            ),
        }
    }

    #[test]
    fn device_rx_feeds_stack_and_tx_drains_to_guest() {
        let mut dev = TunnelDevice::new(1500);
        assert!(dev.pop_host_packet().is_none());
        dev.push_guest_packet(vec![1, 2, 3]);
        // The RX token yields exactly the pushed bytes.
        let (rx, _tx) = dev.receive(Instant::now()).expect("rx token");
        rx.consume(|bytes| assert_eq!(bytes, &[1, 2, 3]));
        // A TX token over the MTU is dropped (fail closed); within it enqueues.
        let tx = dev.transmit(Instant::now()).expect("tx token");
        tx.consume(4, |buf| buf.copy_from_slice(&[9, 8, 7, 6]));
        assert_eq!(dev.pop_host_packet(), Some(vec![9, 8, 7, 6]));
    }

    fn expected() -> ExpectedTunnelSession {
        ExpectedTunnelSession {
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            maximum_frame_size: 1500,
            accepted_features: TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
        }
    }

    fn hello() -> TunnelHello {
        TunnelHello {
            protocol_version: NETWORK_TUNNEL_VERSION,
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            guest_agent_version: "guest-netd/1".to_string(),
            requested_features: TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: 1500,
        }
    }

    fn network_config() -> TunnelNetworkConfig {
        TunnelNetworkConfig {
            interface_name: "mvm-net0".to_string(),
            guest_ipv4: "10.240.0.2".parse().unwrap(),
            prefix_len: 30,
            gateway_ipv4: "10.240.0.1".parse().unwrap(),
            dns_servers: vec!["10.240.0.1".parse().unwrap()],
            mtu: 1500,
            host_entries: Vec::new(),
        }
    }

    fn worker_config(gate: L3ForwardPolicy) -> TunnelWorkerConfig {
        TunnelWorkerConfig {
            expected_session: expected(),
            network_config: network_config(),
            initial_credit: TunnelCreditUpdate {
                flow_id: 0,
                bytes: 1_000_000,
                packets: 100_000,
            },
            packet_policy: TunnelPacketPolicy::L3Forward {
                gate,
                interface_name: Some("mvm-smoltcp".to_string()),
            },
            limits: TunnelWorkerLimits {
                max_packets: 1_000_000,
                max_bytes: 64 * 1024 * 1024,
            },
        }
    }

    fn poll_readable(fd: std::os::fd::RawFd, timeout_ms: i32) -> bool {
        let mut fds = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout_ms) };
        rc > 0 && (fds[0].revents & libc::POLLIN) != 0
    }

    /// End-to-end: a guest smoltcp client connects through the host
    /// `SmoltcpEgress` to a real OS TCP server at the pinned destination,
    /// sends a request, and receives the server's response — proving one
    /// admitted TCP flow bridged to a host socket.
    #[test]
    fn admitted_tcp_flow_reaches_host_server_and_replies() {
        const REQUEST: &[u8] = b"ping-over-smoltcp";
        const RESPONSE: &[u8] = b"pong-from-host";

        // Real OS server at the pinned destination.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server_port = server_addr.port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = vec![0_u8; REQUEST.len()];
            conn.read_exact(&mut buf).unwrap();
            assert_eq!(buf, REQUEST);
            conn.write_all(RESPONSE).unwrap();
            conn.flush().unwrap();
            // Hold the connection open until the client is done reading.
            let mut sink = Vec::new();
            let _ = conn.read_to_end(&mut sink);
        });

        let gate = gate_for("server.test", server_port, &["127.0.0.1"]);
        let (guest_raw, host_raw) = UnixStream::pair().unwrap();

        // Host: worker + smoltcp egress.
        let host_gate = gate.clone();
        let host = std::thread::spawn(move || {
            let mut worker = HostTunnelWorker::new(
                host_raw,
                NoopTunnelAuditSink,
                worker_config(host_gate.clone()),
            )
            .unwrap();
            worker.bootstrap(1, 2, 3).unwrap();
            let mut egress = SmoltcpEgress::new(
                &host_gate,
                EgressConfig {
                    mtu: 1500,
                    ..EgressConfig::default()
                },
            )
            .unwrap();
            let outcome = egress.run(&mut worker).unwrap();
            assert!(matches!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            ));
        });

        // Guest: negotiate the tunnel, then run a smoltcp client that connects
        // to the pinned destination and speaks over the tunnel.
        let mut session =
            mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest_raw);
        session.negotiate(hello(), 1).unwrap();
        session.recv_network_config().unwrap();
        session.recv_control().unwrap(); // initial credit

        let mut guest_dev = TunnelDevice::new(1500);
        let mut gcfg = IfaceConfig::new(HardwareAddress::Ip);
        gcfg.random_seed = 0xC0FF_EE00;
        let mut giface = GuestIface::new(gcfg, &mut guest_dev, Instant::now());
        giface.update_ip_addrs(|addrs| {
            let _ = addrs.push(WireCidr::new(
                IpAddress::Ipv4(WireV4::new(10, 240, 0, 2)),
                30,
            ));
        });
        giface
            .routes_mut()
            .add_default_ipv4_route(WireV4::new(10, 240, 0, 1))
            .unwrap();

        let mut gsockets = GuestSockets::new(Vec::new());
        let client = gsockets.add(gtcp::Socket::new(
            gtcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
            gtcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
        ));
        gsockets
            .get_mut::<gtcp::Socket>(client)
            .connect(
                giface.context(),
                (WireV4::new(127, 0, 0, 1), server_port),
                49_152,
            )
            .unwrap();

        let mut sent = false;
        let mut received = Vec::new();
        let mut tx_seq = 0_u64;
        let fd = session.as_raw_fd();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);

        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "flow did not complete"
            );
            giface.poll(Instant::now(), &mut guest_dev, &mut gsockets);

            while let Some(pkt) = guest_dev.pop_host_packet() {
                session.send_packet(0, 0, tx_seq, pkt).unwrap();
                tx_seq += 1;
            }

            if poll_readable(fd, 5)
                && let Ok(frame) = session.recv_packet()
            {
                guest_dev.push_guest_packet(frame.payload);
            }

            let socket = gsockets.get_mut::<gtcp::Socket>(client);
            if socket.can_send() && !sent {
                socket.send_slice(REQUEST).unwrap();
                sent = true;
            }
            while socket.can_recv() {
                let mut chunk = [0_u8; 1024];
                match socket.recv_slice(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&chunk[..n]),
                }
            }
            if received.len() >= RESPONSE.len() {
                break;
            }
        }

        assert_eq!(received, RESPONSE);

        // Close the client and tear the tunnel down.
        gsockets.get_mut::<gtcp::Socket>(client).close();
        for _ in 0..50 {
            giface.poll(Instant::now(), &mut guest_dev, &mut gsockets);
            while let Some(pkt) = guest_dev.pop_host_packet() {
                session.send_packet(0, 0, tx_seq, pkt).unwrap();
                tx_seq += 1;
            }
            if poll_readable(fd, 5)
                && let Ok(frame) = session.recv_packet()
            {
                guest_dev.push_guest_packet(frame.payload);
            }
        }

        session
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                tx_seq,
            )
            .unwrap();

        host.join().unwrap();
        server.join().unwrap();
    }

    /// A denied (unpinned) destination opens no host connection and is audited
    /// as a drop.
    #[test]
    fn denied_destination_opens_no_host_connection() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct SharedAudit(Arc<Mutex<Vec<TunnelAuditEvent>>>);
        impl TunnelAuditSink for SharedAudit {
            type Error = std::convert::Infallible;
            fn record(&mut self, event: TunnelAuditEvent) -> Result<(), Self::Error> {
                self.0.lock().unwrap().push(event);
                Ok(())
            }
        }

        // A server exists, but the gate pins a DIFFERENT address, so the guest's
        // destination is unadmitted.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let never_connected = Arc::new(AtomicBool::new(true));
        let flag = never_connected.clone();
        let server = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(2) {
                if listener.accept().is_ok() {
                    flag.store(false, Ordering::Relaxed);
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        // Pin an address the guest will NOT target (guest targets 127.0.0.1).
        let gate = gate_for("server.test", server_port, &["10.13.13.13"]);
        let audit = SharedAudit::default();
        let events = audit.0.clone();
        let (guest_raw, host_raw) = UnixStream::pair().unwrap();

        let host_gate = gate.clone();
        let host = std::thread::spawn(move || {
            let mut worker =
                HostTunnelWorker::new(host_raw, audit, worker_config(host_gate.clone())).unwrap();
            worker.bootstrap(1, 2, 3).unwrap();
            let mut egress = SmoltcpEgress::new(&host_gate, EgressConfig::default()).unwrap();
            egress.run(&mut worker).unwrap();
        });

        let mut session =
            mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest_raw);
        session.negotiate(hello(), 1).unwrap();
        session.recv_network_config().unwrap();
        session.recv_control().unwrap();

        // A hand-built IPv4/TCP SYN to the unadmitted destination.
        let mut syn = vec![0_u8; 40];
        syn[0] = 0x45; // v4, IHL 5
        syn[9] = IP_PROTO_TCP;
        syn[16..20].copy_from_slice(&Ipv4Addr::new(127, 0, 0, 1).octets());
        syn[22..24].copy_from_slice(&server_port.to_be_bytes());
        session.send_packet(0, 0, 0, syn).unwrap();

        // Give the host loop time to gate + audit the drop.
        std::thread::sleep(Duration::from_millis(200));
        session
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                1,
            )
            .unwrap();

        host.join().unwrap();
        server.join().unwrap();

        assert!(
            never_connected.load(Ordering::Relaxed),
            "no host connection may open for a denied destination"
        );
        let recorded = events.lock().unwrap();
        assert!(
            recorded.iter().any(|e| matches!(
                e,
                TunnelAuditEvent::PacketL3Dropped {
                    reason: L3DropReason::UnpinnedDst,
                    ..
                }
            )),
            "a denied destination must be audited as an L3 drop"
        );
        assert!(
            !recorded
                .iter()
                .any(|e| matches!(e, TunnelAuditEvent::TcpFlowOpened { .. })),
            "no TCP flow may open for a denied destination"
        );
    }
}
