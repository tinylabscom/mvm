//! Userspace TCP/IP egress for the host-forwarded packet tunnel.
//!
//! The guest hands the host raw IPv4 packets over the network tunnel. Rather
//! than inject admitted packets into a privileged kernel TUN device with NAT,
//! the host terminates the guest's TCP and UDP flows in an in-process `smoltcp`
//! stack and bridges each admitted flow to an ordinary host socket — no root, no
//! host network device. This is the sole host-side L3 forwarder on every unix
//! host.
//!
//! Admission is unchanged: every guest packet is gated by
//! [`L3ForwardPolicy::decide_packet`] before it reaches the stack, exactly like
//! the raw-L3 decision gate. Only admitted packets are fed to `smoltcp`; a
//! denied destination is audited and dropped and never opens a socket. The
//! stack's gateway lives at `10.240.0.1/30` with the guest at `10.240.0.2`.
//!
//! Scope: TCP, UDP, and ICMP-echo forward. TCP terminates each guest flow and
//! splices it to a host `TcpStream`; UDP bridges each admitted guest 4-tuple to
//! a connected host `UdpSocket`, reaping idle flows on a timeout (UDP has no
//! close). An admitted guest ICMP echo request is relayed via an unprivileged
//! host ping socket (an unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` socket); the
//! host waits for the reply and synthesizes an echo reply back to the guest, so
//! `ping <admitted-host>` works. DNS already works via the guest `/etc/hosts`
//! injection (the tunnel hands the guest pin-consistent entries), so no resolver
//! is needed here.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::State;
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use crate::net_l3::{L3Decision, L3DropReason, L3ForwardPolicy};
use crate::network_tunnel::{
    GuestSessionEvent, HostNetworkTunnelWorker, TunnelAuditEvent, TunnelAuditSink,
    TunnelWorkerError, TunnelWorkerOutcome,
};

/// IPv4 protocol number for TCP.
const IP_PROTO_TCP: u8 = 6;
/// IPv4 protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;
/// IPv4 protocol number for ICMP.
const IP_PROTO_ICMP: u8 = 1;
/// ICMP type for an echo request (the `ping` probe).
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP type for an echo reply.
const ICMP_ECHO_REPLY: u8 = 0;
/// Minimum IPv4 header length (no options).
const IPV4_MIN_HEADER_LEN: usize = 20;
/// Bytes of an ICMP echo header preceding its payload (type, code, checksum,
/// identifier, sequence).
const ICMP_ECHO_HEADER_LEN: usize = 8;
/// Default TTL for host-synthesized reply packets handed back to the guest.
const REPLY_TTL: u8 = 64;
/// Scratch buffer for a host ICMP reply read off a ping socket.
const ICMP_REPLY_MAX: usize = 1500;
/// Upper bound on datagrams moved per UDP socket per service iteration, in each
/// direction, so one busy flow can't starve the loop.
const UDP_BATCH_PER_ITER: usize = 64;
/// Largest UDP payload a host reply buffer holds. Datagrams the host server
/// sends larger than the tunnel MTU are framed and dropped downstream by the
/// device (fail closed), so this only bounds the scratch buffer.
const UDP_DATAGRAM_MAX: usize = 65_507;
/// Userspace-stack gateway address + prefix. The guest lives at `10.240.0.2`
/// inside the same `/30`.
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
    /// Per-admitted-port `smoltcp` UDP payload-ring size, each direction.
    pub udp_buffer_bytes: usize,
    /// Number of datagram slots in each per-port UDP metadata ring.
    pub udp_packet_slots: usize,
    /// A UDP flow with no traffic either way for longer than this is reaped
    /// (UDP has no close signal, so idle timeout is the only reclaim path).
    pub udp_idle_timeout: Duration,
    /// An in-flight ICMP echo with no reply within this window is reaped and
    /// dropped (host unreachable or reply lost). The host ping socket is
    /// non-blocking, so this only bounds how long a pending echo is retained.
    pub icmp_reply_timeout: Duration,
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
            udp_buffer_bytes: 64 * 1024,
            udp_packet_slots: 32,
            udp_idle_timeout: Duration::from_secs(30),
            icmp_reply_timeout: Duration::from_secs(5),
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

/// A guest UDP 4-tuple. The guest source lives behind the tunnel; the host
/// bridges each distinct tuple to its own connected host socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    guest: SocketAddrV4,
    dst: SocketAddrV4,
}

/// One admitted guest UDP flow bridged to a connected host `UdpSocket`. Unlike
/// TCP there is no stream — datagrams relay statelessly and the flow is reaped
/// once idle past the configured timeout.
struct UdpFlow {
    socket: UdpSocket,
    dst: Ipv4Addr,
    dst_port: u16,
    /// The guest source endpoint replies are framed back to.
    guest: IpEndpoint,
    flow_id: u32,
    guest_to_host_bytes: u64,
    host_to_guest_bytes: u64,
    /// Wall-clock of the last datagram either way; drives idle reaping.
    last_activity: std::time::Instant,
}

/// One admitted, in-flight guest ICMP echo request relayed to an unprivileged
/// host ping socket. The socket is connected to the pinned destination and read
/// non-blocking each iteration; on the first echo reply the host synthesizes a
/// reply carrying the guest's original identifier/sequence/payload and frames it
/// back. Held until the reply arrives or the reply timeout elapses. One socket
/// per in-flight echo makes reply attribution unambiguous, so macOS rewriting
/// the datagram socket's identifier is irrelevant.
struct IcmpEcho {
    /// Connected host ping socket; closed on drop.
    socket: OwnedFd,
    dst: Ipv4Addr,
    /// The guest source address the synthesized reply is framed back to.
    guest_src: Ipv4Addr,
    /// The guest's original echo identifier, echoed in the synthesized reply.
    ident: u16,
    /// The guest's original echo sequence, echoed in the synthesized reply.
    sequence: u16,
    /// The guest's original echo payload, echoed back verbatim.
    payload: Vec<u8>,
    flow_id: u32,
    /// When the request was sent to the host, driving reply-timeout reaping.
    sent_at: std::time::Instant,
}

/// Userspace TCP/UDP egress stack: terminates admitted guest flows and bridges
/// each to a host socket.
pub struct SmoltcpEgress {
    gate: L3ForwardPolicy,
    config: EgressConfig,
    device: TunnelDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// Listening TCP sockets, keyed by handle → the port they listen on.
    listeners: HashMap<SocketHandle, u16>,
    /// Established bridged TCP flows, keyed by their `smoltcp` socket handle.
    flows: HashMap<SocketHandle, HostBridge>,
    /// One bound `smoltcp` UDP socket per admitted port, keyed by port. These
    /// persist for the session and demultiplex every guest tuple to that port.
    udp_ports: HashMap<u16, SocketHandle>,
    /// Established bridged UDP flows, keyed by the guest 4-tuple.
    udp_flows: HashMap<UdpFlowKey, UdpFlow>,
    /// In-flight ICMP echoes awaiting a host reply. These never touch the
    /// `smoltcp` stack — the stack has no ICMP socket — they relay directly
    /// through host ping sockets.
    icmp_echoes: Vec<IcmpEcho>,
    /// Synthesized IPv4/ICMP echo replies queued for the guest, drained beside
    /// the stack's own TX packets.
    icmp_replies: VecDeque<Vec<u8>>,
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
            udp_ports: HashMap::new(),
            udp_flows: HashMap::new(),
            icmp_echoes: Vec::new(),
            icmp_replies: VecDeque::new(),
            listen_ports: ports,
            next_flow_id: 0,
            next_tx_sequence: 0,
            stop: None,
        };
        egress.open_udp_listeners();
        egress.replenish_listeners();
        Ok(egress)
    }

    /// Bind one persistent `smoltcp` UDP socket per admitted port. `any_ip`
    /// accepts the concrete destination; the datagram's `local_address` metadata
    /// carries which pinned dst the guest targeted, so a single socket per port
    /// serves every admitted destination on it.
    fn open_udp_listeners(&mut self) {
        let ports = self.listen_ports.clone();
        for port in ports {
            if self.udp_ports.contains_key(&port) {
                continue;
            }
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; self.config.udp_packet_slots],
                    vec![0_u8; self.config.udp_buffer_bytes],
                ),
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; self.config.udp_packet_slots],
                    vec![0_u8; self.config.udp_buffer_bytes],
                ),
            );
            if socket.bind(port).is_err() {
                continue;
            }
            let handle = self.sockets.add(socket);
            self.udp_ports.insert(port, handle);
        }
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
        worker: &mut HostNetworkTunnelWorker<S, A>,
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

    /// Wait a short slice when flows or in-flight echoes are active (to move
    /// bytes / collect replies promptly) and up to the idle timeout otherwise
    /// (so timers still fire).
    fn iteration_timeout_ms(&self) -> i32 {
        let active = !self.flows.is_empty() || !self.icmp_echoes.is_empty();
        let timeout = if active {
            Duration::from_millis(5)
        } else {
            self.config.idle_poll_timeout
        };
        i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX)
    }

    /// Gate one guest packet and, if admitted, hand it to the stack. A denied
    /// destination is audited and dropped — no socket is opened. Admitted TCP
    /// and UDP packets are served by their bound sockets. An admitted ICMP echo
    /// request is intercepted here (the stack has no ICMP socket) and relayed via
    /// an unprivileged host ping socket; its reply is synthesized back to the
    /// guest, so `ping <admitted-host>` works.
    fn ingest_guest_packet<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        // ICMP echo requests can't be served by the stack (no ICMP socket);
        // relay admitted ones directly and synthesize the reply. Non-echo ICMP
        // falls through to the generic gate below and is dropped by the stack.
        if let Some(echo) = parse_icmp_echo_request(&payload) {
            return self.relay_icmp_echo(worker, echo);
        }
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

    /// Gate an admitted ICMP echo request, open a host ping socket, send the
    /// probe, and register the in-flight echo. A denied destination or an
    /// in-flight-echo cap hit opens no socket and is audited via
    /// `IcmpEchoDenied`. A host-socket/send failure is not a gate denial, so it
    /// is logged and the echo dropped (mirroring a failed TCP host connect).
    fn relay_icmp_echo<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
        echo: IcmpEchoRequest,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        if let L3Decision::Drop(reason) = self.gate.decide(echo.dst, IP_PROTO_ICMP, None) {
            return worker.record_tunnel_audit(TunnelAuditEvent::IcmpEchoDenied {
                dst: echo.dst,
                reason,
            });
        }
        // Bound in-flight echoes alongside TCP/UDP flows against the flow cap.
        if self.flows.len() + self.udp_flows.len() + self.icmp_echoes.len() >= self.config.max_flows
        {
            return worker.record_tunnel_audit(TunnelAuditEvent::IcmpEchoDenied {
                dst: echo.dst,
                reason: L3DropReason::PortNotAllowed,
            });
        }
        let socket = match open_host_icmp(echo.dst) {
            Ok(socket) => socket,
            Err(err) => {
                tracing::warn!(dst = %echo.dst, error = %err, "smoltcp egress icmp host socket failed");
                return Ok(());
            }
        };
        if let Err(err) =
            send_host_icmp(socket.as_raw_fd(), echo.ident, echo.sequence, &echo.payload)
        {
            tracing::warn!(dst = %echo.dst, error = %err, "smoltcp egress icmp host send failed");
            return Ok(());
        }
        let flow_id = self.next_flow_id;
        self.next_flow_id = self.next_flow_id.wrapping_add(1);
        self.icmp_echoes.push(IcmpEcho {
            socket,
            dst: echo.dst,
            guest_src: echo.src,
            ident: echo.ident,
            sequence: echo.sequence,
            payload: echo.payload,
            flow_id,
            sent_at: std::time::Instant::now(),
        });
        Ok(())
    }

    /// Promote accepted listeners into bridges and splice established flows.
    fn service_flows<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        self.promote_accepted_listeners(worker)?;
        self.pump_established_flows(worker)?;
        self.service_udp_flows(worker)?;
        self.service_icmp_echoes(worker)?;
        self.replenish_listeners();
        Ok(())
    }

    /// Read each in-flight echo's host ping socket non-blocking. On the first
    /// echo reply, synthesize an IPv4/ICMP echo reply carrying the guest's
    /// original identifier/sequence/payload, queue it for the guest, and audit
    /// `IcmpEchoRelayed`. Echoes with no reply within the timeout are reaped and
    /// dropped (logged, not gate-denied). The host socket closes on drop.
    fn service_icmp_echoes<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        let now = std::time::Instant::now();
        let timeout = self.config.icmp_reply_timeout;
        // Take ownership so the reply queue / audit sink can be touched without a
        // borrow conflict; survivors go back at the end.
        let echoes = std::mem::take(&mut self.icmp_echoes);
        let mut kept: Vec<IcmpEcho> = Vec::with_capacity(echoes.len());
        for echo in echoes {
            if recv_icmp_echo_reply(echo.socket.as_raw_fd()) {
                let reply = build_icmp_echo_reply(
                    echo.dst,
                    echo.guest_src,
                    echo.ident,
                    echo.sequence,
                    &echo.payload,
                );
                self.icmp_replies.push_back(reply);
                worker.record_tunnel_audit(TunnelAuditEvent::IcmpEchoRelayed {
                    flow_id: echo.flow_id,
                    dst: echo.dst,
                })?;
                continue;
            }
            if now.duration_since(echo.sent_at) >= timeout {
                tracing::warn!(dst = %echo.dst, "smoltcp egress icmp echo reply timed out");
                continue;
            }
            kept.push(echo);
        }
        self.icmp_echoes = kept;
        Ok(())
    }

    /// A listener that left the `Listen` state received a SYN. Read its intended
    /// destination, re-check the gate (defence in depth — ingest already
    /// admitted it), open a host stream, and register a bridge; on deny or a
    /// failed host connect, reset the guest socket.
    fn promote_accepted_listeners<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
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
        worker: &mut HostNetworkTunnelWorker<S, A>,
        handle: SocketHandle,
        dst: Ipv4Addr,
        dst_port: u16,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        if self.flows.len() + self.udp_flows.len() >= self.config.max_flows {
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
        worker: &mut HostNetworkTunnelWorker<S, A>,
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

    /// Relay UDP both ways and reap idle flows.
    fn service_udp_flows<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        self.pump_udp_guest_to_host(worker)?;
        self.pump_udp_host_to_guest();
        self.reap_idle_udp_flows(worker)?;
        Ok(())
    }

    /// Drain each per-port UDP socket and relay admitted datagrams out the
    /// matching connected host socket, opening a flow on the first datagram of a
    /// tuple. Denied destinations and cap hits are audited and dropped without
    /// opening a host socket.
    fn pump_udp_guest_to_host<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        let ports: Vec<(u16, SocketHandle)> =
            self.udp_ports.iter().map(|(&p, &h)| (p, h)).collect();
        for (port, handle) in ports {
            // Drain into an owned batch first so the socket borrow is released
            // before we touch flow state / host sockets.
            let mut batch: Vec<(IpEndpoint, Ipv4Addr, Vec<u8>)> = Vec::new();
            {
                let socket = self.sockets.get_mut::<udp::Socket>(handle);
                while batch.len() < UDP_BATCH_PER_ITER {
                    match socket.recv() {
                        Ok((data, meta)) => {
                            let Some(dst) = meta.local_address.and_then(ipv4_of) else {
                                continue;
                            };
                            batch.push((meta.endpoint, dst, data.to_vec()));
                        }
                        Err(_) => break,
                    }
                }
            }
            for (guest, dst, data) in batch {
                self.relay_guest_datagram(worker, port, guest, dst, data)?;
            }
        }
        Ok(())
    }

    /// Gate + relay one guest datagram, creating the flow on first sight.
    fn relay_guest_datagram<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
        port: u16,
        guest: IpEndpoint,
        dst: Ipv4Addr,
        data: Vec<u8>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        // Per-flow datagram-size cap (fail closed on oversize).
        if data.len() > self.config.max_flow_buffer_bytes {
            return worker.record_tunnel_audit(TunnelAuditEvent::UdpFlowDenied {
                dst,
                dst_port: port,
                reason: L3DropReason::PortNotAllowed,
            });
        }
        // Defence in depth: re-gate even though ingest already admitted it.
        if let L3Decision::Drop(reason) = self.gate.decide(dst, IP_PROTO_UDP, Some(port)) {
            return worker.record_tunnel_audit(TunnelAuditEvent::UdpFlowDenied {
                dst,
                dst_port: port,
                reason,
            });
        }
        let Some(guest_v4) = ipv4_of(guest.addr) else {
            return Ok(());
        };
        let key = UdpFlowKey {
            guest: SocketAddrV4::new(guest_v4, guest.port),
            dst: SocketAddrV4::new(dst, port),
        };
        if !self.udp_flows.contains_key(&key) {
            if self.flows.len() + self.udp_flows.len() >= self.config.max_flows {
                return worker.record_tunnel_audit(TunnelAuditEvent::UdpFlowDenied {
                    dst,
                    dst_port: port,
                    reason: L3DropReason::PortNotAllowed,
                });
            }
            let socket = match open_host_udp(dst, port) {
                Ok(socket) => socket,
                Err(err) => {
                    // Host unreachable is not a gate denial; record for
                    // observability and drop the datagram.
                    tracing::warn!(%dst, dst_port = port, error = %err, "smoltcp egress udp host connect failed");
                    return Ok(());
                }
            };
            let flow_id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1);
            self.udp_flows.insert(
                key,
                UdpFlow {
                    socket,
                    dst,
                    dst_port: port,
                    guest,
                    flow_id,
                    guest_to_host_bytes: 0,
                    host_to_guest_bytes: 0,
                    last_activity: std::time::Instant::now(),
                },
            );
            worker.record_tunnel_audit(TunnelAuditEvent::UdpFlowOpened {
                flow_id,
                dst,
                dst_port: port,
            })?;
        }
        let flow = self.udp_flows.get_mut(&key).expect("udp flow present");
        match flow.socket.send(&data) {
            Ok(n) => {
                flow.guest_to_host_bytes = flow.guest_to_host_bytes.saturating_add(n as u64);
                flow.last_activity = std::time::Instant::now();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => {
                tracing::warn!(%dst, dst_port = port, error = %err, "smoltcp egress udp host send failed");
            }
        }
        Ok(())
    }

    /// Read replies off each flow's host socket and frame them back into the
    /// per-port UDP socket, sourced from the pinned dst so the guest sees the
    /// reply as coming from where it sent.
    fn pump_udp_host_to_guest(&mut self) {
        let mut scratch = vec![0_u8; UDP_DATAGRAM_MAX];
        let keys: Vec<UdpFlowKey> = self.udp_flows.keys().copied().collect();
        for key in keys {
            let Some(&handle) = self.udp_ports.get(&key.dst.port()) else {
                continue;
            };
            let mut replies: Vec<Vec<u8>> = Vec::new();
            {
                let flow = self.udp_flows.get_mut(&key).expect("udp flow present");
                while replies.len() < UDP_BATCH_PER_ITER {
                    match flow.socket.recv(&mut scratch) {
                        Ok(0) => break,
                        Ok(n) => {
                            flow.host_to_guest_bytes =
                                flow.host_to_guest_bytes.saturating_add(n as u64);
                            flow.last_activity = std::time::Instant::now();
                            replies.push(scratch[..n].to_vec());
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
            if replies.is_empty() {
                continue;
            }
            let guest = self.udp_flows.get(&key).expect("udp flow present").guest;
            let dst_addr = IpAddress::Ipv4(*key.dst.ip());
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            for reply in replies {
                let mut meta = udp::UdpMetadata::from(guest);
                meta.local_address = Some(dst_addr);
                // Buffer-full is the only failure and simply drops the reply
                // (fail closed); the guest retransmits at the app layer.
                let _ = socket.send_slice(&reply, meta);
            }
        }
    }

    /// Reap UDP flows idle past the configured timeout, auditing each close with
    /// its relayed byte counts.
    fn reap_idle_udp_flows<S, A>(
        &mut self,
        worker: &mut HostNetworkTunnelWorker<S, A>,
    ) -> Result<(), TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        let now = std::time::Instant::now();
        let timeout = self.config.udp_idle_timeout;
        let expired: Vec<UdpFlowKey> = self
            .udp_flows
            .iter()
            .filter(|(_, flow)| now.duration_since(flow.last_activity) >= timeout)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            let flow = self.udp_flows.remove(&key).expect("udp flow present");
            worker.record_tunnel_audit(TunnelAuditEvent::UdpFlowClosed {
                flow_id: flow.flow_id,
                dst: flow.dst,
                dst_port: flow.dst_port,
                guest_to_host_bytes: flow.guest_to_host_bytes,
                host_to_guest_bytes: flow.host_to_guest_bytes,
            })?;
        }
        Ok(())
    }

    /// Ensure each admitted port has one live TCP listener, up to the flow cap.
    /// The persistent per-port UDP sockets are excluded from the count so they
    /// never crowd out TCP listeners.
    fn replenish_listeners(&mut self) {
        let total = self
            .sockets
            .iter()
            .count()
            .saturating_sub(self.udp_ports.len());
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
        worker: &mut HostNetworkTunnelWorker<S, A>,
    ) -> Result<Option<TunnelWorkerOutcome>, TunnelWorkerError>
    where
        S: Read + Write + AsRawFd,
        A: TunnelAuditSink,
    {
        // Synthesized ICMP echo replies (host-forwarded, not stack-emitted) frame
        // back through the same guest packet path as the stack's TX packets.
        while let Some(reply) = self.icmp_replies.pop_front() {
            let sequence = self.next_tx_sequence;
            self.next_tx_sequence = self.next_tx_sequence.wrapping_add(1);
            if let Some(outcome) = worker.send_guest_packet(0, sequence, reply)? {
                return Ok(Some(outcome));
            }
        }
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

/// Open a nonblocking host UDP socket connected to the admitted destination.
/// `connect` fixes the peer so stray datagrams from other hosts are rejected.
fn open_host_udp(dst: Ipv4Addr, dst_port: u16) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(SocketAddr::new(IpAddr::V4(dst), dst_port))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// A parsed guest ICMP echo request: its addresses and the fields echoed back.
struct IcmpEchoRequest {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
    sequence: u16,
    payload: Vec<u8>,
}

/// Bounds-checked parse of an IPv4 ICMP echo request. Returns `None` for
/// anything that isn't a well-formed IPv4 packet carrying an ICMP echo request
/// (type 8, code 0) — every other packet (short, wrong version, non-ICMP,
/// non-echo) falls through to the generic gate and is handled there.
fn parse_icmp_echo_request(packet: &[u8]) -> Option<IcmpEchoRequest> {
    if packet.len() < IPV4_MIN_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || packet.len() < header_len {
        return None;
    }
    if packet[9] != IP_PROTO_ICMP {
        return None;
    }
    let icmp = &packet[header_len..];
    if icmp.len() < ICMP_ECHO_HEADER_LEN || icmp[0] != ICMP_ECHO_REQUEST || icmp[1] != 0 {
        return None;
    }
    Some(IcmpEchoRequest {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        ident: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: icmp[ICMP_ECHO_HEADER_LEN..].to_vec(),
    })
}

/// Open a non-blocking, unprivileged host ICMP socket connected to `dst`. macOS
/// grants `SOCK_DGRAM`/`IPPROTO_ICMP` without root; on Linux the same socket is
/// unprivileged when the worker's gid falls in `net.ipv4.ping_group_range` (the
/// standard container/desktop default) and otherwise fails closed — TCP/UDP/DNS
/// egress is unaffected. `connect` fixes the peer so stray replies from other
/// hosts are rejected and `send`/`recv` suffice.
fn open_host_icmp(dst: Ipv4Addr) -> std::io::Result<OwnedFd> {
    // SAFETY: standard socket(2); the raw fd is immediately owned so it is closed
    // on every return path.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid, owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: F_GETFL/F_SETFL on an owned fd; errors are surfaced, not ignored.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    // macOS/BSD `sockaddr_in` carries a `sin_len` byte that Linux omits, and the
    // `sin_family` width differs (u8 on Apple, u16 on Linux) — cast to the field.
    #[cfg(target_os = "macos")]
    {
        addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    }
    addr.sin_family = libc::AF_INET as _;
    addr.sin_addr.s_addr = u32::from(dst).to_be();
    // SAFETY: `addr` is a fully initialized sockaddr_in of the passed length.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(owned)
}

/// Send one ICMP echo request on a connected host ping socket. The kernel may
/// rewrite the identifier and recompute the checksum on this datagram socket;
/// the reply is attributed by socket, not by identifier, so that is harmless.
fn send_host_icmp(fd: RawFd, ident: u16, sequence: u16, payload: &[u8]) -> std::io::Result<()> {
    let mut msg = vec![0_u8; ICMP_ECHO_HEADER_LEN + payload.len()];
    msg[0] = ICMP_ECHO_REQUEST;
    msg[4..6].copy_from_slice(&ident.to_be_bytes());
    msg[6..8].copy_from_slice(&sequence.to_be_bytes());
    msg[ICMP_ECHO_HEADER_LEN..].copy_from_slice(payload);
    let checksum = internet_checksum(&msg);
    msg[2..4].copy_from_slice(&checksum.to_be_bytes());
    // SAFETY: `msg` is a valid, initialized buffer of the passed length.
    let n = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Non-blocking read of a host ping socket: `true` iff an ICMP echo reply is
/// available. macOS delivers the datagram with its IPv4 header intact, so the
/// header is skipped before inspecting the ICMP type. Other payloads (WouldBlock,
/// a non-echo-reply message) return `false`, leaving the echo in flight.
fn recv_icmp_echo_reply(fd: RawFd) -> bool {
    let mut buf = [0_u8; ICMP_REPLY_MAX];
    // SAFETY: `buf` is a valid, writable buffer of the passed length.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n <= 0 {
        return false;
    }
    let datagram = &buf[..n as usize];
    // Datagram carries the IPv4 header on macOS; skip it to reach the ICMP type.
    let icmp = match datagram.first() {
        Some(first) if first >> 4 == 4 => {
            let header_len = usize::from(first & 0x0f) * 4;
            if header_len < IPV4_MIN_HEADER_LEN || datagram.len() < header_len {
                return false;
            }
            &datagram[header_len..]
        }
        _ => datagram,
    };
    matches!(icmp.first(), Some(&ICMP_ECHO_REPLY))
}

/// Build a complete IPv4/ICMP echo reply packet with valid IPv4 and ICMP
/// checksums, sourced from the pinged host and destined for the guest, echoing
/// the guest's original identifier, sequence, and payload.
fn build_icmp_echo_reply(
    host: Ipv4Addr,
    guest: Ipv4Addr,
    ident: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = ICMP_ECHO_HEADER_LEN + payload.len();
    let total_len = IPV4_MIN_HEADER_LEN + icmp_len;
    let mut packet = vec![0_u8; total_len];
    // IPv4 header.
    packet[0] = 0x45; // version 4, IHL 5 (no options)
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = REPLY_TTL;
    packet[9] = IP_PROTO_ICMP;
    packet[12..16].copy_from_slice(&host.octets());
    packet[16..20].copy_from_slice(&guest.octets());
    let ip_checksum = internet_checksum(&packet[..IPV4_MIN_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    // ICMP echo reply.
    let icmp = &mut packet[IPV4_MIN_HEADER_LEN..];
    icmp[0] = ICMP_ECHO_REPLY;
    icmp[4..6].copy_from_slice(&ident.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    icmp[ICMP_ECHO_HEADER_LEN..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(&packet[IPV4_MIN_HEADER_LEN..]);
    packet[IPV4_MIN_HEADER_LEN + 2..IPV4_MIN_HEADER_LEN + 4]
        .copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

/// One's-complement internet checksum over a byte slice whose own checksum field
/// is pre-zeroed.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
        ExpectedTunnelSession, HostNetworkTunnelWorker, NoopTunnelAuditSink, TunnelPacketPolicy,
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
            let mut worker = HostNetworkTunnelWorker::new(
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
                HostNetworkTunnelWorker::new(host_raw, audit, worker_config(host_gate.clone()))
                    .unwrap();
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

    /// End-to-end: a guest smoltcp UDP socket sends a datagram through the host
    /// `SmoltcpEgress` to a real OS UDP echo server at the pinned destination
    /// and receives the echoed reply — proving one admitted UDP flow bridged to
    /// a connected host socket in both directions.
    #[test]
    fn admitted_udp_flow_reaches_host_server_and_replies() {
        const REQUEST: &[u8] = b"udp-ping-over-smoltcp";
        const RESPONSE: &[u8] = b"udp-pong-from-host";

        // Real OS UDP echo server at the pinned destination.
        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_port = server_sock.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut buf = [0_u8; 1024];
            let (n, peer) = server_sock.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], REQUEST);
            server_sock.send_to(RESPONSE, peer).unwrap();
        });

        let gate = gate_for("server.test", server_port, &["127.0.0.1"]);
        let (guest_raw, host_raw) = UnixStream::pair().unwrap();

        let host_gate = gate.clone();
        let host = std::thread::spawn(move || {
            let mut worker = HostNetworkTunnelWorker::new(
                host_raw,
                NoopTunnelAuditSink,
                worker_config(host_gate.clone()),
            )
            .unwrap();
            worker.bootstrap(1, 2, 3).unwrap();
            let mut egress = SmoltcpEgress::new(&host_gate, EgressConfig::default()).unwrap();
            let outcome = egress.run(&mut worker).unwrap();
            assert!(matches!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            ));
        });

        // Guest: negotiate, then a smoltcp UDP socket that speaks to the pinned
        // destination over the tunnel.
        let mut session =
            mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest_raw);
        session.negotiate(hello(), 1).unwrap();
        session.recv_network_config().unwrap();
        session.recv_control().unwrap();

        let mut guest_dev = TunnelDevice::new(1500);
        let mut gcfg = IfaceConfig::new(HardwareAddress::Ip);
        gcfg.random_seed = 0xC0FF_EE01;
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
        let client = gsockets.add(udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0_u8; 16 * 1024]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0_u8; 16 * 1024]),
        ));
        gsockets
            .get_mut::<udp::Socket>(client)
            .bind(49_152)
            .unwrap();
        let dst = IpEndpoint {
            addr: IpAddress::Ipv4(WireV4::new(127, 0, 0, 1)),
            port: server_port,
        };

        let mut sent = false;
        let mut received = Vec::new();
        let mut tx_seq = 0_u64;
        let fd = session.as_raw_fd();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);

        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "udp flow did not complete"
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

            let socket = gsockets.get_mut::<udp::Socket>(client);
            if socket.can_send() && !sent {
                socket.send_slice(REQUEST, dst).unwrap();
                sent = true;
            }
            while socket.can_recv() {
                match socket.recv() {
                    Ok((data, _meta)) => received.extend_from_slice(data),
                    Err(_) => break,
                }
            }
            if received.len() >= RESPONSE.len() {
                break;
            }
        }

        assert_eq!(received, RESPONSE);

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

    /// A denied (unpinned) UDP destination opens no host socket and is audited
    /// as a drop, with no `UdpFlowOpened`.
    #[test]
    fn denied_udp_destination_opens_no_host_socket() {
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

        // A UDP server exists, but the gate pins a DIFFERENT address, so the
        // guest's destination is unadmitted.
        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let server_port = server_sock.local_addr().unwrap().port();
        let never_received = Arc::new(AtomicBool::new(true));
        let flag = never_received.clone();
        let server = std::thread::spawn(move || {
            let mut buf = [0_u8; 1024];
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(2) {
                if server_sock.recv_from(&mut buf).is_ok() {
                    flag.store(false, Ordering::Relaxed);
                    return;
                }
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
                HostNetworkTunnelWorker::new(host_raw, audit, worker_config(host_gate.clone()))
                    .unwrap();
            worker.bootstrap(1, 2, 3).unwrap();
            let mut egress = SmoltcpEgress::new(&host_gate, EgressConfig::default()).unwrap();
            egress.run(&mut worker).unwrap();
        });

        let mut session =
            mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest_raw);
        session.negotiate(hello(), 1).unwrap();
        session.recv_network_config().unwrap();
        session.recv_control().unwrap();

        // A hand-built IPv4/UDP datagram to the unadmitted destination.
        let mut dgram = vec![0_u8; 28];
        dgram[0] = 0x45; // v4, IHL 5
        dgram[9] = IP_PROTO_UDP;
        dgram[16..20].copy_from_slice(&Ipv4Addr::new(127, 0, 0, 1).octets());
        dgram[20..22].copy_from_slice(&49_152_u16.to_be_bytes()); // src port
        dgram[22..24].copy_from_slice(&server_port.to_be_bytes()); // dst port
        dgram[24..26].copy_from_slice(&8_u16.to_be_bytes()); // udp length
        session.send_packet(0, 0, 0, dgram).unwrap();

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
            never_received.load(Ordering::Relaxed),
            "no host socket may relay a datagram for a denied destination"
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
            "a denied UDP destination must be audited as an L3 drop"
        );
        assert!(
            !recorded
                .iter()
                .any(|e| matches!(e, TunnelAuditEvent::UdpFlowOpened { .. })),
            "no UDP flow may open for a denied destination"
        );
    }

    /// Build a raw IPv4/ICMP echo request from the guest to `dst`.
    fn ipv4_icmp_echo_request(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        ident: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0_u8; ICMP_ECHO_HEADER_LEN + payload.len()];
        icmp[0] = ICMP_ECHO_REQUEST;
        icmp[4..6].copy_from_slice(&ident.to_be_bytes());
        icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
        icmp[ICMP_ECHO_HEADER_LEN..].copy_from_slice(payload);
        let ck = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());

        let total = IPV4_MIN_HEADER_LEN + icmp.len();
        let mut packet = vec![0_u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = IP_PROTO_ICMP;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        let ip_ck = internet_checksum(&packet[..IPV4_MIN_HEADER_LEN]);
        packet[10..12].copy_from_slice(&ip_ck.to_be_bytes());
        packet[IPV4_MIN_HEADER_LEN..].copy_from_slice(&icmp);
        packet
    }

    /// End-to-end: a guest ICMP echo request to the pinned loopback destination
    /// is relayed by the host `SmoltcpEgress` through an unprivileged ping socket
    /// (the loopback kernel replies) and a synthesized echo reply frames back to
    /// the guest with matching identifier, sequence, and payload — proving
    /// `ping <admitted-host>` works on the macOS userspace stack.
    #[test]
    fn admitted_icmp_echo_reaches_pinned_host_and_replies() {
        // The relay opens an unprivileged SOCK_DGRAM/IPPROTO_ICMP ping socket.
        // macOS grants it freely; on Linux it needs the process gid inside
        // net.ipv4.ping_group_range. Where the environment forbids it (a
        // locked-down CI container), skip rather than fail — the relay logic is
        // identical; only the host socket is unavailable.
        if open_host_icmp(Ipv4Addr::new(127, 0, 0, 1)).is_err() {
            eprintln!("skipping admitted_icmp_echo: host ping socket unavailable");
            return;
        }
        const IDENT: u16 = 0xBEEF;
        const SEQUENCE: u16 = 7;
        const PAYLOAD: &[u8] = b"icmp-echo-over-smoltcp";
        let guest_ip = Ipv4Addr::new(10, 240, 0, 2);
        let dst = Ipv4Addr::new(127, 0, 0, 1);

        // Pin 127.0.0.1 (admitted on some port; ICMP is gated on dst IP alone).
        let gate = gate_for("server.test", 443, &["127.0.0.1"]);
        let (guest_raw, host_raw) = UnixStream::pair().unwrap();

        let host_gate = gate.clone();
        let host = std::thread::spawn(move || {
            let mut worker = HostNetworkTunnelWorker::new(
                host_raw,
                NoopTunnelAuditSink,
                worker_config(host_gate.clone()),
            )
            .unwrap();
            worker.bootstrap(1, 2, 3).unwrap();
            let mut egress = SmoltcpEgress::new(&host_gate, EgressConfig::default()).unwrap();
            let outcome = egress.run(&mut worker).unwrap();
            assert!(matches!(
                outcome,
                TunnelWorkerOutcome::GuestShutdown(TunnelShutdownReason::GuestStopping)
            ));
        });

        let mut session =
            mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest_raw);
        session.negotiate(hello(), 1).unwrap();
        session.recv_network_config().unwrap();
        session.recv_control().unwrap();

        let request = ipv4_icmp_echo_request(guest_ip, dst, IDENT, SEQUENCE, PAYLOAD);
        session.send_packet(0, 0, 0, request).unwrap();

        let fd = session.as_raw_fd();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let mut reply: Option<Vec<u8>> = None;
        while std::time::Instant::now() < deadline {
            if poll_readable(fd, 50)
                && let Ok(frame) = session.recv_packet()
                && let Some(echo) = parse_icmp_echo_reply(&frame.payload)
            {
                reply = Some(echo);
                break;
            }
        }

        let echo = reply.expect("an echo reply must frame back to the guest");
        // ICMP starts after the 20-byte IPv4 header of the synthesized reply.
        let icmp = &echo[IPV4_MIN_HEADER_LEN..];
        assert_eq!(icmp[0], ICMP_ECHO_REPLY, "type must be echo reply");
        assert_eq!(
            u16::from_be_bytes([icmp[4], icmp[5]]),
            IDENT,
            "identifier must match the request"
        );
        assert_eq!(
            u16::from_be_bytes([icmp[6], icmp[7]]),
            SEQUENCE,
            "sequence must match the request"
        );
        assert_eq!(
            &icmp[ICMP_ECHO_HEADER_LEN..],
            PAYLOAD,
            "payload must echo the request"
        );
        // The reply is sourced from the pinged host, destined for the guest.
        assert_eq!(&echo[12..16], &dst.octets(), "reply source is the host");
        assert_eq!(&echo[16..20], &guest_ip.octets(), "reply dest is the guest");

        session
            .send_control(
                TunnelControlMessage::Shutdown(TunnelShutdownReason::GuestStopping),
                0,
                0,
                1,
            )
            .unwrap();
        host.join().unwrap();
    }

    /// Recognize a synthesized IPv4/ICMP echo reply frame (validating the IPv4
    /// header the way the guest stack would before matching it).
    fn parse_icmp_echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < IPV4_MIN_HEADER_LEN || packet[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if header_len < IPV4_MIN_HEADER_LEN || packet.len() < header_len {
            return None;
        }
        if packet[9] != IP_PROTO_ICMP {
            return None;
        }
        let icmp = &packet[header_len..];
        if icmp.len() < ICMP_ECHO_HEADER_LEN || icmp[0] != ICMP_ECHO_REPLY {
            return None;
        }
        Some(packet.to_vec())
    }

    /// A denied (unpinned) ICMP echo destination opens no host ping socket and is
    /// audited as an `IcmpEchoDenied`, with no `IcmpEchoRelayed`.
    #[test]
    fn denied_icmp_echo_opens_no_host_socket() {
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

        let guest_ip = Ipv4Addr::new(10, 240, 0, 2);
        // Guest targets 127.0.0.1, but the gate pins a DIFFERENT address.
        let dst = Ipv4Addr::new(127, 0, 0, 1);
        let gate = gate_for("server.test", 443, &["10.13.13.13"]);
        let audit = SharedAudit::default();
        let events = audit.0.clone();
        let (guest_raw, host_raw) = UnixStream::pair().unwrap();

        let host_gate = gate.clone();
        let host = std::thread::spawn(move || {
            let mut worker =
                HostNetworkTunnelWorker::new(host_raw, audit, worker_config(host_gate.clone()))
                    .unwrap();
            worker.bootstrap(1, 2, 3).unwrap();
            let mut egress = SmoltcpEgress::new(&host_gate, EgressConfig::default()).unwrap();
            egress.run(&mut worker).unwrap();
        });

        let mut session =
            mvm_guest::network_tunnel::GuestNetworkTunnelSession::from_stream(guest_raw);
        session.negotiate(hello(), 1).unwrap();
        session.recv_network_config().unwrap();
        session.recv_control().unwrap();

        let request = ipv4_icmp_echo_request(guest_ip, dst, 0x1111, 1, b"denied");
        session.send_packet(0, 0, 0, request).unwrap();

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

        let recorded = events.lock().unwrap();
        assert!(
            recorded.iter().any(|e| matches!(
                e,
                TunnelAuditEvent::IcmpEchoDenied {
                    reason: L3DropReason::UnpinnedDst,
                    ..
                }
            )),
            "a denied ICMP echo must be audited as IcmpEchoDenied"
        );
        assert!(
            !recorded
                .iter()
                .any(|e| matches!(e, TunnelAuditEvent::IcmpEchoRelayed { .. })),
            "no echo may be relayed for a denied destination"
        );
    }
}
