//! The machine-scoped L3 gateway.
//!
//! One gateway per machine. It binds the session, validates every frame and
//! every IP packet, applies the signed plan's policy, serves the synthetic
//! resolver, hands admitted packets to the platform datapath, returns
//! admitted replies to the guest, and deletes everything when the machine
//! exits.
//!
//! It is not a packet forwarder with a policy bolted on: the datapath is
//! only reachable with an `AdmittedPacket`, which only the admitter
//! produces, so the ordering — vsock, then session, then validation, then
//! policy, then forwarding — is structural.
//!
//! I/O lives in the caller. This type is driven by feeding it bytes and
//! draining what it produces, which is what lets the whole gateway run in
//! unprivileged tests against an in-memory transport and datapath.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};

use mvm_contract::l3::{
    Config, ErrorCode, ErrorMessage, Hello, Ipv4Config, Ipv6Config, MessageType, ParsedIpPacket,
    Ready, Shutdown, ShutdownReason, frame, ip, limits, message,
};
use mvm_contract::protocol::dns::{DnsRcode, DnsRecordType, decode_query, encode_response};
use mvm_net::channel::VmInstanceIdentity;
use mvm_net::l3::{
    AddressLease, DenyCode, DnsBindingStore, DnsLimits, FlowLimits, FlowTable, GatewayService,
    InboundVerdict, IngressTable, L3Admitter, L3PolicyConfig, OutboundVerdict, SessionId,
};

use super::datapath::{
    DatapathError, DatapathHandle, DatapathRequest, ForwardingCapabilities, InboundDrain,
    L3Datapath, V6Link,
};
use super::metrics::GatewayMetrics;
use super::packet::{build_udp_v4, build_udp_v6};

/// How many packets may sit in either direction's queue before the gateway
/// starts dropping.
///
/// Tail-drop, not head-drop and not unbounded growth: the newest packet is
/// discarded, a counter moves, and TCP's own congestion control does the
/// rest. Dropping the oldest would reorder a flow; growing without bound
/// hands a guest a memory-exhaustion primitive.
pub const DEFAULT_QUEUE_DEPTH: usize = 256;

/// Ceiling on DNS queries per second for one machine.
pub const DEFAULT_DNS_QPS: u32 = 50;

/// Packets one [`Gateway::poll_inbound`] pass may take off the datapath.
///
/// A burst that arrives faster than the guest can be handed it must not be
/// able to hold the drive loop inside this drain and starve the guest-facing
/// side. The guest-facing read has carried the same budget since it shipped;
/// this is that treatment pointed the other way, and the number matches
/// because a guest read yields about one packet too.
///
/// Not a throughput ceiling: the pass reports [`InboundDrain::Backlogged`]
/// when the budget cuts it off, and the loop comes straight back rather than
/// waiting on a readiness edge it has already spent.
pub const MAX_INBOUND_PACKETS_PER_PASS: usize = 32;

/// TTL, or hop limit, on a synthesized resolver reply. The guest is one hop
/// away over the tunnel's own link, so this is only ever decremented by the
/// guest's own receive path.
const DNS_REPLY_TTL: u8 = 64;

/// Everything the gateway needs to serve one machine.
pub struct GatewayConfig {
    /// Host-owned identity of the VM boot this gateway serves. Everything
    /// authorizes against this, never against a CID, an endpoint path, or
    /// anything the guest said.
    pub instance: VmInstanceIdentity,
    pub machine_id: String,
    pub plan_digest: String,
    /// Capabilities the admitted plan needs from the forwarding backend.
    pub required_capabilities: ForwardingCapabilities,
    pub lease: AddressLease,
    pub policy: L3PolicyConfig,
    pub flow_limits: FlowLimits,
    pub dns_limits: DnsLimits,
    pub queue_depth: usize,
    pub dns_qps: u32,
    /// Ingress mappings the plan declared. Opened by the caller; the table
    /// here is what inbound admission consults.
    pub ingress: IngressTable,
}

impl GatewayConfig {
    /// A configuration with the default bounds.
    pub fn new(
        machine_id: impl Into<String>,
        plan_digest: impl Into<String>,
        lease: AddressLease,
        policy: L3PolicyConfig,
    ) -> Self {
        let machine_id = machine_id.into();
        let plan_digest = plan_digest.into();
        Self {
            instance: VmInstanceIdentity::new(
                "local",
                machine_id.clone(),
                // A caller that does not supply an identity gets a boot id
                // derived from the plan, which is at least per-plan rather
                // than constant. Production callers pass a real one.
                format!("boot-{plan_digest}"),
                plan_digest.clone(),
            ),
            required_capabilities: ForwardingCapabilities {
                tcp: true,
                udp: true,
                controlled_dns: true,
                declared_ingress: true,
                // The lease is the request. A machine holding an IPv6 pair
                // was admitted for the family, so a backend that cannot
                // carry it must refuse the session rather than let the
                // guest configure an address whose packets go nowhere.
                ipv6_flows: lease.gateway_v6.is_some(),
                ..ForwardingCapabilities::NONE
            },
            machine_id,
            plan_digest,
            lease,
            policy,
            flow_limits: FlowLimits::default(),
            dns_limits: DnsLimits::default(),
            queue_depth: DEFAULT_QUEUE_DEPTH,
            dns_qps: DEFAULT_DNS_QPS,
            ingress: IngressTable::with_defaults(),
        }
    }
}

/// Resolves a name on behalf of the guest. Injected so the DNS path is
/// testable without touching the network, and so a deployment can supply
/// its own resolver.
pub trait HostResolver: Send + Sync {
    /// Resolve `name`, returning the addresses and the upstream TTL in
    /// seconds. An empty vector is a successful NODATA answer.
    fn resolve(&self, name: &str, qtype: DnsRecordType)
    -> Result<(Vec<IpAddr>, u32), ResolveError>;
}

/// Why a resolution failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("resolving {0:?} failed")]
    Failed(String),
}

/// What a gateway did with one thing it was given. Returned rather than
/// logged so the caller decides what to audit and at what level; the
/// gateway never writes a line per packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEvent {
    /// The handshake completed and the session is carrying packets.
    TunnelReady { session: SessionId },
    /// A guest packet was forwarded to the host network.
    FlowAdmitted {
        src: IpAddr,
        dst: IpAddr,
        dst_port: u16,
        protocol: u8,
    },
    /// A guest packet was refused.
    FlowDenied {
        reason: DenyCode,
        dst: Option<IpAddr>,
        dst_port: Option<u16>,
    },
    /// A host packet was delivered to the guest.
    InboundDelivered { src: IpAddr, bytes: usize },
    /// A host packet was refused.
    InboundDenied { reason: DenyCode },
    /// A DNS question was answered.
    DnsAdmitted { name: String, answers: usize },
    /// A DNS question was refused.
    DnsDenied { name: String, reason: &'static str },
    /// A frame failed validation. The connection is finished.
    MalformedFrame { detail: String },
    /// A frame carried a session that is not the live one.
    StaleSession,
    /// A packet was dropped because a queue was full.
    QueueOverflow { direction: Direction },
    /// The rate limiter refused a DNS query.
    RateLimited,
    /// The session ended and its resources were released.
    CleanedUp { session: SessionId },
}

/// One pass of [`Gateway::poll_inbound`].
#[derive(Debug)]
pub struct InboundPass {
    pub events: Vec<GatewayEvent>,
    pub drain: InboundDrain,
}

/// Which way a packet was going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Guest to host network.
    Egress,
    /// Host network to guest.
    Ingress,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Egress => "egress",
            Self::Ingress => "ingress",
        }
    }
}

/// Why the gateway could not proceed.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// The peer violated the protocol. The connection must be dropped.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// A message payload was malformed.
    #[error(transparent)]
    Message(#[from] message::MessageError),
    /// The platform cannot serve a datapath.
    #[error(transparent)]
    Datapath(#[from] DatapathError),
    /// The gateway is not in a state where this is meaningful.
    #[error("gateway is not ready")]
    NotReady,
}

/// Lifecycle of a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    /// Waiting for `HELLO`.
    AwaitingHello,
    /// `CONFIG` sent; waiting for `READY`.
    AwaitingReady,
    /// Carrying packets.
    Ready,
    /// Finished. Terminal.
    Closed,
}

/// One machine's gateway.
pub struct Gateway {
    instance: VmInstanceIdentity,
    machine_id: String,
    plan_digest: String,
    session: SessionId,
    state: GatewayState,
    admitter: L3Admitter,
    datapath: Box<dyn DatapathHandle>,
    resolver: std::sync::Arc<dyn HostResolver>,
    metrics: GatewayMetrics,
    /// Frames waiting to go to the guest. Bounded; tail-dropped.
    to_guest: VecDeque<Vec<u8>>,
    queue_depth: usize,
    /// Partial-frame accumulator for the data connection.
    rx_buf: Vec<u8>,
    /// Reusable framing buffer.
    frame_buf: Vec<u8>,
    /// Reusable inbound read buffer.
    recv_buf: Vec<u8>,
    dns_tokens: u32,
    dns_qps: u32,
    dns_window_start_millis: u64,
    ip_id: u16,
}

impl std::fmt::Debug for Gateway {
    /// Deliberately narrow: a gateway holds a live datapath, a resolver, and
    /// buffers of guest packet bytes. Formatting those would put payload in
    /// a log line, which this mode never does.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("instance", &self.instance.audit_label())
            .field("session", &self.session)
            .field("state", &self.state)
            .field("queued_frames", &self.to_guest.len())
            .finish_non_exhaustive()
    }
}

impl Gateway {
    /// Open a gateway: check the platform, take a datapath, and start the
    /// handshake clock.
    ///
    /// Fails closed — if the platform has no datapath, no session opens and
    /// the guest is told why, rather than being handed a tunnel that would
    /// drop everything.
    pub fn open(
        config: GatewayConfig,
        session: SessionId,
        datapath: &dyn L3Datapath,
        resolver: std::sync::Arc<dyn HostResolver>,
    ) -> Result<Self, GatewayError> {
        datapath.is_available()?;
        // Refuse a plan the backend cannot actually serve, before anything
        // boots. A userspace socket gateway that cannot carry ICMP must not
        // admit a plan that asks for it and then quietly drop it.
        let missing = datapath
            .capabilities()
            .shortfall(&config.required_capabilities);
        if !missing.is_empty() {
            return Err(GatewayError::Datapath(DatapathError::CapabilityShortfall {
                backend: "selected forwarding backend",
                missing,
            }));
        }
        let handle = datapath.open(&DatapathRequest {
            machine_id: config.machine_id.clone(),
            gateway: config.lease.gateway,
            guest: config.lease.guest,
            prefix_len: config.lease.prefix_len(),
            // One lease, read once. A backend addressing a guest in a family
            // the lease never granted would be addressing somewhere nothing
            // admitted.
            v6: config
                .lease
                .gateway_v6
                .zip(config.lease.guest_v6)
                .map(|(gateway, guest)| V6Link {
                    gateway,
                    guest,
                    prefix_len: config.lease.prefix_len_v6(),
                }),
            mtu: config.policy.mtu,
            // Copied out before the table moves into the admitter below. A
            // backend that serves ingress by binding a listener needs the
            // same declarations admission will check inbound packets
            // against — one source, read twice, rather than two lists that
            // can disagree about which ports are exposed.
            ingress: config.ingress.iter().copied().collect(),
        })?;

        let admitter = L3Admitter::new(
            config.lease,
            config.policy.clone(),
            FlowTable::new(config.flow_limits),
            DnsBindingStore::new(config.dns_limits, config.policy.admitted_private.clone()),
            config.ingress,
        );

        Ok(Self {
            instance: config.instance,
            machine_id: config.machine_id,
            plan_digest: config.plan_digest,
            session,
            state: GatewayState::AwaitingHello,
            admitter,
            datapath: handle,
            resolver,
            metrics: GatewayMetrics::default(),
            to_guest: VecDeque::with_capacity(config.queue_depth),
            queue_depth: config.queue_depth,
            rx_buf: Vec::with_capacity(limits::MAX_WIRE_LEN * 2),
            frame_buf: Vec::with_capacity(limits::MAX_WIRE_LEN),
            recv_buf: vec![0u8; limits::MAX_PAYLOAD_LEN],
            dns_tokens: config.dns_qps,
            dns_qps: config.dns_qps,
            dns_window_start_millis: 0,
            ip_id: 1,
        })
    }

    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    /// The host-owned boot identity this gateway is bound to.
    pub fn instance(&self) -> &VmInstanceIdentity {
        &self.instance
    }

    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    pub fn session(&self) -> SessionId {
        self.session
    }

    pub fn state(&self) -> GatewayState {
        self.state
    }

    pub fn metrics(&self) -> &GatewayMetrics {
        &self.metrics
    }

    pub fn admitter(&self) -> &L3Admitter {
        &self.admitter
    }

    pub fn admitter_mut(&mut self) -> &mut L3Admitter {
        &mut self.admitter
    }

    pub fn datapath(&self) -> &dyn DatapathHandle {
        self.datapath.as_ref()
    }

    /// Drive the datapath's clock-bound work: connects the kernel has
    /// decided, transport timers, expiries.
    ///
    /// Forwarded rather than handing the handle out mutably. A caller
    /// holding `&mut dyn DatapathHandle` is one standing beside the
    /// admitter, and nothing outside this gateway needs that in order to
    /// make time pass.
    ///
    /// Passes the datapath's own [`InboundDrain`] through: whether a pass
    /// left work behind is the caller's business, since the caller is what
    /// decides whether to wait.
    pub fn service_datapath(&mut self, now_millis: u64) -> Result<InboundDrain, DatapathError> {
        self.datapath.service(now_millis)
    }

    /// Handle one complete control frame from the guest.
    ///
    /// Returns the bytes to write back on the control connection, plus what
    /// happened.
    pub fn handle_control_frame(
        &mut self,
        bytes: &[u8],
        now_millis: u64,
    ) -> Result<(Vec<u8>, Vec<GatewayEvent>), GatewayError> {
        let parsed = frame::decode(bytes).map_err(|err| {
            self.metrics.malformed_frames += 1;
            GatewayError::Protocol(err.to_string())
        })?;
        let mut events = Vec::new();

        match (self.state, parsed.header.msg_type) {
            (GatewayState::AwaitingHello, MessageType::Hello) => {
                // `HELLO` names no machine. Identity came from which per-VM
                // listener this connection arrived on, which the caller
                // resolved before constructing this gateway.
                let hello = Hello::decode(parsed.payload)?;
                if hello.version != limits::PROTOCOL_VERSION {
                    return Ok((
                        self.error_frame(ErrorCode::FeatureUnsupported, "unsupported version"),
                        events,
                    ));
                }
                // A machine leased an IPv6 pair was admitted for the
                // family. A guest that cannot apply one leaves the host
                // enforcing anti-spoofing against an address nothing
                // configured, so the session is refused rather than
                // quietly downgraded to what the plan did not ask for.
                if self.admitter.lease().gateway_v6.is_some()
                    && hello.features & message::features::IPV6 == 0
                {
                    return Ok((
                        self.error_frame(
                            ErrorCode::FeatureUnsupported,
                            "machine was leased an ipv6 pair the guest did not offer to apply",
                        ),
                        events,
                    ));
                }
                let config = self.assign_config(hello.features);
                self.state = GatewayState::AwaitingReady;
                Ok((self.encode(MessageType::Config, &config.encode()), events))
            }
            (GatewayState::AwaitingReady, MessageType::Ready) => {
                if parsed.header.session_id != self.session.0 {
                    self.metrics.stale_session_frames += 1;
                    events.push(GatewayEvent::StaleSession);
                    return Ok((
                        self.error_frame(ErrorCode::StaleSession, "session mismatch"),
                        events,
                    ));
                }
                let ready = Ready::decode(parsed.payload)?;
                if ready.mtu != self.admitter.config().mtu {
                    return Err(GatewayError::Protocol(format!(
                        "guest reported mtu {}, host assigned {}",
                        ready.mtu,
                        self.admitter.config().mtu
                    )));
                }
                self.admitter.set_ready(true);
                self.state = GatewayState::Ready;
                self.metrics.tunnel_ready_at_millis = Some(now_millis);
                events.push(GatewayEvent::TunnelReady {
                    session: self.session,
                });
                Ok((Vec::new(), events))
            }
            (_, MessageType::Heartbeat) => {
                self.metrics.heartbeats_received += 1;
                Ok((Vec::new(), events))
            }
            (_, MessageType::Shutdown) => {
                events.extend(self.close());
                Ok((Vec::new(), events))
            }
            (state, msg) => Err(GatewayError::Protocol(format!(
                "{msg:?} is not valid in state {state:?}"
            ))),
        }
    }

    /// Feed bytes from the data connection. Complete frames are validated,
    /// their packets admitted, and admitted ones forwarded.
    ///
    /// Returns what happened. Frames whose packets are refused produce a
    /// `FlowDenied` event and a counter, not an error — a hostile guest must
    /// not be able to kill its own connection by sending one bad packet, or
    /// the drop path becomes a denial of service against the rest of its
    /// traffic.
    pub fn ingest_data_bytes(
        &mut self,
        bytes: &[u8],
        now_millis: u64,
    ) -> Result<Vec<GatewayEvent>, GatewayError> {
        self.rx_buf.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            let consumed = match frame::decode(&self.rx_buf) {
                Ok(parsed) => {
                    let consumed = parsed.consumed;
                    if parsed.header.msg_type != MessageType::Packet {
                        self.metrics.malformed_frames += 1;
                        return Err(GatewayError::Protocol(format!(
                            "{:?} is not a data-plane message",
                            parsed.header.msg_type
                        )));
                    }
                    if parsed.header.session_id != self.session.0 {
                        self.metrics.stale_session_frames += 1;
                        events.push(GatewayEvent::StaleSession);
                        consumed
                    } else {
                        let start = frame::LENGTH_PREFIX_LEN + limits::HEADER_LEN;
                        let end = start + parsed.payload.len();
                        // Move the packet out of the accumulator so the
                        // borrow ends before admission mutates the gateway.
                        let len = end - start;
                        self.recv_buf[..len].copy_from_slice(&self.rx_buf[start..end]);
                        let packet: Vec<u8> = self.recv_buf[..len].to_vec();
                        events.extend(self.admit_and_forward(&packet, now_millis));
                        consumed
                    }
                }
                Err(frame::FrameError::Incomplete { .. }) => break,
                Err(err) => {
                    self.metrics.malformed_frames += 1;
                    events.push(GatewayEvent::MalformedFrame {
                        detail: err.to_string(),
                    });
                    return Err(GatewayError::Protocol(err.to_string()));
                }
            };
            self.rx_buf.drain(..consumed);
        }
        Ok(events)
    }

    /// Admit one guest packet and act on the verdict.
    fn admit_and_forward(&mut self, packet: &[u8], now_millis: u64) -> Vec<GatewayEvent> {
        let mut events = Vec::new();
        // The verdict borrows `packet`, so everything that needs the
        // admitter mutably happens after this scope.
        enum Action {
            Forward,
            Dns(ParsedIpPacket),
            Deny(DenyCode, Option<IpAddr>, Option<u16>),
        }
        let action = match self.admitter.admit_outbound(packet, now_millis) {
            OutboundVerdict::Forward(admitted) => {
                let meta = *admitted.meta();
                match self.datapath.send_to_network(&admitted) {
                    Ok(()) => {
                        self.metrics.packets_egress += 1;
                        self.metrics.bytes_egress += meta.total_len as u64;
                        events.push(GatewayEvent::FlowAdmitted {
                            src: meta.src,
                            dst: meta.dst,
                            dst_port: meta.dst_port.unwrap_or(0),
                            protocol: meta.protocol,
                        });
                    }
                    Err(_) => self.metrics.datapath_errors += 1,
                }
                Action::Forward
            }
            OutboundVerdict::Gateway(GatewayService::Dns, meta) => Action::Dns(meta),
            OutboundVerdict::Deny(code) => {
                let meta = ip::parse(packet).ok();
                Action::Deny(
                    code,
                    meta.as_ref().map(|m| m.dst),
                    meta.as_ref().and_then(|m| m.dst_port),
                )
            }
        };

        match action {
            Action::Forward => {}
            Action::Dns(meta) => events.extend(self.serve_dns(packet, &meta, now_millis)),
            Action::Deny(code, dst, dst_port) => {
                self.metrics.record_deny(code);
                events.push(GatewayEvent::FlowDenied {
                    reason: code,
                    dst,
                    dst_port,
                });
            }
        }
        events
    }

    /// Take up to one pass's worth of what the host network has for this
    /// machine, admit it, and queue the survivors for the guest.
    ///
    /// Bounded by [`MAX_INBOUND_PACKETS_PER_PASS`], and it says so when the
    /// bound is what stopped it. Draining to `WouldBlock` would let a burst
    /// hold the caller here while the guest-facing side went unserviced —
    /// the starvation the guest-facing drain's own budget exists to prevent,
    /// pointed the other way. A guest picks the destinations that reply, so
    /// it has a hand on the rate.
    pub fn poll_inbound(&mut self, now_millis: u64) -> InboundPass {
        let mut events = Vec::new();
        let mut drain = InboundDrain::Backlogged;
        for _ in 0..MAX_INBOUND_PACKETS_PER_PASS {
            let mut buf = std::mem::take(&mut self.recv_buf);
            let n = match self.datapath.recv_from_network(&mut buf) {
                Ok(0) => {
                    self.recv_buf = buf;
                    drain = InboundDrain::Idle;
                    break;
                }
                Ok(n) => n,
                Err(DatapathError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    self.recv_buf = buf;
                    drain = InboundDrain::Idle;
                    break;
                }
                Err(_) => {
                    self.metrics.datapath_errors += 1;
                    self.recv_buf = buf;
                    drain = InboundDrain::Idle;
                    break;
                }
            };
            let packet: Vec<u8> = buf[..n].to_vec();
            self.recv_buf = buf;
            match self.admitter.admit_inbound(&packet, now_millis) {
                InboundVerdict::Deliver(deliverable) => {
                    let meta = *deliverable.meta();
                    let bytes = deliverable.bytes().to_vec();
                    if self.queue_to_guest(&bytes) {
                        self.metrics.packets_ingress += 1;
                        self.metrics.bytes_ingress += meta.total_len as u64;
                        events.push(GatewayEvent::InboundDelivered {
                            src: meta.src,
                            bytes: meta.total_len,
                        });
                    } else {
                        events.push(GatewayEvent::QueueOverflow {
                            direction: Direction::Ingress,
                        });
                    }
                }
                InboundVerdict::Deny(code) => {
                    self.metrics.record_deny(code);
                    events.push(GatewayEvent::InboundDenied { reason: code });
                }
            }
        }
        InboundPass { events, drain }
    }

    /// Take everything queued for the guest's data connection.
    pub fn take_guest_frames(&mut self) -> Vec<Vec<u8>> {
        self.to_guest.drain(..).collect()
    }

    /// Expire idle flows and stale DNS bindings. Called on a timer by the
    /// caller; separated so the tests drive it deterministically.
    pub fn tick(&mut self, now_millis: u64) -> usize {
        let expired = self.admitter.flows_mut().expire_idle(now_millis).len();
        let pruned = self.admitter.dns_mut().prune_expired(now_millis);
        self.metrics.flows_expired += expired as u64;
        self.metrics.dns_bindings_expired += pruned as u64;
        expired + pruned
    }

    /// End the session and release everything it held.
    ///
    /// Deterministic and idempotent: the flow table, DNS bindings, ingress
    /// mappings, queued frames, and the platform datapath all go, and
    /// running it twice is a no-op. It is the same path for a normal stop
    /// and for a failed startup.
    pub fn close(&mut self) -> Vec<GatewayEvent> {
        if self.state == GatewayState::Closed {
            return Vec::new();
        }
        self.admitter.set_ready(false);
        let flows = self.admitter.flows_mut().clear();
        self.admitter.dns_mut().clear();
        let mappings = self.admitter.ingress_mut().clear();
        self.to_guest.clear();
        self.rx_buf.clear();
        let _ = self.datapath.close();
        self.state = GatewayState::Closed;
        self.metrics.flows_closed_on_teardown += flows.len() as u64;
        self.metrics.ingress_closed_on_teardown += mappings.len() as u64;
        vec![GatewayEvent::CleanedUp {
            session: self.session,
        }]
    }

    /// A `SHUTDOWN` frame to send the guest before closing.
    pub fn shutdown_frame(&mut self, reason: ShutdownReason) -> Vec<u8> {
        let payload = Shutdown { reason }.encode();
        self.encode(MessageType::Shutdown, &payload)
    }

    /// The configuration this gateway assigns. Every value is host-chosen.
    ///
    /// `offered` is what the guest proposed in `HELLO`; the IPv6 half is
    /// assigned only where the lease and the offer agree, so the guest is
    /// never handed an assignment it said it cannot apply.
    fn assign_config(&self, offered: u32) -> Config {
        let lease = self.admitter.lease();
        let v6 = lease
            .gateway_v6
            .zip(lease.guest_v6)
            .map(|(gateway, guest)| {
                Ipv6Config {
                    address: guest.octets(),
                    prefix_len: lease.prefix_len_v6(),
                    peer: gateway.octets(),
                    // The resolver is the gateway in this family too, so a
                    // guest that prefers IPv6 still resolves through the
                    // host-terminated resolver rather than around it.
                    dns: gateway.octets(),
                }
            });
        Config {
            v4: Some(Ipv4Config {
                address: lease.guest.octets(),
                prefix_len: lease.prefix_len(),
                peer: lease.gateway.octets(),
                // The resolver lives on the gateway address: the guest's
                // only reachable DNS destination is the one the host
                // terminates, which is what makes domain rules enforceable.
                dns: lease.gateway.octets(),
            }),
            v6,
            mtu: self.admitter.config().mtu,
            queue_count: limits::QUEUE_COUNT_V1,
            features: message::features::granted(offered, v6.is_some()),
            policy_epoch: self.admitter.config().policy_epoch,
        }
    }

    /// Answer a guest DNS question, applying domain policy before anything
    /// is returned.
    fn serve_dns(
        &mut self,
        packet: &[u8],
        meta: &ParsedIpPacket,
        now_millis: u64,
    ) -> Vec<GatewayEvent> {
        let mut events = Vec::new();
        if !self.take_dns_token(now_millis) {
            self.metrics.dns_rate_limited += 1;
            events.push(GatewayEvent::RateLimited);
            return events;
        }
        // Version 1 serves UDP DNS. TCP DNS to the resolver is admitted by
        // policy but not answered here; a guest that falls back to TCP sees
        // a refused connection rather than a hang.
        if meta.protocol != mvm_contract::l3::proto::UDP {
            self.metrics.dns_denied += 1;
            events.push(GatewayEvent::DnsDenied {
                name: String::new(),
                reason: "tcp_dns_unsupported",
            });
            return events;
        }
        // The protocol crate's extractor rather than this module's v4-only
        // one: a query may arrive in either family, and it has already
        // structurally validated this packet.
        let Some(payload) = ip::udp_payload(packet, meta) else {
            self.metrics.dns_denied += 1;
            events.push(GatewayEvent::DnsDenied {
                name: String::new(),
                reason: "malformed_datagram",
            });
            return events;
        };
        let Ok(question) = decode_query(payload) else {
            self.metrics.dns_denied += 1;
            events.push(GatewayEvent::DnsDenied {
                name: String::new(),
                reason: "malformed_query",
            });
            return events;
        };

        let epoch = self.admitter.config().policy_epoch;
        let ports = self.admitted_ports_for(&question.name);
        let response = match self.resolver.resolve(&question.name, question.qtype) {
            Ok((answers, ttl_secs)) => {
                let ttl_millis = u64::from(ttl_secs).saturating_mul(1000);
                match self.admitter.dns_mut().bind_answer(
                    &question.name,
                    &answers,
                    &ports,
                    ttl_millis,
                    epoch,
                    now_millis,
                ) {
                    Ok(bound) => {
                        self.metrics.dns_admitted += 1;
                        events.push(GatewayEvent::DnsAdmitted {
                            name: question.name.clone(),
                            answers: bound.len(),
                        });
                        encode_response(&question, DnsRcode::NoError, &bound)
                    }
                    Err(deny) => {
                        self.metrics.dns_denied += 1;
                        events.push(GatewayEvent::DnsDenied {
                            name: question.name.clone(),
                            reason: deny_label(&deny),
                        });
                        // REFUSED, not NXDOMAIN: the name may well exist,
                        // and telling the guest otherwise would be a lie it
                        // could cache.
                        encode_response(&question, DnsRcode::Refused, &[])
                    }
                }
            }
            Err(_) => {
                self.metrics.dns_denied += 1;
                events.push(GatewayEvent::DnsDenied {
                    name: question.name.clone(),
                    reason: "resolution_failed",
                });
                // REFUSED rather than a server-failure code: the shared
                // codec carries only the two outcomes policy needs, and a
                // failed lookup is, from the guest's side, the same fact —
                // this name is not available to it.
                encode_response(&question, DnsRcode::Refused, &[])
            }
        };

        // The reply comes from the gateway address, which inbound admission
        // recognizes as host-originated — and in the family the query
        // arrived in, since that is the only one the guest is listening on
        // for this exchange.
        let lease = *self.admitter.lease();
        let guest_port = meta.src_port.unwrap_or(0);
        self.ip_id = self.ip_id.wrapping_add(1);
        let reply = match (lease.gateway_v6, lease.guest_v6, meta.src) {
            (Some(gateway), Some(guest), IpAddr::V6(_)) => {
                build_udp_v6(gateway, guest, 53, guest_port, &response, DNS_REPLY_TTL)
            }
            _ => build_udp_v4(
                lease.gateway,
                lease.guest,
                53,
                guest_port,
                &response,
                DNS_REPLY_TTL,
                self.ip_id,
            ),
        };
        if reply.len() <= self.admitter.config().mtu as usize {
            self.queue_to_guest(&reply);
        } else {
            self.metrics.dns_denied += 1;
        }
        events
    }

    /// Ports the plan admits for `name`, so a binding never widens what was
    /// granted. An empty list means the name was admitted without a port
    /// constraint.
    fn admitted_ports_for(&self, _name: &str) -> Vec<u16> {
        // The canonical projection is expressed over addresses, not names,
        // so the port constraint a name inherits is whatever the resolved
        // address then has to satisfy at connect time. Returning an empty
        // list here keeps the binding itself port-agnostic and leaves the
        // per-packet port check to `CanonicalEgress`, which is the single
        // source of truth for it.
        Vec::new()
    }

    /// Frame a packet for the guest, tail-dropping when the queue is full.
    fn queue_to_guest(&mut self, packet: &[u8]) -> bool {
        if self.to_guest.len() >= self.queue_depth {
            self.metrics.queue_drops_ingress += 1;
            return false;
        }
        self.frame_buf.clear();
        if frame::encode_into(
            &mut self.frame_buf,
            MessageType::Packet,
            self.session.0,
            0,
            packet,
        )
        .is_err()
        {
            self.metrics.malformed_frames += 1;
            return false;
        }
        self.to_guest.push_back(self.frame_buf.clone());
        true
    }

    /// Fixed-window token bucket over DNS queries.
    fn take_dns_token(&mut self, now_millis: u64) -> bool {
        if now_millis.saturating_sub(self.dns_window_start_millis) >= 1000 {
            self.dns_window_start_millis = now_millis;
            self.dns_tokens = self.dns_qps;
        }
        if self.dns_tokens == 0 {
            return false;
        }
        self.dns_tokens -= 1;
        true
    }

    fn encode(&mut self, msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
        self.frame_buf.clear();
        // The payloads here are all fixed-size control messages well under
        // the cap, so encoding cannot fail; an empty frame on the impossible
        // path is still safe (the guest reads nothing).
        if frame::encode_into(&mut self.frame_buf, msg_type, self.session.0, 0, payload).is_err() {
            return Vec::new();
        }
        self.frame_buf.clone()
    }

    fn error_frame(&mut self, code: ErrorCode, detail: &str) -> Vec<u8> {
        let payload = ErrorMessage::new(code, detail).encode();
        self.encode(MessageType::Error, &payload)
    }
}

fn deny_label(deny: &mvm_net::l3::DnsDeny) -> &'static str {
    use mvm_net::l3::DnsDeny as D;
    match deny {
        D::NameNotAdmitted(_) => "name_not_admitted",
        D::Rebinding { .. } => "rebinding",
        D::NoAdmissibleAnswer(_) => "no_admissible_answer",
        D::TableFull { .. } => "binding_table_full",
        D::NameTableFull { .. } => "name_table_full",
        D::AliasChainTooDeep { .. } => "alias_chain_too_deep",
        D::MalformedName => "malformed_name",
    }
}

/// A resolver backed by a fixed table. Used by tests and by deployments
/// that pin every name.
pub struct StaticResolver {
    entries: std::collections::BTreeMap<String, (Vec<IpAddr>, u32)>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
        }
    }

    pub fn with(mut self, name: &str, ips: &[IpAddr], ttl_secs: u32) -> Self {
        self.entries
            .insert(name.to_ascii_lowercase(), (ips.to_vec(), ttl_secs));
        self
    }
}

impl Default for StaticResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl HostResolver for StaticResolver {
    fn resolve(
        &self,
        name: &str,
        _qtype: DnsRecordType,
    ) -> Result<(Vec<IpAddr>, u32), ResolveError> {
        self.entries
            .get(&name.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| ResolveError::Failed(name.to_string()))
    }
}

/// Whether an address is the one the gateway assigned to a machine — the
/// check the caller uses when routing an inbound host packet to a session.
pub fn belongs_to(lease: &AddressLease, addr: Ipv4Addr) -> bool {
    lease.guest == addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netd::datapath::LoopbackDatapath;
    use crate::netd::test_packets::{tcp, v4_packet};
    use crate::netd::userspace::UserspaceSocketDatapath;
    use mvm_contract::l3::proto;
    use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
    use mvm_net::l3::{AddressAllocator, AdmittedPacket, IngressMapping};
    use std::sync::Arc;
    use std::time::Duration;

    const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const SESSION: SessionId = SessionId(0x1122_3344_5566_7788);

    fn lease() -> AddressLease {
        AddressAllocator::with_defaults().allocate().unwrap()
    }

    use std::net::Ipv6Addr;

    const GATEWAY_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 1);
    const GUEST_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xc9, 0, 0, 0, 0, 0, 2);

    /// A minimal well-formed IPv6 packet carrying `payload`, with no
    /// extension headers.
    fn v6_packet(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        p[6] = protocol;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    /// A backend that carries everything except IPv6 flows — the shape the
    /// Linux TUN datapath reports until its v6 half lands.
    struct V4OnlyDatapath;

    impl L3Datapath for V4OnlyDatapath {
        fn open(
            &self,
            _req: &DatapathRequest,
        ) -> Result<Box<dyn crate::netd::datapath::DatapathHandle>, DatapathError> {
            LoopbackDatapath::sink().open(_req)
        }

        fn is_available(&self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn capabilities(&self) -> ForwardingCapabilities {
            ForwardingCapabilities {
                arbitrary_ipv6: false,
                ipv6_flows: false,
                ..ForwardingCapabilities::FULL_L3
            }
        }
    }

    fn rule(net: &str, port: u16) -> CanonicalRule {
        CanonicalRule {
            proto: Proto::Tcp,
            net: net.parse().unwrap(),
            port_lo: port,
            port_hi: port,
        }
    }

    fn open_gateway(policy: L3PolicyConfig, dp: &dyn L3Datapath) -> Gateway {
        let resolver =
            Arc::new(StaticResolver::new().with("api.example.com", &[IpAddr::V4(REMOTE)], 60));
        Gateway::open(
            GatewayConfig::new("vm-a", "sha256:plan", lease(), policy),
            SESSION,
            dp,
            resolver,
        )
        .unwrap()
    }

    fn open_443(dp: &dyn L3Datapath) -> Gateway {
        open_gateway(
            L3PolicyConfig {
                egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
                ..L3PolicyConfig::default()
            },
            dp,
        )
    }

    /// Drive the handshake to `Ready`.
    fn handshake(gw: &mut Gateway) {
        let hello = frame::encode(MessageType::Hello, 0, 0, &Hello::v1().encode()).unwrap();
        let (config_frame, _) = gw.handle_control_frame(&hello, 0).unwrap();
        let parsed = frame::decode(&config_frame).unwrap();
        assert_eq!(parsed.header.msg_type, MessageType::Config);
        let cfg = Config::decode(parsed.payload).unwrap();
        let ready = Ready {
            policy_epoch: cfg.policy_epoch,
            mtu: cfg.mtu,
            resolver_configured: true,
        };
        let ready_frame = frame::encode(MessageType::Ready, SESSION.0, 0, &ready.encode()).unwrap();
        let (_, events) = gw.handle_control_frame(&ready_frame, 1).unwrap();
        assert!(matches!(events[0], GatewayEvent::TunnelReady { .. }));
    }

    #[test]
    fn the_handshake_assigns_a_host_chosen_configuration() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        let hello = frame::encode(MessageType::Hello, 0, 0, &Hello::v1().encode()).unwrap();
        let (config_frame, _) = gw.handle_control_frame(&hello, 0).unwrap();
        let parsed = frame::decode(&config_frame).unwrap();
        assert_eq!(parsed.header.session_id, SESSION.0);
        let cfg = Config::decode(parsed.payload).unwrap();
        let v4 = cfg.v4.unwrap();
        let lease = *gw.admitter().lease();
        assert_eq!(v4.address, lease.guest.octets());
        assert_eq!(v4.peer, lease.gateway.octets());
        assert_eq!(
            v4.dns,
            lease.gateway.octets(),
            "the guest's only resolver must be the one the host terminates"
        );
        assert_eq!(cfg.queue_count, 1);
        assert_eq!(cfg.mtu, limits::MTU_V1);
    }

    #[test]
    fn packets_are_refused_until_ready() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 0).unwrap();
        assert!(matches!(
            events[0],
            GatewayEvent::FlowDenied {
                reason: DenyCode::SessionNotReady,
                ..
            }
        ));
    }

    #[test]
    fn an_admitted_packet_reaches_the_datapath() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 2).unwrap();
        assert!(matches!(events[0], GatewayEvent::FlowAdmitted { .. }));
        assert_eq!(gw.metrics().packets_egress, 1);
    }

    #[test]
    fn a_denied_packet_never_reaches_the_datapath() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        // Wrong port for the only rule.
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 8080, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 2).unwrap();
        assert!(matches!(
            events[0],
            GatewayEvent::FlowDenied {
                reason: DenyCode::PortNotAdmitted,
                ..
            }
        ));
        assert_eq!(gw.metrics().packets_egress, 0);
    }

    #[test]
    fn a_denied_packet_does_not_kill_the_connection() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let denied = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 22, ip::TCP_SYN));
        let allowed = v4_packet(proto::TCP, guest, REMOTE, &tcp(50001, 443, ip::TCP_SYN));
        let mut wire = Vec::new();
        frame::encode_into(&mut wire, MessageType::Packet, SESSION.0, 0, &denied).unwrap();
        frame::encode_into(&mut wire, MessageType::Packet, SESSION.0, 0, &allowed).unwrap();
        let events = gw.ingest_data_bytes(&wire, 2).unwrap();
        assert!(matches!(events[0], GatewayEvent::FlowDenied { .. }));
        assert!(
            matches!(events[1], GatewayEvent::FlowAdmitted { .. }),
            "one refused packet must not stop the rest of the guest's traffic"
        );
    }

    #[test]
    fn a_frame_bearing_another_sessions_id_is_dropped() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0 ^ 0xff, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 2).unwrap();
        assert_eq!(events, vec![GatewayEvent::StaleSession]);
        assert_eq!(gw.metrics().packets_egress, 0);
        assert_eq!(gw.metrics().stale_session_frames, 1);
    }

    #[test]
    fn a_control_message_on_the_data_connection_is_a_protocol_violation() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let wire = frame::encode(MessageType::Hello, SESSION.0, 0, &Hello::v1().encode()).unwrap();
        assert!(gw.ingest_data_bytes(&wire, 2).is_err());
    }

    #[test]
    fn an_oversized_frame_announcement_is_refused_before_allocation() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let bogus = ((limits::MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        assert!(gw.ingest_data_bytes(&bogus, 2).is_err());
        assert_eq!(gw.metrics().malformed_frames, 1);
    }

    #[test]
    fn return_traffic_is_delivered_and_unsolicited_traffic_is_not() {
        // Echo the packet back with src/dst and ports swapped.
        let dp = LoopbackDatapath::new(|pkt| {
            let mut reply = pkt.to_vec();
            let (src, dst) = (reply[12..16].to_vec(), reply[16..20].to_vec());
            reply[12..16].copy_from_slice(&dst);
            reply[16..20].copy_from_slice(&src);
            let (sp, dp_) = (reply[20..22].to_vec(), reply[22..24].to_vec());
            reply[20..22].copy_from_slice(&dp_);
            reply[22..24].copy_from_slice(&sp);
            Some(reply)
        });
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        gw.ingest_data_bytes(&wire, 2).unwrap();

        let pass = gw.poll_inbound(3);
        assert!(
            matches!(pass.events[0], GatewayEvent::InboundDelivered { .. }),
            "{:?}",
            pass.events
        );
        assert_eq!(gw.take_guest_frames().len(), 1);
    }

    /// A datapath whose inbound queue the test fills, so one pass meets far
    /// more than it is allowed to take.
    ///
    /// `LoopbackDatapath` cannot stand in: it produces at most one reply per
    /// packet the guest sent, so a burst larger than the guest's own traffic
    /// is unreachable through it.
    #[derive(Clone, Default)]
    struct BurstNetwork {
        inbound: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    }

    impl BurstNetwork {
        fn deliver(&self, packet: Vec<u8>) {
            self.inbound
                .lock()
                .expect("inbound queue")
                .push_back(packet);
        }

        /// Packets the network is still holding.
        fn queued(&self) -> usize {
            self.inbound.lock().expect("inbound queue").len()
        }
    }

    impl L3Datapath for BurstNetwork {
        fn open(&self, _req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
            Ok(Box::new(self.clone()))
        }

        fn is_available(&self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn capabilities(&self) -> ForwardingCapabilities {
            ForwardingCapabilities::FULL_L3
        }
    }

    impl DatapathHandle for BurstNetwork {
        fn send_to_network(&mut self, _packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
            Ok(())
        }

        fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
            match self.inbound.lock().expect("inbound queue").pop_front() {
                Some(packet) => {
                    let n = packet.len().min(buf.len());
                    buf[..n].copy_from_slice(&packet[..n]);
                    Ok(n)
                }
                None => Err(DatapathError::Io(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                ))),
            }
        }

        fn close(&mut self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn description(&self) -> String {
            "a host network holding a burst the test queued".to_string()
        }
    }

    /// The defect this pins: the drain ran until the datapath said
    /// `WouldBlock`, so a burst was taken in full before the pass returned
    /// to the guest-facing side. The guest-facing read has had a budget and
    /// a backlog report since it shipped; this is the same treatment
    /// pointed the other way.
    #[test]
    fn the_inbound_drain_stops_at_its_budget_and_says_so() {
        let dp = BurstNetwork::default();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        // Unsolicited, so each packet is refused rather than delivered: the
        // budget is spent per packet the drain takes off the datapath, and a
        // refusal costs the same pass as a delivery.
        let burst = MAX_INBOUND_PACKETS_PER_PASS * 3;
        for _ in 0..burst {
            dp.deliver(v4_packet(proto::TCP, REMOTE, guest, &tcp(443, 50000, 0)));
        }

        for pass in 0..3 {
            let taken = gw.poll_inbound(3);
            assert_eq!(
                taken.events.len(),
                MAX_INBOUND_PACKETS_PER_PASS,
                "pass {pass} must take its budget and no more"
            );
            assert_eq!(
                taken.drain,
                InboundDrain::Backlogged,
                "a pass its budget cut off has to say so, or the rest waits for \
                 a readiness edge that has already been spent"
            );
            assert_eq!(
                dp.queued(),
                burst - MAX_INBOUND_PACKETS_PER_PASS * (pass + 1),
                "the packets the budget cut off must still be on the datapath, \
                 not dropped"
            );
        }
        let after = gw.poll_inbound(3);
        assert!(
            after.events.is_empty(),
            "the burst is exhausted, so the pass after it takes nothing"
        );
        assert_eq!(after.drain, InboundDrain::Idle);
    }

    /// A datapath that always says its own bound cut the pass short.
    ///
    /// The report belongs to the datapath — a userspace one raises it when a
    /// flow's host-to-guest pump stops at its byte budget — and the driver
    /// that decides whether to wait sits above the gateway, so the gateway
    /// has to carry it rather than swallow it.
    #[derive(Clone, Default)]
    struct BackloggedNetwork;

    impl L3Datapath for BackloggedNetwork {
        fn open(&self, _req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
            Ok(Box::new(self.clone()))
        }

        fn is_available(&self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn capabilities(&self) -> ForwardingCapabilities {
            ForwardingCapabilities::FULL_L3
        }
    }

    impl DatapathHandle for BackloggedNetwork {
        fn send_to_network(&mut self, _packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
            Ok(())
        }

        fn recv_from_network(&mut self, _buf: &mut [u8]) -> Result<usize, DatapathError> {
            Err(DatapathError::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock,
            )))
        }

        fn service(&mut self, _now_millis: u64) -> Result<InboundDrain, DatapathError> {
            Ok(InboundDrain::Backlogged)
        }

        fn close(&mut self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn description(&self) -> String {
            "a host network whose every service pass ends backlogged".to_string()
        }
    }

    #[test]
    fn a_backlogged_service_pass_reaches_the_caller_that_decides_to_wait() {
        let dp = BackloggedNetwork;
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        assert_eq!(
            gw.service_datapath(3).expect("service"),
            InboundDrain::Backlogged,
            "the gateway may not swallow a datapath's backlog: it is the \
             driver above that decides whether to wait, not this"
        );
    }

    #[test]
    fn an_unsolicited_inbound_packet_is_refused() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        // Inject directly: nothing was sent, so nothing may come back.
        let events = {
            let unsolicited = v4_packet(proto::TCP, REMOTE, guest, &tcp(443, 50000, 0));
            // Round-trip it through a datapath that replays one packet.
            let dp2 = LoopbackDatapath::new(move |_| None);
            let mut gw2 = open_443(&dp2);
            handshake(&mut gw2);
            match gw2.admitter_mut().admit_inbound(&unsolicited, 5) {
                InboundVerdict::Deny(code) => code,
                InboundVerdict::Deliver(_) => panic!("unsolicited inbound must be refused"),
            }
        };
        assert_eq!(events, DenyCode::UnsolicitedInbound);
    }

    #[test]
    fn a_declared_ingress_mapping_admits_a_new_inbound_flow() {
        let dp = LoopbackDatapath::sink();
        let mut config = GatewayConfig::new(
            "vm-a",
            "sha256:plan",
            lease(),
            L3PolicyConfig {
                egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
                ..L3PolicyConfig::default()
            },
        );
        config
            .ingress
            .declare(IngressMapping::tcp("0.0.0.0".parse().unwrap(), 8080, 80))
            .unwrap();
        let mut gw = Gateway::open(config, SESSION, &dp, Arc::new(StaticResolver::new())).unwrap();
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let inbound = v4_packet(proto::TCP, REMOTE, guest, &tcp(40000, 80, ip::TCP_SYN));
        assert!(matches!(
            gw.admitter_mut().admit_inbound(&inbound, 5),
            InboundVerdict::Deliver(_)
        ));
    }

    /// Drive the gateway the way its loop does — service the datapath,
    /// then drain what it produced — until `ready` holds. Bounded: a
    /// condition that never comes true must fail an assertion, never hang.
    fn drive_gateway_until(gw: &mut Gateway, ready: impl Fn(&Gateway) -> bool) -> bool {
        for pass in 0..200u64 {
            gw.service_datapath(pass).expect("service");
            gw.poll_inbound(pass);
            if ready(gw) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }

    /// **Default-deny holds across the seam, for a real inbound datagram.**
    ///
    /// The userspace datapath binds a host listener because the plan
    /// declared a mapping — but binding is not admitting. Every datagram
    /// that listener produces leaves through the datapath's read path and
    /// goes back through `admit_inbound`, which refuses one whose guest
    /// port has no declared mapping. Withdrawing the declaration stops
    /// delivery while the socket is still bound and still receiving, which
    /// is the only arrangement in which "the datapath cannot smuggle an
    /// undeclared delivery" means anything: the packet exists, it reaches
    /// the seam, and the seam is what turns it away.
    #[test]
    fn an_inbound_datagram_reaches_the_guest_only_while_its_mapping_is_declared() {
        let host_port = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("probe a free port")
            .local_addr()
            .expect("local addr")
            .port();
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut config =
            GatewayConfig::new("vm-a", "sha256:plan", lease(), L3PolicyConfig::default());
        config
            .ingress
            .declare(IngressMapping::udp(loopback, host_port, 5140))
            .expect("declare a datagram mapping");
        let dp = UserspaceSocketDatapath::new();
        let mut gw = Gateway::open(config, SESSION, &dp, Arc::new(StaticResolver::new()))
            .expect("the backend advertises declared ingress, so this plan is servable");
        handshake(&mut gw);

        let declared = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a peer");
        declared
            .send_to(b"declared", (Ipv4Addr::LOCALHOST, host_port))
            .expect("a peer datagram toward the declared mapping");
        assert!(
            drive_gateway_until(&mut gw, |g| g.metrics().packets_ingress > 0),
            "a datagram for a declared mapping must reach the guest, or the refusal \
             below proves nothing"
        );
        assert_eq!(gw.metrics().denies_for(DenyCode::UnsolicitedInbound), 0);

        gw.admitter_mut()
            .ingress_mut()
            .withdraw(loopback, host_port);

        // A second peer, deliberately. The first one's datagram opened a
        // flow-table entry, so anything further from that exact 4-tuple is
        // return traffic and would be admitted on the flow rather than on
        // the declaration — which would make this assert nothing.
        let stranger = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a second peer");
        stranger
            .send_to(b"undeclared", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        assert!(
            drive_gateway_until(&mut gw, |g| g
                .metrics()
                .denies_for(DenyCode::UnsolicitedInbound)
                > 0),
            "a datagram whose guest port is no longer declared must be refused and counted"
        );
        assert_eq!(
            gw.metrics().packets_ingress,
            1,
            "and nothing beyond the declared one reached the guest"
        );
    }

    // ---- DNS --------------------------------------------------------

    fn dns_query(name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes()); // A
        msg.extend_from_slice(&1u16.to_be_bytes()); // IN
        msg
    }

    fn dns_packet(gw: &Gateway, name: &str) -> Vec<u8> {
        let lease = *gw.admitter().lease();
        let query = dns_query(name);
        let mut udp = Vec::new();
        udp.extend_from_slice(&40000u16.to_be_bytes());
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&((8 + query.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&query);
        v4_packet(proto::UDP, lease.guest, lease.gateway, &udp)
    }

    #[test]
    fn an_approved_domain_is_answered_and_then_reachable() {
        let dp = LoopbackDatapath::sink();
        // Deny-all static rules: only the DNS binding can open the path.
        let mut gw = open_gateway(L3PolicyConfig::default(), &dp);
        handshake(&mut gw);

        let query = dns_packet(&gw, "api.example.com");
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &query).unwrap();
        let events = gw.ingest_data_bytes(&wire, 10).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GatewayEvent::DnsAdmitted { answers: 1, .. })),
            "{events:?}"
        );
        // The answer was framed back to the guest.
        assert_eq!(gw.take_guest_frames().len(), 1);

        // And the address it returned is now reachable.
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 11).unwrap();
        assert!(matches!(events[0], GatewayEvent::FlowAdmitted { .. }));
    }

    /// A query arriving over IPv6 has to be answered over IPv6. The reply
    /// is built by the gateway, not by a stack that would have picked the
    /// family for it, so a v4-only builder would leave a dual-stack guest
    /// waiting on an answer that was never addressed to it.
    #[test]
    fn a_v6_dns_query_is_answered_from_the_v6_gateway_address() {
        let dp = LoopbackDatapath::sink();
        let resolver =
            Arc::new(StaticResolver::new().with("api.example.com", &[IpAddr::V4(REMOTE)], 60));
        let mut gw = Gateway::open(
            GatewayConfig::new(
                "vm-a",
                "sha256:plan",
                lease().with_v6(GATEWAY_V6, GUEST_V6),
                L3PolicyConfig::default(),
            ),
            SESSION,
            &dp,
            resolver,
        )
        .unwrap();
        handshake(&mut gw);

        let query = dns_query("api.example.com");
        let mut udp = Vec::new();
        udp.extend_from_slice(&40000u16.to_be_bytes());
        udp.extend_from_slice(&53u16.to_be_bytes());
        udp.extend_from_slice(&((8 + query.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&query);
        let packet = v6_packet(proto::UDP, GUEST_V6, GATEWAY_V6, &udp);

        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &packet).unwrap();
        let events = gw.ingest_data_bytes(&wire, 10).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GatewayEvent::DnsAdmitted { answers: 1, .. })),
            "{events:?}"
        );

        let frames = gw.take_guest_frames();
        assert_eq!(frames.len(), 1, "the guest is owed exactly one answer");
        let decoded = frame::decode(&frames[0]).unwrap();
        let reply = ip::parse(decoded.payload).expect("the answer is a well-formed packet");
        assert_eq!(reply.src, IpAddr::V6(GATEWAY_V6));
        assert_eq!(reply.dst, IpAddr::V6(GUEST_V6));
        assert_eq!(reply.src_port, Some(53));
        assert_eq!(reply.dst_port, Some(40000));
    }

    #[test]
    fn a_denied_domain_is_refused_and_opens_nothing() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_gateway(L3PolicyConfig::default(), &dp);
        handshake(&mut gw);
        let query = dns_packet(&gw, "evil.example.com");
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &query).unwrap();
        let events = gw.ingest_data_bytes(&wire, 10).unwrap();
        assert!(
            events.iter().any(|e| matches!(
                e,
                GatewayEvent::DnsDenied {
                    reason: "resolution_failed",
                    ..
                }
            )),
            "{events:?}"
        );
        // Nothing became reachable.
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 11).unwrap();
        assert!(matches!(events[0], GatewayEvent::FlowDenied { .. }));
    }

    #[test]
    fn a_rebinding_answer_is_refused_and_the_guest_is_told_refused() {
        let resolver = Arc::new(StaticResolver::new().with(
            "rebind.example.com",
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            60,
        ));
        let dp = LoopbackDatapath::sink();
        let mut gw = Gateway::open(
            GatewayConfig::new("vm-a", "sha256:plan", lease(), L3PolicyConfig::default()),
            SESSION,
            &dp,
            resolver,
        )
        .unwrap();
        handshake(&mut gw);
        let query = dns_packet(&gw, "rebind.example.com");
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &query).unwrap();
        let events = gw.ingest_data_bytes(&wire, 10).unwrap();
        assert!(
            events.iter().any(|e| matches!(
                e,
                GatewayEvent::DnsDenied {
                    reason: "rebinding",
                    ..
                }
            )),
            "{events:?}"
        );
    }

    #[test]
    fn dns_queries_are_rate_limited() {
        let dp = LoopbackDatapath::sink();
        let mut config =
            GatewayConfig::new("vm-a", "sha256:plan", lease(), L3PolicyConfig::default());
        config.dns_qps = 2;
        let resolver =
            Arc::new(StaticResolver::new().with("api.example.com", &[IpAddr::V4(REMOTE)], 60));
        let mut gw = Gateway::open(config, SESSION, &dp, resolver).unwrap();
        handshake(&mut gw);
        let query = dns_packet(&gw, "api.example.com");
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &query).unwrap();
        for _ in 0..2 {
            gw.ingest_data_bytes(&wire, 10).unwrap();
        }
        let events = gw.ingest_data_bytes(&wire, 10).unwrap();
        assert!(events.contains(&GatewayEvent::RateLimited), "{events:?}");
        assert_eq!(gw.metrics().dns_rate_limited, 1);
        // A new window refills the bucket.
        let events = gw.ingest_data_bytes(&wire, 1100).unwrap();
        assert!(!events.contains(&GatewayEvent::RateLimited));
    }

    // ---- bounds and cleanup ----------------------------------------

    #[test]
    fn the_guest_queue_tail_drops_instead_of_growing() {
        let dp = LoopbackDatapath::sink();
        let mut config = GatewayConfig::new(
            "vm-a",
            "sha256:plan",
            lease(),
            L3PolicyConfig {
                egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
                ..L3PolicyConfig::default()
            },
        );
        config.queue_depth = 4;
        let mut gw = Gateway::open(config, SESSION, &dp, Arc::new(StaticResolver::new())).unwrap();
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        for _ in 0..10 {
            let reply = v4_packet(proto::TCP, REMOTE, guest, &tcp(443, 50000, 0));
            gw.queue_to_guest(&reply);
        }
        assert_eq!(gw.take_guest_frames().len(), 4);
        assert_eq!(gw.metrics().queue_drops_ingress, 6);
    }

    #[test]
    fn closing_releases_every_resource_and_is_idempotent() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        gw.ingest_data_bytes(&wire, 2).unwrap();
        assert_eq!(gw.admitter().flows().len(), 1);

        let events = gw.close();
        assert_eq!(events, vec![GatewayEvent::CleanedUp { session: SESSION }]);
        assert_eq!(gw.state(), GatewayState::Closed);
        assert!(gw.admitter().flows().is_empty());
        assert!(gw.admitter().dns().is_empty());
        assert!(gw.admitter().ingress().is_empty());
        assert!(gw.take_guest_frames().is_empty());

        assert!(gw.close().is_empty(), "closing twice must be a no-op");
    }

    #[test]
    fn a_closed_gateway_admits_nothing_further() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        gw.close();
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        let events = gw.ingest_data_bytes(&wire, 3).unwrap();
        assert!(matches!(
            events[0],
            GatewayEvent::FlowDenied {
                reason: DenyCode::SessionNotReady,
                ..
            }
        ));
    }

    #[test]
    fn a_guest_shutdown_closes_the_gateway() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let wire = frame::encode(
            MessageType::Shutdown,
            SESSION.0,
            0,
            &Shutdown {
                reason: ShutdownReason::GuestExiting,
            }
            .encode(),
        )
        .unwrap();
        let (_, events) = gw.handle_control_frame(&wire, 5).unwrap();
        assert_eq!(events, vec![GatewayEvent::CleanedUp { session: SESSION }]);
        assert_eq!(gw.state(), GatewayState::Closed);
    }

    #[test]
    fn ticking_expires_idle_flows_and_stale_bindings() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        handshake(&mut gw);
        let guest = gw.admitter().lease().guest;
        let pkt = v4_packet(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
        let wire = frame::encode(MessageType::Packet, SESSION.0, 0, &pkt).unwrap();
        gw.ingest_data_bytes(&wire, 0).unwrap();
        assert_eq!(gw.tick(1), 0);
        assert_eq!(gw.tick(mvm_net::l3::flow::DEFAULT_TCP_IDLE_MILLIS), 1);
        assert!(gw.admitter().flows().is_empty());
    }

    #[test]
    fn an_unsupported_platform_refuses_to_open_a_gateway() {
        let dp = super::super::datapath::UnsupportedDatapath::new("macos");
        let err = Gateway::open(
            GatewayConfig::new("vm-a", "sha256:plan", lease(), L3PolicyConfig::default()),
            SESSION,
            &dp,
            Arc::new(StaticResolver::new()),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GatewayError::Datapath(DatapathError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_stale_ready_frame_is_refused_with_a_named_error() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        let hello = frame::encode(MessageType::Hello, 0, 0, &Hello::v1().encode()).unwrap();
        gw.handle_control_frame(&hello, 0).unwrap();
        let ready = Ready {
            policy_epoch: 0,
            mtu: limits::MTU_V1,
            resolver_configured: true,
        };
        let wire = frame::encode(MessageType::Ready, SESSION.0 ^ 0xff, 0, &ready.encode()).unwrap();
        let (reply, events) = gw.handle_control_frame(&wire, 1).unwrap();
        assert_eq!(events, vec![GatewayEvent::StaleSession]);
        let parsed = frame::decode(&reply).unwrap();
        assert_eq!(parsed.header.msg_type, MessageType::Error);
        assert_eq!(
            ErrorMessage::decode(parsed.payload).unwrap().code,
            ErrorCode::StaleSession
        );
        assert_ne!(gw.state(), GatewayState::Ready);
    }

    #[test]
    fn a_guest_reporting_a_different_mtu_is_a_protocol_violation() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_443(&dp);
        let hello = frame::encode(MessageType::Hello, 0, 0, &Hello::v1().encode()).unwrap();
        gw.handle_control_frame(&hello, 0).unwrap();
        let ready = Ready {
            policy_epoch: 0,
            mtu: 9000,
            resolver_configured: true,
        };
        let wire = frame::encode(MessageType::Ready, SESSION.0, 0, &ready.encode()).unwrap();
        assert!(gw.handle_control_frame(&wire, 1).is_err());
    }

    /// The lease is the request. A machine issued a v6 pair has one
    /// because something admitted it, so the backend that carries its
    /// traffic has to be able to carry that family — otherwise the guest
    /// gets an address whose packets die somewhere it cannot see.
    #[test]
    fn a_lease_with_a_v6_pair_requires_ipv6_flows_of_the_backend() {
        let dual = GatewayConfig::new(
            "vm-a",
            "sha256:plan",
            lease().with_v6(GATEWAY_V6, GUEST_V6),
            L3PolicyConfig::default(),
        );
        assert!(
            dual.required_capabilities.ipv6_flows,
            "a v6 lease must require ipv6_flows of the forwarding backend"
        );
        let v4_only = GatewayConfig::new("vm-a", "sha256:plan", lease(), L3PolicyConfig::default());
        assert!(
            !v4_only.required_capabilities.ipv6_flows,
            "a v4-only lease must require exactly what it required before v6 existed"
        );
    }

    /// A backend that cannot carry v6 flows must refuse the session before
    /// the VM boots, rather than drop the guest's v6 packets afterwards.
    #[test]
    fn a_backend_without_ipv6_flows_refuses_a_dual_stack_lease() {
        let dp = V4OnlyDatapath;
        let resolver = Arc::new(StaticResolver::new());
        let err = Gateway::open(
            GatewayConfig::new(
                "vm-a",
                "sha256:plan",
                lease().with_v6(GATEWAY_V6, GUEST_V6),
                L3PolicyConfig::default(),
            ),
            SESSION,
            &dp,
            resolver.clone(),
        )
        .expect_err("a v4-only backend cannot serve a dual-stack lease");
        assert!(
            matches!(
                &err,
                GatewayError::Datapath(DatapathError::CapabilityShortfall { missing, .. })
                    if missing.contains(&"ipv6_flows")
            ),
            "{err:?}"
        );
        // The same backend still serves a v4-only lease: the refusal is
        // about what was leased, not about the backend as such.
        Gateway::open(
            GatewayConfig::new("vm-a", "sha256:plan", lease(), L3PolicyConfig::default()),
            SESSION,
            &dp,
            resolver,
        )
        .expect("a v4-only lease is within a v4-only backend's capabilities");
    }

    /// The end of the host-side half: what the allocator leased has to be
    /// what the guest is told to configure, verbatim and in both families.
    #[test]
    fn the_assigned_config_carries_the_leases_v6_pair() {
        let dp = LoopbackDatapath::sink();
        let mut gw = Gateway::open(
            GatewayConfig::new(
                "vm-a",
                "sha256:plan",
                lease().with_v6(GATEWAY_V6, GUEST_V6),
                L3PolicyConfig::default(),
            ),
            SESSION,
            &dp,
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
        let guest_v4 = gw.admitter().lease().guest;
        let hello = frame::encode(MessageType::Hello, 0, 0, &Hello::v1().encode()).unwrap();
        let (config_frame, _) = gw.handle_control_frame(&hello, 0).unwrap();
        let parsed = frame::decode(&config_frame).unwrap();
        let cfg = Config::decode(parsed.payload).unwrap();

        let v6 = cfg
            .v6
            .expect("a dual-stack lease assigns a v6 configuration");
        assert_eq!(Ipv6Addr::from(v6.address), GUEST_V6);
        assert_eq!(Ipv6Addr::from(v6.peer), GATEWAY_V6);
        // The resolver is the gateway in both families, so a guest that
        // prefers v6 still reaches the host-terminated resolver — the one
        // thing that makes domain rules enforceable.
        assert_eq!(Ipv6Addr::from(v6.dns), GATEWAY_V6);
        assert_ne!(
            cfg.features & message::features::IPV6,
            0,
            "the granted feature bits must say the v6 half is live"
        );
        // The v4 half is untouched.
        let v4 = cfg.v4.expect("a dual-stack assignment is additive");
        assert_eq!(Ipv4Addr::from(v4.address), guest_v4);
    }

    /// A v4-only machine must see exactly the bytes it saw before any of
    /// this existed.
    #[test]
    fn a_v4_only_lease_assigns_no_v6_and_grants_no_feature_bit() {
        let dp = LoopbackDatapath::sink();
        let mut gw = open_gateway(L3PolicyConfig::default(), &dp);
        let hello = frame::encode(MessageType::Hello, 0, 0, &Hello::v1().encode()).unwrap();
        let (config_frame, _) = gw.handle_control_frame(&hello, 0).unwrap();
        let cfg = Config::decode(frame::decode(&config_frame).unwrap().payload).unwrap();
        assert_eq!(cfg.v6, None);
        assert_eq!(cfg.features, 0);
    }

    /// Silently degrading to v4 would leave an operator believing the
    /// workload got the family its plan asked for.
    #[test]
    fn a_guest_that_does_not_offer_ipv6_is_refused_a_v6_lease() {
        let dp = LoopbackDatapath::sink();
        let mut gw = Gateway::open(
            GatewayConfig::new(
                "vm-a",
                "sha256:plan",
                lease().with_v6(GATEWAY_V6, GUEST_V6),
                L3PolicyConfig::default(),
            ),
            SESSION,
            &dp,
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
        let silent_guest = Hello {
            version: limits::PROTOCOL_VERSION,
            features: 0,
            max_queues: 1,
        };
        let hello = frame::encode(MessageType::Hello, 0, 0, &silent_guest.encode()).unwrap();
        let (reply, _) = gw.handle_control_frame(&hello, 0).unwrap();
        let parsed = frame::decode(&reply).unwrap();
        assert_eq!(
            parsed.header.msg_type,
            MessageType::Error,
            "a guest that cannot apply the assignment must be told, not quietly downgraded"
        );
    }

    #[test]
    fn arbitrary_data_bytes_never_panic() {
        let mut state = 0xFEED_FACE_DEAD_BEEFu64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..250usize {
            let dp = LoopbackDatapath::sink();
            let mut gw = open_443(&dp);
            handshake(&mut gw);
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = gw.ingest_data_bytes(&buf, 5);
        }
    }
}
