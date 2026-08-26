//! FlowMux session acceptor for the single workload networking endpoint.
//!
//! This module owns the host side of one authenticated FlowMux session:
//! handshake, frame I/O, and dispatch to the per-flow handlers. The current
//! implementation accepts one session, completes the handshake, and runs a
//! minimal TCP data relay, one-shot DNS resolution, and a basic UDP association
//! relay for guest-initiated `OpenTcp`, `Resolve`, and `OpenUdp` flows.
//! Everything else fails closed with `GoAway`.

mod http_flow;
mod ingress;
pub mod registry;
mod resources;
mod tcp_relay;
use tcp_relay::connect_first_admitted;
mod udp_relay;
mod wire;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::dns::{MAX_DNS_MESSAGE, decode_query, encode_response};
use mvm_contract::protocol::network_flow::hello::{Handshake, agree};
use mvm_contract::protocol::network_flow::{
    Direction, FrameError, HEADER_LEN, IngressFlowKind, LENGTH_PREFIX_LEN, Opcode,
    SessionValidator, UDP_ADDR_PREFIX_LEN, decode,
};
use mvm_core::net::session::Session;
use mvm_vmm::vsock_egress_bridge::egress_gate::{DnsVerdict, EgressGate, EgressVerdict};
use tracing::{info, warn};

pub use self::ingress::FlowMuxIngressHandle;
use self::ingress::{
    SharedIngressOpenWaiters, SharedUdpAssociations, emit_unbound_audit, lock_pending_ingress,
    lock_tcp_streams, lock_udp_associations,
};
use self::registry::{RegistryLimits, StreamRegistry, class_for_open};
pub use self::resources::{
    ConnectionRateLimiter, FlowMuxVmResources, MAX_CONCURRENT_FLOWMUX_SESSIONS,
};
use self::udp_relay::{
    UdpAssociationHandle, UdpPeerAdmission, UdpRelayParams, UdpSendMsg, decode_udp_addr,
    run_udp_relay, udp_event_sources,
};
use self::wire::{
    is_peer_disconnect, lock_registry, lock_session, lock_validator, parse_host_port,
    write_frame_to,
};

use crate::supervisor::audit_recorder::{EventCategory, Recorder};
use crate::supervisor::dns_resolver::resolve_hostname_ips;
/// How this side names itself in a handshake refusal. Only ever read by a
/// human reading the error.
const HOST_BUILD: &str = concat!("mvm-hostd ", env!("CARGO_PKG_VERSION"));

/// Per-address connect budget when trying an admitted set: small so an
/// unreachable address (e.g. an AAAA with no host IPv6 egress) fails over to
/// the next candidate quickly.
const PER_IP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Why the FlowMux session ended.
#[derive(Debug, thiserror::Error)]
pub enum FlowMuxError {
    /// Handshake with the guest failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// A frame from the guest violated the protocol or session state.
    #[error("frame refused: {0}")]
    FrameRefused(String),
    /// An I/O error occurred on the transport.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),
}

/// Host-owned context for one authenticated FlowMux session.
pub struct FlowMuxSession {
    /// The read half of the underlying authenticated stream. Only the main
    /// session thread reads from this fd.
    reader: UnixStream,
    /// The write half, shared with per-stream relay threads so they can send
    /// `Data`/`HalfClose`/`Reset` frames back to the guest.
    writer: Arc<Mutex<UnixStream>>,
    /// The authenticated session is shared between the main thread (for
    /// opening inbound frames) and relay threads (for sealing outbound frames).
    /// Both directions use independent sequence counters inside one session.
    session: Arc<Mutex<Session>>,
    /// Shared with the per-stream relay threads.
    ///
    /// The relay writes the host's own `Data` frames, and those have to be
    /// admitted here or this side's credit counter is credited by every guest
    /// grant and debited by nothing.
    validator: Arc<Mutex<SessionValidator>>,
    registry: Arc<Mutex<StreamRegistry>>,
    /// Active guest-initiated TCP streams and their upstream sockets. The host
    /// half of each stream lives in a dedicated thread.
    streams: Arc<Mutex<BTreeMap<u32, TcpStreamHandle>>>,
    /// Host-initiated opens awaiting the guest's loopback connect decision.
    pending_ingress: SharedIngressOpenWaiters,
    /// The rate/inflight guard the ICMP verb admits against.
    ///
    /// Per session, like the registry: one guest's echoes cannot spend
    /// another's budget.
    icmp_rate: Arc<crate::supervisor::egress_rate::EgressRateGuard>,
    /// Typed HTTP flows still being assembled, by stream id.
    http_flows: http_flow::HttpFlows,
    /// Cancellation owners for typed HTTP tasks after their request assembly
    /// entry has been released.
    http_cancellations: http_flow::HttpCancellations,
    /// The substitution service typed HTTP flows are forwarded through.
    ///
    /// `None` on an endpoint that assembled no substitution service, where an
    /// `OpenHttp` is refused rather than silently forwarded unsubstituted —
    /// forwarding it would send a `mvm-secret-<hex>` placeholder to a real
    /// upstream.
    substitution: Option<Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>>,
    /// Active guest-initiated UDP associations. Each association runs in its
    /// own relay thread.
    udp_associations: SharedUdpAssociations,
    gate: Arc<EgressGate>,
    read_buf: Vec<u8>,
    limits: RegistryLimits,
    connect_timeout: Duration,
    /// Optional chain-signed audit recorder. The endpoint process builds this
    /// from the tenant's host signer key; tests run without one.
    recorder: Option<Arc<Recorder>>,
    /// Captured Tokio runtime handle so synchronous session code can drive
    /// the async audit signer without spawning a background task.
    runtime_handle: Option<tokio::runtime::Handle>,
    /// Per-class rate limiter for new TCP connects, UDP associations, and
    /// DNS resolves.
    rate_limiter: Arc<ConnectionRateLimiter>,
}

impl std::fmt::Debug for FlowMuxSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowMuxSession")
            .field("session_id", &self.session_id())
            .field("streams", &lock_tcp_streams(&self.streams).len())
            .finish_non_exhaustive()
    }
}

/// The host-side handle for one active TCP flow. The relay thread owns a
/// clone of `upstream`; this half lets the main thread forward guest data and
/// shut the socket down when the guest closes or resets.
struct TcpStreamHandle {
    upstream: TcpStream,
    /// Set by the relay thread when the upstream socket reaches EOF.
    host_half_closed: Arc<AtomicBool>,
    /// Set by the main thread when the stream is being torn down so the relay
    /// thread does not emit a stale `HalfClose` or `Reset` after an explicit
    /// reset or full close.
    retired: Arc<AtomicBool>,
}

/// What one accepted FlowMux session needs to serve.
///
/// A struct with a builder rather than a longer argument list: the optional
/// halves — the audit recorder and the substitution service — are exactly the
/// ones a caller is most likely to pass in the wrong order.
pub struct FlowMuxAccept {
    session_id: String,
    host_key: SigningKey,
    guest_anchor: VerifyingKey,
    limits: RegistryLimits,
    gate: Arc<EgressGate>,
    recorder: Option<Arc<Recorder>>,
    substitution: Option<Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>>,
    vm_resources: Option<Arc<FlowMuxVmResources>>,
    ingress_mappings: Vec<(u16, IngressFlowKind)>,
}

impl FlowMuxAccept {
    /// The required half: who this session is, whose key signs it, and which
    /// single guest identity it will accept.
    #[must_use]
    pub fn new(
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
    ) -> Self {
        Self::new_shared(session_id, host_key, guest_anchor, limits, Arc::new(gate))
    }

    /// Build from the endpoint's single shared claim-10 policy object.
    #[must_use]
    pub fn new_shared(
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: VerifyingKey,
        limits: RegistryLimits,
        gate: Arc<EgressGate>,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            host_key,
            guest_anchor,
            limits,
            gate,
            recorder: None,
            substitution: None,
            vm_resources: None,
            ingress_mappings: Vec::new(),
        }
    }

    /// Attach the chain-signed audit recorder.
    #[must_use]
    pub fn with_recorder(mut self, recorder: Option<Arc<Recorder>>) -> Self {
        self.recorder = recorder;
        self
    }

    /// Attach the substitution service typed HTTP flows forward through.
    ///
    /// Without it an `OpenHttp` is refused: a flow that may name a
    /// `mvm-secret-<hex>` placeholder has nothing to resolve it, and
    /// forwarding it anyway would put the placeholder on the wire to a real
    /// upstream.
    #[must_use]
    pub fn with_substitution(
        mut self,
        substitution: Option<Arc<crate::supervisor::network_endpoint_proxy::SubstitutionService>>,
    ) -> Self {
        self.substitution = substitution;
        self
    }

    /// Attach the endpoint's VM-wide budget, rate guards, and session owner.
    #[must_use]
    pub fn with_vm_resources(mut self, resources: Arc<FlowMuxVmResources>) -> Self {
        self.vm_resources = Some(resources);
        self
    }

    /// Attach the signed ingress mapping IDs this session may open.
    #[must_use]
    pub fn with_ingress_mappings(mut self, mappings: impl IntoIterator<Item = u16>) -> Self {
        self.ingress_mappings = mappings
            .into_iter()
            .map(|mapping| (mapping, IngressFlowKind::Tcp))
            .collect();
        self
    }

    /// Attach signed ingress mapping IDs and their transport classes.
    #[must_use]
    pub fn with_ingress_transports(
        mut self,
        mappings: impl IntoIterator<Item = (u16, IngressFlowKind)>,
    ) -> Self {
        self.ingress_mappings = mappings.into_iter().collect();
        self
    }
}

impl Drop for FlowMuxSession {
    fn drop(&mut self) {
        let mut cancellations = self
            .http_cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, sender) in std::mem::take(&mut *cancellations) {
            let _ = sender.send(true);
        }
    }
}

impl FlowMuxSession {
    /// Return the session identifier for logging and correlation.
    pub fn session_id(&self) -> String {
        lock_session(&self.session).session_id().to_string()
    }

    /// Clone the host-initiated ingress half of this authenticated session.
    #[must_use]
    pub fn ingress_handle(&self) -> FlowMuxIngressHandle {
        FlowMuxIngressHandle {
            session: Arc::clone(&self.session),
            writer: Arc::clone(&self.writer),
            validator: Arc::clone(&self.validator),
            registry: Arc::clone(&self.registry),
            streams: Arc::clone(&self.streams),
            pending: Arc::clone(&self.pending_ingress),
            credit_wait: self.limits.credit_wait,
            recorder: self.recorder.as_ref().map(Arc::clone),
            runtime_handle: self.runtime_handle.clone(),
            udp_associations: Arc::clone(&self.udp_associations),
            udp_idle_timeout: self.limits.udp_idle_timeout,
            max_udp_peers: self.limits.max_udp_peers,
        }
    }

    /// Accept one authenticated FlowMux session on `stream`.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept(
        stream: UnixStream,
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: &VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
    ) -> Result<Self, FlowMuxError> {
        Self::accept_with(
            stream,
            FlowMuxAccept::new(session_id, host_key, guest_anchor.to_owned(), limits, gate),
        )
    }

    /// Accept one authenticated FlowMux session with an optional audit
    /// recorder attached.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept_with(
        mut stream: UnixStream,
        params: FlowMuxAccept,
    ) -> Result<Self, FlowMuxError> {
        let FlowMuxAccept {
            session_id,
            host_key,
            guest_anchor,
            limits,
            gate,
            recorder,
            substitution,
            vm_resources,
            ingress_mappings,
        } = params;
        let session_id = session_id.as_str();
        // Split the socket into independent read/write descriptors so the
        // main thread can block on guest frames while relay threads emit
        // upstream data back to the guest.
        let writer = stream.try_clone()?;
        let (session, _peer_key) = Session::host(&mut stream, session_id, host_key)
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        if session.peer_verifying_key() != &guest_anchor {
            return Err(FlowMuxError::Handshake(
                "guest identity does not match pinned anchor".to_string(),
            ));
        }

        info!(session_id, "FlowMux handshake complete");

        let resources = vm_resources
            .unwrap_or_else(|| Arc::new(FlowMuxVmResources::from_registry_limits(limits)));
        Ok(Self {
            reader: stream,
            writer: Arc::new(Mutex::new(writer)),
            session: Arc::new(Mutex::new(session)),
            validator: Arc::new(Mutex::new(SessionValidator::new_with_ingress(
                ingress_mappings,
            ))),
            registry: Arc::new(Mutex::new(StreamRegistry::with_budget(
                limits,
                Arc::clone(&resources.registry_budget),
            ))),
            streams: Arc::new(Mutex::new(BTreeMap::new())),
            pending_ingress: Arc::new(Mutex::new(BTreeMap::new())),
            icmp_rate: Arc::clone(&resources.icmp_rate),
            http_flows: BTreeMap::new(),
            http_cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            substitution,
            udp_associations: Arc::new(Mutex::new(BTreeMap::new())),
            gate,
            read_buf: Vec::with_capacity(4096),
            limits,
            connect_timeout: Duration::from_secs(30),
            recorder,
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            rate_limiter: Arc::clone(&resources.rate_limiter),
        })
    }

    /// Emit a payload-free audit entry. The labels carry only metadata
    /// (stream id, class, target, verdict) — never payload bytes.
    ///
    /// Best effort: a missing recorder or absent Tokio runtime is ignored so
    /// audit plumbing never blocks the networking path.
    fn emit_audit(
        &self,
        category: EventCategory,
        event_name: &str,
        labels: BTreeMap<String, String>,
    ) {
        emit_unbound_audit(
            self.recorder.as_ref(),
            self.runtime_handle.as_ref(),
            category,
            event_name,
            labels,
        );
    }

    /// Check the per-class connection-rate limiter. Returns `true` when the
    /// attempt is admitted (or when limiting is disabled for this class).
    fn check_connection_rate(&self, class: registry::FlowClass) -> bool {
        self.rate_limiter.try_open(class)
    }

    /// Render a list of IP addresses as a compact, stable label value.
    fn format_ips(ips: &[IpAddr]) -> String {
        let mut out = String::with_capacity(ips.len() * 16);
        for (i, ip) in ips.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&ip.to_string());
        }
        out
    }

    /// Serve the session until it closes or errors.
    ///
    /// The implementation completes the FlowMux `Hello`/`HelloAck` exchange,
    /// then dispatches flow frames. `OpenTcp` flows that pass the shared
    /// [`EgressGate`] are connected on the host and relayed; everything else
    /// is refused or terminated with `GoAway`.
    pub fn serve(&mut self) -> Result<(), FlowMuxError> {
        // Wait for the guest's Hello, then acknowledge. The authenticated
        // session is already established; this is the FlowMux session opening.
        let guest_payload_len = match self.read_frame()? {
            Some((Opcode::Hello, 0, payload_len)) => payload_len,
            Some((opcode, _, _)) => {
                return Err(FlowMuxError::FrameRefused(format!(
                    "expected Hello as first FlowMux frame, got {opcode:?}"
                )));
            }
            None => {
                return Err(FlowMuxError::FrameRefused(
                    "peer closed before Hello".to_string(),
                ));
            }
        };

        // Refuse a guest built against a different revision before serving it
        // anything. A GoAway first, so the guest reports the same mismatch
        // rather than a bare disconnect it cannot explain.
        let local = Handshake::local(HOST_BUILD);
        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let guest = Handshake::decode(
            &self.read_buf[payload_start..payload_start + guest_payload_len as usize],
        )
        .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        if let Err(e) = agree(&local, &guest) {
            self.send_goaway(&e.to_string())?;
            return Err(FlowMuxError::FrameRefused(e.to_string()));
        }

        lock_validator(&self.validator)
            .admit(&mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
            ))
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        lock_validator(&self.validator)
            .mark_hello_ack_sent()
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        // Make readiness visible to concurrent host-side ingress before the
        // peer can observe the acknowledgement that promises that readiness.
        self.send_hello_ack()?;

        loop {
            let (opcode, stream_id, payload_len) = match self.read_frame()? {
                Some(facts) => facts,
                None => {
                    info!("FlowMux peer closed session");
                    return Ok(());
                }
            };

            if let Err(e) = lock_validator(&self.validator).admit(&Self::inbound_frame_facts(
                &self.read_buf,
                opcode,
                stream_id,
                payload_len,
            )) {
                warn!(error = %e, "FlowMux frame refused by session validator");
                self.send_goaway(&e.to_string())?;
                return Ok(());
            }

            match opcode {
                Opcode::Hello => {
                    // A second Hello is illegal after the session is established;
                    // the validator already refuses it.
                }
                Opcode::OpenTcp => {
                    if let Err(e) = self.handle_open_tcp(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux TCP open failed");
                        self.send_reset(stream_id, "host error")?;
                    }
                }
                Opcode::InboundReady => {
                    self.handle_inbound_ready(stream_id);
                }
                Opcode::InboundRefused => {
                    self.handle_inbound_refused(stream_id, payload_len);
                }
                Opcode::Data => {
                    if let Err(e) = self.handle_guest_data(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux data forwarding failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::HalfClose => {
                    if let Err(e) = self.handle_guest_half_close(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux half-close failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::Reset => {
                    self.reset_stream(stream_id)?;
                }
                Opcode::WindowUpdate => {
                    if let Err(e) = self.handle_window_update(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux window update failed");
                        let _ = self.reset_stream(stream_id);
                    }
                }
                Opcode::OpenUdp => {
                    if let Err(e) = self.handle_open_udp(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux UDP open failed");
                        self.send_refused(stream_id, "host error")?;
                    }
                }
                Opcode::UdpSend => {
                    if let Err(e) = self.handle_udp_send(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux UDP send failed");
                        self.remove_udp_association(stream_id);
                    }
                }
                Opcode::Resolve => {
                    let open_err = class_for_open(opcode).and_then(|class| {
                        lock_registry(&self.registry)
                            .open_guest(stream_id, class)
                            .err()
                    });
                    if let Some(e) = open_err {
                        warn!(error = %e, stream_id, "FlowMux refusing DNS resolve");
                        self.send_resolve_refused(stream_id, &e.to_string())?;
                    } else if let Err(e) = self.handle_resolve(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux DNS resolve failed");
                        self.send_resolve_refused(stream_id, "resolve failed")?;
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::IcmpEcho => {
                    if let Err(e) = self.handle_icmp_echo(stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux ICMP echo failed");
                        self.send_icmp_refused(stream_id, "icmp echo failed")?;
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::OpenHttp => {
                    if let Err(e) = self.handle_open_http(stream_id) {
                        warn!(error = %e, stream_id, "FlowMux HTTP open failed");
                        self.send_refused(stream_id, "http open refused")?;
                        self.http_flows.remove(&stream_id);
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::HttpRequestHead | Opcode::HttpRequestBody => {
                    if let Err(e) = self.handle_http_request_frame(opcode, stream_id, payload_len) {
                        warn!(error = %e, stream_id, "FlowMux HTTP request refused");
                        self.send_reset(stream_id, "http request refused")?;
                        self.http_flows.remove(&stream_id);
                        self.remove_stream(stream_id);
                    }
                }
                Opcode::CloseUdp => {
                    self.remove_udp_association(stream_id);
                }
                _ => {
                    if lock_registry(&self.registry).get(stream_id).is_some() {
                        warn!(?opcode, stream_id, "FlowMux skeleton rejects flow frame");
                        self.send_goaway("flow frames not yet implemented")?;
                    } else {
                        warn!(?opcode, stream_id, "FlowMux frame on unknown stream");
                        self.send_goaway("unknown stream")?;
                    }
                    return Ok(());
                }
            }
        }
    }

    fn handle_open_tcp(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        if payload_len == 0 || payload_len > 256 {
            self.send_refused(stream_id, "OpenTcp target missing or too long")?;
            return Ok(());
        }

        let target = match std::str::from_utf8(self.frame_payload(payload_len)) {
            Ok(s) => s,
            Err(_) => {
                self.send_refused(stream_id, "OpenTcp target is not UTF-8")?;
                return Ok(());
            }
        };

        let (host, port) = match parse_host_port(target) {
            Ok(pair) => pair,
            Err(e) => {
                self.send_refused(stream_id, &format!("invalid OpenTcp target: {e}"))?;
                return Ok(());
            }
        };
        let target = target.to_string();

        if let Some(reason) = self
            .substitution
            .as_ref()
            .and_then(|service| service.opaque_refusal_reason(host))
        {
            self.send_refused(stream_id, reason)?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target),
                    ("reason".to_string(), "typed_transform_required".to_string()),
                ]),
            );
            return Ok(());
        }

        if !self.check_connection_rate(registry::FlowClass::Tcp) {
            self.send_refused(stream_id, "rate limited")?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "tcp".to_string()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), "rate_limited".to_string()),
                ]),
            );
            return Ok(());
        }

        let decision = self.gate.decide_target(host, port);
        // Recorded on every audit entry this connect emits, so the chain says
        // which namespace authorized (or refused) the flow rather than leaving
        // a reader to infer it from the target's shape.
        let route = decision.route.as_str().to_string();
        let (ips, port) = match decision.verdict {
            EgressVerdict::Allow { ips, port } => (ips, port),
            EgressVerdict::Deny(reason) => {
                self.send_refused(stream_id, &reason.to_string())?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
                        ("route".to_string(), route.clone()),
                        ("target".to_string(), target.to_string()),
                        ("reason".to_string(), "policy_denied".to_string()),
                    ]),
                );
                return Ok(());
            }
            EgressVerdict::Malformed => {
                self.send_refused(stream_id, "malformed destination")?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
                        ("route".to_string(), route.clone()),
                        ("target".to_string(), target.to_string()),
                        ("reason".to_string(), "malformed".to_string()),
                    ]),
                );
                return Ok(());
            }
        };

        let open_err = lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Tcp)
            .err();
        if let Some(e) = open_err {
            self.send_refused(stream_id, &e.to_string())?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "tcp".to_string()),
                    ("route".to_string(), route.clone()),
                    ("target".to_string(), target.to_string()),
                    ("reason".to_string(), "resource_exhausted".to_string()),
                ]),
            );
            return Ok(());
        }

        let upstream = match connect_first_admitted(&ips, port, self.connect_timeout) {
            Some(stream) => stream,
            None => {
                warn!(stream_id, %target, "FlowMux TCP connect failed");
                let _ = lock_registry(&self.registry).retire(stream_id);
                self.send_refused(stream_id, "connection failed")?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
                        ("route".to_string(), route.clone()),
                        ("target".to_string(), target.to_string()),
                        ("reason".to_string(), "connect_failed".to_string()),
                    ]),
                );
                return Ok(());
            }
        };

        let confirm_err = lock_registry(&self.registry).confirm(stream_id).err();
        if let Some(e) = confirm_err {
            let _ = lock_registry(&self.registry).retire(stream_id);
            self.send_refused(stream_id, &e.to_string())?;
            return Ok(());
        }

        self.send_opened(stream_id)?;
        self.spawn_tcp_relay(stream_id, upstream)?;
        self.emit_audit(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "tcp".to_string()),
                ("route".to_string(), route.clone()),
                ("target".to_string(), target.to_string()),
                ("resolved_ips".to_string(), Self::format_ips(&ips)),
            ]),
        );
        Ok(())
    }

    fn handle_resolve(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        if payload_len == 0 || payload_len as usize > MAX_DNS_MESSAGE {
            self.send_resolve_refused(stream_id, "DNS query missing or oversized")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        let query = self.frame_payload(payload_len);

        let question = match decode_query(query) {
            Ok(q) => q,
            Err(e) => {
                self.send_resolve_refused(stream_id, &format!("malformed DNS query: {e:?}"))?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        };

        if !self.check_connection_rate(registry::FlowClass::Dns) {
            self.send_resolve_refused(stream_id, "rate limited")?;
            self.emit_audit(
                EventCategory::Dns,
                "dns.refused",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("qname".to_string(), question.name.clone()),
                    ("qtype".to_string(), question.qtype.to_string()),
                    ("reason".to_string(), "rate_limited".to_string()),
                ]),
            );
            self.remove_stream(stream_id);
            return Ok(());
        }

        let timeout = self.connect_timeout;
        let verdict = self
            .gate
            .dns_verdict(&question.name, question.qtype, |name| {
                resolve_hostname_ips(name, timeout)
            });

        let response = match verdict {
            DnsVerdict::Resolved(ips) => {
                self.emit_audit(
                    EventCategory::Dns,
                    "dns.resolved",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("qname".to_string(), question.name.clone()),
                        ("qtype".to_string(), question.qtype.to_string()),
                        ("resolved_ips".to_string(), Self::format_ips(&ips)),
                    ]),
                );
                encode_response(
                    &question,
                    mvm_contract::protocol::dns::DnsRcode::NoError,
                    &ips,
                )
            }
            DnsVerdict::Refused => {
                self.emit_audit(
                    EventCategory::Dns,
                    "dns.refused",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("qname".to_string(), question.name.clone()),
                        ("qtype".to_string(), question.qtype.to_string()),
                        ("reason".to_string(), "policy_denied".to_string()),
                    ]),
                );
                self.send_resolve_refused(stream_id, "policy refused")?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        };

        self.send_resolved(stream_id, &response)?;
        self.remove_stream(stream_id);
        Ok(())
    }

    fn handle_open_udp(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        if !self.check_connection_rate(registry::FlowClass::Udp) {
            self.send_refused(stream_id, "rate limited")?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "udp".to_string()),
                    ("reason".to_string(), "rate_limited".to_string()),
                ]),
            );
            return Ok(());
        }

        let open_err = lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Udp)
            .err();
        if let Some(e) = open_err {
            self.send_refused(stream_id, &e.to_string())?;
            self.emit_audit(
                EventCategory::Host,
                "host.flow.denied",
                BTreeMap::from([
                    ("stream_id".to_string(), stream_id.to_string()),
                    ("class".to_string(), "udp".to_string()),
                    ("reason".to_string(), "resource_exhausted".to_string()),
                ]),
            );
            return Ok(());
        }

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            warn!(stream_id, error = %e, "FlowMux UDP bind failed");
            FlowMuxError::Transport(e)
        })?;
        let (poll, waker) = udp_event_sources(&socket).map_err(FlowMuxError::Transport)?;
        let idle_timeout = self.limits.udp_idle_timeout;
        let max_peers = self.limits.max_udp_peers;

        let (tx, rx) = std::sync::mpsc::channel();
        let session = Arc::clone(&self.session);
        let writer = Arc::clone(&self.writer);
        let registry_arc = Arc::clone(&self.registry);
        std::thread::Builder::new()
            .name(format!("flowmux-udp-{stream_id}"))
            .spawn(move || {
                run_udp_relay(UdpRelayParams {
                    stream_id,
                    socket,
                    poll,
                    session,
                    writer,
                    idle_timeout,
                    max_peers,
                    peer_admission: UdpPeerAdmission::GuestMayIntroduce,
                    rx,
                    registry: registry_arc,
                })
            })
            .map_err(FlowMuxError::Transport)?;

        lock_udp_associations(&self.udp_associations).insert(
            stream_id,
            UdpAssociationHandle {
                tx,
                waker,
                peer_admission: UdpPeerAdmission::GuestMayIntroduce,
            },
        );
        self.send_udp_opened(stream_id)?;
        self.emit_audit(
            EventCategory::Host,
            "host.flow.allowed",
            BTreeMap::from([
                ("stream_id".to_string(), stream_id.to_string()),
                ("class".to_string(), "udp".to_string()),
            ]),
        );
        Ok(())
    }

    fn handle_udp_send(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        let relay = match lock_udp_associations(&self.udp_associations).get(&stream_id) {
            Some(handle) => (
                handle.tx.clone(),
                Arc::clone(&handle.waker),
                handle.peer_admission,
            ),
            None => {
                warn!(stream_id, "UdpSend on unknown association");
                self.send_goaway("unknown UDP association")?;
                return Ok(());
            }
        };

        let payload = self.frame_payload(payload_len);
        if payload.len() < UDP_ADDR_PREFIX_LEN {
            return Err(FlowMuxError::FrameRefused(
                "UdpSend payload too short".to_string(),
            ));
        }

        let (ip, port, datagram) = decode_udp_addr(payload)
            .map_err(|e| FlowMuxError::FrameRefused(format!("invalid UdpSend address: {e}")))?;
        let target = format!("{ip}:{port}");

        if relay.2 == UdpPeerAdmission::GuestMayIntroduce {
            if let Some(reason) = self
                .substitution
                .as_ref()
                .and_then(|service| service.opaque_refusal_reason(&ip.to_string()))
            {
                warn!(stream_id, %target, reason, "FlowMux opaque UDP transform refused");
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "udp".to_string()),
                        ("target".to_string(), target),
                        ("reason".to_string(), "typed_transform_required".to_string()),
                    ]),
                );
                return Ok(());
            }

            match self.gate.decide_udp_request(&target) {
                EgressVerdict::Allow { .. } => {}
                EgressVerdict::Deny(reason) => {
                    warn!(stream_id, %target, %reason, "FlowMux UDP datagram denied");
                    return Ok(());
                }
                EgressVerdict::Malformed => {
                    return Err(FlowMuxError::FrameRefused(
                        "malformed UDP destination".to_string(),
                    ));
                }
            }
        }

        let msg = UdpSendMsg {
            destination: SocketAddr::new(ip, port),
            payload: datagram.to_vec(),
        };
        if relay.0.send(msg).is_err() {
            return Err(FlowMuxError::FrameRefused(
                "UDP relay thread has exited".to_string(),
            ));
        }
        relay.1.wake().map_err(FlowMuxError::Transport)?;
        Ok(())
    }

    fn remove_udp_association(&mut self, stream_id: u32) {
        if let Some(UdpAssociationHandle { tx, waker, .. }) =
            lock_udp_associations(&self.udp_associations).remove(&stream_id)
        {
            drop(tx);
            let _ = waker.wake();
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_udp_opened(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        info!(stream_id, "FlowMux sending UdpOpened");
        self.write_frame(Opcode::UdpOpened, stream_id, b"")?;
        self.mark_sent(Opcode::UdpOpened, stream_id);
        Ok(())
    }

    fn spawn_tcp_relay(&mut self, stream_id: u32, upstream: TcpStream) -> Result<(), FlowMuxError> {
        self.ingress_handle().spawn_tcp_relay(stream_id, upstream)
    }

    fn handle_guest_data(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        let payload = self.frame_payload(payload_len).to_vec();

        let mut streams = lock_tcp_streams(&self.streams);
        let handle = match streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "Data frame on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        if handle.host_half_closed.load(Ordering::Relaxed) {
            drop(streams);
            self.send_reset(stream_id, "data after host half-close")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        {
            let mut reg = lock_registry(&self.registry);
            if let Err(e) = reg.consume_guest_credit(stream_id, payload_len) {
                warn!(error = %e, stream_id, "guest credit exhausted");
                drop(reg);
                drop(streams);
                self.send_reset(stream_id, "credit exhausted")?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        }

        if let Err(e) = handle
            .upstream
            .write_all(&payload)
            .and_then(|_| handle.upstream.flush())
        {
            warn!(error = %e, stream_id, "write to upstream failed");
            drop(streams);
            self.send_reset(stream_id, "upstream write failed")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        // Replenish the consumed credit so the guest can keep sending.
        //
        // A zero-length DATA frame consumes no credit, and the protocol treats
        // a zero-delta window update as a frame error. Sending one anyway kills
        // the session the frame was meant to keep flowing — and it dies on the
        // *guest's* validator, so the host log shows nothing wrong.
        if payload_len > 0 {
            {
                let mut reg = lock_registry(&self.registry);
                let _ = reg.grant_guest_credit(stream_id, payload_len);
            }
            self.send_window_update(stream_id, payload_len)?;
        }
        Ok(())
    }

    fn handle_guest_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        let mut streams = lock_tcp_streams(&self.streams);
        let handle = match streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "HalfClose on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        let _ = handle.upstream.shutdown(std::net::Shutdown::Write);

        if handle.host_half_closed.load(Ordering::Relaxed) {
            // Both directions are now done.
            handle.retired.store(true, Ordering::Relaxed);
            drop(streams);
            self.send_reset(stream_id, "stream complete")?;
            self.remove_stream(stream_id);
        } else {
            let _ = lock_registry(&self.registry).half_close(stream_id);
        }
        Ok(())
    }

    /// Serve one host-mediated ICMP echo.
    ///
    /// A NIC-less guest has no raw socket, so the host echoes on its behalf.
    /// The decision — parse, bounds, admission, rate — is
    /// [`icmp_handler::serve_request`], shared with every other transport that
    /// has ever carried this verb, so they cannot drift on what is allowed.
    fn handle_icmp_echo(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        use crate::supervisor::{icmp_audit, icmp_echo, icmp_handler};

        if !self.check_connection_rate(registry::FlowClass::Icmp) {
            return Err(FlowMuxError::FrameRefused("icmp rate limit".to_string()));
        }
        lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Icmp)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        let line = String::from_utf8_lossy(self.frame_payload(payload_len)).into_owned();
        let (replies, audit) = icmp_handler::serve_request(
            &line,
            &self.gate,
            &self.icmp_rate,
            &icmp_echo::PingSocketEcho,
        );
        if let Some(recorder) = self.recorder.as_deref() {
            icmp_audit::emit_icmp_echo_blocking(recorder, &audit);
        }

        // One echo per flow, so the last reply ends it. A refusal is an answer
        // too — the guest gets the reason rather than a closed stream.
        let last = replies.len().saturating_sub(1);
        for (index, reply) in replies.into_iter().enumerate() {
            let encoded = serde_json::to_vec(&reply)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
            let opcode = match reply {
                mvm_core::icmp_wire::IcmpEchoReply::Refused { .. } => Opcode::IcmpRefused,
                _ => Opcode::IcmpReply,
            };
            self.write_frame(opcode, stream_id, &encoded)?;
            if index == last {
                self.mark_sent(opcode, stream_id);
            }
        }
        self.remove_stream(stream_id);
        Ok(())
    }

    fn send_icmp_refused(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        let reply = mvm_core::icmp_wire::IcmpEchoReply::Refused {
            message: reason.to_string(),
        };
        let encoded =
            serde_json::to_vec(&reply).map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.write_frame(Opcode::IcmpRefused, stream_id, &encoded)?;
        self.mark_sent(Opcode::IcmpRefused, stream_id);
        Ok(())
    }

    /// Open a typed HTTP flow.
    ///
    /// Refused outright when this endpoint assembled no substitution service:
    /// the flow exists to carry a request that may name a placeholder, and
    /// there would be nothing here to resolve it. Failing the open is the
    /// difference between a workload that cannot reach the network and one
    /// that sends `mvm-secret-<hex>` to a real upstream.
    fn handle_open_http(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        if self.substitution.is_none() {
            return Err(FlowMuxError::FrameRefused(
                "no substitution service on this endpoint".to_string(),
            ));
        }
        if !self.check_connection_rate(registry::FlowClass::Http) {
            return Err(FlowMuxError::FrameRefused(
                "http open rate limit".to_string(),
            ));
        }
        lock_registry(&self.registry)
            .open_guest(stream_id, registry::FlowClass::Http)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.http_flows
            .insert(stream_id, http_flow::HttpFlow::new());
        self.send_opened(stream_id)
    }

    /// Take one head or body frame, and forward as soon as the declared body
    /// has arrived in full.
    fn handle_http_request_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        let payload = self.frame_payload(payload_len).to_vec();
        let flow = self.http_flows.get_mut(&stream_id).ok_or_else(|| {
            FlowMuxError::FrameRefused(format!("http frame on unopened flow {stream_id}"))
        })?;
        if opcode == Opcode::HttpRequestHead {
            let request = flow
                .accept_head(&payload)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
            let (Some(service), Some(handle)) = (&self.substitution, &self.runtime_handle) else {
                return Err(FlowMuxError::FrameRefused(
                    "no runtime to forward the http flow on".to_string(),
                ));
            };
            let (cancel_sender, cancel_receiver) = tokio::sync::watch::channel(false);
            self.http_cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(stream_id, cancel_sender);
            let task = http_flow::ForwardTask::builder()
                .runtime(handle.clone())
                .service(Arc::clone(service))
                .session(Arc::clone(&self.session))
                .writer(Arc::clone(&self.writer))
                .stream_id(stream_id)
                .request(request)
                .cancellation(cancel_receiver)
                .cancellations(Arc::clone(&self.http_cancellations))
                .registry(Arc::clone(&self.registry))
                .build()
                .map_err(|error| FlowMuxError::FrameRefused(error.to_string()))?;
            http_flow::spawn_forward(task);
        } else {
            flow.accept_body(&payload)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        }
        if flow.is_complete() {
            http_flow::cancel(&mut self.http_flows, stream_id);
        }
        Ok(())
    }

    /// The payload of the frame currently in `read_buf`.
    ///
    /// The frame is decoded in place, so the payload is readable without a
    /// copy. One accessor rather than the same two-line slice at each call
    /// site: those indexed unchecked, so a frame shorter than its header
    /// claimed would have panicked the session thread rather than refusing a
    /// frame.
    fn frame_payload(&self, payload_len: u32) -> &[u8] {
        let start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let end = start.saturating_add(payload_len as usize);
        self.read_buf.get(start..end).unwrap_or(&[])
    }

    fn handle_window_update(
        &mut self,
        stream_id: u32,
        payload_len: u32,
    ) -> Result<(), FlowMuxError> {
        if payload_len != 4 {
            return Err(FlowMuxError::FrameRefused(
                "WindowUpdate payload must be 4 bytes".to_string(),
            ));
        }
        let payload = self.frame_payload(payload_len);
        let delta = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        lock_registry(&self.registry)
            .grant_host_credit(stream_id, delta)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))
    }

    fn handle_inbound_ready(&mut self, stream_id: u32) {
        let result = lock_registry(&self.registry)
            .confirm(stream_id)
            .map_err(|error| error.to_string());
        if let Some(sender) = lock_pending_ingress(&self.pending_ingress).remove(&stream_id) {
            let _ = sender.send(result);
        }
    }

    fn handle_inbound_refused(&mut self, stream_id: u32, payload_len: u32) {
        let reason = String::from_utf8_lossy(self.frame_payload(payload_len)).into_owned();
        let _ = lock_registry(&self.registry).retire(stream_id);
        if let Some(sender) = lock_pending_ingress(&self.pending_ingress).remove(&stream_id) {
            let _ = sender.send(Err(reason));
        }
    }

    fn reset_stream(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        // Dropping an incomplete typed request wipes its zeroizing body buffer.
        // A guest reset is cancellation, not permission to retain the partial
        // cleartext until the authenticated session itself eventually exits.
        self.http_flows.remove(&stream_id);
        http_flow::cancel_forwarding(&self.http_cancellations, stream_id);
        let was_live = lock_tcp_streams(&self.streams).remove(&stream_id);
        let live = was_live.is_some();
        if let Some(handle) = was_live {
            handle.retired.store(true, Ordering::Relaxed);
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
        // Only announce a teardown we are actually performing. A relay thread
        // that already reset this stream has told the guest once; telling it
        // again names a stream the guest has retired, which is a protocol error
        // on its validator and kills the whole session — taking every other
        // live stream with it. The guest is right to refuse the second one, so
        // the fix belongs here.
        if live {
            self.send_reset(stream_id, "reset by peer")?;
        }
        Ok(())
    }

    fn remove_stream(&mut self, stream_id: u32) {
        if let Some(handle) = lock_tcp_streams(&self.streams).remove(&stream_id) {
            handle.retired.store(true, Ordering::Relaxed);
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_hello_ack(&self) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HelloAck, 0, &Handshake::local(HOST_BUILD).encode())
    }

    fn send_goaway(&self, reason: &str) -> Result<(), FlowMuxError> {
        warn!(%reason, "FlowMux sending GoAway");
        self.write_frame(Opcode::GoAway, 0, reason.as_bytes())
    }

    /// Facts for a frame arriving from the guest.
    ///
    /// A `WindowUpdate`'s payload *is* its credit, and the validator refuses an
    /// update that carries none. Describing one by length alone therefore
    /// refuses every window update the guest sends, and the host answers a
    /// perfectly good frame with `GoAway` — killing the session on the first
    /// credit the guest returns. The guest-side reader has the same shape for
    /// the same reason.
    fn inbound_frame_facts(
        read_buf: &[u8],
        opcode: Opcode,
        stream_id: u32,
        payload_len: u32,
    ) -> mvm_contract::protocol::network_flow::FrameFacts {
        let facts = mvm_contract::protocol::network_flow::FrameFacts::new(
            Direction::GuestToHost,
            opcode,
            stream_id,
        )
        .with_payload(payload_len);
        if opcode != Opcode::WindowUpdate {
            return facts;
        }
        let start = LENGTH_PREFIX_LEN + HEADER_LEN;
        match read_buf.get(start..start + 4) {
            // A malformed or truncated update keeps no credit, so the
            // validator still refuses it — this reads the field, it does not
            // wave frames through.
            Some([a, b, c, d]) => facts.with_credit(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => facts,
        }
    }

    /// Advance the local state machine for a frame the host is about to send.
    /// Each side validates the frames it reads, but a confirming or terminal
    /// frame sent by the host still moves the host-side view of the stream.
    fn mark_sent(&mut self, opcode: Opcode, stream_id: u32) {
        let _ = lock_validator(&self.validator).admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::HostToGuest,
                opcode,
                stream_id,
            ),
        );
    }

    fn send_opened(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        info!(stream_id, "FlowMux sending Opened");
        self.write_frame(Opcode::Opened, stream_id, b"")?;
        self.mark_sent(Opcode::Opened, stream_id);
        Ok(())
    }

    fn send_refused(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending Refused");
        self.write_frame(Opcode::Refused, stream_id, reason.as_bytes())?;
        self.mark_sent(Opcode::Refused, stream_id);
        Ok(())
    }

    fn send_resolved(&mut self, stream_id: u32, response: &[u8]) -> Result<(), FlowMuxError> {
        info!(stream_id, len = response.len(), "FlowMux sending Resolved");
        self.write_frame(Opcode::Resolved, stream_id, response)?;
        self.mark_sent(Opcode::Resolved, stream_id);
        Ok(())
    }

    fn send_resolve_refused(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending ResolveRefused");
        self.write_frame(Opcode::ResolveRefused, stream_id, reason.as_bytes())?;
        self.mark_sent(Opcode::ResolveRefused, stream_id);
        Ok(())
    }

    fn send_reset(&self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        warn!(stream_id, %reason, "FlowMux sending Reset");
        self.write_frame(Opcode::Reset, stream_id, reason.as_bytes())
    }

    fn send_window_update(&self, stream_id: u32, delta: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::WindowUpdate, stream_id, &delta.to_be_bytes())
    }

    fn write_frame(
        &self,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        write_frame_to(&self.session, &self.writer, opcode, stream_id, payload)
    }

    /// Read one decrypted FlowMux frame from the peer, returning the opcode,
    /// stream id, and payload length, or `None` on clean close.
    ///
    /// The session layer encrypts each frame; this helper reads the encrypted
    /// envelope, opens it, and decodes the inner FlowMux header.
    fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32)>, FlowMuxError> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) if is_peer_disconnect(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let sealed_len = u32::from_be_bytes(len_buf) as usize;
        if sealed_len == 0 {
            return Ok(None);
        }
        if sealed_len > 1 << 20 {
            return Err(FlowMuxError::FrameRefused(format!(
                "FlowMux sealed frame length {sealed_len} exceeds 1 MiB"
            )));
        }
        let mut sealed_buf = vec![0u8; sealed_len];
        if let Err(e) = self.reader.read_exact(&mut sealed_buf) {
            if is_peer_disconnect(&e) {
                return Ok(None);
            }
            return Err(e.into());
        }

        let sealed = mvm_core::net::session::SealedFrame::decode(&sealed_buf)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
        self.read_buf = {
            let mut session = lock_session(&self.session);
            session
                .open(&sealed)
                .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?
        };

        let frame = match decode(&self.read_buf) {
            Ok(frame) => frame,
            Err(FrameError::Incomplete { have: 0, .. }) => return Ok(None),
            Err(e) => return Err(FlowMuxError::FrameRefused(e.to_string())),
        };

        Ok(Some((
            frame.header.opcode,
            frame.header.stream_id,
            frame.header.payload_len,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::udp_relay::encode_udp_addr;
    use mvm_contract::protocol::network_flow::hello::BEHAVIOR_REVISION;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::network_flow::{Opcode, encode_into};
    use mvm_core::net::session::Session;
    use rand::Rng;
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::*;

    fn fresh_keys() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let verify = key.verifying_key();
        (key, verify)
    }

    #[test]
    fn accept_rejects_wrong_guest_anchor() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, _guest_verify) = fresh_keys();
        let (_wrong_key, wrong_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &wrong_verify,
                RegistryLimits::default(),
                gate,
            )
            .map(|_| ())
        });

        // Drive the guest side of the handshake with the *correct* guest key;
        // the host must still reject because the anchor does not match.
        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        // The handshake itself is the test; no frames are exchanged.
        let _ = guest_stream;

        let result = host_handle.join().unwrap();
        assert!(
            matches!(result, Err(FlowMuxError::Handshake(_))),
            "expected handshake failure due to anchor mismatch, got {result:?}"
        );
    }

    fn read_flowmux_frame(
        stream: &mut UnixStream,
        session: &mut Session,
    ) -> (Opcode, u32, Vec<u8>) {
        let sealed = mvm_core::net::session::read_sealed_frame(stream, 1 << 20).unwrap();
        let plaintext = session.open(&sealed).unwrap();
        let parsed = mvm_contract::protocol::network_flow::decode(&plaintext).unwrap();
        (
            parsed.header.opcode,
            parsed.header.stream_id,
            parsed.payload.to_vec(),
        )
    }

    /// The guest's HelloAck must carry the host's handshake, or a guest built
    /// against a different revision has nothing to compare against.
    #[test]
    fn the_hello_ack_carries_the_host_handshake() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();
        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let host_handle = thread::spawn(move || {
            FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                EgressGate::default_deny(),
            )
            .unwrap()
            .serve()
        });

        let (mut guest_session, _id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _sid, payload) = read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);
        let host = Handshake::decode(&payload).expect("HelloAck carries a handshake");
        assert_eq!(host.behavior_revision, BEHAVIOR_REVISION);
        assert_eq!(host.build, HOST_BUILD);

        drop(guest_stream);
        let _ = host_handle.join().unwrap();
    }

    /// The failure this whole handshake exists for: two halves built against
    /// different revisions. The host must refuse, and must say GoAway first so
    /// the guest reports the same mismatch rather than a bare disconnect.
    #[test]
    fn a_guest_from_another_revision_is_refused_by_name() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();
        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let host_handle = thread::spawn(move || {
            FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                EgressGate::default_deny(),
            )
            .unwrap()
            .serve()
        });

        let (mut guest_session, _id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
        let stale = Handshake {
            behavior_revision: BEHAVIOR_REVISION.wrapping_add(1),
            build: "mvm-agentd from-a-stale-tree".to_string(),
        };
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &stale.encode(),
        );

        let (opcode, _sid, payload) = read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::GoAway,
            "a mismatch must say why, not hang up"
        );
        let reason = String::from_utf8(payload).expect("GoAway reason is text");
        assert!(reason.contains("mvm-agentd from-a-stale-tree"), "{reason}");
        assert!(reason.contains(HOST_BUILD), "{reason}");

        let err = host_handle
            .join()
            .unwrap()
            .expect_err("the session must not be served");
        assert!(err.to_string().contains("revision"), "{err}");
    }

    /// A peer that predates the handshake sends an empty Hello payload. That
    /// is the stale-binary case, so it must be refused rather than defaulted.
    #[test]
    fn a_guest_with_no_handshake_at_all_is_refused() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();
        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let host_handle = thread::spawn(move || {
            FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                EgressGate::default_deny(),
            )
            .unwrap()
            .serve()
        });

        let (mut guest_session, _id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
        write_frame(&mut guest_stream, &mut guest_session, Opcode::Hello, 0, b"");

        let err = host_handle
            .join()
            .unwrap()
            .expect_err("an empty Hello must not open a session");
        assert!(err.to_string().contains("handshake"), "{err}");
    }

    #[test]
    fn accept_succeeds_and_sends_hello_ack() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        // The guest must send Hello to open the FlowMux session.
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        // Read the HelloAck from the host.
        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        // Send a flow frame on an unknown stream and expect a GoAway.
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Data,
            1,
            b"hello",
        );

        let (opcode, _stream_id, goaway_payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::GoAway);
        assert!(!goaway_payload.is_empty());

        // Close the guest side; the host serve loop should end cleanly.
        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn open_tcp_to_unknown_host_is_refused_by_default_deny_gate() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            b"example.com:443",
        );

        let (opcode, _stream_id, payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        // The session stays alive; an unknown-stream frame afterward still
        // receives a GoAway rather than dropping the connection.
        write_frame(&mut guest_stream, &mut guest_session, Opcode::Data, 3, b"?");

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn declared_inbound_tcp_uses_an_even_stream_and_roundtrips_external_data() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();
        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        let (ingress_tx, ingress_rx) = std::sync::mpsc::sync_channel(1);

        let host = thread::spawn(move || {
            let mut session = FlowMuxSession::accept_with(
                host_stream,
                FlowMuxAccept::new(
                    "test-session",
                    host_key,
                    guest_verify,
                    RegistryLimits::default(),
                    EgressGate::default_deny(),
                )
                .with_ingress_mappings([17]),
            )
            .unwrap();
            ingress_tx.send(session.ingress_handle()).unwrap();
            session.serve()
        });

        let (mut guest_session, _) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        let ingress = ingress_rx.recv().unwrap();
        let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
        let mut external = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        external
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let (opened_tx, opened_rx) = std::sync::mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = opened_tx.send(ingress.open_tcp(17, accepted));
        });
        match opened_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(result) => panic!("host ingress opener returned before guest readiness: {result:?}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(error) => panic!("host ingress opener channel failed: {error}"),
        }

        let (opcode, stream_id, mapping) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::InboundOpen);
        assert_eq!(stream_id % 2, 0);
        assert_eq!(mapping, 17_u16.to_be_bytes());
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::InboundReady,
            stream_id,
            &[],
        );
        opened_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("guest readiness must wake the host opener")
            .unwrap();

        external.write_all(b"from-external").unwrap();
        let (opcode, data_stream, payload) = loop {
            let frame = read_flowmux_frame(&mut guest_stream, &mut guest_session);
            if frame.0 == Opcode::Data {
                break frame;
            }
        };
        assert_eq!((opcode, data_stream), (Opcode::Data, stream_id));
        assert_eq!(payload, b"from-external");

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Data,
            stream_id,
            b"from-guest",
        );
        let mut response = [0_u8; 10];
        external.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"from-guest");

        drop(external);
        drop(guest_stream);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn declared_inbound_udp_replies_only_to_an_observed_peer() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();
        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        let (ingress_tx, ingress_rx) = std::sync::mpsc::sync_channel(1);
        let host = thread::spawn(move || {
            let mut session = FlowMuxSession::accept_with(
                host_stream,
                FlowMuxAccept::new(
                    "test-session",
                    host_key,
                    guest_verify,
                    RegistryLimits::default(),
                    EgressGate::default_deny(),
                )
                .with_ingress_transports([(17, IngressFlowKind::Udp)]),
            )
            .unwrap();
            ingress_tx.send(session.ingress_handle()).unwrap();
            session.serve()
        });

        let (mut guest_session, _) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();
        guest_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        let listener = std::net::UdpSocket::bind((local_test_ip(), 0)).unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let ingress = ingress_rx.recv().unwrap();
        let (opened_tx, opened_rx) = std::sync::mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = opened_tx.send(ingress.open_udp(17, listener));
        });
        let (opcode, stream_id, mapping) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(
            (opcode, mapping),
            (Opcode::InboundOpen, 17_u16.to_be_bytes().to_vec())
        );
        assert_eq!(stream_id % 2, 0);
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::InboundReady,
            stream_id,
            &[],
        );
        opened_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("guest UDP readiness must wake the host opener")
            .unwrap();

        let external = std::net::UdpSocket::bind((local_test_ip(), 0)).unwrap();
        external
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        external.send_to(b"udp-request", listener_addr).unwrap();
        let (opcode, data_stream, payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!((opcode, data_stream), (Opcode::UdpRecv, stream_id));
        let (peer_ip, peer_port, body) = decode_udp_addr(&payload).unwrap();
        assert_eq!(
            SocketAddr::new(peer_ip, peer_port),
            external.local_addr().unwrap()
        );
        assert_eq!(body, b"udp-request");

        let mut reply = udp_relay::encode_udp_addr(peer_ip, peer_port);
        reply.extend_from_slice(b"udp-response");
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::UdpSend,
            stream_id,
            &reply,
        );
        let mut response = [0_u8; 32];
        let (received, _) = external
            .recv_from(&mut response)
            .expect("observed UDP peer must receive the guest reply");
        assert_eq!(&response[..received], b"udp-response");

        let unknown = std::net::UdpSocket::bind((local_test_ip(), 0)).unwrap();
        unknown
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let unknown_addr = unknown.local_addr().unwrap();
        let mut forged = udp_relay::encode_udp_addr(unknown_addr.ip(), unknown_addr.port());
        forged.extend_from_slice(b"must-not-arrive");
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::UdpSend,
            stream_id,
            &forged,
        );
        let error = unknown.recv_from(&mut response).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::CloseUdp,
            stream_id,
            &[],
        );
        drop(guest_stream);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn parse_host_port_accepts_ipv4_and_names() {
        assert_eq!(
            parse_host_port("127.0.0.1:443").unwrap(),
            ("127.0.0.1", 443)
        );
        assert_eq!(
            parse_host_port("example.com:80").unwrap(),
            ("example.com", 80)
        );
    }

    #[test]
    fn parse_host_port_rejects_missing_port_and_empty_host() {
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port(":443").is_err());
        assert!(parse_host_port("example.com:99999").is_err());
    }

    fn build_dns_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
        let mut query = Vec::from(id.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            query.push(u8::try_from(label.len()).expect("test label length fits in u8"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    #[test]
    fn open_udp_creates_association_and_replies_udp_opened() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::OpenUdp,
            1,
            b"",
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::UdpOpened);

        // Close the association cleanly.
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::CloseUdp,
            1,
            b"",
        );

        // The session is still alive.
        write_frame(&mut guest_stream, &mut guest_session, Opcode::Data, 3, b"?");

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn resolve_to_unknown_host_is_refused_by_default_deny_gate() {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();

        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();

        let gate = EgressGate::default_deny();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                RegistryLimits::default(),
                gate,
            )
            .unwrap();
            session.serve()
        });

        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);

        let query = build_dns_query("example.com", 1, 0x1234);
        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Resolve,
            1,
            &query,
        );

        let (opcode, _stream_id, payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::ResolveRefused);
        assert!(!payload.is_empty());

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }
    fn local_test_ip() -> IpAddr {
        use mvm_contract::policy::network_policy::is_mandatory_deny;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind probe socket");
        socket
            .connect("1.1.1.1:80")
            .expect("probe socket should have a route");
        let ip = socket.local_addr().expect("local addr").ip();
        assert!(
            !is_mandatory_deny(ip),
            "test IP {ip} is in a mandatory-deny range"
        );
        ip
    }

    fn gate_allowing_ports(ip: IpAddr, tcp_ports: &[u16], udp_ports: &[u16]) -> EgressGate {
        use mvm_contract::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
        let cidr = if ip.is_ipv4() {
            format!("{ip}/32")
        } else {
            format!("{ip}/128")
        };
        let net: ipnet::IpNet = cidr.parse().unwrap();
        let mut rules = Vec::new();
        for &port in tcp_ports {
            rules.push(CanonicalRule {
                proto: Proto::Tcp,
                net,
                port_lo: port,
                port_hi: port,
            });
        }
        for &port in udp_ports {
            rules.push(CanonicalRule {
                proto: Proto::Udp,
                net: cidr.parse().unwrap(),
                port_lo: port,
                port_hi: port,
            });
        }
        EgressGate::new(CanonicalEgress::Rules(rules))
    }

    fn gate_allowing_addr(ip: IpAddr, tcp_port: u16, udp_port: Option<u16>) -> EgressGate {
        use mvm_contract::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
        let cidr = if ip.is_ipv4() {
            format!("{ip}/32")
        } else {
            format!("{ip}/128")
        };
        let net: ipnet::IpNet = cidr.parse().unwrap();
        let mut rules = vec![CanonicalRule {
            proto: Proto::Tcp,
            net,
            port_lo: tcp_port,
            port_hi: tcp_port,
        }];
        if let Some(port) = udp_port {
            rules.push(CanonicalRule {
                proto: Proto::Udp,
                net: cidr.parse().unwrap(),
                port_lo: port,
                port_hi: port,
            });
        }
        EgressGate::new(CanonicalEgress::Rules(rules))
    }

    fn gate_with_pinned_localhost() -> EgressGate {
        use chrono::{Duration as ChronoDuration, Utc};
        use mvm_contract::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_contract::policy::network_policy::{HostPort, NetworkPolicy};

        let now = Utc::now();
        let later = now + ChronoDuration::hours(1);
        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "localhost",
            vec!["127.0.0.1".parse().unwrap()],
            now.to_rfc3339(),
            later.to_rfc3339(),
        ));
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("localhost", 53)]);
        EgressGate::from_network_policy(&policy, &pins, &now.to_rfc3339())
    }

    fn run_session(
        gate: EgressGate,
    ) -> (
        UnixStream,
        Session,
        thread::JoinHandle<Result<(), FlowMuxError>>,
    ) {
        run_session_with(gate, RegistryLimits::default())
    }

    fn run_session_with(
        gate: EgressGate,
        limits: RegistryLimits,
    ) -> (
        UnixStream,
        Session,
        thread::JoinHandle<Result<(), FlowMuxError>>,
    ) {
        let (host_key, host_verify) = fresh_keys();
        let (guest_key, guest_verify) = fresh_keys();
        let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
        let host_handle = thread::spawn(move || {
            let mut session = FlowMuxSession::accept(
                host_stream,
                "test-session",
                host_key,
                &guest_verify,
                limits,
                gate,
            )
            .unwrap();
            session.serve()
        });
        let (mut guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        write_frame(
            &mut guest_stream,
            &mut guest_session,
            Opcode::Hello,
            0,
            &Handshake::local("test-guest").encode(),
        );

        let (opcode, _stream_id, _payload) =
            read_flowmux_frame(&mut guest_stream, &mut guest_session);
        assert_eq!(opcode, Opcode::HelloAck);
        (guest_stream, guest_session, host_handle)
    }

    fn write_frame(
        stream: &mut UnixStream,
        session: &mut Session,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) {
        let mut buf = Vec::new();
        encode_into(&mut buf, opcode, stream_id, payload).unwrap();
        let sealed = session.seal(&buf).unwrap();
        let mut sealed_bytes = Vec::new();
        sealed.encode(&mut sealed_bytes).unwrap();
        let len = u32::try_from(sealed_bytes.len()).unwrap();
        stream.write_all(&len.to_be_bytes()).unwrap();
        stream.write_all(&sealed_bytes).unwrap();
        stream.flush().unwrap();
    }

    /// A download larger than `MAX_STREAM_CREDIT` must complete.
    ///
    /// The relay writes through `write_frame_to`, which does not hold the
    /// validator, so the validator never sees the host's own outbound `Data`.
    /// Its host-side counter is credited by every guest `WindowUpdate` it
    /// admits and debited by nothing, so it climbs until a legitimate grant
    /// pushes it past the cap and the session is torn down with a `GoAway`.
    /// Only a transfer past the cap reaches it: below that the counter simply
    /// climbs unnoticed.
    #[test]
    fn a_download_past_the_credit_cap_is_not_torn_down() {
        let total = mvm_contract::protocol::network_flow::MAX_STREAM_CREDIT as usize + 512 * 1024;
        let addr = tcp_source_server(total);
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        let mut got = 0usize;
        loop {
            let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            match opcode {
                Opcode::Data => {
                    got += payload.len();
                    // Return the credit, as the real guest client does.
                    let delta = u32::try_from(payload.len()).unwrap();
                    write_frame(
                        &mut guest,
                        &mut guest_session,
                        Opcode::WindowUpdate,
                        1,
                        &delta.to_be_bytes(),
                    );
                }
                Opcode::HalfClose => break,
                Opcode::WindowUpdate => {}
                other => panic!(
                    "unexpected {other:?} after {got} of {total} bytes: {}",
                    String::from_utf8_lossy(&payload)
                ),
            }
        }
        assert_eq!(got, total, "the whole body must arrive");

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A session with no substitution service refuses to open an HTTP flow.
    ///
    /// The flow exists to carry a request that may name a `mvm-secret-<hex>`
    /// placeholder. With nothing to resolve it, forwarding the request anyway
    /// would put the placeholder on the wire to a real upstream, so the open
    /// fails instead.
    #[test]
    fn an_http_flow_without_a_substitution_service_is_refused() {
        let (mut guest, mut guest_session, host) =
            run_session(mvm_runtime::vmm::egress_gate::EgressGate::default_deny());
        write_frame(&mut guest, &mut guest_session, Opcode::OpenHttp, 1, b"");
        let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert_eq!(stream_id, 1);
        assert!(
            !payload.is_empty(),
            "a refusal must say why, not close silently"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A guest echo request reaches the shared decision and comes back as a
    /// reply on the same flow.
    ///
    /// The gate here denies everything, so what this pins is that the refusal
    /// is *answered* rather than dropped: a `ping` against a denied host must
    /// say why, and the flow must retire either way.
    #[test]
    fn an_icmp_echo_is_answered_on_its_own_flow() {
        let (mut guest, mut guest_session, host) =
            run_session(mvm_runtime::vmm::egress_gate::EgressGate::default_deny());
        let request = mvm_core::icmp_wire::IcmpEchoRequest {
            host: "example.com".into(),
            count: 1,
            payload_len: 56,
            timeout_ms: 500,
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::IcmpEcho,
            1,
            &encoded,
        );

        let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(
            opcode,
            Opcode::IcmpRefused,
            "a denied destination must be answered, not dropped"
        );
        assert_eq!(stream_id, 1);
        let reply: mvm_core::icmp_wire::IcmpEchoReply = serde_json::from_slice(&payload).unwrap();
        assert!(
            matches!(reply, mvm_core::icmp_wire::IcmpEchoReply::Refused { .. }),
            "unexpected reply: {reply:?}"
        );

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// A malformed echo request is refused rather than parsed loosely — the
    /// same fail-closed shape every other verb on this session has.
    #[test]
    fn a_malformed_icmp_echo_is_refused() {
        let (mut guest, mut guest_session, host) =
            run_session(mvm_runtime::vmm::egress_gate::EgressGate::default_deny());
        write_frame(&mut guest, &mut guest_session, Opcode::IcmpEcho, 1, b"{{{{");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::IcmpRefused);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    /// An upstream that writes `total` bytes and then closes.
    fn tcp_source_server(total: usize) -> SocketAddr {
        let listener =
            std::net::TcpListener::bind(std::net::SocketAddr::new(local_test_ip(), 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let chunk = vec![b'd'; 8 * 1024];
            let mut sent = 0usize;
            while sent < total {
                let n = chunk.len().min(total - sent);
                if stream.write_all(&chunk[..n]).is_err() {
                    return;
                }
                sent += n;
            }
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
        addr
    }

    fn tcp_echo_server() -> SocketAddr {
        tcp_echo_server_on(local_test_ip())
    }

    fn tcp_echo_server_on(ip: IpAddr) -> SocketAddr {
        let listener = std::net::TcpListener::bind(std::net::SocketAddr::new(ip, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        stream.write_all(&buf[..n]).unwrap();
                        stream.flush().unwrap();
                    }
                    Err(_) => break,
                }
            }
        });
        addr
    }

    fn udp_echo_server() -> SocketAddr {
        udp_echo_server_on(local_test_ip())
    }

    fn tcp_banner_server() -> SocketAddr {
        let listener =
            std::net::TcpListener::bind(std::net::SocketAddr::new(local_test_ip(), 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"banner");
            }
        });
        addr
    }

    fn udp_echo_server_on(ip: IpAddr) -> SocketAddr {
        let socket = std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)).unwrap();
        let addr = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..n], peer);
            }
        });
        addr
    }

    #[test]
    fn open_tcp_to_allowed_local_addr_roundtrips_data() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        let payload = b"ping";
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, payload);
        let data = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            if opcode == Opcode::Data {
                break frame;
            }
            // WindowUpdate and other non-data frames are expected before the
            // upstream response reaches us.
        };
        assert_eq!(&data[..], payload);

        write_frame(&mut guest, &mut guest_session, Opcode::HalfClose, 1, b"");
        let opcode = loop {
            let (op, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            if op == Opcode::HalfClose {
                break op;
            }
            // WindowUpdate may be in flight before the relay observes EOF.
            assert_eq!(op, Opcode::WindowUpdate);
        };
        assert_eq!(opcode, Opcode::HalfClose);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn open_tcp_to_denied_local_addr_is_refused() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        let denied_port = addr.port().wrapping_add(1);
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), denied_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn open_tcp_to_allowed_but_unbound_addr_is_refused_truthfully() {
        let ip = local_test_ip();
        // Bind briefly to let the OS assign a free port, then drop the
        // listener so the attempted connect fails with ECONNREFUSED.
        let free_port = std::net::TcpListener::bind(std::net::SocketAddr::new(ip, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(ip, free_port, None));
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", ip, free_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn udp_send_recv_to_allowed_local_addr() {
        let addr = udp_echo_server();
        let (mut guest, mut guest_session, host) = run_session_with(
            gate_allowing_addr(addr.ip(), 0, Some(addr.port())),
            RegistryLimits::default(),
        );
        write_frame(&mut guest, &mut guest_session, Opcode::OpenUdp, 1, b"");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::UdpOpened);

        let mut payload = encode_udp_addr(addr.ip(), addr.port());
        payload.extend_from_slice(b"hello");
        write_frame(&mut guest, &mut guest_session, Opcode::UdpSend, 1, &payload);

        let (opcode, _stream_id, recv) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::UdpRecv);
        let (source_ip, source_port, body) = decode_udp_addr(&recv).unwrap();
        assert_eq!(SocketAddr::new(source_ip, source_port), addr);
        assert_eq!(body, b"hello");

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn udp_association_expires_on_idle() {
        let limits = RegistryLimits {
            udp_idle_timeout: Duration::from_millis(100),
            max_udp_peers: 2,
            ..Default::default()
        };
        let addr = udp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session_with(gate_allowing_addr(addr.ip(), 0, Some(addr.port())), limits);
        write_frame(&mut guest, &mut guest_session, Opcode::OpenUdp, 1, b"");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::UdpOpened);

        thread::sleep(Duration::from_millis(250));
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::CloseUdp);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn udp_peer_bound_limits_distinct_peers() {
        let limits = RegistryLimits {
            max_udp_peers: 2,
            ..Default::default()
        };
        let (mut guest, mut guest_session, host) = run_session_with(
            EgressGate::new(mvm_contract::policy::projection::CanonicalEgress::Unrestricted),
            limits,
        );
        write_frame(&mut guest, &mut guest_session, Opcode::OpenUdp, 1, b"");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::UdpOpened);

        let ip = local_test_ip();
        let d1 = std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)).unwrap();
        let d2 = std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)).unwrap();
        let d3 = std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)).unwrap();
        let dests = [
            d1.local_addr().unwrap(),
            d2.local_addr().unwrap(),
            d3.local_addr().unwrap(),
        ];

        for dest in &dests {
            let mut payload = encode_udp_addr(dest.ip(), dest.port());
            payload.extend_from_slice(b"x");
            write_frame(&mut guest, &mut guest_session, Opcode::UdpSend, 1, &payload);
        }

        thread::sleep(Duration::from_millis(200));

        let mut buf = [0u8; 16];
        assert_eq!(d1.recv(&mut buf).unwrap(), 1);
        assert_eq!(d2.recv(&mut buf).unwrap(), 1);
        d3.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let r = d3.recv(&mut buf);
        assert!(matches!(
            r,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
        ));

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn resolve_to_pinned_localhost_returns_address() {
        let (mut guest, mut guest_session, host) = run_session(gate_with_pinned_localhost());
        let query = build_dns_query("localhost", 1, 0x1234);
        write_frame(&mut guest, &mut guest_session, Opcode::Resolve, 1, &query);

        let (opcode, _stream_id, response) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Resolved);
        assert!(!response.is_empty());
        assert_eq!(&response[..2], &[0x12, 0x34]);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn concurrent_tcp_flows_are_independent() {
        let addr1 = tcp_echo_server();
        let addr2 = tcp_echo_server();
        let (mut guest, mut guest_session, host) = run_session(gate_allowing_ports(
            addr1.ip(),
            &[addr1.port(), addr2.port()],
            &[],
        ));

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr1.ip(), addr1.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            3,
            format!("{}:{}", addr2.ip(), addr2.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, b"alpha");
        write_frame(&mut guest, &mut guest_session, Opcode::Data, 3, b"beta");

        let mut got1: Option<Vec<u8>> = None;
        let mut got3: Option<Vec<u8>> = None;
        while got1.is_none() || got3.is_none() {
            let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            match opcode {
                Opcode::Data if stream_id == 1 => got1 = Some(payload),
                Opcode::Data if stream_id == 3 => got3 = Some(payload),
                Opcode::WindowUpdate => {}
                other => panic!("unexpected opcode {other:?} on stream {stream_id}"),
            }
        }
        assert_eq!(got1.unwrap().as_slice(), b"alpha");
        assert_eq!(got3.unwrap().as_slice(), b"beta");

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_and_udp_flows_are_concurrent() {
        let tcp_addr = tcp_echo_server();
        let udp_addr = udp_echo_server();
        let (mut guest, mut guest_session, host) = run_session(gate_allowing_ports(
            tcp_addr.ip(),
            &[tcp_addr.port()],
            &[udp_addr.port()],
        ));

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", tcp_addr.ip(), tcp_addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, &mut guest_session, Opcode::OpenUdp, 3, b"");
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::UdpOpened);

        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, b"tcp-ping");
        let mut udp_payload = encode_udp_addr(udp_addr.ip(), udp_addr.port());
        udp_payload.extend_from_slice(b"udp-ping");
        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::UdpSend,
            3,
            &udp_payload,
        );

        let mut tcp_reply: Option<Vec<u8>> = None;
        let mut udp_reply: Option<Vec<u8>> = None;
        while tcp_reply.is_none() || udp_reply.is_none() {
            let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            match opcode {
                Opcode::Data if stream_id == 1 => tcp_reply = Some(payload),
                Opcode::UdpRecv if stream_id == 3 => udp_reply = Some(payload),
                Opcode::WindowUpdate => {}
                other => panic!("unexpected opcode {other:?} on stream {stream_id}"),
            }
        }
        assert_eq!(tcp_reply.unwrap().as_slice(), b"tcp-ping");
        let udp_payload = udp_reply.unwrap();
        let (source_ip, source_port, body) = decode_udp_addr(&udp_payload).unwrap();
        assert_eq!(SocketAddr::new(source_ip, source_port), udp_addr);
        assert_eq!(body, b"udp-ping");

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn guest_half_close_is_replied_with_host_half_close() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, b"hello");
        let (opcode, _, payload) = loop {
            let (op, sid, frame) = read_flowmux_frame(&mut guest, &mut guest_session);
            if op == Opcode::Data {
                break (op, sid, frame);
            }
            assert_eq!(op, Opcode::WindowUpdate);
        };
        assert_eq!(opcode, Opcode::Data);
        assert_eq!(payload.as_slice(), b"hello");

        write_frame(&mut guest, &mut guest_session, Opcode::HalfClose, 1, b"");
        let opcode = loop {
            let (op, _stream_id, _payload) = read_flowmux_frame(&mut guest, &mut guest_session);
            if op == Opcode::HalfClose {
                break op;
            }
            assert_eq!(op, Opcode::WindowUpdate);
        };
        assert_eq!(opcode, Opcode::HalfClose);

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn guest_reset_retires_stream() {
        let addr = tcp_echo_server();
        let (mut guest, mut guest_session, host) =
            run_session(gate_allowing_addr(addr.ip(), addr.port(), None));

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, &mut guest_session, Opcode::Reset, 1, b"bye");
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Reset);

        write_frame(&mut guest, &mut guest_session, Opcode::Data, 1, b"?");
        let (opcode, _, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::GoAway);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_connection_rate_limit_refuses_overflow() {
        let addr = tcp_echo_server();
        let limits = RegistryLimits {
            tcp_connect_rate: 1,
            ..Default::default()
        };
        let (mut guest, mut guest_session, host) =
            run_session_with(gate_allowing_addr(addr.ip(), addr.port(), None), limits);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            3,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Refused);
        assert!(std::str::from_utf8(&payload).unwrap().contains("rate"));

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn dns_resolve_rate_limit_refuses_overflow() {
        let limits = RegistryLimits {
            dns_resolve_rate: 1,
            ..Default::default()
        };
        let (mut guest, mut guest_session, host) =
            run_session_with(gate_with_pinned_localhost(), limits);

        let query1 = build_dns_query("localhost", 1, 0x1234);
        write_frame(&mut guest, &mut guest_session, Opcode::Resolve, 1, &query1);
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Resolved);

        let query3 = build_dns_query("localhost", 1, 0x1235);
        write_frame(&mut guest, &mut guest_session, Opcode::Resolve, 3, &query3);
        let (opcode, _, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::ResolveRefused);
        assert!(std::str::from_utf8(&payload).unwrap().contains("rate"));

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn host_credit_exhaustion_sends_reset() {
        let addr = tcp_banner_server();
        let limits = RegistryLimits {
            initial_credit: 0,
            // A guest that never grants credit is exactly what the wait exists
            // to tolerate, so shrink it here rather than spending the whole
            // production bound proving the give-up path still fires.
            credit_wait: Duration::from_millis(200),
            ..Default::default()
        };
        let (mut guest, mut guest_session, host) =
            run_session_with(gate_allowing_addr(addr.ip(), addr.port(), None), limits);

        write_frame(
            &mut guest,
            &mut guest_session,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Opened);

        let (opcode, _, payload) = read_flowmux_frame(&mut guest, &mut guest_session);
        assert_eq!(opcode, Opcode::Reset);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn vm_resources_bound_sessions_and_return_slots_on_drop() {
        let resources = Arc::new(FlowMuxVmResources::new(
            mvm_core::plan::NetworkLimits::default(),
        ));
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_FLOWMUX_SESSIONS {
            permits.push(
                resources
                    .try_acquire_session()
                    .expect("session below the endpoint ceiling"),
            );
        }
        assert!(resources.try_acquire_session().is_none());

        drop(permits.pop());
        assert!(resources.try_acquire_session().is_some());
    }

    #[test]
    fn vm_resources_share_one_rate_budget_across_session_clones() {
        let limits = RegistryLimits {
            tcp_connect_rate: 1,
            ..Default::default()
        };
        let resources = Arc::new(FlowMuxVmResources::from_registry_limits(limits));
        let first_session = Arc::clone(&resources);
        let second_session = Arc::clone(&resources);

        assert!(
            first_session
                .rate_limiter
                .try_open(registry::FlowClass::Tcp)
        );
        assert!(
            !second_session
                .rate_limiter
                .try_open(registry::FlowClass::Http),
            "typed HTTP and opaque TCP sessions must spend one VM rate budget"
        );
    }
}
