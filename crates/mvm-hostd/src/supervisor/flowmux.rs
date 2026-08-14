//! FlowMux session acceptor for the single workload networking endpoint.
//!
//! This module owns the host side of one authenticated FlowMux session:
//! handshake, frame I/O, and dispatch to the per-flow handlers. The current
//! implementation accepts one session, completes the handshake, and runs a
//! minimal TCP data relay, one-shot DNS resolution, and a basic UDP association
//! relay for guest-initiated `OpenTcp`, `Resolve`, and `OpenUdp` flows.
//! Everything else fails closed with `GoAway`.

pub mod registry;

use std::collections::{BTreeMap, BTreeSet};
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
use mvm_contract::protocol::network_flow::{
    Direction, FrameError, HEADER_LEN, LENGTH_PREFIX_LEN, MAX_UDP_DATAGRAM_LEN, Opcode,
    SessionValidator, UDP_ADDR_PREFIX_LEN, decode,
};
use mvm_core::net::session::Session;
use mvm_vmm::vsock_egress_bridge::egress_gate::{DnsVerdict, EgressGate, EgressVerdict};
use tracing::{info, warn};

use self::registry::{RegistryLimits, StreamRegistry, class_for_open};

use crate::supervisor::audit_recorder::{EventCategory, Recorder};
use crate::supervisor::raw_egress::resolve_hostname_ips_pure;
use mvm_core::rate_limit::TokenBucket;

/// Per-address connect budget when trying an admitted set: small so an
/// unreachable address (e.g. an AAAA with no host IPv6 egress) fails over to
/// the next candidate quickly.
const PER_IP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-session rate limiter for new connection/association/resolve attempts.
///
/// A guest can otherwise force the host to open an unbounded number of TCP
/// connections, UDP associations, or DNS queries per second. Each class gets
/// its own one-second-burst token bucket; zero capacity disables limiting.
#[derive(Debug)]
pub struct ConnectionRateLimiter {
    tcp: Mutex<TokenBucket>,
    udp: Mutex<TokenBucket>,
    dns: Mutex<TokenBucket>,
}

impl ConnectionRateLimiter {
    /// Build a limiter from the per-class rates in [`RegistryLimits`].
    pub fn from_limits(limits: &RegistryLimits) -> Self {
        Self {
            tcp: Mutex::new(TokenBucket::new(limits.tcp_connect_rate)),
            udp: Mutex::new(TokenBucket::new(limits.udp_open_rate)),
            dns: Mutex::new(TokenBucket::new(limits.dns_resolve_rate)),
        }
    }

    /// Try to admit one new flow of `class`. Returns `true` when admitted or
    /// when the limiter for this class is disabled.
    pub fn try_open(&self, class: registry::FlowClass) -> bool {
        let bucket = match class {
            registry::FlowClass::Tcp => &self.tcp,
            registry::FlowClass::Udp => &self.udp,
            registry::FlowClass::Dns => &self.dns,
        };
        let mut guard = bucket.lock().expect("rate limiter bucket poisoned");
        // A zero-capacity bucket means "unlimited" for this class.
        if guard.capacity() == 0.0 {
            return true;
        }
        guard.try_take()
    }
}

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
    session: Session,
    validator: SessionValidator,
    registry: Arc<Mutex<StreamRegistry>>,
    /// Active guest-initiated TCP streams and their upstream sockets. The host
    /// half of each stream lives in a dedicated thread.
    streams: BTreeMap<u32, TcpStreamHandle>,
    /// Active guest-initiated UDP associations. Each association runs in its
    /// own relay thread.
    udp_associations: BTreeMap<u32, UdpAssociationHandle>,
    gate: EgressGate,
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
            .field("streams", &self.streams.len())
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

/// A request from the main session thread to a UDP relay thread to send one
/// datagram to an admitted destination.
struct UdpSendMsg {
    destination: SocketAddr,
    payload: Vec<u8>,
}

/// The host-side handle for one active UDP association. The relay thread owns
/// the socket; the main thread forwards guest `UdpSend` frames through a
/// channel.
struct UdpAssociationHandle {
    tx: std::sync::mpsc::Sender<UdpSendMsg>,
}

impl FlowMuxSession {
    /// Return the session identifier for logging and correlation.
    pub fn session_id(&self) -> &str {
        self.session.session_id()
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
        Self::accept_with_recorder(
            stream,
            session_id,
            host_key,
            guest_anchor,
            limits,
            gate,
            None,
        )
    }

    /// Accept one authenticated FlowMux session with an optional audit
    /// recorder attached.
    ///
    /// `session_id` must be unique per VM boot. `host_key` signs the
    /// handshake; `guest_anchor` is the only guest identity this endpoint
    /// will accept. A mismatch fails closed.
    pub fn accept_with_recorder(
        mut stream: UnixStream,
        session_id: &str,
        host_key: SigningKey,
        guest_anchor: &VerifyingKey,
        limits: RegistryLimits,
        gate: EgressGate,
        recorder: Option<Arc<Recorder>>,
    ) -> Result<Self, FlowMuxError> {
        // Split the socket into independent read/write descriptors so the
        // main thread can block on guest frames while relay threads emit
        // upstream data back to the guest.
        let writer = stream.try_clone()?;
        let (session, _peer_key) = Session::host(&mut stream, session_id, host_key)
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        if session.peer_verifying_key() != guest_anchor {
            return Err(FlowMuxError::Handshake(
                "guest identity does not match pinned anchor".to_string(),
            ));
        }

        info!(session_id, "FlowMux handshake complete");

        Ok(Self {
            reader: stream,
            writer: Arc::new(Mutex::new(writer)),
            session,
            validator: SessionValidator::default(),
            registry: Arc::new(Mutex::new(StreamRegistry::new(limits))),
            streams: BTreeMap::new(),
            udp_associations: BTreeMap::new(),
            gate,
            read_buf: Vec::with_capacity(4096),
            limits,
            connect_timeout: Duration::from_secs(30),
            recorder,
            runtime_handle: tokio::runtime::Handle::try_current().ok(),
            rate_limiter: Arc::new(ConnectionRateLimiter::from_limits(&limits)),
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
        let (Some(recorder), Some(handle)) = (&self.recorder, &self.runtime_handle) else {
            return;
        };
        let recorder = Arc::clone(recorder);
        let event_name = event_name.to_string();
        let fut = async move {
            let _ = recorder.record_unbound(category, event_name, labels).await;
        };
        // The session runs in `spawn_blocking`; block_on is acceptable
        // because the audit signer writes to a local file and returns quickly.
        handle.block_on(fut);
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
        match self.read_frame()? {
            Some((Opcode::Hello, 0, 0)) => {}
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
        }

        self.validator
            .admit(&mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
            ))
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        self.send_hello_ack()?;
        self.validator
            .mark_hello_ack_sent()
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;

        loop {
            let (opcode, stream_id, payload_len) = match self.read_frame()? {
                Some(facts) => facts,
                None => {
                    info!("FlowMux peer closed session");
                    return Ok(());
                }
            };

            if let Err(e) = self.validator.admit(
                &mvm_contract::protocol::network_flow::FrameFacts::new(
                    Direction::GuestToHost,
                    opcode,
                    stream_id,
                )
                .with_payload(payload_len),
            ) {
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

        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let target = match std::str::from_utf8(&self.read_buf[payload_start..payload_end]) {
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

        let (ips, port) = match self.gate.decide_request(&format!("{host}:{port}")) {
            EgressVerdict::Allow { ips, port } => (ips, port),
            EgressVerdict::Deny(reason) => {
                self.send_refused(stream_id, &reason.to_string())?;
                self.emit_audit(
                    EventCategory::Host,
                    "host.flow.denied",
                    BTreeMap::from([
                        ("stream_id".to_string(), stream_id.to_string()),
                        ("class".to_string(), "tcp".to_string()),
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

        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let query = &self.read_buf[payload_start..payload_end];

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
                resolve_hostname_ips_pure(name, timeout)
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
        let idle_timeout = self.limits.udp_idle_timeout;
        let max_peers = self.limits.max_udp_peers;

        let (tx, rx) = std::sync::mpsc::channel();
        let writer = Arc::clone(&self.writer);
        let registry_arc = Arc::clone(&self.registry);
        std::thread::Builder::new()
            .name(format!("flowmux-udp-{stream_id}"))
            .spawn(move || {
                run_udp_relay(
                    stream_id,
                    socket,
                    writer,
                    idle_timeout,
                    max_peers,
                    rx,
                    registry_arc,
                )
            })
            .map_err(FlowMuxError::Transport)?;

        self.udp_associations
            .insert(stream_id, UdpAssociationHandle { tx });
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
        let handle = match self.udp_associations.get(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "UdpSend on unknown association");
                self.send_goaway("unknown UDP association")?;
                return Ok(());
            }
        };

        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let payload = &self.read_buf[payload_start..payload_end];
        if payload.len() < UDP_ADDR_PREFIX_LEN {
            return Err(FlowMuxError::FrameRefused(
                "UdpSend payload too short".to_string(),
            ));
        }

        let (ip, port, datagram) = decode_udp_addr(payload)
            .map_err(|e| FlowMuxError::FrameRefused(format!("invalid UdpSend address: {e}")))?;
        let target = format!("{ip}:{port}");

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

        let msg = UdpSendMsg {
            destination: SocketAddr::new(ip, port),
            payload: datagram.to_vec(),
        };
        if handle.tx.send(msg).is_err() {
            return Err(FlowMuxError::FrameRefused(
                "UDP relay thread has exited".to_string(),
            ));
        }
        Ok(())
    }

    fn remove_udp_association(&mut self, stream_id: u32) {
        let _ = self.udp_associations.remove(&stream_id);
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_udp_opened(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        info!(stream_id, "FlowMux sending UdpOpened");
        self.write_frame(Opcode::UdpOpened, stream_id, b"")?;
        self.mark_sent(Opcode::UdpOpened, stream_id);
        Ok(())
    }

    fn spawn_tcp_relay(&mut self, stream_id: u32, upstream: TcpStream) -> Result<(), FlowMuxError> {
        let upstream_read = upstream.try_clone()?;
        let host_half_closed = Arc::new(AtomicBool::new(false));
        let relay_flag = Arc::clone(&host_half_closed);
        let retired = Arc::new(AtomicBool::new(false));
        let retired_flag = Arc::clone(&retired);
        let writer = Arc::clone(&self.writer);
        let registry = Arc::clone(&self.registry);

        std::thread::Builder::new()
            .name(format!("flowmux-tcp-{stream_id}"))
            .spawn(move || {
                run_tcp_relay(
                    stream_id,
                    upstream_read,
                    writer,
                    registry,
                    relay_flag,
                    retired_flag,
                )
            })
            .map_err(FlowMuxError::Transport)?;

        self.streams.insert(
            stream_id,
            TcpStreamHandle {
                upstream,
                host_half_closed,
                retired,
            },
        );
        Ok(())
    }

    fn handle_guest_data(&mut self, stream_id: u32, payload_len: u32) -> Result<(), FlowMuxError> {
        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let payload = &self.read_buf[payload_start..payload_end];

        let handle = match self.streams.get_mut(&stream_id) {
            Some(h) => h,
            None => {
                warn!(stream_id, "Data frame on unknown stream");
                self.send_goaway("unknown stream")?;
                return Ok(());
            }
        };

        if handle.host_half_closed.load(Ordering::Relaxed) {
            self.send_reset(stream_id, "data after host half-close")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        {
            let mut reg = lock_registry(&self.registry);
            if let Err(e) = reg.consume_guest_credit(stream_id, payload_len) {
                warn!(error = %e, stream_id, "guest credit exhausted");
                drop(reg);
                self.send_reset(stream_id, "credit exhausted")?;
                self.remove_stream(stream_id);
                return Ok(());
            }
        }

        if let Err(e) = handle
            .upstream
            .write_all(payload)
            .and_then(|_| handle.upstream.flush())
        {
            warn!(error = %e, stream_id, "write to upstream failed");
            self.send_reset(stream_id, "upstream write failed")?;
            self.remove_stream(stream_id);
            return Ok(());
        }

        // Replenish the consumed credit so the guest can keep sending.
        {
            let mut reg = lock_registry(&self.registry);
            let _ = reg.grant_guest_credit(stream_id, payload_len);
        }
        self.send_window_update(stream_id, payload_len)?;
        Ok(())
    }

    fn handle_guest_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        let handle = match self.streams.get_mut(&stream_id) {
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
            self.send_reset(stream_id, "stream complete")?;
            self.remove_stream(stream_id);
        } else {
            let _ = lock_registry(&self.registry).half_close(stream_id);
        }
        Ok(())
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
        let payload_start = LENGTH_PREFIX_LEN + HEADER_LEN;
        let payload_end = payload_start + payload_len as usize;
        let payload = &self.read_buf[payload_start..payload_end];
        let delta = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        lock_registry(&self.registry)
            .grant_host_credit(stream_id, delta)
            .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))
    }

    fn reset_stream(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        if let Some(handle) = self.streams.remove(&stream_id) {
            handle.retired.store(true, Ordering::Relaxed);
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
        self.send_reset(stream_id, "reset by peer")?;
        Ok(())
    }

    fn remove_stream(&mut self, stream_id: u32) {
        if let Some(handle) = self.streams.remove(&stream_id) {
            handle.retired.store(true, Ordering::Relaxed);
            let _ = handle.upstream.shutdown(std::net::Shutdown::Both);
        }
        let _ = lock_registry(&self.registry).retire(stream_id);
    }

    fn send_hello_ack(&self) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HelloAck, 0, b"")
    }

    fn send_goaway(&self, reason: &str) -> Result<(), FlowMuxError> {
        warn!(%reason, "FlowMux sending GoAway");
        self.write_frame(Opcode::GoAway, 0, reason.as_bytes())
    }

    /// Advance the local state machine for a frame the host is about to send.
    /// Each side validates the frames it reads, but a confirming or terminal
    /// frame sent by the host still moves the host-side view of the stream.
    fn mark_sent(&mut self, opcode: Opcode, stream_id: u32) {
        let _ = self
            .validator
            .admit(&mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::HostToGuest,
                opcode,
                stream_id,
            ));
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
        write_frame_to(&self.writer, opcode, stream_id, payload)
    }

    /// Read one decrypted FlowMux frame from the peer, returning the opcode,
    /// stream id, and payload length, or `None` on clean close.
    ///
    /// The session layer encrypts each frame; this helper reads the encrypted
    /// envelope, opens it, and decodes the inner FlowMux header. The skeleton
    /// currently sends plaintext FlowMux frames, so this reads the length
    /// prefix that `encode_into` produces and decodes the frame directly.
    fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32)>, FlowMuxError> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            // A reset or abort from the guest is an ungraceful but expected
            // close of the Unix stream; treat it the same as EOF.
            Err(e) if is_peer_disconnect(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        if frame_len == 0 {
            return Ok(None);
        }
        if frame_len > 1 << 20 {
            return Err(FlowMuxError::FrameRefused(format!(
                "FlowMux frame length {frame_len} exceeds 1 MiB"
            )));
        }
        self.read_buf.resize(4 + frame_len, 0);
        self.read_buf[..4].copy_from_slice(&len_buf);
        if let Err(e) = self.reader.read_exact(&mut self.read_buf[4..]) {
            if is_peer_disconnect(&e) {
                return Ok(None);
            }
            return Err(e.into());
        }

        // The payload is currently passed through unencrypted because the
        // encrypted wire format for `SealedFrame` is not yet defined.

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

/// Returns true for the common "peer closed the connection" I/O errors that
/// can race with an in-flight read when the guest drops its socket.
fn is_peer_disconnect(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}

/// Lock the shared writer, recovering from poison so a crashed relay thread
/// does not silence the whole session.
fn lock_writer(writer: &Mutex<UnixStream>) -> std::sync::MutexGuard<'_, UnixStream> {
    writer.lock().unwrap_or_else(|e| e.into_inner())
}

/// Lock the shared registry, recovering from poison.
fn lock_registry(registry: &Mutex<StreamRegistry>) -> std::sync::MutexGuard<'_, StreamRegistry> {
    registry.lock().unwrap_or_else(|e| e.into_inner())
}

/// Serialize and send one frame through a shared writer.
fn write_frame_to(
    writer: &Mutex<UnixStream>,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), FlowMuxError> {
    let mut wire = Vec::new();
    mvm_contract::protocol::network_flow::encode_into(&mut wire, opcode, stream_id, payload)
        .map_err(|e| FlowMuxError::FrameRefused(e.to_string()))?;
    let mut w = lock_writer(writer);
    w.write_all(&wire)?;
    w.flush()?;
    Ok(())
}

/// Try each admitted address in order, first success wins, bounded overall by
/// `overall_timeout` and per-address by [`PER_IP_CONNECT_TIMEOUT`]. This is
/// the happy-eyeballs fallover used by the raw egress path, expressed
/// synchronously because the FlowMux session runs in `spawn_blocking`.
fn connect_first_admitted(
    ips: &[IpAddr],
    port: u16,
    overall_timeout: Duration,
) -> Option<TcpStream> {
    let deadline = std::time::Instant::now() + overall_timeout;
    for ip in ips {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let budget = remaining.min(PER_IP_CONNECT_TIMEOUT);
        match TcpStream::connect_timeout(&std::net::SocketAddr::new(*ip, port), budget) {
            Ok(stream) => return Some(stream),
            Err(e) => warn!(%ip, %port, error = %e, "FlowMux TCP connect attempt failed"),
        }
    }
    None
}

/// Per-stream relay thread: read from the upstream TCP socket and forward
/// each chunk to the guest as a `Data` frame. EOF becomes a `HalfClose`;
/// errors become a `Reset`.
fn run_tcp_relay(
    stream_id: u32,
    mut upstream: TcpStream,
    writer: Arc<Mutex<UnixStream>>,
    registry: Arc<Mutex<StreamRegistry>>,
    host_half_closed: Arc<AtomicBool>,
    retired: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) => {
                host_half_closed.store(true, Ordering::Relaxed);
                if !retired.load(Ordering::Relaxed)
                    && write_frame_to(&writer, Opcode::HalfClose, stream_id, &[]).is_err()
                {
                    warn!(stream_id, "FlowMux relay failed to send HalfClose");
                }
                break;
            }
            Ok(n) => {
                if let Err(e) = lock_registry(&registry).consume_host_credit(stream_id, n as u32) {
                    warn!(stream_id, error = %e, "FlowMux host credit exhausted");
                    let _ =
                        write_frame_to(&writer, Opcode::Reset, stream_id, b"host credit exhausted");
                    host_half_closed.store(true, Ordering::Relaxed);
                    break;
                }
                if write_frame_to(&writer, Opcode::Data, stream_id, &buf[..n]).is_err() {
                    warn!(stream_id, "FlowMux relay failed to send Data");
                    break;
                }
            }
            Err(e) => {
                warn!(stream_id, error = %e, "FlowMux upstream read failed");
                if !retired.load(Ordering::Relaxed) {
                    let reason = format!("upstream error: {e}");
                    let _ = write_frame_to(&writer, Opcode::Reset, stream_id, reason.as_bytes());
                }
                host_half_closed.store(true, Ordering::Relaxed);
                break;
            }
        }
    }
    // The stream remains in the registry until the main thread observes the
    // half-close/reset and retires it, so we do not race with in-flight guest
    // frames here.
    let _ = registry;
}

/// Per-association UDP relay thread: read datagrams from the upstream socket
/// and forward them to the guest as `UdpRecv` frames. Guest `UdpSend`
/// requests arrive through a channel so the socket stays owned by one thread.
///
/// The relay enforces two association bounds: a limit on distinct peers and
/// an idle timeout that closes the association when no bytes flow in either
/// direction for too long.
fn run_udp_relay(
    stream_id: u32,
    socket: std::net::UdpSocket,
    writer: Arc<Mutex<UnixStream>>,
    idle_timeout: Duration,
    max_peers: usize,
    rx: std::sync::mpsc::Receiver<UdpSendMsg>,
    registry: Arc<Mutex<StreamRegistry>>,
) {
    const MAX_POLL: Duration = Duration::from_secs(1);

    let mut buf = vec![0_u8; MAX_UDP_DATAGRAM_LEN];
    let mut peers: BTreeSet<SocketAddr> = BTreeSet::new();
    let mut last_activity = std::time::Instant::now();
    let mut idle_expired = false;

    loop {
        let remaining = idle_timeout.saturating_sub(last_activity.elapsed());
        if remaining.is_zero() {
            idle_expired = true;
            break;
        }
        let budget = remaining.min(MAX_POLL);
        if socket.set_read_timeout(Some(budget)).is_err() {
            warn!(stream_id, "FlowMux UDP relay failed to set read timeout");
            break;
        }

        let mut activity_this_iter = false;
        match socket.recv_from(&mut buf) {
            Ok((len, source)) => {
                let already_peer = peers.contains(&source);
                if !already_peer && peers.len() >= max_peers {
                    // Peer bound would be exceeded; drop silently.
                    activity_this_iter = true;
                } else {
                    peers.insert(source);
                    let mut payload = encode_udp_addr(source.ip(), source.port());
                    payload.extend_from_slice(&buf[..len]);
                    let frame_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
                    if let Err(e) =
                        lock_registry(&registry).consume_host_credit(stream_id, frame_len)
                    {
                        warn!(stream_id, error = %e, "FlowMux UDP host credit exhausted");
                        let _ = write_frame_to(
                            &writer,
                            Opcode::Reset,
                            stream_id,
                            b"host credit exhausted",
                        );
                        break;
                    }
                    if write_frame_to(&writer, Opcode::UdpRecv, stream_id, &payload).is_err() {
                        break;
                    }
                    activity_this_iter = true;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                warn!(stream_id, error = %e, "FlowMux UDP recv failed");
                break;
            }
        }

        // Drain any guest-send requests without blocking.
        while let Ok(msg) = rx.try_recv() {
            activity_this_iter = true;
            let already_peer = peers.contains(&msg.destination);
            if !already_peer && peers.len() >= max_peers {
                // Peer bound would be exceeded; drop silently.
                continue;
            }
            peers.insert(msg.destination);
            if socket.send_to(&msg.payload, msg.destination).is_err() {
                break;
            }
        }

        if activity_this_iter {
            last_activity = std::time::Instant::now();
        }
    }

    let _ = lock_registry(&registry).retire(stream_id);
    if idle_expired {
        let _ = write_frame_to(&writer, Opcode::CloseUdp, stream_id, b"idle timeout");
    } else {
        let _ = write_frame_to(&writer, Opcode::Reset, stream_id, b"UDP relay error");
    }
}

/// Encode a UDP address prefix: one family tag, a 16-byte address slot, and a
/// big-endian port. IPv4 is carried as an IPv4-mapped IPv6 address under tag
/// `0x01`; IPv6 uses tag `0x04`.
fn encode_udp_addr(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDP_ADDR_PREFIX_LEN);
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&[0; 10]);
            out.extend_from_slice(&[0xff, 0xff]);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Decode a UDP address prefix. Returns the address, port, and the remaining
/// payload bytes (the datagram body).
fn decode_udp_addr(bytes: &[u8]) -> Result<(IpAddr, u16, &[u8]), String> {
    if bytes.len() < UDP_ADDR_PREFIX_LEN {
        return Err(format!(
            "UdpSend prefix too short: {} < {}",
            bytes.len(),
            UDP_ADDR_PREFIX_LEN
        ));
    }
    let tag = bytes[0];
    let addr_bytes: [u8; 16] = bytes[1..17]
        .try_into()
        .map_err(|_| "address slot truncated".to_string())?;
    let port = u16::from_be_bytes([bytes[17], bytes[18]]);

    let ip = match tag {
        0x01 => match IpAddr::from(addr_bytes) {
            IpAddr::V6(v6) => IpAddr::from(
                v6.to_ipv4_mapped()
                    .ok_or_else(|| "IPv4-mapped address expected".to_string())?,
            ),
            IpAddr::V4(_) => return Err("IPv4-mapped address expected".to_string()),
        },
        0x04 => IpAddr::from(addr_bytes),
        _ => return Err(format!("unknown UDP address family tag: {tag}")),
    };

    Ok((ip, port, &bytes[UDP_ADDR_PREFIX_LEN..]))
}

fn parse_host_port(target: &str) -> Result<(&str, u16), String> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| "target must be host:port".to_string())?;
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("port must be a 16-bit integer: {port_str}"))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::thread;

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::network_flow::{Opcode, encode_into};
    use mvm_core::net::session::Session;
    use rand::RngCore;
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::*;

    fn fresh_keys() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
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

        let result = host_handle.join().unwrap();
        assert!(
            matches!(result, Err(FlowMuxError::Handshake(_))),
            "expected handshake failure due to anchor mismatch, got {result:?}"
        );
    }

    fn read_flowmux_frame(stream: &mut UnixStream) -> (Opcode, u32, Vec<u8>) {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) => panic!("read len failed: {e:?}"),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = Vec::with_capacity(4 + len);
        buf.extend_from_slice(&len_buf);
        buf.resize(4 + len, 0);
        stream.read_exact(&mut buf[4..]).unwrap();
        let parsed = mvm_contract::protocol::network_flow::decode(&buf).unwrap();
        (
            parsed.header.opcode,
            parsed.header.stream_id,
            parsed.payload.to_vec(),
        )
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

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        // The guest must send Hello to open the FlowMux session.
        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        // Read the HelloAck from the host.
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        // Send a flow frame on an unknown stream and expect a GoAway.
        let mut payload = Vec::new();
        encode_into(&mut payload, Opcode::Data, 1, b"hello").unwrap();
        guest_stream.write_all(&payload).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, goaway_payload) = read_flowmux_frame(&mut guest_stream);
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

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        let mut open = Vec::new();
        encode_into(&mut open, Opcode::OpenTcp, 1, b"example.com:443").unwrap();
        guest_stream.write_all(&open).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        // The session stays alive; an unknown-stream frame afterward still
        // receives a GoAway rather than dropping the connection.
        let mut data = Vec::new();
        encode_into(&mut data, Opcode::Data, 3, b"?").unwrap();
        guest_stream.write_all(&data).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
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

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        let mut open = Vec::new();
        encode_into(&mut open, Opcode::OpenUdp, 1, b"").unwrap();
        guest_stream.write_all(&open).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::UdpOpened);

        // Close the association cleanly.
        let mut close = Vec::new();
        encode_into(&mut close, Opcode::CloseUdp, 1, b"").unwrap();
        guest_stream.write_all(&close).unwrap();
        guest_stream.flush().unwrap();

        // The session is still alive.
        let mut data = Vec::new();
        encode_into(&mut data, Opcode::Data, 3, b"?").unwrap();
        guest_stream.write_all(&data).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::GoAway);

        drop(guest_stream);
        host_handle.join().unwrap().unwrap();
    }

    #[test]
    fn udp_addr_roundtrips_ipv4_and_ipv6() {
        let (ip4, port4) = ("192.0.2.10".parse::<std::net::IpAddr>().unwrap(), 5353);
        let encoded4 = encode_udp_addr(ip4, port4);
        let (decoded4_ip, decoded4_port, rest4) = decode_udp_addr(&encoded4).unwrap();
        assert_eq!(decoded4_ip, ip4);
        assert_eq!(decoded4_port, port4);
        assert!(rest4.is_empty());

        let (ip6, port6) = ("2001:db8::1".parse::<std::net::IpAddr>().unwrap(), 443);
        let encoded6 = encode_udp_addr(ip6, port6);
        let (decoded6_ip, decoded6_port, rest6) = decode_udp_addr(&encoded6).unwrap();
        assert_eq!(decoded6_ip, ip6);
        assert_eq!(decoded6_port, port6);
        assert!(rest6.is_empty());
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

        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);

        let query = build_dns_query("example.com", 1, 0x1234);
        let mut resolve = Vec::new();
        encode_into(&mut resolve, Opcode::Resolve, 1, &query).unwrap();
        guest_stream.write_all(&resolve).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest_stream);
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

    fn run_session(gate: EgressGate) -> (UnixStream, thread::JoinHandle<Result<(), FlowMuxError>>) {
        run_session_with(gate, RegistryLimits::default())
    }

    fn run_session_with(
        gate: EgressGate,
        limits: RegistryLimits,
    ) -> (UnixStream, thread::JoinHandle<Result<(), FlowMuxError>>) {
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
        let (_guest_session, _session_id) =
            Session::guest(&mut guest_stream, guest_key, &host_verify).unwrap();

        let mut hello = Vec::new();
        encode_into(&mut hello, Opcode::Hello, 0, b"").unwrap();
        guest_stream.write_all(&hello).unwrap();
        guest_stream.flush().unwrap();

        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest_stream);
        assert_eq!(opcode, Opcode::HelloAck);
        (guest_stream, host_handle)
    }

    fn write_frame(stream: &mut UnixStream, opcode: Opcode, stream_id: u32, payload: &[u8]) {
        let mut buf = Vec::new();
        encode_into(&mut buf, opcode, stream_id, payload).unwrap();
        stream.write_all(&buf).unwrap();
        stream.flush().unwrap();
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
        let (mut guest, host) = run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        let payload = b"ping";
        write_frame(&mut guest, Opcode::Data, 1, payload);
        let data = loop {
            let (opcode, _stream_id, frame) = read_flowmux_frame(&mut guest);
            if opcode == Opcode::Data {
                break frame;
            }
            // WindowUpdate and other non-data frames are expected before the
            // upstream response reaches us.
        };
        assert_eq!(&data[..], payload);

        write_frame(&mut guest, Opcode::HalfClose, 1, b"");
        let opcode = loop {
            let (op, _stream_id, _payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session(gate_allowing_addr(addr.ip(), addr.port(), None));
        let denied_port = addr.port().wrapping_add(1);
        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), denied_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest);
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

        let (mut guest, host) = run_session(gate_allowing_addr(ip, free_port, None));
        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", ip, free_port).as_bytes(),
        );
        let (opcode, _stream_id, payload) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Refused);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }

    #[test]
    fn udp_send_recv_to_allowed_local_addr() {
        let addr = udp_echo_server();
        let (mut guest, host) = run_session_with(
            gate_allowing_addr(addr.ip(), 0, Some(addr.port())),
            RegistryLimits::default(),
        );
        write_frame(&mut guest, Opcode::OpenUdp, 1, b"");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::UdpOpened);

        let mut payload = encode_udp_addr(addr.ip(), addr.port());
        payload.extend_from_slice(b"hello");
        write_frame(&mut guest, Opcode::UdpSend, 1, &payload);

        let (opcode, _stream_id, recv) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) =
            run_session_with(gate_allowing_addr(addr.ip(), 0, Some(addr.port())), limits);
        write_frame(&mut guest, Opcode::OpenUdp, 1, b"");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::UdpOpened);

        thread::sleep(Duration::from_millis(250));
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session_with(
            EgressGate::new(mvm_contract::policy::projection::CanonicalEgress::Unrestricted),
            limits,
        );
        write_frame(&mut guest, Opcode::OpenUdp, 1, b"");
        let (opcode, _stream_id, _payload) = read_flowmux_frame(&mut guest);
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
            write_frame(&mut guest, Opcode::UdpSend, 1, &payload);
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
        let (mut guest, host) = run_session(gate_with_pinned_localhost());
        let query = build_dns_query("localhost", 1, 0x1234);
        write_frame(&mut guest, Opcode::Resolve, 1, &query);

        let (opcode, _stream_id, response) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session(gate_allowing_ports(
            addr1.ip(),
            &[addr1.port(), addr2.port()],
            &[],
        ));

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr1.ip(), addr1.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            3,
            format!("{}:{}", addr2.ip(), addr2.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, Opcode::Data, 1, b"alpha");
        write_frame(&mut guest, Opcode::Data, 3, b"beta");

        let mut got1: Option<Vec<u8>> = None;
        let mut got3: Option<Vec<u8>> = None;
        while got1.is_none() || got3.is_none() {
            let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session(gate_allowing_ports(
            tcp_addr.ip(),
            &[tcp_addr.port()],
            &[udp_addr.port()],
        ));

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", tcp_addr.ip(), tcp_addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, Opcode::OpenUdp, 3, b"");
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::UdpOpened);

        write_frame(&mut guest, Opcode::Data, 1, b"tcp-ping");
        let mut udp_payload = encode_udp_addr(udp_addr.ip(), udp_addr.port());
        udp_payload.extend_from_slice(b"udp-ping");
        write_frame(&mut guest, Opcode::UdpSend, 3, &udp_payload);

        let mut tcp_reply: Option<Vec<u8>> = None;
        let mut udp_reply: Option<Vec<u8>> = None;
        while tcp_reply.is_none() || udp_reply.is_none() {
            let (opcode, stream_id, payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session(gate_allowing_addr(addr.ip(), addr.port(), None));

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, Opcode::Data, 1, b"hello");
        let (opcode, _, payload) = loop {
            let (op, sid, frame) = read_flowmux_frame(&mut guest);
            if op == Opcode::Data {
                break (op, sid, frame);
            }
            assert_eq!(op, Opcode::WindowUpdate);
        };
        assert_eq!(opcode, Opcode::Data);
        assert_eq!(payload.as_slice(), b"hello");

        write_frame(&mut guest, Opcode::HalfClose, 1, b"");
        let opcode = loop {
            let (op, _stream_id, _payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session(gate_allowing_addr(addr.ip(), addr.port(), None));

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(&mut guest, Opcode::Reset, 1, b"bye");
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Reset);

        write_frame(&mut guest, Opcode::Data, 1, b"?");
        let (opcode, _, payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) =
            run_session_with(gate_allowing_addr(addr.ip(), addr.port(), None), limits);

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            3,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, payload) = read_flowmux_frame(&mut guest);
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
        let (mut guest, host) = run_session_with(gate_with_pinned_localhost(), limits);

        let query1 = build_dns_query("localhost", 1, 0x1234);
        write_frame(&mut guest, Opcode::Resolve, 1, &query1);
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Resolved);

        let query3 = build_dns_query("localhost", 1, 0x1235);
        write_frame(&mut guest, Opcode::Resolve, 3, &query3);
        let (opcode, _, payload) = read_flowmux_frame(&mut guest);
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
            ..Default::default()
        };
        let (mut guest, host) =
            run_session_with(gate_allowing_addr(addr.ip(), addr.port(), None), limits);

        write_frame(
            &mut guest,
            Opcode::OpenTcp,
            1,
            format!("{}:{}", addr.ip(), addr.port()).as_bytes(),
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Opened);

        let (opcode, _, payload) = read_flowmux_frame(&mut guest);
        assert_eq!(opcode, Opcode::Reset);
        assert!(!payload.is_empty());

        drop(guest);
        host.join().unwrap().unwrap();
    }
}
