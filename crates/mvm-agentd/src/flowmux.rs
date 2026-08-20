//! Guest-side FlowMux client for the converged workload networking path.
//!
//! This module implements the in-guest half of the converged workload
//! networking path: one authenticated FlowMux session to the host
//! `GuestService::NetworkFlow` port, shared by SOCKS5/HTTP/DNS loopback
//! adapters. See `specs/notes/316-guest-flowmux-adapter.md` for the full design.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::network_flow::hello::{Handshake, agree};
use mvm_contract::protocol::network_flow::{
    Direction, FrameError, MAX_UDP_DATAGRAM_LEN, Opcode, SessionValidator, UDP_ADDR_PREFIX_LEN,
    decode, encode_into,
};
use mvm_core::net::session::Session;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::flowmux_drive::GuestIngressTarget;

/// How this side names itself in a handshake refusal. Only ever read by a
/// human reading the error.
const GUEST_BUILD: &str = concat!("mvm-agentd ", env!("CARGO_PKG_VERSION"));

/// Initial stream ID for guest-initiated flows. Guest IDs are odd.
const FIRST_GUEST_STREAM_ID: u32 = 1;

/// Guest-side errors from the FlowMux client.
#[derive(Debug, thiserror::Error)]
pub enum FlowMuxError {
    /// The authenticated handshake failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// A frame violated the protocol.
    #[error("frame error: {0}")]
    Frame(String),
    /// The session closed or the host sent `GoAway`.
    #[error("session closed: {0}")]
    SessionClosed(String),
    /// An I/O error occurred on the transport.
    #[error("transport error: {0}")]
    Transport(#[from] io::Error),
    /// The host refused an operation.
    #[error("refused: {0}")]
    Refused(String),
    /// An internal channel was closed unexpectedly.
    #[error("client channel closed")]
    ChannelClosed,
}

/// Ceiling for the initial-connect backoff.
pub const CONNECT_RETRY_MAX_MS: u64 = 250;

/// How long the egress client may spend retrying its initial connect.
///
/// The guest init waits exactly this long for the proxy to bind, so the client
/// must not retry past it.
pub const CONNECT_RETRY_BUDGET: std::time::Duration =
    mvm_core::guest_netd::EGRESS_PROXY_READY_TIMEOUT;

/// Backoff before re-attempting the initial connect, doubling per attempt.
///
/// Starts at 2 ms deliberately. The gap being waited out is a process start,
/// usually a few milliseconds; a coarser first sleep would spend more time
/// waiting than the race it is recovering from.
#[must_use]
pub fn connect_retry_delay(attempt: u32) -> std::time::Duration {
    let scaled = 1u64.saturating_mul(1u64 << attempt.min(16));
    std::time::Duration::from_millis(scaled.min(CONNECT_RETRY_MAX_MS))
}

impl FlowMuxError {
    /// Whether a *first* connect that failed this way is worth retrying.
    ///
    /// A guest routinely reaches its dial before the host endpoint is
    /// listening — the guest boots in tens of milliseconds and the endpoint is
    /// a separate process the host is still starting — so the dial is reset
    /// and the connection is refused by nothing more than timing. That is a
    /// race, and races are waited out.
    ///
    /// Everything else is a decision: a failed handshake, a refusal, or a
    /// protocol violation means the host considered this guest and said no.
    /// Retrying a decision only delays an accurate error and can look like a
    /// guest hammering an endpoint that already rejected it.
    #[must_use]
    pub fn connect_is_retryable(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    fn refused(reason: impl Into<String>) -> Self {
        Self::Refused(reason.into())
    }
}

impl From<FrameError> for FlowMuxError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value.to_string())
    }
}

/// Events delivered to a TCP stream from the session pump.
#[derive(Debug)]
enum StreamEvent {
    /// Payload bytes from the host.
    Data(Vec<u8>),
    /// Host half-closed its write direction.
    HalfClose,
    /// Host aborted the stream.
    Reset(String),
    /// Host granted additional credit.
    WindowUpdate,
}

/// Events delivered to a UDP association from the session pump.
#[derive(Debug)]
enum UdpEvent {
    /// An incoming datagram.
    Recv(SocketAddr, Vec<u8>),
    /// Host closed the association.
    CloseUdp(String),
    /// Host aborted the association.
    Reset(String),
}

/// Per-stream bookkeeping inside the session task.
struct TcpStreamState {
    tx: mpsc::UnboundedSender<StreamEvent>,
    /// True once the host has sent `HalfClose`.
    host_half_closed: bool,
}

/// Per-UDP-association bookkeeping inside the session task.
struct UdpAssociationState {
    tx: mpsc::UnboundedSender<UdpEvent>,
}

struct InboundUdpDatagram {
    peer: SocketAddr,
    payload: Vec<u8>,
}

/// A request from a client handle to the session pump.
#[derive(Debug)]
enum ClientRequest {
    /// Open a TCP flow.
    OpenTcp {
        /// Destination requested by the guest.
        target: String,
        /// Guest-allocated stream ID.
        stream_id: u32,
        /// Channel back to the caller.
        respond: oneshot::Sender<Result<FlowMuxStream, FlowMuxError>>,
    },
    /// Open a UDP association.
    OpenUdp {
        /// Guest-allocated stream ID.
        stream_id: u32,
        /// Channel back to the caller.
        respond: oneshot::Sender<Result<FlowMuxUdpSocket, FlowMuxError>>,
    },
    /// Resolve a DNS name.
    Resolve {
        /// Guest-allocated stream ID.
        stream_id: u32,
        /// Raw DNS query bytes.
        query: Vec<u8>,
        /// Channel back to the caller.
        respond: oneshot::Sender<Result<Vec<u8>, FlowMuxError>>,
    },
    /// Send data on an open TCP stream.
    SendData { stream_id: u32, bytes: Vec<u8> },
    /// Send a `HalfClose` on an open TCP stream.
    HalfClose { stream_id: u32 },
    /// Send a `Reset` on an open TCP stream.
    Reset { stream_id: u32, reason: String },
    /// Send a datagram on an open UDP association.
    UdpSend {
        stream_id: u32,
        destination: SocketAddr,
        payload: Vec<u8>,
    },
    /// Reply from a declared guest-loopback UDP target to an observed peer.
    InboundUdpReply {
        stream_id: u32,
        peer: SocketAddr,
        payload: Vec<u8>,
    },
    /// Close a UDP association from the guest side.
    CloseUdp { stream_id: u32 },
}

/// Snapshot of session health observed by client handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// The FlowMux handshake has not completed. No flow may be opened yet —
    /// publishing `Ready` before the two peers have agreed is what let a
    /// mismatched host look healthy until the first flow failed.
    Connecting,
    /// Handshake complete and flows may be opened.
    Ready,
    /// Reconnecting after a transport failure.
    Reconnecting,
    /// The session will not come back. Carries why: for a handshake refusal
    /// the reason names both builds, and it is the only thing that tells an
    /// operator which of the two halves to rebuild.
    Dead(Arc<str>),
}

/// An open request that is waiting for the host to confirm or refuse.
#[derive(Debug)]
enum PendingOpen {
    /// A TCP open awaiting `Opened` or `Refused`.
    Tcp {
        respond: oneshot::Sender<Result<FlowMuxStream, FlowMuxError>>,
        stream_event_tx: mpsc::UnboundedSender<StreamEvent>,
        stream_event_rx: mpsc::UnboundedReceiver<StreamEvent>,
    },
    /// A UDP open awaiting `UdpOpened` or `Refused`.
    Udp {
        respond: oneshot::Sender<Result<FlowMuxUdpSocket, FlowMuxError>>,
        udp_event_tx: mpsc::UnboundedSender<UdpEvent>,
        udp_event_rx: mpsc::UnboundedReceiver<UdpEvent>,
    },
}

/// A FlowMux client handle.
///
/// Owns the authenticated session (in a background task) and exposes async
/// methods to open TCP/UDP flows and resolve DNS names. Clones of the handle
/// share the same session and reconnect state.
#[derive(Debug, Clone)]
pub struct FlowMuxClient {
    tx: mpsc::UnboundedSender<ClientRequest>,
    state: watch::Receiver<SessionState>,
    next_stream_id: Arc<AtomicU32>,
}

impl FlowMuxClient {
    /// Connect to the host NetworkFlow channel and complete the FlowMux
    /// handshake (`Hello` / `HelloAck`).
    ///
    /// The cryptographic session handshake is performed as the guest using
    /// `guest_signing_key` and the pinned host anchor. After the handshake the
    /// session task takes ownership of `stream` and runs until it closes.
    pub async fn connect<S>(
        stream: S,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with_ingress(stream, guest_signing_key, host_anchor, Vec::new()).await
    }

    /// Connect with the signed plan's guest-loopback ingress targets.
    pub async fn connect_with_ingress<S>(
        stream: S,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
        ingress_targets: Vec<GuestIngressTarget>,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        let handshake = tokio::task::spawn_blocking(move || {
            let mut adapter = AsyncStreamSyncAdapter::new(stream, handle);
            Session::guest(&mut adapter, guest_signing_key, &host_anchor)
                .map_err(|e| FlowMuxError::Handshake(e.to_string()))
                .map(|(session, session_id)| {
                    let stream = adapter.into_inner();
                    (session, session_id, stream)
                })
        })
        .await
        .map_err(|e| FlowMuxError::Handshake(e.to_string()))?;

        let (session, _session_id, stream) = handshake?;

        let (client_tx, client_rx) = mpsc::unbounded_channel();
        let (state_tx, state_rx) = watch::channel(SessionState::Connecting);

        let mut targets = BTreeMap::new();
        for target in ingress_targets {
            if target.mapping_id == 0 || targets.insert(target.mapping_id, target).is_some() {
                return Err(FlowMuxError::Frame(
                    "ingress targets must have unique non-zero mapping ids".to_string(),
                ));
            }
        }

        let next_stream_id = Arc::new(AtomicU32::new(FIRST_GUEST_STREAM_ID));
        let pump = SessionPump {
            stream: Box::pin(stream),
            session,
            validator: SessionValidator::new_with_ingress(targets.iter().map(
                |(&mapping, target)| {
                    let kind = match target.protocol {
                        mvm_contract::plan::IngressProtocol::Tcp => {
                            mvm_contract::protocol::network_flow::IngressFlowKind::Tcp
                        }
                        mvm_contract::plan::IngressProtocol::Udp => {
                            mvm_contract::protocol::network_flow::IngressFlowKind::Udp
                        }
                    };
                    (mapping, kind)
                },
            )),
            client_rx,
            client_tx: client_tx.clone(),
            state_tx,
            ingress_targets: targets,
            tcp_streams: BTreeMap::new(),
            udp_associations: BTreeMap::new(),
            inbound_udp: BTreeMap::new(),
            pending_opens: BTreeMap::new(),
            pending_resolves: BTreeMap::new(),
            frame_reader: FrameReader::default(),
        };

        tokio::spawn(async move {
            if let Err(e) = pump.run().await {
                warn!(error = %e, "FlowMux session pump ended");
            }
        });

        Ok(Self {
            tx: client_tx,
            state: state_rx,
            next_stream_id,
        })
    }

    /// Wait until the session is ready, or fail if it becomes dead.
    async fn await_ready(&self) -> Result<(), FlowMuxError> {
        let mut state = self.state.clone();
        loop {
            let snapshot = state.borrow().clone();
            match snapshot {
                SessionState::Ready => return Ok(()),
                SessionState::Dead(reason) => {
                    return Err(FlowMuxError::SessionClosed(reason.to_string()));
                }
                SessionState::Connecting | SessionState::Reconnecting => {
                    if state.changed().await.is_err() {
                        return Err(FlowMuxError::SessionClosed("state watch closed".into()));
                    }
                }
            }
        }
    }

    /// Allocate a fresh odd guest stream ID.
    fn alloc_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(2, Ordering::Relaxed)
    }

    /// A receiver that tracks the session lifecycle.
    pub fn state(&self) -> watch::Receiver<SessionState> {
        self.state.clone()
    }

    /// Open a TCP flow to `target` (`host:port`).
    ///
    /// This waits for the host to confirm the open with `Opened` before
    /// returning. A refused open surfaces as [`FlowMuxError::Refused`].
    pub async fn open_tcp(&self, target: &str) -> Result<FlowMuxStream, FlowMuxError> {
        self.await_ready().await?;
        let stream_id = self.alloc_stream_id();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ClientRequest::OpenTcp {
                target: target.to_string(),
                stream_id,
                respond: tx,
            })
            .map_err(|_| FlowMuxError::ChannelClosed)?;
        rx.await.map_err(|_| FlowMuxError::ChannelClosed)?
    }

    /// Open a UDP association.
    pub async fn open_udp(&self) -> Result<FlowMuxUdpSocket, FlowMuxError> {
        self.await_ready().await?;
        let stream_id = self.alloc_stream_id();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ClientRequest::OpenUdp {
                stream_id,
                respond: tx,
            })
            .map_err(|_| FlowMuxError::ChannelClosed)?;
        rx.await.map_err(|_| FlowMuxError::ChannelClosed)?
    }

    /// Resolve a DNS name. Returns the raw DNS response bytes.
    pub async fn resolve(&self, name: &str, qtype: u16) -> Result<Vec<u8>, FlowMuxError> {
        self.await_ready().await?;
        let stream_id = self.alloc_stream_id();
        let query = build_dns_query(name, qtype, stream_id as u16)?;
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ClientRequest::Resolve {
                stream_id,
                query,
                respond: tx,
            })
            .map_err(|_| FlowMuxError::ChannelClosed)?;
        rx.await.map_err(|_| FlowMuxError::ChannelClosed)?
    }
}

/// Background task that owns the FlowMux session.
struct SessionPump<S> {
    stream: Pin<Box<S>>,
    session: mvm_core::net::session::Session,
    validator: SessionValidator,
    client_rx: mpsc::UnboundedReceiver<ClientRequest>,
    client_tx: mpsc::UnboundedSender<ClientRequest>,
    state_tx: watch::Sender<SessionState>,
    ingress_targets: BTreeMap<u16, GuestIngressTarget>,
    tcp_streams: BTreeMap<u32, TcpStreamState>,
    udp_associations: BTreeMap<u32, UdpAssociationState>,
    inbound_udp: BTreeMap<u32, mpsc::Sender<InboundUdpDatagram>>,
    pending_opens: BTreeMap<u32, PendingOpen>,
    pending_resolves: BTreeMap<u32, oneshot::Sender<Result<Vec<u8>, FlowMuxError>>>,
    /// Survives a `select!` cancellation so a half-read frame resumes.
    frame_reader: FrameReader,
}

impl<S> SessionPump<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(mut self) -> Result<(), FlowMuxError> {
        let outcome = self.run_until_closed().await;
        self.fail_all("session closed");
        let reason: Arc<str> = match &outcome {
            Ok(()) => Arc::from("session closed"),
            Err(e) => Arc::from(e.to_string().as_str()),
        };
        let _ = self.state_tx.send(SessionState::Dead(reason));
        outcome
    }

    async fn run_until_closed(&mut self) -> Result<(), FlowMuxError> {
        self.send_hello().await?;
        self.read_hello_ack().await?;
        let _ = self.state_tx.send(SessionState::Ready);

        loop {
            tokio::select! {
                biased;
                req = self.client_rx.recv() => {
                    match req {
                        Some(req) => self.handle_request(req).await?,
                        None => {
                            info!("FlowMux client dropped; closing session");
                            break;
                        }
                    }
                }
                frame = self
                    .frame_reader
                    .read(&mut self.stream, &mut self.session) => {
                    match frame? {
                        Some((opcode, stream_id, _payload_len, payload)) => {
                            self.handle_frame(opcode, stream_id, payload).await?;
                        }
                        None => {
                            info!("FlowMux peer closed session");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn fail_all(&mut self, reason: &str) {
        let reason = reason.to_string();
        for (_id, state) in std::mem::take(&mut self.tcp_streams) {
            let _ = state.tx.send(StreamEvent::Reset(reason.clone()));
        }
        for (_id, state) in std::mem::take(&mut self.udp_associations) {
            let _ = state.tx.send(UdpEvent::Reset(reason.clone()));
        }
        for (_id, pending) in std::mem::take(&mut self.pending_opens) {
            complete_pending_open_error(pending, FlowMuxError::SessionClosed(reason.clone()));
        }
        for (_id, respond) in std::mem::take(&mut self.pending_resolves) {
            let _ = respond.send(Err(FlowMuxError::SessionClosed(reason.clone())));
        }
    }

    async fn send_hello(&mut self) -> Result<(), FlowMuxError> {
        let payload = Handshake::local(GUEST_BUILD).encode();
        self.validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::Hello,
                0,
                payload.len() as u32,
            ))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        self.write_frame(Opcode::Hello, 0, &payload).await
    }

    async fn read_hello_ack(&mut self) -> Result<(), FlowMuxError> {
        let (opcode, stream_id, payload_len, payload) =
            self.read_frame().await?.ok_or_else(|| {
                // The host closing here is the shape of a host that is not
                // speaking FlowMux at all, so say so rather than reporting a
                // bare disconnect the operator has to guess at.
                FlowMuxError::SessionClosed(format!(
                    "host closed the connection before answering the FlowMux handshake; \
                     this guest is {GUEST_BUILD} — the host endpoint is either stale or \
                     serving a different egress protocol"
                ))
            })?;
        if opcode != Opcode::HelloAck || stream_id != 0 {
            return Err(FlowMuxError::Frame(format!(
                "expected HelloAck, got {opcode:?} on stream {stream_id}"
            )));
        }
        let host = Handshake::decode(&payload).map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        agree(&Handshake::local(GUEST_BUILD), &host)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        self.validator
            .admit(&frame_facts(
                Direction::HostToGuest,
                Opcode::HelloAck,
                stream_id,
                payload_len,
            ))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        Ok(())
    }

    async fn handle_request(&mut self, req: ClientRequest) -> Result<(), FlowMuxError> {
        match req {
            ClientRequest::OpenTcp {
                target,
                stream_id,
                respond,
            } => {
                self.do_open_tcp(target, stream_id, respond).await;
            }
            ClientRequest::OpenUdp { stream_id, respond } => {
                self.do_open_udp(stream_id, respond).await;
            }
            ClientRequest::Resolve {
                stream_id,
                query,
                respond,
            } => {
                self.do_resolve(stream_id, query, respond).await;
            }
            ClientRequest::SendData { stream_id, bytes } => {
                self.send_data(stream_id, &bytes).await?;
            }
            ClientRequest::HalfClose { stream_id } => {
                self.send_half_close(stream_id).await?;
            }
            ClientRequest::Reset { stream_id, reason } => {
                self.send_reset(stream_id, &reason).await?;
            }
            ClientRequest::UdpSend {
                stream_id,
                destination,
                payload,
            } => {
                self.send_udp(stream_id, destination, &payload).await?;
            }
            ClientRequest::InboundUdpReply {
                stream_id,
                peer,
                payload,
            } => {
                self.send_udp(stream_id, peer, &payload).await?;
            }
            ClientRequest::CloseUdp { stream_id } => {
                self.send_close_udp(stream_id).await?;
            }
        }
        Ok(())
    }

    async fn do_open_tcp(
        &mut self,
        target: String,
        stream_id: u32,
        respond: oneshot::Sender<Result<FlowMuxStream, FlowMuxError>>,
    ) {
        if self
            .validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::OpenTcp,
                stream_id,
                target.len() as u32,
            ))
            .is_err()
        {
            let _ = respond.send(Err(FlowMuxError::SessionClosed("invalid open".into())));
            return;
        }

        let (stream_event_tx, stream_event_rx) = mpsc::unbounded_channel();
        self.pending_opens.insert(
            stream_id,
            PendingOpen::Tcp {
                respond,
                stream_event_tx,
                stream_event_rx,
            },
        );

        if let Err(e) = self
            .write_frame(Opcode::OpenTcp, stream_id, target.as_bytes())
            .await
            && let Some(PendingOpen::Tcp { respond, .. }) = self.pending_opens.remove(&stream_id)
        {
            let _ = respond.send(Err(e));
        }
    }

    async fn do_open_udp(
        &mut self,
        stream_id: u32,
        respond: oneshot::Sender<Result<FlowMuxUdpSocket, FlowMuxError>>,
    ) {
        if self
            .validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::OpenUdp,
                stream_id,
                0,
            ))
            .is_err()
        {
            let _ = respond.send(Err(FlowMuxError::SessionClosed("invalid open".into())));
            return;
        }

        let (udp_event_tx, udp_event_rx) = mpsc::unbounded_channel();
        self.pending_opens.insert(
            stream_id,
            PendingOpen::Udp {
                respond,
                udp_event_tx,
                udp_event_rx,
            },
        );

        if let Err(e) = self.write_frame(Opcode::OpenUdp, stream_id, &[]).await
            && let Some(PendingOpen::Udp { respond, .. }) = self.pending_opens.remove(&stream_id)
        {
            let _ = respond.send(Err(e));
        }
    }

    async fn do_resolve(
        &mut self,
        stream_id: u32,
        query: Vec<u8>,
        respond: oneshot::Sender<Result<Vec<u8>, FlowMuxError>>,
    ) {
        if self
            .validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::Resolve,
                stream_id,
                query.len() as u32,
            ))
            .is_err()
        {
            let _ = respond.send(Err(FlowMuxError::SessionClosed("invalid resolve".into())));
            return;
        }

        self.pending_resolves.insert(stream_id, respond);

        if let Err(e) = self.write_frame(Opcode::Resolve, stream_id, &query).await
            && let Some(respond) = self.pending_resolves.remove(&stream_id)
        {
            let _ = respond.send(Err(e));
        }
    }

    async fn handle_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload: Vec<u8>,
    ) -> Result<(), FlowMuxError> {
        self.validator
            .admit(&inbound_frame_facts(opcode, stream_id, &payload))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;

        match opcode {
            Opcode::InboundOpen => {
                self.handle_inbound_open(stream_id, &payload).await?;
            }
            Opcode::Opened => {
                if let Some(PendingOpen::Tcp {
                    respond,
                    stream_event_tx,
                    stream_event_rx,
                }) = self.pending_opens.remove(&stream_id)
                {
                    let handle = FlowMuxStream {
                        stream_id,
                        tx: self.client_tx.clone(),
                        rx: stream_event_rx,
                        read_buf: Vec::new(),
                    };
                    self.tcp_streams.insert(
                        stream_id,
                        TcpStreamState {
                            tx: stream_event_tx,
                            host_half_closed: false,
                        },
                    );
                    let _ = respond.send(Ok(handle));
                }
            }
            Opcode::UdpOpened => {
                if let Some(PendingOpen::Udp {
                    respond,
                    udp_event_tx,
                    udp_event_rx,
                }) = self.pending_opens.remove(&stream_id)
                {
                    let handle = FlowMuxUdpSocket {
                        stream_id,
                        tx: self.client_tx.clone(),
                        rx: udp_event_rx,
                    };
                    self.udp_associations
                        .insert(stream_id, UdpAssociationState { tx: udp_event_tx });
                    let _ = respond.send(Ok(handle));
                }
            }
            Opcode::Refused => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(pending) = self.pending_opens.remove(&stream_id) {
                    complete_pending_open_error(pending, FlowMuxError::refused(reason));
                } else if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Err(FlowMuxError::refused(reason)));
                }
            }
            Opcode::Resolved => {
                if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Ok(payload));
                }
            }
            Opcode::ResolveRefused => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Err(FlowMuxError::refused(reason)));
                }
            }
            Opcode::Data => {
                let consumed = u32::try_from(payload.len()).unwrap_or(u32::MAX);
                let delivered = match self.tcp_streams.get_mut(&stream_id) {
                    Some(state) => {
                        let _ = state.tx.send(StreamEvent::Data(payload));
                        true
                    }
                    None => false,
                };
                // Return the credit those bytes consumed.
                //
                // The host replenishes the guest's window on every DATA it
                // relays, but nothing replenished the host's — so the host→guest
                // window drained and the host reset the stream the moment it hit
                // zero. That caps every download at one window (~48 KiB here) and
                // surfaces as a truncated archive rather than as a flow-control
                // failure. Only for a stream we still hold: replenishing one we
                // have already retired would name a stream the host has closed.
                if delivered && consumed > 0 {
                    self.send_window_update(stream_id, consumed).await?;
                }
            }
            Opcode::HalfClose => {
                if let Some(state) = self.tcp_streams.get_mut(&stream_id) {
                    state.host_half_closed = true;
                    let _ = state.tx.send(StreamEvent::HalfClose);
                }
            }
            Opcode::Reset => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(state) = self.tcp_streams.remove(&stream_id) {
                    let _ = state.tx.send(StreamEvent::Reset(reason.clone()));
                }
                if let Some(state) = self.udp_associations.remove(&stream_id) {
                    let _ = state.tx.send(UdpEvent::Reset(reason.clone()));
                }
                self.inbound_udp.remove(&stream_id);
                if let Some(pending) = self.pending_opens.remove(&stream_id) {
                    complete_pending_open_error(
                        pending,
                        FlowMuxError::SessionClosed(reason.clone()),
                    );
                }
                if let Some(respond) = self.pending_resolves.remove(&stream_id) {
                    let _ = respond.send(Err(FlowMuxError::SessionClosed(reason)));
                }
            }
            Opcode::UdpRecv => {
                if let Ok((addr, body)) = decode_udp_addr(&payload) {
                    if let Some(sender) = self.inbound_udp.get(&stream_id) {
                        let _ = sender.try_send(InboundUdpDatagram {
                            peer: addr,
                            payload: body.to_vec(),
                        });
                    } else if let Some(state) = self.udp_associations.get_mut(&stream_id) {
                        let _ = state.tx.send(UdpEvent::Recv(addr, body.to_vec()));
                    }
                }
            }
            Opcode::CloseUdp => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(state) = self.udp_associations.remove(&stream_id) {
                    let _ = state.tx.send(UdpEvent::CloseUdp(reason));
                }
                self.inbound_udp.remove(&stream_id);
            }
            Opcode::WindowUpdate => {
                if payload.len() == 4 {
                    let delta =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    if let Some(state) = self.tcp_streams.get_mut(&stream_id) {
                        let _delta = delta;
                        let _ = state.tx.send(StreamEvent::WindowUpdate);
                    }
                }
            }
            Opcode::GoAway => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                return Err(FlowMuxError::SessionClosed(reason));
            }
            _ => {
                warn!(
                    ?opcode,
                    stream_id, "FlowMux client ignoring unexpected frame"
                );
            }
        }
        Ok(())
    }

    async fn handle_inbound_open(
        &mut self,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let Some(mapping_id) = decode_ingress_mapping_id(payload) else {
            return self
                .send_inbound_refused(stream_id, "missing ingress mapping id")
                .await;
        };
        let Some(target) = self.ingress_targets.get(&mapping_id).cloned() else {
            return self
                .send_inbound_refused(stream_id, "undeclared ingress mapping")
                .await;
        };
        match target.protocol {
            mvm_contract::plan::IngressProtocol::Tcp => {
                self.open_inbound_tcp(stream_id, mapping_id, &target).await
            }
            mvm_contract::plan::IngressProtocol::Udp => {
                self.open_inbound_udp(stream_id, mapping_id, &target).await
            }
        }
    }

    async fn open_inbound_tcp(
        &mut self,
        stream_id: u32,
        mapping_id: u16,
        target: &GuestIngressTarget,
    ) -> Result<(), FlowMuxError> {
        let guest_ip = target.guest_addr.parse().map_err(|error| {
            FlowMuxError::Frame(format!("invalid guest ingress target: {error}"))
        })?;
        let address = SocketAddr::new(guest_ip, target.guest_port);
        let local = match tokio::net::TcpStream::connect(address).await {
            Ok(stream) => stream,
            Err(error) => {
                warn!(mapping_id, %address, %error, "guest ingress target refused connection");
                return self
                    .send_inbound_refused(stream_id, "guest loopback target unavailable")
                    .await;
            }
        };

        let (stream_event_tx, stream_event_rx) = mpsc::unbounded_channel();
        self.tcp_streams.insert(
            stream_id,
            TcpStreamState {
                tx: stream_event_tx,
                host_half_closed: false,
            },
        );
        self.send_inbound_ready(stream_id).await?;

        let mut flow = FlowMuxStream {
            stream_id,
            tx: self.client_tx.clone(),
            rx: stream_event_rx,
            read_buf: Vec::new(),
        };
        tokio::spawn(async move {
            let mut local = local;
            if let Err(error) = tokio::io::copy_bidirectional(&mut local, &mut flow).await {
                warn!(stream_id, %error, "guest ingress relay ended");
            }
        });
        Ok(())
    }

    async fn open_inbound_udp(
        &mut self,
        stream_id: u32,
        mapping_id: u16,
        target: &GuestIngressTarget,
    ) -> Result<(), FlowMuxError> {
        let guest_ip = target.guest_addr.parse().map_err(|error| {
            FlowMuxError::Frame(format!("invalid guest UDP ingress target: {error}"))
        })?;
        let target_addr = SocketAddr::new(guest_ip, target.guest_port);
        let bind_addr = SocketAddr::new(guest_ip, 0);
        let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(error) => {
                warn!(mapping_id, %bind_addr, %error, "guest UDP ingress bind failed");
                return self
                    .send_inbound_refused(stream_id, "guest UDP ingress unavailable")
                    .await;
            }
        };
        if let Err(error) = socket.connect(target_addr).await {
            warn!(mapping_id, %target_addr, %error, "guest UDP ingress target connect failed");
            return self
                .send_inbound_refused(stream_id, "guest UDP ingress target unavailable")
                .await;
        }

        let (datagram_tx, mut datagram_rx) = mpsc::channel::<InboundUdpDatagram>(64);
        self.inbound_udp.insert(stream_id, datagram_tx);
        self.send_inbound_ready(stream_id).await?;
        let client_tx = self.client_tx.clone();
        tokio::spawn(async move {
            let mut response = vec![0_u8; MAX_UDP_DATAGRAM_LEN];
            while let Some(datagram) = datagram_rx.recv().await {
                if let Err(error) = socket.send(&datagram.payload).await {
                    warn!(stream_id, %error, "guest UDP ingress delivery failed");
                    break;
                }
                let received =
                    match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut response))
                        .await
                    {
                        Ok(Ok(received)) => received,
                        Ok(Err(error)) => {
                            warn!(stream_id, %error, "guest UDP ingress reply failed");
                            break;
                        }
                        Err(_) => continue,
                    };
                if client_tx
                    .send(ClientRequest::InboundUdpReply {
                        stream_id,
                        peer: datagram.peer,
                        payload: response[..received].to_vec(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(())
    }

    async fn send_inbound_ready(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::InboundReady,
                stream_id,
                0,
            ))
            .map_err(|error| FlowMuxError::Frame(error.to_string()))?;
        self.write_frame(Opcode::InboundReady, stream_id, &[]).await
    }

    async fn send_inbound_refused(
        &mut self,
        stream_id: u32,
        reason: &str,
    ) -> Result<(), FlowMuxError> {
        self.validator
            .admit(&frame_facts(
                Direction::GuestToHost,
                Opcode::InboundRefused,
                stream_id,
                reason.len() as u32,
            ))
            .map_err(|error| FlowMuxError::Frame(error.to_string()))?;
        self.write_frame(Opcode::InboundRefused, stream_id, reason.as_bytes())
            .await
    }

    async fn send_data(&mut self, stream_id: u32, bytes: &[u8]) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::Data, stream_id, bytes).await
    }

    async fn send_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HalfClose, stream_id, &[]).await
    }

    /// Grant the host `delta` more bytes of room on this stream.
    ///
    /// The mirror of the host's replenish. A zero delta is a frame error by
    /// the protocol, so callers only reach here with bytes actually consumed.
    async fn send_window_update(&mut self, stream_id: u32, delta: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::WindowUpdate, stream_id, &delta.to_be_bytes())
            .await?;
        // Advance our own view of the host's allowance to match what we just
        // told it. The validator only learns of credit it admits, so a grant
        // that goes out on the wire without this leaves the local window
        // shrinking while the host's grows — and the guest then refuses the
        // host's data as over-credit, on a window it granted itself.
        // The host keeps its own view in step the same way, via `mark_sent`.
        let _ = self.validator.admit(
            &mvm_contract::protocol::network_flow::FrameFacts::new(
                Direction::GuestToHost,
                Opcode::WindowUpdate,
                stream_id,
            )
            .with_payload(4)
            .with_credit(delta),
        );
        Ok(())
    }

    async fn send_reset(&mut self, stream_id: u32, reason: &str) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::Reset, stream_id, reason.as_bytes())
            .await
    }

    async fn send_udp(
        &mut self,
        stream_id: u32,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let mut wire = encode_udp_addr(destination.ip(), destination.port());
        wire.extend_from_slice(payload);
        self.write_frame(Opcode::UdpSend, stream_id, &wire).await
    }

    async fn send_close_udp(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::CloseUdp, stream_id, &[]).await
    }

    async fn write_frame(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        let mut frame = Vec::new();
        encode_into(&mut frame, opcode, stream_id, payload)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        let sealed = self
            .session
            .seal(&frame)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        let mut sealed_bytes = Vec::new();
        sealed
            .encode(&mut sealed_bytes)
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        let len = u32::try_from(sealed_bytes.len())
            .map_err(|_| FlowMuxError::Frame("sealed frame too large".into()))?;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&sealed_bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Option<(Opcode, u32, u32, Vec<u8>)>, FlowMuxError> {
        read_sealed_frame_from(&mut self.stream, &mut self.session).await
    }
}

/// Largest sealed frame the guest will accept off the wire.
const MAX_SEALED_LEN: usize = 1 << 20;

/// One decoded frame: opcode, stream id, payload length, payload bytes.
pub(crate) type DecodedFrame = (Opcode, u32, u32, Vec<u8>);

/// The outcome of reading one frame. `Ok(None)` is a clean close on a frame
/// boundary, never a truncated frame.
pub(crate) type FrameRead = Result<Option<DecodedFrame>, FlowMuxError>;

/// A resumable read of one sealed frame.
///
/// The pump reads inside `tokio::select!`, which drops the losing branch's
/// future. A read that keeps its partial buffer in locals loses whatever it had
/// already taken off the socket, and the next read then takes body bytes for a
/// length prefix — the stream desyncs and every later frame is garbage. Holding
/// the partial state here instead means a cancelled read *resumes* rather than
/// restarts.
///
/// It only bites under load, because it needs a client request to be ready
/// while a frame is still arriving. A quiet session reads whole frames between
/// requests and looks perfectly correct.
#[derive(Default)]
pub(crate) struct FrameReader {
    /// The 4-byte length prefix, filled incrementally.
    len_buf: [u8; 4],
    /// How much of `len_buf` is populated.
    len_filled: usize,
    /// The body buffer, allocated once the prefix is known.
    body: Option<Vec<u8>>,
    /// How much of `body` is populated.
    body_filled: usize,
}

impl FrameReader {
    /// Read the next frame, resuming any partially-read one.
    ///
    /// Cancel-safe: every `.await` sits between reads, and the byte counts are
    /// updated before the next one, so dropping the future loses nothing.
    pub(crate) async fn read<S>(
        &mut self,
        stream: &mut S,
        session: &mut mvm_core::net::session::Session,
    ) -> FrameRead
    where
        S: AsyncRead + Unpin,
    {
        while self.len_filled < self.len_buf.len() {
            let n = stream.read(&mut self.len_buf[self.len_filled..]).await?;
            if n == 0 {
                // Clean close only on a frame boundary; mid-prefix EOF is a
                // truncated frame and must not read as "peer went away".
                return if self.len_filled == 0 {
                    Ok(None)
                } else {
                    Err(FlowMuxError::Frame(
                        "peer closed mid length prefix".to_string(),
                    ))
                };
            }
            self.len_filled += n;
        }

        if self.body.is_none() {
            let sealed_len = u32::from_be_bytes(self.len_buf) as usize;
            if sealed_len == 0 {
                self.reset();
                return Ok(None);
            }
            if sealed_len > MAX_SEALED_LEN {
                return Err(FlowMuxError::Frame(format!(
                    "sealed frame length {sealed_len} exceeds {MAX_SEALED_LEN}"
                )));
            }
            self.body = Some(vec![0u8; sealed_len]);
        }
        let body = self.body.as_mut().expect("body allocated above");
        while self.body_filled < body.len() {
            let n = stream.read(&mut body[self.body_filled..]).await?;
            if n == 0 {
                return Err(FlowMuxError::Frame("peer closed mid frame".to_string()));
            }
            self.body_filled += n;
        }

        let sealed_buf = self.body.take().expect("body allocated above");
        self.reset();
        decode_sealed(&sealed_buf, session)
    }

    /// Drop the partial state so the next call starts a fresh frame.
    fn reset(&mut self) {
        self.len_filled = 0;
        self.body = None;
        self.body_filled = 0;
    }
}

/// Read exactly one sealed frame, start to finish.
///
/// For callers that await the read directly. A caller that races this against
/// another future in `select!` must use [`FrameReader`] instead — see its docs
/// for what a dropped read costs.
pub(crate) async fn read_sealed_frame_from<S>(
    stream: &mut S,
    session: &mut mvm_core::net::session::Session,
) -> FrameRead
where
    S: AsyncRead + Unpin,
{
    FrameReader::default().read(stream, session).await
}

/// Open and decode one sealed frame's bytes.
fn decode_sealed(sealed_buf: &[u8], session: &mut mvm_core::net::session::Session) -> FrameRead {
    let sealed = mvm_core::net::session::SealedFrame::decode(sealed_buf)
        .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
    let plaintext = session
        .open(&sealed)
        .map_err(|e| FlowMuxError::Frame(e.to_string()))?;

    let parsed = decode(&plaintext)?;
    Ok(Some((
        parsed.header.opcode,
        parsed.header.stream_id,
        parsed.header.payload_len,
        parsed.payload.to_vec(),
    )))
}

fn complete_pending_open_error(pending: PendingOpen, error: FlowMuxError) {
    match pending {
        PendingOpen::Tcp { respond, .. } => {
            let _ = respond.send(Err(error));
        }
        PendingOpen::Udp { respond, .. } => {
            let _ = respond.send(Err(error));
        }
    }
}

/// An async TCP-like stream over a FlowMux session.
#[derive(Debug)]
pub struct FlowMuxStream {
    stream_id: u32,
    tx: mpsc::UnboundedSender<ClientRequest>,
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    read_buf: Vec<u8>,
}

impl FlowMuxStream {
    /// The FlowMux stream ID.
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

impl AsyncRead for FlowMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(bytes))) => {
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..n]);
                if bytes.len() > n {
                    self.read_buf.extend_from_slice(&bytes[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::HalfClose)) => Poll::Ready(Ok(())),
            Poll::Ready(Some(StreamEvent::Reset(reason))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, reason)))
            }
            Poll::Ready(Some(StreamEvent::WindowUpdate)) => {
                // Credit grants are consumed internally; ignore for read.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for FlowMuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let bytes = buf.to_vec();
        let len = bytes.len();
        match self.tx.send(ClientRequest::SendData {
            stream_id: self.stream_id,
            bytes,
        }) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "FlowMux session closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.tx.send(ClientRequest::HalfClose {
            stream_id: self.stream_id,
        });
        Poll::Ready(Ok(()))
    }
}

impl Drop for FlowMuxStream {
    fn drop(&mut self) {
        let _ = self.tx.send(ClientRequest::Reset {
            stream_id: self.stream_id,
            reason: "stream dropped".into(),
        });
    }
}

/// An async UDP-like socket over a FlowMux session.
#[derive(Debug)]
pub struct FlowMuxUdpSocket {
    stream_id: u32,
    tx: mpsc::UnboundedSender<ClientRequest>,
    rx: mpsc::UnboundedReceiver<UdpEvent>,
}

impl FlowMuxUdpSocket {
    /// Send a datagram to `destination`.
    pub async fn send_to(
        &self,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), FlowMuxError> {
        self.tx
            .send(ClientRequest::UdpSend {
                stream_id: self.stream_id,
                destination,
                payload: payload.to_vec(),
            })
            .map_err(|_| FlowMuxError::ChannelClosed)
    }

    /// Receive a datagram and its source address.
    pub async fn recv_from(&mut self) -> Result<(SocketAddr, Vec<u8>), FlowMuxError> {
        match self.rx.recv().await {
            Some(UdpEvent::Recv(addr, body)) => Ok((addr, body)),
            Some(UdpEvent::CloseUdp(reason)) | Some(UdpEvent::Reset(reason)) => {
                Err(FlowMuxError::SessionClosed(reason))
            }
            None => Err(FlowMuxError::ChannelClosed),
        }
    }
}

impl Drop for FlowMuxUdpSocket {
    fn drop(&mut self) {
        let _ = self.tx.send(ClientRequest::CloseUdp {
            stream_id: self.stream_id,
        });
    }
}

/// Bridge an async stream into a synchronous `Read`/`Write` stream so the
/// synchronous `Session::guest` handshake can run on it from `spawn_blocking`.
pub(crate) struct AsyncStreamSyncAdapter<S> {
    stream: S,
    handle: tokio::runtime::Handle,
}

impl<S> AsyncStreamSyncAdapter<S> {
    pub(crate) fn new(stream: S, handle: tokio::runtime::Handle) -> Self {
        Self { stream, handle }
    }

    pub(crate) fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Read for AsyncStreamSyncAdapter<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.block_on(self.stream.read(buf))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Write for AsyncStreamSyncAdapter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle.block_on(self.stream.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.block_on(self.stream.flush())
    }
}

fn frame_facts(
    direction: Direction,
    opcode: Opcode,
    stream_id: u32,
    payload_len: u32,
) -> mvm_contract::protocol::network_flow::FrameFacts {
    mvm_contract::protocol::network_flow::FrameFacts::new(direction, opcode, stream_id)
        .with_payload(payload_len)
}

/// Facts for a frame arriving from the host.
///
/// A `WindowUpdate`'s payload *is* its credit, and the validator rejects an
/// update that carries none. Describing one by length alone therefore fails
/// every single window update — reported as the host sending a credit-less
/// frame, when the host sent a perfectly good one and the guest simply never
/// looked at it. The session dies on the first replenish, which is the first
/// byte of real traffic.
fn inbound_frame_facts(
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) -> mvm_contract::protocol::network_flow::FrameFacts {
    let facts = frame_facts(
        Direction::HostToGuest,
        opcode,
        stream_id,
        payload.len() as u32,
    );
    match (opcode, payload) {
        (Opcode::InboundOpen, payload) => decode_ingress_mapping_id(payload)
            .map_or(facts, |mapping| facts.with_ingress_mapping(mapping)),
        (Opcode::WindowUpdate, [a, b, c, d]) => {
            facts.with_credit(u32::from_be_bytes([*a, *b, *c, *d]))
        }
        // A malformed update keeps no credit, so the validator still refuses
        // it — the decode is a faithful read, not a way to wave frames through.
        _ => facts,
    }
}

fn decode_ingress_mapping_id(payload: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = payload.get(..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Encode one DNS A or AAAA question for a FlowMux `Resolve` frame.
pub fn build_dns_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, FlowMuxError> {
    let mut query = Vec::with_capacity(64);

    // Header: ID, flags (standard recursive query), QDCOUNT=1, others 0.
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());
    query.extend_from_slice(&0_u16.to_be_bytes());

    let normalized = name.trim_end_matches('.');
    if normalized.is_empty() || normalized.len() > 253 {
        return Err(FlowMuxError::Frame("invalid DNS name".into()));
    }
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(FlowMuxError::Frame("invalid DNS label".into()));
        }
        query.push(
            u8::try_from(label.len()).map_err(|_| FlowMuxError::Frame("label too long".into()))?,
        );
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);

    let qtype_value = match qtype {
        1 => 1u16,
        28 => 28u16,
        _ => return Err(FlowMuxError::Frame(format!("unsupported qtype {qtype}"))),
    };
    query.extend_from_slice(&qtype_value.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN

    Ok(query)
}

/// Encode the destination prefix carried by a FlowMux UDP frame.
pub fn encode_udp_addr(ip: std::net::IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDP_ADDR_PREFIX_LEN);
    match ip {
        std::net::IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&[0; 10]);
            out.extend_from_slice(&[0xff, 0xff]);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Decode the source prefix and datagram body carried by a FlowMux UDP frame.
pub fn decode_udp_addr(bytes: &[u8]) -> Result<(SocketAddr, &[u8]), FlowMuxError> {
    if bytes.len() < UDP_ADDR_PREFIX_LEN {
        return Err(FlowMuxError::Frame(format!(
            "short UDP address: {} < {UDP_ADDR_PREFIX_LEN}",
            bytes.len()
        )));
    }
    let address: [u8; 16] = bytes[1..17]
        .try_into()
        .map_err(|_| FlowMuxError::Frame("truncated UDP address slot".into()))?;
    let ip =
        match bytes[0] {
            0x01 => {
                let v6 = std::net::Ipv6Addr::from(address);
                std::net::IpAddr::V4(v6.to_ipv4_mapped().ok_or_else(|| {
                    FlowMuxError::Frame("IPv4-mapped UDP address expected".into())
                })?)
            }
            0x04 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(address)),
            tag => {
                return Err(FlowMuxError::Frame(format!(
                    "unknown UDP address tag {tag}"
                )));
            }
        };
    let port = u16::from_be_bytes([bytes[17], bytes[18]]);
    let addr = SocketAddr::new(ip, port);
    Ok((addr, &bytes[UDP_ADDR_PREFIX_LEN..]))
}

/// Default timeout for an individual call that waits through reconnect.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Reconnect policy: bounded exponential backoff with a small absolute cap.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Initial delay before the first reconnect attempt.
    pub initial_delay: Duration,
    /// Maximum delay between attempts.
    pub max_delay: Duration,
    /// Maximum number of reconnect attempts before giving up.
    pub max_attempts: u32,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(16),
            max_attempts: 10,
        }
    }
}

/// A reconnecting FlowMux client.
///
/// Wraps one active [`FlowMuxClient`] session and transparently re-creates it
/// on transport failure. Live handles from a lost session fail promptly; new
/// requests block until a fresh session is established or reconnect is
/// exhausted. No request body, datagram, or `Open` frame is replayed across
/// sessions.
#[derive(Debug, Clone)]
pub struct FlowMuxReconnectClient {
    current: watch::Receiver<Option<Arc<FlowMuxClient>>>,
}

impl FlowMuxReconnectClient {
    /// Connect to the host and start the reconnect owner.
    ///
    /// `connector` is called to obtain a new transport each time the current
    /// session dies. The initial connection uses `connector()`; subsequent
    /// attempts use the same factory under bounded exponential backoff.
    pub async fn connect<S, F, Fut>(
        connector: F,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<S, FlowMuxError>> + Send,
    {
        Self::connect_with_ingress(connector, guest_signing_key, host_anchor, Vec::new()).await
    }

    /// Connect and retain the signed ingress target set across reconnects.
    pub async fn connect_with_ingress<S, F, Fut>(
        connector: F,
        guest_signing_key: SigningKey,
        host_anchor: VerifyingKey,
        ingress_targets: Vec<GuestIngressTarget>,
    ) -> Result<Self, FlowMuxError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<S, FlowMuxError>> + Send,
    {
        let ingress_targets = Arc::new(ingress_targets);
        let initial = connector().await?;
        let client = Arc::new(
            FlowMuxClient::connect_with_ingress(
                initial,
                guest_signing_key.clone(),
                host_anchor,
                ingress_targets.as_ref().clone(),
            )
            .await?,
        );
        let (current_tx, current_rx) = watch::channel(Some(Arc::clone(&client)));

        tokio::spawn(async move {
            let mut state_rx = client.state();
            reconnect_loop(
                connector,
                guest_signing_key,
                host_anchor,
                ingress_targets,
                current_tx,
                &mut state_rx,
                ReconnectPolicy::default(),
            )
            .await;
        });

        Ok(Self {
            current: current_rx,
        })
    }

    /// Wait until there is a ready session and return a clone of it.
    ///
    /// Two watches move independently here: `current` names which client the
    /// reconnect loop owns, and the client's own state says whether that one
    /// has finished its handshake. Waiting on only the first parks forever on
    /// a client that is still connecting, since nothing replaces it.
    async fn active_client(&self) -> Result<Arc<FlowMuxClient>, FlowMuxError> {
        let mut current = self.current.clone();
        loop {
            let snapshot = current.borrow().clone();
            let Some(client) = snapshot else {
                if current.changed().await.is_err() {
                    return Err(FlowMuxError::SessionClosed("reconnect owner gone".into()));
                }
                continue;
            };

            let mut state = client.state();
            let settled = loop {
                match state.borrow().clone() {
                    SessionState::Ready => break Some(client),
                    // Dead is the reconnect loop's cue; wait for the client it
                    // puts in place rather than re-reading this one.
                    SessionState::Dead(_) => break None,
                    SessionState::Connecting | SessionState::Reconnecting => {}
                }
                tokio::select! {
                    changed = state.changed() => {
                        if changed.is_err() {
                            break None;
                        }
                    }
                    changed = current.changed() => {
                        if changed.is_err() {
                            return Err(FlowMuxError::SessionClosed("reconnect owner gone".into()));
                        }
                        break None;
                    }
                }
            };
            if let Some(client) = settled {
                return Ok(client);
            }
            if current.has_changed().unwrap_or(false) {
                continue;
            }
            if current.changed().await.is_err() {
                return Err(FlowMuxError::SessionClosed("reconnect owner gone".into()));
            }
        }
    }

    /// Open a TCP flow to `target` (`host:port`).
    pub async fn open_tcp(&self, target: &str) -> Result<FlowMuxStream, FlowMuxError> {
        let client = tokio::time::timeout(CALL_TIMEOUT, self.active_client())
            .await
            .map_err(|_| FlowMuxError::SessionClosed("reconnect timed out".into()))??;
        client.open_tcp(target).await
    }

    /// Open a UDP association.
    pub async fn open_udp(&self) -> Result<FlowMuxUdpSocket, FlowMuxError> {
        let client = tokio::time::timeout(CALL_TIMEOUT, self.active_client())
            .await
            .map_err(|_| FlowMuxError::SessionClosed("reconnect timed out".into()))??;
        client.open_udp().await
    }

    /// Resolve a DNS name. Returns the raw DNS response bytes.
    pub async fn resolve(&self, name: &str, qtype: u16) -> Result<Vec<u8>, FlowMuxError> {
        let client = tokio::time::timeout(CALL_TIMEOUT, self.active_client())
            .await
            .map_err(|_| FlowMuxError::SessionClosed("reconnect timed out".into()))??;
        client.resolve(name, qtype).await
    }

    /// Build a reconnect client from an existing watch receiver.
    ///
    /// Test-only: lets in-crate tests stand up a client that is already
    /// connected to a mock host without going through the reconnect factory.
    #[cfg(test)]
    pub(crate) fn from_receiver(current: watch::Receiver<Option<Arc<FlowMuxClient>>>) -> Self {
        Self { current }
    }
}

async fn reconnect_loop<S, F, Fut>(
    connector: F,
    guest_signing_key: SigningKey,
    host_anchor: VerifyingKey,
    ingress_targets: Arc<Vec<GuestIngressTarget>>,
    current_tx: watch::Sender<Option<Arc<FlowMuxClient>>>,
    state_rx: &mut watch::Receiver<SessionState>,
    policy: ReconnectPolicy,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn() -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<S, FlowMuxError>> + Send,
{
    let mut delay = policy.initial_delay;
    let mut attempts = 0_u32;

    loop {
        // Wait for the current session to die.
        loop {
            if matches!(*state_rx.borrow(), SessionState::Dead(_)) {
                break;
            }
            if state_rx.changed().await.is_err() {
                // The session task dropped its state sender. That is the
                // strongest evidence the session is gone, not a signal to stop
                // watching — a session can end without ever publishing `Dead`.
                // Returning here drops `current_tx`, so every waiter fails with
                // "reconnect owner gone" and the guest never gets a second
                // session, which is indistinguishable from having no network.
                break;
            }
        }

        attempts += 1;
        if attempts > policy.max_attempts {
            warn!("FlowMux reconnect exhausted; entering dead state");
            let _ = current_tx.send(None);
            return;
        }

        let jitter = Duration::from_millis(u64::from(rand::random::<u16>()) % 100);
        tokio::time::sleep(delay + jitter).await;
        delay = (delay * 2).min(policy.max_delay);

        match connector().await {
            Ok(stream) => {
                match FlowMuxClient::connect_with_ingress(
                    stream,
                    guest_signing_key.clone(),
                    host_anchor,
                    ingress_targets.as_ref().clone(),
                )
                .await
                {
                    Ok(client) => {
                        let new_client = Arc::new(client);
                        let state = new_client.state();
                        if current_tx.send(Some(new_client)).is_err() {
                            return;
                        }
                        *state_rx = state;
                        attempts = 0;
                        delay = policy.initial_delay;
                    }
                    Err(e) => {
                        warn!(error = %e, "FlowMux reconnect handshake failed");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "FlowMux reconnect transport failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::network_flow::hello::BEHAVIOR_REVISION;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn udp_addr_roundtrips_ipv4_and_ipv6() {
        let v4 = SocketAddr::new(std::net::IpAddr::from([127, 0, 0, 1]), 1234);
        let encoded = encode_udp_addr(v4.ip(), v4.port());
        assert_eq!(encoded.len(), UDP_ADDR_PREFIX_LEN);
        assert_eq!(
            &encoded[..13],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        );
        let (decoded, rest) = decode_udp_addr(&encoded).unwrap();
        assert_eq!(decoded, v4);
        assert!(rest.is_empty());

        let v6 = SocketAddr::new(std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST), 5678);
        let encoded = encode_udp_addr(v6.ip(), v6.port());
        let (decoded, rest) = decode_udp_addr(&encoded).unwrap();
        assert_eq!(decoded, v6);
        assert!(rest.is_empty());
    }

    #[test]
    fn udp_addr_refuses_a_short_or_non_mapped_ipv4_slot() {
        assert!(decode_udp_addr(&[0x01, 127, 0, 0, 1, 0, 53]).is_err());
        let mut non_mapped = vec![0x01];
        non_mapped.extend_from_slice(&[0; 16]);
        non_mapped.extend_from_slice(&53_u16.to_be_bytes());
        assert!(decode_udp_addr(&non_mapped).is_err());
    }

    #[test]
    fn dns_query_encodes_a_and_aaaa() {
        let a = build_dns_query("example.com", 1, 0x1234).unwrap();
        assert_eq!(&a[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([a[2], a[3]]), 0x0100);
        assert_eq!(u16::from_be_bytes([a[4], a[5]]), 1);
        assert!(a.len() > 12);

        let aaaa = build_dns_query("example.com", 28, 0xabcd).unwrap();
        assert_eq!(&aaaa[0..2], &[0xab, 0xcd]);
    }

    fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let bytes: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    async fn host_handshake<S>(
        stream: S,
        host_key: SigningKey,
    ) -> (S, mvm_core::net::session::Session)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handle = tokio::runtime::Handle::try_current().unwrap();
        tokio::task::spawn_blocking(move || {
            let mut adapter = AsyncStreamSyncAdapter::new(stream, handle);
            let result =
                mvm_core::net::session::Session::host(&mut adapter, "test-session", host_key);
            let stream = adapter.into_inner();
            result.map(|(session, _peer)| (stream, session))
        })
        .await
        .unwrap()
        .unwrap()
    }

    async fn send_frame<S>(
        stream: &mut S,
        session: &mut mvm_core::net::session::Session,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) where
        S: AsyncWrite + Unpin,
    {
        let mut wire = Vec::new();
        encode_into(&mut wire, opcode, stream_id, payload).unwrap();
        let sealed = session.seal(&wire).unwrap();
        let mut sealed_bytes = Vec::new();
        sealed.encode(&mut sealed_bytes).unwrap();
        let len = u32::try_from(sealed_bytes.len()).unwrap();
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        stream.write_all(&sealed_bytes).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Seal a frame and hand back its exact wire bytes, so a test can deliver
    /// it in pieces.
    fn frame_bytes(
        session: &mut mvm_core::net::session::Session,
        opcode: Opcode,
        stream_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut wire = Vec::new();
        encode_into(&mut wire, opcode, stream_id, payload).unwrap();
        let sealed = session.seal(&wire).unwrap();
        let mut sealed_bytes = Vec::new();
        sealed.encode(&mut sealed_bytes).unwrap();
        let len = u32::try_from(sealed_bytes.len()).unwrap();
        let mut out = len.to_be_bytes().to_vec();
        out.extend_from_slice(&sealed_bytes);
        out
    }

    /// A handshaken guest/host session pair over a duplex.
    async fn session_pair() -> (
        tokio::io::DuplexStream,
        mvm_core::net::session::Session,
        tokio::io::DuplexStream,
        mvm_core::net::session::Session,
    ) {
        let (host_key, host_anchor) = generate_keypair();
        let (guest_key, _) = generate_keypair();
        let (guest_stream, host_stream) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(host_handshake(host_stream, host_key));
        let handle = tokio::runtime::Handle::try_current().unwrap();
        let (guest_stream, guest_session) = tokio::task::spawn_blocking(move || {
            let mut adapter = AsyncStreamSyncAdapter::new(guest_stream, handle);
            let result =
                mvm_core::net::session::Session::guest(&mut adapter, guest_key, &host_anchor);
            let stream = adapter.into_inner();
            result.map(|(session, _id)| (stream, session))
        })
        .await
        .unwrap()
        .unwrap();
        let (host_stream, host_session) = host.await.unwrap();
        (guest_stream, guest_session, host_stream, host_session)
    }

    /// The pump reads inside `select!`, so a read that loses the race is
    /// dropped part-way through a frame. It has to resume, not restart:
    /// restarting re-reads body bytes as a length prefix and every later frame
    /// on the session is garbage.
    ///
    /// Confirmed red before the `FrameReader` change, with the same
    /// `sealed frame length ... exceeds 1048576` a builder VM produced once a
    /// download was large enough to keep a request ready mid-frame.
    #[tokio::test]
    async fn a_cancelled_read_resumes_the_frame_it_was_part_way_through() {
        let (mut guest_stream, mut guest_session, mut host_stream, mut host_session) =
            session_pair().await;
        let wire = frame_bytes(&mut host_session, Opcode::Data, 1, b"payload-after-cancel");
        let mut reader = FrameReader::default();

        // Deliver a partial length prefix and let the read be cancelled on it.
        host_stream.write_all(&wire[..2]).await.unwrap();
        host_stream.flush().await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                reader.read(&mut guest_stream, &mut guest_session),
            )
            .await
            .is_err(),
            "the read must still be pending, so the timeout cancels it"
        );

        // Deliver the rest of the prefix plus part of the body, cancel again.
        let mid = wire.len() - 4;
        host_stream.write_all(&wire[2..mid]).await.unwrap();
        host_stream.flush().await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                reader.read(&mut guest_stream, &mut guest_session),
            )
            .await
            .is_err(),
            "a body-truncated read must also stay pending"
        );

        // The remainder completes the frame the two cancellations were inside.
        host_stream.write_all(&wire[mid..]).await.unwrap();
        host_stream.flush().await.unwrap();
        let (opcode, stream_id, _len, payload) = reader
            .read(&mut guest_stream, &mut guest_session)
            .await
            .expect("the resumed read must succeed")
            .expect("a frame, not a clean close");
        assert_eq!(opcode, Opcode::Data);
        assert_eq!(stream_id, 1);
        assert_eq!(payload, b"payload-after-cancel");
    }

    /// Cancellation must not cost frame *ordering* either: a session that was
    /// interrupted keeps decrypting subsequent frames, which it cannot do if
    /// the byte stream slipped by even one.
    #[tokio::test]
    async fn frames_after_a_cancelled_read_still_decrypt_in_order() {
        let (mut guest_stream, mut guest_session, mut host_stream, mut host_session) =
            session_pair().await;
        let first = frame_bytes(&mut host_session, Opcode::Data, 1, b"first");
        let second = frame_bytes(&mut host_session, Opcode::Data, 1, b"second");
        let mut reader = FrameReader::default();

        host_stream.write_all(&first[..3]).await.unwrap();
        host_stream.flush().await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                reader.read(&mut guest_stream, &mut guest_session),
            )
            .await
            .is_err()
        );

        host_stream.write_all(&first[3..]).await.unwrap();
        host_stream.write_all(&second).await.unwrap();
        host_stream.flush().await.unwrap();

        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let (_, _, _, payload) = reader
                .read(&mut guest_stream, &mut guest_session)
                .await
                .expect("decrypts in order")
                .expect("a frame");
            assert_eq!(payload, expected);
        }
    }

    async fn recv_frame<S>(
        stream: &mut S,
        session: &mut mvm_core::net::session::Session,
    ) -> Option<(Opcode, u32, u32, Vec<u8>)>
    where
        S: AsyncRead + Unpin,
    {
        read_sealed_frame_from(stream, session).await.unwrap()
    }

    #[tokio::test]
    async fn guest_client_handshakes_and_exchanges_tcp_data() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;

            let (opcode, _sid, _len, payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            Handshake::decode(&payload).expect("Hello carries the guest's handshake");

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            let (opcode, sid, _len, payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::OpenTcp);
            assert_eq!(sid, 1);
            assert_eq!(payload, b"example.com:80");

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::Opened,
                sid,
                &[],
            )
            .await;

            let (opcode, data_sid, _len, payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Data);
            assert_eq!(data_sid, sid);
            assert_eq!(payload, b"ping");

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::Data,
                sid,
                b"pong",
            )
            .await;

            // The guest returns the credit it just consumed before anything
            // else. A real host depends on this — without it the host's window
            // drains and it resets the stream — so the double asserts it
            // rather than tolerating it.
            let (opcode, wu_sid, _len, payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::WindowUpdate);
            assert_eq!(wu_sid, sid);
            assert_eq!(
                payload,
                (b"pong".len() as u32).to_be_bytes(),
                "the grant must be exactly the bytes delivered"
            );

            let (opcode, hc_sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::HalfClose);
            assert_eq!(hc_sid, sid);

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HalfClose,
                sid,
                &[],
            )
            .await;
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("guest handshake");
        let mut stream = client.open_tcp("example.com:80").await.unwrap();

        let written = stream.write(b"ping").await.unwrap();
        assert_eq!(written, 4);

        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");

        stream.shutdown().await.unwrap();

        host.await.unwrap();
    }

    #[tokio::test]
    async fn guest_client_relays_declared_inbound_tcp_to_loopback() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let guest_port = listener.local_addr().unwrap().port();
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;
            let (opcode, _, _, _) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::InboundOpen,
                2,
                &17_u16.to_be_bytes(),
            )
            .await;
            let (opcode, stream_id, _, _) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!((opcode, stream_id), (Opcode::InboundReady, 2));

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::Data,
                2,
                b"from-host",
            )
            .await;
            loop {
                let (opcode, stream_id, _, payload) =
                    recv_frame(&mut host_stream, &mut host_session)
                        .await
                        .unwrap();
                if opcode == Opcode::Data {
                    assert_eq!(stream_id, 2);
                    assert_eq!(payload, b"from-guest");
                    break;
                }
                assert_eq!(opcode, Opcode::WindowUpdate);
            }
        });

        let _client = FlowMuxClient::connect_with_ingress(
            guest_stream,
            guest_key,
            host_anchor,
            vec![GuestIngressTarget {
                mapping_id: 17,
                protocol: mvm_contract::plan::IngressProtocol::Tcp,
                guest_addr: std::net::Ipv4Addr::LOCALHOST.to_string(),
                guest_port,
            }],
        )
        .await
        .expect("guest handshake");

        let (mut loopback, _) = listener.accept().await.unwrap();
        let mut payload = [0_u8; 9];
        loopback.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"from-host");
        loopback.write_all(b"from-guest").await.unwrap();
        host.await.unwrap();
    }

    #[tokio::test]
    async fn guest_client_refuses_inbound_tcp_when_loopback_target_is_unavailable() {
        let guest_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;
            let (opcode, _, _, _) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::InboundOpen,
                2,
                &23_u16.to_be_bytes(),
            )
            .await;
            let (opcode, stream_id, _, reason) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!((opcode, stream_id), (Opcode::InboundRefused, 2));
            assert!(!reason.is_empty());
        });

        let _client = FlowMuxClient::connect_with_ingress(
            guest_stream,
            guest_key,
            host_anchor,
            vec![GuestIngressTarget {
                mapping_id: 23,
                protocol: mvm_contract::plan::IngressProtocol::Tcp,
                guest_addr: std::net::Ipv4Addr::LOCALHOST.to_string(),
                guest_port,
            }],
        )
        .await
        .expect("guest handshake");
        host.await.unwrap();
    }

    #[tokio::test]
    async fn guest_client_relays_declared_inbound_udp_to_loopback() {
        let service = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let guest_port = service.local_addr().unwrap().port();
        let external_peer = SocketAddr::new(std::net::Ipv4Addr::new(192, 0, 2, 44).into(), 4040);
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;
            let (opcode, _, _, _) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::InboundOpen,
                2,
                &31_u16.to_be_bytes(),
            )
            .await;
            let (opcode, stream_id, _, _) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!((opcode, stream_id), (Opcode::InboundReady, 2));

            let mut datagram = encode_udp_addr(external_peer.ip(), external_peer.port());
            datagram.extend_from_slice(b"udp-request");
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::UdpRecv,
                2,
                &datagram,
            )
            .await;
            let (opcode, stream_id, _, payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!((opcode, stream_id), (Opcode::UdpSend, 2));
            let (peer, body) = decode_udp_addr(&payload).unwrap();
            assert_eq!(peer, external_peer);
            assert_eq!(body, b"udp-response");
        });

        let _client = FlowMuxClient::connect_with_ingress(
            guest_stream,
            guest_key,
            host_anchor,
            vec![GuestIngressTarget {
                mapping_id: 31,
                protocol: mvm_contract::plan::IngressProtocol::Udp,
                guest_addr: std::net::Ipv4Addr::LOCALHOST.to_string(),
                guest_port,
            }],
        )
        .await
        .expect("guest handshake");

        let mut request = [0_u8; 64];
        let (received, source) = service.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..received], b"udp-request");
        service.send_to(b"udp-response", source).await.unwrap();
        host.await.unwrap();
    }

    #[tokio::test]
    async fn guest_client_surfaces_refused_tcp_open() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;

            let (opcode, _sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            let (opcode, sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::OpenTcp);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::Refused,
                sid,
                b"denied",
            )
            .await;
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("guest handshake");
        let err = client.open_tcp("example.com:80").await.unwrap_err();
        assert!(
            matches!(err, FlowMuxError::Refused(_)),
            "unexpected err: {err}"
        );

        host.await.unwrap();
    }

    /// A fresh client has not handshaken yet. Publishing `Ready` at
    /// construction let a caller open a flow into a session that had agreed
    /// nothing, so a mismatched host looked healthy until the flow failed.
    #[tokio::test]
    async fn a_fresh_client_is_connecting_until_the_host_answers() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;
            let (opcode, _sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            started_tx.send(()).unwrap();
            // Hold the HelloAck back so the client is observed mid-handshake.
            release_rx.await.unwrap();
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;
            // Stay up: dropping the stream here would end the pump and the
            // client would go Dead before the test could observe Ready.
            finish_rx.await.unwrap();
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("transport session");
        started_rx.await.unwrap();
        assert_eq!(*client.state().borrow(), SessionState::Connecting);

        release_tx.send(()).unwrap();
        let mut state = client.state();
        while *state.borrow() != SessionState::Ready {
            state.changed().await.expect("state watch stays open");
        }

        finish_tx.send(()).unwrap();
        host.await.unwrap();
    }

    /// A host built against a different revision must be named, not silently
    /// tolerated: the guest is the side whose logs an operator reads first.
    #[tokio::test]
    async fn a_host_from_another_revision_is_refused_by_name() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;
            let (opcode, _sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            let stale = Handshake {
                behavior_revision: BEHAVIOR_REVISION.wrapping_add(1),
                build: "mvm-hostd from-a-stale-tree".to_string(),
            };
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &stale.encode(),
            )
            .await;
        });

        // `connect` returns once the transport session is up; the FlowMux
        // handshake runs in the pump, so the refusal surfaces on the first
        // flow — which is the call an operator sees fail.
        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("transport session");
        let err = client
            .open_tcp("example.com:80")
            .await
            .expect_err("a mismatched host must not serve a flow");
        let msg = err.to_string();
        assert!(msg.contains("mvm-hostd from-a-stale-tree"), "{msg}");
        assert!(msg.contains(GUEST_BUILD), "{msg}");

        host.await.unwrap();
    }

    /// A host that hangs up without answering is the shape of a host serving
    /// some other protocol. Say that, rather than reporting a bare close.
    #[tokio::test]
    async fn a_host_that_never_answers_the_handshake_says_so() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;
            let (opcode, _sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            drop(host_stream);
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("transport session");
        let err = client
            .open_tcp("example.com:80")
            .await
            .expect_err("a silent host must not serve a flow");
        let msg = err.to_string();
        assert!(msg.contains("FlowMux handshake"), "{msg}");
        assert!(msg.contains(GUEST_BUILD), "{msg}");

        host.await.unwrap();
    }

    #[tokio::test]
    async fn guest_client_resolves_dns_name() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;

            let (opcode, _sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            let (opcode, sid, _len, payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Resolve);
            let question = mvm_contract::protocol::dns::decode_query(&payload).unwrap();
            assert_eq!(question.name, "example.com");

            let response = mvm_contract::protocol::dns::encode_response(
                &question,
                mvm_contract::protocol::dns::DnsRcode::NoError,
                &["93.184.216.34".parse().unwrap()],
            );
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::Resolved,
                sid,
                &response,
            )
            .await;
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("guest handshake");
        let response = client.resolve("example.com", 1).await.unwrap();
        assert!(!response.is_empty());

        host.await.unwrap();
    }

    #[tokio::test]
    async fn session_loss_fails_live_handles_and_new_opens() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;

            let (opcode, _sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::Hello);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            let (opcode, sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            assert_eq!(opcode, Opcode::OpenTcp);
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::Opened,
                sid,
                &[],
            )
            .await;
            // Abruptly close the host transport.
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("guest handshake");
        let mut stream = client.open_tcp("example.com:80").await.unwrap();

        host.await.unwrap();
        // Allow the session pump to observe the EOF and clean up.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut buf = [0u8; 16];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);

        let err = client.open_tcp("example.com:80").await.unwrap_err();
        assert!(matches!(err, FlowMuxError::SessionClosed(_)));
    }

    #[tokio::test]
    async fn reconnect_client_fails_when_initial_transport_fails() {
        let (guest_key, _guest_anchor) = generate_keypair();
        let (_host_key, host_anchor) = generate_keypair();

        let client = FlowMuxReconnectClient::connect(
            || async {
                Err::<tokio::io::DuplexStream, _>(FlowMuxError::Transport(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "transport refused",
                )))
            },
            guest_key,
            host_anchor,
        )
        .await;

        assert!(client.is_err());
    }
}

#[cfg(test)]
mod connect_retry_tests {
    use super::*;

    /// The failure this exists for: the host endpoint is not listening yet and
    /// the guest's dial is reset.
    #[test]
    fn a_transport_error_is_retryable() {
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "reset by peer");
        assert!(FlowMuxError::Transport(reset).connect_is_retryable());

        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "nothing listening");
        assert!(FlowMuxError::Transport(refused).connect_is_retryable());
    }

    /// A decision must not be retried: the host looked at this guest and said
    /// no, and retrying only delays an accurate diagnosis.
    #[test]
    fn a_rejection_is_never_retryable() {
        for err in [
            FlowMuxError::Handshake("bad signature".into()),
            FlowMuxError::Refused("not admitted".into()),
            FlowMuxError::Frame("bad length prefix".into()),
            FlowMuxError::SessionClosed("go away".into()),
            FlowMuxError::ChannelClosed,
        ] {
            assert!(
                !err.connect_is_retryable(),
                "{err} must not be retried on connect"
            );
        }
    }

    /// The retry budget must stay inside the window the guest init is willing
    /// to wait, or the client is killed mid-retry and diagnosed as having
    /// exited rather than as having lost a race.
    #[test]
    fn the_retry_budget_fits_inside_the_readiness_timeout() {
        assert!(
            CONNECT_RETRY_BUDGET <= mvm_core::guest_netd::EGRESS_PROXY_READY_TIMEOUT,
            "retry budget {CONNECT_RETRY_BUDGET:?} exceeds the supervisor's wait"
        );
    }

    #[test]
    fn the_connect_backoff_starts_small_and_saturates() {
        let ms = |a| connect_retry_delay(a).as_millis() as u64;
        assert_eq!(ms(1), 2, "a lost race must not cost more than the race did");
        assert_eq!(ms(2), 4);
        assert_eq!(ms(3), 8);
        assert!(ms(1) < ms(2) && ms(2) < ms(3), "must be monotonic");
        assert_eq!(
            ms(u32::MAX),
            CONNECT_RETRY_MAX_MS,
            "must saturate, not overflow"
        );
    }
}
