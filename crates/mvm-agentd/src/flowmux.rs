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
use mvm_contract::protocol::network_flow::{
    Direction, FrameError, Opcode, SessionValidator, decode, encode_into,
};
use mvm_core::net::session::Session;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

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

impl FlowMuxError {
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
    /// Close a UDP association from the guest side.
    CloseUdp { stream_id: u32 },
}

/// Snapshot of session health observed by client handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Handshake complete and flows may be opened.
    Ready,
    /// Reconnecting after a transport failure.
    Reconnecting,
    /// Reconnect attempts exhausted; the client is dead.
    Dead,
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
        let (state_tx, state_rx) = watch::channel(SessionState::Ready);

        let next_stream_id = Arc::new(AtomicU32::new(FIRST_GUEST_STREAM_ID));
        let pump = SessionPump {
            stream: Box::pin(stream),
            session,
            validator: SessionValidator::default(),
            client_rx,
            client_tx: client_tx.clone(),
            state_tx,
            tcp_streams: BTreeMap::new(),
            udp_associations: BTreeMap::new(),
            pending_opens: BTreeMap::new(),
            pending_resolves: BTreeMap::new(),
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
            let snapshot = *state.borrow();
            match snapshot {
                SessionState::Ready => return Ok(()),
                SessionState::Dead => return Err(FlowMuxError::SessionClosed("dead".into())),
                SessionState::Reconnecting => {
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
    tcp_streams: BTreeMap<u32, TcpStreamState>,
    udp_associations: BTreeMap<u32, UdpAssociationState>,
    pending_opens: BTreeMap<u32, PendingOpen>,
    pending_resolves: BTreeMap<u32, oneshot::Sender<Result<Vec<u8>, FlowMuxError>>>,
}

impl<S> SessionPump<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(mut self) -> Result<(), FlowMuxError> {
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
                frame = read_sealed_frame_from(&mut self.stream, &mut self.session) => {
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
        self.fail_all("session closed");
        let _ = self.state_tx.send(SessionState::Dead);
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
        self.validator
            .admit(&frame_facts(Direction::GuestToHost, Opcode::Hello, 0, 0))
            .map_err(|e| FlowMuxError::Frame(e.to_string()))?;
        self.write_frame(Opcode::Hello, 0, &[]).await
    }

    async fn read_hello_ack(&mut self) -> Result<(), FlowMuxError> {
        let (opcode, stream_id, _payload_len, payload) = self
            .read_frame()
            .await?
            .ok_or_else(|| FlowMuxError::SessionClosed("peer closed before HelloAck".into()))?;
        if opcode != Opcode::HelloAck || stream_id != 0 || !payload.is_empty() {
            return Err(FlowMuxError::Frame(format!(
                "expected HelloAck, got {opcode:?} on stream {stream_id}"
            )));
        }
        self.validator
            .admit(&frame_facts(
                Direction::HostToGuest,
                Opcode::HelloAck,
                stream_id,
                0,
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
                if let Some(state) = self.tcp_streams.get_mut(&stream_id) {
                    let _ = state.tx.send(StreamEvent::Data(payload));
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
                if let Some(state) = self.udp_associations.get_mut(&stream_id)
                    && let Ok((addr, body)) = decode_udp_addr(&payload)
                {
                    let _ = state.tx.send(UdpEvent::Recv(addr, body.to_vec()));
                }
            }
            Opcode::CloseUdp => {
                let reason = String::from_utf8_lossy(&payload).into_owned();
                if let Some(state) = self.udp_associations.remove(&stream_id) {
                    let _ = state.tx.send(UdpEvent::CloseUdp(reason));
                }
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

    async fn send_data(&mut self, stream_id: u32, bytes: &[u8]) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::Data, stream_id, bytes).await
    }

    async fn send_half_close(&mut self, stream_id: u32) -> Result<(), FlowMuxError> {
        self.write_frame(Opcode::HalfClose, stream_id, &[]).await
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

pub(crate) async fn read_sealed_frame_from<S>(
    stream: &mut S,
    session: &mut mvm_core::net::session::Session,
) -> Result<Option<(Opcode, u32, u32, Vec<u8>)>, FlowMuxError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let sealed_len = u32::from_be_bytes(len_buf) as usize;
    if sealed_len == 0 {
        return Ok(None);
    }
    const MAX_SEALED_LEN: usize = 1 << 20;
    if sealed_len > MAX_SEALED_LEN {
        return Err(FlowMuxError::Frame(format!(
            "sealed frame length {sealed_len} exceeds {MAX_SEALED_LEN}"
        )));
    }
    let mut sealed_buf = vec![0u8; sealed_len];
    stream.read_exact(&mut sealed_buf).await?;

    let sealed = mvm_core::net::session::SealedFrame::decode(&sealed_buf)
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
        (Opcode::WindowUpdate, [a, b, c, d]) => {
            facts.with_credit(u32::from_be_bytes([*a, *b, *c, *d]))
        }
        // A malformed update keeps no credit, so the validator still refuses
        // it — the decode is a faithful read, not a way to wave frames through.
        _ => facts,
    }
}

fn build_dns_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, FlowMuxError> {
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

fn encode_udp_addr(ip: std::net::IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 2);
    match ip {
        std::net::IpAddr::V4(v4) => {
            out.push(0x01);
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

fn decode_udp_addr(bytes: &[u8]) -> Result<(SocketAddr, &[u8]), FlowMuxError> {
    if bytes.is_empty() {
        return Err(FlowMuxError::Frame("empty UDP address".into()));
    }
    let (ip, rest) = match bytes[0] {
        0x01 => {
            if bytes.len() < 1 + 4 + 2 {
                return Err(FlowMuxError::Frame("short IPv4 UDP address".into()));
            }
            let ip = std::net::IpAddr::from(std::net::Ipv4Addr::new(
                bytes[1], bytes[2], bytes[3], bytes[4],
            ));
            (ip, &bytes[5..])
        }
        0x04 => {
            if bytes.len() < 1 + 16 + 2 {
                return Err(FlowMuxError::Frame("short IPv6 UDP address".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            let ip = std::net::IpAddr::from(std::net::Ipv6Addr::from(octets));
            (ip, &bytes[17..])
        }
        tag => {
            return Err(FlowMuxError::Frame(format!(
                "unknown UDP address tag {tag}"
            )));
        }
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    let addr = SocketAddr::new(ip, port);
    Ok((addr, &rest[2..]))
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
        let initial = connector().await?;
        let client = Arc::new(
            FlowMuxClient::connect(initial, guest_signing_key.clone(), host_anchor).await?,
        );
        let (current_tx, current_rx) = watch::channel(Some(Arc::clone(&client)));

        tokio::spawn(async move {
            let mut state_rx = client.state();
            reconnect_loop(
                connector,
                guest_signing_key,
                host_anchor,
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
    async fn active_client(&self) -> Result<Arc<FlowMuxClient>, FlowMuxError> {
        let mut current = self.current.clone();
        loop {
            let snapshot = current.borrow().clone();
            if let Some(client) = snapshot {
                let ready = {
                    let state = client.state();
                    *state.borrow() == SessionState::Ready
                };
                if ready {
                    return Ok(client);
                }
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
            if *state_rx.borrow() == SessionState::Dead {
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
                match FlowMuxClient::connect(stream, guest_signing_key.clone(), host_anchor).await {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn udp_addr_roundtrips_ipv4_and_ipv6() {
        let v4 = SocketAddr::new(std::net::IpAddr::from([127, 0, 0, 1]), 1234);
        let encoded = encode_udp_addr(v4.ip(), v4.port());
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
            assert!(payload.is_empty());

            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &[],
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
                &[],
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
                &[],
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
                &[],
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
