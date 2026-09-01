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
    Direction, FrameError, MAX_UDP_DATAGRAM_LEN, Opcode, SessionValidator, decode, encode_into,
};
use mvm_core::net::session::Session;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::flowmux_drive::GuestIngressTarget;
mod reconnect;
mod wire;

pub use reconnect::{FlowMuxReconnectClient, ReconnectPolicy};
pub use wire::{build_dns_query, decode_udp_addr, encode_udp_addr};

mod client;
mod pump;

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
    /// Policy admitted the target, but the host could not connect upstream.
    #[error("upstream connect failed: {0}")]
    UpstreamConnect(String),
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

/// Largest sealed frame the guest will accept off the wire.
const MAX_SEALED_LEN: usize = 1 << 20;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::network_flow::hello::BEHAVIOR_REVISION;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[tokio::test]
    async fn guest_client_distinguishes_an_upstream_connect_failure() {
        let (guest_stream, host_stream) = tokio::io::duplex(4096);
        let (guest_key, _guest_anchor) = generate_keypair();
        let (host_key, host_anchor) = generate_keypair();

        let host = tokio::spawn(async move {
            let (mut host_stream, mut host_session) = host_handshake(host_stream, host_key).await;

            let _hello = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .await;

            let (_opcode, sid, _len, _payload) = recv_frame(&mut host_stream, &mut host_session)
                .await
                .unwrap();
            send_frame(
                &mut host_stream,
                &mut host_session,
                Opcode::ConnectFailed,
                sid,
                b"connection failed",
            )
            .await;
        });

        let client = FlowMuxClient::connect(guest_stream, guest_key, host_anchor)
            .await
            .expect("guest handshake");
        let err = client.open_tcp("example.com:80").await.unwrap_err();
        assert!(
            matches!(err, FlowMuxError::UpstreamConnect(_)),
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
            FlowMuxError::UpstreamConnect("connection failed".into()),
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
