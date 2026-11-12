//! A std-only TCP [`PeerTransport`]: one length-prefixed canonical envelope
//! per connection, answered with the destination's typed verdict.
//!
//! The listener binds an address the operator names (no default, no wildcard
//! choice) and hands each frame to the destination node's `MailboxService`
//! over its own socket, so signature, capability, epoch and replay checks all
//! run at the destination. It carries envelopes only: no packets, no guest
//! network, no fallback path.
//!
//! Test support, deliberately not a shipped module: `check-single-network-path`
//! admits no host TCP socket in `mvm-hostd/src`, and the production transport
//! is a later piece of work.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use mvm_contract::protocol::mailbox::SignedMailboxCapability;
use mvm_core::mailbox::decode_envelope;
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::transport::{
    AuthorizedMailboxFrame, AuthorizedRoute, CancellationToken, ChannelLimits, PeerChannel,
    PeerTransport, TransportError,
};

use mvm_hostd::mailbox_service::send;

/// Sending side. The route's locator is the destination `host:port`.
pub struct TcpPeerTransport {
    pub io_timeout: Duration,
}

struct TcpChannel {
    addr: SocketAddr,
    limits: ChannelLimits,
    io_timeout: Duration,
}

fn dial(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, TransportError> {
    let stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|_| TransportError::Partitioned)?;
    let set = stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)));
    set.map_err(|_| TransportError::Partitioned)?;
    Ok(stream)
}

impl PeerTransport for TcpPeerTransport {
    fn connect(
        &self,
        route: &AuthorizedRoute,
        limits: ChannelLimits,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PeerChannel>, TransportError> {
        if cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        let addr: SocketAddr = route
            .locator()
            .as_str()
            .parse()
            .map_err(|_| TransportError::UnknownRoute)?;
        dial(addr, self.io_timeout)?; // fail closed now if the peer is down
        Ok(Box::new(TcpChannel {
            addr,
            limits,
            io_timeout: self.io_timeout,
        }))
    }
}

impl PeerChannel for TcpChannel {
    fn try_send(
        &mut self,
        frame: &AuthorizedMailboxFrame,
        cancellation: &CancellationToken,
    ) -> Result<(), TransportError> {
        if cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        if frame.encoded_len() > self.limits.max_frame_bytes() {
            return Err(TransportError::FrameTooLarge);
        }
        let mut stream = dial(self.addr, self.io_timeout)?;
        // A listener that refuses on length alone closes early; its verdict
        // is still readable, so a failed write is not itself the answer.
        let _ = stream
            .write_all(&(frame.encoded_len() as u32).to_be_bytes())
            .and_then(|()| stream.write_all(frame.as_bytes()));
        let mut reply = Vec::new();
        stream
            .read_to_end(&mut reply)
            .map_err(|_| TransportError::Partitioned)?;
        match serde_json::from_slice::<Result<(), Refusal>>(&reply) {
            Ok(Ok(())) => Ok(()),
            _ => Err(TransportError::Refused),
        }
    }
}

/// Receiving-side bounds.
#[derive(Debug, Clone, Copy)]
pub struct TcpListenerLimits {
    pub max_frame_bytes: usize,
    pub max_pending_bytes: usize,
    pub max_connections: usize,
    pub io_timeout: Duration,
}

/// Where accepted frames go: the destination's mailbox socket, under the
/// capability that node accepts for that mailbox.
pub struct TcpPeerListener {
    addr: SocketAddr,
    cancel: CancellationToken,
    worker: Option<JoinHandle<()>>,
}

struct Destination {
    socket: PathBuf,
    capability: SignedMailboxCapability,
    limits: TcpListenerLimits,
    pending: AtomicUsize,
}

impl TcpPeerListener {
    pub fn bind(
        addr: SocketAddr,
        socket: PathBuf,
        capability: SignedMailboxCapability,
        limits: TcpListenerLimits,
        cancel: CancellationToken,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let dest = Arc::new(Destination {
            socket,
            capability,
            limits,
            pending: AtomicUsize::new(0),
        });
        let token = cancel.clone();
        let worker = std::thread::spawn(move || {
            let active = Arc::new(AtomicUsize::new(0));
            let mut handlers: Vec<JoinHandle<()>> = Vec::new();
            while !token.is_cancelled() {
                let Ok((stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                if active.fetch_add(1, Ordering::SeqCst) >= dest.limits.max_connections {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue; // over the connection bound: dropped unread
                }
                let (dest, active) = (dest.clone(), active.clone());
                handlers.retain(|h| !h.is_finished());
                handlers.push(std::thread::spawn(move || {
                    let _ = stream.set_nonblocking(false);
                    handle(&dest, stream);
                    active.fetch_sub(1, Ordering::SeqCst);
                }));
            }
            handlers.into_iter().for_each(|h| {
                let _ = h.join();
            });
        });
        Ok(Self {
            addr,
            cancel,
            worker: Some(worker),
        })
    }

    /// The bound address (useful when bound to port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TcpPeerListener {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn handle(dest: &Destination, mut stream: TcpStream) {
    let t = Some(dest.limits.io_timeout);
    let _ = stream.set_read_timeout(t);
    let _ = stream.set_write_timeout(t);
    let verdict = read_frame(dest, &mut stream).and_then(|body| {
        let envelope = decode_envelope(&body).map_err(|_| Refusal::Malformed)?;
        send(&dest.socket, &dest.capability, &envelope)
    });
    if let Ok(reply) = serde_json::to_vec(&verdict) {
        let _ = stream.write_all(&reply);
    }
}

fn read_frame(dest: &Destination, stream: &mut TcpStream) -> Result<Vec<u8>, Refusal> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|_| Refusal::Malformed)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > dest.limits.max_frame_bytes {
        return Err(Refusal::Oversized(dest.limits.max_frame_bytes));
    }
    if dest.pending.fetch_add(len, Ordering::SeqCst) + len > dest.limits.max_pending_bytes {
        dest.pending.fetch_sub(len, Ordering::SeqCst);
        return Err(Refusal::QueueFull(dest.limits.max_pending_bytes));
    }
    let mut body = vec![0u8; len];
    let read = stream.read_exact(&mut body);
    dest.pending.fetch_sub(len, Ordering::SeqCst);
    read.map_err(|_| Refusal::Malformed)?;
    Ok(body)
}
