//! Transport: a TCP stream, optionally wrapped in TLS.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Sleep;
use tokio_rustls::client::TlsStream;

/// Plaintext or TLS.
///
/// An enum rather than `Box<dyn AsyncRead + AsyncWrite>` so the hot read path
/// stays a static dispatch and the type says exactly which two cases exist.
#[derive(Debug)]
enum Kind {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

/// A connected stream that cannot stall forever.
///
/// `DEFAULT_CONNECT_TIMEOUT` bounds *reaching* a peer. Nothing bounded what
/// happened afterwards: a peer that completes the handshake and then stops
/// sending leaves a read parked in `epoll` indefinitely, because the only other
/// deadline is the whole-request timeout, which is `None` unless a caller sets
/// it — and the OCI registry client does not.
///
/// The bound here is **idle time between reads**, not total duration. A total
/// deadline would be the wrong instrument: a multi-hundred-megabyte blob pull is
/// legitimately slow, and capping the whole request would break exactly the
/// large images this is meant to keep working. What is never legitimate is a
/// connection that yields no bytes at all for minutes.
pub struct Stream {
    kind: Kind,
    idle: Duration,
    /// Armed on the first `Pending` and cleared whenever bytes arrive, so the
    /// budget applies per stall rather than to the transfer as a whole.
    deadline: Option<Pin<Box<Sleep>>>,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("kind", &self.kind)
            .field("idle", &self.idle)
            .finish_non_exhaustive()
    }
}

impl Stream {
    pub fn plain(tcp: TcpStream, idle: Duration) -> Self {
        Self {
            kind: Kind::Plain(tcp),
            idle,
            deadline: None,
        }
    }

    pub fn tls(tls: Box<TlsStream<TcpStream>>, idle: Duration) -> Self {
        Self {
            kind: Kind::Tls(tls),
            idle,
            deadline: None,
        }
    }

    fn poll_inner_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.kind {
            Kind::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Kind::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_inner_read(cx, buf) {
            Poll::Ready(result) => {
                // Progress — including a clean EOF. Disarm so the next stall
                // gets a fresh budget rather than inheriting a spent one.
                this.deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let idle = this.idle;
                let deadline = this
                    .deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
                match deadline.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.deadline = None;
                        Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("read timed out: no bytes from peer for {idle:?}"),
                        )))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.get_mut().kind {
            Kind::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Kind::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().kind {
            Kind::Plain(s) => Pin::new(s).poll_flush(cx),
            Kind::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().kind {
            Kind::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Kind::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}
