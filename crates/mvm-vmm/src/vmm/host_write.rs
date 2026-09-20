//! Guest→host byte delivery onto a non-blocking host socket, without loss.
//!
//! Every vsock bridge forwards the guest's `OP_RW` payloads to a Unix socket
//! whose reader is another process: the per-VM network endpoint, the host agent
//! client, a console client. That reader runs when the host scheduler lets it,
//! and a macOS Unix stream socket buffers only 8 KiB. A payload the socket
//! cannot take yet has to wait somewhere; dropping it corrupts the byte stream
//! the reader is parsing, and nothing downstream can tell a gap from a frame.
//!
//! [`HostWriteBacklog`] is that somewhere. What the socket refuses is queued
//! and retried from the host-I/O loop, and the caller learns how many bytes
//! actually reached the socket. Those are the bytes the device may report to
//! the guest as forwarded (`fwd_cnt`): a queued byte has not been consumed yet,
//! so the guest's send window stays shut until it is. That makes the queue
//! self-bounding — a guest that honours its credit can never have more than one
//! window outstanding — and a guest that overruns it is refused rather than
//! buffered without limit.

use std::io::{ErrorKind, Write};

use super::vsock_transport::HOST_BUF_ALLOC;

/// Most bytes one connection may have queued for its host socket. It is the
/// receive window the device advertises, so a guest that stays within its
/// credit never reaches it.
pub(crate) const MAX_HOST_BACKLOG: usize = HOST_BUF_ALLOC as usize;

/// The outcome of offering bytes to a host socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostWrite {
    /// This many bytes reached the socket during the call, queued ones first.
    /// Anything not yet written is still queued, in order.
    Forwarded(usize),
    /// The stream cannot continue: the host side closed or errored, or the
    /// guest sent more than the window it was granted. Tear it down.
    Failed,
}

/// Bytes accepted from the guest that the host socket has not taken yet.
#[derive(Debug, Default)]
pub(crate) struct HostWriteBacklog {
    queued: Vec<u8>,
}

impl HostWriteBacklog {
    /// Append `payload` behind anything already queued, then write as much as
    /// the socket takes without blocking.
    pub(crate) fn submit<W: Write>(&mut self, sink: &mut W, payload: &[u8]) -> HostWrite {
        if self.queued.len().saturating_add(payload.len()) > MAX_HOST_BACKLOG {
            return HostWrite::Failed;
        }
        self.queued.extend_from_slice(payload);
        self.flush(sink)
    }

    /// Write queued bytes until the socket would block or the queue is empty.
    pub(crate) fn flush<W: Write>(&mut self, sink: &mut W) -> HostWrite {
        let mut written = 0;
        while written < self.queued.len() {
            match sink.write(&self.queued[written..]) {
                Ok(0) => return HostWrite::Failed,
                Ok(n) => written += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => return HostWrite::Failed,
            }
        }
        self.queued.drain(..written);
        HostWrite::Forwarded(written)
    }

    /// Whether bytes are waiting for the socket.
    pub(crate) fn is_pending(&self) -> bool {
        !self.queued.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that takes at most `room` bytes, then refuses until drained.
    struct Tight {
        taken: Vec<u8>,
        room: usize,
    }

    impl Write for Tight {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.room == 0 {
                return Err(ErrorKind::WouldBlock.into());
            }
            let n = buf.len().min(self.room);
            self.taken.extend_from_slice(&buf[..n]);
            self.room -= n;
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bytes_the_socket_refuses_are_kept_in_order_and_delivered_later() {
        let mut sink = Tight {
            taken: Vec::new(),
            room: 3,
        };
        let mut backlog = HostWriteBacklog::default();

        assert_eq!(
            backlog.submit(&mut sink, b"abcdef"),
            HostWrite::Forwarded(3)
        );
        assert!(backlog.is_pending());
        assert_eq!(backlog.submit(&mut sink, b"gh"), HostWrite::Forwarded(0));

        sink.room = 100;
        assert_eq!(backlog.flush(&mut sink), HostWrite::Forwarded(5));
        assert!(!backlog.is_pending());
        assert_eq!(sink.taken, b"abcdefgh");
    }

    #[test]
    fn a_guest_that_overruns_its_window_is_refused_not_buffered() {
        let mut sink = Tight {
            taken: Vec::new(),
            room: 0,
        };
        let mut backlog = HostWriteBacklog::default();

        assert_eq!(
            backlog.submit(&mut sink, &vec![0; MAX_HOST_BACKLOG]),
            HostWrite::Forwarded(0)
        );
        assert_eq!(backlog.submit(&mut sink, b"x"), HostWrite::Failed);
    }

    #[test]
    fn a_closed_host_socket_fails_the_stream() {
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(theirs);
        let mut backlog = HostWriteBacklog::default();

        assert_eq!(backlog.submit(&mut ours, b"hello"), HostWrite::Failed);
    }

    /// The failure this type exists for: a socket whose reader is not running.
    /// Everything the guest sent must come out the far side, byte for byte,
    /// once the reader catches up.
    #[test]
    fn a_stalled_reader_loses_nothing() {
        use std::io::Read;

        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let payload: Vec<u8> = (0..MAX_HOST_BACKLOG).map(|i| (i % 251) as u8).collect();
        let mut backlog = HostWriteBacklog::default();

        let HostWrite::Forwarded(first) = backlog.submit(&mut ours, &payload) else {
            panic!("an open socket accepts the submission");
        };
        assert!(first < payload.len(), "the socket buffer must be smaller");
        assert!(backlog.is_pending());

        let mut received = Vec::with_capacity(payload.len());
        let mut buf = vec![0; 64 * 1024];
        while received.len() < payload.len() {
            let n = theirs.read(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
            assert!(matches!(backlog.flush(&mut ours), HostWrite::Forwarded(_)));
        }
        assert!(!backlog.is_pending());
        assert_eq!(received, payload);
    }
}
