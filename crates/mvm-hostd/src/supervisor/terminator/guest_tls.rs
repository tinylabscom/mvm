//! The terminated TLS stream over the guest's end of a flow.
//!
//! rustls writes from inside a read. A read first flushes whatever TLS output
//! is pending, and right after the handshake that is never empty: the server
//! queues its TLS 1.3 session tickets when the client's `Finished` arrives and
//! sends them from the read that is waiting for the first request. Whether that
//! write fails when the guest has already hung up depends on the host: on Linux
//! a write to a Unix socket whose peer has shut down fails with `EPIPE`, on
//! macOS it succeeds. A failed flush fails the read before rustls has looked at
//! the bytes the guest did send, so a guest that wrote half a request and left
//! looked like one that closed having sent nothing, and nothing was recorded.
//!
//! [`TerminatedTls`] keeps a read about what the guest sent. A write made on
//! behalf of a read that fails because the guest has gone is discarded, and the
//! read carries on through the bytes already in the socket to the real end of
//! the stream. A write the flow makes itself after that — a response — fails
//! with the error the guest's departure caused, so nothing is answered into a
//! socket already known to be gone.

use std::io::{self, IoSlice, Read, Write};

use super::read::is_peer_gone;

/// A server-side TLS stream whose reads report what the guest sent, whether or
/// not the guest is still reading.
pub(super) struct TerminatedTls<T: Read + Write> {
    stream: rustls::StreamOwned<rustls::ServerConnection, GuestEnd<T>>,
}

impl<T: Read + Write> TerminatedTls<T> {
    pub(super) fn new(connection: rustls::ServerConnection, transport: T) -> Self {
        Self {
            stream: rustls::StreamOwned::new(connection, GuestEnd::new(transport)),
        }
    }
}

impl<T: Read + Write> Read for TerminatedTls<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.sock.reading = true;
        let read = self.stream.read(buf);
        self.stream.sock.reading = false;
        read
    }
}

impl<T: Read + Write> Write for TerminatedTls<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.sock.still_reading()?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.sock.still_reading()?;
        self.stream.flush()
    }
}

/// The transport under the TLS stream, which tells a write rustls makes while
/// reading from one the flow makes to answer.
struct GuestEnd<T> {
    transport: T,
    /// Set for the duration of a [`TerminatedTls`] read.
    reading: bool,
    /// How a write made while reading failed because the guest had gone.
    stopped_reading: Option<io::ErrorKind>,
}

impl<T> GuestEnd<T> {
    fn new(transport: T) -> Self {
        Self {
            transport,
            reading: false,
            stopped_reading: None,
        }
    }

    /// Whether `error` is a write the guest's departure failed during a read,
    /// to be discarded. Remembers the departure if so.
    fn discards(&mut self, error: &io::Error) -> bool {
        let gone = self.reading && is_peer_gone(error.kind());
        if gone {
            self.stopped_reading = Some(error.kind());
        }
        gone
    }

    /// Refuse a write the flow makes once the guest is known to have gone.
    fn still_reading(&self) -> io::Result<()> {
        match self.stopped_reading {
            Some(kind) => Err(io::Error::new(kind, "the guest stopped reading the flow")),
            None => Ok(()),
        }
    }
}

impl<T: Read> Read for GuestEnd<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.transport.read(buf)
    }
}

impl<T: Write> Write for GuestEnd<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.transport.write(buf) {
            Err(error) if self.discards(&error) => Ok(buf.len()),
            written => written,
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self.transport.write_vectored(bufs) {
            Err(error) if self.discards(&error) => Ok(bufs.iter().map(|buf| buf.len()).sum()),
            written => written,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.transport.flush() {
            Err(error) if self.discards(&error) => Ok(()),
            flushed => flushed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport whose every write fails with `kind` and which reads `data`.
    struct RefusesWrites {
        data: io::Cursor<Vec<u8>>,
        kind: io::ErrorKind,
        written: usize,
    }

    impl RefusesWrites {
        fn new(kind: io::ErrorKind) -> Self {
            Self {
                data: io::Cursor::new(b"what the guest sent".to_vec()),
                kind,
                written: 0,
            }
        }
    }

    impl Read for RefusesWrites {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.data.read(buf)
        }
    }

    impl Write for RefusesWrites {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            self.written += 1;
            Err(io::Error::from(self.kind))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_the_departed_guest_refuses_while_reading_is_discarded() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::UnexpectedEof,
        ] {
            let mut end = GuestEnd::new(RefusesWrites::new(kind));
            end.reading = true;
            assert_eq!(end.write(b"ticket").expect("discarded"), 6, "{kind:?}");
            let bufs = [IoSlice::new(b"tick"), IoSlice::new(b"et")];
            assert_eq!(end.write_vectored(&bufs).expect("discarded"), 6);
            let mut read = Vec::new();
            end.read_to_end(&mut read).expect("the reads are untouched");
            assert_eq!(read, b"what the guest sent");
            assert_eq!(end.stopped_reading, Some(kind));
        }
    }

    #[test]
    fn once_the_guest_has_gone_the_flow_cannot_answer_it() {
        let mut end = GuestEnd::new(RefusesWrites::new(io::ErrorKind::BrokenPipe));
        end.reading = true;
        assert_eq!(end.write(b"ticket").expect("discarded"), 6);
        end.reading = false;
        let refused = end.still_reading().expect_err("refused");
        assert_eq!(refused.kind(), io::ErrorKind::BrokenPipe);
    }

    /// The flow's own write reaches the transport and fails with the
    /// transport's error: only writes made while reading are discarded.
    #[test]
    fn a_write_outside_a_read_is_not_discarded() {
        let mut end = GuestEnd::new(RefusesWrites::new(io::ErrorKind::BrokenPipe));
        let failed = end.write(b"response").expect_err("not discarded");
        assert_eq!(failed.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(end.transport.written, 1);
        assert_eq!(end.stopped_reading, None);
    }

    /// Only the guest leaving is discarded. Any other failure of a write made
    /// while reading still fails the read.
    #[test]
    fn any_other_write_failure_while_reading_still_fails() {
        let mut end = GuestEnd::new(RefusesWrites::new(io::ErrorKind::PermissionDenied));
        end.reading = true;
        let failed = end.write(b"ticket").expect_err("not discarded");
        assert_eq!(failed.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(end.stopped_reading, None);
        end.still_reading()
            .expect("nothing recorded the guest leaving");
    }
}
