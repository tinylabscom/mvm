//! Readiness-backed blocking reads and bounded writes over one nonblocking socket.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

pub(super) struct Readiness {
    poll: Poll,
    events: Events,
}

impl Readiness {
    pub(super) fn new(stream: &UnixStream, interest: Interest) -> io::Result<Self> {
        let poll = Poll::new()?;
        let fd = stream.as_raw_fd();
        poll.registry()
            .register(&mut SourceFd(&fd), Token(0), interest)?;
        Ok(Self {
            poll,
            events: Events::with_capacity(1),
        })
    }

    pub(super) fn wait_until(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        loop {
            let remaining = deadline
                .map(|deadline| {
                    deadline
                        .checked_duration_since(Instant::now())
                        .filter(|remaining| !remaining.is_zero())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::TimedOut, "FlowMux I/O deadline expired")
                        })
                })
                .transpose()?;
            match self.poll.poll(&mut self.events, remaining) {
                Ok(()) if !self.events.is_empty() => return Ok(()),
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// Preserve blocking Read semantics while the shared descriptor stays nonblocking.
pub(super) struct BlockingReader {
    stream: UnixStream,
    readiness: Readiness,
    timeout: Option<Duration>,
}

impl BlockingReader {
    pub(super) fn new(stream: UnixStream) -> io::Result<Self> {
        let timeout = stream.read_timeout()?;
        read_deadline(timeout)?;
        // Authentication used blocking I/O. Set this once for both cloned halves;
        // every subsequent read/write waits for readiness instead of blocking in I/O.
        stream.set_nonblocking(true)?;
        let readiness = Readiness::new(&stream, Interest::READABLE)?;
        Ok(Self {
            stream,
            readiness,
            timeout,
        })
    }

    pub(super) fn stream(&self) -> &UnixStream {
        &self.stream
    }
}

impl Read for BlockingReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let deadline = read_deadline(self.timeout)?;
        loop {
            match self.stream.read(bytes) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.readiness.wait_until(deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn read_deadline(timeout: Option<Duration>) -> io::Result<Option<Instant>> {
    timeout
        .map(|timeout| {
            Instant::now().checked_add(timeout).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "FlowMux read timeout overflows the monotonic clock",
                )
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    #[test]
    fn read_exact_preserves_fragmented_bytes_across_readiness_waits() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut reader = BlockingReader::new(stream).unwrap();
        peer.write_all(b"first").unwrap();
        let (finished, done) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let mut bytes = [0; 11];
            let result = reader.read_exact(&mut bytes);
            let _ = finished.send((result, bytes));
        });
        assert!(matches!(
            done.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        peer.write_all(b"second").unwrap();
        let (result, bytes) = done.recv_timeout(Duration::from_secs(2)).unwrap();
        result.unwrap();
        assert_eq!(&bytes, b"firstsecond");
        worker.join().unwrap();
    }

    #[test]
    fn read_exact_reports_eof_without_losing_the_partial_prefix() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut reader = BlockingReader::new(stream).unwrap();
        peer.write_all(b"abc").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let mut bytes = [0; 6];
        assert_eq!(
            reader.read_exact(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(&bytes[..3], b"abc");
    }

    #[test]
    fn an_existing_read_timeout_still_bounds_an_idle_read() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut reader = BlockingReader::new(stream).unwrap();
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(reader.read(&mut []).unwrap(), 0);
    }
}
