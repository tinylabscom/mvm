//! Nonblocking local I/O under one monotonic deadline, including trickled data.
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

fn wait(stream: &UnixStream, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let millis = remaining.as_millis().saturating_add(1);
        let timeout = i32::try_from(millis).unwrap_or(i32::MAX);
        let mut fd = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: one initialized pollfd, writable for the duration of poll.
        let rc = unsafe { libc::poll(&mut fd, 1, timeout) };
        if rc > 0 {
            return Ok(());
        }
        if rc == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn perform<T>(
    stream: &UnixStream,
    events: libc::c_short,
    deadline: Instant,
    mut operation: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match operation() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait(stream, events, deadline)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

pub(super) fn read_exact(
    mut stream: &UnixStream,
    mut buf: &mut [u8],
    end: Instant,
) -> io::Result<()> {
    while !buf.is_empty() {
        let n = perform(stream, libc::POLLIN, end, || stream.read(buf))?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

pub(super) fn eof(mut stream: &UnixStream, end: Instant) -> io::Result<()> {
    let mut byte = [0];
    if perform(stream, libc::POLLIN, end, || stream.read(&mut byte))? != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

pub(super) fn write_all(mut stream: &UnixStream, mut buf: &[u8], end: Instant) -> io::Result<()> {
    while !buf.is_empty() {
        let n = perform(stream, libc::POLLOUT, end, || stream.write(buf))?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
    }
    Ok(())
}
