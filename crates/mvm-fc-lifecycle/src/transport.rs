use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::{Serialize, de::DeserializeOwned};

use crate::protocol::MAX_FRAME;
use crate::{Error, Result};

pub(crate) const CONNECTION_BUDGET: Duration = Duration::from_secs(2);

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::Io(std::io::ErrorKind::TimedOut.into()))
}

pub(crate) fn connect(path: &str, deadline: Instant) -> Result<UnixStream> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    // socket2 bounds nonblocking connect and checks SO_ERROR before returning.
    socket.connect_timeout(&socket2::SockAddr::unix(path)?, remaining(deadline)?)?;
    let fd: std::os::fd::OwnedFd = socket.into();
    Ok(fd.into())
}

fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(Error::Protocol),
            Ok(n) => bytes = &mut bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(crate) fn receive<T: DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<T> {
    let mut prefix = [0; 4];
    read_exact(stream, &mut prefix, deadline)?;
    let size = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::Limit)?;
    if size == 0 || size > MAX_FRAME {
        return Err(Error::Limit);
    }
    let mut bytes = vec![0; size];
    read_exact(stream, &mut bytes, deadline)?;
    // Exactly one frame and a half-close. No request is acted on until EOF:
    // trailing frames, junk and slow drip inputs cannot mutate the registry.
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(&mut [0]) {
            Ok(0) => break,
            Ok(_) => return Err(Error::Protocol),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Protocol)
}

pub(crate) fn send<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(Error::Limit);
    }
    let size = u32::try_from(bytes.len())
        .map_err(|_| Error::Limit)?
        .to_be_bytes();
    for mut bytes in [size.as_slice(), bytes.as_slice()] {
        while !bytes.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            match stream.write(bytes) {
                Ok(0) => return Err(Error::Protocol),
                Ok(n) => bytes = &bytes[n..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
    stream.shutdown(Shutdown::Write)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Operation, RegistrationId, Request};
    fn deadline() -> Instant {
        Instant::now() + CONNECTION_BUDGET
    }
    #[test]
    fn real_socket_pair_roundtrip() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let id = RegistrationId::from_bytes([42; 32]);
        send(
            &mut a,
            &Request {
                version: 1,
                operation: Operation::Query { id },
            },
            deadline(),
        )
        .unwrap();
        assert_eq!(receive::<Request>(&mut b, deadline()).unwrap().version, 1);
    }
    #[test]
    fn malformed_oversized_truncated_and_trailing_frames_fail() {
        for bytes in [
            vec![0, 0, 0, 0],
            vec![0, 1, 0, 0],
            vec![0, 0, 0, 5, b'{'],
            vec![0, 0, 0, 1, b'?', b'x'],
            vec![0, 0, 0],
        ] {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            a.write_all(&bytes).unwrap();
            a.shutdown(Shutdown::Write).unwrap();
            assert!(receive::<Request>(&mut b, deadline()).is_err());
        }
    }
    #[test]
    fn idle_and_expired_connections_are_bounded() {
        let (_a, mut b) = UnixStream::pair().unwrap();
        assert!(receive::<Request>(&mut b, Instant::now() + Duration::from_millis(10)).is_err());
        assert!(receive::<Request>(&mut b, Instant::now()).is_err());
    }
    #[test]
    fn absent_endpoint_returns_an_error() {
        // No fixture directory, install, or privileged pathname is created.
        assert!(connect("/nonexistent-mvm-fc-lifecycle/socket", deadline()).is_err());
    }
}
