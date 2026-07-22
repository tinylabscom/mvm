//! Shared guest-side host-vsock session lifecycle helpers.
//!
//! The guest helpers in this crate share one transport shape:
//! dial a host vsock port, write one framing prelude that tells the
//! host what to do with the stream, then splice bytes both ways.
//! The guest stays responsible for the exact prelude bytes, and the
//! host stays responsible for all admission/policy decisions.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

use mvm_core::guest_netd::ConnectAck;

/// One guest-initiated session to a host AF_VSOCK port.
pub struct HostVsockSession<U> {
    upstream: U,
}

impl HostVsockSession<TcpStream> {
    /// Dial a host AF_VSOCK stream to `port`.
    pub async fn connect(port: u32) -> std::io::Result<Self> {
        Ok(Self {
            upstream: connect_host_vsock(port).await?,
        })
    }
}

impl<U> HostVsockSession<U>
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an already-connected upstream stream.
    pub fn new(upstream: U) -> Self {
        Self { upstream }
    }

    /// Write the exact initial metadata bytes the host expects.
    pub async fn write_initial_bytes(mut self, bytes: &[u8]) -> std::io::Result<Self> {
        self.upstream.write_all(bytes).await?;
        self.upstream.flush().await?;
        Ok(self)
    }

    /// Proxy bytes between the guest-side client and the host-side upstream.
    pub async fn splice<C>(mut self, mut client: C) -> std::io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::io::copy_bidirectional(&mut client, &mut self.upstream)
            .await
            .map(|_| ())
    }

    /// Recover the wrapped upstream stream for flows that need a custom relay.
    pub fn into_inner(self) -> U {
        self.upstream
    }

    /// Read the host's one-byte connect-result ack that follows the target-line
    /// frame on the raw-egress protocol. Fail-closed: EOF or an unrecognised byte
    /// is treated as a connect failure so the caller answers its client honestly.
    pub async fn read_connect_ack(&mut self) -> ConnectAck {
        let mut byte = [0u8; 1];
        match self.upstream.read_exact(&mut byte).await {
            Ok(_) => ConnectAck::from_byte(byte[0]).unwrap_or(ConnectAck::Fail),
            Err(_) => ConnectAck::Fail,
        }
    }
}

/// Open a stream to the host over AF_VSOCK.
pub async fn connect_host_vsock(port: u32) -> std::io::Result<TcpStream> {
    tokio::task::spawn_blocking(move || connect_host_vsock_blocking(port))
        .await
        .map_err(|e| std::io::Error::other(format!("vsock dial task failed: {e}")))?
}

#[cfg(target_os = "linux")]
fn connect_host_vsock_blocking(port: u32) -> std::io::Result<TcpStream> {
    const VMADDR_CID_HOST: u32 = 2;

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

#[cfg(not(target_os = "linux"))]
fn connect_host_vsock_blocking(_port: u32) -> std::io::Result<TcpStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "AF_VSOCK guest dialing is only available on Linux guests",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn write_initial_bytes_precedes_spliced_payload() {
        let (mut client_side, client_bridge) = tokio::io::duplex(128);
        let (upstream_bridge, mut upstream_side) = tokio::io::duplex(128);

        let task = tokio::spawn(async move {
            HostVsockSession::new(upstream_bridge)
                .write_initial_bytes(b"hello\n")
                .await
                .unwrap()
                .splice(client_bridge)
                .await
                .unwrap();
        });

        client_side.write_all(b"ping").await.unwrap();

        let mut prelude = [0_u8; 6];
        upstream_side.read_exact(&mut prelude).await.unwrap();
        assert_eq!(&prelude, b"hello\n");

        let mut payload = [0_u8; 4];
        upstream_side.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");

        upstream_side.write_all(b"pong").await.unwrap();
        let mut response = [0_u8; 4];
        client_side.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        drop(client_side);
        drop(upstream_side);
        task.await.unwrap();
    }
}
