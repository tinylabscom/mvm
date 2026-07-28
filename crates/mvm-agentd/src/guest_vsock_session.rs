//! Shared guest-side host-vsock session lifecycle helpers.
//!
//! The guest helpers in this crate share one transport shape:
//! dial a host vsock port, write one framing prelude that tells the
//! host what to do with the stream, then splice bytes both ways.
//! The guest stays responsible for the exact prelude bytes, and the
//! host stays responsible for all admission/policy decisions.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use mvm_core::guest_netd::ConnectAck;

/// Guest→host vsock stream. A native async AF_VSOCK stream on Linux guests
/// (the only place a microVM ever runs), and a never-constructed stand-in on
/// other hosts so the addon helper bins still `cargo check` during macOS
/// development — there `connect` fails closed with `Unsupported` and this type
/// is a signature placeholder that is never built.
#[cfg(target_os = "linux")]
pub type HostVsockStream = tokio_vsock::VsockStream;
#[cfg(not(target_os = "linux"))]
pub type HostVsockStream = tokio::net::TcpStream;

/// CID of the host end of an AF_VSOCK link, as seen from inside a guest.
#[cfg(target_os = "linux")]
const HOST_CID: u32 = 2;

/// One guest-initiated session to a host AF_VSOCK port.
pub struct HostVsockSession<U> {
    upstream: U,
}

impl HostVsockSession<HostVsockStream> {
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

/// Open a native async AF_VSOCK stream to the host.
///
/// The error is left with its OS `ErrorKind` intact — a caller can still tell
/// connect-refused / timed-out / reset apart — and carries the host CID+port as
/// context.
#[cfg(target_os = "linux")]
pub async fn connect_host_vsock(port: u32) -> std::io::Result<HostVsockStream> {
    use tokio_vsock::{VsockAddr, VsockStream};

    VsockStream::connect(VsockAddr::new(HOST_CID, port))
        .await
        .map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("AF_VSOCK dial to host cid={HOST_CID} port={port} failed: {err}"),
            )
        })
}

/// Non-Linux hosts have no AF_VSOCK guest endpoint. Fail closed so the addon
/// helper bins compile during macOS development but never pretend to reach a
/// host.
#[cfg(not(target_os = "linux"))]
pub async fn connect_host_vsock(_port: u32) -> std::io::Result<HostVsockStream> {
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

    #[tokio::test]
    async fn read_connect_ack_maps_host_byte() {
        let (mut host_side, guest_bridge) = tokio::io::duplex(8);
        let mut session = HostVsockSession::new(guest_bridge);

        host_side
            .write_all(&[ConnectAck::Ok.as_byte()])
            .await
            .unwrap();
        assert_eq!(session.read_connect_ack().await, ConnectAck::Ok);

        host_side.write_all(&[0xFF]).await.unwrap();
        assert_eq!(session.read_connect_ack().await, ConnectAck::Fail);
    }

    #[tokio::test]
    async fn read_connect_ack_treats_eof_as_fail() {
        let (host_side, guest_bridge) = tokio::io::duplex(8);
        let mut session = HostVsockSession::new(guest_bridge);

        drop(host_side);
        assert_eq!(session.read_connect_ack().await, ConnectAck::Fail);
    }
}
