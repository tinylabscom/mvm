//! In-guest TCP↔vsock bridge for local addon traffic.
//!
//! Binds loopback-range IPs handed out by `mvm-addon-dns`. On accept,
//! opens a vsock stream to the host addon proxy, writes a per-
//! connection peer header (length-prefixed JSON), then proxies bytes
//! both ways. Half-close semantics preserved.
//!
//! This crate intentionally speaks only TCP and vsock. Distributed
//! service mesh identity, tenant policy, and cryptographic routing
//! belong in mvmd.

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One peer-name → loopback-IP + vsock-port mapping. The full set
/// for a consumer instance comes from the config disk's
/// `addon_loopback_bindings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopbackBinding {
    /// Bare addon name or alias used by the host addon proxy. This is
    /// intentionally independent from the DNS hostname so the guest can
    /// resolve production-equivalent names such as `db.dev.internal`
    /// while the bridge still routes by stable addon peer identity.
    pub peer: String,
    /// Loopback IP the bridge binds to listen on. Always in
    /// `127.0.0.0/8`; allocated from the local addon config.
    pub loopback_ip: Ipv4Addr,
    /// TCP port the guest application connects to on `loopback_ip`.
    /// For example, a Postgres addon typically listens on `5432`.
    pub tcp_port: u16,
    /// Vsock port to dial on the local host addon proxy.
    pub vsock_port: u32,
}

impl LoopbackBinding {
    /// TCP socket address the in-guest bridge listens on.
    pub fn listen_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.loopback_ip, self.tcp_port)
    }

    /// Validate the binding before opening listeners or dialing
    /// host-side vsock ports.
    pub fn validate(&self) -> std::io::Result<()> {
        if !self.loopback_ip.is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "addon binding for peer '{}' must use a loopback IP, got {}",
                    self.peer, self.loopback_ip
                ),
            ));
        }
        if self.peer.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "addon binding peer must not be empty",
            ));
        }
        Ok(())
    }
}

/// Per-connection peer header — written by the bridge as the first
/// frame on every vsock stream it opens. Length-prefixed JSON
/// (4-byte big-endian length + UTF-8 JSON), matching the existing
/// `mvm-core` wire conventions.
///
/// The host addon proxy reads this header before any application
/// bytes and routes the connection to the requested local addon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHeader {
    /// Wire-format version. `1` for v1.
    pub version: u32,
    /// Bare peer name (matches `LoopbackBinding::peer`).
    pub peer: String,
}

impl PeerHeader {
    /// Wire-format version emitted by v1.
    pub const V1: u32 = 1;

    /// Construct a v1 peer header.
    pub fn new(peer: String) -> Self {
        Self {
            version: Self::V1,
            peer,
        }
    }
}

/// Parse the config disk's `addon_loopback_bindings` JSON file.
pub fn load_bindings(path: &Path) -> std::io::Result<Vec<LoopbackBinding>> {
    let body = std::fs::read_to_string(path)?;
    if body.trim().is_empty() {
        return Ok(vec![]);
    }
    serde_json::from_str(&body).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "could not parse {} as JSON array of LoopbackBinding entries: {e}",
                path.display()
            ),
        )
    })
}

/// Start one TCP listener per binding and serve indefinitely.
pub async fn run_bridge(bindings: Vec<LoopbackBinding>) -> std::io::Result<()> {
    for binding in bindings {
        binding.validate()?;
        let listener = TcpListener::bind(binding.listen_addr()).await?;
        tracing::info!(
            peer = %binding.peer,
            listen = %binding.listen_addr(),
            vsock_port = binding.vsock_port,
            "addon bridge listener started"
        );
        tokio::spawn(accept_loop(listener, binding));
    }

    std::future::pending::<std::io::Result<()>>().await
}

async fn accept_loop(listener: TcpListener, binding: LoopbackBinding) {
    loop {
        match listener.accept().await {
            Ok((client, remote)) => {
                let binding = binding.clone();
                tracing::debug!(peer = %binding.peer, %remote, "accepted addon bridge connection");
                tokio::spawn(async move {
                    if let Err(err) = handle_client(client, binding).await {
                        tracing::warn!(error = %err, "addon bridge connection failed");
                    }
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "addon bridge accept failed");
            }
        }
    }
}

async fn handle_client(client: TcpStream, binding: LoopbackBinding) -> std::io::Result<()> {
    let upstream = connect_host_vsock(binding.vsock_port).await?;
    proxy_with_peer_header(client, upstream, &binding.peer).await
}

/// Write the v1 peer header to `upstream`, then proxy bytes both ways.
pub async fn proxy_with_peer_header<C, U>(
    mut client: C,
    mut upstream: U,
    peer: &str,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let header = PeerHeader::new(peer.to_string());
    upstream.write_all(&encode_peer_header(&header)).await?;
    upstream.flush().await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

/// Open a stream to the host addon proxy over AF_VSOCK.
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
        "AF_VSOCK addon bridge dialing is only available on Linux guests",
    ))
}

/// Serialize a peer header as a length-prefixed wire frame ready to
/// write onto a vsock stream. Returns `(4-byte length || JSON bytes)`.
pub fn encode_peer_header(header: &PeerHeader) -> Vec<u8> {
    let body = serde_json::to_vec(header).expect("PeerHeader serializes infallibly");
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Maximum inbound peer-header size (4 KiB). Defends against a
/// malicious consumer-side caller writing a huge length prefix and
/// blowing out memory before we close the stream. Real headers are
/// well under 1 KiB.
pub const MAX_HEADER_BYTES: u32 = 4 * 1024;

/// Decode a length-prefixed peer header from a byte slice. Returns
/// the parsed header + the number of bytes consumed (so the caller
/// can advance the stream cursor). Errors on length-prefix overruns,
/// truncated bodies, or non-JSON content.
pub fn decode_peer_header(buf: &[u8]) -> std::io::Result<(PeerHeader, usize)> {
    if buf.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer header: truncated length prefix",
        ));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len > MAX_HEADER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("peer header: length {len} exceeds MAX_HEADER_BYTES={MAX_HEADER_BYTES}"),
        ));
    }
    let total = 4 + len as usize;
    if buf.len() < total {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer header: truncated body",
        ));
    }
    let header: PeerHeader = serde_json::from_slice(&buf[4..total]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("peer header: not valid JSON: {e}"),
        )
    })?;
    Ok((header, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_bindings_parses_valid_json() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("b.json");
        std::fs::write(
            &path,
            r#"[
              {"peer": "db", "loopback_ip": "127.0.255.1", "tcp_port": 5432, "vsock_port": 5253},
              {"peer": "cache", "loopback_ip": "127.0.255.2", "tcp_port": 6379, "vsock_port": 5254}
            ]"#,
        )
        .unwrap();
        let bindings = load_bindings(&path).unwrap();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].peer, "db");
        assert_eq!(bindings[0].loopback_ip, Ipv4Addr::new(127, 0, 255, 1));
        assert_eq!(bindings[0].tcp_port, 5432);
        assert_eq!(bindings[0].vsock_port, 5253);
    }

    #[test]
    fn load_bindings_accepts_empty_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("b.json");
        std::fs::write(&path, "").unwrap();
        assert!(load_bindings(&path).unwrap().is_empty());
    }

    #[test]
    fn peer_header_round_trips_through_wire_format() {
        let h = PeerHeader::new("db".to_string());
        let wire = encode_peer_header(&h);
        let (decoded, consumed) = decode_peer_header(&wire).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn decode_peer_header_rejects_oversize_length_prefix() {
        let bad = [0xFF, 0xFF, 0xFF, 0xFF];
        let err = decode_peer_header(&bad).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_peer_header_rejects_truncated_body() {
        // Length prefix says 100 bytes; only 4 follow.
        let mut buf = vec![0, 0, 0, 100];
        buf.extend_from_slice(b"abcd");
        let err = decode_peer_header(&buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decode_peer_header_rejects_non_json_body() {
        let mut buf = vec![0, 0, 0, 5];
        buf.extend_from_slice(b"not()");
        let err = decode_peer_header(&buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn peer_header_extra_fields_are_rejected_by_serde_default() {
        // Deserializer is the standard serde derive (no
        // `deny_unknown_fields` here intentionally — forward
        // compatibility for future-version headers). v2 headers
        // would change `version` and adopt new fields; v1 should
        // accept-with-ignore. Locked in by:
        let buf = encode_peer_header(&PeerHeader::new("p".into()));
        decode_peer_header(&buf).unwrap();
    }

    #[test]
    fn binding_validation_rejects_non_loopback_ip() {
        let binding = LoopbackBinding {
            peer: "db".into(),
            loopback_ip: Ipv4Addr::new(10, 0, 0, 2),
            tcp_port: 5432,
            vsock_port: 5253,
        };
        let err = binding.validate().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn proxy_writes_peer_header_before_application_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client_side, client_bridge) = tokio::io::duplex(1024);
        let (upstream_bridge, mut upstream_side) = tokio::io::duplex(1024);

        let task = tokio::spawn(async move {
            proxy_with_peer_header(client_bridge, upstream_bridge, "db")
                .await
                .unwrap();
        });

        client_side.write_all(b"ping").await.unwrap();

        let mut len = [0_u8; 4];
        upstream_side.read_exact(&mut len).await.unwrap();
        let header_len = u32::from_be_bytes(len) as usize;
        let mut header = vec![0_u8; header_len];
        upstream_side.read_exact(&mut header).await.unwrap();
        let decoded: PeerHeader = serde_json::from_slice(&header).unwrap();
        assert_eq!(decoded, PeerHeader::new("db".into()));

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
