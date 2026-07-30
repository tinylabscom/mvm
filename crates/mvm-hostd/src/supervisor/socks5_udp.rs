//! Policy-gated SOCKS5 UDP Associate relay over the egress vsock stream.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::io::{Read, Write};

use mvm_core::socks5_udp::{self, Address, Datagram};
use mvm_runtime::vmm::egress_gate::{EgressGate, EgressVerdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::supervisor::raw_egress;

/// First-line marker selecting the SOCKS5 UDP relay on the shared egress stream.
pub const FRAME_LINE: &str = mvm_core::socks5_udp::FRAME_LINE;

/// Serve one SOCKS5 UDP association over an asynchronous egress stream.
pub async fn serve<S>(mut guest: S, gate: &EgressGate, timeout: Duration) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ipv4 = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let ipv6 = tokio::net::UdpSocket::bind("[::]:0").await.ok();
    while let Some(frame) = read_frame_async(&mut guest, timeout).await? {
        let packet = Datagram::decode(&frame).map_err(invalid_datagram)?;
        let Some(response) = relay_async(&packet, gate, &ipv4, ipv6.as_ref(), timeout).await?
        else {
            continue;
        };
        write_frame_async(&mut guest, &response, timeout).await?;
    }
    Ok(())
}

async fn relay_async(
    packet: &Datagram,
    gate: &EgressGate,
    ipv4: &tokio::net::UdpSocket,
    ipv6: Option<&tokio::net::UdpSocket>,
    timeout: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
    let target = packet.address.target(packet.port);
    let (ips, port) = match gate.decide_udp_request_with(&target, |host| {
        raw_egress::resolve_hostname_ips_pure(host, timeout)
    }) {
        EgressVerdict::Allow { ips, port } => (ips, port),
        // A refused datagram is answered with silence (SOCKS UDP has no error
        // reply), so the reason is logged host-side rather than dropped.
        EgressVerdict::Deny(reason) => {
            tracing::debug!(%target, %reason, "socks5-udp: refusing datagram");
            return Ok(None);
        }
        EgressVerdict::Malformed => {
            tracing::debug!(%target, "socks5-udp: refusing malformed datagram target");
            return Ok(None);
        }
    };

    let mut sent = false;
    for ip in &ips {
        let destination = SocketAddr::new(*ip, port);
        let socket = match ip {
            IpAddr::V4(_) => ipv4,
            IpAddr::V6(_) => match ipv6 {
                Some(socket) => socket,
                None => continue,
            },
        };
        socket.send_to(&packet.payload, destination).await?;
        sent = true;
    }
    if !sent {
        return Ok(None);
    }

    let response =
        match tokio::time::timeout(timeout, receive_matching_async(ipv4, ipv6, &ips, port)).await {
            Ok(response) => response?,
            Err(_) => return Ok(None),
        };
    Ok(response.map(|(payload, source)| {
        Datagram {
            address: Address::Ip(source.ip()),
            port: source.port(),
            payload,
        }
        .encode()
        .expect("socket addresses always encode")
    }))
}

async fn receive_matching_async(
    ipv4: &tokio::net::UdpSocket,
    ipv6: Option<&tokio::net::UdpSocket>,
    ips: &[IpAddr],
    port: u16,
) -> std::io::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut ipv4_buffer = vec![0_u8; socks5_udp::MAX_DATAGRAM_BYTES];
    let mut ipv6_buffer = vec![0_u8; socks5_udp::MAX_DATAGRAM_BYTES];
    loop {
        let received = match ipv6 {
            Some(ipv6) => {
                tokio::select! {
                    result = ipv4.recv_from(&mut ipv4_buffer) => {
                        let (length, source) = result?;
                        (length, source, &ipv4_buffer)
                    },
                    result = ipv6.recv_from(&mut ipv6_buffer) => {
                        let (length, source) = result?;
                        (length, source, &ipv6_buffer)
                    },
                }
            }
            None => {
                let (length, source) = ipv4.recv_from(&mut ipv4_buffer).await?;
                (length, source, &ipv4_buffer)
            }
        };
        let (length, source, buffer) = received;
        if source.port() == port && ips.iter().any(|ip| *ip == source.ip()) {
            return Ok(Some((buffer[..length].to_vec(), source)));
        }
    }
}

/// Serve one SOCKS5 UDP association over a blocking AF_VSOCK stream.
#[cfg(target_os = "linux")]
pub fn serve_blocking(
    mut guest: std::fs::File,
    gate: &EgressGate,
    timeout: Duration,
) -> std::io::Result<()> {
    let ipv4 = std::net::UdpSocket::bind("0.0.0.0:0")?;
    ipv4.set_read_timeout(Some(timeout))?;
    ipv4.set_write_timeout(Some(timeout))?;
    let ipv6 = std::net::UdpSocket::bind("[::]:0").ok();
    if let Some(socket) = &ipv6 {
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
    }
    while let Some(frame) = read_frame_blocking(&mut guest)? {
        let packet = Datagram::decode(&frame).map_err(invalid_datagram)?;
        let Some(response) = relay_blocking(&packet, gate, &ipv4, ipv6.as_ref(), timeout)? else {
            continue;
        };
        write_frame_blocking(&mut guest, &response)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn relay_blocking(
    packet: &Datagram,
    gate: &EgressGate,
    ipv4: &std::net::UdpSocket,
    ipv6: Option<&std::net::UdpSocket>,
    timeout: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
    let target = packet.address.target(packet.port);
    let (ips, port) = match gate.decide_udp_request_with(&target, |host| {
        raw_egress::resolve_hostname_ips_pure(host, timeout)
    }) {
        EgressVerdict::Allow { ips, port } => (ips, port),
        EgressVerdict::Deny(reason) => {
            tracing::debug!(%target, %reason, "socks5-udp: refusing datagram");
            return Ok(None);
        }
        EgressVerdict::Malformed => {
            tracing::debug!(%target, "socks5-udp: refusing malformed datagram target");
            return Ok(None);
        }
    };
    let mut selected = None;
    for ip in &ips {
        let socket = match ip {
            IpAddr::V4(_) => ipv4,
            IpAddr::V6(_) => match ipv6 {
                Some(socket) => socket,
                None => continue,
            },
        };
        socket.send_to(&packet.payload, SocketAddr::new(*ip, port))?;
        selected = Some((socket, *ip));
    }
    let Some((socket, expected_ip)) = selected else {
        return Ok(None);
    };
    let mut buffer = vec![0_u8; socks5_udp::MAX_DATAGRAM_BYTES];
    loop {
        let (length, source) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if source.ip() == expected_ip && source.port() == port {
            let response = Datagram {
                address: Address::Ip(source.ip()),
                port: source.port(),
                payload: buffer[..length].to_vec(),
            }
            .encode()
            .expect("socket addresses always encode");
            return Ok(Some(response));
        }
    }
}

async fn read_frame_async<S>(stream: &mut S, timeout: Duration) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > socks5_udp::MAX_DATAGRAM_BYTES {
        return Err(invalid_frame());
    }
    let mut frame = vec![0_u8; length];
    with_timeout(timeout, stream.read_exact(&mut frame)).await?;
    Ok(Some(frame))
}

async fn write_frame_async<S>(
    stream: &mut S,
    frame: &[u8],
    timeout: Duration,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(frame.len()).map_err(|_| invalid_frame())?;
    with_timeout(timeout, stream.write_all(&length.to_be_bytes())).await?;
    with_timeout(timeout, stream.write_all(frame)).await?;
    with_timeout(timeout, stream.flush()).await
}

#[cfg(target_os = "linux")]
fn read_frame_blocking(stream: &mut std::fs::File) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 2];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > socks5_udp::MAX_DATAGRAM_BYTES {
        return Err(invalid_frame());
    }
    let mut frame = vec![0_u8; length];
    stream.read_exact(&mut frame)?;
    Ok(Some(frame))
}

#[cfg(target_os = "linux")]
fn write_frame_blocking(stream: &mut std::fs::File, frame: &[u8]) -> std::io::Result<()> {
    let length = u16::try_from(frame.len()).map_err(|_| invalid_frame())?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()
}

async fn with_timeout<T>(
    timeout: Duration,
    operation: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| timed_out())?
}

fn invalid_datagram(_error: socks5_udp::DecodeError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "malformed SOCKS5 UDP datagram",
    )
}

fn invalid_frame() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid SOCKS5 UDP frame length",
    )
}

fn timed_out() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 UDP relay timed out")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::projection::CanonicalEgress;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn exchange(client: &mut tokio::io::DuplexStream, packet: &Datagram) -> Option<Datagram> {
        let frame = packet.encode().expect("test packet encodes");
        client
            .write_all(
                &u16::try_from(frame.len())
                    .expect("test frame fits")
                    .to_be_bytes(),
            )
            .await
            .expect("write length");
        client.write_all(&frame).await.expect("write frame");
        let mut length = [0_u8; 2];
        match tokio::time::timeout(Duration::from_millis(200), client.read_exact(&mut length)).await
        {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return None,
        }
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        client
            .read_exact(&mut response)
            .await
            .expect("read response");
        Some(Datagram::decode(&response).expect("response decodes"))
    }

    #[tokio::test]
    async fn default_deny_drops_udp_without_host_send() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(4096);
        let task =
            tokio::spawn(async move { serve(server, &gate, Duration::from_millis(100)).await });
        let packet = Datagram {
            address: Address::Ip("192.0.2.1".parse().expect("valid address")),
            port: 5353,
            payload: b"query".to_vec(),
        };
        assert!(exchange(&mut client, &packet).await.is_none());
        drop(client);
        task.await
            .expect("handler joins")
            .expect("handler succeeds");
    }

    #[tokio::test]
    async fn malformed_frame_fails_closed() {
        let gate = EgressGate::new(CanonicalEgress::Unrestricted);
        let (mut client, server) = tokio::io::duplex(32);
        let task = tokio::spawn(async move { serve(server, &gate, Duration::from_secs(1)).await });
        client
            .write_all(&[0, 3, 0, 0, 0])
            .await
            .expect("write malformed");
        let error = task
            .await
            .expect("handler joins")
            .expect_err("rejects malformed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
