//! Per-association UDP datagram relay and its address codec.
//!
//! One FlowMux `OpenUdp` flow becomes one relay thread that owns the upstream
//! socket. Datagrams arriving from upstream are framed as `UdpRecv`; guest
//! `UdpSend` requests reach the socket through a channel so ownership stays
//! with the single relay thread. Both directions carry the peer address in the
//! wire prefix this module encodes and decodes.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use mvm_contract::protocol::network_flow::{MAX_UDP_DATAGRAM_LEN, Opcode, UDP_ADDR_PREFIX_LEN};
use mvm_core::net::session::Session;
use tracing::warn;

use super::registry::StreamRegistry;
use super::{lock_registry, write_frame_to};

/// A request from the main session thread to a UDP relay thread to send one
/// datagram to an admitted destination.
pub(super) struct UdpSendMsg {
    pub(super) destination: SocketAddr,
    pub(super) payload: Vec<u8>,
}

/// The host-side handle for one active UDP association. The relay thread owns
/// the socket; the main thread forwards guest `UdpSend` frames through a
/// channel.
pub(super) struct UdpAssociationHandle {
    pub(super) tx: std::sync::mpsc::Sender<UdpSendMsg>,
    pub(super) waker: Arc<Waker>,
    pub(super) peer_admission: UdpPeerAdmission,
}

/// Parameters for the per-association UDP relay thread.
#[derive(Debug)]
pub(super) struct UdpRelayParams {
    pub(super) stream_id: u32,
    pub(super) socket: std::net::UdpSocket,
    pub(super) poll: Poll,
    pub(super) session: Arc<Mutex<Session>>,
    pub(super) writer: Arc<Mutex<UnixStream>>,
    pub(super) idle_timeout: Duration,
    pub(super) max_peers: usize,
    pub(super) peer_admission: UdpPeerAdmission,
    pub(super) rx: std::sync::mpsc::Receiver<UdpSendMsg>,
    pub(super) registry: Arc<Mutex<StreamRegistry>>,
}

/// Whether a guest datagram may introduce a peer or may only answer one that
/// previously sent to the host socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UdpPeerAdmission {
    /// Outbound association: the guest selects admitted destinations.
    GuestMayIntroduce,
    /// Ingress mapping: the guest may reply only to observed external peers.
    ObservedOnly,
}

/// Per-association UDP relay thread: read datagrams from the upstream socket
/// and forward them to the guest as `UdpRecv` frames. Guest `UdpSend`
/// requests arrive through a channel so the socket stays owned by one thread.
///
/// The relay enforces two association bounds: a limit on distinct peers and
/// an idle timeout that closes the association when no bytes flow in either
/// direction for too long.
pub(super) fn run_udp_relay(params: UdpRelayParams) {
    let UdpRelayParams {
        stream_id,
        socket,
        mut poll,
        session,
        writer,
        idle_timeout,
        max_peers,
        peer_admission,
        rx,
        registry,
    } = params;

    let mut buf = vec![0_u8; MAX_UDP_DATAGRAM_LEN];
    let mut events = Events::with_capacity(4);
    let mut peers: BTreeSet<SocketAddr> = BTreeSet::new();
    let mut last_activity = std::time::Instant::now();
    let mut idle_expired = false;
    let mut guest_closed = false;
    let mut relay_failed = false;

    loop {
        let remaining = idle_timeout.saturating_sub(last_activity.elapsed());
        if remaining.is_zero() {
            idle_expired = true;
            break;
        }
        if let Err(error) = poll.poll(&mut events, Some(remaining)) {
            warn!(stream_id, %error, "FlowMux UDP event wait failed");
            relay_failed = true;
            break;
        }
        if events.is_empty() {
            idle_expired = true;
            break;
        }

        let mut activity_this_iter = false;
        for event in &events {
            match event.token() {
                UDP_SOCKET => loop {
                    match socket.recv_from(&mut buf) {
                        Ok((len, source)) => {
                            activity_this_iter = true;
                            let already_peer = peers.contains(&source);
                            if !already_peer && peers.len() >= max_peers {
                                continue;
                            }
                            peers.insert(source);
                            let mut payload = encode_udp_addr(source.ip(), source.port());
                            payload.extend_from_slice(&buf[..len]);
                            let frame_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
                            if let Err(e) =
                                lock_registry(&registry).consume_host_credit(stream_id, frame_len)
                            {
                                warn!(stream_id, error = %e, "FlowMux UDP host credit exhausted");
                                let _ = write_frame_to(
                                    &session,
                                    &writer,
                                    Opcode::Reset,
                                    stream_id,
                                    b"host credit exhausted",
                                );
                                relay_failed = true;
                                break;
                            }
                            if write_frame_to(
                                &session,
                                &writer,
                                Opcode::UdpRecv,
                                stream_id,
                                &payload,
                            )
                            .is_err()
                            {
                                relay_failed = true;
                                break;
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => {
                            warn!(stream_id, %error, "FlowMux UDP recv failed");
                            relay_failed = true;
                            break;
                        }
                    }
                },
                UDP_WAKE => loop {
                    match rx.try_recv() {
                        Ok(msg) => {
                            activity_this_iter = true;
                            let already_peer = peers.contains(&msg.destination);
                            if !already_peer {
                                if peer_admission == UdpPeerAdmission::ObservedOnly
                                    || peers.len() >= max_peers
                                {
                                    continue;
                                }
                                peers.insert(msg.destination);
                            }
                            if let Err(error) = socket.send_to(&msg.payload, msg.destination) {
                                warn!(stream_id, %error, "FlowMux UDP send failed");
                                relay_failed = true;
                                break;
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            guest_closed = true;
                            break;
                        }
                    }
                },
                _ => {}
            }
            if guest_closed || relay_failed {
                break;
            }
        }

        if activity_this_iter {
            last_activity = std::time::Instant::now();
        }
        if guest_closed || relay_failed {
            break;
        }
    }

    let _ = lock_registry(&registry).retire(stream_id);
    if idle_expired {
        let _ = write_frame_to(
            &session,
            &writer,
            Opcode::CloseUdp,
            stream_id,
            b"idle timeout",
        );
    } else if relay_failed {
        let _ = write_frame_to(
            &session,
            &writer,
            Opcode::Reset,
            stream_id,
            b"UDP relay error",
        );
    }
}

pub(super) const UDP_SOCKET: Token = Token(0);
pub(super) const UDP_WAKE: Token = Token(1);

pub(super) fn udp_event_sources(
    socket: &std::net::UdpSocket,
) -> std::io::Result<(Poll, Arc<Waker>)> {
    socket.set_nonblocking(true)?;
    let poll = Poll::new()?;
    let fd = socket.as_raw_fd();
    let mut source = SourceFd(&fd);
    poll.registry()
        .register(&mut source, UDP_SOCKET, Interest::READABLE)?;
    let waker = Arc::new(Waker::new(poll.registry(), UDP_WAKE)?);
    Ok((poll, waker))
}

/// Encode a UDP address prefix: one family tag, a 16-byte address slot, and a
/// big-endian port. IPv4 is carried as an IPv4-mapped IPv6 address under tag
/// `0x01`; IPv6 uses tag `0x04`.
pub(super) fn encode_udp_addr(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDP_ADDR_PREFIX_LEN);
    match ip {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&[0; 10]);
            out.extend_from_slice(&[0xff, 0xff]);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Decode a UDP address prefix. Returns the address, port, and the remaining
/// payload bytes (the datagram body).
pub(super) fn decode_udp_addr(bytes: &[u8]) -> Result<(IpAddr, u16, &[u8]), String> {
    if bytes.len() < UDP_ADDR_PREFIX_LEN {
        return Err(format!(
            "UdpSend prefix too short: {} < {}",
            bytes.len(),
            UDP_ADDR_PREFIX_LEN
        ));
    }
    let tag = bytes[0];
    let addr_bytes: [u8; 16] = bytes[1..17]
        .try_into()
        .map_err(|_| "address slot truncated".to_string())?;
    let port = u16::from_be_bytes([bytes[17], bytes[18]]);

    let ip = match tag {
        0x01 => match IpAddr::from(addr_bytes) {
            IpAddr::V6(v6) => IpAddr::from(
                v6.to_ipv4_mapped()
                    .ok_or_else(|| "IPv4-mapped address expected".to_string())?,
            ),
            IpAddr::V4(_) => return Err("IPv4-mapped address expected".to_string()),
        },
        0x04 => IpAddr::from(addr_bytes),
        _ => return Err(format!("unknown UDP address family tag: {tag}")),
    };

    Ok((ip, port, &bytes[UDP_ADDR_PREFIX_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_addr_roundtrips_ipv4_and_ipv6() {
        let (ip4, port4) = ("192.0.2.10".parse::<std::net::IpAddr>().unwrap(), 5353);
        let encoded4 = encode_udp_addr(ip4, port4);
        let (decoded4_ip, decoded4_port, rest4) = decode_udp_addr(&encoded4).unwrap();
        assert_eq!(decoded4_ip, ip4);
        assert_eq!(decoded4_port, port4);
        assert!(rest4.is_empty());

        let (ip6, port6) = ("2001:db8::1".parse::<std::net::IpAddr>().unwrap(), 443);
        let encoded6 = encode_udp_addr(ip6, port6);
        let (decoded6_ip, decoded6_port, rest6) = decode_udp_addr(&encoded6).unwrap();
        assert_eq!(decoded6_ip, ip6);
        assert_eq!(decoded6_port, port6);
        assert!(rest6.is_empty());
    }
}
