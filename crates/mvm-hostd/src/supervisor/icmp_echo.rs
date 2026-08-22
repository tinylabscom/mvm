//! Host-side ICMP echo, performed on a guest's behalf.
//!
//! The guest has no NIC and no raw socket, so it cannot originate ICMP at all.
//! The host owns the only network stack in the picture and echoes for it, which
//! keeps the vsock-only invariant intact: no IP ever leaves the guest, and the
//! destination is decided by the same claim-10 gate every other egress verb uses.
//!
//! The socket is `SOCK_DGRAM`/`IPPROTO_ICMP` — the unprivileged "ping socket",
//! available to an ordinary user on macOS and on Linux when
//! `net.ipv4.ping_group_range` covers the process. It is deliberately *not*
//! `SOCK_RAW`: raw would need `CAP_NET_RAW`/root and would let this code read
//! every ICMP packet on the host, which is far more authority than echoing one
//! admitted destination needs. When the kernel refuses the socket, echo reports
//! that plainly rather than escalating.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

/// ICMPv4 echo request/reply message types.
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
/// ICMPv6 echo request/reply message types.
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
/// Bytes of ICMP header before the payload: type, code, checksum, id, seq.
const ICMP_HEADER_LEN: usize = 8;
/// Receive buffer: the largest payload we ever send, plus both headers and room
/// for an IPv4 header some kernels prepend on the ping socket.
const RECV_BUF_LEN: usize = mvm_core::icmp_wire::MAX_PAYLOAD_LEN as usize + 128;

/// One echo attempt's outcome: the round trip, or `None` when it timed out.
pub type EchoOutcome = Option<Duration>;

/// Sends one ICMP echo and waits for its reply.
///
/// A trait so the request handler can be exercised without a network or a
/// kernel that permits ping sockets — the handler's job is admission, bounds and
/// framing, and that logic should be testable on its own.
pub trait EchoTransport: Send + Sync {
    /// Echo `ip` once with sequence `seq` and `payload_len` payload bytes,
    /// waiting at most `timeout`. `Ok(None)` is a timeout, which is an ordinary
    /// result rather than a failure; `Err` means the echo could not be attempted.
    fn echo(
        &self,
        ip: IpAddr,
        seq: u16,
        payload_len: u16,
        timeout: Duration,
    ) -> io::Result<EchoOutcome>;
}

/// The real transport: one unprivileged ping socket per echo.
///
/// A socket per echo rather than one reused across a request keeps replies
/// unambiguous without an in-flight table — the kernel may rewrite the ICMP id,
/// so a shared socket would need sequence matching against concurrent requests.
/// Echoes are at most [`MAX_ECHO_COUNT`] per request and paced by their own
/// round trips, so the socket churn is not a hot path.
///
/// [`MAX_ECHO_COUNT`]: mvm_core::icmp_wire::MAX_ECHO_COUNT
pub struct PingSocketEcho;

impl EchoTransport for PingSocketEcho {
    fn echo(
        &self,
        ip: IpAddr,
        seq: u16,
        payload_len: u16,
        timeout: Duration,
    ) -> io::Result<EchoOutcome> {
        let socket = IcmpSocket::open(ip)?;
        socket.set_recv_timeout(timeout)?;
        let request = build_echo_request(ip, seq, payload_len);
        let started = Instant::now();
        socket.send_to(&request, ip)?;
        loop {
            let remaining = timeout.checked_sub(started.elapsed());
            let Some(remaining) = remaining.filter(|r| !r.is_zero()) else {
                return Ok(None);
            };
            socket.set_recv_timeout(remaining)?;
            match socket.recv(&mut [0u8; RECV_BUF_LEN]) {
                // A datagram arrived but was not our reply (a stale echo, or
                // another message the kernel delivered). Keep waiting out the
                // remaining budget rather than reporting a false timeout.
                Ok(None) => continue,
                Ok(Some(())) => return Ok(Some(started.elapsed())),
                Err(e) if is_timeout(&e) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
}

/// Whether an error is a receive timeout rather than a real failure.
fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// An owned unprivileged ICMP socket for one address family.
struct IcmpSocket {
    fd: OwnedFd,
    v6: bool,
    /// Sequence this socket is waiting on, so a stray datagram is not counted.
    seq: std::cell::Cell<u16>,
}

impl IcmpSocket {
    fn open(ip: IpAddr) -> io::Result<Self> {
        let (domain, proto, v6) = match ip {
            IpAddr::V4(_) => (libc::AF_INET, libc::IPPROTO_ICMP, false),
            IpAddr::V6(_) => (libc::AF_INET6, libc::IPPROTO_ICMPV6, true),
        };
        // SAFETY: a plain socket(2) with constant arguments; the returned fd is
        // adopted by OwnedFd below and closed on drop.
        let raw = unsafe { libc::socket(domain, libc::SOCK_DGRAM, proto) };
        if raw < 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "open unprivileged ICMP socket: {error}. On Linux this needs \
                     net.ipv4.ping_group_range to cover this process's group"
                ),
            ));
        }
        // SAFETY: `raw` is a fresh fd this call owns and has not shared.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd,
            v6,
            seq: std::cell::Cell::new(0),
        })
    }

    fn set_recv_timeout(&self, timeout: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: `tv` outlives the call and its length is the size of the type
        // the option expects.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::from_ref(&tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn send_to(&self, packet: &[u8], ip: IpAddr) -> io::Result<()> {
        let (addr, len) = sockaddr_for(ip);
        self.seq.set(sequence_of(packet).unwrap_or(0));
        // SAFETY: `packet` and `addr` are live for the call; `len` is the
        // matching sockaddr length for the family.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                0,
                std::ptr::from_ref(&addr).cast(),
                len,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read one datagram. `Ok(Some(()))` is our echo reply; `Ok(None)` is a
    /// datagram that was not (keep waiting).
    fn recv(&self, buf: &mut [u8; RECV_BUF_LEN]) -> io::Result<Option<()>> {
        // SAFETY: `buf` is a live, correctly sized buffer for the call.
        let got = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let datagram = &buf[..got as usize];
        Ok(is_our_echo_reply(datagram, self.v6, self.seq.get()).then_some(()))
    }
}

/// Whether `datagram` is the echo reply we are waiting for.
///
/// Some kernels hand the ping socket the IPv4 header as well, so an IPv4 header
/// is skipped when present. The ICMP id is deliberately not matched: the kernel
/// rewrites it on a ping socket, so the sequence number is the only field that
/// survives the round trip unchanged.
fn is_our_echo_reply(datagram: &[u8], v6: bool, seq: u16) -> bool {
    let icmp = strip_ipv4_header(datagram);
    if icmp.len() < ICMP_HEADER_LEN {
        return false;
    }
    let expected_type = if v6 {
        ICMPV6_ECHO_REPLY
    } else {
        ICMPV4_ECHO_REPLY
    };
    icmp[0] == expected_type && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

/// Drop a leading IPv4 header when the kernel included one.
fn strip_ipv4_header(datagram: &[u8]) -> &[u8] {
    if datagram.len() < 20 || datagram[0] >> 4 != 4 {
        return datagram;
    }
    let header_len = usize::from(datagram[0] & 0x0f) * 4;
    // An IHL below the 20-byte minimum is not a header we understand; leave the
    // datagram alone rather than slicing on a nonsense length.
    if !(20..=datagram.len()).contains(&header_len) {
        return datagram;
    }
    &datagram[header_len..]
}

/// The sequence number carried by an echo request we built.
fn sequence_of(packet: &[u8]) -> Option<u16> {
    (packet.len() >= ICMP_HEADER_LEN).then(|| u16::from_be_bytes([packet[6], packet[7]]))
}

/// Build an echo request for `ip`.
///
/// The IPv4 checksum is computed here because the ping socket does not fill it
/// on every platform. ICMPv6's checksum covers a pseudo-header the kernel owns,
/// so it is left zero for the kernel to complete — writing one here would be
/// wrong on both counts.
fn build_echo_request(ip: IpAddr, seq: u16, payload_len: u16) -> Vec<u8> {
    let v6 = ip.is_ipv6();
    let mut packet = vec![0u8; ICMP_HEADER_LEN + usize::from(payload_len)];
    packet[0] = if v6 {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMPV4_ECHO_REQUEST
    };
    packet[1] = 0;
    // [2..4] checksum, filled below for v4.
    // [4..6] id: left zero; the kernel assigns the ping socket's own id.
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    // A recognisable, non-secret payload pattern, the same shape ping uses.
    for (offset, byte) in packet[ICMP_HEADER_LEN..].iter_mut().enumerate() {
        *byte = (offset % 256) as u8;
    }
    if !v6 {
        let sum = internet_checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// The 16-bit one's-complement checksum from RFC 1071.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for pair in chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A `sockaddr_storage` for `ip` with port zero (ICMP has no port), plus its
/// family-correct length.
fn sockaddr_for(ip: IpAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            // SAFETY: `storage` is at least as large and as aligned as
            // `sockaddr_in`, and is zeroed above.
            let addr =
                unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in>() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            (storage, len)
        }
        IpAddr::V6(v6) => {
            let len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            // SAFETY: as above, for the v6 layout.
            let addr =
                unsafe { &mut *std::ptr::from_mut(&mut storage).cast::<libc::sockaddr_in6>() };
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_port = 0;
            addr.sin6_addr.s6_addr = v6.octets();
            (storage, len)
        }
    }
}

/// Unused-import guard: these types name the families this module handles.
const _: Option<(Ipv4Addr, Ipv6Addr, SocketAddr)> = None;

#[cfg(test)]
mod tests {
    use super::*;

    /// Opt-in live check: proves the unprivileged ping socket actually opens and
    /// round-trips on this host. Ignored by default because it needs the network
    /// and a kernel that permits ping sockets; run with
    /// `cargo test -p mvm-hostd icmp_echo -- --ignored`.
    #[test]
    #[ignore = "requires network and an unprivileged ICMP socket"]
    fn live_echo_round_trips_to_a_public_resolver() {
        let outcome = PingSocketEcho
            .echo(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                1,
                56,
                Duration::from_secs(3),
            )
            .expect("ping socket must open and send");
        let rtt = outcome.expect("a public resolver should answer within 3s");
        assert!(
            rtt < Duration::from_secs(3),
            "round trip {rtt:?} exceeded the timeout"
        );
    }

    #[test]
    fn checksum_matches_the_rfc1071_worked_example() {
        // RFC 1071 §3's example octets and their expected one's-complement sum.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_handles_an_odd_length_by_padding_the_tail() {
        // The trailing byte is summed as a high-order octet, not dropped.
        assert_ne!(
            internet_checksum(&[0x00, 0x00, 0xff]),
            internet_checksum(&[0x00, 0x00])
        );
    }

    /// A built request must be a well-formed echo whose own checksum verifies —
    /// a packet whose checksum covers the wrong bytes is silently dropped by the
    /// destination and reads to the caller as 100% loss.
    #[test]
    fn ipv4_request_is_a_valid_echo_with_a_verifying_checksum() {
        let packet = build_echo_request(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 7, 56);
        assert_eq!(packet.len(), ICMP_HEADER_LEN + 56);
        assert_eq!(packet[0], ICMPV4_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 7);
        // Summing a correct packet including its checksum yields zero.
        assert_eq!(internet_checksum(&packet), 0);
    }

    /// ICMPv6's checksum covers a pseudo-header only the kernel can build, so
    /// the packet must leave it zero rather than carrying a wrong one.
    #[test]
    fn ipv6_request_leaves_the_checksum_for_the_kernel() {
        let packet = build_echo_request(IpAddr::V6(Ipv6Addr::LOCALHOST), 3, 16);
        assert_eq!(packet[0], ICMPV6_ECHO_REQUEST);
        assert_eq!(&packet[2..4], &[0, 0]);
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 3);
    }

    #[test]
    fn reply_matching_accepts_our_sequence_and_rejects_others() {
        let mut reply = vec![0u8; ICMP_HEADER_LEN];
        reply[0] = ICMPV4_ECHO_REPLY;
        reply[6..8].copy_from_slice(&9u16.to_be_bytes());

        assert!(is_our_echo_reply(&reply, false, 9));
        assert!(!is_our_echo_reply(&reply, false, 8), "wrong sequence");
        assert!(!is_our_echo_reply(&reply, true, 9), "wrong family");

        // An echo *request* looped back is not a reply.
        let mut request = reply.clone();
        request[0] = ICMPV4_ECHO_REQUEST;
        assert!(!is_our_echo_reply(&request, false, 9));
    }

    /// Kernels differ on whether the ping socket includes the IPv4 header, so
    /// matching has to work either way — otherwise echo reports 100% loss on
    /// exactly one platform.
    #[test]
    fn reply_matching_tolerates_a_leading_ipv4_header() {
        let mut icmp = vec![0u8; ICMP_HEADER_LEN];
        icmp[0] = ICMPV4_ECHO_REPLY;
        icmp[6..8].copy_from_slice(&4u16.to_be_bytes());

        let mut with_header = vec![0u8; 20];
        with_header[0] = 0x45; // IPv4, IHL 5 → 20 bytes.
        with_header.extend_from_slice(&icmp);

        assert!(is_our_echo_reply(&with_header, false, 4));
        assert!(
            is_our_echo_reply(&icmp, false, 4),
            "bare ICMP still matches"
        );
    }

    #[test]
    fn short_or_nonsense_datagrams_are_not_replies() {
        assert!(!is_our_echo_reply(&[], false, 0));
        assert!(!is_our_echo_reply(&[0u8; 4], false, 0));
        // Claims IPv4 with an impossible IHL — must not panic or slice wrongly.
        let mut bogus = vec![0u8; 24];
        bogus[0] = 0x4f; // IHL 15 → 60 bytes, longer than the datagram.
        assert!(!is_our_echo_reply(&bogus, false, 0));
    }
}
