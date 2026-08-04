//! UDP associations: a guest's datagrams, re-originated on host sockets.
//!
//! There is no connection to terminate here, so none of the deferred
//! handshake machinery the TCP path needs applies. What remains is a table
//! keyed on the guest's 4-tuple, one connected host socket per entry, and a
//! reply path that synthesizes IP+UDP back toward the guest.
//!
//! DNS never reaches this file. It is answered above the seam, by the
//! host-terminated resolver, so nothing here ever opens a socket toward a
//! nameserver and no guest can use a resolver query to reach one.
//!
//! # Destination integrity
//!
//! The same property the TCP path states, and the same two rules, because
//! translating to a socket re-derives a destination that policy already
//! checked: `connect()` is handed only the [`SocketAddr`] built from the
//! admitted flow key — never a hostname and never anything resolved, which
//! would re-enter name resolution *below* the seam that admitted the
//! address. Everything after that goes through the socket's connected
//! peer: [`std::net::UdpSocket::send`] takes no address at all, so a
//! datagram structurally cannot leave for anywhere else.
//!
//! # Off-path datagrams
//!
//! The property TCP gets for free and UDP does not. A datagram socket that
//! reads with `recv_from` accepts from **any** source, so an attacker who
//! can guess the host's ephemeral port can inject a reply the guest will
//! believe came from the destination it dialled — a spoofed DNS answer, a
//! forged QUIC initial, an off-path response to a request it never made.
//!
//! Two layers close it. The socket is connected, so the kernel itself
//! discards anything not from the association's peer before this process
//! sees it. And every datagram that does arrive is checked against the
//! admitted destination by [`from_admitted_peer`] before it is turned into
//! a packet for the guest, so the kernel's filter is verified rather than
//! assumed — the same relationship [`assert_peer_matches`] has to
//! `connect()` on the TCP side.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use mvm_net::l3::flow::FlowKey;
use mvm_protocol::l3::ip::UDP_HEADER_LEN;
use mvm_protocol::l3::ip::proto;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr};
use socket2::{Domain, Protocol, Socket, Type};

use crate::netd::datapath::DatapathError;

use super::limits::{
    ASSOCIATION_LIFETIME_MILLIS, DATAGRAMS_PER_ASSOCIATION_POLL, MAX_DATAGRAM_PAYLOAD_BYTES,
};
use super::readiness::{Watch, Watched};
use super::tcp::{is_terminal_host_error, same_host};

/// TTL on a synthesized reply. The guest is one hop away over the datapath's
/// own link, so this is only ever decremented by the guest's own receive
/// path; the conventional 64 keeps the packet indistinguishable from one a
/// real peer sent.
const DATAGRAM_HOP_LIMIT: u8 = 64;

/// Datagrams a poll refused to hand on, by reason.
///
/// Taken rather than read, so the caller folds each count into the machine's
/// metrics exactly once with no delta bookkeeping of its own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DatagramDrops {
    /// Datagrams from somewhere other than the admitted destination.
    ///
    /// Expected to be zero: the socket is connected, so the kernel drops
    /// these first. A non-zero value means the kernel's filter did not hold
    /// and this process caught an injection attempt, which is worth its own
    /// number rather than a share of anything else.
    pub off_path: u64,
    /// Replies too large for the guest's link.
    pub oversized: u64,
    /// Replies that could not be addressed to the guest at all, because the
    /// flow's remote and the guest's lease are of different families.
    ///
    /// Structurally unreachable — a remote is reached over the interface the
    /// guest's address is configured on — and counted rather than dropped
    /// for the same reason the TCP path counts a reset it could not build:
    /// the visible consequence is a guest missing an answer, so it must not
    /// be silent if the impossible happens.
    pub unaddressable: u64,
}

/// One guest datagram conversation, re-originated on a host socket.
struct Association {
    /// Connected to [`Self::peer`], so the kernel filters the receive side
    /// and the send side takes no destination. Registered on the datapath's
    /// readiness set for as long as it is open.
    socket: Watched<UdpSocket>,
    /// The admitted destination, kept for the check that verifies the
    /// kernel's filter rather than trusting it.
    peer: SocketAddr,
    /// When this association ends, taken once from the datagram that opened
    /// it and never moved. See [`ASSOCIATION_LIFETIME_MILLIS`].
    deadline_millis: u64,
}

/// Whether an association survived a poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    /// Nothing more to read this pass. Says nothing about whether anything
    /// was read — a peer with nothing to say and one that filled the pass's
    /// budget both end here.
    Idle,
    /// The host socket is finished. On a connected datagram socket this is
    /// how an ICMP unreachable arrives, so it means the destination is not
    /// answering rather than that the host is at fault.
    Failed,
}

impl Association {
    /// Take up to one pass's datagrams off the host socket, as packets
    /// addressed to the guest.
    fn drain(
        &mut self,
        key: FlowKey,
        guest: IpAddr,
        out: &mut Vec<Vec<u8>>,
        drops: &mut DatagramDrops,
    ) -> DrainOutcome {
        // One byte past the bound, so a datagram the link cannot carry is
        // *detected* rather than silently shortened: `recv_from` truncates
        // to the buffer and discards the rest, so a read that fills this is
        // one that lost bytes.
        let mut buf = [0u8; MAX_DATAGRAM_PAYLOAD_BYTES + 1];
        for _ in 0..DATAGRAMS_PER_ASSOCIATION_POLL {
            let (len, from) = match self.socket.recv_from(&mut buf) {
                Ok(read) => read,
                Err(e) if !is_terminal_host_error(e.kind()) => return DrainOutcome::Idle,
                Err(_) => return DrainOutcome::Failed,
            };
            if !from_admitted_peer(from, self.peer) {
                // The kernel should already have dropped this; that it did
                // not is worth a number of its own.
                drops.off_path = drops.off_path.saturating_add(1);
                continue;
            }
            if len > MAX_DATAGRAM_PAYLOAD_BYTES {
                drops.oversized = drops.oversized.saturating_add(1);
                continue;
            }
            match synthesize_datagram(&key, guest, &buf[..len]) {
                Some(packet) => out.push(packet),
                None => drops.unaddressable = drops.unaddressable.saturating_add(1),
            }
        }
        DrainOutcome::Idle
    }
}

/// Guest datagram conversations, keyed by the guest's 4-tuple.
///
/// `guest` is the address the session leased, and it is the authority on
/// where a synthesized reply is addressed — never the source field of
/// whatever the guest last sent, for the reason
/// [`super::tcp::HalfOpen::reset_for_guest`] gives.
pub struct UdpAssociations {
    entries: BTreeMap<FlowKey, Association>,
    capacity: usize,
    guest: IpAddr,
    drops: DatagramDrops,
    /// Every association's socket goes on the datapath's readiness set, so a
    /// peer's reply wakes the drive loop rather than waiting out its tick.
    watch: Watch,
}

impl UdpAssociations {
    pub fn new(capacity: usize, guest: IpAddr, watch: Watch) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
            guest,
            drops: DatagramDrops::default(),
            watch,
        }
    }

    /// Associations currently held. Each one parks a host descriptor.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether this flow already has a socket.
    pub fn holds(&self, key: &FlowKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Whether a flow without an association could still get one.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// Drop every association, closing the host descriptor each one parks.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Take the drop counts accumulated since the last call.
    pub fn take_drops(&mut self) -> DatagramDrops {
        std::mem::take(&mut self.drops)
    }

    /// Send one admitted guest datagram, opening an association for it if
    /// this flow has none.
    ///
    /// Refusals are returned rather than swallowed. A datagram this
    /// datapath quietly discards is a guest whose QUIC handshake or metric
    /// push hangs with nothing anywhere to explain it, and UDP gives the
    /// guest no reset to read either.
    pub fn send(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        now_millis: u64,
    ) -> Result<(), DatapathError> {
        if key.protocol != proto::UDP {
            return Err(DatapathError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{key:?} is not a datagram flow"),
            )));
        }
        if payload.len() > MAX_DATAGRAM_PAYLOAD_BYTES {
            return Err(DatapathError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "a {} byte datagram exceeds the {MAX_DATAGRAM_PAYLOAD_BYTES} bytes this \
                     link carries",
                    payload.len()
                ),
            )));
        }
        self.open(key, now_millis)?;
        let Some(entry) = self.entries.get_mut(&key) else {
            unreachable!("open returned Ok without leaving an association behind");
        };
        // No destination argument: the socket is connected, so this
        // datagram structurally cannot leave for anywhere but the address
        // policy admitted.
        match entry.socket.send(payload) {
            Ok(_) => Ok(()),
            Err(e) if !is_terminal_host_error(e.kind()) => Err(DatapathError::Io(e)),
            Err(e) => {
                // The socket is finished — an ICMP unreachable from the
                // last datagram surfaces here — so give the descriptor
                // back now rather than waiting out the deadline on a
                // conversation that has already ended.
                self.entries.remove(&key);
                Err(DatapathError::Io(e))
            }
        }
    }

    /// Ensure `key` has an association, refusing rather than evicting when
    /// the table is full.
    fn open(&mut self, key: FlowKey, now_millis: u64) -> Result<(), DatapathError> {
        if self.entries.contains_key(&key) {
            return Ok(());
        }
        if self.is_full() {
            // Drop the newcomer, never a live entry. Evicting to make room
            // would let one guest flow end another's — a resource limit
            // turned into a correctness bug — which is the posture every
            // other table in this datapath takes at capacity.
            return Err(DatapathError::Io(io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("{} datagram associations already open", self.capacity),
            )));
        }
        // The destination comes from the admitted flow key, never from a
        // re-read of the guest's bytes: re-deriving it here would put a
        // second parse below the policy seam that checked the first.
        let peer = SocketAddr::new(key.remote, key.remote_port);
        // Registered before the association exists, so the table never holds
        // a socket the drive loop cannot be woken for.
        let socket =
            Watched::new(&self.watch, connect_datagram_socket(peer)?).map_err(DatapathError::Io)?;
        self.entries.insert(
            key,
            Association {
                socket,
                peer,
                // Taken once, here, and never moved again.
                deadline_millis: now_millis.saturating_add(ASSOCIATION_LIFETIME_MILLIS),
            },
        );
        Ok(())
    }

    /// Take what every association's peer has sent, as packets for the
    /// guest.
    pub fn poll(&mut self, now_millis: u64) -> Vec<Vec<u8>> {
        let guest = self.guest;
        let mut out = Vec::new();
        let mut finished = Vec::new();
        for (key, entry) in &mut self.entries {
            // An association past its deadline carries nothing, even before
            // the reaper has run. `poll` and `expire` are driven
            // independently, so without this a caller that polls more often
            // than it expires would go on moving traffic on a conversation
            // this datapath has already ended.
            if now_millis >= entry.deadline_millis {
                continue;
            }
            if entry.drain(*key, guest, &mut out, &mut self.drops) == DrainOutcome::Failed {
                finished.push(*key);
            }
        }
        for key in finished {
            self.entries.remove(&key);
        }
        out
    }

    /// Drop associations that have reached their deadline, reporting how
    /// many went.
    pub fn expire(&mut self, now_millis: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now_millis < entry.deadline_millis);
        before - self.entries.len()
    }

    /// The local address of a flow's host socket. Test-only: production has
    /// no business knowing which ephemeral port the kernel picked, and a
    /// test needs it to aim an off-path datagram at the socket under test.
    #[cfg(test)]
    pub(crate) fn host_local_addr(&self, key: &FlowKey) -> Option<SocketAddr> {
        self.entries.get(key)?.socket.local_addr().ok()
    }
}

impl std::fmt::Debug for UdpAssociations {
    /// Hand-written for the reason [`super::tcp::HalfOpen`]'s is: a derived
    /// one would be tempted to grow a payload field, and these carry
    /// guest-controlled bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpAssociations")
            .field("len", &self.entries.len())
            .field("capacity", &self.capacity)
            .field("drops", &self.drops)
            .finish()
    }
}

/// Whether a received datagram really came from the destination policy
/// admitted.
///
/// The host is compared canonically, for the reason [`same_host`] gives,
/// and the port exactly: a reply from another port on the same machine is a
/// different service, and nothing admitted it.
fn from_admitted_peer(from: SocketAddr, admitted: SocketAddr) -> bool {
    from.port() == admitted.port() && same_host(from.ip(), admitted.ip())
}

/// Build the packet a reply becomes on the guest's link: addressed from the
/// destination the guest dialled, to the address the session leased it.
///
/// `None` only when the leased guest address and the flow's remote are of
/// different families, which cannot happen — a flow's remote is reached
/// over the interface the guest's address is configured on. It is not a
/// statement about which families are supported; both are emitted.
fn synthesize_datagram(key: &FlowKey, guest: IpAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp = UdpRepr {
        src_port: key.remote_port,
        dst_port: key.guest_port,
    };
    match (key.remote, guest) {
        (IpAddr::V4(remote), IpAddr::V4(guest)) => {
            Some(emit_v4_datagram(remote, guest, &udp, payload))
        }
        (IpAddr::V6(remote), IpAddr::V6(guest)) => {
            Some(emit_v6_datagram(remote, guest, &udp, payload))
        }
        _ => None,
    }
}

fn emit_v4_datagram(src: Ipv4Addr, dst: Ipv4Addr, udp: &UdpRepr, payload: &[u8]) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: UDP_HEADER_LEN + payload.len(),
        hop_limit: DATAGRAM_HOP_LIMIT,
    };
    let checksums = ChecksumCapabilities::default();
    let mut bytes = vec![0u8; ip.buffer_len() + ip.payload_len];
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet, &checksums);
    udp.emit(
        &mut UdpPacket::new_unchecked(packet.payload_mut()),
        &src.into(),
        &dst.into(),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &checksums,
    );
    bytes
}

/// IPv6 has no header checksum, but the UDP checksum is computed over a
/// different pseudo-header from IPv4's, so the two cannot share an emitter.
fn emit_v6_datagram(src: Ipv6Addr, dst: Ipv6Addr, udp: &UdpRepr, payload: &[u8]) -> Vec<u8> {
    let ip = Ipv6Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: UDP_HEADER_LEN + payload.len(),
        hop_limit: DATAGRAM_HOP_LIMIT,
    };
    let checksums = ChecksumCapabilities::default();
    let mut bytes = vec![0u8; ip.buffer_len() + ip.payload_len];
    let mut packet = Ipv6Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet);
    udp.emit(
        &mut UdpPacket::new_unchecked(packet.payload_mut()),
        &src.into(),
        &dst.into(),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &checksums,
    );
    bytes
}

/// Open a non-blocking datagram socket connected to `dst`.
fn connect_datagram_socket(dst: SocketAddr) -> Result<UdpSocket, DatapathError> {
    let socket = Socket::new(Domain::for_address(dst), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| host_socket_unavailable(dst, &e))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| host_socket_unavailable(dst, &e))?;
    // A `&SockAddr` built from the admitted key, never a name and never a
    // `ToSocketAddrs` a resolver could get in front of.
    socket
        .connect(&dst.into())
        .map_err(|e| host_socket_unavailable(dst, &e))?;
    Ok(socket.into())
}

fn host_socket_unavailable(dst: SocketAddr, source: &io::Error) -> DatapathError {
    DatapathError::Io(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("no host datagram socket for {dst}: {source}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::readiness::ReadinessSet;
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    /// A readiness set for a table under test, with its poll side dropped.
    ///
    /// These tests drive the table directly rather than waiting on it, so
    /// nothing here polls. What the sockets need is somewhere to register
    /// and unregister, and that outlives the set the watch came from.
    fn watch() -> Watch {
        ReadinessSet::new()
            .expect("a readiness set needs no privileges")
            .watch()
    }

    /// How long a fixture waits on a loopback round trip before failing.
    /// Bounded, so a datapath that never answers fails an assertion rather
    /// than hanging the suite.
    const ROUND_TRIP_BUDGET: Duration = Duration::from_secs(2);

    /// How long an ICMP unreachable is given to reach a connected socket's
    /// error queue. Loopback, so this is generous: measured on this path,
    /// a refusal is reported on every attempt past a few milliseconds and
    /// on only a few percent of attempts with no wait at all.
    const ICMP_SETTLE: Duration = Duration::from_millis(25);

    /// The address the session leased this guest. Deliberately not an
    /// address any fixture packet carries: a reply must be addressed from
    /// the lease, and a fixture where the two agree could not tell which
    /// one the code read.
    fn guest() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 201, 0, 6))
    }

    fn key() -> FlowKey {
        key_with_port(50_000)
    }

    fn key_with_port(guest_port: u16) -> FlowKey {
        FlowKey {
            protocol: proto::UDP,
            guest_port,
            remote: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: 443,
        }
    }

    fn key_to(dst: SocketAddr) -> FlowKey {
        FlowKey {
            protocol: proto::UDP,
            guest_port: 50_000,
            remote: dst.ip(),
            remote_port: dst.port(),
        }
    }

    /// A loopback destination that discards whatever it is sent.
    ///
    /// The socket is returned so the caller holds the port for the test's
    /// lifetime. Nothing reads it: a fixture that wants a quiet peer wants
    /// datagrams to go nowhere, not to come back.
    fn bind_udp_sink() -> (UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a loopback sink");
        let addr = socket.local_addr().expect("local addr");
        (socket, addr)
    }

    /// A loopback UDP echo server, bounded in both time and datagram count
    /// so its thread cannot outlive the test that started it.
    fn bind_udp_echo_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a loopback echo server");
        let addr = socket.local_addr().expect("local addr");
        socket
            .set_read_timeout(Some(ROUND_TRIP_BUDGET))
            .expect("a bounded read");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            for _ in 0..16 {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                if socket.send_to(&buf[..n], from).is_err() {
                    return;
                }
            }
        });
        addr
    }

    /// Drive `poll` until it yields something, or fail. Bounded on both
    /// counts: a reply that never arrives must produce an assertion, never
    /// a hang.
    fn poll_until_nonempty(a: &mut UdpAssociations, budget: Duration) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + budget;
        loop {
            let replies = a.poll(0);
            if !replies.is_empty() || Instant::now() >= deadline {
                return replies;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The IPv4 source, destination, ports and body of a synthesized reply.
    fn reply_parts(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>) {
        let ip = Ipv4Packet::new_checked(packet).expect("a well-formed IPv4 packet");
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let udp = UdpPacket::new_checked(ip.payload()).expect("a well-formed UDP datagram");
        (
            ip.src_addr(),
            ip.dst_addr(),
            udp.src_port(),
            udp.dst_port(),
            udp.payload().to_vec(),
        )
    }

    #[test]
    fn a_datagram_round_trips_through_a_host_socket() {
        let echo = bind_udp_echo_server();
        let mut a = UdpAssociations::new(64, guest(), watch());
        a.send(key_to(echo), b"ping", 0).expect("send");
        let replies = poll_until_nonempty(&mut a, ROUND_TRIP_BUDGET);
        assert_eq!(replies.len(), 1, "the echo server's answer must come back");
        let (src, dst, src_port, dst_port, body) = reply_parts(&replies[0]);
        assert_eq!(body, b"ping");
        assert_eq!(
            IpAddr::V4(src),
            echo.ip(),
            "the reply is addressed from the destination policy admitted"
        );
        assert_eq!(src_port, echo.port());
        assert_eq!(
            IpAddr::V4(dst),
            guest(),
            "and to the address the session leased, not to anything the guest wrote"
        );
        assert_eq!(dst_port, 50_000);
    }

    #[test]
    fn associations_expire_on_the_datagram_timeout() {
        let mut a = UdpAssociations::new(64, guest(), watch());
        a.send(key(), b"x", 0).expect("send");
        assert_eq!(a.len(), 1);
        assert_eq!(a.expire(ASSOCIATION_LIFETIME_MILLIS), 1);
        assert_eq!(a.len(), 0, "and the descriptor goes with it");
    }

    #[test]
    fn an_association_inside_its_lifetime_is_not_expired() {
        let mut a = UdpAssociations::new(64, guest(), watch());
        a.send(key(), b"x", 0).expect("send");
        assert_eq!(a.expire(ASSOCIATION_LIFETIME_MILLIS - 1), 0);
        assert_eq!(a.len(), 1);
    }

    /// **The deadline is absolute.** A lifetime that later traffic pushes
    /// out is one a guest holds open for the machine's whole life by
    /// sending a byte a minute — 64 descriptors at a time, none of them
    /// ever reclaimed. The same argument that made the TCP path's bounds
    /// absolute rather than refreshable.
    ///
    /// The destination is a bound sink rather than a closed port, for the
    /// reason
    /// [`a_bound_destination_absorbs_a_second_datagram_rather_than_refusing_it`]
    /// states: this is the only fixture here that sends twice on one
    /// association, so it is the only one a refusal reaches.
    #[test]
    fn traffic_does_not_push_out_an_associations_deadline() {
        let (_sink, dst) = bind_udp_sink();
        let mut a = UdpAssociations::new(64, guest(), watch());
        let flow = key_to(dst);
        a.send(flow, b"first", 0).expect("send");
        a.send(flow, b"second", ASSOCIATION_LIFETIME_MILLIS - 1)
            .expect("a later datagram on the same association");
        assert_eq!(a.len(), 1, "and it is still one association, not two");
        assert_eq!(
            a.expire(ASSOCIATION_LIFETIME_MILLIS),
            1,
            "the deadline is taken from the datagram that opened the association"
        );
    }

    /// **A quiet destination has to exist.** A closed port is the opposite
    /// of quiet: the kernel answers it with an ICMP port-unreachable, the
    /// association's socket is connected, and the next `send` on it
    /// reports that back as `ECONNREFUSED`. Any fixture here that sends
    /// twice on one association is then testing the refusal rather than
    /// whatever it meant to test — and refusal is a real signal this path
    /// is meant to surface, so the fixture is what has to change.
    ///
    /// The wait is the subject, not a timing tolerance: the refusal is an
    /// ICMP round trip, so without it a destination that refuses passes
    /// this most of the time and fails under load.
    #[test]
    fn a_bound_destination_absorbs_a_second_datagram_rather_than_refusing_it() {
        let (_sink, dst) = bind_udp_sink();
        let mut a = UdpAssociations::new(64, guest(), watch());
        let flow = key_to(dst);
        a.send(flow, b"first", 0).expect("send");
        std::thread::sleep(ICMP_SETTLE);
        a.send(flow, b"second", 1)
            .expect("a destination that discards must never refuse");
    }

    #[test]
    fn the_association_table_drops_rather_than_evicting() {
        let mut a = UdpAssociations::new(2, guest(), watch());
        for i in 0..8 {
            let _ = a.send(key_with_port(50_000 + i), b"x", 0);
        }
        assert_eq!(a.len(), 2);
        assert!(
            a.holds(&key_with_port(50_000)) && a.holds(&key_with_port(50_001)),
            "the two that arrived first are the two that survive: at capacity the \
             newcomer is refused, an established association is never evicted"
        );
    }

    #[test]
    fn a_refused_association_reports_rather_than_dropping_silently() {
        let mut a = UdpAssociations::new(1, guest(), watch());
        a.send(key_with_port(50_000), b"x", 0).expect("inside cap");
        assert!(
            a.send(key_with_port(50_001), b"x", 0).is_err(),
            "a datagram that opened no association must reach the caller as an error, \
             not vanish into a guest that hangs with nothing to explain it"
        );
    }

    /// **Off-path injection.** A datagram socket read with `recv_from`
    /// takes from any source, so anyone who can guess the host's ephemeral
    /// port could put a forged answer in front of the guest. Nothing that
    /// the association did not address may reach it.
    #[test]
    fn a_datagram_from_an_off_path_sender_never_reaches_the_guest() {
        let echo = bind_udp_echo_server();
        let mut a = UdpAssociations::new(64, guest(), watch());
        let flow = key_to(echo);
        a.send(flow, b"ping", 0).expect("send");
        assert!(
            !poll_until_nonempty(&mut a, ROUND_TRIP_BUDGET).is_empty(),
            "the admitted destination's own reply must arrive, or this test proves nothing"
        );

        let local = a.host_local_addr(&flow).expect("the association's socket");
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local.port());
        let off_path = UdpSocket::bind("127.0.0.1:0").expect("bind an unrelated sender");
        off_path
            .send_to(b"injected", target)
            .expect("the injection is sent; it must simply not be delivered");
        std::thread::sleep(Duration::from_millis(50));

        let replies = a.poll(1);
        assert!(
            replies.is_empty(),
            "a datagram from a source the guest never addressed reached it: {replies:?}"
        );
    }

    /// The check that verifies the kernel's filter rather than assuming it.
    /// Exercised directly because, when both layers work, no datagram can
    /// reach it through a socket.
    #[test]
    fn the_source_check_admits_only_the_destination_policy_admitted() {
        let admitted: SocketAddr = "203.0.113.7:443".parse().expect("parse");
        assert!(from_admitted_peer(admitted, admitted));
        assert!(
            !from_admitted_peer("203.0.113.8:443".parse().expect("parse"), admitted),
            "another host is not the admitted destination"
        );
        assert!(
            !from_admitted_peer("203.0.113.7:444".parse().expect("parse"), admitted),
            "another port on the same host is a different service, and nothing admitted it"
        );
        assert!(
            from_admitted_peer("[::ffff:203.0.113.7]:443".parse().expect("parse"), admitted),
            "the v4-mapped form encodes the same 32 bits and reached the same machine"
        );
    }

    /// An expired association must carry nothing, even before the reaper
    /// has run. `poll` and `expire` are driven independently, so a caller
    /// that polls more often than it expires would otherwise go on moving
    /// traffic on a conversation the datapath has already ended.
    #[test]
    fn an_expired_association_delivers_nothing() {
        let echo = bind_udp_echo_server();
        let mut a = UdpAssociations::new(64, guest(), watch());
        a.send(key_to(echo), b"ping", 0).expect("send");
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            a.poll(ASSOCIATION_LIFETIME_MILLIS).is_empty(),
            "a reply arriving past the deadline belongs to an association that is over"
        );
    }

    /// The guest's link cannot carry more than an MTU and this datapath
    /// refuses fragments, so a larger datagram has nowhere to go. Refused
    /// where the caller can see it rather than silently shortened.
    #[test]
    fn an_oversized_payload_is_refused_rather_than_truncated() {
        let mut a = UdpAssociations::new(64, guest(), watch());
        assert!(
            a.send(key(), &vec![0u8; MAX_DATAGRAM_PAYLOAD_BYTES + 1], 0)
                .is_err()
        );
        assert_eq!(a.len(), 0, "and it opens no association either");
        assert!(
            a.send(key(), &vec![0u8; MAX_DATAGRAM_PAYLOAD_BYTES], 0)
                .is_ok(),
            "a datagram at exactly the bound still goes"
        );
    }

    /// The table is keyed by protocol as well as by address, and a TCP key
    /// reaching it means the handle dispatched to the wrong translation.
    #[test]
    fn a_key_that_is_not_a_datagram_flow_is_refused() {
        let mut a = UdpAssociations::new(64, guest(), watch());
        let mut wrong = key();
        wrong.protocol = proto::TCP;
        assert!(a.send(wrong, b"x", 0).is_err());
        assert_eq!(a.len(), 0);
    }

    /// Per-association cost here is a descriptor, so a teardown that leaked
    /// one would accumulate across machine restarts.
    #[test]
    fn clear_releases_every_descriptor_and_is_idempotent() {
        let mut a = UdpAssociations::new(64, guest(), watch());
        for i in 0..4 {
            a.send(key_with_port(50_000 + i), b"x", 0).expect("send");
        }
        assert_eq!(a.len(), 4);
        a.clear();
        assert_eq!(a.len(), 0);
        a.clear();
        assert_eq!(a.len(), 0);
    }

    /// One poll must not be able to read a talkative peer's whole backlog:
    /// everything it produces goes onto one bounded queue, and what will
    /// not fit is read only to be discarded.
    #[test]
    fn one_poll_takes_a_bounded_number_of_datagrams() {
        let echo = bind_udp_echo_server();
        let mut a = UdpAssociations::new(64, guest(), watch());
        let flow = key_to(echo);
        for i in 0..(DATAGRAMS_PER_ASSOCIATION_POLL + 3) {
            a.send(flow, &[i as u8], 0).expect("send");
        }
        // Give every echo time to come back before the bound is measured,
        // so a short read is the bound and not the network.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(a.poll(1).len(), DATAGRAMS_PER_ASSOCIATION_POLL);
    }

    /// Both families are emitted, and a reply the datapath cannot address
    /// is reported rather than sent to the wrong place.
    #[test]
    fn a_reply_is_emitted_for_either_family_and_for_neither_mixture() {
        let v4 = synthesize_datagram(&key(), guest(), b"body").expect("v4 to v4");
        assert_eq!(reply_parts(&v4).4, b"body");

        let mut v6_key = key();
        v6_key.remote = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let v6_guest = IpAddr::V6("fd00::2".parse::<Ipv6Addr>().expect("parse"));
        let v6 = synthesize_datagram(&v6_key, v6_guest, b"body").expect("v6 to v6");
        let ip = Ipv6Packet::new_checked(&v6).expect("a well-formed IPv6 packet");
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        assert_eq!(IpAddr::V6(ip.dst_addr()), v6_guest);

        assert!(
            synthesize_datagram(&v6_key, guest(), b"body").is_none(),
            "a v6 remote and a v4 guest cannot share a packet"
        );
    }
}
