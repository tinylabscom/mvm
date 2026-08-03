//! Half-open TCP connections: the guest's handshake, deferred.
//!
//! The gateway could answer a guest SYN immediately and connect to the real
//! destination afterwards. That is one round trip cheaper and needs none of
//! the state here, and it was rejected: it makes the guest's `connect()`
//! lie. The guest would reach ESTABLISHED for destinations that do not
//! exist, and the failure would surface later as a mid-stream reset. Health
//! probes, service discovery, and retry logic all read `connect()` success
//! as a reachability signal, so all of them would behave wrongly — and the
//! audit log records the admitted flow either way, so the lie is invisible
//! there.
//!
//! So the guest reaches ESTABLISHED only once the real destination has
//! accepted. Given a listening socket, smoltcp answers a SYN itself, which
//! is exactly the behaviour being rejected — so the SYN never reaches the
//! stack. It is parsed and held here while a non-blocking host `connect()`
//! runs, and only a connect that actually succeeded releases it.
//!
//! # Destination integrity
//!
//! The one security property socket translation does not inherit for free.
//! A host TUN puts the admitted packet's own bytes on the wire, so the
//! destination that policy checked *is* the destination reached, and no
//! divergence is representable. Translating to a socket re-derives that
//! destination and hands it to `connect()`, and any divergence between the
//! checked value and the connected one is a policy bypass the audit log
//! cannot show, because the log records the admitted metadata rather than
//! the socket's real peer.
//!
//! Two rules close it. `connect()` is handed only the [`SocketAddr`] built
//! from the admitted packet — never a hostname, never a string through
//! `ToSocketAddrs`, either of which would re-enter name resolution *below*
//! the policy seam. And [`assert_peer_matches`] asserts the connected
//! socket's real peer against that admitted destination before the held SYN
//! is released, so "we derived it correctly" is checked rather than
//! assumed.
//!
//! Which destinations are permissible is not decided here — address-class
//! and allow-list policy live above this file, in `mvm_net::l3::admit`.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;

use mvm_net::l3::admit::DenyCode;
use mvm_net::l3::flow::FlowKey;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber,
};
use socket2::{Domain, Protocol, Socket, Type};

use crate::netd::datapath::DatapathError;
use crate::netd::metrics::GatewayMetrics;

use super::limits::HALF_OPEN_TIMEOUT_MILLIS;

/// A guest SYN held back from the stack while its host connect runs.
pub struct HalfOpen {
    key: FlowKey,
    /// The guest's SYN, verbatim. Replayed into the stack once the host
    /// side is real, so smoltcp emits the SYN-ACK against the packet the
    /// guest actually sent rather than one reconstructed from the key.
    syn: Vec<u8>,
    socket: TcpStream,
    opened_at_millis: u64,
    /// Latched because a synchronous connect failure — what loopback to a
    /// closed port reports on some platforms — hands the error to the
    /// caller and clears `SO_ERROR` with it. The socket is then writable
    /// with nothing pending, which is indistinguishable from success.
    refused_at_open: bool,
}

impl HalfOpen {
    pub fn key(&self) -> FlowKey {
        self.key
    }

    /// The held SYN, to be replayed into the stack.
    pub fn syn(&self) -> &[u8] {
        &self.syn
    }

    /// Take ownership of the connected host socket this flow re-originates
    /// on, leaving the rest behind.
    pub fn into_socket(self) -> TcpStream {
        self.socket
    }

    /// The reset this flow owes the guest, addressed from the destination
    /// the guest tried to reach to the address the session leased it.
    ///
    /// `guest` comes from the lease, never from the held SYN's source
    /// field. The SYN's source is guest-written; it is trustworthy today
    /// only because admission rejects a spoofed source upstream, and a
    /// packet the host *originates* should not inherit its destination
    /// from a second component staying correct. The lease is the authority
    /// on where this guest is.
    pub fn reset_for_guest(&self, guest: IpAddr) -> Option<Vec<u8>> {
        let parsed = mvm_protocol::l3::ip::parse(&self.syn).ok()?;
        let acknowledging = mvm_protocol::l3::ip::tcp_sequence(&self.syn, &parsed)?;
        synthesize_rst(&self.key, guest, acknowledging)
    }
}

impl std::fmt::Debug for HalfOpen {
    /// Hand-written because the held SYN is guest-controlled bytes; a
    /// derived `Debug` would splatter them into any log line that formats
    /// a table.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HalfOpen")
            .field("key", &self.key)
            .field("syn_len", &self.syn.len())
            .field("opened_at_millis", &self.opened_at_millis)
            .field("refused_at_open", &self.refused_at_open)
            .finish()
    }
}

/// What a guest SYN met when it reached the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynOutcome {
    /// A new half-open entry; a host connect is now running.
    Started,
    /// A retransmit of a SYN already being worked on. No second host
    /// socket, and no fresh timeout either: a guest that retransmits
    /// aggressively must not be able to multiply the host's descriptor
    /// cost for one flow, nor to hold one descriptor open indefinitely by
    /// refreshing it.
    Folded,
    Refused(DenyCode),
}

/// Where a host connect has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectProgress {
    /// The kernel has not finished with it.
    Pending,
    /// Connected. The guest may now be told so.
    Established,
    /// Refused, unreachable, or timed out at the kernel's own timer.
    Failed,
}

/// Guest SYNs awaiting their host connect, keyed by the guest's 4-tuple.
#[derive(Debug)]
pub struct HalfOpenTable {
    entries: BTreeMap<FlowKey, HalfOpen>,
    capacity: usize,
    /// The address this session leased its guest. The authority on where a
    /// host-originated packet is addressed — see
    /// [`HalfOpen::reset_for_guest`].
    guest: IpAddr,
}

impl HalfOpenTable {
    pub fn new(capacity: usize, guest: IpAddr) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
            guest,
        }
    }

    /// The leased guest address, for callers that build their own resets
    /// from what [`Self::expire`] hands back.
    pub fn guest(&self) -> IpAddr {
        self.guest
    }

    /// Half-open entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Take a guest SYN.
    ///
    /// `dst` is the already-admitted destination; admission happens before
    /// this table, so a SYN that arrives here has passed policy and the
    /// only question left is whether the destination accepts.
    pub fn on_syn(
        &mut self,
        key: FlowKey,
        syn_bytes: Vec<u8>,
        dst: SocketAddr,
        now_millis: u64,
    ) -> SynOutcome {
        if self.entries.contains_key(&key) {
            return SynOutcome::Folded;
        }
        if self.entries.len() >= self.capacity {
            // Drop the newcomer, never a live entry. Evicting to make room
            // would let a guest displace its own in-flight connections with
            // a flood, turning a resource limit into a correctness bug —
            // the same posture the flow table takes at capacity.
            return SynOutcome::Refused(DenyCode::FlowTableFull);
        }
        let (socket, refused_at_open) = match start_connect(dst) {
            Ok(socket) => (socket, false),
            Err(ConnectStartError::Refused(socket)) => (socket, true),
            // No socket at all: EMFILE, an address family the host cannot
            // open, or a sandbox refusing the call. Not a capacity
            // condition — reporting it as a full table would point an
            // operator at a ceiling mvm chose instead of at the one the OS
            // is imposing.
            Err(ConnectStartError::NoSocket) => {
                return SynOutcome::Refused(DenyCode::HostSocketUnavailable);
            }
        };
        self.entries.insert(
            key,
            HalfOpen {
                key,
                syn: syn_bytes,
                socket,
                opened_at_millis: now_millis,
                refused_at_open,
            },
        );
        SynOutcome::Started
    }

    /// Poll every half-open connect once and take out everything the kernel
    /// has decided, leaving only those still in flight.
    ///
    /// Each resolved entry is yielded exactly once — it is *moved* out of
    /// the map, so "once" is structural rather than bookkept. Replaying a
    /// SYN a second time would re-drive a handshake the guest has already
    /// completed.
    ///
    /// Failures come back alongside successes rather than being discarded:
    /// a guest whose connect failed is still waiting on a SYN-ACK that will
    /// never arrive, and the caller cannot synthesize the reset it is owed
    /// for a flow it was never told about.
    ///
    /// A connect that succeeded to the *wrong* peer is a failure too, and
    /// is checked here rather than by the caller: this is the only way a
    /// held SYN leaves the table, so a mismatched flow structurally cannot
    /// reach the stack.
    ///
    /// The guest is told the same thing either way — a reset — but the
    /// *host* is not. A destination-integrity violation is a policy event
    /// and a refused connect is not, so a mismatch counts a
    /// [`DenyCode::PeerDestinationMismatch`] deny on `metrics` while an
    /// ordinary failure counts nothing. Without that an operator reading
    /// the counters cannot tell the one thing this check exists to detect
    /// from a destination that happened to be down.
    ///
    /// The label is its own, not [`DenyCode::WrongDestination`]: that one
    /// counts inbound packets addressed to somebody else, which is routine
    /// noise, and a shared counter would let any guest bury this signal
    /// under it.
    pub fn resolve(&mut self, metrics: &mut GatewayMetrics) -> Resolved {
        let guest = self.guest;
        let mut out = Resolved::default();
        let mut still_pending = BTreeMap::new();
        for (key, entry) in std::mem::take(&mut self.entries) {
            match progress(&entry) {
                ConnectProgress::Pending => {
                    still_pending.insert(key, entry);
                }
                ConnectProgress::Established => {
                    match assert_peer_matches(&entry.socket, entry.key.remote) {
                        Ok(()) => out.established.push(entry),
                        Err(_) => {
                            metrics.record_deny(DenyCode::PeerDestinationMismatch);
                            fail_flow(&mut out, entry, guest, metrics);
                        }
                    }
                }
                ConnectProgress::Failed => fail_flow(&mut out, entry, guest, metrics),
            }
        }
        self.entries = still_pending;
        out
    }

    /// Drop entries whose host connect has taken longer than
    /// [`HALF_OPEN_TIMEOUT_MILLIS`], measured from when the SYN arrived.
    ///
    /// Without this a destination that neither accepts nor refuses — a
    /// dropping firewall — parks a descriptor until the kernel's own much
    /// longer connect timeout, which is a hostile guest's cheapest way to
    /// hold host resources.
    ///
    /// An entry whose connect has *already succeeded* is never aged out,
    /// however old it is. Expiry and resolution are driven independently,
    /// so a loop that expires more often than it resolves would otherwise
    /// discard connections the host had genuinely established and leave the
    /// guest's SYN unanswered — punishing a slow poller, not a slow
    /// destination.
    ///
    /// An expired entry owes its guest a reset for the same reason a failed
    /// one does. It is not built here because expiry is a plain drop with
    /// nowhere to put the bytes; build it with
    /// [`HalfOpen::reset_for_guest`] and [`Self::guest`].
    pub fn expire(&mut self, now_millis: u64) -> Vec<HalfOpen> {
        let mut dropped = Vec::new();
        let mut kept = BTreeMap::new();
        for (key, entry) in std::mem::take(&mut self.entries) {
            // Saturating: a caller whose clock stepped backwards must not
            // wrap into an enormous age and expire every live entry.
            let aged =
                now_millis.saturating_sub(entry.opened_at_millis) >= HALF_OPEN_TIMEOUT_MILLIS;
            // Short-circuited so the common, un-aged case costs no syscall.
            if aged && progress(&entry) != ConnectProgress::Established {
                dropped.push(entry);
            } else {
                kept.insert(key, entry);
            }
        }
        self.entries = kept;
        dropped
    }
}

/// What one [`HalfOpenTable::resolve`] took out of the table.
#[derive(Debug, Default)]
pub struct Resolved {
    /// Connects that succeeded. Replay these SYNs into the stack; it will
    /// emit the SYN-ACK and the guest reaches ESTABLISHED — now, and only
    /// now, truthfully.
    pub established: Vec<HalfOpen>,
    /// Connects that failed, whether the destination refused them or the
    /// socket reached the wrong peer. Each of these owes the guest a reset:
    /// it is still waiting on a handshake that will never complete.
    pub failed: Vec<HalfOpen>,
    /// The resets [`Self::failed`] owes its guests, ready to hand to the
    /// guest-facing device.
    ///
    /// Built during `resolve` rather than on demand so that a reset which
    /// could not be built is counted where the counters are, instead of
    /// vanishing from a `filter_map` the caller cannot see.
    pub resets: Vec<Vec<u8>>,
}

/// Record a flow that will never reach ESTABLISHED, and the reset it owes.
///
/// A reset that cannot be built increments `datapath_errors` rather than
/// being dropped: the visible consequence is a guest hanging until its own
/// connect timeout, which is exactly the failure the deferred handshake
/// exists to prevent, so it must not be silent.
fn fail_flow(out: &mut Resolved, entry: HalfOpen, guest: IpAddr, metrics: &mut GatewayMetrics) {
    match entry.reset_for_guest(guest) {
        Some(reset) => out.resets.push(reset),
        None => metrics.datapath_errors += 1,
    }
    out.failed.push(entry);
}

/// Assert that the socket really is connected to the destination policy
/// admitted, and refuse the flow if it is not.
///
/// Cheap enough to run on every completed connect, and it is what turns
/// "the datapath derived the destination correctly" from an assumption into
/// something checked against the kernel's own view of the connection.
pub fn assert_peer_matches(socket: &TcpStream, admitted: IpAddr) -> Result<(), DatapathError> {
    let peer = socket.peer_addr()?;
    if same_host(peer.ip(), admitted) {
        return Ok(());
    }
    Err(DatapathError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "host socket is connected to {} but policy admitted {admitted}",
            peer.ip()
        ),
    )))
}

/// Whether two addresses name the same host.
///
/// Compared on the canonical form, so `::ffff:203.0.113.1` and
/// `203.0.113.1` are one host rather than two. They are one host: the
/// v4-mapped form is an encoding of the same 32 bits, and a socket
/// connected to either reached the same machine. Treating them as unequal
/// would tear down flows that went exactly where policy said while denying
/// nothing, and canonicalising cannot make two *different* addresses equal
/// — the mapping is injective.
///
/// This is an identity test, not a policy test. Whether an address may be
/// reached at all is decided above this file, by `mvm_net::l3::admit`,
/// which today refuses **every** non-IPv4 destination outright rather than
/// collapsing a mapped form and range-checking the result. So a mapped
/// destination cannot be admitted at all, and this comparison never has to
/// arbitrate one. A future IPv6 datapath that relaxes that refusal must
/// collapse the mapped form *before* its range checks; the collapse here is
/// downstream of policy and is not a substitute for it.
fn same_host(reached: IpAddr, admitted: IpAddr) -> bool {
    reached.to_canonical() == admitted.to_canonical()
}

/// Build the reset a guest is owed when the host side of its flow will
/// never come up, so its `connect()` fails as it would on a real path
/// instead of hanging until the guest's own timeout.
///
/// `key` supplies the admitted flow identity the reset must appear to come
/// from, `guest` the leased address it is sent to, and `acknowledging` the
/// sequence number of the SYN being answered. RFC 793's answer to a SYN is
/// `RST|ACK` with sequence zero acknowledging the SYN's sequence plus one —
/// a reset outside that window is discarded by the guest's stack and is no
/// reset at all.
///
/// `None` only when the leased guest address and the flow's remote are of
/// different families, which cannot happen: a flow's remote is reached over
/// the interface the guest's address is configured on. It is not a
/// statement about which families are supported — both are emitted.
pub fn synthesize_rst(key: &FlowKey, guest: IpAddr, acknowledging: u32) -> Option<Vec<u8>> {
    let tcp = TcpRepr {
        src_port: key.remote_port,
        dst_port: key.guest_port,
        control: TcpControl::Rst,
        seq_number: TcpSeqNumber(0),
        // `as i32` is the wrap TCP sequence arithmetic is defined on: the
        // space is modulo 2^32, and smoltcp carries it signed.
        ack_number: Some(TcpSeqNumber(acknowledging as i32) + 1),
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    match (key.remote, guest) {
        (IpAddr::V4(remote), IpAddr::V4(guest)) => Some(emit_v4_reset(remote, guest, &tcp)),
        (IpAddr::V6(remote), IpAddr::V6(guest)) => Some(emit_v6_reset(remote, guest, &tcp)),
        _ => None,
    }
}

/// Emit `tcp` inside an IPv4 header. The header checksum is written by
/// `emit` and covers only the header, so writing the segment afterwards
/// does not invalidate it.
fn emit_v4_reset(remote: Ipv4Addr, guest: Ipv4Addr, tcp: &TcpRepr<'_>) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: remote,
        dst_addr: guest,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: RESET_HOP_LIMIT,
    };
    let checksums = ChecksumCapabilities::default();
    let mut bytes = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet, &checksums);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &remote.into(),
        &guest.into(),
        &checksums,
    );
    bytes
}

/// Emit `tcp` inside an IPv6 header. IPv6 has no header checksum, but the
/// TCP checksum is computed over a different pseudo-header from IPv4's, so
/// the two cannot share an emitter.
fn emit_v6_reset(remote: Ipv6Addr, guest: Ipv6Addr, tcp: &TcpRepr<'_>) -> Vec<u8> {
    let ip = Ipv6Repr {
        src_addr: remote,
        dst_addr: guest,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: RESET_HOP_LIMIT,
    };
    let mut bytes = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
    let mut packet = Ipv6Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet);
    tcp.emit(
        &mut TcpPacket::new_unchecked(packet.payload_mut()),
        &remote.into(),
        &guest.into(),
        &ChecksumCapabilities::default(),
    );
    bytes
}

/// TTL on a synthesized reset. The guest is one hop away over the stack's
/// own interface, so this is only ever decremented by the guest's own
/// receive path; the conventional 64 keeps the packet indistinguishable
/// from one a real peer sent.
const RESET_HOP_LIMIT: u8 = 64;

/// Why a connect could not even be started.
enum ConnectStartError {
    /// The kernel answered synchronously with a terminal failure —
    /// `ECONNREFUSED`, `EAGAIN`, `ENETUNREACH`. The socket comes back so
    /// the entry can still exist and be reported to the guest through the
    /// same path as an asynchronous failure.
    Refused(TcpStream),
    /// No socket to speak of.
    NoSocket,
}

/// Open a non-blocking connect toward `dst`.
fn start_connect(dst: SocketAddr) -> Result<TcpStream, ConnectStartError> {
    let socket = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))
        .map_err(|_| ConnectStartError::NoSocket)?;
    if socket.set_nonblocking(true).is_err() {
        return Err(ConnectStartError::NoSocket);
    }
    match socket.connect(&dst.into()) {
        // Connected outright — loopback often does.
        Ok(()) => Ok(socket.into()),
        Err(e) if is_in_progress(&e) => Ok(socket.into()),
        // Anything else is terminal, and the error has been handed to us
        // inline — never stored in the socket, so `SO_ERROR` is empty and a
        // later readiness check cannot rediscover it. Latched instead.
        Err(_) => Err(ConnectStartError::Refused(socket.into())),
    }
}

/// Whether a `connect(2)` return means the kernel has *taken* the connect
/// and will report its outcome later.
///
/// Matched on the raw errno, never on [`io::ErrorKind`]. `EINPROGRESS` and
/// `EAGAIN` both map to [`io::ErrorKind::WouldBlock`] on some platforms,
/// and they mean opposite things here: `EINPROGRESS` is a connect under
/// way, while `EAGAIN` — which Linux returns for ephemeral-port and
/// route-cache exhaustion — is **terminal**. Accepting `EAGAIN` as
/// in-progress leaves a socket that never left `TCP_CLOSE`; Linux reports
/// `TCP_CLOSE` as `POLLHUP`, so it reads as writable, and its `SO_ERROR` is
/// empty because the error was returned inline and never stored. That is
/// `Established` on an unconnected socket — the same lie the latch exists
/// to stop, reached through the arm that skips the latch.
fn is_in_progress(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EINPROGRESS) | Some(libc::EALREADY)
    )
}

/// Where this entry's host connect has got to.
///
/// A non-blocking connect signals completion by making the socket
/// writable. Writability alone says only that the kernel is done, not that
/// it succeeded: a **refused** connection is writable too, and carries a
/// non-zero `SO_ERROR`. So writability decides *whether* the answer is in,
/// and the pending error decides *what* the answer is. Reading writability
/// as success would report every refused connection as established, which
/// is the exact failure the deferred handshake exists to prevent.
fn progress(entry: &HalfOpen) -> ConnectProgress {
    if entry.refused_at_open {
        return ConnectProgress::Failed;
    }
    if !is_writable(&entry.socket) {
        return ConnectProgress::Pending;
    }
    match entry.socket.take_error() {
        // No pending error on a socket the kernel has finished with: the
        // one case that means connected.
        Ok(None) => ConnectProgress::Established,
        // A pending error is a failed connect; a `getsockopt` we could not
        // even read fails closed the same way, because the alternative is
        // guessing in the direction that lies to the guest.
        Ok(Some(_)) | Err(_) => ConnectProgress::Failed,
    }
}

/// Whether the kernel has finished with this connect.
///
/// `POLLERR`/`POLLHUP` count as finished as much as `POLLOUT` does: a
/// refused connect can report them without `POLLOUT`, and treating that as
/// still-pending would park the entry until its timeout instead of failing
/// it now.
fn is_writable(socket: &TcpStream) -> bool {
    let mut pfd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one initialised `pollfd` with a matching count of 1, and a
    // zero timeout so the call cannot block. `poll` writes only `revents`.
    let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
    ready > 0 && pfd.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netd::test_packets::{tcp, v4_packet};
    use mvm_net::l3::flow::FlowKey;
    use mvm_protocol::l3::ip::proto;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::time::{Duration, Instant};

    use super::super::limits::{DEFAULT_MAX_HALF_OPEN, HALF_OPEN_TIMEOUT_MILLIS};

    /// The address the session leased this guest. Deliberately not the
    /// source address `syn_bytes` carries: the reset must be addressed from
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
            protocol: proto::TCP,
            guest_port,
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_port: 443,
        }
    }

    fn syn_bytes() -> Vec<u8> {
        v4_packet(
            proto::TCP,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            &tcp(50_000, 443, mvm_protocol::l3::ip::TCP_SYN),
        )
    }

    fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener")
    }

    fn some_dst() -> SocketAddr {
        listener().local_addr().expect("local addr")
    }

    fn unreachable_dst() -> SocketAddr {
        let l = listener();
        let addr = l.local_addr().expect("local addr");
        drop(l);
        addr
    }

    fn poll_until_replayable(t: &mut HalfOpenTable, budget: Duration) -> Vec<HalfOpen> {
        let deadline = Instant::now() + budget;
        loop {
            let ready = t.resolve(&mut GatewayMetrics::default()).established;
            if !ready.is_empty() || Instant::now() >= deadline {
                return ready;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A `HalfOpen` around a socket that really is connected — writable,
    /// with an empty `SO_ERROR`. That state is byte-identical to the trap
    /// states (a drained synchronous error, an `EAGAIN` socket still in
    /// `TCP_CLOSE`), so only `refused_at_open` can tell them apart.
    ///
    /// `held` is borrowed rather than opened here so the caller keeps the
    /// listener alive: dropping it would RST the peer and the socket would
    /// stop being the writable-with-no-error state under test.
    fn entry_over_a_live_socket(held: &TcpListener, refused_at_open: bool) -> HalfOpen {
        HalfOpen {
            key: key(),
            syn: syn_bytes(),
            socket: connected_socket(held),
            opened_at_millis: 0,
            refused_at_open,
        }
    }

    fn connected_socket(held: &TcpListener) -> std::net::TcpStream {
        std::net::TcpStream::connect(held.local_addr().expect("local addr")).expect("connect")
    }

    /// An entry whose socket really is connected to 127.0.0.1 while its
    /// admitted destination says somewhere else — the divergence
    /// `assert_peer_matches` exists to catch.
    fn mismatched_entry(held: &TcpListener) -> HalfOpen {
        let mut entry = entry_over_a_live_socket(held, false);
        entry.key.remote = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        entry
    }

    /// The reset owed for the standard fixture flow, built the way
    /// production builds it: through the held SYN, addressed from the lease.
    fn held_syn_reset() -> Vec<u8> {
        let held = listener();
        entry_over_a_live_socket(&held, true)
            .reset_for_guest(guest())
            .expect("an IPv4 flow to an IPv4 guest can always be reset")
    }

    #[test]
    fn a_syn_does_not_reach_the_stack_until_the_host_connect_succeeds() {
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        let outcome = t.on_syn(key(), syn_bytes(), unreachable_dst(), 0);
        assert!(matches!(outcome, SynOutcome::Started));
        assert!(
            t.resolve(&mut GatewayMetrics::default())
                .established
                .is_empty(),
            "nothing may be replayed into the stack before connect resolves"
        );
    }

    #[test]
    fn a_retransmitted_syn_folds_into_the_existing_entry() {
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        let dst = some_dst();
        t.on_syn(key(), syn_bytes(), dst, 0);
        let again = t.on_syn(key(), syn_bytes(), dst, 10);
        assert!(matches!(again, SynOutcome::Folded));
        assert_eq!(
            t.len(),
            1,
            "a retransmit must not open a second host socket"
        );
    }

    #[test]
    fn a_syn_flood_is_bounded_by_the_half_open_cap() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(4, guest());
        for i in 0..64 {
            t.on_syn(key_with_port(40_000 + i), syn_bytes(), dst, 0);
        }
        assert_eq!(
            t.len(),
            4,
            "the cap, not the descriptor limit, is what a SYN flood hits"
        );
    }

    #[test]
    fn a_full_table_refuses_the_newcomer_and_keeps_the_live_entry() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(1, guest());
        assert!(matches!(
            t.on_syn(key_with_port(1), syn_bytes(), dst, 0),
            SynOutcome::Started
        ));
        assert!(matches!(
            t.on_syn(key_with_port(2), syn_bytes(), dst, 0),
            SynOutcome::Refused(DenyCode::FlowTableFull)
        ));
        // Evicting the live entry to make room would let a guest displace
        // its own connections with a flood.
        assert!(matches!(
            t.on_syn(key_with_port(1), syn_bytes(), dst, 1),
            SynOutcome::Folded
        ));
    }

    /// A fold that refreshed the entry's clock would hand a guest an
    /// unbounded descriptor hold for the price of one SYN every ten
    /// seconds.
    ///
    /// Asserted on the stored timestamp rather than through `expire`: a
    /// live loopback connect may or may not have completed by the time
    /// `expire` runs, and since expiry rescues completed connects, routing
    /// this property through `expire` would make it a race.
    #[test]
    fn a_retransmit_does_not_extend_the_half_open_timeout() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.on_syn(key(), syn_bytes(), dst, 0);
        t.on_syn(key(), syn_bytes(), dst, HALF_OPEN_TIMEOUT_MILLIS - 1);
        assert_eq!(
            t.entries[&key()].opened_at_millis,
            0,
            "a retransmit must not restart the clock"
        );
    }

    /// The entry is latched-failed so its connect can never resolve to
    /// `Established`, which is what makes the drop deterministic — expiry
    /// deliberately rescues completed connects.
    #[test]
    fn a_half_open_entry_times_out() {
        let held = listener();
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.entries
            .insert(key(), entry_over_a_live_socket(&held, true));
        let dropped = t.expire(HALF_OPEN_TIMEOUT_MILLIS);
        assert_eq!(dropped.len(), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn an_entry_inside_its_timeout_is_not_expired() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.on_syn(key(), syn_bytes(), dst, 0);
        assert!(t.expire(HALF_OPEN_TIMEOUT_MILLIS - 1).is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn a_completed_connect_becomes_replayable_exactly_once() {
        let listener = listener();
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.on_syn(
            key(),
            syn_bytes(),
            listener.local_addr().expect("local addr"),
            0,
        );
        let _accepted = listener.accept().expect("accept");
        let first = poll_until_replayable(&mut t, Duration::from_secs(2));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].key(), key());
        assert_eq!(first[0].syn(), syn_bytes().as_slice());
        assert!(
            t.resolve(&mut GatewayMetrics::default())
                .established
                .is_empty(),
            "an entry must not be replayed twice — that would re-drive the handshake"
        );
        assert_eq!(t.len(), 0);
    }

    /// The inversion this whole type exists to prevent. A refused connect
    /// leaves the socket *writable* — writability alone would report it as
    /// established and the guest would see a successful `connect()` to a
    /// destination that rejected us.
    #[test]
    fn a_refused_connect_is_never_replayable() {
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        assert!(matches!(
            t.on_syn(key(), syn_bytes(), unreachable_dst(), 0),
            SynOutcome::Started
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let resolved = t.resolve(&mut GatewayMetrics::default());
            assert!(
                resolved.established.is_empty(),
                "a connect that failed must never be reported as established"
            );
            if let Some(failed) = resolved.failed.first() {
                // The caller must learn *which* flow failed, or it cannot
                // synthesize the reset the guest is owed.
                assert_eq!(failed.key(), key());
                assert!(t.is_empty());
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("a refused connect must resolve and be reported as failed, not linger");
    }

    /// The other half of the same inversion, and the one no live socket can
    /// demonstrate: a connect refused *synchronously* has already had its
    /// `SO_ERROR` consumed by the `connect()` return, so it polls writable
    /// with nothing pending — byte for byte what a successful connect looks
    /// like. Only the latch tells them apart, and the two assertions here
    /// differ in nothing else.
    #[test]
    fn a_drained_error_is_not_mistaken_for_a_completed_connect() {
        let held = listener();
        let mut entry = entry_over_a_live_socket(&held, true);
        assert_eq!(progress(&entry), ConnectProgress::Failed);
        entry.refused_at_open = false;
        assert_eq!(progress(&entry), ConnectProgress::Established);
    }

    /// `EAGAIN` from `connect(2)` — Linux returns it for ephemeral-port and
    /// route-cache exhaustion — is **terminal**, not a connect in progress.
    /// It shares [`io::ErrorKind::WouldBlock`] with `EINPROGRESS`, so only
    /// the raw errno separates them; classifying on `ErrorKind` reads
    /// `EAGAIN` as in-progress, leaves a socket that never left
    /// `TCP_CLOSE`, and `TCP_CLOSE` polls as `POLLHUP` with an empty
    /// `SO_ERROR` — which is `Established` on a socket connected to
    /// nothing.
    #[test]
    fn eagain_at_connect_is_terminal_not_a_connect_in_progress() {
        let eagain = io::Error::from_raw_os_error(libc::EAGAIN);
        assert!(
            !is_in_progress(&eagain),
            "EAGAIN is a failed connect, not one the kernel has taken"
        );
        assert!(is_in_progress(&io::Error::from_raw_os_error(
            libc::EINPROGRESS
        )));
        assert!(!is_in_progress(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
        // The whole trap in one line: the two errnos are indistinguishable
        // through `ErrorKind` on this platform, so a classifier that looks
        // at `ErrorKind` cannot be correct.
        if eagain.kind() == io::Error::from_raw_os_error(libc::EINPROGRESS).kind() {
            assert_ne!(libc::EAGAIN, libc::EINPROGRESS);
        }
    }

    /// The end of the chain finding 1 opens: an `EAGAIN` classified as
    /// terminal latches, and a latched entry over a socket that polls
    /// writable-with-no-error still resolves to `Failed`.
    #[test]
    fn an_eagain_at_open_is_latched_and_never_becomes_established() {
        let eagain = io::Error::from_raw_os_error(libc::EAGAIN);
        let held = listener();
        let entry = entry_over_a_live_socket(&held, !is_in_progress(&eagain));
        assert_eq!(
            progress(&entry),
            ConnectProgress::Failed,
            "an EAGAIN connect must never be reported as established"
        );
    }

    /// Expiry and resolution are driven independently. A loop that expires
    /// more often than it resolves must not throw away connections the host
    /// actually established.
    #[test]
    fn expiry_does_not_discard_a_connect_that_already_completed() {
        let held = listener();
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.entries
            .insert(key(), entry_over_a_live_socket(&held, false));
        assert!(
            t.expire(HALF_OPEN_TIMEOUT_MILLIS * 10).is_empty(),
            "a completed connect is not a stalled one, however old"
        );
        assert_eq!(t.len(), 1);
        assert_eq!(
            t.resolve(&mut GatewayMetrics::default()).established.len(),
            1
        );
    }

    #[test]
    fn a_zero_capacity_table_refuses_everything() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(0, guest());
        assert!(matches!(
            t.on_syn(key(), syn_bytes(), dst, 0),
            SynOutcome::Refused(DenyCode::FlowTableFull)
        ));
        assert_eq!(t.len(), 0);
    }

    /// A full table and a host that cannot open a socket are different
    /// conditions and must not share an audit label: one points an operator
    /// at a ceiling mvm chose, the other at the descriptor limit the OS is
    /// imposing.
    #[test]
    fn a_socket_that_cannot_be_opened_is_not_reported_as_a_full_table() {
        assert_ne!(
            DenyCode::HostSocketUnavailable.as_str(),
            DenyCode::FlowTableFull.as_str()
        );
        assert_eq!(
            DenyCode::HostSocketUnavailable.as_str(),
            "host_socket_unavailable"
        );
    }

    /// With a host TUN the admitted packet's bytes are what goes on the
    /// wire, so the checked destination is the reached one by construction.
    /// Socket translation re-derives it, so the equality has to be asserted.
    #[test]
    fn a_socket_connected_elsewhere_is_refused() {
        let held = listener();
        let sock =
            std::net::TcpStream::connect(held.local_addr().expect("local addr")).expect("connect");
        let wrong = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert!(
            assert_peer_matches(&sock, wrong).is_err(),
            "a peer that is not the admitted destination must tear the flow down"
        );
    }

    #[test]
    fn a_matching_peer_is_accepted() {
        let held = listener();
        let sock =
            std::net::TcpStream::connect(held.local_addr().expect("local addr")).expect("connect");
        assert!(assert_peer_matches(&sock, IpAddr::V4(Ipv4Addr::LOCALHOST)).is_ok());
    }

    /// A v4-mapped v6 address is the classic way to smuggle a destination
    /// past a naive equality check, and it can bite in both directions.
    ///
    /// `::ffff:127.0.0.1` and `127.0.0.1` name **one host**; the mapping is
    /// an encoding of the same 32 bits, not a different destination. So the
    /// comparison is on the canonical form: treating the two as unequal
    /// would tear down a flow that reached exactly the admitted host while
    /// denying nothing. What canonicalisation must *not* do is collapse
    /// distinct addresses, which the second half asserts.
    #[test]
    fn a_v4_mapped_peer_is_compared_on_its_canonical_form() {
        let mapped_loopback = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let mapped_elsewhere = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 1).to_ipv6_mapped());

        assert!(same_host(mapped_loopback, IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(same_host(IpAddr::V4(Ipv4Addr::LOCALHOST), mapped_loopback));
        assert!(
            !same_host(mapped_elsewhere, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "canonicalising must not make two different hosts compare equal"
        );

        // The same two directions through the real entry point, over a
        // socket whose peer genuinely is 127.0.0.1.
        let held = listener();
        let sock =
            std::net::TcpStream::connect(held.local_addr().expect("local addr")).expect("connect");
        assert!(assert_peer_matches(&sock, mapped_loopback).is_ok());
        assert!(assert_peer_matches(&sock, mapped_elsewhere).is_err());
    }

    #[test]
    fn a_failed_connect_synthesizes_a_reset_toward_the_guest() {
        let rst = held_syn_reset();
        let parsed = mvm_protocol::l3::ip::parse(&rst).expect("the synthesized packet must parse");
        assert_eq!(parsed.protocol, proto::TCP);
        let flags = mvm_protocol::l3::ip::tcp_flags(&rst, &parsed).expect("a TCP header");
        assert!(flags & mvm_protocol::l3::ip::TCP_RST != 0);

        // Sourced from the destination the flow was admitted for and
        // addressed to the leased guest — the guest's stack drops anything
        // else.
        assert_eq!(parsed.src, key().remote);
        assert_eq!(parsed.src_port, Some(key().remote_port));
        assert_eq!(parsed.dst, guest());
        assert_eq!(parsed.dst_port, Some(key().guest_port));
    }

    /// The destination of a host-originated packet comes from the lease,
    /// not from the source address the guest wrote in its own SYN. The SYN
    /// here carries a different address, and the reset must ignore it: it
    /// is only ever trustworthy because anti-spoofing upstream rejects a
    /// forged source, and a packet the host originates must not depend on a
    /// second component staying correct.
    #[test]
    fn the_reset_is_addressed_from_the_lease_not_the_guests_own_syn() {
        let syn_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_ne!(syn_source, guest(), "the fixture must be able to tell");
        let rst = held_syn_reset();
        let parsed = mvm_protocol::l3::ip::parse(&rst).expect("parses");
        assert_eq!(parsed.dst, guest());
        assert_ne!(parsed.dst, syn_source);
    }

    /// A reset a guest's TCP discards is not a reset. RFC 793 answers a SYN
    /// with `RST|ACK`, sequence zero, acknowledging the SYN's sequence plus
    /// one; anything else is out of window and the guest keeps waiting.
    #[test]
    fn the_reset_acknowledges_the_syn_it_answers() {
        let rst = held_syn_reset();
        let ip = smoltcp::wire::Ipv4Packet::new_checked(&rst).expect("ipv4");
        assert!(ip.verify_checksum(), "a real guest verifies this");
        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(tcp.rst());
        assert!(tcp.ack());
        assert_eq!(tcp.seq_number(), smoltcp::wire::TcpSeqNumber(0));
        // `syn_bytes` carries sequence zero, so the acknowledgement is one.
        assert_eq!(tcp.ack_number(), smoltcp::wire::TcpSeqNumber(1));
        assert!(
            tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()),
            "a real guest verifies this too"
        );
    }

    /// A guest cannot suppress the reset it is owed by lying about its own
    /// TCP header length. The data-offset nibble is guest-written and can
    /// declare a header longer than the bytes present; a reader that
    /// honoured it before reading the sequence number would refuse the SYN
    /// and emit nothing, which is a guest hanging on a handshake by its own
    /// choice of one nibble.
    #[test]
    fn a_lying_tcp_data_offset_cannot_suppress_the_reset() {
        let mut header = tcp(50_000, 443, mvm_protocol::l3::ip::TCP_SYN);
        header[4..8].copy_from_slice(&41u32.to_be_bytes());
        // 15 words = a 60-byte header declared inside 20 bytes.
        header[12] = 0xF0;
        let syn = v4_packet(
            proto::TCP,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            &header,
        );
        let entry = HalfOpen {
            key: key(),
            syn,
            socket: connected_socket(&listener()),
            opened_at_millis: 0,
            refused_at_open: true,
        };
        let rst = entry
            .reset_for_guest(guest())
            .expect("a crafted data offset must not suppress the reset");
        let ip = smoltcp::wire::Ipv4Packet::new_checked(&rst).expect("ipv4");
        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(tcp.rst());
        assert_eq!(tcp.ack_number(), smoltcp::wire::TcpSeqNumber(42));
    }

    /// An IPv6 flow gets a real IPv6 reset, not a skipped one. Admission
    /// refuses non-IPv4 destinations today, so this is not reachable yet —
    /// but a datapath that grew IPv6 and silently stopped resetting failed
    /// connects would reintroduce the hanging `connect()` this whole module
    /// exists to prevent, and nothing else would notice.
    #[test]
    fn an_ipv6_flow_gets_an_ipv6_reset() {
        let remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let guest_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let key = FlowKey {
            protocol: proto::TCP,
            guest_port: 50_000,
            remote: IpAddr::V6(remote),
            remote_port: 443,
        };
        let rst = synthesize_rst(&key, IpAddr::V6(guest_v6), 7).expect("an IPv6 reset");

        let parsed = mvm_protocol::l3::ip::parse(&rst).expect("parses");
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.protocol, proto::TCP);
        assert_eq!(parsed.src, IpAddr::V6(remote));
        assert_eq!(parsed.dst, IpAddr::V6(guest_v6));
        assert_eq!(parsed.src_port, Some(443));
        assert_eq!(parsed.dst_port, Some(50_000));

        let ip = smoltcp::wire::Ipv6Packet::new_checked(&rst).expect("ipv6");
        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
        assert!(tcp.rst());
        assert!(tcp.ack());
        assert_eq!(tcp.ack_number(), smoltcp::wire::TcpSeqNumber(8));
        assert!(
            tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()),
            "the IPv6 pseudo-header differs from IPv4's, so this is the check that matters"
        );
    }

    /// The only `None`: a leased guest address of a different family from
    /// the flow's remote, which cannot arise because a flow is reached over
    /// the interface the guest's address is configured on.
    #[test]
    fn a_reset_across_address_families_is_refused_rather_than_faked() {
        assert!(synthesize_rst(&key(), IpAddr::V6(Ipv6Addr::LOCALHOST), 0).is_none());
    }

    /// The check has to run before the SYN is handed back for replay, not
    /// after: a flow whose peer is not the admitted destination must never
    /// reach ESTABLISHED. `resolve` is the only way to get a SYN out of the
    /// table, so putting the check there makes "before" structural.
    #[test]
    fn a_peer_that_is_not_the_admitted_destination_never_reaches_established() {
        let held = listener();
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        let entry = mismatched_entry(&held);
        t.entries.insert(entry.key, entry);

        let mut metrics = GatewayMetrics::default();
        let resolved = t.resolve(&mut metrics);
        assert!(
            resolved.established.is_empty(),
            "a mismatched peer must not be replayed into the stack"
        );
        assert_eq!(resolved.failed.len(), 1);
        assert_eq!(resolved.resets.len(), 1, "and it is owed a reset");
        assert!(t.is_empty());
    }

    /// The violation must be *visible*, and visible as itself. A refused
    /// connect and a socket that reached the wrong host are the same event
    /// to the guest and entirely different events to the operator: one is a
    /// destination being down, the other is the single failure destination
    /// integrity exists to catch.
    ///
    /// So the mismatch counts, a refusal does not, and — the part that is
    /// easy to get wrong — the mismatch does **not** land on
    /// `wrong_destination`, which `admit` already uses for inbound packets
    /// addressed to somebody else. Sharing that label would let any guest
    /// bury this signal under routine noise it generates itself.
    #[test]
    fn a_peer_mismatch_counts_under_its_own_label_and_a_refusal_counts_at_all() {
        let held = listener();
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        let entry = mismatched_entry(&held);
        t.entries.insert(entry.key, entry);
        let mut mismatch = GatewayMetrics::default();
        t.resolve(&mut mismatch);
        assert_eq!(mismatch.denies_for(DenyCode::PeerDestinationMismatch), 1);
        assert_eq!(
            mismatch.denies_for(DenyCode::WrongDestination),
            0,
            "inbound noise and a mis-connected socket must not share a counter"
        );
        assert_eq!(mismatch.total_denies(), 1, "and nothing else");

        // The same shape of failure, arrived at honestly: the destination
        // refused. No policy event, so no deny.
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.on_syn(key(), syn_bytes(), unreachable_dst(), 0);
        let mut refusal = GatewayMetrics::default();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !t.resolve(&mut refusal).failed.is_empty() {
                assert_eq!(refusal.denies_for(DenyCode::PeerDestinationMismatch), 0);
                assert_eq!(refusal.total_denies(), 0);
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("a refused connect must resolve rather than linger");
    }

    /// The two labels are distinct strings, not just distinct variants: the
    /// metrics map is keyed by `as_str`, so equal labels would collapse the
    /// two counters however different the enum looked.
    #[test]
    fn the_peer_mismatch_label_is_distinct_from_the_inbound_one() {
        assert_eq!(
            DenyCode::PeerDestinationMismatch.as_str(),
            "peer_destination_mismatch"
        );
        assert_ne!(
            DenyCode::PeerDestinationMismatch.as_str(),
            DenyCode::WrongDestination.as_str()
        );
    }

    /// The end of the failed-connect path: a guest whose connect failed is
    /// owed a reset, and the caller gets it without reconstructing
    /// anything.
    #[test]
    fn a_failed_connect_hands_back_the_reset_the_guest_is_owed() {
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, guest());
        t.on_syn(key(), syn_bytes(), unreachable_dst(), 0);
        let mut metrics = GatewayMetrics::default();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let resolved = t.resolve(&mut metrics);
            if !resolved.failed.is_empty() {
                assert_eq!(resolved.resets.len(), 1);
                let parsed = mvm_protocol::l3::ip::parse(&resolved.resets[0]).expect("parses");
                let flags =
                    mvm_protocol::l3::ip::tcp_flags(&resolved.resets[0], &parsed).expect("flags");
                assert!(flags & mvm_protocol::l3::ip::TCP_RST != 0);
                assert_eq!(parsed.dst, guest());
                assert_eq!(
                    metrics.datapath_errors, 0,
                    "a reset that was built is not an error"
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("a refused connect must produce the reset its guest is owed");
    }

    /// A reset the datapath could not build leaves a guest hanging until
    /// its own connect timeout. That is the failure this module exists to
    /// prevent, so it is counted rather than dropped from a `filter_map`
    /// nobody can see.
    #[test]
    fn a_reset_that_cannot_be_built_is_counted_not_dropped() {
        let held = listener();
        // A guest address of a different family from the flow's remote:
        // the one input `synthesize_rst` cannot answer.
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN, IpAddr::V6(Ipv6Addr::LOCALHOST));
        t.entries
            .insert(key(), entry_over_a_live_socket(&held, true));
        let mut metrics = GatewayMetrics::default();
        let resolved = t.resolve(&mut metrics);
        assert_eq!(resolved.failed.len(), 1);
        assert!(resolved.resets.is_empty());
        assert_eq!(metrics.datapath_errors, 1);
    }
}
