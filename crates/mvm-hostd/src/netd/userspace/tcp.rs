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

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;

use mvm_net::l3::admit::DenyCode;
use mvm_net::l3::flow::FlowKey;
use socket2::{Domain, Protocol, Socket, Type};

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
}

impl HalfOpenTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
        }
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
            // The socket itself could not be created or bound to the
            // destination family — descriptor exhaustion or an address the
            // host has no route for. Both mean the host has no room to hold
            // this half-open, which is what the full-table code says.
            Err(ConnectStartError::NoSocket) => {
                return SynOutcome::Refused(DenyCode::FlowTableFull);
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

    /// Entries whose host connect has completed **successfully**, removed
    /// from the table as they are yielded.
    ///
    /// Yielded once: replaying a SYN a second time would re-drive a
    /// handshake the guest has already completed. Entries whose connect
    /// failed are dropped here rather than returned — telling the guest is
    /// the reset path's job, and reporting them as replayable is precisely
    /// the lie this type exists to prevent.
    pub fn replayable(&mut self) -> Vec<HalfOpen> {
        let mut ready = Vec::new();
        let mut still_pending = BTreeMap::new();
        for (key, entry) in std::mem::take(&mut self.entries) {
            match progress(&entry) {
                ConnectProgress::Pending => {
                    still_pending.insert(key, entry);
                }
                ConnectProgress::Established => ready.push(entry),
                ConnectProgress::Failed => drop(entry),
            }
        }
        self.entries = still_pending;
        ready
    }

    /// Drop entries whose host connect has taken longer than
    /// [`HALF_OPEN_TIMEOUT_MILLIS`], measured from when the SYN arrived.
    ///
    /// Without this a destination that neither accepts nor refuses — a
    /// dropping firewall — parks a descriptor until the kernel's own much
    /// longer connect timeout, which is a hostile guest's cheapest way to
    /// hold host resources.
    pub fn expire(&mut self, now_millis: u64) -> Vec<HalfOpen> {
        let mut dropped = Vec::new();
        let mut kept = BTreeMap::new();
        for (key, entry) in std::mem::take(&mut self.entries) {
            // Saturating: a caller whose clock stepped backwards must not
            // wrap into an enormous age and expire every live entry.
            if now_millis.saturating_sub(entry.opened_at_millis) >= HALF_OPEN_TIMEOUT_MILLIS {
                dropped.push(entry);
            } else {
                kept.insert(key, entry);
            }
        }
        self.entries = kept;
        dropped
    }
}

/// Why a connect could not even be started.
enum ConnectStartError {
    /// The kernel answered synchronously with a failure. The socket comes
    /// back so the entry can still exist and be reported to the guest
    /// through the same path as an asynchronous failure.
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
        // A synchronous refusal. The error has been handed to us and
        // `SO_ERROR` cleared with it, so the caller latches this rather
        // than trusting a later readiness check to rediscover it.
        Err(_) => Err(ConnectStartError::Refused(socket.into())),
    }
}

fn is_in_progress(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock)
        || e.raw_os_error() == Some(libc::EINPROGRESS)
        || e.raw_os_error() == Some(libc::EALREADY)
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
    use mvm_net::l3::flow::FlowKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::time::{Duration, Instant};

    use super::super::limits::{DEFAULT_MAX_HALF_OPEN, HALF_OPEN_TIMEOUT_MILLIS};

    fn key() -> FlowKey {
        key_with_port(50_000)
    }

    fn key_with_port(guest_port: u16) -> FlowKey {
        FlowKey {
            protocol: mvm_protocol::l3::ip::proto::TCP,
            guest_port,
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            remote_port: 443,
        }
    }

    fn syn_bytes() -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50_000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = mvm_protocol::l3::ip::TCP_SYN;

        let total = 20 + tcp.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = mvm_protocol::l3::ip::proto::TCP;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        packet.extend_from_slice(&tcp);
        packet
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
            let ready = t.replayable();
            if !ready.is_empty() || Instant::now() >= deadline {
                return ready;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_syn_does_not_reach_the_stack_until_the_host_connect_succeeds() {
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
        let outcome = t.on_syn(key(), syn_bytes(), unreachable_dst(), 0);
        assert!(matches!(outcome, SynOutcome::Started));
        assert!(
            t.replayable().is_empty(),
            "nothing may be replayed into the stack before connect resolves"
        );
    }

    #[test]
    fn a_retransmitted_syn_folds_into_the_existing_entry() {
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
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
        let mut t = HalfOpenTable::new(4);
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
        let mut t = HalfOpenTable::new(1);
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
    #[test]
    fn a_retransmit_does_not_extend_the_half_open_timeout() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
        t.on_syn(key(), syn_bytes(), dst, 0);
        t.on_syn(key(), syn_bytes(), dst, HALF_OPEN_TIMEOUT_MILLIS - 1);
        assert_eq!(t.expire(HALF_OPEN_TIMEOUT_MILLIS).len(), 1);
    }

    #[test]
    fn a_half_open_entry_times_out() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
        t.on_syn(key(), syn_bytes(), dst, 0);
        let dropped = t.expire(HALF_OPEN_TIMEOUT_MILLIS);
        assert_eq!(dropped.len(), 1);
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn an_entry_inside_its_timeout_is_not_expired() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
        t.on_syn(key(), syn_bytes(), dst, 0);
        assert!(t.expire(HALF_OPEN_TIMEOUT_MILLIS - 1).is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn a_completed_connect_becomes_replayable_exactly_once() {
        let listener = listener();
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
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
            t.replayable().is_empty(),
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
        let mut t = HalfOpenTable::new(DEFAULT_MAX_HALF_OPEN);
        assert!(matches!(
            t.on_syn(key(), syn_bytes(), unreachable_dst(), 0),
            SynOutcome::Started
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            assert!(
                t.replayable().is_empty(),
                "a connect that failed must never be reported as established"
            );
            if t.is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("a refused connect must resolve and be dropped, not linger until timeout");
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
        let addr = held.local_addr().expect("local addr");
        let connected = std::net::TcpStream::connect(addr).expect("connect");
        let mut entry = HalfOpen {
            key: key(),
            syn: syn_bytes(),
            socket: connected,
            opened_at_millis: 0,
            refused_at_open: true,
        };
        assert_eq!(progress(&entry), ConnectProgress::Failed);
        entry.refused_at_open = false;
        assert_eq!(progress(&entry), ConnectProgress::Established);
    }

    #[test]
    fn a_zero_capacity_table_refuses_everything() {
        let held = listener();
        let dst = held.local_addr().expect("local addr");
        let mut t = HalfOpenTable::new(0);
        assert!(matches!(
            t.on_syn(key(), syn_bytes(), dst, 0),
            SynOutcome::Refused(DenyCode::FlowTableFull)
        ));
        assert_eq!(t.len(), 0);
    }
}
