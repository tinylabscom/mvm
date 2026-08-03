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
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;

use mvm_net::l3::admit::DenyCode;
use mvm_net::l3::flow::FlowKey;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::tcp::{RecvError, Socket as TcpSocket, SocketBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv4Repr,
    Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};

use crate::netd::datapath::DatapathError;
use crate::netd::metrics::GatewayMetrics;

use super::accept_mtu;
use super::device::{GuestDevice, PushOutcome, QueueDepths};
use super::limits::{
    FLOW_RX_QUEUE_DEPTH, FLOW_TX_QUEUE_DEPTH, HALF_OPEN_TIMEOUT_MILLIS, KEEPALIVE_IDLE_SECS,
    KEEPALIVE_PROBE_INTERVAL_SECS, KEEPALIVE_PROBE_RETRIES, RESET_DELIVERY_TIMEOUT_MILLIS,
    SOCKET_RX_BUFFER, SOCKET_TX_BUFFER,
};

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

    /// Drop every held entry, closing the host descriptor each one parks.
    ///
    /// Teardown, not policy: the guests behind these entries are owed
    /// nothing, because the machine they belong to is going away with them.
    pub fn clear(&mut self) {
        self.entries.clear();
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

/// What one bounded pump pass moved.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PumpStats {
    /// Bytes taken out of the stack and written to the host socket.
    pub to_host: usize,
    /// Bytes read off the host socket and handed to the stack.
    pub to_guest: usize,
    /// Times a direction had bytes to move and the far side would not take
    /// them. This is the visible half of backpressure: the bytes stay
    /// where they were and the window closes behind them.
    pub stalled: usize,
}

/// The most either direction may move in one pass.
///
/// Not a new number: it is the tighter of the two per-socket buffers, the
/// same pair the per-machine memory ceiling is computed from. One pass
/// cannot exceed it anyway, because nothing refills a buffer mid-pass — so
/// this states the bound rather than inventing one, and keeps it stated if
/// a later change ever does let a buffer drain inside a pass.
pub const fn max_bytes_per_pass() -> usize {
    const {
        // A budget at or past a buffer is no bound at all — it is a no-op
        // the moment anything frees buffer space mid-pass. Asserted at
        // compile time because no behavioural test can separate the two
        // limits while they coincide.
        assert!(pass_budget() <= SOCKET_RX_BUFFER);
        assert!(pass_budget() <= SOCKET_TX_BUFFER);
        assert!(pass_budget() > 0);
    }
    pass_budget()
}

const fn pass_budget() -> usize {
    if SOCKET_RX_BUFFER < SOCKET_TX_BUFFER {
        SOCKET_RX_BUFFER
    } else {
        SOCKET_TX_BUFFER
    }
}

/// One admitted flow: the guest's TCP terminated in userspace, and the same
/// conversation re-originated on a host socket.
///
/// Each flow carries its own stack rather than sharing one interface with a
/// socket per flow. The guest addresses each flow at *its own* destination,
/// so a shared interface would have to hold every destination any guest
/// dialled — smoltcp's address list holds four — or else answer for every
/// address in existence via `set_any_ip`, which is a far wider surface than
/// one interface per admitted destination. Per-flow also makes the buffer
/// ceiling per-flow arithmetic rather than a shared pool one talkative flow
/// can monopolise.
pub struct EstablishedFlow {
    key: FlowKey,
    /// The address this session leased the guest, for the resets a failing
    /// flow owes it.
    guest: IpAddr,
    /// `Option` so the descriptor can be released deterministically rather
    /// than whenever the flow happens to drop.
    host: Option<TcpStream>,
    device: GuestDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    /// The guest has closed its sending half. Latched, because the host
    /// shutdown it implies may have to wait for buffered bytes to drain.
    guest_fin_seen: bool,
    /// The shutdown has been attempted, successfully or not.
    fin_forwarded: bool,
    write_shutdown: bool,
    host_read_eof: bool,
    /// The first non-recoverable host-socket error this flow met. Kept
    /// rather than dropped: a silent drop here is a guest hanging to its
    /// own timeout with nothing to explain it.
    host_error: Option<io::ErrorKind>,
    /// The clock the stack was last driven at.
    ///
    /// Held so a host-side failure can be turned into a reset *now*,
    /// without a timestamp from the caller: a reset built at time zero on a
    /// stack whose timers are minutes in would be emitted against a clock
    /// that has already run, and every retransmit and timeout on this flow
    /// would be judged against the wrong instant.
    last_polled_millis: u64,
    /// A reset is owed to the guest but has not been sent yet, and the
    /// clock at which it goes out regardless. `Some` means owed.
    /// See [`Self::deliver_then_reset`].
    reset_deadline: Option<u64>,
}

impl EstablishedFlow {
    /// Build a flow from a half-open entry whose host connect completed,
    /// replaying the held SYN into the flow's own stack so the guest's
    /// handshake completes only against a destination that really accepted.
    pub fn from_half_open(
        entry: HalfOpen,
        guest: IpAddr,
        mtu: usize,
        now_millis: u64,
    ) -> Result<Self, DatapathError> {
        let key = entry.key();
        let syn = entry.syn().to_vec();
        let mut flow = Self::open(entry.into_socket(), key, guest, mtu, now_millis)?;
        flow.deliver_from_guest(&syn);
        flow.poll(now_millis);
        Ok(flow)
    }

    fn open(
        host: TcpStream,
        key: FlowKey,
        guest: IpAddr,
        mtu: usize,
        now_millis: u64,
    ) -> Result<Self, DatapathError> {
        // Re-asserted rather than assumed: a blocking write in the pump
        // would park the whole drive loop on one slow destination.
        host.set_nonblocking(true)?;
        // The only thing that separates a connection nobody is using from
        // one nobody is answering. An established flow is otherwise
        // ageless — nothing in TCP obliges either end to speak — so without
        // this a peer that vanished silently holds its descriptor for as
        // long as the machine lives. Deliberately *not* an idle timer:
        // this datapath carries streaming protocols that are quiet by
        // design, and quietness is not a fault. When the probes go
        // unanswered the socket errors, and the ordinary host-error path
        // resets the guest and gives the descriptor back.
        SockRef::from(&host).set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(KEEPALIVE_IDLE_SECS))
                .with_interval(std::time::Duration::from_secs(
                    KEEPALIVE_PROBE_INTERVAL_SECS,
                ))
                .with_retries(KEEPALIVE_PROBE_RETRIES),
        )?;

        // The per-flow depths, never the machine-wide default: this device
        // is per flow, so its depths multiply by the socket cap and are
        // part of the per-machine ceiling. That ceiling is also computed
        // from the fixed MTU, so an MTU above it is refused rather than
        // sized for. Asymmetric because the guest-bound side has to hold
        // an ACK burst as well as a pass's data.
        let mut device = GuestDevice::new(
            accept_mtu(mtu)?,
            QueueDepths {
                from_guest: FLOW_RX_QUEUE_DEPTH,
                to_guest: FLOW_TX_QUEUE_DEPTH,
            },
        );
        let mut config = Config::new(HardwareAddress::Ip);
        // Recommended by smoltcp's own doc on `Config::random_seed`: a
        // predictable seed would make the ISNs and IPv4 identification
        // field this flow generates predictable too — to the guest, which
        // is the one party here we do not trust.
        config.random_seed = rand::random();
        // Seeded with the caller's clock, not zero: an interface born at
        // zero and then polled at the real time jumps its whole timer base
        // forward on the first pass.
        let mut interface = Interface::new(config, &mut device, smol_now(now_millis));
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(host_cidr(key.remote))
                .expect("a freshly created address list has room for its first entry");
        });

        let mut socket = TcpSocket::new(
            SocketBuffer::new(vec![0u8; SOCKET_RX_BUFFER]),
            SocketBuffer::new(vec![0u8; SOCKET_TX_BUFFER]),
        );
        socket
            .listen(IpListenEndpoint {
                addr: Some(smol_addr(key.remote)),
                port: key.remote_port,
            })
            .map_err(|e| {
                DatapathError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cannot terminate the guest half of {key:?}: {e}"),
                ))
            })?;
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);

        Ok(Self {
            key,
            guest,
            host: Some(host),
            device,
            interface,
            sockets,
            handle,
            guest_fin_seen: false,
            fin_forwarded: false,
            write_shutdown: false,
            host_read_eof: false,
            host_error: None,
            last_polled_millis: now_millis,
            reset_deadline: None,
        })
    }

    pub fn key(&self) -> FlowKey {
        self.key
    }

    /// The address this session leased the guest.
    pub fn guest(&self) -> IpAddr {
        self.guest
    }

    /// Hand a guest packet to this flow's stack.
    pub fn deliver_from_guest(&mut self, packet: &[u8]) -> PushOutcome {
        self.device.push_from_guest(packet)
    }

    /// Take one packet the stack has produced for the guest, oldest first.
    ///
    /// The single-packet form is what a datapath read wants: its caller
    /// hands over one buffer and takes one packet, and a version that
    /// drained the whole queue would need somewhere to put the rest.
    pub fn next_guest_packet(&mut self) -> Option<Vec<u8>> {
        self.device.pop_for_guest()
    }

    /// Packets waiting on the guest's drain.
    ///
    /// A flow whose connection has ended still owes the guest whatever it
    /// already produced — the reset that explains the ending, above all —
    /// so this is what stops a reaper discarding those bytes.
    pub fn pending_to_guest(&self) -> usize {
        self.device.pending_to_guest()
    }

    /// Take everything the stack has produced for the guest.
    ///
    /// Bounded by the device's queue depth, which drops rather than grows.
    pub fn take_guest_packets(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(packet) = self.next_guest_packet() {
            out.push(packet);
        }
        out
    }

    /// Move bytes in both directions, once, within a bounded budget.
    ///
    /// Takes `metrics` so a guest-bound queue overflow reaches an operator
    /// and not only a debugger holding the flow: the drop costs the guest
    /// a retransmission timeout, and a symptom that expensive has to be
    /// countable from outside the process.
    pub fn pump(&mut self, now_millis: u64, metrics: &mut GatewayMetrics) -> PumpStats {
        let mut stats = PumpStats::default();
        let dropped_before = self.device.dropped_to_guest();
        // Ingest what the guest sent and let the stack answer it, so this
        // pass works on the freshest state rather than the last one's.
        self.poll(now_millis);
        if self.guest_to_host(&mut stats) {
            self.guest_fin_seen = true;
        }
        self.forward_guest_fin();
        self.host_to_guest(&mut stats);
        // A host socket that failed is a conversation that cannot continue,
        // in either direction. Told here rather than left for a caller to
        // notice, because the caller that does not notice leaves the guest
        // waiting on a socket nobody is going to answer. A reset deferred
        // by [`Self::deliver_then_reset`] is retried on every later pass,
        // which is why this does not test `host_error` alone.
        if let Some(kind) = self.host_error {
            self.on_host_error(kind);
        }
        // Emit what the two directions produced, so the guest's ACKs and
        // the peer's bytes leave in the pass they arrived in.
        self.poll(now_millis);
        // A delta rather than an assignment: the flow's own counter is
        // cumulative and several flows share one metrics record.
        metrics.queue_drops_egress = metrics
            .queue_drops_egress
            .saturating_add(self.device.dropped_to_guest() - dropped_before);
        stats
    }

    /// Reconcile the host socket's write half with the stack's view of the
    /// guest's sending half.
    ///
    /// `shutdown(Write)`, never `close`: the peer may have a whole response
    /// still to write, and closing would discard it and break every
    /// half-duplex protocol. Guest bytes the host has not seen yet are
    /// written first — see [`Self::forward_guest_fin`].
    ///
    /// A caller reaches for this because it believes it saw a FIN. That
    /// belief is a **hint to look**, never the authority: the FIN flag is
    /// guest-written, and a caller reading it off the packet reads it
    /// before the stack has judged whether the segment was even in window.
    /// Taking the caller's word lets a guest half-close a conversation it
    /// never legitimately closed — truncating the in-flight request, and
    /// wedging the flow, since nothing may be written after a forwarded
    /// FIN. So the only thing that latches it here is
    /// [`RecvError::Finished`] from the stack itself, exactly as in
    /// [`Self::pump`]. An out-of-window FIN the stack discarded leaves
    /// this a no-op.
    pub fn on_guest_fin(&mut self) {
        let mut stats = PumpStats::default();
        if self.guest_to_host(&mut stats) {
            self.guest_fin_seen = true;
        }
        self.forward_guest_fin();
    }

    /// Tell the guest that this flow's host socket has failed, and release
    /// it.
    ///
    /// Without this the guest's stack waits on a connection nobody is going
    /// to answer, for as long as its own retransmit timer takes to give up
    /// — minutes, during which the guest's application looks wedged for no
    /// visible reason. A reset turns that into an immediate `ECONNRESET`,
    /// which the guest's stack already knows what to do with.
    ///
    /// The reset comes from the live socket's own [`TcpSocket::abort`],
    /// **not** from [`synthesize_rst`]. That function answers a SYN whose
    /// sequence number is right there in the held SYN; an established flow
    /// has no held SYN, and its correct sequence numbers live inside the
    /// stack, where nothing outside can read them. Fabricating a pair here
    /// would produce a reset outside the guest's window, which its stack
    /// discards in silence — leaving exactly the hang this exists to
    /// prevent, now with a packet on the wire to make it look handled.
    /// smoltcp emits one reset per aborted connection and then forgets the
    /// endpoint, so calling this twice cannot produce two.
    ///
    /// [`io::ErrorKind::WouldBlock`] and [`io::ErrorKind::Interrupted`] are
    /// not failures and are ignored — see [`is_terminal_host_error`].
    pub fn on_host_error(&mut self, kind: io::ErrorKind) {
        if !is_terminal_host_error(kind) {
            return;
        }
        if self.host.is_some() {
            // `get_or_insert`, so the *first* error is the one that
            // explains the flow. A later one is a consequence of it.
            self.host_error.get_or_insert(kind);
            // The descriptor is dead whatever happens next; release it now
            // rather than holding it for however long the reset takes.
            self.close_host();
            // Taken once, from the failure, and never moved afterwards —
            // see [`RESET_DELIVERY_TIMEOUT_MILLIS`].
            self.reset_deadline = Some(
                self.last_polled_millis
                    .saturating_add(RESET_DELIVERY_TIMEOUT_MILLIS),
            );
        }
        if self.reset_deadline.is_some() {
            self.deliver_then_reset();
        }
    }

    /// Hand the guest everything the host already received for it, and only
    /// then reset.
    ///
    /// The peer's last act is very often to send a complete response and
    /// then close hard — `SO_LINGER 0`, which surfaces here as
    /// `ECONNRESET`. Those bytes are already on this host, sitting in the
    /// stack's send buffer, and smoltcp's aborted-socket dispatch emits a
    /// **payload-less** RST: resetting first throws away a response the
    /// server did send, and the guest's application sees a request that
    /// failed for no reason. Losing an answered request is worse than the
    /// hang the reset exists to prevent.
    ///
    /// So the reset waits for the send buffer to empty, which means waiting
    /// for the guest to *acknowledge* those bytes rather than merely for
    /// them to be emitted. A reset arriving alongside unacknowledged data
    /// is entitled to discard it — that is what a receiving stack does with
    /// its pending receive queue — so "emitted" is not the same as
    /// "delivered", and only the acknowledgement proves the second.
    ///
    /// **Bounded by its own deadline**, not by anything outside: a guest
    /// that stops acknowledging — a crash, a zero window, or simply a
    /// hostile guest choosing not to — would otherwise hold this flow's
    /// buffers and its slot in the host's socket budget for the machine's
    /// whole life, since nothing else ages an established flow and the
    /// descriptor this one would have blocked on is already gone.
    ///
    /// The deadline is absolute and set once at the failure. It is
    /// deliberately not smoltcp's `set_timeout`, which measures the gap
    /// between packets the *remote* sends: a guest can refresh that by
    /// acknowledging without ever draining, and a terminator a guest can
    /// postpone is not a terminator. `set_timeout` is also evaluated
    /// unconditionally in smoltcp's dispatch, so a socket left carrying one
    /// would abort a perfectly healthy quiet connection — the streaming
    /// case this datapath must not break.
    fn deliver_then_reset(&mut self) {
        // Emit whatever the guest's window allows before anything else.
        self.poll(self.last_polled_millis);
        let overdue = self
            .reset_deadline
            .is_some_and(|deadline| self.last_polled_millis >= deadline);
        if self.socket().send_queue() > 0 && !overdue {
            return;
        }
        self.sockets.get_mut::<TcpSocket>(self.handle).abort();
        // Aborting only moves the socket's state; the reset itself leaves
        // on the next poll.
        self.poll(self.last_polled_millis);
        self.reset_deadline = None;
    }

    /// Release the host descriptor now rather than at drop.
    pub fn close_host(&mut self) {
        self.host = None;
    }

    /// Bytes this flow is holding on the guest's behalf, in either
    /// direction, across **every** place it holds them.
    ///
    /// The device queues are counted alongside the socket's ring buffers
    /// rather than left out. They are the larger of the two terms, and a
    /// measure that omitted them would report a flow as inside its bound
    /// while its packet queues grew — which is exactly the growth
    /// [`FLOW_BUFFER_BYTES`](super::limits::FLOW_BUFFER_BYTES) exists to
    /// bound, and the only growth a test can observe.
    pub fn bytes_buffered(&self) -> usize {
        let socket = self.socket();
        socket.recv_queue() + socket.send_queue() + self.device.bytes_queued()
    }

    /// Whether the host socket's write half has been shut down.
    pub fn host_write_shutdown(&self) -> bool {
        self.write_shutdown
    }

    /// Whether the host descriptor has been released.
    pub fn host_socket_closed(&self) -> bool {
        self.host.is_none()
    }

    /// Stack-produced packets this flow discarded because the guest-bound
    /// queue was full. Each one costs the guest a retransmission timeout,
    /// so a non-zero value here is a real symptom, not noise.
    pub fn dropped_to_guest(&self) -> u64 {
        self.device.dropped_to_guest()
    }

    /// Whether the guest's connection is still exchanging packets.
    pub fn is_active(&self) -> bool {
        self.socket().is_active()
    }

    /// The first non-recoverable host-socket error, if any. The guest is
    /// owed a reset for it; building that reset is not this type's job.
    pub fn host_error(&self) -> Option<io::ErrorKind> {
        self.host_error
    }

    fn socket(&self) -> &TcpSocket<'static> {
        self.sockets.get::<TcpSocket>(self.handle)
    }

    fn poll(&mut self, now_millis: u64) {
        self.last_polled_millis = now_millis;
        self.interface
            .poll(smol_now(now_millis), &mut self.device, &mut self.sockets);
    }

    /// Move guest bytes out of the stack and onto the host socket, and
    /// report whether the guest has finished sending.
    ///
    /// The host write's own return value decides how much is consumed from
    /// the stack, so a short write leaves the remainder exactly where it
    /// was and `WouldBlock` consumes nothing at all. There is no second
    /// copy and no offset to keep. That *is* the backpressure mechanism:
    /// unconsumed bytes hold the stack's receive window closed, and the
    /// guest's own TCP stops sending. Nothing counts them and nothing has
    /// to.
    fn guest_to_host(&mut self, stats: &mut PumpStats) -> bool {
        let Self {
            host,
            sockets,
            handle,
            host_error,
            write_shutdown,
            ..
        } = self;
        // Nothing may follow a FIN we have already forwarded.
        if *write_shutdown {
            return false;
        }
        let Some(stream) = host.as_mut() else {
            return false;
        };
        let socket = sockets.get_mut::<TcpSocket>(*handle);
        let mut budget = max_bytes_per_pass();
        while budget > 0 {
            let borrowed = &mut *stream;
            let step = match socket.recv(|data| write_some(borrowed, data, budget)) {
                Ok(step) => step,
                // Every byte the guest will ever send has been handed over.
                Err(RecvError::Finished) => return true,
                Err(RecvError::InvalidState) => break,
            };
            match step {
                HostWrite::Wrote(n) => {
                    stats.to_host += n;
                    budget -= n;
                }
                HostWrite::Idle => break,
                HostWrite::Blocked => {
                    stats.stalled += 1;
                    break;
                }
                HostWrite::Failed(kind) => {
                    *host_error = Some(kind);
                    break;
                }
            }
        }
        false
    }

    /// Move peer bytes off the host socket and into the stack.
    ///
    /// The mirror of the rule above: when the stack's send buffer is full
    /// we stop reading the host socket, its own receive window closes, and
    /// the peer stalls.
    fn host_to_guest(&mut self, stats: &mut PumpStats) {
        let Self {
            host,
            sockets,
            handle,
            host_read_eof,
            host_error,
            ..
        } = self;
        if *host_read_eof {
            return;
        }
        let Some(stream) = host.as_mut() else {
            return;
        };
        let socket = sockets.get_mut::<TcpSocket>(*handle);
        let mut budget = max_bytes_per_pass();
        while budget > 0 {
            if !socket.may_send() {
                break;
            }
            if !socket.can_send() {
                stats.stalled += 1;
                break;
            }
            let borrowed = &mut *stream;
            let step = match socket.send(|buf| read_some(borrowed, buf, budget)) {
                Ok(step) => step,
                Err(_) => break,
            };
            match step {
                HostRead::Read(n) => {
                    stats.to_guest += n;
                    budget -= n;
                }
                HostRead::Idle => break,
                // The peer has closed its sending half. Pass that on as a
                // FIN so the guest's read returns instead of hanging; our
                // own write half stays open, because the guest may not be
                // finished.
                HostRead::Eof => {
                    *host_read_eof = true;
                    socket.close();
                    break;
                }
                HostRead::Failed(kind) => {
                    *host_error = Some(kind);
                    break;
                }
            }
        }
    }

    /// Hand the guest's FIN on to the host, once, and only once every guest
    /// byte has already been written there.
    ///
    /// Shutting down early truncates the request: the guest's last segment
    /// can still be sitting in the stack's receive buffer when its FIN
    /// arrives, and the peer would see a short body followed by a clean
    /// close — indistinguishable from the guest having sent exactly that.
    fn forward_guest_fin(&mut self) {
        if !self.guest_fin_seen || self.fin_forwarded {
            return;
        }
        if self.socket().recv_queue() > 0 {
            return;
        }
        let Some(stream) = self.host.as_ref() else {
            return;
        };
        // Latched before the call, so a shutdown the kernel refuses — the
        // peer having already reset, say — is not retried every pass.
        self.fin_forwarded = true;
        match stream.shutdown(Shutdown::Write) {
            Ok(()) => self.write_shutdown = true,
            Err(e) => self.host_error = Some(e.kind()),
        }
    }
}

impl std::fmt::Debug for EstablishedFlow {
    /// Hand-written for the same reason [`HalfOpen`]'s is: the buffers hold
    /// guest-controlled bytes, and a derived `Debug` would splatter them
    /// into any log line that formats a flow table.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstablishedFlow")
            .field("key", &self.key)
            .field("bytes_buffered", &self.bytes_buffered())
            .field("write_shutdown", &self.write_shutdown)
            .field("host_read_eof", &self.host_read_eof)
            .field("host_closed", &self.host.is_none())
            .field("host_error", &self.host_error)
            .finish()
    }
}

/// Whether a host-socket error ends the flow, as opposed to asking the
/// caller to come back.
///
/// The two transient kinds are named and everything else is terminal,
/// rather than the reverse. A kind missing from a terminal *allow*-list is
/// a flow that hangs until the guest's own timer gives up, with nothing to
/// say why; a kind wrongly treated as terminal is a connection that ends
/// with a reset the guest's application sees immediately. The second
/// failure is visible and the first is not, so the default falls that way.
///
/// `WouldBlock` and `Interrupted` are not failures at all: they are a
/// non-blocking socket saying "not now" and a syscall interrupted by a
/// signal. Treating either as fatal would tear down healthy flows under
/// exactly the load that produces them.
fn is_terminal_host_error(kind: io::ErrorKind) -> bool {
    !matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
}

/// What one attempt to hand bytes to the host socket did.
enum HostWrite {
    Wrote(usize),
    /// There was nothing to write. Not a stall: there was no demand.
    Idle,
    /// The host will not take a byte. Nothing was consumed from the stack.
    Blocked,
    Failed(io::ErrorKind),
}

/// What one attempt to take bytes off the host socket did.
enum HostRead {
    Read(usize),
    /// Nothing available right now.
    Idle,
    /// The peer closed its sending half.
    Eof,
    Failed(io::ErrorKind),
}

/// Write at most `budget` bytes of `data`, reporting how many the host
/// actually took so the caller consumes exactly that much.
fn write_some(stream: &mut TcpStream, data: &mut [u8], budget: usize) -> (usize, HostWrite) {
    let take = data.len().min(budget);
    if take == 0 {
        return (0, HostWrite::Idle);
    }
    match stream.write(&data[..take]) {
        // Zero bytes written from a non-empty slice is not progress; read
        // as a refusal so the loop cannot spin on it.
        Ok(0) => (0, HostWrite::Blocked),
        Ok(n) => (n, HostWrite::Wrote(n)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, HostWrite::Blocked),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => (0, HostWrite::Idle),
        Err(e) => (0, HostWrite::Failed(e.kind())),
    }
}

/// Read at most `budget` bytes into the stack's send buffer, reporting how
/// many arrived so the caller enqueues exactly that much.
fn read_some(stream: &mut TcpStream, buf: &mut [u8], budget: usize) -> (usize, HostRead) {
    let take = buf.len().min(budget);
    if take == 0 {
        return (0, HostRead::Idle);
    }
    match stream.read(&mut buf[..take]) {
        Ok(0) => (0, HostRead::Eof),
        Ok(n) => (n, HostRead::Read(n)),
        // A host with nothing to say is idle, not stalled — the stall in
        // this direction is our *own* buffer filling up.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, HostRead::Idle),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => (0, HostRead::Idle),
        Err(e) => (0, HostRead::Failed(e.kind())),
    }
}

/// The single-host prefix for `ip`, the only address a flow's stack answers
/// for: the destination the guest dialled and policy admitted.
fn host_cidr(ip: IpAddr) -> IpCidr {
    match ip {
        IpAddr::V4(a) => IpCidr::new(IpAddress::Ipv4(a), 32),
        IpAddr::V6(a) => IpCidr::new(IpAddress::Ipv6(a), 128),
    }
}

/// The caller's clock in the stack's own units. Saturating, so a caller
/// whose clock is past the i64 millisecond range cannot wrap the stack's
/// timers into the past.
fn smol_now(now_millis: u64) -> SmolInstant {
    SmolInstant::from_millis(i64::try_from(now_millis).unwrap_or(i64::MAX))
}

fn smol_addr(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
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
        (IpAddr::V4(remote), IpAddr::V4(guest)) => Some(emit_v4_segment(remote, guest, &tcp)),
        (IpAddr::V6(remote), IpAddr::V6(guest)) => Some(emit_v6_segment(remote, guest, &tcp)),
        _ => None,
    }
}

/// Emit `tcp` inside an IPv4 header. The header checksum is written by
/// `emit` and covers only the header, so writing the segment afterwards
/// does not invalidate it.
///
/// Named by direction rather than by role: this datapath emits segments
/// both ways — host-originated resets toward the guest, and, in the test
/// fixtures, guest segments toward a destination — and a signature that
/// said `remote, guest` would read as an argument order the second use
/// violates.
pub(super) fn emit_v4_segment(src: Ipv4Addr, dst: Ipv4Addr, tcp: &TcpRepr<'_>) -> Vec<u8> {
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
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
        &src.into(),
        &dst.into(),
        &checksums,
    );
    bytes
}

/// Emit `tcp` inside an IPv6 header. IPv6 has no header checksum, but the
/// TCP checksum is computed over a different pseudo-header from IPv4's, so
/// the two cannot share an emitter.
fn emit_v6_segment(remote: Ipv6Addr, guest: Ipv6Addr, tcp: &TcpRepr<'_>) -> Vec<u8> {
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
    use mvm_protocol::l3::limits::MTU_V1;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::time::{Duration, Instant};

    use super::super::limits::{
        DATA_SEGMENTS_PER_PASS, DEFAULT_MAX_HALF_OPEN, FLOW_BUFFER_BYTES, HALF_OPEN_TIMEOUT_MILLIS,
        POLLS_PER_PASS, SOCKET_RX_BUFFER, SOCKET_TX_BUFFER,
    };

    impl EstablishedFlow {
        /// A pass whose drop counter nobody is reading. Tests that assert
        /// on `queue_drops_egress` call the real signature instead.
        fn pump_ignoring_metrics(&mut self, now_millis: u64) -> PumpStats {
            self.pump(now_millis, &mut GatewayMetrics::default())
        }
    }

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

    // ---- established flows ------------------------------------------

    /// The destination the fixture flow was admitted for.
    ///
    /// Deliberately not a loopback address, even though the host socket
    /// underneath *is* a loopback pair: the guest-facing stack is addressed
    /// by the admitted destination while the host socket is addressed by
    /// the kernel, and a fixture where the two coincide could not tell
    /// which of them a bug had reached for.
    fn flow_key() -> FlowKey {
        FlowKey {
            protocol: proto::TCP,
            guest_port: 50_000,
            remote: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            remote_port: 443,
        }
    }

    fn guest_v4() -> Ipv4Addr {
        match guest() {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => unreachable!("the fixture lease is IPv4"),
        }
    }

    /// The guest's initial sequence number. Any value works; a fixed one
    /// makes a desynchronised fixture obvious in a packet dump.
    const GUEST_ISN: u32 = 1_000;

    /// Writes attempted before a fixture that cannot fill a socket gives up.
    ///
    /// A fake that never reports `WouldBlock` would turn this suite's
    /// negatives into a hang rather than a failure, so every fill is
    /// bounded and its inability to block is reported to the caller.
    const FILL_ATTEMPTS: usize = 512;

    /// Pump passes a fixture will wait through for the peer's bytes to
    /// cross loopback. Bounded for the same reason.
    const PUMP_ATTEMPTS: usize = 100;

    /// A guest TCP endpoint driven by hand.
    ///
    /// The real guest is on the other side of a vsock link; here its
    /// segments are built directly so a test can decide exactly what the
    /// stack sees and when.
    struct FakeGuest {
        key: FlowKey,
        guest: Ipv4Addr,
        seq: u32,
        /// What to acknowledge — the stack's ISN plus one. Zero until the
        /// SYN-ACK has been read.
        ack: u32,
        /// The MSS this guest's SYN advertises. `None` omits the option
        /// entirely, which an ordinary guest may well do and which drops
        /// the stack to its 536 byte default — the case that decides how
        /// deep the guest-bound queue has to be.
        mss: Option<u16>,
    }

    impl FakeGuest {
        fn new(key: FlowKey) -> Self {
            Self {
                key,
                guest: guest_v4(),
                seq: GUEST_ISN,
                ack: 0,
                mss: Some(1_400),
            }
        }

        /// A guest whose SYN carries no MSS option at all.
        fn without_mss_option(key: FlowKey) -> Self {
            Self {
                mss: None,
                ..Self::new(key)
            }
        }

        /// A guest that asks for segments so small that no queue depth can
        /// hold a pass's worth of them.
        fn with_tiny_mss(key: FlowKey) -> Self {
            Self {
                mss: Some(64),
                ..Self::new(key)
            }
        }

        fn remote_v4(&self) -> Ipv4Addr {
            match self.key.remote {
                IpAddr::V4(a) => a,
                IpAddr::V6(_) => unreachable!("the fixture flow is IPv4"),
            }
        }

        fn segment(&self, control: TcpControl, ack: Option<u32>, payload: &[u8]) -> Vec<u8> {
            let tcp = TcpRepr {
                src_port: self.key.guest_port,
                dst_port: self.key.remote_port,
                control,
                seq_number: TcpSeqNumber(self.seq as i32),
                ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
                window_len: u16::MAX,
                window_scale: None,
                max_seg_size: matches!(control, TcpControl::Syn)
                    .then_some(self.mss)
                    .flatten(),
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload,
            };
            emit_v4_segment(self.guest, self.remote_v4(), &tcp)
        }

        fn syn(&self) -> Vec<u8> {
            self.segment(TcpControl::Syn, None, &[])
        }

        /// Answer the SYN-ACK the flow's constructor already produced, so
        /// the stack reaches ESTABLISHED.
        fn complete_handshake(&mut self, flow: &mut EstablishedFlow) {
            self.ack = peer_isn(&flow.take_guest_packets()) + 1;
            self.seq = GUEST_ISN + 1;
            flow.deliver_from_guest(&self.segment(TcpControl::None, Some(self.ack), &[]));
            flow.pump_ignoring_metrics(0);
            let _ = flow.take_guest_packets();
            assert!(
                flow.is_active(),
                "the fixture must reach ESTABLISHED before any test runs"
            );
        }

        /// Offer one segment and report what the device did with it.
        ///
        /// The sequence advances either way, exactly as a real guest's
        /// would: it sent those bytes whether or not the host kept them.
        /// A refused segment is therefore a sequence hole, which is how a
        /// test builds one without contriving it.
        fn send(&mut self, flow: &mut EstablishedFlow, payload: &[u8]) -> PushOutcome {
            let outcome =
                flow.deliver_from_guest(&self.segment(TcpControl::None, Some(self.ack), payload));
            self.seq = self.seq.wrapping_add(payload.len() as u32);
            outcome
        }

        /// Push `bytes` of guest data at the flow's device in segments
        /// that fit the MTU, without letting the stack drain them.
        fn queue(&mut self, flow: &mut EstablishedFlow, bytes: usize) {
            let chunk = [0xABu8; 1_024];
            let mut sent = 0;
            while sent < bytes {
                let n = chunk.len().min(bytes - sent);
                self.send(flow, &chunk[..n]);
                sent += n;
            }
        }

        /// The same, then let the stack take in as much as its window
        /// allows.
        ///
        /// The poll matters: without it the segments sit in the device
        /// queue and the socket's receive buffer stays empty, which would
        /// make every assertion about the socket's own buffering vacuous.
        fn offer(&mut self, flow: &mut EstablishedFlow, bytes: usize) {
            self.queue(flow, bytes);
            flow.poll(0);
            let _ = flow.take_guest_packets();
        }

        /// Acknowledge every data segment in `packets`, as a real guest's
        /// stack would.
        ///
        /// Needed because "the host emitted it" and "the guest has it" are
        /// different claims: a reset arriving beside unacknowledged data is
        /// entitled to discard it. A fixture that only checked emission
        /// could not tell the two apart.
        fn acknowledge(&mut self, flow: &mut EstablishedFlow, packets: &[Vec<u8>]) {
            for p in packets {
                let Ok(ip) = smoltcp::wire::Ipv4Packet::new_checked(p.as_slice()) else {
                    continue;
                };
                let Ok(seg) = smoltcp::wire::TcpPacket::new_checked(ip.payload()) else {
                    continue;
                };
                let end = (seg.seq_number().0 as u32).wrapping_add(seg.payload().len() as u32);
                // Signed compare, the arithmetic TCP sequence space is
                // defined on, so a wrap does not read as a jump backwards.
                if end.wrapping_sub(self.ack) as i32 > 0 {
                    self.ack = end;
                }
            }
            flow.deliver_from_guest(&self.segment(TcpControl::None, Some(self.ack), &[]));
        }

        fn fin(&mut self, flow: &mut EstablishedFlow) {
            flow.deliver_from_guest(&self.segment(TcpControl::Fin, Some(self.ack), &[]));
            self.seq = self.seq.wrapping_add(1);
        }

        /// A FIN far outside the stack's receive window — a hostile
        /// guest's cheapest attempt to half-close a conversation it has
        /// not finished. The stack discards it; nothing else may act on
        /// it. The real sequence is left untouched so the guest can carry
        /// on sending legitimately afterwards.
        fn out_of_window_fin(&mut self, flow: &mut EstablishedFlow) {
            let real_seq = self.seq;
            self.seq = self.seq.wrapping_add(1_000_000);
            let forged = self.segment(TcpControl::Fin, Some(self.ack), &[]);
            self.seq = real_seq;
            flow.deliver_from_guest(&forged);
        }
    }

    fn peer_isn(packets: &[Vec<u8>]) -> u32 {
        for p in packets {
            let ip = smoltcp::wire::Ipv4Packet::new_checked(p.as_slice()).expect("ipv4");
            let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).expect("tcp");
            if tcp.syn() && tcp.ack() {
                return tcp.seq_number().0 as u32;
            }
        }
        panic!("the stack must answer a replayed SYN with a SYN-ACK");
    }

    fn carries_payload(packets: &[Vec<u8>], wanted: &[u8]) -> bool {
        packets.iter().any(|p| {
            let Ok(ip) = smoltcp::wire::Ipv4Packet::new_checked(p.as_slice()) else {
                return false;
            };
            let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(ip.payload()) else {
                return false;
            };
            tcp.payload().windows(wanted.len()).any(|w| w == wanted)
        })
    }

    /// A connected loopback pair: the flow's host socket, and the peer at
    /// the far end standing in for the real destination.
    fn host_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let l = listener();
        let host = std::net::TcpStream::connect(l.local_addr().expect("local addr"))
            .expect("connect to the fixture listener");
        let (peer, _) = l.accept().expect("accept");
        (host, peer)
    }

    /// Consecutive refusals a fixture takes as "this socket is staying
    /// full".
    ///
    /// One refusal is not the last word. `write` returns `WouldBlock` when
    /// the *send* buffer is full, and the kernel then keeps moving those
    /// bytes into the peer's receive buffer, which frees room here — so a
    /// fixture that stopped at the first refusal would hand the pump a
    /// socket that had quietly become writable again.
    const SETTLED_BLOCKS: usize = 8;

    /// Write into `sock` until the kernel keeps refusing.
    ///
    /// Returns whether it settled full, and how much went in. Bounded on
    /// both counts: a socket that never blocks makes the caller assert,
    /// never spin.
    fn fill_until_would_block(sock: &std::net::TcpStream) -> (bool, usize) {
        sock.set_nonblocking(true).expect("nonblocking");
        let chunk = [0u8; 16 * 1024];
        let mut writer: &std::net::TcpStream = sock;
        let mut total = 0usize;
        let mut refusals = 0usize;
        for _ in 0..FILL_ATTEMPTS {
            match writer.write(&chunk) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    refusals = 0;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    refusals += 1;
                    if refusals >= SETTLED_BLOCKS {
                        return (true, total);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
        (false, total)
    }

    fn half_open_over(host: std::net::TcpStream, key: FlowKey, syn: Vec<u8>) -> HalfOpen {
        HalfOpen {
            key,
            syn,
            socket: host,
            opened_at_millis: 0,
            refused_at_open: false,
        }
    }

    fn flow_over(host: std::net::TcpStream) -> (EstablishedFlow, FakeGuest) {
        flow_over_with(host, FakeGuest::new(flow_key()))
    }

    fn flow_over_with(host: std::net::TcpStream, mut g: FakeGuest) -> (EstablishedFlow, FakeGuest) {
        let entry = half_open_over(host, flow_key(), g.syn());
        let mut flow = EstablishedFlow::from_half_open(entry, guest(), MTU_V1 as usize, 0)
            .expect("a completed connect becomes a flow");
        g.complete_handshake(&mut flow);
        (flow, g)
    }

    /// The peer is returned rather than dropped: dropping it would reset
    /// the connection and every test below would be measuring a dead
    /// socket.
    fn established_flow_with_peer() -> (EstablishedFlow, std::net::TcpStream, FakeGuest) {
        let (host, peer) = host_pair();
        let (flow, g) = flow_over(host);
        (flow, peer, g)
    }

    /// A flow whose host socket will not take another byte, with a full
    /// receive buffer of guest data waiting to go out over it.
    fn established_flow_with_full_host_buffer() -> (EstablishedFlow, std::net::TcpStream, FakeGuest)
    {
        let (host, peer) = host_pair();
        let (blocked, filled) = fill_until_would_block(&host);
        assert!(
            blocked && filled > 0,
            "the fixture must actually block the host socket, not merely write to it"
        );
        let (mut flow, mut g) = flow_over(host);
        g.offer(&mut flow, SOCKET_RX_BUFFER);
        (flow, peer, g)
    }

    /// Pump until `wanted` reaches the guest, accumulating everything the
    /// stack emits on the way.
    ///
    /// Waiting for merely *a* packet is not enough: the stack has its own
    /// traffic to send — the ACK answering the guest's FIN, for one — and
    /// a wait that stopped at the first packet would hand back that ACK
    /// before the peer's bytes had crossed loopback, then blame the pump
    /// for their absence. Bounded: on exhaustion it returns what it saw,
    /// so the caller's assertion fails rather than the test hanging.
    fn pump_until_payload(flow: &mut EstablishedFlow, wanted: &[u8]) -> Vec<Vec<u8>> {
        let mut seen = Vec::new();
        for pass in 0..PUMP_ATTEMPTS {
            flow.pump_ignoring_metrics(pass as u64);
            seen.extend(flow.take_guest_packets());
            if carries_payload(&seen, wanted) {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        seen
    }

    /// Backpressure is what makes the stated memory ceiling real. Without
    /// it the buffers grow to meet demand and the ceiling is fiction.
    #[test]
    fn a_slow_host_socket_stops_us_accepting_from_the_stack() {
        let (mut flow, _peer, _g) = established_flow_with_full_host_buffer();
        let buffered_before = flow.bytes_buffered();
        assert!(buffered_before > 0, "the fixture must have data to move");

        let stats = flow.pump_ignoring_metrics(0);

        assert!(
            stats.stalled > 0,
            "a host socket that will not take a byte must register as a stall"
        );
        assert_eq!(stats.to_host, 0, "and nothing may claim to have moved");
        assert_eq!(
            flow.bytes_buffered(),
            buffered_before,
            "a stall must leave the guest's bytes in the stack, not discard them"
        );
        assert!(
            flow.bytes_buffered() <= FLOW_BUFFER_BYTES,
            "buffering must stop at the per-flow bound, not grow to meet demand"
        );
    }

    /// The same property under sustained demand: a guest that keeps
    /// pushing at a host socket that never drains must not be able to grow
    /// this flow's footprint past the bound the memory ceiling is computed
    /// from.
    #[test]
    fn backpressure_holds_while_the_guest_keeps_pushing() {
        let (mut flow, _peer, mut g) = established_flow_with_full_host_buffer();
        for pass in 0..16u64 {
            g.offer(&mut flow, SOCKET_RX_BUFFER);
            let stats = flow.pump_ignoring_metrics(pass);
            assert_eq!(stats.to_host, 0, "the host socket is still full");
            assert!(
                flow.bytes_buffered() <= FLOW_BUFFER_BYTES,
                "pass {pass} grew the flow past the per-flow bound"
            );
        }
    }

    /// Closing outright would discard the peer's remaining response and
    /// break every half-duplex protocol.
    #[test]
    fn a_guest_fin_half_closes_the_host_socket() {
        let (mut flow, _peer, mut g) = established_flow_with_peer();
        // A real, in-window FIN, taken in by the stack. `on_guest_fin` acts
        // on the stack's verdict, never the caller's say-so — see
        // `an_out_of_window_fin_cannot_half_close_the_host_socket`.
        g.fin(&mut flow);
        flow.poll(0);

        flow.on_guest_fin();

        assert!(flow.host_write_shutdown());
        assert!(
            !flow.host_socket_closed(),
            "the peer must still be able to send"
        );
    }

    /// The same thing through the path production actually takes: the FIN
    /// arrives as a packet and the pump notices it.
    #[test]
    fn a_guest_fin_arriving_as_a_packet_half_closes_the_host_socket() {
        let (mut flow, _peer, mut g) = established_flow_with_peer();
        g.fin(&mut flow);
        flow.pump_ignoring_metrics(0);
        assert!(flow.host_write_shutdown());
        assert!(!flow.host_socket_closed());
    }

    /// Shutting the write half down before the guest's last bytes have
    /// been written truncates the request — the same bug as closing, one
    /// segment earlier.
    #[test]
    fn a_guest_fin_does_not_truncate_data_the_host_has_not_seen() {
        let (mut flow, mut peer, mut g) = established_flow_with_peer();
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a bounded read");
        let request = b"GET / HTTP/1.0\r\n\r\n";
        g.send(&mut flow, request);
        g.fin(&mut flow);
        flow.pump_ignoring_metrics(0);
        assert!(flow.host_write_shutdown());

        let mut got = Vec::new();
        peer.read_to_end(&mut got)
            .expect("the peer reads to the EOF our shutdown produced");
        assert_eq!(
            got.as_slice(),
            request,
            "the guest's last bytes must precede the FIN we forward"
        );
    }

    /// The peer's response after our FIN must still reach the guest.
    #[test]
    fn the_peer_can_still_send_after_a_guest_fin() {
        let (mut flow, mut peer, mut g) = established_flow_with_peer();
        g.fin(&mut flow);
        flow.poll(0);
        flow.on_guest_fin();
        assert!(
            flow.host_write_shutdown(),
            "the fixture must have shut down"
        );
        peer.write_all(b"trailing response").expect("peer write");
        let to_guest = pump_until_payload(&mut flow, b"trailing response");
        assert!(
            !to_guest.is_empty(),
            "a half-close must not discard what the peer had left to send"
        );
        assert!(
            carries_payload(&to_guest, b"trailing response"),
            "and what reaches the guest must be the peer's bytes"
        );
    }

    /// A hostile guest must not be able to make one pump pass run forever.
    #[test]
    fn a_pump_pass_terminates_under_a_saturating_peer() {
        let (mut flow, peer, _g) = established_flow_with_peer();
        let (_blocked, stuffed) = fill_until_would_block(&peer);
        assert!(
            stuffed > max_bytes_per_pass(),
            "the fixture must offer more than one pass is allowed to take"
        );

        let stats = flow.pump_ignoring_metrics(0);

        assert!(stats.to_guest > 0, "a readable peer must produce progress");
        assert!(
            stats.to_guest <= max_bytes_per_pass(),
            "one pass must be bounded so the drive loop keeps servicing other work"
        );
        assert!(
            stats.to_guest < stuffed,
            "and it must stop before draining what the peer offered"
        );

        // The stack's send buffer is now full and the guest has
        // acknowledged none of it, so the next pass must refuse to take
        // more off the host socket rather than park it somewhere else.
        let next = flow.pump_ignoring_metrics(1);
        assert_eq!(next.to_guest, 0, "there is nowhere to put more");
        assert!(
            next.stalled > 0,
            "and refusing to read is a stall, reported as one"
        );
    }

    /// A guest must not be able to half-close a conversation it never
    /// legitimately closed.
    ///
    /// The FIN flag is guest-written, and a caller that parses it off the
    /// packet reads it *before* the stack has judged whether the segment
    /// was in window. If that caller's word were enough, one bare
    /// out-of-window FIN would shut the host write half down — truncating
    /// whatever request was in flight and wedging the flow, since nothing
    /// may be written after a forwarded FIN. So the stack's own verdict is
    /// the only thing that latches it.
    #[test]
    fn an_out_of_window_fin_cannot_half_close_the_host_socket() {
        let (mut flow, mut peer, mut g) = established_flow_with_peer();
        peer.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("a bounded read");

        g.out_of_window_fin(&mut flow);
        flow.pump_ignoring_metrics(0);
        // Both entry points: the pump, and a caller convinced it saw one.
        flow.on_guest_fin();

        assert!(
            !flow.host_write_shutdown(),
            "a FIN the stack discarded must not reach the host socket"
        );

        // And the flow is not wedged: the guest can still send, and its
        // bytes still arrive.
        let request = b"still talking";
        g.send(&mut flow, request);
        g.fin(&mut flow);
        flow.pump_ignoring_metrics(1);
        assert!(
            flow.host_write_shutdown(),
            "the guest's own in-window FIN must still close the write half"
        );
        let mut got = Vec::new();
        peer.read_to_end(&mut got).expect("the peer reads to EOF");
        assert_eq!(
            got.as_slice(),
            request,
            "the forged FIN must not have cost the guest its own bytes"
        );
    }

    /// The device queues are per-flow state whose filling a guest drives,
    /// and they are the *larger* term in a flow's footprint. A guest that
    /// floods them must hit the flow's bound, not the host's memory:
    /// multiplied by the socket cap, a queue depth chosen for one queue
    /// per machine is the difference between a 68 MiB ceiling and an
    /// 800 MiB one.
    #[test]
    fn a_guest_that_floods_the_device_queue_stays_inside_the_flow_bound() {
        let (mut flow, _peer, mut g) = established_flow_with_full_host_buffer();
        let before = flow.bytes_buffered();

        // Far more than any window, and never given a chance to drain.
        g.queue(&mut flow, FLOW_BUFFER_BYTES * 4);

        assert!(
            flow.bytes_buffered() > before,
            "the fixture must actually load the device queue"
        );
        assert!(
            flow.bytes_buffered() <= FLOW_BUFFER_BYTES,
            "a flow held {} bytes against a {FLOW_BUFFER_BYTES} byte bound",
            flow.bytes_buffered()
        );
    }

    /// A full-throughput pass must fit in the guest-bound queue.
    ///
    /// A segment the queue cannot take is discarded *silently* as far as
    /// smoltcp is concerned — it has already treated it as sent — so the
    /// guest waits out a retransmission timeout, seconds, for something
    /// the host threw away. Sizing the queue by byte budget alone put it
    /// at 12 slots, below the segments plus ACKs one pass emits, and made
    /// that reachable on an ordinary transfer.
    #[test]
    fn a_full_throughput_pass_does_not_overflow_the_guest_bound_queue() {
        let (mut flow, peer, _g) = established_flow_with_peer();
        let (_blocked, stuffed) = fill_until_would_block(&peer);
        assert!(stuffed > max_bytes_per_pass(), "the fixture must saturate");

        let stats = flow.pump_ignoring_metrics(0);

        assert_eq!(stats.to_guest, max_bytes_per_pass());
        assert_eq!(
            flow.dropped_to_guest(),
            0,
            "a pass emitting its full budget must not discard segments the guest \
             will then wait an RTO for"
        );
    }

    /// The same, for the guest that actually decides the depth: one whose
    /// SYN carries no MSS option, so the stack falls back to 536 byte
    /// segments and a full pass becomes ~31 of them rather than ~12.
    #[test]
    fn a_full_throughput_pass_fits_even_at_the_default_segment_size() {
        let (host, peer) = host_pair();
        let (mut flow, _g) = flow_over_with(host, FakeGuest::without_mss_option(flow_key()));
        let (_blocked, stuffed) = fill_until_would_block(&peer);
        assert!(stuffed > max_bytes_per_pass(), "the fixture must saturate");

        let stats = flow.pump_ignoring_metrics(0);
        let packets = flow.take_guest_packets();

        assert_eq!(stats.to_guest, max_bytes_per_pass());
        assert!(
            packets.len() > max_bytes_per_pass() / MTU_V1 as usize,
            "the fixture must actually produce small segments, not full-size ones"
        );
        assert_eq!(
            flow.dropped_to_guest(),
            0,
            "{} segments at the default MSS overflowed the guest-bound queue",
            packets.len()
        );
    }

    /// A guest can drive the segment count past any depth by advertising a
    /// tiny MSS, so the queue cannot promise never to drop. What it must
    /// do is say so: an unreported drop is an RTO nobody can explain.
    #[test]
    fn a_guest_bound_queue_overflow_is_counted_rather_than_silent() {
        let (host, peer) = host_pair();
        let (mut flow, _g) = flow_over_with(host, FakeGuest::with_tiny_mss(flow_key()));
        let (_blocked, _stuffed) = fill_until_would_block(&peer);

        // Seeded, and deliberately not from zero. A record that starts
        // empty with one flow pumping into it cannot tell an accumulation
        // from an assignment: both leave it holding exactly this flow's
        // cumulative figure. The seed stands in for every other flow and
        // every earlier pass that shares this record in production.
        const ALREADY_COUNTED: u64 = 7;
        let mut metrics = GatewayMetrics::default();
        metrics.queue_drops_egress += ALREADY_COUNTED;

        flow.pump(0, &mut metrics);

        assert!(
            flow.dropped_to_guest() > 0,
            "a 64 byte MSS turns one buffer into far more segments than any depth \
             holds; the drops must be visible"
        );
        assert_eq!(
            metrics.queue_drops_egress,
            ALREADY_COUNTED + flow.dropped_to_guest(),
            "a drop only the flow can see is a drop no operator can see, and it must \
             add to what the record already held rather than replace it"
        );

        // And a second pass adds its own drops on top rather than
        // restating the flow's cumulative figure.
        let after_first = metrics.queue_drops_egress;
        flow.pump(1, &mut metrics);
        assert_eq!(
            metrics.queue_drops_egress,
            ALREADY_COUNTED + flow.dropped_to_guest(),
            "the counter must accumulate across passes; it was {after_first} after one"
        );
    }

    /// The failure the guest-bound depth exists to prevent, reached the
    /// way production reaches it: no hostile MSS, no attacker, just this
    /// datapath's own modelled congestion drop.
    ///
    /// A full guest→stack queue drops a segment. That drop is a sequence
    /// hole, and smoltcp answers every segment ingested behind a hole with
    /// an *immediate* ACK — once per segment, in one poll's ingress loop,
    /// with no rate limit. So a poll can emit as many ACKs as the receive
    /// queue was deep. A depth that budgeted two of them, one per poll,
    /// had those ACKs consume the queue before the pass's data segments
    /// were emitted, and every one of those went out as far as smoltcp was
    /// concerned while the guest waited an RTO for it.
    #[test]
    fn a_queue_full_drop_does_not_cost_the_guest_the_passs_data() {
        let (host, peer) = host_pair();
        let (mut flow, mut g) = flow_over(host);
        let mut metrics = GatewayMetrics::default();
        let payload = [0xCDu8; 64];

        // Fill the guest→stack queue until it really refuses one. The
        // refused segment is the hole; nothing about it is contrived.
        let mut refused = false;
        for _ in 0..FLOW_RX_QUEUE_DEPTH + 1 {
            if g.send(&mut flow, &payload) == PushOutcome::DroppedQueueFull {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "the fixture must actually overflow the guest-facing queue, since that \
             drop is what opens the hole"
        );
        flow.pump(0, &mut metrics);
        let _ = flow.take_guest_packets();

        // Everything the guest sends now sits behind the hole, so each
        // segment draws its own immediate ACK when the next poll takes it
        // in. Bounded by the queue that holds them.
        let burst = FLOW_RX_QUEUE_DEPTH - 1;
        for _ in 0..burst {
            assert_eq!(
                g.send(&mut flow, &payload),
                PushOutcome::Queued,
                "the out-of-order burst must fit in the queue it is bounded by"
            );
        }
        // And the peer has a pass's worth of data waiting, so the same
        // pass emits data segments after the ACKs.
        let (_blocked, stuffed) = fill_until_would_block(&peer);
        assert!(stuffed > max_bytes_per_pass(), "the fixture must saturate");

        flow.pump(0, &mut metrics);
        let packets = flow.take_guest_packets();

        // What the pass *produced*, not what survived: a queue that
        // dropped some would otherwise look like a quieter pass, and the
        // non-vacuity check below would pass for the wrong reason.
        let dropped = flow.dropped_to_guest();
        let produced = packets.len() + dropped as usize;
        assert_eq!(
            dropped, 0,
            "{dropped} of the {produced} segments this pass produced were discarded, so \
             the guest waits an RTO apiece for data the host already counted sent"
        );
        assert_eq!(metrics.queue_drops_egress, 0);
        let ack_blind_depth = DATA_SEGMENTS_PER_PASS + POLLS_PER_PASS;
        assert!(
            produced > ack_blind_depth,
            "the pass produced {produced} segments, which a depth blind to ingress ACKs \
             ({ack_blind_depth}) would have held; the fixture proves nothing"
        );
    }

    /// Every way into the device queues is size-checked, not only the
    /// datapath handle's own entry point.
    #[test]
    fn an_oversized_packet_is_refused_at_the_flow_as_well() {
        let (mut flow, _peer, _g) = established_flow_with_peer();
        assert_eq!(
            flow.deliver_from_guest(&vec![0u8; MTU_V1 as usize + 1]),
            PushOutcome::DroppedOversized
        );
        assert_eq!(
            flow.deliver_from_guest(&vec![0u8; MTU_V1 as usize]),
            PushOutcome::Queued,
            "and a packet at exactly the MTU still goes through"
        );
    }

    /// The ceiling is computed from the fixed MTU, so a flow must not be
    /// built with buffers sized for anything larger.
    #[test]
    fn a_flow_refuses_an_mtu_above_the_fixed_one() {
        let (host, _peer) = host_pair();
        let g = FakeGuest::new(flow_key());
        let entry = half_open_over(host, flow_key(), g.syn());
        assert!(
            EstablishedFlow::from_half_open(entry, guest(), 9000, 0).is_err(),
            "a jumbo MTU would silently multiply this flow's share of the ceiling"
        );
    }

    /// Pins the flow's **inline** size — the bytes in the struct itself,
    /// which include smoltcp's `Interface` because it is held by value
    /// under this workspace's feature set.
    ///
    /// What this does *not* cover, stated plainly so nobody reads it as a
    /// guarantee it cannot make: it is blind to the heap. Everything
    /// behind `SocketSet`'s `Vec`, the two socket ring buffers, and the
    /// device queues is one pointer here regardless of how much it
    /// allocates — adding a `Vec` field moves this figure by 24 bytes
    /// whether it holds nothing or a megabyte. Heap growth is covered
    /// per-term instead: the ring buffers by their constants, the device
    /// queues by `a_guest_that_floods_the_device_queue_stays_inside_the_flow_bound`.
    /// A new heap-allocating field is covered by neither, and must be added
    /// to `FLOW_BUFFER_BYTES` by hand.
    ///
    /// Pinned close to the real figure rather than loosely, so that a new
    /// inline field is a failing test and not a rounding error.
    #[test]
    fn a_flows_inline_size_stays_pinned() {
        let inline = std::mem::size_of::<EstablishedFlow>();
        assert!(
            inline <= 1_024,
            "{inline} bytes of inline per-flow state; if this grew on purpose, \
             re-pin it, and check whether the growth was heap rather than inline"
        );
    }

    /// The pass budget has to stay a real bound.
    ///
    /// Nothing frees buffer space inside a pass today, so the buffers
    /// happen to bind at the same value and no behavioural test can
    /// separate the two. That is exactly why this asserts the relation
    /// directly: a budget raised past a buffer is a silently unbounded
    /// pass the moment anything does drain mid-pass.
    #[test]
    fn the_pass_budget_can_never_exceed_a_socket_buffer() {
        assert!(max_bytes_per_pass() <= SOCKET_RX_BUFFER);
        assert!(max_bytes_per_pass() <= SOCKET_TX_BUFFER);
        assert!(max_bytes_per_pass() > 0, "a zero budget moves nothing");
    }

    /// Neither side ready must be a cheap no-op, not a spin.
    #[test]
    fn a_pump_pass_on_an_idle_flow_moves_nothing() {
        let (mut flow, _peer, _g) = established_flow_with_peer();
        assert_eq!(flow.pump_ignoring_metrics(0), PumpStats::default());
    }

    /// Without a way to actually close it, the half-close test's "still
    /// open" assertion would be vacuously true.
    #[test]
    fn closing_the_host_socket_is_observable() {
        let (mut flow, _peer, _g) = established_flow_with_peer();
        assert!(!flow.host_socket_closed());
        flow.close_host();
        assert!(flow.host_socket_closed());
    }

    /// The first reset in `packets`, as its (sequence, acknowledgement)
    /// pair.
    ///
    /// Both numbers come back rather than a bare "there was a reset",
    /// because a reset outside the guest's window is discarded by its stack
    /// and is no reset at all — the assertion that matters is about the
    /// numbers, not the flag.
    fn rst_in(packets: &[Vec<u8>]) -> Option<(u32, u32)> {
        packets.iter().find_map(|p| {
            let ip = smoltcp::wire::Ipv4Packet::new_checked(p.as_slice()).ok()?;
            let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).ok()?;
            tcp.rst()
                .then(|| (tcp.seq_number().0 as u32, tcp.ack_number().0 as u32))
        })
    }

    /// A flow whose host socket will refuse the next write outright, with
    /// guest data already sitting in the stack waiting to go over it.
    ///
    /// The write half is shut down behind the flow's back — the flow's own
    /// `write_shutdown` stays false — so the next `write` is `EPIPE`
    /// without any timing or peer cooperation. A fixture that waited for a
    /// peer to reset would be a fixture that can hang.
    fn flow_whose_host_write_fails_with_data_queued()
    -> (EstablishedFlow, std::net::TcpStream, FakeGuest) {
        let (mut flow, peer, mut g) = established_flow_with_peer();
        flow.host
            .as_ref()
            .expect("the fixture flow holds its host socket")
            .shutdown(Shutdown::Write)
            .expect("shutting the write half down cannot fail on a live socket");
        g.offer(&mut flow, 4 * 1_024);
        assert!(
            flow.socket().recv_queue() > 0,
            "the fixture must leave guest bytes the host has not taken"
        );
        (flow, peer, g)
    }

    /// A host-side failure the guest never learns about is a multi-minute
    /// hang: the guest's stack sits on a connection nobody will answer
    /// until its own retransmit timer gives up.
    #[test]
    fn a_host_side_reset_reaches_the_guest_as_a_reset() {
        let (mut flow, _peer, _g) = established_flow_with_peer();
        flow.on_host_error(io::ErrorKind::ConnectionReset);
        assert!(
            rst_in(&flow.take_guest_packets()).is_some(),
            "the guest's stack must learn, rather than hang to its own timeout"
        );
    }

    #[test]
    fn an_unreachable_host_also_resets_rather_than_hanging() {
        let (mut flow, _peer, _g) = established_flow_with_peer();
        flow.on_host_error(io::ErrorKind::HostUnreachable);
        assert!(rst_in(&flow.take_guest_packets()).is_some());
    }

    /// Every terminal kind, not just the two the fixtures happen to
    /// exercise: a kind missing from the terminal set is a flow that hangs.
    #[test]
    fn every_terminal_host_error_resets_the_guest() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::TimedOut,
        ] {
            let (mut flow, _peer, _g) = established_flow_with_peer();
            flow.on_host_error(kind);
            assert!(
                rst_in(&flow.take_guest_packets()).is_some(),
                "{kind:?} left the guest waiting on a host socket that is gone"
            );
            assert_eq!(flow.host_error(), Some(kind));
            assert!(flow.host_socket_closed(), "{kind:?} must release the fd");
        }
    }

    /// A transient would-block is not a failure and must not tear anything
    /// down: treating one as fatal would reset healthy flows under load,
    /// which is worse than the hang being fixed.
    #[test]
    fn a_would_block_is_not_treated_as_a_host_error() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            let (mut flow, _peer, _g) = established_flow_with_peer();
            flow.on_host_error(kind);
            assert!(flow.take_guest_packets().is_empty(), "{kind:?} emitted");
            assert!(!flow.host_socket_closed(), "{kind:?} closed the socket");
            assert_eq!(flow.host_error(), None, "{kind:?} was latched");
        }
    }

    /// The numbers are the whole point. A reset carrying a sequence the
    /// guest's stack has never heard of is discarded in silence, which puts
    /// the guest back at the hang this exists to prevent — so the reset is
    /// taken from the live stack rather than fabricated.
    #[test]
    fn the_reset_a_host_error_produces_sits_inside_the_guests_window() {
        let (mut flow, _peer, g) = established_flow_with_peer();
        flow.on_host_error(io::ErrorKind::ConnectionReset);
        let (seq, ack) = rst_in(&flow.take_guest_packets()).expect("a reset");
        assert_eq!(
            seq, g.ack,
            "the reset's sequence must be the next byte the guest expects from us"
        );
        assert_eq!(
            ack, g.seq,
            "and it must acknowledge everything the guest has sent"
        );
    }

    /// Two errors on one flow are one reset: smoltcp forgets the endpoint
    /// after emitting it, and the flow must not fabricate a second.
    #[test]
    fn a_second_host_error_does_not_produce_a_second_reset() {
        let (mut flow, _peer, _g) = established_flow_with_peer();
        flow.on_host_error(io::ErrorKind::ConnectionReset);
        assert!(rst_in(&flow.take_guest_packets()).is_some());
        flow.on_host_error(io::ErrorKind::TimedOut);
        assert!(
            rst_in(&flow.take_guest_packets()).is_none(),
            "one aborted connection is one reset"
        );
        assert_eq!(
            flow.host_error(),
            Some(io::ErrorKind::ConnectionReset),
            "the first error is the one that explains the flow"
        );
    }

    /// The carried-forward gap: a flow whose host write failed with data
    /// still queued never reached `forward_guest_fin`, so it claimed to be
    /// open forever while nothing could ever drain it.
    #[test]
    fn a_failed_host_write_still_resolves_the_write_half() {
        let (mut flow, _peer, _g) = flow_whose_host_write_fails_with_data_queued();
        let _ = flow.pump_ignoring_metrics(0);
        assert!(
            flow.host_write_shutdown() || flow.host_socket_closed(),
            "a flow that can never drain must not sit forever claiming it is still open"
        );
    }

    /// And the guest is told, rather than left to time out against a socket
    /// that will never take another byte.
    #[test]
    fn a_failed_host_write_resets_the_guest_too() {
        let (mut flow, _peer, _g) = flow_whose_host_write_fails_with_data_queued();
        let _ = flow.pump_ignoring_metrics(0);
        assert!(rst_in(&flow.take_guest_packets()).is_some());
        assert_eq!(flow.host_error(), Some(io::ErrorKind::BrokenPipe));
    }

    /// Load the stack's send buffer with a peer response the guest has not
    /// been given yet, without letting it reach the guest-bound queue.
    ///
    /// This is the state one pump pass is in when it reads a response and
    /// then meets `ECONNRESET` on the next read — the ordinary shape of a
    /// peer that answers and closes with `SO_LINGER 0`.
    fn buffer_a_peer_response(
        flow: &mut EstablishedFlow,
        peer: &mut std::net::TcpStream,
        body: &[u8],
    ) {
        peer.write_all(body).expect("the peer writes its response");
        peer.flush().expect("flush");
        let mut stats = PumpStats::default();
        for _ in 0..PUMP_ATTEMPTS {
            flow.host_to_guest(&mut stats);
            if flow.socket().send_queue() >= body.len() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            flow.socket().send_queue() >= body.len(),
            "the fixture must leave the response inside the stack, unsent"
        );
        assert!(
            !carries_payload(&flow.take_guest_packets(), body),
            "and it must not already have reached the guest"
        );
    }

    /// A peer that answers and then closes hard is the common case, not an
    /// edge case. Resetting first would throw away a response the server
    /// did send, and the guest's application would see a request that
    /// failed for no reason — worse than the hang the reset prevents.
    #[test]
    fn a_peers_buffered_response_reaches_the_guest_before_the_reset() {
        let (mut flow, mut peer, mut g) = established_flow_with_peer();
        let body = b"HTTP/1.0 200 OK\r\n\r\nthe-answer";
        buffer_a_peer_response(&mut flow, &mut peer, body);

        flow.on_host_error(io::ErrorKind::ConnectionReset);

        let first = flow.take_guest_packets();
        assert!(
            carries_payload(&first, body),
            "the guest must be given what the host already holds for it"
        );
        assert!(
            rst_in(&first).is_none(),
            "and the reset must not overtake it: a reset beside unacknowledged \
             data is entitled to discard that data"
        );

        // Once the guest has acknowledged the response, the reset follows.
        g.acknowledge(&mut flow, &first);
        flow.pump_ignoring_metrics(1);
        assert!(
            rst_in(&flow.take_guest_packets()).is_some(),
            "the guest still has to learn that the flow is over"
        );
        assert!(flow.host_socket_closed(), "and the descriptor is released");
    }

    /// The window assertion again, on a flow whose sequence numbers have
    /// *moved*. Against a quiescent flow the correct answer and the ISN
    /// coincide, so that case cannot tell a live number from a stale one.
    #[test]
    fn the_reset_is_in_window_after_the_flow_has_carried_data() {
        let (mut flow, mut peer, mut g) = established_flow_with_peer();
        let body = b"a-response-that-advances-the-sequence";
        buffer_a_peer_response(&mut flow, &mut peer, body);

        flow.on_host_error(io::ErrorKind::ConnectionReset);
        let delivered = flow.take_guest_packets();
        assert!(carries_payload(&delivered, body));
        g.acknowledge(&mut flow, &delivered);
        flow.pump_ignoring_metrics(1);

        let (seq, ack) = rst_in(&flow.take_guest_packets()).expect("a reset");
        assert_eq!(
            seq, g.ack,
            "the reset must carry the sequence after the data, not the handshake's"
        );
        assert_ne!(
            seq, GUEST_ISN,
            "a fixture where the two coincide could not tell a live number from a stale one"
        );
        assert_eq!(ack, g.seq, "and acknowledge everything the guest sent");
    }

    /// The deferral has to end somewhere. A guest that stops acknowledging
    /// — a crash, a zero window, or a hostile guest choosing not to — would
    /// otherwise hold this flow's buffers and its slot in the host's socket
    /// budget for the machine's whole life: the descriptor is already gone,
    /// so nothing else about this flow can ever fail again, and nothing
    /// ages an established flow.
    #[test]
    fn a_guest_that_stops_acknowledging_cannot_hold_the_flow_forever() {
        let (mut flow, mut peer, _g) = established_flow_with_peer();
        buffer_a_peer_response(&mut flow, &mut peer, b"never-acknowledged");

        flow.on_host_error(io::ErrorKind::ConnectionReset);
        assert!(
            rst_in(&flow.take_guest_packets()).is_none(),
            "the reset is owed but must wait on the data first"
        );

        // Passes go by and the guest acknowledges nothing.
        for pass in 0..5 {
            flow.pump_ignoring_metrics(pass * 1_000);
            assert!(
                rst_in(&flow.take_guest_packets()).is_none(),
                "inside the deadline the guest still gets its chance"
            );
        }
        assert!(flow.is_active(), "and the flow is still held for it");

        flow.pump_ignoring_metrics(RESET_DELIVERY_TIMEOUT_MILLIS + 1);

        assert!(
            rst_in(&flow.take_guest_packets()).is_some(),
            "past the deadline the flow gives up rather than waiting forever"
        );
        assert!(
            !flow.is_active(),
            "and it becomes reapable, so its buffers and budget slot come back"
        );
    }

    /// An established flow is reclaimed when its peer stops answering, not
    /// when it goes quiet — so something has to be doing the asking.
    ///
    /// Asserted by reading the option back rather than by waiting for a
    /// probe to fail: the shortest honest keepalive timeout is over a
    /// minute, which no unit test should sit through, and an unasserted
    /// `setsockopt` is one a refactor deletes in silence.
    #[test]
    fn a_flows_host_socket_asks_whether_its_peer_is_still_there() {
        let (flow, _peer, _g) = established_flow_with_peer();
        let host = flow
            .host
            .as_ref()
            .expect("the fixture flow holds its socket");
        assert!(
            SockRef::from(host)
                .keepalive()
                .expect("reading the keepalive flag back"),
            "a flow whose peer vanishes must be able to find out"
        );
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
