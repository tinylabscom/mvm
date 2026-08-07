//! Declared inbound datagram mappings.
//!
//! An outbound association is authorized by the datagram that created it:
//! the guest sent first, so the host knows where the conversation goes and
//! whose answer is coming back. **Nothing authorizes an inbound datagram.**
//! There is no earlier packet to point at, so a mapping here exists only
//! because policy declared one, and this module never creates one from
//! traffic it observed. A listener nobody declared is a port the workload
//! never asked to expose.
//!
//! # What a mapping accepts from
//!
//! Any source that can reach the host address the mapping declared, and
//! nothing else. **That address is the declaration.** A mapping on
//! `127.0.0.1` is reachable only from this host, one on an interface
//! address only from that interface's network, and the wildcard `0.0.0.0`
//! is gated behind explicit admission before it ever reaches here. A second
//! per-source allow-list is deliberately not invented: the plan carries no
//! such list, so one written here would be policy this datapath chose
//! rather than policy the plan expressed. What this module owes that
//! decision is to bind *exactly* what was declared — binding the wildcard
//! for a mapping that named an address would silently widen the exposure
//! past what was admitted, which is the whole failure the declaration
//! exists to prevent.
//!
//! Admission is still the authority on delivery. A packet synthesized here
//! goes out of the datapath's read path and back through
//! `mvm_net::l3::admit`, which refuses it unless a mapping for that guest
//! port is declared there too. Withdrawing a mapping stops delivery even
//! while the listener is still bound.
//!
//! # What may leave a listener
//!
//! Only a datagram addressed to a peer that has already sent to that
//! mapping, inside that peer's lifetime. A listener's socket is
//! unconnected — `send_to` takes any destination — so a guest able to
//! choose one would have an egress route that never passes the
//! admitted-destination check every other outbound datagram goes through.
//! Anything else is not sent here at all: it falls through to the outbound
//! association path, where the destination comes from an admitted flow key
//! and the socket is connected.
//!
//! # DNS
//!
//! No carve-out, and none is needed. The resolver is terminated above this
//! seam at the *gateway* address; a mapping delivers to the guest's own
//! lease, so the two are never the same destination and no query can reach
//! a nameserver through a socket opened here.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use mvm_contract::l3::ip::proto;
use mvm_core::policy::projection::Proto;
use mvm_net::l3::IngressMapping;
use mvm_net::l3::flow::FlowKey;

use crate::netd::datapath::DatapathError;

use super::GuestAddressing;
use super::limits::{
    ASSOCIATION_LIFETIME_MILLIS, DATAGRAMS_PER_SOURCE_POLL, MAX_DATAGRAM_PAYLOAD_BYTES,
};
use super::readiness::{Watch, Watched};
use super::tcp::is_terminal_host_error;
use super::udp::synthesize_datagram;

/// Bounds one machine's ingress tables are built with.
///
/// A struct rather than two adjacent `usize` arguments: they are both
/// counts, and a transposed pair would silently give a machine sixteen
/// peers per listener and thirty-two listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressBounds {
    /// Host listeners this machine may bind.
    pub listeners: usize,
    /// Peers one listener remembers for the reply path.
    pub peers_per_listener: usize,
}

/// Datagrams a poll refused to hand on, by reason.
///
/// Taken rather than read, for the reason
/// [`super::udp::DatagramDrops`] is: the caller folds each count into the
/// machine's metrics exactly once with no delta bookkeeping of its own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngressDrops {
    /// Datagrams from a peer the listener had no room to remember.
    ///
    /// Dropped rather than delivered: the guest's answer would have nowhere
    /// to go, and a one-way conversation the guest believes it is having is
    /// worse than one it never sees.
    pub peers_full: u64,
    /// Datagrams too large for the guest's link.
    pub oversized: u64,
    /// Datagrams that could not be addressed to the guest at all, because
    /// the session leased it no address in the peer's family.
    pub unaddressable: u64,
    /// Reads that failed on a bound listener.
    ///
    /// The listener is **not** closed for one: it is declared, and a
    /// declared port that stopped answering because of a transient read
    /// error would be a mapping silently withdrawn by traffic.
    pub read_errors: u64,
}

/// One declared mapping's host listener.
struct Listener {
    /// Bound to exactly the address and port the mapping declared, and
    /// registered on the datapath's readiness set for as long as it lives.
    socket: Watched<UdpSocket>,
    /// Guest port this mapping delivers to.
    ///
    /// Taken from the declaration and never from the datagram's own
    /// destination port — that port names the *host* listener, and reading
    /// it would deliver to a guest port nobody declared.
    guest_port: u16,
    /// Peers that have sent here, each with the deadline its entry ends at.
    /// The reply path's only authority on where a datagram may be sent.
    peers: BTreeMap<SocketAddr, u64>,
    peer_capacity: usize,
}

impl Listener {
    /// Take up to one pass's datagrams off this listener, as packets
    /// addressed to the guest.
    fn drain(
        &mut self,
        guest: GuestAddressing,
        now_millis: u64,
        out: &mut Vec<Vec<u8>>,
        drops: &mut IngressDrops,
    ) {
        // One byte past the bound, so a datagram the link cannot carry is
        // *detected* rather than silently shortened: `recv_from` truncates
        // to the buffer and discards the rest, so a read that fills this is
        // one that lost bytes.
        let mut buf = [0u8; MAX_DATAGRAM_PAYLOAD_BYTES + 1];
        for _ in 0..DATAGRAMS_PER_SOURCE_POLL {
            let (len, from) = match self.socket.recv_from(&mut buf) {
                Ok(read) => read,
                Err(e) if !is_terminal_host_error(e.kind()) => return,
                Err(_) => {
                    // Counted, and the listener stays. It is declared, and
                    // a declared port that stopped answering because one
                    // read failed would be a mapping withdrawn by traffic.
                    drops.read_errors = drops.read_errors.saturating_add(1);
                    return;
                }
            };
            if len > MAX_DATAGRAM_PAYLOAD_BYTES {
                drops.oversized = drops.oversized.saturating_add(1);
                continue;
            }
            if !self.remember(from, now_millis) {
                drops.peers_full = drops.peers_full.saturating_add(1);
                continue;
            }
            // The guest port comes from the declaration. `from` supplies
            // only the source the answer has to go back to.
            let key = FlowKey {
                protocol: proto::UDP,
                guest_port: self.guest_port,
                remote: from.ip(),
                remote_port: from.port(),
            };
            match guest
                .matching(key.remote)
                .and_then(|guest| synthesize_datagram(&key, guest, &buf[..len]))
            {
                Some(packet) => out.push(packet),
                None => drops.unaddressable = drops.unaddressable.saturating_add(1),
            }
        }
    }

    /// Note that `from` is a peer this listener may answer, reporting
    /// whether there was room to.
    fn remember(&mut self, from: SocketAddr, now_millis: u64) -> bool {
        let deadline = now_millis.saturating_add(ASSOCIATION_LIFETIME_MILLIS);
        // Absolute, like every other deadline in this datapath: a live
        // entry is not pushed out by later traffic. One already past its
        // own belongs to a conversation that ended, and the datagram
        // opening the next one gets a deadline of its own rather than
        // resurrecting the old.
        if let Some(existing) = self.peers.get_mut(&from) {
            if now_millis >= *existing {
                *existing = deadline;
            }
            return true;
        }
        if self.peers.len() >= self.peer_capacity {
            return false;
        }
        self.peers.insert(from, deadline);
        true
    }

    /// Whether a guest datagram for `peer` belongs on this listener.
    fn answers(&self, guest_port: u16, peer: SocketAddr, now_millis: u64) -> bool {
        self.guest_port == guest_port
            && self
                .peers
                .get(&peer)
                .is_some_and(|deadline| now_millis < *deadline)
    }
}

/// What the ingress path did with a guest datagram offered to it.
#[derive(Debug)]
pub enum ReplyOutcome {
    /// Sent back out the listener the conversation arrived on, so the peer
    /// sees the answer coming from the address it dialled.
    Sent,
    /// Not an ingress conversation: no declared mapping owns this guest
    /// port, or no live peer at that address has sent to it. The caller
    /// falls through to the outbound association path.
    NotIngress,
    /// The listener refused it.
    Failed(DatapathError),
}

/// One machine's declared inbound datagram mappings.
pub struct DatagramIngress {
    /// Keyed by the host bind, so a second mapping on the same address and
    /// port is a lookup rather than a silent replacement — replacing would
    /// close a live listener to make room for a newcomer.
    listeners: BTreeMap<(IpAddr, u16), Listener>,
    bounds: IngressBounds,
    guest: GuestAddressing,
    drops: IngressDrops,
    watch: Watch,
}

impl DatagramIngress {
    pub fn new(bounds: IngressBounds, guest: GuestAddressing, watch: Watch) -> Self {
        Self {
            listeners: BTreeMap::new(),
            bounds,
            guest,
            drops: IngressDrops::default(),
            watch,
        }
    }

    /// Bind the host listener one declared mapping needs.
    ///
    /// Refused rather than skipped when it cannot be served, so a machine
    /// never runs believing it is reachable on a port nothing answers.
    pub fn declare(&mut self, mapping: IngressMapping) -> Result<(), DatapathError> {
        if mapping.proto != Proto::Udp {
            return Err(refuse(format!(
                "{:?} ingress needs a listener whose connections are originated toward the \
                 guest, which this datapath does not build",
                mapping.proto
            )));
        }
        if mapping.host_port == 0 || mapping.guest_port == 0 {
            // Port zero on the host side is an ephemeral bind — a listener
            // on a port nobody declared, which is the one thing a
            // declaration exists to rule out.
            return Err(refuse(
                "an ingress mapping on port 0 names no port at all".to_string(),
            ));
        }
        let bind = SocketAddr::new(mapping.host_addr, mapping.host_port);
        let key = (mapping.host_addr, mapping.host_port);
        if self.listeners.contains_key(&key) {
            return Err(refuse(format!(
                "{bind} is already bound by a declared mapping"
            )));
        }
        if self.listeners.len() >= self.bounds.listeners {
            // Drop the newcomer, never a bound listener. Evicting would let
            // one declared mapping close another's port — a resource limit
            // turned into a declaration nothing serves.
            return Err(refuse(format!(
                "{} declared ingress listeners are already bound",
                self.bounds.listeners
            )));
        }
        let socket = Watched::new(&self.watch, bind_listener(bind)?).map_err(DatapathError::Io)?;
        self.listeners.insert(
            key,
            Listener {
                socket,
                guest_port: mapping.guest_port,
                peers: BTreeMap::new(),
                peer_capacity: self.bounds.peers_per_listener,
            },
        );
        Ok(())
    }

    /// Listeners bound. Each one parks a host descriptor for the machine's
    /// whole life.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    /// Take what every listener's peers have sent, as packets for the
    /// guest.
    pub fn poll(&mut self, now_millis: u64) -> Vec<Vec<u8>> {
        let guest = self.guest;
        let mut out = Vec::new();
        for listener in self.listeners.values_mut() {
            listener.drain(guest, now_millis, &mut out, &mut self.drops);
        }
        out
    }

    /// Send one admitted guest datagram back out the listener its
    /// conversation arrived on, if that is where it belongs.
    ///
    /// [`ReplyOutcome::NotIngress`] whenever the destination is not a live
    /// peer of a declared mapping, so the caller falls through to the
    /// outbound association path. That is the fail-closed direction: the
    /// association path connects its socket to an admitted destination,
    /// while this one holds an unconnected socket that would reach whatever
    /// it was handed.
    pub fn reply(&mut self, key: &FlowKey, payload: &[u8], now_millis: u64) -> ReplyOutcome {
        if key.protocol != proto::UDP {
            return ReplyOutcome::NotIngress;
        }
        let peer = SocketAddr::new(key.remote, key.remote_port);
        let Some(listener) = self
            .listeners
            .values_mut()
            .find(|listener| listener.answers(key.guest_port, peer, now_millis))
        else {
            return ReplyOutcome::NotIngress;
        };
        if payload.len() > MAX_DATAGRAM_PAYLOAD_BYTES {
            return ReplyOutcome::Failed(refuse(format!(
                "a {} byte datagram exceeds the {MAX_DATAGRAM_PAYLOAD_BYTES} bytes this link \
                 carries",
                payload.len()
            )));
        }
        match listener.socket.send_to(payload, peer) {
            Ok(_) => ReplyOutcome::Sent,
            Err(e) => ReplyOutcome::Failed(DatapathError::Io(e)),
        }
    }

    /// Drop peers that have reached their deadline, reporting how many
    /// went. Listeners themselves never expire: they are declared, and a
    /// declared port must answer for as long as the machine runs.
    pub fn expire(&mut self, now_millis: u64) -> usize {
        let mut gone = 0;
        for listener in self.listeners.values_mut() {
            let before = listener.peers.len();
            listener.peers.retain(|_, deadline| now_millis < *deadline);
            gone += before - listener.peers.len();
        }
        gone
    }

    /// Drop every listener, closing the host descriptor each one parks.
    pub fn clear(&mut self) {
        self.listeners.clear();
    }

    /// Take the drop counts accumulated since the last call.
    pub fn take_drops(&mut self) -> IngressDrops {
        std::mem::take(&mut self.drops)
    }

    /// Where a mapping's listener actually bound. Test-only: production has
    /// no business asking, since the answer is what the mapping declared,
    /// and a test needs it to prove exactly that.
    #[cfg(test)]
    pub(crate) fn bound_addr(&self, host_addr: IpAddr, host_port: u16) -> Option<SocketAddr> {
        self.listeners
            .get(&(host_addr, host_port))?
            .socket
            .local_addr()
            .ok()
    }

    /// Peers a mapping's listener is remembering. Test-only.
    #[cfg(test)]
    pub(crate) fn peer_count(&self, host_addr: IpAddr, host_port: u16) -> Option<usize> {
        Some(self.listeners.get(&(host_addr, host_port))?.peers.len())
    }
}

impl std::fmt::Debug for DatagramIngress {
    /// Hand-written for the reason [`super::udp::UdpAssociations`]'s is: a
    /// derived one would be tempted to grow a payload field, and these
    /// carry peer-controlled bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramIngress")
            .field("listeners", &self.listeners.len())
            .field("bounds", &self.bounds)
            .field("drops", &self.drops)
            .finish()
    }
}

/// Refuse a mapping this datapath cannot serve, naming why.
fn refuse(detail: String) -> DatapathError {
    DatapathError::Io(io::Error::new(io::ErrorKind::InvalidInput, detail))
}

/// Bind the host socket one declared mapping listens on.
///
/// Exactly the declared address, and with no address-reuse option: a bind
/// that collides with something else on this host must fail where the
/// machine refuses to start, never quietly share a port whose traffic the
/// kernel would then split between two receivers.
fn bind_listener(bind: SocketAddr) -> Result<UdpSocket, DatapathError> {
    let socket = UdpSocket::bind(bind).map_err(|source| {
        DatapathError::Io(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("no host listener for the declared mapping at {bind}: {source}"),
        ))
    })?;
    socket.set_nonblocking(true).map_err(DatapathError::Io)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::super::readiness::ReadinessSet;
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    /// A readiness set for a table under test, with its poll side dropped.
    /// Nothing here waits on readiness; what the sockets need is somewhere
    /// to register and unregister, and that outlives the set.
    fn watch() -> Watch {
        ReadinessSet::new()
            .expect("a readiness set needs no privileges")
            .watch()
    }

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// The address the session leased this guest. Deliberately not an
    /// address any fixture packet carries, so a delivery addressed from
    /// somewhere else cannot pass by coincidence.
    fn guest() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 201, 0, 6))
    }

    /// The same lease as the per-family value the tables hold. IPv4 only:
    /// these fixtures are the IPv4 path, and a v6 remote against this must
    /// come back unaddressable rather than be sent somewhere invented.
    fn leased() -> GuestAddressing {
        GuestAddressing::new(Ipv4Addr::new(10, 201, 0, 6), None)
    }

    fn bounds() -> IngressBounds {
        IngressBounds {
            listeners: 8,
            peers_per_listener: 8,
        }
    }

    fn ingress(bounds: IngressBounds) -> DatagramIngress {
        DatagramIngress::new(bounds, leased(), watch())
    }

    /// A host port nothing is bound to, for a mapping to declare.
    ///
    /// Probed rather than fixed: a hard-coded port collides with whatever
    /// else this process-parallel suite is running. The probe is dropped
    /// before the port is returned, so a mapping that loses the race to it
    /// fails its `declare` loudly rather than serving a port nobody named.
    fn free_host_port() -> u16 {
        let probe = UdpSocket::bind("127.0.0.1:0").expect("probe a free port");
        probe.local_addr().expect("local addr").port()
    }

    fn udp_mapping(host_port: u16, guest_port: u16) -> IngressMapping {
        IngressMapping::udp(LOOPBACK, host_port, guest_port)
    }

    /// A sender that will act as a remote peer, with a read timeout so a
    /// reply that never comes fails an assertion rather than hanging.
    fn peer() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a peer");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a bounded read");
        socket
    }

    /// Drive `poll` until it yields something, or give up. Bounded on both
    /// counts: a datagram that never arrives must produce an assertion,
    /// never a hang.
    fn poll_until_nonempty(i: &mut DatagramIngress, now_millis: u64) -> Vec<Vec<u8>> {
        for _ in 0..200 {
            let packets = i.poll(now_millis);
            if !packets.is_empty() {
                return packets;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Vec::new()
    }

    /// The IPv4 source, destination, ports and body of a synthesized
    /// packet.
    fn parts(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>) {
        let ip = smoltcp::wire::Ipv4Packet::new_checked(packet).expect("a well-formed IPv4 packet");
        let udp =
            smoltcp::wire::UdpPacket::new_checked(ip.payload()).expect("a well-formed datagram");
        (
            ip.src_addr(),
            ip.dst_addr(),
            udp.src_port(),
            udp.dst_port(),
            udp.payload().to_vec(),
        )
    }

    /// The flow key admission derives from a packet this module
    /// synthesized, which is what a guest's answer to it arrives under.
    fn reply_key(guest_port: u16, peer: SocketAddr) -> FlowKey {
        FlowKey {
            protocol: proto::UDP,
            guest_port,
            remote: peer.ip(),
            remote_port: peer.port(),
        }
    }

    /// **The declared path works.** Everything else here asserts that
    /// something does *not* happen, and none of those means anything unless
    /// the thing that should happen does.
    #[test]
    fn a_declared_mapping_carries_its_peers_datagram_to_the_guest() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let peer = peer();
        peer.send_to(b"hello", (Ipv4Addr::LOCALHOST, host_port))
            .expect("a peer datagram toward the declared mapping");

        let packets = poll_until_nonempty(&mut i, 0);
        assert_eq!(packets.len(), 1, "the declared mapping must deliver");
        let (src, dst, src_port, dst_port, body) = parts(&packets[0]);
        assert_eq!(body, b"hello");
        assert_eq!(IpAddr::V4(src), LOOPBACK, "addressed from the peer");
        assert_eq!(
            IpAddr::V4(dst),
            guest(),
            "and to the address the session leased"
        );
        assert_eq!(src_port, peer.local_addr().expect("addr").port());
        assert_eq!(dst_port, 5140);
    }

    /// **Declared, never inferred.** The datagram's own destination port
    /// names the *host* listener. Delivering to it would put traffic in
    /// front of a guest port nobody declared — an inferred mapping, which
    /// is exactly what an ingress declaration exists to make impossible.
    #[test]
    fn delivery_goes_to_the_guest_port_the_mapping_declared_not_the_one_the_datagram_names() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        peer()
            .send_to(b"x", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");

        let packets = poll_until_nonempty(&mut i, 0);
        assert_eq!(packets.len(), 1, "the fixture datagram must arrive");
        let (_, _, _, dst_port, _) = parts(&packets[0]);
        assert_eq!(
            dst_port, 5140,
            "the guest port comes from the declaration; {host_port} is the host listener"
        );
        assert_ne!(dst_port, host_port);
    }

    /// The bind address is the exposure decision. Binding the wildcard for
    /// a mapping that named an address would expose the guest on every
    /// interface the host has, which is a thing the plan has to say and
    /// this one did not.
    #[test]
    fn a_listener_binds_exactly_the_address_its_mapping_declared() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let bound = i
            .bound_addr(LOOPBACK, host_port)
            .expect("the mapping's listener");
        assert_eq!(bound, SocketAddr::new(LOOPBACK, host_port));
        assert!(
            !bound.ip().is_unspecified(),
            "a mapping that named an address must not be bound on the wildcard"
        );
    }

    /// At capacity the newcomer is refused. Evicting to make room would let
    /// one declared mapping close another's listener — a resource limit
    /// turned into a silently unserved declaration.
    #[test]
    fn the_listener_table_drops_rather_than_evicting() {
        let ports: Vec<u16> = (0..4).map(|_| free_host_port()).collect();
        let mut i = ingress(IngressBounds {
            listeners: 2,
            peers_per_listener: 8,
        });
        for (n, port) in ports.iter().enumerate() {
            let declared = i.declare(udp_mapping(*port, 5140 + n as u16));
            assert_eq!(
                declared.is_ok(),
                n < 2,
                "mapping {n} must {} at a cap of two",
                if n < 2 { "bind" } else { "be refused" }
            );
        }
        assert_eq!(i.len(), 2);
        assert!(
            i.bound_addr(LOOPBACK, ports[0]).is_some()
                && i.bound_addr(LOOPBACK, ports[1]).is_some(),
            "the two declared first are the two that survive"
        );
    }

    /// The same address and port declared twice is a refusal, not a
    /// replacement: replacing would close a live listener.
    #[test]
    fn a_second_mapping_on_one_bind_is_refused_rather_than_replacing_it() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");
        assert!(i.declare(udp_mapping(host_port, 5141)).is_err());
        assert_eq!(i.len(), 1);
    }

    /// Port zero is an ephemeral bind, which is a listener on a port
    /// nobody declared.
    #[test]
    fn a_mapping_naming_port_zero_is_refused() {
        let mut i = ingress(bounds());
        assert!(i.declare(udp_mapping(0, 5140)).is_err());
        assert!(i.declare(udp_mapping(free_host_port(), 0)).is_err());
        assert!(i.is_empty());
    }

    /// TCP declared ingress is not served by this datapath — it would need
    /// a listener whose accepted connections are originated *toward* the
    /// guest — and a mapping it cannot serve is refused rather than bound
    /// as though it were a datagram one.
    #[test]
    fn a_tcp_mapping_is_refused_rather_than_bound_here() {
        let mut i = ingress(bounds());
        assert!(
            i.declare(IngressMapping::tcp(LOOPBACK, free_host_port(), 80))
                .is_err()
        );
        assert!(i.is_empty());
    }

    /// **The reply path.** A peer that dialled the mapping must see the
    /// answer come from the address it dialled, or it discards it as
    /// belonging to no conversation of its own.
    #[test]
    fn a_guest_answer_leaves_by_the_listener_the_conversation_arrived_on() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let peer = peer();
        let peer_addr = peer.local_addr().expect("addr");
        peer.send_to(b"q", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        assert!(
            !poll_until_nonempty(&mut i, 0).is_empty(),
            "the peer's datagram must be taken, or the reply proves nothing"
        );

        assert!(matches!(
            i.reply(&reply_key(5140, peer_addr), b"a", 0),
            ReplyOutcome::Sent
        ));

        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).expect("the guest's answer");
        assert_eq!(&buf[..n], b"a");
        assert_eq!(
            from,
            SocketAddr::new(LOOPBACK, host_port),
            "the answer must come from the address the peer dialled"
        );
    }

    /// **The source policy, in the direction that matters.** A listener's
    /// socket is unconnected, so a guest that could name its destination
    /// would have an egress route around the admitted-destination check
    /// every other outbound datagram passes. Only a peer that has sent to
    /// this mapping may be answered on it.
    #[test]
    fn a_guest_datagram_for_a_peer_that_never_sent_does_not_leave_the_listener() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let known = peer();
        let known_addr = known.local_addr().expect("addr");
        known
            .send_to(b"q", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        assert!(!poll_until_nonempty(&mut i, 0).is_empty());
        assert!(
            matches!(
                i.reply(&reply_key(5140, known_addr), b"a", 0),
                ReplyOutcome::Sent
            ),
            "the peer that did send must be answerable, or this asserts nothing"
        );

        let stranger = peer();
        let stranger_addr = stranger.local_addr().expect("addr");
        assert!(
            matches!(
                i.reply(&reply_key(5140, stranger_addr), b"a", 0),
                ReplyOutcome::NotIngress
            ),
            "a destination the mapping never heard from is not this listener's to reach"
        );
        assert!(
            stranger.recv_from(&mut [0u8; 64]).is_err(),
            "and nothing reached it"
        );
    }

    /// A guest port with no mapping at all has no listener to answer on.
    #[test]
    fn a_guest_datagram_on_an_undeclared_port_is_not_an_ingress_reply() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");
        let peer_addr = peer().local_addr().expect("addr");
        assert!(matches!(
            i.reply(&reply_key(5141, peer_addr), b"a", 0),
            ReplyOutcome::NotIngress
        ));
    }

    /// A peer entry ends on a deadline, like every other per-conversation
    /// resource here, and an ended conversation is no longer a destination
    /// this listener may reach.
    #[test]
    fn an_expired_peer_can_no_longer_be_answered() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let peer = peer();
        let peer_addr = peer.local_addr().expect("addr");
        peer.send_to(b"q", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        assert!(!poll_until_nonempty(&mut i, 0).is_empty());
        assert_eq!(i.peer_count(LOOPBACK, host_port), Some(1));

        assert_eq!(i.expire(ASSOCIATION_LIFETIME_MILLIS), 1);
        assert_eq!(i.peer_count(LOOPBACK, host_port), Some(0));
        assert!(matches!(
            i.reply(
                &reply_key(5140, peer_addr),
                b"a",
                ASSOCIATION_LIFETIME_MILLIS
            ),
            ReplyOutcome::NotIngress
        ));
        assert_eq!(
            i.len(),
            1,
            "the listener itself is declared and does not expire with its peers"
        );
    }

    /// At capacity the newcomer is dropped and counted, and a live peer is
    /// never displaced to make room for it. Delivering the newcomer instead
    /// would hand the guest a question with no way back to whoever asked.
    #[test]
    fn a_peer_table_at_capacity_drops_the_newcomer_rather_than_a_live_peer() {
        let host_port = free_host_port();
        let mut i = ingress(IngressBounds {
            listeners: 8,
            peers_per_listener: 1,
        });
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let first = peer();
        first
            .send_to(b"first", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        assert_eq!(poll_until_nonempty(&mut i, 0).len(), 1);

        let second = peer();
        second
            .send_to(b"second", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send");
        // Bounded: give the datagram every chance to be delivered, so an
        // empty result is the bound and not a race.
        let mut delivered = Vec::new();
        for _ in 0..40 {
            delivered.extend(i.poll(0));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            delivered.is_empty(),
            "a peer past the cap must be dropped, not delivered: {delivered:?}"
        );
        assert_eq!(i.take_drops().peers_full, 1, "and counted");
        assert_eq!(
            i.peer_count(LOOPBACK, host_port),
            Some(1),
            "the peer already remembered is the one that survives"
        );
    }

    /// The guest's link cannot carry more than an MTU and this datapath
    /// refuses fragments, so a larger datagram has nowhere to go. Dropped
    /// rather than shortened: a truncated datagram delivered as whole is
    /// corrupt data the guest cannot detect.
    #[test]
    fn an_oversized_datagram_is_dropped_and_counted_rather_than_truncated() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let peer = peer();
        peer.send_to(
            &vec![0u8; MAX_DATAGRAM_PAYLOAD_BYTES + 1],
            (Ipv4Addr::LOCALHOST, host_port),
        )
        .expect("send");
        let mut delivered = Vec::new();
        for _ in 0..40 {
            delivered.extend(i.poll(0));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(delivered.is_empty(), "{delivered:?}");
        assert_eq!(i.take_drops().oversized, 1);
    }

    /// One poll must not be able to read a talkative peer's whole backlog:
    /// everything it produces goes onto one bounded queue, and what will
    /// not fit is read only to be discarded.
    #[test]
    fn one_poll_takes_a_bounded_number_of_datagrams_per_listener() {
        let host_port = free_host_port();
        let mut i = ingress(bounds());
        i.declare(udp_mapping(host_port, 5140)).expect("declare");

        let peer = peer();
        for n in 0..(DATAGRAMS_PER_SOURCE_POLL + 3) {
            peer.send_to(&[n as u8], (Ipv4Addr::LOCALHOST, host_port))
                .expect("send");
        }
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(i.poll(0).len(), DATAGRAMS_PER_SOURCE_POLL);
    }

    /// Per-listener cost is a descriptor held for the machine's whole life,
    /// so a teardown that leaked one would accumulate across restarts.
    #[test]
    fn clear_releases_every_listener_and_is_idempotent() {
        let mut i = ingress(bounds());
        for n in 0..3u16 {
            i.declare(udp_mapping(free_host_port(), 5140 + n))
                .expect("declare");
        }
        assert_eq!(i.len(), 3);
        i.clear();
        assert_eq!(i.len(), 0);
        i.clear();
        assert_eq!(i.len(), 0);
    }
}
