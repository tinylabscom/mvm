//! End-to-end coverage of the userspace socket datapath, unprivileged.
//!
//! No TUN device, no network namespace, no firewall anchor, no root. What
//! runs here is the shipping code: the real `mvm-netd` process, the real
//! guest agent, the real admission seam, the real host sockets.
//!
//! # Why nothing here talks to `127.0.0.1`
//!
//! `L3Admitter` refuses every loopback destination outright
//! ([`DenyCode::LoopbackDenied`], and `127.0.0.0/8` is in the mandatory-deny
//! list besides), and an `AdmittedPacket` is constructible only by that
//! admitter. A guest→datapath→loopback path is therefore unreachable by
//! construction, not by oversight. So every destination here is a listener
//! bound to a **private, non-loopback address this host already owns**,
//! discovered at runtime. Nothing leaves the machine: the host connects to
//! its own address, and the kernel routes it internally. A host with no such
//! interface cannot run these, and they say so rather than passing quietly.
//!
//! One consequence to know about before it surprises someone: binding a
//! non-loopback port is what a host firewall notices, so a machine running
//! one may prompt on first run, and one configured to *drop* rather than
//! refuse turns a refused connect into a pending one. Every wait here is
//! bounded against both, and the reset witness allows for the slower route.
//!
//! # Two ways in, on purpose
//!
//! The tests that can run in real time drive the **`mvm-netd` process** —
//! its own pump loop, its own trait object, its own service pass. A suite
//! that only ever serviced a handle it constructed itself would exercise
//! precisely the thing production can fail to do, and would stay green
//! through that failure; that is how the datapath once shipped with nothing
//! driving it.
//!
//! The flow-lifetime tests drive a handle directly, because their deadlines
//! are tens of seconds and the only honest way to reach them is an injected
//! clock. Every behaviour those cover is a datapath internal, and each one
//! the loop is responsible for driving is covered above through the process.
//!
//! # Timing
//!
//! The datapath's host sockets are registered on its readiness descriptor,
//! so a resolved connect and an arriving byte wake the drive loop rather
//! than waiting out its 50ms tick; the tick is now the floor on *time-driven*
//! work only — expiries, half-open timeouts, transport timers.
//!
//! The deadlines here stay in seconds anyway, and are deliberately not
//! tightened. What they are sized against is not the tick: these spawn a real
//! process, may prompt a host firewall on a first run, and run under a
//! process-parallel suite. A budget cut to the latency this datapath can now
//! achieve would be measuring the test host's scheduler. The witness that
//! readiness actually fires belongs where it can assert on readiness rather
//! than on elapsed time, and it lives in the datapath's own module tree.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mvm_agentd::l3::{
    AgentState, MemoryTun, NetAgent, RecordingConfigurator, RecordingPrivilegeDropper,
};
use mvm_hostd::netd::config::{NETD_READY_MARKER, NetdConfig, NetdEgress, NetdRule, NetdUdsLayout};
use mvm_hostd::netd::userspace::limits::{
    HALF_CLOSED_TIMEOUT_MILLIS, HANDSHAKE_COMPLETION_TIMEOUT_MILLIS,
};
use mvm_hostd::netd::userspace::readiness::ReadinessSet;
use mvm_hostd::netd::userspace::{UserspaceHandle, UserspaceSocketDatapath};
use mvm_hostd::netd::{DatapathHandle, DatapathRequest, select_host_datapath};
use mvm_net::channel::GuestService;
use mvm_net::l3::{DenyCode, DnsBindingStore, FlowLimits, FlowTable, L3Admitter, OutboundVerdict};
use mvm_protocol::l3::MTU_V1;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
    UdpRepr,
};

// ---------------------------------------------------------------------
// no SYN-ACK the host side has not earned
// ---------------------------------------------------------------------

/// The decision this makes executable: a guest must never see ESTABLISHED
/// for a destination that did not take the connection.
///
/// The observable is a destination that *refuses*, not one that merely has
/// not called `accept()` yet — a listening socket's backlog completes the
/// handshake in the kernel with no `accept()` anywhere, so "before the
/// listener accepts" is not something a host socket can distinguish. A
/// closed port is: the connect fails, and the only thing the guest may ever
/// be told is a reset.
///
/// This is the whole point of the deferred handshake. A stack that answered
/// the guest's SYN locally — the obvious implementation, and the one this
/// datapath deliberately does not have — would send a SYN-ACK here, and the
/// guest's `connect()` would return success for a destination that refused
/// it.
#[test]
fn a_refused_destination_reaches_the_guest_as_a_reset_and_never_as_a_syn_ack() {
    let Some(host) = host_target() else { return };
    let dead = closed_port_on(host);
    let cfg = config("netd-usp-refused", &[tcp_rule(host, dead)], &[]);
    let Some(mut netd) = Netd::start(&cfg) else {
        return;
    };

    netd.send(
        Segment {
            guest: cfg.guest_ipv4,
            guest_port: GUEST_PORT,
            dst: SocketAddr::new(IpAddr::V4(host), dead),
            control: TcpControl::Syn,
            seq: GUEST_ISN,
            ack: None,
            payload: &[],
        }
        .emit(),
    );

    // Longer than the others on purpose. A host whose firewall *drops* the
    // SYN rather than refusing it leaves the connect pending, and the reset
    // then comes from the half-open expiry ten seconds later. Either route
    // satisfies this witness; only the budget has to cover the slower one.
    let seen = netd.collect(Duration::from_secs(30), |packets| {
        packets.iter().filter_map(|p| tcp_of(p)).any(|s| s.rst)
    });
    let segments: Vec<Tcp> = seen.iter().filter_map(|p| tcp_of(p)).collect();

    assert!(
        !segments.iter().any(|s| s.syn && s.ack),
        "a destination that refused the connect must never be acknowledged \
         to the guest as established: {segments:?}"
    );
    assert!(
        segments.iter().any(|s| s.rst && s.dst_port == GUEST_PORT),
        "a failed connect owes the guest a reset, or its connect() hangs \
         until its own timeout: {segments:?}"
    );
}

// ---------------------------------------------------------------------
// bytes, both ways, at the admitted destination
// ---------------------------------------------------------------------

/// A translated flow has to carry payload in both directions — and the peer
/// that receives it has to be the destination policy admitted, which on a
/// datapath that re-derives destinations into `connect()` calls is a
/// property worth checking against the kernel's own view rather than
/// assuming.
#[test]
fn bytes_flow_both_ways_and_the_peer_is_the_admitted_destination() {
    let Some(host) = host_target() else { return };
    let listener = TcpListener::bind((host, 0)).expect("bind the admitted destination");
    let dst = listener.local_addr().expect("local addr");
    let cfg = config("netd-usp-duplex", &[tcp_rule(host, dst.port())], &[]);
    let Some(mut netd) = Netd::start(&cfg) else {
        return;
    };

    // Off-thread with its result on a channel rather than a join: `accept`
    // has no timeout of its own, and a host that never delivers the
    // connection must fail this test rather than park it forever.
    let (served, from_server) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().expect("accept the re-originated flow");
        peer.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("read timeout");
        let mut got = [0u8; 4];
        peer.read_exact(&mut got).expect("the guest's bytes arrive");
        peer.write_all(b"pong").expect("answer the guest");
        peer.flush().ok();
        let _ = served.send((got, peer.local_addr().expect("server local addr")));
    });

    let isn = netd.establish(&cfg, dst);
    netd.send(
        Segment {
            guest: cfg.guest_ipv4,
            guest_port: GUEST_PORT,
            dst,
            control: TcpControl::None,
            seq: GUEST_ISN.wrapping_add(1),
            ack: Some(isn.wrapping_add(1)),
            payload: b"ping",
        }
        .emit(),
    );

    let seen = netd.collect(Duration::from_secs(10), |packets| {
        packets
            .iter()
            .filter_map(|p| tcp_of(p))
            .any(|s| s.payload == b"pong")
    });
    assert!(
        seen.iter()
            .filter_map(|p| tcp_of(p))
            .any(|s| s.payload == b"pong" && s.dst_port == GUEST_PORT),
        "the destination's reply must be framed back to the guest: {:?}",
        seen.iter().filter_map(|p| tcp_of(p)).collect::<Vec<_>>()
    );

    let (got, served_at) = from_server
        .recv_timeout(Duration::from_secs(30))
        .expect("the destination must receive the guest's bytes and answer them");
    assert_eq!(
        &got, b"ping",
        "the guest's payload must reach the peer intact"
    );
    assert_eq!(
        served_at, dst,
        "the flow must terminate at the destination policy admitted, not \
         merely at something that answered"
    );
}

// ---------------------------------------------------------------------
// default-deny
// ---------------------------------------------------------------------

/// Default-deny, observed from outside the process: an unadmitted
/// destination sees no connection at all. Not a late refusal, not a socket
/// opened and dropped — nothing.
///
/// The admitted destination is opened in the same run, so a suite that
/// silently stopped forwarding altogether cannot pass this.
#[test]
fn a_destination_policy_did_not_admit_is_never_connected_to() {
    let Some(host) = host_target() else { return };
    let admitted = TcpListener::bind((host, 0)).expect("bind the admitted destination");
    let refused = TcpListener::bind((host, 0)).expect("bind the unadmitted destination");
    let admitted_addr = admitted.local_addr().expect("local addr");
    let refused_addr = refused.local_addr().expect("local addr");
    let cfg = config(
        "netd-usp-deny",
        &[tcp_rule(host, admitted_addr.port())],
        &[],
    );
    let Some(mut netd) = Netd::start(&cfg) else {
        return;
    };

    for (port, dst) in [(GUEST_PORT, admitted_addr), (GUEST_PORT + 1, refused_addr)] {
        netd.send(
            Segment {
                guest: cfg.guest_ipv4,
                guest_port: port,
                dst,
                control: TcpControl::Syn,
                seq: GUEST_ISN,
                ack: None,
                payload: &[],
            }
            .emit(),
        );
    }

    // Wait on the admitted flow's SYN-ACK. It is the ordering anchor: by the
    // time it arrives the datapath has had the denied SYN for at least as
    // long, so an empty accept queue below is a refusal rather than a race.
    let seen = netd.collect(Duration::from_secs(10), |packets| {
        packets
            .iter()
            .filter_map(|p| tcp_of(p))
            .any(|s| s.syn && s.ack)
    });
    assert!(
        seen.iter()
            .filter_map(|p| tcp_of(p))
            .any(|s| s.syn && s.ack && s.dst_port == GUEST_PORT),
        "the admitted destination must still be reachable, or this test \
         proves only that nothing works: {seen:?}"
    );
    admitted
        .set_nonblocking(true)
        .expect("non-blocking accept probe");
    assert!(
        admitted.accept().is_ok(),
        "the admitted destination must have a connection waiting"
    );

    refused
        .set_nonblocking(true)
        .expect("non-blocking accept probe");
    assert!(
        refused.accept().is_err(),
        "a destination policy did not admit must never be connected to"
    );
    assert!(
        !seen
            .iter()
            .filter_map(|p| tcp_of(p))
            .any(|s| s.dst_port == GUEST_PORT + 1),
        "a denied packet is refused above the datapath: the guest gets \
         nothing back for it, not even a reset the host never earned"
    );
}

/// The same refusal, named. The deny code is a counter inside the gateway
/// process and cannot be read from outside it, so the reason is pinned at
/// the seam that produces it — which is also the seam that makes forwarding
/// unrepresentable: no `AdmittedPacket`, no call the datapath could make.
#[test]
fn a_denied_destination_is_refused_by_name_before_any_socket_exists() {
    let Some(host) = host_target() else { return };
    let admitted = TcpListener::bind((host, 0)).expect("bind the admitted destination");
    let refused = TcpListener::bind((host, 0)).expect("bind the unadmitted destination");
    let admitted_addr = admitted.local_addr().expect("local addr");
    let refused_addr = refused.local_addr().expect("local addr");
    let cfg = config(
        "usp-deny-code",
        &[tcp_rule(host, admitted_addr.port())],
        &[],
    );
    let mut translator = Translator::open(&cfg);

    let denied = Segment {
        guest: cfg.guest_ipv4,
        guest_port: GUEST_PORT,
        dst: refused_addr,
        control: TcpControl::Syn,
        seq: GUEST_ISN,
        ack: None,
        payload: &[],
    }
    .emit();
    assert_eq!(
        translator.verdict(&denied),
        Some(DenyCode::PortNotAdmitted),
        "an admitted host on an unadmitted port is a port refusal: the two \
         are different fixes for whoever wrote the policy"
    );

    let elsewhere = Segment {
        guest: cfg.guest_ipv4,
        guest_port: GUEST_PORT,
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        control: TcpControl::Syn,
        seq: GUEST_ISN,
        ack: None,
        payload: &[],
    }
    .emit();
    assert_eq!(
        translator.verdict(&elsewhere),
        Some(DenyCode::DestinationNotAdmitted),
        "a host no rule covers is a destination refusal"
    );

    translator.service(0);
    refused
        .set_nonblocking(true)
        .expect("non-blocking accept probe");
    assert!(
        refused.accept().is_err(),
        "a denied packet must never have reached a host socket"
    );
    assert_eq!(
        translator.handle.open_socket_count(),
        0,
        "and must cost no descriptor"
    );
}

// ---------------------------------------------------------------------
// datagrams
// ---------------------------------------------------------------------

/// A guest datagram is re-originated on a host socket, and the peer's answer
/// comes back framed for the guest.
#[test]
fn a_guest_datagram_round_trips_over_a_host_socket() {
    let Some(host) = host_target() else { return };
    let peer = UdpSocket::bind((host, 0)).expect("bind the admitted destination");
    let dst = peer.local_addr().expect("local addr");
    let cfg = config("netd-usp-udp", &[], &[udp_rule(host, dst.port())]);
    let Some(mut netd) = Netd::start(&cfg) else {
        return;
    };

    netd.send(datagram(cfg.guest_ipv4, GUEST_PORT, dst, b"ping"));

    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut buf = [0u8; 64];
    let (n, from) = peer
        .recv_from(&mut buf)
        .expect("the guest's datagram arrives");
    assert_eq!(&buf[..n], b"ping");
    peer.send_to(b"pong", from).expect("answer the guest");

    let seen = netd.collect(Duration::from_secs(10), |packets| {
        packets
            .iter()
            .filter_map(|p| udp_of(p))
            .any(|d| d.payload == b"pong")
    });
    assert!(
        seen.iter()
            .filter_map(|p| udp_of(p))
            .any(|d| d.payload == b"pong" && d.dst_port == GUEST_PORT),
        "the peer's answer must reach the guest: {:?}",
        seen.iter().filter_map(|p| udp_of(p)).collect::<Vec<_>>()
    );
}

/// A datagram socket accepts from anywhere unless something stops it, so an
/// attacker who guesses the host's ephemeral port could otherwise inject an
/// answer the guest believes came from the destination it dialled.
///
/// The off-path datagram is sent *first*, so a guest that receives the
/// legitimate answer has provably had the chance to receive the forged one.
#[test]
fn an_off_path_datagram_never_reaches_the_guest() {
    let Some(host) = host_target() else { return };
    let peer = UdpSocket::bind((host, 0)).expect("bind the admitted destination");
    let dst = peer.local_addr().expect("local addr");
    let cfg = config("netd-usp-udp-offpath", &[], &[udp_rule(host, dst.port())]);
    let Some(mut netd) = Netd::start(&cfg) else {
        return;
    };

    netd.send(datagram(cfg.guest_ipv4, GUEST_PORT, dst, b"ping"));

    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut buf = [0u8; 64];
    let (n, association) = peer
        .recv_from(&mut buf)
        .expect("the guest's datagram arrives");
    assert_eq!(&buf[..n], b"ping");

    // Same host, same association port, different source: exactly what an
    // off-path injector has.
    let off_path = UdpSocket::bind((host, 0)).expect("bind the off-path sender");
    off_path
        .send_to(b"forged", association)
        .expect("the injection is attempted");
    peer.send_to(b"pong", association)
        .expect("the real answer follows it");

    let seen = netd.collect(Duration::from_secs(10), |packets| {
        packets
            .iter()
            .filter_map(|p| udp_of(p))
            .any(|d| d.payload == b"pong")
    });
    let payloads: Vec<Vec<u8>> = seen
        .iter()
        .filter_map(|p| udp_of(p))
        .map(|d| d.payload)
        .collect();
    assert!(
        payloads.iter().any(|p| p == b"pong"),
        "the legitimate answer must arrive, or the negative below is vacuous: {payloads:?}"
    );
    assert!(
        !payloads.iter().any(|p| p == b"forged"),
        "a datagram from a source the guest never addressed must not reach it: {payloads:?}"
    );
}

// ---------------------------------------------------------------------
// flow lifetime bounds
// ---------------------------------------------------------------------

/// A guest that is sent a SYN-ACK and never answers it leaves its flow where
/// no host error can ever arrive — nothing to read, nothing to write, no
/// keepalive, no reset deadline. Without a bound it holds a descriptor and a
/// slot in the socket budget for the machine's whole life.
///
/// Driven on an injected clock: the deadline is ten seconds, and a test that
/// waited it out in real time would be ten seconds of nothing per run.
#[test]
fn a_handshake_the_guest_never_finishes_gives_its_socket_back() {
    let Some(host) = host_target() else { return };
    let listener = TcpListener::bind((host, 0)).expect("bind the admitted destination");
    let dst = listener.local_addr().expect("local addr");
    let cfg = config("usp-unfinished", &[tcp_rule(host, dst.port())], &[]);
    let mut translator = Translator::open(&cfg);

    translator.open_flow(&cfg, dst, GUEST_PORT);
    assert_eq!(
        translator.handle.open_socket_count(),
        1,
        "the connect must have become a flow over a real host socket"
    );

    // Read the reset, not the socket count: a reclaimed flow stays in the
    // table until the guest takes the reset it is owed, so the count alone
    // cannot tell "still waiting" from "already reset".
    translator.service(HANDSHAKE_COMPLETION_TIMEOUT_MILLIS - 1);
    let early = translator.drain();
    assert!(
        !early.iter().filter_map(|p| tcp_of(p)).any(|s| s.rst),
        "inside the bound the guest still gets its chance to answer: {early:?}"
    );
    assert_eq!(translator.handle.open_socket_count(), 1);

    translator.service(HANDSHAKE_COMPLETION_TIMEOUT_MILLIS);
    let told = translator.drain();
    assert!(
        told.iter().filter_map(|p| tcp_of(p)).any(|s| s.rst),
        "a guest whose flow is reclaimed is told, not left waiting: {told:?}"
    );
    translator.service(HANDSHAKE_COMPLETION_TIMEOUT_MILLIS);
    assert_eq!(
        translator.handle.open_socket_count(),
        0,
        "and the budget slot comes back"
    );
}

/// Once the peer stops sending, the datapath stops reading that socket, so
/// no host error can surface on it again and nothing else would ever end the
/// flow. The bound is what stops a guest from parking descriptors behind
/// peers that have already finished.
#[test]
fn a_half_closed_flow_gives_its_socket_back() {
    let Some(host) = host_target() else { return };
    let listener = TcpListener::bind((host, 0)).expect("bind the admitted destination");
    let dst = listener.local_addr().expect("local addr");
    let cfg = config("usp-half-closed", &[tcp_rule(host, dst.port())], &[]);
    let mut translator = Translator::open(&cfg);

    let isn = translator.open_flow(&cfg, dst, GUEST_PORT);
    let peer = listener.accept().expect("accept the re-originated flow").0;
    translator.finish_handshake(&cfg, dst, GUEST_PORT, isn);

    // The peer is done talking; the guest never says it is.
    peer.shutdown(std::net::Shutdown::Write)
        .expect("the peer closes its half");
    // Settled at zero on purpose: the bound runs from the pass that
    // *observes* the peer finish, not from when the peer finished, so a
    // fixture that let the observation land at an arbitrary clock would be
    // asserting against a deadline it cannot name.
    translator.settle(0);
    assert_eq!(
        translator.handle.open_socket_count(),
        1,
        "a peer that merely finished sending does not end the flow on its own"
    );
    translator.service(HALF_CLOSED_TIMEOUT_MILLIS - 1);
    let early = translator.drain();
    assert!(
        !early.iter().filter_map(|p| tcp_of(p)).any(|s| s.rst),
        "inside the bound the guest may still be uploading: {early:?}"
    );
    assert_eq!(translator.handle.open_socket_count(), 1);

    translator.service(HALF_CLOSED_TIMEOUT_MILLIS);
    let _ = translator.drain();
    translator.service(HALF_CLOSED_TIMEOUT_MILLIS);
    assert_eq!(
        translator.handle.open_socket_count(),
        0,
        "past the bound the half-closed flow gives its descriptor back"
    );
    drop(peer);
}

/// The mirror that keeps the two above from being a reaper that eats
/// everything: a quiet flow whose peer is alive is **not** reclaimed. This
/// datapath carries streams that are idle by design — an event stream
/// between events, a socket between messages — and a reaper measuring
/// quietness would kill them and leave nothing behind but a dropped
/// connection.
#[test]
fn a_quiet_flow_with_a_live_peer_is_not_reclaimed() {
    let Some(host) = host_target() else { return };
    let listener = TcpListener::bind((host, 0)).expect("bind the admitted destination");
    let dst = listener.local_addr().expect("local addr");
    let cfg = config("usp-quiet", &[tcp_rule(host, dst.port())], &[]);
    let mut translator = Translator::open(&cfg);

    let isn = translator.open_flow(&cfg, dst, GUEST_PORT);
    let peer = listener.accept().expect("accept the re-originated flow").0;
    translator.finish_handshake(&cfg, dst, GUEST_PORT, isn);

    // Well past both deadlines the two tests above rely on, with neither
    // side saying anything and the peer still there.
    //
    // Drained every pass, and that is the load-bearing part: a reclaimed
    // flow is *kept* in the table while it still holds the reset it owes
    // the guest, so a socket count read without draining cannot tell a
    // surviving flow from a reset one. The reset itself is the signal.
    let quiet_for = HALF_CLOSED_TIMEOUT_MILLIS * 2 + HANDSHAKE_COMPLETION_TIMEOUT_MILLIS;
    for step in 1..=8u64 {
        translator.service(quiet_for * step / 8);
        let told = translator.drain();
        assert!(
            !told.iter().filter_map(|p| tcp_of(p)).any(|s| s.rst),
            "a working connection with nothing to say must not be reset: \
             quietness is not evidence of a dead peer: {told:?}"
        );
    }
    assert_eq!(
        translator.handle.open_socket_count(),
        1,
        "and it must still hold its host socket"
    );
    drop(peer);
}

// ---------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------

/// The guest's source port. One flow per test, so a fixed value makes a
/// desynchronised fixture obvious in a packet dump.
const GUEST_PORT: u16 = 50_000;
/// The guest's initial sequence number, fixed for the same reason.
const GUEST_ISN: u32 = 1_000;
/// Hop limit on every fixture packet. Nothing decrements it: the guest is
/// one in-memory hop away.
const HOP_LIMIT: u8 = 64;

/// A private, non-loopback IPv4 this host owns, or `None`.
///
/// `getifaddrs` rather than a literal or a connect-to-the-internet probe:
/// the address has to be one the host will actually accept a connection on,
/// and no packet may leave the machine.
fn discover_private_ipv4() -> Option<Ipv4Addr> {
    // SAFETY: a standard getifaddrs walk. Every pointer is null-checked and
    // the list is freed before return.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut found = None;
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let sin = ifa.ifa_addr as *const libc::sockaddr_in;
                // `s_addr` is network byte order, so its bytes are the octets.
                let o = (*sin).sin_addr.s_addr.to_ne_bytes();
                let ip = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
                if ip.is_private() && !ip.is_loopback() && !ip.is_link_local() {
                    found = Some(ip);
                    break;
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        found
    }
}

/// The destination address these tests use, or `None` with the reason
/// printed.
///
/// Two conditions. The host must own a private non-loopback address, for the
/// reason in this file's header. And it must be a host this datapath is
/// actually the one selected on: a Linux host holding CAP_NET_ADMIN gets the
/// packet-level TUN datapath instead, and the same suite run there would be
/// asserting against a different backend.
fn host_target() -> Option<Ipv4Addr> {
    if select_host_datapath().fallback_reason.is_none() {
        eprintln!(
            "skipped: this host serves the packet-level datapath, so the userspace \
             socket datapath is not what a gateway here would use"
        );
        return None;
    }
    let found = discover_private_ipv4();
    if found.is_none() {
        eprintln!(
            "skipped: no private non-loopback IPv4 on this host. Loopback is \
             mandatory-deny by design, so there is no destination a guest could \
             be admitted to reach"
        );
    }
    found
}

/// A port on `host` nothing is listening on, so a connect to it is refused
/// rather than left pending. Taken from the kernel's own ephemeral range and
/// released, which is the only way to name a free port without guessing.
fn closed_port_on(host: Ipv4Addr) -> u16 {
    let probe = TcpListener::bind((host, 0)).expect("bind a probe listener");
    let port = probe.local_addr().expect("local addr").port();
    drop(probe);
    port
}

fn tcp_rule(host: Ipv4Addr, port: u16) -> NetdRule {
    NetdRule {
        proto: "tcp".into(),
        cidr: format!("{host}/32"),
        port_lo: port,
        port_hi: port,
    }
}

fn udp_rule(host: Ipv4Addr, port: u16) -> NetdRule {
    NetdRule {
        proto: "udp".into(),
        cidr: format!("{host}/32"),
        port_lo: port,
        port_hi: port,
    }
}

/// One machine's configuration, admitting exactly the rules it is given.
///
/// The destination is private, so it needs an explicit `admitted_private`
/// entry as well: an allow-list rule alone does not open an RFC1918 range,
/// which is itself the posture worth having.
fn config(vm_id: &str, tcp: &[NetdRule], udp: &[NetdRule]) -> NetdConfig {
    let mut rules = tcp.to_vec();
    rules.extend_from_slice(udp);
    let private: Vec<String> = rules.iter().map(|r| r.cidr.clone()).collect();
    NetdConfig {
        node_id: "node-1".into(),
        vm_id: vm_id.into(),
        boot_id: "boot-1".into(),
        plan_digest: "sha256:plan".into(),
        uds_layout: NetdUdsLayout::PerVmDir,
        gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
        guest_ipv4: Ipv4Addr::new(10, 201, 0, 6),
        gateway_ipv6: None,
        guest_ipv6: None,
        mtu: MTU_V1,
        egress: NetdEgress::Rules(rules),
        admitted_private_cidrs: private,
        icmp: Default::default(),
        policy_epoch: 1,
        max_flows: 4096,
        queue_depth: 256,
        dns_qps: 50,
        ingress: Vec::new(),
    }
}

// ---------------------------------------------------------------------
// the shipping process, driven by the real agent
// ---------------------------------------------------------------------

const NETD_BIN: &str = env!("CARGO_BIN_EXE_mvm-netd");

/// How long the process gets to bind its channels and say so. Generous:
/// binding is microseconds, and the only thing that eats real time here is a
/// host that is slow to *start* the process at all.
const READY_DEADLINE: Duration = Duration::from_secs(120);

/// A live `mvm-netd` process with the real guest agent attached to it.
struct Netd {
    child: Child,
    agent: NetAgent<MemoryTun, RecordingConfigurator>,
    data: UnixStream,
    /// Kept alive: the process's sockets live under it, and dropping it
    /// early would pull them out from under the running child.
    _home: tempfile::TempDir,
    /// Held so the session stays up; the gateway ends when it closes.
    _control: UnixStream,
}

impl Netd {
    /// Start the process, connect both guest channels, and complete the
    /// handshake. `None` when the process refused to serve this host, which
    /// is reported rather than swallowed.
    fn start(cfg: &NetdConfig) -> Option<Self> {
        let home = tempfile::tempdir().expect("temp home");
        let mut child = Command::new(NETD_BIN)
            .env("MVM_HOME", home.path())
            .env("HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mvm-netd");
        child
            .stdin
            .take()
            .expect("stdin piped")
            .write_all(serde_json::to_string(cfg).expect("config json").as_bytes())
            .expect("write the config");

        // Read the marker off-thread against a deadline. A pipe read has no
        // timeout of its own, and a child that never reaches `main` — a
        // freshly linked binary held at exec by a host's code-evaluation
        // service will do it — would otherwise park the whole suite here.
        let mut reader = BufReader::new(child.stdout.take().expect("stdout piped"));
        let (marker, ready) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = marker.send(reader.read_line(&mut line).map(|_| line));
        });
        let line = match ready.recv_timeout(READY_DEADLINE) {
            Ok(Ok(line)) if !line.is_empty() => line,
            Ok(_) => {
                let mut stderr = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut stderr);
                }
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("skipped: mvm-netd refused to serve this host: {stderr}");
                return None;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "mvm-netd printed no ready marker within {READY_DEADLINE:?}. It binds \
                     its channels before printing, so this is a host that did not run the \
                     process rather than a gateway that refused"
                );
            }
        };
        assert!(
            line.starts_with(NETD_READY_MARKER),
            "expected the ready marker, got {line:?}"
        );

        // Both channels before the handshake: the process accepts control
        // and then data, so an agent that handshakes with the data channel
        // unconnected talks to a process still sitting in `accept`.
        let mut control = connect(home.path(), &cfg.vm_id, GuestService::NetworkControl);
        let data = connect(
            home.path(),
            &cfg.vm_id,
            GuestService::NetworkData { queue: 0 },
        );
        data.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");
        // The handshake is a blocking read. Bounded, so a process that dies
        // between the ready marker and its first control frame fails the
        // test instead of parking it forever.
        control
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("read timeout");

        let mut agent = NetAgent::new(MemoryTun::new("mvm0"), RecordingConfigurator::default())
            .with_privilege_dropper(Box::new(RecordingPrivilegeDropper::default()));
        agent
            .handshake(&mut control)
            .expect("the agent completes the handshake against the real process");
        assert_eq!(agent.state(), AgentState::Ready);

        Some(Self {
            child,
            agent,
            data,
            _home: home,
            _control: control,
        })
    }

    /// Put one packet on the guest's TUN and let the agent frame it across.
    fn send(&mut self, packet: Vec<u8>) {
        let Self { agent, data, .. } = self;
        agent.tun_mut().push_outbound(packet);
        assert_eq!(
            agent.pump_tun_to_transport(data).expect("frame the packet"),
            1,
            "the agent must accept the fixture packet"
        );
    }

    /// Collect packets the process delivers to the guest until `done` holds
    /// or `budget` elapses.
    ///
    /// Never asserts on its own: a test that wants an absence reads the
    /// whole collection, and one that wants a presence says so itself.
    fn collect(&mut self, budget: Duration, done: impl Fn(&[Vec<u8>]) -> bool) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + budget;
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        while Instant::now() < deadline {
            match self.data.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.agent
                        .ingest_transport_bytes(&buf[..n])
                        .expect("the host's frames must be well formed");
                    seen.extend(self.agent.tun_mut().take_delivered());
                    if done(&seen) {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(err) => panic!("reading the guest data channel: {err}"),
            }
        }
        seen
    }

    /// Send a SYN and return the stack's initial sequence number from the
    /// SYN-ACK it earns, having answered it as the guest would.
    fn establish(&mut self, cfg: &NetdConfig, dst: SocketAddr) -> u32 {
        self.send(
            Segment {
                guest: cfg.guest_ipv4,
                guest_port: GUEST_PORT,
                dst,
                control: TcpControl::Syn,
                seq: GUEST_ISN,
                ack: None,
                payload: &[],
            }
            .emit(),
        );
        let seen = self.collect(Duration::from_secs(10), |packets| {
            packets
                .iter()
                .filter_map(|p| tcp_of(p))
                .any(|s| s.syn && s.ack)
        });
        let isn = seen
            .iter()
            .filter_map(|p| tcp_of(p))
            .find(|s| s.syn && s.ack && s.dst_port == GUEST_PORT)
            .map(|s| s.seq)
            .expect("a live destination must earn the guest its SYN-ACK");
        self.send(
            Segment {
                guest: cfg.guest_ipv4,
                guest_port: GUEST_PORT,
                dst,
                control: TcpControl::None,
                seq: GUEST_ISN.wrapping_add(1),
                ack: Some(isn.wrapping_add(1)),
                payload: &[],
            }
            .emit(),
        );
        isn
    }
}

impl Drop for Netd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Resolve a service socket under this test's home and connect, retrying
/// briefly: the ready marker means bound, not yet accepted.
///
/// The path is derived from an explicit root rather than by moving
/// `MVM_HOME` around the process, which several tests in one binary cannot
/// do without racing each other.
fn connect(home: &std::path::Path, vm_id: &str, service: GuestService) -> UnixStream {
    let state = mvm_core::config::vm_state_dir_at(home, vm_id);
    let path = mvm_core::config::vm_vsock_port_socket_at(&state, service.port());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(&path) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect to {}: {e}", path.display()),
        }
    }
}

// ---------------------------------------------------------------------
// the datapath alone, on an injected clock
// ---------------------------------------------------------------------

/// The real admission seam over a real userspace handle, serviced by the
/// test.
///
/// Only for behaviour whose deadlines are tens of seconds. Everything the
/// drive loop is responsible for driving is covered through the process
/// above; a handle a test services itself cannot witness that.
struct Translator {
    admitter: L3Admitter,
    handle: UserspaceHandle,
}

impl Translator {
    fn open(cfg: &NetdConfig) -> Self {
        let mut admitter = L3Admitter::new(
            cfg.lease(),
            cfg.to_policy().expect("policy"),
            FlowTable::new(FlowLimits::default()),
            DnsBindingStore::with_defaults(),
            cfg.to_ingress_table().expect("ingress"),
        );
        admitter.set_ready(true);
        let handle = UserspaceSocketDatapath::new()
            .open_handle(&DatapathRequest {
                machine_id: cfg.vm_id.clone(),
                gateway: cfg.gateway_ipv4,
                guest: cfg.guest_ipv4,
                prefix_len: cfg.lease().prefix_len(),
                gateway_v6: cfg.gateway_ipv6,
                guest_v6: cfg.guest_ipv6,
                mtu: cfg.mtu,
                ingress: Vec::new(),
            })
            .expect("opening a userspace handle needs no privileges");
        Self { admitter, handle }
    }

    /// Why admission refused this packet, or `None` if it forwarded.
    fn verdict(&mut self, packet: &[u8]) -> Option<DenyCode> {
        match self.admitter.admit_outbound(packet, 0) {
            OutboundVerdict::Deny(code) => Some(code),
            OutboundVerdict::Forward(_) => None,
            OutboundVerdict::Gateway(service, _) => {
                panic!("the fixture packet reached the gateway service {service:?}")
            }
        }
    }

    /// Admit one packet and forward it, as the gateway would.
    fn send(&mut self, packet: &[u8], now_millis: u64) {
        match self.admitter.admit_outbound(packet, now_millis) {
            OutboundVerdict::Forward(admitted) => self
                .handle
                .send_to_network(&admitted)
                .expect("the datapath accepts an admitted packet"),
            other => panic!("the fixture packet was not admitted: {other:?}"),
        }
    }

    fn service(&mut self, now_millis: u64) {
        self.handle.service(now_millis).expect("service");
    }

    /// Everything the handle is holding for the guest right now.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; MTU_V1 as usize];
        while let Ok(n) = self.handle.recv_from_network(&mut buf) {
            out.push(buf[..n].to_vec());
        }
        out
    }

    /// Service repeatedly at one clock value, so anything the host sockets
    /// have to report has arrived and every deadline it arms is anchored at
    /// a time the test named.
    fn settle(&mut self, now_millis: u64) {
        for _ in 0..SETTLE_PASSES {
            self.service(now_millis);
            let _ = self.drain();
            std::thread::sleep(SETTLE_PAUSE);
        }
    }

    /// Send a SYN, drive until the host connect resolves, and return the
    /// stack's initial sequence number from the SYN-ACK.
    fn open_flow(&mut self, cfg: &NetdConfig, dst: SocketAddr, guest_port: u16) -> u32 {
        self.open_flow_paced(cfg, dst, guest_port, SETTLE_PAUSE)
    }

    /// [`Self::open_flow`], with the wait between passes named by the caller.
    ///
    /// A correctness fixture pauses, because it is not timing anything and a
    /// spin would burn a core for the whole suite. A measurement of how long
    /// this takes cannot pause: the pause would be most of what it reported.
    fn open_flow_paced(
        &mut self,
        cfg: &NetdConfig,
        dst: SocketAddr,
        guest_port: u16,
        pause: Duration,
    ) -> u32 {
        self.send(
            &Segment {
                guest: cfg.guest_ipv4,
                guest_port,
                dst,
                control: TcpControl::Syn,
                seq: GUEST_ISN,
                ack: None,
                payload: &[],
            }
            .emit(),
            0,
        );
        // Bounded by wall clock rather than by a pass count, so the budget
        // means the same thing whether or not the caller pauses between
        // passes.
        let start = Instant::now();
        while start.elapsed() < OPEN_FLOW_BUDGET {
            self.service(0);
            for packet in self.drain() {
                if let Some(seg) = tcp_of(&packet)
                    && seg.syn
                    && seg.ack
                    && seg.dst_port == guest_port
                {
                    return seg.seq;
                }
            }
            if !pause.is_zero() {
                std::thread::sleep(pause);
            }
        }
        panic!("a connect to a live destination must earn the guest a SYN-ACK");
    }

    /// Answer the SYN-ACK, so the flow leaves SYN-RECEIVED. Without it every
    /// assertion about an established flow would be about a handshake that
    /// never finished.
    fn finish_handshake(&mut self, cfg: &NetdConfig, dst: SocketAddr, guest_port: u16, isn: u32) {
        self.send(
            &Segment {
                guest: cfg.guest_ipv4,
                guest_port,
                dst,
                control: TcpControl::None,
                seq: GUEST_ISN.wrapping_add(1),
                ack: Some(isn.wrapping_add(1)),
                payload: &[],
            }
            .emit(),
            0,
        );
        self.service(0);
        let _ = self.drain();
    }
}

/// How long a fixture will wait for a host connect on this machine to
/// resolve. Only ever reached on the way to a failure, so it is sized to
/// outlast a loaded host rather than to keep a passing run short.
const OPEN_FLOW_BUDGET: Duration = Duration::from_secs(5);

/// The wait a correctness fixture takes between service passes. A spin would
/// burn a core for the length of the suite to save milliseconds nothing is
/// measuring.
const SETTLE_PAUSE: Duration = Duration::from_millis(2);

/// Passes [`Translator::settle`] makes. Comfortably more than a loopback
/// socket needs to report a peer's close, and cheap: each is one poll.
const SETTLE_PASSES: usize = 25;

// ---------------------------------------------------------------------
// packets
// ---------------------------------------------------------------------

/// One guest segment, described by every field that matters rather than by a
/// row of positional arguments: with a sequence and an acknowledgement both
/// in play, two adjacent `u32`s are a transposition waiting to happen.
struct Segment<'a> {
    guest: Ipv4Addr,
    guest_port: u16,
    dst: SocketAddr,
    control: TcpControl,
    seq: u32,
    ack: Option<u32>,
    payload: &'a [u8],
}

impl Segment<'_> {
    /// Emitted through smoltcp rather than hand-laid, because the checksum
    /// has to be right: a segment with a zero checksum is dropped by the
    /// flow's own stack before it reaches anything under test, and the test
    /// would then be asserting against a packet nothing ever saw.
    fn emit(&self) -> Vec<u8> {
        let dst = match self.dst.ip() {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => panic!("the fixture destinations are IPv4"),
        };
        let tcp = TcpRepr {
            src_port: self.guest_port,
            dst_port: self.dst.port(),
            control: self.control,
            // `as i32` is the wrap TCP sequence arithmetic is defined on.
            seq_number: TcpSeqNumber(self.seq as i32),
            ack_number: self.ack.map(|a| TcpSeqNumber(a as i32)),
            window_len: u16::MAX,
            window_scale: None,
            max_seg_size: matches!(self.control, TcpControl::Syn).then_some(1_400),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: self.payload,
        };
        let ip = Ipv4Repr {
            src_addr: self.guest,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: HOP_LIMIT,
        };
        let checksums = ChecksumCapabilities::default();
        let mut bytes = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
        ip.emit(&mut packet, &checksums);
        tcp.emit(
            &mut TcpPacket::new_unchecked(packet.payload_mut()),
            &self.guest.into(),
            &dst.into(),
            &checksums,
        );
        bytes
    }
}

/// One guest datagram toward `dst`.
fn datagram(guest: Ipv4Addr, guest_port: u16, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let remote = match dst.ip() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => panic!("the fixture destinations are IPv4"),
    };
    let udp = UdpRepr {
        src_port: guest_port,
        dst_port: dst.port(),
    };
    let ip = Ipv4Repr {
        src_addr: guest,
        dst_addr: remote,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: HOP_LIMIT,
    };
    let checksums = ChecksumCapabilities::default();
    let mut bytes = vec![0u8; ip.buffer_len() + ip.payload_len];
    let mut packet = Ipv4Packet::new_unchecked(&mut bytes);
    ip.emit(&mut packet, &checksums);
    udp.emit(
        &mut UdpPacket::new_unchecked(packet.payload_mut()),
        &guest.into(),
        &remote.into(),
        payload.len(),
        |buf| buf.copy_from_slice(payload),
        &checksums,
    );
    bytes
}

/// What a TCP segment carried, in the terms the assertions are written in.
#[derive(Debug)]
struct Tcp {
    dst_port: u16,
    syn: bool,
    ack: bool,
    rst: bool,
    seq: u32,
    /// What the sender has acknowledged; meaningful only when `ack` is set.
    /// Anything holding a send window open needs it: without it a sender
    /// cannot tell how much of what it sent is still outstanding.
    ack_number: u32,
    payload: Vec<u8>,
}

fn tcp_of(packet: &[u8]) -> Option<Tcp> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Tcp {
        return None;
    }
    let seg = TcpPacket::new_checked(ip.payload()).ok()?;
    Some(Tcp {
        dst_port: seg.dst_port(),
        syn: seg.syn(),
        ack: seg.ack(),
        rst: seg.rst(),
        seq: seg.seq_number().0 as u32,
        ack_number: seg.ack_number().0 as u32,
        payload: seg.payload().to_vec(),
    })
}

/// What a UDP datagram carried.
#[derive(Debug)]
struct Udp {
    dst_port: u16,
    payload: Vec<u8>,
}

fn udp_of(packet: &[u8]) -> Option<Udp> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let datagram = UdpPacket::new_checked(ip.payload()).ok()?;
    Some(Udp {
        dst_port: datagram.dst_port(),
        payload: datagram.payload().to_vec(),
    })
}

// =====================================================================
// what the datapath costs
// =====================================================================
//
// These measure the userspace datapath itself: the `Translator` above drives
// a `UserspaceHandle` directly, through the same admission seam production
// uses, so what is timed is admission plus the stack plus the host sockets
// and nothing else. Driving the `mvm-netd` process instead would fold the
// guest channel's framing and a UDS round trip into every number, which
// measures the tunnel rather than the thing this decides about.
//
// Every one is `#[ignore]`d. They run for seconds, they are timing-sensitive
// by construction, and a benchmark that can go red on a loaded CI box trains
// people to ignore red. Run them deliberately, on a quiet host:
//
//   cargo test --release -p mvm-hostd --test userspace_datapath \
//       -- --ignored --nocapture --test-threads 1
//
// `--release` because a timing figure from an unoptimized build measures the
// optimizer's absence, and `--test-threads 1` because two benchmarks sharing
// the host's cores measure each other.

/// Payload on a bulk guest segment. A full MTU-sized segment, so a
/// throughput figure is dominated by bytes moved rather than by per-packet
/// framing.
const BENCH_SEGMENT: usize = 1_400;

/// Bytes moved per measurement, summed across every flow in it. Fixed
/// **aggregate** rather than fixed per-flow, so each point of the
/// concurrency sweep does the same total work and the comparison between
/// them is about scheduling rather than about volume.
const BENCH_TOTAL_BYTES: usize = 16 * 1024 * 1024;

/// Wall-clock ceiling on one bulk measurement. Reached only when something
/// has stalled, in which case the run says so rather than reporting the
/// throughput of a stall.
const BENCH_DEADLINE: Duration = Duration::from_secs(120);

/// How much this fake guest leaves outstanding before waiting for an
/// acknowledgement. Half the datapath's 16 KiB receive buffer: enough to
/// keep the window open, far enough inside it that a sender with no
/// retransmit of its own never has a segment dropped for overrunning it.
const BENCH_WINDOW: u32 = 8 * 1024;

/// Flow counts the concurrency sweep visits. The question these answer is
/// whether one serial service pass is the ceiling, so they span a range
/// wide enough for a flat line to be distinguishable from a rising one.
const BENCH_FLOW_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];

/// One flow's guest-side sequence bookkeeping.
///
/// The datapath terminates the guest's TCP, so something has to hold up the
/// guest's half of the conversation: acknowledge what arrives, and keep a
/// send window open. That is all this is — enough TCP to keep a flow moving,
/// deliberately not a stack.
struct GuestFlow {
    port: u16,
    dst: SocketAddr,
    /// Next sequence number this guest sends from.
    tx_seq: u32,
    /// Highest sequence number the datapath has acknowledged.
    tx_acked: u32,
    /// Next sequence number this guest expects to receive.
    rx_next: u32,
}

impl GuestFlow {
    /// Bytes sent but not yet acknowledged.
    fn outstanding(&self) -> u32 {
        self.tx_seq.wrapping_sub(self.tx_acked)
    }
}

impl Translator {
    /// Open a flow and finish its handshake, returning the bookkeeping that
    /// keeps it moving.
    fn establish_flow(&mut self, cfg: &NetdConfig, dst: SocketAddr, port: u16) -> GuestFlow {
        let isn = self.open_flow(cfg, dst, port);
        self.finish_handshake(cfg, dst, port, isn);
        GuestFlow {
            port,
            dst,
            tx_seq: GUEST_ISN.wrapping_add(1),
            tx_acked: GUEST_ISN.wrapping_add(1),
            rx_next: isn.wrapping_add(1),
        }
    }

    /// Send one guest segment on `flow`, carrying `payload`, and advance the
    /// flow's send sequence past it.
    fn send_on(&mut self, cfg: &NetdConfig, flow: &mut GuestFlow, payload: &[u8], now: u64) {
        self.send(
            &Segment {
                guest: cfg.guest_ipv4,
                guest_port: flow.port,
                dst: flow.dst,
                control: TcpControl::None,
                seq: flow.tx_seq,
                ack: Some(flow.rx_next),
                payload,
            }
            .emit(),
            now,
        );
        flow.tx_seq = flow.tx_seq.wrapping_add(payload.len() as u32);
    }

    /// Take everything the handle is holding, fold it into the flows it
    /// belongs to, and report how many payload bytes arrived.
    ///
    /// A reset here is fatal to the measurement rather than ignorable: a
    /// benchmark that quietly kept timing after its flow died would report
    /// the throughput of an empty loop.
    fn absorb(&mut self, flows: &mut [GuestFlow]) -> usize {
        let mut delivered = 0;
        for packet in self.drain() {
            let Some(seg) = tcp_of(&packet) else { continue };
            let Some(flow) = flows.iter_mut().find(|f| f.port == seg.dst_port) else {
                continue;
            };
            assert!(
                !seg.rst,
                "the datapath reset a flow mid-measurement; the figure that \
                 followed would be the throughput of a dead flow"
            );
            if seg.ack {
                // Sequence arithmetic wraps, so "further along" is a signed
                // difference, never a `>`.
                if (seg.ack_number.wrapping_sub(flow.tx_acked) as i32) > 0 {
                    flow.tx_acked = seg.ack_number;
                }
            }
            if !seg.payload.is_empty() && seg.seq == flow.rx_next {
                flow.rx_next = flow.rx_next.wrapping_add(seg.payload.len() as u32);
                delivered += seg.payload.len();
            }
        }
        delivered
    }

    /// Acknowledge, on every flow, everything received so far.
    fn ack_all(&mut self, cfg: &NetdConfig, flows: &[GuestFlow], now: u64) {
        for flow in flows {
            self.send(
                &Segment {
                    guest: cfg.guest_ipv4,
                    guest_port: flow.port,
                    dst: flow.dst,
                    control: TcpControl::None,
                    seq: flow.tx_seq,
                    ack: Some(flow.rx_next),
                    payload: &[],
                }
                .emit(),
                now,
            );
        }
    }
}

// ---------------------------------------------------------------------
// the host side of a measurement
// ---------------------------------------------------------------------

/// What a host peer does with a connection the datapath re-originates.
#[derive(Clone)]
enum PeerRole {
    /// Write this many bytes, then hold the connection open. Held open on
    /// purpose: a peer that closed would send a FIN, the flow would finish,
    /// and the measurement would be racing the datapath reaping it.
    Source(usize),
    /// Read and count, into a counter the measurement can watch.
    Sink(Arc<AtomicUsize>),
    /// Send every byte straight back, so a round trip has something to
    /// turn around.
    Echo,
}

/// A listener on this host playing one role for every flow that reaches it.
///
/// One helper rather than three: the three roles differ only in what they do
/// with an accepted socket, and a separate listener apiece would be the same
/// accept loop written three times.
struct HostPeer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl HostPeer {
    fn start(host: Ipv4Addr, role: PeerRole) -> Self {
        let listener = TcpListener::bind((host, 0)).expect("bind the admitted destination");
        let addr = listener.local_addr().expect("local addr");
        listener
            .set_nonblocking(true)
            .expect("a stoppable accept loop needs a non-blocking listener");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((peer, _)) => {
                        peer.set_nonblocking(false).ok();
                        let role = role.clone();
                        let flag = Arc::clone(&flag);
                        // Detached: a connection's thread ends when its
                        // socket does, and every socket here dies when the
                        // datapath under measurement is dropped.
                        std::thread::spawn(move || serve_peer(peer, role, &flag));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Self { addr, stop }
    }
}

impl Drop for HostPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// One accepted connection, played out to its role's end.
fn serve_peer(mut peer: TcpStream, role: PeerRole, stop: &AtomicBool) {
    match role {
        PeerRole::Source(total) => {
            let chunk = vec![0x5Au8; 64 * 1024];
            let mut left = total;
            while left > 0 {
                let n = left.min(chunk.len());
                if peer.write_all(&chunk[..n]).is_err() {
                    return;
                }
                left -= n;
            }
            peer.flush().ok();
            // Park rather than return: returning drops the socket, and the
            // FIN that follows would end a flow the measurement is still
            // timing.
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        PeerRole::Sink(count) => {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = peer.read(&mut buf) {
                if n == 0 {
                    break;
                }
                count.fetch_add(n, Ordering::Relaxed);
            }
        }
        PeerRole::Echo => {
            let mut buf = vec![0u8; 8 * 1024];
            while let Ok(n) = peer.read(&mut buf) {
                if n == 0 || peer.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------

/// Report one throughput measurement in a shape that can be compared across
/// runs and across hosts.
fn report_throughput(label: &str, bytes: usize, elapsed: Duration, flows: usize, passes: u64) {
    let mbps = (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1e6;
    let per_pass = bytes as f64 / passes.max(1) as f64;
    let pass_ns = elapsed.as_nanos() as f64 / passes.max(1) as f64;
    println!(
        "{label}: {flows:>2} flow(s)  {mbps:>8.0} Mb/s  \
         {:.1} MiB in {:.3}s  {passes} passes  {per_pass:.0} B/pass  {pass_ns:.0} ns/pass",
        bytes as f64 / (1024.0 * 1024.0),
        elapsed.as_secs_f64()
    );
}

/// Report a latency distribution. Percentiles rather than a mean: the mean
/// of a distribution with a scheduler tail in it describes nothing.
fn report_latency(label: &str, mut samples: Vec<Duration>) {
    assert!(!samples.is_empty(), "{label} produced no samples");
    samples.sort_unstable();
    let at = |q: f64| -> Duration {
        let i = ((samples.len() - 1) as f64 * q).round() as usize;
        samples[i]
    };
    let total: Duration = samples.iter().sum();
    println!(
        "{label}: n={}  mean {:>8.1}us  p50 {:>8.1}us  p90 {:>8.1}us  \
         p99 {:>8.1}us  max {:>8.1}us",
        samples.len(),
        total.as_secs_f64() * 1e6 / samples.len() as f64,
        at(0.50).as_secs_f64() * 1e6,
        at(0.90).as_secs_f64() * 1e6,
        at(0.99).as_secs_f64() * 1e6,
        samples[samples.len() - 1].as_secs_f64() * 1e6,
    );
}

/// Milliseconds since a measurement began, for the datapath's caller-supplied
/// clock.
fn clock(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

// ---------------------------------------------------------------------
// throughput
// ---------------------------------------------------------------------

/// Bulk host→guest on one flow: the direction where the datapath does the
/// reading, and the one a workload pulling an image or a dataset lives on.
#[test]
#[ignore = "a benchmark: run deliberately on a quiet host, see this section's header"]
fn measure_throughput_host_to_guest() {
    let Some(host) = host_target() else { return };
    let (bytes, elapsed, passes) = host_to_guest_run(host, 1);
    report_throughput("host→guest", bytes, elapsed, 1, passes);
}

/// Bulk guest→host on one flow: the direction where the guest's segments
/// are the input, so admission runs on every one of them.
#[test]
#[ignore = "a benchmark: run deliberately on a quiet host, see this section's header"]
fn measure_throughput_guest_to_host() {
    let Some(host) = host_target() else { return };
    let counted = Arc::new(AtomicUsize::new(0));
    let peer = HostPeer::start(host, PeerRole::Sink(Arc::clone(&counted)));
    let cfg = config("netd-bench-g2h", &[tcp_rule(host, peer.addr.port())], &[]);
    let mut tr = Translator::open(&cfg);
    let mut flow = tr.establish_flow(&cfg, peer.addr, GUEST_PORT);

    let payload = vec![0xA5u8; BENCH_SEGMENT];
    let start = Instant::now();
    let mut passes = 0u64;
    let mut sent = 0usize;
    // Measured at the receiving socket, not at the send call: bytes handed
    // to the stack that never left it are not throughput.
    while counted.load(Ordering::Relaxed) < BENCH_TOTAL_BYTES {
        assert!(
            start.elapsed() < BENCH_DEADLINE,
            "guest→host stalled at {} of {BENCH_TOTAL_BYTES} bytes",
            counted.load(Ordering::Relaxed)
        );
        let now = clock(start);
        // Keep the window open, never overrun it: this guest has no
        // retransmit, so a dropped segment would wedge the flow rather than
        // cost it a round trip.
        while flow.outstanding() < BENCH_WINDOW && sent < BENCH_TOTAL_BYTES {
            tr.send_on(&cfg, &mut flow, &payload, now);
            sent += payload.len();
        }
        tr.service(now);
        passes += 1;
        tr.absorb(std::slice::from_mut(&mut flow));
    }
    let elapsed = start.elapsed();
    let moved = counted.load(Ordering::Relaxed);
    drop(tr);
    drop(peer);
    report_throughput("guest→host", moved, elapsed, 1, passes);
}

// ---------------------------------------------------------------------
// the measurement multi-queue turns on
// ---------------------------------------------------------------------

/// Aggregate throughput against flow count, at a fixed total byte budget.
///
/// This is the one that speaks to multi-queue. `service()` pumps every flow
/// on a machine in one serial pass, so if that pass is the ceiling the
/// aggregate is flat across this sweep and splitting the flows across queues
/// is the thing that would move it. If the aggregate rises with flow count,
/// the serial pass is not what is limiting and a second queue would buy
/// nothing.
///
/// Fixed *aggregate* budget, so every point does identical total work and
/// the only variable is how many flows it is spread over.
#[test]
#[ignore = "a benchmark: run deliberately on a quiet host, see this section's header"]
fn measure_concurrency_scaling() {
    let Some(host) = host_target() else { return };
    println!("aggregate host→guest throughput against flow count:");
    for flows in BENCH_FLOW_COUNTS {
        let (bytes, elapsed, passes) = host_to_guest_run(host, flows);
        report_throughput("  scaling", bytes, elapsed, flows, passes);
    }
}

/// Move `BENCH_TOTAL_BYTES` host→guest, split evenly across `flows` flows.
///
/// Returns what actually arrived, how long it took, and how many service
/// passes carried it — the last because bytes-per-pass is what separates a
/// datapath limited by its per-pass bound from one limited by anything else.
fn host_to_guest_run(host: Ipv4Addr, flows: usize) -> (usize, Duration, u64) {
    let per_flow = BENCH_TOTAL_BYTES / flows;
    let peer = HostPeer::start(host, PeerRole::Source(per_flow));
    let cfg = config(
        &format!("netd-bench-h2g-{flows}"),
        &[tcp_rule(host, peer.addr.port())],
        &[],
    );
    let mut tr = Translator::open(&cfg);
    let mut open: Vec<GuestFlow> = (0..flows)
        .map(|i| tr.establish_flow(&cfg, peer.addr, GUEST_PORT + i as u16))
        .collect();

    let want = per_flow * flows;
    let start = Instant::now();
    let mut got = 0usize;
    let mut passes = 0u64;
    while got < want {
        assert!(
            start.elapsed() < BENCH_DEADLINE,
            "host→guest stalled at {got} of {want} bytes across {flows} flow(s)"
        );
        let now = clock(start);
        tr.service(now);
        passes += 1;
        got += tr.absorb(&mut open);
        // The datapath's window only reopens when the guest acknowledges, so
        // this is part of the path being measured rather than bookkeeping
        // beside it.
        tr.ack_all(&cfg, &open, now);
    }
    let elapsed = start.elapsed();
    drop(tr);
    drop(peer);
    (got, elapsed, passes)
}

// ---------------------------------------------------------------------
// latency
// ---------------------------------------------------------------------

/// Connect-to-established: a guest's SYN to the SYN-ACK the datapath only
/// sends once a real host socket has connected.
///
/// This is the cost the deferred handshake buys its correctness with, so it
/// is the one worth knowing.
#[test]
#[ignore = "a benchmark: run deliberately on a quiet host, see this section's header"]
fn measure_connect_latency() {
    let Some(host) = host_target() else { return };
    const SAMPLES: usize = 30;
    let peer = HostPeer::start(host, PeerRole::Echo);
    let cfg = config(
        "netd-bench-connect",
        &[tcp_rule(host, peer.addr.port())],
        &[],
    );
    let mut tr = Translator::open(&cfg);

    let mut samples = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let began = Instant::now();
        // Spins rather than pausing: a 2ms sleep between passes would be
        // most of what this reported.
        tr.open_flow_paced(&cfg, peer.addr, GUEST_PORT + i as u16, Duration::ZERO);
        samples.push(began.elapsed());
    }
    drop(tr);
    drop(peer);
    report_latency("connect→established", samples);
}

/// Round trip on an established flow: a guest segment out, the echoed bytes
/// back. Everything the datapath does per exchange, with no bulk buffering
/// to hide behind.
#[test]
#[ignore = "a benchmark: run deliberately on a quiet host, see this section's header"]
fn measure_round_trip_latency() {
    let Some(host) = host_target() else { return };
    const SAMPLES: usize = 300;
    const PROBE: usize = 64;
    let peer = HostPeer::start(host, PeerRole::Echo);
    let cfg = config("netd-bench-rtt", &[tcp_rule(host, peer.addr.port())], &[]);
    let mut tr = Translator::open(&cfg);
    let mut flow = tr.establish_flow(&cfg, peer.addr, GUEST_PORT);
    let probe = vec![0x3Cu8; PROBE];

    let start = Instant::now();
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let began = Instant::now();
        tr.send_on(&cfg, &mut flow, &probe, clock(start));
        let mut back = 0usize;
        while back < PROBE {
            assert!(
                began.elapsed() < Duration::from_secs(10),
                "an echoed probe never came back; the flow is not moving"
            );
            tr.service(clock(start));
            back += tr.absorb(std::slice::from_mut(&mut flow));
        }
        samples.push(began.elapsed());
    }
    drop(tr);
    drop(peer);
    report_latency("guest→host→guest round trip", samples);
}

// ---------------------------------------------------------------------
// where the time goes
// ---------------------------------------------------------------------

/// The cost of a service pass that has nothing to carry, against the number
/// of established-but-quiet flows it walks.
///
/// This is the coarse decomposition: the value at zero flows is what one
/// pass costs the machine no matter what — readiness drain, the expiry
/// sweeps, the interface poll — and the slope is what each additional flow
/// adds to every pass whether or not it has bytes. Together they say how
/// much of a loaded pass is fixed overhead and how much is per-flow work,
/// which is what decides whether splitting flows across queues could help.
#[test]
#[ignore = "a benchmark: run deliberately on a quiet host, see this section's header"]
fn measure_idle_service_pass_cost() {
    let Some(host) = host_target() else { return };
    const PASSES: usize = 20_000;

    // Isolated first, so the fixed cost below is attributed rather than
    // guessed at. Every pass drains the readiness set exactly once, and on a
    // pass whose tables are empty that non-blocking wait is the only syscall
    // the pass is obliged to make.
    let mut bare = ReadinessSet::new().expect("a poll set needs no privileges");
    let start = Instant::now();
    for _ in 0..PASSES {
        std::hint::black_box(bare.drain());
    }
    println!(
        "bare readiness drain, nothing registered: {:>7.0} ns/call",
        start.elapsed().as_nanos() as f64 / PASSES as f64
    );

    println!("cost of one service pass carrying nothing:");
    for flows in [0usize, 1, 4, 16] {
        let peer = HostPeer::start(host, PeerRole::Echo);
        let cfg = config(
            &format!("netd-bench-idle-{flows}"),
            &[tcp_rule(host, peer.addr.port())],
            &[],
        );
        let mut tr = Translator::open(&cfg);
        let mut open: Vec<GuestFlow> = (0..flows)
            .map(|i| tr.establish_flow(&cfg, peer.addr, GUEST_PORT + i as u16))
            .collect();
        // Settle first, so nothing left over from the handshakes is counted
        // against the idle pass.
        for _ in 0..50 {
            tr.service(0);
            tr.absorb(&mut open);
        }

        let start = Instant::now();
        for _ in 0..PASSES {
            tr.service(clock(start));
        }
        let elapsed = start.elapsed();
        drop(tr);
        drop(peer);
        println!(
            "  idle pass: {flows:>2} flow(s)  {:>7.0} ns/pass  ({PASSES} passes in {:.3}s)",
            elapsed.as_nanos() as f64 / PASSES as f64,
            elapsed.as_secs_f64()
        );
    }
}
