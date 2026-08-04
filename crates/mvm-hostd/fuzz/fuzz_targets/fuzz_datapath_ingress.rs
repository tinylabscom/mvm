// Fuzz the userspace socket datapath's guest-facing ingress.
//
// These are the bytes a guest puts on the vsock channel. They reach three
// pieces of real code in order, and this target drives all three rather
// than a stand-in for any of them:
//
//   1. `L3Admitter::admit_outbound` — the first parse, and the only thing
//      that can mint the `AdmittedPacket` a datapath will accept. Runs on
//      the frame exactly as the fuzzer produced it, IPv4 and IPv6 alike.
//   2. `UserspaceHandle::send_to_network` — the datapath's own re-read of
//      an admitted packet (`udp_payload`, `tcp_flags`), the host-socket
//      budget, and the connect it starts. Fed a normalized copy, because
//      a packet that fails anti-spoofing never gets this far.
//   3. `EstablishedFlow::deliver_from_guest` + `pump` — the per-flow
//      smoltcp stack that terminates the guest's TCP. This is the only
//      place guest bytes reach `Interface::poll`.
//
// Harness goal, as everywhere else in this repo: never panic on any input.
// Garbage must fail closed to a deny, a drop, or an `Err` — never an abort,
// and never an unwrap on a guest-written length or an index derived from
// one. IPv6 matters even though admission refuses it: `ip::parse` walks the
// extension chain before the version check refuses the packet, so the
// bounded walk is reachable with a chain an attacker chose.
//
// Both host sockets this target opens are listeners it created on this
// machine, so nothing it connects to is anything it does not own.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Mutex, OnceLock, PoisonError};

use libfuzzer_sys::fuzz_target;
use mvm_core::policy::projection::CanonicalEgress;
use mvm_hostd::netd::userspace::UserspaceSocketDatapath;
use mvm_hostd::netd::userspace::readiness::ReadinessSet;
use mvm_hostd::netd::userspace::tcp::{EstablishedFlow, HalfOpenTable};
use mvm_hostd::netd::{DatapathHandle, DatapathRequest, GatewayMetrics};
use mvm_net::l3::alloc::AddressLease;
use mvm_net::l3::{
    DnsBindingStore, DnsLimits, FlowKey, FlowLimits, FlowTable, IngressTable, L3Admitter,
    L3PolicyConfig, OutboundVerdict,
};
use mvm_protocol::l3::limits::MTU_V1;
use mvm_protocol::l3::{ip, proto};

/// Frames per input. A datapath is stateful — one packet can open a flow
/// but never also send on it — so an exec has to be a short sequence. The
/// cap keeps a single input from turning into an unbounded run.
const MAX_FRAMES: usize = 24;

/// Half-open entries the flow leg will hold at once. Each one parks a host
/// descriptor for the length of an exec, so this is deliberately far below
/// what the datapath itself allows.
const HALF_OPEN_CAPACITY: usize = 4;

/// Accepted connections the sinks keep alive. Held rather than dropped so a
/// flow stays established long enough to carry the frames that follow its
/// SYN; bounded so a long run cannot accumulate descriptors.
const MAX_HELD: usize = 64;

/// The /30 the fuzzed session leases. Any address works — it only has to be
/// the one anti-spoofing compares against.
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);

fuzz_target!(|data: &[u8]| {
    let mut admitter = admitter();
    let mut metrics = GatewayMetrics::default();
    let mut handle = open_handle();
    // The sockets a half-open entry parks register here. Nothing polls it:
    // this harness drives the table directly, and what the entries need is
    // somewhere to register and unregister.
    let Ok(readiness) = ReadinessSet::new() else {
        return;
    };
    let mut half_open = HalfOpenTable::new(HALF_OPEN_CAPACITY, IpAddr::V4(GUEST), readiness.watch());
    let mut flow: Option<EstablishedFlow> = None;
    let mut now: u64 = 0;

    for frame in frames(data) {
        // Guest-chosen, so the harness lets the fuzzer choose it: a run
        // that only ever advances a millisecond never reaches an expiry.
        now = now.saturating_add(1 + u64::from(frame.first().copied().unwrap_or(0)) * 64);

        // 1. Admission, on the bytes as sent. Both directions: an inbound
        // packet is host-network input, which is no more trusted.
        let _ = admitter.admit_outbound(frame, now);
        let _ = admitter.admit_inbound(frame, now);

        // The datapath's own re-read of a packet admission passed. Reached
        // through `send_to_network` below too, but only for frames that
        // survive normalization; called here so every frame exercises it.
        if let Ok(meta) = ip::parse(frame) {
            let _ = ip::udp_payload(frame, &meta);
            if let Some(flags) = ip::tcp_flags(frame, &meta) {
                let _ = meta.is_tcp_syn_only(flags);
            }
            let _ = ip::tcp_sequence(frame, &meta);
        }

        // 2. The datapath proper, for frames a real guest could have sent.
        if let (Some(handle), Some(sink)) = (handle.as_mut(), routable_sink())
            && let Some(packet) = normalized(frame, sink)
            && let OutboundVerdict::Forward(admitted) = admitter.admit_outbound(&packet, now)
        {
            let _ = handle.send_to_network(&admitted);
        }
        if let Some(handle) = handle.as_mut() {
            let _ = handle.service(now);
            let mut buf = [0u8; MTU_V1 as usize];
            while handle.recv_from_network(&mut buf).is_ok() {}
        }

        // 3. The flow's stack, on the bytes as sent. Its own table rather
        // than the handle's, because a frame reaches a flow only after
        // admission accepted it and nothing the fuzzer writes will be
        // admitted twice in a row to the same key — and because this is
        // where an IPv6 frame can reach smoltcp, which parses a hop-by-hop
        // chain before it checks any address.
        if let Some(sink) = loopback_sink() {
            if flow.is_none() && half_open.is_empty() {
                let key = FlowKey {
                    protocol: proto::TCP,
                    guest_port: guest_port(frame),
                    remote: sink.ip(),
                    remote_port: sink.port(),
                };
                let _ = half_open.on_syn(key, frame.to_vec(), sink, now);
            }
            let resolved = half_open.resolve(&mut metrics);
            for entry in resolved.established {
                if flow.is_none()
                    && let Ok(opened) = EstablishedFlow::from_half_open(
                        entry,
                        IpAddr::V4(GUEST),
                        MTU_V1 as usize,
                        now,
                    )
                {
                    flow = Some(opened);
                }
            }
        }
        if let Some(flow) = flow.as_mut() {
            let _ = flow.deliver_from_guest(frame);
            let _ = flow.pump(now, &mut metrics);
            let _ = flow.take_guest_packets();
        }
    }
});

/// Split the input into packets.
///
/// A two-byte length then that many bytes, so the fuzzer controls both the
/// packet boundaries and the disagreement between a declared length and the
/// bytes actually present — which is the bug class this target is looking
/// for one layer up.
fn frames(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 && out.len() < MAX_FRAMES {
        let declared = usize::from(u16::from_le_bytes([data[0], data[1]]));
        data = &data[2..];
        let (frame, rest) = data.split_at(declared.min(data.len()));
        out.push(frame);
        data = rest;
    }
    out
}

/// A session whose policy admits everything the address-class checks do not
/// refuse outright.
///
/// Deliberately the most permissive rule set that exists, so the fuzzer
/// spends its time past the policy gate rather than bouncing off it. The
/// class refusals — loopback, link-local, multicast, reserved, mandatory
/// deny — are not configurable and still apply.
fn admitter() -> L3Admitter {
    let config = L3PolicyConfig {
        egress: CanonicalEgress::Unrestricted,
        admitted_private: private_ranges(),
        ..L3PolicyConfig::default()
    };
    let mut admitter = L3Admitter::new(
        AddressLease::for_test(GATEWAY, GUEST),
        config,
        FlowTable::new(FlowLimits::default()),
        DnsBindingStore::new(DnsLimits::default(), private_ranges()),
        IngressTable::default(),
    );
    // Otherwise every packet stops at the handshake gate and nothing below
    // it is ever reached.
    admitter.set_ready(true);
    admitter
}

/// The private ranges this session opens.
///
/// Exactly the sink's own address, read off the listener the harness bound
/// rather than written down. The sink is an address of this host, which on
/// most machines is RFC1918, and a private destination that no rule admits
/// is refused by class before any of the datapath is reached.
fn private_ranges() -> Vec<ipnet::IpNet> {
    routable_sink()
        .and_then(|sink| ipnet::IpNet::new(sink.ip(), 32).ok())
        .into_iter()
        .collect()
}

/// An open datapath for the fuzzed machine, or `None` if this environment
/// cannot give it one.
fn open_handle() -> Option<mvm_hostd::netd::userspace::UserspaceHandle> {
    UserspaceSocketDatapath::new()
        .open_handle(&DatapathRequest {
            machine_id: "fuzz".to_string(),
            gateway: GATEWAY,
            guest: GUEST,
            prefix_len: 30,
            mtu: MTU_V1,
            ingress: Vec::new(),
        })
        .ok()
}

/// Rewrite a frame into one a real guest on this session could have sent.
///
/// Source and destination are pinned because admission refuses anything
/// else: a spoofed source never reaches a datapath, so a fuzzer that only
/// ever sent spoofed sources would be fuzzing the deny branch. Everything
/// else the parsers read — header length, options, declared lengths, flags,
/// sequence numbers, payload — is left exactly as the fuzzer wrote it.
///
/// Checksums are repaired for the same reason: smoltcp verifies them on
/// ingress, so an unrepaired frame stops at that branch instead of reaching
/// the stack. IPv6 frames are not normalized at all — their target is the
/// bounded extension walk, which runs before any checksum.
fn normalized(frame: &[u8], sink: SocketAddr) -> Option<Vec<u8>> {
    let SocketAddr::V4(sink) = sink else {
        return None;
    };
    let meta = ip::parse(frame).ok()?;
    if meta.version != 4 || meta.fragment {
        return None;
    }
    if !matches!(meta.protocol, proto::TCP | proto::UDP) {
        return None;
    }
    let ihl = usize::from(frame[0] & 0x0f) * 4;
    let mut packet = frame[..meta.total_len].to_vec();
    packet.get_mut(12..16)?.copy_from_slice(&GUEST.octets());
    packet.get_mut(16..20)?.copy_from_slice(&sink.ip().octets());
    packet
        .get_mut(ihl + 2..ihl + 4)?
        .copy_from_slice(&sink.port().to_be_bytes());
    repair_checksums(&mut packet, ihl, meta.protocol)?;
    Some(packet)
}

/// Recompute the IPv4 header checksum and the transport checksum in place.
fn repair_checksums(packet: &mut [u8], ihl: usize, protocol: u8) -> Option<()> {
    packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
    let header = checksum(packet.get(..ihl)?, 0);
    packet
        .get_mut(10..12)?
        .copy_from_slice(&header.to_be_bytes());

    let field = if protocol == proto::TCP { 16 } else { 6 };
    let transport_len = packet.len().checked_sub(ihl)?;
    packet.get_mut(ihl + field..ihl + field + 2)?.fill(0);
    // The pseudo-header: addresses, protocol, transport length.
    let mut pseudo = [0u8; 12];
    pseudo[..8].copy_from_slice(packet.get(12..20)?);
    pseudo[9] = protocol;
    pseudo[10..].copy_from_slice(&u16::try_from(transport_len).ok()?.to_be_bytes());
    let seed = partial_sum(&pseudo, 0);
    let sum = checksum(packet.get(ihl..)?, seed);
    // A zero UDP checksum means "not computed", so the all-ones form is
    // the one a sender transmits.
    let sum = if sum == 0 && protocol == proto::UDP {
        0xffff
    } else {
        sum
    };
    packet
        .get_mut(ihl + field..ihl + field + 2)?
        .copy_from_slice(&sum.to_be_bytes());
    Some(())
}

fn checksum(bytes: &[u8], seed: u32) -> u16 {
    !fold(partial_sum(bytes, seed))
}

fn partial_sum(bytes: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // The high half is zero once the loop ends.
    sum as u16
}

/// A guest source port for the flow leg, taken from the frame so distinct
/// inputs open distinct flows rather than folding into one key.
fn guest_port(frame: &[u8]) -> u16 {
    let hi = frame.first().copied().unwrap_or(1);
    let lo = frame.get(1).copied().unwrap_or(1);
    u16::from_be_bytes([hi, lo]) | 1
}

/// The sink the flow leg connects to. Loopback, because that leg builds its
/// half-open entries directly and never asks admission, which refuses a
/// loopback destination outright.
fn loopback_sink() -> Option<SocketAddr> {
    static SINK: OnceLock<Option<SocketAddr>> = OnceLock::new();
    *SINK.get_or_init(|| listen(IpAddr::V4(Ipv4Addr::LOCALHOST)))
}

/// The sink the datapath leg connects to.
///
/// This host's own routable address, discovered rather than configured. It
/// has to be one admission will accept, which rules out loopback; a locally
/// bound address keeps the connection on this machine anyway, so the fuzzer
/// still opens nothing it does not own. `None` on a host with no such
/// address — the datapath leg then exercises admission and its own service
/// pass, and opens no socket.
fn routable_sink() -> Option<SocketAddr> {
    static SINK: OnceLock<Option<SocketAddr>> = OnceLock::new();
    *SINK.get_or_init(|| listen(host_address()?))
}

fn listen(addr: IpAddr) -> Option<SocketAddr> {
    static HELD: Mutex<Vec<TcpStream>> = Mutex::new(Vec::new());
    let listener = TcpListener::bind(SocketAddr::new(addr, 0)).ok()?;
    let bound = listener.local_addr().ok()?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
            if held.len() >= MAX_HELD {
                held.remove(0);
            }
            held.push(stream);
        }
    });
    Some(bound)
}

/// The address this host answers on.
///
/// A connected UDP socket transmits nothing; the kernel just picks the
/// source address it would route from, which is the answer. The probe
/// destination is a documentation prefix precisely because nothing is
/// there and nothing is sent to it.
fn host_address() -> Option<IpAddr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect((Ipv4Addr::new(198, 51, 100, 1), 9)).ok()?;
    let local = probe.local_addr().ok()?.ip();
    (!local.is_loopback() && !local.is_unspecified()).then_some(local)
}
