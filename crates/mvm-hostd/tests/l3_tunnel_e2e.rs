//! End-to-end tests for the L3 TUN-over-vsock tunnel, unprivileged.
//!
//! The real guest agent, the real wire protocol, the real policy core, and
//! the real host gateway, joined by an in-memory guest channel and an
//! in-memory forwarding backend. Only the two platform edges are
//! substituted: the TUN device and the host datapath.
//!
//! That substitution is what makes these run in ordinary CI, and it is also
//! why they are worth having: everything between the guest's TUN fd and the
//! host's forwarding call is exercised exactly as it ships.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use mvm_agentd::l3::{
    AgentState, MemoryTun, NetAgent, RecordingConfigurator, RecordingPrivilegeDropper,
};
use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_hostd::netd::{Gateway, GatewayConfig, GatewayEvent, LoopbackDatapath, StaticResolver};
use mvm_net::channel::{GuestService, VmInstanceIdentity};
use mvm_net::l3::{
    AddressAllocator, AddressLease, DenyCode, IngressMapping, L3PolicyConfig, SessionId,
};
use mvm_protocol::l3::{MessageType, frame, ip, proto};

const REMOTE: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
/// A routable public address the policy does not admit. Deliberately not a
/// documentation or benchmarking range: those are refused by the
/// address-class check before the allow-list is consulted, which would test
/// the wrong thing.
const DENIED: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

// ---------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------

/// One machine's guest and host halves, wired together.
struct Tunnel {
    agent: NetAgent<MemoryTun, RecordingConfigurator>,
    gateway: Gateway,
    /// Bytes the agent has written to the data channel and the gateway has
    /// not yet consumed.
    guest_to_host: Vec<u8>,
    now: u64,
}

fn lease_for(allocator: &mut AddressAllocator) -> AddressLease {
    allocator.allocate().expect("pool has room")
}

fn rule(net: &str, port: u16) -> CanonicalRule {
    CanonicalRule {
        proto: Proto::Tcp,
        net: net.parse().unwrap(),
        port_lo: port,
        port_hi: port,
    }
}

/// A policy admitting TCP/443 to the example address and nothing else.
fn allow_443() -> L3PolicyConfig {
    L3PolicyConfig {
        egress: CanonicalEgress::Rules(vec![rule("93.184.216.34/32", 443)]),
        ..L3PolicyConfig::default()
    }
}

impl Tunnel {
    /// Bring up a tunnel through the full handshake.
    fn up(
        machine_id: &str,
        boot_id: &str,
        session: SessionId,
        lease: AddressLease,
        policy: L3PolicyConfig,
        datapath: &LoopbackDatapath,
        ingress: Option<IngressMapping>,
    ) -> Self {
        let resolver =
            Arc::new(StaticResolver::new().with("api.example.com", &[IpAddr::V4(REMOTE)], 60));
        let mut config = GatewayConfig::new(machine_id, "sha256:plan", lease, policy);
        config.instance = VmInstanceIdentity::new("node-1", machine_id, boot_id, "sha256:plan");
        if let Some(mapping) = ingress {
            config.ingress.declare(mapping).expect("declare ingress");
        }
        let mut gateway = Gateway::open(config, session, datapath, resolver).expect("open gateway");
        // The real drop is a process-global, one-way side effect; a test
        // that performed it would disarm the rest of the run.
        let mut agent = NetAgent::new(MemoryTun::new("mvm0"), RecordingConfigurator::default())
            .with_privilege_dropper(Box::new(RecordingPrivilegeDropper::default()));

        // The handshake, over the control channel, byte for byte.
        let mut control = ControlChannel::default();
        agent_send_hello(&mut agent, &mut control, &mut gateway);

        Self {
            agent,
            gateway,
            guest_to_host: Vec::new(),
            now: 10,
        }
    }

    /// Push a packet onto the guest's TUN and carry it all the way through.
    fn guest_sends(&mut self, packet: Vec<u8>) -> Vec<GatewayEvent> {
        self.agent.tun_mut().push_outbound(packet);
        self.agent
            .pump_tun_to_transport(&mut self.guest_to_host)
            .expect("pump");
        let bytes = std::mem::take(&mut self.guest_to_host);
        self.now += 1;
        let events = self
            .gateway
            .ingest_data_bytes(&bytes, self.now)
            .expect("gateway ingest");
        // Anything the gateway queued for the guest goes back down.
        self.drain_to_guest();
        events
    }

    /// Move host-network traffic through inbound admission and into the
    /// guest.
    fn poll_host(&mut self) -> Vec<GatewayEvent> {
        self.now += 1;
        let events = self.gateway.poll_inbound(self.now).events;
        self.drain_to_guest();
        events
    }

    fn drain_to_guest(&mut self) {
        for framed in self.gateway.take_guest_frames() {
            self.agent
                .ingest_transport_bytes(&framed)
                .expect("agent ingest");
        }
    }

    /// Packets the guest's stack actually received.
    fn guest_received(&mut self) -> Vec<Vec<u8>> {
        self.agent.tun_mut().take_delivered()
    }

    fn guest_addr(&self) -> Ipv4Addr {
        self.gateway.admitter().lease().guest
    }

    fn gateway_addr(&self) -> Ipv4Addr {
        self.gateway.admitter().lease().gateway
    }
}

/// The control channel as a plain byte buffer pair — the handshake is
/// synchronous and one message at a time.
#[derive(Default)]
struct ControlChannel {
    to_guest: std::io::Cursor<Vec<u8>>,
    from_guest: Vec<u8>,
}

impl std::io::Read for ControlChannel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.to_guest, buf)
    }
}

impl std::io::Write for ControlChannel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.from_guest.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run HELLO → CONFIG → READY between a real agent and a real gateway.
fn agent_send_hello(
    agent: &mut NetAgent<MemoryTun, RecordingConfigurator>,
    control: &mut ControlChannel,
    gateway: &mut Gateway,
) {
    // The agent writes HELLO and blocks on CONFIG, so the gateway's reply
    // has to be staged before the handshake call.
    let hello = frame::encode(
        MessageType::Hello,
        0,
        0,
        &mvm_protocol::l3::Hello::v1().encode(),
    )
    .unwrap();
    let (config_frame, _) = gateway
        .handle_control_frame(&hello, 0)
        .expect("gateway handles hello");
    control.to_guest = std::io::Cursor::new(config_frame);

    agent.handshake(control).expect("agent handshake");
    assert_eq!(agent.state(), AgentState::Ready);

    // The agent's READY is the last thing it wrote.
    let ready = last_frame(&control.from_guest);
    let (_, events) = gateway
        .handle_control_frame(&ready, 1)
        .expect("gateway handles ready");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::TunnelReady { .. })),
        "{events:?}"
    );
}

fn last_frame(buf: &[u8]) -> Vec<u8> {
    let mut rest = buf;
    let mut last = Vec::new();
    while let Ok(parsed) = frame::decode(rest) {
        last = rest[..parsed.consumed].to_vec();
        rest = &rest[parsed.consumed..];
    }
    last
}

// ---------------------------------------------------------------------
// packet builders
// ---------------------------------------------------------------------

fn v4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = protocol;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&src_port.to_be_bytes());
    t[2..4].copy_from_slice(&dst_port.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t
}

fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&src_port.to_be_bytes());
    u[2..4].copy_from_slice(&dst_port.to_be_bytes());
    u[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(payload);
    u
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x4242u16.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg
}

/// A datapath that swaps addresses and ports, standing in for a peer that
/// answers.
fn echoing_datapath() -> LoopbackDatapath {
    LoopbackDatapath::new(|pkt| {
        if pkt.len() < 28 {
            return None;
        }
        let mut reply = pkt.to_vec();
        let (src, dst) = (reply[12..16].to_vec(), reply[16..20].to_vec());
        reply[12..16].copy_from_slice(&dst);
        reply[16..20].copy_from_slice(&src);
        let (sp, dp) = (reply[20..22].to_vec(), reply[22..24].to_vec());
        reply[20..22].copy_from_slice(&dp);
        reply[22..24].copy_from_slice(&sp);
        Some(reply)
    })
}

fn single_tunnel(policy: L3PolicyConfig, datapath: &LoopbackDatapath) -> Tunnel {
    let mut allocator = AddressAllocator::with_defaults();
    Tunnel::up(
        "vm-a",
        "boot-1",
        SessionId(0xAAAA_BBBB_CCCC_DDDD),
        lease_for(&mut allocator),
        policy,
        datapath,
        None,
    )
}

// ---------------------------------------------------------------------
// 1. a guest TCP flow reaches an allowed destination
// ---------------------------------------------------------------------

#[test]
fn guest_tcp_traffic_reaches_an_allowed_host_through_the_whole_stack() {
    let dp = echoing_datapath();
    let mut t = single_tunnel(allow_443(), &dp);
    let guest = t.guest_addr();

    let events = t.guest_sends(v4(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN)));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::FlowAdmitted { dst_port: 443, .. })),
        "{events:?}"
    );

    // The peer's reply comes back through inbound admission into the guest.
    let events = t.poll_host();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::InboundDelivered { .. })),
        "{events:?}"
    );
    let received = t.guest_received();
    assert_eq!(received.len(), 1);
    let parsed = ip::parse(&received[0]).expect("the guest received a well-formed packet");
    assert_eq!(parsed.src, IpAddr::V4(REMOTE));
    assert_eq!(parsed.dst, IpAddr::V4(guest));
    assert_eq!(parsed.dst_port, Some(50000));
}

// ---------------------------------------------------------------------
// 2. denied destination and denied port
// ---------------------------------------------------------------------

#[test]
fn the_same_guest_cannot_reach_a_denied_destination_or_port() {
    let dp = echoing_datapath();
    let mut t = single_tunnel(allow_443(), &dp);
    let guest = t.guest_addr();

    let events = t.guest_sends(v4(proto::TCP, guest, DENIED, &tcp(50000, 443, ip::TCP_SYN)));
    assert!(
        events.iter().any(|e| matches!(
            e,
            GatewayEvent::FlowDenied {
                reason: DenyCode::DestinationNotAdmitted,
                ..
            }
        )),
        "{events:?}"
    );

    let events = t.guest_sends(v4(
        proto::TCP,
        guest,
        REMOTE,
        &tcp(50000, 8080, ip::TCP_SYN),
    ));
    assert!(
        events.iter().any(|e| matches!(
            e,
            GatewayEvent::FlowDenied {
                reason: DenyCode::PortNotAdmitted,
                ..
            }
        )),
        "{events:?}"
    );

    assert!(
        t.guest_received().is_empty(),
        "a refused packet must produce nothing for the guest"
    );
}

// ---------------------------------------------------------------------
// 3. UDP DNS, and a UDP application flow
// ---------------------------------------------------------------------

#[test]
fn dns_is_answered_by_the_gateway_and_opens_the_name_it_admitted() {
    let dp = echoing_datapath();
    // Deny-all static rules: only a DNS binding can open a path.
    let mut t = single_tunnel(L3PolicyConfig::default(), &dp);
    let guest = t.guest_addr();
    let gateway = t.gateway_addr();

    let query = udp(40000, 53, &dns_query("api.example.com"));
    let events = t.guest_sends(v4(proto::UDP, guest, gateway, &query));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::DnsAdmitted { answers: 1, .. })),
        "{events:?}"
    );

    // The answer arrived at the guest, from the synthetic resolver.
    let answers = t.guest_received();
    assert_eq!(answers.len(), 1, "the guest must receive a DNS reply");
    let parsed = ip::parse(&answers[0]).unwrap();
    assert_eq!(parsed.src, IpAddr::V4(gateway));
    assert_eq!(parsed.src_port, Some(53));
    assert_eq!(parsed.dst_port, Some(40000));

    // And the address it returned is now reachable.
    let events = t.guest_sends(v4(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN)));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::FlowAdmitted { .. })),
        "{events:?}"
    );
}

#[test]
fn a_udp_application_flow_works_and_its_reply_returns() {
    let dp = echoing_datapath();
    let policy = L3PolicyConfig {
        egress: CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Udp,
            net: "93.184.216.34/32".parse().unwrap(),
            port_lo: 9999,
            port_hi: 9999,
        }]),
        ..L3PolicyConfig::default()
    };
    let mut t = single_tunnel(policy, &dp);
    let guest = t.guest_addr();

    let events = t.guest_sends(v4(proto::UDP, guest, REMOTE, &udp(40000, 9999, b"ping")));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::FlowAdmitted { .. })),
        "{events:?}"
    );
    t.poll_host();
    assert_eq!(
        t.guest_received().len(),
        1,
        "the datagram reply must return"
    );
}

#[test]
fn dns_to_any_other_resolver_is_refused_under_an_allowlist_policy() {
    let dp = echoing_datapath();
    let mut t = single_tunnel(allow_443(), &dp);
    let guest = t.guest_addr();
    let query = udp(40000, 53, &dns_query("api.example.com"));
    let events = t.guest_sends(v4(proto::UDP, guest, Ipv4Addr::new(8, 8, 8, 8), &query));
    assert!(
        events.iter().any(|e| matches!(
            e,
            GatewayEvent::FlowDenied {
                reason: DenyCode::DestinationNotAdmitted,
                ..
            }
        )),
        "the guest must not be able to resolve elsewhere: {events:?}"
    );
}

// ---------------------------------------------------------------------
// 4. declared TCP ingress
// ---------------------------------------------------------------------

#[test]
fn a_declared_tcp_ingress_mapping_reaches_the_guest_and_an_undeclared_port_does_not() {
    let dp = LoopbackDatapath::sink();
    let mut allocator = AddressAllocator::with_defaults();
    let mut t = Tunnel::up(
        "vm-a",
        "boot-1",
        SessionId(1),
        lease_for(&mut allocator),
        allow_443(),
        &dp,
        Some(IngressMapping::tcp("0.0.0.0".parse().unwrap(), 8080, 80)),
    );
    let guest = t.guest_addr();

    let declared = v4(proto::TCP, REMOTE, guest, &tcp(40000, 80, ip::TCP_SYN));
    assert!(matches!(
        t.gateway.admitter_mut().admit_inbound(&declared, 20),
        mvm_net::l3::InboundVerdict::Deliver(_)
    ));

    let undeclared = v4(proto::TCP, REMOTE, guest, &tcp(40000, 81, ip::TCP_SYN));
    assert!(matches!(
        t.gateway.admitter_mut().admit_inbound(&undeclared, 20),
        mvm_net::l3::InboundVerdict::Deny(DenyCode::UnsolicitedInbound)
    ));
}

// ---------------------------------------------------------------------
// 5. source-address spoofing
// ---------------------------------------------------------------------

#[test]
fn source_address_spoofing_is_rejected() {
    let dp = echoing_datapath();
    let mut t = single_tunnel(allow_443(), &dp);
    let gateway = t.gateway_addr();

    for spoof in [
        Ipv4Addr::new(10, 201, 99, 99),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::LOCALHOST,
        gateway,
    ] {
        let events = t.guest_sends(v4(proto::TCP, spoof, REMOTE, &tcp(50000, 443, ip::TCP_SYN)));
        assert!(
            events.iter().any(|e| matches!(
                e,
                GatewayEvent::FlowDenied {
                    reason: DenyCode::SpoofedSource,
                    ..
                }
            )),
            "source {spoof} must be refused: {events:?}"
        );
    }
}

// ---------------------------------------------------------------------
// 6. killing the tunnel removes guest network access
// ---------------------------------------------------------------------

#[test]
fn killing_the_host_tunnel_immediately_removes_guest_network_access() {
    let dp = echoing_datapath();
    let mut t = single_tunnel(allow_443(), &dp);
    let guest = t.guest_addr();

    // Working first.
    let events = t.guest_sends(v4(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN)));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::FlowAdmitted { .. }))
    );

    // The host closes the gateway.
    let events = t.gateway.close();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GatewayEvent::CleanedUp { .. }))
    );

    // Nothing gets through afterwards, and there is no fallback.
    let events = t.guest_sends(v4(proto::TCP, guest, REMOTE, &tcp(50001, 443, ip::TCP_SYN)));
    assert!(
        events
            .iter()
            .all(|e| !matches!(e, GatewayEvent::FlowAdmitted { .. })),
        "{events:?}"
    );

    // And the guest side, told to shut down, marks its interface down.
    t.agent.fail_closed();
    assert_eq!(t.agent.state(), AgentState::Unavailable);
    assert!(!t.agent.state().network_available());
    assert_eq!(t.agent.configurator().downed, vec!["mvm0".to_string()]);
}

// ---------------------------------------------------------------------
// 7. a restart reuses nothing
// ---------------------------------------------------------------------

#[test]
fn restarting_a_machine_reuses_no_session_address_or_flow_state() {
    let dp = echoing_datapath();
    let mut allocator = AddressAllocator::with_defaults();

    let first_lease = lease_for(&mut allocator);
    let mut first = Tunnel::up(
        "vm-a",
        "boot-1",
        SessionId(0x1111_1111_1111_1111),
        first_lease,
        allow_443(),
        &dp,
        None,
    );
    let guest = first.guest_addr();
    first.guest_sends(v4(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN)));
    assert_eq!(first.gateway.admitter().flows().len(), 1);

    // Stop.
    first.gateway.close();
    assert!(first.gateway.admitter().flows().is_empty());
    let first_session = first.gateway.session();
    let first_instance = first.gateway.instance().clone();

    // Restart: a fresh boot id, a fresh session, a fresh address.
    let second_lease = lease_for(&mut allocator);
    let second = Tunnel::up(
        "vm-a",
        "boot-2",
        SessionId(0x2222_2222_2222_2222),
        second_lease,
        allow_443(),
        &dp,
        None,
    );
    assert_ne!(second.gateway.session(), first_session);
    assert_ne!(second.guest_addr(), guest);
    assert!(second.gateway.admitter().flows().is_empty());
    assert!(!second.gateway.instance().is_same_boot(&first_instance));
    assert!(second.gateway.instance().is_same_machine(&first_instance));
}

// ---------------------------------------------------------------------
// 8. machines are isolated from one another
// ---------------------------------------------------------------------

#[test]
fn two_machines_cannot_use_each_others_addresses_sessions_or_bindings() {
    let dp = echoing_datapath();
    let mut allocator = AddressAllocator::with_defaults();
    let a_session = SessionId(0xAAAA_AAAA_AAAA_AAAA);
    let b_session = SessionId(0xBBBB_BBBB_BBBB_BBBB);

    let mut a = Tunnel::up(
        "vm-a",
        "boot-a",
        a_session,
        lease_for(&mut allocator),
        allow_443(),
        &dp,
        None,
    );
    let mut b = Tunnel::up(
        "vm-b",
        "boot-b",
        b_session,
        lease_for(&mut allocator),
        allow_443(),
        &dp,
        None,
    );

    let a_addr = a.guest_addr();
    let b_addr = b.guest_addr();
    assert_ne!(a_addr, b_addr, "two machines must not share an address");

    // A cannot source packets as B.
    let events = a.guest_sends(v4(
        proto::TCP,
        b_addr,
        REMOTE,
        &tcp(50000, 443, ip::TCP_SYN),
    ));
    assert!(
        events.iter().any(|e| matches!(
            e,
            GatewayEvent::FlowDenied {
                reason: DenyCode::SpoofedSource,
                ..
            }
        )),
        "{events:?}"
    );

    // A frame carrying B's session is refused by A's gateway.
    let packet = v4(proto::TCP, a_addr, REMOTE, &tcp(50000, 443, ip::TCP_SYN));
    let wire = frame::encode(MessageType::Packet, b_session.0, 0, &packet).unwrap();
    let events = a.gateway.ingest_data_bytes(&wire, 30).unwrap();
    assert_eq!(events, vec![GatewayEvent::StaleSession]);

    // A DNS binding made by B does not admit anything for A.
    b.gateway
        .admitter_mut()
        .dns_mut()
        .bind_answer(
            "private.example.com",
            &[IpAddr::V4(DENIED)],
            &[443],
            60_000,
            0,
            30,
        )
        .expect("bind for b");
    let events = a.guest_sends(v4(
        proto::TCP,
        a_addr,
        DENIED,
        &tcp(50000, 443, ip::TCP_SYN),
    ));
    assert!(
        events.iter().any(|e| matches!(
            e,
            GatewayEvent::FlowDenied {
                reason: DenyCode::DestinationNotAdmitted,
                ..
            }
        )),
        "one machine's DNS binding must not open a path for another: {events:?}"
    );
}

// ---------------------------------------------------------------------
// 9. cleanup leaves nothing behind
// ---------------------------------------------------------------------

#[test]
fn cleanup_releases_every_piece_of_per_machine_state() {
    let dp = echoing_datapath();
    let mut allocator = AddressAllocator::with_defaults();
    let lease = lease_for(&mut allocator);
    let mut t = Tunnel::up(
        "vm-a",
        "boot-1",
        SessionId(7),
        lease,
        allow_443(),
        &dp,
        Some(IngressMapping::tcp("127.0.0.1".parse().unwrap(), 8080, 80)),
    );
    let guest = t.guest_addr();
    t.guest_sends(v4(proto::TCP, guest, REMOTE, &tcp(50000, 443, ip::TCP_SYN)));
    t.gateway
        .admitter_mut()
        .dns_mut()
        .bind_answer(
            "api.example.com",
            &[IpAddr::V4(REMOTE)],
            &[443],
            60_000,
            0,
            5,
        )
        .unwrap();
    assert!(!t.gateway.admitter().flows().is_empty());
    assert!(!t.gateway.admitter().dns().is_empty());
    assert!(!t.gateway.admitter().ingress().is_empty());

    t.gateway.close();

    assert!(
        t.gateway.admitter().flows().is_empty(),
        "flows must be gone"
    );
    assert!(
        t.gateway.admitter().dns().is_empty(),
        "dns bindings must be gone"
    );
    assert!(
        t.gateway.admitter().ingress().is_empty(),
        "ingress mappings must be gone"
    );
    assert!(
        t.gateway.take_guest_frames().is_empty(),
        "queues must be gone"
    );

    // The address lease is reclaimable, and the next allocation is a
    // different subnet rather than the one just freed.
    allocator.release(&lease);
    let next = allocator.allocate().unwrap();
    assert_ne!(next.subnet, lease.subnet);
}

// ---------------------------------------------------------------------
// transport invariants
// ---------------------------------------------------------------------

#[test]
fn control_and_packet_traffic_use_different_services() {
    // The separation is what stops a saturated uplink from starving the
    // machine's own control plane.
    assert_ne!(
        GuestService::NetworkControl.port(),
        GuestService::NetworkData { queue: 0 }.port()
    );
    assert_ne!(
        GuestService::NetworkData { queue: 0 }.port(),
        GuestService::MachineControl.port()
    );
}

#[test]
fn every_guest_packet_leaves_as_exactly_one_framed_message() {
    let dp = LoopbackDatapath::sink();
    let mut t = single_tunnel(allow_443(), &dp);
    let guest = t.guest_addr();

    for port in 0..5u16 {
        t.agent.tun_mut().push_outbound(v4(
            proto::TCP,
            guest,
            REMOTE,
            &tcp(50000 + port, 443, ip::TCP_SYN),
        ));
    }
    let mut wire = Vec::new();
    assert_eq!(t.agent.pump_tun_to_transport(&mut wire).unwrap(), 5);

    let mut rest = wire.as_slice();
    let mut frames = 0;
    while let Ok(parsed) = frame::decode(rest) {
        assert_eq!(parsed.header.msg_type, MessageType::Packet);
        // One complete IP packet per frame, no Ethernet header.
        let inner = ip::parse(parsed.payload).expect("payload is one IP packet");
        assert_eq!(inner.version, 4);
        assert_eq!(inner.total_len, parsed.payload.len());
        rest = &rest[parsed.consumed..];
        frames += 1;
    }
    assert_eq!(frames, 5);
    assert!(rest.is_empty());
}

#[test]
fn the_guest_agent_never_asserts_its_own_identity() {
    // HELLO carries a version, feature bits, and a queue count — nothing
    // that names a machine, a tenant, or a boot. Identity is the host's.
    let hello = mvm_protocol::l3::Hello::v1().encode();
    assert_eq!(hello.len(), mvm_protocol::l3::message::HELLO_LEN);
    assert_eq!(hello.len(), 7);
}
