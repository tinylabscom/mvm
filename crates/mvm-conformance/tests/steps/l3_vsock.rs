//! Step definitions for the L3 TUN-over-vsock witnesses.
//!
//! Every scenario here is decidable without a VM: the launch guard, the
//! admission core, the DNS binding store, and the session/lease identity
//! model are all pure, so they run in the hermetic lane rather than behind
//! `@live`. The privileged datapath — real TUN, real nftables — is covered
//! by `mvm-hostd`'s gated integration lane instead, because it needs
//! `CAP_NET_ADMIN` and cannot be decided from types alone.

use std::net::{IpAddr, Ipv4Addr};

use cucumber::{given, then, when};
use mvm_core::plan::NetworkMode;
use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_core::vm_backend::{VmCapabilities, VmStartConfig};
use mvm_net::channel::{GuestService, VmInstanceIdentity};
use mvm_net::l3::{
    AddressAllocator, DnsBindingStore, FlowTable, InboundVerdict, IngressMapping, IngressTable,
    L3Admitter, L3PolicyConfig, OutboundVerdict, SessionRegistry,
};
use mvm_net::lease::{
    ControlPlaneLossPolicy, LeaseContext, LeaseRequest, LocalLeaseAuthority, verify_lease,
};
use mvm_protocol::l3::{ip, proto};
use mvm_runtime::machine::nic_guard::{NicGuardError, enforce_no_guest_nic};
use mvm_runtime::machine::{Machine, NetworkMode as MachineNetworkMode};

use crate::world::CliWorld;

const LEASE_KEY: [u8; 32] = [11u8; 32];
const LEASE_NOW: u64 = 5_000_000;

// ---------------------------------------------------------------------
// launch guard
// ---------------------------------------------------------------------

#[given("a machine that selects the l3-vsock network mode")]
fn machine_selects_l3(world: &mut CliWorld) {
    world.l3_machine = Some(
        Machine::builder()
            .image("alpine")
            .network(MachineNetworkMode::L3Vsock)
            .build()
            .expect("build the machine"),
    );
}

#[then("the backend it selects advertises no routable guest NIC")]
fn backend_has_no_routable_nic(world: &mut CliWorld) {
    let machine = world.l3_machine.as_ref().expect("a machine was selected");
    let backend = machine
        .select_backend()
        .expect("a backend that carries the tunnel");
    let caps = backend.capabilities();
    assert!(
        caps.no_routable_guest_nic,
        "backend advertises a routable NIC"
    );
    assert!(caps.l3_vsock, "backend does not carry the tunnel");
}

#[then("the launch specification carries no guest network-device field")]
fn spec_has_no_nic_field(_world: &mut CliWorld) {
    let rendered = format!("{:?}", VmStartConfig::default());
    for forbidden in [
        "tap",
        "nic",
        "network_interface",
        "guest_mac",
        "bridge",
        "virtio_net",
    ] {
        assert!(
            !rendered.contains(&format!("{forbidden}:")),
            "the launch specification grew a {forbidden:?} field"
        );
    }
}

#[when("it is checked against a backend that drains a NIC instead of omitting one")]
fn checked_against_draining_backend(world: &mut CliWorld) {
    // libkrun's posture: no routable NIC, brokered proxy, but a virtio-net
    // device is still attached.
    let caps = VmCapabilities {
        vsock: true,
        no_routable_guest_nic: true,
        host_vsock_proxy: true,
        l3_vsock: false,
        ..VmCapabilities::default()
    };
    world.l3_guard_result = Some(enforce_no_guest_nic(
        NetworkMode::L3Vsock,
        &VmStartConfig::default(),
        "libkrun",
        &caps,
    ));
}

#[when("it is checked against a backend that offers only the brokered mode")]
fn checked_against_brokered_backend(world: &mut CliWorld) {
    let caps = VmCapabilities {
        vsock: true,
        no_routable_guest_nic: true,
        host_vsock_proxy: true,
        ..VmCapabilities::default()
    };
    let machine = world.l3_machine.as_ref().expect("a machine was selected");
    world.l3_backend_check = Some(machine.check_backend(&caps).map_err(|e| e.missing));
}

#[then("the launch is refused naming the missing tunnel capability")]
fn launch_refused_naming_capability(world: &mut CliWorld) {
    let result = world.l3_guard_result.take().expect("a guard result");
    match result {
        Err(NicGuardError::BackendLacksTunnel { backend }) => {
            assert_eq!(backend, "libkrun");
        }
        other => panic!("expected a named tunnel-capability refusal, got {other:?}"),
    }
}

#[then("the launch is refused rather than degraded")]
fn launch_refused_not_degraded(world: &mut CliWorld) {
    let result = world.l3_backend_check.take().expect("a backend check");
    let missing = result.expect_err("a brokered-only backend must not serve l3-vsock");
    assert!(
        missing.contains(&"l3_vsock"),
        "the shortfall must name the tunnel capability: {missing:?}"
    );
}

#[given("a machine run that declares an allowed host but no network mode")]
fn machine_run_with_allow_host(world: &mut CliWorld) {
    // The default is what matters: an egress rule says *where* traffic may
    // go, not *how* it travels.
    world.l3_machine = Some(
        Machine::builder()
            .image("alpine")
            .build()
            .expect("build the machine"),
    );
}

#[then("the selected network mode is the socket-aware default")]
fn mode_is_the_default(world: &mut CliWorld) {
    let machine = world.l3_machine.as_ref().expect("a machine");
    assert_eq!(
        machine.spec().network,
        MachineNetworkMode::None,
        "a machine that names no mode must not land on the tunnel"
    );
    let req = machine.required_capabilities();
    assert!(!req.l3_vsock, "the tunnel must never be implied");
}

// ---------------------------------------------------------------------
// admission
// ---------------------------------------------------------------------

fn admitter_with(egress: CanonicalEgress) -> L3Admitter {
    let lease = AddressAllocator::with_defaults()
        .allocate()
        .expect("pool has room");
    let mut admitter = L3Admitter::new(
        lease,
        L3PolicyConfig {
            egress,
            ..L3PolicyConfig::default()
        },
        FlowTable::with_defaults(),
        DnsBindingStore::with_defaults(),
        IngressTable::with_defaults(),
    );
    admitter.set_ready(true);
    admitter
}

fn parse_host_port(spec: &str) -> (Ipv4Addr, u16) {
    let (host, port) = spec.rsplit_once(':').expect("host:port");
    (
        host.parse().expect("an IPv4 address"),
        port.parse().expect("a port"),
    )
}

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

#[given(expr = "an admitted L3 session that allows {string}")]
fn session_allowing(world: &mut CliWorld, spec: String) {
    let (host, port) = parse_host_port(&spec);
    world.l3_admitter = Some(admitter_with(CanonicalEgress::Rules(vec![CanonicalRule {
        proto: Proto::Tcp,
        net: format!("{host}/32").parse().expect("a /32"),
        port_lo: port,
        port_hi: port,
    }])));
}

#[given("an admitted L3 session with unrestricted egress")]
fn session_unrestricted(world: &mut CliWorld) {
    world.l3_admitter = Some(admitter_with(CanonicalEgress::Unrestricted));
}

#[given("an admitted L3 session with deny-all egress")]
fn session_deny_all(world: &mut CliWorld) {
    world.l3_admitter = Some(admitter_with(CanonicalEgress::Rules(Vec::new())));
}

/// Run one outbound packet through admission and record the verdict.
fn send(world: &mut CliWorld, packet: Vec<u8>) {
    let admitter = world.l3_admitter.as_mut().expect("a session");
    world.l3_verdict = Some(match admitter.admit_outbound(&packet, 100) {
        OutboundVerdict::Forward(_) => Ok(()),
        OutboundVerdict::Gateway(..) => Ok(()),
        OutboundVerdict::Deny(code) => Err(code.as_str()),
    });
    world.l3_last_packet = Some(packet);
}

#[when(expr = "the guest sends a TCP packet to {string}")]
fn guest_sends_tcp(world: &mut CliWorld, spec: String) {
    let (host, port) = parse_host_port(&spec);
    let guest = world.l3_admitter.as_ref().expect("a session").lease().guest;
    send(
        world,
        v4(proto::TCP, guest, host, &tcp(50000, port, ip::TCP_SYN)),
    );
}

#[when("the guest sends a TCP packet from a source it was not assigned")]
fn guest_sends_spoofed(world: &mut CliWorld) {
    let spoof = Ipv4Addr::new(10, 201, 200, 200);
    send(
        world,
        v4(
            proto::TCP,
            spoof,
            Ipv4Addr::new(93, 184, 216, 34),
            &tcp(50000, 443, ip::TCP_SYN),
        ),
    );
}

#[when(expr = "the guest sends a fragmented packet to {string}")]
fn guest_sends_fragment(world: &mut CliWorld, spec: String) {
    let (host, port) = parse_host_port(&spec);
    let guest = world.l3_admitter.as_ref().expect("a session").lease().guest;
    let mut packet = v4(proto::TCP, guest, host, &tcp(50000, port, ip::TCP_SYN));
    packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    send(world, packet);
}

#[then("the packet is forwarded to the host network")]
fn packet_forwarded(world: &mut CliWorld) {
    let verdict = world.l3_verdict.take().expect("a verdict");
    assert_eq!(verdict, Ok(()), "the packet should have been admitted");
}

#[then(expr = "the packet is refused with reason {string}")]
fn packet_refused_with(world: &mut CliWorld, reason: String) {
    let verdict = world.l3_verdict.take().expect("a verdict");
    assert_eq!(verdict, Err(reason.as_str()), "unexpected verdict");
}

#[when("an unsolicited packet arrives for the guest")]
fn unsolicited_inbound(world: &mut CliWorld) {
    let admitter = world.l3_admitter.as_mut().expect("a session");
    let guest = admitter.lease().guest;
    let packet = v4(
        proto::TCP,
        Ipv4Addr::new(93, 184, 216, 34),
        guest,
        &tcp(443, 50000, ip::TCP_SYN),
    );
    world.l3_inbound_verdict = Some(match admitter.admit_inbound(&packet, 101) {
        InboundVerdict::Deliver(_) => Ok(()),
        InboundVerdict::Deny(code) => Err(code.as_str()),
    });
}

#[when("the peer replies on the same flow")]
fn peer_replies(world: &mut CliWorld) {
    let admitter = world.l3_admitter.as_mut().expect("a session");
    let guest = admitter.lease().guest;
    let packet = v4(
        proto::TCP,
        Ipv4Addr::new(93, 184, 216, 34),
        guest,
        &tcp(443, 50000, ip::TCP_SYN | ip::TCP_ACK),
    );
    world.l3_inbound_verdict = Some(match admitter.admit_inbound(&packet, 102) {
        InboundVerdict::Deliver(_) => Ok(()),
        InboundVerdict::Deny(code) => Err(code.as_str()),
    });
}

#[given("a declared TCP ingress mapping to guest port 80")]
fn declare_ingress(world: &mut CliWorld) {
    world
        .l3_admitter
        .as_mut()
        .expect("a session")
        .ingress_mut()
        .declare(IngressMapping::tcp("0.0.0.0".parse().unwrap(), 8080, 80))
        .expect("declare the mapping");
}

#[when("an inbound packet arrives for guest port 80")]
fn inbound_for_port_80(world: &mut CliWorld) {
    let admitter = world.l3_admitter.as_mut().expect("a session");
    let guest = admitter.lease().guest;
    let packet = v4(
        proto::TCP,
        Ipv4Addr::new(93, 184, 216, 34),
        guest,
        &tcp(40000, 80, ip::TCP_SYN),
    );
    world.l3_inbound_verdict = Some(match admitter.admit_inbound(&packet, 103) {
        InboundVerdict::Deliver(_) => Ok(()),
        InboundVerdict::Deny(code) => Err(code.as_str()),
    });
}

#[then("the inbound packet is delivered to the guest")]
fn inbound_delivered(world: &mut CliWorld) {
    let verdict = world.l3_inbound_verdict.take().expect("an inbound verdict");
    assert_eq!(verdict, Ok(()), "the packet should have been delivered");
}

#[then(expr = "the inbound packet is refused with reason {string}")]
fn inbound_refused_with(world: &mut CliWorld, reason: String) {
    let verdict = world.l3_inbound_verdict.take().expect("an inbound verdict");
    assert_eq!(verdict, Err(reason.as_str()), "unexpected inbound verdict");
}

// ---------------------------------------------------------------------
// controlled DNS
// ---------------------------------------------------------------------

#[when(expr = "the host resolver admits {string} as {string}")]
fn resolver_admits(world: &mut CliWorld, name: String, addr: String) {
    let ip: Ipv4Addr = addr.parse().expect("an IPv4 address");
    world
        .l3_admitter
        .as_mut()
        .expect("a session")
        .dns_mut()
        .bind_answer(&name, &[IpAddr::V4(ip)], &[443], 60_000, 0, 100)
        .expect("the answer should be admissible");
}

#[then(expr = "the guest may reach {string}")]
fn guest_may_reach(world: &mut CliWorld, spec: String) {
    let (host, port) = parse_host_port(&spec);
    let guest = world.l3_admitter.as_ref().expect("a session").lease().guest;
    let packet = v4(proto::TCP, guest, host, &tcp(50000, port, ip::TCP_SYN));
    let admitter = world.l3_admitter.as_mut().expect("a session");
    assert!(
        matches!(
            admitter.admit_outbound(&packet, 101),
            OutboundVerdict::Forward(_)
        ),
        "{spec} should be reachable after the resolver admitted it"
    );
}

#[then(expr = "the guest may not reach {string}")]
fn guest_may_not_reach(world: &mut CliWorld, spec: String) {
    let (host, port) = parse_host_port(&spec);
    let guest = world.l3_admitter.as_ref().expect("a session").lease().guest;
    let packet = v4(proto::TCP, guest, host, &tcp(50000, port, ip::TCP_SYN));
    let admitter = world.l3_admitter.as_mut().expect("a session");
    assert!(
        matches!(
            admitter.admit_outbound(&packet, 101),
            OutboundVerdict::Deny(_)
        ),
        "{spec} must stay closed: a DNS answer opens only what it resolved"
    );
}

#[then(expr = "binding {string} to {string} is refused")]
fn binding_refused(world: &mut CliWorld, name: String, addr: String) {
    let ip: Ipv4Addr = addr.parse().expect("an IPv4 address");
    let result = world
        .l3_admitter
        .as_mut()
        .expect("a session")
        .dns_mut()
        .bind_answer(&name, &[IpAddr::V4(ip)], &[443], 60_000, 0, 100);
    assert!(
        result.is_err(),
        "an answer pointing at {addr} must be refused as rebinding"
    );
}

// ---------------------------------------------------------------------
// session lifecycle
// ---------------------------------------------------------------------

#[given("the guest has an established flow")]
fn established_flow(world: &mut CliWorld) {
    let guest = world.l3_admitter.as_ref().expect("a session").lease().guest;
    let packet = v4(
        proto::TCP,
        guest,
        Ipv4Addr::new(93, 184, 216, 34),
        &tcp(50000, 443, ip::TCP_SYN),
    );
    let admitter = world.l3_admitter.as_mut().expect("a session");
    assert!(matches!(
        admitter.admit_outbound(&packet, 100),
        OutboundVerdict::Forward(_)
    ));
    assert_eq!(admitter.flows().len(), 1);
}

#[when("the machine restarts")]
fn machine_restarts(world: &mut CliWorld) {
    let mut allocator = AddressAllocator::with_defaults();
    let mut registry = SessionRegistry::new();
    let first = registry
        .open(
            "vm-a",
            "sha256:plan",
            0,
            allocator.allocate().unwrap(),
            0xFEED,
            0,
        )
        .expect("open the first session")
        .id();
    registry.invalidate("vm-a");
    let second = registry
        .open(
            "vm-a",
            "sha256:plan",
            0,
            allocator.allocate().unwrap(),
            0xFEED,
            10,
        )
        .expect("open the second session")
        .id();
    world.l3_previous_session = Some(first);
    world.l3_current_session = Some(second);
    // The restarted machine starts from an empty admitter.
    world.l3_admitter = Some(admitter_with(CanonicalEgress::Rules(Vec::new())));
}

#[then("the new session differs from the previous one")]
fn new_session_differs(world: &mut CliWorld) {
    let previous = world.l3_previous_session.expect("a previous session");
    let current = world.l3_current_session.expect("a current session");
    assert_ne!(
        previous, current,
        "a restart must mint a fresh session, even with identical entropy"
    );
}

#[then("the new session has no flows")]
fn new_session_has_no_flows(world: &mut CliWorld) {
    assert!(
        world
            .l3_admitter
            .as_ref()
            .expect("a session")
            .flows()
            .is_empty(),
        "a restart must inherit no flow state"
    );
}

// ---------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------

fn lease_authority() -> LocalLeaseAuthority {
    LocalLeaseAuthority::new("node-1", LEASE_KEY)
}

#[given("a locally issued network lease for one VM boot")]
fn issue_lease(world: &mut CliWorld) {
    let authority = lease_authority();
    let instance = VmInstanceIdentity::new("node-1", "vm-a", "boot-1", "sha256:plan");
    let lease = authority.issue(&LeaseRequest {
        instance: &instance,
        tenant_id: "default",
        ipv4: Ipv4Addr::new(10, 201, 0, 6),
        gateway_ipv4: Ipv4Addr::new(10, 201, 0, 5),
        dns_name: None,
        routes: &[],
        ingress: &[],
        egress_policy_digest: "sha256:egress",
        policy_epoch: 1,
        now_millis: LEASE_NOW,
    });
    world.l3_lease = Some(lease);
    world.l3_lease_instance = Some(instance);
}

fn present_lease(world: &mut CliWorld, instance: VmInstanceIdentity, now_millis: u64) {
    let lease = world.l3_lease.as_ref().expect("a lease");
    let result = verify_lease(
        lease,
        &lease_authority(),
        &LeaseContext {
            instance,
            plan_policy_epoch: 1,
            egress_policy_digest: "sha256:egress".to_string(),
            now_millis,
        },
    );
    world.l3_lease_result = Some(result.map_err(|e| e.to_string()));
}

#[when("the same lease is presented for a different boot of that machine")]
fn lease_for_later_boot(world: &mut CliWorld) {
    present_lease(
        world,
        VmInstanceIdentity::new("node-1", "vm-a", "boot-2", "sha256:plan"),
        LEASE_NOW,
    );
}

#[when("the same lease is presented on a different node")]
fn lease_on_other_node(world: &mut CliWorld) {
    present_lease(
        world,
        VmInstanceIdentity::new("node-2", "vm-a", "boot-1", "sha256:plan"),
        LEASE_NOW,
    );
}

#[when("the lease validity window has passed")]
fn lease_expired(world: &mut CliWorld) {
    let expires = world.l3_lease.as_ref().expect("a lease").expires_at_millis;
    let instance = world
        .l3_lease_instance
        .clone()
        .expect("the issuing instance");
    present_lease(world, instance, expires);
}

#[then("the lease is refused")]
fn lease_refused(world: &mut CliWorld) {
    let result = world.l3_lease_result.take().expect("a lease verdict");
    assert!(result.is_err(), "the lease should not have verified");
}

#[then("no control-plane loss policy permits traffic after lease expiry")]
fn loss_policies_fail_closed(_world: &mut CliWorld) {
    for policy in [
        ControlPlaneLossPolicy::HoldExistingDenyNew,
        ControlPlaneLossPolicy::HoldUntilExpiry,
        ControlPlaneLossPolicy::DenyImmediately,
    ] {
        assert!(
            !policy.after_expiry_permits_anything(),
            "{policy:?} must deny once the lease expires"
        );
    }
}

// ---------------------------------------------------------------------
// forwarding capabilities and transport separation
// ---------------------------------------------------------------------

#[given("a forwarding backend that only translates host sockets")]
fn userspace_backend(world: &mut CliWorld) {
    world.l3_backend_capabilities =
        Some(mvm_hostd::netd::ForwardingCapabilities::USERSPACE_SOCKETS);
}

#[when("a plan requires arbitrary packet forwarding")]
fn plan_requires_packet_forwarding(world: &mut CliWorld) {
    let required = mvm_hostd::netd::ForwardingCapabilities {
        icmp: true,
        arbitrary_ipv4: true,
        raw_ip_protocols: true,
        ..mvm_hostd::netd::ForwardingCapabilities::USERSPACE_SOCKETS
    };
    let available = world
        .l3_backend_capabilities
        .expect("a backend was selected");
    world.l3_capability_shortfall = Some(
        available
            .shortfall(&required)
            .into_iter()
            .map(str::to_string)
            .collect(),
    );
}

#[then("admission reports the missing forwarding capabilities")]
fn admission_reports_shortfall(world: &mut CliWorld) {
    let missing = world
        .l3_capability_shortfall
        .take()
        .expect("a capability check");
    assert!(
        !missing.is_empty(),
        "a plan needing packet forwarding must not be admitted on a socket gateway"
    );
    for expected in ["icmp", "arbitrary_ipv4", "raw_ip_protocols"] {
        assert!(
            missing.iter().any(|m| m == expected),
            "the shortfall must name {expected}: {missing:?}"
        );
    }
}

#[then("the network control and network data services use different ports")]
fn control_and_data_differ(_world: &mut CliWorld) {
    assert_ne!(
        GuestService::NetworkControl.port(),
        GuestService::NetworkData { queue: 0 }.port(),
        "bulk packet traffic must not share the control connection"
    );
}

#[then("neither shares the machine-control service port")]
fn neither_shares_machine_control(_world: &mut CliWorld) {
    let machine_control = GuestService::MachineControl.port();
    assert_ne!(GuestService::NetworkControl.port(), machine_control);
    assert_ne!(
        GuestService::NetworkData { queue: 0 }.port(),
        machine_control
    );
}
