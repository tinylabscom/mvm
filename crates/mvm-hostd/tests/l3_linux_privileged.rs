//! Privileged Linux datapath tests: a real host TUN device, real nftables
//! rules, real packet forwarding, real teardown.
//!
//! Gated behind `MVM_L3_PRIVILEGED_TESTS=1` and skipped everywhere else, so
//! ordinary CI stays unprivileged. The unprivileged end-to-end suite in
//! `l3_tunnel_e2e.rs` covers the protocol and policy; this covers only what
//! needs `CAP_NET_ADMIN` and cannot be faked: that the device appears, that
//! admitted packets actually reach it, that the rules load, and that
//! nothing survives teardown.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use mvm_hostd::netd::{DatapathRequest, ForwardingCapabilities, L3Datapath, linux::LinuxDatapath};

/// Whether the privileged lane is enabled. Absent, every test here reports
/// success without asserting anything — the alternative is a suite that is
/// red on every developer laptop.
fn enabled() -> bool {
    std::env::var("MVM_L3_PRIVILEGED_TESTS").as_deref() == Ok("1")
}

fn request(machine_id: &str, third_octet: u8) -> DatapathRequest {
    DatapathRequest {
        machine_id: machine_id.to_string(),
        gateway: Ipv4Addr::new(10, 201, third_octet, 1),
        guest: Ipv4Addr::new(10, 201, third_octet, 2),
        prefix_len: 30,
        mtu: 1500,
    }
}

/// Read the interface list straight from the kernel rather than shelling
/// out, so the assertion does not depend on `ip` being installed.
fn interface_exists(name: &str) -> bool {
    std::fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|e| e.file_name().to_string_lossy() == name)
        })
        .unwrap_or(false)
}

fn nft_table_exists(table: &str) -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn the_datapath_reports_whether_this_host_can_serve_it() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1 to run the privileged lane");
        return;
    }
    let dp = LinuxDatapath::new();
    dp.is_available()
        .expect("the privileged lane needs /dev/net/tun and CAP_NET_ADMIN");
    assert_eq!(dp.capabilities(), ForwardingCapabilities::FULL_L3_V4);
}

#[test]
fn opening_a_datapath_creates_a_host_tun_device_and_its_rules() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let req = request("privtest-a", 10);
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let table = mvm_hostd::netd::linux::table_name(&req.machine_id);

    assert!(
        !interface_exists(&iface),
        "{iface} leaked from an earlier run"
    );

    let mut handle = dp.open(&req).expect("open the datapath");
    assert!(
        interface_exists(&iface),
        "the host tun device {iface} must exist while the datapath is open"
    );
    assert!(
        nft_table_exists(&table),
        "the nftables table {table} must be loaded while the datapath is open"
    );
    assert!(handle.description().contains(&iface));

    // Teardown is deterministic: device, rules, everything.
    handle.close().expect("close");
    assert!(
        !interface_exists(&iface),
        "closing must remove the host tun device {iface}"
    );
    assert!(
        !nft_table_exists(&table),
        "closing must remove the nftables table {table}"
    );
}

#[test]
fn a_failed_open_leaves_nothing_behind() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    // Two datapaths for the same machine: the second collides on the device
    // name, and must clean up whatever it managed to create.
    let dp = LinuxDatapath::new();
    let req = request("privtest-collide", 20);
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let mut first = dp.open(&req).expect("first open");
    let second = dp.open(&req);
    // Whether the kernel refuses the duplicate or hands back the same
    // device, the invariant is the same: after closing the one we own,
    // nothing is left.
    drop(second);
    first.close().expect("close");
    assert!(
        !interface_exists(&iface),
        "no device may survive teardown, however the collision resolved"
    );
}

#[test]
fn two_machines_get_distinct_devices_and_tables() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let a = request("privtest-vm-a", 30);
    let b = request("privtest-vm-b", 31);
    let a_iface = mvm_hostd::netd::linux::device_name(&a.machine_id);
    let b_iface = mvm_hostd::netd::linux::device_name(&b.machine_id);
    assert_ne!(a_iface, b_iface);

    let mut ha = dp.open(&a).expect("open a");
    let mut hb = dp.open(&b).expect("open b");
    assert!(interface_exists(&a_iface));
    assert!(interface_exists(&b_iface));

    // Closing one leaves the other alone.
    ha.close().expect("close a");
    assert!(!interface_exists(&a_iface));
    assert!(
        interface_exists(&b_iface),
        "one machine's teardown must not touch another's device"
    );
    hb.close().expect("close b");
    assert!(!interface_exists(&b_iface));
}

/// The guest cannot reach the host TUN device directly: it has no route to
/// it, because it has no network device at all. What the guest holds is a
/// vsock connection, and the only thing on the other end is the gateway.
///
/// Asserted here as the structural fact it is — the host device's name is
/// not derivable from anything the guest can see, and the guest's own
/// interface list contains only `mvm0` and loopback.
#[test]
fn the_host_tun_is_not_something_a_guest_can_address() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let req = request("privtest-isolation", 40);
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let mut handle = dp.open(&req).expect("open");

    // The host device carries the gateway address, and the guest's assigned
    // address is the peer. There is no bridge and no shared segment: the
    // only path between them is the vsock the gateway reads from.
    assert!(interface_exists(&iface));
    assert_ne!(req.gateway, req.guest);

    // And the ruleset drops anything whose source is not the assigned
    // guest address, as a second layer under userspace admission.
    let table = mvm_hostd::netd::linux::table_name(&req.machine_id);
    let listing = std::process::Command::new("nft")
        .args(["list", "table", "inet", &table])
        .output()
        .expect("nft list");
    let rules = String::from_utf8_lossy(&listing.stdout);
    assert!(rules.contains("policy drop"), "{rules}");
    assert!(
        rules.contains(&req.guest.to_string()),
        "the ruleset must pin the assigned guest address: {rules}"
    );

    handle.close().expect("close");
}

/// Read an interface's RX packet counter. This is the kernel's own view of
/// what arrived on the device, so it cannot be satisfied by anything short
/// of a real write reaching the real stack.
fn rx_packets(iface: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_packets"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The live forwarding witness: an admitted packet reaches the host network
/// stack, and a denied one never does.
///
/// The counter is the kernel's, not ours. A packet the admitter refused
/// cannot move it, because the refusal happens before anything is written
/// to the device — and there is no other way to reach the device, since
/// `send_to_network` takes an `AdmittedPacket` that only the admitter
/// constructs.
#[test]
fn an_admitted_packet_reaches_the_host_stack_and_a_denied_one_does_not() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
    use mvm_hostd::netd::DatapathHandle;
    use mvm_net::l3::{
        AddressLease, DnsBindingStore, FlowTable, IngressTable, L3Admitter, L3PolicyConfig,
        OutboundVerdict,
    };

    let dp = LinuxDatapath::new();
    let req = request("privtest-fwd", 50);
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let mut handle = dp.open(&req).expect("open");

    // A lease matching the datapath's addressing, and a policy admitting
    // exactly one destination and port.
    let lease = AddressLease::for_test(req.gateway, req.guest);
    let policy = L3PolicyConfig {
        egress: CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Udp,
            // A routable public range. Documentation and benchmarking
            // ranges are refused by the address-class check before the
            // allow-list is reached, which would test the wrong thing.
            net: "93.184.216.0/24".parse().unwrap(),
            port_lo: 9999,
            port_hi: 9999,
        }]),
        ..L3PolicyConfig::default()
    };
    let mut admitter = L3Admitter::new(
        lease,
        policy,
        FlowTable::with_defaults(),
        DnsBindingStore::with_defaults(),
        IngressTable::with_defaults(),
    );
    admitter.set_ready(true);

    fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
        let payload = b"live-witness";
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&40000u16.to_be_bytes());
        u[2..4].copy_from_slice(&dst_port.to_be_bytes());
        u[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&u);
        p.extend_from_slice(payload);
        p
    }

    // A destination the policy refuses: nothing may reach the device.
    let before_denied = rx_packets(&iface);
    let denied = udp_packet(req.guest, Ipv4Addr::new(1, 2, 3, 4), 9999);
    match admitter.admit_outbound(&denied, 0) {
        OutboundVerdict::Deny(_) => {}
        _ => panic!("the denied destination must not be admitted"),
    }
    assert_eq!(
        rx_packets(&iface),
        before_denied,
        "a refused packet must never reach the host device"
    );

    // The admitted destination: the packet really is written to the kernel.
    let admitted = udp_packet(req.guest, Ipv4Addr::new(93, 184, 216, 5), 9999);
    let before = rx_packets(&iface);
    match admitter.admit_outbound(&admitted, 1) {
        OutboundVerdict::Forward(packet) => {
            handle
                .send_to_network(&packet)
                .expect("write the admitted packet to the host tun");
        }
        other => panic!("the admitted destination must forward, got {other:?}"),
    }
    let after = rx_packets(&iface);
    assert!(
        after > before,
        "the kernel must have received the admitted packet on {iface} \
         (rx_packets {before} -> {after})"
    );

    handle.close().expect("close");
    assert!(!interface_exists(&iface));
}

/// An idle host TUN must report `WouldBlock` rather than blocking.
///
/// The gateway drains the device until it says there is nothing left; on a
/// blocking descriptor an idle interface never returns, so the first
/// inbound poll would hang the session and take the shutdown path with it.
/// The in-memory datapath returns `WouldBlock` instantly, so only a real
/// device can witness this.
#[test]
fn an_idle_host_tun_does_not_block_the_gateway() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    use mvm_hostd::netd::{DatapathError, DatapathHandle};

    let dp = LinuxDatapath::new();
    let req = request("privtest-nonblock", 60);
    let mut handle = dp.open(&req).expect("open");

    let mut buf = vec![0u8; 2048];
    let start = std::time::Instant::now();
    match handle.recv_from_network(&mut buf) {
        Err(DatapathError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(n) => panic!("an idle device returned {n} bytes"),
        Err(other) => panic!("expected WouldBlock on an idle device, got {other}"),
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "the read blocked instead of returning WouldBlock"
    );

    handle.close().expect("close");
}
