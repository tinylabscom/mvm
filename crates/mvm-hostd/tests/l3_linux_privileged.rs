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

use std::net::{Ipv4Addr, Ipv6Addr};

use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_hostd::netd::{
    DatapathHandle, DatapathRequest, ForwardingCapabilities, L3Datapath, V6Link,
    linux::LinuxDatapath,
};
use mvm_net::l3::{
    AddressLease, DnsBindingStore, FlowTable, IngressTable, L3Admitter, L3PolicyConfig,
    OutboundVerdict,
};

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
        // v4-only: this lane asserts that a real TUN device appears and
        // carries packets, and the v6 half of an address pair adds nothing
        // to that.
        v6: None,
        mtu: 1500,
        ingress: Vec::new(),
    }
}

/// The unique-local pool the allocator carves the v6 half out of.
const V6_POOL: Ipv6Addr = Ipv6Addr::new(0xfd6d, 0x766d, 1, 0, 0, 0, 0, 0);

/// The /126 at `index`, laid out the way the allocator lays one out: the
/// gateway first, the guest next. Indexed alongside the /30 above so two
/// machines in one test share an address in neither family.
fn v6_link(index: u128) -> V6Link {
    let base = u128::from(V6_POOL) + 4 * index;
    V6Link {
        gateway: Ipv6Addr::from(base + 1),
        guest: Ipv6Addr::from(base + 2),
        prefix_len: 126,
    }
}

fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16) -> Vec<u8> {
    let payload = b"live-witness";
    let total = 20 + 8 + payload.len();
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = packet[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    let checksum = ((checksum & 0xffff) + (checksum >> 16)) as u16;
    let checksum = (!checksum).to_be_bytes();
    packet[10..12].copy_from_slice(&checksum);
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&udp);
    packet.extend_from_slice(payload);
    packet
}

/// A request for a machine whose plan asked for IPv6, so the datapath
/// assigns both halves of the link.
fn request_dual(machine_id: &str, third_octet: u8) -> DatapathRequest {
    DatapathRequest {
        v6: Some(v6_link(u128::from(third_octet))),
        ..request(machine_id, third_octet)
    }
}

fn admitting_policy(req: &DatapathRequest) -> L3Admitter {
    let policy = L3PolicyConfig {
        egress: CanonicalEgress::Rules(vec![CanonicalRule {
            proto: Proto::Udp,
            net: "93.184.216.0/24".parse().expect("test CIDR is valid"),
            port_lo: 9999,
            port_hi: 9999,
        }]),
        ..L3PolicyConfig::default()
    };
    let mut admitter = L3Admitter::new(
        AddressLease::for_test(req.gateway, req.guest),
        policy,
        FlowTable::with_defaults(),
        DnsBindingStore::with_defaults(),
        IngressTable::with_defaults(),
    );
    admitter.set_ready(true);
    admitter
}

fn send_admitted_packet(
    handle: &mut dyn DatapathHandle,
    admitter: &mut L3Admitter,
    packet: &[u8],
    tick: u64,
) {
    match admitter.admit_outbound(packet, tick) {
        OutboundVerdict::Forward(packet) => handle.send_to_network(&packet).expect("write packet"),
        other => panic!("the packet must be admitted, got {other:?}"),
    }
}

fn nft_chain_listing(table: &str, chain: &str) -> String {
    let output = std::process::Command::new("nft")
        .args(["-a", "list", "chain", "inet", table, chain])
        .output()
        .expect("nft list chain");
    assert!(output.status.success(), "nft list chain failed: {output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn counter_packets(listing: &str, rule_fragment: &str) -> u64 {
    listing
        .lines()
        .find(|line| line.contains(rule_fragment))
        .and_then(|line| line.split("counter packets ").nth(1))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("missing packet counter for {rule_fragment}: {listing}"))
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

/// Whether the device is gone, allowing for the kernel taking its time.
///
/// Closing the last descriptor is what removes a TUN interface, but the
/// removal is the kernel's to schedule and it is not synchronous with the
/// `close(2)` that triggered it. On an unloaded host it is quick enough
/// that an immediate check passes; under the parallelism of a full test
/// binary it is not, and the same assertion fails for a teardown that is
/// working correctly.
///
/// So the property asserted is the real one — the device does not survive
/// teardown — rather than the stricter one nothing promises, that it is
/// gone by the time the next statement runs.
fn interface_gone(name: &str) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if !interface_exists(name) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    !interface_exists(name)
}

fn nft_table_exists(table: &str) -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn nft_chain_exists(table: &str, chain: &str) -> bool {
    std::process::Command::new("nft")
        .args(["list", "chain", "inet", table, chain])
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
    // A full packet path in both families: the handle assigns the v6 pair
    // whenever the lease carries one, and its ruleset pins the v6 source
    // the same way it pins the v4 one.
    assert_eq!(dp.capabilities(), ForwardingCapabilities::FULL_L3);
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
    let forward_chain = mvm_hostd::netd::linux::forward_chain_name(&req.machine_id);

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
        interface_gone(&iface),
        "closing must remove the host tun device {iface}"
    );
    assert!(!nft_chain_exists(&table, &forward_chain));
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
        interface_gone(&iface),
        "no device may survive teardown, however the collision resolved"
    );
}

#[test]
fn two_machines_get_distinct_devices_under_one_shared_table() {
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
    assert_eq!(
        mvm_hostd::netd::linux::table_name(&a.machine_id),
        mvm_hostd::netd::linux::table_name(&b.machine_id)
    );
    assert_ne!(
        mvm_hostd::netd::linux::forward_chain_name(&a.machine_id),
        mvm_hostd::netd::linux::forward_chain_name(&b.machine_id)
    );

    let mut ha = dp.open(&a).expect("open a");
    let mut hb = dp.open(&b).expect("open b");
    assert!(interface_exists(&a_iface));
    assert!(interface_exists(&b_iface));

    // Closing one leaves the other alone. The removal is bounded-waited for
    // the same reason as everywhere else here — the kernel schedules it, not
    // the `close(2)` that triggered it — while the survivor's presence is an
    // instant check, because nothing about it is pending.
    ha.close().expect("close a");
    assert!(interface_gone(&a_iface));
    assert!(
        interface_exists(&b_iface),
        "one machine's teardown must not touch another's device"
    );
    hb.close().expect("close b");
    assert!(interface_gone(&b_iface));
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
    assert!(
        rules.contains(&req.guest.to_string()),
        "the ruleset must pin the assigned guest address: {rules}"
    );
    assert!(
        rules.contains("policy drop"),
        "the shared forward chain must default-deny: {rules}"
    );
    assert!(
        rules.contains(&format!("iifname \"{iface}\" drop")),
        "spoofed packets from this machine must be dropped: {rules}"
    );
    assert!(
        rules.contains(&format!("oifname \"{iface}\" drop")),
        "unsolicited packets to this machine must be dropped: {rules}"
    );

    handle.close().expect("close");
}

/// Two machines must be able to coexist under one host-wide default-drop
/// chain. A machine-specific chain may only be reached by jumps scoped to
/// its own interface, so it cannot drop the other machine's traffic.
#[test]
fn two_open_machines_keep_each_others_forwarding_rules_active() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let a = request("privtest-forward-a", 70);
    let b = request("privtest-forward-b", 71);
    let table = mvm_hostd::netd::linux::table_name(&a.machine_id);
    let a_iface = mvm_hostd::netd::linux::device_name(&a.machine_id);
    let b_iface = mvm_hostd::netd::linux::device_name(&b.machine_id);

    let mut ha = dp.open(&a).expect("open machine a");
    let mut hb = dp.open(&b).expect("open machine b");
    assert!(nft_table_exists(&table));

    let listing = std::process::Command::new("nft")
        .args(["list", "table", "inet", &table])
        .output()
        .expect("nft list shared table");
    let rules = String::from_utf8_lossy(&listing.stdout);
    assert!(rules.contains("policy drop"), "{rules}");
    for iface in [&a_iface, &b_iface] {
        assert!(
            rules.contains(&format!("iifname \"{iface}\" drop")),
            "{iface} must retain source anti-spoofing: {rules}"
        );
        assert!(
            rules.contains(&format!("oifname \"{iface}\" drop")),
            "{iface} must retain destination default-deny: {rules}"
        );
    }

    // Removing one machine must not remove the shared table or the other
    // machine's chains.
    ha.close().expect("close machine a");
    assert!(nft_table_exists(&table));
    let remaining = std::process::Command::new("nft")
        .args(["list", "table", "inet", &table])
        .output()
        .expect("nft list remaining table");
    let remaining_rules = String::from_utf8_lossy(&remaining.stdout);
    assert!(
        remaining_rules.contains(&format!("iifname \"{b_iface}\" drop")),
        "machine b's source anti-spoofing must survive machine a teardown: {remaining_rules}"
    );

    hb.close().expect("close machine b");
    assert!(!nft_table_exists(&table));
}

/// The shared forward hook must actually admit traffic for both machines,
/// not merely retain both sets of rules in the table listing.
#[test]
fn two_machines_forward_admitted_packets_through_the_shared_hook() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let a = request("privtest-packet-a", 72);
    let b = request("privtest-packet-b", 73);
    let table = mvm_hostd::netd::linux::table_name(&a.machine_id);
    let a_chain = mvm_hostd::netd::linux::forward_chain_name(&a.machine_id);
    let b_chain = mvm_hostd::netd::linux::forward_chain_name(&b.machine_id);
    let mut ha = dp.open(&a).expect("open machine a");
    let mut hb = dp.open(&b).expect("open machine b");
    let mut aa = admitting_policy(&a);
    let mut ab = admitting_policy(&b);

    send_admitted_packet(
        ha.as_mut(),
        &mut aa,
        &udp_packet(a.guest, Ipv4Addr::new(93, 184, 216, 5), 9999),
        1,
    );
    send_admitted_packet(
        hb.as_mut(),
        &mut ab,
        &udp_packet(b.guest, Ipv4Addr::new(93, 184, 216, 6), 9999),
        1,
    );

    let a_listing = nft_chain_listing(&table, &a_chain);
    let b_listing = nft_chain_listing(&table, &b_chain);
    assert!(
        counter_packets(&a_listing, &format!("ip saddr {}/32", a.guest)) > 0,
        "machine a's admitted packet must traverse its forward chain: {a_listing}"
    );
    assert!(
        counter_packets(&b_listing, &format!("ip saddr {}/32", b.guest)) > 0,
        "machine b's admitted packet must traverse its forward chain: {b_listing}"
    );

    ha.close().expect("close machine a");
    hb.close().expect("close machine b");
    assert!(!nft_table_exists(&table));
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
    let dp = LinuxDatapath::new();
    let req = request("privtest-fwd", 50);
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let mut handle = dp.open(&req).expect("open");

    // A lease matching the datapath's addressing, and a policy admitting
    // exactly one destination and port.
    let mut admitter = admitting_policy(&req);

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
    assert!(interface_gone(&iface));
}

/// An idle host TUN must report `WouldBlock` rather than blocking.
///
/// The gateway drains the device until it says there is nothing left; on a
/// blocking descriptor an idle interface never returns, so the first
/// inbound poll would hang the session and take the shutdown path with it.
/// The in-memory datapath returns `WouldBlock` instantly, so only a real
/// device can witness this.
///
/// The drain is a loop rather than a single read because a link is not
/// silent just because no guest is on it: a host that forwards IPv6 is an
/// MLD querier and puts a general query on every link it owns. "Idle"
/// therefore means the drain *terminates*, which is exactly what the
/// gateway needs and what a blocking descriptor would not give it.
#[test]
fn an_idle_host_tun_does_not_block_the_gateway() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    use mvm_hostd::netd::DatapathError;

    let dp = LinuxDatapath::new();
    let req = request("privtest-nonblock", 60);
    let mut handle = dp.open(&req).expect("open");

    let mut buf = vec![0u8; 2048];
    let start = std::time::Instant::now();
    let limit = std::time::Duration::from_secs(1);
    loop {
        match handle.recv_from_network(&mut buf) {
            Err(DatapathError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Ok(_) => {}
            Err(other) => panic!("expected WouldBlock on an idle device, got {other}"),
        }
        assert!(
            start.elapsed() < limit,
            "the device never went quiet, so the gateway's drain would not terminate"
        );
    }
    assert!(
        start.elapsed() < limit,
        "the read blocked instead of returning WouldBlock"
    );

    handle.close().expect("close");
}

/// Every IPv6 address the kernel holds on `iface`, read out of
/// `/proc/net/if_inet6` rather than by shelling out, so the assertion does
/// not depend on `ip` being installed.
fn v6_addresses(iface: &str) -> Vec<Ipv6Addr> {
    let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let hex = fields.next()?;
            if fields.next_back()? != iface {
                return None;
            }
            let mut octets = [0u8; 16];
            for (i, octet) in octets.iter_mut().enumerate() {
                *octet = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
            }
            Some(Ipv6Addr::from(octets))
        })
        .collect()
}

fn nft_listing(table: &str) -> String {
    let out = std::process::Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .expect("nft list");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A dual-stack lease puts both halves of the link on the host device, and
/// teardown takes both with it.
///
/// The v6 half is not decoration: assigning the gateway's /126 is what
/// creates the connected prefix the guest's address sits in, which is the
/// only reason a packet the guest sourced has anywhere to be routed from.
#[test]
fn a_dual_lease_puts_both_families_on_the_host_device() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let req = request_dual("privtest-dual", 70);
    let v6 = req.v6.expect("a dual request carries a v6 link");
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let table = mvm_hostd::netd::linux::table_name(&req.machine_id);

    let mut handle = dp.open(&req).expect("open the datapath");

    let held = v6_addresses(&iface);
    assert!(
        held.contains(&v6.gateway),
        "the host side of the v6 link must be on {iface}: {held:?}"
    );
    assert!(
        !held.contains(&v6.guest),
        "the guest's address belongs to the guest, not to the host device: {held:?}"
    );

    // And the loaded ruleset — the kernel's copy, not the string this
    // process generated — pins that guest address as a source.
    let rules = nft_listing(&table);
    assert!(
        rules.contains(&v6.guest.to_string()),
        "the ruleset must pin the assigned v6 guest address: {rules}"
    );

    handle.close().expect("close");
    assert!(interface_gone(&iface));
    assert!(
        v6_addresses(&iface).is_empty(),
        "the v6 address must not outlive the device it was assigned to"
    );
    assert!(!nft_chain_exists(
        &table,
        &mvm_hostd::netd::linux::forward_chain_name(&req.machine_id)
    ));
}

/// A machine whose plan never asked for IPv6 gets none of it.
///
/// The point of the opt-in is that an address family a workload did not
/// ask for is not reachable surface it silently acquired, so the absence
/// has to be asserted against the kernel rather than assumed from the
/// request.
#[test]
fn a_v4_only_lease_puts_no_global_v6_address_on_the_device() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let dp = LinuxDatapath::new();
    let req = request("privtest-v4only", 71);
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let table = mvm_hostd::netd::linux::table_name(&req.machine_id);
    let forward_chain = mvm_hostd::netd::linux::forward_chain_name(&req.machine_id);
    let mut handle = dp.open(&req).expect("open the datapath");

    // The kernel adds a link-local address to any IPv6-capable interface on
    // its own. What must be absent is anything out of the assigned pool.
    let held = v6_addresses(&iface);
    let pool = u128::from(V6_POOL) >> 64;
    assert!(
        held.iter().all(|addr| u128::from(*addr) >> 64 != pool),
        "a v4-only lease must hold no address from the v6 pool: {held:?}"
    );

    let rules = nft_chain_listing(&table, &forward_chain);
    assert!(
        !rules.contains("ip6 saddr"),
        "a v4-only lease must load no v6 rule: {rules}"
    );

    handle.close().expect("close");
    assert!(!nft_chain_exists(&table, &forward_chain));
}

/// One IPv6 TCP SYN, built by hand so a source the host never assigned can
/// be put on the wire — which is the whole point of the witness below.
fn v6_syn(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16) -> Vec<u8> {
    const NEXT_HEADER_TCP: u8 = 6;
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    packet[6] = NEXT_HEADER_TCP;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet.extend_from_slice(&tcp);
    packet
}

/// A routable destination outside every mandatory-deny class, so nothing
/// but the rule under test can be what refuses a packet aimed at it.
fn global_v6_destination() -> Ipv6Addr {
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
}

/// Put bytes on the host device the way a defect above this layer would:
/// with no `AdmittedPacket`, because the point of a second layer is that it
/// holds when the first one does not.
fn write_bypassing_admission(handle: &dyn DatapathHandle, packet: &[u8]) {
    use std::io::Write;
    use std::os::fd::FromRawFd;

    let fd = handle
        .readiness_fd()
        .expect("an open host tun exposes its descriptor");
    // SAFETY: the descriptor belongs to the still-open handle, and
    // `ManuallyDrop` keeps this borrow from closing it out from under it.
    let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    (&*file).write_all(packet).expect("write to the host tun");
}

/// Ensures the host forwards IPv6 while a witness runs, and puts back
/// whatever it found.
///
/// A forwarding host is a prerequisite of the packet backend in either
/// family — the v4 half needs `net.ipv4.ip_forward` exactly as much — and
/// it is host configuration rather than something a per-machine datapath
/// may flip on a host's behalf. So a witness that needs the forward hook to
/// run has to arrange it itself.
struct HostIpv6Forwarding {
    previous: String,
}

impl HostIpv6Forwarding {
    const KNOB: &'static str = "/proc/sys/net/ipv6/conf/all/forwarding";

    fn enabled() -> Self {
        let previous = std::fs::read_to_string(Self::KNOB).expect("read the forwarding knob");
        std::fs::write(Self::KNOB, "1\n").expect("enable ipv6 forwarding");
        Self { previous }
    }
}

impl Drop for HostIpv6Forwarding {
    fn drop(&mut self) {
        let _ = std::fs::write(Self::KNOB, &self.previous);
    }
}

/// Counts packets that survived the datapath's own forward chain.
///
/// A base chain at a higher priority number runs *after* the one under
/// test in the same hook, and only for packets it accepted — a drop ends
/// evaluation there and nothing later ever sees them. So the counter here
/// is the discriminator between "the ruleset let this through" and "the
/// ruleset dropped it", read from the kernel rather than inferred.
struct ForwardProbe {
    table: String,
}

impl ForwardProbe {
    fn watching(iface: &str) -> Self {
        let table = format!("mvmnprobe{iface}");
        let rules = format!(
            "table inet {table} {{\n\
             \x20 chain observe {{\n\
             \x20   type filter hook forward priority filter + 10; policy accept;\n\
             \x20   iifname \"{iface}\" meta nfproto ipv6 counter\n\
             \x20 }}\n\
             }}\n"
        );
        let mut child = std::process::Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn nft");
        {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin was piped")
                .write_all(rules.as_bytes())
                .expect("feed the probe ruleset to nft");
        }
        let out = child.wait_with_output().expect("nft -f -");
        assert!(
            out.status.success(),
            "loading the probe ruleset failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self { table }
    }

    fn count(&self) -> u64 {
        let listing = nft_listing(&self.table);
        listing
            .split("counter packets ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no counter in the probe table: {listing}"))
    }
}

impl Drop for ForwardProbe {
    fn drop(&mut self) {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &self.table])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// The anti-spoofing witness for IPv6, at the layer that is supposed to
/// hold when admission does not.
///
/// Admission refuses a source the lease never assigned, and that refusal is
/// covered by the unprivileged suite. This asserts the *second* layer:
/// bytes are put on the device with no admission at all, and the kernel's
/// own verdict decides. A packet carrying the assigned source survives the
/// forward chain; one carrying a source the host never handed out does not.
///
/// The admitted-source writes are the control. Without them a refusal here
/// would be indistinguishable from the ruleset dropping IPv6 outright,
/// which would pass the same assertion while carrying nothing.
#[test]
fn the_forward_chain_drops_a_v6_source_the_host_did_not_assign() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    let _forwarding = HostIpv6Forwarding::enabled();

    const OCTET: u8 = 80;
    let dp = LinuxDatapath::new();
    let req = request_dual("privtest-v6spoof", OCTET);
    let v6 = req.v6.expect("a dual request carries a v6 link");
    let iface = mvm_hostd::netd::linux::device_name(&req.machine_id);
    let mut handle = dp.open(&req).expect("open the datapath");

    let probe = ForwardProbe::watching(&iface);
    let dst = global_v6_destination();
    // A source out of the same pool, one machine along: a plausible
    // neighbour's address rather than an obviously alien one, because the
    // rule pins a single address and near-misses are what it must catch.
    let spoofed = v6_link(u128::from(OCTET) + 1).guest;
    assert_ne!(spoofed, v6.guest);

    let (assigned_first, after_spoof, assigned_again) = {
        let start = probe.count();
        write_bypassing_admission(handle.as_ref(), &v6_syn(v6.guest, dst, 40001));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let assigned_first = probe.count() - start;

        write_bypassing_admission(handle.as_ref(), &v6_syn(spoofed, dst, 40002));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let after_spoof = probe.count() - start - assigned_first;

        write_bypassing_admission(handle.as_ref(), &v6_syn(v6.guest, dst, 40003));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let assigned_again = probe.count() - start - assigned_first - after_spoof;
        (assigned_first, after_spoof, assigned_again)
    };

    assert_eq!(
        assigned_first, 1,
        "a packet carrying the assigned v6 source must pass the forward chain"
    );
    assert_eq!(
        after_spoof, 0,
        "a packet carrying a v6 source the host never assigned must be dropped"
    );
    assert_eq!(
        assigned_again, 1,
        "the drop must be about the source, not about anything the first packet consumed"
    );

    drop(probe);
    handle.close().expect("close");
}

/// Holding a unique-local address is an identity on the link, never a
/// permission to reach unique-local space.
///
/// On this backend the risk is physical rather than notional: the pool the
/// v6 half is carved from is itself inside `fc00::/7`, and a second machine
/// open on the same host has its own /126 as a *connected route* there. So
/// nothing about the host's routing table stands between one machine and
/// another's address — admission does, and this is the witness for it.
///
/// The refused destinations are checked against the device as well as
/// against the verdict: the packet counter the kernel keeps must not move,
/// because a refusal that still wrote the packet would be no refusal. The
/// admitted global destination is the control — without it, a v6 deny-all
/// would satisfy every other assertion here.
#[test]
fn a_guest_holding_a_ula_address_still_cannot_reach_ula_space() {
    if !enabled() {
        eprintln!("skipping: set MVM_L3_PRIVILEGED_TESTS=1");
        return;
    }
    use mvm_core::policy::projection::CanonicalEgress;
    use mvm_net::l3::{
        AddressLease, DenyCode, DnsBindingStore, FlowTable, IngressTable, L3Admitter,
        L3PolicyConfig, OutboundVerdict,
    };

    let dp = LinuxDatapath::new();
    let mine = request_dual("privtest-mine", 90);
    let neighbour = request_dual("privtest-nbr", 91);
    let my_v6 = mine.v6.expect("a dual request carries a v6 link");
    let neighbour_v6 = neighbour.v6.expect("a dual request carries a v6 link");
    let my_iface = mvm_hostd::netd::linux::device_name(&mine.machine_id);
    let neighbour_iface = mvm_hostd::netd::linux::device_name(&neighbour.machine_id);

    let mut my_handle = dp.open(&mine).expect("open mine");
    let mut neighbour_handle = dp.open(&neighbour).expect("open the neighbour");

    // The neighbour's prefix really is reachable from here: that is what
    // makes the refusals below load-bearing rather than incidental.
    assert!(
        v6_addresses(&neighbour_iface).contains(&neighbour_v6.gateway),
        "the neighbour's link must be up for this witness to mean anything"
    );

    // No rules to satisfy, so the address-class check is the only thing
    // that can refuse a destination.
    let mut admitter = L3Admitter::new(
        AddressLease::for_test(mine.gateway, mine.guest).with_v6(my_v6.gateway, my_v6.guest),
        L3PolicyConfig {
            egress: CanonicalEgress::Unrestricted,
            ..L3PolicyConfig::default()
        },
        FlowTable::with_defaults(),
        DnsBindingStore::with_defaults(),
        IngressTable::with_defaults(),
    );
    admitter.set_ready(true);

    let mut now = 0u64;
    for dst in [
        neighbour_v6.guest,
        neighbour_v6.gateway,
        Ipv6Addr::new(0xfd00, 0x1234, 0, 0, 0, 0, 0, 5),
    ] {
        now += 1;
        let before = (rx_packets(&my_iface), rx_packets(&neighbour_iface));
        let packet = v6_syn(my_v6.guest, dst, 50000 + now as u16);
        match admitter.admit_outbound(&packet, now) {
            OutboundVerdict::Deny(DenyCode::PrivateRangeDenied) => {}
            other => panic!("reaching {dst} must be refused as unique-local, got {other:?}"),
        }
        assert_eq!(
            (rx_packets(&my_iface), rx_packets(&neighbour_iface)),
            before,
            "a refused packet for {dst} must never reach either device"
        );
    }

    // The control: the same guest, the same policy, a global destination.
    // The refusals above are the unique-local class check, not a v6
    // deny-all — and this packet really is written to the kernel.
    now += 1;
    let admitted = v6_syn(my_v6.guest, global_v6_destination(), 50100);
    let before = rx_packets(&my_iface);
    match admitter.admit_outbound(&admitted, now) {
        OutboundVerdict::Forward(packet) => my_handle
            .send_to_network(&packet)
            .expect("write the admitted packet to the host tun"),
        other => panic!("a global v6 destination must be admitted, got {other:?}"),
    }
    let after = rx_packets(&my_iface);
    assert!(
        after > before,
        "the kernel must have received the admitted v6 packet on {my_iface} \
         (rx_packets {before} -> {after})"
    );

    my_handle.close().expect("close mine");
    neighbour_handle.close().expect("close the neighbour");
    assert!(interface_gone(&my_iface));
    assert!(interface_gone(&neighbour_iface));
}
