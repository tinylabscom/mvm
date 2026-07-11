//! Live host-mechanism witness for the raw-L3 egress forward path.
//!
//! Exercises the real Linux TUN-open + kernel NAT install/teardown without a
//! workload microVM. It creates a host TUN via `/dev/net/tun`, assigns the
//! gateway address, installs the masquerade table, injects a crafted IPv4/UDP
//! packet, asserts the NAT table is present in `nft list ruleset`, and asserts
//! teardown removes it.
//!
//! Skipped by default. Requires both `MVM_TUNNEL_HOST_TUN_LIVE=1` and
//! root/CAP_NET_ADMIN (TUN creation + `ip`/`nft` mutation). Never runs in normal
//! CI: the whole file is Linux-only and returns early with an eprintln when the
//! gate is unset or the process is unprivileged.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::process::Command;

use mvm_core::protocol::network_tunnel::host_tun_nat_table_name;
use mvm_hostd::host_tun::{
    HostTunDevice, PacketDevice, setup_host_tun_egress, teardown_host_tun_egress,
};

const ENABLE_VAR: &str = "MVM_TUNNEL_HOST_TUN_LIVE";

fn live_enabled() -> bool {
    std::env::var(ENABLE_VAR).as_deref() == Ok("1")
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Self-cleaning guard: teardown runs on drop even if an assert panics, so a
/// failed run never leaks a NAT table or a dangling TUN.
struct TunGuard {
    iface: String,
    device: Option<HostTunDevice>,
}

impl TunGuard {
    fn teardown(&mut self) {
        let _ = teardown_host_tun_egress(&self.iface);
        // Drop the fd last: the interface disappears with its owning fd.
        self.device = None;
    }
}

impl Drop for TunGuard {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// The current nftables ruleset text, or an empty string if `nft` is absent.
fn nft_ruleset() -> String {
    Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Compute the standard IPv4 header checksum over `header` (checksum field zero).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A minimal, well-formed IPv4/UDP packet from the guest side of the tunnel /30
/// toward an arbitrary upstream on port 53. The kernel accepts the injection;
/// this exercises the real device write path.
fn crafted_ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let payload: &[u8] = b"mvm-tun-live";
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // IPv4, IHL=5 (no options)
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    // UDP header: src 40000 -> dst 53, length, checksum 0 (optional for IPv4).
    pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[test]
fn host_tun_open_nat_install_inject_and_teardown() {
    if !live_enabled() {
        eprintln!(
            "[host_tun_nat_live] skipped - set {ENABLE_VAR}=1 to run the live host \
             TUN + NAT witness"
        );
        return;
    }
    if !is_root() {
        eprintln!(
            "[host_tun_nat_live] skipped - needs root/CAP_NET_ADMIN to open /dev/net/tun \
             and mutate ip/nft"
        );
        return;
    }

    // Unique, IFNAMSIZ-safe interface name so parallel runs don't collide.
    let iface = format!("mvmhtl{}", std::process::id() % 100_000);
    let table = host_tun_nat_table_name(&iface);

    let device = HostTunDevice::open_named(&iface).expect("open host TUN");
    let mut guard = TunGuard {
        iface: iface.clone(),
        device: Some(device),
    };

    setup_host_tun_egress(&iface).expect("assign gateway addr + install NAT");

    // The scoped masquerade table must now be live in the kernel.
    let installed = nft_ruleset();
    assert!(
        installed.contains(&table),
        "NAT table {table} not found after setup; ruleset:\n{installed}"
    );

    // Inject a crafted guest-origin packet through the real device write path.
    let packet =
        crafted_ipv4_udp_packet(Ipv4Addr::new(10, 240, 0, 2), Ipv4Addr::new(203, 0, 113, 9));
    let written = guard
        .device
        .as_mut()
        .expect("device present")
        .write_packet(&packet)
        .expect("inject packet into host TUN");
    assert_eq!(written, packet.len(), "short write into host TUN");

    // Explicit teardown, then assert the kernel table is gone.
    guard.teardown();
    let after = nft_ruleset();
    assert!(
        !after.contains(&table),
        "NAT table {table} still present after teardown; ruleset:\n{after}"
    );
}
