//! `mvm-guest-netd` — guest-side packet-tunnel worker.
//!
//! Spawned as a long-lived helper when the shared `mvm.network_tunnel=`
//! cmdline token is present. Owns the guest TUN device plus the backend-agnostic
//! tunnel session for the VM lifetime.

#[cfg(target_os = "linux")]
fn main() {
    use mvm_agentd::guest_tun::PacketDevice;

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let Some(mut tunnel) =
        mvm_agentd::network_tunnel::bootstrap_from_cmdline(&cmdline, "mvm-guest-netd/1", 10, 1)
            .unwrap_or_else(|e| {
                eprintln!("mvm-guest-netd: bootstrap failed: {e}");
                std::process::exit(1);
            })
    else {
        eprintln!("mvm-guest-netd: no tunnel runtime config present; exiting");
        return;
    };

    let mut tun = tunnel.prepare_tun_device().unwrap_or_else(|e| {
        eprintln!("mvm-guest-netd: prepare TUN device failed: {e}");
        std::process::exit(1);
    });

    eprintln!(
        "mvm-guest-netd: tunnel up on {} port {}",
        tun.interface_name(),
        tunnel.runtime_config.guest_port
    );

    if let Err(e) = tunnel.run_blocking_packet_loop(&mut tun, 1, 2) {
        eprintln!("mvm-guest-netd: packet loop failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mvm-guest-netd is Linux-only");
    std::process::exit(2);
}
