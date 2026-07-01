//! Live proof that `WorkloadRunner` — the driver-generic workload start over the
//! `VmmDriver` seam — boots a real guest with claim-10 egress enforced by the
//! host endpoint. This exercises the ADR-102 core path (spawn the gating endpoint
//! → map the config to a `VmmSpec` → `InHouseDriver::boot`), which is distinct
//! from `HvfBackend`'s inline start and is what will replace it.
//!
//! Boots the initramfs echo guest with an allow-list policy that admits a
//! discovered LAN destination, and asserts the guest reached it over vsock — the
//! endpoint (spawned by the runner) gated + proxied, the run loop only relayed.
//! macOS / Apple silicon. Build the aux bins + guest first (see hvf-relay-egress).

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn discover_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    use std::net::Ipv4Addr;
    // SAFETY: standard getifaddrs walk; every pointer is null-checked and the list
    // is freed before return.
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use mvm_backend::driver::InHouseDriver;
    use mvm_backend::workload_runner::{RealEndpointSpawner, WorkloadRunner};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::vm_backend::{VmBackend, VmStartConfig, VmStatus};

    let lan = discover_lan_ipv4().expect(
        "no private non-loopback IPv4 interface — this proof needs a routable LAN address \
         (loopback is mandatory-deny by design)",
    );
    let kernel = std::env::var("MVM_HVF_KERNEL")
        .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image-builder".into());
    let initramfs = std::env::var("MVM_HVF_INITRD")
        .unwrap_or_else(|_| "/tmp/hvf-egress-guest/initramfs.cpio".into());

    // Echo server on the discovered LAN address, ephemeral port. Self-terminating.
    let listener = TcpListener::bind((lan, 0)).expect("bind echo server");
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().expect("echo local_addr");
    let echo = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(12);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut c, _)) => {
                    c.set_nonblocking(false).ok();
                    let mut buf = [0u8; 64];
                    if let Ok(n) = c.read(&mut buf) {
                        let _ = c.write_all(&buf[..n]);
                    }
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(_) => return,
            }
        }
    });

    let name = "hvf-workload-runner-demo";
    // The guest reads its egress target from the cmdline; bound the run.
    // SAFETY: single-threaded example setup.
    unsafe {
        std::env::set_var(
            "MVM_HVF_BOOTARGS_EXTRA",
            format!("mvm.egress_target={}:{}", addr.ip(), addr.port()),
        );
        std::env::set_var("MVM_HVF_TIMEOUT", "8");
    }

    // No rootfs disk — the echo guest is initramfs-only. Drive the full VmBackend
    // surface (start → status → logs → stop), so this proves WorkloadRunner AS the
    // workload backend, not just its start helper.
    let policy = NetworkPolicy::allow_list(vec![HostPort::new(lan.to_string(), addr.port())]);
    let config = VmStartConfig {
        name: name.into(),
        kernel_path: Some(kernel),
        initrd_path: Some(initramfs),
        network_policy: policy,
        ..Default::default()
    };

    let backend = WorkloadRunner::new(InHouseDriver::new(), RealEndpointSpawner);
    let id = backend
        .start(&config)
        .expect("WorkloadRunner starts the in-house VM");

    for _ in 0..150 {
        if backend.status(&id).unwrap() == VmStatus::Stopped {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = echo.join();

    let console = backend.logs(&id, 0, false).unwrap_or_default();
    let _ = backend.stop(&id);
    let reachable = console.contains("egress reply over vsock: ping");
    println!("WorkloadRunner: admitted destination reachable: {reachable}");
    if reachable {
        println!(
            "PROOF: WorkloadRunner (the driver-seam workload path) booted the guest, spawned the \
             gating endpoint, and the guest reached the admitted LAN destination over vsock — \
             claim-10 enforced by the endpoint, the run loop a pure relay."
        );
    } else {
        eprintln!("FAILED: no egress reply. console:\n{console}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    println!("hvf-workload-runner: only on macOS / Apple silicon");
}
