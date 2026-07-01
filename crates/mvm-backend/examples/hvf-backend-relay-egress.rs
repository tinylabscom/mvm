//! Live proof that claim-10 egress is enforced through the *production*
//! `HvfBackend` when it is routed onto the relay path (`MVM_HVF_EGRESS_RELAY=1`):
//! the backend spawns the per-VM `mvm-substitution-endpoint` itself, threads its
//! UDS into the guest's `EGRESS_PORT`, and boots via `InHouseDriver`. The run
//! loop is a pure relay; the endpoint gates.
//!
//! Sibling to `hvf-relay-egress`, but entered through `HvfBackend::start` (not
//! the driver directly) so it exercises the real backend routing + the
//! `RealEndpointSpawner`, not a hand-wired harness. Runs twice against a
//! discovered LAN echo server: once with a policy that admits it (reply expected)
//! and once with a policy that admits only a different port (reply refused). Both
//! verdicts must hold.
//!
//! macOS / Apple silicon. Build the per-VM aux bins and echo guest first:
//! ```sh
//! cargo build -p mvm-vm-host --bin mvm-hvf-supervisor
//! cargo build -p mvm-hostd --bin mvm-substitution-endpoint
//! OUT=/tmp/hvf-egress-guest bash crates/mvm-backend/examples/hvf-egress-guest/build.sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_SUBSTITUTION_ENDPOINT_PATH=target/debug/mvm-substitution-endpoint \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-egress-guest/initramfs.cpio \
//!   cargo run -p mvm-backend --example hvf-backend-relay-egress
//! ```

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
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    use mvm_backend::hvf_backend::HvfBackend;
    use mvm_core::config::vm_state_dir;
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::vm_backend::{VmBackend, VmStartConfig, VmStatus};

    // Route the production backend onto the relay egress path for the whole run.
    // SAFETY: single-threaded example setup.
    unsafe { std::env::set_var("MVM_HVF_EGRESS_RELAY", "1") };

    // One run: bind a LAN echo server, gate it with `policy`, start the guest
    // through HvfBackend with its egress relayed to the endpoint, and report
    // whether the guest received the proxied echo. `name` must be unique per run.
    fn run_once(
        name: &str,
        kernel: &str,
        initramfs: &str,
        lan: std::net::Ipv4Addr,
        policy_for: impl Fn(u16) -> NetworkPolicy,
    ) -> (bool, String) {
        use std::io::{Read as _, Write as _};

        let listener = TcpListener::bind((lan, 0)).expect("bind echo server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking echo listener");
        let addr = listener.local_addr().expect("echo local_addr");
        // Self-terminating: a refused run never connects, so accept must not block
        // forever — poll with a deadline, echo once if a connection lands.
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

        let state_dir = vm_state_dir(name);
        let _ = std::fs::create_dir_all(&state_dir);
        // No admitted plan on disk → the relay path takes the raw egress branch and
        // gates on the config's network_policy. Drop any stale plan from a prior run.
        let _ = std::fs::remove_file(state_dir.join("plan.json"));

        // The guest reads its target from the cmdline; bound the run and end it via
        // the workload-exit report (or the timeout backstop for the refused case).
        // SAFETY: single-threaded example setup.
        unsafe {
            std::env::set_var("MVM_HVF_KERNEL", kernel);
            std::env::set_var("MVM_HVF_INITRD", initramfs);
            std::env::set_var(
                "MVM_HVF_BOOTARGS_EXTRA",
                format!("mvm.egress_target={}:{}", addr.ip(), addr.port()),
            );
            std::env::set_var("MVM_HVF_TIMEOUT", "8");
        }

        // Initramfs-only echo guest: no rootfs (rootfs_path empty). The backend
        // spawns the gating endpoint itself and relays EGRESS_PORT to it.
        let config = VmStartConfig {
            name: name.to_string(),
            rootfs_path: String::new(),
            kernel_path: Some(kernel.to_string()),
            initrd_path: Some(initramfs.to_string()),
            cpus: 1,
            memory_mib: 512,
            network_policy: policy_for(addr.port()),
            ..Default::default()
        };

        let backend = HvfBackend;
        let id = backend
            .start(&config)
            .expect("HvfBackend::start (relay) boots");
        for _ in 0..150 {
            if backend.status(&id).unwrap() == VmStatus::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = echo.join();
        // Reap the supervisor + the endpoint (stop owns endpoint teardown).
        let _ = backend.stop(&id);

        let console = std::fs::read_to_string(state_dir.join("console.log")).unwrap_or_default();
        let reachable = console.contains("egress reply over vsock: ping");
        (reachable, console)
    }

    let lan = discover_lan_ipv4().expect(
        "no private non-loopback IPv4 interface — this proof needs a routable LAN address \
         (loopback is mandatory-deny by design)",
    );
    let kernel = std::env::var("MVM_HVF_KERNEL")
        .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image-builder".into());
    let initramfs = std::env::var("MVM_HVF_INITRD")
        .unwrap_or_else(|_| "/tmp/hvf-egress-guest/initramfs.cpio".into());

    // Admit run: the policy admits exactly the echo destination → reachable.
    let (admit_ok, admit_console) = run_once(
        "hvf-backend-relay-admit",
        &kernel,
        &initramfs,
        lan,
        |port| NetworkPolicy::allow_list(vec![HostPort::new(lan.to_string(), port)]),
    );
    // Deny run: the policy admits only a DIFFERENT port, so the real target is not
    // admitted → refused. Proves the endpoint gate discriminates by policy.
    let (deny_reachable, deny_console) =
        run_once("hvf-backend-relay-deny", &kernel, &initramfs, lan, |port| {
            NetworkPolicy::allow_list(vec![HostPort::new(lan.to_string(), port.wrapping_add(1))])
        });

    println!("admitted destination reachable: {admit_ok}");
    println!("non-admitted destination reachable: {deny_reachable}");

    if admit_ok && !deny_reachable {
        println!(
            "PROOF: routed through the production HvfBackend relay path, the in-house VMM guest \
             reached the admitted LAN destination over vsock and was refused the non-admitted \
             one — the host endpoint enforces claim-10, no guest NIC, no in-loop gate."
        );
    } else {
        eprintln!("FAILED: admit_ok={admit_ok} deny_reachable={deny_reachable}");
        eprintln!("--- admit console ---\n{admit_console}");
        eprintln!("--- deny console ---\n{deny_console}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    println!("hvf-backend-relay-egress: only on macOS / Apple silicon");
}
