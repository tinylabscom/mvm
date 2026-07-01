//! Prove the end-to-end policy-driven vsock egress through the HVF backend +
//! supervisor: a VM started with an allow-list `NetworkPolicy` reaches
//! the admitted destination over vsock; the supervisor resolves the host pin,
//! projects the gate, and proxies. macOS / Apple-silicon.
//!
//! Binds a loopback echo server on an ephemeral port and reads its address back
//! — no hardcoded address — so the test is deterministic and offline. The
//! discovered target is admitted by policy and injected into the guest cmdline.
//!
//! ```sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-init-echo/initramfs.cpio \
//!  ./target/debug/examples/hvf-backend-egress
//! ```

/// First non-loopback, non-link-local private IPv4 on this host, discovered via
/// `getifaddrs` — never a literal. The egress proof needs a routable-to-host
/// address the gate can admit; loopback and link-local are mandatory-deny.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn discover_lan_ipv4() -> Option<std::net::Ipv4Addr> {
    use std::net::Ipv4Addr;
    // SAFETY: standard getifaddrs walk; every pointer is null-checked, and the
    // list is freed before return.
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
                // s_addr is network byte order; its in-memory bytes are the octets.
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

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf_backend::HvfBackend;
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::vm_backend::{VmBackend, VmStartConfig, VmStatus};
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        // Bound the run so the demo always terminates (this echo guest doesn't
        // report a workload-exit), then observe via status/logs.
        // SAFETY: single-threaded test setup.
        unsafe { std::env::set_var("MVM_HVF_TIMEOUT", "8") };

        // One-shot echo server on the discovered LAN address, ephemeral port —
        // no hardcoded address. The gate mandatory-denies loopback/link-local, so
        // the proof admits a real routable-to-host address, discovered at runtime.
        let lan = discover_lan_ipv4().expect(
            "no private non-loopback IPv4 interface found — this proof needs a LAN address \
             (loopback is mandatory-deny by design)",
        );
        let listener = TcpListener::bind((lan, 0)).expect("bind echo server");
        let addr = listener.local_addr().expect("echo local_addr");
        let host = addr.ip().to_string();
        let port = addr.port();
        let echo = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = c.read(&mut buf) {
                    let _ = c.write_all(&buf[..n]);
                }
            }
        });

        // Thread the discovered target into the guest via the kernel cmdline; the
        // baked init reads `mvm.egress_target=` from /proc/cmdline. The guest
        // learns the destination at boot rather than baking one in.
        // SAFETY: single-threaded test setup.
        unsafe {
            std::env::set_var(
                "MVM_HVF_BOOTARGS_EXTRA",
                format!("mvm.egress_target={host}:{port}"),
            )
        };

        let backend = HvfBackend;
        let cfg = VmStartConfig {
            name: "hvf-egress-policy-demo".to_string(),
            kernel_path: Some(
                std::env::var("MVM_HVF_KERNEL")
                    .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image".into()),
            ),
            initrd_path: std::env::var("MVM_HVF_INITRD").ok(),
            // Policy-driven: admit exactly the dynamically bound echo destination.
            network_policy: NetworkPolicy::allow_list(vec![HostPort {
                host: host.clone(),
                port,
            }]),
            ..Default::default()
        };

        let id = backend.start(&cfg).expect("start");
        // Poll until the (bounded) supervisor stops, then read the captured console.
        for _ in 0..150 {
            if backend.status(&id).unwrap() == VmStatus::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = echo.join();
        let logs = backend.logs(&id, 0, false).unwrap_or_default();
        let ok = logs.contains("egress reply over vsock: ping");
        println!("policy: allow-list [{host}:{port}] | egress reply received: {ok}");
        if ok {
            println!(
                "PROOF: a VM started with an allow-list NetworkPolicy reached {host}:{port} over \
                 vsock — the supervisor resolved the pin, projected the claim-10 gate, and proxied \
                 the bytes (no guest NIC)."
            );
        } else {
            eprintln!("no proxied reply; console:\n{logs}");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-backend-egress: only on macOS / Apple silicon");
}
