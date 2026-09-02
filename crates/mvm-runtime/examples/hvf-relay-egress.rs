//! Live proof that claim-10 egress is enforced by the host-side endpoint — not the
//! guest run loop — on the hvf VMM.
//!
//! Boots the echo guest through `HvfDriver` with its `EGRESS_PORT` relayed to a
//! per-VM `mvm-network-endpoint` that carries the resolved `NetworkPolicy`.
//! The run loop is a pure relay (no in-loop gate); the endpoint gates. Runs twice
//! against a discovered LAN echo server: once with a policy that admits it (reply
//! expected) and once with a policy that admits only a different port (reply
//! refused). Both verdicts must hold, proving the gate discriminates by policy
//! from its new home in the endpoint.
//!
//! macOS / Apple silicon. The per-VM aux bins must be built first:
//! ```sh
//! cargo build -p mvm-hostd --bin mvm-hvf-supervisor
//! cargo build -p mvm-hostd --bin mvm-network-endpoint
//! OUT=/tmp/hvf-egress-guest bash crates/mvm-runtime/examples/hvf-egress-guest/build.sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_SUBSTITUTION_ENDPOINT_PATH=target/debug/mvm-network-endpoint \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-egress-guest/initramfs.cpio \
//!   cargo run -p mvm-runtime --example hvf-relay-egress
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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use mvm_core::config::vm_state_dir;
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::vm_backend::VmStatus;
    use mvm_net::channel::GuestService;
    use mvm_runtime::driver::HvfDriver;
    use mvm_runtime::driver::{
        ConsoleCapture, KernelImage, VmmDriver, VmmSpec, VsockDirection, VsockPort,
    };

    fn endpoint_bin() -> PathBuf {
        std::env::var("MVM_SUBSTITUTION_ENDPOINT_PATH")
            .unwrap_or_else(|_| "target/debug/mvm-network-endpoint".into())
            .into()
    }

    // Spawn the per-VM endpoint bound at `uds`, gating raw egress against `policy`.
    // Blocks until the endpoint prints its ready handshake line (it is listening by
    // then). The child is returned so the caller keeps it alive + reaps it.
    fn spawn_endpoint(uds: &std::path::Path, policy: &NetworkPolicy) -> Child {
        let cfg = serde_json::json!({
            "tenant_id": "local",
            "secrets": [],
            "transport": { "kind": "uds", "path": uds },
            "network_policy": policy,
            "egress_mode": "raw",
        });
        let mut child = Command::new(endpoint_bin())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn mvm-network-endpoint");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(cfg.to_string().as_bytes())
            .expect("write endpoint config");
        // One handshake line on stdout = bound + listening.
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("read endpoint handshake");
        child
    }

    // One run: bind a LAN echo server, gate it with `policy`, boot the guest with
    // its egress relayed to the endpoint, and report whether the guest received the
    // proxied echo. `name` must be unique per run so the state dirs don't collide.
    fn run_once(
        name: &str,
        kernel: &str,
        initramfs: &str,
        lan: std::net::Ipv4Addr,
        policy_for: impl Fn(u16) -> NetworkPolicy,
    ) -> (bool, String) {
        let listener = TcpListener::bind((lan, 0)).expect("bind echo server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking echo listener");
        let addr = listener.local_addr().expect("echo local_addr");
        // Self-terminating: a refused run never connects here, so accept must not
        // block forever — poll with a deadline, echo once if a connection lands.
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
        let uds = state_dir.join("egress-endpoint.sock");
        let _ = std::fs::remove_file(&uds);
        let mut endpoint = spawn_endpoint(&uds, &policy_for(addr.port()));

        // The guest reads its target from the cmdline; bound the run and end it via
        // the workload-exit report (or the timeout backstop for the refused case).
        // SAFETY: single-threaded example setup.
        unsafe {
            std::env::set_var("MVM_HVF_KERNEL", kernel);
            std::env::set_var(
                "MVM_HVF_BOOTARGS_EXTRA",
                format!("mvm.egress_target={}:{}", addr.ip(), addr.port()),
            );
            std::env::set_var("MVM_HVF_TIMEOUT", "8");
        }

        let spec = VmmSpec {
            builder_egress_endpoint: None,
            name: name.to_string(),
            kernel: KernelImage::Path(kernel.into()),
            initramfs: Some(initramfs.into()),
            cmdline: String::new(),
            vcpus: 1,
            cpu_grant: None,
            memory_mib: 512,
            mem_initial_mib: None,
            blocks: vec![],
            shares: vec![],
            // The one channel off the box: the guest dials EGRESS_PORT, the host
            // relays it to the gating endpoint's UDS.
            vsock: vec![VsockPort {
                service: GuestService::NetworkFlow,
                host_uds: uds.clone(),
                direction: VsockDirection::GuestDials,
            }],
            console: ConsoleCapture {
                log_path: state_dir.join("console.log"),
            },
            trusted_builder: false,
            plan_binding: None,
        };

        let driver = HvfDriver::new();
        let vm = driver.boot(&spec).expect("boot hvf VM");
        for _ in 0..150 {
            if vm.status().unwrap() == VmStatus::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = echo.join();
        let _ = endpoint.kill();
        let _ = endpoint.wait(); // reap the endpoint so it doesn't linger as a zombie

        let console = std::fs::read_to_string(state_dir.join("console.log")).unwrap_or_default();
        let reachable = console.contains("egress reply over vsock: ping");
        (reachable, console)
    }

    let _ = Instant::now();
    let lan = discover_lan_ipv4().expect(
        "no private non-loopback IPv4 interface — this proof needs a routable LAN address \
         (loopback is mandatory-deny by design)",
    );
    let kernel = std::env::var("MVM_HVF_KERNEL")
        .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image-builder".into());
    let initramfs = std::env::var("MVM_HVF_INITRD")
        .unwrap_or_else(|_| "/tmp/hvf-egress-guest/initramfs.cpio".into());

    // Admit run: the policy admits exactly the echo destination → reachable.
    let (admit_ok, admit_console) =
        run_once("hvf-relay-egress-admit", &kernel, &initramfs, lan, |port| {
            NetworkPolicy::allow_list(vec![HostPort::new(lan.to_string(), port)])
        });
    // Deny run: the policy admits only a DIFFERENT port, so the real target is not
    // admitted → refused. Proves the endpoint gate discriminates by policy.
    let (deny_reachable, deny_console) =
        run_once("hvf-relay-egress-deny", &kernel, &initramfs, lan, |port| {
            NetworkPolicy::allow_list(vec![HostPort::new(lan.to_string(), port.wrapping_add(1))])
        });

    println!("admitted destination reachable: {admit_ok}");
    println!("non-admitted destination reachable: {deny_reachable}");

    if admit_ok && !deny_reachable {
        println!(
            "PROOF: with the claim-10 gate now in the host endpoint (the run loop is a pure \
             relay), the hvf VMM guest reached the admitted LAN destination over vsock and \
             was refused the non-admitted one — enforcement preserved, no guest NIC."
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
    println!("hvf-relay-egress: only on macOS / Apple silicon");
}
