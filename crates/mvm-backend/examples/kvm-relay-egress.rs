//! Prove claim-10 egress on the Linux/KVM in-house path with the gate in the
//! **host endpoint**, not the run loop. The guest's vsock egress port is a pure
//! relay to a per-VM `mvm-substitution-endpoint` carrying the resolved
//! `NetworkPolicy`; the endpoint gates + proxies, the run loop only pipes bytes.
//!
//! Runs the same raw-egress guest as `kvm-backend-egress` (it dials the egress
//! port, writes `"<host>:<port>\n"` then `"ping"`, reads the echo). Two runs
//! against a local echo server at the guest's baked target: a policy that admits
//! it (reply seen) and one that admits a different port (refused — no reply).
//! Linux / x86_64 + `/dev/kvm`.
//!
//! ```sh
//! MVM_KVM_KERNEL=/root/bzImage-thin MVM_KVM_INITRD=/root/guest/initramfs.cpio \
//! MVM_KVM_EGRESS_TARGET=88.99.197.234:9099 \
//! MVM_SUBSTITUTION_ENDPOINT_PATH=target/debug/mvm-substitution-endpoint \
//! cargo run -p mvm-backend --example kvm-relay-egress
//! ```

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use mvm_backend::kvm::{KvmVm, vm::vsock_mmio_cmdline_arg, x86_boot};
    use mvm_backend::vmm::hv::{HypervisorVm, prot};
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

    // The guest's baked egress target (its init dials this host:port). The box's
    // own address, so it is stable and self-contained (not a stale dev IP).
    let target = std::env::var("MVM_KVM_EGRESS_TARGET").expect("MVM_KVM_EGRESS_TARGET=ip:port");
    let addr: std::net::SocketAddr = target.parse().expect("ip:port");
    let kernel = std::env::var("MVM_KVM_KERNEL").expect("MVM_KVM_KERNEL");
    let bz = std::fs::read(&kernel).expect("read kernel");
    let initrd = std::env::var("MVM_KVM_INITRD")
        .ok()
        .map(|p| std::fs::read(p).expect("read initrd"));

    fn endpoint_bin() -> PathBuf {
        std::env::var("MVM_SUBSTITUTION_ENDPOINT_PATH")
            .unwrap_or_else(|_| "target/debug/mvm-substitution-endpoint".into())
            .into()
    }

    // Spawn the per-VM endpoint bound at `uds`, gating raw egress against `policy`.
    // Blocks until the ready handshake line, then returns the child to keep alive.
    fn spawn_endpoint(uds: &Path, policy: &NetworkPolicy) -> Child {
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
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mvm-substitution-endpoint");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(cfg.to_string().as_bytes())
            .expect("write endpoint config");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("read endpoint handshake");
        child
    }

    // One run: bind a self-contained echo at the guest's target, gate with
    // `policy`, boot the guest with egress relayed to the endpoint, and report
    // whether the guest saw the proxied echo (console marker from the init).
    let run_once = |policy: NetworkPolicy| -> bool {
        let listener = TcpListener::bind(addr).expect("bind echo server");
        listener.set_nonblocking(true).unwrap();
        let echo = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(18);
            while std::time::Instant::now() < deadline {
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

        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("egress-endpoint.sock");
        let mut endpoint = spawn_endpoint(&uds, &policy);

        const MEM: usize = 512 << 20;
        // SAFETY: anonymous shared mapping of MEM bytes for guest RAM.
        let mem = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                MEM,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert!(p != libc::MAP_FAILED, "mmap guest RAM");
            std::slice::from_raw_parts_mut(p as *mut u8, MEM)
        };
        let vm = KvmVm::create().expect("create KVM VM");
        // SAFETY: `mem` stays mapped for the VM's lifetime.
        unsafe {
            vm.map_ram(mem.as_mut_ptr(), 0, MEM, prot::RWX)
                .expect("map_ram");
        }
        let cmdline = format!(
            "earlyprintk=serial,ttyS0,115200 console=ttyS0 acpi=off pci=off reboot=t \
             panic=-1 nokaslr {}",
            vsock_mmio_cmdline_arg()
        );
        let cfg = x86_boot::BootConfig {
            mem_size: MEM,
            cmdline: &cmdline,
            bzimage: &bz,
            initrd: initrd.as_deref(),
        };

        static STOP: AtomicBool = AtomicBool::new(false);
        STOP.store(false, std::sync::atomic::Ordering::Relaxed);
        let result = vm
            .boot_with_relay(mem, &cfg, Duration::from_secs(18), &uds, &STOP)
            .expect("boot");
        let _ = echo.join();
        let _ = endpoint.kill();
        let _ = endpoint.wait();
        // SAFETY: unmap the guest RAM.
        unsafe {
            libc::munmap(mem.as_mut_ptr() as *mut libc::c_void, MEM);
        }

        let console = String::from_utf8_lossy(&result.console).into_owned();
        console.contains("reply n=4 data=ping")
    };

    // Admit: the policy admits the guest's exact target → reply seen.
    let admit_ok = run_once(NetworkPolicy::allow_list(vec![HostPort::new(
        addr.ip().to_string(),
        addr.port(),
    )]));
    // Deny: the policy admits only a different port → the endpoint refuses.
    let deny_reachable = run_once(NetworkPolicy::allow_list(vec![HostPort::new(
        addr.ip().to_string(),
        addr.port().wrapping_add(1),
    )]));

    println!("KVM relay: admitted destination reachable: {admit_ok}");
    println!("KVM relay: non-admitted destination reachable: {deny_reachable}");
    if admit_ok && !deny_reachable {
        println!(
            "PROOF: x86_64 KVM guest reached the admitted destination over vsock and was refused \
             the non-admitted one — claim-10 enforced by the host endpoint, the run loop a pure \
             relay (no in-VMM gate, no NIC)."
        );
    } else {
        eprintln!("FAILED: admit_ok={admit_ok} deny_reachable={deny_reachable}");
        std::process::exit(1);
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    println!("kvm-relay-egress: only supported on linux / x86_64");
}
