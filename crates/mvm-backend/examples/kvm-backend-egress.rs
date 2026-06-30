//! Boot an x86_64 Linux guest under the mvm KVM backend with **vsock-only egress**
//!  — no guest NIC. Proves the Linux in-house path: the guest reaches the
//! network only by opening a vsock stream to the host egress gateway, which decides
//! each target against the claim-10 policy and proxies admitted flows. Same run
//! loop + `EgressProxy` the HVF backend uses.
//!
//! Linux / x86_64 + `/dev/kvm` only.
//!
//! ```sh
//! MVM_KVM_KERNEL=/path/bzImage MVM_KVM_INITRD=/path/egress-init.cpio \
//! MVM_KVM_EGRESS_ALLOW=192.168.1.10:9099 \
//! cargo run -p mvm-backend --example kvm-backend-egress
//! ```
//! The guest init connects vsock → egress port, writes `"<host>:<port>\n"` then
//! `"ping"`, and reads the proxied echo. A local echo server is started at the
//! admitted destination so the round-trip is self-contained.

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use mvm_backend::kvm::{KvmVm, vm::vsock_mmio_cmdline_arg, x86_boot};
        use mvm_backend::vmm::egress_gate::EgressGate;
        use mvm_backend::vmm::hv::{HypervisorVm, prot};
        use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
        use std::io::{Read, Write};
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        static STOP: AtomicBool = AtomicBool::new(false);

        let kernel = std::env::var("MVM_KVM_KERNEL").expect("MVM_KVM_KERNEL");
        let bz = std::fs::read(&kernel).expect("read kernel");
        let initrd = std::env::var("MVM_KVM_INITRD")
            .ok()
            .map(|p| std::fs::read(p).expect("read initrd"));

        // Admitted destination from MVM_KVM_EGRESS_ALLOW=ip:port (default-deny
        // otherwise). A self-contained loopback-of-LAN echo server runs there.
        let allow = std::env::var("MVM_KVM_EGRESS_ALLOW").ok();
        let gate = match &allow {
            Some(hostport) => {
                let addr: std::net::SocketAddr = hostport.parse().expect("ip:port");
                let cidr = format!("{}/32", addr.ip());
                EgressGate::new(CanonicalEgress::Rules(vec![CanonicalRule {
                    proto: Proto::Tcp,
                    net: cidr.parse().unwrap(),
                    port_lo: addr.port(),
                    port_hi: addr.port(),
                }]))
            }
            None => EgressGate::default_deny(),
        };

        // One-shot echo server at the admitted destination.
        if let Some(hostport) = allow.clone() {
            let listener = std::net::TcpListener::bind(&hostport).expect("bind echo server");
            std::thread::spawn(move || {
                if let Ok((mut sock, _)) = listener.accept() {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = sock.read(&mut buf) {
                        let _ = sock.write_all(&buf[..n]);
                    }
                }
            });
        }

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
        // SAFETY: `mem` stays mapped for the VM's lifetime (process lifetime here).
        unsafe {
            vm.map_ram(mem.as_mut_ptr(), 0, MEM, prot::RWX)
                .expect("map_ram");
        }

        // No NIC — only the vsock virtio-mmio device (claim-10 egress rides it).
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

        let result = vm
            .boot_with_egress(mem, &cfg, Duration::from_secs(20), gate, &STOP)
            .expect("boot");

        print!("{}", String::from_utf8_lossy(&result.console));
        eprintln!("\n---- {} console bytes ----", result.console.len());
        eprintln!("egress allowed: {:?}", result.egress_allowed);
        eprintln!("egress denied:  {:?}", result.egress_denied);
        eprintln!("workload exit:  {:?}", result.workload_exit_code);
        // The proof is host-side truth: the gate admitted + opened the target
        // (egress_allowed), not a console substring. A clean round-trip also
        // reports workload_exit == Some(0) from the guest.
        let proxied = result
            .egress_allowed
            .iter()
            .any(|t| Some(t) == allow.as_ref());
        if proxied {
            eprintln!(
                "PROOF: x86_64 KVM guest reached {} over vsock with NO NIC — claim-10 \
                 gate admitted + proxied (same EgressProxy as HVF).",
                allow.as_deref().unwrap_or("?")
            );
        } else {
            eprintln!("no proxied egress observed (egress_allowed empty)");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    println!("kvm-backend-egress: only supported on linux / x86_64");
}
