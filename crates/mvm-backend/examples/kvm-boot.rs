//! Boot an x86_64 Linux bzImage under KVM via the mvm KVM backend driven by the
//! unified run loop (`mvm_backend::vmm::run`) — the *same* loop body the HVF
//! backend uses, with a 16550 console as the only x86-specific device.
//!
//! Linux / x86_64 + `/dev/kvm` only.
//!
//! ```sh
//! cargo run -p mvm-backend --example kvm-boot -- /boot/vmlinuz-x.y.z
//! MVM_KVM_INITRD=initramfs.cpio cargo run -p mvm-backend --example kvm-boot
//! ```
//! Kernel path: argv[1], else $MVM_KVM_KERNEL, else /boot/vmlinuz.

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        use mvm_backend::kvm::{KvmVm, x86_boot};
        use mvm_backend::vmm::hv::{HypervisorVm, prot};
        use std::time::Duration;

        let path = std::env::args()
            .nth(1)
            .or_else(|| std::env::var("MVM_KVM_KERNEL").ok())
            .unwrap_or_else(|| "/boot/vmlinuz".to_string());
        let bz = std::fs::read(&path).expect("read kernel");
        let initrd = std::env::var("MVM_KVM_INITRD")
            .ok()
            .map(|p| std::fs::read(p).expect("read initrd"));
        eprintln!(
            "booting {} ({} bytes){} under the mvm KVM backend…",
            path,
            bz.len(),
            initrd
                .as_ref()
                .map(|r| format!(" + initramfs ({} bytes)", r.len()))
                .unwrap_or_default()
        );

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

        let cfg = x86_boot::BootConfig {
            mem_size: MEM,
            cmdline: "earlyprintk=serial,ttyS0,115200 console=ttyS0 acpi=off pci=off \
                      reboot=t panic=-1 nokaslr",
            bzimage: &bz,
            initrd: initrd.as_deref(),
        };
        let console = vm
            .boot_to_console(mem, &cfg, Duration::from_secs(30))
            .expect("boot");
        print!("{}", String::from_utf8_lossy(&console));
        eprintln!("\n---- {} console bytes ----", console.len());
        if console.windows(17).any(|w| w == b"USERSPACE REACHED") {
            eprintln!(
                "PROOF: x86_64 Linux booted to userspace (PID 1) under the mvm KVM \
                 backend + unified run loop."
            );
        } else if console.is_empty() {
            eprintln!("no console output captured");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    println!("kvm-boot: only supported on linux / x86_64");
}
