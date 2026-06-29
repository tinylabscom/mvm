//! Boot a real arm64 Linux kernel under HVF and print its earlycon output.
//!
//! ```sh
//! cargo build -p mvm-backend --example hvf-kernel-boot
//! codesign --sign - --force \
//!   --entitlements <(printf '%s' \
//!     '<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>') \
//!   target/debug/examples/hvf-kernel-boot
//! ./target/debug/examples/hvf-kernel-boot [path-to-arm64-Image]
//! ```
//! Kernel path: argv[1], else $MVM_HVF_KERNEL, else /tmp/mvm-hvf-kernel/Image.

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use std::time::Duration;

        let path = std::env::args().nth(1).unwrap_or_else(|| {
            std::env::var("MVM_HVF_KERNEL")
                .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image".to_string())
        });
        let image = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("could not read kernel {path}: {e}");
                std::process::exit(2);
            }
        };
        println!("booting {} ({} bytes) under HVF…", path, image.len());

        match mvm_backend::hvf::boot_kernel(&image, Duration::from_secs(3)) {
            Ok(r) => {
                println!("---- guest earlycon ----");
                print!("{}", String::from_utf8_lossy(&r.console));
                println!("\n---- end ----");
                println!(
                    "exit_reason={} watchdog={} console_bytes={}",
                    r.exit_reason,
                    r.stopped_by_watchdog,
                    r.console.len()
                );
                println!(
                    "diag: data_aborts={} mmio_writes={} hvc_calls={} other_exc={} final_pc={:#x}",
                    r.data_aborts, r.mmio_writes, r.hvc_calls, r.other_exceptions, r.final_pc
                );
                println!(
                    "diag: psci_fns={:#x?} other_ecs={:#x?}",
                    r.psci_fns, r.other_ecs
                );
                println!("diag: fault_addrs={:#x?}", r.fault_addrs);
                if r.console.is_empty() {
                    eprintln!("no console output captured");
                    std::process::exit(1);
                }
                println!("PROOF: a real arm64 Linux kernel executed under HVF and printed.");
            }
            Err(e) => {
                eprintln!("kernel boot failed: {e:?}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-kernel-boot: only supported on macOS / Apple silicon");
}
