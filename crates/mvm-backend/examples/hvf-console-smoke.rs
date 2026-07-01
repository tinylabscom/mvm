//! Runnable proof of the HVF MMIO trap-and-emulate + emulated PL011 console.
//!
//! Build, codesign with the hypervisor entitlement, then run:
//! ```sh
//! cargo build -p mvm-backend --example hvf-console-smoke
//! codesign --sign - --force \
//!   --entitlements <(printf '%s' \
//!     '<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>') \
//!   target/debug/examples/hvf-console-smoke
//! ./target/debug/examples/hvf-console-smoke
//! ```

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf::console_smoke;
        match console_smoke() {
            Ok(p) => {
                println!(
                    "HVF console OK: output={:?} mmio_writes={} exit_reason={}",
                    String::from_utf8_lossy(&p.output),
                    p.mmio_writes,
                    p.exit_reason
                );
                assert_eq!(p.output, b"OK\n", "guest console output mismatch");
                assert_eq!(p.mmio_writes, 3, "expected three UART data writes");
                println!(
                    "PROOF: guest stores trapped as MMIO, were decoded from the ESR and \
                     dispatched to an emulated PL011, and the host captured the bytes."
                );
            }
            Err(e) => {
                eprintln!("HVF console FAILED: {e:?}");
                eprintln!("(VmCreate(..) means the binary lacks com.apple.security.hypervisor)");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-console-smoke: only supported on macOS / Apple silicon");
}
