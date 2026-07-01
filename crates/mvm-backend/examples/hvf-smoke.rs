//! Runnable proof of the raw-HVF guest-RAM-mapping + minimal-boot primitive.
//!
//! Build, codesign with the hypervisor entitlement, then run:
//! ```sh
//! cargo build -p mvm-backend --example hvf-smoke
//! codesign --sign - --force \
//!   --entitlements <(printf '%s' \
//!     '<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>') \
//!   target/debug/examples/hvf-smoke
//! ./target/debug/examples/hvf-smoke
//! ```
//! Without the entitlement `hv_vm_create` fails and the example exits nonzero.

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf::{MAGIC, boot_smoke};
        match boot_smoke() {
            Ok(p) => {
                println!(
                    "HVF boot OK: x0={:#x} data@0x1000={:#x} exit_reason={} syndrome={:#x}",
                    p.x0, p.data_word, p.exit_reason, p.syndrome
                );
                assert_eq!(p.x0, MAGIC, "guest register did not hold the magic value");
                assert_eq!(
                    p.data_word, MAGIC,
                    "guest did not write magic to mapped RAM"
                );
                println!(
                    "PROOF: guest executed from mapped RWX RAM, wrote to mapped RW RAM, \
                     and its register/exit state is host-observable."
                );
            }
            Err(e) => {
                eprintln!("HVF boot FAILED: {e:?}");
                eprintln!(
                    "(if this is VmCreate(..), the binary lacks the \
                     com.apple.security.hypervisor entitlement — codesign it first)"
                );
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-smoke: only supported on macOS / Apple silicon");
}
