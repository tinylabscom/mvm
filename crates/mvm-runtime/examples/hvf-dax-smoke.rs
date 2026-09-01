//! Live proof of virtio-fs DAX on the raw-HVF backend.
//!
//! ```sh
//! cargo build -p mvm-runtime --example hvf-dax-smoke
//! codesign --sign - --force \
//!   --entitlements <(printf '%s' \
//!     '<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>') \
//!   target/debug/examples/hvf-dax-smoke
//! MVM_HVF_KERNEL=.mvm-test/cache/kernels/aarch64/builder/vmlinux \
//! MVM_HVF_INITRAMFS=/tmp/hvf-dax-guest/initramfs.cpio \
//! MVM_HVF_VIRTIOFS_ROOT=/tmp/hvf-dax-root \
//!   ./target/debug/examples/hvf-dax-smoke
//! ```

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use std::path::PathBuf;
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        static STOP: AtomicBool = AtomicBool::new(false);

        let kernel = std::env::var("MVM_HVF_KERNEL")
            .unwrap_or_else(|_| ".mvm-test/cache/kernels/aarch64/builder/vmlinux".into());
        let initramfs = std::env::var("MVM_HVF_INITRAMFS")
            .map(|p| std::fs::read(&p).expect("read initramfs"))
            .unwrap_or_else(|_| {
                std::fs::read("/tmp/hvf-dax-guest/initramfs.cpio").expect("default initramfs")
            });
        let virtiofs_root = std::env::var("MVM_HVF_VIRTIOFS_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/hvf-dax-root"));

        println!("booting HVF DAX smoke:");
        println!("  kernel: {kernel}");
        println!("  initramfs: {} bytes", initramfs.len());
        println!("  virtiofs_root: {}", virtiofs_root.display());

        let params = mvm_runtime::backends::hvf::KernelBootUntilParams::builder_file(
            std::path::Path::new(&kernel),
            Duration::from_secs(30),
        )
        .initramfs(Some(&initramfs))
        .channels(mvm_runtime::backends::hvf::HostChannels {
            virtiofs_root: Some(virtiofs_root),
            ..Default::default()
        })
        .stop(&STOP)
        .build();

        match mvm_runtime::backends::hvf::boot_kernel_until(params) {
            Ok(r) => {
                println!("---- guest console ----");
                print!("{}", String::from_utf8_lossy(&r.console));
                println!("---- end ----");
                println!(
                    "exit_reason={} console_bytes={}",
                    r.exit_reason,
                    r.console.len()
                );
                if let Some(code) = r.workload_exit_code {
                    println!("workload exit code: {code}");
                }
                let ok = String::from_utf8_lossy(&r.console)
                    .contains("DAX option present in /proc/mounts");
                if ok {
                    println!("PROOF: virtio-fs DAX negotiated and mounted under HVF.");
                } else {
                    eprintln!("FAIL: DAX option not observed in guest console");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("hvf-dax-smoke failed: {e:?}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-dax-smoke: only supported on macOS / Apple silicon");
}
