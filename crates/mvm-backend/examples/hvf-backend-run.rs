//! Drive the HVF `VmBackend` lifecycle end to end: `start` (spawns the detached
//! `mvm-hvf-supervisor`), `status`, `list`, `logs`, `stop`. macOS / Apple-silicon.
//!
//! ```sh
//! cargo build -p mvm-backend --bin mvm-hvf-supervisor --example hvf-backend-run
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor MVM_HVF_TIMEOUT=5 \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-init/initramfs.cpio \
//!   MVM_HVF_DISK=/tmp/hvf-init/disk.bin \
//!   ./target/debug/examples/hvf-backend-run
//! ```

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf_backend::HvfBackend;
        use mvm_core::vm_backend::{VmBackend, VmStartConfig, VmStatus};
        use std::time::Duration;

        let backend = HvfBackend;
        let cfg = VmStartConfig {
            name: "hvf-backend-demo".to_string(),
            kernel_path: Some(
                std::env::var("MVM_HVF_KERNEL")
                    .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image".into()),
            ),
            initrd_path: std::env::var("MVM_HVF_INITRD").ok(),
            rootfs_path: std::env::var("MVM_HVF_DISK").unwrap_or_default(),
            ..Default::default()
        };

        let id = backend.start(&cfg).expect("HvfBackend::start");
        println!("started: {id:?}");
        println!("status after start: {:?}", backend.status(&id).unwrap());
        println!(
            "list: {:?}",
            backend
                .list()
                .unwrap()
                .iter()
                .map(|v| &v.name)
                .collect::<Vec<_>>()
        );

        // Bounded run: wait for the supervisor to finish (it flushes console.log
        // and drops its PID file on exit), then read the captured console.
        for _ in 0..120 {
            if backend.status(&id).unwrap() == VmStatus::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let logs = backend.logs(&id, 0, false).unwrap_or_default();
        let userspace = logs.contains("USERSPACE REACHED");
        println!("status after run: {:?}", backend.status(&id).unwrap());
        println!(
            "console bytes: {}, userspace reached: {userspace}",
            logs.len()
        );
        backend.stop(&id).expect("stop");
        println!("status after stop: {:?}", backend.status(&id).unwrap());
        if userspace {
            println!(
                "PROOF: HvfBackend started a guest to userspace (PID 1) via the detached \
                 mvm-hvf-supervisor, observed it via status/logs, and stopped it."
            );
        } else {
            eprintln!("no userspace marker in console; logs:\n{logs}");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-backend-run: only on macOS / Apple silicon");
}
