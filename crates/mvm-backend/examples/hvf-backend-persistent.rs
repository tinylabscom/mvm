//! Prove the HVF backend's persistent-until-stop lifecycle: start a VM with no
//! timeout, confirm it is still Running well past when a bounded run would have
//! exited, then `stop` it gracefully (console flushed). macOS / Apple-silicon.
//!
//! ```sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-init/initramfs.cpio \
//!   MVM_HVF_DISK=/tmp/hvf-init/disk.bin \
//!   ./target/debug/examples/hvf-backend-persistent
//! ```
//! Note: MVM_HVF_TIMEOUT is deliberately *unset* so the VM runs until stop.

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf_backend::HvfBackend;
        use mvm_core::vm_backend::{VmBackend, VmStartConfig, VmStatus};
        use std::time::Duration;

        // SAFETY: single-threaded; ensure no bounded timeout so the run is persistent.
        unsafe { std::env::remove_var("MVM_HVF_TIMEOUT") };

        let backend = HvfBackend;
        let cfg = VmStartConfig {
            name: "hvf-persistent-demo".to_string(),
            kernel_path: Some(
                std::env::var("MVM_HVF_KERNEL")
                    .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image".into()),
            ),
            initrd_path: std::env::var("MVM_HVF_INITRD").ok(),
            rootfs_path: std::env::var("MVM_HVF_DISK").unwrap_or_default(),
            ..Default::default()
        };

        let id = backend.start(&cfg).expect("start");
        println!("started persistent: {id:?}");

        // Stay alive well past any bounded-run timeout (the supervisor's bounded
        // default was 30s; a transient demo uses ~5s). 8s of continuous Running
        // proves the run is not timeout-driven.
        for i in 1..=8 {
            std::thread::sleep(Duration::from_secs(1));
            let st = backend.status(&id).unwrap();
            println!("  +{i}s status: {st:?}");
            assert_eq!(
                st,
                VmStatus::Running,
                "persistent VM must stay Running until stopped"
            );
        }

        println!("stopping...");
        backend.stop(&id).expect("stop");
        for _ in 0..50 {
            if backend.status(&id).unwrap() == VmStatus::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(
            backend.status(&id).unwrap(),
            VmStatus::Stopped,
            "stop must end the VM"
        );

        let logs = backend.logs(&id, 0, false).unwrap_or_default();
        let userspace = logs.contains("USERSPACE REACHED");
        println!(
            "after stop: console bytes={}, userspace reached={userspace}",
            logs.len()
        );
        if userspace {
            println!(
                "PROOF: HvfBackend ran a persistent guest (Running for 8s, no timeout), \
                 then stop() ended it gracefully with the console flushed."
            );
        } else {
            eprintln!("graceful-stop console not flushed; logs:\n{logs}");
            std::process::exit(1);
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-backend-persistent: only on macOS / Apple silicon");
}
