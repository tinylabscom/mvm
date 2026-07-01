//! Prove the HVF backend's *transient* (default) lifecycle: start a workload VM,
//! and `wait` returns the workload's exit code (reported by the guest over the
//! workload-exit vsock port — VM life = workload life). macOS / Apple-silicon.
//!
//! The demo guest exits 42, so `wait` must return code 42.
//!
//! ```sh
//! MVM_HVF_SUPERVISOR_PATH=target/debug/mvm-hvf-supervisor \
//!   MVM_HVF_KERNEL=/tmp/mvm-hvf-kernel/Image-builder \
//!   MVM_HVF_INITRD=/tmp/hvf-init-transient/initramfs.cpio \
//!   ./target/debug/examples/hvf-backend-transient
//! ```

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use mvm_backend::hvf_backend::HvfBackend;
        use mvm_core::vm_backend::{VmBackend, VmStartConfig};

        // SAFETY: single-threaded; no bounded timeout — the workload ends the VM.
        unsafe { std::env::remove_var("MVM_HVF_TIMEOUT") };

        let backend = HvfBackend;
        let cfg = VmStartConfig {
            name: "hvf-transient-demo".to_string(),
            kernel_path: Some(
                std::env::var("MVM_HVF_KERNEL")
                    .unwrap_or_else(|_| "/tmp/mvm-hvf-kernel/Image".into()),
            ),
            initrd_path: std::env::var("MVM_HVF_INITRD").ok(),
            ..Default::default()
        };

        let id = backend.start(&cfg).expect("start transient");
        println!("started transient: {id:?}");

        // Default transient: block until the workload exits, returning its code.
        let status = backend.wait(&id).expect("wait");
        println!("wait -> code={:?} success={}", status.code, status.success);
        assert_eq!(
            status.code,
            Some(42),
            "wait must return the workload's exit code"
        );
        assert!(!status.success, "exit code 42 is not success");

        let logs = backend.logs(&id, 0, false).unwrap_or_default();
        println!("console bytes: {}", logs.len());
        println!(
            "PROOF: HvfBackend ran a transient workload to completion; the guest reported \
             exit code 42 over the workload-exit vsock port and wait() returned it \
             (VM life = workload life)."
        );
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    println!("hvf-backend-transient: only on macOS / Apple silicon");
}
