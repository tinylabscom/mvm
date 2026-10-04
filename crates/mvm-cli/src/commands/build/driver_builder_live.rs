//! Live boots of the driver-backed builders from this binary's embedded boot
//! payload. Image resolution and builder construction live in
//! `mvm_runtime::builder_runner`; the payload source is this crate's, so the
//! tests that need both live here.

#[cfg(test)]
mod tests {
    use mvm_runtime::builder_runner::resolve_driver_builder_image;

    /// A builder job on a real HVF builder, booted from the payload: PID 1 runs
    /// from the payload's tmpfs copy and the kernel command line carries the
    /// digest, whatever the image baked. Run on macOS 26+ Apple Silicon after
    /// `mvmctl bootstrap`, from a binary that registered the payload source.
    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[ignore = "live: needs macOS/Apple Silicon and a bootstrapped builder image"]
    fn live_hvf_builder_runs_from_the_boot_payload() {
        use mvm_build::builder_vm::BuilderShellJob;

        mvm_build::builder_boot::register_boot_payload_source(Box::new(
            crate::host_binaries::extract::EmbeddedBootPayload,
        ));
        let image = resolve_driver_builder_image().expect("run `mvmctl bootstrap` first");
        let tmp = tempfile::tempdir().expect("tempdir");
        let work_dir = tmp.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("create work_dir");
        let job = BuilderShellJob {
            work_dir,
            artifact_out: tmp.path().join("out"),
            script: "set -eu\nreadlink /proc/1/exe > /out/pid1.txt\n\
                     cat /proc/cmdline > /out/cmdline.txt\n"
                .to_string(),
            extra_disks: Vec::new(),
        };

        let result = mvm_runtime::builder_runner::DriverBuilderVm::new(
            mvm_backends::driver::hvf::HvfDriver::new(),
            image.kernel,
            image.rootfs,
        )
        .with_closure_nar(image.closure_nar)
        .run_shell_script(&job)
        .expect("HVF builder shell job must succeed");

        let pid1 = std::fs::read_to_string(result.job_dir.join("pid1.txt")).expect("pid1.txt");
        let cmdline =
            std::fs::read_to_string(result.job_dir.join("cmdline.txt")).expect("cmdline.txt");
        assert_eq!(pid1.trim(), "/run/mvm/host-bins/mvm-host-vm-init");
        assert!(cmdline.contains("mvm.boot_payload="), "{cmdline}");
        assert!(!cmdline.contains("init="), "{cmdline}");
    }

    /// The same on the Firecracker builder. Run on a KVM host after
    /// `mvmctl bootstrap`, which auto-detects Firecracker there.
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "live: needs Linux + /dev/kvm and a bootstrapped builder image"]
    fn live_firecracker_builder_runs_a_shell_job() {
        use mvm_build::builder_vm::BuilderShellJob;

        mvm_build::builder_boot::register_boot_payload_source(Box::new(
            crate::host_binaries::extract::EmbeddedBootPayload,
        ));
        let image = resolve_driver_builder_image().expect("run `mvmctl bootstrap` first");
        let tmp = tempfile::tempdir().expect("tempdir");
        let work_dir = tmp.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("create work_dir");
        let job = BuilderShellJob {
            work_dir,
            artifact_out: tmp.path().join("out"),
            script: "set -eu\nuname -m > /out/uname.txt\nreadlink /proc/1/exe > /out/pid1.txt\n"
                .to_string(),
            extra_disks: Vec::new(),
        };

        let result = mvm_runtime::builder_runner::DriverBuilderVm::new(
            mvm_backends::driver::fc::FcDriver::new(),
            image.kernel,
            image.rootfs,
        )
        .with_closure_nar(image.closure_nar)
        .run_shell_script(&job)
        .expect("Firecracker builder shell job must succeed");

        let uname = std::fs::read_to_string(result.job_dir.join("uname.txt"))
            .expect("the guest wrote its artifact");
        assert_eq!(uname.trim(), std::env::consts::ARCH);
        let pid1 = std::fs::read_to_string(result.job_dir.join("pid1.txt")).expect("pid1.txt");
        assert_eq!(pid1.trim(), "/run/mvm/host-bins/mvm-host-vm-init");
    }
}
