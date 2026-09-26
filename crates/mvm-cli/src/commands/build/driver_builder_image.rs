//! The builder image the driver-backed builders (HVF, Firecracker) boot.
//!
//! They boot the builder image exactly as Stage 0 built it or the release
//! fetched it, with nothing baked in: mvm's own builder binaries arrive in the
//! boot payload each boot carries. Resolution goes through
//! `ensure_builder_vm_image`, the same freshness decision the libkrun and QEMU
//! builders take — cache contract, source fingerprint, shared-cache seeding and
//! auto-bootstrap — so no builder backend boots an image the others would
//! refuse.
//!
//! The kernel is passed through unconverted. `FcDriver` normalises it at boot
//! (`ensure_fc_loadable_kernel`), which is the one place that knows what
//! Firecracker can load; HVF boots the arm64 `Image` as is.

use std::path::{Path, PathBuf};

use mvm_build::builder_vm::{BuilderVmError, BuilderVmImage, builder_vm_cache_dir, host_arch_tag};

/// The builder image a driver-backed builder boots: kernel, rootfs, and the
/// seeded Nix store closure when the image carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverBuilderImage {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub closure_nar: Option<PathBuf>,
}

/// Resolve the current builder image for the host architecture.
pub fn resolve_driver_builder_image() -> Result<DriverBuilderImage, BuilderVmError> {
    let image = mvm_build::builder_vm_image::ensure_builder_vm_image()?;
    driver_builder_image_from(&image, &builder_vm_cache_dir().join(host_arch_tag()))
}

/// The driver-builder view of a resolved image. A `RootDir` seed is Stage 0's
/// input, never a bootable builder image.
fn driver_builder_image_from(
    image: &BuilderVmImage,
    arch_dir: &Path,
) -> Result<DriverBuilderImage, BuilderVmError> {
    match image {
        BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path,
            ..
        } => Ok(DriverBuilderImage {
            kernel: kernel_path.clone(),
            rootfs: rootfs_path.clone(),
            closure_nar: mvm_build::builder_pack::closure_nar_path(arch_dir),
        }),
        BuilderVmImage::RootDir { .. } => Err(BuilderVmError::VmmFailed {
            detail: "the builder image cache holds a Stage 0 seed, not a bootable builder \
                     image; run `mvmctl bootstrap`"
                .to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resolved_image_boots_as_is() {
        let dir = tempfile::tempdir().unwrap();
        let image = BuilderVmImage::new(
            dir.path().join("vmlinux"),
            dir.path().join("rootfs.ext4"),
            "console=hvc0".to_string(),
        );

        let resolved = driver_builder_image_from(&image, dir.path()).unwrap();

        assert_eq!(resolved.kernel, dir.path().join("vmlinux"));
        assert_eq!(resolved.rootfs, dir.path().join("rootfs.ext4"));
        assert_eq!(resolved.closure_nar, None);
    }

    #[test]
    fn the_seeded_closure_is_carried_when_the_image_has_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(mvm_build::builder_pack::CLOSURE_FILE), b"x").unwrap();
        let image = BuilderVmImage::new(
            dir.path().join("vmlinux"),
            dir.path().join("rootfs.ext4"),
            String::new(),
        );

        let resolved = driver_builder_image_from(&image, dir.path()).unwrap();

        assert_eq!(
            resolved.closure_nar,
            Some(dir.path().join(mvm_build::builder_pack::CLOSURE_FILE))
        );
    }

    #[test]
    fn a_stage0_seed_is_not_a_builder_image() {
        let image = BuilderVmImage::new_root_dir(PathBuf::from("/seed"), "/init");
        let err = driver_builder_image_from(&image, Path::new("/cache"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("mvmctl bootstrap"), "{err}");
    }

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
