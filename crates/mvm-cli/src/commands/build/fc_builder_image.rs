//! Firecracker builder-image resolver.
//!
//! Firecracker boots the builder image exactly as Stage 0 left it under
//! `builder_vm_cache_dir()/<arch>/`. That image is built from this tree's
//! `nix/images/builder-vm` flake, which installs `mvm-host-vm-init` at
//! `/sbin/mvm-host-vm-init` itself, so there is nothing to bake in and no
//! patcher VM to run — the libkrun builder boots the same files the same way,
//! and like libkrun the image is only as current as the last bootstrap.
//!
//! The kernel is passed through unconverted. `FcDriver` normalises it at boot
//! (`ensure_fc_loadable_kernel`), which is the one place that knows what
//! Firecracker can load.

use std::path::{Path, PathBuf};

use mvm_build::builder_vm::{BuilderVmError, builder_vm_cache_dir};

/// The Firecracker builder image: kernel, rootfs, and the seeded Nix store
/// closure when the image carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcBuilderImage {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub closure_nar: Option<PathBuf>,
}

/// Resolve the Firecracker builder image for the host architecture.
pub fn resolve_fc_builder_image() -> Result<FcBuilderImage, BuilderVmError> {
    fc_builder_image_in(&builder_vm_cache_dir().join(std::env::consts::ARCH))
}

/// Resolve the builder image held in `arch_dir`, refusing when either half
/// is missing. Reads nothing but file metadata.
fn fc_builder_image_in(arch_dir: &Path) -> Result<FcBuilderImage, BuilderVmError> {
    let kernel = require_image_file(arch_dir, "vmlinux", "kernel")?;
    let rootfs = require_image_file(arch_dir, "rootfs.ext4", "rootfs")?;
    Ok(FcBuilderImage {
        kernel,
        rootfs,
        closure_nar: mvm_build::builder_pack::closure_nar_path(arch_dir),
    })
}

fn require_image_file(arch_dir: &Path, name: &str, what: &str) -> Result<PathBuf, BuilderVmError> {
    let path = arch_dir.join(name);
    if path.is_file() {
        return Ok(path);
    }
    Err(BuilderVmError::VmmFailed {
        detail: format!(
            "Firecracker builder {what} not found at {}; run `mvmctl bootstrap` \
             to build the builder image first",
            path.display()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn a_bootstrapped_image_resolves_to_the_stage0_output_as_is() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "vmlinux");
        write(dir.path(), "rootfs.ext4");

        let image = fc_builder_image_in(dir.path()).unwrap();

        assert_eq!(image.kernel, dir.path().join("vmlinux"));
        assert_eq!(image.rootfs, dir.path().join("rootfs.ext4"));
        assert_eq!(image.closure_nar, None);
    }

    #[test]
    fn a_missing_kernel_refuses_and_says_to_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4");

        let err = fc_builder_image_in(dir.path()).unwrap_err().to_string();

        assert!(err.contains("kernel not found"), "{err}");
        assert!(err.contains("mvmctl bootstrap"), "{err}");
    }

    #[test]
    fn a_missing_rootfs_refuses_and_says_to_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "vmlinux");

        let err = fc_builder_image_in(dir.path()).unwrap_err().to_string();

        assert!(err.contains("rootfs not found"), "{err}");
        assert!(err.contains("mvmctl bootstrap"), "{err}");
    }

    #[test]
    fn a_directory_named_like_the_kernel_is_not_an_image() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("vmlinux")).unwrap();
        write(dir.path(), "rootfs.ext4");

        assert!(fc_builder_image_in(dir.path()).is_err());
    }

    #[test]
    fn the_seeded_closure_is_carried_when_the_image_has_one() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "vmlinux");
        write(dir.path(), "rootfs.ext4");
        write(dir.path(), mvm_build::builder_pack::CLOSURE_FILE);

        let image = fc_builder_image_in(dir.path()).unwrap();

        assert_eq!(
            image.closure_nar,
            Some(dir.path().join(mvm_build::builder_pack::CLOSURE_FILE))
        );
    }

    /// The proof this change could not run: a shell job on the Firecracker
    /// builder, booted from a bootstrapped image. Run on a KVM host after
    /// `mvmctl bootstrap`, which auto-detects Firecracker there.
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "live: needs Linux + /dev/kvm and a bootstrapped builder image"]
    fn live_firecracker_builder_runs_a_shell_job() {
        use mvm_build::builder_vm::{BuilderShellJob, BuilderVm};

        let image = resolve_fc_builder_image().expect("run `mvmctl bootstrap` first");
        let tmp = tempfile::tempdir().expect("tempdir");
        let work_dir = tmp.path().join("work");
        std::fs::create_dir_all(&work_dir).expect("create work_dir");
        let job = BuilderShellJob {
            work_dir,
            artifact_out: tmp.path().join("out"),
            script: "set -eu\nuname -m > /out/uname.txt\n".to_string(),
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
    }
}
