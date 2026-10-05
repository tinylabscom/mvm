//! The driver-backed builders (HVF, Firecracker) and their Stage 0, offered to
//! `mvm-build`'s backend selection.
//!
//! `mvm-build` constructs the libkrun, QEMU and WebLinux builders itself, but it
//! cannot name the driver types: they live a layer up. A process that wants to
//! build on HVF or Firecracker registers these constructors once — `mvmctl` at
//! startup, a library caller before its first build — and a process that never
//! does gets those backends' named refusal.
//!
//! The builder image is booted exactly as Stage 0 built it or the release
//! fetched it, with nothing baked in: mvm's own builder binaries arrive in the
//! boot payload each boot carries. Resolution goes through
//! `ensure_builder_vm_image`, the same cache contract, shared-cache seeding and
//! auto-bootstrap decision the libkrun and QEMU builders take, so no builder
//! backend boots an image the others would refuse.
//!
//! The kernel is passed through unconverted. `FcDriver` normalises it at boot
//! (`ensure_fc_loadable_kernel`), which is the one place that knows what
//! Firecracker can load; HVF boots the arm64 `Image` as is.

use std::path::{Path, PathBuf};

use mvm_backends::driver::{fc::FcDriver, hvf::HvfDriver};
use mvm_build::builder_backend_select::{
    BuilderBackendChoice, register_driver_builders, register_stage0_builders,
};
use mvm_build::builder_vm::{
    BuilderVm, BuilderVmError, BuilderVmImage, builder_vm_cache_dir, host_arch_tag,
};

use super::{DriverBuilderVm, Stage0Vm};
use crate::driver::VmmDriver;

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

/// Register the HVF and Firecracker builder and Stage 0 constructors with
/// `mvm-build`. Only the first registration in a process takes effect, so
/// calling this again is harmless.
pub fn register_driver_backed_builders() {
    register_driver_builders(Box::new(|choice| {
        driver_builder(choice, resolve_driver_builder_image)
    }));
    register_stage0_builders(Box::new(stage0_builder));
}

/// The driver-backed builder for `choice`, booted from the image `resolve`
/// returns, or `None` when `choice` is not a driver-backed backend. The image
/// is resolved only for a driver-backed choice.
fn driver_builder(
    choice: BuilderBackendChoice,
    resolve: impl FnOnce() -> Result<DriverBuilderImage, BuilderVmError>,
) -> Option<Result<Box<dyn BuilderVm>, BuilderVmError>> {
    match choice {
        BuilderBackendChoice::Hvf => Some(resolve().map(|image| boot(HvfDriver::new(), image))),
        BuilderBackendChoice::Firecracker => {
            Some(resolve().map(|image| boot(FcDriver::new(), image)))
        }
        BuilderBackendChoice::Libkrun
        | BuilderBackendChoice::Qemu
        | BuilderBackendChoice::WebLinux => None,
    }
}

fn boot<D: VmmDriver + Clone + 'static>(
    driver: D,
    image: DriverBuilderImage,
) -> Box<dyn BuilderVm> {
    Box::new(
        DriverBuilderVm::new(driver, image.kernel, image.rootfs)
            .with_closure_nar(image.closure_nar),
    )
}

/// Stage 0 runs before a builder image exists, so unlike the builder it
/// resolves no image. libkrun, QEMU and WebLinux are resolved by `mvm-build`
/// itself.
fn stage0_builder(choice: BuilderBackendChoice) -> Option<Box<dyn BuilderVm>> {
    match choice {
        BuilderBackendChoice::Hvf => Some(Box::new(Stage0Vm::new(HvfDriver::new()))),
        BuilderBackendChoice::Firecracker => Some(Box::new(Stage0Vm::new(FcDriver::new()))),
        BuilderBackendChoice::Libkrun
        | BuilderBackendChoice::Qemu
        | BuilderBackendChoice::WebLinux => None,
    }
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

    fn image(dir: &Path) -> DriverBuilderImage {
        DriverBuilderImage {
            kernel: dir.join("vmlinux"),
            rootfs: dir.join("rootfs.ext4"),
            closure_nar: None,
        }
    }

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

    #[test]
    fn hvf_and_firecracker_get_a_driver_builder_from_the_resolved_image() {
        let dir = tempfile::tempdir().unwrap();
        for choice in [BuilderBackendChoice::Hvf, BuilderBackendChoice::Firecracker] {
            let builder = driver_builder(choice, || Ok(image(dir.path())));
            assert!(
                matches!(builder, Some(Ok(_))),
                "{} is driver-backed",
                choice.name()
            );
        }
    }

    #[test]
    fn other_backends_get_none_and_resolve_no_image() {
        for choice in [
            BuilderBackendChoice::Libkrun,
            BuilderBackendChoice::Qemu,
            BuilderBackendChoice::WebLinux,
        ] {
            let builder = driver_builder(choice, || {
                panic!("{} must not resolve a builder image", choice.name())
            });
            assert!(builder.is_none(), "{} is not driver-backed", choice.name());
        }
    }

    #[test]
    fn an_image_that_cannot_be_resolved_is_that_backends_error() {
        let builder = driver_builder(BuilderBackendChoice::Firecracker, || {
            Err(BuilderVmError::VmmFailed {
                detail: "no builder image".to_string(),
            })
        });
        let Some(Err(err)) = builder else {
            panic!("the resolution error is returned, not swallowed");
        };
        assert!(err.to_string().contains("no builder image"), "{err}");
    }

    #[test]
    fn stage0_is_offered_for_exactly_the_driver_backed_backends() {
        assert!(stage0_builder(BuilderBackendChoice::Hvf).is_some());
        assert!(stage0_builder(BuilderBackendChoice::Firecracker).is_some());
        assert!(stage0_builder(BuilderBackendChoice::Libkrun).is_none());
        assert!(stage0_builder(BuilderBackendChoice::Qemu).is_none());
        assert!(stage0_builder(BuilderBackendChoice::WebLinux).is_none());
    }
}
