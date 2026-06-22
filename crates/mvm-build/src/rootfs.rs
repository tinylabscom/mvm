//! Rootfs image materialization helpers.
//!
//! Takes an OCI-unpacked directory tree and turns it
//! into the `rootfs.ext4` disk image that the runtime can boot. The
//! host side is deliberately small: it allocates the sparse output
//! file, then asks the existing builder VM to run `mkfs.ext4`, mount
//! the new filesystem, copy the unpacked tree into it, and unmount.
//! This keeps ext4 creation inside the Linux builder boundary instead
//! of depending on host tools.

#[cfg(feature = "builder-vm")]
use std::path::Path;
use std::path::PathBuf;

use thiserror::Error;

const DEFAULT_MIN_IMAGE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_SIZE_MULTIPLIER_NUMERATOR: u64 = 3;
const DEFAULT_SIZE_MULTIPLIER_DENOMINATOR: u64 = 2;
const DEFAULT_GUEST_OUTPUT_DEVICE: &str = "/dev/vdc";

/// Inputs for [`materialize_ext4`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeExt4Input {
    /// Directory tree produced by the OCI layer unpacker.
    pub unpacked_root: PathBuf,
    /// Host path of the sparse ext4 image to create.
    pub output: PathBuf,
    /// Sum of OCI layer uncompressed sizes for this image.
    pub uncompressed_size_bytes: u64,
}

impl MaterializeExt4Input {
    pub fn new(unpacked_root: PathBuf, output: PathBuf, uncompressed_size_bytes: u64) -> Self {
        Self {
            unpacked_root,
            output,
            uncompressed_size_bytes,
        }
    }
}

/// Sizing and guest-copy options for [`materialize_ext4`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeExt4Options {
    /// Minimum sparse image size, defaulting to 64 MiB.
    pub min_image_size_bytes: u64,
    /// Numerator for the uncompressed-size multiplier. The default
    /// pair is 3/2, i.e. 1.5x.
    pub size_multiplier_numerator: u64,
    /// Denominator for the uncompressed-size multiplier.
    pub size_multiplier_denominator: u64,
    /// Guest block device path for the output sparse file. Builder
    /// backends attach their persistent Nix store as `/dev/vdb`, so the
    /// first caller-provided extra disk is `/dev/vdc`.
    pub guest_output_device: String,
}

impl Default for MaterializeExt4Options {
    fn default() -> Self {
        Self {
            min_image_size_bytes: DEFAULT_MIN_IMAGE_SIZE_BYTES,
            size_multiplier_numerator: DEFAULT_SIZE_MULTIPLIER_NUMERATOR,
            size_multiplier_denominator: DEFAULT_SIZE_MULTIPLIER_DENOMINATOR,
            guest_output_device: DEFAULT_GUEST_OUTPUT_DEVICE.to_string(),
        }
    }
}

/// Descriptor returned after successful materialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedExt4 {
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Error)]
pub enum RootfsError {
    #[error("unpacked root is not a directory: {0}")]
    UnpackedRootNotDirectory(PathBuf),

    #[error("invalid ext4 size multiplier denominator: 0")]
    InvalidSizeMultiplier,

    #[error("allocating sparse rootfs image {path}: {source}")]
    AllocateSparseImage {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("builder-vm feature is required for ext4 materialization")]
    BuilderVmFeatureDisabled,

    #[cfg(feature = "builder-vm")]
    #[error("builder VM ext4 materialization failed: {0}")]
    BuilderVm(#[from] crate::builder_vm::BuilderVmError),
}

/// Estimate the sparse image size for an OCI rootfs.
///
/// The sizing rule is `sum(layer.uncompressed_size) * 1.5`
/// with a 64 MiB floor. This function rounds up for odd byte counts
/// and saturates on overflow so a maliciously large manifest fails at
/// sparse-file allocation instead of wrapping small.
pub fn estimate_ext4_size(
    uncompressed_size_bytes: u64,
    options: &MaterializeExt4Options,
) -> Result<u64, RootfsError> {
    if options.size_multiplier_denominator == 0 {
        return Err(RootfsError::InvalidSizeMultiplier);
    }

    let scaled = uncompressed_size_bytes
        .saturating_mul(options.size_multiplier_numerator)
        .saturating_add(options.size_multiplier_denominator - 1)
        / options.size_multiplier_denominator;
    Ok(scaled.max(options.min_image_size_bytes))
}

/// Materialize `input.unpacked_root` into `input.output`.
///
/// The host allocates the sparse file, but never formats it. When
/// compiled with the `builder-vm` feature, the existing libkrun
/// builder VM receives the unpacked tree over virtio-fs and the
/// sparse output image as a writable virtio-blk device, then runs
/// `mkfs.ext4` inside the guest. Default builds return
/// [`RootfsError::BuilderVmFeatureDisabled`] because they do not link
/// the libkrun builder launcher.
pub fn materialize_ext4(
    input: &MaterializeExt4Input,
    options: &MaterializeExt4Options,
) -> Result<MaterializedExt4, RootfsError> {
    if !input.unpacked_root.is_dir() {
        return Err(RootfsError::UnpackedRootNotDirectory(
            input.unpacked_root.clone(),
        ));
    }

    let size_bytes = estimate_ext4_size(input.uncompressed_size_bytes, options)?;

    #[cfg(not(feature = "builder-vm"))]
    {
        let _ = size_bytes;
        Err(RootfsError::BuilderVmFeatureDisabled)
    }

    #[cfg(feature = "builder-vm")]
    {
        allocate_sparse_image(&input.output, size_bytes)?;

        if let Err(err) = materialize_ext4_in_builder_vm(input, options, size_bytes) {
            let _ = std::fs::remove_file(&input.output);
            return Err(err);
        }

        Ok(MaterializedExt4 {
            path: input.output.clone(),
            size_bytes,
        })
    }
}

#[cfg(feature = "builder-vm")]
fn allocate_sparse_image(path: &Path, size_bytes: u64) -> Result<(), RootfsError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| RootfsError::AllocateSparseImage {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let file = std::fs::File::create(path).map_err(|source| RootfsError::AllocateSparseImage {
        path: path.to_path_buf(),
        source,
    })?;
    file.set_len(size_bytes)
        .map_err(|source| RootfsError::AllocateSparseImage {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn materialize_ext4_in_builder_vm(
    input: &MaterializeExt4Input,
    options: &MaterializeExt4Options,
    device_size_bytes: u64,
) -> Result<(), RootfsError> {
    use crate::builder_backend_select::BuilderBackendChoice;
    use crate::libkrun_builder::{BuilderExtraDisk, BuilderShellJob, LibkrunBuilderVm};
    use crate::qemu_builder::QemuBuilderVm;
    use crate::vz_builder::VzBuilderVm;

    let artifact_out = input
        .output
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let script = ext4_materialization_script(&options.guest_output_device, device_size_bytes);
    let shell_job = BuilderShellJob {
        work_dir: input.unpacked_root.clone(),
        artifact_out,
        script,
        extra_disks: vec![BuilderExtraDisk {
            id: "oci-rootfs".to_string(),
            path: input.output.clone(),
            read_only: false,
        }],
    };

    // Auto-fallback: an auto-detected libkrun materializer that fails at
    // VM creation on Linux (libkrun rc -22 / `KVM_SET_USER_MEMORY_REGION`)
    // transparently retries on the qemu builder, which works there. An
    // explicit `MVM_BUILDER_BACKEND` opts out.
    let selected = ext4_materializer_choice();
    let explicit = crate::builder_backend_select::resolve_env_override().is_some();
    crate::builder_backend_select::run_with_builder_fallback(selected, explicit, |choice| {
        match choice {
            BuilderBackendChoice::Libkrun => LibkrunBuilderVm::default()
                .run_shell_script(&shell_job)
                .map(|_| ()),
            BuilderBackendChoice::Qemu => QemuBuilderVm::new()
                .run_shell_script(&shell_job)
                .map(|_| ()),
            BuilderBackendChoice::Vz => VzBuilderVm::new().run_shell_script(&shell_job).map(|_| ()),
        }
    })?;
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn ext4_materializer_choice() -> crate::builder_backend_select::BuilderBackendChoice {
    use crate::builder_backend_select::{BuilderBackendChoice, resolve_env_override};

    // Preserve the historical default: OCI materialization has always used
    // libkrun unless an operator explicitly asks for QEMU. Do not use
    // resolve_choice(), because macOS 26+ auto-detects Vz and Vz has no
    // shell-job materializer yet.
    match resolve_env_override() {
        Some(BuilderBackendChoice::Qemu) => BuilderBackendChoice::Qemu,
        Some(BuilderBackendChoice::Vz) => BuilderBackendChoice::Vz,
        Some(BuilderBackendChoice::Libkrun) | None => BuilderBackendChoice::Libkrun,
    }
}

/// Safety margin (bytes) left between the formatted ext4 size and the
/// backing device size. The builder VM (libkrun) and the workload
/// backends (Vz, Firecracker) can report a virtio-blk device size that
/// differs from the host sparse file by up to ~64 KiB in either
/// direction (kernel/VMM rounding). Formatting `mkfs.ext4` to the full
/// device size makes a filesystem that boots on the backend whose device
/// view matches but panics with "bad geometry: block count … exceeds
/// size of device" on one that reports fewer blocks. A 1 MiB margin
/// safely absorbs the discrepancy on every backend.
#[cfg(any(test, feature = "builder-vm"))]
const EXT4_DEVICE_MARGIN_BYTES: u64 = 1024 * 1024;

/// ext4 block size used when formatting with an explicit block count.
#[cfg(any(test, feature = "builder-vm"))]
const EXT4_BLOCK_SIZE_BYTES: u64 = 4096;

/// Number of `EXT4_BLOCK_SIZE_BYTES` blocks to format, given the host
/// sparse-file size. Subtracts the device margin, then rounds down to a
/// whole block count.
#[cfg(any(test, feature = "builder-vm"))]
fn ext4_block_count(device_size_bytes: u64) -> u64 {
    device_size_bytes.saturating_sub(EXT4_DEVICE_MARGIN_BYTES) / EXT4_BLOCK_SIZE_BYTES
}

/// Shell executed inside the builder VM. Public within the crate so
/// tests can pin the command shape without booting a VM.
///
/// `device_size_bytes` is the host sparse-file size; the script formats
/// the ext4 to an explicit block count a margin below it so the image
/// mounts on a workload backend whose virtio-blk device reports slightly
/// fewer blocks than the builder VM saw (see [`EXT4_DEVICE_MARGIN_BYTES`]).
#[cfg(any(test, feature = "builder-vm"))]
pub(crate) fn ext4_materialization_script(
    guest_output_device: &str,
    device_size_bytes: u64,
) -> String {
    format!(
        r#"#!/bin/sh
set -eu

ROOTFS_DEV='{guest_output_device}'
MOUNTPOINT=/tmp/mvm-image-rootfs

mkdir -p "$MOUNTPOINT"
/sbin/mkfs.ext4 -F -b {block_size} "$ROOTFS_DEV" {block_count}
mount -t ext4 "$ROOTFS_DEV" "$MOUNTPOINT"
trap 'umount "$MOUNTPOINT" 2>/dev/null || true' EXIT
cp -aR /work/. "$MOUNTPOINT"/
sync
umount "$MOUNTPOINT"
trap - EXIT
"#,
        guest_output_device = shell_single_quote_escape(guest_output_device),
        block_size = EXT4_BLOCK_SIZE_BYTES,
        block_count = ext4_block_count(device_size_bytes),
    )
}

#[cfg(any(test, feature = "builder-vm"))]
fn shell_single_quote_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "builder-vm")]
    use crate::builder_backend_select::{BuilderBackendChoice, MVM_BUILDER_BACKEND_ENV};
    #[cfg(feature = "builder-vm")]
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn estimate_uses_sixty_four_mib_floor() {
        let options = MaterializeExt4Options::default();
        assert_eq!(estimate_ext4_size(1, &options).unwrap(), 64 * 1024 * 1024);
    }

    #[test]
    fn estimate_uses_one_point_five_x_rounded_up() {
        let options = MaterializeExt4Options::default();
        assert_eq!(
            estimate_ext4_size(100 * 1024 * 1024, &options).unwrap(),
            150 * 1024 * 1024
        );
        assert_eq!(estimate_ext4_size(3, &options).unwrap(), 64 * 1024 * 1024);
    }

    #[test]
    fn estimate_rejects_zero_denominator() {
        let options = MaterializeExt4Options {
            size_multiplier_denominator: 0,
            ..MaterializeExt4Options::default()
        };
        assert!(matches!(
            estimate_ext4_size(1, &options),
            Err(RootfsError::InvalidSizeMultiplier)
        ));
    }

    #[test]
    fn script_formats_mounts_copies_and_unmounts_inside_guest() {
        let script = ext4_materialization_script("/dev/vdc", 64 * 1024 * 1024);
        // Formats to an explicit block count a margin below the device
        // so the image mounts on a backend reporting fewer blocks.
        assert!(script.contains("/sbin/mkfs.ext4 -F -b 4096 \"$ROOTFS_DEV\""));
        assert!(script.contains("mount -t ext4 \"$ROOTFS_DEV\" \"$MOUNTPOINT\""));
        assert!(script.contains("cp -aR /work/. \"$MOUNTPOINT\"/"));
        assert!(script.contains("umount \"$MOUNTPOINT\""));
        assert!(!script.contains("mke2fs -d"));
    }

    #[test]
    fn ext4_block_count_leaves_a_one_mib_margin() {
        // 64 MiB device → format (64 MiB - 1 MiB) / 4096 = 16128 blocks.
        assert_eq!(ext4_block_count(64 * 1024 * 1024), 16128);
        // The formatted size is strictly below the device size by at
        // least the margin, so a backend reporting up to 1 MiB fewer
        // bytes still mounts it.
        let dev = 128 * 1024 * 1024;
        assert!(ext4_block_count(dev) * 4096 + EXT4_DEVICE_MARGIN_BYTES <= dev + 4096);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn materializer_defaults_to_libkrun_for_historical_compatibility() {
        let mut env = TestEnv::new();
        env.remove(MVM_BUILDER_BACKEND_ENV);

        assert_eq!(ext4_materializer_choice(), BuilderBackendChoice::Libkrun);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn materializer_honors_explicit_qemu_backend() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_BACKEND_ENV, "qemu");

        assert_eq!(ext4_materializer_choice(), BuilderBackendChoice::Qemu);
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn materializer_honors_explicit_vz_backend() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_BACKEND_ENV, "vz");

        assert_eq!(ext4_materializer_choice(), BuilderBackendChoice::Vz);
    }

    #[cfg(not(feature = "builder-vm"))]
    #[test]
    fn materialize_without_builder_vm_feature_reports_feature_disabled_without_output() {
        let unpacked = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let output = output_dir.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(unpacked.path().to_path_buf(), output.clone(), 1);

        let err = materialize_ext4(&input, &MaterializeExt4Options::default()).unwrap_err();
        assert!(matches!(err, RootfsError::BuilderVmFeatureDisabled));
        assert!(!output.exists());
    }
}
