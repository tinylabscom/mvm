//! Deciding how one builder boot reaches its PID 1, on the host.
//!
//! `mvmctl` registers where the boot payload comes from — its embedded
//! binaries, which only it can reach — and every builder backend asks
//! [`stage_builder_boot`] for the boot before composing its VM. With a source
//! registered, every boot carries the payload, whatever the image's ABI: a
//! legacy image's baked copies are then never executed, so a stale one cannot
//! matter. Without one (a test binary, a library embedder), the only bootable
//! image is a legacy one, and an image declaring ABI 1 or above is refused
//! here, by name, rather than failing in the guest with no init to run.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use mvm_core::image_set::BuilderBootAbi;
use thiserror::Error;

use super::abi::{
    BootAbiError, IMAGE_ABI_MARKER, baked_only_abis, check_image_abi, parse_image_abi_marker,
    payload_supported_abis,
};
use super::cmdline::{BuilderBoot, builder_boot_cmdline};
use super::payload::{BootPayloadError, BuilderBootPayload};
use crate::builder_vm::BuilderVmImage;

/// The payload's file name inside a booting VM's own state directory.
pub const PAYLOAD_FILE_NAME: &str = "boot-payload.cpio";

/// Where the boot payload comes from.
pub trait BootPayloadSource: Send + Sync {
    /// Assemble the payload for one boot.
    fn boot_payload(&self) -> Result<BuilderBootPayload, BootPayloadError>;
}

static SOURCE: OnceLock<Box<dyn BootPayloadSource>> = OnceLock::new();

/// Register the payload source. Called once at CLI startup; later calls are
/// ignored.
pub fn register_boot_payload_source(source: Box<dyn BootPayloadSource>) {
    let _ = SOURCE.set(source);
}

/// Whether this process can hand builder boots a payload, and so which image
/// ABIs it can boot.
pub fn supported_image_abis() -> mvm_core::image_set::BuilderBootAbiRange {
    if SOURCE.get().is_some() {
        payload_supported_abis()
    } else {
        baked_only_abis()
    }
}

/// Why a builder boot could not be staged.
#[derive(Debug, Error)]
pub enum StageBootError {
    #[error(transparent)]
    Payload(#[from] BootPayloadError),
    #[error("builder image {}: {source}", .rootfs.display())]
    Abi {
        rootfs: PathBuf,
        #[source]
        source: BootAbiError,
    },
    #[error("reading {IMAGE_ABI_MARKER} from builder image {}: {detail}", .rootfs.display())]
    ImageUnreadable { rootfs: PathBuf, detail: String },
}

/// Stage the boot for one builder VM whose state lives in `state_dir` and whose
/// image is `rootfs`.
pub fn stage_builder_boot(state_dir: &Path, rootfs: &Path) -> Result<BuilderBoot, StageBootError> {
    match SOURCE.get() {
        Some(source) => stage_payload_boot(source.as_ref(), state_dir),
        None => baked_boot(rootfs),
    }
}

/// Stage the boot for a builder that assembles its command line from an
/// image descriptor, and point `image` at the contract's command line instead
/// of whatever the image recorded.
///
/// The host owns the command line: an image's `cmdline.txt` predates the boot
/// payload and names an `init=` an image without baked binaries does not have.
/// A `RootDir` seed is Stage 0, which has its own init and no payload, and is
/// returned unchanged.
pub fn stage_image_boot(
    image: &BuilderVmImage,
    state_dir: &Path,
    console_base: &str,
) -> Result<(BuilderVmImage, BuilderBoot), StageBootError> {
    match image {
        BuilderVmImage::Rootfs {
            kernel_path,
            rootfs_path,
            ..
        } => {
            let boot = stage_builder_boot(state_dir, rootfs_path)?;
            let staged = BuilderVmImage::Rootfs {
                kernel_path: kernel_path.clone(),
                rootfs_path: rootfs_path.clone(),
                cmdline: builder_boot_cmdline(console_base, &boot, false),
            };
            Ok((staged, boot))
        }
        BuilderVmImage::RootDir { .. } => Ok((image.clone(), BuilderBoot::Baked)),
    }
}

/// Write the payload into the VM's state directory. A fresh copy per boot: it
/// is a few megabytes, and a shared copy would be one more file another
/// process could replace between assembly and boot.
fn stage_payload_boot(
    source: &dyn BootPayloadSource,
    state_dir: &Path,
) -> Result<BuilderBoot, StageBootError> {
    let payload = source.boot_payload()?;
    let initramfs = state_dir.join(PAYLOAD_FILE_NAME);
    payload.write_to(&initramfs)?;
    Ok(BuilderBoot::Payload {
        initramfs,
        digest: payload.digest(),
    })
}

/// Boot without a payload, which only an image that bakes its own init allows.
fn baked_boot(rootfs: &Path) -> Result<BuilderBoot, StageBootError> {
    let abi = read_image_boot_abi(rootfs)?;
    check_image_abi(abi, baked_only_abis()).map_err(|source| StageBootError::Abi {
        rootfs: rootfs.to_path_buf(),
        source,
    })?;
    Ok(BuilderBoot::Baked)
}

/// The boot ABI a builder image declares, read off the ext4 image on the host.
pub fn read_image_boot_abi(rootfs: &Path) -> Result<BuilderBootAbi, StageBootError> {
    let unreadable = |detail: String| StageBootError::ImageUnreadable {
        rootfs: rootfs.to_path_buf(),
        detail,
    };
    let fs = ext4_view::Ext4::load_from_path(rootfs).map_err(|e| unreadable(e.to_string()))?;
    let marker = if fs
        .exists(IMAGE_ABI_MARKER)
        .map_err(|e| unreadable(e.to_string()))?
    {
        Some(
            fs.read_to_string(IMAGE_ABI_MARKER)
                .map_err(|e| unreadable(e.to_string()))?,
        )
    } else {
        None
    };
    parse_image_abi_marker(marker.as_deref()).map_err(|source| StageBootError::Abi {
        rootfs: rootfs.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSource(PathBuf);

    impl BootPayloadSource for FakeSource {
        fn boot_payload(&self) -> Result<BuilderBootPayload, BootPayloadError> {
            BuilderBootPayload::builder().host_bin_dir(&self.0).build()
        }
    }

    fn image_with_marker(dir: &Path, marker: Option<&str>) -> PathBuf {
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("etc/mvm")).unwrap();
        std::fs::create_dir_all(tree.join("run")).unwrap();
        if let Some(marker) = marker {
            std::fs::write(tree.join("etc/mvm/builder-boot-abi"), marker).unwrap();
        }
        let image = dir.join("rootfs.ext4");
        mvm_fs::rootfs::materialize_ext4_pure(&tree, &image, &Default::default()).unwrap();
        image
    }

    #[test]
    fn a_registered_source_stages_the_payload_into_the_vm_state_dir() {
        let bins = tempfile::tempdir().unwrap();
        std::fs::write(bins.path().join("mvm-host-vm-init"), b"INIT").unwrap();
        std::fs::write(bins.path().join("mvm-builderd"), b"BUILDERD").unwrap();
        let state = tempfile::tempdir().unwrap();

        let boot =
            stage_payload_boot(&FakeSource(bins.path().to_path_buf()), state.path()).unwrap();

        let initramfs = state.path().join(PAYLOAD_FILE_NAME);
        assert_eq!(boot.initramfs(), Some(initramfs.as_path()));
        let expected = FakeSource(bins.path().to_path_buf())
            .boot_payload()
            .unwrap();
        assert_eq!(std::fs::read(&initramfs).unwrap(), expected.cpio());
        assert_eq!(boot.payload_digest(), Some(&expected.digest()));
    }

    #[test]
    fn a_source_that_cannot_assemble_refuses_the_boot() {
        let empty = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let err =
            stage_payload_boot(&FakeSource(empty.path().to_path_buf()), state.path()).unwrap_err();
        assert!(matches!(err, StageBootError::Payload(_)), "{err}");
    }

    #[test]
    fn without_a_payload_a_legacy_image_boots_its_own_init() {
        let dir = tempfile::tempdir().unwrap();
        let image = image_with_marker(dir.path(), None);
        assert_eq!(baked_boot(&image).unwrap(), BuilderBoot::Baked);
        let image = image_with_marker(&dir.path().join("zero"), Some("0\n"));
        assert_eq!(baked_boot(&image).unwrap(), BuilderBoot::Baked);
    }

    /// An ABI 1 image has no init of its own, so a host that cannot supply the
    /// payload must refuse before booting a guest that would panic for want of
    /// one.
    #[test]
    fn without_a_payload_an_image_that_needs_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let image = image_with_marker(dir.path(), Some("1\n"));
        assert_eq!(
            read_image_boot_abi(&image).unwrap(),
            BuilderBootAbi::PAYLOAD
        );
        let err = baked_boot(&image).unwrap_err().to_string();
        assert!(err.contains("ABI 1") && err.contains("0..=0"), "{err}");
    }

    #[test]
    fn an_unreadable_image_is_refused_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let not_ext4 = dir.path().join("rootfs.ext4");
        std::fs::write(&not_ext4, b"not an ext4 image").unwrap();
        let err = read_image_boot_abi(&not_ext4).unwrap_err();
        assert!(
            matches!(err, StageBootError::ImageUnreadable { .. }),
            "{err}"
        );
    }
}
