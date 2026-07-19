use super::*;

#[cfg(feature = "builder-vm")]
pub(super) fn verify_stage0_rootfs_has_init(rootfs: &std::path::Path) -> Result<()> {
    let fs = ext4_view::Ext4::load_from_path(rootfs)
        .with_context(|| format!("opening {} as ext4", rootfs.display()))?;
    let present = fs.exists(HOST_VM_INIT_ROOTFS_PATH).with_context(|| {
        format!(
            "looking up {HOST_VM_INIT_ROOTFS_PATH} in {}",
            rootfs.display()
        )
    })?;
    if !present {
        anyhow::bail!(
            "Stage 0 builder VM rootfs {} is missing {HOST_VM_INIT_ROOTFS_PATH}",
            rootfs.display()
        );
    }
    Ok(())
}

pub(super) fn validate_dev_image_artifacts(
    kernel: impl AsRef<std::path::Path>,
    rootfs: impl AsRef<std::path::Path>,
) -> Result<()> {
    const KERNEL_MIN_BYTES: u64 = 1024 * 1024;
    const ROOTFS_MIN_BYTES: u64 = 4 * 1024 * 1024;
    const EXT4_MAGIC_OFFSET: u64 = 1024 + 56;
    const EXT4_MAGIC: [u8; 2] = [0x53, 0xEF];

    let kernel = kernel.as_ref();
    let rootfs = rootfs.as_ref();

    let kernel_size = std::fs::metadata(kernel)
        .with_context(|| format!("stat {}", kernel.display()))?
        .len();
    if kernel_size < KERNEL_MIN_BYTES {
        anyhow::bail!(
            "kernel at {} is only {} bytes (expected ≥ {})",
            kernel.display(),
            kernel_size,
            KERNEL_MIN_BYTES,
        );
    }

    let rootfs_size = std::fs::metadata(rootfs)
        .with_context(|| format!("stat {}", rootfs.display()))?
        .len();
    if rootfs_size < ROOTFS_MIN_BYTES {
        anyhow::bail!(
            "rootfs at {} is only {} bytes (expected ≥ {})",
            rootfs.display(),
            rootfs_size,
            ROOTFS_MIN_BYTES,
        );
    }

    use std::io::{Read, Seek, SeekFrom};
    let mut f =
        std::fs::File::open(rootfs).with_context(|| format!("open {}", rootfs.display()))?;
    f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET))
        .with_context(|| format!("seek to ext4 magic in {}", rootfs.display()))?;
    let mut magic = [0u8; 2];
    f.read_exact(&mut magic)
        .with_context(|| format!("read ext4 magic from {}", rootfs.display()))?;
    if magic != EXT4_MAGIC {
        anyhow::bail!(
            "rootfs at {} does not have ext4 magic at offset {} (got {magic:02x?})",
            rootfs.display(),
            EXT4_MAGIC_OFFSET,
        );
    }

    Ok(())
}
