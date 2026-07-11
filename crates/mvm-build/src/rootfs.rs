//! Rootfs image materialization helpers.
//!
//! Takes an OCI-unpacked directory tree and turns it
//! into the `rootfs.ext4` disk image that the runtime can boot. The
//! host side is deliberately small: it allocates the sparse output
//! file, then asks the existing builder VM to run `mkfs.ext4`, mount
//! the new filesystem, copy the unpacked tree into it, and unmount.
//! This keeps ext4 creation inside the Linux builder boundary instead
//! of depending on host tools.

#[cfg(feature = "pure-mkfs")]
use std::io::{Seek, SeekFrom, Write};
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
    /// When true, the pure path also computes dm-verity and writes the
    /// `rootfs.verity` + `rootfs.roothash` sidecars beside the image. Off by
    /// default so materializing a rootfs is a pure mechanism swap: the run path
    /// today boots these images without rootfs verity (the boot config sets
    /// `verity_path`/`roothash` to `None`), and emitting sidecars a probe would
    /// pick up would silently change that. The builder-VM path ignores this.
    pub emit_verity: bool,
}

impl MaterializeExt4Input {
    pub fn new(unpacked_root: PathBuf, output: PathBuf, uncompressed_size_bytes: u64) -> Self {
        Self {
            unpacked_root,
            output,
            uncompressed_size_bytes,
            emit_verity: false,
        }
    }

    /// Opt into dm-verity sidecar emission on the pure path.
    pub fn with_verity(mut self) -> Self {
        self.emit_verity = true;
        self
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
    /// 64-char lowercase-hex dm-verity root hash, when the materializer computed
    /// it in-process (the `pure-mkfs` path writes `rootfs.verity` +
    /// `rootfs.roothash` beside the image). `None` for the builder-VM path, which
    /// generates verity separately.
    pub verity_root_hash: Option<String>,
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

    #[cfg(feature = "pure-mkfs")]
    #[error("walking unpacked tree at {path}: {source}")]
    PureWalk {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[cfg(feature = "pure-mkfs")]
    #[error("building ext4 image in-process: {0}")]
    PureBuild(#[from] mvm_ext4::Ext4Error),

    #[cfg(feature = "pure-mkfs")]
    #[error("writing rootfs image {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(feature = "pure-mkfs")]
impl RootfsError {
    /// Whether a pure-path failure is a *capacity limit* of the in-process ext4
    /// writer (the image is too big / too fragmented, or an inode's xattrs
    /// overflow the in-inode area), meaning the run path can retry via the
    /// builder VM. A malformed-tree or I/O failure returns `false`.
    pub fn is_pure_capacity_limit(&self) -> bool {
        matches!(self, RootfsError::PureBuild(e) if e.is_capacity_limit())
    }

    /// Whether the run path should retry this pure-path failure via the builder
    /// VM (which has no such limits and whose `cp -a` preserves xattrs). A
    /// malformed tree or I/O error is genuine and surfaces unchanged.
    pub fn pure_should_fall_back(&self) -> bool {
        self.is_pure_capacity_limit()
    }
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
            verity_root_hash: None,
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

    // Keep the materializer on the same builder-backend policy as the rest of
    // the builder surface. In particular, do not silently retry on qemu here:
    // qemu's user-net path is a dev/test tier, not a production substitute for
    // the vsock-oriented builder/runtime contract.
    let selected = ext4_materializer_choice();
    let explicit = crate::builder_backend_select::resolve_env_override().is_some();
    crate::builder_backend_select::run_with_builder_fallback(selected, explicit, |choice| {
        match choice {
            BuilderBackendChoice::Libkrun | BuilderBackendChoice::Hvf => {
                LibkrunBuilderVm::default()
                    .run_shell_script(&shell_job)
                    .map(|_| ())
            }
            BuilderBackendChoice::Qemu => QemuBuilderVm::new()
                .run_shell_script(&shell_job)
                .map(|_| ()),
        }
    })?;
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn ext4_materializer_choice() -> crate::builder_backend_select::BuilderBackendChoice {
    // Use the resolved builder backend (override → env → auto-detect: macOS 26+
    // Apple Silicon → hvf builder, everywhere else → libkrun). Delegates to
    // `resolve_choice()` so the materializer always uses the same backend as
    // every other build entry point.
    crate::builder_backend_select::resolve_choice()
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

#[cfg(feature = "pure-mkfs")]
/// Materialize `input.unpacked_root` into `input.output` **in-process** — no
/// builder VM, no `mkfs`, no subprocess. Walks the unpacked tree and builds a
/// deterministic read-only ext4 image with the memory-safe `mvm-ext4` writer.
///
/// This is the no-shell path the local run uses. It reads
/// the whole tree into memory (each file's bytes + the assembled image), which
/// is fine for small/medium rootfs; large images want the streaming +
/// multi-block-group follow-ups. The output is a valid ext4 real readers mount;
/// integrity is provided by dm-verity, added on top (not by in-filesystem
/// checksums).
pub fn materialize_ext4_pure(
    input: &MaterializeExt4Input,
) -> Result<MaterializedExt4, RootfsError> {
    if !input.unpacked_root.is_dir() {
        return Err(RootfsError::UnpackedRootNotDirectory(
            input.unpacked_root.clone(),
        ));
    }
    let nodes = collect_nodes(&input.unpacked_root)?;
    // The run path's cache dir (`.../rootfs/<key>/`) may not exist yet — the
    // builder-VM path created it via `allocate_sparse_image`, so the pure path
    // must create it too before writing the image + its sidecars.
    if let Some(parent) = input.output.parent() {
        std::fs::create_dir_all(parent).map_err(|source| RootfsError::WriteOutput {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let size_bytes = stream_pure_ext4_output(&nodes, &input.output)?;

    if !input.emit_verity {
        return Ok(MaterializedExt4 {
            path: input.output.clone(),
            size_bytes,
            verity_root_hash: None,
        });
    }

    // dm-verity, computed in-process (no `veritysetup`). v1, sha256, 4 KiB
    // data+hash blocks, zero salt — the params the boot path expects. Write the
    // hash tree + 64-hex root hash beside the image under the fixed names
    // `probe_verity_sidecar` reads (`rootfs.verity` / `rootfs.roothash`).
    let image = std::fs::read(&input.output).map_err(|source| RootfsError::WriteOutput {
        path: input.output.clone(),
        source,
    })?;
    let salt = [0u8; 32];
    let verity = mvm_ext4::verity::format(&image, &salt, 4096, 4096);
    let dir = input
        .output
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let root_hex = mvm_ext4::verity::to_hex(&verity.root_hash);
    write_sidecar(&dir.join("rootfs.verity"), &verity.hash_tree)?;
    write_sidecar(
        &dir.join("rootfs.roothash"),
        format!("{root_hex}\n").as_bytes(),
    )?;

    Ok(MaterializedExt4 {
        path: input.output.clone(),
        size_bytes,
        verity_root_hash: Some(root_hex),
    })
}

#[cfg(feature = "pure-mkfs")]
fn stream_pure_ext4_output(
    nodes: &[mvm_ext4::Node],
    output: &std::path::Path,
) -> Result<u64, RootfsError> {
    let mut file = std::fs::File::create(output).map_err(|source| RootfsError::WriteOutput {
        path: output.to_path_buf(),
        source,
    })?;
    let size_bytes = match mvm_ext4::emit_image(nodes, |offset, bytes| {
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(bytes))
    }) {
        Ok(size_bytes) => size_bytes,
        Err(mvm_ext4::EmitImageError::Build(err)) => return Err(RootfsError::PureBuild(err)),
        Err(mvm_ext4::EmitImageError::Emit(source)) => {
            return Err(RootfsError::WriteOutput {
                path: output.to_path_buf(),
                source,
            });
        }
    };
    file.set_len(size_bytes)
        .map_err(|source| RootfsError::WriteOutput {
            path: output.to_path_buf(),
            source,
        })?;
    Ok(size_bytes)
}

#[cfg(feature = "pure-mkfs")]
fn write_sidecar(path: &std::path::Path, body: &[u8]) -> Result<(), RootfsError> {
    std::fs::write(path, body).map_err(|source| RootfsError::WriteOutput {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(feature = "pure-mkfs")]
/// Walk `root` into a flat `Node` list (guest-absolute paths), symlink-aware
/// (never follows). Directories and their descendants, regular files (contents
/// read in), and symlinks are captured; other inode types (fifo/socket/device)
/// are skipped — an OCI rootfs mounts devtmpfs for those.
fn collect_nodes(root: &std::path::Path) -> Result<Vec<mvm_ext4::Node>, RootfsError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = std::fs::read_dir(&dir).map_err(|source| RootfsError::PureWalk {
            path: dir.clone(),
            source,
        })?;
        for entry in read {
            let entry = entry.map_err(|source| RootfsError::PureWalk {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let guest_path = guest_path_of(root, &path);
            let ft = entry.file_type().map_err(|source| RootfsError::PureWalk {
                path: path.clone(),
                source,
            })?;
            // Capture image-semantic xattrs (file capabilities, POSIX ACLs,
            // user/trusted attrs) so the writer preserves them inline. Attrs too
            // large for the in-inode area surface later as XattrTooLarge (a
            // capacity limit → builder-VM fallback). Host-managed labels the
            // guest re-derives (SELinux/IMA/EVM, macOS `com.apple.*`) are skipped.
            if ft.is_symlink() {
                let target = std::fs::read_link(&path).map_err(|source| RootfsError::PureWalk {
                    path: path.clone(),
                    source,
                })?;
                out.push(mvm_ext4::Node::Symlink {
                    path: guest_path,
                    target: target.to_string_lossy().into_owned(),
                });
            } else if ft.is_dir() {
                let xattrs = collect_guest_xattrs(&path);
                out.push(mvm_ext4::Node::Dir {
                    path: guest_path,
                    mode: mode_of(&path, 0o755),
                    xattrs,
                });
                stack.push(path);
            } else if ft.is_file() {
                let data =
                    read_file_for_guest_image(&path).map_err(|source| RootfsError::PureWalk {
                        path: path.clone(),
                        source,
                    })?;
                let xattrs = collect_guest_xattrs(&path);
                out.push(mvm_ext4::Node::File {
                    path: guest_path,
                    mode: mode_of(&path, 0o644),
                    data,
                    xattrs,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "pure-mkfs")]
fn read_file_for_guest_image(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let metadata = std::fs::symlink_metadata(path)?;
                let original_mode = metadata.permissions().mode();
                let widened_mode = original_mode | 0o400;
                if widened_mode == original_mode {
                    return Err(err);
                }

                std::fs::set_permissions(path, std::fs::Permissions::from_mode(widened_mode))?;
                let read_result = std::fs::read(path);
                let restore_result =
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(original_mode));
                match (read_result, restore_result) {
                    (Ok(bytes), Ok(())) => Ok(bytes),
                    (Ok(_), Err(restore_err)) => Err(restore_err),
                    (Err(read_err), Ok(())) => Err(read_err),
                    (Err(read_err), Err(_restore_err)) => Err(read_err),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                Err(err)
            }
        }
        Err(err) => Err(err),
    }
}

/// The name of the first extended attribute on `path` that the pure writer can't
/// represent and the guest actually needs, or `None`. Ignores host-managed
/// labels (SELinux/IMA/EVM, macOS `com.apple.*`) so the guest re-derives them.
#[cfg(feature = "pure-mkfs")]
fn collect_guest_xattrs(path: &std::path::Path) -> Vec<mvm_ext4::Xattr> {
    // A read failure means the FS doesn't support xattrs (or we lack access):
    // nothing to preserve.
    let Ok(names) = xattr::list(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in names {
        let name = name.to_string_lossy().into_owned();
        if xattr_matters_for_guest(&name)
            && let Ok(Some(value)) = xattr::get(path, &name)
        {
            out.push(mvm_ext4::Xattr { name, value });
        }
    }
    // Deterministic order (the writer also sorts, but keep the node stable).
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Whether an xattr name carries guest-relevant image semantics the pure writer
/// would silently drop. File capabilities and POSIX ACLs are preserved; other
/// `security.*` attrs are host-managed labels the guest kernel re-derives (or
/// that don't port between hosts) and are deliberately ignored.
#[cfg(feature = "pure-mkfs")]
fn xattr_matters_for_guest(name: &str) -> bool {
    match name {
        "security.capability" | "system.posix_acl_access" | "system.posix_acl_default" => true,
        _ if name.starts_with("security.") => false,
        _ => name.starts_with("user.") || name.starts_with("trusted."),
    }
}

#[cfg(feature = "pure-mkfs")]
/// Guest-absolute path for `path` under `root` (e.g. `root/etc/hosts` → `/etc/hosts`).
fn guest_path_of(root: &std::path::Path, path: &std::path::Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => format!("/{}", path.to_string_lossy()),
    }
}

#[cfg(feature = "pure-mkfs")]
/// Unix permission bits of `path` (not following symlinks), or `default` on a
/// non-unix host.
fn mode_of(path: &std::path::Path, default: u16) -> u16 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::symlink_metadata(path) {
            Ok(m) => (m.permissions().mode() & 0o7777) as u16,
            Err(_) => default,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        default
    }
}

#[cfg(any(test, feature = "builder-vm"))]
fn shell_single_quote_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_capacity_limit_is_retryable_but_malformed_is_not() {
        let capacity = RootfsError::PureBuild(mvm_ext4::Ext4Error::FileTooFragmented {
            ino: 12,
            extents: 9,
        });
        assert!(
            capacity.is_pure_capacity_limit(),
            "a capacity limit must be retryable via the builder VM"
        );
        let malformed = RootfsError::PureBuild(mvm_ext4::Ext4Error::BadPath("//a".into()));
        assert!(
            !malformed.is_pure_capacity_limit(),
            "a malformed-tree error must surface, not fall back"
        );
        let io = RootfsError::WriteOutput {
            path: PathBuf::from("/x"),
            source: std::io::Error::other("boom"),
        };
        assert!(!io.is_pure_capacity_limit());
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn only_image_semantic_xattrs_are_captured() {
        // Captured (image semantics the guest needs and won't re-derive).
        assert!(xattr_matters_for_guest("security.capability"));
        assert!(xattr_matters_for_guest("system.posix_acl_access"));
        assert!(xattr_matters_for_guest("system.posix_acl_default"));
        assert!(xattr_matters_for_guest("user.mvm.anything"));
        assert!(xattr_matters_for_guest("trusted.foo"));
        // Ignored: host-managed labels the guest re-derives. Capturing SELinux
        // would attach a host label to *every* file on an SELinux-labelled host
        // (Fedora/RHEL) and bloat every inode's xattr area for nothing.
        assert!(!xattr_matters_for_guest("security.selinux"));
        assert!(!xattr_matters_for_guest("security.ima"));
        assert!(!xattr_matters_for_guest("security.evm"));
        assert!(!xattr_matters_for_guest("com.apple.provenance"));
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn xattr_bearing_tree_materializes_in_process() {
        let src = tempfile::tempdir().unwrap();
        let bin = src.path().join("ping");
        std::fs::write(&bin, b"\x7fELF fake binary").unwrap();
        // Skip where the host FS can't hold xattrs (some CI tmpfs). A small
        // `user.*` attr fits the in-inode area, so the pure writer represents it
        // and materialize succeeds — no builder-VM fallback.
        if xattr::set(&bin, "user.mvm.test_cap", b"cap").is_err() {
            return;
        }
        assert_eq!(
            collect_guest_xattrs(&bin),
            vec![mvm_ext4::Xattr {
                name: "user.mvm.test_cap".into(),
                value: b"cap".to_vec(),
            }],
            "the walk must capture the image-semantic xattr"
        );
        let out = tempfile::tempdir().unwrap();
        let input =
            MaterializeExt4Input::new(src.path().to_path_buf(), out.path().join("rootfs.ext4"), 0);
        materialize_ext4_pure(&input).expect("a small xattr fits inline; materialize succeeds");
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn oversized_xattr_falls_back_to_builder_vm() {
        let src = tempfile::tempdir().unwrap();
        let bin = src.path().join("big");
        std::fs::write(&bin, b"x").unwrap();
        // A value far larger than the ~90-byte in-inode area can't be written
        // inline (no external xattr block yet), so the build errors — and that
        // error must route to the builder-VM fallback, not surface.
        if xattr::set(&bin, "user.big", &vec![0u8; 512]).is_err() {
            return;
        }
        let out = tempfile::tempdir().unwrap();
        let input =
            MaterializeExt4Input::new(src.path().to_path_buf(), out.path().join("rootfs.ext4"), 0);
        let err = materialize_ext4_pure(&input).expect_err("an oversized xattr can't be inline");
        assert!(
            err.pure_should_fall_back(),
            "an oversized xattr must route to the builder-VM fallback, got {err:?}"
        );
    }

    #[cfg(feature = "builder-vm")]
    use crate::builder_backend_select::{BuilderBackendChoice, MVM_BUILDER_BACKEND_ENV};
    #[cfg(feature = "builder-vm")]
    use mvm_core::util::test_env::TestEnv;

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_writes_a_valid_ext4_from_a_dir_tree() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("hosts", src.path().join("etc/localhost")).unwrap();

        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0);

        let mat = materialize_ext4_pure(&input).expect("pure materialize");
        assert_eq!(mat.path, out_path);
        assert!(mat.size_bytes > 0);

        let img = std::fs::read(&out_path).unwrap();
        assert_eq!(img.len() as u64, mat.size_bytes);
        // ext4 superblock magic 0xEF53 (LE) at byte 1024 + 0x38.
        assert_eq!(&img[1024 + 0x38..1024 + 0x3A], &[0x53, 0xEF]);
        // Deterministic: same tree materializes to byte-identical output.
        let out2 = out.path().join("rootfs2.ext4");
        let input2 = MaterializeExt4Input::new(src.path().to_path_buf(), out2.clone(), 0);
        materialize_ext4_pure(&input2).unwrap();
        assert_eq!(std::fs::read(&out2).unwrap(), img);

        // Default (no `with_verity`): no root hash, no sidecars — the run path
        // boots these images without rootfs verity, so a probe must find nothing.
        assert!(mat.verity_root_hash.is_none());
        assert!(!out.path().join("rootfs.verity").exists());
        assert!(!out.path().join("rootfs.roothash").exists());
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_matches_dense_writer_bytes() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();

        let nodes = collect_nodes(src.path()).expect("collect nodes");
        let dense = mvm_ext4::build_image(&nodes).expect("dense ext4 image");

        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0);
        let materialized = materialize_ext4_pure(&input).expect("pure materialize");

        assert_eq!(std::fs::read(&out_path).unwrap(), dense);
        assert_eq!(materialized.size_bytes, dense.len() as u64);
    }

    #[cfg(all(feature = "pure-mkfs", unix))]
    #[test]
    fn collect_nodes_reads_owner_unreadable_files_without_changing_guest_mode() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("etc")).unwrap();
        let shadow = src.path().join("etc/shadow");
        std::fs::write(&shadow, b"root:*:19793:0:99999:7:::\n").unwrap();
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o0)).unwrap();

        let nodes = collect_nodes(src.path()).expect("collect nodes");
        let node = nodes
            .into_iter()
            .find_map(|node| match node {
                mvm_ext4::Node::File {
                    path, mode, data, ..
                } if path == "/etc/shadow" => Some((mode, data)),
                _ => None,
            })
            .expect("shadow file node");

        assert_eq!(node.0, 0);
        assert_eq!(node.1, b"root:*:19793:0:99999:7:::\n");
        let restored_mode = std::fs::symlink_metadata(&shadow)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(restored_mode, 0);
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_with_verity_writes_sidecars() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input =
            MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0).with_verity();

        let mat = materialize_ext4_pure(&input).expect("pure materialize with verity");

        // The returned root hash is 64-hex and both sidecars land beside the
        // image under the fixed names the boot path probes for.
        let root_hex = mat.verity_root_hash.expect("verity root hash");
        assert_eq!(root_hex.len(), 64);
        assert!(root_hex.chars().all(|c| c.is_ascii_hexdigit()));
        let verity = std::fs::read(out.path().join("rootfs.verity")).expect("hash tree sidecar");
        assert!(!verity.is_empty());
        let roothash = std::fs::read_to_string(out.path().join("rootfs.roothash")).unwrap();
        assert_eq!(roothash, format!("{root_hex}\n"));
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_rejects_non_directory() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let input =
            MaterializeExt4Input::new(f.path().to_path_buf(), f.path().with_extension("ext4"), 0);
        assert!(matches!(
            materialize_ext4_pure(&input),
            Err(RootfsError::UnpackedRootNotDirectory(_))
        ));
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_creates_missing_output_parent() {
        // The run path's cache dir may not exist yet; the pure writer must
        // create it rather than fail with ENOENT.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"x").unwrap();
        let out = tempfile::tempdir().unwrap();
        let nested = out
            .path()
            .join("rootfs")
            .join("deadbeef")
            .join("rootfs.ext4");
        assert!(!nested.parent().unwrap().exists());

        let input = MaterializeExt4Input::new(src.path().to_path_buf(), nested.clone(), 0);
        materialize_ext4_pure(&input).expect("pure materialize into a missing parent dir");
        assert!(nested.is_file());
    }

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
    fn materializer_defaults_to_resolved_backend() {
        let mut env = TestEnv::new();
        env.remove(MVM_BUILDER_BACKEND_ENV);

        // No override → the resolved backend (macOS 26+ Apple Silicon → Vz,
        // everywhere else → libkrun). On a Vz Mac, forcing libkrun looked for an
        // `aarch64` builder image that is never built there.
        assert_eq!(
            ext4_materializer_choice(),
            crate::builder_backend_select::auto_detect_default()
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn materializer_honors_explicit_qemu_backend() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_BACKEND_ENV, "qemu");

        assert_eq!(ext4_materializer_choice(), BuilderBackendChoice::Qemu);
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
