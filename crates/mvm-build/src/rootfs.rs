//! Rootfs image materialization helpers.
//!
//! Takes an OCI-unpacked directory tree and turns it into the
//! `rootfs.ext4` disk image that the runtime can boot. Two arms share
//! one entry surface:
//!
//! - the pure path delegates the tree walk + in-process emission to
//!   [`mvm_fs::rootfs`] (the single walker/materializer implementation)
//!   and layers dm-verity sidecar emission on top;
//! - the builder-VM path allocates the sparse output file, then asks
//!   the existing builder VM to run `mkfs.ext4`, mount the new
//!   filesystem, copy the unpacked tree into it, and unmount — keeping
//!   ext4 creation inside the Linux builder boundary for trees the
//!   pure writer structurally can't represent.

#[cfg(feature = "builder-vm")]
use std::path::Path;
use std::path::PathBuf;

use mvm_contract::builder::BuilderError;
use thiserror::Error;

const DEFAULT_MIN_IMAGE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_SIZE_MULTIPLIER_NUMERATOR: u64 = 3;
const DEFAULT_SIZE_MULTIPLIER_DENOMINATOR: u64 = 2;
const DEFAULT_GUEST_OUTPUT_DEVICE: &str = "/dev/vdc";

/// ext4 volume label stamped on the libkrun Stage 0 `/work` disk
/// (`libkrun_builder::run_stage0_impl`) so `stage0-init` can find it by
/// content instead of by device-enumeration order. ext4's on-disk
/// `s_volume_name` field caps at 16 bytes; kept well under that. Lives here
/// (ungated) rather than behind `pure-mkfs` so the Stage 0 guest binary,
/// which only needs the string and not the writer, can reference it
/// regardless of which features its own build enables.
pub const STAGE0_WORK_EXT4_LABEL: &str = "mvm-work";

/// ext4 volume label on the persistent Stage 0 Nix store image.
///
/// The store used to be located by device letter, which couples it to how many
/// block devices the backend happens to attach ahead of it. Adding one drive —
/// the FlowMux identity disk — shifted every device behind it, so the guest
/// mounted a 32 KiB identity image as its Nix store, failed, and silently fell
/// back to a RAM-backed tmpfs that cannot hold a kernel source tree. The build
/// then died thousands of lines later on `No space left on device`.
pub const STAGE0_NIX_STORE_EXT4_LABEL: &str = "mvm-nix-store";

/// Inputs for [`materialize_ext4`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeExt4Input {
    /// Directory tree produced by the OCI layer unpacker.
    pub unpacked_root: PathBuf,
    /// Host path of the sparse ext4 image to create.
    pub output: PathBuf,
    /// Sum of OCI layer uncompressed sizes for this image.
    pub uncompressed_size_bytes: u64,
    /// When true, materialization also computes dm-verity and writes the
    /// `rootfs.verity` + `rootfs.roothash` sidecars beside the image. Off by
    /// default so generic callers can opt in deliberately; the run-image path
    /// turns it on to make OCI block roots sealed across both the pure and
    /// builder-VM materializers.
    pub emit_verity: bool,
    /// ext4 volume label (`s_volume_name`) to stamp on the pure-path image,
    /// truncated to 16 bytes by the underlying writer. `None` (the default)
    /// leaves the field zeroed, unchanged from before this option existed.
    /// Only consulted by [`materialize_ext4_pure`] — the builder-VM path
    /// (`materialize_ext4`) doesn't stamp a label.
    pub volume_label: Option<String>,
    /// Nodes the OCI unpacker could not place on the host tree because
    /// the host filesystem folds case, carried here so the image still
    /// gets them. See
    /// [`mvm_fs::oci::unpack::UnpackReport::deferred_nodes`]. Empty on
    /// Linux and on any case-sensitive volume.
    pub deferred_nodes: Vec<mvm_fs::ext4::Node>,
}

impl MaterializeExt4Input {
    /// Start building a [`MaterializeExt4Input`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> MaterializeExt4InputBuilder {
        MaterializeExt4InputBuilder::new()
    }
}

/// Builder for [`MaterializeExt4Input`]. Required fields are checked by
/// [`MaterializeExt4InputBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct MaterializeExt4InputBuilder {
    unpacked_root: Option<PathBuf>,
    output: Option<PathBuf>,
    uncompressed_size_bytes: Option<u64>,
    emit_verity: Option<bool>,
    volume_label: Option<String>,
    deferred_nodes: Option<Vec<mvm_fs::ext4::Node>>,
}

impl MaterializeExt4InputBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            unpacked_root: None,
            output: None,
            uncompressed_size_bytes: None,
            emit_verity: None,
            volume_label: None,
            deferred_nodes: None,
        }
    }

    /// Set `unpacked_root`.
    #[must_use]
    pub fn unpacked_root(mut self, unpacked_root: PathBuf) -> Self {
        self.unpacked_root = Some(unpacked_root);
        self
    }

    /// Set `output`.
    #[must_use]
    pub fn output(mut self, output: PathBuf) -> Self {
        self.output = Some(output);
        self
    }

    /// Set `uncompressed_size_bytes`.
    #[must_use]
    pub fn uncompressed_size_bytes(mut self, uncompressed_size_bytes: u64) -> Self {
        self.uncompressed_size_bytes = Some(uncompressed_size_bytes);
        self
    }

    /// Set `emit_verity`.
    #[must_use]
    pub fn emit_verity(mut self, emit_verity: bool) -> Self {
        self.emit_verity = Some(emit_verity);
        self
    }

    /// Set `volume_label`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn volume_label(mut self, volume_label: impl Into<Option<String>>) -> Self {
        self.volume_label = volume_label.into();
        self
    }

    /// Set `deferred_nodes`.
    #[must_use]
    pub fn deferred_nodes(mut self, deferred_nodes: Vec<mvm_fs::ext4::Node>) -> Self {
        self.deferred_nodes = Some(deferred_nodes);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<MaterializeExt4Input, BuilderError> {
        Ok(MaterializeExt4Input {
            unpacked_root: self.unpacked_root.ok_or(BuilderError::missing(
                "MaterializeExt4Input",
                "unpacked_root",
            ))?,
            output: self
                .output
                .ok_or(BuilderError::missing("MaterializeExt4Input", "output"))?,
            uncompressed_size_bytes: self.uncompressed_size_bytes.ok_or(BuilderError::missing(
                "MaterializeExt4Input",
                "uncompressed_size_bytes",
            ))?,
            emit_verity: self
                .emit_verity
                .ok_or(BuilderError::missing("MaterializeExt4Input", "emit_verity"))?,
            volume_label: self.volume_label,
            deferred_nodes: self.deferred_nodes.ok_or(BuilderError::missing(
                "MaterializeExt4Input",
                "deferred_nodes",
            ))?,
        })
    }
}

impl Default for MaterializeExt4InputBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MaterializeExt4Input {
    pub fn new(unpacked_root: PathBuf, output: PathBuf, uncompressed_size_bytes: u64) -> Self {
        Self {
            unpacked_root,
            output,
            uncompressed_size_bytes,
            emit_verity: false,
            volume_label: None,
            deferred_nodes: Vec::new(),
        }
    }

    /// Carry the unpacker's deferred nodes into the image.
    pub fn with_deferred_nodes(mut self, deferred_nodes: Vec<mvm_fs::ext4::Node>) -> Self {
        self.deferred_nodes = deferred_nodes;
        self
    }

    /// Opt into dm-verity sidecar emission on the pure path.
    pub fn with_verity(mut self) -> Self {
        self.emit_verity = true;
        self
    }

    /// Stamp an ext4 volume label on the pure-path image (e.g.
    /// [`STAGE0_WORK_EXT4_LABEL`]), so a guest can mount it by content
    /// instead of by device path.
    pub fn with_volume_label(mut self, label: impl Into<String>) -> Self {
        self.volume_label = Some(label.into());
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

impl MaterializeExt4Options {
    /// Start building a [`MaterializeExt4Options`] from its defaults. Every value is
    /// set by name, so a call site cannot transpose two fields that
    /// share a type.
    #[must_use]
    pub fn builder() -> MaterializeExt4OptionsBuilder {
        MaterializeExt4OptionsBuilder::new()
    }
}

/// Builder for [`MaterializeExt4Options`]. Unset fields keep the value
/// `MaterializeExt4Options::default()` gives them.
#[derive(Default)]
pub struct MaterializeExt4OptionsBuilder {
    inner: MaterializeExt4Options,
}

impl MaterializeExt4OptionsBuilder {
    /// A builder holding the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MaterializeExt4Options::default(),
        }
    }

    /// Set `min_image_size_bytes`.
    #[must_use]
    pub fn min_image_size_bytes(mut self, min_image_size_bytes: u64) -> Self {
        self.inner.min_image_size_bytes = min_image_size_bytes;
        self
    }

    /// Set `size_multiplier_numerator`.
    #[must_use]
    pub fn size_multiplier_numerator(mut self, size_multiplier_numerator: u64) -> Self {
        self.inner.size_multiplier_numerator = size_multiplier_numerator;
        self
    }

    /// Set `size_multiplier_denominator`.
    #[must_use]
    pub fn size_multiplier_denominator(mut self, size_multiplier_denominator: u64) -> Self {
        self.inner.size_multiplier_denominator = size_multiplier_denominator;
        self
    }

    /// Set `guest_output_device`.
    #[must_use]
    pub fn guest_output_device(mut self, guest_output_device: String) -> Self {
        self.inner.guest_output_device = guest_output_device;
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> MaterializeExt4Options {
        self.inner
    }
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
    /// 64-char lowercase-hex dm-verity root hash when the materializer wrote
    /// `rootfs.verity` + `rootfs.roothash` beside the image.
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

    #[error("dm-verity sidecar emission requires the `pure-mkfs` feature")]
    VerityFeatureDisabled,

    #[error(
        "the builder-VM materializer copies the host tree, so it cannot supply the {0} \
         path(s) the host filesystem could not hold; use the in-process materializer \
         (unset MVM_MATERIALIZE_BUILDER_VM) for this image"
    )]
    DeferredNodesUnsupported(usize),

    #[cfg(feature = "builder-vm")]
    #[error("builder VM ext4 materialization failed: {0}")]
    BuilderVm(#[from] crate::builder_vm::BuilderVmError),

    #[cfg(feature = "pure-mkfs")]
    #[error("walking directory tree at {path}: {source}")]
    PureWalk {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[cfg(feature = "pure-mkfs")]
    #[error(
        "host path {0} is a device, FIFO, or socket special file the ext4 writer cannot represent"
    )]
    UnsupportedNodeType(PathBuf),

    #[cfg(feature = "pure-mkfs")]
    #[error("building ext4 image in-process: {0}")]
    PureBuild(#[from] mvm_fs::ext4::Ext4Error),

    #[cfg(feature = "pure-mkfs")]
    #[error("reading rootfs image {path}: {source}")]
    ReadOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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

#[cfg(feature = "pure-mkfs")]
impl From<mvm_fs::rootfs::MaterializeError> for RootfsError {
    fn from(err: mvm_fs::rootfs::MaterializeError) -> Self {
        use mvm_fs::rootfs::MaterializeError;

        match err {
            MaterializeError::Walk { path, source } => RootfsError::PureWalk { path, source },
            MaterializeError::UnsupportedNodeType(path) => RootfsError::UnsupportedNodeType(path),
            MaterializeError::Build(err) => RootfsError::PureBuild(err),
            MaterializeError::Write { path, source } => RootfsError::WriteOutput { path, source },
        }
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
    let heuristic = mvm_fs::rootfs::SizeHeuristic {
        min_image_size_bytes: options.min_image_size_bytes,
        multiplier_numerator: options.size_multiplier_numerator,
        multiplier_denominator: options.size_multiplier_denominator,
    };
    heuristic
        .estimate(uncompressed_size_bytes)
        .map_err(|mvm_fs::rootfs::InvalidSizeMultiplier| RootfsError::InvalidSizeMultiplier)
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

        let verity_root_hash = maybe_emit_verity_sidecars(input)?;

        Ok(MaterializedExt4 {
            path: input.output.clone(),
            size_bytes,
            verity_root_hash,
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

    // This path copies `/work` (the host tree) into the mounted ext4, so
    // it has no way to place a node the host tree never held. Fail closed
    // rather than emit an image that is quietly missing paths.
    if !input.deferred_nodes.is_empty() {
        return Err(RootfsError::DeferredNodesUnsupported(
            input.deferred_nodes.len(),
        ));
    }

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
            BuilderBackendChoice::WebLinux => Err(crate::builder_vm::BuilderVmError::VmmUnavailable {
                requested: "web-linux".into(),
                reason: "the web-linux builder is browser-only; select libkrun, qemu, or hvf on a native host".into(),
            }),
        }
    })?;
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn ext4_materializer_choice() -> crate::builder_backend_select::BuilderBackendChoice {
    // Use the resolved builder backend (override → env → auto-detect: macOS 26+
    // Apple Silicon → hvf builder, Linux native → qemu builder, everywhere
    // else → libkrun). Delegates to `resolve_choice()` so the materializer
    // always uses the same backend as every other build entry point.
    crate::builder_backend_select::resolve_choice()
}

/// Safety margin (bytes) left between the formatted ext4 size and the
/// backing device size. The builder VM (libkrun) and the workload
/// backends (HVF, Firecracker) can report a virtio-blk device size that
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
/// builder VM, no `mkfs`, no subprocess. Delegates the tree walk + streamed
/// emission to [`mvm_fs::rootfs::materialize_ext4_pure`] (the single
/// walker/materializer implementation), then layers the dm-verity sidecar
/// emission this crate's run path expects on top.
///
/// This is the no-shell path the local run uses. Unsealed callers stream the
/// assembled image to disk while retaining the walked file contents; verity
/// callers additionally retain the dense image bytes needed to build the hash
/// tree. The output is a valid ext4 real readers mount; integrity is provided
/// by dm-verity, added on top (not by in-filesystem checksums).
pub fn materialize_ext4_pure(
    input: &MaterializeExt4Input,
) -> Result<MaterializedExt4, RootfsError> {
    materialize_ext4_pure_with_walk_options(input, mvm_fs::rootfs::WalkOptions::default())
}

/// Materialize with caller-selected source-walk behavior.
///
/// Immutable OCI roots use [`mvm_fs::rootfs::WalkOptions::default`]. Live
/// directory snapshots may instead omit entries that vanish during capture
/// while preserving the same ext4 construction path.
#[cfg(feature = "pure-mkfs")]
pub fn materialize_ext4_pure_with_walk_options(
    input: &MaterializeExt4Input,
    walk: mvm_fs::rootfs::WalkOptions,
) -> Result<MaterializedExt4, RootfsError> {
    if !input.unpacked_root.is_dir() {
        return Err(RootfsError::UnpackedRootNotDirectory(
            input.unpacked_root.clone(),
        ));
    }
    // Stage-0 /work is mounted by label; every other caller leaves
    // volume_label None and gets the unchanged default-options image.
    let mut options = mvm_fs::rootfs::MaterializeOptions::builder()
        .walk(walk)
        .extra_nodes(input.deferred_nodes.clone())
        .build();
    if let Some(label) = &input.volume_label {
        options = options.with_volume_label(label.as_bytes());
    }
    if !input.emit_verity {
        let materialized =
            mvm_fs::rootfs::materialize_ext4_pure(&input.unpacked_root, &input.output, &options)?;
        return Ok(MaterializedExt4 {
            path: materialized.path,
            size_bytes: materialized.size_bytes,
            verity_root_hash: None,
        });
    }

    // Verity needs the dense image bytes to construct its hash tree. Keep that
    // path in memory, while unsealed callers above stream sparse ranges to the
    // output file and avoid retaining a second image-sized allocation.
    let (image, size_bytes) = mvm_fs::rootfs::build_ext4_pure(&input.unpacked_root, &options)?;

    if let Some(parent) = input.output.parent() {
        std::fs::create_dir_all(parent).map_err(|source| RootfsError::WriteOutput {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(&input.output, &image).map_err(|source| RootfsError::WriteOutput {
        path: input.output.clone(),
        source,
    })?;

    let verity_root_hash = Some(emit_verity_sidecars_for_image(&input.output, &image)?);

    Ok(MaterializedExt4 {
        path: input.output.clone(),
        size_bytes,
        verity_root_hash,
    })
}

#[cfg(feature = "pure-mkfs")]
fn write_sidecar(path: &std::path::Path, body: &[u8]) -> Result<(), RootfsError> {
    std::fs::write(path, body).map_err(|source| RootfsError::WriteOutput {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(all(feature = "pure-mkfs", feature = "builder-vm"))]
fn maybe_emit_verity_sidecars(input: &MaterializeExt4Input) -> Result<Option<String>, RootfsError> {
    if !input.emit_verity {
        return Ok(None);
    }

    let image = std::fs::read(&input.output).map_err(|source| RootfsError::ReadOutput {
        path: input.output.clone(),
        source,
    })?;
    Ok(Some(emit_verity_sidecars_for_image(&input.output, &image)?))
}

#[cfg(all(feature = "builder-vm", not(feature = "pure-mkfs")))]
fn maybe_emit_verity_sidecars(input: &MaterializeExt4Input) -> Result<Option<String>, RootfsError> {
    if input.emit_verity {
        return Err(RootfsError::VerityFeatureDisabled);
    }
    Ok(None)
}

#[cfg(feature = "pure-mkfs")]
fn emit_verity_sidecars_for_image(
    image_path: &std::path::Path,
    image: &[u8],
) -> Result<String, RootfsError> {
    // dm-verity, computed in-process (no `veritysetup`). The block sizes and
    // salt must match the pinned `mvm-verity-init` / `veritysetup` contract or
    // the guest will panic at boot with a mismatched hash-tree geometry.
    let salt = [0u8; 32];
    let verity = mvm_fs::ext4::verity::format(
        image,
        &salt,
        mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE as usize,
        mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE as usize,
    );
    let dir = image_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let root_hex = mvm_fs::ext4::verity::to_hex(&verity.root_hash);
    write_sidecar(&dir.join("rootfs.verity"), &verity.hash_tree)?;
    write_sidecar(
        &dir.join("rootfs.roothash"),
        format!("{root_hex}\n").as_bytes(),
    )?;
    Ok(root_hex)
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
        let capacity = RootfsError::PureBuild(mvm_fs::ext4::Ext4Error::FileTooFragmented {
            ino: 12,
            extents: 9,
        });
        assert!(
            capacity.is_pure_capacity_limit(),
            "a capacity limit must be retryable via the builder VM"
        );
        let malformed = RootfsError::PureBuild(mvm_fs::ext4::Ext4Error::BadPath("//a".into()));
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
    fn pure_materialize_without_a_label_leaves_volume_name_zeroed() {
        // Regression guard for the `with_volume_label` plumbing: a caller that
        // never opts in must get byte-identical output to before the option
        // existed — an all-zero `s_volume_name`.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0);

        materialize_ext4_pure(&input).expect("pure materialize");
        let img = std::fs::read(&out_path).unwrap();
        assert_eq!(&img[1024 + 0x78..1024 + 0x88], &[0u8; 16]);
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_with_a_label_stamps_the_ext4_volume_name() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0)
            .with_volume_label(STAGE0_WORK_EXT4_LABEL);

        materialize_ext4_pure(&input).expect("pure materialize");
        let img = std::fs::read(&out_path).unwrap();
        let mut expected = [0u8; 16];
        expected[..STAGE0_WORK_EXT4_LABEL.len()].copy_from_slice(STAGE0_WORK_EXT4_LABEL.as_bytes());
        assert_eq!(&img[1024 + 0x78..1024 + 0x88], &expected);
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn pure_materialize_matches_dense_writer_bytes() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();

        let nodes =
            mvm_fs::rootfs::collect_nodes(src.path(), mvm_fs::rootfs::WalkOptions::default())
                .expect("collect nodes");
        let dense = mvm_fs::ext4::build_image(nodes).expect("dense ext4 image");

        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0);
        let materialized = materialize_ext4_pure(&input).expect("pure materialize");

        assert_eq!(std::fs::read(&out_path).unwrap(), dense);
        assert_eq!(materialized.size_bytes, dense.len() as u64);
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
    fn emit_verity_sidecars_can_seal_an_existing_image() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0);

        let mat = materialize_ext4_pure(&input).expect("pure materialize");
        assert!(mat.verity_root_hash.is_none());

        let image = std::fs::read(&out_path).unwrap();
        let root_hex = emit_verity_sidecars_for_image(&out_path, &image).expect("emit sidecars");
        assert_eq!(root_hex.len(), 64);
        assert!(out.path().join("rootfs.verity").is_file());
        assert_eq!(
            std::fs::read_to_string(out.path().join("rootfs.roothash")).unwrap(),
            format!("{root_hex}\n")
        );
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn emit_verity_sidecars_uses_the_pinned_boot_contract_block_sizes() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let input = MaterializeExt4Input::new(src.path().to_path_buf(), out_path.clone(), 0);
        materialize_ext4_pure(&input).expect("pure materialize");

        let image = std::fs::read(&out_path).unwrap();
        let root_hex = emit_verity_sidecars_for_image(&out_path, &image).expect("emit sidecars");
        let actual_sidecar = std::fs::read(out.path().join("rootfs.verity")).unwrap();
        let expected = mvm_fs::ext4::verity::format(
            &image,
            &[0u8; 32],
            mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE as usize,
            mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE as usize,
        );
        let wrong_contract = mvm_fs::ext4::verity::format(&image, &[0u8; 32], 1024, 4096);

        assert_eq!(actual_sidecar, expected.hash_tree);
        assert_eq!(root_hex, mvm_fs::ext4::verity::to_hex(&expected.root_hash));
        assert_ne!(
            actual_sidecar, wrong_contract.hash_tree,
            "the pure path must not drift to the older 1K/4K verity geometry"
        );
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

        // No override → the resolved backend (macOS 26+ Apple Silicon → HVF,
        // everywhere else → libkrun). On an HVF Mac, forcing libkrun looked for an
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

#[cfg(test)]
mod materialize_ext4_input_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = MaterializeExt4Input::builder().build() else {
            panic!("an empty MaterializeExt4Input builder must not build");
        };
        assert_eq!(
            err,
            BuilderError::missing("MaterializeExt4Input", "unpacked_root")
        );
    }
}

#[cfg(test)]
mod materialize_ext4_options_builder_tests {
    use super::*;

    /// A builder nobody touched has to agree with `MaterializeExt4Options::default()`,
    /// or an unset field silently means something else.
    #[test]
    fn an_untouched_builder_matches_the_type_default() {
        assert!(MaterializeExt4Options::builder().build() == MaterializeExt4Options::default());
    }
}
