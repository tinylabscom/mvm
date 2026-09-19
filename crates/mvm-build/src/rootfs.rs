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

#[cfg(any(test, feature = "builder-vm"))]
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
    /// Owners the image layers declared, by guest path. The unpacked tree
    /// cannot carry them — the unpack runs unprivileged — so the pure writer
    /// applies them to the walked nodes. Empty for a tree that is not built
    /// from image layers, which leaves every node root-owned.
    pub owners: mvm_fs::ownership::OwnerTable,
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
    owners: Option<mvm_fs::ownership::OwnerTable>,
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
            owners: None,
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

    /// Set `owners`.
    #[must_use]
    pub fn owners(mut self, owners: mvm_fs::ownership::OwnerTable) -> Self {
        self.owners = Some(owners);
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
            owners: self
                .owners
                .ok_or(BuilderError::missing("MaterializeExt4Input", "owners"))?,
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
            owners: mvm_fs::ownership::OwnerTable::new(),
        }
    }

    /// Carry the unpacker's deferred nodes into the image.
    pub fn with_deferred_nodes(mut self, deferred_nodes: Vec<mvm_fs::ext4::Node>) -> Self {
        self.deferred_nodes = deferred_nodes;
        self
    }

    /// Give the image the owners its layers declared.
    pub fn with_owners(mut self, owners: mvm_fs::ownership::OwnerTable) -> Self {
        self.owners = owners;
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

/// How a materialization reached the builder-VM writer.
///
/// The builder VM copies the host tree, so it cannot place a path the host
/// filesystem refused or an owner an unprivileged unpack could not apply. What
/// to do about that depends entirely on how the run got here, and naming the
/// wrong one sends a reader after a setting nobody set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderVmRoute {
    /// Asked for outright, so the in-process writer was never tried and is
    /// still available.
    Selected,
    /// Reached automatically after the in-process writer could not emit this
    /// image, carrying the failure that sent it here. Nothing was configured;
    /// the image itself is what has to change.
    PureFallback { because: String },
}

impl BuilderVmRoute {
    /// The half of a refusal that tells a reader what to do about it.
    fn remedy(&self) -> String {
        match self {
            Self::Selected => {
                "use the in-process materializer (unset MVM_MATERIALIZE_BUILDER_VM) for this image"
                    .to_string()
            }
            Self::PureFallback { because } => format!(
                "the in-process materializer, which can, was tried first and could not emit this \
                 image ({because}), so no materializer can build it faithfully"
            ),
        }
    }
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
        "the builder-VM materializer copies the host tree, so it cannot supply the {count} \
         path(s) the host filesystem could not hold; {}", route.remedy()
    )]
    DeferredNodesUnsupported { count: usize, route: BuilderVmRoute },

    #[error(
        "the builder-VM materializer copies the host tree, so it cannot give the {count} \
         path(s) the image layers assign to a non-root account their owners; {}", route.remedy()
    )]
    LayerOwnershipUnsupported { count: usize, route: BuilderVmRoute },

    #[error(
        "the builder-VM materializer cannot carry the extended attribute {name} on {} \
         (file capabilities and ACLs are lost in its copy); {}", path.display(), route.remedy()
    )]
    XattrUnsupported {
        path: PathBuf,
        name: String,
        route: BuilderVmRoute,
    },

    #[error("archiving {path} for the builder VM: {source}")]
    ArchiveTree {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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
    /// VM, which has no size limits. It carries no extended attributes, so a
    /// tree whose attributes overflowed the in-process writer is refused there
    /// in turn, naming this failure. A malformed tree or I/O error is genuine
    /// and surfaces unchanged.
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
///
/// `route` is how the caller got here, and is only ever read to explain a
/// refusal. It is a parameter rather than a default so a caller cannot reach
/// this writer without saying which it is.
pub fn materialize_ext4(
    input: &MaterializeExt4Input,
    options: &MaterializeExt4Options,
    route: &BuilderVmRoute,
) -> Result<MaterializedExt4, RootfsError> {
    if !input.unpacked_root.is_dir() {
        return Err(RootfsError::UnpackedRootNotDirectory(
            input.unpacked_root.clone(),
        ));
    }

    refuse_tree_only_materialization_loss(input, route)?;
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

/// The builder-VM materializer copies the host tree into the image, so
/// anything the host tree cannot hold is lost: a node the host filesystem
/// refused, and an owner an unprivileged unpack could not apply. Fail closed
/// rather than emit an image that is quietly missing paths or has a service's
/// files owned by root.
///
/// The refusal carries `route` because the two ways to be here have different
/// causes: an operator who asked for this writer can stop asking, while an
/// automatic fallback was reached without anyone configuring anything.
fn refuse_tree_only_materialization_loss(
    input: &MaterializeExt4Input,
    route: &BuilderVmRoute,
) -> Result<(), RootfsError> {
    if !input.deferred_nodes.is_empty() {
        return Err(RootfsError::DeferredNodesUnsupported {
            count: input.deferred_nodes.len(),
            route: route.clone(),
        });
    }
    // A path the builder claims is set back to root after the copy, so a
    // layer owner there is not one this writer loses.
    let non_root = input
        .owners
        .non_root_count(&crate::oci_runtime_inject::injected_root_owned_paths());
    if non_root > 0 {
        return Err(RootfsError::LayerOwnershipUnsupported {
            count: non_root,
            route: route.clone(),
        });
    }
    // The archive this writer hands the builder carries no extended
    // attributes, and the builder's `tar` could not restore them if it did.
    let xattr =
        mvm_fs::rootfs::first_guest_semantic_xattr(&input.unpacked_root).map_err(|source| {
            RootfsError::ArchiveTree {
                path: input.unpacked_root.clone(),
                source,
            }
        })?;
    if let Some((path, name)) = xattr {
        return Err(RootfsError::XattrUnsupported {
            path,
            name,
            route: route.clone(),
        });
    }
    Ok(())
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

/// The builder job that turns the tree into an image: the tree archived into
/// `work`, which becomes the job's `/work`, and a script that extracts that
/// archive onto the output disk. The tree itself is never the job's input —
/// the generic staging a work directory passes through drops names and reads
/// special files.
#[cfg(feature = "builder-vm")]
fn builder_rootfs_job(
    input: &MaterializeExt4Input,
    options: &MaterializeExt4Options,
    device_size_bytes: u64,
    work: &Path,
) -> Result<crate::builder_vm::BuilderShellJob, RootfsError> {
    write_rootfs_archive(&input.unpacked_root, &work.join(ROOTFS_ARCHIVE_NAME))?;
    Ok(crate::builder_vm::BuilderShellJob {
        work_dir: work.to_path_buf(),
        artifact_out: input
            .output
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        script: ext4_materialization_script(
            &options.guest_output_device,
            device_size_bytes,
            &crate::oci_runtime_inject::injected_root_owned_paths(),
        ),
        extra_disks: vec![crate::builder_vm::BuilderExtraDisk {
            id: "oci-rootfs".to_string(),
            path: input.output.clone(),
            read_only: false,
        }],
    })
}

#[cfg(feature = "builder-vm")]
fn materialize_ext4_in_builder_vm(
    input: &MaterializeExt4Input,
    options: &MaterializeExt4Options,
    device_size_bytes: u64,
) -> Result<(), RootfsError> {
    let artifact_out = input
        .output
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    // Beside the output rather than in the system temp dir: this path runs for
    // the images too large for the in-process writer, and the archive is the
    // size of the tree.
    let work = tempfile::Builder::new()
        .prefix("mvm-rootfs-archive-")
        .tempdir_in(&artifact_out)
        .map_err(|source| RootfsError::ArchiveTree {
            path: artifact_out.clone(),
            source,
        })?;
    let shell_job = builder_rootfs_job(input, options, device_size_bytes, work.path())?;

    // Keep the materializer on the same builder-backend policy as the rest of
    // the builder surface. In particular, do not silently retry on qemu here:
    // qemu's user-net path is a dev/test tier, not a production substitute for
    // the vsock-oriented builder/runtime contract.
    let selected = ext4_materializer_choice();
    let explicit = crate::builder_backend_select::resolve_env_override().is_some();
    crate::builder_backend_select::run_with_builder_fallback(selected, explicit, |choice| {
        // Through the trait, so the backend the selection resolved is the one
        // that runs the job. This used to match on the choice here, and mapped
        // `Hvf` onto `LibkrunBuilderVm` — which quietly ran an HVF host's shell
        // jobs on libkrun, and is exactly the coupling the builder path is
        // meant not to have.
        crate::builder_backend_select::try_resolve_builder_backend_for(choice)?
            .run_shell_script(&shell_job)
            .map(|_| ())
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
///
/// The tree arrives as [`ROOTFS_ARCHIVE_NAME`], written by
/// [`write_rootfs_archive`] with every entry owned 0:0. `root_owned` names the
/// paths the image builder owns; the script sets each back to root after the
/// extraction anyway, the same guarantee the in-process writer gives through
/// the owner table, so it does not rest on the archive alone.
///
/// What `-h` does and does not promise: `chown -h` does not follow the final
/// component, and `chown -Rh` does not follow links it meets while recursing.
/// Neither stops the kernel resolving a symbolic link in an *intermediate*
/// component of the path it is given. That is safe here only because the host
/// refused, before injection, any tree in which a component leading to a
/// claimed path is a link.
#[cfg(any(test, feature = "builder-vm"))]
pub(crate) fn ext4_materialization_script(
    guest_output_device: &str,
    device_size_bytes: u64,
    root_owned: &mvm_fs::ownership::RootOwnedPaths,
) -> String {
    format!(
        r#"#!/bin/sh
set -eu

ROOTFS_DEV='{guest_output_device}'
MOUNTPOINT=/tmp/mvm-image-rootfs

chown_root() {{
    if [ -e "$1" ] || [ -L "$1" ]; then chown -h 0:0 "$1"; fi
}}
chown_root_tree() {{
    if [ -e "$1" ] || [ -L "$1" ]; then chown -Rh 0:0 "$1"; fi
}}

mkdir -p "$MOUNTPOINT"
/sbin/mkfs.ext4 -F -b {block_size} "$ROOTFS_DEV" {block_count}
mount -t ext4 "$ROOTFS_DEV" "$MOUNTPOINT"
trap 'umount "$MOUNTPOINT" 2>/dev/null || true' EXIT
tar -xf /work/{archive} -C "$MOUNTPOINT"
chown -h 0:0 "$MOUNTPOINT"
{chown_root_owned}sync
umount "$MOUNTPOINT"
trap - EXIT
"#,
        guest_output_device = shell_single_quote_escape(guest_output_device),
        block_size = EXT4_BLOCK_SIZE_BYTES,
        block_count = ext4_block_count(device_size_bytes),
        chown_root_owned = chown_root_owned_lines(root_owned),
        archive = ROOTFS_ARCHIVE_NAME,
    )
}

/// The one file the builder VM's `/work` holds for a rootfs job: the tree as a
/// tar the host wrote itself.
#[cfg(any(test, feature = "builder-vm"))]
const ROOTFS_ARCHIVE_NAME: &str = "mvm-rootfs.tar";

/// Archive the tree at `root` into `out` for the builder VM to extract.
///
/// The builder's generic work-input staging is built for source checkouts: it
/// drops `node_modules`, `target`, `dist`, `.git` and the rest at any depth,
/// and copies a special file by reading it. Applied to an image that deleted a
/// node image's `/usr/local/lib/node_modules`, and would hang on a FIFO. One
/// archive file passes through that staging untouched, so the tree the image
/// writer sees is the tree the host holds.
///
/// Each entry is written the way the image should hold it, not the way the
/// host does:
/// - owned 0:0, which is every owner this writer is allowed to emit (a
///   non-root layer owner outside the claimed paths is refused before this
///   runs), so the guest's `tar` does not restore the host account's ids;
/// - a symbolic link as a link, never its host target;
/// - an owner-unreadable file read the way the in-process writer reads one;
/// - a device, FIFO or socket omitted, as the in-process writer omits it:
///   `devtmpfs` supplies `/dev` at boot.
///
/// Entries are sorted, so the archive is a function of the tree.
#[cfg(any(test, feature = "builder-vm"))]
pub(crate) fn write_rootfs_archive(root: &Path, out: &Path) -> Result<(), RootfsError> {
    let archive_err = |path: &Path| {
        let path = path.to_path_buf();
        move |source| RootfsError::ArchiveTree { path, source }
    };
    let file = std::fs::File::create(out).map_err(archive_err(out))?;
    let mut builder = tar::Builder::new(std::io::BufWriter::new(file));
    builder.follow_symlinks(false);
    let mut stack = vec![PathBuf::new()];
    while let Some(dir_rel) = stack.pop() {
        let dir = root.join(&dir_rel);
        let mut names = std::fs::read_dir(&dir)
            .map_err(archive_err(&dir))?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(archive_err(&dir))?;
        names.sort();
        let mut subdirs = Vec::new();
        for name in names {
            let rel = dir_rel.join(&name);
            if append_archive_entry(&mut builder, root, &rel)? {
                subdirs.push(rel);
            }
        }
        // Reversed, so popping visits subdirectories in sorted order.
        stack.extend(subdirs.into_iter().rev());
    }
    builder
        .into_inner()
        .and_then(|writer| {
            writer
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)
        })
        .and_then(|file| file.sync_all())
        .map_err(archive_err(out))
}

/// Append the node at `root/rel` to `builder`. Returns whether it is a
/// directory the walk should descend into.
#[cfg(any(test, feature = "builder-vm"))]
fn append_archive_entry<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    rel: &Path,
) -> Result<bool, RootfsError> {
    let path = root.join(rel);
    let err = |source| RootfsError::ArchiveTree {
        path: path.clone(),
        source,
    };
    let meta = std::fs::symlink_metadata(&path).map_err(err)?;
    let file_type = meta.file_type();
    if !(file_type.is_dir() || file_type.is_file() || file_type.is_symlink()) {
        return Ok(false);
    }
    let mut header = tar::Header::new_gnu();
    header.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
    header.set_uid(0);
    header.set_gid(0);
    header.set_username("root").map_err(err)?;
    header.set_groupname("root").map_err(err)?;
    if file_type.is_symlink() {
        header.set_size(0);
        let target = std::fs::read_link(&path).map_err(err)?;
        builder
            .append_link(&mut header, rel, &target)
            .map_err(err)?;
        Ok(false)
    } else if file_type.is_dir() {
        header.set_size(0);
        builder
            .append_data(&mut header, rel, std::io::empty())
            .map_err(err)?;
        Ok(true)
    } else {
        // Streamed: this writer exists for the trees too large for the
        // in-process one, so a file is never held in memory whole. The size in
        // the header is the one `set_metadata_in_mode` read with the mode.
        let file = open_for_archive(&path).map_err(err)?;
        builder.append_data(&mut header, rel, file).map_err(err)?;
        Ok(false)
    }
}

/// Open a regular file of the tree for reading, widening an owner-unreadable
/// mode (a 0000 `/etc/shadow`) for the open alone. The mode is restored as
/// soon as the file is open — the descriptor stays readable — so the host
/// tree is left as it was however the archive then fails.
#[cfg(any(test, feature = "builder-vm"))]
fn open_for_archive(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::File::open(path) {
        Ok(file) => Ok(file),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            let original = std::fs::symlink_metadata(path)?.permissions().mode();
            let widened = original | 0o400;
            if widened == original {
                return Err(err);
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(widened))?;
            let opened = std::fs::File::open(path);
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(original))?;
            opened
        }
        Err(err) => Err(err),
    }
}

/// One `chown_root` line per claimed path and one `chown_root_tree` line per
/// claimed tree, each under the image mount point.
#[cfg(any(test, feature = "builder-vm"))]
fn chown_root_owned_lines(root_owned: &mvm_fs::ownership::RootOwnedPaths) -> String {
    let path_lines = root_owned.paths().map(|path| ("chown_root", path));
    let tree_lines = root_owned.trees().map(|tree| ("chown_root_tree", tree));
    path_lines
        .chain(tree_lines)
        .map(|(function, path)| {
            format!(
                "{function} \"$MOUNTPOINT\"'{}'\n",
                shell_single_quote_escape(path)
            )
        })
        .collect()
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

/// The writer options every in-process materialization runs under.
///
/// One function so the ownership guarantee cannot be lost by adding a second
/// entry point: the paths the runtime injects are claimed here, on every tree
/// rather than only on trees built from image layers. A tree carrying no
/// declared owners loses nothing by it, and no caller has to remember to ask.
///
/// Stage-0 `/work` is mounted by label; every other caller leaves
/// `volume_label` unset and gets the unchanged default-options image.
#[cfg(feature = "pure-mkfs")]
fn pure_materialize_options(
    input: &MaterializeExt4Input,
    walk: mvm_fs::rootfs::WalkOptions,
) -> mvm_fs::rootfs::MaterializeOptions {
    let options = mvm_fs::rootfs::MaterializeOptions::builder()
        .walk(walk)
        .extra_nodes(input.deferred_nodes.clone())
        .owners(input.owners.clone())
        .root_owned(crate::oci_runtime_inject::injected_root_owned_paths())
        .build();
    match &input.volume_label {
        Some(label) => options.with_volume_label(label.as_bytes()),
        None => options,
    }
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
    let options = pure_materialize_options(input, walk);
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
        let script = ext4_materialization_script(
            "/dev/vdc",
            64 * 1024 * 1024,
            &mvm_fs::ownership::RootOwnedPaths::none(),
        );
        // Formats to an explicit block count a margin below the device
        // so the image mounts on a backend reporting fewer blocks.
        assert!(script.contains("/sbin/mkfs.ext4 -F -b 4096 \"$ROOTFS_DEV\""));
        assert!(script.contains("mount -t ext4 \"$ROOTFS_DEV\" \"$MOUNTPOINT\""));
        assert!(script.contains("tar -xf /work/mvm-rootfs.tar -C \"$MOUNTPOINT\""));
        assert!(!script.contains("cp -aR"));
        assert!(script.contains("umount \"$MOUNTPOINT\""));
        assert!(!script.contains("mke2fs -d"));
    }

    /// The builder VM copies the host tree with the ids the transport carried
    /// — the host account's — so the files mvm injects are set back to root
    /// after the copy and before the image is flushed, matching the
    /// in-process writer's guarantee.
    #[test]
    fn script_sets_every_injected_path_back_to_root_after_the_copy() {
        let claimed = crate::oci_runtime_inject::injected_root_owned_paths();
        let script = ext4_materialization_script("/dev/vdc", 64 * 1024 * 1024, &claimed);
        let copy = script
            .find("tar -xf /work/mvm-rootfs.tar")
            .expect("extracts the tree");
        let image_root = script
            .find("\nchown -h 0:0 \"$MOUNTPOINT\"\n")
            .expect("the image root is set back to root, without following a link");
        assert!(copy < image_root);
        let flush = script.find("\nsync\n").expect("flushes the image");
        for line in [
            "chown_root \"$MOUNTPOINT\"'/etc/passwd'",
            "chown_root \"$MOUNTPOINT\"'/etc/group'",
            "chown_root \"$MOUNTPOINT\"'/etc'",
            "chown_root \"$MOUNTPOINT\"'/usr/lib/mvm/wrappers/oci-entrypoint'",
            "chown_root_tree \"$MOUNTPOINT\"'/etc/mvm'",
            "chown_root_tree \"$MOUNTPOINT\"'/mvm'",
        ] {
            let at = script
                .find(line)
                .unwrap_or_else(|| panic!("missing {line}"));
            assert!(copy < at && at < flush, "{line} must run after the copy");
        }
        assert_eq!(
            script.matches("chown_root ").count() + script.matches("chown_root_tree ").count(),
            claimed.paths().count() + claimed.trees().count(),
            "one line per claim, nothing else chowned"
        );
        assert!(
            script.contains("chown -h 0:0") && script.contains("chown -Rh 0:0"),
            "never follows a link out of the image"
        );
    }

    /// A claimed path the image does not carry — the trust policy on an
    /// unsealed run — is skipped rather than failing a `set -e` script.
    #[test]
    fn script_chowns_only_what_exists() {
        let script = ext4_materialization_script(
            "/dev/vdc",
            64 * 1024 * 1024,
            &mvm_fs::ownership::RootOwnedPaths::none().with_path("etc/absent"),
        );
        assert!(script.contains(r#"if [ -e "$1" ] || [ -L "$1" ]; then chown -h 0:0 "$1"; fi"#));
        assert!(script.contains("chown_root \"$MOUNTPOINT\"'/etc/absent'"));
    }

    fn archive_entries(archive: &Path) -> Vec<(String, tar::Header, Vec<u8>)> {
        let mut out = Vec::new();
        let mut reader = tar::Archive::new(std::fs::File::open(archive).unwrap());
        for entry in reader.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let header = entry.header().clone();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).unwrap();
            out.push((path.trim_end_matches('/').to_string(), header, body));
        }
        out
    }

    /// The builder VM receives the tree the host holds. The generic
    /// work-input staging drops `node_modules`, `target`, `dist`, `.git` at
    /// any depth; the archive is one file, so a node image keeps
    /// `/usr/local/lib/node_modules`.
    #[test]
    fn the_rootfs_archive_keeps_names_the_workspace_staging_drops() {
        let tree = tempfile::tempdir().unwrap();
        for dir in [
            "usr/local/lib/node_modules/npm",
            "srv/target",
            "srv/dist",
            "srv/.git",
            "srv/result",
        ] {
            std::fs::create_dir_all(tree.path().join(dir)).unwrap();
        }
        std::fs::write(
            tree.path().join("usr/local/lib/node_modules/npm/index.js"),
            b"js",
        )
        .unwrap();
        let out = tempfile::tempdir().unwrap();
        let archive = out.path().join(ROOTFS_ARCHIVE_NAME);

        write_rootfs_archive(tree.path(), &archive).unwrap();

        let paths: Vec<String> = archive_entries(&archive).into_iter().map(|e| e.0).collect();
        for kept in [
            "usr/local/lib/node_modules/npm/index.js",
            "srv/target",
            "srv/dist",
            "srv/.git",
            "srv/result",
        ] {
            assert!(
                paths.iter().any(|p| p == kept),
                "{kept} missing from {paths:?}"
            );
        }
        let again = out.path().join("again.tar");
        write_rootfs_archive(tree.path(), &again).unwrap();
        assert_eq!(
            std::fs::read(&archive).unwrap(),
            std::fs::read(&again).unwrap(),
            "the archive is a function of the tree"
        );
    }

    /// Every entry is root's whatever the host account is, keeps its mode
    /// (setuid included), and a link is stored as a link to the target it
    /// names, never the target's bytes.
    #[test]
    fn the_rootfs_archive_is_root_owned_mode_faithful_and_never_follows_links() {
        use std::os::unix::fs::PermissionsExt;

        let host = tempfile::tempdir().unwrap();
        let secret = host.path().join("id_ed25519");
        std::fs::write(&secret, b"host private key").unwrap();
        let tree = host.path().join("tree");
        std::fs::create_dir_all(tree.join("usr/bin")).unwrap();
        let su = tree.join("usr/bin/su");
        std::fs::write(&su, b"elf").unwrap();
        std::fs::set_permissions(&su, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let shadow = tree.join("shadow");
        std::fs::write(&shadow, b"root:*:").unwrap();
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::os::unix::fs::symlink(&secret, tree.join("k")).unwrap();
        let archive = host.path().join(ROOTFS_ARCHIVE_NAME);

        write_rootfs_archive(&tree, &archive).unwrap();

        let entries = archive_entries(&archive);
        for (path, header, body) in &entries {
            assert_eq!(header.uid().unwrap(), 0, "{path}");
            assert_eq!(header.gid().unwrap(), 0, "{path}");
            assert!(
                !body.windows(16).any(|w| w == b"host private key"),
                "{path} carries the host file a link names"
            );
        }
        let find = |name: &str| entries.iter().find(|e| e.0 == name).unwrap();
        assert_eq!(find("usr/bin/su").1.mode().unwrap() & 0o7777, 0o4755);
        let (_, shadow_header, shadow_body) = find("shadow");
        assert_eq!(shadow_header.mode().unwrap() & 0o7777, 0o000);
        assert_eq!(
            shadow_body, b"root:*:",
            "an owner-unreadable file is still read"
        );
        let (_, link, _) = find("k");
        assert_eq!(link.entry_type(), tar::EntryType::Symlink);
        assert_eq!(link.link_name().unwrap().unwrap(), secret);
        assert_eq!(
            std::fs::metadata(&shadow).unwrap().permissions().mode() & 0o7777,
            0o000,
            "the host file's mode is restored"
        );
    }

    /// A FIFO is omitted, as the in-process writer omits it, rather than read
    /// (which blocks forever) or failing the archive.
    #[test]
    fn the_rootfs_archive_omits_a_fifo_instead_of_reading_it() {
        let tree = tempfile::tempdir().unwrap();
        let fifo = tree.path().join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(tree.path().join("regular"), b"x").unwrap();
        let out = tempfile::tempdir().unwrap();
        let archive = out.path().join(ROOTFS_ARCHIVE_NAME);

        write_rootfs_archive(tree.path(), &archive).unwrap();

        let paths: Vec<String> = archive_entries(&archive).into_iter().map(|e| e.0).collect();
        assert_eq!(paths, ["regular"]);
    }

    /// The job the builder runs gets the archive as its whole `/work`, never
    /// the tree, and its script extracts exactly that archive.
    #[cfg(feature = "builder-vm")]
    #[test]
    fn the_builder_job_is_handed_the_archive_not_the_tree() {
        let tree = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tree.path().join("usr/local/lib/node_modules")).unwrap();
        std::fs::write(tree.path().join("usr/local/lib/node_modules/x.js"), b"js").unwrap();
        let out = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let input =
            MaterializeExt4Input::new(tree.path().to_path_buf(), out.path().join("rootfs.ext4"), 1);

        let job = builder_rootfs_job(
            &input,
            &MaterializeExt4Options::default(),
            64 * 1024 * 1024,
            work.path(),
        )
        .unwrap();

        assert_eq!(job.work_dir, work.path());
        assert_ne!(job.work_dir, input.unpacked_root);
        let listed: Vec<_> = std::fs::read_dir(&job.work_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(listed, [ROOTFS_ARCHIVE_NAME]);
        assert!(
            job.script
                .contains(&format!("tar -xf /work/{ROOTFS_ARCHIVE_NAME}"))
        );
        let paths: Vec<String> = archive_entries(&job.work_dir.join(ROOTFS_ARCHIVE_NAME))
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert!(paths.iter().any(|p| p == "usr/local/lib/node_modules/x.js"));
        assert_eq!(job.extra_disks[0].path, input.output);
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

        // No override → the resolved dependency-free backend (supported Apple
        // Silicon macOS → HVF, everywhere else → QEMU).
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

        let err = materialize_ext4(
            &input,
            &MaterializeExt4Options::default(),
            &BuilderVmRoute::Selected,
        )
        .unwrap_err();
        assert!(matches!(err, RootfsError::BuilderVmFeatureDisabled));
        assert!(!output.exists());
    }
}

#[cfg(all(test, feature = "pure-mkfs"))]
mod injected_ownership_tests {
    use super::*;
    use mvm_fs::ext4::Owner;

    const HOSTILE: Owner = Owner::new(1000, 1000);

    /// An image layer that names the paths mvm injects, with an owner of its
    /// own choosing — the shape a hostile image takes to get `/etc/passwd`
    /// away from root.
    fn hostile_owners() -> mvm_fs::ownership::OwnerTable {
        let tree = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        for path in [
            "etc/passwd",
            "etc/group",
            "etc/mvm/verb-trust.json",
            "usr/lib/mvm/wrappers/oci-entrypoint",
            "srv/app.conf",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_uid(HOSTILE.uid.into());
            header.set_gid(HOSTILE.gid.into());
            header.set_cksum();
            builder.append(&header, std::io::empty()).unwrap();
        }
        let report = mvm_fs::oci::unpack::unpack_layer(
            builder.into_inner().unwrap().as_slice(),
            tree.path(),
            &mvm_fs::oci::unpack::UnpackOptions::default(),
        )
        .unwrap();
        let mut owners = mvm_fs::ownership::OwnerTable::new();
        owners.absorb(&report.ownership);
        owners
    }

    fn owner_in_image(nodes: &[mvm_fs::ext4::Node], path: &str) -> Owner {
        nodes
            .iter()
            .find(|node| node.path() == path)
            .unwrap_or_else(|| panic!("{path} must be in the image"))
            .owner()
    }

    /// The in-process materializer's options claim the injected paths on every
    /// tree, so the image a hostile layer table is applied to still has mvm's
    /// files owned by root — and only those.
    #[test]
    fn an_injected_path_is_root_owned_and_the_image_keeps_the_rest() {
        let tree = tempfile::tempdir().unwrap();
        for dir in ["etc/mvm", "usr/lib/mvm/wrappers", "srv"] {
            std::fs::create_dir_all(tree.path().join(dir)).unwrap();
        }
        for file in [
            "etc/passwd",
            "etc/group",
            "etc/mvm/verb-trust.json",
            "usr/lib/mvm/wrappers/oci-entrypoint",
            "srv/app.conf",
        ] {
            std::fs::write(tree.path().join(file), b"x").unwrap();
        }
        let input =
            MaterializeExt4Input::new(tree.path().to_path_buf(), tree.path().join("out.ext4"), 0)
                .with_owners(hostile_owners());

        let options = pure_materialize_options(&input, mvm_fs::rootfs::WalkOptions::default());
        let nodes = mvm_fs::rootfs::image_nodes(tree.path(), &options).unwrap();

        for injected in [
            "/etc/passwd",
            "/etc/group",
            "/etc/mvm/verb-trust.json",
            "/usr/lib/mvm/wrappers/oci-entrypoint",
        ] {
            assert_eq!(
                owner_in_image(&nodes, injected),
                Owner::ROOT,
                "{injected} is mvm's, whatever the layer declared"
            );
        }
        assert_eq!(
            owner_in_image(&nodes, "/srv/app.conf"),
            HOSTILE,
            "a path mvm does not inject keeps the owner its layer declared"
        );
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

#[cfg(test)]
mod tree_only_materialization_loss_tests {
    use super::*;

    fn input_in(dir: &tempfile::TempDir) -> MaterializeExt4Input {
        MaterializeExt4Input::new(dir.path().to_path_buf(), dir.path().join("rootfs.ext4"), 1)
    }

    fn owners_from_layer(uid: u64) -> mvm_fs::ownership::OwnerTable {
        owners_at("var/lib/svc/", uid)
    }

    /// An image whose only non-root owners sit on paths mvm claims loses
    /// nothing through the tree copy: the script sets those back to root.
    #[test]
    fn a_non_root_owner_only_on_claimed_paths_is_not_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let input = input_in(&dir).with_owners(owners_at("etc/mvm/", 1000));
        assert!(refuse_tree_only_materialization_loss(&input, &BuilderVmRoute::Selected).is_ok());
    }

    fn owners_at(path: &str, uid: u64) -> mvm_fs::ownership::OwnerTable {
        let tree = tempfile::tempdir().unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(0o750);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_uid(uid);
        header.set_gid(uid);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, std::io::empty()).unwrap();
        let report = mvm_fs::oci::unpack::unpack_layer(
            builder.into_inner().unwrap().as_slice(),
            tree.path(),
            &mvm_fs::oci::unpack::UnpackOptions::default(),
        )
        .unwrap();
        let mut owners = mvm_fs::ownership::OwnerTable::new();
        owners.absorb(&report.ownership);
        owners
    }

    /// Copying the host tree would land the service's files owned by
    /// whoever ran the unpack, so the builder-VM materializer refuses — before
    /// allocating an image or starting anything.
    #[test]
    fn non_root_layer_owners_refuse_the_tree_copy_materializer() {
        let dir = tempfile::tempdir().unwrap();
        let input = input_in(&dir).with_owners(owners_from_layer(999));
        let err = materialize_ext4(
            &input,
            &MaterializeExt4Options::default(),
            &BuilderVmRoute::Selected,
        )
        .unwrap_err();
        assert!(
            matches!(err, RootfsError::LayerOwnershipUnsupported { count: 1, .. }),
            "got {err:?}"
        );
        assert!(!input.output.exists(), "refused before allocating an image");
    }

    /// Layers that declare only root lose nothing in a tree copy.
    #[test]
    fn root_only_layer_owners_are_not_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let input = input_in(&dir).with_owners(owners_from_layer(0));
        assert!(
            refuse_tree_only_materialization_loss(&input, &BuilderVmRoute::Selected).is_ok(),
            "root-only owners survive a tree copy"
        );
    }

    #[test]
    fn deferred_nodes_are_still_a_loss() {
        let dir = tempfile::tempdir().unwrap();
        let input = input_in(&dir).with_deferred_nodes(vec![mvm_fs::ext4::Node::Symlink {
            path: "/a".into(),
            target: "b".into(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }]);
        assert!(matches!(
            refuse_tree_only_materialization_loss(&input, &BuilderVmRoute::Selected),
            Err(RootfsError::DeferredNodesUnsupported { count: 1, .. })
        ));
    }

    /// The builder's archive carries no extended attributes and its `tar`
    /// could not restore them, so a tree that has any is refused rather than
    /// emitted without them.
    #[test]
    fn a_guest_semantic_xattr_refuses_the_tree_copy_materializer() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("ping");
        std::fs::write(&bin, b"elf").unwrap();
        if xattr::set(&bin, "user.mvm.cap", b"c").is_err() {
            eprintln!("SKIPPED: host filesystem refused a user extended attribute");
            return;
        }
        let err = refuse_tree_only_materialization_loss(
            &input_in(&dir),
            &BuilderVmRoute::PureFallback {
                because: "xattr too large".to_string(),
            },
        )
        .expect_err("an attribute the writer cannot carry must refuse");
        assert!(
            matches!(&err, RootfsError::XattrUnsupported { name, .. } if name == "user.mvm.cap"),
            "got {err:?}"
        );
        assert!(err.to_string().contains("xattr too large"), "{err}");
    }

    fn refusal_message(route: &BuilderVmRoute) -> String {
        let dir = tempfile::tempdir().unwrap();
        let input = input_in(&dir).with_owners(owners_from_layer(999));
        refuse_tree_only_materialization_loss(&input, route)
            .expect_err("a non-root owner is a loss on either route")
            .to_string()
    }

    /// An operator who asked for the builder VM can stop asking, and the
    /// refusal says so.
    #[test]
    fn a_requested_builder_vm_refusal_names_the_setting_that_selected_it() {
        let message = refusal_message(&BuilderVmRoute::Selected);
        assert!(
            message.contains("unset MVM_MATERIALIZE_BUILDER_VM"),
            "got {message}"
        );
    }

    /// On the automatic fallback nobody set that variable, so naming it sends
    /// a reader after a setting that is not there. Name the failure that
    /// caused the fallback instead.
    #[test]
    fn a_fallback_refusal_names_the_failure_that_caused_it_and_no_setting() {
        let message = refusal_message(&BuilderVmRoute::PureFallback {
            because: "file too fragmented".to_string(),
        });
        assert!(
            !message.contains("MVM_MATERIALIZE_BUILDER_VM"),
            "the fallback path set nothing to unset; got {message}"
        );
        assert!(message.contains("file too fragmented"), "got {message}");
    }
}
