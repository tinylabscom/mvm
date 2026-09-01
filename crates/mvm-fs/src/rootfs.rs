//! Directory tree → deterministic ext4 image: the single mid-layer between an
//! unpacked rootfs tree on the host and the low-level [`crate::ext4`] writer.
//!
//! Everything here is pure and in-process — no `mkfs`, no subprocess, no VM.
//! [`collect_nodes`] walks a host directory into the writer's flat [`Node`]
//! list; [`materialize_ext4_pure`] drives the walk plus the streamed image
//! emission. Higher layers add their own flavor on top — the OCI staging
//! adapter maps errors and keeps an `mke2fs` escape hatch, the build crate
//! adds verity sidecars and a builder-VM fallback — but there is exactly one
//! walk + emission implementation, and this is it.
//!
//! Output is byte-deterministic for a given (tree, options) pair. That is
//! load-bearing: verity caching keys on the emitted bytes, so any change to
//! them is a compatibility break, not a cosmetic one.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::Digest;
use thiserror::Error;

use crate::parallel::par_map;

use crate::ext4::{BuildOptions, EmitImageError, Ext4Error, Node, Xattr};

/// Version of the deterministic ext4 materializer's output contract.
///
/// Bump this when the same source tree and options can produce a different
/// image. The version is deliberately part of measurement output so a
/// filesystem candidate cannot be compared across incompatible artifacts.
pub const EXT4_MATERIALIZER_FORMAT_VERSION: u32 = 1;

/// How [`collect_nodes`] handles a host inode kind the ext4 [`Node`] enum has
/// no variant for (device, FIFO, socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnsupportedNodePolicy {
    /// Omit the node from the image. Correct for an OCI rootfs: those special
    /// files are re-created by devtmpfs at boot, so leaving them out of the
    /// image is the intended behavior, not a loss.
    #[default]
    Skip,
    /// Fail the walk instead of silently dropping the node. Used by callers
    /// materializing a user-supplied host directory (e.g. a host-directory
    /// share), where an omitted file would leave the guest with less than
    /// what the user asked to share.
    Reject,
}

/// How [`collect_nodes`] handles an entry that disappears after directory
/// enumeration but before its metadata or contents can be captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VanishedNodePolicy {
    /// Fail the snapshot. Immutable source trees use this so unexpected source
    /// mutation cannot silently change a rootfs artifact.
    #[default]
    Reject,
    /// Omit entries that vanished while the snapshot was being taken. A live
    /// host-directory share uses this because build tools routinely replace
    /// lockfiles and incremental artifacts during traversal.
    Skip,
}

/// How [`collect_nodes`] treats extended attributes on walked entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XattrPolicy {
    /// Capture image-semantic xattrs (file capabilities, POSIX ACLs,
    /// `user.*` / `trusted.*`) so the writer preserves them inline.
    /// Host-managed labels the guest re-derives (SELinux/IMA/EVM, macOS
    /// `com.apple.*`) are skipped either way.
    #[default]
    GuestSemantic,
    /// Capture no xattrs at all. The OCI staging adapter uses this for parity
    /// with its `mke2fs -E no_copy_xattrs` escape hatch: both arms of that
    /// materializer must emit the same content set.
    Ignore,
}

/// Walk knobs for [`collect_nodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WalkOptions {
    /// Behavior on inode kinds the writer cannot represent.
    pub on_unsupported: UnsupportedNodePolicy,
    /// Extended-attribute capture behavior.
    pub xattrs: XattrPolicy,
    /// Behavior when an enumerated entry disappears during the walk.
    pub on_vanished: VanishedNodePolicy,
}

impl WalkOptions {
    /// Walk options with the given unsupported-node policy and default
    /// (guest-semantic) xattr capture.
    pub fn new(on_unsupported: UnsupportedNodePolicy) -> Self {
        Self {
            on_unsupported,
            ..Self::default()
        }
    }

    /// Set the extended-attribute capture policy.
    pub fn with_xattr_policy(mut self, xattrs: XattrPolicy) -> Self {
        self.xattrs = xattrs;
        self
    }

    /// Set the policy for entries that disappear during the snapshot.
    pub fn with_vanished_node_policy(mut self, on_vanished: VanishedNodePolicy) -> Self {
        self.on_vanished = on_vanished;
        self
    }
}

/// Failure walking a source tree or emitting the image.
#[derive(Debug, Error)]
pub enum MaterializeError {
    /// I/O failure reading the source tree (including a root that is not a
    /// readable directory).
    #[error("walking directory tree at {path}: {source}")]
    Walk {
        /// Path being read when the failure occurred.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The walk hit an inode kind the writer cannot represent under
    /// [`UnsupportedNodePolicy::Reject`].
    #[error(
        "host path {0} is a device, FIFO, or socket special file the ext4 writer cannot represent"
    )]
    UnsupportedNodeType(PathBuf),

    /// The in-process writer rejected the node list.
    #[error("building ext4 image in-process: {0}")]
    Build(#[from] Ext4Error),

    /// I/O failure creating or writing the output image.
    #[error("writing image {path}: {source}")]
    Write {
        /// Output (or output-parent) path being written.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// Sparse-image sizing rule for an OCI rootfs: scale the manifest's summed
/// uncompressed layer size by a multiplier (default 3/2, i.e. 1.5x) with a
/// floor (default 64 MiB). [`SizeHeuristic::estimate`] rounds up on odd byte
/// counts and saturates on overflow so a maliciously large manifest fails at
/// sparse-file allocation instead of wrapping small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeHeuristic {
    /// Minimum sparse image size in bytes.
    pub min_image_size_bytes: u64,
    /// Numerator of the uncompressed-size multiplier.
    pub multiplier_numerator: u64,
    /// Denominator of the uncompressed-size multiplier.
    pub multiplier_denominator: u64,
}

impl Default for SizeHeuristic {
    fn default() -> Self {
        Self {
            min_image_size_bytes: 64 * 1024 * 1024,
            multiplier_numerator: 3,
            multiplier_denominator: 2,
        }
    }
}

/// A [`SizeHeuristic`] carried a zero multiplier denominator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid ext4 size multiplier denominator: 0")]
pub struct InvalidSizeMultiplier;

impl SizeHeuristic {
    /// Estimated sparse image size for `uncompressed_size_bytes` of content.
    pub fn estimate(&self, uncompressed_size_bytes: u64) -> Result<u64, InvalidSizeMultiplier> {
        if self.multiplier_denominator == 0 {
            return Err(InvalidSizeMultiplier);
        }
        let scaled = uncompressed_size_bytes
            .saturating_mul(self.multiplier_numerator)
            .saturating_add(self.multiplier_denominator - 1)
            / self.multiplier_denominator;
        Ok(scaled.max(self.min_image_size_bytes))
    }
}

/// A single entry discovered by the sequential directory walk, before its
/// file contents or xattrs are read in parallel.
struct WalkEntry {
    path: PathBuf,
    guest_path: String,
    file_type: std::fs::FileType,
}

fn vanished_entry(
    policy: VanishedNodePolicy,
    path: &Path,
    source: std::io::Error,
) -> Result<Option<Node>, MaterializeError> {
    if policy == VanishedNodePolicy::Skip && source.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(MaterializeError::Walk {
            path: path.to_path_buf(),
            source,
        })
    }
}

fn should_skip_vanished(policy: VanishedNodePolicy, source: &std::io::Error) -> bool {
    policy == VanishedNodePolicy::Skip && source.kind() == std::io::ErrorKind::NotFound
}

fn read_walk_entry(
    entry: WalkEntry,
    options: WalkOptions,
) -> Result<Option<Node>, MaterializeError> {
    let WalkEntry {
        path,
        guest_path,
        file_type,
    } = entry;
    let node = if file_type.is_symlink() {
        let target = match std::fs::read_link(&path) {
            Ok(target) => target,
            Err(source) => return vanished_entry(options.on_vanished, &path, source),
        };
        Node::Symlink {
            path: guest_path,
            target: target.to_string_lossy().into_owned(),
        }
    } else if file_type.is_dir() {
        Node::Dir {
            path: guest_path,
            mode: mode_of(&path, 0o755),
            xattrs: node_xattrs(options.xattrs, &path),
        }
    } else {
        let data = match read_file_for_guest_image(&path) {
            Ok(data) => data,
            Err(source) => return vanished_entry(options.on_vanished, &path, source),
        };
        Node::File {
            path: guest_path,
            mode: mode_of(&path, 0o644),
            data,
            xattrs: node_xattrs(options.xattrs, &path),
        }
    };
    Ok(Some(node))
}

/// Walk `root` into a flat [`Node`] list (guest-absolute paths), symlink-aware
/// (never follows). Directories and their descendants, regular files (contents
/// read in), and symlinks are captured; other inode types (fifo/socket/device)
/// are handled per `options.on_unsupported`, since the [`Node`] enum has no
/// way to represent them. Extended-attribute capture follows `options.xattrs`.
///
/// The tree structure is walked sequentially so directory traversal stays
/// predictable, but regular-file reads and xattr captures happen in parallel
/// via rayon. The returned nodes are sorted by guest path so the output is
/// deterministic regardless of filesystem read_dir order.
pub fn collect_nodes(root: &Path, options: WalkOptions) -> Result<Vec<Node>, MaterializeError> {
    let mut entries = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(read) => read,
            Err(source) if should_skip_vanished(options.on_vanished, &source) => continue,
            Err(source) => {
                return Err(MaterializeError::Walk {
                    path: dir.clone(),
                    source,
                });
            }
        };
        for entry in read {
            let entry = match entry {
                Ok(entry) => entry,
                Err(source) if should_skip_vanished(options.on_vanished, &source) => continue,
                Err(source) => {
                    return Err(MaterializeError::Walk {
                        path: dir.clone(),
                        source,
                    });
                }
            };
            let path = entry.path();
            let guest_path = guest_path_of(root, &path);
            let ft = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(source) if should_skip_vanished(options.on_vanished, &source) => continue,
                Err(source) => {
                    return Err(MaterializeError::Walk {
                        path: path.clone(),
                        source,
                    });
                }
            };
            if ft.is_dir() {
                stack.push(path.clone());
            } else if !(ft.is_symlink() || ft.is_file()) {
                match options.on_unsupported {
                    UnsupportedNodePolicy::Skip => continue,
                    UnsupportedNodePolicy::Reject => {
                        return Err(MaterializeError::UnsupportedNodeType(path));
                    }
                }
            }
            entries.push(WalkEntry {
                path,
                guest_path,
                file_type: ft,
            });
        }
    }

    let mut nodes: Vec<Node> = par_map(entries, |entry| read_walk_entry(entry, options))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();

    nodes.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(nodes)
}

/// Descriptor returned by [`materialize_ext4_pure`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedImage {
    /// Host path of the written image (same as the `output` argument).
    pub path: PathBuf,
    /// Final image size in bytes.
    pub size_bytes: u64,
}

/// Counts and byte totals for the effective node set sent to the image writer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MaterializationNodeCounts {
    /// Number of nodes, excluding the implicit guest root (`/`).
    pub total: u64,
    /// Number of regular files.
    pub files: u64,
    /// Number of directories.
    pub directories: u64,
    /// Number of symbolic links.
    pub symlinks: u64,
    /// Number of captured extended attributes.
    pub xattrs: u64,
    /// Total bytes in regular-file payloads before filesystem overhead.
    pub file_bytes: u64,
}

/// Timings for the current pure-Rust materialization path, in microseconds.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MaterializationTimings {
    /// Time spent hashing the source directory's content manifest.
    pub source_hash_micros: u64,
    /// Time spent walking the source and reading nodes.
    pub walk_micros: u64,
    /// Time spent constructing the ext4 image in memory.
    pub build_micros: u64,
    /// End-to-end time covered by this report.
    pub total_micros: u64,
}

/// Baseline report for comparing immutable guest filesystem materializers.
///
/// This measures the existing directory-to-ext4 path without booting a VM or
/// writing the image. The source and image digests make reports comparable;
/// the timings are observations and must be aggregated over repeated runs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ext4MaterializationReport {
    /// Version of this report schema.
    pub report_version: u32,
    /// Version of the emitted ext4 byte contract.
    pub materializer_format_version: u32,
    /// SHA-256 of the source directory content manifest.
    pub source_content_sha256: String,
    /// Composition of the nodes passed to the writer.
    pub nodes: MaterializationNodeCounts,
    /// Logical ext4 image size in bytes.
    pub image_size_bytes: u64,
    /// SHA-256 of the emitted ext4 image bytes.
    pub image_sha256: String,
    /// Timings for the measured path.
    pub timings: MaterializationTimings,
}

const MATERIALIZATION_REPORT_VERSION: u32 = 1;

/// Measure the pure-Rust directory-to-ext4 build path.
///
/// The source hash, walk, and image build are intentionally reported as
/// separate phases. This makes it possible to distinguish a filesystem
/// format improvement from a source-scanning or content-addressing cost.
/// `extra_nodes` are included in the node counts and image digest, matching
/// [`build_ext4_pure`].
pub fn measure_ext4_pure(
    root: &Path,
    options: &MaterializeOptions,
) -> Result<Ext4MaterializationReport, MaterializeError> {
    let total_started = Instant::now();

    let hash_started = Instant::now();
    let source_content_sha256 =
        crate::hash::hash_source(root).map_err(|source| MaterializeError::Walk {
            path: root.to_path_buf(),
            source,
        })?;
    let source_hash_micros = elapsed_micros(hash_started.elapsed());

    let walk_started = Instant::now();
    let nodes = merge_extra_nodes(
        collect_nodes(root, options.walk)?,
        options.extra_nodes.clone(),
    );
    let nodes_report = count_nodes(&nodes);
    let walk_micros = elapsed_micros(walk_started.elapsed());

    let build_started = Instant::now();
    let image = crate::ext4::build_image_with_options(nodes, &options.build)?;
    let image_size_bytes = image.len() as u64;
    let image_sha256 = hex::encode(sha2::Sha256::digest(&image));
    let build_micros = elapsed_micros(build_started.elapsed());

    Ok(Ext4MaterializationReport {
        report_version: MATERIALIZATION_REPORT_VERSION,
        materializer_format_version: EXT4_MATERIALIZER_FORMAT_VERSION,
        source_content_sha256,
        nodes: nodes_report,
        image_size_bytes,
        image_sha256,
        timings: MaterializationTimings {
            source_hash_micros,
            walk_micros,
            build_micros,
            total_micros: elapsed_micros(total_started.elapsed()),
        },
    })
}

fn count_nodes(nodes: &[Node]) -> MaterializationNodeCounts {
    let mut counts = MaterializationNodeCounts {
        total: nodes.len() as u64,
        files: 0,
        directories: 0,
        symlinks: 0,
        xattrs: 0,
        file_bytes: 0,
    };
    for node in nodes {
        match node {
            Node::Dir { xattrs, .. } => {
                counts.directories += 1;
                counts.xattrs = counts.xattrs.saturating_add(xattrs.len() as u64);
            }
            Node::File { data, xattrs, .. } => {
                counts.files += 1;
                counts.file_bytes = counts.file_bytes.saturating_add(data.len() as u64);
                counts.xattrs = counts.xattrs.saturating_add(xattrs.len() as u64);
            }
            Node::Symlink { .. } => counts.symlinks += 1,
        }
    }
    counts
}

fn elapsed_micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Walk + emission knobs for [`materialize_ext4_pure`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MaterializeOptions {
    /// Tree-walk behavior.
    pub walk: WalkOptions,
    /// Superblock metadata (UUID, volume label) stamped on the image.
    pub build: BuildOptions,
    /// Nodes to place in the image that the walk cannot find on the host
    /// tree. This is how an OCI unpack carries the entries a case-folding
    /// host filesystem refused to hold — see
    /// [`crate::oci::unpack::UnpackReport::deferred_nodes`]. A node here
    /// wins over a walked node at the same path.
    pub extra_nodes: Vec<Node>,
}

impl MaterializeOptions {
    /// Start building a [`MaterializeOptions`] from its defaults. Every value is
    /// set by name, so a call site cannot transpose two fields that
    /// share a type.
    #[must_use]
    pub fn builder() -> MaterializeOptionsBuilder {
        MaterializeOptionsBuilder::new()
    }
}

/// Builder for [`MaterializeOptions`]. Unset fields keep the value
/// `MaterializeOptions::default()` gives them.
#[derive(Default)]
pub struct MaterializeOptionsBuilder {
    inner: MaterializeOptions,
}

impl MaterializeOptionsBuilder {
    /// A builder holding the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MaterializeOptions::default(),
        }
    }

    /// Set `walk`.
    #[must_use]
    pub fn walk(mut self, walk: WalkOptions) -> Self {
        self.inner.walk = walk;
        self
    }

    /// Set `build`.
    #[must_use]
    pub fn with_build(mut self, build: BuildOptions) -> Self {
        self.inner.build = build;
        self
    }

    /// Set `extra_nodes`.
    #[must_use]
    pub fn extra_nodes(mut self, extra_nodes: Vec<Node>) -> Self {
        self.inner.extra_nodes = extra_nodes;
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> MaterializeOptions {
        self.inner
    }
}

impl MaterializeOptions {
    /// Set the unsupported-node policy for the walk.
    pub fn with_unsupported_node_policy(mut self, policy: UnsupportedNodePolicy) -> Self {
        self.walk.on_unsupported = policy;
        self
    }

    /// Set the extended-attribute capture policy for the walk.
    pub fn with_xattr_policy(mut self, xattrs: XattrPolicy) -> Self {
        self.walk.xattrs = xattrs;
        self
    }

    /// Stamp an ext4 volume label (`s_volume_name`, truncated to 16 bytes by
    /// the writer) so a guest can mount the image by label instead of by
    /// device path.
    pub fn with_volume_label(mut self, label: &[u8]) -> Self {
        self.build = self.build.with_volume_name(label);
        self
    }

    /// Replace the writer's superblock options wholesale (UUID + label).
    pub fn with_build_options(mut self, build: BuildOptions) -> Self {
        self.build = build;
        self
    }

    /// Add nodes the host tree cannot supply, merged over the walk.
    pub fn with_extra_nodes(mut self, extra_nodes: Vec<Node>) -> Self {
        self.extra_nodes = extra_nodes;
        self
    }
}

/// Merge `extra` over `walked`, last-wins by path.
///
/// The two lists are disjoint in practice — an unpack defers a node
/// precisely because the host tree could not hold it, so the walk cannot
/// have found it. The dedup is a guard against emitting two directory
/// entries with the same name if a caller ever passes an overlapping
/// node, which would produce a structurally invalid image rather than a
/// loud error.
fn merge_extra_nodes(mut walked: Vec<Node>, extra: Vec<Node>) -> Vec<Node> {
    if extra.is_empty() {
        return walked;
    }
    let overridden: std::collections::HashSet<&str> =
        extra.iter().map(|node| node.path()).collect();
    walked.retain(|node| !overridden.contains(node.path()));
    walked.extend(extra);
    walked
}

/// Build the directory tree at `root` into an in-memory ext4 image.
///
/// Returns the raw image bytes and the final image size. The whole tree and the
/// assembled image are held in memory, so callers can compute content-addressed
/// sidecars (e.g. dm-verity) from `image` before writing anything to disk.
///
/// Peak memory is roughly 2.5× the tree's byte size — the walked nodes plus the
/// assembled image. The nodes are consumed by the build rather than copied into
/// it, which is why the image does not cost a third copy.
pub fn build_ext4_pure(
    root: &Path,
    options: &MaterializeOptions,
) -> Result<(Vec<u8>, u64), MaterializeError> {
    let nodes = merge_extra_nodes(
        collect_nodes(root, options.walk)?,
        options.extra_nodes.clone(),
    );
    let image = crate::ext4::build_image_with_options(nodes, &options.build)?;
    let size_bytes = image.len() as u64;
    Ok((image, size_bytes))
}

/// Materialize the directory tree at `root` into an ext4 image at `output`,
/// in-process: walk, build, stream-emit, truncate to the final size. Creates
/// `output`'s parent directory if missing. A `root` that is not a readable
/// directory fails with [`MaterializeError::Walk`].
///
/// The whole tree is held in memory (each file's bytes + the assembled image),
/// costing roughly 2.5× the tree's size at peak, which is fine for small/medium
/// rootfs; a tree past the writer's structural limits surfaces as
/// [`MaterializeError::Build`] with a capacity-limit classification callers can
/// use to route to an out-of-process fallback. That classification is
/// structural, not memory-based: the writer's own ceiling is 16 TiB, so a large
/// tree exhausts host memory long before it trips.
///
/// Callers that need to compute sidecars from the image bytes before any disk
/// write should use [`build_ext4_pure`] instead and handle the write
/// themselves.
pub fn materialize_ext4_pure(
    root: &Path,
    output: &Path,
    options: &MaterializeOptions,
) -> Result<MaterializedImage, MaterializeError> {
    let nodes = merge_extra_nodes(
        collect_nodes(root, options.walk)?,
        options.extra_nodes.clone(),
    );
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|source| MaterializeError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let size_bytes = stream_ext4_to_file(nodes, output, &options.build)?;
    Ok(MaterializedImage {
        path: output.to_path_buf(),
        size_bytes,
    })
}

/// Stream the writer's sparse ranges into a file at `output`, then extend the
/// file to the image's full size (untouched ranges stay holes).
fn stream_ext4_to_file(
    nodes: Vec<Node>,
    output: &Path,
    options: &BuildOptions,
) -> Result<u64, MaterializeError> {
    let mut file = std::fs::File::create(output).map_err(|source| MaterializeError::Write {
        path: output.to_path_buf(),
        source,
    })?;
    let size_bytes = match crate::ext4::emit_image_with_options(nodes, options, |offset, bytes| {
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(bytes))
    }) {
        Ok(size_bytes) => size_bytes,
        Err(EmitImageError::Build(err)) => return Err(MaterializeError::Build(err)),
        Err(EmitImageError::Emit(source)) => {
            return Err(MaterializeError::Write {
                path: output.to_path_buf(),
                source,
            });
        }
    };
    file.set_len(size_bytes)
        .map_err(|source| MaterializeError::Write {
            path: output.to_path_buf(),
            source,
        })?;
    Ok(size_bytes)
}

/// Read a regular file's bytes for inclusion in the image, temporarily
/// widening an owner-unreadable mode (e.g. a 0000 `/etc/shadow`) and restoring
/// it afterwards. The captured guest mode is unaffected — the walk reads modes
/// via metadata, not via this read.
fn read_file_for_guest_image(path: &Path) -> std::io::Result<Vec<u8>> {
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

/// The node's xattrs under `policy` — empty under [`XattrPolicy::Ignore`]
/// (no xattr syscalls at all), the image-semantic set otherwise.
fn node_xattrs(policy: XattrPolicy, path: &Path) -> Vec<Xattr> {
    match policy {
        XattrPolicy::GuestSemantic => collect_guest_xattrs(path),
        XattrPolicy::Ignore => Vec::new(),
    }
}

/// The extended attributes on `path` that carry image semantics the guest
/// needs. Attrs too large for the writer's in-inode area surface later as a
/// capacity-limit build error, which callers can route to a fallback that
/// preserves them.
fn collect_guest_xattrs(path: &Path) -> Vec<Xattr> {
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
            out.push(Xattr { name, value });
        }
    }
    // Deterministic order (the writer also sorts, but keep the node stable).
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Whether an xattr name carries guest-relevant image semantics the pure
/// writer would otherwise silently drop. File capabilities and POSIX ACLs are
/// preserved; other `security.*` attrs are host-managed labels the guest
/// kernel re-derives (or that don't port between hosts) and are deliberately
/// ignored.
fn xattr_matters_for_guest(name: &str) -> bool {
    match name {
        "security.capability" | "system.posix_acl_access" | "system.posix_acl_default" => true,
        _ if name.starts_with("security.") => false,
        _ => name.starts_with("user.") || name.starts_with("trusted."),
    }
}

/// Guest-absolute path for `path` under `root` (e.g. `root/etc/hosts` →
/// `/etc/hosts`).
fn guest_path_of(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => format!("/{}", path.to_string_lossy()),
    }
}

/// Unix permission bits of `path` (not following symlinks), or `default` on a
/// non-unix host.
fn mode_of(path: &Path, default: u16) -> u16 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vanished_file_policy_skips_only_not_found_entries() {
        let source = tempfile::TempDir::new().unwrap();
        let path = source.path().join("gone");
        std::fs::write(&path, b"temporary").unwrap();
        let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
        std::fs::remove_file(&path).unwrap();
        let entry = WalkEntry {
            path: path.clone(),
            guest_path: "/gone".to_string(),
            file_type,
        };
        let options = WalkOptions::default().with_vanished_node_policy(VanishedNodePolicy::Skip);

        assert_eq!(read_walk_entry(entry, options).unwrap(), None);

        let rejected = read_walk_entry(
            WalkEntry {
                path,
                guest_path: "/gone".to_string(),
                file_type,
            },
            WalkOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(rejected, MaterializeError::Walk { .. }));
    }

    const SUPERBLOCK: usize = 1024;
    const S_UUID: usize = SUPERBLOCK + 0x68;
    const S_VOLUME_NAME: usize = SUPERBLOCK + 0x78;

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
        // and bloat every inode's xattr area for nothing.
        assert!(!xattr_matters_for_guest("security.selinux"));
        assert!(!xattr_matters_for_guest("security.ima"));
        assert!(!xattr_matters_for_guest("security.evm"));
        assert!(!xattr_matters_for_guest("com.apple.provenance"));
    }

    #[test]
    fn xattr_bearing_tree_materializes_with_the_attr_preserved() {
        let src = tempfile::tempdir().unwrap();
        let bin = src.path().join("ping");
        std::fs::write(&bin, b"\x7fELF fake binary").unwrap();
        // Skip where the host FS can't hold xattrs (some CI tmpfs). A small
        // `user.*` attr fits the in-inode area, so the writer represents it.
        if xattr::set(&bin, "user.mvm.test_cap", b"cap").is_err() {
            return;
        }
        assert_eq!(
            collect_guest_xattrs(&bin),
            vec![Xattr {
                name: "user.mvm.test_cap".into(),
                value: b"cap".to_vec(),
            }],
            "the walk must capture the image-semantic xattr"
        );
        let out = tempfile::tempdir().unwrap();
        materialize_ext4_pure(
            src.path(),
            &out.path().join("rootfs.ext4"),
            &MaterializeOptions::default(),
        )
        .expect("a small xattr fits inline; materialize succeeds");
    }

    #[test]
    fn ignore_xattr_policy_walks_without_capturing() {
        let src = tempfile::tempdir().unwrap();
        let file = src.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        if xattr::set(&file, "user.mvm.attr", b"v").is_err() {
            return;
        }

        let walk = WalkOptions::default().with_xattr_policy(XattrPolicy::Ignore);
        let nodes = collect_nodes(src.path(), walk).expect("collect nodes");
        let [Node::File { xattrs, .. }] = nodes.as_slice() else {
            panic!("expected exactly one file node, got {nodes:?}");
        };
        assert!(
            xattrs.is_empty(),
            "Ignore must capture nothing, got {xattrs:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_nodes_reads_owner_unreadable_files_without_changing_guest_mode() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("etc")).unwrap();
        let shadow = src.path().join("etc/shadow");
        std::fs::write(&shadow, b"root:*:19793:0:99999:7:::\n").unwrap();
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o0)).unwrap();

        let nodes = collect_nodes(src.path(), WalkOptions::default()).expect("collect nodes");
        let node = nodes
            .into_iter()
            .find_map(|node| match node {
                Node::File {
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

    #[cfg(unix)]
    #[test]
    fn collect_nodes_skip_vs_reject_policy_for_unsupported_node_types() {
        let src = tempfile::tempdir().unwrap();
        let sock_path = src.path().join("weird.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&sock_path).expect("bind a real test socket");

        // OCI-rootfs-style walk: devtmpfs recreates these at boot, so silently
        // omitting the node from the image is correct, not a loss.
        let nodes = collect_nodes(src.path(), WalkOptions::new(UnsupportedNodePolicy::Skip))
            .expect("skip policy");
        assert!(
            nodes.is_empty(),
            "a socket must be silently omitted under Skip, got {nodes:?}"
        );

        // Host-directory-share-style walk: a dropped file would silently
        // diverge from what the user asked to share, so fail closed.
        let err = collect_nodes(src.path(), WalkOptions::new(UnsupportedNodePolicy::Reject))
            .expect_err("a socket must be rejected, not silently dropped");
        assert!(
            matches!(err, MaterializeError::UnsupportedNodeType(_)),
            "expected UnsupportedNodeType, got {err:?}"
        );
    }

    #[test]
    fn materialize_writes_a_valid_deterministic_ext4() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("hosts", src.path().join("etc/localhost")).unwrap();

        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let options = MaterializeOptions::default();

        let mat = materialize_ext4_pure(src.path(), &out_path, &options).expect("materialize");
        assert_eq!(mat.path, out_path);
        assert!(mat.size_bytes > 0);

        let img = std::fs::read(&out_path).unwrap();
        assert_eq!(img.len() as u64, mat.size_bytes);
        // ext4 superblock magic 0xEF53 (LE) at byte 1024 + 0x38.
        assert_eq!(&img[SUPERBLOCK + 0x38..SUPERBLOCK + 0x3A], &[0x53, 0xEF]);
        // Deterministic: same tree materializes to byte-identical output.
        let out2 = out.path().join("rootfs2.ext4");
        materialize_ext4_pure(src.path(), &out2, &options).expect("materialize again");
        assert_eq!(std::fs::read(&out2).unwrap(), img);
    }

    #[test]
    fn materialize_matches_dense_writer_bytes() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();

        let nodes = collect_nodes(src.path(), WalkOptions::default()).expect("collect nodes");
        let dense = crate::ext4::build_image(nodes).expect("dense ext4 image");

        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let materialized =
            materialize_ext4_pure(src.path(), &out_path, &MaterializeOptions::default())
                .expect("materialize");

        assert_eq!(std::fs::read(&out_path).unwrap(), dense);
        assert_eq!(materialized.size_bytes, dense.len() as u64);
    }

    #[test]
    fn build_ext4_pure_returns_bytes_before_any_disk_write() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();

        let options = MaterializeOptions::default();
        let (built, size_bytes) = build_ext4_pure(src.path(), &options).expect("build in memory");
        assert!(size_bytes > 0);
        assert_eq!(built.len() as u64, size_bytes);

        // The in-memory result must be byte-identical to the file-written result,
        // so callers can compute content-addressed sidecars from the buffer.
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        materialize_ext4_pure(src.path(), &out_path, &options).expect("materialize");
        assert_eq!(std::fs::read(&out_path).unwrap(), built);
    }

    #[test]
    fn materialization_report_captures_composition_and_is_json_roundtrippable() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("etc")).unwrap();
        std::fs::write(src.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("hosts", src.path().join("etc/localhost")).unwrap();

        let report = measure_ext4_pure(src.path(), &MaterializeOptions::default())
            .expect("measure pure materialization");

        assert_eq!(report.report_version, MATERIALIZATION_REPORT_VERSION);
        assert_eq!(
            report.materializer_format_version,
            EXT4_MATERIALIZER_FORMAT_VERSION
        );
        assert_eq!(report.nodes.total, 4);
        assert_eq!(report.nodes.files, 2);
        assert_eq!(report.nodes.directories, 1);
        assert_eq!(report.nodes.symlinks, 1);
        assert_eq!(report.nodes.file_bytes, 23);
        assert!(report.image_size_bytes > 0);
        assert_eq!(report.image_sha256.len(), 64);
        assert_eq!(report.source_content_sha256.len(), 64);
        assert!(report.timings.total_micros >= report.timings.build_micros);

        let encoded = serde_json::to_vec(&report).expect("serialize report");
        let decoded: Ext4MaterializationReport =
            serde_json::from_slice(&encoded).expect("deserialize report");
        assert_eq!(decoded, report);
    }

    #[test]
    fn materialization_report_identity_changes_with_source_content() {
        let src = tempfile::tempdir().unwrap();
        let file = src.path().join("hello");
        std::fs::write(&file, b"before").unwrap();

        let before =
            measure_ext4_pure(src.path(), &MaterializeOptions::default()).expect("measure before");
        std::fs::write(&file, b"after").unwrap();
        let after =
            measure_ext4_pure(src.path(), &MaterializeOptions::default()).expect("measure after");

        assert_ne!(
            before.source_content_sha256, after.source_content_sha256,
            "source digest must detect changed file bytes"
        );
        assert_ne!(
            before.image_sha256, after.image_sha256,
            "image digest must detect changed emitted bytes"
        );
        assert_eq!(before.nodes.total, after.nodes.total);
        assert_eq!(before.nodes.files, after.nodes.files);
    }

    #[test]
    fn default_options_leave_volume_name_and_uuid_zeroed() {
        // A caller that never opts in must get byte-identical output to the
        // unlabeled default — an all-zero `s_volume_name` and `s_uuid`.
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");

        materialize_ext4_pure(src.path(), &out_path, &MaterializeOptions::default())
            .expect("materialize");
        let img = std::fs::read(&out_path).unwrap();
        assert_eq!(&img[S_UUID..S_UUID + 16], &[0u8; 16]);
        assert_eq!(&img[S_VOLUME_NAME..S_VOLUME_NAME + 16], &[0u8; 16]);
    }

    #[test]
    fn with_volume_label_stamps_the_ext4_volume_name() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let label: &[u8] = b"mvm-extra-0";
        let options = MaterializeOptions::default().with_volume_label(label);

        materialize_ext4_pure(src.path(), &out_path, &options).expect("materialize");
        let img = std::fs::read(&out_path).unwrap();
        assert_eq!(&img[S_VOLUME_NAME..S_VOLUME_NAME + label.len()], label);
        assert!(
            img[S_VOLUME_NAME + label.len()..S_VOLUME_NAME + 16]
                .iter()
                .all(|&b| b == 0),
            "the volume_name field's unused tail must stay zero-padded"
        );
    }

    #[test]
    fn with_build_options_stamps_the_uuid() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("hello"), b"hi\n").unwrap();
        let out = tempfile::tempdir().unwrap();
        let out_path = out.path().join("rootfs.ext4");
        let uuid = [0xAB; 16];
        let options = MaterializeOptions::default()
            .with_build_options(BuildOptions::default().with_uuid(uuid));

        materialize_ext4_pure(src.path(), &out_path, &options).expect("materialize");
        let img = std::fs::read(&out_path).unwrap();
        assert_eq!(&img[S_UUID..S_UUID + 16], &uuid);
    }

    #[test]
    fn materialize_creates_missing_output_parent() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"x").unwrap();
        let out = tempfile::tempdir().unwrap();
        let nested = out
            .path()
            .join("rootfs")
            .join("deadbeef")
            .join("rootfs.ext4");
        assert!(!nested.parent().unwrap().exists());

        materialize_ext4_pure(src.path(), &nested, &MaterializeOptions::default())
            .expect("materialize into a missing parent dir");
        assert!(nested.is_file());
    }

    #[test]
    fn materialize_rejects_a_non_directory_root_as_a_walk_error() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let err = materialize_ext4_pure(
            f.path(),
            &f.path().with_extension("ext4"),
            &MaterializeOptions::default(),
        )
        .expect_err("a plain file is not a walkable tree");
        assert!(
            matches!(err, MaterializeError::Walk { .. }),
            "expected Walk, got {err:?}"
        );
    }

    #[test]
    fn estimate_uses_sixty_four_mib_floor() {
        let heuristic = SizeHeuristic::default();
        assert_eq!(heuristic.estimate(1).unwrap(), 64 * 1024 * 1024);
    }

    #[test]
    fn estimate_uses_one_point_five_x_rounded_up() {
        let heuristic = SizeHeuristic::default();
        assert_eq!(
            heuristic.estimate(100 * 1024 * 1024).unwrap(),
            150 * 1024 * 1024
        );
        assert_eq!(heuristic.estimate(3).unwrap(), 64 * 1024 * 1024);
    }

    #[test]
    fn estimate_rejects_zero_denominator() {
        let heuristic = SizeHeuristic {
            multiplier_denominator: 0,
            ..SizeHeuristic::default()
        };
        assert_eq!(heuristic.estimate(1), Err(InvalidSizeMultiplier));
    }

    #[test]
    fn extra_nodes_reach_the_image_alongside_the_walked_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("tree");
        std::fs::create_dir_all(root.join("usr/share/man/man7")).unwrap();
        std::fs::write(root.join("usr/share/man/man7/PAM.7.gz"), b"page").unwrap();

        let deferred = Node::Symlink {
            path: "/usr/share/man/man7/pam.7.gz".to_string(),
            target: "PAM.7.gz".to_string(),
        };
        let options = MaterializeOptions::default().with_extra_nodes(vec![deferred.clone()]);

        let walked = collect_nodes(&root, options.walk).unwrap();
        assert!(
            !walked.iter().any(|n| n.path() == deferred.path()),
            "the walk cannot see a path the host tree does not hold"
        );

        let merged = merge_extra_nodes(walked, options.extra_nodes.clone());
        assert!(merged.contains(&deferred));
        assert!(
            merged
                .iter()
                .any(|n| n.path() == "/usr/share/man/man7/PAM.7.gz"),
            "merging must not displace the walked occupant"
        );

        // And the whole thing emits a real image.
        let image = tmp.path().join("rootfs.ext4");
        let out = materialize_ext4_pure(&root, &image, &options).expect("materialize");
        assert!(out.size_bytes > 0);
    }

    #[test]
    fn an_extra_node_overrides_a_walked_node_at_the_same_path() {
        let walked = vec![Node::File {
            path: "/etc/motd".to_string(),
            mode: 0o644,
            data: b"walked".to_vec(),
            xattrs: Vec::new(),
        }];
        let extra = vec![Node::File {
            path: "/etc/motd".to_string(),
            mode: 0o600,
            data: b"extra".to_vec(),
            xattrs: Vec::new(),
        }];

        let merged = merge_extra_nodes(walked, extra.clone());
        assert_eq!(
            merged, extra,
            "a duplicate path must resolve to one node, not two directory entries"
        );
    }

    #[test]
    fn empty_extra_nodes_leave_the_walk_untouched() {
        let walked = vec![Node::Symlink {
            path: "/bin/sh".to_string(),
            target: "bash".to_string(),
        }];
        assert_eq!(merge_extra_nodes(walked.clone(), Vec::new()), walked);
    }
}

#[cfg(test)]
mod materialize_options_builder_tests {
    use super::*;

    /// A builder nobody touched has to agree with `MaterializeOptions::default()`,
    /// or an unset field silently means something else.
    #[test]
    fn an_untouched_builder_matches_the_type_default() {
        assert!(MaterializeOptions::builder().build() == MaterializeOptions::default());
    }
}
