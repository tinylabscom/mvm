//! Host-side collection of the files a transient workload hands back.
//!
//! A workload writes its results into an ext4 disk image it was given at boot.
//! Once the guest has flushed and stopped, the host reads that image in-process
//! — there is no protocol with the guest, only bytes on a disk the guest no
//! longer holds — and copies what it finds into a host directory. The image is
//! guest-authored, so every rule here is a refusal, and a refusal rejects the
//! whole collection: a partial result that looks complete is worse than none.
//!
//! - [`rules`]: the per-name and per-path refusals, shared in part with the OCI
//!   unpacker.
//! - [`manifest`]: the sorted (path, size, sha256) record of what came back and
//!   its canonical digest.
//! - [`collect`]: the two-pass walk — validate the whole tree against the
//!   bounds, then extract through directory handles that never follow a link.

pub mod collect;
pub mod manifest;
pub mod rules;

use std::path::PathBuf;

pub use collect::{
    CollectedOutputs, OutputCollection, check_destination_available, collect_from_ext4,
    manifest_path_for,
};
pub use manifest::{MANIFEST_DOMAIN, OutputEntry, OutputEntryKind, OutputManifest};
pub use rules::PathRule;

/// Deepest directory nesting a collection accepts.
pub const MAX_DEPTH: usize = 64;

/// Longest relative path, in bytes, a collection accepts.
pub const MAX_PATH_BYTES: usize = 4096;

/// The two bounds a collection is admitted under, both fixed before boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputBounds {
    /// Refuse when the regular files sum to more bytes than this.
    pub max_bytes: u64,
    /// Refuse when the tree holds more files and directories than this.
    pub max_entries: u64,
}

/// Why a collection was refused. Nothing is left at the destination when one
/// of these is returned.
#[derive(Debug, thiserror::Error)]
pub enum OutputRefusal {
    #[error("output path {path:?} is refused: {rule}")]
    Path { path: String, rule: PathRule },
    #[error("output entry {path:?} is a {kind}; only regular files and directories are collected")]
    EntryType { path: String, kind: &'static str },
    #[error("output entry {path:?} names one type in its directory and another in its inode")]
    TypeMismatch { path: String },
    #[error("output directory {path:?} lists the same name twice")]
    DuplicateName { path: String },
    #[error("outputs exceed the {max_bytes}-byte bound; nothing was collected")]
    ByteBound { max_bytes: u64 },
    #[error("outputs exceed the {max_entries}-entry bound; nothing was collected")]
    EntryBound { max_entries: u64 },
    #[error("output file {path:?} declared {declared} bytes but yielded {read}")]
    SizeMismatch {
        path: String,
        declared: u64,
        read: u64,
    },
    #[error("output destination {} is not an empty directory", .path.display())]
    DestinationNotEmpty { path: PathBuf },
    #[error("output destination {} is not a directory (a symlink is refused, not followed)", .path.display())]
    DestinationNotDirectory { path: PathBuf },
    #[error(
        "output destination {} resolves to {}; refusing to write through a moved or linked parent",
        .granted.display(),
        .resolved.display()
    )]
    DestinationMoved { granted: PathBuf, resolved: PathBuf },
    #[error("output manifest {} already exists; refusing to overwrite it", .path.display())]
    ManifestExists { path: PathBuf },
    #[error("output name {path:?} collides with an entry already written on this host")]
    HostCollision { path: String },
    #[error("output image is unreadable: {reason}")]
    Unreadable { reason: String },
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl OutputRefusal {
    /// Stable tag for the audit chain. Carries the rule, never the path, so a
    /// refusal records why without echoing guest-chosen names into the log.
    pub fn audit_tag(&self) -> &'static str {
        match self {
            Self::Path { rule, .. } => rule.audit_tag(),
            Self::EntryType { kind, .. } => kind,
            Self::TypeMismatch { .. } => "type_mismatch",
            Self::DuplicateName { .. } => "duplicate_name",
            Self::ByteBound { .. } => "byte_bound",
            Self::EntryBound { .. } => "entry_bound",
            Self::SizeMismatch { .. } => "size_mismatch",
            Self::DestinationNotEmpty { .. } => "destination_not_empty",
            Self::DestinationNotDirectory { .. } => "destination_not_directory",
            Self::DestinationMoved { .. } => "destination_moved",
            Self::ManifestExists { .. } => "manifest_exists",
            Self::HostCollision { .. } => "host_collision",
            Self::Unreadable { .. } => "unreadable_image",
            Self::Io { .. } => "host_io",
        }
    }

    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}
