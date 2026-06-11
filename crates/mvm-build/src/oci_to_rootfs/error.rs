//! Typed errors for OCI layer unpack.
//!
//! Every variant names a specific rejection class so callers can
//! distinguish "the registry shipped a malicious tar" from "the
//! disk filled up." Each malicious-tar class gets its own variant
//! here so the integration tests can assert "the right error fired
//! for this attack."

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OciUnpackError {
    /// A tar entry's path attempts to escape the staging root via
    /// `..` components, an absolute path with a non-root prefix,
    /// a Windows drive prefix, or any other form that would land
    /// the unpack outside `staging/`. Path-traversal class.
    #[error("path traversal rejected: {entry_path:?} would escape the staging root")]
    PathTraversal { entry_path: PathBuf },

    /// A tar entry's path lands at or under `/mvm`. That prefix is
    /// reserved for the runtime overlay disk; an OCI image that ships
    /// content there would collide with the mvm bind-mount and is
    /// rejected at admission time.
    #[error(
        "OCI image carries content at reserved path {entry_path:?} \
         (reserved by ADR-051 for the mvm runtime overlay)"
    )]
    ReservedPathCollision { entry_path: PathBuf },

    /// A symlink's target resolves outside the staging root.
    /// Symlink-escape class. Field is named `link_path` (not
    /// `source`) because `thiserror` reserves
    /// `source:` for the error chain; we just want a path here.
    #[error(
        "symlink escape rejected: {link_path:?} -> {target:?} \
         would resolve outside the staging root"
    )]
    SymlinkEscape { link_path: PathBuf, target: PathBuf },

    /// A hardlink's target points outside the staging root, or
    /// names a path that does not exist in the staging directory
    /// at the time the hardlink entry is applied. Hardlink-escape
    /// class.
    #[error(
        "hardlink rejected: {link_path:?} -> {target:?} \
         ({reason})"
    )]
    HardlinkInvalid {
        link_path: PathBuf,
        target: PathBuf,
        reason: &'static str,
    },

    /// A regular-file or layer entry exceeds the configured size
    /// cap. Decompression-bomb class.
    #[error("entry {entry_path:?} size {size} bytes exceeds per-entry cap of {cap} bytes")]
    EntryTooLarge {
        entry_path: PathBuf,
        size: u64,
        cap: u64,
    },

    /// The running total of bytes applied in the current layer
    /// exceeds the configured per-layer cap. Decompression-bomb
    /// class.
    #[error("layer total size {applied} bytes exceeds per-layer cap of {cap} bytes")]
    LayerTooLarge { applied: u64, cap: u64 },

    /// A tar entry has an unsupported type (block device,
    /// character device, FIFO, socket). OCI image rootfs layers
    /// must not contain these; the OCI spec allows them but in
    /// practice they only show up in malicious or
    /// misconfigured images. Reject on principle.
    #[error("unsupported entry type {entry_type:?} for {entry_path:?}")]
    UnsupportedEntryType {
        entry_path: PathBuf,
        entry_type: &'static str,
    },

    /// A whiteout marker has an invalid form (e.g. `.wh.` with
    /// no name following it, or a whiteout name that itself
    /// contains a path traversal).
    #[error("invalid whiteout marker {entry_path:?}: {reason}")]
    InvalidWhiteout {
        entry_path: PathBuf,
        reason: &'static str,
    },

    /// `mke2fs` exited non-zero or could not be spawned — the
    /// host-side orchestrator that turns a staged rootfs into an
    /// ext4 image file. Includes the upstream
    /// stderr so the failure mode is debuggable without re-running
    /// with `-v`.
    #[error("mke2fs failed: {reason}")]
    Mke2fsFailed { reason: String },

    /// `veritysetup format` exited non-zero, could not be spawned,
    /// or produced output that didn't include a parseable
    /// `Root hash:` line. Verity sidecar generation. Includes the
    /// upstream stderr / stdout when present so failures are
    /// debuggable.
    #[error("veritysetup failed: {reason}")]
    VeritysetupFailed { reason: String },

    /// An operation that this crate exposes is not supported on
    /// the current host. ext4 image materialization, for example,
    /// requires Linux + `mke2fs`; on macOS the CLI orchestrator runs
    /// it inside the builder VM. Callers that hit this variant on
    /// macOS should route the operation through the builder VM
    /// rather than reporting failure to the user.
    #[error("host does not support {operation}: {reason}")]
    HostUnsupported {
        operation: &'static str,
        reason: &'static str,
    },

    /// Underlying `std::io` failure during file creation, write,
    /// or close.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
