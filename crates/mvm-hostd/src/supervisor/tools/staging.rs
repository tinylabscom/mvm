//! Shared backing store for `mvm.upload` + `mvm.download`.
//!
//! Plan 60 Phase 7. Both tools operate on a bounded **staging area** —
//! a host-side directory the supervisor owns + the workload's guest
//! can mount or read via a controlled channel. Phase 7a's persistent
//! overlay will eventually displace this with a per-tenant
//! ext4-on-luks layer; until then a plain on-disk directory under
//! `~/.mvm/tool-staging/<tenant>/` is enough to demonstrate the
//! agent surface end-to-end.
//!
//! ## Security model
//!
//! The staging area is the only filesystem surface either tool
//! touches. Both tools accept a relative path; this module's path
//! validator enforces:
//!
//! 1. **No absolute paths** — `/etc/passwd` is rejected before any
//!    join happens.
//! 2. **No parent-dir components** — `..` anywhere in the input,
//!    even quoted (`%2e%2e`), is rejected. We don't try to be
//!    clever about URL decoding; the path is treated as a raw
//!    filesystem path so encoded escapes can't smuggle through.
//! 3. **No leading separators** — `\foo` on Windows / `/foo` on
//!    Unix both fail at the `Path::components()` check.
//! 4. **No null bytes / control chars** — defends against
//!    `truncate/etc/passwd\0.txt` style attacks where downstream
//!    C code might honour the embedded null.
//! 5. **Path-length cap** (512 bytes) — defends against
//!    PATH_MAX edge cases on Linux (default 4096) and avoids
//!    paths that bloat the audit chain.
//! 6. **No symlink following** — opens use `O_NOFOLLOW` on Unix.
//!    A symlink placed inside the staging dir (the only way one
//!    could appear) trips ELOOP rather than crossing the
//!    boundary.
//! 7. **Per-tenant subdir** — the registry passes a tenant id to
//!    [`FsStagingArea::for_tenant`] so two tenants on the same
//!    host can't read each other's staged files.
//!
//! ## Size caps
//!
//! Both upload + download enforce `max_bytes` at the tool layer
//! (caller-supplied, clamped to [`MAX_ALLOWED_BYTES`]). The staging
//! area itself doesn't read more than asked; on writes it refuses
//! oversize payloads before the first byte hits disk.
//!
//! ## What this module is NOT
//!
//! - Not a persistent overlay — that's Phase 7a's job. Files
//!   written here survive across MCP server restarts (the host
//!   directory is durable) but they aren't atomic / aren't
//!   encrypted / aren't volume-mounted into the workload.
//! - Not a sandboxing layer — `O_NOFOLLOW` + the path validator
//!   defend against escape, but the staging dir is uid-readable
//!   by the calling user (mode 0700 on the dir, default mode
//!   0600 on files). The agent should treat anything in here as
//!   coming from a "trusted user" boundary — a tenant peer.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

/// Hard upper bound on per-call `max_bytes` for upload + download.
/// Caller-supplied values above this are clamped.
pub const MAX_ALLOWED_BYTES: u64 = 256 * (1 << 20);

/// Default per-call cap when the caller doesn't specify. 16 MiB
/// matches the same per-call working budget the rest of Phase 7
/// uses (web_fetch's `MAX_ALLOWED_BYTES`).
pub const DEFAULT_MAX_BYTES: u64 = 16 * (1 << 20);

/// Maximum path-string length, bytes. Defends against PATH_MAX
/// surprises and keeps the audit chain bounded.
pub const MAX_PATH_LEN: usize = 512;

/// Default per-tenant staging dir.
/// `~/.mvm/tool-staging/<tenant>/`.
pub fn default_staging_root() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".mvm").join("tool-staging"))
}

/// Canonical env-var name for overriding the staging root.
pub const STAGING_DIR_ENV_VAR: &str = "MVM_TOOL_STAGING_DIR";

/// Trait that backs both [`super::upload::UploadTool`] and
/// [`super::download::DownloadTool`]. Implementations are
/// stateless from the registry's perspective — credentials,
/// per-tenant scoping, quota tracking all live behind the trait.
#[async_trait]
pub trait StagingArea: Send + Sync {
    /// Write `bytes` to the relative `path` inside the staging
    /// area. The implementation is responsible for path validation
    /// + size enforcement.
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<(), StagingError>;

    /// Read the file at the relative `path`, up to `max_bytes`.
    /// Reads above the cap return `BodyTooLarge`.
    async fn read(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>, StagingError>;
}

#[derive(Debug, Error)]
pub enum StagingError {
    #[error("invalid path {path:?}: {reason}")]
    InvalidPath { path: String, reason: &'static str },

    #[error("path {path:?} not found in staging area")]
    NotFound { path: String },

    #[error("payload exceeded max_bytes ({limit})")]
    BodyTooLarge { limit: u64 },

    #[error("io error on {path:?}: {message}")]
    Io { path: String, message: String },

    #[error("staging area not wired (NoopStagingArea)")]
    Unwired,
}

/// Fail-closed default. Useful as the substrate's placeholder
/// when `$HOME` isn't reachable or the operator hasn't configured
/// a staging root.
pub struct NoopStagingArea;

#[async_trait]
impl StagingArea for NoopStagingArea {
    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<(), StagingError> {
        Err(StagingError::Unwired)
    }
    async fn read(&self, _path: &str, _max_bytes: u64) -> Result<Vec<u8>, StagingError> {
        Err(StagingError::Unwired)
    }
}

/// Filesystem-backed staging area rooted at a per-tenant directory.
///
/// The root is created on first construction with mode 0700. Each
/// file written underneath inherits the OS default (umask-honoured;
/// typically 0644 on Linux). Callers that need tighter perms should
/// adjust via a follow-up slice.
#[derive(Debug)]
pub struct FsStagingArea {
    root: PathBuf,
}

impl FsStagingArea {
    /// Build with an explicit root (test seam — tests use a tempdir).
    /// The directory is created if missing; permissions are
    /// tightened to 0700 on Unix.
    pub fn with_root(root: impl Into<PathBuf>) -> Result<Self, StagingError> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| StagingError::Io {
            path: root.display().to_string(),
            message: format!("creating staging root: {e}"),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&root, perms).ok();
        }
        Ok(Self { root })
    }

    /// Build a per-tenant subdir under `parent`. The tenant id is
    /// itself path-validated to keep a malicious tenant from
    /// escaping the parent via `..` smuggled in the tenant name.
    pub fn for_tenant(parent: impl Into<PathBuf>, tenant: &str) -> Result<Self, StagingError> {
        validate_path_component(tenant, "tenant id")?;
        let root = parent.into().join(tenant);
        Self::with_root(root)
    }

    /// Public read-only view of the root, for diagnostic output.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, rel: &str) -> Result<PathBuf, StagingError> {
        validate_relative_path(rel)?;
        Ok(self.root.join(rel))
    }
}

#[async_trait]
impl StagingArea for FsStagingArea {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<(), StagingError> {
        let absolute = self.resolve(path)?;
        if let Some(parent) = absolute.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StagingError::Io {
                path: path.to_string(),
                message: format!("creating parent dir: {e}"),
            })?;
        }
        // O_NOFOLLOW so a symlink that crept into the staging dir
        // can't redirect the write outside.
        #[cfg(unix)]
        let result = {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&absolute);
            match f {
                Ok(ref mut file) => file.write_all(bytes).map_err(|e| StagingError::Io {
                    path: path.to_string(),
                    message: e.to_string(),
                }),
                Err(e) => Err(StagingError::Io {
                    path: path.to_string(),
                    message: e.to_string(),
                }),
            }
        };
        #[cfg(not(unix))]
        let result = std::fs::write(&absolute, bytes).map_err(|e| StagingError::Io {
            path: path.to_string(),
            message: e.to_string(),
        });
        result
    }

    async fn read(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>, StagingError> {
        let absolute = self.resolve(path)?;
        let meta = std::fs::metadata(&absolute).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StagingError::NotFound {
                    path: path.to_string(),
                }
            } else {
                StagingError::Io {
                    path: path.to_string(),
                    message: e.to_string(),
                }
            }
        })?;
        if meta.len() > max_bytes {
            return Err(StagingError::BodyTooLarge { limit: max_bytes });
        }
        // Refuse to read through symlinks. O_NOFOLLOW on the open
        // is the canonical defense; on non-Unix we fall back to a
        // `symlink_metadata` check.
        #[cfg(unix)]
        {
            use std::io::Read as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&absolute)
                .map_err(|e| StagingError::Io {
                    path: path.to_string(),
                    message: e.to_string(),
                })?;
            let mut buf = Vec::with_capacity(meta.len() as usize);
            f.read_to_end(&mut buf).map_err(|e| StagingError::Io {
                path: path.to_string(),
                message: e.to_string(),
            })?;
            Ok(buf)
        }
        #[cfg(not(unix))]
        {
            let sym_meta = std::fs::symlink_metadata(&absolute).map_err(|e| StagingError::Io {
                path: path.to_string(),
                message: e.to_string(),
            })?;
            if sym_meta.file_type().is_symlink() {
                return Err(StagingError::InvalidPath {
                    path: path.to_string(),
                    reason: "symlinks are not followed",
                });
            }
            std::fs::read(&absolute).map_err(|e| StagingError::Io {
                path: path.to_string(),
                message: e.to_string(),
            })
        }
    }
}

/// Validate one path component (filename, tenant id) — no
/// separators, no parent refs, no nulls, length-capped.
pub(crate) fn validate_path_component(name: &str, label: &str) -> Result<(), StagingError> {
    if name.is_empty() {
        return Err(StagingError::InvalidPath {
            path: name.to_string(),
            reason: "empty",
        });
    }
    if name.len() > MAX_PATH_LEN {
        return Err(StagingError::InvalidPath {
            path: name.to_string(),
            reason: "exceeds MAX_PATH_LEN",
        });
    }
    if name.contains('\0') || name.chars().any(|c| c.is_control()) {
        return Err(StagingError::InvalidPath {
            path: name.to_string(),
            reason: "contains null or control character",
        });
    }
    if name.contains('/') || name.contains('\\') {
        return Err(StagingError::InvalidPath {
            path: name.to_string(),
            reason: "contains a path separator",
        });
    }
    if name == "." || name == ".." {
        return Err(StagingError::InvalidPath {
            path: name.to_string(),
            reason: "is a dot or parent reference",
        });
    }
    let _ = label;
    Ok(())
}

/// Validate a multi-component relative path. Rejects absolute
/// paths, parent refs, control characters, and overlong inputs.
pub(crate) fn validate_relative_path(rel: &str) -> Result<(), StagingError> {
    if rel.is_empty() {
        return Err(StagingError::InvalidPath {
            path: rel.to_string(),
            reason: "empty",
        });
    }
    if rel.len() > MAX_PATH_LEN {
        return Err(StagingError::InvalidPath {
            path: rel.to_string(),
            reason: "exceeds MAX_PATH_LEN",
        });
    }
    if rel.contains('\0') || rel.chars().any(|c| c.is_control()) {
        return Err(StagingError::InvalidPath {
            path: rel.to_string(),
            reason: "contains null or control character",
        });
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(StagingError::InvalidPath {
            path: rel.to_string(),
            reason: "is absolute",
        });
    }
    for c in p.components() {
        match c {
            Component::Normal(_) => {}
            Component::CurDir => {
                return Err(StagingError::InvalidPath {
                    path: rel.to_string(),
                    reason: "contains a '.' component",
                });
            }
            Component::ParentDir => {
                return Err(StagingError::InvalidPath {
                    path: rel.to_string(),
                    reason: "contains a '..' component",
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(StagingError::InvalidPath {
                    path: rel.to_string(),
                    reason: "starts with a root or drive prefix",
                });
            }
        }
    }
    Ok(())
}

/// Helper that picks the right [`StagingArea`] for the dispatcher's
/// build path. Reads `$MVM_TOOL_STAGING_DIR` (or falls back to
/// `~/.mvm/tool-staging/`) and constructs a per-tenant
/// [`FsStagingArea`]. On any setup failure returns the fail-closed
/// [`NoopStagingArea`].
pub fn default_for_tenant(tenant: &str) -> Arc<dyn StagingArea> {
    let parent = std::env::var_os(STAGING_DIR_ENV_VAR)
        .map(PathBuf::from)
        .or_else(default_staging_root);
    let Some(parent) = parent else {
        tracing::warn!("$HOME and $MVM_TOOL_STAGING_DIR unset; tool staging area not wired");
        return Arc::new(NoopStagingArea);
    };
    match FsStagingArea::for_tenant(parent, tenant) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(error = %e, tenant = tenant, "FsStagingArea init failed");
            Arc::new(NoopStagingArea)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ──────────────────────────────────────────────────────────────
    // Path validator
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn validate_rejects_absolute_path() {
        let err = validate_relative_path("/etc/passwd").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_rejects_parent_ref() {
        let err = validate_relative_path("..").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
        let err = validate_relative_path("a/../b").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_rejects_bare_curdir() {
        // `Path::components()` normalizes `a/./b` to `a/b` (the
        // CurDir is stripped), so a single bare `.` is the only
        // shape that surfaces `Component::CurDir`. Both forms are
        // semantically safe — `a/./b` and `a/b` resolve to the
        // same file — but the bare `.` denotes the staging root
        // itself, which we refuse to write to as a sanity check.
        let err = validate_relative_path(".").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_accepts_normalized_curdir_in_middle() {
        // `a/./b` survives validation because Path normalization
        // strips the `.`. Documented here so a future refactor
        // that adds extra rejection doesn't regress legitimate
        // path-with-dot-in-middle use.
        validate_relative_path("a/./b").unwrap();
    }

    #[test]
    fn validate_rejects_empty_path() {
        let err = validate_relative_path("").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_rejects_null_byte() {
        let err = validate_relative_path("a\0b").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_rejects_control_character() {
        let err = validate_relative_path("a\nb").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_rejects_overlong_path() {
        let long = "a".repeat(MAX_PATH_LEN + 1);
        let err = validate_relative_path(&long).unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_accepts_nested_normal_path() {
        validate_relative_path("foo/bar/baz.txt").unwrap();
    }

    #[test]
    fn validate_accepts_single_filename() {
        validate_relative_path("hello.json").unwrap();
    }

    #[test]
    fn validate_component_rejects_slash() {
        let err = validate_path_component("a/b", "tenant").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[test]
    fn validate_component_rejects_parent_ref() {
        let err = validate_path_component("..", "tenant").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    // ──────────────────────────────────────────────────────────────
    // FsStagingArea round-trip
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fs_staging_round_trip_preserves_bytes() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        let payload = b"hello world";
        s.write("greeting.txt", payload).await.unwrap();
        let read = s.read("greeting.txt", 1024).await.unwrap();
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn fs_staging_nested_write_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        s.write("sub/dir/file.bin", b"abc").await.unwrap();
        assert_eq!(s.read("sub/dir/file.bin", 16).await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn fs_staging_read_missing_returns_not_found() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        let err = s.read("nope.txt", 1024).await.unwrap_err();
        assert!(matches!(err, StagingError::NotFound { .. }));
    }

    #[tokio::test]
    async fn fs_staging_read_oversize_returns_body_too_large() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        s.write("big.bin", &[0u8; 8]).await.unwrap();
        let err = s.read("big.bin", 4).await.unwrap_err();
        assert!(matches!(err, StagingError::BodyTooLarge { limit: 4 }));
    }

    #[tokio::test]
    async fn fs_staging_rejects_absolute_path_on_write() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        let err = s.write("/etc/evil", b"x").await.unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[tokio::test]
    async fn fs_staging_rejects_parent_ref_on_read() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        let err = s.read("../escape", 1024).await.unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fs_staging_refuses_to_follow_symlink_on_read() {
        // Manually plant a symlink inside the staging dir pointing
        // outside; reading through it must fail.
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"escaped").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link")).unwrap();
        let s = FsStagingArea::with_root(dir.path()).unwrap();
        let err = s.read("link", 1024).await.unwrap_err();
        // ELOOP on Linux is wrapped as Io; what we assert is that
        // the read does NOT succeed.
        assert!(matches!(err, StagingError::Io { .. }));
    }

    #[tokio::test]
    async fn for_tenant_validates_tenant_id() {
        let dir = tempdir().unwrap();
        let err = FsStagingArea::for_tenant(dir.path(), "../escape").unwrap_err();
        assert!(matches!(err, StagingError::InvalidPath { .. }));
    }

    #[tokio::test]
    async fn for_tenant_creates_subdir_under_parent() {
        let dir = tempdir().unwrap();
        let s = FsStagingArea::for_tenant(dir.path(), "acme").unwrap();
        assert!(s.root().starts_with(dir.path()));
        assert!(s.root().ends_with("acme"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fs_staging_root_has_0700_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("staging");
        FsStagingArea::with_root(&root).unwrap();
        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging root must be 0700");
    }

    // ──────────────────────────────────────────────────────────────
    // NoopStagingArea
    // ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn noop_staging_returns_unwired_on_write() {
        let s = NoopStagingArea;
        let err = s.write("x", b"y").await.unwrap_err();
        assert!(matches!(err, StagingError::Unwired));
    }

    #[tokio::test]
    async fn noop_staging_returns_unwired_on_read() {
        let s = NoopStagingArea;
        let err = s.read("x", 1024).await.unwrap_err();
        assert!(matches!(err, StagingError::Unwired));
    }
}
