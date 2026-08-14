//! Resolving and validating the mvm-studio server artifact.
//!
//! This module is the security core of `mvmctl dashboard`, and it is
//! deliberately separable from launching anything: every rule here is a
//! decision about *which file* may be executed, and each one is testable
//! against a directory on disk with no child process involved.
//!
//! Three rules, in the order they bite:
//!
//! 1. **Two fixed locations, in order.** A sibling beside `mvmctl`, then the
//!    managed artifact under `MVM_HOME/bin`. Nothing else. There is no
//!    `--path` flag and no `PATH` lookup, because a launcher that resolves an
//!    executable by name through the environment executes whatever the
//!    environment points at.
//! 2. **No symlink.** A symlink is a redirection that can be repointed after
//!    the check that approved it, so it is refused rather than resolved.
//! 3. **No group- or world-writability**, on the artifact or on the directory
//!    holding it. A file only you can write is worth checking; a file in a
//!    directory anyone can write is not, because the check and the exec are
//!    not the same instant.

use std::path::{Path, PathBuf};

/// The fixed artifact name. Not configurable: see the module docs.
pub const STUDIO_SERVER_BIN: &str = "mvm-studio-server";

/// Why a candidate artifact was refused.
///
/// Separate variants rather than one string because the caller renders
/// different guidance for "not installed" than for "installed unsafely", and
/// because a test asserting the *reason* is a stronger test than one asserting
/// a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocateError {
    /// Neither location held the artifact.
    NotFound {
        /// Every path looked at, in order, so the message can name them.
        searched: Vec<PathBuf>,
    },
    /// The path exists but is a symlink.
    Symlink { path: PathBuf },
    /// The path exists but is not a regular file.
    NotAFile { path: PathBuf },
    /// The artifact, or the directory holding it, is writable by group or
    /// other.
    WritableByOthers { path: PathBuf, mode: u32 },
    /// The artifact is not marked executable.
    NotExecutable { path: PathBuf, mode: u32 },
}

impl std::fmt::Display for LocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { searched } => {
                write!(
                    f,
                    "mvm-studio server not found. Install it so `{STUDIO_SERVER_BIN}` sits \
                     beside mvmctl or under MVM_HOME/bin. Looked in: {}",
                    searched
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Self::Symlink { path } => write!(
                f,
                "{} is a symlink; refusing to launch it. A symlink can be repointed \
                 between the check and the exec, so the artifact must be a real file.",
                path.display()
            ),
            Self::NotAFile { path } => {
                write!(f, "{} is not a regular file", path.display())
            }
            Self::WritableByOthers { path, mode } => write!(
                f,
                "{} is writable by group or other (mode {mode:o}); refusing to launch it",
                path.display()
            ),
            Self::NotExecutable { path, mode } => {
                write!(f, "{} is not executable (mode {mode:o})", path.display())
            }
        }
    }
}

impl std::error::Error for LocateError {}

/// Where to look, in order. Both are derived, never supplied.
pub fn candidate_paths(mvmctl_exe: &Path, mvm_home_bin: &Path) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(2);
    if let Some(dir) = mvmctl_exe.parent() {
        out.push(dir.join(STUDIO_SERVER_BIN));
    }
    out.push(mvm_home_bin.join(STUDIO_SERVER_BIN));
    out
}

/// Resolve the artifact, or say exactly why not.
///
/// Takes both roots as arguments rather than reading the environment, so the
/// rules are testable against a temp dir without touching the real
/// `MVM_HOME` or the real executable path.
pub fn locate_studio_server(
    mvmctl_exe: &Path,
    mvm_home_bin: &Path,
) -> Result<PathBuf, LocateError> {
    let candidates = candidate_paths(mvmctl_exe, mvm_home_bin);
    for candidate in &candidates {
        // `symlink_metadata` does not follow the link — that is the point.
        // `metadata` here would report the *target's* type and mode and
        // silently approve a redirection.
        let Ok(meta) = std::fs::symlink_metadata(candidate) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            return Err(LocateError::Symlink {
                path: candidate.clone(),
            });
        }
        if !meta.file_type().is_file() {
            return Err(LocateError::NotAFile {
                path: candidate.clone(),
            });
        }
        validate_permissions(candidate, &meta)?;
        return Ok(candidate.clone());
    }
    Err(LocateError::NotFound {
        searched: candidates,
    })
}

/// Refuse an artifact anyone else can rewrite, and refuse one in a directory
/// anyone else can rewrite.
///
/// The directory check is the one that is easy to leave out and the one that
/// matters: approving a file inside a world-writable directory approves a name
/// that can be swapped for a different file before it is executed.
#[cfg(unix)]
fn validate_permissions(path: &Path, meta: &std::fs::Metadata) -> Result<(), LocateError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(LocateError::WritableByOthers {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    if mode & 0o111 == 0 {
        return Err(LocateError::NotExecutable {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    if let Some(dir) = path.parent()
        && let Ok(dir_meta) = std::fs::metadata(dir)
    {
        {
            let dir_mode = dir_meta.permissions().mode();
            // Sticky (0o1000) makes a shared directory safe for this purpose:
            // /tmp is world-writable but only the owner may replace an entry.
            if dir_mode & 0o022 != 0 && dir_mode & 0o1000 == 0 {
                return Err(LocateError::WritableByOthers {
                    path: dir.to_path_buf(),
                    mode: dir_mode & 0o7777,
                });
            }
        }
    }
    Ok(())
}

/// Non-Unix hosts expose no comparable mode bits, so the permission rules
/// cannot be enforced there. Stated rather than silently skipped.
#[cfg(not(unix))]
fn validate_permissions(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), LocateError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    fn write_exe(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, b"#!/bin/sh\ntrue\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_sibling_beside_mvmctl_wins_over_the_managed_copy() {
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();

        #[cfg(unix)]
        {
            write_exe(&sibling_dir.join(STUDIO_SERVER_BIN), 0o755);
            write_exe(&home_bin.join(STUDIO_SERVER_BIN), 0o755);
        }

        let found = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap();
        assert_eq!(
            found,
            sibling_dir.join(STUDIO_SERVER_BIN),
            "a sibling install must take precedence over the managed copy"
        );
    }

    #[test]
    fn the_managed_copy_is_the_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();
        #[cfg(unix)]
        write_exe(&home_bin.join(STUDIO_SERVER_BIN), 0o755);

        let found = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap();
        assert_eq!(found, home_bin.join(STUDIO_SERVER_BIN));
    }

    /// The message has to name where it looked, or "not found" is unactionable.
    #[test]
    fn a_missing_artifact_names_every_path_it_tried() {
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();

        let err = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap_err();
        let LocateError::NotFound { searched } = &err else {
            panic!("expected NotFound, got {err:?}");
        };
        assert_eq!(searched.len(), 2);
        let rendered = err.to_string();
        assert!(
            rendered.contains(&sibling_dir.display().to_string()),
            "{rendered}"
        );
        assert!(
            rendered.contains(&home_bin.display().to_string()),
            "{rendered}"
        );
    }

    /// A symlink is refused rather than resolved: it is a redirection that can
    /// be repointed between the check that approved it and the exec.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_artifact_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();

        let real = dir.path().join("real-server");
        write_exe(&real, 0o755);
        std::os::unix::fs::symlink(&real, sibling_dir.join(STUDIO_SERVER_BIN)).unwrap();

        let err = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap_err();
        assert!(
            matches!(err, LocateError::Symlink { .. }),
            "a symlink must be refused, not resolved to its target: {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_artifact_is_refused() {
        for mode in [0o775, 0o777, 0o757] {
            let dir = tempfile::tempdir().unwrap();
            let sibling_dir = dir.path().join("usr-local-bin");
            let home_bin = dir.path().join("mvm-bin");
            fs::create_dir_all(&sibling_dir).unwrap();
            fs::create_dir_all(&home_bin).unwrap();
            write_exe(&sibling_dir.join(STUDIO_SERVER_BIN), mode);

            let err = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap_err();
            assert!(
                matches!(err, LocateError::WritableByOthers { .. }),
                "mode {mode:o} must be refused: {err:?}"
            );
        }
    }

    /// The check people forget. A file only you can write, sitting in a
    /// directory anyone can write, can be replaced between the check and the
    /// exec — so approving it approves a name, not a file.
    #[cfg(unix)]
    #[test]
    fn an_artifact_in_a_world_writable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();
        write_exe(&sibling_dir.join(STUDIO_SERVER_BIN), 0o755);
        // Non-sticky and world-writable: anyone may replace the entry.
        fs::set_permissions(&sibling_dir, fs::Permissions::from_mode(0o777)).unwrap();

        let err = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap_err();
        let LocateError::WritableByOthers { path, .. } = &err else {
            panic!("expected WritableByOthers, got {err:?}");
        };
        assert_eq!(path, &sibling_dir, "the directory is what was unsafe");
    }

    /// Sticky bits make a shared directory safe for this purpose: /tmp is
    /// world-writable, but only an entry's owner may replace it.
    #[cfg(unix)]
    #[test]
    fn a_sticky_world_writable_directory_is_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();
        write_exe(&sibling_dir.join(STUDIO_SERVER_BIN), 0o755);
        fs::set_permissions(&sibling_dir, fs::Permissions::from_mode(0o1777)).unwrap();

        let found = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap();
        assert_eq!(found, sibling_dir.join(STUDIO_SERVER_BIN));
    }

    #[cfg(unix)]
    #[test]
    fn a_non_executable_artifact_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let sibling_dir = dir.path().join("usr-local-bin");
        let home_bin = dir.path().join("mvm-bin");
        fs::create_dir_all(&sibling_dir).unwrap();
        fs::create_dir_all(&home_bin).unwrap();
        write_exe(&sibling_dir.join(STUDIO_SERVER_BIN), 0o644);

        let err = locate_studio_server(&sibling_dir.join("mvmctl"), &home_bin).unwrap_err();
        assert!(
            matches!(err, LocateError::NotExecutable { .. }),
            "expected NotExecutable, got {err:?}"
        );
    }

    /// There is no third location and no environment override. This pins the
    /// search space itself, so adding a `PATH` lookup later is a test failure
    /// rather than a review catch.
    #[test]
    fn there_are_exactly_two_candidate_locations() {
        let candidates = candidate_paths(
            Path::new("/opt/mvm/bin/mvmctl"),
            Path::new("/home/u/.mvm/bin"),
        );
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/opt/mvm/bin").join(STUDIO_SERVER_BIN),
                PathBuf::from("/home/u/.mvm/bin").join(STUDIO_SERVER_BIN),
            ],
            "the search space is two fixed locations, in this order"
        );
    }
}
