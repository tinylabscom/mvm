//! Path-shaped validation primitives for OCI layer unpack.
//!
//! Every tar entry's path is normalized through
//! [`normalize_entry_path`] before any filesystem operation runs.
//! Rejection cases:
//!
//! - `..` components that escape the staging root.
//! - Absolute paths with platform prefixes (Windows drive letters,
//!   UNC paths). OCI rootfs paths are POSIX; anything else is a
//!   sign of a malicious or malformed tar.
//! - Null bytes in any component.
//! - Components named `mvm` at the top level — reserved for the
//!   runtime overlay disk's mount point.
//!
//! Symlink targets get an additional check via
//! [`validate_symlink_target`]: the target, resolved relative to
//! the symlink's directory, must stay within the staging root.
//! Pre-existing symlinks already in the staging dir are *not*
//! followed during this check — we only validate the static link
//! string the tar advertises.

use crate::oci_to_rootfs::error::OciUnpackError;
use std::path::{Component, Path, PathBuf};

/// Top-level path prefix reserved for the mvm runtime overlay disk.
/// OCI images that ship content at or under this prefix are rejected.
pub(crate) const RESERVED_PREFIX: &str = "mvm";

/// Normalize a tar entry's `header.path()` into a relative
/// staging-root-anchored path. Returns the normalized path on
/// success, or one of the rejection variants on policy failure.
pub(crate) fn normalize_entry_path(raw: &Path) -> Result<PathBuf, OciUnpackError> {
    if raw.as_os_str().is_empty() {
        return Err(OciUnpackError::PathTraversal {
            entry_path: raw.to_path_buf(),
        });
    }
    if raw.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(OciUnpackError::PathTraversal {
            entry_path: raw.to_path_buf(),
        });
    }

    let mut clean = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(c) => {
                let bytes = c.as_encoded_bytes();
                if bytes.is_empty() || bytes.contains(&0) {
                    return Err(OciUnpackError::PathTraversal {
                        entry_path: raw.to_path_buf(),
                    });
                }
                clean.push(c);
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                // `..` against an empty stack means we tried to
                // escape the staging root. Reject hard.
                if !clean.pop() {
                    return Err(OciUnpackError::PathTraversal {
                        entry_path: raw.to_path_buf(),
                    });
                }
            }
            Component::RootDir => {
                // A leading slash anchors the entry at the
                // staging root. Drop everything walked so far so
                // `clean` starts fresh from the root.
                clean = PathBuf::new();
            }
            Component::Prefix(_) => {
                // Windows drive letters / UNC prefixes have no
                // place in an OCI rootfs tar. Reject.
                return Err(OciUnpackError::PathTraversal {
                    entry_path: raw.to_path_buf(),
                });
            }
        }
    }

    // Empty path after normalization (e.g. `"./"` or `"."`) is
    // not a meaningful entry; reject so callers don't accidentally
    // try to write to the staging root itself.
    if clean.as_os_str().is_empty() {
        return Err(OciUnpackError::PathTraversal {
            entry_path: raw.to_path_buf(),
        });
    }

    check_reserved_prefix(&clean, raw)?;
    Ok(clean)
}

/// Reject entries whose top-level component is the reserved
/// `mvm` prefix. The check applies to the normalized path; an
/// entry like `./mvm/x` normalizes to `mvm/x` and is caught.
fn check_reserved_prefix(clean: &Path, raw: &Path) -> Result<(), OciUnpackError> {
    if let Some(first) = clean.components().next()
        && let Component::Normal(c) = first
        && c.as_encoded_bytes() == RESERVED_PREFIX.as_bytes()
    {
        return Err(OciUnpackError::ReservedPathCollision {
            entry_path: raw.to_path_buf(),
        });
    }
    Ok(())
}

/// Verify that `target` resolved against `source_dir` stays
/// within the staging root. Operates on the *static* link string;
/// existing symlinks in staging are not followed (which is the
/// right behaviour — we're checking what the layer is asking for,
/// not what's already on disk).
pub(crate) fn validate_symlink_target(source: &Path, target: &Path) -> Result<(), OciUnpackError> {
    if target.as_os_str().is_empty() {
        return Err(OciUnpackError::SymlinkEscape {
            link_path: source.to_path_buf(),
            target: target.to_path_buf(),
        });
    }
    if target.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(OciUnpackError::SymlinkEscape {
            link_path: source.to_path_buf(),
            target: target.to_path_buf(),
        });
    }

    let mut depth: i64 = if target.is_absolute() {
        0
    } else {
        // Relative target — start from the symlink's parent
        // directory's depth. Each Normal component in `source`'s
        // parent contributes one.
        let parent_components: i64 = source
            .parent()
            .map(|p| {
                p.components()
                    .filter(|c| matches!(c, Component::Normal(_)))
                    .count() as i64
            })
            .unwrap_or(0);
        parent_components
    };

    for component in target.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(OciUnpackError::SymlinkEscape {
                        link_path: source.to_path_buf(),
                        target: target.to_path_buf(),
                    });
                }
            }
            Component::RootDir => depth = 0,
            Component::Prefix(_) => {
                return Err(OciUnpackError::SymlinkEscape {
                    link_path: source.to_path_buf(),
                    target: target.to_path_buf(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ok(s: &str) -> PathBuf {
        normalize_entry_path(Path::new(s)).expect("expected normalize success")
    }

    #[test]
    fn normalizes_leading_slash() {
        assert_eq!(ok("/usr/bin/python"), PathBuf::from("usr/bin/python"));
    }

    #[test]
    fn normalizes_dot_components() {
        assert_eq!(ok("./usr/./bin/python"), PathBuf::from("usr/bin/python"));
    }

    #[test]
    fn normalizes_internal_dotdot() {
        // `usr/lib/../bin/python` resolves to `usr/bin/python`.
        // The `..` pops `lib`; we land at `usr` and add `bin/python`.
        assert_eq!(ok("usr/lib/../bin/python"), PathBuf::from("usr/bin/python"));
    }

    #[test]
    fn rejects_dotdot_at_root() {
        let err = normalize_entry_path(Path::new("../etc/passwd")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::PathTraversal { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_chained_dotdot_escape() {
        let err = normalize_entry_path(Path::new("usr/bin/../../../etc/passwd")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::PathTraversal { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_empty_path() {
        let err = normalize_entry_path(Path::new("")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::PathTraversal { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_dot_only_path() {
        let err = normalize_entry_path(Path::new(".")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::PathTraversal { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_mvm_top_level() {
        let err = normalize_entry_path(Path::new("mvm/runtime/agent")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::ReservedPathCollision { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_dotted_mvm_top_level() {
        let err = normalize_entry_path(Path::new("./mvm/x")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::ReservedPathCollision { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_absolute_mvm() {
        let err = normalize_entry_path(Path::new("/mvm/foo")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::ReservedPathCollision { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn permits_mvm_substring_below_top_level() {
        // Reserving only the top-level `mvm` means `usr/mvm-helper`
        // (a hypothetical user file) is fine.
        let p = ok("usr/local/mvm-helper");
        assert_eq!(p, PathBuf::from("usr/local/mvm-helper"));
    }

    #[test]
    fn permits_mvmctl_top_level_because_only_exact_match_reserved() {
        let p = ok("mvmctl");
        assert_eq!(p, PathBuf::from("mvmctl"));
    }

    #[test]
    fn rejects_null_byte_in_path() {
        let err = normalize_entry_path(Path::new("usr/bin/\0foo")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::PathTraversal { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn symlink_relative_target_stays_in_root() {
        // `usr/bin/python` -> `../lib/python3.9` resolves to
        // `usr/lib/python3.9` which is inside the rootfs.
        validate_symlink_target(Path::new("usr/bin/python"), Path::new("../lib/python3.9"))
            .expect("legitimate symlink should validate");
    }

    #[test]
    fn symlink_relative_target_can_traverse_into_sibling_dir() {
        validate_symlink_target(Path::new("usr/bin/python3"), Path::new("python3.9"))
            .expect("same-dir relative target should validate");
    }

    #[test]
    fn symlink_relative_target_escaping_root_rejected() {
        let err = validate_symlink_target(
            Path::new("usr/bin/escape"),
            Path::new("../../../../etc/passwd"),
        )
        .unwrap_err();
        assert!(
            matches!(err, OciUnpackError::SymlinkEscape { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn symlink_absolute_target_stays_in_root() {
        validate_symlink_target(Path::new("usr/bin/python"), Path::new("/usr/lib/python3.9"))
            .expect("absolute path within rootfs should validate");
    }

    #[test]
    fn symlink_empty_target_rejected() {
        let err = validate_symlink_target(Path::new("usr/bin/x"), Path::new("")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::SymlinkEscape { .. }),
            "{err:?}"
        );
    }
}
