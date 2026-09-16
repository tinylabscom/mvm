//! The on-disk layout `install.sh` creates, as far as the binary needs to
//! recognise it.
//!
//! `install.sh` unpacks each release whole into `<lib>/<n>-<version>/` and marks
//! it with [`RELEASE_MARKER`]; `<lib>` itself carries [`LIB_MARKER`]. Those two
//! markers are the only evidence a directory is the installer's, so nothing
//! here — and nothing in `uninstall.sh` — treats an unmarked directory as a
//! release, whatever its name.

use std::path::{Path, PathBuf};

/// Marker file at the root of the installer's library directory.
pub(crate) const LIB_MARKER: &str = ".mvm-lib";
/// Marker file inside each release directory the installer created.
pub(crate) const RELEASE_MARKER: &str = ".mvm-release";

/// The library directory of the install `exe` runs from, when `exe` resolves to
/// a file in a marked release directory of a marked library directory.
pub(crate) fn versioned_lib_dir_of(exe: &Path) -> Option<PathBuf> {
    let exe = std::fs::canonicalize(exe).ok()?;
    let release = exe.parent()?;
    let lib = release.parent()?;
    (release.join(RELEASE_MARKER).is_file() && lib.join(LIB_MARKER).is_file())
        .then(|| lib.to_path_buf())
}

/// Every marked release directory directly under a marked library directory,
/// sorted by path. Empty for an unmarked or missing library directory.
pub(crate) fn release_dirs(lib: &Path) -> Vec<PathBuf> {
    if !lib.join(LIB_MARKER).is_file() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(lib) else {
        return Vec::new();
    };
    let mut releases: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|path| path.join(RELEASE_MARKER).is_file())
        .collect();
    releases.sort();
    releases
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `<root>/lib` with a marker, holding a marked release `1-v1` with an
    /// `mvmctl` file, an unmarked `2024-photos`, and a marked release in an
    /// unmarked sibling library.
    fn layout() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let lib = root.path().join("lib");
        std::fs::create_dir_all(lib.join("1-v1")).unwrap();
        std::fs::write(lib.join(LIB_MARKER), "install_dir=/x\n").unwrap();
        std::fs::write(lib.join("1-v1").join(RELEASE_MARKER), "complete\n").unwrap();
        std::fs::write(lib.join("1-v1").join("mvmctl"), "").unwrap();
        std::fs::create_dir_all(lib.join("2024-photos")).unwrap();
        std::fs::write(lib.join("2024-photos").join("mvmctl"), "").unwrap();
        let other = root.path().join("other");
        std::fs::create_dir_all(other.join("1-v1")).unwrap();
        std::fs::write(other.join("1-v1").join(RELEASE_MARKER), "complete\n").unwrap();
        std::fs::write(other.join("1-v1").join("mvmctl"), "").unwrap();
        root
    }

    #[test]
    fn the_install_scripts_use_the_same_marker_names() {
        for script in [
            include_str!("../../../install.sh"),
            include_str!("../../../uninstall.sh"),
        ] {
            assert!(script.contains(&format!("LIB_MARKER=\"{LIB_MARKER}\"")));
            assert!(script.contains(&format!("RELEASE_MARKER=\"{RELEASE_MARKER}\"")));
        }
    }

    #[test]
    fn an_exe_in_a_marked_release_of_a_marked_library_names_the_library() {
        let root = layout();
        let lib = std::fs::canonicalize(root.path().join("lib")).unwrap();
        assert_eq!(
            versioned_lib_dir_of(&root.path().join("lib/1-v1/mvmctl")),
            Some(lib)
        );
    }

    #[test]
    fn a_link_to_the_release_resolves_to_the_same_library() {
        let root = layout();
        let link = root.path().join("mvmctl");
        std::os::unix::fs::symlink(root.path().join("lib/1-v1/mvmctl"), &link).unwrap();
        assert!(versioned_lib_dir_of(&link).is_some());
    }

    #[test]
    fn a_numbered_name_alone_is_not_a_release() {
        let root = layout();
        assert_eq!(
            versioned_lib_dir_of(&root.path().join("lib/2024-photos/mvmctl")),
            None
        );
        assert_eq!(
            versioned_lib_dir_of(&root.path().join("other/1-v1/mvmctl")),
            None,
            "a marked release in an unmarked library is not an install"
        );
        assert_eq!(versioned_lib_dir_of(&root.path().join("missing")), None);
    }

    #[test]
    fn release_dirs_lists_only_marked_releases_of_a_marked_library() {
        let root = layout();
        assert_eq!(
            release_dirs(&root.path().join("lib")),
            vec![root.path().join("lib/1-v1")]
        );
        assert!(release_dirs(&root.path().join("other")).is_empty());
        assert!(release_dirs(&root.path().join("missing")).is_empty());
    }
}
