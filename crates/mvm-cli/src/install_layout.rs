//! The on-disk layout `install.sh` creates, as far as the binary needs to
//! recognise it.
//!
//! `install.sh` unpacks each release whole into `<lib>/<n>-<version>/` and marks
//! it with [`RELEASE_MARKER`]; `<lib>` itself carries [`LIB_MARKER`]. Those two
//! markers are the only evidence a directory is the installer's, so nothing
//! here — and nothing in `uninstall.sh` — treats an unmarked directory as a
//! release, whatever its name.
//!
//! The Linux `.deb` and `.rpm` install a third marker, [`PACKAGE_MARKER`],
//! under the prefix whose `bin/` holds `mvmctl`. Its presence means the system
//! package manager owns the binaries beside `mvmctl`, and its content names the
//! package format.

use std::path::{Path, PathBuf};

/// Marker file at the root of the installer's library directory.
pub(crate) const LIB_MARKER: &str = ".mvm-lib";
/// Marker file inside each release directory the installer created.
pub(crate) const RELEASE_MARKER: &str = ".mvm-release";

/// Marker file the distribution packages install, relative to the prefix whose
/// `bin/` directory holds `mvmctl` (`/usr/share/mvmctl/package-managed` for
/// `/usr/bin/mvmctl`).
pub(crate) const PACKAGE_MARKER: &str = "share/mvmctl/package-managed";

/// The package format a [`PACKAGE_MARKER`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageFormat {
    Deb,
    Rpm,
}

impl PackageFormat {
    /// The marker content each package writes; nothing else parses.
    fn from_marker(content: &str) -> Option<Self> {
        match content.trim() {
            "deb" => Some(Self::Deb),
            "rpm" => Some(Self::Rpm),
            _ => None,
        }
    }
}

/// A system-package install of `mvmctl`, recognised by its marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageInstall {
    /// The marker that identified the install.
    pub(crate) marker: PathBuf,
    /// The format the marker names, or `None` when its content is not one a
    /// package of ours writes. The marker still means a package owns the
    /// files, so an unreadable format is not evidence of the opposite.
    pub(crate) format: Option<PackageFormat>,
}

/// The package install `exe` belongs to, when `exe` resolves to a file in
/// `bin/` or `lib/mvmctl/` whose prefix carries [`PACKAGE_MARKER`].
pub(crate) fn package_install_of(exe: &Path) -> Option<PackageInstall> {
    let exe = std::fs::canonicalize(exe).ok()?;
    let bin = exe.parent()?;
    let prefix = if bin.file_name()? == "bin" {
        bin.parent()?
    } else if bin.file_name()? == "mvmctl" && bin.parent()?.file_name()? == "lib" {
        bin.parent()?.parent()?
    } else {
        return None;
    };
    let marker = prefix.join(PACKAGE_MARKER);
    if !marker.is_file() {
        return None;
    }
    let format = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|content| PackageFormat::from_marker(&content));
    Some(PackageInstall { marker, format })
}

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
    fn package_markers_follow_canonical_library_executables() {
        for format in ["deb", "rpm", "aur", "nix"] {
            let root = tempfile::tempdir().unwrap();
            let lib = root.path().join("lib/mvmctl");
            let marker = root.path().join(PACKAGE_MARKER);
            std::fs::create_dir_all(&lib).unwrap();
            std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
            std::fs::write(lib.join("mvmctl"), "").unwrap();
            std::fs::write(&marker, format).unwrap();
            let install = package_install_of(&lib.join("mvmctl")).unwrap();
            assert_eq!(install.marker, std::fs::canonicalize(&marker).unwrap());
        }
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

    /// `<root>/usr/bin/mvmctl`, with the package marker under `<root>/usr`
    /// holding `content` when it is `Some`.
    fn package_prefix(content: Option<&str>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let usr = root.path().join("usr");
        std::fs::create_dir_all(usr.join("bin")).unwrap();
        std::fs::write(usr.join("bin/mvmctl"), "").unwrap();
        if let Some(content) = content {
            let marker = usr.join(PACKAGE_MARKER);
            std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
            std::fs::write(marker, content).unwrap();
        }
        root
    }

    #[test]
    fn the_packaging_installs_the_marker_this_binary_looks_for() {
        let manifest = include_str!("../../../Cargo.toml");
        let destination = format!("/usr/{PACKAGE_MARKER}");
        assert!(
            manifest.contains(&format!("\"{}\"", &destination[1..])),
            "the .deb assets must install {destination}"
        );
        assert!(
            manifest.contains(&format!("dest = \"{destination}\"")),
            "the .rpm assets must install {destination}"
        );
        let script = include_str!("../../../scripts/build-distro-packages.sh");
        for format in ["deb", "rpm"] {
            assert!(
                script.contains(&format!("printf '%s\\n' {format}")),
                "the build script must write the {format} marker"
            );
            assert!(PackageFormat::from_marker(&format!("{format}\n")).is_some());
        }
    }

    #[test]
    fn a_binary_under_a_marked_prefix_is_a_package_install() {
        for (content, format) in [
            ("deb\n", Some(PackageFormat::Deb)),
            ("rpm\n", Some(PackageFormat::Rpm)),
            ("pacman\n", None),
        ] {
            let root = package_prefix(Some(content));
            let install = package_install_of(&root.path().join("usr/bin/mvmctl"))
                .expect("a marked prefix is a package install");
            assert_eq!(install.format, format, "marker content {content:?}");
            assert_eq!(
                install.marker,
                std::fs::canonicalize(root.path().join("usr"))
                    .unwrap()
                    .join(PACKAGE_MARKER)
            );
        }
    }

    #[test]
    fn a_link_to_a_packaged_binary_is_still_the_package_install() {
        let root = package_prefix(Some("deb\n"));
        let link = root.path().join("mvmctl");
        std::os::unix::fs::symlink(root.path().join("usr/bin/mvmctl"), &link).unwrap();
        assert!(package_install_of(&link).is_some());
    }

    #[test]
    fn an_unmarked_prefix_or_a_binary_outside_bin_is_not_a_package_install() {
        let root = package_prefix(None);
        assert_eq!(
            package_install_of(&root.path().join("usr/bin/mvmctl")),
            None
        );

        let root = package_prefix(Some("deb\n"));
        let loose = root.path().join("usr/share/mvmctl/mvmctl");
        std::fs::write(&loose, "").unwrap();
        assert_eq!(
            package_install_of(&loose),
            None,
            "only a binary in the prefix's bin/ is the package's"
        );
        assert_eq!(package_install_of(&root.path().join("missing")), None);
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
