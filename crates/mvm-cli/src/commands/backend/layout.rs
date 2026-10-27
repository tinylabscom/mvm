//! The install.sh-managed install the running `mvmctl` belongs to — the
//! layout `backend add` / `backend remove` edit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A versioned install.sh install, resolved from the running executable.
pub(super) struct ManagedInstall {
    /// The release directory the running binary executes from (resolved).
    pub(super) release_dir: PathBuf,
    /// The library directory holding `current` and every release directory.
    pub(super) lib_dir: PathBuf,
    /// The directory whose links reach PATH, recorded in the library marker.
    pub(super) install_dir: PathBuf,
    /// The release tag this install runs, e.g. `v0.25.0`.
    pub(super) tag: String,
}

/// The release tag of a release directory named `<n>-<tag>`. The numeric
/// prefix is the install order; the tag itself may contain hyphens
/// (`v0.18.0-rc.1`).
fn tag_of_release_dir(name: &str) -> Option<&str> {
    let (seq, tag) = name.split_once('-')?;
    (!seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) && !tag.is_empty()).then_some(tag)
}

/// Resolve the running binary's install, or refuse: `backend add`/`remove`
/// edit a release directory, so they need an install.sh layout. Source
/// checkouts build the component from the tree; system packages own their
/// files through the package manager.
pub(super) fn managed_install() -> Result<ManagedInstall> {
    let exe = std::env::current_exe().context("failed to determine the current executable")?;
    if let Some(package) = crate::install_layout::package_install_of(&exe) {
        bail!(
            "this mvmctl belongs to a system package (marker: {}); the package manager \
             owns its backend components",
            package.marker.display()
        );
    }
    let Some(lib_dir) = crate::install_layout::versioned_lib_dir_of(&exe) else {
        bail!(
            "mvmctl backend add/remove manage an install made by install.sh; this mvmctl \
             runs from {}. On a source checkout, build host helpers from the tree instead.",
            exe.display()
        );
    };
    let release_dir = exe
        .canonicalize()
        .context("failed to resolve the current executable")?
        .parent()
        .map(Path::to_path_buf)
        .context("the current executable has no parent directory")?;
    let name = release_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("the release directory name is not UTF-8")?;
    let tag = tag_of_release_dir(name)
        .with_context(|| format!("{name} is not a release directory name"))?
        .to_string();
    let marker = lib_dir.join(crate::install_layout::LIB_MARKER);
    let marker_body = std::fs::read_to_string(&marker)
        .with_context(|| format!("reading {}", marker.display()))?;
    let install_dir = marker_body
        .lines()
        .find_map(|line| line.strip_prefix("install_dir="))
        .map(PathBuf::from)
        .with_context(|| format!("{} records no install_dir", marker.display()))?;
    Ok(ManagedInstall {
        release_dir,
        lib_dir,
        install_dir,
        tag,
    })
}

#[cfg(test)]
mod tests {
    use super::tag_of_release_dir;

    #[test]
    fn release_dir_names_yield_their_tags() {
        assert_eq!(tag_of_release_dir("1-v0.25.0"), Some("v0.25.0"));
        assert_eq!(tag_of_release_dir("12-v0.18.0-rc.1"), Some("v0.18.0-rc.1"));
        assert_eq!(tag_of_release_dir("v0.25.0"), None);
        assert_eq!(tag_of_release_dir("1-"), None);
        assert_eq!(tag_of_release_dir("-v1"), None);
        assert_eq!(tag_of_release_dir("unversioned"), None);
    }
}
