//! Private, process-owned staging directories for plaintext that must exist on
//! disk for a moment: a capture before it is encrypted, a restore after it is
//! decrypted.
//!
//! Each directory is created mode 0700 before anything is written into it, so
//! a permissive umask never widens it, and is named `<prefix><pid>-<random>`.
//! The owner's pid is what lets a later sweep tell an abandoned directory — its
//! process was killed, or aborted without running destructors — from one a
//! live operation is still using. A directory whose owner is alive is never
//! removed, and neither is a name this module did not make.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Create a private staging directory in `parent`, owned by this process.
/// Dropping the returned directory removes it and everything in it.
pub fn create(parent: &Path, prefix: &str) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    let owned_prefix = format!("{prefix}{}-", std::process::id());
    builder.prefix(&owned_prefix);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder
        .tempdir_in(parent)
        .with_context(|| format!("creating private staging in {}", parent.display()))?;
    // The mode passed at creation is still subject to the umask, which can only
    // narrow it. Set it again so the directory is exactly owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.path().display()))?;
    }
    Ok(dir)
}

/// The pid that owns `name`, when `name` is a staging directory made by
/// [`create`] with `prefix`.
fn owner(name: &str, prefix: &str) -> Option<i32> {
    name.strip_prefix(prefix)?
        .split_once('-')?
        .0
        .parse::<i32>()
        .ok()
}

/// The staging directories in `parent` made with `prefix` whose owning process
/// is gone. A missing or unreadable `parent` has none.
pub fn abandoned(parent: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && entry
                    .file_name()
                    .to_str()
                    .and_then(|name| owner(name, prefix))
                    .is_some_and(|pid| !mvm_vmm::host::process_liveness::pid_is_alive(pid))
        })
        .map(|entry| entry.path())
        .collect()
}

/// Remove every directory [`abandoned`] reports. Best effort: one that cannot
/// be removed is logged and left for the next sweep. Returns the directories
/// it removed.
pub fn reclaim_abandoned(parent: &Path, prefix: &str) -> Vec<PathBuf> {
    abandoned(parent, prefix)
        .into_iter()
        .filter(|path| match std::fs::remove_dir_all(path) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "could not reclaim abandoned staging");
                false
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A pid no process can hold: above every platform's pid ceiling.
    const DEAD_PID: i32 = i32::MAX;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn staging_is_private_and_names_its_owner() {
        let parent = tempfile::tempdir().unwrap();
        let staged = create(parent.path(), ".capture-").unwrap();
        assert_eq!(mode(staged.path()), 0o700);
        let name = staged.path().file_name().unwrap().to_str().unwrap();
        assert_eq!(owner(name, ".capture-"), Some(std::process::id() as i32));
        let path = staged.path().to_path_buf();
        drop(staged);
        assert!(!path.exists(), "dropping the staging removes it");
    }

    #[test]
    fn staging_is_private_under_a_permissive_umask() {
        // The umask is process-wide; nextest runs each test in its own process.
        let previous = unsafe { libc::umask(0) };
        let parent = tempfile::tempdir().unwrap();
        let staged = create(parent.path(), ".restore-");
        unsafe { libc::umask(previous) };
        assert_eq!(mode(staged.unwrap().path()), 0o700);
    }

    #[test]
    fn only_abandoned_staging_with_the_prefix_is_reclaimed() {
        let parent = tempfile::tempdir().unwrap();
        let dead = parent.path().join(format!(".capture-{DEAD_PID}-abc"));
        std::fs::create_dir(&dead).unwrap();
        std::fs::write(dead.join("mem.bin"), b"plaintext").unwrap();
        let live = create(parent.path(), ".capture-").unwrap();
        let other_prefix = parent.path().join(format!(".restore-{DEAD_PID}-abc"));
        std::fs::create_dir(&other_prefix).unwrap();
        let not_ours = parent.path().join(".capture-notapid");
        std::fs::create_dir(&not_ours).unwrap();
        let a_file = parent.path().join(format!(".capture-{DEAD_PID}-file"));
        std::fs::write(&a_file, b"user data").unwrap();

        assert_eq!(abandoned(parent.path(), ".capture-"), vec![dead.clone()]);
        assert_eq!(
            reclaim_abandoned(parent.path(), ".capture-"),
            vec![dead.clone()]
        );
        assert!(!dead.exists());
        assert!(live.path().exists(), "a live owner's staging is kept");
        assert!(other_prefix.exists(), "another prefix is not this sweep's");
        assert!(not_ours.exists(), "a name this module did not make is kept");
        assert!(a_file.exists(), "a file is never treated as staging");
    }

    #[test]
    fn a_missing_parent_has_nothing_to_reclaim() {
        let parent = tempfile::tempdir().unwrap();
        assert!(reclaim_abandoned(&parent.path().join("absent"), ".capture-").is_empty());
    }
}
