//! Owner-only files and directories for the state mvm keeps on the host.
//!
//! Everything mvm writes under its home — keys, secrets, audit chains, VM
//! state — belongs to the user running it and nobody else: directories are
//! `0700` and secret files `0600`. That is a Unix permission model, and this
//! module is the single place the crate reaches it, so the platform question
//! is answered once rather than at every call site.
//!
//! A host without Unix permission bits gets a refusal, not a fallback. Every
//! function here returns [`io::ErrorKind::Unsupported`] there instead of
//! creating the file or directory with whatever the platform would choose.
//! On Windows that choice is an ACL inherited from the parent directory, which
//! can leave a key readable by other local accounts while the write appears to
//! succeed — exactly the failure the owner-only rule exists to rule out.
//! A future Windows/WHP host needs a separately verified owner-only DACL
//! implementation before replacing these refusals.

use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(all(test, unix))]
use std::fs::Permissions;

/// Mode of a directory holding private state.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Mode of a file holding a secret.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

#[cfg(unix)]
#[path = "private_fs/platforms/unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "private_fs/platforms/unsupported.rs"]
mod platform;

pub use platform::{
    create_owned_private_dir, ensure_private_dir, mode_bits, permissions, require_current_owner,
    set_mode, sync_managed_directory_chain,
};
#[cfg(all(test, unix))]
use platform::{require_owner_uid, sync_managed_directory_chain_with};

/// The error every function in this module returns on a host without Unix
/// permission bits. `subject` names what was being made private, so the
/// refusal says which file or directory was not written.
pub fn unsupported_platform_error(subject: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "{}: owner-only file permissions are not implemented on this host \
             platform; mvm supports Linux and macOS hosts",
            subject.display()
        ),
    )
}

/// Opening a file whose creation mode is part of the request.
pub trait OpenOptionsModeExt {
    /// Open `path` with these options, creating it at `mode` if the options
    /// create. `mode` is still masked by the process umask, as `open(2)` is;
    /// a caller that must guarantee the bits follows up with [`set_mode`].
    fn open_with_mode(&self, mode: u32, path: impl AsRef<Path>) -> io::Result<File>;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn ownership_predicate_accepts_owned_file_and_directory_without_repair() {
        let directory = tempfile::tempdir().unwrap();
        let file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        for path in [directory.path(), file.path()] {
            let before = std::fs::metadata(path).unwrap();
            require_current_owner(&before).unwrap();
            assert_eq!(mode(path), before.permissions().mode() & 0o777);
        }
    }

    #[test]
    fn ownership_predicate_refuses_different_uid_with_static_diagnostic() {
        for (actual, expected) in [(0, 1), (1, 0), (u32::MAX, 0)] {
            let error = require_owner_uid(actual, expected).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                error.to_string(),
                "object is not owned by the current effective user"
            );
        }
        require_owner_uid(0, 0).unwrap();
        require_owner_uid(u32::MAX, u32::MAX).unwrap();
    }

    #[test]
    fn managed_namespace_sync_is_leaf_first_for_new_and_existing_directories() {
        let home = tempfile::tempdir().unwrap();
        let generation = home.path().join("vms/demo/protected/run/000");
        ensure_private_dir(&generation).unwrap();
        let expected: Vec<_> = generation
            .canonicalize()
            .unwrap()
            .ancestors()
            .map(Path::to_path_buf)
            .collect();
        for _ in 0..2 {
            let mut visited = Vec::new();
            sync_managed_directory_chain_with(home.path(), &generation, |path, file| {
                visited.push(path.to_path_buf());
                file.sync_all()
            })
            .unwrap();
            assert_eq!(visited, expected);
        }
    }

    #[test]
    fn managed_namespace_sync_failure_stops_before_parent_publication() {
        let home = tempfile::tempdir().unwrap();
        let generation = home.path().join("run/000");
        ensure_private_dir(&generation).unwrap();
        let fail = home.path().join("run").canonicalize().unwrap();
        let mut visited = Vec::new();
        assert!(
            sync_managed_directory_chain_with(home.path(), &generation, |path, _| {
                visited.push(path.to_path_buf());
                if path == fail {
                    Err(io::Error::other("injected ancestor failure"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert_eq!(visited.len(), 2);
        assert_eq!(visited.last(), Some(&fail));
        assert!(generation.is_dir());
    }

    #[test]
    fn managed_namespace_refuses_escape_and_symlink_descendants() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("link")).unwrap();
        assert!(sync_managed_directory_chain(home.path(), outside.path()).is_err());
        assert!(sync_managed_directory_chain(home.path(), &home.path().join("../escape")).is_err());
        assert!(sync_managed_directory_chain(home.path(), &home.path().join("link")).is_err());
    }

    #[test]
    fn open_with_mode_creates_the_file_at_the_requested_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open_with_mode(PRIVATE_FILE_MODE, &path)
            .unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn open_with_mode_leaves_the_caller_options_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options.open_with_mode(0o600, dir.path().join("a")).unwrap();
        options.open_with_mode(0o644, dir.path().join("b")).unwrap();
        assert_eq!(mode(&dir.path().join("a")), 0o600);
        assert_eq!(mode(&dir.path().join("b")), 0o644);
    }

    #[test]
    fn set_mode_and_mode_bits_agree() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        set_mode(&path, 0o640).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(mode_bits(&path, &meta).unwrap(), 0o640);
    }

    #[test]
    fn permissions_set_through_a_handle_carry_exactly_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let file = File::create(&path).unwrap();
        file.set_permissions(permissions(&path, 0o604).unwrap())
            .unwrap();
        assert_eq!(mode(&path), 0o604);
    }

    #[test]
    fn ensure_private_dir_creates_and_tightens_a_loose_directory() {
        let root = tempfile::tempdir().unwrap();
        let fresh = root.path().join("fresh/leaf");
        ensure_private_dir(&fresh).unwrap();
        assert_eq!(mode(&fresh), 0o700);

        let loose = root.path().join("loose");
        std::fs::create_dir(&loose).unwrap();
        set_mode(&loose, 0o755).unwrap();
        ensure_private_dir(&loose).unwrap();
        assert_eq!(mode(&loose), 0o700);
    }

    #[test]
    fn ensure_private_dir_creates_private_parents_without_changing_existing_ancestors() {
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), 0o755).unwrap();
        let target = root.path().join("new/nested/leaf");

        ensure_private_dir(&target).unwrap();

        assert_eq!(mode(root.path()), 0o755);
        // The umask may remove owner bits, but must never grant group/other access.
        assert_eq!(mode(&root.path().join("new")) & 0o077, 0);
        assert_eq!(mode(&root.path().join("new/nested")) & 0o077, 0);
        assert_eq!(mode(&target), PRIVATE_DIR_MODE);
    }

    #[test]
    fn ensure_private_dir_preserves_an_existing_private_target() {
        let root = tempfile::tempdir().unwrap();
        set_mode(root.path(), PRIVATE_DIR_MODE).unwrap();
        let marker = root.path().join("marker");
        std::fs::write(&marker, b"synthetic").unwrap();

        ensure_private_dir(root.path()).unwrap();

        assert_eq!(mode(root.path()), PRIVATE_DIR_MODE);
        assert_eq!(std::fs::read(marker).unwrap(), b"synthetic");
    }

    #[test]
    fn ensure_private_dir_rejects_files_as_targets_and_ancestors() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"synthetic").unwrap();
        set_mode(&file, 0o644).unwrap();

        assert!(ensure_private_dir(&file).is_err());
        assert!(ensure_private_dir(file.join("leaf")).is_err());
        assert_eq!(mode(&file), 0o644);
        assert_eq!(std::fs::read(file).unwrap(), b"synthetic");
    }
}

#[cfg(all(test, unix))]
mod owned_dir_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn a_missing_directory_is_created_private() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("socks");
        create_owned_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PRIVATE_DIR_MODE);
    }

    #[test]
    fn an_existing_directory_we_own_is_tightened() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("socks");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        create_owned_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, PRIVATE_DIR_MODE);
    }

    #[test]
    fn a_symlink_planted_at_the_path_is_refused_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let link = root.path().join("socks");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let err = create_owned_private_dir(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // The target was neither chmodded nor adopted.
        let mode = std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777;
        assert_ne!(mode, 0);
    }

    #[test]
    fn a_regular_file_at_the_path_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socks");
        std::fs::write(&path, b"x").unwrap();
        let err = create_owned_private_dir(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_missing_parent_is_an_error_not_created() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("no/such/parent");
        assert!(create_owned_private_dir(&dir).is_err());
        assert!(!root.path().join("no").exists());
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[cfg(not(unix))]
    #[test]
    fn ensure_private_dir_refuses_without_creating_directories() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("missing/leaf");
        let err = ensure_private_dir(&target).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(!root.path().join("missing").exists());
    }

    #[cfg(not(unix))]
    #[test]
    fn other_owner_only_operations_refuse_without_creating_a_file() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("secret");
        let metadata = std::fs::metadata(root.path()).unwrap();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        for error in [
            require_current_owner(&metadata).unwrap_err(),
            options
                .open_with_mode(PRIVATE_FILE_MODE, &target)
                .unwrap_err(),
            set_mode(&target, PRIVATE_FILE_MODE).unwrap_err(),
            permissions(&target, PRIVATE_FILE_MODE).unwrap_err(),
            mode_bits(root.path(), &metadata).unwrap_err(),
            create_owned_private_dir(&target).unwrap_err(),
            sync_managed_directory_chain(root.path(), &target).unwrap_err(),
        ] {
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
        assert!(!target.exists());
    }

    #[test]
    fn the_refusal_is_unsupported_and_names_the_path() {
        let err = unsupported_platform_error(Path::new("/srv/state/keys"));
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let message = err.to_string();
        assert!(message.starts_with("/srv/state/keys: "), "{message}");
        assert!(message.contains("Linux and macOS"), "{message}");
    }
}
