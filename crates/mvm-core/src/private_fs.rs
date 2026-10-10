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
//! succeed — exactly the failure the owner-only rule exists to rule out. mvm
//! does not support Windows hosts; applying an owner-only DACL is the work that
//! would replace these refusals with an implementation.

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io;
use std::path::Path;

/// Mode of a directory holding private state.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Mode of a file holding a secret.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

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

impl OpenOptionsModeExt for OpenOptions {
    #[cfg(unix)]
    fn open_with_mode(&self, mode: u32, path: impl AsRef<Path>) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = self.clone();
        options.mode(mode).open(path)
    }

    #[cfg(not(unix))]
    fn open_with_mode(&self, _mode: u32, path: impl AsRef<Path>) -> io::Result<File> {
        Err(unsupported_platform_error(path.as_ref()))
    }
}

/// Set `path`'s permission bits to exactly `mode`.
#[cfg(unix)]
pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Set `path`'s permission bits to exactly `mode`.
#[cfg(not(unix))]
pub fn set_mode(path: impl AsRef<Path>, _mode: u32) -> io::Result<()> {
    Err(unsupported_platform_error(path.as_ref()))
}

/// Permissions carrying exactly `mode`, for the APIs that take them whole:
/// a temporary created at that mode, or a mode set through an open handle
/// rather than a path. `subject` is the file they are for, named in the
/// refusal on a host without the bits.
#[cfg(unix)]
pub fn permissions(_subject: &Path, mode: u32) -> io::Result<Permissions> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(Permissions::from_mode(mode))
}

/// Permissions carrying exactly `mode`, for the APIs that take them whole:
/// a temporary created at that mode, or a mode set through an open handle
/// rather than a path. `subject` is the file they are for, named in the
/// refusal on a host without the bits.
#[cfg(not(unix))]
pub fn permissions(subject: &Path, _mode: u32) -> io::Result<Permissions> {
    Err(unsupported_platform_error(subject))
}

/// The permission bits (`mode & 0o777`) recorded in `meta`, for the checks
/// that refuse to read a secret another user could also read. `path` is the
/// file `meta` describes, named in the refusal on a host without the bits.
#[cfg(unix)]
pub fn mode_bits(_path: &Path, meta: &Metadata) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(meta.permissions().mode() & 0o777)
}

/// The permission bits (`mode & 0o777`) recorded in `meta`, for the checks
/// that refuse to read a secret another user could also read. `path` is the
/// file `meta` describes, named in the refusal on a host without the bits.
#[cfg(not(unix))]
pub fn mode_bits(path: &Path, _meta: &Metadata) -> io::Result<u32> {
    Err(unsupported_platform_error(path))
}

/// Create `dir` (and any missing parents) and leave it at
/// [`PRIVATE_DIR_MODE`], chmodding only when it is not already there.
///
/// Newly created directories, including missing parents, request
/// [`PRIVATE_DIR_MODE`] at creation (the umask may remove bits). Existing
/// ancestors are not chmodded. A directory under the mvm home goes through
/// [`crate::config::create_private_dir`], which tightens the whole owned chain.
///
/// Path traversal follows symlinks; this is not a symlink-safe containment API.
#[cfg(unix)]
pub fn ensure_private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    let dir = dir.as_ref();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIR_MODE)
        .create(dir)?;
    if mode_bits(dir, &std::fs::metadata(dir)?)? != PRIVATE_DIR_MODE {
        set_mode(dir, PRIVATE_DIR_MODE)?;
    }
    Ok(())
}

/// Refuse directory creation on hosts without Unix permission bits.
#[cfg(not(unix))]
pub fn ensure_private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    Err(unsupported_platform_error(dir.as_ref()))
}

/// Sync a known managed directory and its finite namespace ancestry.
///
/// The configured root is trusted; descendants must be at most eight normal
/// components and are opened descriptor-relatively without following symlinks.
/// No directory is listed. Ancestors of the configured root are also synced so
/// first-use creation of that root's parents cannot leave an unsynced link.
/// This relies on the filesystem honoring directory fsync; it does not certify
/// hardware power-loss behavior.
#[cfg(unix)]
pub fn sync_managed_directory_chain(root: &Path, directory: &Path) -> io::Result<()> {
    sync_managed_directory_chain_with(root, directory, |_, file| file.sync_all())
}

#[cfg(not(unix))]
pub fn sync_managed_directory_chain(root: &Path, _directory: &Path) -> io::Result<()> {
    Err(unsupported_platform_error(root))
}

#[cfg(unix)]
fn sync_managed_directory_chain_with(
    root: &Path,
    directory: &Path,
    mut sync: impl FnMut(&Path, &File) -> io::Result<()>,
) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::path::Component;
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| io::Error::other("directory is outside managed root"))?;
    let components: Vec<_> = relative.components().collect();
    if components.len() > 8
        || components
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::other(
            "invalid managed directory depth or component",
        ));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root_file = File::from(rustix::fs::open(root, flags, Mode::empty())?);
    let canonical_root = root.canonicalize()?;
    if canonical_root.ancestors().count() > 128 {
        return Err(io::Error::other("managed root ancestry exceeds bound"));
    }
    let mut chain = vec![(canonical_root.clone(), root_file)];
    for component in components {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("invalid managed directory component"));
        };
        let (path, parent) = chain
            .last()
            .ok_or_else(|| io::Error::other("managed root missing"))?;
        let child = File::from(rustix::fs::openat(parent, name, flags, Mode::empty())?);
        chain.push((path.join(name), child));
    }
    for (path, directory) in chain.iter().rev() {
        sync(path, directory)?;
    }
    for parent in canonical_root.ancestors().skip(1) {
        let file = File::from(rustix::fs::open(parent, flags, Mode::empty())?);
        sync(parent, &file)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
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

    #[test]
    fn the_refusal_is_unsupported_and_names_the_path() {
        let err = unsupported_platform_error(Path::new("/srv/state/keys"));
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let message = err.to_string();
        assert!(message.starts_with("/srv/state/keys: "), "{message}");
        assert!(message.contains("Linux and macOS"), "{message}");
    }
}
