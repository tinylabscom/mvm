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
/// Only `dir` itself is locked; parents created on the way keep the umask
/// mode. A directory under the mvm home goes through
/// [`crate::config::create_private_dir`], which walks the whole chain.
pub fn ensure_private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    let dir = dir.as_ref();
    if cfg!(not(unix)) {
        return Err(unsupported_platform_error(dir));
    }
    std::fs::create_dir_all(dir)?;
    if mode_bits(dir, &std::fs::metadata(dir)?)? != PRIVATE_DIR_MODE {
        set_mode(dir, PRIVATE_DIR_MODE)?;
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
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn the_refusal_is_unsupported_and_names_the_path() {
        let err = unsupported_platform_error(Path::new("/srv/state/keys"));
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let message = err.to_string();
        assert!(message.starts_with("/srv/state/keys: "), "{message}");
        assert!(message.contains("Linux and macOS"), "{message}");
    }
}
