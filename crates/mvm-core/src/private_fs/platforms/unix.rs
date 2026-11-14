//! Unix owner-only filesystem operations behind the shared private-filesystem API.

use super::{OpenOptionsModeExt, PRIVATE_DIR_MODE};
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io;
use std::path::Path;

/// Require metadata owned by the current effective user.
///
/// This checks ownership only. Callers must separately validate the opened
/// object, its type, links and permissions; it does not bind a path to a handle.
pub fn require_current_owner(metadata: &Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    require_owner_uid(metadata.uid(), rustix::process::geteuid().as_raw())
}

pub(super) fn require_owner_uid(actual: u32, expected: u32) -> io::Result<()> {
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "object is not owned by the current effective user",
        ));
    }
    Ok(())
}

impl OpenOptionsModeExt for OpenOptions {
    fn open_with_mode(&self, mode: u32, path: impl AsRef<Path>) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = self.clone();
        options.mode(mode).open(path)
    }
}

/// Set `path`'s permission bits to exactly `mode`.
pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Permissions carrying exactly `mode`, for the APIs that take them whole:
/// a temporary created at that mode, or a mode set through an open handle
/// rather than a path. `subject` is the file they are for, named in the
/// refusal on a host without the bits.
pub fn permissions(_subject: &Path, mode: u32) -> io::Result<Permissions> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(Permissions::from_mode(mode))
}

/// The permission bits (`mode & 0o777`) recorded in `meta`, for the checks
/// that refuse to read a secret another user could also read. `path` is the
/// file `meta` describes, named in the refusal on a host without the bits.
pub fn mode_bits(_path: &Path, meta: &Metadata) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    Ok(meta.permissions().mode() & 0o777)
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

/// Create `dir` as a private directory the current user owns, or refuse.
///
/// [`ensure_private_dir`] accepts whatever is already at the path. That is
/// right under the mvm home, where every ancestor is the user's own, and wrong
/// in a shared parent such as `/tmp`: another account that created the name
/// first would own the directory this process then binds sockets in or hands
/// to a privileged helper. This creates a single missing component at
/// [`PRIVATE_DIR_MODE`] and, whether it created it or found it, requires a real
/// directory (not a symlink) owned by the current effective user. One the user
/// owns but left wider than [`PRIVATE_DIR_MODE`] is tightened.
pub fn create_owned_private_dir(dir: impl AsRef<Path>) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    let dir = dir.as_ref();
    match std::fs::DirBuilder::new()
        .mode(PRIVATE_DIR_MODE)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a plain directory", dir.display()),
        ));
    }
    require_current_owner(&meta)
        .map_err(|e| io::Error::new(e.kind(), format!("refusing {}: {e}", dir.display())))?;
    if mode_bits(dir, &meta)? != PRIVATE_DIR_MODE {
        set_mode(dir, PRIVATE_DIR_MODE)?;
    }
    Ok(())
}

/// Sync a known managed directory and its finite namespace ancestry.
///
/// The configured root is trusted; descendants must be at most eight normal
/// components and are opened descriptor-relatively without following symlinks.
/// No directory is listed. Ancestors of the configured root are also synced so
/// first-use creation of that root's parents cannot leave an unsynced link.
/// This relies on the filesystem honoring directory fsync; it does not certify
/// hardware power-loss behavior.
pub fn sync_managed_directory_chain(root: &Path, directory: &Path) -> io::Result<()> {
    sync_managed_directory_chain_with(root, directory, |_, file| file.sync_all())
}

pub(super) fn sync_managed_directory_chain_with(
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
