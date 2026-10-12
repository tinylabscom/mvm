//! A canonical namespace whose ancestors cannot be renamed by another uid.

use anyhow::{Context, Result, bail};
use std::fs::{File, Metadata};
use std::path::{Component, Path, PathBuf};

pub(super) fn root(create: bool) -> Result<PathBuf> {
    root_at(Path::new(&mvm_core::config::mvm_home()), create)
}

fn root_at(home: &Path, create: bool) -> Result<PathBuf> {
    let canonical = protected_home(home, create)?;
    let root = canonical.join("runtime-evidence");
    if create {
        private_directory(&root)?;
    } else {
        validate_private_directory(&root)?;
    }
    Ok(root)
}

fn protected_home(home: &Path, create: bool) -> Result<PathBuf> {
    if !home.is_absolute()
        || home
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        bail!("runtime home must be an absolute path without parent traversal");
    }
    let mut existing = home;
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    existing
                        .file_name()
                        .context("runtime home has no filename")?,
                );
                existing = existing
                    .parent()
                    .context("runtime home has no existing ancestor")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    // System aliases such as /tmp are resolved once. No returned path, backend
    // input or later artifact reopen uses the original alias again.
    let mut canonical = existing.canonicalize()?;
    validate_ancestors(&canonical)?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
        private_directory(&canonical)?;
    }
    if create {
        private_directory(&canonical)?;
    } else {
        check_owner(&std::fs::symlink_metadata(&canonical)?)?;
    }
    Ok(canonical)
}

/// Resolve the cache from the protected home, never a replaceable alias.
/// The build-layer source verifier checks the selected pointer/object/tree.
pub(super) fn source_cache_root() -> Result<PathBuf> {
    source_cache_at(Path::new(&mvm_core::config::mvm_home()))
}

pub(super) fn source_cache_at(home: &Path) -> Result<PathBuf> {
    let cache = protected_home(home, false)?.join("cache");
    validate_cache_directory(&cache)?;
    Ok(cache)
}

fn validate_cache_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || mvm_core::private_fs::mode_bits(path, &metadata)? & 0o022 != 0
    {
        bail!(
            "source runtime cache contains an unsafe path: {}",
            path.display()
        );
    }
    check_owner(&metadata)
}

fn validate_ancestors(path: &Path) -> Result<()> {
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.file_type().is_dir() {
            bail!("runtime namespace ancestor is not a real directory");
        }
        validate_ancestor_permissions(&metadata)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_ancestor_permissions(metadata: &Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != uid {
        bail!("runtime namespace ancestor is owned by another uid");
    }
    // In a root/owner-controlled sticky directory, another uid cannot rename
    // the next root/owner-owned entry. Every next component is checked too.
    if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
        bail!("runtime namespace ancestor is writable by another uid");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_ancestor_permissions(_metadata: &Metadata) -> Result<()> {
    bail!("runtime namespaces require Unix ownership and permission semantics")
}

pub(super) fn check_owner(metadata: &Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or memory preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("runtime evidence has a different owner");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        bail!("runtime namespaces require Unix ownership and permission semantics")
    }
}

pub(super) fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || mvm_core::private_fs::mode_bits(path, &metadata)? != 0o700
    {
        bail!("runtime directory is not a private non-symlink directory");
    }
    check_owner(&metadata)
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                bail!("runtime directory is not a real directory");
            }
            check_owner(&metadata)?;
            if mvm_core::private_fs::mode_bits(path, &metadata)? & 0o022 != 0 {
                bail!("runtime directory is writable by another uid");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    validate_private_directory(path)?;
                }
                Err(error) => return Err(error.into()),
            }
            if let Some(parent) = path.parent() {
                mvm_core::util::atomic_io::sync_dir(parent)?;
            }
        }
        Err(error) => return Err(error.into()),
    }
    mvm_core::private_fs::set_mode(path, 0o700)?;
    validate_private_directory(path)
}

pub(super) fn lock(directory: &Path) -> Result<File> {
    let path = directory.join("lifecycle.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || mvm_core::private_fs::mode_bits(&path, &metadata)? != 0o600 {
        bail!("runtime lifecycle lock must be a private regular file");
    }
    check_owner(&metadata)?;
    file.lock()?;
    Ok(file)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn writable_ancestor_is_rejected_before_creating_runtime_storage() {
        let temp = private_tempdir();
        let attacker_parent = temp.path().join("shared");
        std::fs::create_dir(&attacker_parent).unwrap();
        std::fs::set_permissions(&attacker_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let home = attacker_parent.join("victim-home");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(root_at(&home, true).is_err());
        assert!(!home.join("runtime-evidence").exists());
    }

    #[test]
    fn aliases_are_canonicalized_but_runtime_descendant_symlinks_are_refused() {
        let temp = private_tempdir();
        let home = temp.path().join("home");
        private_directory(&home).unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&home, &alias).unwrap();
        let root = root_at(&alias, true).unwrap();
        assert_eq!(root, home.canonicalize().unwrap().join("runtime-evidence"));
        let bad_home = temp.path().join("bad-home");
        private_directory(&bad_home).unwrap();
        std::os::unix::fs::symlink(&root, bad_home.join("runtime-evidence")).unwrap();
        assert!(root_at(&bad_home, true).is_err());
    }

    #[test]
    fn source_cache_paths_do_not_reuse_aliases() {
        let temp = private_tempdir();
        let home = temp.path().join("home");
        private_directory(&home).unwrap();
        private_directory(&home.join("cache")).unwrap();
        let objects = home.join("cache/guest-runtime/v1/objects");
        std::fs::create_dir_all(&objects).unwrap();
        let archive = objects.join("archive");
        std::fs::write(&archive, b"trusted-cache").unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&home, &alias).unwrap();
        let canonical_cache = source_cache_at(&alias).unwrap();
        assert_eq!(canonical_cache, home.canonicalize().unwrap().join("cache"));
        assert!(
            !home.join("runtime-evidence").exists(),
            "source checking is read-only"
        );

        let other = temp.path().join("other");
        private_directory(&other).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&other, &alias).unwrap();
        assert!(source_cache_at(&alias).is_err());
        assert_eq!(
            std::fs::read(canonical_cache.join("guest-runtime/v1/objects/archive")).unwrap(),
            b"trusted-cache"
        );
    }

    #[test]
    fn lock_rejects_symlinks_and_serializes_owners() {
        let temp = private_tempdir();
        let root = root_at(temp.path(), true).unwrap();
        let first = lock(&root).unwrap();
        let (attempted, attempt) = std::sync::mpsc::channel();
        let (acquired, acquire) = std::sync::mpsc::channel();
        let worker_root = root.clone();
        let worker = std::thread::spawn(move || {
            attempted.send(()).unwrap();
            let second = lock(&worker_root).unwrap();
            acquired.send(()).unwrap();
            drop(second);
        });
        attempt.recv().unwrap();
        assert!(
            acquire
                .recv_timeout(std::time::Duration::from_millis(20))
                .is_err()
        );
        drop(first);
        acquire
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        worker.join().unwrap();
        std::fs::rename(root.join("lifecycle.lock"), root.join("target")).unwrap();
        std::os::unix::fs::symlink(root.join("target"), root.join("lifecycle.lock")).unwrap();
        assert!(lock(&root).is_err());
        std::fs::remove_file(root.join("lifecycle.lock")).unwrap();
        std::fs::write(root.join("lifecycle.lock"), b"").unwrap();
        std::fs::set_permissions(
            root.join("lifecycle.lock"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(lock(&root).is_err());
    }
}
