//! Durable bundle users and fail-closed extraction eviction.

use super::{BundleRegistry, stream};
use anyhow::Context;
use std::path::PathBuf;

impl BundleRegistry {
    /// Remove an installed bundle. Best-effort symmetric to
    /// [`install`](Self::install): unlinks both the
    /// cached archive (compressed or legacy plain) AND the extracted
    /// `<sha>/` directory. Idempotent on already-absent entries
    /// (returns `Ok(false)`); returns `Ok(true)` when at least
    /// one of the two artifacts was found and removed.
    ///
    /// Reports IO failures verbatim. Partial cleanup is possible
    /// (archive removed but directory removal raced an open file);
    /// the caller's audit log should reflect the *attempt*, not
    /// the success — the next install of the same sha will refuse
    /// (or overwrite with `force`) cleanly either way.
    pub fn remove(&self, bundle_sha256: &str) -> anyhow::Result<bool> {
        match std::fs::symlink_metadata(&self.root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        let _lease = self.lock_entry(bundle_sha256).map_err(anyhow::Error::msg)?;
        if self.has_bundle_users(bundle_sha256)? {
            anyhow::bail!("bundle {bundle_sha256} is retained by an unresolved VM");
        }
        let mut removed_any = false;

        for archive in [
            self.root.join(format!("{bundle_sha256}.mvmpkg.gz")),
            self.root.join(format!("{bundle_sha256}.mvmpkg")),
        ] {
            match std::fs::remove_file(&archive) {
                Ok(()) => removed_any = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "removing archive {}: {e}",
                        archive.display()
                    ));
                }
            }
        }

        let dir = self.install_dir(bundle_sha256);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => removed_any = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "removing install dir {}: {e}",
                    dir.display()
                ));
            }
        }
        let stale = self.root.join(format!(".{bundle_sha256}.evicting"));
        match std::fs::symlink_metadata(&stale) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(&stale)?;
            }
            Ok(_) => anyhow::bail!("bundle eviction staging is not a directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        for sidecar in [
            self.root.join(format!(".{bundle_sha256}.evictable")),
            self.root.join(format!(".{bundle_sha256}.uses")),
        ] {
            match std::fs::symlink_metadata(&sidecar) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    std::fs::remove_dir(&sidecar)?;
                }
                Ok(_) => std::fs::remove_file(&sidecar)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }

        Ok(removed_any)
    }

    fn bundle_users_dir(&self, sha: &str) -> PathBuf {
        self.root.join(format!(".{sha}.uses"))
    }

    pub(super) fn has_bundle_users(&self, sha: &str) -> anyhow::Result<bool> {
        let dir = self.bundle_users_dir(sha);
        match std::fs::symlink_metadata(&dir) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => anyhow::bail!("bundle use index is not a directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let marker = self.root.join(format!(".{sha}.evictable"));
                return match std::fs::symlink_metadata(&marker) {
                    Ok(_) => anyhow::bail!("bundle use index is missing; retain the extraction"),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(error) => Err(error.into()),
                };
            }
            Err(error) => return Err(error.into()),
        }
        Ok(std::fs::read_dir(&dir)?.next().transpose()?.is_some())
    }

    /// Reserve extracted files for a VM before any backend can start it.
    /// A crashed or uncertain owner retains this record until a confirmed stop.
    pub fn retain_for_vm(&self, sha: &str, vm: &str) -> anyhow::Result<()> {
        crate::naming::validate_vm_name(vm)?;
        let _lease = self.lock_entry(sha).map_err(anyhow::Error::msg)?;
        let dir = self.bundle_users_dir(sha);
        self.has_bundle_users(sha)?;
        crate::config::create_private_dir(&dir)?;
        crate::atomic_io::atomic_write_new(&dir.join(vm), b"retained\n")?;
        crate::private_fs::sync_managed_directory_chain(&self.root, &dir)?;
        Ok(())
    }

    /// Release a VM's retained tree only after its backend confirmed exit.
    /// Other users, a damaged archive, or an older install retain the tree.
    pub fn release_after_stop(&self, sha: &str, vm: &str) -> anyhow::Result<bool> {
        crate::naming::validate_vm_name(vm)?;
        let _lease = self.lock_entry(sha).map_err(anyhow::Error::msg)?;
        let dir = self.bundle_users_dir(sha);
        self.has_bundle_users(sha)
            .context("checking unresolved bundle users before release")?;
        match std::fs::remove_file(dir.join(vm)) {
            Ok(()) => crate::private_fs::sync_managed_directory_chain(&self.root, &dir)
                .context("syncing released bundle user")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!("bundle use for {vm} is missing; retain the extraction")
            }
            Err(error) => return Err(error.into()),
        }
        self.evict_extracted_locked(sha)
            .context("evicting extraction after final bundle user release")
    }

    /// Keep only the exact signed archive for a fresh install with no VM users.
    /// Older installations have no eviction marker and remain untouched.
    pub fn evict_extracted_if_unused(&self, sha: &str) -> anyhow::Result<bool> {
        let _lease = self.lock_entry(sha).map_err(anyhow::Error::msg)?;
        self.evict_extracted_locked(sha)
    }

    fn evict_extracted_locked(&self, sha: &str) -> anyhow::Result<bool> {
        let marker = self.root.join(format!(".{sha}.evictable"));
        match std::fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => anyhow::bail!("bundle eviction marker is not a regular file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        if self
            .has_bundle_users(sha)
            .context("checking remaining bundle users before eviction")?
        {
            return Ok(false);
        }
        let actual = stream::archive_sha256(&self.archive_path(sha))
            .with_context(|| format!("verifying retained archive for {sha}"))?;
        anyhow::ensure!(
            actual == sha,
            "retained archive differs from installed bundle {sha}"
        );

        let extracted = self.install_dir(sha);
        let stale = self.root.join(format!(".{sha}.evicting"));
        match std::fs::symlink_metadata(&stale) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(&stale).context("removing old bundle eviction staging")?;
            }
            Ok(_) => anyhow::bail!("bundle eviction staging is not a directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::symlink_metadata(&extracted) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => anyhow::bail!("bundle extraction is not a directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        std::fs::rename(&extracted, &stale).context("staging bundle extraction for eviction")?;
        crate::private_fs::sync_managed_directory_chain(&self.root, &self.root)
            .context("syncing staged bundle eviction")?;
        std::fs::remove_dir_all(&stale).context("removing staged bundle extraction")?;
        crate::private_fs::sync_managed_directory_chain(&self.root, &self.root)
            .context("syncing completed bundle eviction")?;
        Ok(true)
    }

    pub(super) fn mark_fresh_install_evictable(&self, sha: &str) -> anyhow::Result<()> {
        let uses = self.bundle_users_dir(sha);
        crate::config::create_private_dir(&uses)?;
        crate::private_fs::sync_managed_directory_chain(&self.root, &uses)?;
        crate::atomic_io::atomic_write_new(
            &self.root.join(format!(".{sha}.evictable")),
            b"bundle-eviction-v1\n",
        )?;
        crate::private_fs::sync_managed_directory_chain(&self.root, &self.root)?;
        Ok(())
    }
}
