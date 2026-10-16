//! An archive an invocation owns until it is published.
//!
//! `pack build` exports into a private file beside the destination, checks it,
//! and only then links it into place without replacing anything. Every
//! removal names the private file, never the destination, so a concurrent or
//! substituted file at the destination is never touched.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Error, Result, bail};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) struct StagedArchive {
    staging: PathBuf,
    destination: PathBuf,
}

impl StagedArchive {
    /// Refuse an existing destination up front, then name a private sibling.
    pub(super) fn new(destination: &Path) -> Result<Self> {
        if fs::symlink_metadata(destination).is_ok() {
            bail!(
                "destination already exists: {}; remove it or choose another --out",
                destination.display()
            );
        }
        let name = destination
            .file_name()
            .context("--out must name a file")?
            .to_string_lossy();
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let staging = destination.with_file_name(format!(".{name}.{}.{n}.staging", process::id()));
        Ok(Self {
            staging,
            destination: destination.to_path_buf(),
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.staging
    }

    /// Link the staged file to the destination, failing if anything is there,
    /// then drop the private name.
    pub(super) fn publish(self) -> Result<PathBuf> {
        if let Err(error) = fs::hard_link(&self.staging, &self.destination) {
            let published = if error.kind() == ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "destination appeared during the build: {}; it was left untouched",
                    self.destination.display()
                )
            } else {
                Error::new(error).context(format!("publishing {}", self.destination.display()))
            };
            return Err(self.discard(published));
        }
        fs::remove_file(&self.staging)
            .with_context(|| format!("removing staging file {}", self.staging.display()))?;
        Ok(self.destination)
    }

    /// Remove the private file and return `cause`, extended with any cleanup failure.
    pub(super) fn discard(self, cause: Error) -> Error {
        match fs::remove_file(&self.staging) {
            Ok(()) => cause,
            Err(e) if e.kind() == ErrorKind::NotFound => cause,
            Err(e) => cause.context(format!(
                "also failed to remove staging file {}: {e}",
                self.staging.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(dir: &Path, bytes: &[u8]) -> (StagedArchive, PathBuf) {
        let out = dir.join("app.mvmpkg");
        let s = StagedArchive::new(&out).unwrap();
        fs::write(s.path(), bytes).unwrap();
        (s, out)
    }

    #[test]
    fn publish_moves_the_staged_file_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let (s, out) = staged(dir.path(), b"mine");
        assert_eq!(s.publish().unwrap(), out);
        assert_eq!(fs::read(&out).unwrap(), b"mine");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn same_destination_gets_distinct_staging_files() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("app.mvmpkg");
        let a = StagedArchive::new(&out).unwrap();
        let b = StagedArchive::new(&out).unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn an_existing_destination_is_refused_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("app.mvmpkg");
        fs::write(&out, b"theirs").unwrap();
        let error = StagedArchive::new(&out).err().unwrap();
        assert!(error.to_string().contains("destination already exists"));
        assert_eq!(fs::read(&out).unwrap(), b"theirs");
    }

    #[test]
    fn a_destination_that_appears_later_survives_publish_and_staging_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (s, out) = staged(dir.path(), b"mine");
        fs::write(&out, b"theirs").unwrap();
        let error = s.publish().unwrap_err();
        assert!(error.to_string().contains("appeared during the build"));
        assert_eq!(fs::read(&out).unwrap(), b"theirs");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn discard_removes_only_the_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let (s, out) = staged(dir.path(), b"mine");
        fs::write(&out, b"theirs").unwrap();
        let error = s.discard(anyhow::anyhow!("hash failed"));
        assert_eq!(error.to_string(), "hash failed");
        assert_eq!(fs::read(&out).unwrap(), b"theirs");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_cleanup_failure_is_reported_with_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        let (s, _) = staged(dir.path(), b"mine");
        // A directory in the staging file's place cannot be removed as a file.
        fs::remove_file(s.path()).unwrap();
        fs::create_dir(s.path()).unwrap();
        let error = format!("{:#}", s.discard(anyhow::anyhow!("hash failed")));
        assert!(error.contains("failed to remove staging file"), "{error}");
        assert!(error.contains("hash failed"), "{error}");
    }
}
