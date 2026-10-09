//! Capture-scoped, descriptor-relative access. This is not recursive deletion.
//!
//! The configured root is a trusted boundary. Each descendant is opened without
//! following links. All managed producers and retirement operations must hold
//! the same exclusive directory lock for their lifetime. A hostile process with
//! the host user's privileges is outside this boundary.
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path};

use super::{TranscriptManifest, segment};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};

/// Exclusive ownership of a private capture directory. Keep this alive until
/// the writer has joined or the retirement pass has finished.
pub struct CaptureDirectory {
    dir: File,
}

#[cfg(unix)]
impl CaptureDirectory {
    /// Pin an already trusted configured root, then walk a bounded relative
    /// capture path without following any descendant symlink.
    pub fn open(root: &Path, relative: &Path) -> io::Result<Self> {
        let mut dir = File::from(rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        private_directory(&dir)?;
        let components: Vec<_> = relative.components().collect();
        if components.is_empty() || components.len() > 8 {
            return Err(invalid("capture path must have one to eight components"));
        }
        for component in components {
            let Component::Normal(name) = component else {
                return Err(invalid("capture path must be relative and contained"));
            };
            dir = open_at(&dir, name, OFlags::DIRECTORY)?;
            private_directory(&dir)?;
        }
        Self::lock(dir)
    }

    /// Producer entry point: the caller already owns the capture's parent.
    pub fn for_writer(path: &Path) -> io::Result<Self> {
        let dir = File::from(rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        Self::lock(dir)
    }

    fn lock(dir: File) -> io::Result<Self> {
        private_directory(&dir)?;
        rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self { dir })
    }

    pub fn read_manifest(&self) -> io::Result<TranscriptManifest> {
        let mut file = open_at(
            &self.dir,
            super::MANIFEST_FILENAME.as_ref(),
            OFlags::empty(),
        )?;
        regular_single_link(&file.metadata()?)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(invalid("manifest exceeds bounded retirement size"));
        }
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }

    /// Preflight only filenames authenticated by the caller's manifest. Missing
    /// payload is allowed ONLY for resumption backed by signed expiry evidence.
    pub fn prepare_payload(
        &self,
        manifest: &TranscriptManifest,
        already_retired: bool,
    ) -> io::Result<PreparedPayload> {
        if manifest.chunks.len() > 1_000_000 {
            return Err(invalid("retirement chunk bound exceeded"));
        }
        let spans = segment::segment_spans(&manifest.chunks).map_err(io::Error::other)?;
        if spans.len() > 4096 {
            return Err(invalid("retirement segment bound exceeded"));
        }
        let mut files = Vec::new();
        for span in spans {
            let Some(index) = span.file.strip_suffix(".seg") else {
                return Err(invalid("retirement only accepts ciphertext segment names"));
            };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid(
                    "retirement only accepts numbered ciphertext segments",
                ));
            }
            let mut file = match open_at(&self.dir, span.file.as_ref(), OFlags::empty()) {
                Ok(file) => file,
                Err(error) if already_retired && error.kind() == io::ErrorKind::NotFound => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            regular_single_link(&metadata)?;
            if metadata.len() != span.bytes || span.bytes > 64 * 1024 * 1024 {
                return Err(invalid(
                    "ciphertext segment length mismatch or bound exceeded",
                ));
            }
            for chunk in span.chunks {
                if segment::hash_range(&mut file, chunk).map_err(io::Error::other)?
                    != chunk.sha256_hex
                {
                    return Err(invalid("ciphertext segment digest mismatch"));
                }
            }
            files.push((span.file.to_owned(), metadata));
        }
        Ok(PreparedPayload { files })
    }

    /// Call only after the exact retirement evidence is durably signed.
    /// Revalidate names against the preflight inodes under the exclusive lease.
    pub fn unlink_payload(&self, payload: PreparedPayload) -> io::Result<usize> {
        use std::os::unix::fs::MetadataExt;
        let mut removed = 0;
        for (name, expected) in payload.files {
            let actual = open_at(&self.dir, name.as_ref(), OFlags::empty())?.metadata()?;
            regular_single_link(&actual)?;
            if actual.dev() != expected.dev()
                || actual.ino() != expected.ino()
                || actual.len() != expected.len()
            {
                return Err(invalid("ciphertext segment replaced after preflight"));
            }
            rustix::fs::unlinkat(&self.dir, name.as_str(), AtFlags::empty())?;
            self.dir.sync_all()?;
            removed += 1;
        }
        Ok(removed)
    }
}

/// Bound inode identities obtained from a complete successful preflight.
pub struct PreparedPayload {
    files: Vec<(String, Metadata)>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn private_directory(dir: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = dir.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(invalid("capture directory must be private and host-owned"));
    }
    Ok(())
}

#[cfg(unix)]
fn regular_single_link(metadata: &Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(invalid("capture member must be a single-link regular file"));
    }
    Ok(())
}

#[cfg(unix)]
fn open_at(dir: &File, name: &std::ffi::OsStr, flags: OFlags) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK | flags,
        Mode::empty(),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::{
        AtRestRetention, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME,
        RetentionPolicy, TranscriptWriter, TranscriptWriterConfig,
    };

    fn fixture() -> (tempfile::TempDir, TranscriptManifest) {
        let dir = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(dir.path()).unwrap();
        let mut writer = TranscriptWriter::try_new(
            dir.path(),
            crate::crypto::aead::Key::random(),
            TranscriptWriterConfig {
                capture_id: "synthetic".into(),
                binding: CaptureBinding {
                    tenant_id: "local".into(),
                    vm_name: "synthetic".into(),
                    session_id: None,
                },
                bounds: CaptureBounds {
                    max_duration_secs: 3600,
                    max_bytes: 4096,
                    max_chunks: 10,
                },
                retention: RetentionPolicy::FailClosed,
                at_rest: Some(AtRestRetention::default()),
                generation_budget: None,
                payload_encoding: Default::default(),
                created_unix_secs: 100,
                recipient: "transcript-kek".into(),
                wrapped_data_key_b64: "synthetic-envelope".into(),
            },
        )
        .unwrap();
        writer.push(Direction::Stdout, b"synthetic marker").unwrap();
        let manifest = writer.finalize_at(200).unwrap();
        std::fs::write(
            dir.path().join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        (dir, manifest)
    }

    #[test]
    fn cleanup_preserves_metadata_and_foreign_files() {
        let (dir, manifest) = fixture();
        std::fs::write(dir.path().join("foreign"), b"synthetic foreign").unwrap();
        let capture = CaptureDirectory::for_writer(dir.path()).unwrap();
        let payload = capture.prepare_payload(&manifest, false).unwrap();
        assert_eq!(capture.unlink_payload(payload).unwrap(), 1);
        assert_eq!(capture.read_manifest().unwrap(), manifest);
        assert_eq!(
            std::fs::read(dir.path().join("foreign")).unwrap(),
            b"synthetic foreign"
        );
        assert!(capture.prepare_payload(&manifest, false).is_err());
        assert_eq!(
            capture
                .unlink_payload(capture.prepare_payload(&manifest, true).unwrap())
                .unwrap(),
            0
        );
    }

    #[test]
    fn links_and_replacement_races_refuse_without_unlink() {
        use std::os::unix::fs::symlink;
        for kind in 0..3 {
            let (dir, manifest) = fixture();
            let capture = CaptureDirectory::for_writer(dir.path()).unwrap();
            let payload = capture.prepare_payload(&manifest, false).unwrap();
            let path = dir.path().join(&manifest.chunks[0].file);
            let foreign = dir.path().join("foreign");
            std::fs::rename(&path, &foreign).unwrap();
            match kind {
                0 => symlink(&foreign, &path).unwrap(),
                1 => std::fs::hard_link(&foreign, &path).unwrap(),
                _ => {
                    std::fs::copy(&foreign, &path).unwrap();
                }
            }
            assert!(capture.unlink_payload(payload).is_err());
            assert!(path.symlink_metadata().is_ok());
            assert!(foreign.exists());
            if kind != 2 {
                assert!(capture.prepare_payload(&manifest, false).is_err());
            }
        }
    }

    #[test]
    fn ancestor_links_and_active_leases_refuse() {
        use std::os::unix::fs::symlink;
        let (dir, _) = fixture();
        let parent = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(parent.path()).unwrap();
        symlink(dir.path(), parent.path().join("alias")).unwrap();
        assert!(CaptureDirectory::open(parent.path(), Path::new("alias")).is_err());
        assert!(CaptureDirectory::open(parent.path(), Path::new("../outside")).is_err());
        let lease = CaptureDirectory::for_writer(dir.path()).unwrap();
        assert!(CaptureDirectory::for_writer(dir.path()).is_err());
        drop(lease);
        assert!(CaptureDirectory::for_writer(dir.path()).is_ok());
    }

    #[test]
    fn untrusted_directory_permissions_refuse_before_access() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o755, 0o770, 0o777] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(CaptureDirectory::for_writer(dir.path()).is_err());
        }
        crate::private_fs::ensure_private_dir(dir.path()).unwrap();
        assert!(CaptureDirectory::for_writer(dir.path()).is_ok());
    }
}
