//! Capture-scoped, descriptor-relative access. This is not recursive deletion.
//!
//! The configured root is a trusted boundary. Each descendant is opened without
//! following links. Readers and producers share the directory lock; a reserved
//! private member excludes competing producers. Retirement is exclusive.
//! A hostile process with
//! the host user's privileges is outside this boundary.
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path};

use super::{TranscriptManifest, WRITER_LOCK_FILENAME, segment};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};

/// Exclusive ownership of a private capture directory. Keep this alive until
/// the writer has joined or the retirement pass has finished.
pub struct CaptureDirectory {
    dir: File,
}

#[cfg(unix)]
impl Drop for CaptureDirectory {
    fn drop(&mut self) {
        // A concurrent fork can inherit the file description before CLOEXEC
        // closes it. The directory lease ends with this guard, not that child.
        if let Err(error) = rustix::fs::flock(&self.dir, FlockOperation::Unlock) {
            tracing::warn!(%error, "failed to release capture directory lease");
        }
    }
}

/// Read-only access pinned against retirement, without creating storage.
pub struct CaptureReadDirectory {
    dir: File,
    permissions: ReadPermissions,
}

#[derive(Clone, Copy)]
enum ReadPermissions {
    Protected,
    Legacy,
}

/// Shared directory ownership plus an exclusive producer reservation.
pub(super) struct CaptureProducerDirectory {
    writer: File,
    _reader: CaptureReadDirectory,
}

impl Drop for CaptureReadDirectory {
    fn drop(&mut self) {
        if let Err(error) = rustix::fs::flock(&self.dir, FlockOperation::Unlock) {
            tracing::warn!(%error, "failed to release capture read lease");
        }
    }
}

impl Drop for CaptureProducerDirectory {
    fn drop(&mut self) {
        if let Err(error) = rustix::fs::flock(&self.writer, FlockOperation::Unlock) {
            tracing::warn!(%error, "failed to release capture producer reservation");
        }
        // The reader field subsequently unlocks the shared directory lease.
        // Descriptor close alone would not release surviving duplicated FDs.
    }
}

#[cfg(unix)]
impl CaptureDirectory {
    /// Internal entry point for a directory already opened beneath a pinned home.
    pub(super) fn from_owned_directory(dir: File) -> io::Result<Self> {
        Self::lock(dir)
    }

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

    /// Read one bounded private metadata member through the held directory,
    /// without following links or allocating from an untrusted file length.
    pub fn read_private_member(&self, name: &str, maximum: usize) -> io::Result<Vec<u8>> {
        use std::os::unix::fs::MetadataExt as _;
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(invalid("private metadata name must be one component"));
        }
        let mut file = open_at(&self.dir, name.as_ref(), OFlags::empty())?;
        let metadata = file.metadata()?;
        regular_single_link(&metadata)?;
        if metadata.mode() & 0o777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.len() > maximum as u64
        {
            return Err(invalid("private metadata exceeds its bound or permissions"));
        }
        let limit = maximum
            .checked_add(1)
            .ok_or_else(|| invalid("private metadata bound overflow"))?;
        let mut bytes = Vec::new();
        (&mut file).take(limit as u64).read_to_end(&mut bytes)?;
        if bytes.len() > maximum || bytes.len() as u64 != metadata.len() {
            return Err(invalid(
                "private metadata changed length or exceeds its bound",
            ));
        }
        Ok(bytes)
    }

    pub fn read_manifest(&self) -> io::Result<TranscriptManifest> {
        read_manifest(&self.dir)
    }

    /// Preflight only filenames authenticated by the caller's manifest. Missing
    /// payload is allowed ONLY for resumption backed by signed expiry evidence.
    pub fn prepare_payload(
        &self,
        manifest: &TranscriptManifest,
        already_retired: bool,
    ) -> io::Result<PreparedPayload> {
        validate_writer_member(&self.dir)?;
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
            if metadata.len() != span.bytes || span.bytes > super::MAX_EXPORT_SEGMENT_BYTES {
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
        validate_writer_member(&self.dir)?;
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
            #[cfg(test)]
            faults::hit(faults::Boundary::Unlink)?;
            rustix::fs::unlinkat(&self.dir, name.as_str(), AtFlags::empty())?;
            #[cfg(test)]
            faults::hit(faults::Boundary::DirectorySync)?;
            self.dir.sync_all()?;
            removed += 1;
        }
        // A previous attempt may have unlinked the last segment but failed its
        // directory sync. An empty retry must finish that durability boundary.
        if removed == 0 {
            #[cfg(test)]
            faults::hit(faults::Boundary::DirectorySync)?;
            self.dir.sync_all()?;
        }
        Ok(removed)
    }
}

impl CaptureReadDirectory {
    /// Internal entry point retaining the existing protected-reader validation.
    pub(super) fn from_owned_directory(dir: File) -> io::Result<Self> {
        private_directory(&dir)?;
        Self::lock(dir, ReadPermissions::Protected)
    }

    pub fn open(root: &Path, relative: &Path) -> io::Result<Self> {
        let mut dir = open_existing_directory(root)?;
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
        Self::lock(dir, ReadPermissions::Protected)
    }

    pub(super) fn existing(path: &Path) -> io::Result<Self> {
        Self::lock(open_existing_directory(path)?, ReadPermissions::Protected)
    }

    pub(super) fn legacy_existing(path: &Path) -> io::Result<Self> {
        let dir = open_directory(path)?;
        host_owned_not_publicly_writable(&dir.metadata()?)?;
        Self::lock(dir, ReadPermissions::Legacy)
    }

    fn lock(dir: File, permissions: ReadPermissions) -> io::Result<Self> {
        rustix::fs::flock(&dir, FlockOperation::NonBlockingLockShared)?;
        // Own the lease before any subsequent fallible validation.
        Self { dir, permissions }.validate()
    }

    fn validate(self) -> io::Result<Self> {
        validate_writer_member(&self.dir)?;
        Ok(self)
    }

    pub fn read_manifest(&self) -> io::Result<TranscriptManifest> {
        read_manifest(&self.dir)
    }

    pub(super) fn validate_manifest(&self, manifest: &TranscriptManifest) -> io::Result<()> {
        if matches!(self.permissions, ReadPermissions::Legacy) && manifest.at_rest.is_some() {
            return Err(invalid(
                "protected capture requires private reader permissions",
            ));
        }
        Ok(())
    }

    pub(super) fn open_segment(&self, name: &str, expected: u64) -> io::Result<File> {
        segment::check_safe_name(name).map_err(io::Error::other)?;
        if expected > super::MAX_EXPORT_SEGMENT_BYTES {
            return Err(invalid("ciphertext segment bound exceeded"));
        }
        let file = open_at(&self.dir, name.as_ref(), OFlags::empty())?;
        let metadata = file.metadata()?;
        regular_single_link(&metadata)?;
        host_owned_not_publicly_writable(&metadata)?;
        if matches!(self.permissions, ReadPermissions::Protected) {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o7777 != 0o600 {
                return Err(invalid("protected ciphertext must be private mode 0600"));
            }
        }
        if metadata.len() != expected {
            return Err(invalid("ciphertext segment length mismatch"));
        }
        Ok(file)
    }

    pub(super) fn read_record(
        &self,
        manifest: &TranscriptManifest,
        chunk: &super::ChunkRecord,
        segment_bytes: u64,
    ) -> Result<Vec<u8>, super::TranscriptError> {
        let io = |error: io::Error| super::TranscriptError::Io {
            file: chunk.file.clone(),
            msg: error.to_string(),
        };
        self.validate_manifest(manifest).map_err(io)?;
        super::check_export_readable(manifest)?;
        let mut file = self.open_segment(&chunk.file, segment_bytes).map_err(io)?;
        super::check_export_readable(manifest)?;
        let size = super::export_record_size(chunk)?;
        file.seek(SeekFrom::Start(chunk.offset)).map_err(io)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            super::TranscriptError::BoundExceeded("ciphertext allocation refused".into())
        })?;
        bytes.resize(size, 0);
        for part in bytes.chunks_mut(64 * 1024) {
            let mut filled = 0;
            while filled < part.len() {
                super::check_export_readable(manifest)?;
                let count = match file.read(&mut part[filled..]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result.map_err(io)?,
                };
                super::check_export_readable(manifest)?;
                if count == 0 {
                    return Err(io(io::ErrorKind::UnexpectedEof.into()));
                }
                filled += count;
            }
        }
        if crate::plan::bundle::sha256_hex(&bytes) != chunk.sha256_hex {
            return Err(super::TranscriptError::HashMismatch {
                seq: chunk.seq,
                file: chunk.file.clone(),
            });
        }
        Ok(bytes)
    }
}

impl CaptureProducerDirectory {
    pub(super) fn existing(path: &Path) -> io::Result<Self> {
        Self::reserve(CaptureReadDirectory::existing(path)?)
    }

    fn reserve(reader: CaptureReadDirectory) -> io::Result<Self> {
        let writer = File::from(rustix::fs::openat(
            &reader.dir,
            WRITER_LOCK_FILENAME,
            OFlags::RDONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )?);
        private_writer_member(&writer.metadata()?)?;
        rustix::fs::flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self {
            writer,
            _reader: reader,
        })
    }
}

/// Bound inode identities obtained from a complete successful preflight.
pub struct PreparedPayload {
    files: Vec<(String, Metadata)>,
}

fn open_directory(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn open_existing_directory(path: &Path) -> io::Result<File> {
    let dir = open_directory(path)?;
    private_directory(&dir)?;
    Ok(dir)
}

fn read_manifest(dir: &File) -> io::Result<TranscriptManifest> {
    let mut file = open_at(dir, super::MANIFEST_FILENAME.as_ref(), OFlags::empty())?;
    regular_single_link(&file.metadata()?)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid("capture manifest exceeds size limit"));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid capture manifest JSON at line {} column {}",
                error.line(),
                error.column()
            ),
        )
    })
}

fn private_writer_member(metadata: &Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    regular_single_link(metadata)?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != 0
    {
        return Err(invalid(
            "writer coordination member must be empty, private and host-owned",
        ));
    }
    Ok(())
}

fn validate_writer_member(dir: &File) -> io::Result<()> {
    match open_at(dir, WRITER_LOCK_FILENAME.as_ref(), OFlags::empty()) {
        Ok(file) => private_writer_member(&file.metadata()?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn host_owned_not_publicly_writable(metadata: &Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            "legacy capture members must be host-owned and not publicly writable",
        ));
    }
    Ok(())
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
mod faults {
    use std::{cell::Cell, io};
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Boundary {
        Unlink,
        DirectorySync,
    }
    #[derive(Clone, Copy)]
    struct State {
        boundary: Boundary,
        remaining: usize,
        consumed: bool,
    }
    thread_local! { static STATE: Cell<Option<State>> = const { Cell::new(None) }; }
    pub struct Guard(Option<State>);
    impl Guard {
        pub fn arm(boundary: Boundary, occurrence: usize) -> Self {
            assert!(occurrence > 0);
            Self(STATE.replace(Some(State {
                boundary,
                remaining: occurrence,
                consumed: false,
            })))
        }
        pub fn consumed(&self) -> bool {
            STATE.get().is_some_and(|state| state.consumed)
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            STATE.set(self.0);
        }
    }
    pub fn hit(boundary: Boundary) -> io::Result<()> {
        if let Some(mut state) = STATE.get()
            && state.boundary == boundary
            && !state.consumed
        {
            state.remaining -= 1;
            state.consumed = state.remaining == 0;
            STATE.set(Some(state));
            if state.consumed {
                return Err(io::Error::other("injected cleanup syscall failure"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_and_one_producer_coexist_but_retirement_is_exclusive() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let producer = CaptureProducerDirectory::existing(root.path()).unwrap();
        let first = CaptureReadDirectory::existing(root.path()).unwrap();
        let second = CaptureReadDirectory::existing(root.path()).unwrap();
        assert_eq!(
            CaptureProducerDirectory::existing(root.path())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            CaptureDirectory::for_writer(root.path())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(producer);
        assert!(CaptureDirectory::for_writer(root.path()).is_err());
        drop(first);
        drop(second);
        let retirement = CaptureDirectory::for_writer(root.path()).unwrap();
        assert_eq!(
            CaptureReadDirectory::existing(root.path())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(retirement);
    }

    #[test]
    fn lexical_read_and_producer_unlocks_survive_duplicated_descriptors() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let reader = CaptureReadDirectory::existing(root.path()).unwrap();
        let duplicate_read = reader.dir.try_clone().unwrap();
        drop(reader);
        drop(CaptureDirectory::for_writer(root.path()).unwrap());
        let producer = CaptureProducerDirectory::existing(root.path()).unwrap();
        let duplicate_writer = producer.writer.try_clone().unwrap();
        let duplicate_directory = producer._reader.dir.try_clone().unwrap();
        drop(producer);
        drop(CaptureProducerDirectory::existing(root.path()).unwrap());
        drop(CaptureDirectory::for_writer(root.path()).unwrap());
        assert!(duplicate_read.metadata().unwrap().is_dir());
        assert!(duplicate_directory.metadata().unwrap().is_dir());
        assert!(duplicate_writer.metadata().unwrap().is_file());
    }

    #[test]
    fn failed_producer_reservation_releases_its_duplicated_reader_lease() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let producer = CaptureProducerDirectory::existing(root.path()).unwrap();
        let contender = CaptureReadDirectory::existing(root.path()).unwrap();
        let duplicate = contender.dir.try_clone().unwrap();
        assert_eq!(
            CaptureProducerDirectory::reserve(contender)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(producer);
        drop(CaptureDirectory::for_writer(root.path()).unwrap());
        assert!(duplicate.metadata().unwrap().is_dir());
    }

    #[test]
    fn failed_coordination_validation_lexically_unlocks_despite_a_duplicate() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let path = root.path().join(WRITER_LOCK_FILENAME);
        crate::atomic_io::write_private(&path, b"invalid").unwrap();
        let dir = open_existing_directory(root.path()).unwrap();
        rustix::fs::flock(&dir, FlockOperation::NonBlockingLockShared).unwrap();
        let duplicate = dir.try_clone().unwrap();
        let candidate = CaptureReadDirectory {
            dir,
            permissions: ReadPermissions::Protected,
        };
        assert!(candidate.validate().is_err());
        drop(CaptureDirectory::for_writer(root.path()).unwrap());
        assert_eq!(std::fs::read(path).unwrap(), b"invalid");
        assert!(duplicate.metadata().unwrap().is_dir());
    }

    #[test]
    fn legacy_reads_do_not_repair_modes_and_private_readers_refuse_loose_payload() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let payload = root.path().join("0.seg");
        std::fs::write(&payload, b"abc").unwrap();
        crate::private_fs::set_mode(root.path(), 0o755).unwrap();
        crate::private_fs::set_mode(&payload, 0o644).unwrap();
        let reader = CaptureReadDirectory::legacy_existing(root.path()).unwrap();
        assert!(reader.open_segment("0.seg", 3).is_ok());
        drop(reader);
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::metadata(&payload).unwrap().mode() & 0o777, 0o644);
        crate::private_fs::set_mode(root.path(), 0o700).unwrap();
        let reader = CaptureReadDirectory::existing(root.path()).unwrap();
        assert!(reader.open_segment("0.seg", 3).is_err());
        assert_eq!(std::fs::metadata(payload).unwrap().mode() & 0o777, 0o644);
    }

    #[test]
    fn leased_manifest_errors_drop_payload_diagnostics_without_initializing_storage() {
        use std::error::Error as _;
        let root = tempfile::tempdir().unwrap();
        assert!(CaptureReadDirectory::open(root.path(), Path::new("absent")).is_err());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let marker = "private-manifest-diagnostic-marker";
        let path = root.path().join(super::super::MANIFEST_FILENAME);
        crate::atomic_io::write_private(
            &path,
            serde_json::to_string(&serde_json::json!({"format_version": marker}))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let reader = CaptureReadDirectory::existing(root.path()).unwrap();
        let error = reader.read_manifest().unwrap_err();
        assert!(error.to_string().contains("line"));
        assert!(!format!("{error} {error:#} {error:?} {error:#?}").contains(marker));
        let mut source = error.source();
        while let Some(current) = source {
            assert!(!format!("{current} {current:?}").contains(marker));
            source = current.source();
        }
    }
    use crate::transcript::{
        AtRestRetention, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME,
        RetentionPolicy, TranscriptWriter, TranscriptWriterConfig,
    };

    #[test]
    fn lexical_capture_lease_releases_even_while_a_duplicate_descriptor_survives() {
        let dir = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(dir.path()).unwrap();
        let capture = CaptureDirectory::for_writer(dir.path()).unwrap();
        let duplicate = capture.dir.try_clone().unwrap();
        assert_eq!(
            CaptureDirectory::for_writer(dir.path())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );

        drop(capture);
        let next = CaptureDirectory::for_writer(dir.path())
            .expect("the lexical lease ended even if a fork inherited its file description");
        assert!(duplicate.metadata().unwrap().is_dir());
        drop(next);
        drop(duplicate);
    }

    #[test]
    fn owned_directory_constructors_release_lexically_and_on_failed_validation() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let file = open_existing_directory(root.path()).unwrap();
        let duplicate = file.try_clone().unwrap();
        let exclusive = CaptureDirectory::from_owned_directory(file).unwrap();
        assert!(CaptureReadDirectory::existing(root.path()).is_err());
        drop(exclusive);
        let shared = CaptureReadDirectory::from_owned_directory(
            open_existing_directory(root.path()).unwrap(),
        )
        .unwrap();
        assert!(CaptureDirectory::for_writer(root.path()).is_err());
        drop(shared);
        let next = CaptureDirectory::for_writer(root.path()).unwrap();
        drop(next);
        assert!(duplicate.metadata().unwrap().is_dir());
        std::fs::create_dir(root.path().join(WRITER_LOCK_FILENAME)).unwrap();
        let file = open_existing_directory(root.path()).unwrap();
        let failed_duplicate = file.try_clone().unwrap();
        assert!(CaptureReadDirectory::from_owned_directory(file).is_err());
        // The failed shared guard explicitly unlocks despite its duplicate.
        let next = CaptureDirectory::for_writer(root.path()).unwrap();
        drop(next);
        assert!(failed_duplicate.metadata().unwrap().is_dir());
    }

    #[test]
    fn private_metadata_reads_are_bounded_private_and_descriptor_relative() {
        let root = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(root.path()).unwrap();
        let path = root.path().join("metadata");
        crate::atomic_io::write_private(&path, b"1234").unwrap();
        let lease = CaptureDirectory::for_writer(root.path()).unwrap();
        assert_eq!(lease.read_private_member("metadata", 4).unwrap(), b"1234");
        assert!(lease.read_private_member("metadata", 3).is_err());
        assert!(lease.read_private_member("../metadata", 4).is_err());
        crate::private_fs::set_mode(&path, 0o644).unwrap();
        assert!(lease.read_private_member("metadata", 4).is_err());
        crate::private_fs::set_mode(&path, 0o600).unwrap();
        std::fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(lease.read_private_member("metadata", 4).is_err());
    }

    fn fixture() -> (tempfile::TempDir, TranscriptManifest) {
        let dir = tempfile::tempdir().unwrap();
        crate::private_fs::ensure_private_dir(dir.path()).unwrap();
        let mut writer = TranscriptWriter::new(
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
    fn actual_partial_unlink_and_directory_sync_failures_resume() {
        for boundary in [faults::Boundary::Unlink, faults::Boundary::DirectorySync] {
            let (dir, mut manifest) = fixture();
            let mut second = manifest.chunks[0].clone();
            second.file = "1.seg".into();
            second.seq = 1;
            second.prev_hash = second.sha256_hex.clone();
            std::fs::copy(
                dir.path().join(&manifest.chunks[0].file),
                dir.path().join(&second.file),
            )
            .unwrap();
            manifest.chunks.push(second);
            manifest.sealed_root_hex = crate::transcript::sealed_root_hex(&manifest).unwrap();
            std::fs::write(
                dir.path().join(MANIFEST_FILENAME),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let capture = CaptureDirectory::for_writer(dir.path()).unwrap();
            let payload = capture.prepare_payload(&manifest, false).unwrap();
            let occurrence = if boundary == faults::Boundary::Unlink {
                2
            } else {
                1
            };
            let fault = faults::Guard::arm(boundary, occurrence);
            assert!(capture.unlink_payload(payload).is_err());
            assert!(fault.consumed());
            drop(fault);
            assert!(!dir.path().join("0.seg").exists());
            assert!(dir.path().join("1.seg").exists());
            assert_eq!(capture.read_manifest().unwrap(), manifest);
            assert_eq!(
                capture
                    .unlink_payload(capture.prepare_payload(&manifest, true).unwrap())
                    .unwrap(),
                1
            );
            assert_eq!(
                capture
                    .unlink_payload(capture.prepare_payload(&manifest, true).unwrap())
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn retry_after_last_unlink_must_sync_even_when_no_payload_remains() {
        let (dir, manifest) = fixture();
        let capture = CaptureDirectory::for_writer(dir.path()).unwrap();
        for attempt in 0..2 {
            let payload = capture.prepare_payload(&manifest, attempt > 0).unwrap();
            let fault = faults::Guard::arm(faults::Boundary::DirectorySync, 1);
            assert!(capture.unlink_payload(payload).is_err());
            assert!(fault.consumed(), "empty retry skipped directory durability");
            drop(fault);
            assert!(!dir.path().join(&manifest.chunks[0].file).exists());
            assert_eq!(capture.read_manifest().unwrap(), manifest);
        }
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
