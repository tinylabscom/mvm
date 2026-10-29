//! Fixed-layout local configuration and key access beneath an existing trusted
//! home. Descendants are opened relative to held descriptors, never repaired.
//!
//! Canonical audit/history and retirement delegates remain path-rooted. This
//! does not protect against hostile same-UID namespace mutation of those roots.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustix::fs::{AtFlags, Mode, OFlags};
use zeroize::Zeroizing;

use super::secure_cleanup::{CaptureDirectory, CaptureReadDirectory};
use super::{
    AtRestRetention, PayloadEncoding, RetentionPolicy, TranscriptManifest, TranscriptWriterConfig,
};
use crate::crypto::aead;

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_SESSION_BYTES: usize = 4096;
const MAX_ENUMERATED_ENTRIES_PER_DIRECTORY: usize = 8192;
const MAX_ENUMERATED_ENTRIES_TOTAL: usize = 32768;
const MAX_ENUMERATED_TENANTS: usize = 256;
const MAX_CAPTURE_RESULTS: usize = 4096;
const HOST_PUBLIC: &str = "host-signer.pub";
const HOST_SECRET: &str = "host-signer.ed25519";

fn invalid() -> io::Error {
    io::Error::other("invalid or unavailable managed transcript resource")
}

fn component(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > MAX_COMPONENT_BYTES
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', '\0'])
    {
        return Err(invalid());
    }
    Ok(())
}

fn directory(file: File) -> io::Result<File> {
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o7777 != 0o700 {
        return Err(invalid());
    }
    Ok(file)
}

fn child(parent: &File, name: &str) -> io::Result<File> {
    component(name)?;
    directory(File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn optional<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn create_child(parent: &File, name: &str) -> io::Result<File> {
    component(name)?;
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => parent.sync_all()?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    child(parent, name)
}

fn resource(parent: &File, name: &str, public: bool) -> io::Result<File> {
    let file = File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.nlink() != 1
        || !(m.mode() & 0o7777 == 0o600 || public && m.mode() & 0o7777 == 0o644)
    {
        return Err(invalid());
    }
    Ok(file)
}

fn key_bytes(parent: &File, name: &str, public: bool) -> io::Result<Zeroizing<[u8; 32]>> {
    let file = resource(parent, name, public)?;
    if file.metadata()?.len() != 32 {
        return Err(invalid());
    }
    let mut scratch = Zeroizing::new([0u8; 33]);
    let mut reader = file.take(33);
    let mut count = 0;
    while count < scratch.len() {
        let n = reader.read(&mut scratch[count..])?;
        if n == 0 {
            break;
        }
        count += n;
    }
    if count != 32 || reader.get_ref().metadata()?.len() != 32 {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&scratch[..32]);
    Ok(bytes)
}

/// Owns the existing home descriptor. The home and its ancestors are trusted;
/// the final home itself must not be a symlink. Opening never creates storage.
pub struct LocalTranscriptStore {
    home: File,
}

impl LocalTranscriptStore {
    pub fn open(home: &Path) -> io::Result<Self> {
        let home = File::from(rustix::fs::open(
            home,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = home.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(invalid());
        }
        Ok(Self { home })
    }

    fn transcripts(&self) -> io::Result<File> {
        child(&child(&self.home, "audit")?, "transcripts")
    }

    fn capture(&self, tenant: &str, capture: &str) -> io::Result<File> {
        component(tenant)?;
        component(capture)?;
        child(&child(&self.transcripts()?, tenant)?, capture)
    }

    pub fn read_capture(&self, tenant: &str, capture: &str) -> io::Result<CaptureReadDirectory> {
        CaptureReadDirectory::from_owned_directory(self.capture(tenant, capture)?)
    }

    pub fn exclusive_capture(&self, tenant: &str, capture: &str) -> io::Result<CaptureDirectory> {
        CaptureDirectory::from_owned_directory(self.capture(tenant, capture)?)
    }

    pub fn existing_kek(&self) -> io::Result<aead::Key> {
        let bytes = key_bytes(
            &child(&self.home, "keys")?,
            super::TRANSCRIPT_KEK_FILENAME,
            false,
        )?;
        Ok(aead::Key::from_bytes(*bytes))
    }

    pub fn existing_host_public_key(&self) -> io::Result<VerifyingKey> {
        let bytes = key_bytes(&child(&self.home, "keys")?, HOST_PUBLIC, true)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())
    }

    /// Existing authority only, for the caller's already-preflighted canonical
    /// retirement delegation. Never generates or repairs either half.
    pub fn existing_host_keypair(&self) -> io::Result<(SigningKey, VerifyingKey)> {
        let keys = child(&self.home, "keys")?;
        let signing = SigningKey::from_bytes(&*key_bytes(&keys, HOST_SECRET, false)?);
        let public = VerifyingKey::from_bytes(&*key_bytes(&keys, HOST_PUBLIC, true)?)
            .map_err(|_| invalid())?;
        if signing.verifying_key() != public {
            return Err(invalid());
        }
        Ok((signing, public))
    }

    pub fn capture_ids(&self, filter: Option<&str>) -> io::Result<Vec<(String, String)>> {
        if let Some(name) = filter {
            component(name)?;
        }
        let Some(root) = optional(self.transcripts())? else {
            return Ok(Vec::new());
        };
        let mut budget = Enumeration::default();
        let tenants = match filter {
            Some(name) => vec![name.to_owned()],
            None => budget.names(&root, MAX_ENUMERATED_TENANTS)?,
        };
        let mut result = Vec::new();
        for tenant in tenants {
            let Some(dir) = optional(child(&root, &tenant))? else {
                continue;
            };
            for capture in budget.names(&dir, MAX_CAPTURE_RESULTS)? {
                // Validate the resource too; a name alone is not a directory.
                let _ = child(&dir, &capture)?;
                if result.len() >= MAX_CAPTURE_RESULTS {
                    return Err(invalid());
                }
                result.push((tenant.clone(), capture));
            }
        }
        result.sort();
        Ok(result)
    }

    fn preflight(&self, config: &TranscriptWriterConfig) -> io::Result<()> {
        // Independent branches must all be checked before any creation. Missing
        // transcripts cannot bypass a malicious keys or local-audit resource.
        if let Some(keys) = optional(child(&self.home, "keys"))? {
            optional(key_bytes(&keys, super::TRANSCRIPT_KEK_FILENAME, false))?;
        }
        // Metadata only, opened nonblocking/no-follow; never read audit content.
        optional(resource(&self.home, "audit.jsonl", false))?;
        if let Some(audit) = optional(child(&self.home, "audit"))?
            && let Some(root) = optional(child(&audit, "transcripts"))?
            && let Some(tenant) = optional(child(&root, &config.binding.tenant_id))?
            && optional(child(&tenant, &config.capture_id))?.is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Publish unsigned configuration only. This neither starts a producer nor
    /// creates an authenticated opening, terminal seal or signing authority.
    pub fn create_unsigned_configuration(
        &self,
        mut config: TranscriptWriterConfig,
    ) -> Result<TranscriptManifest, super::TranscriptError> {
        let run = || -> io::Result<TranscriptManifest> {
            validate_config(&config)?;
            #[cfg(not(any(
                target_vendor = "apple",
                target_os = "linux",
                target_os = "android"
            )))]
            return Err(invalid());
            self.preflight(&config)?;
            let keys = create_child(&self.home, "keys")?;
            let kek = load_or_publish_kek(&keys)?;
            let key = aead::Key::random();
            config.wrapped_data_key_b64 = super::wrap_data_key(&kek, &key);
            let manifest = super::initial_manifest(config).map_err(io::Error::other)?;
            let bytes = serde_json::to_vec(&manifest).map_err(|_| invalid())?;
            let audit = create_child(&self.home, "audit")?;
            let root = create_child(&audit, "transcripts")?;
            let tenant = create_child(&root, &manifest.binding.tenant_id)?;
            // Unlike intermediate directories, capture creation is exclusive.
            rustix::fs::mkdirat(&tenant, &manifest.capture_id, Mode::from_raw_mode(0o700))?;
            let mut fresh = FreshCapture {
                parent: &tenant,
                name: &manifest.capture_id,
                dir: None,
                lease: None,
                member_created: false,
                published: false,
            };
            fresh.dir = Some(child(&tenant, &manifest.capture_id)?);
            let dir = fresh.dir.as_ref().ok_or_else(invalid)?;
            fresh.lease = Some(CaptureDirectory::from_owned_directory(dir.try_clone()?)?);
            let mut file = File::from(rustix::fs::openat(
                dir,
                super::MANIFEST_FILENAME,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?);
            fresh.member_created = true;
            file.write_all(&bytes)?;
            #[cfg(test)]
            tests::before_manifest_sync()?;
            file.sync_all()?;
            dir.sync_all()?;
            tenant.sync_all()?;
            fresh.published = true;
            drop(fresh);
            Ok(manifest)
        };
        run().map_err(|_| super::TranscriptError::Io {
            file: super::MANIFEST_FILENAME.into(),
            msg: "unsigned capture configuration unavailable".into(),
        })
    }
}

struct FreshCapture<'a> {
    parent: &'a File,
    name: &'a str,
    dir: Option<File>,
    lease: Option<CaptureDirectory>,
    member_created: bool,
    published: bool,
}

impl Drop for FreshCapture<'_> {
    fn drop(&mut self) {
        if !self.published {
            if let Some(dir) = &self.dir {
                if self.member_created {
                    let _ = rustix::fs::unlinkat(dir, super::MANIFEST_FILENAME, AtFlags::empty());
                }
                let _ = dir.sync_all();
            }
            let _ = rustix::fs::unlinkat(self.parent, self.name, AtFlags::REMOVEDIR);
            let _ = self.parent.sync_all();
        }
        // The lease field unlocks after cleanup, including on unwind.
    }
}

fn validate_config(config: &TranscriptWriterConfig) -> io::Result<()> {
    component(&config.capture_id)?;
    component(&config.binding.tenant_id)?;
    component(&config.binding.vm_name)?;
    if config
        .binding
        .session_id
        .as_ref()
        .is_some_and(|s| s.is_empty() || s.len() > MAX_SESSION_BYTES)
        || !config.wrapped_data_key_b64.is_empty()
        || config.recipient != super::TRANSCRIPT_KEK_RECIPIENT
        || config.generation_budget.is_some()
        || config.at_rest != Some(AtRestRetention::default())
        || config.payload_encoding != PayloadEncoding::Raw
        || config.retention != RetentionPolicy::FailClosed
    {
        return Err(invalid());
    }
    super::validate_protection(
        config.at_rest,
        config.generation_budget,
        config.payload_encoding,
        config.created_unix_secs,
    )
    .map_err(|_| invalid())
}

#[derive(Default)]
struct Enumeration {
    examined: usize,
}
impl Enumeration {
    fn names(&mut self, dir: &File, limit: usize) -> io::Result<Vec<String>> {
        let mut result = Vec::new();
        for (index, entry) in rustix::fs::Dir::read_from(dir)?.enumerate() {
            self.examined += 1;
            if index >= MAX_ENUMERATED_ENTRIES_PER_DIRECTORY
                || self.examined > MAX_ENUMERATED_ENTRIES_TOTAL
            {
                return Err(invalid());
            }
            let entry = entry?;
            let name = entry.file_name().to_str().map_err(|_| invalid())?;
            if matches!(name, "." | "..") {
                continue;
            }
            component(name)?;
            if result.len() >= limit {
                return Err(invalid());
            }
            result.push(name.to_owned());
        }
        Ok(result)
    }
}

struct Temporary<'a> {
    parent: &'a File,
    name: String,
    live: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if self.live {
            let _ = rustix::fs::unlinkat(self.parent, self.name.as_str(), AtFlags::empty());
            let _ = self.parent.sync_all();
        }
    }
}

fn load_or_publish_kek(keys: &File) -> io::Result<aead::Key> {
    if let Some(bytes) = optional(key_bytes(keys, super::TRANSCRIPT_KEK_FILENAME, false))? {
        return Ok(aead::Key::from_bytes(*bytes));
    }
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    {
        let bytes = Zeroizing::new(rand::random::<[u8; 32]>());
        let name = format!(
            ".transcript-kek-{}.tmp",
            hex::encode(rand::random::<[u8; 16]>())
        );
        let mut file = File::from(rustix::fs::openat(
            keys,
            name.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let mut temporary = Temporary {
            parent: keys,
            name,
            live: true,
        };
        file.write_all(bytes.as_ref())?;
        file.sync_all()?;
        let m = file.metadata()?;
        if m.len() != 32
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
            || m.uid() != rustix::process::geteuid().as_raw()
            || !m.is_file()
        {
            return Err(invalid());
        }
        #[cfg(test)]
        tests::before_publication();
        match rustix::fs::renameat_with(
            keys,
            temporary.name.as_str(),
            keys,
            super::TRANSCRIPT_KEK_FILENAME,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => temporary.live = false,
            Err(rustix::io::Errno::EXIST) => {
                rustix::fs::unlinkat(keys, temporary.name.as_str(), AtFlags::empty())?;
                temporary.live = false;
            }
            Err(error) => return Err(error.into()),
        }
        keys.sync_all()?;
        Ok(aead::Key::from_bytes(*key_bytes(
            keys,
            super::TRANSCRIPT_KEK_FILENAME,
            false,
        )?))
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier, mpsc};

    thread_local! {
        static BEFORE_PUBLICATION: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        static FAIL_MANIFEST_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn before_manifest_sync() -> io::Result<()> {
        if FAIL_MANIFEST_SYNC.with(|slot| slot.replace(false)) {
            Err(io::Error::other("injected manifest sync refusal"))
        } else {
            Ok(())
        }
    }

    pub(super) fn before_publication() {
        if let Some(callback) = BEFORE_PUBLICATION.with(|slot| slot.borrow_mut().take()) {
            callback();
        }
    }

    fn config(id: &str) -> TranscriptWriterConfig {
        TranscriptWriterConfig {
            capture_id: id.into(),
            binding: super::super::CaptureBinding {
                tenant_id: "local".into(),
                vm_name: "vm".into(),
                session_id: None,
            },
            bounds: super::super::CaptureBounds {
                max_duration_secs: 60,
                max_bytes: 4096,
                max_chunks: 64,
            },
            retention: RetentionPolicy::FailClosed,
            created_unix_secs: 100,
            at_rest: Some(AtRestRetention::default()),
            generation_budget: None,
            payload_encoding: PayloadEncoding::Raw,
            recipient: super::super::TRANSCRIPT_KEK_RECIPIENT.into(),
            wrapped_data_key_b64: String::new(),
        }
    }

    fn keys(home: &Path) -> File {
        let store = LocalTranscriptStore::open(home).unwrap();
        create_child(&store.home, "keys").unwrap()
    }

    #[test]
    fn initial_manifest_is_exactly_the_existing_writer_snapshot_not_terminal() {
        for protected in [false, true] {
            let home = tempfile::tempdir().unwrap();
            crate::private_fs::ensure_private_dir(home.path()).unwrap();
            let mut left = config("parity");
            let mut right = config("parity");
            left.wrapped_data_key_b64 = "same-wrapped-bytes".into();
            right.wrapped_data_key_b64 = left.wrapped_data_key_b64.clone();
            if !protected {
                left.at_rest = None;
                right.at_rest = None;
            }
            let manifest = super::super::initial_manifest(left).unwrap();
            let expected = super::super::TranscriptWriter::new(
                home.path(),
                aead::Key::from_bytes([7; 32]),
                right,
            )
            .unwrap()
            .seal();
            assert_eq!(
                serde_json::to_vec(&manifest).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
            assert_eq!(manifest.sealed_unix_secs, None);
        }
    }

    #[test]
    fn existing_key_resources_refuse_without_repair_or_unbounded_reads() {
        for kind in [
            "short",
            "long",
            "large",
            "loose",
            "link",
            "hardlink",
            "fifo",
            "directory",
        ] {
            let home = tempfile::tempdir().unwrap();
            let store = LocalTranscriptStore::open(home.path()).unwrap();
            let _ = keys(home.path());
            let path = home
                .path()
                .join("keys")
                .join(super::super::TRANSCRIPT_KEK_FILENAME);
            let outside = home.path().join("outside");
            match kind {
                "link" => {
                    std::fs::write(&outside, [3; 32]).unwrap();
                    symlink(&outside, &path).unwrap();
                }
                "fifo" => assert!(
                    std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap()
                        .success()
                ),
                "directory" => std::fs::create_dir(&path).unwrap(),
                _ => {
                    let len = match kind {
                        "short" => 31,
                        "long" => 33,
                        "large" => 1024 * 1024,
                        _ => 32,
                    };
                    std::fs::write(&path, vec![3; len]).unwrap();
                    std::fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(if kind == "loose" {
                            0o644
                        } else {
                            0o600
                        }),
                    )
                    .unwrap();
                    if kind == "hardlink" {
                        std::fs::hard_link(&path, &outside).unwrap();
                    }
                }
            }
            let before = std::fs::symlink_metadata(&path).unwrap();
            assert!(store.existing_kek().is_err(), "{kind}");
            assert!(
                store
                    .create_unsigned_configuration(config("refused"))
                    .is_err(),
                "{kind}"
            );
            let after = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (before.ino(), before.mode(), before.len(), before.nlink()),
                (after.ino(), after.mode(), after.len(), after.nlink()),
                "{kind}"
            );
            assert!(!home.path().join("audit").exists());
            assert!(!home.path().join("keys").join(HOST_SECRET).exists());
        }
    }

    #[test]
    fn existing_public_and_secret_authority_are_bounded_and_never_initialized_or_repaired() {
        let home = tempfile::tempdir().unwrap();
        let store = LocalTranscriptStore::open(home.path()).unwrap();
        assert!(store.existing_host_public_key().is_err());
        assert!(store.existing_host_keypair().is_err());
        assert!(!home.path().join("keys").exists());
        let _ = keys(home.path());
        let signing = SigningKey::from_bytes(&[4; 32]);
        let secret = home.path().join("keys").join(HOST_SECRET);
        let public = home.path().join("keys").join(HOST_PUBLIC);
        std::fs::write(&secret, [4; 32]).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&public, signing.verifying_key().to_bytes()).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.existing_host_public_key().unwrap(),
            signing.verifying_key()
        );
        assert_eq!(
            store.existing_host_keypair().unwrap().1,
            signing.verifying_key()
        );
        std::fs::write(&public, [8; 33]).unwrap();
        assert!(store.existing_host_public_key().is_err());
        assert!(store.existing_host_keypair().is_err());
        assert_eq!(std::fs::read(&public).unwrap(), [8; 33]);
        std::fs::remove_file(&public).unwrap();
        symlink(&secret, &public).unwrap();
        assert!(store.existing_host_public_key().is_err());
        std::fs::remove_file(&secret).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&secret)
                .status()
                .unwrap()
                .success()
        );
        assert!(store.existing_host_keypair().is_err());
    }

    #[test]
    fn static_descendants_and_local_audit_refuse_before_any_creation() {
        for name in [
            "keys",
            "audit",
            "audit/transcripts",
            "audit/transcripts/local",
            "audit.jsonl",
        ] {
            let home = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            let sentinel = outside.path().join("sentinel");
            std::fs::write(&sentinel, b"unchanged").unwrap();
            let target = home.path().join(name);
            if let Some(parent) = target.parent() {
                crate::private_fs::ensure_private_dir(parent).unwrap();
            }
            symlink(outside.path(), &target).unwrap();
            let store = LocalTranscriptStore::open(home.path()).unwrap();
            assert!(
                store
                    .create_unsigned_configuration(config("refused"))
                    .is_err(),
                "{name}"
            );
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
            assert_eq!(
                std::fs::metadata(outside.path()).unwrap().mode() & 0o7777,
                0o755
            );
            assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
            if name != "keys" {
                assert!(!home.path().join("keys").exists());
            }
        }
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("audit.jsonl");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            LocalTranscriptStore::open(home.path())
                .unwrap()
                .create_unsigned_configuration(config("refused"))
                .is_err()
        );
        assert!(!home.path().join("keys").exists());
    }

    #[test]
    fn concurrent_creators_use_one_complete_single_link_published_key() {
        let home = tempfile::tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let home = home.path().to_owned();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let store = LocalTranscriptStore::open(&home).unwrap();
                    barrier.wait();
                    let manifest = store
                        .create_unsigned_configuration(config(&format!("capture-{index}")))
                        .unwrap();
                    let kek = store.existing_kek().unwrap();
                    super::super::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
                    *kek.expose_bytes()
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(results.iter().all(|bytes| bytes == &results[0]));
        let names: Vec<_> = std::fs::read_dir(home.path().join("keys"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            [std::ffi::OsString::from(
                super::super::TRANSCRIPT_KEK_FILENAME
            )]
        );
        let m = std::fs::metadata(
            home.path()
                .join("keys")
                .join(super::super::TRANSCRIPT_KEK_FILENAME),
        )
        .unwrap();
        assert_eq!((m.len(), m.nlink(), m.mode() & 0o7777), (32, 1, 0o600));
    }

    #[test]
    fn paused_synced_temporary_is_not_a_partial_final_key() {
        let home = tempfile::tempdir().unwrap();
        let _ = keys(home.path());
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let path = home.path().to_owned();
        let thread = std::thread::spawn(move || {
            BEFORE_PUBLICATION.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    ready_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }))
            });
            let store = LocalTranscriptStore::open(&path).unwrap();
            store
                .create_unsigned_configuration(config("paused"))
                .unwrap()
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let store = LocalTranscriptStore::open(home.path()).unwrap();
        assert_eq!(
            store.existing_kek().err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert!(
            !home
                .path()
                .join("keys")
                .join(super::super::TRANSCRIPT_KEK_FILENAME)
                .exists()
        );
        resume_tx.send(()).unwrap();
        let manifest = thread.join().unwrap();
        assert!(
            super::super::unwrap_data_key(
                &store.existing_kek().unwrap(),
                &manifest.wrapped_data_key_b64
            )
            .is_ok()
        );
    }

    #[test]
    fn malformed_configuration_refuses_before_storage_or_keys() {
        let home = tempfile::tempdir().unwrap();
        let store = LocalTranscriptStore::open(home.path()).unwrap();
        for variant in 0..11 {
            let mut c = config("refused");
            match variant {
                0 => c.binding.vm_name = "../vm".into(),
                1 => c.binding.session_id = Some("x".repeat(MAX_SESSION_BYTES + 1)),
                2 => c.wrapped_data_key_b64 = "supplied".into(),
                3 => c.recipient = "other".into(),
                4 => c.at_rest = None,
                5 => c.at_rest.as_mut().unwrap().max_generation_secs += 1,
                6 => c.created_unix_secs = u64::MAX,
                7 => c.generation_budget = Some(super::super::GenerationBudget::default()),
                8 => c.binding.session_id = Some(String::new()),
                9 => c.capture_id = "../capture".into(),
                _ => c.binding.tenant_id = "../tenant".into(),
            }
            assert!(store.create_unsigned_configuration(c).is_err());
            assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn listing_limits_error_instead_of_truncating_or_collecting_unbounded_input() {
        let home = tempfile::tempdir().unwrap();
        let file = LocalTranscriptStore::open(home.path()).unwrap().home;
        let mut exhausted = Enumeration {
            examined: MAX_ENUMERATED_ENTRIES_TOTAL,
        };
        assert!(exhausted.names(&file, MAX_CAPTURE_RESULTS).is_err());
        for i in 0..3 {
            std::fs::create_dir(home.path().join(format!("entry-{i}"))).unwrap();
        }
        assert!(Enumeration::default().names(&file, 2).is_err());
    }

    #[test]
    fn missing_or_symlinked_home_never_initializes_storage() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("missing");
        assert!(LocalTranscriptStore::open(&missing).is_err());
        assert!(!missing.exists());
        let link = parent.path().join("link");
        symlink(parent.path(), &link).unwrap();
        assert!(LocalTranscriptStore::open(&link).is_err());
    }

    #[test]
    fn publication_failure_cleans_only_owned_temporary_and_capture_not_published_keys() {
        let home = tempfile::tempdir().unwrap();
        let store = LocalTranscriptStore::open(home.path()).unwrap();
        let _ = keys(home.path());
        BEFORE_PUBLICATION
            .with(|slot| *slot.borrow_mut() = Some(Box::new(|| panic!("before publish"))));
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.create_unsigned_configuration(config("not-published"))
        }));
        assert!(failure.is_err());
        assert_eq!(
            std::fs::read_dir(home.path().join("keys")).unwrap().count(),
            0
        );
        FAIL_MANIFEST_SYNC.with(|slot| slot.set(true));
        assert!(
            store
                .create_unsigned_configuration(config("failed-manifest"))
                .is_err()
        );
        assert!(
            !home
                .path()
                .join("audit/transcripts/local/failed-manifest")
                .exists()
        );
        // A complete published encryption key is deliberately not erased after
        // later I/O failure: another caller could already be using it.
        assert!(store.existing_kek().is_ok());
        let success = store
            .create_unsigned_configuration(config("success"))
            .unwrap();
        assert_eq!(success.capture_id, "success");
        assert!(!home.path().join("keys").join(HOST_SECRET).exists());
    }
}
