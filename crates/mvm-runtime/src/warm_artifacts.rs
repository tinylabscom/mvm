//! Content-addressed artifact preparation for the resident warm-launch pool.
//!
//! Claims use [`WarmArtifactStore::resolve`] only. Building, downloading,
//! hashing, and copying inputs happen in [`PrewarmQueue::process_next`], which
//! can be driven by a resident worker. A published object is immutable and is
//! visible only after its complete directory has been renamed into place.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::Result;
use mvm_core::vm_backend::{WarmArtifactIdentity, WarmPrewarmSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const OBJECTS_DIR: &str = "objects";
const JOBS_DIR: &str = "jobs";
const STAGING_DIR: &str = "staging";
const MANIFEST_FILE: &str = "manifest.json";

/// Content identity for every input that must be ready before a warm parent
/// can be published. It contains no host paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmArtifactKey {
    /// Backend identity and version, including VMM configuration compatibility.
    pub backend: String,
    pub backend_version: String,
    /// Guest-agent protocol or image identity.
    pub guest_agent_sha256: String,
    /// Kernel content identity.
    pub kernel_sha256: String,
    /// Initramfs content identity.
    pub initramfs_sha256: String,
    /// Workload rootfs content identity.
    pub rootfs_sha256: String,
    /// Runtime overlay identity, when the selected launch needs one.
    pub runtime_overlay_sha256: Option<String>,
}

impl TryFrom<WarmArtifactIdentity> for WarmArtifactKey {
    type Error = WarmArtifactError;

    fn try_from(identity: WarmArtifactIdentity) -> Result<Self, Self::Error> {
        let key = Self {
            backend: identity.backend,
            backend_version: identity.backend_version,
            guest_agent_sha256: identity.guest_agent_sha256,
            kernel_sha256: identity.kernel_sha256,
            initramfs_sha256: identity.initramfs_sha256,
            rootfs_sha256: identity.rootfs_sha256,
            runtime_overlay_sha256: identity.runtime_overlay_sha256,
        };
        key.validate()?;
        Ok(key)
    }
}

impl WarmArtifactKey {
    /// Validate the content identities before using the key for lookup or
    /// publication.
    pub fn validate(&self) -> Result<(), WarmArtifactError> {
        if self.backend.is_empty() || self.backend_version.is_empty() {
            return Err(WarmArtifactError::InvalidKey(
                "backend and backend version are required".into(),
            ));
        }
        for (name, digest) in [
            ("guest_agent_sha256", &self.guest_agent_sha256),
            ("kernel_sha256", &self.kernel_sha256),
            ("initramfs_sha256", &self.initramfs_sha256),
            ("rootfs_sha256", &self.rootfs_sha256),
        ] {
            validate_sha256(name, digest)?;
        }
        if let Some(digest) = &self.runtime_overlay_sha256 {
            validate_sha256("runtime_overlay_sha256", digest)?;
        }
        Ok(())
    }

    /// Return the stable SHA-256 object name for this complete key.
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("WarmArtifactKey is serializable");
        hex::encode(Sha256::digest(bytes))
    }
}

/// One staged artifact and the digest it must have before publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmArtifactInput {
    /// Relative name used inside the immutable object directory.
    pub name: String,
    /// Expected lowercase SHA-256 digest.
    pub sha256: String,
}

impl WarmArtifactInput {
    /// Describe a regular file by hashing it for a later atomic publication.
    pub fn from_file(name: impl Into<String>, path: &Path) -> Result<Self, WarmArtifactError> {
        let name = name.into();
        validate_relative_path(&name)?;
        let (sha256, _) = hash_file(path, &name)?;
        Ok(Self { name, sha256 })
    }
}

/// The immutable manifest stored with a published artifact object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmArtifactManifest {
    /// Schema version for future cache migrations.
    pub schema: u32,
    /// Complete content and runtime compatibility identity.
    pub key: WarmArtifactKey,
    /// Verified files belonging to this object.
    pub files: Vec<WarmArtifactFile>,
}

/// Verified file metadata in a published artifact object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmArtifactFile {
    /// Relative path below the object root.
    pub name: String,
    /// SHA-256 of the published bytes.
    pub sha256: String,
    /// Published byte length.
    pub size_bytes: u64,
}

/// A verified object returned by a cache lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmArtifactSet {
    /// Content-addressed object root. The directory is immutable after return.
    pub root: PathBuf,
    /// Manifest that was verified against the files on disk.
    pub manifest: WarmArtifactManifest,
}

impl WarmArtifactSet {
    /// Resolve one verified artifact path from the manifest. Arbitrary paths
    /// are rejected even though the object was verified as a whole.
    pub fn file_path(&self, name: &str) -> Result<PathBuf, WarmArtifactError> {
        validate_relative_path(name)?;
        if self.manifest.files.iter().any(|file| file.name == name) {
            Ok(self.root.join(name))
        } else {
            Err(WarmArtifactError::Corrupt(format!(
                "artifact {name:?} is not declared by the manifest"
            )))
        }
    }
}

/// Durable state of one asynchronous prewarm job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrewarmJob {
    /// Host-path-free source descriptor retained across worker restarts.
    pub source: WarmPrewarmSource,
    /// The object being prepared.
    pub key: WarmArtifactKey,
    /// Number of worker attempts that have started.
    pub attempts: u32,
    /// Current durable state.
    pub state: PrewarmJobState,
}

/// State persisted for restart recovery and operator visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum PrewarmJobState {
    /// Waiting for a worker.
    Queued,
    /// A worker owns this job and may be interrupted safely.
    Running,
    /// The immutable object was published and verified.
    Published,
    /// The last worker attempt failed; the job remains retryable.
    Failed { reason: String },
}

/// Errors that must never be converted into a cache hit.
#[derive(Debug, Error)]
pub enum WarmArtifactError {
    /// A staged or published file did not match its declared digest.
    #[error("warm artifact {name} failed verification: expected {expected}, got {actual}")]
    HashMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    /// A malformed, incomplete, or tampered object was found.
    #[error("warm artifact object is corrupt: {0}")]
    Corrupt(String),
    /// The requested content identity is not canonical.
    #[error("warm artifact key is invalid: {0}")]
    InvalidKey(String),
    /// A path supplied by a worker escaped its staging/object root.
    #[error("warm artifact path is unsafe: {0:?}")]
    UnsafePath(String),
    /// Filesystem or serialization failure.
    #[error("warm artifact store I/O: {0}")]
    Io(#[from] anyhow::Error),
}

/// Persistent content-addressed object store and job journal.
#[derive(Debug, Clone)]
pub struct WarmArtifactStore {
    root: PathBuf,
}

impl WarmArtifactStore {
    /// Open a store at an explicit root. Production callers should pass the
    /// warm-artifact child of the configured mvm cache directory.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Open the store below the configured mvm cache.
    pub fn open() -> Self {
        Self::at(PathBuf::from(mvm_core::config::mvm_cache_dir()).join("warm-artifacts"))
    }

    /// Resolve and re-verify one object. `None` is a cache miss; corruption is
    /// an error and is never treated as a hit.
    pub fn resolve(
        &self,
        key: &WarmArtifactKey,
    ) -> Result<Option<WarmArtifactSet>, WarmArtifactError> {
        key.validate()?;
        let object_root = self.object_root(key);
        if !object_root.exists() {
            return Ok(None);
        }
        let manifest = read_manifest(&object_root)?;
        if manifest.key != *key
            || object_root.file_name().and_then(|name| name.to_str()) != Some(key.digest().as_str())
        {
            return Err(WarmArtifactError::Corrupt(
                "object identity does not match its manifest".into(),
            ));
        }
        verify_manifest(&object_root, &manifest)?;
        Ok(Some(WarmArtifactSet {
            root: object_root,
            manifest,
        }))
    }

    /// Verify a staged directory and publish it atomically under its key.
    pub fn publish(
        &self,
        key: &WarmArtifactKey,
        staged_root: &Path,
        inputs: &[WarmArtifactInput],
    ) -> Result<WarmArtifactSet, WarmArtifactError> {
        key.validate()?;
        if inputs.is_empty() {
            return Err(WarmArtifactError::Corrupt(
                "cannot publish an empty artifact set".into(),
            ));
        }
        let object_root = self.object_root(key);
        if let Some(existing) = self.resolve(key)? {
            return Ok(existing);
        }
        let objects_root = self.root.join(OBJECTS_DIR);
        fs::create_dir_all(&objects_root).map_err(|error| io_error(&objects_root, error))?;
        let _lock =
            mvm_core::atomic_io::FileLock::acquire(&objects_root).map_err(WarmArtifactError::Io)?;
        if let Some(existing) = self.resolve(key)? {
            return Ok(existing);
        }
        let staging = self.root.join(STAGING_DIR).join(Uuid::new_v4().to_string());
        fs::create_dir_all(&staging).map_err(|error| io_error(&staging, error))?;
        let result = self.populate_and_publish(key, staged_root, inputs, &staging, &object_root);
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    /// Enqueue or return the durable job for a key. Repeated requests are
    /// idempotent and never create duplicate workers.
    pub fn enqueue(
        &self,
        source: WarmPrewarmSource,
        key: WarmArtifactKey,
    ) -> Result<PrewarmJob, WarmArtifactError> {
        source.validate().map_err(WarmArtifactError::InvalidKey)?;
        key.validate()?;
        let path = self.job_path(&key);
        if let Some(existing) = read_job(&path)? {
            if matches!(existing.state, PrewarmJobState::Failed { .. }) {
                let job = PrewarmJob {
                    source,
                    key,
                    attempts: existing.attempts,
                    state: PrewarmJobState::Queued,
                };
                write_job(&path, &job)?;
                return Ok(job);
            }
            return Ok(existing);
        }
        let job = PrewarmJob {
            source,
            key,
            attempts: 0,
            state: PrewarmJobState::Queued,
        };
        write_job(&path, &job)?;
        Ok(job)
    }

    /// Recover jobs interrupted while a worker was running. The staging
    /// directory is disposable; the durable job returns to `Queued`.
    pub fn recover(&self) -> Result<Vec<PrewarmJob>, WarmArtifactError> {
        let jobs_root = self.root.join(JOBS_DIR);
        let entries = match fs::read_dir(&jobs_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(&jobs_root, error)),
        };
        let mut recovered = Vec::new();
        for entry in entries {
            let path = entry.map_err(|error| io_error(&jobs_root, error))?.path();
            let Some(mut job) = read_job(&path)? else {
                continue;
            };
            if job.state == PrewarmJobState::Running {
                job.state = PrewarmJobState::Queued;
                write_job(&path, &job)?;
                recovered.push(job);
            }
        }
        Ok(recovered)
    }

    /// Return all durable jobs in stable filename order.
    pub fn jobs(&self) -> Result<Vec<PrewarmJob>, WarmArtifactError> {
        let jobs_root = self.root.join(JOBS_DIR);
        let entries = match fs::read_dir(&jobs_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(&jobs_root, error)),
        };
        let mut paths = entries
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| io_error(&jobs_root, error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        paths
            .into_iter()
            .filter_map(|path| read_job(&path).transpose())
            .collect()
    }

    fn populate_and_publish(
        &self,
        key: &WarmArtifactKey,
        staged_root: &Path,
        inputs: &[WarmArtifactInput],
        staging: &Path,
        object_root: &Path,
    ) -> Result<WarmArtifactSet, WarmArtifactError> {
        let mut files = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_relative_path(&input.name)?;
            let source = staged_root.join(&input.name);
            let (actual, size_bytes) = hash_file(&source, &input.name)?;
            if actual != input.sha256 {
                return Err(WarmArtifactError::HashMismatch {
                    name: input.name.clone(),
                    expected: input.sha256.clone(),
                    actual,
                });
            }
            let destination = staging.join(&input.name);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
            }
            fs::copy(&source, &destination).map_err(|error| io_error(&source, error))?;
            files.push(WarmArtifactFile {
                name: input.name.clone(),
                sha256: input.sha256.clone(),
                size_bytes,
            });
        }
        let manifest = WarmArtifactManifest {
            schema: 1,
            key: key.clone(),
            files,
        };
        let manifest_path = staging.join(MANIFEST_FILE);
        let body = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| WarmArtifactError::Io(anyhow::Error::new(error)))?;
        mvm_core::atomic_io::atomic_write(&manifest_path, &body).map_err(WarmArtifactError::Io)?;
        verify_manifest(staging, &manifest)?;
        fs::create_dir_all(object_root.parent().expect("object root has a parent"))
            .map_err(|error| io_error(object_root, error))?;
        fs::rename(staging, object_root).map_err(|error| io_error(object_root, error))?;
        Ok(WarmArtifactSet {
            root: object_root.to_path_buf(),
            manifest,
        })
    }

    fn object_root(&self, key: &WarmArtifactKey) -> PathBuf {
        self.root.join(OBJECTS_DIR).join(key.digest())
    }

    fn job_path(&self, key: &WarmArtifactKey) -> PathBuf {
        self.root
            .join(JOBS_DIR)
            .join(format!("{}.json", key.digest()))
    }
}

/// Worker seam for the asynchronous prewarm loop. The implementation that
/// owns Nix/download/image work supplies the callback; claims never call it.
pub struct PrewarmQueue {
    store: WarmArtifactStore,
}

impl PrewarmQueue {
    /// Create a queue backed by the supplied artifact store.
    pub fn new(store: WarmArtifactStore) -> Self {
        Self { store }
    }

    /// Enqueue one content-addressed preparation job.
    pub fn enqueue(
        &self,
        source: WarmPrewarmSource,
        key: WarmArtifactKey,
    ) -> Result<PrewarmJob, WarmArtifactError> {
        self.store.enqueue(source, key)
    }

    /// Access the backing store for worker status and restart recovery.
    pub fn store(&self) -> &WarmArtifactStore {
        &self.store
    }

    /// Process one queued job. The caller supplies the worker that performs
    /// all expensive preparation into `staging_root`; this method only owns
    /// durable state transitions, verification, and atomic publication.
    pub fn process_next<F>(&self, build: F) -> Result<Option<PrewarmJob>, WarmArtifactError>
    where
        F: FnOnce(&WarmPrewarmSource, &WarmArtifactKey, &Path) -> Result<Vec<WarmArtifactInput>>,
    {
        self.process_next_with_readiness(build, |_, _, _| Ok(()))
    }

    /// Process one queued job and require authenticated golden-VM readiness
    /// before publishing its immutable artifact object.
    pub fn process_next_with_readiness<F, V>(
        &self,
        build: F,
        verify_readiness: V,
    ) -> Result<Option<PrewarmJob>, WarmArtifactError>
    where
        F: FnOnce(&WarmPrewarmSource, &WarmArtifactKey, &Path) -> Result<Vec<WarmArtifactInput>>,
        V: FnOnce(&WarmPrewarmSource, &WarmArtifactKey, &Path) -> Result<()>,
    {
        let Some(mut job) = self
            .store
            .jobs()?
            .into_iter()
            .find(|job| job.state == PrewarmJobState::Queued)
        else {
            return Ok(None);
        };
        job.attempts = job.attempts.saturating_add(1);
        job.state = PrewarmJobState::Running;
        let job_path = self.store.job_path(&job.key);
        write_job(&job_path, &job)?;

        let staging_root = self
            .store
            .root
            .join(STAGING_DIR)
            .join(format!("job-{}", job.key.digest()));
        if staging_root.exists() {
            fs::remove_dir_all(&staging_root).map_err(|error| io_error(&staging_root, error))?;
        }
        fs::create_dir_all(&staging_root).map_err(|error| io_error(&staging_root, error))?;
        let build_result = build(&job.source, &job.key, &staging_root);
        let result = match build_result {
            Ok(inputs) => match verify_readiness(&job.source, &job.key, &staging_root) {
                Ok(()) => self.store.publish(&job.key, &staging_root, &inputs),
                Err(error) => Err(WarmArtifactError::Io(error)),
            },
            Err(error) => Err(WarmArtifactError::Io(error)),
        };
        match result {
            Ok(_) => {
                job.state = PrewarmJobState::Published;
                write_job(&job_path, &job)?;
                Ok(Some(job))
            }
            Err(error) => {
                job.state = PrewarmJobState::Failed {
                    reason: error.to_string(),
                };
                write_job(&job_path, &job)?;
                let _ = fs::remove_dir_all(&staging_root);
                Err(error)
            }
        }
    }
}

fn read_manifest(root: &Path) -> Result<WarmArtifactManifest, WarmArtifactError> {
    let path = root.join(MANIFEST_FILE);
    let bytes = fs::read(&path).map_err(|error| io_error(&path, error))?;
    serde_json::from_slice(&bytes).map_err(|error| WarmArtifactError::Corrupt(error.to_string()))
}

fn verify_manifest(root: &Path, manifest: &WarmArtifactManifest) -> Result<(), WarmArtifactError> {
    if manifest.schema != 1 || manifest.files.is_empty() {
        return Err(WarmArtifactError::Corrupt(
            "unsupported or empty artifact manifest".into(),
        ));
    }
    let mut names = BTreeMap::new();
    for file in &manifest.files {
        validate_relative_path(&file.name)?;
        if names.insert(&file.name, ()).is_some() {
            return Err(WarmArtifactError::Corrupt(
                "artifact manifest has duplicate files".into(),
            ));
        }
        let (actual, size_bytes) = hash_file(&root.join(&file.name), &file.name)?;
        if actual != file.sha256 {
            return Err(WarmArtifactError::HashMismatch {
                name: file.name.clone(),
                expected: file.sha256.clone(),
                actual,
            });
        }
        if size_bytes != file.size_bytes {
            return Err(WarmArtifactError::Corrupt(format!(
                "size mismatch for {}: expected {}, got {}",
                file.name, file.size_bytes, size_bytes
            )));
        }
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), WarmArtifactError> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || !Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(WarmArtifactError::UnsafePath(path.to_string()));
    }
    Ok(())
}

fn validate_sha256(name: &str, digest: &str) -> Result<(), WarmArtifactError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WarmArtifactError::InvalidKey(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn hash_file(path: &Path, name: &str) -> Result<(String, u64), WarmArtifactError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(Path::new(name), error))?;
    if !metadata.file_type().is_file() {
        return Err(WarmArtifactError::Corrupt(format!(
            "artifact {name:?} is not a regular file"
        )));
    }
    let mut file = fs::File::open(path).map_err(|error| io_error(Path::new(name), error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error(Path::new(name), error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size
            .checked_add(u64::try_from(read).expect("buffer length fits in u64"))
            .expect("artifact size fits in u64");
    }
    Ok((hex::encode(hasher.finalize()), size))
}

fn read_job(path: &Path) -> Result<Option<PrewarmJob>, WarmArtifactError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| WarmArtifactError::Corrupt(format!("{}: {error}", path.display())))
}

fn write_job(path: &Path, job: &PrewarmJob) -> Result<(), WarmArtifactError> {
    let body = serde_json::to_vec_pretty(job)
        .map_err(|error| WarmArtifactError::Io(anyhow::Error::new(error)))?;
    mvm_core::atomic_io::atomic_write(path, &body).map_err(WarmArtifactError::Io)
}

fn io_error(path: &Path, error: std::io::Error) -> WarmArtifactError {
    WarmArtifactError::Io(anyhow::anyhow!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> WarmArtifactKey {
        WarmArtifactKey {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: "b".repeat(64),
            initramfs_sha256: "c".repeat(64),
            rootfs_sha256: "d".repeat(64),
            runtime_overlay_sha256: Some("e".repeat(64)),
        }
    }

    fn input(name: &str, bytes: &[u8]) -> WarmArtifactInput {
        WarmArtifactInput {
            name: name.into(),
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    fn source() -> WarmPrewarmSource {
        WarmPrewarmSource::OciImage {
            reference: "python:3.12".into(),
        }
    }

    fn identity() -> WarmArtifactIdentity {
        WarmArtifactIdentity {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: "b".repeat(64),
            initramfs_sha256: "c".repeat(64),
            rootfs_sha256: "d".repeat(64),
            runtime_overlay_sha256: Some("e".repeat(64)),
        }
    }

    #[test]
    fn artifact_identity_converts_only_after_digest_validation() {
        let converted = WarmArtifactKey::try_from(identity()).expect("valid identity converts");
        assert_eq!(converted, key());

        let mut invalid = identity();
        invalid.rootfs_sha256 = "not-a-digest".into();
        assert!(matches!(
            WarmArtifactKey::try_from(invalid),
            Err(WarmArtifactError::InvalidKey(_))
        ));
    }

    #[test]
    fn publish_is_atomic_and_resolve_reverifies() {
        let root = tempfile::tempdir().expect("store root");
        let staged = tempfile::tempdir().expect("staging root");
        let bytes = b"immutable kernel";
        fs::write(staged.path().join("kernel"), bytes).expect("write staged file");
        let store = WarmArtifactStore::at(root.path());
        let published = store
            .publish(&key(), staged.path(), &[input("kernel", bytes)])
            .expect("publish succeeds");
        assert_eq!(published.manifest.files.len(), 1);
        assert!(published.root.join(MANIFEST_FILE).is_file());
        assert!(store.resolve(&key()).expect("resolve succeeds").is_some());
        assert!(!root.path().join(STAGING_DIR).join("leftover").exists());
    }

    #[test]
    fn cache_miss_and_corruption_are_distinct_from_a_hit() {
        let root = tempfile::tempdir().expect("store root");
        let store = WarmArtifactStore::at(root.path());
        assert!(store.resolve(&key()).expect("miss is healthy").is_none());
        let staged = tempfile::tempdir().expect("staging root");
        fs::write(staged.path().join("kernel"), b"kernel").expect("write staged file");
        let published = store
            .publish(&key(), staged.path(), &[input("kernel", b"kernel")])
            .expect("publish succeeds");
        fs::write(published.root.join("kernel"), b"tampered").expect("tamper test file");
        assert!(matches!(
            store.resolve(&key()),
            Err(WarmArtifactError::HashMismatch { .. })
        ));
    }

    #[test]
    fn verified_set_exposes_only_manifest_files() {
        let root = tempfile::tempdir().expect("store root");
        let staged = tempfile::tempdir().expect("staging root");
        fs::write(staged.path().join("kernel"), b"kernel").expect("write staged file");
        let store = WarmArtifactStore::at(root.path());
        let published = store
            .publish(&key(), staged.path(), &[input("kernel", b"kernel")])
            .expect("publish succeeds");
        assert_eq!(
            published
                .file_path("kernel")
                .expect("declared file resolves"),
            published.root.join("kernel")
        );
        assert!(matches!(
            published.file_path("rootfs"),
            Err(WarmArtifactError::Corrupt(_))
        ));
    }

    #[test]
    fn interrupted_running_jobs_are_requeued() {
        let root = tempfile::tempdir().expect("store root");
        let store = WarmArtifactStore::at(root.path());
        let job = store.enqueue(source(), key()).expect("enqueue succeeds");
        let path = store.job_path(&job.key);
        let running = PrewarmJob {
            state: PrewarmJobState::Running,
            ..job
        };
        write_job(&path, &running).expect("write running state");
        let recovered = store.recover().expect("recovery succeeds");
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, PrewarmJobState::Queued);
        assert_eq!(recovered[0].source, source());
        assert_eq!(
            store.jobs().expect("list jobs")[0].state,
            PrewarmJobState::Queued
        );
    }

    #[test]
    fn worker_publishes_only_after_the_builder_finishes() {
        let root = tempfile::tempdir().expect("store root");
        let queue = PrewarmQueue::new(WarmArtifactStore::at(root.path()));
        queue.enqueue(source(), key()).expect("enqueue succeeds");
        let processed = queue
            .process_next(|_, _, staging| {
                let bytes = b"ready rootfs";
                fs::write(staging.join("rootfs"), bytes).expect("write builder output");
                Ok(vec![input("rootfs", bytes)])
            })
            .expect("worker succeeds")
            .expect("one job was queued");
        assert_eq!(processed.state, PrewarmJobState::Published);
        assert!(
            queue
                .store()
                .resolve(&key())
                .expect("resolve succeeds")
                .is_some()
        );
    }

    #[test]
    fn readiness_failure_keeps_prepared_artifacts_unpublished() {
        let root = tempfile::tempdir().expect("store root");
        let queue = PrewarmQueue::new(WarmArtifactStore::at(root.path()));
        queue.enqueue(source(), key()).expect("enqueue succeeds");
        let error = queue
            .process_next_with_readiness(
                |_, _, staging| {
                    let bytes = b"ready rootfs";
                    fs::write(staging.join("rootfs"), bytes).expect("write builder output");
                    Ok(vec![input("rootfs", bytes)])
                },
                |_, _, _| Err(anyhow::anyhow!("guest authentication failed")),
            )
            .expect_err("readiness failure is surfaced");
        assert!(error.to_string().contains("guest authentication failed"));
        assert!(
            queue
                .store()
                .resolve(&key())
                .expect("resolve remains a miss")
                .is_none()
        );
        assert!(matches!(
            queue.store().jobs().expect("list jobs")[0].state,
            PrewarmJobState::Failed { .. }
        ));
    }

    #[test]
    fn failed_builder_is_durable_and_retryable() {
        let root = tempfile::tempdir().expect("store root");
        let queue = PrewarmQueue::new(WarmArtifactStore::at(root.path()));
        queue.enqueue(source(), key()).expect("enqueue succeeds");
        let error = queue
            .process_next(|_, _, _| Err(anyhow::anyhow!("builder unavailable")))
            .expect_err("builder failure is surfaced");
        assert!(error.to_string().contains("builder unavailable"));
        assert!(matches!(
            queue.store().jobs().expect("list jobs")[0].state,
            PrewarmJobState::Failed { .. }
        ));
        assert_eq!(
            queue.enqueue(source(), key()).expect("retry enqueue").state,
            PrewarmJobState::Queued
        );
    }

    #[test]
    fn unsafe_staged_paths_are_rejected() {
        let root = tempfile::tempdir().expect("store root");
        let staged = tempfile::tempdir().expect("staging root");
        let store = WarmArtifactStore::at(root.path());
        let error = store
            .publish(&key(), staged.path(), &[input("../escape", b"bad")])
            .expect_err("path traversal must fail");
        assert!(matches!(error, WarmArtifactError::UnsafePath(_)));
    }

    #[test]
    fn malformed_content_identity_is_rejected_before_lookup() {
        let root = tempfile::tempdir().expect("store root");
        let store = WarmArtifactStore::at(root.path());
        let mut invalid = key();
        invalid.rootfs_sha256 = "not-a-digest".into();
        assert!(matches!(
            store.resolve(&invalid),
            Err(WarmArtifactError::InvalidKey(_))
        ));
    }
}
