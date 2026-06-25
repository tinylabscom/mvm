//! Content-addressed local cache for verified attested packs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    LocalPackPolicy, PackBackend, PackKind, PackManifest, PackRevocationChecker, PackTrustStore,
    PackVerifyError, Sha256Hex, VerifiedPack, verify_pack_at,
};

pub const PACK_CACHE_SCHEMA_VERSION: u32 = 1;
pub const PACK_CACHE_DIR_NAME: &str = "packs";
pub const MANIFEST_FILENAME: &str = "manifest.json";
pub const INDEX_FILENAME: &str = "cache-index.json";
pub const PACK_PROTECTION_FILENAME: &str = "pack-protection.json";

#[derive(Debug, Clone)]
pub struct PackCache {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CachedPack {
    pub root: PathBuf,
    pub manifest: PackManifest,
    pub verified: VerifiedPack,
    pub index: PackCacheIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackProtectionRef {
    pub pack_hash: Sha256Hex,
    pub owner_kind: PackProtectionOwnerKind,
    pub owner_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackProtectionOwnerKind {
    Snapshot,
    WarmStandby,
}

#[derive(Debug, Clone)]
pub struct PackPruneRequest {
    pub now: DateTime<Utc>,
    pub dry_run: bool,
    pub protected: Vec<PackProtectionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackPruneReport {
    pub entries: Vec<PackPruneEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackPruneEntry {
    pub directory_name: String,
    pub root: PathBuf,
    pub pack_hash: Option<Sha256Hex>,
    pub readiness: PackCacheReadiness,
    pub action: PackPruneAction,
    pub reason: PackPruneReason,
    pub bytes: u64,
    pub protections: Vec<PackProtectionRef>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackPruneAction {
    Removed,
    WouldRemove,
    Retained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackPruneReason {
    Ready,
    Expired,
    InvalidMetadata,
    Protected,
}

impl PackPruneReport {
    pub fn removed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.action == PackPruneAction::Removed)
            .count()
    }

    pub fn would_remove_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.action == PackPruneAction::WouldRemove)
            .count()
    }

    pub fn protected_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.reason == PackPruneReason::Protected)
            .count()
    }

    pub fn removed_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.action,
                    PackPruneAction::Removed | PackPruneAction::WouldRemove
                )
            })
            .map(|entry| entry.bytes)
            .sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackCacheStatusEntry {
    pub directory_name: String,
    pub root: PathBuf,
    pub index: Option<PackCacheIndex>,
    pub readiness: PackCacheReadiness,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackCacheReadiness {
    Ready,
    Expired,
    MissingIndex,
    MalformedIndex,
    UnsupportedIndexSchema,
    DirectoryHashMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackCacheIndex {
    pub schema_version: u32,
    pub pack_hash: Sha256Hex,
    pub kind: PackKind,
    pub target_arch: crate::arch::GuestArch,
    pub backend_compatibility: Vec<PackBackend>,
    pub channel_identity: String,
    pub expires_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub file_count: usize,
    pub last_used_at: DateTime<Utc>,
    pub last_verified_at: DateTime<Utc>,
}

impl PackCache {
    pub fn default_path() -> PathBuf {
        PathBuf::from(crate::config::mvm_cache_dir()).join(PACK_CACHE_DIR_NAME)
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn by_hash_dir(&self) -> PathBuf {
        self.root.join("by-hash")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    pub fn pack_dir(&self, pack_hash: &Sha256Hex) -> PathBuf {
        self.by_hash_dir().join(pack_hash.as_str())
    }

    pub fn status_entries(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<PackCacheStatusEntry>, PackCacheError> {
        let by_hash_dir = self.by_hash_dir();
        if !by_hash_dir.is_dir() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&by_hash_dir).map_err(|source| PackCacheError::Io {
            path: by_hash_dir.clone(),
            source,
        })?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| PackCacheError::Io {
                path: by_hash_dir.clone(),
                source,
            })?;
            let root = entry.path();
            let metadata = fs::symlink_metadata(&root).map_err(|source| PackCacheError::Io {
                path: root.clone(),
                source,
            })?;
            if !metadata.file_type().is_dir() {
                continue;
            }
            let directory_name = entry.file_name().to_string_lossy().into_owned();
            out.push(status_entry_for_dir(directory_name, root, now));
        }
        out.sort_by(|a, b| {
            let a_used = a.index.as_ref().map(|index| index.last_used_at);
            let b_used = b.index.as_ref().map(|index| index.last_used_at);
            b_used
                .cmp(&a_used)
                .then_with(|| a.directory_name.cmp(&b.directory_name))
        });
        Ok(out)
    }

    pub fn prune(&self, request: &PackPruneRequest) -> Result<PackPruneReport, PackCacheError> {
        let mut protections_by_hash: BTreeMap<String, Vec<PackProtectionRef>> = BTreeMap::new();
        for protection in &request.protected {
            protections_by_hash
                .entry(protection.pack_hash.as_str().to_string())
                .or_default()
                .push(protection.clone());
        }

        let mut entries = Vec::new();
        for status in self.status_entries(request.now)? {
            let pack_hash = status_pack_hash(&status);
            let protections = pack_hash
                .as_ref()
                .and_then(|hash| protections_by_hash.get(hash.as_str()).cloned())
                .unwrap_or_default();
            let candidate_reason = prune_candidate_reason(status.readiness);
            let bytes = directory_size_bytes(&status.root)?;
            let (action, reason) = match (candidate_reason, protections.is_empty()) {
                (None, _) => (PackPruneAction::Retained, PackPruneReason::Ready),
                (Some(_), false) => (PackPruneAction::Retained, PackPruneReason::Protected),
                (Some(reason), true) if request.dry_run => (PackPruneAction::WouldRemove, reason),
                (Some(reason), true) => {
                    fs::remove_dir_all(&status.root).map_err(|source| PackCacheError::Io {
                        path: status.root.clone(),
                        source,
                    })?;
                    (PackPruneAction::Removed, reason)
                }
            };
            entries.push(PackPruneEntry {
                directory_name: status.directory_name,
                root: status.root,
                pack_hash,
                readiness: status.readiness,
                action,
                reason,
                bytes,
                protections,
                detail: status.detail,
            });
        }
        Ok(PackPruneReport { entries })
    }

    pub fn install_from_verified_root(
        &self,
        manifest: &PackManifest,
        source_root: &Path,
        policy: &LocalPackPolicy,
        trust: &dyn PackTrustStore,
        revocations: &dyn PackRevocationChecker,
    ) -> Result<CachedPack, PackCacheError> {
        let verified = verify_pack_at(manifest, source_root, policy, trust, revocations)
            .map_err(PackCacheError::VerifySource)?;
        self.ensure_layout()?;

        let final_dir = self.pack_dir(&verified.pack_hash);
        if final_dir.exists() {
            return self.resolve_verified(&verified.pack_hash, policy, trust, revocations);
        }

        self.clean_stale_quarantine_for_pack(&verified.pack_hash)?;
        let staging = self.staging_dir(&verified.pack_hash)?;
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|source| PackCacheError::Io {
                path: staging.clone(),
                source,
            })?;
        }
        ensure_private_dir(&staging)?;

        let index = PackCacheIndex::from_manifest(manifest, policy.now)?;
        write_restricted_file(
            &staging.join(MANIFEST_FILENAME),
            &manifest.canonical_bytes()?,
        )?;
        write_restricted_file(
            &staging.join(INDEX_FILENAME),
            &serde_json::to_vec(&index).map_err(PackCacheError::Json)?,
        )?;
        for file in &manifest.outputs.files {
            let source = source_root.join(&file.path);
            let destination = staging.join(&file.path);
            copy_regular_file_restricted(&source, &destination)?;
        }

        verify_pack_at(manifest, &staging, policy, trust, revocations)
            .map_err(PackCacheError::VerifyStaging)?;
        fs::rename(&staging, &final_dir).map_err(|source| PackCacheError::Io {
            path: final_dir.clone(),
            source,
        })?;
        self.resolve_verified(&verified.pack_hash, policy, trust, revocations)
    }

    pub fn resolve_verified(
        &self,
        pack_hash: &Sha256Hex,
        policy: &LocalPackPolicy,
        trust: &dyn PackTrustStore,
        revocations: &dyn PackRevocationChecker,
    ) -> Result<CachedPack, PackCacheError> {
        let root = self.pack_dir(pack_hash);
        if !root.is_dir() {
            return Err(PackCacheError::NotFound(pack_hash.clone()));
        }
        let manifest_path = root.join(MANIFEST_FILENAME);
        let manifest_bytes = fs::read(&manifest_path).map_err(|source| PackCacheError::Io {
            path: manifest_path.clone(),
            source,
        })?;
        let manifest: PackManifest =
            serde_json::from_slice(&manifest_bytes).map_err(PackCacheError::Json)?;
        if &manifest.outputs.pack_hash != pack_hash {
            return Err(PackCacheError::PackHashDirectoryMismatch {
                requested: pack_hash.clone(),
                manifest: manifest.outputs.pack_hash.clone(),
            });
        }
        let verified = verify_pack_at(&manifest, &root, policy, trust, revocations)
            .map_err(PackCacheError::VerifyCached)?;
        let index = PackCacheIndex::from_manifest(&manifest, policy.now)?;
        write_restricted_file(
            &root.join(INDEX_FILENAME),
            &serde_json::to_vec(&index).map_err(PackCacheError::Json)?,
        )?;
        Ok(CachedPack {
            root,
            manifest,
            verified,
            index,
        })
    }

    fn ensure_layout(&self) -> Result<(), PackCacheError> {
        ensure_private_dir(&self.root)?;
        ensure_private_dir(&self.by_hash_dir())?;
        ensure_private_dir(&self.quarantine_dir())
    }

    fn clean_stale_quarantine_for_pack(&self, pack_hash: &Sha256Hex) -> Result<(), PackCacheError> {
        let quarantine_dir = self.quarantine_dir();
        let Ok(entries) = fs::read_dir(&quarantine_dir) else {
            return Ok(());
        };
        let prefix = format!("{}.", pack_hash.as_str());
        for entry in entries {
            let entry = entry.map_err(|source| PackCacheError::Io {
                path: quarantine_dir.clone(),
                source,
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with(&prefix) && name.ends_with(".partial") {
                fs::remove_dir_all(entry.path()).map_err(|source| PackCacheError::Io {
                    path: entry.path(),
                    source,
                })?;
            }
        }
        Ok(())
    }

    fn staging_dir(&self, pack_hash: &Sha256Hex) -> Result<PathBuf, PackCacheError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| PackCacheError::Clock(source.to_string()))?
            .as_nanos();
        Ok(self
            .quarantine_dir()
            .join(format!("{}.{}.partial", pack_hash.as_str(), nonce)))
    }
}

impl Default for PackCache {
    fn default() -> Self {
        Self::new(Self::default_path())
    }
}

fn status_pack_hash(status: &PackCacheStatusEntry) -> Option<Sha256Hex> {
    status
        .index
        .as_ref()
        .map(|index| index.pack_hash.clone())
        .or_else(|| Sha256Hex::new(status.directory_name.clone()).ok())
}

fn prune_candidate_reason(readiness: PackCacheReadiness) -> Option<PackPruneReason> {
    match readiness {
        PackCacheReadiness::Ready => None,
        PackCacheReadiness::Expired => Some(PackPruneReason::Expired),
        PackCacheReadiness::MissingIndex
        | PackCacheReadiness::MalformedIndex
        | PackCacheReadiness::UnsupportedIndexSchema
        | PackCacheReadiness::DirectoryHashMismatch => Some(PackPruneReason::InvalidMetadata),
    }
}

fn directory_size_bytes(path: &Path) -> Result<u64, PackCacheError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PackCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }

    let mut total = 0u64;
    let entries = fs::read_dir(path).map_err(|source| PackCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| PackCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        total = total
            .checked_add(directory_size_bytes(&entry.path())?)
            .ok_or(PackCacheError::SizeOverflow)?;
    }
    Ok(total)
}

fn status_entry_for_dir(
    directory_name: String,
    root: PathBuf,
    now: DateTime<Utc>,
) -> PackCacheStatusEntry {
    let index_path = root.join(INDEX_FILENAME);
    let index_bytes = match fs::read(&index_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return PackCacheStatusEntry {
                directory_name,
                root,
                index: None,
                readiness: PackCacheReadiness::MissingIndex,
                detail: Some("cache index missing".to_string()),
            };
        }
        Err(err) => {
            return PackCacheStatusEntry {
                directory_name,
                root,
                index: None,
                readiness: PackCacheReadiness::MalformedIndex,
                detail: Some(format!("cache index unreadable: {err}")),
            };
        }
    };
    let index: PackCacheIndex = match serde_json::from_slice(&index_bytes) {
        Ok(index) => index,
        Err(err) => {
            return PackCacheStatusEntry {
                directory_name,
                root,
                index: None,
                readiness: PackCacheReadiness::MalformedIndex,
                detail: Some(format!("cache index malformed: {err}")),
            };
        }
    };
    let readiness = if index.schema_version != PACK_CACHE_SCHEMA_VERSION {
        PackCacheReadiness::UnsupportedIndexSchema
    } else if index.pack_hash.as_str() != directory_name {
        PackCacheReadiness::DirectoryHashMismatch
    } else if index.expires_at <= now {
        PackCacheReadiness::Expired
    } else {
        PackCacheReadiness::Ready
    };
    let detail = match readiness {
        PackCacheReadiness::Ready => None,
        PackCacheReadiness::Expired => Some("trust metadata expired".to_string()),
        PackCacheReadiness::UnsupportedIndexSchema => Some(format!(
            "cache index schema version {} is unsupported",
            index.schema_version
        )),
        PackCacheReadiness::DirectoryHashMismatch => Some(format!(
            "cache directory name does not match pack hash {}",
            index.pack_hash.as_str()
        )),
        PackCacheReadiness::MissingIndex | PackCacheReadiness::MalformedIndex => None,
    };
    PackCacheStatusEntry {
        directory_name,
        root,
        index: Some(index),
        readiness,
        detail,
    }
}

impl PackCacheIndex {
    pub fn from_manifest(
        manifest: &PackManifest,
        last_verified_at: DateTime<Utc>,
    ) -> Result<Self, PackCacheError> {
        Ok(Self {
            schema_version: PACK_CACHE_SCHEMA_VERSION,
            pack_hash: manifest.outputs.pack_hash.clone(),
            kind: manifest.kind.clone(),
            target_arch: manifest.target_arch,
            backend_compatibility: manifest.backend_compatibility.clone(),
            channel_identity: manifest.trust.channel_identity.clone(),
            expires_at: manifest.trust.expires_at,
            size_bytes: manifest
                .outputs
                .files
                .iter()
                .map(|file| file.size_bytes)
                .try_fold(0u64, |sum, size| {
                    sum.checked_add(size).ok_or(PackCacheError::SizeOverflow)
                })?,
            file_count: manifest.outputs.files.len(),
            last_used_at: last_verified_at,
            last_verified_at,
        })
    }
}

fn ensure_private_dir(path: &Path) -> Result<(), PackCacheError> {
    fs::create_dir_all(path).map_err(|source| PackCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|source| PackCacheError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        if perms.mode() & 0o777 != 0o700 {
            perms.set_mode(0o700);
            fs::set_permissions(path, perms).map_err(|source| PackCacheError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
    }
    Ok(())
}

fn write_restricted_file(path: &Path, bytes: &[u8]) -> Result<(), PackCacheError> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    fs::write(path, bytes).map_err(|source| PackCacheError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    set_restricted_file_permissions(path)
}

fn copy_regular_file_restricted(source: &Path, destination: &Path) -> Result<(), PackCacheError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| PackCacheError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if !metadata.file_type().is_file() {
        return Err(PackCacheError::NonRegularSource(source.to_path_buf()));
    }
    if let Some(parent) = destination.parent() {
        ensure_private_dir(parent)?;
    }
    fs::copy(source, destination).map_err(|source_error| PackCacheError::Io {
        path: destination.to_path_buf(),
        source: source_error,
    })?;
    set_restricted_file_permissions(destination)
}

fn set_restricted_file_permissions(path: &Path) -> Result<(), PackCacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|source| PackCacheError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        if perms.mode() & 0o777 != 0o600 {
            perms.set_mode(0o600);
            fs::set_permissions(path, perms).map_err(|source| PackCacheError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PackCacheError {
    #[error("pack {0:?} is not cached")]
    NotFound(Sha256Hex),
    #[error("source pack verification failed: {0}")]
    VerifySource(#[source] PackVerifyError),
    #[error("staged pack verification failed: {0}")]
    VerifyStaging(#[source] PackVerifyError),
    #[error("cached pack verification failed: {0}")]
    VerifyCached(#[source] PackVerifyError),
    #[error("cache directory hash mismatch: requested {requested:?}, manifest has {manifest:?}")]
    PackHashDirectoryMismatch {
        requested: Sha256Hex,
        manifest: Sha256Hex,
    },
    #[error("pack cache size overflow")]
    SizeOverflow,
    #[error("pack source file is not a regular file: {0}")]
    NonRegularSource(PathBuf),
    #[error("pack cache clock error: {0}")]
    Clock(String),
    #[error("pack cache filesystem error at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Manifest(#[from] super::PackManifestError),
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::fs;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use tempfile::TempDir;

    use super::*;
    use crate::arch::GuestArch;
    use crate::packs::{
        EMPTY_PACK_HASH, FlakeLockIdentity, HostCapability, OciDigest, OciInputIdentity, PackFile,
        PackInputs, PackOutputs, PackProvenance, PackSignature, PolicyCompatibility,
        ReproducibilityStatus, RevocationStatus, SbomReference, SetupCommandIdentity,
        SignatureBundle, SignatureFormat, SignaturePayload, SourceRevisionIdentity, TrustMetadata,
    };
    use crate::plan::bundle::KeyId;

    struct MapTrustStore {
        keys: HashMap<KeyId, VerifyingKey>,
    }

    impl PackTrustStore for MapTrustStore {
        fn verifying_key(&self, key_id: &KeyId) -> Option<VerifyingKey> {
            self.keys.get(key_id).copied()
        }
    }

    struct StaticRevocation;

    impl PackRevocationChecker for StaticRevocation {
        fn status(&self, _key_id: &KeyId, _pack_hash: &Sha256Hex) -> RevocationStatus {
            RevocationStatus::Good
        }
    }

    struct Fixture {
        source: TempDir,
        cache: PackCache,
        manifest: PackManifest,
        policy: LocalPackPolicy,
        trust: MapTrustStore,
        revocations: StaticRevocation,
    }

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid test timestamp")
    }

    fn hash(value: &str) -> Sha256Hex {
        Sha256Hex::from_bytes(value.as_bytes())
    }

    fn digest(value: &str) -> OciDigest {
        OciDigest::new(format!("sha256:{}", hash(value).as_str())).expect("valid digest")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn fixture() -> Fixture {
        let source = TempDir::new().expect("source tempdir");
        fs::create_dir_all(source.path().join("runtime")).expect("mkdir runtime");
        fs::write(source.path().join("runtime/kernel"), b"kernel").expect("write kernel");
        fs::write(source.path().join("runtime/initramfs"), b"initramfs").expect("write initramfs");

        let cache_root = TempDir::new().expect("cache tempdir");
        let cache = PackCache::new(cache_root.keep());
        let key = signing_key();
        let key_id = KeyId::from_pubkey(&key.verifying_key());
        let policy_hash = hash("policy");
        let now = utc(2026, 6, 24);
        let mut manifest = PackManifest {
            schema_version: crate::packs::PACK_SCHEMA_VERSION,
            kind: PackKind::Runtime,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Libkrun],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: policy_hash.clone(),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            inputs: PackInputs {
                flake_locks: vec![FlakeLockIdentity {
                    reference: "github:tinylabs/mvm".to_string(),
                    lock_hash: hash("flake-lock"),
                }],
                derivations: Vec::new(),
                nar_hashes: Vec::new(),
                oci_images: vec![OciInputIdentity {
                    reference: format!("ghcr.io/tinylabs/mvm@{}", digest("oci").as_str()),
                    digest: Some(digest("oci")),
                }],
                setup_commands: vec![SetupCommandIdentity {
                    command_hash: hash("setup"),
                    environment_hash: hash("env"),
                }],
                source_revisions: vec![SourceRevisionIdentity {
                    repository: "https://github.com/tinylabs/mvm".to_string(),
                    revision: "abc123".to_string(),
                    tree_hash: hash("tree"),
                }],
                toolchain_versions: BTreeMap::from([("rustc".to_string(), "1.90.0".to_string())]),
            },
            outputs: PackOutputs {
                pack_hash: Sha256Hex::new(EMPTY_PACK_HASH).expect("zero hash"),
                files: vec![
                    PackFile {
                        path: "runtime/kernel".to_string(),
                        sha256: hash("kernel"),
                        size_bytes: 6,
                    },
                    PackFile {
                        path: "runtime/initramfs".to_string(),
                        sha256: hash("initramfs"),
                        size_bytes: 9,
                    },
                ],
                closure_hash: Some(hash("closure")),
                rootfs_hash: None,
                kernel_hash: Some(hash("kernel")),
                initramfs_hash: Some(hash("initramfs")),
                agent_rootfs_hash: None,
                builder_image_hash: None,
            },
            provenance: PackProvenance {
                builder_identity: "ci-builder".to_string(),
                build_environment_identity: "github-actions".to_string(),
                build_timestamp: utc(2026, 6, 23),
                reproducibility: ReproducibilityStatus::Reproduced,
                sbom: SbomReference {
                    uri: "https://example.test/sbom.spdx.json".to_string(),
                    sha256: hash("sbom"),
                },
                signature_bundle: SignatureBundle {
                    format: SignatureFormat::Ed25519,
                    payload: SignaturePayload::ManifestV1,
                    signatures: Vec::new(),
                },
            },
            trust: TrustMetadata {
                signing_key_id: key_id.clone(),
                expires_at: utc(2026, 12, 31),
                revocation_channel: "https://example.test/revocations.json".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
        };
        manifest.outputs.pack_hash = manifest.computed_pack_hash().expect("pack hash");
        let signature = key.sign(&manifest.signature_payload_bytes().expect("payload"));
        manifest
            .provenance
            .signature_bundle
            .signatures
            .push(PackSignature {
                key_id: key_id.clone(),
                signature_base64: B64.encode(signature.to_bytes()),
                signed_at: now,
                expires_at: utc(2026, 12, 31),
            });
        let policy = LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Libkrun,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash,
            allowed_channels: BTreeSet::from(["stable".to_string()]),
            now,
        };
        let trust = MapTrustStore {
            keys: HashMap::from([(key_id, key.verifying_key())]),
        };
        Fixture {
            source,
            cache,
            manifest,
            policy,
            trust,
            revocations: StaticRevocation,
        }
    }

    #[test]
    fn default_path_lives_under_mvm_cache_dir() {
        let root = PackCache::default_path();
        assert!(root.ends_with(PACK_CACHE_DIR_NAME));
        assert!(root.starts_with(PathBuf::from(crate::config::mvm_cache_dir())));
    }

    #[test]
    fn install_promotes_verified_pack_and_resolve_reverifies() {
        let f = fixture();
        let cached = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install");
        assert_eq!(cached.verified.pack_hash, f.manifest.outputs.pack_hash);
        assert!(cached.root.join(MANIFEST_FILENAME).is_file());
        assert!(cached.root.join(INDEX_FILENAME).is_file());
        assert!(cached.root.join("runtime/kernel").is_file());
        assert_eq!(cached.index.file_count, 2);
        assert_eq!(cached.index.last_used_at, f.policy.now);

        let mut later_policy = f.policy.clone();
        later_policy.now = utc(2026, 6, 25);
        let resolved = f
            .cache
            .resolve_verified(
                &f.manifest.outputs.pack_hash,
                &later_policy,
                &f.trust,
                &f.revocations,
            )
            .expect("resolve");
        assert_eq!(resolved.verified.pack_hash, f.manifest.outputs.pack_hash);
        assert_eq!(resolved.index.last_used_at, later_policy.now);
    }

    #[test]
    fn status_entries_report_ready_expired_and_corrupt_entries() {
        let f = fixture();
        let cached = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install");

        let entries = f
            .cache
            .status_entries(f.policy.now)
            .expect("status entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].readiness, PackCacheReadiness::Ready);
        assert_eq!(entries[0].index.as_ref(), Some(&cached.index));

        let mut expired = cached.index.clone();
        expired.expires_at = utc(2026, 1, 1);
        write_restricted_file(
            &cached.root.join(INDEX_FILENAME),
            &serde_json::to_vec(&expired).expect("serialize expired index"),
        )
        .expect("write expired index");

        let malformed_dir = f.cache.by_hash_dir().join(hash("malformed").as_str());
        fs::create_dir_all(&malformed_dir).expect("malformed dir");
        fs::write(malformed_dir.join(INDEX_FILENAME), b"not json").expect("malformed index");

        let missing_dir = f.cache.by_hash_dir().join(hash("missing").as_str());
        fs::create_dir_all(&missing_dir).expect("missing dir");

        let mismatch_dir = f.cache.by_hash_dir().join(hash("mismatch").as_str());
        fs::create_dir_all(&mismatch_dir).expect("mismatch dir");
        write_restricted_file(
            &mismatch_dir.join(INDEX_FILENAME),
            &serde_json::to_vec(&cached.index).expect("serialize mismatch index"),
        )
        .expect("write mismatch index");

        let entries = f
            .cache
            .status_entries(f.policy.now)
            .expect("status entries");
        let readiness: BTreeMap<String, PackCacheReadiness> = entries
            .into_iter()
            .map(|entry| (entry.directory_name, entry.readiness))
            .collect();
        assert_eq!(
            readiness.get(cached.verified.pack_hash.as_str()),
            Some(&PackCacheReadiness::Expired)
        );
        assert_eq!(
            readiness.get(hash("malformed").as_str()),
            Some(&PackCacheReadiness::MalformedIndex)
        );
        assert_eq!(
            readiness.get(hash("missing").as_str()),
            Some(&PackCacheReadiness::MissingIndex)
        );
        assert_eq!(
            readiness.get(hash("mismatch").as_str()),
            Some(&PackCacheReadiness::DirectoryHashMismatch)
        );
    }

    #[test]
    fn protection_ref_roundtrips_through_json() {
        let protection = PackProtectionRef {
            pack_hash: hash("protected"),
            owner_kind: PackProtectionOwnerKind::Snapshot,
            owner_id: "checkpoint-a".to_string(),
        };

        let json = serde_json::to_string(&protection).expect("serialize protection");
        let back: PackProtectionRef = serde_json::from_str(&json).expect("parse protection");
        assert_eq!(back, protection);
        assert!(json.contains("snapshot"));
    }

    #[test]
    fn prune_removes_expired_and_invalid_entries_but_keeps_ready() {
        let f = fixture();
        let cached = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install");
        let mut expired = cached.index.clone();
        expired.expires_at = utc(2026, 1, 1);
        write_restricted_file(
            &cached.root.join(INDEX_FILENAME),
            &serde_json::to_vec(&expired).expect("serialize expired index"),
        )
        .expect("write expired index");

        let malformed_dir = f.cache.by_hash_dir().join(hash("malformed").as_str());
        fs::create_dir_all(&malformed_dir).expect("malformed dir");
        fs::write(malformed_dir.join(INDEX_FILENAME), b"not json").expect("malformed index");

        let ready_hash = f.manifest.outputs.pack_hash.clone();
        write_restricted_file(
            &cached.root.join(INDEX_FILENAME),
            &serde_json::to_vec(&cached.index).expect("serialize ready index"),
        )
        .expect("restore ready index");
        let mut expired_index = cached.index.clone();
        expired_index.pack_hash = hash("expired");
        expired_index.expires_at = utc(2026, 1, 1);
        let expired_dir = f.cache.by_hash_dir().join(expired_index.pack_hash.as_str());
        fs::create_dir_all(&expired_dir).expect("expired dir");
        write_restricted_file(
            &expired_dir.join(INDEX_FILENAME),
            &serde_json::to_vec(&expired_index).expect("serialize expired index"),
        )
        .expect("write expired index");

        let report = f
            .cache
            .prune(&PackPruneRequest {
                now: f.policy.now,
                dry_run: false,
                protected: Vec::new(),
            })
            .expect("prune");

        assert_eq!(report.removed_count(), 2);
        assert!(f.cache.pack_dir(&ready_hash).is_dir(), "ready pack is kept");
        assert!(!malformed_dir.exists(), "malformed entry is removed");
        assert!(!expired_dir.exists(), "expired entry is removed");
        assert!(report.entries.iter().any(|entry| {
            entry.pack_hash.as_ref() == Some(&ready_hash)
                && entry.action == PackPruneAction::Retained
                && entry.reason == PackPruneReason::Ready
        }));
    }

    #[test]
    fn prune_dry_run_reports_without_removing() {
        let f = fixture();
        let expired_hash = hash("expired-dry-run");
        let expired_dir = f.cache.by_hash_dir().join(expired_hash.as_str());
        fs::create_dir_all(&expired_dir).expect("expired dir");
        let index = PackCacheIndex {
            schema_version: PACK_CACHE_SCHEMA_VERSION,
            pack_hash: expired_hash.clone(),
            kind: PackKind::Runtime,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Libkrun],
            channel_identity: "stable".to_string(),
            expires_at: utc(2026, 1, 1),
            size_bytes: 1,
            file_count: 0,
            last_used_at: utc(2026, 1, 1),
            last_verified_at: utc(2026, 1, 1),
        };
        write_restricted_file(
            &expired_dir.join(INDEX_FILENAME),
            &serde_json::to_vec(&index).expect("serialize index"),
        )
        .expect("write index");

        let report = f
            .cache
            .prune(&PackPruneRequest {
                now: f.policy.now,
                dry_run: true,
                protected: Vec::new(),
            })
            .expect("prune");

        assert_eq!(report.would_remove_count(), 1);
        assert_eq!(report.removed_count(), 0);
        assert!(expired_dir.is_dir(), "dry-run keeps the pack directory");
    }

    #[test]
    fn prune_retains_protected_expired_pack() {
        let f = fixture();
        let protected_hash = hash("protected-expired");
        let protected_dir = f.cache.by_hash_dir().join(protected_hash.as_str());
        fs::create_dir_all(&protected_dir).expect("protected dir");
        let index = PackCacheIndex {
            schema_version: PACK_CACHE_SCHEMA_VERSION,
            pack_hash: protected_hash.clone(),
            kind: PackKind::Runtime,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Libkrun],
            channel_identity: "stable".to_string(),
            expires_at: utc(2026, 1, 1),
            size_bytes: 1,
            file_count: 0,
            last_used_at: utc(2026, 1, 1),
            last_verified_at: utc(2026, 1, 1),
        };
        write_restricted_file(
            &protected_dir.join(INDEX_FILENAME),
            &serde_json::to_vec(&index).expect("serialize index"),
        )
        .expect("write index");

        let protection = PackProtectionRef {
            pack_hash: protected_hash.clone(),
            owner_kind: PackProtectionOwnerKind::WarmStandby,
            owner_id: "standby-a".to_string(),
        };
        let report = f
            .cache
            .prune(&PackPruneRequest {
                now: f.policy.now,
                dry_run: false,
                protected: vec![protection.clone()],
            })
            .expect("prune");

        assert_eq!(report.removed_count(), 0);
        assert_eq!(report.protected_count(), 1);
        assert!(protected_dir.is_dir(), "protected pack is retained");
        assert!(report.entries.iter().any(|entry| {
            entry.pack_hash.as_ref() == Some(&protected_hash)
                && entry.action == PackPruneAction::Retained
                && entry.reason == PackPruneReason::Protected
                && entry.protections == vec![protection.clone()]
        }));
    }

    #[test]
    #[cfg(unix)]
    fn prune_ignores_symlinked_pack_directory() {
        let f = fixture();
        let outside = TempDir::new().expect("outside tempdir");
        fs::write(outside.path().join("sentinel"), b"keep").expect("write sentinel");
        fs::create_dir_all(f.cache.by_hash_dir()).expect("by-hash dir");
        let link_hash = hash("symlink");
        std::os::unix::fs::symlink(outside.path(), f.cache.pack_dir(&link_hash))
            .expect("symlink pack dir");

        let report = f
            .cache
            .prune(&PackPruneRequest {
                now: f.policy.now,
                dry_run: false,
                protected: Vec::new(),
            })
            .expect("prune");

        assert!(report.entries.is_empty());
        assert!(
            outside.path().join("sentinel").is_file(),
            "prune must not follow or remove symlinked cache entries"
        );
    }

    #[test]
    fn tampered_source_never_promotes_from_quarantine() {
        let f = fixture();
        fs::write(f.source.path().join("runtime/kernel"), b"tampered").expect("tamper source");
        let err = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect_err("tampered source rejected");
        assert!(matches!(err, PackCacheError::VerifySource(_)));
        assert!(!f.cache.pack_dir(&f.manifest.outputs.pack_hash).exists());
    }

    #[test]
    fn cached_pack_is_reverified_before_use() {
        let f = fixture();
        let cached = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install");
        fs::write(cached.root.join("runtime/kernel"), b"poison").expect("poison cached file");
        let err = f
            .cache
            .resolve_verified(
                &f.manifest.outputs.pack_hash,
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect_err("poisoned cache rejected");
        assert!(matches!(err, PackCacheError::VerifyCached(_)));
    }

    #[test]
    fn stale_quarantine_dir_is_cleaned_before_install() {
        let f = fixture();
        let stale = f.cache.quarantine_dir().join(format!(
            "{}.123.partial",
            f.manifest.outputs.pack_hash.as_str()
        ));
        fs::create_dir_all(&stale).expect("stale quarantine");
        fs::write(stale.join("junk"), b"junk").expect("write junk");

        f.cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install");
        assert!(
            !f.cache
                .quarantine_dir()
                .read_dir()
                .expect("read quarantine")
                .any(|entry| entry.expect("entry").path().join("junk").exists())
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_permissions_are_restrictive() {
        use std::os::unix::fs::PermissionsExt;

        let f = fixture();
        let cached = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install");
        assert_eq!(
            fs::metadata(f.cache.root())
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(cached.root.join("runtime/kernel"))
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_source_file_is_rejected() {
        use std::os::unix::fs::symlink;

        let f = fixture();
        fs::remove_file(f.source.path().join("runtime/kernel")).expect("remove kernel");
        symlink("/etc/passwd", f.source.path().join("runtime/kernel")).expect("symlink");
        let err = f
            .cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect_err("symlink source rejected");
        assert!(matches!(err, PackCacheError::VerifySource(_)));
    }
}
