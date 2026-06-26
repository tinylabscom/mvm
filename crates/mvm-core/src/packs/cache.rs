//! Content-addressed local cache for verified attested packs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    LocalPackPolicy, PackBackend, PackKind, PackManifest, PackPolicyMode, PackRevocationChecker,
    PackTrustStore, PackVerifyError, SetupCacheLayerIdentity, Sha256Hex, VerifiedPack,
    verify_pack_at,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPrepareRequest {
    pub input: PackPrepareInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_kind: Option<PackKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_setup_cache_layers: Vec<SetupCacheLayerIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPrepareInput {
    pub raw: String,
    pub kind: PackPrepareInputKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flake_lock_hash: Option<Sha256Hex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPrepareInputKind {
    OciImage,
    Flake,
    LocalPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPrepareReport {
    pub input: PackPrepareInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_pack_hash: Option<Sha256Hex>,
    pub state: PackPrepareState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<PackPrepareReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<PackKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub builder_vm_required: bool,
    pub download_required: bool,
    pub fast_path_eligible: bool,
    pub trust_state: PackTrustState,
    #[serde(default)]
    pub setup_cache: PackPrepareSetupCacheReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPrepareState {
    Ready,
    Missing,
    RequiresBuilder,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPrepareReason {
    MissingPack,
    MutableInput,
    PrivateInput,
    ExpiredSignature,
    ExpiredTrustMetadata,
    RevokedSigner,
    UnsupportedBackend,
    IncompatibleHost,
    LocalRebuildRequired,
    PolicyRefusal,
    TrustUnavailable,
    CacheMetadataInvalid,
    InputMismatch,
    SetupCacheMiss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackTrustState {
    Verified,
    NotChecked,
    Untrusted,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPrepareSetupCacheReport {
    pub state: PackPrepareSetupCacheState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<PackPrepareSetupCacheLayerReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPrepareSetupCacheState {
    NotRequested,
    Hit,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackPrepareSetupCacheLayerReport {
    pub cache_key: Sha256Hex,
    pub state: PackPrepareSetupCacheLayerState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPrepareSetupCacheLayerState {
    Hit,
    Missing,
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

    pub fn install_from_archive_reader<R: Read>(
        &self,
        archive: R,
        policy: &LocalPackPolicy,
        trust: &dyn PackTrustStore,
        revocations: &dyn PackRevocationChecker,
    ) -> Result<CachedPack, PackCacheError> {
        self.ensure_layout()?;
        let staging = self.archive_staging_dir()?;
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|source| PackCacheError::Io {
                path: staging.clone(),
                source,
            })?;
        }
        ensure_private_dir(&staging)?;
        let result =
            self.install_from_archive_reader_inner(&staging, archive, policy, trust, revocations);
        if result.is_err() && staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn install_from_archive_reader_inner<R: Read>(
        &self,
        staging: &Path,
        archive: R,
        policy: &LocalPackPolicy,
        trust: &dyn PackTrustStore,
        revocations: &dyn PackRevocationChecker,
    ) -> Result<CachedPack, PackCacheError> {
        extract_pack_archive(archive, staging)?;
        let manifest_path = staging.join(MANIFEST_FILENAME);
        let manifest_bytes = fs::read(&manifest_path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                PackCacheError::MissingArchiveManifest
            } else {
                PackCacheError::Io {
                    path: manifest_path.clone(),
                    source,
                }
            }
        })?;
        let manifest: PackManifest = serde_json::from_slice(&manifest_bytes)?;
        let verified = verify_pack_at(&manifest, staging, policy, trust, revocations)
            .map_err(PackCacheError::VerifyStaging)?;

        let final_dir = self.pack_dir(&verified.pack_hash);
        if final_dir.exists() {
            fs::remove_dir_all(staging).map_err(|source| PackCacheError::Io {
                path: staging.to_path_buf(),
                source,
            })?;
            return self.resolve_verified(&verified.pack_hash, policy, trust, revocations);
        }

        self.clean_stale_quarantine_for_pack(&verified.pack_hash)?;
        let index = PackCacheIndex::from_manifest(&manifest, policy.now)?;
        write_restricted_file(
            &staging.join(INDEX_FILENAME),
            &serde_json::to_vec(&index).map_err(PackCacheError::Json)?,
        )?;
        verify_pack_at(&manifest, staging, policy, trust, revocations)
            .map_err(PackCacheError::VerifyStaging)?;
        fs::rename(staging, &final_dir).map_err(|source| PackCacheError::Io {
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

    pub fn prepare_report(
        &self,
        request: &PackPrepareRequest,
        policy: &LocalPackPolicy,
        trust: &dyn PackTrustStore,
        revocations: &dyn PackRevocationChecker,
    ) -> Result<PackPrepareReport, PackCacheError> {
        if policy.policy_mode == PackPolicyMode::LocalRebuildRequired {
            return Ok(PackPrepareReport::requires_builder_without_pack(
                request,
                PackPrepareReason::LocalRebuildRequired,
                "local policy requires builder preparation for this input",
            ));
        }
        if request.input.kind == PackPrepareInputKind::OciImage
            && !request.input.raw.contains("@sha256:")
        {
            return Ok(PackPrepareReport::refused(
                request,
                PackPrepareReason::MutableInput,
                PackTrustState::NotChecked,
                "OCI input must be pinned to a digest for attested fast launch",
            ));
        }

        let mut input_mismatch = false;
        for status in self.status_entries(policy.now)? {
            let Some(index) = &status.index else {
                continue;
            };
            if let Some(expected_hash) = &request.pack_hash
                && &index.pack_hash != expected_hash
            {
                continue;
            }
            if let Some(expected_kind) = &request.expected_kind
                && &index.kind != expected_kind
            {
                continue;
            }

            let manifest = match read_cached_manifest(&status.root) {
                Ok(manifest) => manifest,
                Err(error) => {
                    if request.pack_hash.as_ref() == Some(&index.pack_hash) {
                        return Ok(PackPrepareReport::refused_for_index(
                            request,
                            index,
                            &status.root,
                            PackPrepareReason::CacheMetadataInvalid,
                            PackTrustState::Untrusted,
                            error.to_string(),
                        ));
                    }
                    continue;
                }
            };
            if !manifest_matches_input(&manifest, &request.input) {
                input_mismatch = true;
                continue;
            }
            return Ok(prepare_report_for_manifest(
                request,
                &status,
                index,
                &manifest,
                policy,
                trust,
                revocations,
            ));
        }

        if request.pack_hash.is_some() && input_mismatch {
            return Ok(PackPrepareReport::refused(
                request,
                PackPrepareReason::InputMismatch,
                PackTrustState::NotChecked,
                "cached pack does not match the requested input",
            ));
        }

        Ok(PackPrepareReport::missing(request))
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

    fn archive_staging_dir(&self) -> Result<PathBuf, PackCacheError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|source| PackCacheError::Clock(source.to_string()))?
            .as_nanos();
        Ok(self
            .quarantine_dir()
            .join(format!("archive.{nonce}.partial")))
    }
}

impl PackPrepareReport {
    fn ready_with_setup_cache(
        request: &PackPrepareRequest,
        index: &PackCacheIndex,
        root: &Path,
        setup_cache: PackPrepareSetupCacheReport,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::Ready,
            reason: None,
            pack_hash: Some(index.pack_hash.clone()),
            kind: Some(index.kind.clone()),
            cache_root: Some(root.to_path_buf()),
            size_bytes: Some(index.size_bytes),
            builder_vm_required: false,
            download_required: false,
            fast_path_eligible: true,
            trust_state: PackTrustState::Verified,
            setup_cache,
            detail: Some(detail.into()),
        }
    }

    fn missing(request: &PackPrepareRequest) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::Missing,
            reason: Some(PackPrepareReason::MissingPack),
            pack_hash: request.pack_hash.clone(),
            kind: request.expected_kind.clone(),
            cache_root: None,
            size_bytes: None,
            builder_vm_required: true,
            download_required: true,
            fast_path_eligible: false,
            trust_state: PackTrustState::NotChecked,
            setup_cache: PackPrepareSetupCacheReport::not_requested(),
            detail: Some("no matching verified pack is cached".to_string()),
        }
    }

    fn requires_builder_without_pack(
        request: &PackPrepareRequest,
        reason: PackPrepareReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::RequiresBuilder,
            reason: Some(reason),
            pack_hash: request.pack_hash.clone(),
            kind: request.expected_kind.clone(),
            cache_root: None,
            size_bytes: None,
            builder_vm_required: true,
            download_required: false,
            fast_path_eligible: false,
            trust_state: PackTrustState::NotChecked,
            setup_cache: PackPrepareSetupCacheReport::not_requested(),
            detail: Some(detail.into()),
        }
    }

    fn requires_builder(
        request: &PackPrepareRequest,
        index: &PackCacheIndex,
        root: &Path,
        reason: PackPrepareReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::RequiresBuilder,
            reason: Some(reason),
            pack_hash: Some(index.pack_hash.clone()),
            kind: Some(index.kind.clone()),
            cache_root: Some(root.to_path_buf()),
            size_bytes: Some(index.size_bytes),
            builder_vm_required: true,
            download_required: false,
            fast_path_eligible: false,
            trust_state: PackTrustState::NotChecked,
            setup_cache: PackPrepareSetupCacheReport::not_requested(),
            detail: Some(detail.into()),
        }
    }

    fn requires_builder_verified(
        request: &PackPrepareRequest,
        index: &PackCacheIndex,
        root: &Path,
        reason: PackPrepareReason,
        setup_cache: PackPrepareSetupCacheReport,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::RequiresBuilder,
            reason: Some(reason),
            pack_hash: Some(index.pack_hash.clone()),
            kind: Some(index.kind.clone()),
            cache_root: Some(root.to_path_buf()),
            size_bytes: Some(index.size_bytes),
            builder_vm_required: true,
            download_required: false,
            fast_path_eligible: false,
            trust_state: PackTrustState::Verified,
            setup_cache,
            detail: Some(detail.into()),
        }
    }

    fn refused(
        request: &PackPrepareRequest,
        reason: PackPrepareReason,
        trust_state: PackTrustState,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::Refused,
            reason: Some(reason),
            pack_hash: request.pack_hash.clone(),
            kind: request.expected_kind.clone(),
            cache_root: None,
            size_bytes: None,
            builder_vm_required: false,
            download_required: false,
            fast_path_eligible: false,
            trust_state,
            setup_cache: PackPrepareSetupCacheReport::not_requested(),
            detail: Some(detail.into()),
        }
    }

    fn refused_for_index(
        request: &PackPrepareRequest,
        index: &PackCacheIndex,
        root: &Path,
        reason: PackPrepareReason,
        trust_state: PackTrustState,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            input: request.input.clone(),
            requested_pack_hash: request.pack_hash.clone(),
            state: PackPrepareState::Refused,
            reason: Some(reason),
            pack_hash: Some(index.pack_hash.clone()),
            kind: Some(index.kind.clone()),
            cache_root: Some(root.to_path_buf()),
            size_bytes: Some(index.size_bytes),
            builder_vm_required: false,
            download_required: false,
            fast_path_eligible: false,
            trust_state,
            setup_cache: PackPrepareSetupCacheReport::not_requested(),
            detail: Some(detail.into()),
        }
    }
}

impl Default for PackPrepareSetupCacheReport {
    fn default() -> Self {
        Self::not_requested()
    }
}

impl PackPrepareSetupCacheReport {
    fn not_requested() -> Self {
        Self {
            state: PackPrepareSetupCacheState::NotRequested,
            layers: Vec::new(),
        }
    }

    fn for_manifest(
        required: &[SetupCacheLayerIdentity],
        manifest: &PackManifest,
    ) -> PackPrepareSetupCacheReport {
        if required.is_empty() {
            return Self::not_requested();
        }

        let declared_keys = manifest
            .inputs
            .setup_cache_layers
            .iter()
            .map(|layer| layer.cache_key().as_str().to_string())
            .collect::<BTreeSet<_>>();
        let mut layers = Vec::with_capacity(required.len());
        let mut all_hit = true;
        for layer in required {
            let cache_key = layer.cache_key();
            let hit = declared_keys.contains(cache_key.as_str());
            if !hit {
                all_hit = false;
            }
            layers.push(PackPrepareSetupCacheLayerReport {
                cache_key,
                state: if hit {
                    PackPrepareSetupCacheLayerState::Hit
                } else {
                    PackPrepareSetupCacheLayerState::Missing
                },
                detail: if hit {
                    None
                } else {
                    Some("required setup-cache layer identity is not declared by the pack".into())
                },
            });
        }

        Self {
            state: if all_hit {
                PackPrepareSetupCacheState::Hit
            } else {
                PackPrepareSetupCacheState::Missing
            },
            layers,
        }
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

fn read_cached_manifest(root: &Path) -> Result<PackManifest, PackCacheError> {
    let manifest_path = root.join(MANIFEST_FILENAME);
    let manifest_bytes = fs::read(&manifest_path).map_err(|source| PackCacheError::Io {
        path: manifest_path,
        source,
    })?;
    serde_json::from_slice(&manifest_bytes).map_err(PackCacheError::Json)
}

fn prepare_report_for_manifest(
    request: &PackPrepareRequest,
    status: &PackCacheStatusEntry,
    index: &PackCacheIndex,
    manifest: &PackManifest,
    policy: &LocalPackPolicy,
    trust: &dyn PackTrustStore,
    revocations: &dyn PackRevocationChecker,
) -> PackPrepareReport {
    if manifest.policy_compatibility.local_rebuild_required {
        return PackPrepareReport::requires_builder(
            request,
            index,
            &status.root,
            PackPrepareReason::LocalRebuildRequired,
            "pack policy declares that local rebuild is required",
        );
    }
    if status.readiness != PackCacheReadiness::Ready {
        return PackPrepareReport::refused_for_index(
            request,
            index,
            &status.root,
            reason_for_readiness(status.readiness),
            trust_state_for_readiness(status.readiness),
            status
                .detail
                .clone()
                .unwrap_or_else(|| "pack cache metadata is not ready".to_string()),
        );
    }
    match verify_pack_at(manifest, &status.root, policy, trust, revocations) {
        Ok(_) => {
            let setup_cache = PackPrepareSetupCacheReport::for_manifest(
                &request.required_setup_cache_layers,
                manifest,
            );
            if setup_cache.state == PackPrepareSetupCacheState::Missing {
                return PackPrepareReport::requires_builder_verified(
                    request,
                    index,
                    &status.root,
                    PackPrepareReason::SetupCacheMiss,
                    setup_cache,
                    "matching pack verified but required setup-cache layers are missing",
                );
            }
            PackPrepareReport::ready_with_setup_cache(
                request,
                index,
                &status.root,
                setup_cache,
                "matching pack verified and is eligible for fast launch",
            )
        }
        Err(error) => {
            let reason = reason_for_verify_error(&error);
            let trust_state = trust_state_for_verify_error(&error);
            PackPrepareReport::refused_for_index(
                request,
                index,
                &status.root,
                reason,
                trust_state,
                error.to_string(),
            )
        }
    }
}

fn manifest_matches_input(manifest: &PackManifest, input: &PackPrepareInput) -> bool {
    match input.kind {
        PackPrepareInputKind::OciImage => manifest
            .inputs
            .oci_images
            .iter()
            .any(|oci| oci.reference == input.raw),
        PackPrepareInputKind::Flake => manifest.inputs.flake_locks.iter().any(|flake| {
            flake.reference == input.raw
                && input
                    .flake_lock_hash
                    .as_ref()
                    .is_none_or(|lock_hash| &flake.lock_hash == lock_hash)
        }),
        PackPrepareInputKind::LocalPath => manifest
            .inputs
            .source_revisions
            .iter()
            .any(|source| source.repository == input.raw),
    }
}

fn reason_for_readiness(readiness: PackCacheReadiness) -> PackPrepareReason {
    match readiness {
        PackCacheReadiness::Ready => PackPrepareReason::CacheMetadataInvalid,
        PackCacheReadiness::Expired => PackPrepareReason::ExpiredTrustMetadata,
        PackCacheReadiness::MissingIndex
        | PackCacheReadiness::MalformedIndex
        | PackCacheReadiness::UnsupportedIndexSchema
        | PackCacheReadiness::DirectoryHashMismatch => PackPrepareReason::CacheMetadataInvalid,
    }
}

fn trust_state_for_readiness(readiness: PackCacheReadiness) -> PackTrustState {
    match readiness {
        PackCacheReadiness::Ready => PackTrustState::NotChecked,
        PackCacheReadiness::Expired => PackTrustState::Expired,
        PackCacheReadiness::MissingIndex
        | PackCacheReadiness::MalformedIndex
        | PackCacheReadiness::UnsupportedIndexSchema
        | PackCacheReadiness::DirectoryHashMismatch => PackTrustState::Untrusted,
    }
}

fn reason_for_verify_error(error: &PackVerifyError) -> PackPrepareReason {
    match error {
        PackVerifyError::IncompatibleArchitecture { .. } => PackPrepareReason::IncompatibleHost,
        PackVerifyError::IncompatibleBackend { .. } => PackPrepareReason::UnsupportedBackend,
        PackVerifyError::ExpiredSignature { .. } => PackPrepareReason::ExpiredSignature,
        PackVerifyError::ExpiredTrustMetadata { .. } => PackPrepareReason::ExpiredTrustMetadata,
        PackVerifyError::Revoked { .. } => PackPrepareReason::RevokedSigner,
        PackVerifyError::MutableOciReference { .. } => PackPrepareReason::MutableInput,
        PackVerifyError::MissingHostCapability(_)
        | PackVerifyError::PolicyHashMismatch { .. }
        | PackVerifyError::ChannelNotAllowed(_)
        | PackVerifyError::ChannelPolicyMissing(_)
        | PackVerifyError::ChannelSigningKeysMissing(_)
        | PackVerifyError::SigningKeyNotAllowedForChannel { .. }
        | PackVerifyError::MirrorIdentityMismatch { .. }
        | PackVerifyError::MirrorPolicyMissing(_) => PackPrepareReason::PolicyRefusal,
        PackVerifyError::LocalRebuildRequiredPolicy => PackPrepareReason::LocalRebuildRequired,
        PackVerifyError::UnknownSigningKey { .. }
        | PackVerifyError::SignatureInvalid
        | PackVerifyError::SignatureMissingForKey(_)
        | PackVerifyError::MalformedKeyId(_)
        | PackVerifyError::MalformedSignature(_)
        | PackVerifyError::SignatureBundleEmpty
        | PackVerifyError::UnsupportedSignatureBundle => PackPrepareReason::TrustUnavailable,
        PackVerifyError::UnsupportedSchemaVersion { .. }
        | PackVerifyError::MissingOutputHash(_)
        | PackVerifyError::InvalidSetupCacheLayer { .. }
        | PackVerifyError::UnsafeFilePath(_)
        | PackVerifyError::DuplicateFile(_)
        | PackVerifyError::FileReadFailed { .. }
        | PackVerifyError::FileSizeMismatch { .. }
        | PackVerifyError::FileHashMismatch { .. }
        | PackVerifyError::PackHashMismatch { .. }
        | PackVerifyError::Manifest(_) => PackPrepareReason::CacheMetadataInvalid,
    }
}

fn trust_state_for_verify_error(error: &PackVerifyError) -> PackTrustState {
    match error {
        PackVerifyError::ExpiredSignature { .. } | PackVerifyError::ExpiredTrustMetadata { .. } => {
            PackTrustState::Expired
        }
        PackVerifyError::Revoked { .. } => PackTrustState::Revoked,
        PackVerifyError::UnknownSigningKey { .. }
        | PackVerifyError::SignatureInvalid
        | PackVerifyError::SignatureMissingForKey(_)
        | PackVerifyError::MalformedKeyId(_)
        | PackVerifyError::MalformedSignature(_)
        | PackVerifyError::SignatureBundleEmpty
        | PackVerifyError::UnsupportedSignatureBundle => PackTrustState::Untrusted,
        _ => PackTrustState::NotChecked,
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

fn extract_pack_archive<R: Read>(archive: R, staging: &Path) -> Result<(), PackCacheError> {
    let mut archive = tar::Archive::new(archive);
    let entries = archive
        .entries()
        .map_err(|source| PackCacheError::ArchiveRead {
            path: PathBuf::from("<archive>"),
            source,
        })?;
    for entry in entries {
        let mut entry = entry.map_err(|source| PackCacheError::ArchiveRead {
            path: PathBuf::from("<archive>"),
            source,
        })?;
        let raw_path = entry.path().map_err(|source| PackCacheError::ArchiveRead {
            path: PathBuf::from("<archive>"),
            source,
        })?;
        let relative = safe_archive_path(raw_path.as_ref())?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let destination = staging.join(&relative);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            ensure_private_dir(&destination)?;
        } else if entry_type.is_file() {
            if let Some(parent) = destination.parent() {
                ensure_private_dir(parent)?;
            }
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|source| PackCacheError::Io {
                    path: destination.clone(),
                    source,
                })?;
            io::copy(&mut entry, &mut out).map_err(|source| PackCacheError::ArchiveRead {
                path: relative.clone(),
                source,
            })?;
            set_restricted_file_permissions(&destination)?;
        } else {
            return Err(PackCacheError::UnsupportedArchiveEntry {
                path: relative,
                entry_type: format!("{entry_type:?}"),
            });
        }
    }
    Ok(())
}

fn safe_archive_path(path: &Path) -> Result<PathBuf, PackCacheError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PackCacheError::UnsafeArchivePath(path.to_path_buf()));
            }
        }
    }
    Ok(out)
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
    #[error("pack archive is missing manifest.json")]
    MissingArchiveManifest,
    #[error("pack archive path is unsafe: {0}")]
    UnsafeArchivePath(PathBuf),
    #[error("pack archive entry {path} has unsupported type {entry_type}")]
    UnsupportedArchiveEntry { path: PathBuf, entry_type: String },
    #[error("pack archive read failed at {}: {source}", path.display())]
    ArchiveRead {
        path: PathBuf,
        source: std::io::Error,
    },
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
    use std::io::Cursor;

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
        ReproducibilityStatus, RevocationStatus, SbomReference, SetupCacheLayerIdentity,
        SetupCommandIdentity, SignatureBundle, SignatureFormat, SignaturePayload,
        SourceRevisionIdentity, TrustMetadata,
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

    struct StaticRevocation {
        status: RevocationStatus,
    }

    impl PackRevocationChecker for StaticRevocation {
        fn status(&self, _key_id: &KeyId, _pack_hash: &Sha256Hex) -> RevocationStatus {
            self.status.clone()
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
                setup_cache_layers: vec![SetupCacheLayerIdentity {
                    image_digest: Some(digest("oci")),
                    flake_lock_hash: Some(hash("flake-lock")),
                    setup_command_hash: hash("setup"),
                    environment_hash: hash("env"),
                    mount_shape_hash: hash("mounts"),
                    runtime_pack_hash: hash("runtime-pack"),
                    policy_hash: policy_hash.clone(),
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
            policy_mode: PackPolicyMode::OnlineDefault,
            channel_policies: BTreeMap::new(),
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
            revocations: StaticRevocation {
                status: RevocationStatus::Good,
            },
        }
    }

    fn prepare_request(input: String) -> PackPrepareRequest {
        PackPrepareRequest {
            input: PackPrepareInput {
                raw: input,
                kind: PackPrepareInputKind::OciImage,
                flake_lock_hash: None,
            },
            expected_kind: Some(PackKind::Runtime),
            pack_hash: None,
            required_setup_cache_layers: Vec::new(),
        }
    }

    fn flake_prepare_request(reference: &str, lock_hash: Sha256Hex) -> PackPrepareRequest {
        PackPrepareRequest {
            input: PackPrepareInput {
                raw: reference.to_string(),
                kind: PackPrepareInputKind::Flake,
                flake_lock_hash: Some(lock_hash),
            },
            expected_kind: Some(PackKind::Runtime),
            pack_hash: None,
            required_setup_cache_layers: Vec::new(),
        }
    }

    fn oci_input(f: &Fixture) -> String {
        f.manifest.inputs.oci_images[0].reference.clone()
    }

    fn setup_cache_layer(f: &Fixture) -> SetupCacheLayerIdentity {
        f.manifest.inputs.setup_cache_layers[0].clone()
    }

    fn prepare_request_with_setup_cache(
        input: String,
        layer: SetupCacheLayerIdentity,
    ) -> PackPrepareRequest {
        let mut request = prepare_request(input);
        request.required_setup_cache_layers = vec![layer];
        request
    }

    fn install_fixture_pack(f: &Fixture) -> CachedPack {
        f.cache
            .install_from_verified_root(
                &f.manifest,
                f.source.path(),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("install fixture pack")
    }

    fn resign_manifest(manifest: &mut PackManifest) {
        let key = signing_key();
        manifest.outputs.pack_hash = manifest.computed_pack_hash().expect("pack hash");
        let signature = key.sign(&manifest.signature_payload_bytes().expect("payload"));
        manifest.provenance.signature_bundle.signatures = vec![PackSignature {
            key_id: KeyId::from_pubkey(&key.verifying_key()),
            signature_base64: B64.encode(signature.to_bytes()),
            signed_at: utc(2026, 6, 24),
            expires_at: utc(2026, 12, 31),
        }];
    }

    fn append_archive_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("append archive file");
    }

    fn pack_archive_bytes(f: &Fixture) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        append_archive_file(
            &mut builder,
            MANIFEST_FILENAME,
            &f.manifest.canonical_bytes().expect("manifest bytes"),
        );
        append_archive_file(&mut builder, "runtime/kernel", b"kernel");
        append_archive_file(&mut builder, "runtime/initramfs", b"initramfs");
        builder.finish().expect("finish archive");
        builder.into_inner().expect("archive bytes")
    }

    fn archive_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in files {
            append_archive_file(&mut builder, path, bytes);
        }
        builder.finish().expect("finish archive");
        builder.into_inner().expect("archive bytes")
    }

    fn raw_archive_with_file_path(path: &str, bytes: &[u8]) -> Vec<u8> {
        fn write_octal(field: &mut [u8], value: u64) {
            field.fill(0);
            let digits = format!("{value:0width$o}", width = field.len() - 1);
            field[..digits.len()].copy_from_slice(digits.as_bytes());
        }

        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], bytes.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let checksum_digits = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_digits.as_bytes());

        let mut archive = Vec::from(header);
        archive.extend_from_slice(bytes);
        let padding = (512 - (bytes.len() % 512)) % 512;
        archive.resize(archive.len() + padding, 0);
        archive.extend_from_slice(&[0u8; 1024]);
        archive
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
    fn prepare_report_marks_matching_cached_pack_ready() {
        let f = fixture();
        let cached = install_fixture_pack(&f);
        let report = f
            .cache
            .prepare_report(
                &prepare_request(oci_input(&f)),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Ready);
        assert_eq!(report.pack_hash, Some(cached.verified.pack_hash));
        assert_eq!(report.trust_state, PackTrustState::Verified);
        assert!(report.fast_path_eligible);
        assert!(!report.builder_vm_required);
        assert_eq!(
            report.setup_cache.state,
            PackPrepareSetupCacheState::NotRequested
        );
    }

    #[test]
    fn prepare_request_defaults_required_setup_cache_layers_for_older_json() {
        let request: PackPrepareRequest = serde_json::from_value(serde_json::json!({
            "input": {
                "raw": "ghcr.io/tinylabs/mvm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "kind": "oci_image"
            },
            "expected_kind": "runtime"
        }))
        .expect("old request shape deserializes");

        assert!(request.required_setup_cache_layers.is_empty());
    }

    #[test]
    fn prepare_report_marks_required_setup_cache_hit_ready() {
        let f = fixture();
        let cached = install_fixture_pack(&f);
        let layer = setup_cache_layer(&f);
        let expected_key = layer.cache_key();
        let report = f
            .cache
            .prepare_report(
                &prepare_request_with_setup_cache(oci_input(&f), layer),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Ready);
        assert_eq!(report.pack_hash, Some(cached.verified.pack_hash));
        assert_eq!(report.trust_state, PackTrustState::Verified);
        assert_eq!(report.setup_cache.state, PackPrepareSetupCacheState::Hit);
        assert_eq!(report.setup_cache.layers.len(), 1);
        assert_eq!(report.setup_cache.layers[0].cache_key, expected_key);
        assert_eq!(
            report.setup_cache.layers[0].state,
            PackPrepareSetupCacheLayerState::Hit
        );
        assert!(report.fast_path_eligible);
        assert!(!report.builder_vm_required);
    }

    #[test]
    fn prepare_report_requires_builder_when_setup_cache_layer_missing() {
        let f = fixture();
        install_fixture_pack(&f);
        let mut layer = setup_cache_layer(&f);
        layer.setup_command_hash = hash("changed-setup");
        let expected_key = layer.cache_key();
        let report = f
            .cache
            .prepare_report(
                &prepare_request_with_setup_cache(oci_input(&f), layer),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::RequiresBuilder);
        assert_eq!(report.reason, Some(PackPrepareReason::SetupCacheMiss));
        assert_eq!(report.trust_state, PackTrustState::Verified);
        assert_eq!(
            report.setup_cache.state,
            PackPrepareSetupCacheState::Missing
        );
        assert_eq!(report.setup_cache.layers[0].cache_key, expected_key);
        assert_eq!(
            report.setup_cache.layers[0].state,
            PackPrepareSetupCacheLayerState::Missing
        );
        assert!(report.builder_vm_required);
        assert!(!report.fast_path_eligible);
    }

    #[test]
    fn prepare_report_invalidates_setup_cache_on_each_identity_dimension() {
        let f = fixture();
        install_fixture_pack(&f);
        let base = setup_cache_layer(&f);
        let mut cases = Vec::new();

        let mut changed = base.clone();
        changed.image_digest = Some(digest("changed-oci"));
        cases.push(("image digest", changed));

        let mut changed = base.clone();
        changed.flake_lock_hash = Some(hash("changed-flake-lock"));
        cases.push(("flake lock hash", changed));

        let mut changed = base.clone();
        changed.setup_command_hash = hash("changed-setup");
        cases.push(("setup command hash", changed));

        let mut changed = base.clone();
        changed.environment_hash = hash("changed-env");
        cases.push(("environment hash", changed));

        let mut changed = base.clone();
        changed.mount_shape_hash = hash("changed-mounts");
        cases.push(("mount shape hash", changed));

        let mut changed = base.clone();
        changed.runtime_pack_hash = hash("changed-runtime-pack");
        cases.push(("runtime pack hash", changed));

        let mut changed = base;
        changed.policy_hash = hash("changed-policy");
        cases.push(("policy hash", changed));

        for (dimension, layer) in cases {
            let report = f
                .cache
                .prepare_report(
                    &prepare_request_with_setup_cache(oci_input(&f), layer),
                    &f.policy,
                    &f.trust,
                    &f.revocations,
                )
                .unwrap_or_else(|error| panic!("{dimension} prepare report failed: {error}"));

            assert_eq!(
                report.state,
                PackPrepareState::RequiresBuilder,
                "{dimension} must invalidate setup-cache readiness"
            );
            assert_eq!(
                report.reason,
                Some(PackPrepareReason::SetupCacheMiss),
                "{dimension} must report setup-cache miss"
            );
            assert_eq!(
                report.setup_cache.state,
                PackPrepareSetupCacheState::Missing,
                "{dimension} must mark setup-cache missing"
            );
            assert!(report.builder_vm_required, "{dimension}");
            assert!(!report.fast_path_eligible, "{dimension}");
        }
    }

    #[test]
    fn prepare_report_matches_flake_lock_hash() {
        let f = fixture();
        let cached = install_fixture_pack(&f);
        let report = f
            .cache
            .prepare_report(
                &flake_prepare_request("github:tinylabs/mvm", hash("flake-lock")),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Ready);
        assert_eq!(report.pack_hash, Some(cached.verified.pack_hash));
        assert_eq!(report.trust_state, PackTrustState::Verified);
    }

    #[test]
    fn prepare_report_refuses_mismatched_flake_lock_hash_for_requested_pack() {
        let f = fixture();
        let cached = install_fixture_pack(&f);
        let mut request = flake_prepare_request("github:tinylabs/mvm", hash("other-flake-lock"));
        request.pack_hash = Some(cached.verified.pack_hash);

        let report = f
            .cache
            .prepare_report(&request, &f.policy, &f.trust, &f.revocations)
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Refused);
        assert_eq!(report.reason, Some(PackPrepareReason::InputMismatch));
        assert_eq!(report.trust_state, PackTrustState::NotChecked);
    }

    #[test]
    fn prepare_report_rejects_mutable_oci_input_before_cache_lookup() {
        let f = fixture();
        let report = f
            .cache
            .prepare_report(
                &prepare_request("ghcr.io/tinylabs/mvm:latest".to_string()),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Refused);
        assert_eq!(report.reason, Some(PackPrepareReason::MutableInput));
        assert_eq!(report.trust_state, PackTrustState::NotChecked);
        assert!(!report.download_required);
    }

    #[test]
    fn prepare_report_marks_uncached_input_missing_and_builder_required() {
        let f = fixture();
        let report = f
            .cache
            .prepare_report(
                &prepare_request(format!(
                    "ghcr.io/tinylabs/other@{}",
                    digest("other").as_str()
                )),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Missing);
        assert_eq!(report.reason, Some(PackPrepareReason::MissingPack));
        assert!(report.builder_vm_required);
        assert!(report.download_required);
    }

    #[test]
    fn prepare_report_maps_incompatible_backend_to_unsupported_backend() {
        let f = fixture();
        install_fixture_pack(&f);
        let mut policy = f.policy.clone();
        policy.backend = PackBackend::Qemu;
        let report = f
            .cache
            .prepare_report(
                &prepare_request(oci_input(&f)),
                &policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Refused);
        assert_eq!(report.reason, Some(PackPrepareReason::UnsupportedBackend));
        assert_eq!(report.trust_state, PackTrustState::NotChecked);
    }

    #[test]
    fn prepare_report_maps_expired_cache_metadata_to_expired_trust() {
        let f = fixture();
        let cached = install_fixture_pack(&f);
        let mut expired = cached.index.clone();
        expired.expires_at = utc(2026, 1, 1);
        write_restricted_file(
            &cached.root.join(INDEX_FILENAME),
            &serde_json::to_vec(&expired).expect("serialize expired index"),
        )
        .expect("write expired index");

        let report = f
            .cache
            .prepare_report(
                &prepare_request(oci_input(&f)),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Refused);
        assert_eq!(report.reason, Some(PackPrepareReason::ExpiredTrustMetadata));
        assert_eq!(report.trust_state, PackTrustState::Expired);
    }

    #[test]
    fn prepare_report_maps_revocation_to_revoked_signer() {
        let mut f = fixture();
        install_fixture_pack(&f);
        f.revocations.status = RevocationStatus::Revoked {
            reason: "key compromised".to_string(),
        };
        let report = f
            .cache
            .prepare_report(
                &prepare_request(oci_input(&f)),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::Refused);
        assert_eq!(report.reason, Some(PackPrepareReason::RevokedSigner));
        assert_eq!(report.trust_state, PackTrustState::Revoked);
    }

    #[test]
    fn prepare_report_routes_local_rebuild_required_to_builder() {
        let mut f = fixture();
        f.manifest.policy_compatibility.local_rebuild_required = true;
        resign_manifest(&mut f.manifest);
        let cached = install_fixture_pack(&f);
        let report = f
            .cache
            .prepare_report(
                &prepare_request(oci_input(&f)),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::RequiresBuilder);
        assert_eq!(report.reason, Some(PackPrepareReason::LocalRebuildRequired));
        assert_eq!(report.pack_hash, Some(cached.verified.pack_hash));
        assert!(report.builder_vm_required);
        assert!(!report.fast_path_eligible);
    }

    #[test]
    fn prepare_report_routes_local_rebuild_policy_to_builder_without_pack_lookup() {
        let mut f = fixture();
        f.policy.policy_mode = PackPolicyMode::LocalRebuildRequired;

        let report = f
            .cache
            .prepare_report(
                &prepare_request(oci_input(&f)),
                &f.policy,
                &f.trust,
                &f.revocations,
            )
            .expect("prepare report");

        assert_eq!(report.state, PackPrepareState::RequiresBuilder);
        assert_eq!(report.reason, Some(PackPrepareReason::LocalRebuildRequired));
        assert_eq!(report.pack_hash, None);
        assert!(report.builder_vm_required);
        assert!(!report.download_required);
        assert!(!report.fast_path_eligible);
    }

    #[test]
    fn install_archive_extracts_to_quarantine_and_promotes_atomically() {
        let f = fixture();
        let archive = pack_archive_bytes(&f);
        let cached = f
            .cache
            .install_from_archive_reader(Cursor::new(archive), &f.policy, &f.trust, &f.revocations)
            .expect("install archive");

        assert_eq!(cached.verified.pack_hash, f.manifest.outputs.pack_hash);
        assert!(cached.root.join(MANIFEST_FILENAME).is_file());
        assert!(cached.root.join(INDEX_FILENAME).is_file());
        assert_eq!(
            fs::read(cached.root.join("runtime/kernel")).expect("read kernel"),
            b"kernel"
        );
        assert!(
            f.cache
                .quarantine_dir()
                .read_dir()
                .expect("read quarantine")
                .next()
                .is_none(),
            "successful promotion leaves no partial quarantine directory"
        );
    }

    #[test]
    fn archive_missing_manifest_cleans_partial_extraction() {
        let f = fixture();
        let archive = archive_with_files(&[("runtime/kernel", b"kernel")]);
        let err = f
            .cache
            .install_from_archive_reader(Cursor::new(archive), &f.policy, &f.trust, &f.revocations)
            .expect_err("manifest is required");

        assert!(matches!(err, PackCacheError::MissingArchiveManifest));
        assert!(!f.cache.pack_dir(&f.manifest.outputs.pack_hash).exists());
        assert!(
            f.cache
                .quarantine_dir()
                .read_dir()
                .expect("read quarantine")
                .next()
                .is_none(),
            "failed extraction removes partial quarantine directory"
        );
    }

    #[test]
    fn archive_duplicate_file_cleans_partial_extraction() {
        let f = fixture();
        let archive = archive_with_files(&[
            (
                MANIFEST_FILENAME,
                &f.manifest.canonical_bytes().expect("manifest bytes"),
            ),
            ("runtime/kernel", b"kernel"),
            ("runtime/kernel", b"kernel"),
            ("runtime/initramfs", b"initramfs"),
        ]);
        let err = f
            .cache
            .install_from_archive_reader(Cursor::new(archive), &f.policy, &f.trust, &f.revocations)
            .expect_err("duplicate file must fail");

        assert!(matches!(err, PackCacheError::Io { .. }));
        assert!(!f.cache.pack_dir(&f.manifest.outputs.pack_hash).exists());
        assert!(
            f.cache
                .quarantine_dir()
                .read_dir()
                .expect("read quarantine")
                .next()
                .is_none(),
            "partial extraction is cleaned after duplicate entry failure"
        );
    }

    #[test]
    fn archive_unsafe_paths_are_rejected_before_promotion() {
        let f = fixture();
        let archive = raw_archive_with_file_path("../escape", b"nope");
        let err = f
            .cache
            .install_from_archive_reader(Cursor::new(archive), &f.policy, &f.trust, &f.revocations)
            .expect_err("unsafe path must fail");

        assert!(matches!(err, PackCacheError::UnsafeArchivePath(_)));
        assert!(!f.cache.pack_dir(&f.manifest.outputs.pack_hash).exists());
    }

    #[test]
    fn archive_symlink_entries_are_rejected_before_promotion() {
        let f = fixture();
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("/etc/passwd").expect("set link name");
        header.set_cksum();
        builder
            .append_data(&mut header, "runtime/link", Cursor::new(Vec::new()))
            .expect("append symlink");
        builder.finish().expect("finish archive");
        let archive = builder.into_inner().expect("archive bytes");

        let err = f
            .cache
            .install_from_archive_reader(Cursor::new(archive), &f.policy, &f.trust, &f.revocations)
            .expect_err("symlink entry must fail");

        assert!(matches!(
            err,
            PackCacheError::UnsupportedArchiveEntry { .. }
        ));
        assert!(!f.cache.pack_dir(&f.manifest.outputs.pack_hash).exists());
    }

    #[test]
    fn poisoned_archive_contents_never_promote() {
        let f = fixture();
        let mut builder = tar::Builder::new(Vec::new());
        append_archive_file(
            &mut builder,
            MANIFEST_FILENAME,
            &f.manifest.canonical_bytes().expect("manifest bytes"),
        );
        append_archive_file(&mut builder, "runtime/kernel", b"tampered");
        append_archive_file(&mut builder, "runtime/initramfs", b"initramfs");
        builder.finish().expect("finish archive");
        let archive = builder.into_inner().expect("archive bytes");

        let err = f
            .cache
            .install_from_archive_reader(Cursor::new(archive), &f.policy, &f.trust, &f.revocations)
            .expect_err("tampered archive file must fail verification");

        assert!(matches!(err, PackCacheError::VerifyStaging(_)));
        assert!(!f.cache.pack_dir(&f.manifest.outputs.pack_hash).exists());
        assert!(
            f.cache
                .quarantine_dir()
                .read_dir()
                .expect("read quarantine")
                .next()
                .is_none(),
            "failed verification removes partial quarantine directory"
        );
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
