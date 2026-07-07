//! Attested pack manifests and local verification.
//!
//! Packs are broader than `.mvmpkg` workload bundles: they cover runtime,
//! builder, and image/project artifacts. The manifest is strict JSON, carries
//! SHA-256 identities for every file, and is verified against local policy
//! before any caller can consume the artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::arch::GuestArch;
use crate::plan::bundle::KeyId;

pub const PACK_SCHEMA_VERSION: u32 = 1;
pub const EMPTY_PACK_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Runtime,
    Builder,
    ImageProject,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackBackend {
    Firecracker,
    Libkrun,
    Vz,
    Qemu,
    Docker,
    Hvf,
}

impl fmt::Display for PackBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PackBackend::Firecracker => "firecracker",
            PackBackend::Libkrun => "libkrun",
            PackBackend::Vz => "vz",
            PackBackend::Qemu => "qemu",
            PackBackend::Docker => "docker",
            PackBackend::Hvf => "hvf",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostCapability(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    pub fn new(value: impl Into<String>) -> Result<Self, PackManifestError> {
        let value = value.into();
        if is_sha256_hex(&value) {
            Ok(Self(value))
        } else {
            Err(PackManifestError::InvalidSha256Hex(value))
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Sha256Hex::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct OciDigest(String);

impl OciDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, PackManifestError> {
        let value = value.into();
        if let Some(hex) = value.strip_prefix("sha256:")
            && is_sha256_hex(hex)
        {
            return Ok(Self(value));
        }
        Err(PackManifestError::InvalidOciDigest(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OciDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        OciDigest::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub schema_version: u32,
    pub kind: PackKind,
    pub target_arch: GuestArch,
    pub backend_compatibility: Vec<PackBackend>,
    pub required_host_capabilities: Vec<HostCapability>,
    pub policy_compatibility: PolicyCompatibility,
    pub inputs: PackInputs,
    pub outputs: PackOutputs,
    pub provenance: PackProvenance,
    pub trust: TrustMetadata,
}

impl PackManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PackManifestError> {
        serde_json::to_vec(self).map_err(PackManifestError::Json)
    }

    pub fn signature_payload_bytes(&self) -> Result<Vec<u8>, PackManifestError> {
        let mut payload = self.clone();
        payload.provenance.signature_bundle.signatures.clear();
        serde_json::to_vec(&payload).map_err(PackManifestError::Json)
    }

    pub fn pack_hash_payload_bytes(&self) -> Result<Vec<u8>, PackManifestError> {
        let mut payload = self.clone();
        payload.outputs.pack_hash = Sha256Hex::new(EMPTY_PACK_HASH)?;
        payload.provenance.signature_bundle.signatures.clear();
        serde_json::to_vec(&payload).map_err(PackManifestError::Json)
    }

    pub fn computed_pack_hash(&self) -> Result<Sha256Hex, PackManifestError> {
        Ok(Sha256Hex::from_bytes(&self.pack_hash_payload_bytes()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCompatibility {
    pub policy_hash: Sha256Hex,
    pub local_rebuild_required: bool,
    pub allowed_channels: Vec<String>,
}

/// The `policy_compatibility.policy_hash` convention a host pack (Builder,
/// Runtime) is pinned to: sha256 of the arch's nix system string. Both the
/// producer (baked into the manifest) and the host verifier (derived and
/// compared) MUST call this so the convention has a single owner and cannot
/// silently drift between the two sides.
pub fn host_pack_policy_hash(arch: GuestArch) -> Sha256Hex {
    Sha256Hex::from_bytes(arch.nix_system().as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackInputs {
    pub flake_locks: Vec<FlakeLockIdentity>,
    pub derivations: Vec<DerivationIdentity>,
    pub nar_hashes: Vec<NarIdentity>,
    pub oci_images: Vec<OciInputIdentity>,
    pub setup_commands: Vec<SetupCommandIdentity>,
    pub source_revisions: Vec<SourceRevisionIdentity>,
    pub toolchain_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlakeLockIdentity {
    pub reference: String,
    pub lock_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationIdentity {
    pub drv_path: String,
    pub output_name: String,
    pub nar_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NarIdentity {
    pub store_path: String,
    pub nar_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciInputIdentity {
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<OciDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupCommandIdentity {
    pub command_hash: Sha256Hex,
    pub environment_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisionIdentity {
    pub repository: String,
    pub revision: String,
    pub tree_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackOutputs {
    pub pack_hash: Sha256Hex,
    pub files: Vec<PackFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initramfs_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_rootfs_hash: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_image_hash: Option<Sha256Hex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackFile {
    pub path: String,
    pub sha256: Sha256Hex,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackProvenance {
    pub builder_identity: String,
    pub build_environment_identity: String,
    pub build_timestamp: DateTime<Utc>,
    pub reproducibility: ReproducibilityStatus,
    pub sbom: SbomReference,
    pub signature_bundle: SignatureBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproducibilityStatus {
    Reproduced,
    NotReproduced,
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomReference {
    pub uri: String,
    pub sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBundle {
    pub format: SignatureFormat,
    pub payload: SignaturePayload,
    pub signatures: Vec<PackSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureFormat {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePayload {
    ManifestV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSignature {
    pub key_id: KeyId,
    pub signature_base64: String,
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustMetadata {
    pub signing_key_id: KeyId,
    pub expires_at: DateTime<Utc>,
    pub revocation_channel: String,
    pub channel_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log: Option<TransparencyLogReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyLogReference {
    pub log_id: String,
    pub entry_uuid: String,
    pub checkpoint_hash: Sha256Hex,
}

#[derive(Debug, Clone)]
pub struct LocalPackPolicy {
    pub host_arch: GuestArch,
    pub backend: PackBackend,
    pub host_capabilities: BTreeSet<HostCapability>,
    pub policy_hash: Sha256Hex,
    pub allowed_channels: BTreeSet<String>,
    pub now: DateTime<Utc>,
}

pub trait PackTrustStore {
    fn verifying_key(&self, key_id: &KeyId) -> Option<VerifyingKey>;
}

pub trait PackRevocationChecker {
    fn status(&self, key_id: &KeyId, pack_hash: &Sha256Hex) -> RevocationStatus;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    Good,
    Revoked { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPack {
    pub pack_hash: Sha256Hex,
    pub file_count: usize,
    pub signer_key_id: KeyId,
}

pub fn verify_pack_at(
    manifest: &PackManifest,
    root: &Path,
    policy: &LocalPackPolicy,
    trust: &dyn PackTrustStore,
    revocations: &dyn PackRevocationChecker,
) -> Result<VerifiedPack, PackVerifyError> {
    validate_manifest(manifest, policy)?;
    verify_files(manifest, root)?;
    verify_pack_hash(manifest)?;
    verify_signature(manifest, policy, trust)?;
    verify_revocation(manifest, revocations)?;
    Ok(VerifiedPack {
        pack_hash: manifest.outputs.pack_hash.clone(),
        file_count: manifest.outputs.files.len(),
        signer_key_id: manifest.trust.signing_key_id.clone(),
    })
}

pub fn validate_manifest(
    manifest: &PackManifest,
    policy: &LocalPackPolicy,
) -> Result<(), PackVerifyError> {
    if manifest.schema_version != PACK_SCHEMA_VERSION {
        return Err(PackVerifyError::UnsupportedSchemaVersion {
            got: manifest.schema_version,
            expected: PACK_SCHEMA_VERSION,
        });
    }
    if manifest.target_arch != policy.host_arch {
        return Err(PackVerifyError::IncompatibleArchitecture {
            got: manifest.target_arch,
            expected: policy.host_arch,
        });
    }
    if !manifest.backend_compatibility.contains(&policy.backend) {
        return Err(PackVerifyError::IncompatibleBackend {
            backend: policy.backend.clone(),
        });
    }
    for required in &manifest.required_host_capabilities {
        if !policy.host_capabilities.contains(required) {
            return Err(PackVerifyError::MissingHostCapability(required.0.clone()));
        }
    }
    if manifest.policy_compatibility.policy_hash != policy.policy_hash {
        return Err(PackVerifyError::PolicyHashMismatch {
            declared: manifest.policy_compatibility.policy_hash.clone(),
            expected: policy.policy_hash.clone(),
        });
    }
    if !policy
        .allowed_channels
        .contains(&manifest.trust.channel_identity)
    {
        return Err(PackVerifyError::ChannelNotAllowed(
            manifest.trust.channel_identity.clone(),
        ));
    }
    if manifest.trust.expires_at <= policy.now {
        return Err(PackVerifyError::ExpiredTrustMetadata {
            expired_at: manifest.trust.expires_at,
        });
    }
    validate_required_outputs(manifest)?;
    validate_oci_inputs(manifest)?;
    validate_file_paths(manifest)?;
    validate_signature_bundle(manifest)?;
    Ok(())
}

fn verify_files(manifest: &PackManifest, root: &Path) -> Result<(), PackVerifyError> {
    for file in &manifest.outputs.files {
        let path = root.join(&file.path);
        let (actual_hash, actual_size) =
            hash_file(&path).map_err(|reason| PackVerifyError::FileReadFailed {
                path: file.path.clone(),
                reason,
            })?;
        if actual_size != file.size_bytes {
            return Err(PackVerifyError::FileSizeMismatch {
                path: file.path.clone(),
                declared: file.size_bytes,
                actual: actual_size,
            });
        }
        if actual_hash != file.sha256 {
            return Err(PackVerifyError::FileHashMismatch {
                path: file.path.clone(),
                declared: file.sha256.clone(),
                actual: actual_hash,
            });
        }
    }
    Ok(())
}

fn verify_pack_hash(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    let computed = manifest.computed_pack_hash()?;
    if computed != manifest.outputs.pack_hash {
        return Err(PackVerifyError::PackHashMismatch {
            declared: manifest.outputs.pack_hash.clone(),
            actual: computed,
        });
    }
    Ok(())
}

fn verify_signature(
    manifest: &PackManifest,
    policy: &LocalPackPolicy,
    trust: &dyn PackTrustStore,
) -> Result<(), PackVerifyError> {
    let signature = manifest
        .provenance
        .signature_bundle
        .signatures
        .iter()
        .find(|signature| signature.key_id == manifest.trust.signing_key_id)
        .ok_or_else(|| {
            PackVerifyError::SignatureMissingForKey(manifest.trust.signing_key_id.clone())
        })?;
    if signature.expires_at <= policy.now {
        return Err(PackVerifyError::ExpiredSignature {
            key_id: signature.key_id.clone(),
            expired_at: signature.expires_at,
        });
    }
    let verifying_key = trust.verifying_key(&signature.key_id).ok_or_else(|| {
        PackVerifyError::UnknownSigningKey {
            key_id: signature.key_id.clone(),
        }
    })?;
    let signature_bytes = decode_signature(&signature.signature_base64)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(&manifest.signature_payload_bytes()?, &signature)
        .map_err(|_| PackVerifyError::SignatureInvalid)
}

fn verify_revocation(
    manifest: &PackManifest,
    revocations: &dyn PackRevocationChecker,
) -> Result<(), PackVerifyError> {
    match revocations.status(&manifest.trust.signing_key_id, &manifest.outputs.pack_hash) {
        RevocationStatus::Good => Ok(()),
        RevocationStatus::Revoked { reason } => Err(PackVerifyError::Revoked {
            key_id: manifest.trust.signing_key_id.clone(),
            reason,
        }),
    }
}

fn validate_required_outputs(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    if manifest.outputs.files.is_empty() {
        return Err(PackVerifyError::MissingOutputHash("files".to_string()));
    }
    match manifest.kind {
        PackKind::Runtime => {
            require_hash(manifest.outputs.kernel_hash.as_ref(), "kernel_hash")?;
            if manifest.outputs.initramfs_hash.is_none()
                && manifest.outputs.agent_rootfs_hash.is_none()
            {
                return Err(PackVerifyError::MissingOutputHash(
                    "initramfs_hash_or_agent_rootfs_hash".to_string(),
                ));
            }
        }
        PackKind::Builder => {
            require_hash(
                manifest.outputs.builder_image_hash.as_ref(),
                "builder_image_hash",
            )?;
            require_hash(manifest.outputs.kernel_hash.as_ref(), "kernel_hash")?;
        }
        PackKind::ImageProject => {
            require_hash(manifest.outputs.rootfs_hash.as_ref(), "rootfs_hash")?;
        }
    }
    Ok(())
}

fn require_hash(hash: Option<&Sha256Hex>, field: &str) -> Result<(), PackVerifyError> {
    if hash.is_some() {
        Ok(())
    } else {
        Err(PackVerifyError::MissingOutputHash(field.to_string()))
    }
}

fn validate_oci_inputs(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    for input in &manifest.inputs.oci_images {
        let Some(digest) = &input.digest else {
            return Err(PackVerifyError::MutableOciReference {
                reference: input.reference.clone(),
            });
        };
        let digest_suffix = format!("@{}", digest.as_str());
        if !input.reference.ends_with(&digest_suffix) {
            return Err(PackVerifyError::MutableOciReference {
                reference: input.reference.clone(),
            });
        }
    }
    Ok(())
}

fn validate_file_paths(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    let mut seen = BTreeSet::new();
    for file in &manifest.outputs.files {
        if !seen.insert(file.path.clone()) {
            return Err(PackVerifyError::DuplicateFile(file.path.clone()));
        }
        if !pack_path_is_safe(&file.path) {
            return Err(PackVerifyError::UnsafeFilePath(file.path.clone()));
        }
    }
    Ok(())
}

/// A pack file path must be a relative, normal-component path with no escape:
/// non-empty, no backslash, not absolute, and no `..`/root/prefix components. The
/// producer checks this before reading a file so bytes outside the pack root are
/// never hashed or attested; the verifier checks it before trusting a manifest.
fn pack_path_is_safe(path: &str) -> bool {
    if path.is_empty() || path.contains('\\') {
        return false;
    }
    let path = Path::new(path);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_signature_bundle(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    if manifest.provenance.signature_bundle.format != SignatureFormat::Ed25519 {
        return Err(PackVerifyError::UnsupportedSignatureBundle);
    }
    if manifest.provenance.signature_bundle.payload != SignaturePayload::ManifestV1 {
        return Err(PackVerifyError::UnsupportedSignatureBundle);
    }
    if manifest.provenance.signature_bundle.signatures.is_empty() {
        return Err(PackVerifyError::SignatureBundleEmpty);
    }
    for signature in &manifest.provenance.signature_bundle.signatures {
        if !signature.key_id.is_well_formed() {
            return Err(PackVerifyError::MalformedKeyId(signature.key_id.clone()));
        }
        decode_signature(&signature.signature_base64)?;
    }
    if !manifest.trust.signing_key_id.is_well_formed() {
        return Err(PackVerifyError::MalformedKeyId(
            manifest.trust.signing_key_id.clone(),
        ));
    }
    Ok(())
}

fn decode_signature(encoded: &str) -> Result<[u8; 64], PackVerifyError> {
    let bytes = B64
        .decode(encoded)
        .map_err(|reason| PackVerifyError::MalformedSignature(reason.to_string()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        PackVerifyError::MalformedSignature(format!(
            "expected 64 signature bytes, got {}",
            bytes.len()
        ))
    })
}

fn hash_file(path: &Path) -> Result<(Sha256Hex, u64), String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok((Sha256Hex(format!("{:x}", hasher.finalize())), total))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug, Error)]
pub enum PackManifestError {
    #[error("invalid sha256 hex digest {0:?}")]
    InvalidSha256Hex(String),
    #[error("invalid OCI digest {0:?}")]
    InvalidOciDigest(String),
    #[error("file {path:?} could not be hashed: {reason}")]
    FileHash { path: String, reason: String },
    // Boxed: `PackVerifyError::Manifest` already carries a `PackManifestError`, so
    // embedding it by value would make the type infinitely sized.
    #[error("produced pack failed validation: {0}")]
    Invalid(#[source] Box<PackVerifyError>),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<PackVerifyError> for PackManifestError {
    fn from(error: PackVerifyError) -> Self {
        PackManifestError::Invalid(Box::new(error))
    }
}

#[derive(Debug, Error)]
pub enum PackVerifyError {
    #[error("pack schema version {got} not supported (expected {expected})")]
    UnsupportedSchemaVersion { got: u32, expected: u32 },
    #[error("pack target architecture {got} is incompatible with host architecture {expected}")]
    IncompatibleArchitecture { got: GuestArch, expected: GuestArch },
    #[error("pack is not compatible with backend {backend}")]
    IncompatibleBackend { backend: PackBackend },
    #[error("pack requires missing host capability {0}")]
    MissingHostCapability(String),
    #[error("pack policy hash mismatch: declared {declared:?}, expected {expected:?}")]
    PolicyHashMismatch {
        declared: Sha256Hex,
        expected: Sha256Hex,
    },
    #[error("pack channel {0:?} is not allowed by local policy")]
    ChannelNotAllowed(String),
    #[error("pack trust metadata expired at {expired_at}")]
    ExpiredTrustMetadata { expired_at: DateTime<Utc> },
    #[error("pack is missing required output hash {0}")]
    MissingOutputHash(String),
    #[error("mutable OCI reference is not eligible for attested fast launch: {reference}")]
    MutableOciReference { reference: String },
    #[error("unsafe pack file path {0:?}")]
    UnsafeFilePath(String),
    #[error("duplicate pack file path {0:?}")]
    DuplicateFile(String),
    #[error("signature bundle is empty")]
    SignatureBundleEmpty,
    #[error("signature bundle format or payload is unsupported")]
    UnsupportedSignatureBundle,
    #[error("malformed key id {0:?}")]
    MalformedKeyId(KeyId),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("file {path} could not be read: {reason}")]
    FileReadFailed { path: String, reason: String },
    #[error("file {path} size mismatch: declared {declared}, actual {actual}")]
    FileSizeMismatch {
        path: String,
        declared: u64,
        actual: u64,
    },
    #[error("file {path} hash mismatch: declared {declared:?}, actual {actual:?}")]
    FileHashMismatch {
        path: String,
        declared: Sha256Hex,
        actual: Sha256Hex,
    },
    #[error("pack hash mismatch: declared {declared:?}, actual {actual:?}")]
    PackHashMismatch {
        declared: Sha256Hex,
        actual: Sha256Hex,
    },
    #[error("no signature found for signing key {0:?}")]
    SignatureMissingForKey(KeyId),
    #[error("signature for key {key_id:?} expired at {expired_at}")]
    ExpiredSignature {
        key_id: KeyId,
        expired_at: DateTime<Utc>,
    },
    #[error("unknown signing key {key_id:?}")]
    UnknownSigningKey { key_id: KeyId },
    #[error("pack signature did not verify")]
    SignatureInvalid,
    #[error("pack signer {key_id:?} is revoked: {reason}")]
    Revoked { key_id: KeyId, reason: String },
    #[error(transparent)]
    Manifest(#[from] PackManifestError),
}

/// Manifest metadata a `PackBuilder` stamps into the produced pack. Every field
/// maps directly to a `PackManifest` field except the hash-derived outputs, which
/// the builder computes from the file set, and `signing_key_id`, which the builder
/// derives from the signing key.
#[derive(Debug, Clone)]
pub struct PackMetadata {
    pub kind: PackKind,
    pub target_arch: GuestArch,
    pub backend_compatibility: Vec<PackBackend>,
    pub required_host_capabilities: Vec<HostCapability>,
    pub policy_compatibility: PolicyCompatibility,
    pub inputs: PackInputs,
    pub provenance: PackProvenanceMeta,
    pub trust: PackTrustMeta,
    pub signature: SignatureValidity,
}

/// Non-hash provenance the caller supplies; the signature bundle is assembled by
/// the builder.
#[derive(Debug, Clone)]
pub struct PackProvenanceMeta {
    pub builder_identity: String,
    pub build_environment_identity: String,
    pub build_timestamp: DateTime<Utc>,
    pub reproducibility: ReproducibilityStatus,
    pub sbom: SbomReference,
}

/// Trust metadata minus `signing_key_id`, which the builder derives from the key.
#[derive(Debug, Clone)]
pub struct PackTrustMeta {
    pub expires_at: DateTime<Utc>,
    pub revocation_channel: String,
    pub channel_identity: String,
    pub mirror_identity: Option<String>,
    pub transparency_log: Option<TransparencyLogReference>,
}

/// Validity window stamped onto the produced signature.
#[derive(Debug, Clone)]
pub struct SignatureValidity {
    pub signed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Typed output hashes the caller already knows for the assembled artifacts. The
/// per-file `PackOutputs.files` and `pack_hash` are computed by the builder; these
/// carry the closure/rootfs/kernel-level identities the manifest also records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackOutputHashes {
    pub closure_hash: Option<Sha256Hex>,
    pub rootfs_hash: Option<Sha256Hex>,
    pub kernel_hash: Option<Sha256Hex>,
    pub initramfs_hash: Option<Sha256Hex>,
    pub agent_rootfs_hash: Option<Sha256Hex>,
    pub builder_image_hash: Option<Sha256Hex>,
}

/// Inverse of `verify_pack_at`: hashes a file set under `root`, computes the pack
/// hash, and signs the manifest so `verify_pack_at` accepts the result. Files are
/// addressed by their in-pack relative path and hashed with the same helper the
/// verifier uses, so producer and verifier can never drift.
pub struct PackBuilder<'a> {
    root: PathBuf,
    metadata: PackMetadata,
    output_hashes: PackOutputHashes,
    files: Vec<String>,
    signing_key: &'a SigningKey,
}

impl<'a> PackBuilder<'a> {
    pub fn new(
        root: impl Into<PathBuf>,
        metadata: PackMetadata,
        signing_key: &'a SigningKey,
    ) -> Self {
        Self {
            root: root.into(),
            metadata,
            output_hashes: PackOutputHashes::default(),
            files: Vec::new(),
            signing_key,
        }
    }

    /// Add one file by its path relative to the pack root.
    pub fn file(mut self, path: impl Into<String>) -> Self {
        self.files.push(path.into());
        self
    }

    /// Add several files by their paths relative to the pack root.
    pub fn files(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.files.extend(paths.into_iter().map(Into::into));
        self
    }

    pub fn output_hashes(mut self, hashes: PackOutputHashes) -> Self {
        self.output_hashes = hashes;
        self
    }

    pub fn build(self) -> Result<PackManifest, PackManifestError> {
        let files = self.hash_files()?;
        let signing_key_id = KeyId::from_pubkey(&self.signing_key.verifying_key());
        let outputs = PackOutputs {
            pack_hash: Sha256Hex::new(EMPTY_PACK_HASH)?,
            files,
            closure_hash: self.output_hashes.closure_hash,
            rootfs_hash: self.output_hashes.rootfs_hash,
            kernel_hash: self.output_hashes.kernel_hash,
            initramfs_hash: self.output_hashes.initramfs_hash,
            agent_rootfs_hash: self.output_hashes.agent_rootfs_hash,
            builder_image_hash: self.output_hashes.builder_image_hash,
        };
        let provenance = PackProvenance {
            builder_identity: self.metadata.provenance.builder_identity,
            build_environment_identity: self.metadata.provenance.build_environment_identity,
            build_timestamp: self.metadata.provenance.build_timestamp,
            reproducibility: self.metadata.provenance.reproducibility,
            sbom: self.metadata.provenance.sbom,
            signature_bundle: SignatureBundle {
                format: SignatureFormat::Ed25519,
                payload: SignaturePayload::ManifestV1,
                signatures: Vec::new(),
            },
        };
        let trust = TrustMetadata {
            signing_key_id: signing_key_id.clone(),
            expires_at: self.metadata.trust.expires_at,
            revocation_channel: self.metadata.trust.revocation_channel,
            channel_identity: self.metadata.trust.channel_identity,
            mirror_identity: self.metadata.trust.mirror_identity,
            transparency_log: self.metadata.trust.transparency_log,
        };
        let mut manifest = PackManifest {
            schema_version: PACK_SCHEMA_VERSION,
            kind: self.metadata.kind,
            target_arch: self.metadata.target_arch,
            backend_compatibility: self.metadata.backend_compatibility,
            required_host_capabilities: self.metadata.required_host_capabilities,
            policy_compatibility: self.metadata.policy_compatibility,
            inputs: self.metadata.inputs,
            outputs,
            provenance,
            trust,
        };
        // Refuse to sign a manifest the verifier would reject for missing the
        // outputs this kind requires, rather than shipping a dead signed pack.
        validate_required_outputs(&manifest)?;
        manifest.outputs.pack_hash = manifest.computed_pack_hash()?;
        let signature = self.signing_key.sign(&manifest.signature_payload_bytes()?);
        manifest
            .provenance
            .signature_bundle
            .signatures
            .push(PackSignature {
                key_id: signing_key_id,
                signature_base64: B64.encode(signature.to_bytes()),
                signed_at: self.metadata.signature.signed_at,
                expires_at: self.metadata.signature.expires_at,
            });
        Ok(manifest)
    }

    fn hash_files(&self) -> Result<Vec<PackFile>, PackManifestError> {
        self.files
            .iter()
            .map(|path| {
                // Reject escapes before touching the filesystem so nothing outside
                // the pack root is ever read or attested.
                if !pack_path_is_safe(path) {
                    return Err(PackVerifyError::UnsafeFilePath(path.clone()).into());
                }
                let (sha256, size_bytes) = hash_file(&self.root.join(path)).map_err(|reason| {
                    PackManifestError::FileHash {
                        path: path.clone(),
                        reason,
                    }
                })?;
                Ok(PackFile {
                    path: path.clone(),
                    sha256,
                    size_bytes,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::fs;

    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn host_pack_policy_hash_matches_sha256_of_nix_system() {
        // Guards the one convention both producer and verifier share. If this
        // value changes, every previously produced host pack stops verifying.
        assert_eq!(
            host_pack_policy_hash(GuestArch::Aarch64),
            Sha256Hex::from_bytes(b"aarch64-linux")
        );
        assert_eq!(
            host_pack_policy_hash(GuestArch::X86_64),
            Sha256Hex::from_bytes(b"x86_64-linux")
        );
    }

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
        dir: TempDir,
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
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn fixture(kind: PackKind) -> Fixture {
        let dir = TempDir::new().expect("tempdir");
        fs::create_dir_all(dir.path().join("runtime")).expect("mkdir runtime");
        fs::write(dir.path().join("runtime/kernel"), b"kernel").expect("write kernel");
        fs::write(dir.path().join("runtime/initramfs"), b"initramfs").expect("write initramfs");
        fs::write(dir.path().join("runtime/rootfs"), b"rootfs").expect("write rootfs");
        fs::write(dir.path().join("runtime/builder.img"), b"builder").expect("write builder");

        let key = signing_key();
        let key_id = KeyId::from_pubkey(&key.verifying_key());
        let now = utc(2026, 6, 24);
        let policy_hash = hash("policy");
        let mut manifest = PackManifest {
            schema_version: PACK_SCHEMA_VERSION,
            kind,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Libkrun, PackBackend::Vz],
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
                derivations: vec![DerivationIdentity {
                    drv_path: "/nix/store/example.drv".to_string(),
                    output_name: "out".to_string(),
                    nar_hash: hash("drv-nar"),
                }],
                nar_hashes: vec![NarIdentity {
                    store_path: "/nix/store/example".to_string(),
                    nar_hash: hash("nar"),
                }],
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
                    PackFile {
                        path: "runtime/rootfs".to_string(),
                        sha256: hash("rootfs"),
                        size_bytes: 6,
                    },
                    PackFile {
                        path: "runtime/builder.img".to_string(),
                        sha256: hash("builder"),
                        size_bytes: 7,
                    },
                ],
                closure_hash: Some(hash("closure")),
                rootfs_hash: Some(hash("rootfs")),
                kernel_hash: Some(hash("kernel")),
                initramfs_hash: Some(hash("initramfs")),
                agent_rootfs_hash: None,
                builder_image_hash: Some(hash("builder")),
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
                mirror_identity: Some("origin".to_string()),
                transparency_log: Some(TransparencyLogReference {
                    log_id: "rekor".to_string(),
                    entry_uuid: "uuid".to_string(),
                    checkpoint_hash: hash("checkpoint"),
                }),
            },
        };
        manifest.outputs.pack_hash = manifest.computed_pack_hash().expect("pack hash");
        let payload = manifest.signature_payload_bytes().expect("payload");
        let signature = key.sign(&payload);
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
        let revocations = StaticRevocation {
            status: RevocationStatus::Good,
        };
        Fixture {
            dir,
            manifest,
            policy,
            trust,
            revocations,
        }
    }

    fn verify(fixture: &Fixture) -> Result<VerifiedPack, PackVerifyError> {
        verify_pack_at(
            &fixture.manifest,
            fixture.dir.path(),
            &fixture.policy,
            &fixture.trust,
            &fixture.revocations,
        )
    }

    #[test]
    fn runtime_manifest_roundtrips() {
        let f = fixture(PackKind::Runtime);
        let json = serde_json::to_string(&f.manifest).expect("serialize");
        let recovered: PackManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, f.manifest);
    }

    #[test]
    fn builder_manifest_roundtrips() {
        let f = fixture(PackKind::Builder);
        let json = serde_json::to_string(&f.manifest).expect("serialize");
        let recovered: PackManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, f.manifest);
    }

    #[test]
    fn image_project_manifest_roundtrips() {
        let f = fixture(PackKind::ImageProject);
        let json = serde_json::to_string(&f.manifest).expect("serialize");
        let recovered: PackManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, f.manifest);
    }

    #[test]
    fn verifies_valid_runtime_pack() {
        let f = fixture(PackKind::Runtime);
        let verified = verify(&f).expect("valid pack verifies");
        assert_eq!(verified.pack_hash, f.manifest.outputs.pack_hash);
        assert_eq!(verified.file_count, 4);
    }

    #[test]
    fn parser_rejects_missing_hash_field() {
        let f = fixture(PackKind::Runtime);
        let mut value = serde_json::to_value(&f.manifest).expect("json");
        value["outputs"]["files"][0]
            .as_object_mut()
            .expect("file object")
            .remove("sha256");
        let err = serde_json::from_value::<PackManifest>(value).expect_err("missing hash rejected");
        assert!(err.to_string().contains("missing field `sha256`"));
    }

    #[test]
    fn validation_rejects_unsupported_schema_version() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.schema_version = PACK_SCHEMA_VERSION + 1;
        let err = verify(&f).expect_err("unsupported schema rejected");
        assert!(matches!(
            err,
            PackVerifyError::UnsupportedSchemaVersion { .. }
        ));
    }

    #[test]
    fn validation_rejects_mutable_oci_reference() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.inputs.oci_images[0] = OciInputIdentity {
            reference: "ghcr.io/tinylabs/mvm:latest".to_string(),
            digest: None,
        };
        resign(&mut f.manifest);
        let err = verify(&f).expect_err("mutable OCI rejected");
        assert!(matches!(err, PackVerifyError::MutableOciReference { .. }));
    }

    #[test]
    fn validation_rejects_expired_trust_metadata() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.trust.expires_at = utc(2026, 1, 1);
        resign(&mut f.manifest);
        let err = verify(&f).expect_err("expired trust rejected");
        assert!(matches!(err, PackVerifyError::ExpiredTrustMetadata { .. }));
    }

    #[test]
    fn validation_rejects_incompatible_architecture() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.target_arch = match GuestArch::host() {
            GuestArch::X86_64 => GuestArch::Aarch64,
            GuestArch::Aarch64 => GuestArch::X86_64,
        };
        resign(&mut f.manifest);
        let err = verify(&f).expect_err("arch mismatch rejected");
        assert!(matches!(
            err,
            PackVerifyError::IncompatibleArchitecture { .. }
        ));
    }

    #[test]
    fn validation_rejects_incompatible_backend() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.backend_compatibility = vec![PackBackend::Firecracker];
        resign(&mut f.manifest);
        let err = verify(&f).expect_err("backend mismatch rejected");
        assert!(matches!(err, PackVerifyError::IncompatibleBackend { .. }));
    }

    #[test]
    fn tamper_rejects_changed_file_contents() {
        let f = fixture(PackKind::Runtime);
        fs::write(f.dir.path().join("runtime/kernel"), b"tampered").expect("tamper file");
        let err = verify(&f).expect_err("changed file rejected");
        assert!(matches!(err, PackVerifyError::FileSizeMismatch { .. }));
    }

    #[test]
    fn tamper_rejects_changed_manifest() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.provenance.builder_identity = "attacker".to_string();
        f.manifest.outputs.pack_hash = f.manifest.computed_pack_hash().expect("pack hash");
        let err = verify(&f).expect_err("changed manifest rejected");
        assert!(matches!(err, PackVerifyError::SignatureInvalid));
    }

    #[test]
    fn tamper_rejects_mismatched_pack_hash() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.outputs.pack_hash = hash("wrong-pack");
        resign_without_recomputing_pack_hash(&mut f.manifest);
        let err = verify(&f).expect_err("pack hash mismatch rejected");
        assert!(matches!(err, PackVerifyError::PackHashMismatch { .. }));
    }

    #[test]
    fn tamper_rejects_revoked_signature() {
        let mut f = fixture(PackKind::Runtime);
        f.revocations.status = RevocationStatus::Revoked {
            reason: "key compromised".to_string(),
        };
        let err = verify(&f).expect_err("revoked pack rejected");
        assert!(matches!(err, PackVerifyError::Revoked { .. }));
    }

    #[test]
    fn tamper_rejects_expired_signature() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.provenance.signature_bundle.signatures[0].expires_at = utc(2026, 1, 1);
        let err = verify(&f).expect_err("expired signature rejected");
        assert!(matches!(err, PackVerifyError::ExpiredSignature { .. }));
    }

    fn empty_inputs() -> PackInputs {
        PackInputs {
            flake_locks: Vec::new(),
            derivations: Vec::new(),
            nar_hashes: Vec::new(),
            oci_images: Vec::new(),
            setup_commands: Vec::new(),
            source_revisions: Vec::new(),
            toolchain_versions: BTreeMap::new(),
        }
    }

    /// Common producer metadata for `kind`, hvf-compatible and matching `hvf_policy`.
    fn producer_metadata(kind: PackKind) -> PackMetadata {
        PackMetadata {
            kind,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Hvf, PackBackend::Libkrun],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: hash("policy"),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            inputs: empty_inputs(),
            provenance: PackProvenanceMeta {
                builder_identity: "ci-builder".to_string(),
                build_environment_identity: "github-actions".to_string(),
                build_timestamp: utc(2026, 6, 23),
                reproducibility: ReproducibilityStatus::Reproduced,
                sbom: SbomReference {
                    uri: "https://example.test/sbom.spdx.json".to_string(),
                    sha256: hash("sbom"),
                },
            },
            trust: PackTrustMeta {
                expires_at: utc(2026, 12, 31),
                revocation_channel: "https://example.test/revocations.json".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            },
        }
    }

    /// Produce a `Builder` pack via `PackBuilder` whose artifacts live under `dir`,
    /// compatible with the hvf backend. Returns the signed manifest.
    fn produced_hvf_builder_pack(dir: &TempDir) -> PackManifest {
        fs::write(dir.path().join("kernel"), b"builder-kernel").expect("write kernel");
        fs::write(dir.path().join("builder.img"), b"builder-image").expect("write builder");
        let key = signing_key();
        PackBuilder::new(dir.path(), producer_metadata(PackKind::Builder), &key)
            .files(["kernel", "builder.img"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(b"builder-kernel")),
                builder_image_hash: Some(Sha256Hex::from_bytes(b"builder-image")),
                ..Default::default()
            })
            .build()
            .expect("produce pack")
    }

    /// Produce a `Runtime` pack, exercising the kernel + initramfs required-output
    /// branch the `Builder` fixture doesn't reach.
    fn produced_runtime_pack(dir: &TempDir) -> PackManifest {
        fs::write(dir.path().join("kernel"), b"runtime-kernel").expect("write kernel");
        fs::write(dir.path().join("initramfs"), b"runtime-initramfs").expect("write initramfs");
        let key = signing_key();
        PackBuilder::new(dir.path(), producer_metadata(PackKind::Runtime), &key)
            .files(["kernel", "initramfs"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(b"runtime-kernel")),
                initramfs_hash: Some(Sha256Hex::from_bytes(b"runtime-initramfs")),
                ..Default::default()
            })
            .build()
            .expect("produce runtime pack")
    }

    fn hvf_policy() -> LocalPackPolicy {
        LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash: hash("policy"),
            allowed_channels: BTreeSet::from(["stable".to_string()]),
            now: utc(2026, 6, 24),
        }
    }

    fn hvf_trust_store() -> MapTrustStore {
        let key = signing_key();
        let key_id = KeyId::from_pubkey(&key.verifying_key());
        MapTrustStore {
            keys: HashMap::from([(key_id, key.verifying_key())]),
        }
    }

    #[test]
    fn produced_pack_verifies_on_hvf_policy() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_hvf_builder_pack(&dir);
        let revocations = StaticRevocation {
            status: RevocationStatus::Good,
        };
        let verified = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &hvf_trust_store(),
            &revocations,
        )
        .expect("produced pack verifies");
        assert_eq!(verified.file_count, 2);
        assert_eq!(verified.pack_hash, manifest.outputs.pack_hash);
        assert_eq!(
            verified.signer_key_id,
            KeyId::from_pubkey(&signing_key().verifying_key())
        );
    }

    #[test]
    fn produced_pack_roundtrips_serde() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_hvf_builder_pack(&dir);
        let json = serde_json::to_string(&manifest).expect("serialize");
        let recovered: PackManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, manifest);
    }

    #[test]
    fn produced_pack_rejects_file_tamper() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_hvf_builder_pack(&dir);
        fs::write(dir.path().join("kernel"), b"tampered-kernel").expect("tamper file");
        let revocations = StaticRevocation {
            status: RevocationStatus::Good,
        };
        let err = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &hvf_trust_store(),
            &revocations,
        )
        .expect_err("tampered file rejected");
        assert!(matches!(
            err,
            PackVerifyError::FileSizeMismatch { .. } | PackVerifyError::FileHashMismatch { .. }
        ));
    }

    #[test]
    fn produced_pack_rejects_manifest_tamper() {
        let dir = TempDir::new().expect("tempdir");
        let mut manifest = produced_hvf_builder_pack(&dir);
        // Re-stamp the pack hash so the tampered field passes the hash gate and the
        // failure lands squarely on the signature check.
        manifest.provenance.builder_identity = "attacker".to_string();
        manifest.outputs.pack_hash = manifest.computed_pack_hash().expect("pack hash");
        let revocations = StaticRevocation {
            status: RevocationStatus::Good,
        };
        let err = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &hvf_trust_store(),
            &revocations,
        )
        .expect_err("tampered manifest rejected");
        assert!(matches!(err, PackVerifyError::SignatureInvalid));
    }

    #[test]
    fn produced_runtime_pack_verifies_on_hvf_policy() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_runtime_pack(&dir);
        let revocations = StaticRevocation {
            status: RevocationStatus::Good,
        };
        let verified = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &hvf_trust_store(),
            &revocations,
        )
        .expect("produced runtime pack verifies");
        assert_eq!(verified.file_count, 2);
        assert_eq!(
            verified.signer_key_id,
            KeyId::from_pubkey(&signing_key().verifying_key())
        );
    }

    #[test]
    fn build_rejects_missing_required_output_hash() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("kernel"), b"builder-kernel").expect("write kernel");
        fs::write(dir.path().join("builder.img"), b"builder-image").expect("write builder");
        let key = signing_key();
        // Builder kind requires builder_image_hash + kernel_hash; supply neither.
        let result = PackBuilder::new(dir.path(), producer_metadata(PackKind::Builder), &key)
            .files(["kernel", "builder.img"])
            .build();
        assert!(matches!(
            result,
            Err(PackManifestError::Invalid(inner))
                if matches!(*inner, PackVerifyError::MissingOutputHash(_))
        ));
    }

    #[test]
    fn build_rejects_unsafe_file_path_before_hashing() {
        let dir = TempDir::new().expect("tempdir");
        let key = signing_key();
        // The traversal target is never created; an `UnsafeFilePath` (not a
        // `FileHash`) error proves `build()` refused before any read outside root.
        let result = PackBuilder::new(dir.path(), producer_metadata(PackKind::Builder), &key)
            .file("../escape")
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(hash("kernel")),
                builder_image_hash: Some(hash("builder")),
                ..Default::default()
            })
            .build();
        assert!(matches!(
            result,
            Err(PackManifestError::Invalid(inner))
                if matches!(*inner, PackVerifyError::UnsafeFilePath(_))
        ));
    }

    fn resign(manifest: &mut PackManifest) {
        manifest.outputs.pack_hash = manifest.computed_pack_hash().expect("pack hash");
        resign_without_recomputing_pack_hash(manifest);
    }

    fn resign_without_recomputing_pack_hash(manifest: &mut PackManifest) {
        let key = signing_key();
        manifest.provenance.signature_bundle.signatures.clear();
        let payload = manifest.signature_payload_bytes().expect("payload");
        let signature = key.sign(&payload);
        manifest
            .provenance
            .signature_bundle
            .signatures
            .push(PackSignature {
                key_id: KeyId::from_pubkey(&key.verifying_key()),
                signature_base64: B64.encode(signature.to_bytes()),
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            });
    }
}
