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

use mvm_contract::protocol::extension_pack::{ExtensionContractError, ExtensionPackContract};

use crate::arch::GuestArch;
use crate::plan::bundle::{KeyId, key_id_from_identity, key_id_from_pubkey};

pub const PACK_SCHEMA_VERSION: u32 = 1;
pub const EMPTY_PACK_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Sidecar file name for the detached cosign bundle backing a keyless
/// (Sigstore-authority) pack. Reserved alongside the manifest file name so a
/// declared pack file can never collide with it.
pub const COSIGN_BUNDLE_FILE_NAME: &str = "manifest.cosign.bundle";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Runtime,
    Builder,
    ImageProject,
    Extension,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackBackend {
    Firecracker,
    Libkrun,
    Qemu,
    Hvf,
}

impl fmt::Display for PackBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PackBackend::Firecracker => "firecracker",
            PackBackend::Libkrun => "libkrun",
            PackBackend::Qemu => "qemu",
            PackBackend::Hvf => "hvf",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostCapability(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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
        Self(hex::encode(Sha256::digest(bytes)))
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
        use crate::digest_shape::Sha256PrefixedShape;
        let value = value.into();
        // Shares the `sha256:<64 lowercase hex>` shape check with the other
        // prefixed content-address newtypes; this type keeps its single flat
        // error, so every non-Ok shape maps to `InvalidOciDigest`.
        match crate::digest_shape::validate_sha256_prefixed(&value) {
            Sha256PrefixedShape::Ok => Ok(Self(value)),
            Sha256PrefixedShape::MissingPrefix
            | Sha256PrefixedShape::WrongLength { .. }
            | Sha256PrefixedShape::NonHex { .. } => Err(PackManifestError::InvalidOciDigest(value)),
        }
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
    /// Present only for [`PackKind::Extension`]. The enclosing pack supplies
    /// the signature, artifact digest, provenance, SBOM, expiry, and
    /// revocation channel for this generic extension declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<ExtensionPackContract>,
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
    /// Keyless authority: the detached cosign bundle sidecar is authoritative and
    /// the in-manifest `signatures` list is empty.
    Sigstore,
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

/// Trust inputs for the keyless (Sigstore) pack verifier: the identities the
/// bundle's signing certificate must carry (tried in order, exact match) and
/// the expected OIDC issuer. Carried by the caller rather than looked up from
/// a key store, since there is no key to look up.
#[derive(Debug, Clone)]
pub struct KeylessTrust {
    pub accepted_identities: Vec<String>,
    pub issuer: String,
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

/// Keyless counterpart to `verify_pack_at`: authority is a detached cosign
/// bundle over the manifest bytes checked against a compiled-in identity
/// list, rather than an in-manifest ed25519 signature checked against a key
/// store. The shape/authority gate runs first so a mis-routed ed25519 pack
/// fails on `WrongSignatureAuthority` before any signature bytes are touched;
/// the signature step runs next so a garbage bundle fails closed before the
/// shared structural/hash/revocation middle ever sees the pack.
#[cfg(feature = "manifest-verify")]
pub fn verify_pack_keyless_at(
    manifest: &PackManifest,
    root: &Path,
    policy: &LocalPackPolicy,
    cosign_bundle: &[u8],
    keyless: &KeylessTrust,
    revocations: &dyn PackRevocationChecker,
) -> Result<VerifiedPack, PackVerifyError> {
    validate_signature_bundle_keyless(manifest)?;
    // Bind the pack's stamped signer id to the identity that actually verifies
    // it: only consider accepted identities whose derived key id equals
    // `signing_key_id`, so the signature and the id revocation keys on cannot
    // name different signers. A pack whose stamped id matches no accepted
    // identity is refused before any signature bytes are examined.
    let stamped = &manifest.trust.signing_key_id;
    let candidates: Vec<&str> = keyless
        .accepted_identities
        .iter()
        .filter(|identity| key_id_from_identity(identity) == *stamped)
        .map(String::as_str)
        .collect();
    if candidates.is_empty() {
        return Err(PackVerifyError::SignerIdentityMismatch {
            signing_key_id: stamped.clone(),
        });
    }
    let payload = manifest.signature_payload_bytes()?;
    let mut failure: Option<String> = None;
    let verified =
        candidates.iter().any(
            |identity| match crate::crypto::image_verify::verify_signed_payload(
                &payload,
                cosign_bundle,
                identity,
                &keyless.issuer,
            ) {
                Ok(()) => true,
                Err(error) => {
                    failure = Some(error.to_string());
                    false
                }
            },
        );
    if !verified {
        return Err(PackVerifyError::KeylessSignatureInvalid(
            failure.unwrap_or_else(|| {
                "keyless signature did not verify under any candidate identity".to_string()
            }),
        ));
    }
    validate_manifest_structural(manifest, policy)?;
    verify_files(manifest, root)?;
    verify_pack_hash(manifest)?;
    verify_revocation(manifest, revocations)?;
    Ok(VerifiedPack {
        pack_hash: manifest.outputs.pack_hash.clone(),
        file_count: manifest.outputs.files.len(),
        signer_key_id: manifest.trust.signing_key_id.clone(),
    })
}

/// No-feature fallback: refuse every keyless pack. Builds without
/// `manifest-verify` drop the sigstore dependency tree in exchange for
/// losing keyless verification entirely; the ed25519 `verify_pack_at` path
/// is unaffected.
#[cfg(not(feature = "manifest-verify"))]
pub fn verify_pack_keyless_at(
    _manifest: &PackManifest,
    _root: &Path,
    _policy: &LocalPackPolicy,
    _cosign_bundle: &[u8],
    _keyless: &KeylessTrust,
    _revocations: &dyn PackRevocationChecker,
) -> Result<VerifiedPack, PackVerifyError> {
    Err(PackVerifyError::KeylessSignatureInvalid(
        "manifest-verify feature disabled in this build; rebuild mvmctl with \
         default features to accept keyless-signed packs"
            .to_string(),
    ))
}

pub fn validate_manifest(
    manifest: &PackManifest,
    policy: &LocalPackPolicy,
) -> Result<(), PackVerifyError> {
    validate_manifest_structural(manifest, policy)?;
    validate_signature_bundle(manifest)
}

/// Everything `validate_manifest` checks except the signature-bundle shape, so
/// both the keyed and keyless verifiers can share one structural gate.
pub fn validate_manifest_structural(
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
    validate_extension_contract(manifest)?;
    validate_oci_inputs(manifest)?;
    validate_file_paths(manifest)?;
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
        PackKind::Extension => {}
    }
    Ok(())
}

fn validate_extension_contract(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    match (&manifest.kind, &manifest.extension) {
        (PackKind::Extension, Some(extension)) => {
            extension.validate()?;
            if !manifest
                .outputs
                .files
                .iter()
                .any(|file| file.path == extension.artifact)
            {
                return Err(PackVerifyError::ExtensionEntrypointNotDeclared(
                    extension.artifact.clone(),
                ));
            }
            Ok(())
        }
        (PackKind::Extension, None) => Err(PackVerifyError::MissingExtensionContract),
        (_, Some(_)) => Err(PackVerifyError::UnexpectedExtensionContract),
        (_, None) => Ok(()),
    }
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

/// Shape gate for a keyless pack: the authority must be declared `Sigstore`
/// (an `Ed25519`-declared pack is rejected as the wrong authority, not routed
/// through the keyed shape rules), the in-manifest signature list must be
/// empty (the detached cosign bundle sidecar is authoritative), and the
/// signing key id must still be well-formed even though it names no key.
#[cfg(feature = "manifest-verify")]
fn validate_signature_bundle_keyless(manifest: &PackManifest) -> Result<(), PackVerifyError> {
    if manifest.provenance.signature_bundle.format != SignatureFormat::Sigstore {
        return Err(PackVerifyError::WrongSignatureAuthority {
            expected: SignatureFormat::Sigstore,
            found: manifest.provenance.signature_bundle.format.clone(),
        });
    }
    if manifest.provenance.signature_bundle.payload != SignaturePayload::ManifestV1 {
        return Err(PackVerifyError::UnsupportedSignatureBundle);
    }
    if !manifest.provenance.signature_bundle.signatures.is_empty() {
        return Err(PackVerifyError::UnsupportedSignatureBundle);
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

/// Stream `path` through a `Sha256` hasher in fixed-size chunks (never reads
/// the whole file into memory) and return its lowercase-hex digest and byte
/// length. Shared with `action::hash_file_streaming`, which needs the raw
/// `io::Error` to tell a missing file apart from any other read failure.
pub(crate) fn stream_sha256(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

fn hash_file(path: &Path) -> Result<(Sha256Hex, u64), String> {
    let (hex, size) = stream_sha256(path).map_err(|error| error.to_string())?;
    Ok((Sha256Hex(hex), size))
}

pub(crate) fn is_sha256_hex(value: &str) -> bool {
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
    #[error("extension pack is missing its extension contract")]
    MissingExtensionContract,
    #[error("non-extension pack carries an extension contract")]
    UnexpectedExtensionContract,
    #[error("extension entrypoint {0:?} is not a declared pack file")]
    ExtensionEntrypointNotDeclared(String),
    #[error("invalid extension contract: {0}")]
    InvalidExtensionContract(#[from] ExtensionContractError),
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
    #[error("pack declares signature authority {found:?}, expected {expected:?}")]
    WrongSignatureAuthority {
        expected: SignatureFormat,
        found: SignatureFormat,
    },
    #[error("keyless signature verification failed: {0}")]
    KeylessSignatureInvalid(String),
    #[error("pack signer id {signing_key_id:?} matches no accepted release identity")]
    SignerIdentityMismatch { signing_key_id: KeyId },
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

/// The signing authority a `PackBuilder` assembles under. Carried at
/// construction rather than as an `Option<&SigningKey>` field so the two build
/// shapes — ed25519-keyed and keyless (Sigstore) — cannot be mismatched: there
/// is exactly one `build()` method, and which signing path it takes is fixed
/// the moment the builder is constructed, not decided by which finisher method
/// happens to get called.
enum PackSigner<'a> {
    Ed25519(&'a SigningKey),
    Keyless { identity: String },
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
    extension: Option<ExtensionPackContract>,
    signer: PackSigner<'a>,
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
            extension: None,
            signer: PackSigner::Ed25519(signing_key),
        }
    }

    /// Keyless counterpart to `new`: no ed25519 key, since the produced manifest
    /// carries no in-manifest signature — the detached cosign bundle a release
    /// pipeline signs separately is authoritative. `identity` is the release
    /// identity the manifest's `signing_key_id` is derived from.
    pub fn new_keyless(
        root: impl Into<PathBuf>,
        metadata: PackMetadata,
        identity: impl Into<String>,
    ) -> Self {
        Self {
            root: root.into(),
            metadata,
            output_hashes: PackOutputHashes::default(),
            files: Vec::new(),
            extension: None,
            signer: PackSigner::Keyless {
                identity: identity.into(),
            },
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

    /// Attach the generic extension declaration. Validation refuses it on any
    /// pack kind other than `extension`.
    pub fn extension(mut self, extension: ExtensionPackContract) -> Self {
        self.extension = Some(extension);
        self
    }

    /// Assembles and, for the ed25519 authority, signs the manifest. Which
    /// path runs is fixed by the `PackSigner` chosen at construction time:
    ///
    /// - `Ed25519`: signs the assembled manifest under the held key and
    ///   appends the resulting signature to the bundle.
    /// - `Keyless`: stamps a `Sigstore`-authority manifest with an
    ///   identity-derived `signing_key_id` and an empty in-manifest signature
    ///   list, and leaves it unsigned. The caller (a release pipeline) signs
    ///   `manifest.canonical_bytes()` out of band with `cosign sign-blob` and
    ///   ships the detached bundle as the pack's authority.
    pub fn build(self) -> Result<PackManifest, PackManifestError> {
        // Read the signer through a borrow first so `self` stays whole for the
        // `assemble` call below — `&SigningKey` is `Copy`, so this doesn't move
        // anything out of `self.signer`.
        let (signing_key_id, signature_format, signing_key) = match &self.signer {
            PackSigner::Ed25519(signing_key) => (
                key_id_from_pubkey(&signing_key.verifying_key()),
                SignatureFormat::Ed25519,
                Some(*signing_key),
            ),
            PackSigner::Keyless { identity } => (
                key_id_from_identity(identity),
                SignatureFormat::Sigstore,
                None,
            ),
        };
        let signature_validity = self.metadata.signature.clone();
        let mut manifest = self.assemble(signing_key_id.clone(), signature_format)?;
        if let Some(signing_key) = signing_key {
            let signature = signing_key.sign(&manifest.signature_payload_bytes()?);
            manifest
                .provenance
                .signature_bundle
                .signatures
                .push(PackSignature {
                    key_id: signing_key_id,
                    signature_base64: B64.encode(signature.to_bytes()),
                    signed_at: signature_validity.signed_at,
                    expires_at: signature_validity.expires_at,
                });
        }
        Ok(manifest)
    }

    /// Shared assembly for both authority shapes: hash the declared files,
    /// stamp outputs/provenance/trust from `self.metadata`, validate the
    /// required-output shape for `kind`, and compute the real pack hash (which
    /// covers `trust.signing_key_id`, so it must be computed after that field is
    /// set). Leaves the signature bundle's `signatures` list empty — `build`
    /// fills it in for the ed25519 authority; the Sigstore authority stays
    /// empty by design.
    fn assemble(
        self,
        signing_key_id: KeyId,
        signature_format: SignatureFormat,
    ) -> Result<PackManifest, PackManifestError> {
        let files = self.hash_files()?;
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
                format: signature_format,
                payload: SignaturePayload::ManifestV1,
                signatures: Vec::new(),
            },
        };
        let trust = TrustMetadata {
            signing_key_id,
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
            extension: self.extension,
            inputs: self.metadata.inputs,
            outputs,
            provenance,
            trust,
        };
        // Refuse to produce a manifest the verifier would reject for missing the
        // outputs this kind requires, rather than shipping a dead pack.
        validate_required_outputs(&manifest)?;
        manifest.outputs.pack_hash = manifest.computed_pack_hash()?;
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

    use mvm_contract::protocol::agent_capability::{
        AGENT_CAPABILITY_PROTOCOL_VERSION, CapabilityDescriptor, CapabilityId, CapabilityLimits,
        SchemaRef,
    };
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_contract::protocol::extension_pack::{
        EXTENSION_PACK_SCHEMA, ExtensionBudgets, ExtensionId, ExtensionPackContract,
        ExtensionPlacement, ExtensionProtocolRange, ExtensionVersion,
    };

    use super::*;

    #[test]
    fn signature_format_sigstore_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&SignatureFormat::Sigstore).expect("serialize"),
            "\"sigstore\""
        );
        let back: SignatureFormat =
            serde_json::from_str("\"sigstore\"").expect("deserialize sigstore");
        assert_eq!(back, SignatureFormat::Sigstore);
    }

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
        let key_id = key_id_from_pubkey(&key.verifying_key());
        let now = utc(2026, 6, 24);
        let policy_hash = hash("policy");
        let mut manifest = PackManifest {
            schema_version: PACK_SCHEMA_VERSION,
            kind,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Libkrun, PackBackend::Hvf],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: policy_hash.clone(),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            extension: None,
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
    fn structural_validation_ignores_signature_bundle_shape() {
        let mut f = fixture(PackKind::Runtime);
        f.manifest.provenance.signature_bundle.signatures.clear();
        // Full validate_manifest would fail on the empty bundle; structural must not.
        validate_manifest_structural(&f.manifest, &f.policy).expect("structural passes");
        assert!(matches!(
            validate_manifest(&f.manifest, &f.policy),
            Err(PackVerifyError::SignatureBundleEmpty)
        ));
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

    fn extension_contract(entrypoint: &str) -> ExtensionPackContract {
        let descriptor = CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.assurance.v1").expect("service"),
                "probe",
            )
            .expect("capability"))
            .description("one declared assurance probe")
            .input_schema(SchemaRef::new("probe.input.v1", [1; 32]).expect("input"))
            .output_schema(SchemaRef::new("probe.output.v1", [2; 32]).expect("output"))
            .limits(CapabilityLimits::new(4096, 4096, 1000).expect("limits"))
            .build()
            .expect("descriptor");
        ExtensionPackContract {
            schema: EXTENSION_PACK_SCHEMA.to_string(),
            extension_id: ExtensionId::parse("org.example.assurance").expect("id"),
            version: ExtensionVersion::parse("0.1.0").expect("version"),
            protocol: ExtensionProtocolRange {
                min_mvm_version: ExtensionVersion::parse("0.18.0").expect("min"),
                max_mvm_version: ExtensionVersion::parse("0.18.9").expect("max"),
                min_protocol: 1,
                max_protocol: 1,
            },
            placement: ExtensionPlacement::GuestWorkload,
            artifact: "extension.ext4".to_string(),
            entrypoint: entrypoint.to_string(),
            capabilities: vec![descriptor],
            budgets: ExtensionBudgets {
                cpu_millis: 500,
                memory_bytes: 128 * 1024 * 1024,
                duration_ms: 60_000,
                max_steps: 12,
                max_concurrency: 1,
                max_payload_bytes: 4096,
                max_output_bytes: 4096,
                max_artifact_bytes: 1024 * 1024,
            },
            revocation_identity: "org.example.assurance.release".to_string(),
            permission_delta: "May invoke one declared assurance probe.".to_string(),
        }
    }

    #[test]
    fn signed_extension_pack_verifies_through_the_generic_pack_path() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(
            dir.path().join("extension.ext4"),
            b"synthetic-extension-filesystem",
        )
        .expect("artifact");
        let key = signing_key();
        let manifest = PackBuilder::new(dir.path(), producer_metadata(PackKind::Extension), &key)
            .file("extension.ext4")
            .extension(extension_contract("bin/extension"))
            .build()
            .expect("produce extension pack");
        let verified = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &hvf_trust_store(),
            &StaticRevocation {
                status: RevocationStatus::Good,
            },
        )
        .expect("extension pack verifies");
        assert_eq!(verified.pack_hash, manifest.outputs.pack_hash);
        assert!(manifest.extension.is_some());
    }

    #[test]
    fn signed_extension_pack_refuses_an_unsupported_protocol() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("extension.ext4"), b"extension-filesystem").expect("artifact");
        let key = signing_key();
        let mut extension = extension_contract("bin/extension");
        extension.protocol.min_protocol = AGENT_CAPABILITY_PROTOCOL_VERSION.saturating_add(1);
        extension.protocol.max_protocol = extension.protocol.min_protocol;
        let manifest = PackBuilder::new(dir.path(), producer_metadata(PackKind::Extension), &key)
            .file("extension.ext4")
            .extension(extension)
            .build()
            .expect("produce extension pack");
        let error = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &hvf_trust_store(),
            &StaticRevocation {
                status: RevocationStatus::Good,
            },
        )
        .expect_err("unsupported protocol must fail");
        assert!(matches!(
            error,
            PackVerifyError::InvalidExtensionContract(
                ExtensionContractError::UnsupportedProtocolRange
            )
        ));
    }

    #[test]
    fn signed_extension_pack_refuses_an_untrusted_signer() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("extension.ext4"), b"extension-filesystem").expect("artifact");
        let key = signing_key();
        let manifest = PackBuilder::new(dir.path(), producer_metadata(PackKind::Extension), &key)
            .file("extension.ext4")
            .extension(extension_contract("bin/extension"))
            .build()
            .expect("produce extension pack");
        let error = verify_pack_at(
            &manifest,
            dir.path(),
            &hvf_policy(),
            &MapTrustStore {
                keys: HashMap::new(),
            },
            &StaticRevocation {
                status: RevocationStatus::Good,
            },
        )
        .expect_err("unknown signer must fail");
        assert!(matches!(error, PackVerifyError::UnknownSigningKey { .. }));
    }

    #[test]
    fn extension_entrypoint_must_be_a_verified_pack_file() {
        let mut manifest = fixture(PackKind::Runtime).manifest;
        manifest.kind = PackKind::Extension;
        let mut extension = extension_contract("bin/extension");
        extension.artifact = "not-declared.ext4".to_string();
        manifest.extension = Some(extension);
        assert!(matches!(
            validate_extension_contract(&manifest),
            Err(PackVerifyError::ExtensionEntrypointNotDeclared(_))
        ));
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
        let key_id = key_id_from_pubkey(&key.verifying_key());
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
            key_id_from_pubkey(&signing_key().verifying_key())
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
            key_id_from_pubkey(&signing_key().verifying_key())
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

    const SIGSTORE_IDENTITY: &str =
        "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";

    /// Produce a `Builder` pack via `PackBuilder::new_keyless` + `build`,
    /// exercising the same file set as `produced_hvf_builder_pack` but with no
    /// ed25519 key.
    fn produced_keyless_builder_pack(dir: &TempDir) -> PackManifest {
        fs::write(dir.path().join("kernel"), b"builder-kernel").expect("write kernel");
        fs::write(dir.path().join("builder.img"), b"builder-image").expect("write builder");
        PackBuilder::new_keyless(
            dir.path(),
            producer_metadata(PackKind::Builder),
            SIGSTORE_IDENTITY,
        )
        .files(["kernel", "builder.img"])
        .output_hashes(PackOutputHashes {
            kernel_hash: Some(Sha256Hex::from_bytes(b"builder-kernel")),
            builder_image_hash: Some(Sha256Hex::from_bytes(b"builder-image")),
            ..Default::default()
        })
        .build()
        .expect("produce keyless pack")
    }

    #[test]
    fn build_sigstore_produces_sigstore_authority_manifest() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_keyless_builder_pack(&dir);
        assert_eq!(
            manifest.provenance.signature_bundle.format,
            SignatureFormat::Sigstore
        );
        assert!(manifest.provenance.signature_bundle.signatures.is_empty());
        assert_eq!(
            manifest.trust.signing_key_id,
            key_id_from_identity(SIGSTORE_IDENTITY)
        );
    }

    #[test]
    fn build_sigstore_canonical_bytes_equal_signature_payload_bytes() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_keyless_builder_pack(&dir);
        // The empty-signatures invariant: for a Sigstore manifest the payload a
        // release pipeline signs is exactly the manifest's canonical bytes.
        assert_eq!(
            manifest.canonical_bytes().expect("canonical bytes"),
            manifest.signature_payload_bytes().expect("payload bytes")
        );
    }

    #[test]
    fn build_sigstore_pack_hash_is_self_consistent() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_keyless_builder_pack(&dir);
        assert_eq!(
            manifest.computed_pack_hash().expect("computed hash"),
            manifest.outputs.pack_hash
        );
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn build_sigstore_manifest_passes_keyless_shape_gate() {
        let dir = TempDir::new().expect("tempdir");
        let manifest = produced_keyless_builder_pack(&dir);
        assert!(validate_signature_bundle_keyless(&manifest).is_ok());
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
                key_id: key_id_from_pubkey(&key.verifying_key()),
                signature_base64: B64.encode(signature.to_bytes()),
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            });
    }

    #[cfg(feature = "manifest-verify")]
    mod keyless {
        use super::*;

        const IDENTITY: &str =
            "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.17.0";
        const ISSUER: &str = "https://token.actions.githubusercontent.com";

        fn trust() -> KeylessTrust {
            KeylessTrust {
                accepted_identities: vec![IDENTITY.to_string()],
                issuer: ISSUER.to_string(),
            }
        }

        /// A produced builder pack rewritten for the keyless authority: format
        /// flipped to `Sigstore`, the in-manifest signature cleared (the
        /// detached bundle is authoritative), and `signing_key_id` swapped for
        /// the identity-derived id. The pack hash is recomputed after editing
        /// `trust` since `signing_key_id` is covered by the pack-hash payload.
        fn sigstore_manifest(dir: &TempDir) -> PackManifest {
            let mut m = produced_hvf_builder_pack(dir);
            m.provenance.signature_bundle.format = SignatureFormat::Sigstore;
            m.provenance.signature_bundle.signatures.clear();
            m.trust.signing_key_id = key_id_from_identity(IDENTITY);
            m.outputs.pack_hash = m.computed_pack_hash().expect("pack hash");
            m
        }

        #[test]
        fn ed25519_pack_rejected_by_keyless_verifier() {
            let dir = TempDir::new().expect("tempdir");
            let m = produced_hvf_builder_pack(&dir);
            let err = verify_pack_keyless_at(
                &m,
                dir.path(),
                &hvf_policy(),
                b"bundle",
                &trust(),
                &StaticRevocation {
                    status: RevocationStatus::Good,
                },
            )
            .expect_err("wrong authority");
            assert!(matches!(
                err,
                PackVerifyError::WrongSignatureAuthority { .. }
            ));
        }

        #[test]
        fn garbage_bundle_is_keyless_signature_invalid() {
            let dir = TempDir::new().expect("tempdir");
            let m = sigstore_manifest(&dir);
            let err = verify_pack_keyless_at(
                &m,
                dir.path(),
                &hvf_policy(),
                b"not a bundle",
                &trust(),
                &StaticRevocation {
                    status: RevocationStatus::Good,
                },
            )
            .expect_err("bad bundle");
            assert!(matches!(err, PackVerifyError::KeylessSignatureInvalid(_)));
        }

        #[test]
        fn signer_id_not_matching_accepted_identity_is_rejected() {
            let dir = TempDir::new().expect("tempdir");
            // sigstore_manifest stamps signing_key_id = from_identity(IDENTITY).
            let m = sigstore_manifest(&dir);
            // A trust root that accepts only a different release identity: its
            // derived id can't equal the stamped one, so the pack is refused
            // before any signature bytes are examined — the stamped signer id
            // must correspond to the identity that would verify it.
            let other = KeylessTrust {
                accepted_identities: vec![
                    "https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v9.9.9"
                        .to_string(),
                ],
                issuer: ISSUER.to_string(),
            };
            let err = verify_pack_keyless_at(
                &m,
                dir.path(),
                &hvf_policy(),
                b"bundle",
                &other,
                &StaticRevocation {
                    status: RevocationStatus::Good,
                },
            )
            .expect_err("signer id mismatch");
            assert!(matches!(
                err,
                PackVerifyError::SignerIdentityMismatch { .. }
            ));
        }

        #[test]
        fn non_empty_signatures_rejected_by_keyless_shape_gate() {
            let dir = TempDir::new().expect("tempdir");
            let mut m = sigstore_manifest(&dir);
            // A Sigstore-declared pack must still carry an empty signature
            // list; restoring one here exercises the shape gate rather than
            // the signature step.
            m.provenance
                .signature_bundle
                .signatures
                .push(PackSignature {
                    key_id: key_id_from_identity(IDENTITY),
                    signature_base64: B64.encode([0u8; 64]),
                    signed_at: utc(2026, 6, 24),
                    expires_at: utc(2026, 12, 31),
                });
            m.outputs.pack_hash = m.computed_pack_hash().expect("pack hash");
            let err = verify_pack_keyless_at(
                &m,
                dir.path(),
                &hvf_policy(),
                b"not a bundle",
                &trust(),
                &StaticRevocation {
                    status: RevocationStatus::Good,
                },
            )
            .expect_err("non-empty signatures rejected");
            assert!(matches!(err, PackVerifyError::UnsupportedSignatureBundle));
        }

        #[test]
        fn malformed_signing_key_id_rejected_by_keyless_shape_gate() {
            let dir = TempDir::new().expect("tempdir");
            let mut m = sigstore_manifest(&dir);
            m.trust.signing_key_id = KeyId("not-well-formed".to_string());
            m.outputs.pack_hash = m.computed_pack_hash().expect("pack hash");
            let err = verify_pack_keyless_at(
                &m,
                dir.path(),
                &hvf_policy(),
                b"not a bundle",
                &trust(),
                &StaticRevocation {
                    status: RevocationStatus::Good,
                },
            )
            .expect_err("malformed key id rejected");
            assert!(matches!(err, PackVerifyError::MalformedKeyId(_)));
        }
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn keyless_verifier_fails_closed_without_manifest_verify_feature() {
        let dir = TempDir::new().expect("tempdir");
        let m = produced_hvf_builder_pack(&dir);
        let trust = KeylessTrust {
            accepted_identities: vec!["irrelevant".to_string()],
            issuer: "irrelevant".to_string(),
        };
        let err = verify_pack_keyless_at(
            &m,
            dir.path(),
            &hvf_policy(),
            b"bundle",
            &trust,
            &StaticRevocation {
                status: RevocationStatus::Good,
            },
        )
        .expect_err("keyless verifier disabled without feature");
        assert!(matches!(err, PackVerifyError::KeylessSignatureInvalid(_)));
    }
}
