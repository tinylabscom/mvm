//! Stable identities and digest pins for registry-delivered product packs.
//!
//! This is deliberately separate from [`crate::packs`]. That module describes
//! MVM's verified runtime/build artifacts, while registry packs are user-facing
//! products named `namespace/name[@version]`. A lockfile selects one exact
//! version and hashes the raw manifest bytes before a later layer parses or
//! verifies the signed manifest.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::crypto::image_verify::VerifiedSigner;
use crate::packs::{KeylessTrust, Sha256Hex, pack_path_is_safe};
use crate::release_version::{ReleaseVersion, VersionSyntax};

/// Current on-disk registry-pack lockfile schema.
pub const PACK_LOCK_SCHEMA_VERSION: u32 = 1;
/// Current signed product-pack manifest schema.
pub const REGISTRY_PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Current publisher trust-policy schema.
pub const REGISTRY_PACK_PUBLISHER_POLICY_SCHEMA_VERSION: u32 = 1;

const REGISTRY_PAYLOAD_DIR_NAME: &str = "payload";
const MAX_REGISTRY_PAYLOAD_FILES: usize = 4096;
const MAX_REGISTRY_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024 * 1024;
pub(crate) const REGISTRY_MANIFEST_FILE_NAME: &str = "manifest.json";
pub(crate) const REGISTRY_SIGNATURE_FILE_NAME: &str = "manifest.sigstore.json";

/// Errors produced while parsing registry identities or enforcing a lockfile.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryPackError {
    /// A user or registry supplied a non-canonical pack reference.
    #[error("invalid pack reference {value:?}: {reason}")]
    InvalidReference { value: String, reason: String },
    /// Lock entries must pin a version rather than follow a mutable latest.
    #[error("pack lock entry {reference:?} does not include an exact version")]
    UnversionedPin { reference: String },
    /// The lock schema is newer or older than this binary understands.
    #[error("unsupported pack lock schema version {got}; expected {expected}")]
    UnsupportedSchemaVersion { got: u32, expected: u32 },
    /// A lock may select only one version for each namespace/name coordinate.
    #[error("pack lock contains more than one pin for {coordinate}")]
    DuplicatePin { coordinate: String },
    /// Resolution tried to use a pack absent from the lock.
    #[error("pack {reference} is not pinned in the lockfile")]
    UnpinnedPack { reference: String },
    /// A versioned request disagreed with the lock's exact selection.
    #[error("pack {coordinate} requested version {requested}, but the lock pins {pinned}")]
    RequestedVersionMismatch {
        coordinate: String,
        requested: String,
        pinned: String,
    },
    /// The fetched manifest bytes differ from the digest selected by the lock.
    #[error("pack manifest digest drift for {reference}: pinned {pinned:?}, got {actual:?}")]
    ManifestDigestMismatch {
        reference: String,
        pinned: Sha256Hex,
        actual: Sha256Hex,
    },
}

/// Namespace/name identity shared by versioned and unversioned references.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PackCoordinate {
    namespace: String,
    name: String,
}

impl PackCoordinate {
    fn parse(value: &str) -> Result<Self, RegistryPackError> {
        let Some((namespace, name)) = value.split_once('/') else {
            return Err(invalid_reference(value, "expected namespace/name"));
        };
        if name.contains('/') {
            return Err(invalid_reference(
                value,
                "expected exactly one namespace separator",
            ));
        }
        validate_component(value, "namespace", namespace)?;
        validate_component(value, "name", name)?;
        Ok(Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
        })
    }
}

impl fmt::Display for PackCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// A strict semantic version preserved in the exact spelling a registry signs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackVersion(String);

impl PackVersion {
    fn parse(reference: &str, value: &str) -> Result<Self, RegistryPackError> {
        if ReleaseVersion::parse(value, VersionSyntax::Strict).is_none() {
            return Err(invalid_reference(
                reference,
                "version must be canonical semantic version syntax",
            ));
        }
        Ok(Self(value.to_string()))
    }

    /// Return the canonical semantic-version text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A product-pack reference in `namespace/name[@version]` form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackReference {
    coordinate: PackCoordinate,
    version: Option<PackVersion>,
}

impl PackReference {
    /// Pack namespace, such as `agents` or `runtime`.
    pub fn namespace(&self) -> &str {
        &self.coordinate.namespace
    }

    /// Pack name within its namespace.
    pub fn name(&self) -> &str {
        &self.coordinate.name
    }

    /// Requested exact version, or `None` when the lock selects it.
    pub fn version(&self) -> Option<&PackVersion> {
        self.version.as_ref()
    }

    pub fn coordinate_string(&self) -> String {
        self.coordinate.to_string()
    }
}

impl FromStr for PackReference {
    type Err = RegistryPackError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.contains(char::is_whitespace) {
            return Err(invalid_reference(
                value,
                "reference is empty or contains whitespace",
            ));
        }
        let (coordinate, version) = match value.split_once('@') {
            Some((coordinate, version)) if !version.contains('@') => {
                let parsed = PackVersion::parse(value, version)?;
                (coordinate, Some(parsed))
            }
            Some(_) => {
                return Err(invalid_reference(
                    value,
                    "expected at most one version separator",
                ));
            }
            None => (value, None),
        };
        Ok(Self {
            coordinate: PackCoordinate::parse(coordinate)?,
            version,
        })
    }
}

impl fmt::Display for PackReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.coordinate.fmt(f)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

impl Serialize for PackReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PackReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

/// One exact registry-pack version and the digest of its signed manifest bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackPin {
    reference: PackReference,
    manifest_sha256: Sha256Hex,
}

impl PackPin {
    /// Construct a pin, refusing a reference that omits its version.
    pub fn new(
        reference: PackReference,
        manifest_sha256: Sha256Hex,
    ) -> Result<Self, RegistryPackError> {
        if reference.version.is_none() {
            return Err(RegistryPackError::UnversionedPin {
                reference: reference.to_string(),
            });
        }
        Ok(Self {
            reference,
            manifest_sha256,
        })
    }

    /// Exact versioned reference selected by this pin.
    pub fn reference(&self) -> &PackReference {
        &self.reference
    }

    /// SHA-256 digest of the exact signed manifest bytes.
    pub fn manifest_sha256(&self) -> &Sha256Hex {
        &self.manifest_sha256
    }
}

impl<'de> Deserialize<'de> for PackPin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WirePin {
            reference: PackReference,
            manifest_sha256: Sha256Hex,
        }

        let wire = WirePin::deserialize(deserializer)?;
        PackPin::new(wire.reference, wire.manifest_sha256).map_err(serde::de::Error::custom)
    }
}

/// Fail-closed selection of one exact signed manifest per product-pack name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackLockfile {
    schema_version: u32,
    packs: Vec<PackPin>,
}

impl PackLockfile {
    /// Construct a lock under the current schema and reject duplicate names.
    pub fn new(packs: Vec<PackPin>) -> Result<Self, RegistryPackError> {
        validate_pins(&packs)?;
        Ok(Self {
            schema_version: PACK_LOCK_SCHEMA_VERSION,
            packs,
        })
    }

    /// Exact pins in their stable serialized order.
    pub fn pins(&self) -> &[PackPin] {
        &self.packs
    }

    /// Require the requested pack to be pinned and the raw manifest bytes to
    /// match its exact digest.
    pub fn verify_manifest(
        &self,
        requested: &PackReference,
        manifest_bytes: &[u8],
    ) -> Result<&PackPin, RegistryPackError> {
        let pin = self
            .packs
            .iter()
            .find(|pin| pin.reference.coordinate == requested.coordinate)
            .ok_or_else(|| RegistryPackError::UnpinnedPack {
                reference: requested.to_string(),
            })?;

        if let Some(requested_version) = &requested.version {
            let pinned_version = pin
                .reference
                .version
                .as_ref()
                .expect("PackPin construction requires a version");
            if requested_version != pinned_version {
                return Err(RegistryPackError::RequestedVersionMismatch {
                    coordinate: requested.coordinate_string(),
                    requested: requested_version.to_string(),
                    pinned: pinned_version.to_string(),
                });
            }
        }

        let actual = Sha256Hex::from_bytes(manifest_bytes);
        if actual != pin.manifest_sha256 {
            return Err(RegistryPackError::ManifestDigestMismatch {
                reference: pin.reference.to_string(),
                pinned: pin.manifest_sha256.clone(),
                actual,
            });
        }
        Ok(pin)
    }
}

impl<'de> Deserialize<'de> for PackLockfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireLock {
            schema_version: u32,
            packs: Vec<PackPin>,
        }

        let wire = WireLock::deserialize(deserializer)?;
        if wire.schema_version != PACK_LOCK_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(
                RegistryPackError::UnsupportedSchemaVersion {
                    got: wire.schema_version,
                    expected: PACK_LOCK_SCHEMA_VERSION,
                },
            ));
        }
        PackLockfile::new(wire.packs).map_err(serde::de::Error::custom)
    }
}

/// One file declared by a signed product-pack manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackFile {
    /// Normal relative path below the pack root.
    pub path: String,
    /// Digest of the exact file bytes.
    pub sha256: Sha256Hex,
    /// Exact file length in bytes.
    pub size: u64,
}

/// The signed manifest declares either a legacy source image or an immutable
/// built workload image, never both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RegistryPackImage {
    Source(RegistryPackSourceImage),
    Built(Box<crate::registry_pack_image::BuiltPackImageDescriptor>),
}

/// Source files for a legacy microVM image a pack can build and boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackSourceImage {
    /// In-pack path to `mvm.toml` beside `flake.nix` and `flake.lock`.
    pub manifest: String,
}

/// Strict metadata signed by a registry-pack publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackManifest {
    pub schema_version: u32,
    /// Exact versioned identity of these manifest bytes.
    pub reference: PackReference,
    pub description: String,
    /// Optional for policy-only packs; required when booting a pack's image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<RegistryPackImage>,
    pub files: Vec<RegistryPackFile>,
}

/// Keyless signing authority permitted to publish one namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryPackPublisher {
    namespace: String,
    issuer: String,
    accepted_identities: Vec<String>,
}

impl RegistryPackPublisher {
    /// Construct a publisher authority, refusing malformed or ambiguous input.
    ///
    /// The namespace `"*"` is the wildcard: it applies to every namespace
    /// that has no exact publisher entry. Operators choose it explicitly.
    pub fn new(
        namespace: impl Into<String>,
        issuer: impl Into<String>,
        accepted_identities: Vec<String>,
    ) -> Result<Self, RegistryPackVerificationError> {
        let namespace = namespace.into();
        if namespace != "*" {
            PackCoordinate::parse(&format!("{namespace}/pack")).map_err(|error| {
                RegistryPackVerificationError::InvalidPublisherPolicy {
                    reason: error.to_string(),
                }
            })?;
        }
        let issuer = issuer.into();
        if issuer.trim().is_empty() {
            return Err(RegistryPackVerificationError::InvalidPublisherPolicy {
                reason: "publisher issuer is empty".to_string(),
            });
        }
        let mut identities = BTreeSet::new();
        for identity in &accepted_identities {
            if identity.trim().is_empty() || !identities.insert(identity) {
                return Err(RegistryPackVerificationError::InvalidPublisherPolicy {
                    reason: "publisher identities must be non-empty and unique".to_string(),
                });
            }
        }
        if accepted_identities.is_empty() {
            return Err(RegistryPackVerificationError::InvalidPublisherPolicy {
                reason: "publisher must declare at least one signing identity".to_string(),
            });
        }
        Ok(Self {
            namespace,
            issuer,
            accepted_identities,
        })
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn keyless_trust(&self) -> KeylessTrust {
        KeylessTrust {
            accepted_identities: self.accepted_identities.clone(),
            issuer: self.issuer.clone(),
        }
    }
}

impl<'de> Deserialize<'de> for RegistryPackPublisher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WirePublisher {
            namespace: String,
            issuer: String,
            accepted_identities: Vec<String>,
        }

        let wire = WirePublisher::deserialize(deserializer)?;
        Self::new(wire.namespace, wire.issuer, wire.accepted_identities)
            .map_err(serde::de::Error::custom)
    }
}

/// Operator-owned map from pack namespaces to accepted signing authorities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryPackPublisherPolicy {
    schema_version: u32,
    publishers: Vec<RegistryPackPublisher>,
    #[serde(skip)]
    legacy_identity_expires_at: Option<DateTime<Utc>>,
}

impl RegistryPackPublisherPolicy {
    pub fn new(
        publishers: Vec<RegistryPackPublisher>,
    ) -> Result<Self, RegistryPackVerificationError> {
        let mut namespaces = BTreeSet::new();
        for publisher in &publishers {
            if !namespaces.insert(publisher.namespace.clone()) {
                return Err(RegistryPackVerificationError::DuplicatePublisherNamespace {
                    namespace: publisher.namespace.clone(),
                });
            }
        }
        Ok(Self {
            schema_version: REGISTRY_PACK_PUBLISHER_POLICY_SCHEMA_VERSION,
            publishers,
            legacy_identity_expires_at: None,
        })
    }

    pub fn publishers(&self) -> &[RegistryPackPublisher] {
        &self.publishers
    }

    /// The trust for `namespace`: the exact publisher entry when one exists,
    /// otherwise the `"*"` wildcard publisher when the policy declares one.
    pub fn trust_for_namespace(
        &self,
        namespace: &str,
    ) -> Result<KeylessTrust, RegistryPackVerificationError> {
        self.trust_for_namespace_at(namespace, Utc::now())
    }

    fn trust_for_namespace_at(
        &self,
        namespace: &str,
        now: DateTime<Utc>,
    ) -> Result<KeylessTrust, RegistryPackVerificationError> {
        let mut trust = self
            .publishers
            .iter()
            .find(|publisher| publisher.namespace == namespace)
            .or_else(|| {
                self.publishers
                    .iter()
                    .find(|publisher| publisher.namespace == "*")
            })
            .map(RegistryPackPublisher::keyless_trust)
            .ok_or_else(|| RegistryPackVerificationError::UntrustedNamespace {
                namespace: namespace.to_string(),
            })?;
        if self
            .legacy_identity_expires_at
            .as_ref()
            .is_some_and(|cutoff| &now >= cutoff)
        {
            trust
                .accepted_identities
                .retain(|identity| identity != LEGACY_PACK_SIGNING_IDENTITY);
        }
        Ok(trust)
    }
}

/// Keyless signing identity of the official pack registry's publish workflow.
///
/// Packs published from `tinylabscom/mvm-packs` are signed keyless in
/// `.github/workflows/publish.yml` on the main branch; trust decisions check
/// this identity under the GitHub OIDC issuer.
pub const OFFICIAL_PACK_SIGNING_IDENTITY: &str =
    "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main";

/// Previous publish identity accepted temporarily for `agent` and `runtime`
/// packs that were signed before the repository rename.
pub const LEGACY_PACK_SIGNING_IDENTITY: &str =
    "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main";

/// UTC instant when the built-in policy stops accepting the previous identity.
pub const LEGACY_PACK_SIGNING_CUTOFF: &str = "2026-11-06T00:00:00Z";

/// OIDC issuer that vouches for [`OFFICIAL_PACK_SIGNING_IDENTITY`].
pub const OFFICIAL_PACK_SIGNING_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The publisher trust policy that applies when the operator has made no
/// trust decision of their own. It accepts only the existing `agent` and
/// `runtime` namespaces under the current identity, and temporarily under
/// the previous identity. An operator policy file replaces it wholesale.
pub fn official_publisher_policy() -> RegistryPackPublisherPolicy {
    let publishers = ["agent", "runtime"]
        .into_iter()
        .map(|namespace| {
            RegistryPackPublisher::new(
                namespace,
                OFFICIAL_PACK_SIGNING_ISSUER,
                vec![
                    OFFICIAL_PACK_SIGNING_IDENTITY.to_string(),
                    LEGACY_PACK_SIGNING_IDENTITY.to_string(),
                ],
            )
            .expect("the built-in publisher policy is built from valid constants")
        })
        .collect();
    let mut policy = RegistryPackPublisherPolicy::new(publishers)
        .expect("the built-in publisher policy has unique namespaces");
    policy.legacy_identity_expires_at = Some(
        DateTime::parse_from_rfc3339(LEGACY_PACK_SIGNING_CUTOFF)
            .expect("the built-in legacy identity cutoff is valid")
            .with_timezone(&Utc),
    );
    policy
}

impl<'de> Deserialize<'de> for RegistryPackPublisherPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WirePolicy {
            schema_version: u32,
            publishers: Vec<RegistryPackPublisher>,
        }

        let wire = WirePolicy::deserialize(deserializer)?;
        if wire.schema_version != REGISTRY_PACK_PUBLISHER_POLICY_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(
                RegistryPackVerificationError::UnsupportedPublisherPolicySchema {
                    got: wire.schema_version,
                    expected: REGISTRY_PACK_PUBLISHER_POLICY_SCHEMA_VERSION,
                },
            ));
        }
        Self::new(wire.publishers).map_err(serde::de::Error::custom)
    }
}

/// Inputs required to authenticate and parse one registry-pack manifest.
#[derive(Clone, Copy)]
pub struct RegistryPackVerification<'a> {
    requested: &'a PackReference,
    manifest_bytes: &'a [u8],
    signature_bundle: &'a [u8],
    lock: &'a PackLockfile,
    publisher_policy: &'a RegistryPackPublisherPolicy,
}

impl<'a> RegistryPackVerification<'a> {
    pub fn new(
        requested: &'a PackReference,
        manifest_bytes: &'a [u8],
        signature_bundle: &'a [u8],
        lock: &'a PackLockfile,
        publisher_policy: &'a RegistryPackPublisherPolicy,
    ) -> Self {
        Self {
            requested,
            manifest_bytes,
            signature_bundle,
            lock,
            publisher_policy,
        }
    }
}

/// A manifest authenticated against both the lock and namespace authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryPack {
    manifest: RegistryPackManifest,
    manifest_sha256: Sha256Hex,
    manifest_bytes: Vec<u8>,
    signature_bundle: Vec<u8>,
    signer: VerifiedSigner,
}

impl VerifiedRegistryPack {
    pub fn manifest(&self) -> &RegistryPackManifest {
        &self.manifest
    }

    pub fn manifest_sha256(&self) -> &Sha256Hex {
        &self.manifest_sha256
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn signature_bundle(&self) -> &[u8] {
        &self.signature_bundle
    }

    /// The certificate identity that authenticated the signed manifest.
    pub fn signer(&self) -> &VerifiedSigner {
        &self.signer
    }

    /// Registry-local files and separately released image assets form one
    /// authenticated payload. Their names cannot overlap.
    pub fn payload_files(&self) -> Vec<RegistryPackFile> {
        payload_files(&self.manifest)
    }
}

fn payload_files(manifest: &RegistryPackManifest) -> Vec<RegistryPackFile> {
    let mut files = manifest.files.clone();
    if let Some(RegistryPackImage::Built(image)) = &manifest.image {
        files.extend(image.assets().into_iter().map(|asset| RegistryPackFile {
            path: asset.name.as_str().to_string(),
            sha256: asset.sha256.clone(),
            size: asset.size,
        }));
    }
    files
}

/// A registry pack published beneath its exact manifest digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRegistryPack {
    root: PathBuf,
}

impl InstalledRegistryPack {
    pub(crate) fn from_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn payload_root(&self) -> PathBuf {
        self.root.join(REGISTRY_PAYLOAD_DIR_NAME)
    }

    /// Exact signed manifest bytes recorded beside the payload.
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(REGISTRY_MANIFEST_FILE_NAME)
    }

    /// Sigstore bundle authenticating the manifest.
    pub fn signature_path(&self) -> PathBuf {
        self.root.join(REGISTRY_SIGNATURE_FILE_NAME)
    }
}

#[derive(Debug, Error)]
pub enum RegistryPackInstallError {
    #[error(transparent)]
    Verification(#[from] RegistryPackVerificationError),
    #[error(transparent)]
    Cache(#[from] crate::pack_cache::PackCacheError),
    #[error("registry-pack cache i/o error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

fn install_io_at(path: &Path) -> impl Fn(std::io::Error) -> RegistryPackInstallError + '_ {
    move |source| RegistryPackInstallError::Io {
        path: path.display().to_string(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum RegistryPackVerificationError {
    #[error(transparent)]
    Lock(#[from] RegistryPackError),
    #[error("invalid registry-pack publisher policy: {reason}")]
    InvalidPublisherPolicy { reason: String },
    #[error("duplicate publisher authority for namespace {namespace}")]
    DuplicatePublisherNamespace { namespace: String },
    #[error("unsupported publisher policy schema version {got}; expected {expected}")]
    UnsupportedPublisherPolicySchema { got: u32, expected: u32 },
    #[error("no trusted publisher is configured for namespace {namespace}")]
    UntrustedNamespace { namespace: String },
    #[error("registry-pack signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error("registry-pack manifest is not valid JSON: {0}")]
    ManifestParse(String),
    #[error("unsupported registry-pack manifest schema version {got}; expected {expected}")]
    UnsupportedManifestSchema { got: u32, expected: u32 },
    #[error("registry-pack manifest names {manifest}, but the lock selects {locked}")]
    ManifestReferenceMismatch { manifest: String, locked: String },
    #[error("registry-pack manifest description is empty")]
    EmptyDescription,
    #[error("registry-pack manifest contains no files")]
    EmptyFiles,
    #[error("registry-pack manifest contains duplicate file {path:?}")]
    DuplicateFile { path: String },
    #[error("registry-pack manifest contains unsafe file path {path:?}")]
    UnsafeFilePath { path: String },
    #[error("registry-pack image declaration is invalid: {reason}")]
    InvalidImageDeclaration { reason: String },
    #[error(
        "no trusted released image verifier compatible with the current image-set lock is available"
    )]
    BuiltImageVerifierUnavailable,
    #[error("registry-pack image mvm.toml is invalid: {reason}")]
    InvalidImageManifest { reason: String },
    #[error("registry-pack payload path {path:?} could not be read: {reason}")]
    PayloadFileRead { path: String, reason: String },
    #[error("registry-pack payload path {path:?} is not a regular file")]
    NonRegularPayloadPath { path: String },
    #[error(
        "registry-pack payload file {path:?} size mismatch: declared {declared}, actual {actual}"
    )]
    PayloadSizeMismatch {
        path: String,
        declared: u64,
        actual: u64,
    },
    #[error(
        "registry-pack payload file {path:?} digest mismatch: declared {declared:?}, actual {actual:?}"
    )]
    PayloadHashMismatch {
        path: String,
        declared: Sha256Hex,
        actual: Sha256Hex,
    },
    #[error("registry-pack payload contains undeclared path {path:?}")]
    UndeclaredPayloadPath { path: String },
}

/// Verify the lock pin and publisher signature before parsing the manifest.
pub fn verify_registry_pack(
    request: &RegistryPackVerification<'_>,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    verify_registry_pack_with(request, check_registry_pack_signature)
}

/// Verify a fetched pack for first adoption, before any pin exists.
///
/// The load path is lock-first: [`verify_registry_pack`] refuses drift between
/// a pinned digest and fetched bytes. Adoption inverts the order because there
/// is nothing to drift against yet: the namespace authority is consulted
/// first, the signature is checked against it, and only then is the manifest
/// parsed and its reference matched against the request. The caller derives a
/// pin from the returned value and records it in the lockfile.
pub fn adopt_registry_pack(
    request: &PackAdoption<'_>,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    adopt_registry_pack_with(request, check_registry_pack_signature)
}

/// A fetched pack awaiting first adoption: exact bytes, no pin yet.
#[derive(Debug, Clone, Copy)]
pub struct PackAdoption<'a> {
    pub requested: &'a PackReference,
    pub manifest_bytes: &'a [u8],
    pub signature_bundle: &'a [u8],
    pub publisher_policy: &'a RegistryPackPublisherPolicy,
}

pub(crate) type RegistryPackSignatureChecker =
    fn(&[u8], &[u8], &KeylessTrust) -> Result<VerifiedSigner, RegistryPackVerificationError>;

/// The production signature checker (real cosign verification when the
/// `manifest-verify` feature is built in, an unconditional refusal
/// otherwise). Crate-internal so the store facade's public entry points can
/// default to it.
pub(crate) fn default_signature_checker() -> RegistryPackSignatureChecker {
    check_registry_pack_signature
}

pub(crate) fn adopt_registry_pack_with(
    request: &PackAdoption<'_>,
    check_signature: RegistryPackSignatureChecker,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    let trust = request
        .publisher_policy
        .trust_for_namespace(request.requested.namespace())?;
    let signer = check_signature(request.manifest_bytes, request.signature_bundle, &trust)?;
    finish_registry_pack_verification(
        request.requested,
        request.manifest_bytes,
        request.signature_bundle,
        signer,
        None,
    )
}

pub(crate) fn verify_registry_pack_with(
    request: &RegistryPackVerification<'_>,
    check_signature: RegistryPackSignatureChecker,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    let pin = request
        .lock
        .verify_manifest(request.requested, request.manifest_bytes)?;
    let trust = request
        .publisher_policy
        .trust_for_namespace(pin.reference().namespace())?;
    let signer = check_signature(request.manifest_bytes, request.signature_bundle, &trust)?;
    finish_registry_pack_verification(
        request.requested,
        request.manifest_bytes,
        request.signature_bundle,
        signer,
        Some(pin),
    )
}

fn finish_registry_pack_verification(
    requested: &PackReference,
    manifest_bytes: &[u8],
    signature_bundle: &[u8],
    signer: VerifiedSigner,
    pin: Option<&PackPin>,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    let manifest: RegistryPackManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| RegistryPackVerificationError::ManifestParse(error.to_string()))?;
    if manifest.schema_version != REGISTRY_PACK_MANIFEST_SCHEMA_VERSION {
        return Err(RegistryPackVerificationError::UnsupportedManifestSchema {
            got: manifest.schema_version,
            expected: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
        });
    }
    let manifest_sha256 = match pin {
        Some(pin) => {
            if &manifest.reference != pin.reference() {
                return Err(RegistryPackVerificationError::ManifestReferenceMismatch {
                    manifest: manifest.reference.to_string(),
                    locked: pin.reference().to_string(),
                });
            }
            pin.manifest_sha256().clone()
        }
        None => {
            if manifest.reference.coordinate != requested.coordinate
                || requested
                    .version
                    .as_ref()
                    .is_some_and(|version| Some(version) != manifest.reference.version.as_ref())
            {
                return Err(RegistryPackVerificationError::ManifestReferenceMismatch {
                    manifest: manifest.reference.to_string(),
                    locked: requested.to_string(),
                });
            }
            Sha256Hex::from_bytes(manifest_bytes)
        }
    };
    validate_registry_pack_manifest(&manifest)?;
    Ok(VerifiedRegistryPack {
        manifest,
        manifest_sha256,
        manifest_bytes: manifest_bytes.to_vec(),
        signature_bundle: signature_bundle.to_vec(),
        signer,
    })
}

fn validate_registry_pack_manifest(
    manifest: &RegistryPackManifest,
) -> Result<(), RegistryPackVerificationError> {
    if manifest.description.trim().is_empty() {
        return Err(RegistryPackVerificationError::EmptyDescription);
    }
    if manifest.files.is_empty() {
        return Err(RegistryPackVerificationError::EmptyFiles);
    }
    let mut paths = BTreeSet::new();
    let files = payload_files(manifest);
    if files.len() > MAX_REGISTRY_PAYLOAD_FILES {
        return Err(RegistryPackVerificationError::InvalidImageDeclaration {
            reason: "pack payload exceeds 4096 files".to_string(),
        });
    }
    let total = files
        .iter()
        .try_fold(0_u64, |sum, file| sum.checked_add(file.size));
    if total.is_none_or(|size| size > MAX_REGISTRY_PAYLOAD_BYTES) {
        return Err(RegistryPackVerificationError::InvalidImageDeclaration {
            reason: "pack payload exceeds 32 GiB".to_string(),
        });
    }
    for file in &files {
        if !paths.insert(file.path.as_str()) {
            return Err(RegistryPackVerificationError::DuplicateFile {
                path: file.path.clone(),
            });
        }
        if !pack_path_is_safe(&file.path) {
            return Err(RegistryPackVerificationError::UnsafeFilePath {
                path: file.path.clone(),
            });
        }
    }
    for path in &paths {
        for parent in Path::new(path).ancestors().skip(1) {
            if paths.contains(parent.to_string_lossy().as_ref()) {
                return Err(RegistryPackVerificationError::UnsafeFilePath {
                    path: path.to_string(),
                });
            }
        }
    }
    if let Some(RegistryPackImage::Source(image)) = &manifest.image {
        let path = &image.manifest;
        let manifest_path = Path::new(path);
        if !pack_path_is_safe(path)
            || !path.starts_with("pack/")
            || manifest_path
                .file_name()
                .is_none_or(|name| name != "mvm.toml")
        {
            return Err(RegistryPackVerificationError::InvalidImageDeclaration {
                reason: format!("manifest path {path:?} must be a safe in-pack mvm.toml"),
            });
        }
        let parent = manifest_path
            .parent()
            .expect("a safe in-pack mvm.toml has a parent");
        for name in ["mvm.toml", "flake.nix", "flake.lock"] {
            let required = parent.join(name);
            let required = required.to_string_lossy();
            if !paths.contains(required.as_ref()) {
                return Err(RegistryPackVerificationError::InvalidImageDeclaration {
                    reason: format!("image source file {required:?} is not declared"),
                });
            }
        }
    }
    if let Some(RegistryPackImage::Built(image)) = &manifest.image {
        image
            .validate_pin(
                &manifest.reference,
                &crate::image_set::image_train_lock().image_set,
            )
            .map_err(
                |error| RegistryPackVerificationError::InvalidImageDeclaration {
                    reason: error.to_string(),
                },
            )?;
    }
    Ok(())
}

mod built_image;
use built_image::verify_built_image_authenticity;
pub use built_image::{ensure_built_image_verifier_available, verify_built_image_provenance};

/// Verify the unpacked payload against an already authenticated manifest.
///
/// Every declared file must be a regular file with the exact signed length and
/// digest. The payload must contain no undeclared files or symbolic links, so a
/// transport cannot smuggle unsigned content into a later profile or runtime
/// reader.
pub fn verify_registry_pack_contents(
    verified: &VerifiedRegistryPack,
    root: &Path,
) -> Result<(), RegistryPackVerificationError> {
    verify_registry_pack_contents_with(verified, root, verify_built_image_authenticity)
}

type BuiltImageChecker =
    fn(&VerifiedRegistryPack, &Path) -> Result<(), RegistryPackVerificationError>;

fn verify_registry_pack_contents_with(
    verified: &VerifiedRegistryPack,
    root: &Path,
    check_built: BuiltImageChecker,
) -> Result<(), RegistryPackVerificationError> {
    use std::io::Read;
    let root_metadata = std::fs::symlink_metadata(root).map_err(|error| {
        RegistryPackVerificationError::PayloadFileRead {
            path: ".".to_string(),
            reason: error.to_string(),
        }
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(RegistryPackVerificationError::NonRegularPayloadPath {
            path: ".".to_string(),
        });
    }

    let files = verified.payload_files();
    let declared = files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    refuse_undeclared_payload_paths(root, root, &declared)?;
    for file in &files {
        let path = root.join(&file.path);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            RegistryPackVerificationError::PayloadFileRead {
                path: file.path.clone(),
                reason: error.to_string(),
            }
        })?;
        if !metadata.file_type().is_file() {
            return Err(RegistryPackVerificationError::NonRegularPayloadPath {
                path: file.path.clone(),
            });
        }
        if metadata.len() != file.size {
            return Err(RegistryPackVerificationError::PayloadSizeMismatch {
                path: file.path.clone(),
                declared: file.size,
                actual: metadata.len(),
            });
        }
        let hash = || -> std::io::Result<(Sha256Hex, u64)> {
            let mut reader = std::fs::File::open(&path)?.take(file.size + 1);
            let digest = crate::crypto::image_verify::sha256_reader(&mut reader)?;
            let actual_size = file.size + 1 - reader.limit();
            Ok((
                Sha256Hex::new(digest).expect("SHA-256 reader returns a canonical digest"),
                actual_size,
            ))
        };
        let (actual_hash, actual_size) =
            hash().map_err(|error| RegistryPackVerificationError::PayloadFileRead {
                path: file.path.clone(),
                reason: error.to_string(),
            })?;
        if actual_size != file.size {
            return Err(RegistryPackVerificationError::PayloadSizeMismatch {
                path: file.path.clone(),
                declared: file.size,
                actual: actual_size,
            });
        }
        if actual_hash != file.sha256 {
            return Err(RegistryPackVerificationError::PayloadHashMismatch {
                path: file.path.clone(),
                declared: file.sha256.clone(),
                actual: actual_hash,
            });
        }
    }
    refuse_undeclared_payload_paths(root, root, &declared)?;
    if let Some(image) = &verified.manifest().image {
        match image {
            RegistryPackImage::Source(source) => {
                validate_registry_pack_image_manifest(verified, root, source)?;
            }
            RegistryPackImage::Built(_) => check_built(verified, root)?,
        }
    }
    Ok(())
}

fn validate_registry_pack_image_manifest(
    verified: &VerifiedRegistryPack,
    root: &Path,
    image: &RegistryPackSourceImage,
) -> Result<(), RegistryPackVerificationError> {
    const MAX_IMAGE_MANIFEST_BYTES: u64 = 64 * 1024;
    let file = verified
        .manifest()
        .files
        .iter()
        .find(|file| file.path == image.manifest)
        .ok_or_else(|| RegistryPackVerificationError::InvalidImageDeclaration {
            reason: "the image mvm.toml is not a signed payload file".to_string(),
        })?;
    if file.size > MAX_IMAGE_MANIFEST_BYTES {
        return Err(RegistryPackVerificationError::InvalidImageManifest {
            reason: "mvm.toml exceeds the 64 KiB limit".to_string(),
        });
    }
    let bytes = std::fs::read(root.join(&image.manifest)).map_err(|error| {
        RegistryPackVerificationError::PayloadFileRead {
            path: image.manifest.clone(),
            reason: error.to_string(),
        }
    })?;
    let digest = Sha256Hex::from_bytes(&bytes);
    if digest != file.sha256 {
        return Err(RegistryPackVerificationError::PayloadHashMismatch {
            path: image.manifest.clone(),
            declared: file.sha256.clone(),
            actual: digest,
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        RegistryPackVerificationError::InvalidImageManifest {
            reason: "mvm.toml must be UTF-8".to_string(),
        }
    })?;
    let table: toml::Table =
        toml::from_str(text).map_err(|_| RegistryPackVerificationError::InvalidImageManifest {
            reason: "mvm.toml is not valid TOML".to_string(),
        })?;
    for key in table.keys() {
        if !matches!(
            key.as_str(),
            "schema_version" | "flake" | "profile" | "name"
        ) {
            return Err(RegistryPackVerificationError::InvalidImageManifest {
                reason: format!("mvm.toml field {key:?} cannot grant host authority"),
            });
        }
    }
    let manifest = crate::domain::manifest::Manifest::from_toml_str(text).map_err(|_| {
        RegistryPackVerificationError::InvalidImageManifest {
            reason: "mvm.toml does not satisfy the workload manifest schema".to_string(),
        }
    })?;
    if manifest.flake.as_deref().is_some_and(|flake| flake != ".") {
        return Err(RegistryPackVerificationError::InvalidImageManifest {
            reason: "flake must select the signed local image directory".to_string(),
        });
    }
    Ok(())
}

/// Verify and atomically publish a registry pack beneath its manifest digest.
///
/// A valid existing entry is reused after exact sidecar and payload
/// re-verification. A poisoned entry is removed and replaced by a fully
/// verified same-filesystem quarantine directory in one rename.
pub fn install_registry_pack_at(
    cache_root: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    install_registry_pack_at_with(
        cache_root,
        staged_root,
        verified,
        verify_built_image_authenticity,
    )
}

fn install_registry_pack_at_with(
    cache_root: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
    check_built: BuiltImageChecker,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    verify_registry_pack_contents_with(verified, staged_root, check_built)?;
    let final_dir = cache_root.join(verified.manifest_sha256().as_str());
    if std::fs::symlink_metadata(&final_dir).is_ok() {
        if cached_registry_pack_is_valid(&final_dir, verified, check_built) {
            return Ok(InstalledRegistryPack { root: final_dir });
        }
        remove_registry_cache_entry(&final_dir)?;
    }

    let publish =
        crate::pack_cache::atomically_populate_dir_at(cache_root, &final_dir, |quarantine| {
            populate_registry_quarantine(quarantine, staged_root, verified, check_built)
        });
    match publish {
        Ok(()) => Ok(InstalledRegistryPack { root: final_dir }),
        Err(_) if cached_registry_pack_is_valid(&final_dir, verified, check_built) => {
            Ok(InstalledRegistryPack { root: final_dir })
        }
        Err(error) => Err(error),
    }
}

/// Verify and atomically publish a registry pack in the configured MVM cache.
pub fn install_registry_pack(
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    install_registry_pack_at(
        &crate::config::registry_pack_cache_dir(),
        staged_root,
        verified,
    )
}

fn populate_registry_quarantine(
    quarantine: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
    check_built: BuiltImageChecker,
) -> Result<(), RegistryPackInstallError> {
    use std::io::Read;
    let payload_root = quarantine.join(REGISTRY_PAYLOAD_DIR_NAME);
    std::fs::create_dir_all(&payload_root).map_err(install_io_at(&payload_root))?;
    for file in verified.payload_files() {
        let source = staged_root.join(&file.path);
        let destination = payload_root.join(&file.path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(install_io_at(parent))?;
        }
        let mut input = std::fs::File::open(&source)
            .map_err(install_io_at(&source))?
            .take(file.size + 1);
        let mut output = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(install_io_at(&destination))?;
        std::io::copy(&mut input, &mut output).map_err(install_io_at(&source))?;
    }
    let manifest_path = quarantine.join(REGISTRY_MANIFEST_FILE_NAME);
    std::fs::write(&manifest_path, verified.manifest_bytes())
        .map_err(install_io_at(&manifest_path))?;
    let signature_path = quarantine.join(REGISTRY_SIGNATURE_FILE_NAME);
    std::fs::write(&signature_path, verified.signature_bundle())
        .map_err(install_io_at(&signature_path))?;
    verify_registry_pack_contents_with(verified, &payload_root, check_built)?;
    Ok(())
}

fn cached_registry_pack_is_valid(
    root: &Path,
    verified: &VerifiedRegistryPack,
    check_built: BuiltImageChecker,
) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return false;
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    let mut names = BTreeSet::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return false;
        };
        let Ok(file_type) = entry.file_type() else {
            return false;
        };
        let expected_type = if name == REGISTRY_PAYLOAD_DIR_NAME {
            file_type.is_dir() && !file_type.is_symlink()
        } else {
            file_type.is_file() && !file_type.is_symlink()
        };
        if !expected_type {
            return false;
        }
        names.insert(name);
    }
    let expected = BTreeSet::from([
        REGISTRY_PAYLOAD_DIR_NAME.to_string(),
        REGISTRY_MANIFEST_FILE_NAME.to_string(),
        REGISTRY_SIGNATURE_FILE_NAME.to_string(),
    ]);
    if names != expected {
        return false;
    }
    let manifest_matches = std::fs::read(root.join(REGISTRY_MANIFEST_FILE_NAME))
        .is_ok_and(|bytes| bytes == verified.manifest_bytes());
    let signature_matches = std::fs::read(root.join(REGISTRY_SIGNATURE_FILE_NAME))
        .is_ok_and(|bytes| bytes == verified.signature_bundle());
    manifest_matches
        && signature_matches
        && verify_registry_pack_contents_with(
            verified,
            &root.join(REGISTRY_PAYLOAD_DIR_NAME),
            check_built,
        )
        .is_ok()
}

fn remove_registry_cache_entry(path: &Path) -> Result<(), RegistryPackInstallError> {
    let metadata = std::fs::symlink_metadata(path).map_err(install_io_at(path))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path).map_err(install_io_at(path))
    } else {
        std::fs::remove_file(path).map_err(install_io_at(path))
    }
}

fn refuse_undeclared_payload_paths(
    root: &Path,
    directory: &Path,
    declared: &BTreeSet<&str>,
) -> Result<(), RegistryPackVerificationError> {
    let entries = std::fs::read_dir(directory).map_err(|error| {
        RegistryPackVerificationError::PayloadFileRead {
            path: relative_payload_path(root, directory),
            reason: error.to_string(),
        }
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| RegistryPackVerificationError::PayloadFileRead {
            path: relative_payload_path(root, directory),
            reason: error.to_string(),
        })?;
        let path = entry.path();
        let relative = relative_payload_path(root, &path);
        let file_type =
            entry
                .file_type()
                .map_err(|error| RegistryPackVerificationError::PayloadFileRead {
                    path: relative.clone(),
                    reason: error.to_string(),
                })?;
        if file_type.is_symlink() {
            return Err(RegistryPackVerificationError::NonRegularPayloadPath { path: relative });
        }
        if file_type.is_dir() {
            refuse_undeclared_payload_paths(root, &path, declared)?;
        } else if !file_type.is_file() {
            return Err(RegistryPackVerificationError::NonRegularPayloadPath { path: relative });
        } else if !declared.contains(relative.as_str()) {
            return Err(RegistryPackVerificationError::UndeclaredPayloadPath { path: relative });
        }
    }
    Ok(())
}

fn relative_payload_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .filter(|path| !path.is_empty())
        .unwrap_or(".")
        .to_string()
}

#[cfg(feature = "manifest-verify")]
pub(crate) fn check_registry_pack_signature(
    manifest_bytes: &[u8],
    signature_bundle: &[u8],
    trust: &KeylessTrust,
) -> Result<VerifiedSigner, RegistryPackVerificationError> {
    let identities: Vec<&str> = trust
        .accepted_identities
        .iter()
        .map(String::as_str)
        .collect();
    crate::crypto::image_verify::verify_signed_payload_and_signer_under_any_identity(
        manifest_bytes,
        signature_bundle,
        &identities,
        &trust.issuer,
    )
    .map_err(|error| RegistryPackVerificationError::SignatureInvalid(error.to_string()))
}

#[cfg(not(feature = "manifest-verify"))]
pub(crate) fn check_registry_pack_signature(
    _manifest_bytes: &[u8],
    _signature_bundle: &[u8],
    _trust: &KeylessTrust,
) -> Result<VerifiedSigner, RegistryPackVerificationError> {
    Err(RegistryPackVerificationError::SignatureInvalid(
        "manifest-verify feature disabled in this build".to_string(),
    ))
}

fn validate_pins(packs: &[PackPin]) -> Result<(), RegistryPackError> {
    let mut coordinates = BTreeSet::new();
    for pin in packs {
        if !coordinates.insert(pin.reference.coordinate.clone()) {
            return Err(RegistryPackError::DuplicatePin {
                coordinate: pin.reference.coordinate_string(),
            });
        }
    }
    Ok(())
}

fn validate_component(
    reference: &str,
    label: &str,
    component: &str,
) -> Result<(), RegistryPackError> {
    let valid_length = (1..=64).contains(&component.len());
    let valid_edges = component
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && component
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    let valid_characters = component.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
    });
    if valid_length && valid_edges && valid_characters {
        Ok(())
    } else {
        Err(invalid_reference(
            reference,
            &format!(
                "{label} must be 1-64 lowercase ASCII letters, digits, '.', '_' or '-', with an alphanumeric first and last character"
            ),
        ))
    }
}

fn invalid_reference(value: &str, reason: &str) -> RegistryPackError {
    RegistryPackError::InvalidReference {
        value: value.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_env::TestEnv;

    const MANIFEST: &[u8] = br#"{"schema_version":1,"name":"python"}"#;

    fn reference(value: &str) -> PackReference {
        value
            .parse()
            .unwrap_or_else(|error| panic!("{value}: {error}"))
    }

    fn pin(value: &str, bytes: &[u8]) -> PackPin {
        PackPin::new(reference(value), Sha256Hex::from_bytes(bytes)).unwrap()
    }

    fn publisher_policy() -> RegistryPackPublisherPolicy {
        RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "runtime",
                "https://token.actions.githubusercontent.com",
                vec![OFFICIAL_PACK_SIGNING_IDENTITY.to_string()],
            )
            .unwrap(),
        ])
        .unwrap()
    }

    fn signed_manifest_bytes(reference: &str) -> Vec<u8> {
        serde_json::to_vec(&RegistryPackManifest {
            schema_version: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
            reference: self::reference(reference),
            description: "Python runtime".to_string(),
            image: None,
            files: vec![RegistryPackFile {
                path: "pack/profile.toml".to_string(),
                sha256: Sha256Hex::from_bytes(b"profile"),
                size: 7,
            }],
        })
        .unwrap()
    }

    fn verified_payload() -> VerifiedRegistryPack {
        let manifest_bytes = signed_manifest_bytes("runtime/python@1.2.3");
        VerifiedRegistryPack {
            manifest: serde_json::from_slice(&manifest_bytes).unwrap(),
            manifest_sha256: Sha256Hex::from_bytes(&manifest_bytes),
            manifest_bytes,
            signature_bundle: b"test bundle".to_vec(),
            signer: VerifiedSigner {
                identity: OFFICIAL_PACK_SIGNING_IDENTITY.to_string(),
                issuer: OFFICIAL_PACK_SIGNING_ISSUER.to_string(),
            },
        }
    }

    fn accept_signature(
        _payload: &[u8],
        _bundle: &[u8],
        _trust: &KeylessTrust,
    ) -> Result<VerifiedSigner, RegistryPackVerificationError> {
        Ok(VerifiedSigner {
            identity: OFFICIAL_PACK_SIGNING_IDENTITY.to_string(),
            issuer: OFFICIAL_PACK_SIGNING_ISSUER.to_string(),
        })
    }

    fn reject_signature(
        _payload: &[u8],
        _bundle: &[u8],
        _trust: &KeylessTrust,
    ) -> Result<VerifiedSigner, RegistryPackVerificationError> {
        Err(RegistryPackVerificationError::SignatureInvalid(
            "test refusal".to_string(),
        ))
    }

    #[test]
    fn a_wildcard_publisher_trusts_every_namespace_an_exact_entry_does_not() {
        let policy = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new("runtime", "issuer-a", vec!["identity-a".to_string()])
                .unwrap(),
            RegistryPackPublisher::new("*", "issuer-b", vec!["identity-b".to_string()]).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            policy.trust_for_namespace("runtime").unwrap().issuer,
            "issuer-a"
        );
        assert_eq!(
            policy.trust_for_namespace("agent").unwrap().issuer,
            "issuer-b"
        );
        assert!(
            RegistryPackPublisherPolicy::new(vec![
                RegistryPackPublisher::new("*", "issuer-a", vec!["identity-a".to_string()])
                    .unwrap(),
                RegistryPackPublisher::new("*", "issuer-b", vec!["identity-b".to_string()])
                    .unwrap(),
            ])
            .is_err()
        );
    }

    #[test]
    fn the_official_default_policy_matches_its_constants() {
        let policy = official_publisher_policy();
        let before_cutoff = chrono::DateTime::parse_from_rfc3339("2026-11-05T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let at_cutoff = chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for namespace in ["agent", "runtime"] {
            let trust = policy
                .trust_for_namespace_at(namespace, before_cutoff)
                .unwrap();
            assert_eq!(trust.issuer, OFFICIAL_PACK_SIGNING_ISSUER);
            assert_eq!(
                trust.accepted_identities,
                [OFFICIAL_PACK_SIGNING_IDENTITY, LEGACY_PACK_SIGNING_IDENTITY]
            );
            let trust = policy.trust_for_namespace_at(namespace, at_cutoff).unwrap();
            assert_eq!(trust.accepted_identities, [OFFICIAL_PACK_SIGNING_IDENTITY]);
        }
        assert!(policy.trust_for_namespace("mvm").is_err());
        assert!(policy.trust_for_namespace("community").is_err());
        assert_eq!(
            OFFICIAL_PACK_SIGNING_IDENTITY,
            "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
        );
    }

    #[test]
    fn operator_publisher_policy_is_unaffected_by_legacy_cutoff() {
        let policy = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "agent",
                OFFICIAL_PACK_SIGNING_ISSUER,
                vec![LEGACY_PACK_SIGNING_IDENTITY.to_string()],
            )
            .unwrap(),
        ])
        .unwrap();
        let after_cutoff = chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            policy
                .trust_for_namespace_at("agent", after_cutoff)
                .unwrap()
                .accepted_identities,
            [LEGACY_PACK_SIGNING_IDENTITY]
        );
    }

    #[test]
    fn registry_reference_round_trips_with_and_without_a_version() {
        for value in ["agents/claude", "runtime/python@1.2.3", "acme/x@1.0.0-rc.1"] {
            let parsed = reference(value);
            assert_eq!(parsed.to_string(), value);

            let json = serde_json::to_string(&parsed).unwrap();
            let decoded: PackReference = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, parsed);
        }
    }

    #[test]
    fn registry_reference_rejects_ambiguous_or_noncanonical_input() {
        for value in [
            "",
            "python",
            "/python",
            "runtime/",
            "a/b/c",
            "Runtime/python",
            "runtime/python@",
            "runtime/python@v1.2.3",
            "runtime/python@01.2.3",
            "runtime/python@1.2.3@other",
            "runtime/python latest",
            "runtime/-python",
            "runtime/python_",
        ] {
            assert!(
                value.parse::<PackReference>().is_err(),
                "{value:?} must be refused"
            );
        }
    }

    #[test]
    fn a_lock_pin_requires_an_exact_version() {
        let error =
            PackPin::new(reference("runtime/python"), Sha256Hex::from_bytes(MANIFEST)).unwrap_err();

        assert!(matches!(error, RegistryPackError::UnversionedPin { .. }));
    }

    #[test]
    fn lockfile_round_trip_preserves_exact_pins() {
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", MANIFEST)]).unwrap();
        let json = serde_json::to_vec(&lock).unwrap();
        let decoded: PackLockfile = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded, lock);
        assert_eq!(
            decoded.pins()[0].reference().to_string(),
            "runtime/python@1.2.3"
        );
    }

    #[test]
    fn lockfile_deserialization_refuses_unknown_fields_and_schema_versions() {
        let digest = Sha256Hex::from_bytes(MANIFEST);
        let unknown = format!(
            r#"{{"schema_version":1,"packs":[{{"reference":"runtime/python@1.2.3","manifest_sha256":"{}","escape_hatch":true}}]}}"#,
            digest.as_str()
        );
        assert!(serde_json::from_str::<PackLockfile>(&unknown).is_err());

        let unsupported = format!(
            r#"{{"schema_version":2,"packs":[{{"reference":"runtime/python@1.2.3","manifest_sha256":"{}"}}]}}"#,
            digest.as_str()
        );
        assert!(serde_json::from_str::<PackLockfile>(&unsupported).is_err());
    }

    #[test]
    fn lockfile_refuses_duplicate_coordinates_even_at_different_versions() {
        let error = PackLockfile::new(vec![
            pin("runtime/python@1.2.3", MANIFEST),
            pin("runtime/python@1.2.4", b"new manifest"),
        ])
        .unwrap_err();

        assert!(matches!(error, RegistryPackError::DuplicatePin { .. }));
    }

    #[test]
    fn pinned_manifest_bytes_are_accepted_for_versioned_and_unversioned_requests() {
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", MANIFEST)]).unwrap();

        for requested in ["runtime/python", "runtime/python@1.2.3"] {
            let verified = lock
                .verify_manifest(&reference(requested), MANIFEST)
                .unwrap();
            assert_eq!(verified.reference().to_string(), "runtime/python@1.2.3");
        }
    }

    #[test]
    fn lockfile_refuses_missing_version_and_digest_drift() {
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", MANIFEST)]).unwrap();

        assert!(matches!(
            lock.verify_manifest(&reference("runtime/node"), MANIFEST),
            Err(RegistryPackError::UnpinnedPack { .. })
        ));
        assert!(matches!(
            lock.verify_manifest(&reference("runtime/python@1.2.4"), MANIFEST),
            Err(RegistryPackError::RequestedVersionMismatch { .. })
        ));
        assert!(matches!(
            lock.verify_manifest(&reference("runtime/python"), b"tampered"),
            Err(RegistryPackError::ManifestDigestMismatch { .. })
        ));
    }

    #[test]
    fn publisher_policy_is_strict_unique_and_fail_closed() {
        let policy = publisher_policy();
        assert!(policy.trust_for_namespace("runtime").is_ok());
        assert!(matches!(
            policy.trust_for_namespace("agents"),
            Err(RegistryPackVerificationError::UntrustedNamespace { .. })
        ));
        let json = serde_json::to_vec(&policy).unwrap();
        assert_eq!(
            serde_json::from_slice::<RegistryPackPublisherPolicy>(&json).unwrap(),
            policy
        );

        let duplicate = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new("runtime", "issuer", vec!["one".to_string()]).unwrap(),
            RegistryPackPublisher::new("runtime", "issuer", vec!["two".to_string()]).unwrap(),
        ]);
        assert!(matches!(
            duplicate,
            Err(RegistryPackVerificationError::DuplicatePublisherNamespace { .. })
        ));

        let unknown = serde_json::from_str::<RegistryPackPublisherPolicy>(
            r#"{"schema_version":1,"publishers":[],"surprise":true}"#,
        );
        assert!(unknown.is_err());
        let unsupported = serde_json::from_str::<RegistryPackPublisherPolicy>(
            r#"{"schema_version":2,"publishers":[]}"#,
        );
        assert!(unsupported.is_err());
    }

    #[test]
    fn verification_checks_the_lock_before_the_signature() {
        let bytes = signed_manifest_bytes("runtime/python@1.2.3");
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", b"other")]).unwrap();
        let policy = publisher_policy();
        let requested = reference("runtime/python@1.2.3");
        let request = RegistryPackVerification::new(&requested, &bytes, b"bundle", &lock, &policy);

        let error = verify_registry_pack_with(&request, reject_signature).unwrap_err();
        assert!(matches!(
            error,
            RegistryPackVerificationError::Lock(RegistryPackError::ManifestDigestMismatch { .. })
        ));
    }

    #[test]
    fn verification_checks_the_signature_before_parsing() {
        let bytes = b"not json";
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", bytes)]).unwrap();
        let policy = publisher_policy();
        let requested = reference("runtime/python@1.2.3");
        let request = RegistryPackVerification::new(&requested, bytes, b"bundle", &lock, &policy);

        let error = verify_registry_pack_with(&request, reject_signature).unwrap_err();
        assert!(matches!(
            error,
            RegistryPackVerificationError::SignatureInvalid(_)
        ));
    }

    #[test]
    fn verified_manifest_must_name_the_locked_reference_and_safe_unique_files() {
        let bytes = signed_manifest_bytes("runtime/python@1.2.3");
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", &bytes)]).unwrap();
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        let request = RegistryPackVerification::new(&requested, &bytes, b"bundle", &lock, &policy);
        let verified = verify_registry_pack_with(&request, accept_signature).unwrap();
        assert_eq!(verified.manifest().reference, requested);
        assert!(verified.manifest().image.is_none());
        assert_eq!(verified.manifest_sha256(), &Sha256Hex::from_bytes(&bytes));
        assert_eq!(verified.manifest_bytes(), bytes);
        assert_eq!(verified.signature_bundle(), b"bundle");
        assert_eq!(verified.signer().identity, OFFICIAL_PACK_SIGNING_IDENTITY);
        assert_eq!(verified.signer().issuer, OFFICIAL_PACK_SIGNING_ISSUER);

        for files in [
            vec![RegistryPackFile {
                path: "../escape".to_string(),
                sha256: Sha256Hex::from_bytes(b"x"),
                size: 1,
            }],
            vec![
                RegistryPackFile {
                    path: "pack/file".to_string(),
                    sha256: Sha256Hex::from_bytes(b"x"),
                    size: 1,
                },
                RegistryPackFile {
                    path: "pack/file".to_string(),
                    sha256: Sha256Hex::from_bytes(b"x"),
                    size: 1,
                },
            ],
        ] {
            let invalid = serde_json::to_vec(&RegistryPackManifest {
                schema_version: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
                reference: reference("runtime/python@1.2.3"),
                description: "invalid".to_string(),
                image: None,
                files,
            })
            .unwrap();
            let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", &invalid)]).unwrap();
            let request =
                RegistryPackVerification::new(&requested, &invalid, b"bundle", &lock, &policy);
            assert!(verify_registry_pack_with(&request, accept_signature).is_err());
        }
    }

    #[test]
    fn a_signed_image_descriptor_names_only_declared_in_pack_source_files() {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&signed_manifest_bytes("runtime/python@1.2.3")).unwrap();
        manifest["image"] = serde_json::json!({"manifest": "pack/image/mvm.toml"});
        for path in [
            "pack/image/mvm.toml",
            "pack/image/flake.nix",
            "pack/image/flake.lock",
        ] {
            manifest["files"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "path": path,
                    "sha256": Sha256Hex::from_bytes(path.as_bytes()),
                    "size": path.len(),
                }));
        }
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        let verify = |value: &serde_json::Value| {
            let bytes = serde_json::to_vec(value).unwrap();
            let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", &bytes)]).unwrap();
            let request =
                RegistryPackVerification::new(&requested, &bytes, b"bundle", &lock, &policy);
            verify_registry_pack_with(&request, accept_signature)
        };

        let verified = verify(&manifest).expect("declared image files verify");
        assert_eq!(
            verified.manifest().image,
            Some(RegistryPackImage::Source(RegistryPackSourceImage {
                manifest: "pack/image/mvm.toml".to_string(),
            }))
        );
        let mut unknown = manifest.clone();
        unknown["image"]["host_path"] = serde_json::json!("/etc/mvm");
        assert!(matches!(
            verify(&unknown),
            Err(RegistryPackVerificationError::ManifestParse(_))
        ));

        for missing in [
            "pack/image/mvm.toml",
            "pack/image/flake.nix",
            "pack/image/flake.lock",
        ] {
            let mut invalid = manifest.clone();
            invalid["files"]
                .as_array_mut()
                .unwrap()
                .retain(|file| file["path"] != missing);
            assert!(verify(&invalid).is_err(), "missing {missing} must fail");
        }

        for path in ["../mvm.toml", "/etc/mvm.toml", "pack/other.toml"] {
            let mut invalid = manifest.clone();
            invalid["image"]["manifest"] = serde_json::json!(path);
            assert!(
                verify(&invalid).is_err(),
                "unsafe image path {path} must fail"
            );
        }
    }

    #[test]
    fn signed_built_image_declaration_requires_the_compiled_base_pin() {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&signed_manifest_bytes("runtime/python@1.2.3")).unwrap();
        let lock = &crate::image_set::image_train_lock().image_set;
        let asset = |name: &str| {
            serde_json::json!({
                "name": name, "sha256": "0".repeat(64), "size": 1,
            })
        };
        manifest["image"] = serde_json::json!({
            "schema_version": 2,
            "platform": "linux/x86_64",
            "base_set": {
                "repository": lock.repository,
                "release_tag": lock.release_tag,
                "manifest_sha256": lock.manifest_sha256,
            },
            "release": {
                "repository": "tinylabscom/mvm-packs",
                "tag": "pack-runtime-python-v1.2.3",
            },
            "assets": {
                "rootfs": asset("rootfs.ext4"),
                "verity": asset("rootfs.verity"),
                "roothash": asset("rootfs.roothash"),
                "mvm_meta": asset("mvm-meta.json"),
                "rootfs_signature_bundle": asset("rootfs.signature.json"),
                "provenance_statement": asset("provenance.json"),
                "provenance_signature_bundle": asset("provenance.signature.json"),
            },
        });
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        let verify = |value: &serde_json::Value| {
            let bytes = serde_json::to_vec(value).unwrap();
            let pins = PackLockfile::new(vec![pin("runtime/python@1.2.3", &bytes)]).unwrap();
            let request =
                RegistryPackVerification::new(&requested, &bytes, b"bundle", &pins, &policy);
            verify_registry_pack_with(&request, accept_signature)
        };
        let verified = verify(&manifest).expect("current pinned built-image declaration");
        assert!(matches!(
            verified.manifest().image,
            Some(RegistryPackImage::Built(_))
        ));
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("pack")).unwrap();
        std::fs::write(root.path().join("pack/profile.toml"), b"profile").unwrap();
        assert!(matches!(
            verify_registry_pack_contents(&verified, root.path()),
            Err(RegistryPackVerificationError::PayloadFileRead { .. })
        ));
        let mut stale = manifest.clone();
        stale["image"]["base_set"]["manifest_sha256"] = serde_json::json!("0".repeat(64));
        assert!(matches!(
            verify(&stale),
            Err(RegistryPackVerificationError::InvalidImageDeclaration { .. })
        ));
        let mut mixed = manifest;
        mixed["image"]["manifest"] = serde_json::json!("pack/image/mvm.toml");
        assert!(matches!(
            verify(&mixed),
            Err(RegistryPackVerificationError::ManifestParse(_))
        ));
    }

    #[test]
    fn manifest_reference_cannot_disagree_with_the_lock() {
        let bytes = signed_manifest_bytes("runtime/node@1.2.3");
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", &bytes)]).unwrap();
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        let request = RegistryPackVerification::new(&requested, &bytes, b"bundle", &lock, &policy);

        assert!(matches!(
            verify_registry_pack_with(&request, accept_signature),
            Err(RegistryPackVerificationError::ManifestReferenceMismatch { .. })
        ));
    }

    #[test]
    fn manifest_schema_and_unknown_fields_are_refused_after_signature_verification() {
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        for bytes in [
            br#"{"schema_version":2,"reference":"runtime/python@1.2.3","description":"Python","files":[{"path":"pack/file","sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881","size":1}]}"#.as_slice(),
            br#"{"schema_version":1,"reference":"runtime/python@1.2.3","description":"Python","files":[{"path":"pack/file","sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881","size":1}],"surprise":true}"#.as_slice(),
        ] {
            let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", bytes)]).unwrap();
            let request =
                RegistryPackVerification::new(&requested, bytes, b"bundle", &lock, &policy);
            assert!(verify_registry_pack_with(&request, accept_signature).is_err());
        }
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn public_verifier_rejects_a_malformed_signature_bundle() {
        let bytes = signed_manifest_bytes("runtime/python@1.2.3");
        let lock = PackLockfile::new(vec![pin("runtime/python@1.2.3", &bytes)]).unwrap();
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        let request = RegistryPackVerification::new(
            &requested,
            &bytes,
            b"not a signature bundle",
            &lock,
            &policy,
        );

        assert!(matches!(
            verify_registry_pack(&request),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn signed_pack_records_the_accepted_certificate_identity() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mvm-cli/tests/fixtures/signed-registry-go");
        let manifest = std::fs::read(fixture.join("manifest.json")).unwrap();
        let bundle = std::fs::read(fixture.join("manifest.sigstore.json")).unwrap();
        let requested = reference("runtime/go@1.0.0");
        let policy = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "runtime",
                OFFICIAL_PACK_SIGNING_ISSUER,
                vec![
                    OFFICIAL_PACK_SIGNING_IDENTITY.to_string(),
                    LEGACY_PACK_SIGNING_IDENTITY.to_string(),
                ],
            )
            .unwrap(),
        ])
        .unwrap();
        let adoption = PackAdoption {
            requested: &requested,
            manifest_bytes: &manifest,
            signature_bundle: &bundle,
            publisher_policy: &policy,
        };
        let verified = adopt_registry_pack(&adoption).unwrap();
        assert_eq!(verified.signer().identity, LEGACY_PACK_SIGNING_IDENTITY);
        assert_eq!(verified.signer().issuer, OFFICIAL_PACK_SIGNING_ISSUER);

        let wrong_policy = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "runtime",
                OFFICIAL_PACK_SIGNING_ISSUER,
                vec![OFFICIAL_PACK_SIGNING_IDENTITY.to_string()],
            )
            .unwrap(),
        ])
        .unwrap();
        let wrong_adoption = PackAdoption {
            publisher_policy: &wrong_policy,
            ..adoption
        };
        assert!(matches!(
            adopt_registry_pack(&wrong_adoption),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
    }

    #[cfg(not(feature = "manifest-verify"))]
    #[test]
    fn signer_cannot_be_recorded_without_the_keyless_verifier() {
        let manifest = signed_manifest_bytes("runtime/python@1.2.3");
        let requested = reference("runtime/python@1.2.3");
        let policy = publisher_policy();
        let adoption = PackAdoption {
            requested: &requested,
            manifest_bytes: &manifest,
            signature_bundle: b"bundle",
            publisher_policy: &policy,
        };
        assert!(matches!(
            adopt_registry_pack(&adoption),
            Err(RegistryPackVerificationError::SignatureInvalid(_))
        ));
    }

    #[test]
    fn verified_payload_accepts_exactly_the_declared_files() {
        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join("profile.toml"), b"profile").unwrap();
        let verified = verified_payload();

        verify_registry_pack_contents(&verified, root.path()).unwrap();
    }

    #[test]
    fn verified_payload_refuses_missing_tampered_and_undeclared_files() {
        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        let verified = verified_payload();

        let missing = verify_registry_pack_contents(&verified, root.path()).unwrap_err();
        assert!(matches!(
            missing,
            RegistryPackVerificationError::PayloadFileRead { .. }
        ));

        std::fs::write(pack.join("profile.toml"), b"too long").unwrap();
        let wrong_size = verify_registry_pack_contents(&verified, root.path()).unwrap_err();
        assert!(matches!(
            wrong_size,
            RegistryPackVerificationError::PayloadSizeMismatch { .. }
        ));

        std::fs::write(pack.join("profile.toml"), b"PROFILE").unwrap();
        let tampered = verify_registry_pack_contents(&verified, root.path()).unwrap_err();
        assert!(matches!(
            tampered,
            RegistryPackVerificationError::PayloadHashMismatch { .. }
        ));

        std::fs::write(pack.join("profile.toml"), b"profile").unwrap();
        std::fs::write(pack.join("escape.toml"), b"undeclared").unwrap();
        let undeclared = verify_registry_pack_contents(&verified, root.path()).unwrap_err();
        assert!(matches!(
            undeclared,
            RegistryPackVerificationError::UndeclaredPayloadPath { .. }
        ));
    }

    fn image_payload(manifest_toml: &[u8]) -> (tempfile::TempDir, VerifiedRegistryPack) {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("pack/image");
        std::fs::create_dir_all(&image).unwrap();
        let files = [
            ("pack/image/mvm.toml", manifest_toml),
            ("pack/image/flake.nix", b"{ outputs = _: {}; }".as_slice()),
            ("pack/image/flake.lock", b"{}".as_slice()),
        ];
        let declared = files
            .into_iter()
            .map(|(path, bytes)| {
                std::fs::write(root.path().join(path), bytes).unwrap();
                RegistryPackFile {
                    path: path.to_string(),
                    sha256: Sha256Hex::from_bytes(bytes),
                    size: bytes.len() as u64,
                }
            })
            .collect();
        let manifest = RegistryPackManifest {
            schema_version: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
            reference: reference("runtime/python@1.2.3"),
            description: "Python image".to_string(),
            image: Some(RegistryPackImage::Source(RegistryPackSourceImage {
                manifest: "pack/image/mvm.toml".to_string(),
            })),
            files: declared,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let verified = VerifiedRegistryPack {
            manifest,
            manifest_sha256: Sha256Hex::from_bytes(&manifest_bytes),
            manifest_bytes,
            signature_bundle: b"test bundle".to_vec(),
            signer: VerifiedSigner {
                identity: OFFICIAL_PACK_SIGNING_IDENTITY.to_string(),
                issuer: OFFICIAL_PACK_SIGNING_ISSUER.to_string(),
            },
        };
        (root, verified)
    }

    #[test]
    fn verified_image_payload_requires_a_local_source_only_manifest() {
        let (root, verified) = image_payload(b"schema_version = 1\nflake = \".\"\n");
        verify_registry_pack_contents(&verified, root.path()).unwrap();

        for invalid in [
            b"flake = \"github:elsewhere/image\"\n".as_slice(),
            b"flake = \"../outside\"\n".as_slice(),
            b"flake = \".\"\nnet = true\n".as_slice(),
            b"flake = \".\"\n[policy]\nprofile = \"host-admin\"\n".as_slice(),
            b"this is not TOML".as_slice(),
        ] {
            let (root, verified) = image_payload(invalid);
            assert!(matches!(
                verify_registry_pack_contents(&verified, root.path()),
                Err(RegistryPackVerificationError::InvalidImageManifest { .. })
            ));
        }

        let oversized = vec![b' '; 64 * 1024 + 1];
        let (root, verified) = image_payload(&oversized);
        assert!(matches!(
            verify_registry_pack_contents(&verified, root.path()),
            Err(RegistryPackVerificationError::InvalidImageManifest { .. })
        ));

        let (root, verified) = image_payload(b"\xff");
        assert!(matches!(
            verify_registry_pack_contents(&verified, root.path()),
            Err(RegistryPackVerificationError::InvalidImageManifest { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn verified_payload_refuses_a_symlink_even_when_its_target_matches() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"profile").unwrap();
        symlink(&outside, pack.join("profile.toml")).unwrap();
        let verified = verified_payload();

        let error = verify_registry_pack_contents(&verified, root.path()).unwrap_err();
        assert!(matches!(
            error,
            RegistryPackVerificationError::NonRegularPayloadPath { .. }
        ));
    }

    #[test]
    fn registry_pack_install_is_content_addressed_and_preserves_trust_sidecars() {
        let cache = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let pack = staged.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join("profile.toml"), b"profile").unwrap();
        let verified = verified_payload();

        let installed = install_registry_pack_at(cache.path(), staged.path(), &verified).unwrap();

        assert_eq!(
            installed.root(),
            cache.path().join(verified.manifest_sha256().as_str())
        );
        assert_eq!(
            std::fs::read(installed.payload_root().join("pack/profile.toml")).unwrap(),
            b"profile"
        );
        assert_eq!(
            std::fs::read(installed.root().join(REGISTRY_MANIFEST_FILE_NAME)).unwrap(),
            verified.manifest_bytes()
        );
        assert_eq!(
            std::fs::read(installed.root().join(REGISTRY_SIGNATURE_FILE_NAME)).unwrap(),
            verified.signature_bundle()
        );
    }

    #[test]
    fn registry_pack_install_refuses_before_touching_the_cache() {
        let cache = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let pack = staged.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join("profile.toml"), b"tampered").unwrap();
        let verified = verified_payload();

        let error = install_registry_pack_at(cache.path(), staged.path(), &verified).unwrap_err();

        assert!(matches!(
            error,
            RegistryPackInstallError::Verification(
                RegistryPackVerificationError::PayloadSizeMismatch { .. }
            )
        ));
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
    }

    #[test]
    fn registry_pack_install_replaces_a_poisoned_cached_copy() {
        let cache = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let pack = staged.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join("profile.toml"), b"profile").unwrap();
        let verified = verified_payload();
        let installed = install_registry_pack_at(cache.path(), staged.path(), &verified).unwrap();
        let cached_profile = installed.payload_root().join("pack/profile.toml");
        std::fs::write(&cached_profile, b"poison!").unwrap();

        let repaired = install_registry_pack_at(cache.path(), staged.path(), &verified).unwrap();

        assert_eq!(repaired.root(), installed.root());
        assert_eq!(std::fs::read(cached_profile).unwrap(), b"profile");
        verify_registry_pack_contents(&verified, &repaired.payload_root()).unwrap();
    }

    #[test]
    fn configured_registry_pack_install_honors_mvm_home() {
        let home = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        let pack = staged.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join("profile.toml"), b"profile").unwrap();
        let verified = verified_payload();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let installed = install_registry_pack(staged.path(), &verified).unwrap();

        assert_eq!(
            installed.root(),
            home.path()
                .join("cache/registry-packs")
                .join(verified.manifest_sha256().as_str())
        );
    }
}
