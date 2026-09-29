//! Stable identities and digest pins for registry-delivered product packs.
//!
//! This is deliberately separate from [`crate::packs`]. That module describes
//! MVM's verified runtime/build artifacts, while registry packs are user-facing
//! products named `namespace/name[@version]`. A lockfile selects one exact
//! version and hashes the raw manifest bytes before a later layer parses or
//! verifies the signed manifest.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::packs::{KeylessTrust, Sha256Hex, pack_path_is_safe};
use crate::release_version::{ReleaseVersion, VersionSyntax};

/// Current on-disk registry-pack lockfile schema.
pub const PACK_LOCK_SCHEMA_VERSION: u32 = 1;
/// Current signed product-pack manifest schema.
pub const REGISTRY_PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Current publisher trust-policy schema.
pub const REGISTRY_PACK_PUBLISHER_POLICY_SCHEMA_VERSION: u32 = 1;

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

    fn coordinate_string(&self) -> String {
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

/// Strict metadata signed by a registry-pack publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackManifest {
    pub schema_version: u32,
    /// Exact versioned identity of these manifest bytes.
    pub reference: PackReference,
    pub description: String,
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
    pub fn new(
        namespace: impl Into<String>,
        issuer: impl Into<String>,
        accepted_identities: Vec<String>,
    ) -> Result<Self, RegistryPackVerificationError> {
        let namespace = namespace.into();
        PackCoordinate::parse(&format!("{namespace}/pack")).map_err(|error| {
            RegistryPackVerificationError::InvalidPublisherPolicy {
                reason: error.to_string(),
            }
        })?;
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
        })
    }

    pub fn publishers(&self) -> &[RegistryPackPublisher] {
        &self.publishers
    }

    pub fn trust_for_namespace(
        &self,
        namespace: &str,
    ) -> Result<KeylessTrust, RegistryPackVerificationError> {
        self.publishers
            .iter()
            .find(|publisher| publisher.namespace == namespace)
            .map(RegistryPackPublisher::keyless_trust)
            .ok_or_else(|| RegistryPackVerificationError::UntrustedNamespace {
                namespace: namespace.to_string(),
            })
    }
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
    pub manifest: RegistryPackManifest,
    pub manifest_sha256: Sha256Hex,
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
}

/// Verify the lock pin and publisher signature before parsing the manifest.
pub fn verify_registry_pack(
    request: &RegistryPackVerification<'_>,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    verify_registry_pack_with(request, check_registry_pack_signature)
}

type RegistryPackSignatureChecker =
    fn(&[u8], &[u8], &KeylessTrust) -> Result<(), RegistryPackVerificationError>;

fn verify_registry_pack_with(
    request: &RegistryPackVerification<'_>,
    check_signature: RegistryPackSignatureChecker,
) -> Result<VerifiedRegistryPack, RegistryPackVerificationError> {
    let pin = request
        .lock
        .verify_manifest(request.requested, request.manifest_bytes)?;
    let trust = request
        .publisher_policy
        .trust_for_namespace(pin.reference().namespace())?;
    check_signature(request.manifest_bytes, request.signature_bundle, &trust)?;

    let manifest: RegistryPackManifest = serde_json::from_slice(request.manifest_bytes)
        .map_err(|error| RegistryPackVerificationError::ManifestParse(error.to_string()))?;
    if manifest.schema_version != REGISTRY_PACK_MANIFEST_SCHEMA_VERSION {
        return Err(RegistryPackVerificationError::UnsupportedManifestSchema {
            got: manifest.schema_version,
            expected: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
        });
    }
    if &manifest.reference != pin.reference() {
        return Err(RegistryPackVerificationError::ManifestReferenceMismatch {
            manifest: manifest.reference.to_string(),
            locked: pin.reference().to_string(),
        });
    }
    validate_registry_pack_manifest(&manifest)?;
    Ok(VerifiedRegistryPack {
        manifest,
        manifest_sha256: pin.manifest_sha256().clone(),
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
    for file in &manifest.files {
        if !paths.insert(&file.path) {
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
    Ok(())
}

#[cfg(feature = "manifest-verify")]
fn check_registry_pack_signature(
    manifest_bytes: &[u8],
    signature_bundle: &[u8],
    trust: &KeylessTrust,
) -> Result<(), RegistryPackVerificationError> {
    let identities: Vec<&str> = trust
        .accepted_identities
        .iter()
        .map(String::as_str)
        .collect();
    crate::crypto::image_verify::verify_signed_payload_under_any_identity(
        manifest_bytes,
        signature_bundle,
        &identities,
        &trust.issuer,
    )
    .map_err(|error| RegistryPackVerificationError::SignatureInvalid(error.to_string()))
}

#[cfg(not(feature = "manifest-verify"))]
fn check_registry_pack_signature(
    _manifest_bytes: &[u8],
    _signature_bundle: &[u8],
    _trust: &KeylessTrust,
) -> Result<(), RegistryPackVerificationError> {
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
        RegistryPackPublisherPolicy::new(vec![RegistryPackPublisher::new(
            "runtime",
            "https://token.actions.githubusercontent.com",
            vec!["https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main".to_string()],
        )
        .unwrap()])
        .unwrap()
    }

    fn signed_manifest_bytes(reference: &str) -> Vec<u8> {
        serde_json::to_vec(&RegistryPackManifest {
            schema_version: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
            reference: self::reference(reference),
            description: "Python runtime".to_string(),
            files: vec![RegistryPackFile {
                path: "pack/profile.toml".to_string(),
                sha256: Sha256Hex::from_bytes(b"profile"),
                size: 7,
            }],
        })
        .unwrap()
    }

    fn accept_signature(
        _payload: &[u8],
        _bundle: &[u8],
        _trust: &KeylessTrust,
    ) -> Result<(), RegistryPackVerificationError> {
        Ok(())
    }

    fn reject_signature(
        _payload: &[u8],
        _bundle: &[u8],
        _trust: &KeylessTrust,
    ) -> Result<(), RegistryPackVerificationError> {
        Err(RegistryPackVerificationError::SignatureInvalid(
            "test refusal".to_string(),
        ))
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
    fn publisher_rejects_malformed_security_policy_fields() {
        for (issuer, identities) in [
            (" ", vec!["publisher@example.com".to_string()]),
            ("issuer", Vec::new()),
            ("issuer", vec![" ".to_string()]),
            (
                "issuer",
                vec![
                    "publisher@example.com".to_string(),
                    "publisher@example.com".to_string(),
                ],
            ),
        ] {
            assert!(matches!(
                RegistryPackPublisher::new("runtime", issuer, identities),
                Err(RegistryPackVerificationError::InvalidPublisherPolicy { .. })
            ));
        }
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
        assert_eq!(verified.manifest.reference, requested);
        assert_eq!(verified.manifest_sha256, Sha256Hex::from_bytes(&bytes));

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
}
