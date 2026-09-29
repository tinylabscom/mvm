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

use crate::packs::Sha256Hex;
use crate::release_version::{ReleaseVersion, VersionSyntax};

/// Current on-disk registry-pack lockfile schema.
pub const PACK_LOCK_SCHEMA_VERSION: u32 = 1;

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
}
