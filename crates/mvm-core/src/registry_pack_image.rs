//! The signed descriptor for a built registry-pack workload image.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::image_verify::{VerifiedSigner, verify_signed_payload, verify_signed_sha256};
use crate::image_set::{ArtifactName, ImageLock, ReleaseTag, RepositorySlug};
use crate::packs::Sha256Hex;
use crate::registry_pack::PackReference;

/// The supported guest architecture of one published image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BuiltImagePlatform {
    #[serde(rename = "linux/x86_64")]
    LinuxX86_64,
    #[serde(rename = "linux/aarch64")]
    LinuxAarch64,
}

/// One externally published release asset and its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltImageAsset {
    pub name: ArtifactName,
    pub sha256: Sha256Hex,
    pub size: u64,
}

/// The seven assets needed to prove and boot one workload root filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltImageAssets {
    pub rootfs: BuiltImageAsset,
    pub verity: BuiltImageAsset,
    pub roothash: BuiltImageAsset,
    pub mvm_meta: BuiltImageAsset,
    pub rootfs_signature_bundle: BuiltImageAsset,
    pub provenance_statement: BuiltImageAsset,
    pub provenance_signature_bundle: BuiltImageAsset,
}

/// The exact signed image set from which the workload image was composed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltImageBaseSet {
    pub repository: RepositorySlug,
    pub release_tag: ReleaseTag,
    pub manifest_sha256: Sha256Hex,
}

/// The immutable release carrying the image and its attestations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltImageRelease {
    pub repository: RepositorySlug,
    pub tag: String,
}

/// Schema-v2 image metadata bound by a signed pack manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltPackImageDescriptor {
    pub schema_version: u32,
    pub platform: BuiltImagePlatform,
    pub base_set: BuiltImageBaseSet,
    pub release: BuiltImageRelease,
    pub assets: BuiltImageAssets,
}

/// A descriptor is not eligible for asset fetch unless all immutable names
/// and the compiled base-set pin agree.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuiltImageDescriptorError {
    #[error("unsupported built pack image schema version {0}")]
    SchemaVersion(u32),
    #[error("built pack image requires a versioned pack reference")]
    UnversionedReference,
    #[error("built pack image base set does not match the compiled image lock")]
    BaseSetMismatch,
    #[error("built pack image release does not match its pack reference")]
    ReleaseMismatch,
    #[error("built pack image asset {role} must be named {expected} and have positive size")]
    InvalidAsset {
        role: &'static str,
        expected: &'static str,
    },
    #[error("built pack image provenance is invalid: {reason}")]
    InvalidProvenance { reason: String },
}

const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
const BUILD_TYPE: &str =
    "https://github.com/tinylabscom/mvm-packs/blob/main/README.packs.md#pack-image-composition-v1";
const PUBLISHER_IDENTITY: &str =
    "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main";
const PUBLISHER_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<ProvenanceSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: ProvenancePredicate,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceSubject {
    name: String,
    digest: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProvenancePredicate {
    build_definition: ProvenanceBuildDefinition,
    run_details: ProvenanceRunDetails,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProvenanceBuildDefinition {
    build_type: String,
    external_parameters: ProvenanceExternalParameters,
    internal_parameters: ProvenanceInternalParameters,
    resolved_dependencies: Vec<ProvenanceDependency>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceExternalParameters {
    reference: PackReference,
    base_set: BuiltImageBaseSet,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceInternalParameters {
    verifier_sha256: Sha256Hex,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceDependency {
    uri: String,
    digest: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProvenanceRunDetails {
    builder: ProvenanceBuilder,
    metadata: ProvenanceMetadata,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceBuilder {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProvenanceMetadata {
    invocation_id: String,
}

fn invalid_provenance(reason: impl Into<String>) -> BuiltImageDescriptorError {
    BuiltImageDescriptorError::InvalidProvenance {
        reason: reason.into(),
    }
}

impl BuiltPackImageDescriptor {
    /// Every externally published image and attestation asset.
    pub fn assets(&self) -> [&BuiltImageAsset; 7] {
        [
            &self.assets.rootfs,
            &self.assets.verity,
            &self.assets.roothash,
            &self.assets.mvm_meta,
            &self.assets.rootfs_signature_bundle,
            &self.assets.provenance_statement,
            &self.assets.provenance_signature_bundle,
        ]
    }

    /// Authenticate the measured root filesystem without loading it into memory.
    /// The caller must hash the retained file against `assets.rootfs` first.
    pub fn verify_rootfs_signature(&self, bundle: &[u8]) -> Result<(), BuiltImageDescriptorError> {
        verify_signed_sha256(
            self.assets.rootfs.sha256.as_str(),
            bundle,
            PUBLISHER_IDENTITY,
            PUBLISHER_ISSUER,
        )
        .map_err(|error| invalid_provenance(format!("rootfs signature refused: {error}")))
    }

    /// Validate the metadata before any external asset is fetched or trusted.
    /// This does not verify the asset bytes or their signatures.
    pub fn validate_pin(
        &self,
        reference: &PackReference,
        lock: &ImageLock,
    ) -> Result<(), BuiltImageDescriptorError> {
        if self.schema_version != 2 {
            return Err(BuiltImageDescriptorError::SchemaVersion(
                self.schema_version,
            ));
        }
        let version = reference
            .version()
            .ok_or(BuiltImageDescriptorError::UnversionedReference)?;
        if self.base_set.repository != lock.repository
            || self.base_set.release_tag != lock.release_tag
            || self.base_set.manifest_sha256 != lock.manifest_sha256
        {
            return Err(BuiltImageDescriptorError::BaseSetMismatch);
        }
        let expected_tag = format!(
            "pack-{}-{}-v{version}",
            reference.namespace(),
            reference.name()
        );
        if self.release.repository.as_str() != "tinylabscom/mvm-packs"
            || self.release.tag != expected_tag
        {
            return Err(BuiltImageDescriptorError::ReleaseMismatch);
        }
        for (role, expected, asset) in [
            ("rootfs", "rootfs.ext4", &self.assets.rootfs),
            ("verity", "rootfs.verity", &self.assets.verity),
            ("roothash", "rootfs.roothash", &self.assets.roothash),
            ("mvm_meta", "mvm-meta.json", &self.assets.mvm_meta),
            (
                "rootfs_signature_bundle",
                "rootfs.signature.json",
                &self.assets.rootfs_signature_bundle,
            ),
            (
                "provenance_statement",
                "provenance.json",
                &self.assets.provenance_statement,
            ),
            (
                "provenance_signature_bundle",
                "provenance.signature.json",
                &self.assets.provenance_signature_bundle,
            ),
        ] {
            if asset.name.as_str() != expected || asset.size == 0 {
                return Err(BuiltImageDescriptorError::InvalidAsset { role, expected });
            }
        }
        Ok(())
    }

    /// Authenticate the statement and require that its signed contents bind
    /// the image digest, current base lock, versioned pack, and publisher.
    /// A caller must still verify all release assets and the rootfs signature
    /// before installation or admission.
    pub fn verify_signed_provenance(
        &self,
        reference: &PackReference,
        lock: &ImageLock,
        publisher: &VerifiedSigner,
        statement: &[u8],
        bundle: &[u8],
    ) -> Result<Sha256Hex, BuiltImageDescriptorError> {
        self.validate_pin(reference, lock)?;
        if publisher.identity != PUBLISHER_IDENTITY || publisher.issuer != PUBLISHER_ISSUER {
            return Err(invalid_provenance("image publisher identity or issuer"));
        }
        let statement_size = u64::try_from(statement.len())
            .map_err(|_| invalid_provenance("statement length overflow"))?;
        let bundle_size = u64::try_from(bundle.len())
            .map_err(|_| invalid_provenance("bundle length overflow"))?;
        if statement_size != self.assets.provenance_statement.size
            || Sha256Hex::from_bytes(statement) != self.assets.provenance_statement.sha256
            || bundle_size != self.assets.provenance_signature_bundle.size
            || Sha256Hex::from_bytes(bundle) != self.assets.provenance_signature_bundle.sha256
        {
            return Err(invalid_provenance("statement or bundle digest differs"));
        }
        verify_signed_payload(statement, bundle, &publisher.identity, &publisher.issuer)
            .map_err(|error| invalid_provenance(format!("signature refused: {error}")))?;
        self.validate_provenance_payload(reference, &publisher.identity, statement)
    }

    /// Check the producer statement's exact artifact, base, and workflow
    /// bindings. The caller must authenticate the statement's Sigstore bundle
    /// separately before accepting this structural check as evidence. Returns
    /// the pinned verifier digest for the caller's released-client check.
    pub(crate) fn validate_provenance_payload(
        &self,
        reference: &PackReference,
        publisher_identity: &str,
        bytes: &[u8],
    ) -> Result<Sha256Hex, BuiltImageDescriptorError> {
        if publisher_identity != PUBLISHER_IDENTITY {
            return Err(invalid_provenance("image publisher workflow"));
        }
        let statement: ProvenanceStatement = serde_json::from_slice(bytes)
            .map_err(|error| invalid_provenance(format!("statement parse failed: {error}")))?;
        if statement.statement_type != STATEMENT_TYPE
            || statement.predicate_type != PREDICATE_TYPE
            || statement.subject.len() != 1
        {
            return Err(invalid_provenance(
                "statement type, predicate, or subject set",
            ));
        }
        let subject = &statement.subject[0];
        if subject.name != "rootfs.ext4"
            || subject.digest.len() != 1
            || subject.digest.get("sha256").map(String::as_str)
                != Some(self.assets.rootfs.sha256.as_str())
        {
            return Err(invalid_provenance("rootfs subject digest"));
        }
        let predicate = statement.predicate;
        let build = predicate.build_definition;
        if build.build_type != BUILD_TYPE
            || build.external_parameters.reference != *reference
            || build.external_parameters.base_set != self.base_set
        {
            return Err(invalid_provenance(
                "build type, pack reference, or base set",
            ));
        }
        if predicate.run_details.builder.id != publisher_identity
            || !predicate
                .run_details
                .metadata
                .invocation_id
                .starts_with("https://github.com/tinylabscom/mvm-packs/actions/runs/")
        {
            return Err(invalid_provenance("publisher workflow or invocation"));
        }
        if build.resolved_dependencies.len() != 5 {
            return Err(invalid_provenance("resolved dependency set"));
        }
        let mut seen = BTreeSet::new();
        let mut git_source = false;
        let mut images_lock = false;
        for dependency in build.resolved_dependencies {
            if !seen.insert(dependency.uri.clone()) || dependency.digest.len() != 1 {
                return Err(invalid_provenance("duplicate or ambiguous dependency"));
            }
            match dependency.uri.as_str() {
                "candidate.json" | "application-layer/rootfs.ext4" => {
                    let Some(digest) = dependency.digest.get("sha256") else {
                        return Err(invalid_provenance("candidate or layer digest type"));
                    };
                    if Sha256Hex::new(digest.clone()).is_err() {
                        return Err(invalid_provenance("candidate or layer digest syntax"));
                    }
                }
                "image-set.json" => {
                    if dependency.digest.get("sha256").map(String::as_str)
                        != Some(self.base_set.manifest_sha256.as_str())
                    {
                        return Err(invalid_provenance("signed base manifest digest"));
                    }
                }
                "mvm/images.lock" => {
                    if dependency.digest.get("sha256").map(String::as_str)
                        != Some(crate::image_set::image_train_lock_sha256().as_str())
                    {
                        return Err(invalid_provenance("compiled images lock digest"));
                    }
                    images_lock = true;
                }
                source if source.starts_with("git+https://github.com/tinylabscom/mvm-packs@") => {
                    let commit = source.rsplit_once('@').map(|(_, commit)| commit);
                    if !commit.is_some_and(|value| {
                        value.len() == 40
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                            && dependency.digest.get("gitCommit").map(String::as_str) == Some(value)
                    }) {
                        return Err(invalid_provenance("publisher source commit"));
                    }
                    git_source = true;
                }
                _ => return Err(invalid_provenance("unexpected resolved dependency")),
            }
        }
        if !git_source
            || !images_lock
            || !seen.contains("candidate.json")
            || !seen.contains("application-layer/rootfs.ext4")
            || !seen.contains("image-set.json")
        {
            return Err(invalid_provenance("missing required resolved dependency"));
        }
        Ok(build.internal_parameters.verifier_sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_set::image_train_lock;

    fn descriptor() -> BuiltPackImageDescriptor {
        let lock = &image_train_lock().image_set;
        let digest = Sha256Hex::from_bytes(b"test asset");
        let asset = |name: &str| BuiltImageAsset {
            name: ArtifactName::new(name).expect("valid asset name"),
            sha256: digest.clone(),
            size: 1,
        };
        BuiltPackImageDescriptor {
            schema_version: 2,
            platform: BuiltImagePlatform::LinuxX86_64,
            base_set: BuiltImageBaseSet {
                repository: lock.repository.clone(),
                release_tag: lock.release_tag.clone(),
                manifest_sha256: lock.manifest_sha256.clone(),
            },
            release: BuiltImageRelease {
                repository: RepositorySlug::new("tinylabscom/mvm-packs").expect("valid repository"),
                tag: "pack-runtime-python-v1.0.0".to_string(),
            },
            assets: BuiltImageAssets {
                rootfs: asset("rootfs.ext4"),
                verity: asset("rootfs.verity"),
                roothash: asset("rootfs.roothash"),
                mvm_meta: asset("mvm-meta.json"),
                rootfs_signature_bundle: asset("rootfs.signature.json"),
                provenance_statement: asset("provenance.json"),
                provenance_signature_bundle: asset("provenance.signature.json"),
            },
        }
    }

    #[test]
    fn built_rootfs_signature_refuses_an_invalid_bundle() {
        let error = descriptor()
            .verify_rootfs_signature(b"not a Sigstore bundle")
            .expect_err("rootfs bytes are not authenticated by a bad bundle");
        assert!(matches!(
            error,
            BuiltImageDescriptorError::InvalidProvenance { .. }
        ));
    }

    fn reference() -> PackReference {
        "runtime/python@1.0.0".parse().expect("valid reference")
    }

    fn provenance() -> serde_json::Value {
        let image = descriptor();
        let base = &image.base_set;
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "rootfs.ext4", "digest": {
                "sha256": image.assets.rootfs.sha256.as_str()
            }}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/tinylabscom/mvm-packs/blob/main/README.packs.md#pack-image-composition-v1",
                    "externalParameters": {
                        "reference": "runtime/python@1.0.0",
                        "base_set": {
                            "repository": base.repository.as_str(),
                            "release_tag": base.release_tag.as_str(),
                            "manifest_sha256": base.manifest_sha256.as_str()
                        }
                    },
                    "internalParameters": {"verifier_sha256": "a".repeat(64)},
                    "resolvedDependencies": [
                        {"uri": "candidate.json", "digest": {"sha256": "b".repeat(64)}},
                        {"uri": "application-layer/rootfs.ext4", "digest": {"sha256": "c".repeat(64)}},
                        {"uri": "image-set.json", "digest": {"sha256": base.manifest_sha256.as_str()}},
                        {"uri": "mvm/images.lock", "digest": {"sha256":
                            crate::image_set::image_train_lock_sha256().as_str()}},
                        {"uri": format!("git+https://github.com/tinylabscom/mvm-packs@{}", "d".repeat(40)),
                         "digest": {"gitCommit": "d".repeat(40)}}
                    ]
                },
                "runDetails": {
                    "builder": {"id": "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"},
                    "metadata": {"invocationId": "https://github.com/tinylabscom/mvm-packs/actions/runs/1/attempts/1"}
                }
            }
        })
    }

    #[test]
    fn producer_provenance_binds_image_base_reference_and_publisher() {
        let bytes = serde_json::to_vec(&provenance()).expect("statement JSON");
        let verifier = descriptor()
            .validate_provenance_payload(
                &reference(),
                "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main",
                &bytes,
            )
            .expect("producer statement binds all required inputs");
        assert_eq!(verifier.as_str(), "a".repeat(64));
    }

    #[test]
    fn producer_provenance_refuses_changed_subject_base_signer_or_materials() {
        let identity = "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main";
        for field in [
            "subject",
            "base",
            "signer",
            "material",
            "lock",
            "lock-other-valid",
        ] {
            let mut statement = provenance();
            match field {
                "subject" => {
                    statement["subject"][0]["digest"]["sha256"] =
                        serde_json::Value::String("e".repeat(64))
                }
                "base" => {
                    statement["predicate"]["buildDefinition"]["externalParameters"]["base_set"]["manifest_sha256"] =
                        serde_json::Value::String("e".repeat(64))
                }
                "signer" => {
                    statement["predicate"]["runDetails"]["builder"]["id"] =
                        serde_json::Value::String("https://untrusted.example/workflow".to_string())
                }
                "material" => {
                    statement["predicate"]["buildDefinition"]["resolvedDependencies"][2]["digest"]
                        ["sha256"] = serde_json::Value::String("e".repeat(64))
                }
                "lock" => {
                    statement["predicate"]["buildDefinition"]["resolvedDependencies"][3]["digest"]
                        ["sha256"] = serde_json::Value::String("not-a-digest".to_string())
                }
                "lock-other-valid" => {
                    statement["predicate"]["buildDefinition"]["resolvedDependencies"][3]["digest"]
                        ["sha256"] = serde_json::Value::String("e".repeat(64))
                }
                _ => unreachable!("test enumerates each tamper target"),
            }
            let bytes = serde_json::to_vec(&statement).expect("statement JSON");
            assert!(
                descriptor()
                    .validate_provenance_payload(&reference(), identity, &bytes)
                    .is_err(),
                "{field} tamper must be refused"
            );
        }
        let mut self_consistent_wrong_publisher = provenance();
        self_consistent_wrong_publisher["predicate"]["runDetails"]["builder"]["id"] =
            serde_json::Value::String("https://untrusted.example/workflow".to_string());
        let bytes = serde_json::to_vec(&self_consistent_wrong_publisher).expect("statement JSON");
        descriptor()
            .validate_provenance_payload(&reference(), "https://untrusted.example/workflow", &bytes)
            .expect_err("matching an untrusted signer is not the publisher workflow");
    }

    #[test]
    fn signed_provenance_gate_refuses_unsigned_bundle_and_changed_base_lock() {
        let statement = serde_json::to_vec(&provenance()).expect("statement JSON");
        let bundle = b"not a Sigstore bundle";
        let mut image = descriptor();
        image.assets.provenance_statement.sha256 = Sha256Hex::from_bytes(&statement);
        image.assets.provenance_statement.size =
            u64::try_from(statement.len()).expect("test statement length fits");
        image.assets.provenance_signature_bundle.sha256 = Sha256Hex::from_bytes(bundle);
        image.assets.provenance_signature_bundle.size =
            u64::try_from(bundle.len()).expect("test bundle length fits");
        let publisher = VerifiedSigner {
            identity: "https://github.com/tinylabscom/mvm-packs/.github/workflows/publish.yml@refs/heads/main"
                .to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        };
        let lock = &image_train_lock().image_set;
        assert!(matches!(
            image.verify_signed_provenance(&reference(), lock, &publisher, &statement, bundle),
            Err(BuiltImageDescriptorError::InvalidProvenance { .. })
        ));
        let moved = crate::image_set::ImageLock {
            manifest_sha256: Sha256Hex::from_bytes(b"different base"),
            ..lock.clone()
        };
        assert_eq!(
            image.verify_signed_provenance(&reference(), &moved, &publisher, &statement, bundle),
            Err(BuiltImageDescriptorError::BaseSetMismatch)
        );
        let mut changed_statement = statement;
        changed_statement.push(b'\n');
        assert!(matches!(
            image.verify_signed_provenance(
                &reference(),
                lock,
                &publisher,
                &changed_statement,
                bundle,
            ),
            Err(BuiltImageDescriptorError::InvalidProvenance { .. })
        ));
    }

    #[test]
    fn built_descriptor_roundtrips_and_accepts_exact_base_lock() {
        let expected = descriptor();
        let encoded = serde_json::to_vec(&expected).expect("serialize descriptor");
        let decoded: BuiltPackImageDescriptor =
            serde_json::from_slice(&encoded).expect("parse descriptor");
        assert_eq!(decoded, expected);
        decoded
            .validate_pin(&reference(), &image_train_lock().image_set)
            .expect("exact descriptor pin");
    }

    #[test]
    fn built_descriptor_refuses_a_moved_base_lock_and_release() {
        let lock = &image_train_lock().image_set;
        let mut changed_base = descriptor();
        changed_base.base_set.manifest_sha256 = Sha256Hex::from_bytes(b"different base");
        assert_eq!(
            changed_base.validate_pin(&reference(), lock),
            Err(BuiltImageDescriptorError::BaseSetMismatch)
        );

        let mut descriptor = descriptor();
        descriptor.release.tag = "pack-runtime-python-v1.0.1".to_string();
        assert_eq!(
            descriptor.validate_pin(&reference(), lock),
            Err(BuiltImageDescriptorError::ReleaseMismatch)
        );
    }

    #[test]
    fn built_descriptor_refuses_missing_or_misnamed_attestations() {
        let mut value = serde_json::to_value(descriptor()).expect("serialize descriptor");
        value["assets"]
            .as_object_mut()
            .expect("assets object")
            .remove("provenance_statement");
        assert!(serde_json::from_value::<BuiltPackImageDescriptor>(value).is_err());

        let mut descriptor = descriptor();
        descriptor.assets.provenance_signature_bundle.name =
            ArtifactName::new("other.json").expect("valid asset name");
        assert!(matches!(
            descriptor.validate_pin(&reference(), &image_train_lock().image_set),
            Err(BuiltImageDescriptorError::InvalidAsset {
                role: "provenance_signature_bundle",
                ..
            })
        ));
    }

    #[test]
    fn built_descriptor_refuses_unknown_fields_and_platforms() {
        let mut value = serde_json::to_value(descriptor()).expect("serialize descriptor");
        value["assets"]["rootfs"]["url"] =
            serde_json::Value::String("https://untrusted.example/rootfs.ext4".to_string());
        assert!(serde_json::from_value::<BuiltPackImageDescriptor>(value).is_err());

        let mut value = serde_json::to_value(descriptor()).expect("serialize descriptor");
        value["platform"] = serde_json::Value::String("linux/other".to_string());
        assert!(serde_json::from_value::<BuiltPackImageDescriptor>(value).is_err());
    }

    #[test]
    fn built_descriptor_refuses_empty_assets_and_unversioned_references() {
        let lock = &image_train_lock().image_set;
        let mut empty_asset = descriptor();
        empty_asset.assets.rootfs.size = 0;
        assert!(matches!(
            empty_asset.validate_pin(&reference(), lock),
            Err(BuiltImageDescriptorError::InvalidAsset { role: "rootfs", .. })
        ));

        let unversioned = "runtime/python"
            .parse()
            .expect("valid unversioned reference");
        assert_eq!(
            descriptor().validate_pin(&unversioned, lock),
            Err(BuiltImageDescriptorError::UnversionedReference)
        );
    }
}
