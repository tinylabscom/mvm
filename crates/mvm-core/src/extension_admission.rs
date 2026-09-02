//! Admission of independently signed optional extension packs.
//!
//! Verification proves what the publisher signed. Admission narrows that
//! maximum to the request, host policy, short-lived grant, and explicit
//! approval, then returns the exact binding to embed in the signed execution
//! plan. Ordinary launches never call this module.

use std::collections::{BTreeSet, HashSet};

use mvm_contract::protocol::agent_capability::{CapabilityDescriptor, CapabilityId};
use mvm_contract::protocol::extension_pack::{
    ExtensionBudgets, ExtensionPlacement, ExtensionPlanBinding,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::packs::{PackKind, PackManifest, VerifiedPack};

/// The four host/operator authority sources intersected with the pack maximum.
pub struct ExtensionAuthority<'a> {
    pub requested: &'a HashSet<CapabilityId>,
    pub policy_ceiling: &'a HashSet<CapabilityId>,
    pub session_grant: &'a HashSet<CapabilityId>,
    pub explicit_approval: &'a HashSet<CapabilityId>,
}

/// Local ceilings that a publisher cannot widen.
pub struct ExtensionAdmissionPolicy<'a> {
    pub placements: &'a BTreeSet<ExtensionPlacement>,
    pub budgets: ExtensionBudgets,
}

/// Build the exact extension binding for a signed execution plan.
pub fn admit_extension(
    manifest: &PackManifest,
    verified: &VerifiedPack,
    authority: ExtensionAuthority<'_>,
    policy: ExtensionAdmissionPolicy<'_>,
) -> Result<ExtensionPlanBinding, ExtensionAdmissionError> {
    if manifest.kind != PackKind::Extension {
        return Err(ExtensionAdmissionError::WrongPackKind);
    }
    if manifest.outputs.pack_hash != verified.pack_hash
        || manifest.trust.signing_key_id != verified.signer_key_id
    {
        return Err(ExtensionAdmissionError::VerificationIdentityMismatch);
    }
    let extension = manifest
        .extension
        .as_ref()
        .ok_or(ExtensionAdmissionError::MissingContract)?;
    extension.validate()?;
    if !mvm_version_is_supported(
        env!("CARGO_PKG_VERSION"),
        extension.protocol.min_mvm_version.as_str(),
        extension.protocol.max_mvm_version.as_str(),
    ) {
        return Err(ExtensionAdmissionError::UnsupportedMvmVersion);
    }
    if !policy.placements.contains(&extension.placement) {
        return Err(ExtensionAdmissionError::PlacementNotAllowed);
    }

    let capabilities: Vec<_> = extension
        .capabilities
        .iter()
        .filter(|descriptor| authority.requested.contains(&descriptor.id))
        .filter(|descriptor| authority.policy_ceiling.contains(&descriptor.id))
        .filter(|descriptor| authority.session_grant.contains(&descriptor.id))
        .filter(|descriptor| authority.explicit_approval.contains(&descriptor.id))
        .map(CapabilityDescriptor::binding)
        .collect();
    if capabilities.is_empty() {
        return Err(ExtensionAdmissionError::NoCapabilitiesRemain);
    }

    let budgets = intersect_budgets(extension.budgets, policy.budgets);
    let artifact = manifest
        .outputs
        .files
        .iter()
        .find(|file| file.path == extension.artifact)
        .ok_or(ExtensionAdmissionError::ArtifactNotDeclared)?;
    if artifact.size_bytes > budgets.max_artifact_bytes {
        return Err(ExtensionAdmissionError::ArtifactBudgetExceeded);
    }

    let contract_bytes =
        serde_json::to_vec(extension).map_err(|_| ExtensionAdmissionError::ContractEncoding)?;
    Ok(ExtensionPlanBinding {
        extension_id: extension.extension_id.clone(),
        version: extension.version.clone(),
        pack_digest: decode_pack_digest(verified.pack_hash.as_str())?,
        contract_digest: Sha256::digest(contract_bytes).into(),
        placement: extension.placement,
        artifact: extension.artifact.clone(),
        entrypoint: extension.entrypoint.clone(),
        capabilities,
        budgets,
    })
}

fn decode_pack_digest(value: &str) -> Result<[u8; 32], ExtensionAdmissionError> {
    let decoded = hex::decode(value).map_err(|_| ExtensionAdmissionError::InvalidPackDigest)?;
    decoded
        .try_into()
        .map_err(|_| ExtensionAdmissionError::InvalidPackDigest)
}

fn intersect_budgets(left: ExtensionBudgets, right: ExtensionBudgets) -> ExtensionBudgets {
    ExtensionBudgets {
        cpu_millis: left.cpu_millis.min(right.cpu_millis),
        memory_bytes: left.memory_bytes.min(right.memory_bytes),
        duration_ms: left.duration_ms.min(right.duration_ms),
        max_steps: left.max_steps.min(right.max_steps),
        max_concurrency: left.max_concurrency.min(right.max_concurrency),
        max_payload_bytes: left.max_payload_bytes.min(right.max_payload_bytes),
        max_output_bytes: left.max_output_bytes.min(right.max_output_bytes),
        max_artifact_bytes: left.max_artifact_bytes.min(right.max_artifact_bytes),
    }
}

fn mvm_version_is_supported(current: &str, minimum: &str, maximum: &str) -> bool {
    fn parse(value: &str) -> Option<(u64, u64, u64)> {
        let core = value.split_once('-').map_or(value, |(core, _)| core);
        let mut parts = core.split('.');
        let parsed = (
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        parts.next().is_none().then_some(parsed)
    }
    parse(current)
        .zip(parse(minimum))
        .zip(parse(maximum))
        .is_some_and(|((current, minimum), maximum)| (minimum..=maximum).contains(&current))
}

#[derive(Debug, Error)]
pub enum ExtensionAdmissionError {
    #[error("pack is not an extension pack")]
    WrongPackKind,
    #[error("verified pack identity does not match the supplied manifest")]
    VerificationIdentityMismatch,
    #[error("extension pack has no extension contract")]
    MissingContract,
    #[error("extension placement is not permitted by host policy")]
    PlacementNotAllowed,
    #[error("extension does not support this MVM version")]
    UnsupportedMvmVersion,
    #[error("no capability survives extension authority intersection")]
    NoCapabilitiesRemain,
    #[error("extension artifact is not declared by the verified pack")]
    ArtifactNotDeclared,
    #[error("extension artifact exceeds the effective artifact budget")]
    ArtifactBudgetExceeded,
    #[error("extension contract could not be encoded")]
    ContractEncoding,
    #[error("verified pack digest is malformed")]
    InvalidPackDigest,
    #[error(transparent)]
    Contract(#[from] mvm_contract::protocol::extension_pack::ExtensionContractError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::agent_capability::{
        CapabilityDescriptor, CapabilityId, CapabilityLimits, SchemaRef,
    };
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_contract::protocol::extension_pack::{
        EXTENSION_PACK_SCHEMA, ExtensionId, ExtensionPackContract, ExtensionProtocolRange,
        ExtensionVersion,
    };

    use crate::arch::GuestArch;
    use crate::packs::{
        EMPTY_PACK_HASH, HostCapability, PackBackend, PackFile, PackInputs, PackOutputs,
        PackProvenance, PolicyCompatibility, ReproducibilityStatus, SbomReference, Sha256Hex,
        SignatureBundle, SignatureFormat, SignaturePayload, TrustMetadata,
    };
    use crate::plan::bundle::KeyId;

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.assurance.v1").expect("service"),
                "probe",
            )
            .expect("id"))
            .description("bounded probe")
            .input_schema(SchemaRef::new("probe.input.v1", [1; 32]).expect("input"))
            .output_schema(SchemaRef::new("probe.output.v1", [2; 32]).expect("output"))
            .limits(CapabilityLimits::new(100, 100, 100).expect("limits"))
            .build()
            .expect("descriptor")
    }

    fn budgets() -> ExtensionBudgets {
        ExtensionBudgets {
            cpu_millis: 100,
            memory_bytes: 1024,
            duration_ms: 1000,
            max_steps: 12,
            max_concurrency: 1,
            max_payload_bytes: 100,
            max_output_bytes: 100,
            max_artifact_bytes: 1024,
        }
    }

    fn fixture() -> (PackManifest, VerifiedPack, CapabilityId) {
        let descriptor = descriptor();
        let capability = descriptor.id.clone();
        let pack_hash = Sha256Hex::new("1".repeat(64)).expect("digest");
        let signer = KeyId("ed25519:test".to_string());
        let manifest = PackManifest {
            schema_version: 1,
            kind: PackKind::Extension,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Hvf],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: Sha256Hex::new(EMPTY_PACK_HASH).expect("hash"),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            extension: Some(ExtensionPackContract {
                schema: EXTENSION_PACK_SCHEMA.to_string(),
                extension_id: ExtensionId::parse("org.example.extension").expect("id"),
                version: ExtensionVersion::parse("1.0.0").expect("version"),
                protocol: ExtensionProtocolRange {
                    min_mvm_version: ExtensionVersion::parse("0.18.0").expect("min"),
                    max_mvm_version: ExtensionVersion::parse("0.18.9").expect("max"),
                    min_protocol: 1,
                    max_protocol: 1,
                },
                placement: ExtensionPlacement::GuestWorkload,
                artifact: "extension.ext4".to_string(),
                entrypoint: "bin/extension".to_string(),
                capabilities: vec![descriptor],
                budgets: budgets(),
                revocation_identity: "org.example.extension.release".to_string(),
                permission_delta: "May invoke one bounded probe.".to_string(),
            }),
            inputs: PackInputs {
                flake_locks: vec![],
                derivations: vec![],
                nar_hashes: vec![],
                oci_images: vec![],
                setup_commands: vec![],
                source_revisions: vec![],
                toolchain_versions: Default::default(),
            },
            outputs: PackOutputs {
                pack_hash: pack_hash.clone(),
                files: vec![PackFile {
                    path: "extension.ext4".to_string(),
                    sha256: Sha256Hex::new(EMPTY_PACK_HASH).expect("artifact digest"),
                    size_bytes: 512,
                }],
                closure_hash: None,
                rootfs_hash: None,
                kernel_hash: None,
                initramfs_hash: None,
                agent_rootfs_hash: None,
                builder_image_hash: None,
            },
            provenance: PackProvenance {
                builder_identity: "builder".to_string(),
                build_environment_identity: "ci".to_string(),
                build_timestamp: chrono::Utc::now(),
                reproducibility: ReproducibilityStatus::NotChecked,
                sbom: SbomReference {
                    uri: "urn:sbom:test".to_string(),
                    sha256: Sha256Hex::new(EMPTY_PACK_HASH).expect("hash"),
                },
                signature_bundle: SignatureBundle {
                    format: SignatureFormat::Ed25519,
                    payload: SignaturePayload::ManifestV1,
                    signatures: vec![],
                },
            },
            trust: TrustMetadata {
                signing_key_id: signer.clone(),
                expires_at: chrono::Utc::now(),
                revocation_channel: "https://example.test/revocations".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
        };
        (
            manifest,
            VerifiedPack {
                pack_hash,
                file_count: 1,
                signer_key_id: signer,
            },
            capability,
        )
    }

    #[test]
    fn all_five_authorities_must_agree() {
        let (manifest, verified, capability) = fixture();
        let all = HashSet::from([capability.clone()]);
        let placements = BTreeSet::from([ExtensionPlacement::GuestWorkload]);
        let binding = admit_extension(
            &manifest,
            &verified,
            ExtensionAuthority {
                requested: &all,
                policy_ceiling: &all,
                session_grant: &all,
                explicit_approval: &all,
            },
            ExtensionAdmissionPolicy {
                placements: &placements,
                budgets: budgets(),
            },
        )
        .expect("admitted");
        assert_eq!(binding.capabilities.len(), 1);

        let none = HashSet::new();
        assert!(matches!(
            admit_extension(
                &manifest,
                &verified,
                ExtensionAuthority {
                    requested: &all,
                    policy_ceiling: &all,
                    session_grant: &all,
                    explicit_approval: &none,
                },
                ExtensionAdmissionPolicy {
                    placements: &placements,
                    budgets: budgets(),
                },
            ),
            Err(ExtensionAdmissionError::NoCapabilitiesRemain)
        ));
    }

    #[test]
    fn effective_artifact_budget_is_enforced_before_admission() {
        let (manifest, verified, capability) = fixture();
        let all = HashSet::from([capability]);
        let placements = BTreeSet::from([ExtensionPlacement::GuestWorkload]);
        let mut ceiling = budgets();
        ceiling.max_artifact_bytes = 511;
        assert!(matches!(
            admit_extension(
                &manifest,
                &verified,
                ExtensionAuthority {
                    requested: &all,
                    policy_ceiling: &all,
                    session_grant: &all,
                    explicit_approval: &all,
                },
                ExtensionAdmissionPolicy {
                    placements: &placements,
                    budgets: ceiling,
                },
            ),
            Err(ExtensionAdmissionError::ArtifactBudgetExceeded)
        ));
    }
}
