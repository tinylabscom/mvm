//! Expected prepared OCI identity, not cached authorization.
//!
//! These records may be displayed or persisted by callers. Only the canonical
//! client resolver can establish whether the current cache matches them.

use serde::{Deserialize, Serialize};

/// Trust qualification of the additive prepared-image selection surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedImageTrust {
    /// Content digests were checked; no publisher signature is asserted.
    DevelopmentDigestOnly,
}

/// Untrusted expected identity. It carries no cache paths or authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOciSelection {
    pub canonical_reference: String,
    pub manifest_digest: String,
    pub rootfs_sha256: String,
    pub verity_sha256: String,
    pub roothash: String,
    /// Canonical sidecar checksum, excluding its incidental build timestamp.
    pub guest_sidecar_sha256: String,
    pub runtime_identity: String,
    pub platform: String,
    pub backend: String,
    pub layer_digests: Vec<String>,
    pub trust: PreparedImageTrust,
}

impl PreparedOciSelection {
    /// Provenance labels for the original admission after MVM revalidation.
    pub fn audit_labels(&self) -> std::collections::BTreeMap<String, String> {
        let mut labels = std::collections::BTreeMap::from([
            ("oci_source".into(), "run_image".into()),
            (
                "oci_supplied_reference".into(),
                self.canonical_reference.clone(),
            ),
            (
                "oci_canonical_reference".into(),
                self.canonical_reference.clone(),
            ),
            ("oci_resolved_digest".into(), self.manifest_digest.clone()),
            ("oci_layer_digests".into(), self.layer_digests.join(",")),
            (
                "oci_verification_status".into(),
                "digest-verified-signature-not-required".into(),
            ),
            ("prepared_rootfs_sha256".into(), self.rootfs_sha256.clone()),
            (
                "prepared_runtime_identity".into(),
                self.runtime_identity.clone(),
            ),
            ("prepared_platform".into(), self.platform.clone()),
            ("prepared_trust".into(), "development-digest-only".into()),
        ]);
        if let Ok(reference) = self
            .canonical_reference
            .parse::<mvm_contract::oci::ImageReference>()
        {
            labels.insert("oci_registry".into(), reference.registry);
            labels.insert("oci_repository".into(), reference.repository);
            labels.insert(
                "oci_trust_policy".into(),
                if reference.digest.is_some() {
                    "digest-pinned"
                } else {
                    "mutable-reference-resolved-to-digest"
                }
                .into(),
            );
        }
        labels
    }
}

/// Stable prepared-image refusal category, preserved across client surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedImageErrorKind {
    NotPrepared,
    MissingKernel,
    RuntimeUnavailable,
    RuntimeMismatch,
    PlatformMismatch,
    CorruptPreparation,
    SelectionChanged,
    TrustPolicyRefused,
    UnsupportedMode,
}

impl PreparedImageErrorKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotPrepared => "PREPARED_IMAGE_NOT_PREPARED",
            Self::MissingKernel => "PREPARED_IMAGE_MISSING_KERNEL",
            Self::RuntimeUnavailable => "PREPARED_IMAGE_RUNTIME_UNAVAILABLE",
            Self::RuntimeMismatch => "PREPARED_IMAGE_RUNTIME_MISMATCH",
            Self::PlatformMismatch => "PREPARED_IMAGE_PLATFORM_MISMATCH",
            Self::CorruptPreparation => "PREPARED_IMAGE_CORRUPT",
            Self::SelectionChanged => "PREPARED_IMAGE_SELECTION_CHANGED",
            Self::TrustPolicyRefused => "PREPARED_IMAGE_TRUST_REFUSED",
            Self::UnsupportedMode => "PREPARED_IMAGE_UNSUPPORTED",
        }
    }
}

/// Explicit operator action; retrying a launch never performs the remedy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedImageRemedy {
    PrepareImage,
    Bootstrap,
    PrepareCompatibleImage,
    Reselect,
    ExplicitProductionPreparation,
    ChangeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{kind:?}: {reference}: {detail}")]
pub struct PreparedImageError {
    pub kind: PreparedImageErrorKind,
    pub reference: String,
    pub detail: String,
}

impl PreparedImageError {
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub const fn remedy(&self) -> PreparedImageRemedy {
        match self.kind {
            PreparedImageErrorKind::NotPrepared
            | PreparedImageErrorKind::RuntimeMismatch
            | PreparedImageErrorKind::CorruptPreparation => PreparedImageRemedy::PrepareImage,
            PreparedImageErrorKind::MissingKernel | PreparedImageErrorKind::RuntimeUnavailable => {
                PreparedImageRemedy::Bootstrap
            }
            PreparedImageErrorKind::PlatformMismatch => PreparedImageRemedy::PrepareCompatibleImage,
            PreparedImageErrorKind::SelectionChanged => PreparedImageRemedy::Reselect,
            PreparedImageErrorKind::TrustPolicyRefused => {
                PreparedImageRemedy::ExplicitProductionPreparation
            }
            PreparedImageErrorKind::UnsupportedMode => PreparedImageRemedy::ChangeRequest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_roundtrips_without_losing_code_or_remedy() {
        let refusal = PreparedImageError {
            kind: PreparedImageErrorKind::SelectionChanged,
            reference: "docker.io/library/alpine:3.20".into(),
            detail: "prepared bytes changed".into(),
        };
        let restored: PreparedImageError =
            serde_json::from_slice(&serde_json::to_vec(&refusal).unwrap()).unwrap();
        assert_eq!(restored, refusal);
        assert_eq!(restored.code(), "PREPARED_IMAGE_SELECTION_CHANGED");
        assert_eq!(restored.remedy(), PreparedImageRemedy::Reselect);
    }
}
