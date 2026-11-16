//! Shared local deploy-record wire types.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Schema version of the local deploy record.
pub const DEPLOY_RECORD_SCHEMA_VERSION: u32 = 2;

/// Exact-byte identities of the sealed deploy archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigests {
    /// BLAKE3 identity used by the local content-addressed store.
    pub blake3: String,
    /// SHA-256 identity retained for external tooling and interop.
    pub sha256: String,
    /// Number of bytes hashed in the archive.
    pub size_bytes: u64,
}

/// Exact-byte identity of the filesystem image that the boot path mounts.
///
/// This is deliberately separate from [`ArtifactDigests`]: the deploy archive
/// is a transport envelope, while this identity names the boot subject. A
/// caller must never use the archive digest as a rootfs digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootArtifactIdentity {
    /// Stable artifact kind understood by the boot path.
    pub kind: String,
    /// BLAKE3 identity used by the local content-addressed store.
    pub blake3: String,
    /// SHA-256 identity used by the signed execution plan and dm-verity
    /// interoperability boundaries.
    pub sha256: String,
    /// Number of bytes in the exact boot artifact.
    pub size_bytes: u64,
}

/// The pinned runtime environment used when the workload is admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPin {
    /// Lowercase hexadecimal SHA-256 of the workload kernel.
    pub kernel_sha256: String,
}

/// The verified dependency-volume evidence carried by a deploy record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyVolumeRecord {
    /// Hash returned by `verify_sealed_volume`.
    pub volume_hash: String,
    /// SHA-256 of the sealed SBOM bytes.
    pub sbom_sha256: String,
    /// SHA-256 of the sealed CVE result bytes.
    pub cve_sha256: String,
}

/// Local attestation record for a sealed workload artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRecord {
    /// Record schema version. Readers must reject versions they do not know.
    pub schema_version: u32,
    /// Workload identifier from the IR.
    pub workload_id: String,
    /// Internal canonical IR fingerprint used by launch plans.
    pub ir_hash: String,
    /// Exact-byte identities of the sealed image archive.
    pub image: ArtifactDigests,
    /// Exact-byte identity of the filesystem image selected for boot.
    pub boot_artifact: BootArtifactIdentity,
    /// Runtime environment pin, when one was resolved before deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentPin>,
    /// Dependency-volume evidence, when the workload uses one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_volume: Option<DependencyVolumeRecord>,
}
