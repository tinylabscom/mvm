//! Data types shared by the OCI cache core: the on-disk cache index, cached
//! image/layer records, provenance, trust decisions, and registry policy.
//! Pure types — no cache I/O, no network, no trust enforcement logic.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use mvm_fs::oci::ImageReference;

/// Name of the OCI cache index file, relative to the cache root.
pub(super) const INDEX_FILE: &str = "index.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OciCacheIndex {
    #[serde(default = "schema_version")]
    pub(super) schema_version: u32,
    #[serde(default)]
    pub(super) images: Vec<CachedOciImage>,
}

impl Default for OciCacheIndex {
    fn default() -> Self {
        // Hand-written, NOT derived: a derived `Default` sets `schema_version`
        // to 0 (the u32 default), which `save_index` then persists and the next
        // `load_index` rejects as unsupported. The `#[serde(default)]` only
        // fills a *missing* field on deserialize — it does not feed `Default`.
        Self {
            schema_version: schema_version(),
            images: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct OciImageConfigInner {
    #[serde(default, rename = "Entrypoint")]
    pub(super) entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    pub(super) cmd: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    pub(super) env: Vec<String>,
    #[serde(default, rename = "WorkingDir")]
    pub(super) working_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct OciImageConfig {
    #[serde(default, rename = "config")]
    pub(super) config: OciImageConfigInner,
}

pub(super) fn schema_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::commands) struct CachedOciImage {
    pub(super) reference: String,
    pub(super) registry: String,
    pub(super) repository: String,
    pub(super) tag: Option<String>,
    pub(super) resolved_digest: String,
    pub(super) fetched_at: String,
    pub(super) manifest_path: String,
    #[serde(default)]
    pub(super) config_path: Option<String>,
    #[serde(default)]
    pub(super) rootfs_path: Option<String>,
    /// Runtime identity (crate version + epoch) of the guest agent/netinit
    /// baked into `rootfs_path`. A mismatch with the running mvmctl forces
    /// re-materialization so a stale agent — e.g. one predating the interactive
    /// exec handler — is never reused. Absent on entries written before the
    /// tag existed, which therefore read as stale and re-materialize.
    #[serde(default)]
    pub(super) runtime_tag: Option<String>,
    #[serde(default)]
    pub(super) claims_path: Option<String>,
    #[serde(default)]
    pub(super) layers: Vec<CachedOciLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct ResolvedOciRunImage {
    pub reference: String,
    pub resolved_digest: String,
    pub rootfs_path: PathBuf,
    /// The prepared rootfs-only OCI tree, when it is present on disk — the
    /// source a virtiofs-root dev boot serves directly. This is distinct from
    /// the raw unpacked layer tree so the virtiofs `RootfsOnly` contract does
    /// not share one injected runtime layout with the block-backed ext4 image.
    pub unpacked_root: Option<PathBuf>,
    pub pulled: bool,
    pub provenance: OciProvenance,
    pub auth_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::commands) struct OciProvenance {
    pub schema_version: u32,
    pub source: String,
    pub supplied_reference: String,
    pub canonical_reference: String,
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub resolved_digest: String,
    pub layer_digests: Vec<String>,
    pub trust_policy: String,
    pub verification_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct CachedOciLayer {
    pub(super) digest: String,
    #[serde(default)]
    pub(super) size_bytes: u64,
    #[serde(default)]
    pub(super) path: Option<String>,
}

impl CachedOciImage {
    pub(super) fn provenance(
        &self,
        source: &str,
        supplied_reference: &str,
        trust: &OciTrustDecision,
    ) -> OciProvenance {
        OciProvenance {
            schema_version: 1,
            source: source.to_string(),
            supplied_reference: supplied_reference.to_string(),
            canonical_reference: self.reference.clone(),
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            tag: self.tag.clone(),
            resolved_digest: self.resolved_digest.clone(),
            layer_digests: self
                .layers
                .iter()
                .map(|layer| layer.digest.clone())
                .collect(),
            trust_policy: trust.trust_policy.clone(),
            verification_status: trust.verification_status.clone(),
        }
    }
}

impl OciProvenance {
    pub(in crate::commands) fn audit_labels(&self) -> Vec<(String, String)> {
        vec![
            ("oci_source".to_string(), self.source.clone()),
            (
                "oci_supplied_reference".to_string(),
                self.supplied_reference.clone(),
            ),
            (
                "oci_canonical_reference".to_string(),
                self.canonical_reference.clone(),
            ),
            ("oci_registry".to_string(), self.registry.clone()),
            ("oci_repository".to_string(), self.repository.clone()),
            (
                "oci_resolved_digest".to_string(),
                self.resolved_digest.clone(),
            ),
            (
                "oci_layer_digests".to_string(),
                self.layer_digests.join(","),
            ),
            ("oci_trust_policy".to_string(), self.trust_policy.clone()),
            (
                "oci_verification_status".to_string(),
                self.verification_status.clone(),
            ),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OciTrustDecision {
    pub(super) trust_policy: String,
    pub(super) verification_status: String,
}

impl OciTrustDecision {
    pub(super) fn dev_digest_only(image_ref: &ImageReference) -> Self {
        let trust_policy = if image_ref.is_digest_pinned() {
            "digest-pinned"
        } else {
            "mutable-reference-resolved-to-digest"
        };
        Self {
            trust_policy: trust_policy.to_string(),
            verification_status: "digest-verified-signature-not-required".to_string(),
        }
    }

    pub(super) fn cosign_verified(identity: &CosignIdentity) -> Self {
        Self {
            trust_policy: "prod-cosign-required".to_string(),
            verification_status: format!(
                "cosign-verified identity={} issuer={}",
                identity.certificate_identity, identity.certificate_oidc_issuer
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct OciRegistryPolicy {
    #[serde(default)]
    pub(super) allowed_registries: Vec<String>,
    #[serde(default = "super::trust::default_require_signatures")]
    pub(super) require_signatures: bool,
    #[serde(default)]
    pub(super) cosign: Vec<CosignIdentity>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CosignIdentity {
    pub(super) certificate_identity: String,
    pub(super) certificate_oidc_issuer: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct ImageListRow {
    pub(super) reference: String,
    pub(super) registry: String,
    pub(super) repository: String,
    pub(super) tag: Option<String>,
    pub(super) resolved_digest: String,
    pub(super) fetched_at: String,
    pub(super) size_bytes: u64,
    pub(super) layers: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct InspectOutput {
    pub(super) image: CachedOciImage,
    pub(super) size_bytes: u64,
    pub(super) manifest: Option<serde_json::Value>,
    pub(super) config: Option<serde_json::Value>,
    pub(super) claims: Option<serde_json::Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RemoveOutcome {
    pub(super) reference: String,
    pub(super) removed_files: usize,
    pub(super) freed_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn sample_image(reference: &str, digest: &str, layer_path: &str) -> CachedOciImage {
        CachedOciImage {
            reference: reference.to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: Some("3.20".to_string()),
            resolved_digest: digest.to_string(),
            fetched_at: "2026-05-18T00:00:00Z".to_string(),
            manifest_path: "manifests/alpine.json".to_string(),
            config_path: Some("configs/alpine.json".to_string()),
            rootfs_path: None,
            runtime_tag: None,
            claims_path: Some("claims/alpine.json".to_string()),
            layers: vec![CachedOciLayer {
                digest: "sha256:layer".to_string(),
                size_bytes: 4,
                path: Some(layer_path.to_string()),
            }],
        }
    }

    #[test]
    fn provenance_labels_cover_claim_10_fields() {
        let image = sample_image(
            "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "blobs/a",
        );

        let trust = OciTrustDecision {
            trust_policy: "prod-cosign-required".to_string(),
            verification_status: "cosign-verified identity=repo issuer=issuer".to_string(),
        };
        let provenance = image.provenance("image_pull", "alpine@sha256:aaa", &trust);
        let labels: BTreeMap<_, _> = provenance.audit_labels().into_iter().collect();

        assert_eq!(provenance.registry, "docker.io");
        assert_eq!(provenance.repository, "library/alpine");
        assert_eq!(
            provenance.resolved_digest,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(provenance.layer_digests, vec!["sha256:layer"]);
        assert_eq!(provenance.trust_policy, "prod-cosign-required");
        assert_eq!(
            labels.get("oci_supplied_reference").map(String::as_str),
            Some("alpine@sha256:aaa")
        );
        assert_eq!(
            labels.get("oci_verification_status").map(String::as_str),
            Some("cosign-verified identity=repo issuer=issuer")
        );
    }
}
