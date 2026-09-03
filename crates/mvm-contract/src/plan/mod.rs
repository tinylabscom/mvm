//! Plan types — the signed `ExecutionPlan` contract itself and the pure
//! serde DTOs it's built from. Logic (sign/verify/hash/resolve/synth/fs/net/io)
//! stays in `mvm-core::plan`, which re-exports these types at their
//! existing paths.

pub mod bundle;
pub mod execution_plan;
pub mod sdk_sidecar;
pub mod types;
pub mod validity;
pub mod verb;
pub mod verb_grant;
pub mod verb_trust;

pub use execution_plan::{ExecutionPlan, SCHEMA_VERSION};
pub use sdk_sidecar::{
    SDK_HOST_SERVICES, SDK_SIDECAR_GUEST_PATH, SDK_SIDECAR_LIB_PATH, is_sdk_host_service,
    sdk_host_services_in, sdk_sidecar_required, sdk_sidecar_required_for,
};
pub use types::{
    AdmissionProfile, ArtifactDigests, ArtifactPolicy, AttestationMode, AttestationRequirement,
    AuditLabels, AuditTaxonomy, BuildProvenance, CallerCommitment, CallerCommitmentParseError,
    DepsVolumeBinding, DepsVolumeBindingError, FsPolicyRef, HostShareGrant, IngressMapping,
    IngressMappingBuildError, IngressMappingBuilder, IngressMappingError, IngressMappingsError,
    IngressProtocol, IngressTransform, InputKind, KeyRotationSpec, NetworkLimits,
    NetworkLimitsBuilder, NetworkLimitsError, NetworkMode, Nonce, NonceParseError, PlanId,
    PlanSeccompTier, PlanSeccompTierParseError, PolicyRef, PostRunLifecycle, ReleasePin, Resources,
    RuntimeProfileRef, SecretBinding, SecretReleasePolicy, SecretSource, ShareKind, SignedImageRef,
    StreamRetention, TenantId, TimeoutSpec, Variant, WorkloadId, WorkloadIntent,
    validate_ingress_mappings, validate_ingress_material,
};
pub use types::{AssetIdentity, AssetKind};
pub use validity::FreshnessClaims;
pub use verb::{VerbId, VerbIdError};
pub use verb_grant::{VERB_GRANT_BASELINE, VerbGrant, VerbGrantError};
pub use verb_trust::{GrantKeySource, VERB_TRUST_POLICY_VERSION, VerbTrustPolicy};
