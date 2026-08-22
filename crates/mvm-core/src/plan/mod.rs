//! plan — typed, signed `ExecutionPlan` contract for mvm workloads (was `mvm-plan`).
//!
//! The `ExecutionPlan` is the runtime contract every workload boots
//! from: image + resources + every policy reference, signed with
//! Ed25519, audit-bound to a stable `plan_id` so audit entries can
//! refer back to the exact plan version a workload ran under.
//!
//! Resolvers for the `*Ref` fields (PolicyRef, FsPolicyRef, etc.)
//! are scaffolded as opaque newtypes here and filled in later: the
//! egress + tool-gate policies, then the attestation requirement.
//!
//! Structure:
//! - `execution_plan` — `ExecutionPlan`, `SCHEMA_VERSION`.
//! - `types` — every `*Ref` / `*Spec` placeholder type the plan
//!   references. Each is a thin newtype with serde + deny_unknown_fields
//!   so older verifiers fail closed on a future field addition.
//! - `signing` — `SignedExecutionPlan` envelope + sign/verify helpers
//!   using ed25519_dalek directly. Reuses the `SignedPayload` shape
//!   from `mvm-core::protocol::signing` so plan signatures fit the
//!   existing audit + control-plane wire types.
//! - `validity` — `check_window` + `NonceStore` for replay
//!   protection. Distinct from `signing`: the
//!   envelope check answers "is this signature valid for this plan",
//!   the validity check answers "should we accept this otherwise-
//!   valid plan now".

pub mod bundle;
pub mod content_id;
pub mod signing;
pub mod synthesis;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod validity;

// `execution_plan`, `types`, `verb`, `verb_grant`, `verb_trust` are
// pure-DTO leaves that now live in `mvm-contract`; re-exported here as
// module aliases so every existing
// `crate::plan::{execution_plan,types,verb,verb_grant,verb_trust}::X` path
// keeps resolving unchanged.
pub use mvm_contract::plan::{execution_plan, sdk_sidecar, types, verb, verb_grant, verb_trust};

pub use bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleInstallError, BundleManifest,
    BundleRegistry, BundleResolveError, BundleResolver, BundleResources, BundleVerifyError,
    FsBundleResolver, FsTrustStore, InstalledBundle, KeyId, PlanArtifact, PlanBundleError,
    TrustStore, VerifiedBundle, VerityInfo, bundle_sha256, read_and_verify_bundle, sha256_hex,
    signature_from_base64, signature_to_base64, verify_plan_bundle, write_bundle,
};
pub use content_id::{PlanIdMismatch, compute_plan_id, verify_plan_id};
pub use execution_plan::{ExecutionPlan, SCHEMA_VERSION};
pub use sdk_sidecar::{
    SDK_HOST_SERVICES, SDK_SIDECAR_GUEST_PATH, SDK_SIDECAR_LIB_PATH, is_sdk_host_service,
    sdk_host_services_in, sdk_sidecar_required, sdk_sidecar_required_for,
};
pub use signing::{
    PlanVerifyError, SignedExecutionPlan, plan_from_admitted_json, redaction_from_signed_json,
    secrets_from_signed_json, sign_plan, tenant_from_signed_json, verify_plan,
};
pub use synthesis::{
    DEFAULT_AUDIT_EVENT_PREFIX, DEFAULT_INTENT, DEFAULT_POLICY_REF, DEFAULT_TENANT, SynthesisInput,
    VALIDITY_WINDOW_MINUTES, synthesize_plan,
};
pub use types::{
    AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, AuditLabels,
    AuditTaxonomy, DepsVolumeBinding, DepsVolumeBindingError, EnvironmentRef, FsPolicyRef,
    HostShareGrant, IngressMapping, IngressMappingBuildError, IngressMappingBuilder,
    IngressMappingError, IngressMappingsError, IngressProtocol, IngressTransform, KeyRotationSpec,
    NetworkLimits, NetworkLimitsBuilder, NetworkLimitsError, NetworkMode, Nonce, NonceParseError,
    PlanId, PlanSeccompTier, PlanSeccompTierParseError, PolicyRef, PostRunLifecycle, ReleasePin,
    Resources, RuntimeProfileRef, SecretBinding, SecretReleasePolicy, SecretSource, ShareKind,
    SignedImageRef, StreamRetention, TenantId, TimeoutSpec, Variant, WorkloadId, WorkloadIntent,
    validate_ingress_mappings, validate_ingress_material,
};
pub use validity::{
    CheckedFreshness, Freshness, FreshnessClaims, NonceStore, PlanValidityError, check_window,
};
pub use verb::{VerbId, VerbIdError};
pub use verb_grant::{VERB_GRANT_BASELINE, VerbGrant, VerbGrantError};
pub use verb_trust::{GrantKeySource, VERB_TRUST_POLICY_VERSION, VerbTrustPolicy};
