//! mvm-plan — typed, signed `ExecutionPlan` contract for mvm workloads.
//!
//! Plan 37 §3.3 (CORNERSTONE) makes the `ExecutionPlan` the runtime
//! contract every workload boots from: image + resources + every
//! policy reference, signed with Ed25519, audit-bound to a stable
//! `plan_id` so audit entries can refer back to the exact plan
//! version a workload ran under.
//!
//! Wave 1.1 of plan 37 lands the type itself + the signed envelope.
//! Resolvers for the `*Ref` fields (PolicyRef, FsPolicyRef, etc.)
//! are scaffolded as opaque newtypes here and filled in subsequent
//! waves (Wave 2 wires the egress + tool-gate policies, Wave 3 the
//! attestation requirement, etc.).
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
//! - `validity` — `check_window` + `NonceStore` for plan 37
//!   Addendum G4 replay protection. Distinct from `signing`: the
//!   envelope check answers "is this signature valid for this plan",
//!   the validity check answers "should we accept this otherwise-
//!   valid plan now".

pub mod bundle;
pub mod execution_plan;
pub mod signing;
pub mod types;
pub mod validity;

pub use bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleInstallError, BundleManifest,
    BundleRegistry, BundleResolveError, BundleResolver, BundleResources, BundleVerifyError,
    FsBundleResolver, FsTrustStore, InstalledBundle, KeyId, PlanArtifact, PlanBundleError,
    TrustStore, VerifiedBundle, VerityInfo, bundle_sha256, read_and_verify_bundle, sha256_hex,
    signature_from_base64, signature_to_base64, verify_plan_bundle, write_bundle,
};
pub use execution_plan::{ExecutionPlan, SCHEMA_VERSION};
pub use signing::{
    PlanVerifyError, SignedExecutionPlan, redaction_from_signed_json, secrets_from_signed_json,
    sign_plan, tenant_from_signed_json, verify_plan,
};
pub use types::{
    AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, AuditTaxonomy,
    DepsVolumeBinding, DepsVolumeBindingError, FsPolicyRef, HostShareGrant, KeyRotationSpec, Nonce,
    NonceParseError, PlanId, PlanSeccompTier, PlanSeccompTierParseError, PolicyRef,
    PostRunLifecycle, ReleasePin, Resources, RuntimeProfileRef, SecretBinding, SecretReleasePolicy,
    SecretSource, ShareKind, SignedImageRef, TenantId, TimeoutSpec, Variant, WorkloadId,
    WorkloadIntent,
};
pub use validity::{NonceStore, PlanValidityError, check_window};
