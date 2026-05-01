//! mvm-policy — signed `PolicyBundle` carrying network, egress, PII,
//! tool, artifact, key, and audit policies referenced by an
//! `ExecutionPlan`.
//!
//! Plan 37 §10. Every executable artifact (image, kernel, policy
//! bundle) is signed and verified at admission. Plan 36 closed the
//! image side (cosign-keyless on the dev/builder image manifest);
//! this crate closes the policy-bundle side using the same Ed25519
//! envelope shape `mvm-plan` introduced for `SignedExecutionPlan`.
//!
//! Wave 1.2 of plan 37 lands the bundle type + signed envelope. The
//! sub-policies (NetworkPolicy, EgressPolicy, PiiPolicy, ToolPolicy,
//! ArtifactPolicy, KeyPolicy, AuditPolicy) are scaffolded as minimal
//! placeholders here — each gets its real shape in subsequent
//! waves. The bundle wire format ships before substance so consumers
//! can land their resolver hooks against a stable type.
//!
//! Structure:
//! - `bundle` — `PolicyBundle` + `SCHEMA_VERSION`.
//! - `policies` — sub-policy stubs (NetworkPolicy, EgressPolicy, ...).
//! - `signing` — `SignedPolicyBundle` envelope + sign/verify.

pub mod bundle;
pub mod policies;
pub mod signing;

pub use bundle::{PolicyBundle, PolicyId, SCHEMA_VERSION, TenantOverlay};
pub use policies::{
    ArtifactPolicy, AuditPolicy, EgressPolicy, KeyPolicy, NetworkPolicy, PiiPolicy, ToolPolicy,
};
pub use signing::{BundleVerifyError, SignedPolicyBundle, sign_bundle, verify_bundle};
