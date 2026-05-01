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
//! - `plan` — `ExecutionPlan`, `SCHEMA_VERSION`.
//! - `types` — every `*Ref` / `*Spec` placeholder type the plan
//!   references. Each is a thin newtype with serde + deny_unknown_fields
//!   so older verifiers fail closed on a future field addition.
//! - `signing` — `SignedExecutionPlan` envelope + sign/verify helpers
//!   using ed25519_dalek directly. Reuses the `SignedPayload` shape
//!   from `mvm-core::protocol::signing` so plan signatures fit the
//!   existing audit + control-plane wire types.

pub mod plan;
pub mod signing;
pub mod types;

pub use plan::{ExecutionPlan, SCHEMA_VERSION};
pub use signing::{PlanVerifyError, SignedExecutionPlan, sign_plan, verify_plan};
pub use types::{
    ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef, KeyRotationSpec, PlanId,
    PolicyRef, PostRunLifecycle, ReleasePin, Resources, RuntimeProfileRef, SecretBinding,
    SecretSource, SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
};
