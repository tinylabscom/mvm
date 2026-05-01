//! Decorated execution plans — the contract between workload intent and the
//! runtime supervisor.
//!
//! This crate ships the typed `ExecutionPlan`, the signed-envelope wrapper,
//! and the admission-time validity checks (signature + replay protection).
//! See whitepaper §3.3 and plan 37 Wave 1.
//!
//! Most reference types here are scaffolds: they define the shape mvmd /
//! `mvm-policy` / `mvm-supervisor` will eventually populate, but the
//! resolvers themselves are out of scope for this crate. The shape is
//! load-bearing — every "signed/audited/policy-pinned" claim downstream
//! keys off these fields.

pub mod envelope;
pub mod plan;
pub mod refs;
pub mod replay;

pub use envelope::{SignedExecutionPlan, sign_plan, verify_plan};
pub use plan::{ExecutionPlan, PlanId, Resources, WorkloadId};
pub use refs::{
    ArtifactPolicy, AttestationRequirement, FsPolicyRef, KeyRotationSpec, PolicyRef,
    PostRunLifecycle, ReleasePin, RuntimeProfileRef, SecretBinding, SignedImageRef,
};
pub use replay::{NonceStore, PlanValidityError};
