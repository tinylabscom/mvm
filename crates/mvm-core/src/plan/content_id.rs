//! Content-addressing for [`ExecutionPlan`]: a plan's `plan_id` is the SHA-256
//! of its load-bearing content, rendered `sha256:<64 lowercase hex>`.
//!
//! This is a **per-execution** identity, not a workload identity: because the
//! id commits to the full content — including the per-synthesis nonce and the
//! validity window — it changes on every synthesis and every revision. The
//! *stable* identity of a workload across executions is `(tenant, workload)`
//! (the [`ExecutionPlan::tenant`] + [`ExecutionPlan::workload`] fields);
//! `plan_id` addresses one concrete run of it.
//!
//! The id commits to every load-bearing field of the plan *except* the id
//! itself — so a run is addressable and hash-linkable by digest, and two plans
//! with identical content share an id. The per-synthesis nonce is part of that
//! content, so each synthesis still yields a distinct id even for the same
//! workload shape.
//!
//! Two things are outside the digest input by construction:
//! - `plan_id` — the value being derived; including it would be circular.
//! - the Ed25519 signature — it lives in the signed envelope, not in the plan
//!   body, so it is already outside the digested bytes. The signature covers
//!   the whole plan (including the derived id), so the ordering is: derive id,
//!   set it, then sign.
//!
//! The derivation serializes the plan, drops the `plan_id` key, and hashes the
//! remainder. Serializing through [`serde_json::Value`] (whose object keys sort
//! deterministically) means every current and future load-bearing field is
//! covered automatically — a field cannot silently fall outside the address the
//! way a hand-maintained field list could drift. This is host-only,
//! single-implementation hashing with no cross-language conformance need — the
//! same posture the checkpoint content-address and the audit envelope take.

use sha2::{Digest, Sha256};

use crate::digest_shape::SHA256_PREFIX;
use crate::plan::{ExecutionPlan, PlanId};

/// The JSON key `plan_id` serializes under; dropped from the digest input so
/// the address commits to content only, never to its own output.
const PLAN_ID_FIELD: &str = "plan_id";

/// Derive `plan`'s content-address: `sha256:<hex>` over every load-bearing
/// field except `plan_id`. Pure and deterministic — the id a synthesized plan
/// carries is exactly this value, and a verifier recomputes it the same way.
pub fn compute_plan_id(plan: &ExecutionPlan) -> PlanId {
    let mut value = serde_json::to_value(plan).expect("ExecutionPlan is always JSON-serializable");
    value
        .as_object_mut()
        .expect("ExecutionPlan serializes as a JSON object")
        .remove(PLAN_ID_FIELD);
    let bytes = serde_json::to_vec(&value).expect("a serde_json::Value re-serializes");
    PlanId(format!(
        "{SHA256_PREFIX}{}",
        hex::encode(Sha256::digest(&bytes))
    ))
}

/// Fail-closed content-address check: the plan's stored `plan_id` must equal
/// the address recomputed from its load-bearing content. A mismatch means the
/// id is not a genuine content-address of this body — reject rather than trust
/// an unverifiable id.
pub fn verify_plan_id(plan: &ExecutionPlan) -> Result<(), PlanIdMismatch> {
    let recomputed = compute_plan_id(plan);
    if recomputed == plan.plan_id {
        Ok(())
    } else {
        Err(PlanIdMismatch {
            stored: plan.plan_id.0.clone(),
            recomputed: recomputed.0,
        })
    }
}

/// [`verify_plan_id`] failure: the stored id is not the content-address of the
/// plan body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "plan_id is not a content-address of the plan body: stored {stored}, recomputed {recomputed}"
)]
pub struct PlanIdMismatch {
    pub stored: String,
    pub recomputed: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest_shape::{Sha256PrefixedShape, validate_sha256_prefixed};
    use crate::plan::test_support::PlanFixture;

    fn plan() -> ExecutionPlan {
        PlanFixture::new().build()
    }

    #[test]
    fn compute_is_deterministic() {
        let p = plan();
        assert_eq!(compute_plan_id(&p), compute_plan_id(&p));
    }

    #[test]
    fn id_has_sha256_prefixed_shape() {
        // Reuse the one shared shape validator so this id can never drift from
        // the checkpoint/OCI/semantic-address content-address wire shape.
        let id = compute_plan_id(&plan());
        assert!(matches!(
            validate_sha256_prefixed(&id.0),
            Sha256PrefixedShape::Ok
        ));
        assert_eq!(id.0.len(), SHA256_PREFIX.len() + 64);
    }

    #[test]
    fn identical_content_yields_identical_id() {
        // Two independently-built plans with identical load-bearing content
        // (same nonce, same window) address to the same id.
        let from = chrono::Utc::now();
        let until = from + chrono::Duration::minutes(10);
        let a = PlanFixture::new()
            .nonce([4u8; 16])
            .validity(from, until)
            .build();
        let b = PlanFixture::new()
            .nonce([4u8; 16])
            .validity(from, until)
            .build();
        assert_eq!(compute_plan_id(&a), compute_plan_id(&b));
    }

    #[test]
    fn excludes_plan_id_field_no_circularity() {
        // Altering the id the derivation is over must not move the address —
        // otherwise the id would depend on its own value.
        let mut p = plan();
        let base = compute_plan_id(&p);
        p.plan_id = PlanId("something-entirely-different".to_string());
        assert_eq!(base, compute_plan_id(&p));
        p.plan_id = PlanId(base.0.clone());
        assert_eq!(base, compute_plan_id(&p));
    }

    #[test]
    fn changing_any_load_bearing_field_changes_id() {
        let base_plan = plan();
        let base = compute_plan_id(&base_plan);

        let mut p = base_plan.clone();
        p.tenant.0 = "other-tenant".to_string();
        assert_ne!(base, compute_plan_id(&p), "tenant");

        let mut p = base_plan.clone();
        p.workload.0 = "other-workload".to_string();
        assert_ne!(base, compute_plan_id(&p), "workload");

        let mut p = base_plan.clone();
        p.resources.cpus += 1;
        assert_ne!(base, compute_plan_id(&p), "resources.cpus");

        let mut p = base_plan.clone();
        p.image.sha256 = "b".repeat(64);
        assert_ne!(base, compute_plan_id(&p), "image.sha256");

        let mut p = base_plan.clone();
        p.nonce = crate::plan::Nonce::from_bytes([0xcd; 16]);
        assert_ne!(base, compute_plan_id(&p), "nonce");

        let mut p = base_plan.clone();
        p.valid_until += chrono::Duration::seconds(1);
        assert_ne!(base, compute_plan_id(&p), "valid_until");

        let mut p = base_plan;
        p.plan_version += 1;
        assert_ne!(base, compute_plan_id(&p), "plan_version");
    }

    #[test]
    fn verify_accepts_a_content_addressed_plan() {
        let mut p = plan();
        p.plan_id = compute_plan_id(&p);
        assert_eq!(verify_plan_id(&p), Ok(()));
    }

    #[test]
    fn verify_rejects_an_id_that_is_not_the_content_address() {
        let mut p = plan();
        p.plan_id = compute_plan_id(&p);
        let good = p.plan_id.0.clone();
        p.plan_id = PlanId("sha256:not-the-real-address".to_string());
        let err = verify_plan_id(&p).unwrap_err();
        assert_eq!(err.stored, "sha256:not-the-real-address");
        assert_eq!(err.recomputed, good);
    }

    #[test]
    fn verify_rejects_after_a_load_bearing_field_is_mutated() {
        // A tamper that keeps the old id but edits content: the recomputed
        // address no longer matches, so the check fails closed.
        let mut p = plan();
        p.plan_id = compute_plan_id(&p);
        p.resources.mem_mib += 1;
        assert!(verify_plan_id(&p).is_err());
    }
}
