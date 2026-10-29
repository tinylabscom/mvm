//! Verification of the plan a restored child runs under.
//!
//! A restore spends no nonce: host admission already spent the child plan's
//! once, so this check is stateless by construction (no ledger is taken) and
//! the supervisor can repeat it without turning the restore into a replay.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;

use super::{ExecutionPlan, SignedExecutionPlan, verify_plan, verify_plan_id};

/// Whether the caller holds a chain-verified digest of the restored rootfs.
#[derive(Clone, Copy)]
pub enum ImageBinding<'a> {
    /// The plan must pin exactly this digest.
    Pinned(&'a str),
    /// The caller has no verified digest; only identity and signature bind.
    NotChecked,
}

/// What the restored machine is, as the verifier must find the plan describing.
pub struct RestoredChildBinding<'a> {
    /// The fresh identity the child runs under; the plan's workload.
    pub vm_name: &'a str,
    pub image: ImageBinding<'a>,
    pub now: DateTime<Utc>,
}

/// Verify `signed` under `trusted` and bind it to the restored machine.
///
/// Refuses a bad signature, an inconsistent plan id, a plan for another
/// workload or image, and a plan outside its validity window.
pub fn verify_restored_child_plan(
    signed: &SignedExecutionPlan,
    trusted: &VerifyingKey,
    binding: &RestoredChildBinding<'_>,
) -> anyhow::Result<ExecutionPlan> {
    let signer = signed.0.signer_id.clone();
    let plan = verify_plan(signed, &[(signer.as_str(), trusted)])?;
    verify_plan_id(&plan)?;
    anyhow::ensure!(
        plan.workload.0 == binding.vm_name,
        "restored child plan names workload '{}', not '{}'",
        plan.workload.0,
        binding.vm_name
    );
    if let ImageBinding::Pinned(image) = binding.image {
        anyhow::ensure!(
            plan.image.sha256.eq_ignore_ascii_case(image),
            "restored child plan pins a different image than the one restored"
        );
    }
    anyhow::ensure!(
        plan.valid_from <= binding.now && binding.now < plan.valid_until,
        "restored child plan is outside its validity window"
    );
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::test_support::PlanFixture;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed(workload: &str, signer: &SigningKey) -> (SignedExecutionPlan, String) {
        let plan = PlanFixture::new().workload(workload).build();
        let image = plan.image.sha256.clone();
        (crate::plan::sign_plan(&plan, signer, "host:t"), image)
    }

    fn check(
        s: &SignedExecutionPlan,
        k: &SigningKey,
        vm: &str,
        image: Option<&str>,
    ) -> anyhow::Result<ExecutionPlan> {
        verify_restored_child_plan(
            s,
            &k.verifying_key(),
            &RestoredChildBinding {
                vm_name: vm,
                image: image.map_or(ImageBinding::NotChecked, ImageBinding::Pinned),
                now: Utc::now(),
            },
        )
    }

    #[test]
    fn a_plan_signed_for_this_child_verifies() {
        let k = key(1);
        let (s, image) = signed("child", &k);
        assert!(check(&s, &k, "child", Some(&image)).is_ok());
    }

    #[test]
    fn a_validly_signed_plan_for_another_workload_is_refused() {
        let k = key(1);
        let (s, _) = signed("someone-else", &k);
        let e = check(&s, &k, "child", None).unwrap_err();
        assert!(e.to_string().contains("names workload"));
    }

    #[test]
    fn a_validly_signed_plan_for_another_image_is_refused() {
        let k = key(1);
        let (s, _) = signed("child", &k);
        assert!(check(&s, &k, "child", Some(&"f".repeat(64))).is_err());
    }

    #[test]
    fn a_plan_from_an_untrusted_signer_or_tampered_payload_is_refused() {
        let (s, _) = signed("child", &key(1));
        assert!(check(&s, &key(2), "child", None).is_err());
        let mut forged = s.clone();
        forged.0.payload.push(b' ');
        assert!(check(&forged, &key(1), "child", None).is_err());
    }

    #[test]
    fn an_expired_plan_is_refused() {
        let k = key(1);
        let now = Utc::now();
        let plan = PlanFixture::new()
            .workload("child")
            .validity(
                now - chrono::Duration::minutes(10),
                now - chrono::Duration::minutes(5),
            )
            .build();
        let s = crate::plan::sign_plan(&plan, &k, "host:t");
        assert!(check(&s, &k, "child", None).is_err());
    }
}
