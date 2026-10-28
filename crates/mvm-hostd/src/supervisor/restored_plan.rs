//! The plan a restored child's supervisor accepts as its authority.
//!
//! The restoring host spent the plan's nonce at admission, so this only
//! verifies: signature under the host key, plan id, validity window, and that
//! the plan names this child. It never consults a nonce ledger, which would
//! refuse the restore as a replay.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::plan::{
    ExecutionPlan, RestoredChildBinding, SignedExecutionPlan, verify_restored_child_plan,
};

/// Verify the plan a restore config carries, under the host signer whose key
/// lives beside `signing_key_path`.
pub fn verify_restored_plan(
    plan: &serde_json::Value,
    vm_name: &str,
    signing_key_path: Option<&Path>,
) -> Result<ExecutionPlan> {
    let keys_dir = signing_key_path
        .and_then(Path::parent)
        .context("a restored child's plan needs the host signing key location")?;
    let trusted = crate::audit::host_keypair::load_or_init_at(keys_dir)
        .context("loading the host signer to verify the restored child's plan")?
        .verifying_key();
    let signed: SignedExecutionPlan = serde_json::from_value(plan.clone())
        .context("a restored child's plan must be a signed plan")?;
    verify_restored_child_plan(
        &signed,
        &trusted,
        &RestoredChildBinding {
            vm_name,
            image_sha256: None,
            now: chrono::Utc::now(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{sign_plan, test_support::PlanFixture};

    fn signed_json(workload: &str, dir: &Path) -> serde_json::Value {
        let signer = crate::audit::host_keypair::load_or_init_at(dir).unwrap();
        let plan = PlanFixture::new().workload(workload).build();
        serde_json::to_value(sign_plan(&plan, &signer.signing, "host:t")).unwrap()
    }

    #[test]
    fn the_child_plan_signed_by_the_host_is_accepted_without_a_nonce_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("host-signer.ed25519");
        let json = signed_json("child", dir.path());
        // Verified twice: a nonce spend would refuse the second as a replay.
        for _ in 0..2 {
            assert!(verify_restored_plan(&json, "child", Some(&key)).is_ok());
        }
    }

    #[test]
    fn a_validly_signed_plan_for_another_workload_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("host-signer.ed25519");
        let json = signed_json("other", dir.path());
        assert!(verify_restored_plan(&json, "child", Some(&key)).is_err());
    }

    #[test]
    fn a_plan_signed_by_another_key_is_refused() {
        let signing_dir = tempfile::tempdir().unwrap();
        let trust_dir = tempfile::tempdir().unwrap();
        let json = signed_json("child", signing_dir.path());
        let key = trust_dir.path().join("host-signer.ed25519");
        assert!(verify_restored_plan(&json, "child", Some(&key)).is_err());
    }
}
