//! The plan a restored child's supervisor accepts as its authority.
//!
//! The restoring host spent the plan's nonce at admission, so this only
//! verifies: signature under the host key, plan id, validity window, and that
//! the plan names this child. It never consults a nonce ledger, which would
//! refuse the restore as a replay, and it never creates a key: a missing host
//! key refuses the restore.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::plan::{
    ExecutionPlan, ImageBinding, RestoredChildBinding, SignedExecutionPlan,
    verify_restored_child_plan,
};

use crate::audit::host_keypair::{PUBLIC_FILENAME, SECRET_FILENAME};

/// Verify the plan a restore config carries, under the host signer whose key
/// lives beside `signing_key_path`. Loads the key verify-only.
pub fn verify_restored_plan(
    plan: &serde_json::Value,
    vm_name: &str,
    signing_key_path: Option<&Path>,
) -> Result<ExecutionPlan> {
    let keys_dir = signing_key_path
        .and_then(Path::parent)
        .context("a restored child's plan needs the host signing key location")?;
    let (_, trusted) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys_dir.join(SECRET_FILENAME),
        &keys_dir.join(PUBLIC_FILENAME),
    )
    .context("loading the existing host signer to verify the restored child's plan")?;
    let signed: SignedExecutionPlan = serde_json::from_value(plan.clone())
        .context("a restored child's plan must be a signed plan")?;
    verify_restored_child_plan(
        &signed,
        &trusted,
        &RestoredChildBinding {
            vm_name,
            image: ImageBinding::NotChecked,
            now: chrono::Utc::now(),
        },
    )
}

/// The only plan a supervisor may arm bounds or capture from. A restore's
/// plan is verified here, before any timer or audit emitter exists, and the
/// caller arms from the returned value rather than from the raw config.
pub fn plan_to_arm(
    cfg_plan: Option<&serde_json::Value>,
    restoring: bool,
    vm_name: &str,
    signing_key_path: Option<&Path>,
) -> Result<Option<serde_json::Value>> {
    match (cfg_plan, restoring) {
        (Some(plan), true) => {
            let verified = verify_restored_plan(plan, vm_name, signing_key_path)?;
            Ok(Some(serde_json::to_value(verified)?))
        }
        (plan, _) => Ok(plan.cloned()),
    }
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

    #[test]
    fn a_missing_host_key_refuses_and_mints_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let json = signed_json("child", other.path());
        let key = dir.path().join("host-signer.ed25519");
        assert!(verify_restored_plan(&json, "child", Some(&key)).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn an_unverifiable_plan_arms_nothing_and_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let key = dir.path().join("host-signer.ed25519");
        let json = signed_json("other", dir.path());
        assert!(plan_to_arm(Some(&json), true, "child", Some(&key)).is_err());
        assert_eq!(std::fs::read_dir(audit.path()).unwrap().count(), 0);
        // A cold boot's plan passes through untouched.
        assert_eq!(
            plan_to_arm(Some(&json), false, "child", Some(&key)).unwrap(),
            Some(json)
        );
    }

    /// The deadline runs from the moment the restored supervisor arms, not
    /// from the plan's earlier validity start, and the kill is audited under
    /// the child's plan.
    #[test]
    fn a_restored_childs_wall_clock_runs_from_restore_and_audits_the_child() {
        use crate::supervisor::wall_clock::{
            SupervisorTimerInputs, WorkloadKiller, arm_for_supervisor,
        };
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct Counting(Arc<AtomicUsize>);
        impl WorkloadKiller for Counting {
            fn kill(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let key = dir.path().join("host-signer.ed25519");
        let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        let now = chrono::Utc::now();
        let mut plan = PlanFixture::new()
            .workload("child")
            .validity(
                now - chrono::Duration::minutes(9),
                now + chrono::Duration::minutes(5),
            )
            .build();
        plan.resources.timeouts.exec_secs = 1;
        let signed = sign_plan(&plan, &signer.signing, "host:t");
        let child_plan_id =
            serde_json::from_slice::<mvm_core::plan::ExecutionPlan>(&signed.0.payload)
                .unwrap()
                .plan_id
                .0;
        let json = serde_json::to_value(signed).unwrap();

        let armed = plan_to_arm(Some(&json), true, "child", Some(&key))
            .unwrap()
            .unwrap();
        let kills = Arc::new(AtomicUsize::new(0));
        let pid = state.path().join("hvf.pid");
        let inputs = SupervisorTimerInputs {
            plan_json: Some(&armed),
            audit_dir: Some(audit.path()),
            signing_key_path: Some(&key),
            vm_state_dir: state.path(),
            pid_file: &pid,
        };
        let _guard = arm_for_supervisor(inputs, Box::new(Counting(kills.clone()))).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(kills.load(Ordering::SeqCst), 0, "not born expired");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert_eq!(kills.load(Ordering::SeqCst), 1);
        let chain = std::fs::read_dir(audit.path())
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect::<String>();
        assert!(
            chain.contains(&child_plan_id),
            "kill audited under the child: {chain}"
        );
    }
}
