//! Deliberate prefix pruning with protected-capture evidence admission.
use super::ui;
use anyhow::Result;
use mvm_client::audit::{AuditPruneMode, AuditPruneOutcome, prune_audit};

/// Dry-run unless acknowledged. The signer rechecks pins inside its commit lock.
pub(super) fn audit_prune(tenant: &str, through: u64, ack: bool) -> Result<()> {
    let mode = if ack {
        AuditPruneMode::Commit
    } else {
        AuditPruneMode::Preview
    };
    match prune_audit(tenant, through, mode)? {
        AuditPruneOutcome::NothingToPrune { floor, through } => ui::info(&format!(
            "Nothing to prune for tenant '{tenant}': no retired segments in {floor}..={through}."
        )),
        AuditPruneOutcome::WouldPrune {
            floor,
            through,
            segments,
            entries,
        } => ui::warn(&format!(
            "Would remove {} segment(s) ({}..={}) and {entries} entries from tenant \
             '{tenant}'.\nThose entries stop being independently verifiable — the surviving \
             chain will attest that they were removed, and how many, but never again what \
             they said.\nRe-run with --ack to proceed.",
            segments, floor, through
        )),
        AuditPruneOutcome::Pruned { through, entries } => ui::success(&format!(
            "Pruned segments 1..={through} from tenant '{tenant}': {entries} entries removed and recorded in \
             the chain. `mvmctl trust audit verify` will now report the chain as verified with a \
             deliberate gap."
        )),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_hostd::audit::host_keypair as host_signer;
    use mvm_hostd::supervisor::audit::{AuditSigner, for_plan};
    use mvm_hostd::supervisor::audit_file::{FileAuditSigner, RotationPolicy};

    #[test]
    fn invalid_tenant_refuses_before_keys_or_chain_discovery() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        for tenant in ["", "/", "../outside", "/outside", "a/b", "./local"] {
            for ack in [false, true] {
                let error = audit_prune(tenant, 1, ack).unwrap_err().to_string();
                assert_eq!(error, "invalid prune tenant component");
            }
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn missing_prune_authority_does_not_initialize_keys() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        for ack in [false, true] {
            assert!(
                audit_prune("local", 1, ack)
                    .unwrap_err()
                    .to_string()
                    .contains("authority")
            );
        }
        assert!(!root.path().join("keys").exists());
        assert!(!root.path().join("audit").exists());
    }

    #[test]
    fn dry_run_explains_pins_and_ack_refuses_without_audit_mutation() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        let signer = host_signer::load_or_init().unwrap();
        let audit = root.path().join("audit");
        let signer = FileAuditSigner::open(signer.signing, &audit)
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(1));
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .build();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            signer
                .sign_and_emit(&for_plan(
                    &plan,
                    None,
                    "transcript.opened",
                    [("capture_id".into(), "synthetic-opaque-id".into())],
                ))
                .await
                .unwrap();
            signer
                .sign_and_emit(&for_plan(&plan, None, "plan.exited", std::iter::empty()))
                .await
                .unwrap();
        });
        let segment = audit.join("local.seg-000001.jsonl");
        let active = audit.join("local.jsonl");
        let before = (
            std::fs::read(&segment).unwrap(),
            std::fs::read(&active).unwrap(),
        );
        for ack in [false, true] {
            let error = format!("{:#}", audit_prune("local", 1, ack).unwrap_err());
            assert!(error.contains("pins segment 1"));
            assert!(!error.contains("synthetic-opaque-id"));
            assert!(!error.contains(&root.path().to_string_lossy().to_string()));
            assert_eq!(std::fs::read(&segment).unwrap(), before.0);
            assert_eq!(std::fs::read(&active).unwrap(), before.1);
        }
    }
}
