//! Deliberate prefix pruning with protected-capture evidence admission.
use super::{default_audit_dir, host_signer, ui};
use anyhow::{Context, Result};

/// Dry-run unless acknowledged. The signer rechecks pins inside its commit lock.
pub(super) fn audit_prune(tenant: &str, through: u64, ack: bool) -> Result<()> {
    let dir = default_audit_dir()?;
    let keys = host_signer::default_keys_dir()?;
    let (signing, verifying) = mvm_core::crypto::ed25519_keypair::load_existing(
        &keys.join(host_signer::SECRET_FILENAME),
        &keys.join(host_signer::PUBLIC_FILENAME),
    )
    .map_err(|_| anyhow::anyhow!("existing audit authority is unavailable; refusing prune"))?;
    let verified = mvm_hostd::supervisor::verify_segment_set(&dir, tenant, &verifying)
        .map_err(|_| anyhow::anyhow!("refusing to prune: the audit chain does not verify"))?;
    let floor = verified.pruned.map_or(1, |p| p.through + 1);
    let doomed: Vec<_> = verified
        .segments
        .iter()
        .filter(|s| !s.active && s.seq >= floor && s.seq <= through)
        .collect();
    if doomed.is_empty() {
        ui::info(&format!(
            "Nothing to prune for tenant '{tenant}': no retired segments in {floor}..={through}."
        ));
        return Ok(());
    }
    let entries: usize = doomed.iter().filter_map(|s| s.entries).sum();
    let file_signer = mvm_hostd::supervisor::FileAuditSigner::open(signing, &dir)
        .context("opening the audit signer to assess the prune")?;
    if !ack {
        file_signer
            .check_prune_pins(&mvm_core::plan::TenantId(tenant.to_string()), through)
            .context("dry-run blocked; no audit or payload evidence removed")?;
        ui::warn(&format!(
            "Would remove {} segment(s) ({}..={}) and {entries} entries from tenant \
             '{tenant}'.\nThose entries stop being independently verifiable — the surviving \
             chain will attest that they were removed, and how many, but never again what \
             they said.\nRe-run with --ack to proceed.",
            doomed.len(),
            floor,
            through
        ));
        return Ok(());
    }
    let pruned = file_signer
        .prune_through(&mvm_core::plan::TenantId(tenant.to_string()), through)
        .context("pruning audit segments")?;
    ui::success(&format!(
        "Pruned segments 1..={} from tenant '{tenant}': {} entries removed and recorded in \
         the chain. `mvmctl trust audit verify` will now report the chain as verified with a \
         deliberate gap.",
        pruned.through, pruned.entries
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_hostd::supervisor::audit::{AuditSigner, for_plan};
    use mvm_hostd::supervisor::audit_file::{FileAuditSigner, RotationPolicy};

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
