use super::*;
use crate::admission::entrypoint_resolve::ResolvedEntrypoint;
use crate::admission::{AdmissionContext, AdmitPlanForBootParams, admit_plan_for_boot};
use chrono::{DateTime, Utc};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use mvm_core::util::test_env::TestEnv;
use mvm_core::vm_backend::VmStartConfig;
use mvm_hostd::plan_admission::{
    InMemoryNonceLedger, populate_audit_substrate, stash_plan_and_mint_verb_grant,
};
use std::time::Duration;

/// Long enough to be unmistakable against clock granularity, short enough for
/// a unit test. A real cold build takes minutes; the property is the same.
const SLOW_PREPARATION: Duration = Duration::from_millis(1500);

struct Host {
    _env: TestEnv,
    dir: tempfile::TempDir,
    rootfs: std::path::PathBuf,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"boot-order rootfs").expect("rootfs");
        Self {
            _env: env,
            dir,
            rootfs,
        }
    }

    /// The real admission a launch performs: a freshly synthesized, signed
    /// plan carrying a restricted agent-verb set, so a grant is minted.
    fn admit(&self, ledger: &InMemoryNonceLedger) -> AdmissionContext {
        let keys = self.dir.path().join("keys");
        let audit = self.dir.path().join("audit");
        admit_plan_for_boot(AdmitPlanForBootParams {
            outputs: Vec::new(),
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-boot-order",
            backend_name: "firecracker",
            configured_images_dir: None,
            rootfs_path: &self.rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 256,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            ledger,
            keys_dir: Some(&keys),
            audit_dir: Some(&audit),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: Vec::new(),
            restrict_agent_verbs: true,
            services: Vec::new(),
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test resolves none"),
        })
        .expect("admission")
    }

    /// What the launch does next: thread the plan into the config and mint
    /// the grant the guest will check.
    fn mint(&self, config: &mut VmStartConfig, admission: &AdmissionContext) -> VerbGrantEnvelope {
        populate_audit_substrate(config, &admission.admitted, None).expect("substrate");
        stash_plan_and_mint_verb_grant(config)
            .expect("mint")
            .expect("a restricted plan carries a grant")
    }
}

fn config() -> VmStartConfig {
    VmStartConfig {
        name: "vm-boot-order".to_string(),
        ..VmStartConfig::default()
    }
}

fn slow_preparation(prepared_at: &mut Option<DateTime<Utc>>) -> Result<()> {
    std::thread::sleep(SLOW_PREPARATION);
    *prepared_at = Some(Utc::now());
    Ok(())
}

/// The acceptance property: however long preparation takes, the grant the
/// guest checks still has the plan's whole validity window left when
/// preparation ends.
#[test]
fn a_slow_preparation_cannot_spend_the_grant_window() {
    let host = Host::new();
    let ledger = InMemoryNonceLedger::new();
    let mut config = config();
    let mut prepared_at = None;

    let admission = admit_after_preparation(
        &mut config,
        |_| slow_preparation(&mut prepared_at),
        |_| Ok(host.admit(&ledger)),
    )
    .unwrap();
    let envelope = host.mint(&mut config, &admission);

    let plan = admission.admitted.plan();
    let window = plan.valid_until - plan.valid_from;
    let prepared_at = prepared_at.expect("preparation ran");
    assert!(
        plan.valid_from >= prepared_at,
        "the plan's window must open after preparation, not before it"
    );
    assert_eq!(envelope.grant.not_after, plan.valid_until);
    assert!(
        envelope.grant.not_after >= prepared_at + window,
        "a grant expiring at {} leaves less than the {window} window after a preparation that \
         ended at {prepared_at}",
        envelope.grant.not_after
    );
}

/// The control: the old order, admission first, loses exactly the time the
/// preparation took. This is the failure the ordering exists to prevent, and
/// what makes the test above able to fail.
#[test]
fn admitting_before_preparation_loses_the_preparation_time() {
    let host = Host::new();
    let ledger = InMemoryNonceLedger::new();
    let mut config = config();
    let admission = host.admit(&ledger);
    let mut prepared_at = None;
    slow_preparation(&mut prepared_at).unwrap();
    let envelope = host.mint(&mut config, &admission);

    let plan = admission.admitted.plan();
    let window = plan.valid_until - plan.valid_from;
    let lost = prepared_at.unwrap() + window - envelope.grant.not_after;
    assert!(
        lost >= chrono::Duration::from_std(SLOW_PREPARATION).unwrap(),
        "admitting first should have cost the preparation time, lost only {lost}"
    );
}

#[test]
fn a_failed_preparation_admits_nothing() {
    let mut config = config();
    let mut admitted = false;
    let err = admit_after_preparation(
        &mut config,
        |_| anyhow::bail!("overlay build failed"),
        |_| {
            admitted = true;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("overlay build failed"));
    assert!(!admitted, "no plan is signed for a boot that cannot happen");
}

#[test]
fn preparation_sees_and_admission_receives_the_prepared_config() {
    let mut config = config();
    let seen = admit_after_preparation(
        &mut config,
        |c| {
            c.initrd_path = Some("/cache/initramfs".to_string());
            Ok(())
        },
        |c| Ok(c.initrd_path.clone()),
    )
    .unwrap();
    assert_eq!(seen.as_deref(), Some("/cache/initramfs"));
}
