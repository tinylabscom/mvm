//! What actually bounded a boot, reported on the path `mvmctl` takes.
//!
//! The backend read-back and the chain-signed entry both existed before this
//! module; what did not exist was a call to either from the CLI's own start
//! path. A bounded boot therefore emitted `plan.admitted` and `plan.launched`
//! and never said what bounded it, and `machine inspect` showed the request —
//! which is precisely the confusion the read-back exists to prevent, since a
//! request and an enforcement are indistinguishable in a spec file and only one
//! of them is a security property.
//!
//! This runs after the VM is up, and it is the one post-start step that can
//! still refuse the boot. If the backend cannot apply the admitted grants, the
//! VM is running without the bounds it was admitted under; it is stopped, the
//! chain records `plan.failed`, and no `plan.grants_enforced` entry is written.
//! Recording an all-`Declared` tier in its place would sign a statement about
//! enforcement that no backend made.
//!
//! What stays non-fatal is everything after a successful application: a
//! per-VM record or a log line that could not be written leaves a missing line,
//! not a wrong one, and killing a bounded workload over it trades that line for
//! a dead job.

use mvm_contract::grants::Grants;
use mvm_contract::protocol::resource_controls::EnforcedGrants;

use crate::StartedVm;
use crate::admission::AdmissionContext;

/// Apply the admitted grants to the VM `started` holds, persist what bounded it
/// where `machine inspect` can find it, put it on the chain-signed log, and
/// tell the operator when a bound that was asked for did not happen.
///
/// The requested grants come from the signed plan the boot was admitted under,
/// never from the caller's arguments: what a run was authorized to consume is
/// settled at admission, and re-deriving it here would let the report describe
/// a different request than the one that was signed.
///
/// # Errors
///
/// Fails when the backend cannot apply the grants. The VM has been stopped and
/// `plan.failed` recorded by the time this returns.
pub fn report_enforced_grants(
    ctx: &AdmissionContext,
    started: &StartedVm,
) -> anyhow::Result<EnforcedGrants> {
    let undeclared = Grants::default();
    let requested = ctx.admitted.plan().grants.as_ref().unwrap_or(&undeclared);

    let enforced = mvm_hostd::plan_admission::apply_admitted_grants_or_undo_launch(
        started.backend(),
        started.vm_id(),
        &ctx.admitted,
        Some(&ctx.emitter),
    )?;

    crate::record_enforced_grants(&started.vm_id().0, &enforced);

    if let Err(e) = ctx
        .emitter
        .emit_grants_enforced(ctx.admitted.plan(), &enforced)
    {
        tracing::warn!(error = %e, "audit emit_grants_enforced failed (non-fatal)");
    }

    if let Some(reason) = degradation_warning(requested, &enforced) {
        mvm_runtime::ui::warn(&reason);
    }

    Ok(enforced)
}

/// The operator-visible sentence for a boot that asked for a bound and did not
/// get one, or `None` when there is nothing to report.
///
/// Split from the reporting so the silence case is testable without a boot: the
/// defect was a run that degraded correctly and said nothing, and a test that
/// can only observe the warning by starting a VM is how that shipped.
fn degradation_warning(requested: &Grants, enforced: &EnforcedGrants) -> Option<String> {
    mvm_core::spawn_scope::cpu_degradation_reason(
        requested.cpu.as_ref(),
        enforced.cpu,
        mvm_core::spawn_scope::mechanism_gap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::CpuGrant;
    use mvm_contract::protocol::resource_controls::EnforcedTier;
    use mvm_hostd::plan_admission::InMemoryNonceLedger;

    use crate::admission::entrypoint_resolve::ResolvedEntrypoint;
    use crate::admission::{AdmitPlanForBootParams, admit_plan_for_boot};

    /// Admit a real plan carrying `grants` and return its context plus the
    /// audit dir the chain was written to. The signer, chain and plan are the
    /// production ones — the only thing injected is where they live.
    fn admitted_with_grants(
        vm_name: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> (AdmissionContext, tempfile::TempDir, tempfile::TempDir) {
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let rootfs_dir = tempfile::tempdir().expect("rootfs dir");
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs bytes").expect("write rootfs");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            outputs: Vec::new(),
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name,
            backend_name: "libkrun",
            configured_images_dir: None,
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
            grants,
            // The gate measures a declared bound against a real tier's
            // mechanisms; admitting without one refuses rather than guessing.
            backend_kind: Some(mvm_core::protocol::vm_backend::BackendKind::Libkrun),
            entrypoint: ResolvedEntrypoint::unresolved("this test resolves no entrypoint"),
        })
        .expect("admission succeeds");
        (ctx, keys_dir, audit_dir)
    }

    /// The defect: a boot on the CLI's own path emitted `plan.admitted` and
    /// `plan.launched` and never said what bounded it. Asserted against the
    /// reporter the CLI start path calls, not against `admit_and_boot_local`,
    /// which no `mvmctl` invocation reaches.
    #[test]
    fn a_bounded_cli_boot_emits_grants_enforced() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        // A libkrun wall-clock bound rather than a CPU share: its supervisor
        // timer exists on every supported host, while cgroup shares are
        // Linux-only. The fixture therefore exercises a genuinely enforceable
        // grant on both Linux and macOS.
        let (ctx, _keys, audit_dir) =
            admitted_with_grants("vm-grants-enforced", Some(wall_clock_grant()));

        // Read back through the libkrun runner itself, not a double: this is the
        // backend the plan was admitted for, and its `apply_grants` reads the
        // record its supervisor writes, answering `Declared` when there is none.
        let started = StartedVm::from_started(
            mvm_runtime::backend::AnyBackend::from_hypervisor("libkrun"),
            mvm_core::protocol::vm_backend::VmId("vm-grants-enforced".into()),
        );
        let enforced = report_enforced_grants(&ctx, &started).expect("grants applied");

        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("the chain file exists");
        assert!(
            chain.contains("plan.grants_enforced"),
            "a boot on the CLI path must record what bounded it: {chain}"
        );
        assert!(
            chain.contains(enforced.wall_clock.label()),
            "the entry must carry the tier that was read back ({}): {chain}",
            enforced.wall_clock.label()
        );

        // The same tier must survive to `machine inspect`, which reads it from
        // the per-VM record rather than from this process.
        assert_eq!(
            crate::enforced_grants_of("vm-grants-enforced"),
            Some(enforced),
            "the recorded tier is what inspect will show"
        );
    }

    /// A mock VM actually started on `mock`, so a stop is observable.
    #[cfg(feature = "test-support")]
    fn started_on_mock(mock: &mvm_runtime::MockBackend, vm_name: &str) -> StartedVm {
        use mvm_core::vm_backend::VmBackend as _;
        let vm_id = mock
            .start(&mvm_core::vm_backend::VmStartConfig {
                name: vm_name.into(),
                ..Default::default()
            })
            .expect("mock start");
        StartedVm::from_started(mvm_runtime::backend::AnyBackend::Mock(mock.clone()), vm_id)
    }

    fn wall_clock_grant() -> Grants {
        mvm_contract::grants::Grants {
            wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(30).expect("nonzero"),
            }),
            ..Default::default()
        }
    }

    /// The defect this guards: a backend that failed to apply the grants was
    /// answered with an all-`Declared` tier, which was then signed into
    /// `plan.grants_enforced` for a VM left running unbounded. The boot must
    /// refuse instead — VM stopped, `plan.failed` at the `grants` stage, and no
    /// enforcement entry or per-VM record.
    #[cfg(feature = "test-support")]
    #[test]
    fn a_grant_that_fails_to_apply_refuses_the_cli_boot() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        let vm = "vm-grants-apply-fails";
        let (ctx, _keys, audit_dir) = admitted_with_grants(vm, Some(wall_clock_grant()));
        let mock = mvm_runtime::MockBackend::new().with_failing_apply_grants();
        let started = started_on_mock(&mock, vm);

        let err = report_enforced_grants(&ctx, &started)
            .expect_err("a boot whose grants could not be applied must not proceed");

        assert!(
            format!("{err:#}").contains("applying the admitted plan's grants"),
            "{err:#}"
        );
        assert_eq!(
            mock.count(),
            0,
            "the VM that could not be bounded is stopped"
        );
        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("the chain file exists");
        assert!(
            chain.contains("plan.failed") && chain.contains("\"grants\""),
            "the refusal is on the chain, naming the grants stage: {chain}"
        );
        assert!(
            !chain.contains("plan.grants_enforced"),
            "no enforcement may be recorded for grants that were never applied: {chain}"
        );
        assert_eq!(
            crate::enforced_grants_of(vm),
            None,
            "inspect must not show a tier for a boot that was refused"
        );
    }

    /// The other side of the line: a backend that applies the grants and
    /// reports `Declared` because the host has no mechanism answered
    /// successfully. That boot proceeds, and `declared` is what gets recorded.
    #[cfg(feature = "test-support")]
    #[test]
    fn a_host_without_a_mechanism_boots_and_records_declared() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        let vm = "vm-grants-declared";
        let (ctx, _keys, audit_dir) = admitted_with_grants(vm, Some(wall_clock_grant()));
        let mock = mvm_runtime::MockBackend::new();
        let started = started_on_mock(&mock, vm);

        let enforced = report_enforced_grants(&ctx, &started).expect("the boot proceeds");

        assert_eq!(enforced, EnforcedGrants::all_declared());
        assert_eq!(mock.count(), 1, "the VM keeps running");
        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("the chain file exists");
        assert!(chain.contains("plan.grants_enforced"), "{chain}");
        assert!(!chain.contains("plan.failed"), "{chain}");
        assert_eq!(crate::enforced_grants_of(vm), Some(enforced));
    }

    #[test]
    fn a_degraded_boot_warns() {
        let requested = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        let reason = degradation_warning(&requested, &EnforcedGrants::all_declared())
            .expect("an unenforced share must produce an operator warning");
        assert!(reason.contains("1500"), "{reason}");
        assert!(reason.contains("NOT enforced"), "{reason}");
    }

    #[test]
    fn a_bounded_run_does_not_warn() {
        let requested = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        assert_eq!(
            degradation_warning(
                &requested,
                &EnforcedGrants {
                    cpu: EnforcedTier::Cgroup2CpuMax,
                    wall_clock: EnforcedTier::Declared,
                    ..EnforcedGrants::all_declared()
                }
            ),
            None
        );
    }

    #[test]
    fn a_run_that_asked_for_nothing_does_not_warn() {
        assert_eq!(
            degradation_warning(&Grants::default(), &EnforcedGrants::all_declared()),
            None
        );
    }
}
