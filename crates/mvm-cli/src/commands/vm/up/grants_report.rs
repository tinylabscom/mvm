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
//! Everything here runs after the VM is up, so nothing here can refuse a boot.
//! A failure to read, record, or log degrades to a warning: refusing after the
//! fact prevents nothing, and killing a running workload because a display
//! record could not be written trades a missing line for a dead job.

use mvm_contract::grants::Grants;
use mvm_contract::protocol::resource_controls::EnforcedGrants;

use super::admission::AdmissionContext;

/// Read back what bounded `vm_name`, persist it where `machine inspect` can
/// find it, put it on the chain-signed log, and tell the operator when a bound
/// that was asked for did not happen.
///
/// The requested grants come from the signed plan the boot was admitted under,
/// never from the caller's arguments: what a run was authorized to consume is
/// settled at admission, and re-deriving it here would let the report describe
/// a different request than the one that was signed.
pub(super) fn report_enforced_grants(
    ctx: &Option<AdmissionContext>,
    backend_name: &str,
    vm_name: &str,
) -> EnforcedGrants {
    let undeclared = Grants::default();
    let requested = ctx
        .as_ref()
        .and_then(|ctx| ctx.admitted.plan().grants.as_ref())
        .unwrap_or(&undeclared);

    let enforced = read_back_tier(backend_name, vm_name, requested);

    mvm_client::record_enforced_grants(vm_name, &enforced);

    if let Some(ctx) = ctx
        && let Err(e) = ctx
            .emitter
            .emit_grants_enforced(ctx.admitted.plan(), &enforced)
    {
        tracing::warn!(error = %e, "audit emit_grants_enforced failed (non-fatal)");
    }

    if let Some(reason) = degradation_warning(requested, &enforced) {
        crate::ui::warn(&reason);
    }

    enforced
}

/// Ask the backend what bounded this VM.
///
/// A read-back failure answers "nothing is known to bound it" rather than
/// propagating: the VM is already running, and understating an unmeasured
/// dimension is the only answer that can never be wrong in the dangerous
/// direction.
fn read_back_tier(backend_name: &str, vm_name: &str, requested: &Grants) -> EnforcedGrants {
    match mvm_client::enforced_grants_after_start(backend_name, vm_name, requested) {
        Ok(enforced) => enforced,
        Err(e) => {
            tracing::warn!(
                error = %e,
                vm = vm_name,
                "reading back the enforced grants failed (non-fatal)"
            );
            EnforcedGrants::all_declared()
        }
    }
}

/// The operator-visible sentence for a boot that asked for a bound and did not
/// get one, or `None` when there is nothing to report.
///
/// Split from the reporting so the silence case is testable without a boot: the
/// defect was a run that degraded correctly and said nothing, and a test that
/// can only observe the warning by starting a VM is how that shipped.
fn degradation_warning(requested: &Grants, enforced: &EnforcedGrants) -> Option<String> {
    mvm_core::cpu_scope::cpu_degradation_reason(
        requested.cpu.as_ref(),
        enforced.cpu,
        mvm_core::cpu_scope::mechanism_gap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::CpuGrant;
    use mvm_contract::protocol::resource_controls::EnforcedTier;
    use mvm_hostd::plan_admission::InMemoryNonceLedger;

    use crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint;
    use crate::commands::vm::up::{AdmitPlanForBootParams, admit_plan_for_boot};

    /// Admit a real plan carrying `grants` and return its context plus the
    /// audit dir the chain was written to. The signer, chain and plan are the
    /// production ones — the only thing injected is where they live.
    fn admitted_with_grants(
        vm_name: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> (
        Option<AdmissionContext>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let rootfs_dir = tempfile::tempdir().expect("rootfs dir");
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs bytes").expect("write rootfs");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name,
            backend_name: "libkrun",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
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
        let grants = mvm_contract::grants::Grants {
            wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(30).expect("nonzero"),
            }),
            ..Default::default()
        };
        let (ctx, _keys, audit_dir) = admitted_with_grants("vm-grants-enforced", Some(grants));
        assert!(ctx.is_some(), "the fixture must actually admit");

        let enforced = report_enforced_grants(&ctx, "libkrun", "vm-grants-enforced");

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
            mvm_client::enforced_grants_of("vm-grants-enforced"),
            Some(enforced),
            "the recorded tier is what inspect will show"
        );
    }

    /// A run that was never admitted still has to record a tier: `machine
    /// inspect` on a `--no-supervisor` boot would otherwise show the request
    /// with nothing beside it.
    #[test]
    fn an_unadmitted_boot_still_records_a_tier() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        let enforced = report_enforced_grants(&None, "firecracker", "vm-no-admission");
        assert_eq!(
            mvm_client::enforced_grants_of("vm-no-admission"),
            Some(enforced)
        );
    }

    /// The second half of the live finding: with the mechanism missing the boot
    /// degrades, which is deliberate — and said nothing, which is not. Every
    /// host reaches a warning here, because a host with no gap still has an
    /// unenforced tier to explain.
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
