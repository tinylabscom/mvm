//! What a boot on the CLI's own path committed against the host budget,
//! recorded where every later admission's committed-total check can count it.
//!
//! The budget gate a boot is admitted under measures the host's committed
//! total from per-VM charge records. The gate and the record used to be
//! reachable only as a pair inside one launch path, while the path `mvmctl`
//! actually takes admitted against the total and never contributed to it —
//! so ten CLI-booted machines were invisible to the eleventh's admission.
//! This module is the record half on that path, with the same contract as
//! the grants step beside it: fatal, and the VM is stopped rather than left
//! running as a machine the host's accounting never saw.

use crate::StartedVm;
use crate::admission::AdmissionContext;

/// File the charge record under `vm_name` for the boot `started` holds, and
/// stop the VM when the record cannot be written.
///
/// Runs after the grants step and before the volume leases commit: a refusal
/// here rolls the launch back exactly like a grant application failure, and
/// the uncommitted leases release with it. The charge comes from the signed
/// plan the boot was admitted under, never from the caller's arguments — the
/// committed total must reflect what admission granted, not what a flag asks.
///
/// # Errors
///
/// Fails when the charge record cannot be written. The VM has been stopped
/// and `plan.failed` recorded by the time this returns.
pub fn record_boot_charge(
    ctx: &AdmissionContext,
    vm_name: &str,
    started: &StartedVm,
) -> anyhow::Result<()> {
    mvm_hostd::plan_admission::record_charge_or_undo_launch(
        started.backend(),
        started.vm_id(),
        vm_name,
        &ctx.admitted,
        Some(&ctx.emitter),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::budget::MachineCharge;
    use mvm_hostd::plan_admission::InMemoryNonceLedger;

    use crate::admission::entrypoint_resolve::ResolvedEntrypoint;
    use crate::admission::{AdmitPlanForBootParams, admit_plan_for_boot};

    /// Admit a real plan for `vm_name` and return its context. Mirrors the
    /// fixture in the grants reporter: the signer, chain and plan are the
    /// production ones, with only where they live injected.
    fn admitted(vm_name: &str) -> (AdmissionContext, tempfile::TempDir, tempfile::TempDir) {
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let rootfs_dir = tempfile::tempdir().expect("rootfs dir");
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs bytes").expect("write rootfs");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tools: Default::default(),
            instructions: Default::default(),
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
            grants: None,
            backend_kind: Some(mvm_core::protocol::vm_backend::BackendKind::Libkrun),
            entrypoint: ResolvedEntrypoint::unresolved("this test resolves no entrypoint"),
        })
        .expect("admission succeeds");
        (ctx, keys_dir, audit_dir)
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

    /// The defect this guards: the budget gate a CLI boot admitted against
    /// never saw that boot again, so the host's committed total stayed at
    /// zero no matter how many machines the CLI path started. A boot on the
    /// CLI path must leave the charge record the total is summed from.
    #[test]
    fn a_cli_boot_records_its_admitted_charge() {
        let home = tempfile::tempdir().expect("home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        let vm = "vm-budget-charge";
        let (ctx, _keys, _audit) = admitted(vm);
        // The success path never touches the backend — the record is a file
        // write — so a fabricated StartedVm answers without a boot. The
        // failure path, which must observe a stop, uses the mock in the test
        // below and is gated on test-support like its grants reporter twin.
        let started = StartedVm::from_started(
            mvm_runtime::backend::AnyBackend::from_hypervisor("libkrun"),
            mvm_core::protocol::vm_backend::VmId(vm.into()),
        );

        record_boot_charge(&ctx, vm, &started).expect("the charge records");

        let record =
            mvm_core::config::vm_state_dir_at(home.path(), vm).join("admitted-charge.json");
        let bytes = std::fs::read(&record).expect("the charge record is written");
        let charge: MachineCharge = serde_json::from_slice(&bytes).expect("record parses");
        assert_eq!(
            charge.memory_mib, 512,
            "the plan granted 512 MiB: {charge:?}"
        );
        assert_eq!(
            charge.cpu_millicores, 0,
            "the plan declared no CPU bound: {charge:?}"
        );
    }

    /// A charge that cannot be recorded refuses the boot on this path too:
    /// the VM stops, and the chain carries `plan.failed` at the host-budget
    /// stage — the same contract the shared tail has always had.
    #[cfg(feature = "test-support")]
    #[test]
    fn a_charge_that_fails_to_record_refuses_the_cli_boot() {
        let home = tempfile::tempdir().expect("home");
        // A regular file where the vms dir must be: the record's create_dir_all
        // then fails with NotADirectory.
        std::fs::write(home.path().join("vms"), b"not a directory").expect("blocker file");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        let vm = "vm-budget-blocked";
        let (ctx, _keys, audit_dir) = admitted(vm);
        let mock = mvm_runtime::MockBackend::new();
        let started = started_on_mock(&mock, vm);

        record_boot_charge(&ctx, vm, &started)
            .expect_err("a boot whose charge cannot be recorded must not proceed");

        assert_eq!(
            mock.count(),
            0,
            "the VM that could not be counted is stopped"
        );
        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("the chain file exists");
        assert!(
            chain.contains("plan.failed") && chain.contains("host-budget"),
            "the refusal is on the chain, naming the host-budget stage: {chain}"
        );
    }
}
