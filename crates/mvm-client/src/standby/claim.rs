//! Admitted warm-child claim facade.

use anyhow::{Context, Result};
use mvm_core::checkpoint::CheckpointId;
use mvm_core::vm_backend::StandbyHandle;
use mvm_runtime::AnyBackend;

use super::{OwnedWarmClaim, PlanlessWarmParentAnchor, SupervisorStandbyPool};
use crate::admission::{CliAdmission, CliStartFailureKind, cli_start_failure_kind};
use crate::checkpoint::anchor::SignedChainAnchor;
use crate::{ChildGrantIssuer, ClaimContext};

struct HostChildGrantIssuer;

impl ChildGrantIssuer for HostChildGrantIssuer {
    fn issue(
        &self,
        config: &mvm_core::vm_backend::VmStartConfig,
    ) -> Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
        crate::admission::stash_plan_and_mint_verb_grant(config)
    }
}

/// Typed result of spending an admitted CLI launch against one selected parent.
pub enum CliWarmClaimOutcome {
    /// The selected parent became the admitted child.
    Claimed(OwnedWarmClaim),
    /// Another claimant won the reservation; the exact capability was restored.
    ReservationLost,
    /// The child reserved before admission could not be resumed and was
    /// discarded before it ran; the exact capability was restored.
    PreloadedChildUnusable,
    /// The claim reached a terminal gate, or retained uncertain native custody.
    ///
    /// The admission is spent in both cases. [`CliStartFailureKind::UncertainStop`]
    /// distinguishes the nonterminal custody outcome from a terminal refusal.
    Refused(anyhow::Error),
}

/// Consume the slot's opaque admission against one already-selected parent.
///
/// The slot contains the same prepared capability again only for
/// [`CliWarmClaimOutcome::ReservationLost`]. Claimed and refused outcomes retain
/// only the deferred audit continuation, so neither can cold-dispatch.
///
/// `preloaded_lifecycle` is the selected standby's preloaded-child gate when
/// the launch reserved that child before admission; the claim runs under it.
pub fn claim_selected_cli_warm(
    admission: &std::cell::RefCell<Option<CliAdmission>>,
    backend: &AnyBackend,
    pool: &SupervisorStandbyPool,
    handle: &StandbyHandle,
    preloaded_lifecycle: Option<&mvm_runtime::vm::instance_snapshot::MachineLifecycleLock>,
) -> CliWarmClaimOutcome {
    let Some(owner) = admission.borrow_mut().take() else {
        return CliWarmClaimOutcome::Refused(anyhow::anyhow!("warm claim lost its CLI admission"));
    };
    let result = claim_selected(owner, backend, pool, handle, preloaded_lifecycle);
    match result {
        SelectedClaim::Claimed { owner, claim } => {
            *admission.borrow_mut() = Some(owner);
            // A record left behind is `Claimed`, which expiry removes without
            // touching the claimed VM.
            if let Err(error) = pool.remove(&handle.id) {
                tracing::warn!(standby = %handle.id, error = %format!("{error:#}"), "claimed standby record not removed");
            }
            mvm_core::launch_trace::lap("warm_claim.pool_remove");
            CliWarmClaimOutcome::Claimed(claim)
        }
        SelectedClaim::ReservationLost(owner) => {
            *admission.borrow_mut() = Some(owner);
            CliWarmClaimOutcome::ReservationLost
        }
        SelectedClaim::Refused { owner, error } => {
            *admission.borrow_mut() = Some(owner);
            CliWarmClaimOutcome::Refused(error)
        }
    }
}

enum SelectedClaim {
    Claimed {
        owner: CliAdmission,
        claim: OwnedWarmClaim,
    },
    ReservationLost(CliAdmission),
    Refused {
        owner: CliAdmission,
        error: anyhow::Error,
    },
}

fn claim_selected(
    owner: CliAdmission,
    backend: &AnyBackend,
    pool: &SupervisorStandbyPool,
    handle: &StandbyHandle,
    preloaded_lifecycle: Option<&mvm_runtime::vm::instance_snapshot::MachineLifecycleLock>,
) -> SelectedClaim {
    let result = build_claim_context(backend, handle);
    let (checkpoints, snapshots, anchor, parent_checkpoint, registry_path, grant_issuer) =
        match result {
            Ok(context) => context,
            Err(error) => {
                let owner = owner.spend_warm_refusal();
                return SelectedClaim::Refused { owner, error };
            }
        };
    let ctx = ClaimContext {
        pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: anchor.as_ref(),
        parent_checkpoint: &parent_checkpoint,
        registry_path: &registry_path,
        grant_issuer: Some(&grant_issuer),
        preloaded_child_lifecycle: preloaded_lifecycle,
    };
    mvm_core::launch_trace::lap("warm_claim.claim_context");
    let (owner, result) = owner.claim_prepared_warm(backend, &ctx, handle);
    mvm_core::launch_trace::lap("warm_claim.dispatch_return");
    match result {
        Ok(claim) => SelectedClaim::Claimed { owner, claim },
        Err(error)
            if error
                .downcast_ref::<mvm_core::vm_backend::StandbyError>()
                .is_some_and(|error| {
                    matches!(error, mvm_core::vm_backend::StandbyError::ReservationLost)
                }) =>
        {
            SelectedClaim::ReservationLost(owner)
        }
        Err(error) => {
            debug_assert!(
                !matches!(
                    cli_start_failure_kind(&error),
                    None | Some(CliStartFailureKind::StateNotOwned)
                ) || owner.is_spent(),
                "a reached warm dispatch must spend authority"
            );
            SelectedClaim::Refused { owner, error }
        }
    }
}

type ClaimInputs = (
    crate::checkpoint::CheckpointStore,
    mvm_fs::snapshot_store::FsSnapshotStore,
    Box<dyn crate::checkpoint::CheckpointChainAnchor>,
    CheckpointId,
    std::path::PathBuf,
    HostChildGrantIssuer,
);

fn build_claim_context(backend: &AnyBackend, handle: &StandbyHandle) -> Result<ClaimInputs> {
    let parent_checkpoint = handle
        .parent_checkpoint
        .as_deref()
        .map(|id| CheckpointId::new(id.to_string()))
        .with_context(|| format!("standby '{}' was never captured to a checkpoint", handle.id))?;
    let checkpoints = crate::checkpoint::CheckpointStore::open();
    let snapshots =
        mvm_fs::snapshot_store::FsSnapshotStore::new(mvm_core::config::snapshots_dir())?;
    // Closes the parent selection, so the host key load the anchor makes next
    // is lapped on its own.
    mvm_core::launch_trace::lap("warm_claim.parent_selected");
    let anchor: Box<dyn crate::checkpoint::CheckpointChainAnchor> =
        if backend.as_vm_backend().supports_resident_handoff() {
            Box::new(SignedChainAnchor::empty())
        } else {
            Box::new(PlanlessWarmParentAnchor::for_checkpoint(
                &checkpoints,
                &parent_checkpoint,
            )?)
        };
    Ok((
        checkpoints,
        snapshots,
        anchor,
        parent_checkpoint,
        crate::name_registry::registry_path(),
        HostChildGrantIssuer,
    ))
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;

    struct Fixture {
        _env: mvm_core::util::test_env::TestEnv,
        _home: tempfile::TempDir,
        _runtime: tempfile::TempDir,
        audit: tempfile::TempDir,
        backend: AnyBackend,
        slot: std::cell::RefCell<Option<CliAdmission>>,
        pool: SupervisorStandbyPool,
        handle: StandbyHandle,
        config: mvm_core::vm_backend::VmStartConfig,
        plan_id: mvm_core::plan::PlanId,
        nonce: mvm_core::plan::Nonce,
        capability_identity: (usize, usize),
    }

    fn prepared_fixture(backend: AnyBackend, name: &str) -> Fixture {
        prepared_fixture_with(backend, name, None)
    }

    /// A fixture admitted with `grants` on its signed plan.
    fn prepared_fixture_with(
        backend: AnyBackend,
        name: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> Fixture {
        let backend_kind = backend.kind();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("home");
        env.isolate_mvm_home(home.path());
        let keys = tempfile::tempdir().expect("keys");
        let audit = tempfile::tempdir().expect("audit");
        let runtime_dir = tempfile::tempdir().expect("runtime");
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"warm child").expect("rootfs");
        let ledger = crate::admission::InMemoryNonceLedger::new();
        let runtime = mvm_build::guest_runtime::evidence::verified_release_runtime_fixture(
            runtime_dir.path(),
            mvm_core::arch::GuestArch::host(),
            mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
            mvm_runtime::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
        );
        let release = std::sync::Arc::clone(&runtime.release);
        let prepared = crate::admission::prepare_cli_cold(
            &backend,
            mvm_core::vm_backend::VmStartConfig {
                name: name.into(),
                rootfs_path: rootfs.display().to_string(),
                ..Default::default()
            },
            |config| {
                config.runtime_release_proof = Some(release.proof().clone());
                config.runtime_overlay_path = Some(runtime.overlay.display().to_string());
                config.runtime_overlay_verity_path =
                    Some(runtime.overlay_verity.display().to_string());
                config.runtime_overlay_roothash = Some(runtime.overlay_roothash.clone());
                config.runtime_overlay_version = Some(release.proof().version.clone());
                config.initrd_path = Some(runtime.initramfs.display().to_string());
                Ok(Some(release))
            },
            |config, verified_runtime| {
                let verified_runtime =
                    verified_runtime.context("fixture must retain verified runtime")?;
                let (context, durability) =
                    crate::admission::admit_plan_for_boot_with_verified_runtime_syncing_beside_boot(
                    crate::admission::AdmitPlanForBootParams {
                        vm_name: name,
                        keys_dir: Some(keys.path()),
                        audit_dir: Some(audit.path()),
                        runtime_config: Some(config),
                        grants: grants.clone(),
                        backend_kind: grants.as_ref().map(|_| backend_kind),
                        backend_name: if grants.is_some() { "mock" } else { "firecracker" },
                        // A dev run records a grant the mock tier cannot meter.
                        restrict_agent_verbs: grants.is_none(),
                        ..crate::admission::admit_plan_tests::pinning_params(&rootfs, &ledger)
                    },
                    verified_runtime,
                )?;
                config.admission_durability = Some(durability);
                config.plan_json = Some(serde_json::to_string(context.admitted.signed())?);
                Ok(crate::admission::CliColdAdmissionInput::new(
                    CliAdmission::new_for_rootfs(context, &rootfs),
                    None,
                ))
            },
        )
        .expect("prepared CLI cold");
        let plan_id = prepared.admission.plan().plan_id.clone();
        let nonce = prepared.admission.plan().nonce.clone();
        let capability_identity = prepared
            .admission
            .warm_test_identity()
            .expect("prepared runtime and continuation identity");
        let config = prepared.config;
        let slot = std::cell::RefCell::new(Some(prepared.admission));
        let pool = SupervisorStandbyPool::at(home.path().join("pool"));
        let handle = StandbyHandle {
            id: "selected-parent".into(),
            template_id: None,
            control_socket: String::new(),
            pid: 0,
            kernel_sha256: String::new(),
            vcpus: 1,
            mem_mib: 128,
            binding_nonce: String::new(),
            spawned_unix_secs: 0,
            state: mvm_core::vm_backend::StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: Some("parent-checkpoint".into()),
            preloaded_child_vm_name: None,
            vsock_egress: false,
        };
        pool.record(&handle).expect("selected record");
        Fixture {
            _env: env,
            _home: home,
            _runtime: runtime_dir,
            audit,
            backend,
            slot,
            pool,
            handle,
            config,
            plan_id,
            nonce,
            capability_identity,
        }
    }

    fn assert_exact_capability(fixture: &Fixture) {
        let owner = fixture.slot.borrow();
        let owner = owner.as_ref().expect("slot owner remains");
        assert_eq!(owner.plan().plan_id, fixture.plan_id);
        assert_eq!(owner.plan().nonce, fixture.nonce);
        assert_eq!(
            owner.warm_test_identity(),
            Some(fixture.capability_identity),
            "runtime evidence and continuation allocation remain exact"
        );
    }

    #[test]
    fn successful_facade_claim_transfers_child_and_removes_pool_record_only_on_success() {
        let fixture = prepared_fixture(
            AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby()),
            "client-warm-success",
        );
        let CliWarmClaimOutcome::Claimed(claim) = claim_selected_cli_warm(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle,
            None,
        ) else {
            panic!("mock facade claim must succeed");
        };
        assert!(fixture.pool.load(&fixture.handle.id).is_err());
        assert!(
            fixture
                .slot
                .borrow()
                .as_ref()
                .expect("audit owner")
                .is_spent()
        );
        let (id, lifecycle) = claim.into_parts();
        assert_eq!(id.0, fixture.handle.id);
        let chain =
            std::fs::read_to_string(fixture.audit.path().join("local.jsonl")).expect("audit chain");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert!(!chain.contains("plan.launched"), "{chain}");
        assert!(!chain.contains("plan.failed"), "{chain}");
        drop(lifecycle);
        fixture.backend.stop(&id).expect("stop claimed mock child");
    }

    fn reservation_loss_restores_exact_capability(fixture: Fixture, remove: bool) {
        if remove {
            fixture
                .pool
                .remove(&fixture.handle.id)
                .expect("winner removes record");
        } else {
            fixture
                .pool
                .mark_claimed(&fixture.handle.id)
                .expect("winner claims record");
        }
        assert!(matches!(
            claim_selected_cli_warm(
                &fixture.slot,
                &fixture.backend,
                &fixture.pool,
                &fixture.handle,
                None,
            ),
            CliWarmClaimOutcome::ReservationLost
        ));
        assert_exact_capability(&fixture);
        let cold_name = fixture.config.name.clone();
        let owner = fixture.slot.into_inner().expect("restored owner");
        let (_owner, result) = owner.start_cold(&fixture.backend, fixture.config, Vec::new());
        result.expect("optional reservation loss retains cold dispatch");
        fixture
            .backend
            .stop(&mvm_core::vm_backend::VmId(cold_name))
            .expect("stop optional cold fallback");
    }

    #[test]
    fn claimed_record_race_restores_exact_slot_for_optional_cold_dispatch() {
        reservation_loss_restores_exact_capability(
            prepared_fixture(
                AnyBackend::Mock(
                    mvm_runtime::mock::MockBackend::new()
                        .with_standby()
                        .with_lost_standby_reservation()
                        .with_verified_release_runtime(),
                ),
                "client-warm-claimed-race",
            ),
            false,
        );
    }

    #[test]
    fn removed_record_race_restores_exact_slot_for_optional_cold_dispatch() {
        reservation_loss_restores_exact_capability(
            prepared_fixture(
                AnyBackend::Mock(
                    mvm_runtime::mock::MockBackend::new()
                        .with_standby()
                        .with_lost_standby_reservation()
                        .with_verified_release_runtime(),
                ),
                "client-warm-removed-race",
            ),
            true,
        );
    }

    #[test]
    fn uncertain_facade_dispatch_spends_authority_and_retains_parent_and_child_state() {
        let fixture = prepared_fixture(
            AnyBackend::Mock(
                mvm_runtime::mock::MockBackend::new()
                    .with_standby()
                    .with_uncertain_standby_stop(),
            ),
            "client-warm-uncertain",
        );
        fixture
            .pool
            .mark_claimed(&fixture.handle.id)
            .expect("runner reserved parent");
        let CliWarmClaimOutcome::Refused(error) = claim_selected_cli_warm(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle,
            None,
        ) else {
            panic!("uncertain mock claim must refuse");
        };
        assert_eq!(
            crate::admission::cli_start_failure_kind(&error),
            Some(crate::admission::CliStartFailureKind::UncertainStop)
        );
        let owner = fixture.slot.borrow();
        assert!(owner.as_ref().expect("audit owner").is_spent());
        assert_eq!(
            fixture.pool.load(&fixture.handle.id).expect("parent").state,
            mvm_core::vm_backend::StandbyState::Claimed
        );
        assert!(matches!(
            fixture
                .backend
                .status(&mvm_core::vm_backend::VmId(fixture.handle.id.clone())),
            Ok(mvm_core::vm_backend::VmStatus::Running)
        ));
        let chain =
            std::fs::read_to_string(fixture.audit.path().join("local.jsonl")).expect("audit chain");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert!(!chain.contains("plan.launched"), "{chain}");
        assert!(!chain.contains("plan.failed"), "{chain}");
    }

    #[test]
    fn terminal_parent_preparation_refusal_spends_slot_and_keeps_pool_record() {
        let mut fixture = prepared_fixture(
            AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby()),
            "client-warm-prep-refusal",
        );
        fixture.handle.parent_checkpoint = None;
        let CliWarmClaimOutcome::Refused(error) = claim_selected_cli_warm(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle,
            None,
        ) else {
            panic!("missing authenticated parent source must refuse");
        };
        assert!(
            format!("{error:#}").contains("never captured to a checkpoint"),
            "{error:#}"
        );
        let owner = fixture.slot.borrow();
        let owner = owner.as_ref().expect("spent audit owner remains");
        assert!(owner.is_spent());
        assert_eq!(owner.plan().plan_id, fixture.plan_id);
        assert!(
            fixture.pool.load(&fixture.handle.id).is_ok(),
            "client removes a selected record only after successful claim"
        );
    }

    /// A stand-in for a paused VMM, which every release signals.
    fn paused_vmm() -> std::process::Child {
        mvm_runtime::mock::MockBackend::spawn_stand_in_vmm().expect("stand-in paused VMM")
    }

    /// The fixture's parent with a paused child preloaded by the mock backend,
    /// recorded, and reserved the way a launch reserves it before admission.
    /// The fixture admitted its plan under the child's name.
    fn reserved_preload(
        process: &std::process::Child,
    ) -> (Fixture, crate::standby::PreloadedReservation) {
        reserved_preload_for(process, "selected-parent-child", None)
    }

    /// [`reserved_preload`] for a launch admitted under `name` with `grants`.
    fn reserved_preload_for(
        process: &std::process::Child,
        name: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> (Fixture, crate::standby::PreloadedReservation) {
        let backend = AnyBackend::Mock(
            mvm_runtime::mock::MockBackend::new().with_preloaded_standby(process.id()),
        );
        let mut fixture = prepared_fixture_with(backend, name, grants);
        fixture.pool = SupervisorStandbyPool::at(fixture._home.path().join("pool"))
            .with_stop_child(mvm_runtime::standby_pool::stop_stand_in);
        let AnyBackend::Mock(mock) = &fixture.backend else {
            panic!("mock backend");
        };
        let gate = mock
            .preload_standby(&mut fixture.handle)
            .expect("mock preload");
        fixture
            .pool
            .record(&fixture.handle)
            .expect("publish preloaded record");
        drop(gate);
        let (handle, lifecycle) = fixture
            .pool
            .reserve_preloaded_compatible(&fixture.handle.compat())
            .expect("pool readable")
            .expect("reserved before admission");
        (
            fixture,
            crate::standby::PreloadedReservation { handle, lifecycle },
        )
    }

    #[test]
    fn an_admitted_launch_resumes_the_child_it_reserved_under_that_childs_name() {
        let mut process = paused_vmm();
        let (fixture, reserved) = reserved_preload(&process);

        let outcome = crate::standby::claim_for_admitted_launch(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle.compat(),
            Some(&reserved),
        )
        .expect("pool readable");

        let Some(CliWarmClaimOutcome::Claimed(claim)) = outcome else {
            panic!("the reserved child must be claimed");
        };
        let (id, lifecycle) = claim.into_parts();
        assert_eq!(
            id.0, "selected-parent-child",
            "the VM that runs is the admitted name"
        );
        assert!(lifecycle.is_none(), "the launcher keeps the one gate");
        assert!(
            fixture.pool.load(&fixture.handle.id).is_err(),
            "one claim per child"
        );
        let chain =
            std::fs::read_to_string(fixture.audit.path().join("local.jsonl")).expect("audit chain");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert!(chain.contains("selected-parent-child"), "{chain}");
        let _ = process.kill();
        let _ = process.wait();
    }

    /// A second, ordinary standby beside the preloaded one, sharing its shape.
    fn record_ordinary_standby(fixture: &Fixture) -> StandbyHandle {
        let mut ordinary = fixture.handle.clone();
        ordinary.id = "ordinary-parent".into();
        ordinary.pid = 0;
        ordinary.preloaded_child_vm_name = None;
        ordinary.control_socket = String::new();
        fixture.pool.record(&ordinary).expect("ordinary standby");
        ordinary
    }

    /// Through the real claim path, a launch the reserved child cannot serve
    /// (here its plan names another VM; a CPU grant on the signed plan takes
    /// the same branch, see `a_preloaded_child_serves_only_its_own_grant_free_compatible_launch`).
    /// The child is left intact for the next launch and this one forks
    /// another standby.
    #[test]
    fn an_unservable_launch_forks_another_standby_and_leaves_the_child_intact() {
        let mut process = paused_vmm();
        let (fixture, reserved) = reserved_preload_for(&process, "another-launch", None);
        record_ordinary_standby(&fixture);
        let before = fixture
            .pool
            .load(&fixture.handle.id)
            .expect("preloaded record");

        let outcome = crate::standby::claim_for_admitted_launch(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle.compat(),
            Some(&reserved),
        )
        .expect("pool readable");

        let Some(CliWarmClaimOutcome::Claimed(claim)) = outcome else {
            panic!("the launch forks the ordinary standby");
        };
        assert_eq!(claim.into_parts().0.0, "ordinary-parent");
        assert!(
            process.try_wait().unwrap().is_none(),
            "the paused child is untouched"
        );
        assert_eq!(
            fixture.pool.load(&fixture.handle.id).expect("record"),
            before,
            "the preloaded record is exactly as it was"
        );
        drop(reserved);
        assert!(
            fixture
                .pool
                .reserve_preloaded_compatible(&fixture.handle.compat())
                .expect("pool readable")
                .is_some(),
            "a following grant-free launch can still take the child"
        );
        let _ = process.kill();
        let _ = process.wait();
    }

    /// With no other standby the cold boot needs the admitted name the child
    /// holds (here a reshaped launch), so the reserved standby goes and no
    /// demoted parent is left; the launch keeps its admission.
    #[test]
    fn an_unservable_launch_with_no_other_standby_boots_cold_under_its_name() {
        let mut process = paused_vmm();
        let (fixture, reserved) = reserved_preload_for(&process, "selected-parent-child", None);
        let mut reshaped = fixture.handle.compat();
        reshaped.vcpus = reshaped.vcpus.saturating_add(1);

        let outcome = crate::standby::claim_for_admitted_launch(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &reshaped,
            Some(&reserved),
        )
        .expect("pool readable");

        assert!(outcome.is_none(), "no warm claim: the launch boots cold");
        assert_exact_capability(&fixture);
        assert!(!process.wait().expect("released child").success());
        assert!(
            fixture.pool.load(&fixture.handle.id).is_err(),
            "no demoted parent left"
        );
        assert!(
            mvm_runtime::vm::name_custody::NameCustody::require_cold_state("selected-parent-child")
                .is_ok(),
            "the admitted name is free for the cold boot"
        );
    }

    /// The live-witness case through the real claim path: the signed plan
    /// grants a CPU share, so the reserved child is not taken.
    #[test]
    fn a_cpu_granted_launch_never_takes_the_reserved_child() {
        let mut process = paused_vmm();
        let grant = Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
            ..Default::default()
        });
        let (fixture, reserved) = reserved_preload_for(&process, "selected-parent-child", grant);
        assert!(
            fixture
                .slot
                .borrow()
                .as_ref()
                .expect("admission")
                .plan()
                .grants
                .is_some(),
            "the fixture's signed plan carries the grant"
        );

        let outcome = crate::standby::claim_for_admitted_launch(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle.compat(),
            Some(&reserved),
        )
        .expect("pool readable");

        assert!(
            outcome.is_none(),
            "not claimed: with no other standby it boots cold"
        );
        assert_exact_capability(&fixture);
        let _ = process.kill();
        let _ = process.wait();
    }

    #[test]
    fn a_lost_reservation_keeps_the_admission_for_the_cold_boot() {
        let mut process = paused_vmm();
        let (mut fixture, reserved) = reserved_preload(&process);
        fixture.backend = AnyBackend::Mock(
            mvm_runtime::mock::MockBackend::new()
                .with_preloaded_standby(process.id())
                .with_lost_standby_reservation(),
        );

        let outcome = crate::standby::claim_for_admitted_launch(
            &fixture.slot,
            &fixture.backend,
            &fixture.pool,
            &fixture.handle.compat(),
            Some(&reserved),
        )
        .expect("pool readable");

        assert!(matches!(
            outcome,
            Some(CliWarmClaimOutcome::PreloadedChildUnusable)
        ));
        assert_exact_capability(&fixture);
        // The launcher then releases the child so the cold boot can take its name.
        fixture
            .pool
            .release_reserved_preload(&reserved.handle, &reserved.lifecycle)
            .expect("release");
        assert!(
            mvm_runtime::vm::name_custody::NameCustody::require_cold_state("selected-parent-child")
                .is_ok(),
            "the admitted name is free for the cold boot"
        );
        let _ = process.kill();
        let _ = process.wait();
    }

    /// Each fact known before admission decides on its own; the baseline
    /// launch does reserve.
    #[test]
    fn launches_known_to_be_unservable_reserve_no_preloaded_child() {
        let mut process = paused_vmm();
        let (fixture, reserved) = reserved_preload(&process);
        drop(reserved);
        let kernel = fixture._home.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").expect("kernel");
        let base = mvm_core::vm_backend::VmStartConfig {
            warm_pool_size: 1,
            kernel_path: Some(kernel.display().to_string()),
            cpus: u32::from(fixture.handle.vcpus),
            memory_mib: fixture.handle.mem_mib,
            ..fixture.config.clone()
        };
        let mut matching = fixture.handle.clone();
        let want = crate::standby::standby_compat(&base).expect("compat");
        matching.kernel_sha256 = want.kernel_sha256.clone();
        matching.image_sha256 = want.image_sha256.clone();
        matching.vsock_egress = want.vsock_egress;
        matching.root_strategy = want.root_strategy;
        fixture
            .pool
            .record(&matching)
            .expect("record matching standby");
        let reserve = |config: &mvm_core::vm_backend::VmStartConfig, host_volumes: bool| {
            let mut config = config.clone();
            crate::standby::reserve_preloaded_for_launch(
                &fixture.backend,
                &mut config,
                host_volumes,
            )
            .expect("reserve")
        };

        let disabled = mvm_core::vm_backend::VmStartConfig {
            warm_pool_size: 0,
            ..base.clone()
        };
        assert!(reserve(&base, true).is_none(), "host volumes");
        assert!(reserve(&disabled, false).is_none(), "standbys disabled");
        assert!(
            crate::standby::preload_known_unservable(&base, Some(250)),
            "a host default CPU share"
        );
        let mut config = base.clone();
        let reserved =
            crate::standby::reserve_preloaded_for_launch(&fixture.backend, &mut config, false)
                .expect("reserve")
                .expect("the baseline launch reserves");
        assert_eq!(
            config.name, "selected-parent-child",
            "named after the child"
        );
        drop(reserved);
        let _ = process.kill();
        let _ = process.wait();
    }

    #[test]
    fn a_backend_without_preload_reserves_nothing() {
        let fixture = prepared_fixture(
            AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby()),
            "no-preload",
        );
        let mut config = mvm_core::vm_backend::VmStartConfig {
            warm_pool_size: 1,
            ..fixture.config.clone()
        };
        assert!(
            crate::standby::reserve_preloaded_for_launch(&fixture.backend, &mut config, false)
                .expect("reserve")
                .is_none()
        );
        assert_eq!(config.name, "no-preload");
    }
}
