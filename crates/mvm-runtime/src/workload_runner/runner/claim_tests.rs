//! Tests for the warm claim: lineage and content gates, fresh identity.
#![cfg(test)]

use super::{admission::admitted_network_limits, parent_verify::*, test_support::*, *};
use crate::checkpoint::capture_vm_full;
use crate::driver::MockDriver;
use crate::workload_runner::standby_boot::factory_parent_spec;
use mvm_agentd::vsock::{BROKER_PORT, EGRESS_PORT};
use mvm_core::checkpoint::{CheckpointDigest, CheckpointMeta};
use mvm_core::crypto::vmgenid::GENID_BYTES;
use mvm_core::plan::VerbId;
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use mvm_core::util::test_env::TestEnv;
use mvm_core::vm_backend::StandbyState;
use mvm_fs::snapshot_store::SnapshotStore;
use std::sync::Mutex;

/// A `CheckpointChainAnchor` double: reports the parent as audited (echoing
/// its own recomputed creation digest) so the lineage gate passes, and every
/// other checkpoint as un-audited.
struct ClaimTestAnchor {
    verdicts: std::collections::HashMap<String, CheckpointDigest>,
}

impl ClaimTestAnchor {
    fn audited(meta: &CheckpointMeta) -> Self {
        let mut verdicts = std::collections::HashMap::new();
        verdicts.insert(meta.id.to_string(), meta.compute_meta_digest());
        Self { verdicts }
    }

    /// No signed creation entry for any checkpoint → the lineage gate refuses
    /// the parent as un-audited.
    fn unaudited() -> Self {
        Self {
            verdicts: std::collections::HashMap::new(),
        }
    }
}

impl CheckpointChainAnchor for ClaimTestAnchor {
    fn recorded_creation_tenant(&self, _meta: &CheckpointMeta) -> Result<Option<String>> {
        Ok(None)
    }

    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        Ok(self.verdicts.get(&meta.id.to_string()).cloned())
    }
}

/// An `NetworkEndpointSpawner` double that keys its returned socket on the vm name it
/// is handed — mirroring `RealNetworkEndpointSpawner` — and records that name, so a
/// test can prove the child endpoint is keyed on the child's own id and the
/// parent got none, with no real endpoint process.
#[derive(Default)]
struct KeyingSpawner {
    seen_vm: Mutex<Option<String>>,
    spawned: Mutex<Option<std::sync::mpsc::Sender<String>>>,
}

impl NetworkEndpointSpawner for KeyingSpawner {
    fn prepare_identity(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>> {
        Ok(
            matches!(req.identity, FlowMuxIdentitySource::Mint).then(|| {
                req.state_dir
                    .join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE)
            }),
        )
    }

    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        *self.seen_vm.lock().unwrap() = Some(req.vm_name.to_string());
        if let Some(spawned) = self.spawned.lock().unwrap().as_ref() {
            let _ = spawned.send(req.vm_name.to_string());
        }
        Ok(SpawnedEndpoint {
            egress_uds: vm_network_endpoint_socket(req.vm_name),
            identity_drive: None,
        })
    }
}

/// Seed a clean, audited, pre-workload parent checkpoint and return
/// `(store, snapshots, parent_id, parent_meta)`. With `with_overlay_sidecar`
/// the source rootfs carries an overlay-aware sidecar so its clone clears the
/// same host gate a cold boot runs; without it, the child's overlay-contract
/// gate refuses — the wiring witness. The `TempDir`s must outlive the stores.
fn seed_audited_parent(
    store_root: &Path,
    src_root: &Path,
    with_overlay_sidecar: bool,
) -> (
    CheckpointStore,
    FsSnapshotStore,
    CheckpointId,
    CheckpointMeta,
) {
    seed_audited_parent_with_grants(store_root, src_root, with_overlay_sidecar, None)
}

/// Seed a warm parent whose sealed record carries `grants`, so a claim has a
/// real permission set to be bounded against.
fn seed_audited_parent_with_grants(
    store_root: &Path,
    src_root: &Path,
    with_overlay_sidecar: bool,
    grants: Option<mvm_contract::grants::Grants>,
) -> (
    CheckpointStore,
    FsSnapshotStore,
    CheckpointId,
    CheckpointMeta,
) {
    seed_audited_parent_in(
        CheckpointStore::at(store_root.join("checkpoints")),
        store_root,
        src_root,
        with_overlay_sidecar,
        grants,
    )
}

/// Seed a warm parent into `checkpoints`, which decides whether the
/// capture is sealed.
fn seed_audited_parent_in(
    checkpoints: CheckpointStore,
    store_root: &Path,
    src_root: &Path,
    with_overlay_sidecar: bool,
    grants: Option<mvm_contract::grants::Grants>,
) -> (
    CheckpointStore,
    FsSnapshotStore,
    CheckpointId,
    CheckpointMeta,
) {
    let snapshots = FsSnapshotStore::new(store_root.join("snapshots")).unwrap();

    let rootfs = src_root.join("rootfs.ext4");
    std::fs::write(&rootfs, b"clean-parent-rootfs").unwrap();
    if with_overlay_sidecar {
        // runtime_lean=true so the overlay sidecar clears the gate under every
        // runtime-source policy, exactly like the cold-boot admission tests.
        mvm_build::builder_vm::GuestSidecar::for_oci_run("warm-parent", false, true)
            .write_to_dir(src_root)
            .unwrap();
    }

    // The synthetic parent carries checked-source evidence. Only execution
    // and the audit anchor are mocked; runtime verification is not.
    let runtime_config = checked_source_config("warm-parent", rootfs.display().to_string());
    let lease = crate::runtime_evidence::RuntimeLifecycleLease::acquire("warm-parent").unwrap();
    let bound = lease.bind(&runtime_config).unwrap();
    crate::base::runtime_meta::record_from_start_config("warm-parent", StartMode::Detached, &bound)
        .unwrap();
    let runtime_binding = crate::base::runtime_meta::read("warm-parent")
        .unwrap()
        .unwrap()
        .runtime_launch_binding;
    drop(lease);
    let parent_id = CheckpointId::new("warm-parent-cp");
    let driver = MockDriver::default().with_vm_full_rootfs(&rootfs);
    let boot = factory_parent_spec(&bound, &vm_state_dir("warm-parent"), |has_disk| {
        driver.workload_base_bootargs(has_disk)
    });
    driver.boot(&boot).unwrap();
    let control = driver.vm_full_control("warm-parent").unwrap();
    let parent_meta = capture_vm_full(
        &checkpoints,
        CaptureVmFullParams {
            id: parent_id.clone(),
            vm_name: "warm-parent".into(),
            supervisor_config_digest: "d".into(),
            runtime_overlay_version: bound.runtime_overlay_version,
            runtime_launch_binding: runtime_binding,
            supervisor_config_src: None,
            tag: None,
            created_unix: 1,
            retain_paused: false,
            grants,
            parent: None,
            session: None,
            workspace_volumes: Vec::new(),
            key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
        },
        control.as_ref(),
    )
    .unwrap();
    let snapshot_id = format!(
        "checkpoint-{parent_id}-content-{}",
        mvm_core::checkpoint::content_manifest_digest(&parent_meta.content)
    );
    snapshots
        .create(
            &mvm_fs::snapshot_store::SnapshotId::with_digest(
                snapshot_id.clone(),
                mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string(),
            ),
            &checkpoints.content_dir(&parent_id),
        )
        .unwrap();
    let parent_meta = parent_meta.with_snapshot_id(snapshot_id);
    checkpoints.write_meta(&parent_meta).unwrap();
    (checkpoints, snapshots, parent_id, parent_meta)
}

fn materialized_parent_rootfs_digest(
    checkpoints: &CheckpointStore,
    parent: &CheckpointMeta,
) -> String {
    materialized_blob_sha256(checkpoints, parent, mvm_core::checkpoint::ROOTFS_BLOB).unwrap()
}

/// A warm parent captured under the host key, as production captures it,
/// with a child preloaded from it by the runner's own pool-refill path.
struct ProtectedPreloadedParent {
    _env: TestEnv,
    _home: tempfile::TempDir,
    store_root: tempfile::TempDir,
    src: tempfile::TempDir,
    checkpoints: CheckpointStore,
    snapshots: FsSnapshotStore,
    parent_id: CheckpointId,
    parent_meta: CheckpointMeta,
    pool: SupervisorStandbyPool,
    handle: StandbyHandle,
}

impl ProtectedPreloadedParent {
    fn seed(runner: &WorkloadRunner<MockDriver, KeyingSpawner, RecordingBrokerRegistrar>) -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        env.set(
            crate::vm::snapshot_key::SNAPSHOT_TENANT_KEY_ENV,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let sealed_store = CheckpointStore::at(store_root.path().join("checkpoints"))
            .with_key_custody(std::sync::Arc::new(crate::checkpoint::HostKeyCustody));
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent_in(sealed_store, store_root.path(), src.path(), true, None);
        assert!(parent_meta.protection.is_sealed());

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let mut handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        handle.parent_checkpoint = Some(parent_id.to_string());
        let anchor = ClaimTestAnchor::audited(&parent_meta);
        let opened_before = crate::checkpoint::chunk_opens::under(store_root.path());
        let child_gate = runner
            .preload_standby_child(
                &PreloadContext {
                    checkpoints: &checkpoints,
                    snapshots: &snapshots,
                    anchor: &anchor,
                    registry_path: &store_root.path().join("vm-names.json"),
                },
                &mut handle,
            )
            .expect("preload a child from the protected parent");
        assert!(
            crate::checkpoint::chunk_opens::under(store_root.path()) > opened_before,
            "preparing the standby is where the parent's content is opened"
        );
        pool.record(&handle).unwrap();
        drop(child_gate);
        Self {
            _env: env,
            _home: home,
            store_root,
            src,
            checkpoints,
            snapshots,
            parent_id,
            parent_meta,
            pool,
            handle,
        }
    }

    fn claim(
        &self,
        runner: &WorkloadRunner<MockDriver, KeyingSpawner, RecordingBrokerRegistrar>,
    ) -> std::result::Result<VmId, StandbyError> {
        self.claim_as(runner, self.child_name(), None, None)
            .map(|owned| owned.into_parts().0)
    }

    fn child_name(&self) -> &str {
        self.handle
            .preloaded_child_vm_name
            .as_deref()
            .expect("preloaded child identity")
    }

    /// Claim with a plan admitted under `plan_name` and carrying `grants`,
    /// with or without the child's lifecycle gate held by the caller.
    fn claim_as(
        &self,
        runner: &WorkloadRunner<MockDriver, KeyingSpawner, RecordingBrokerRegistrar>,
        plan_name: &str,
        grants: Option<mvm_contract::grants::Grants>,
        held: Option<&crate::vm::instance_snapshot::MachineLifecycleLock>,
    ) -> std::result::Result<crate::backend::OwnedWarmClaim, StandbyError> {
        self.claim_handle_as(runner, &self.handle, plan_name, grants, held)
    }

    /// [`Self::claim_as`] against the pool's current record for `handle`.
    fn claim_handle_as(
        &self,
        runner: &WorkloadRunner<MockDriver, KeyingSpawner, RecordingBrokerRegistrar>,
        handle: &StandbyHandle,
        plan_name: &str,
        grants: Option<mvm_contract::grants::Grants>,
        held: Option<&crate::vm::instance_snapshot::MachineLifecycleLock>,
    ) -> std::result::Result<crate::backend::OwnedWarmClaim, StandbyError> {
        let parent_digest = materialized_parent_rootfs_digest(&self.checkpoints, &self.parent_meta);
        let registry_path = self.store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&self.parent_meta);
        let mut plan = mvm_core::plan::plan_from_admitted_json(&signed_child_plan_json_named(
            &parent_digest,
            plan_name,
        ))
        .expect("signed child fixture");
        plan.grants = grants;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let claim = admitted_child_claim(
            &self.src.path().join("rootfs.ext4"),
            serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap(),
        );
        let ctx = ClaimContext {
            pool: &self.pool,
            checkpoints: &self.checkpoints,
            snapshots: &self.snapshots,
            anchor: &anchor,
            parent_checkpoint: &self.parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
            preloaded_child_lifecycle: held,
        };
        runner.claim_standby_owned(&ctx, handle, &claim)
    }

    fn chunk_objects(&self) -> Vec<PathBuf> {
        // Everything in a sealed content dir that is not a blob's sealed
        // index is a chunk object.
        let mut objects = Vec::new();
        let mut stack = vec![self.checkpoints.content_dir(&self.parent_id)];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_none_or(|ext| ext != "sealed") {
                    objects.push(path);
                }
            }
        }
        objects
    }
}

fn claim_runner() -> WorkloadRunner<MockDriver, KeyingSpawner, RecordingBrokerRegistrar> {
    WorkloadRunner::new(
        MockDriver::default().with_preloaded_standby(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    )
}

/// Pool refill opened the parent's sealed content into the preloaded child,
/// so a claim decrypts none of it again: it authenticates the sealed
/// objects where they lie and wakes the child that already holds them.
#[test]
fn a_warm_claim_on_a_protected_preloaded_parent_decrypts_no_chunk() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    assert!(
        !parent.chunk_objects().is_empty(),
        "the parent must hold sealed chunks for this to mean anything"
    );
    let before = crate::checkpoint::chunk_opens::under(parent.store_root.path());

    let child = parent.claim(&runner).expect("claim a protected parent");

    assert_eq!(
        Some(child.0.as_str()),
        parent.handle.preloaded_child_vm_name.as_deref(),
        "the claim wakes the child prepared at refill"
    );
    assert_eq!(
        crate::checkpoint::chunk_opens::under(parent.store_root.path()),
        before,
        "a warm claim must not decrypt the parent's content again"
    );
    assert_eq!(runner.driver.forked_children().len(), 1);
}

#[test]
fn a_warm_claim_refuses_changed_materialized_runtime_evidence_without_decrypting() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let child = parent.handle.preloaded_child_vm_name.as_ref().unwrap();
    std::fs::write(vm_state_dir(child).join("runtime-artifacts.json"), b"{}").unwrap();
    let before = crate::checkpoint::chunk_opens::under(parent.store_root.path());

    let error = parent.claim(&runner).expect_err("changed child evidence");
    assert!(
        error.to_string().contains("evidence digest mismatch"),
        "{error}"
    );
    assert_eq!(
        crate::checkpoint::chunk_opens::under(parent.store_root.path()),
        before
    );
    assert!(runner.driver.forked_children().is_empty());
}

/// A committed preloaded-child claim consumes its standby parent, so the
/// claim records the consumption in the adopted child's state dir the same
/// way a resident claim does: the parent dir holds the state the paused
/// child was loaded from and can only be removed once the child's exit is
/// confirmed.
#[test]
fn preloaded_claim_marks_the_consumed_parent_for_stop_time_cleanup() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let parent_vm_name = parent.handle.id.clone();

    let child = parent.claim(&runner).expect("preloaded claim");

    let child_dir = vm_state_dir(&child.0);
    let marker =
        std::fs::read_to_string(child_dir.join(warm_claim::CONSUMED_PRELOADED_PARENT_FILE))
            .expect("a committed preloaded claim records its consumed parent");
    assert_eq!(
        marker.trim(),
        parent_vm_name,
        "the marker names the standby parent the claim consumed"
    );
    assert!(
        vm_state_dir(&parent_vm_name).is_dir(),
        "the parent dir must outlive the claim: the paused child was loaded from it"
    );
    assert!(
        !child_dir
            .join(crate::standby_pool::PRELOADED_CHILD_RESERVATION_FILE)
            .exists(),
        "a resumed child is no longer a standby the orphan sweep may stop"
    );
    assert!(
        !child_dir
            .join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE)
            .exists(),
        "a preloaded adoption is not a resident handoff and must not write its marker"
    );
}

/// The launcher reserved the child by taking its lifecycle gate before it
/// admitted the plan. The claim runs under that gate rather than waiting on a
/// second one, and hands no second gate back.
#[test]
fn a_preloaded_claim_runs_under_the_gate_its_launcher_holds() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let held =
        crate::vm::instance_snapshot::MachineLifecycleLock::acquire(parent.child_name()).unwrap();

    let owned = parent
        .claim_as(&runner, parent.child_name(), None, Some(&held))
        .expect("claim under the held gate");

    let (id, lifecycle) = owned.into_parts();
    assert_eq!(id.0, parent.child_name());
    assert!(lifecycle.is_none(), "the launcher keeps the one gate");
    assert_eq!(runner.driver.forked_children().len(), 1);
}

/// The preloaded claim's own stage laps: no materialization, and the resume
/// named apart from a fork, so the two warm paths compare stage by stage.
#[test]
fn a_preloaded_claim_laps_the_resume_and_no_materialization() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let mut parent = ProtectedPreloadedParent::seed(&runner);
    parent
        ._env
        .set(mvm_core::launch_trace::PHASE_TIMING_ENV, "1");
    let held =
        crate::vm::instance_snapshot::MachineLifecycleLock::acquire(parent.child_name()).unwrap();

    let before = mvm_core::launch_trace::recorded_laps().len();
    mvm_core::launch_trace::lap_reset(None);
    let _claimed = parent
        .claim_as(&runner, parent.child_name(), None, Some(&held))
        .expect("preloaded claim");

    let names: Vec<String> = mvm_core::launch_trace::recorded_laps()[before..]
        .iter()
        .map(|lap| lap.name.clone())
        .collect();
    assert_eq!(
        names,
        [
            "warm_claim.parent_verified",
            "warm_claim.runtime_verified",
            "warm_claim.plan_and_grant_binds",
            "warm_claim.child_identity_and_lock",
            "warm_claim.endpoint_ready",
            "warm_claim.broker_registered",
            "warm_claim.admission_durability",
            "warm_claim.preloaded_resumed",
            "warm_claim.identity_verified",
            "warm_claim.commit",
        ]
    );
}

#[test]
fn a_preloaded_claim_refuses_a_held_gate_for_another_machine() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let other = crate::vm::instance_snapshot::MachineLifecycleLock::acquire("other-vm").unwrap();

    let error = parent
        .claim_as(&runner, parent.child_name(), None, Some(&other))
        .expect_err("a gate for another machine is not the child's reservation");

    assert!(error.to_string().contains("different machine"), "{error}");
    assert!(runner.driver.forked_children().is_empty());
}

/// The signed plan names the VM it admits. A preloaded child already has a
/// name, so a plan admitted under any other name cannot run as it: the paused
/// child stays untouched and the parent returns to the pool.
#[test]
fn a_preloaded_child_refuses_a_plan_admitted_under_another_name() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);

    let error = parent
        .claim_as(&runner, "another-launch", None, None)
        .expect_err("the plan names another VM");

    assert!(error.to_string().contains("admitted under"), "{error}");
    assert!(runner.driver.forked_children().is_empty());
    assert!(
        vm_state_dir(parent.child_name()).is_dir(),
        "child untouched"
    );
    assert!(
        parent
            .pool
            .load(&parent.handle.id)
            .unwrap()
            .state
            .is_claimable()
    );
}

/// A preloaded child's VMM was started before any claim, without a CPU
/// scope, so it cannot carry a CPU grant; such a launch takes the fork path.
#[test]
fn a_preloaded_child_refuses_a_plan_with_a_cpu_grant() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let grants = mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
        ..Default::default()
    };

    let error = parent
        .claim_as(&runner, parent.child_name(), Some(grants), None)
        .expect_err("a CPU grant cannot bind a preloaded child");

    assert!(error.to_string().contains("CPU grant"), "{error}");
    assert!(runner.driver.forked_children().is_empty());
    assert!(
        parent
            .pool
            .load(&parent.handle.id)
            .unwrap()
            .state
            .is_claimable()
    );
}

/// The launch the live witness failed on: a plan with a CPU grant reaches a
/// reserved preloaded child. The refusal happens before any state changes, so
/// the record is exactly as it was and the next, grant-free launch still
/// resumes the same child.
#[test]
fn a_refused_preloaded_claim_leaves_the_child_for_the_next_launch() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let before = parent.pool.load(&parent.handle.id).unwrap();
    let held =
        crate::vm::instance_snapshot::MachineLifecycleLock::acquire(parent.child_name()).unwrap();
    let grants = mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 }),
        ..Default::default()
    };

    parent
        .claim_as(&runner, parent.child_name(), Some(grants), Some(&held))
        .expect_err("a CPU grant cannot resume a preloaded child");
    assert_eq!(
        parent.pool.load(&parent.handle.id).unwrap(),
        before,
        "a refused claim restores the record exactly"
    );
    assert!(runner.driver.forked_children().is_empty());

    let resumed = parent
        .claim_as(&runner, parent.child_name(), None, Some(&held))
        .expect("the next grant-free launch resumes the same child");
    assert_eq!(resumed.into_parts().0.0, parent.child_name());
}

#[test]
fn preload_marks_the_child_state_with_its_owning_standby() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);

    let marker = vm_state_dir(parent.child_name())
        .join(crate::standby_pool::PRELOADED_CHILD_RESERVATION_FILE);
    assert_eq!(std::fs::read_to_string(marker).unwrap(), parent.handle.id);
    assert!(
        crate::vm::name_custody::NameCustody::require_cold_state(parent.child_name()).is_err(),
        "a cold launch cannot take a preloaded child's name"
    );
}

#[test]
fn consumed_preloaded_parent_cleanup_waits_for_confirmed_exit() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _env = TestEnv::new();

    let parent_dir = vm_state_dir("standby-parent");
    std::fs::create_dir_all(&parent_dir).unwrap();
    std::fs::write(parent_dir.join("rootfs.ext4"), b"parent-rootfs").unwrap();
    let pool = SupervisorStandbyPool::open().unwrap();
    pool.record(&idle_parent_handle(
        "standby-parent",
        std::path::Path::new("/tmp/control.sock"),
    ))
    .unwrap();
    let child_dir = vm_state_dir("vm-child");
    std::fs::create_dir_all(&child_dir).unwrap();
    warm_claim::record_consumed_preloaded_parent(&child_dir, "standby-parent").unwrap();

    // No confirmed exit: the load opened the parent dir's recorded drives,
    // so nothing may be removed while the child may still run.
    warm_claim::cleanup_consumed_preloaded_parent(&child_dir, false);
    assert!(
        parent_dir.is_dir(),
        "parent dir must survive an unconfirmed stop"
    );
    assert!(
        pool.load("standby-parent").is_ok(),
        "pool record must survive an unconfirmed stop"
    );
    assert!(
        child_dir
            .join(warm_claim::CONSUMED_PRELOADED_PARENT_FILE)
            .exists(),
        "the marker must survive an unconfirmed stop"
    );

    // Confirmed exit: parent dir, pool record, and marker all go.
    warm_claim::cleanup_consumed_preloaded_parent(&child_dir, true);
    assert!(
        !parent_dir.exists(),
        "confirmed child stop removes the consumed parent dir"
    );
    assert!(
        pool.load("standby-parent").is_err(),
        "confirmed child stop removes the parent's pool record"
    );
    assert!(
        !child_dir
            .join(warm_claim::CONSUMED_PRELOADED_PARENT_FILE)
            .exists(),
        "cleanup consumes its marker"
    );

    // NotFound-tolerant: a second cleanup (crash mid-claim shapes) is a no-op.
    warm_claim::cleanup_consumed_preloaded_parent(&child_dir, true);
}

#[test]
fn consumed_preloaded_parent_cleanup_refuses_a_marker_that_fails_name_validation() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _env = TestEnv::new();

    let child_dir = vm_state_dir("vm-child");
    std::fs::create_dir_all(&child_dir).unwrap();
    std::fs::write(
        child_dir.join(warm_claim::CONSUMED_PRELOADED_PARENT_FILE),
        "../escape\n",
    )
    .unwrap();

    warm_claim::cleanup_consumed_preloaded_parent(&child_dir, true);

    assert!(
        child_dir
            .join(warm_claim::CONSUMED_PRELOADED_PARENT_FILE)
            .exists(),
        "an invalid parent name must leave the marker and every path in place"
    );
    assert!(child_dir.is_dir());
}

/// A saved-state claim that forks a fresh child adopts no preloaded child,
/// so it must not record the preloaded-consumption marker.
#[test]
fn forked_saved_state_claim_marks_no_consumed_preloaded_parent() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let child = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("saved-state claim");
    let child_dir = vm_state_dir(&child.0);
    assert!(
        !child_dir
            .join(warm_claim::CONSUMED_PRELOADED_PARENT_FILE)
            .exists(),
        "only a claim that adopts a preloaded child consumes the parent's state dir; \
             a forked claim materializes its own"
    );
    drop(env);
}

/// A saved-state parent and a claim whose start config carries `durability`.
struct DurabilityClaim {
    _env: TestEnv,
    _home: tempfile::TempDir,
    store_root: tempfile::TempDir,
    checkpoints: CheckpointStore,
    snapshots: FsSnapshotStore,
    parent_id: CheckpointId,
    parent_meta: CheckpointMeta,
    pool: SupervisorStandbyPool,
    handle: StandbyHandle,
    claim: StandbyClaim,
}

impl DurabilityClaim {
    fn seed(durability: mvm_core::admission_durability::AdmissionDurability) -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let store_root = tempfile::tempdir().unwrap();
        let src = store_root.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), &src, true);
        let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let mut claim = admitted_child_claim(
            &src.join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );
        claim
            .start_config
            .as_mut()
            .expect("admitted claim carries a start config")
            .admission_durability = Some(durability);
        Self {
            _env: env,
            _home: home,
            store_root,
            checkpoints,
            snapshots,
            parent_id,
            parent_meta,
            pool,
            handle,
            claim,
        }
    }

    fn claim(
        &self,
        runner: &WorkloadRunner<MockDriver, KeyingSpawner, RecordingBrokerRegistrar>,
    ) -> std::result::Result<VmId, StandbyError> {
        let registry_path = self.store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&self.parent_meta);
        let ctx = ClaimContext {
            pool: &self.pool,
            checkpoints: &self.checkpoints,
            snapshots: &self.snapshots,
            anchor: &anchor,
            parent_checkpoint: &self.parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
            preloaded_child_lifecycle: None,
        };
        runner.claim_standby(&ctx, &self.handle, &self.claim)
    }
}

/// The child is prepared while the admission's audit sync is in flight, but
/// the VMM is not forked until it has finished: a restored guest runs the
/// moment the fork resumes it, so the fork is where a warm claim waits, as
/// activation is where a cold boot waits.
#[test]
fn a_warm_claim_prepares_beside_the_admission_sync_and_forks_after_it() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (release, held) = std::sync::mpsc::channel::<()>();
    let durability = mvm_core::admission_durability::AdmissionDurability::spawn(move || {
        held.recv().expect("released");
        Ok(())
    })
    .expect("spawn the sync");
    let fixture = DurabilityClaim::seed(durability);
    let (spawned_tx, spawned) = std::sync::mpsc::channel();
    let spawner = KeyingSpawner::default();
    *spawner.spawned.lock().unwrap() = Some(spawned_tx);
    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(driver.clone(), spawner, RecordingBrokerRegistrar::new());

    std::thread::scope(|scope| {
        let (done_tx, done) = std::sync::mpsc::channel();
        let (fixture, runner) = (&fixture, &runner);
        scope.spawn(move || {
            let _ = done_tx.send(fixture.claim(runner));
        });
        let child = spawned
            .recv_timeout(Duration::from_secs(60))
            .expect("the child endpoint is spawned while the sync is held");
        assert!(
            done.recv_timeout(Duration::from_millis(500)).is_err(),
            "the claim finished while the admission sync was still held"
        );
        assert!(
            driver.forked_children().is_empty(),
            "no child VMM is forked before the admission is durable"
        );
        release.send(()).expect("release the sync");
        let claimed = done
            .recv_timeout(Duration::from_secs(60))
            .expect("the claim finishes once the sync succeeds")
            .expect("the claim commits");
        assert_eq!(claimed.0, child);
        assert_eq!(driver.forked_children().len(), 1);
    });
}

/// A failed admission sync refuses the claim before the fork, and the claim's
/// cleanup returns the parent and removes the prepared child.
#[test]
fn a_failed_admission_sync_refuses_the_warm_claim_before_the_fork() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = DurabilityClaim::seed(
        mvm_core::admission_durability::AdmissionDurability::settled(Err(anyhow::anyhow!(
            "injected audit sync failure"
        ))),
    );
    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );

    let error = fixture
        .claim(&runner)
        .expect_err("a claim whose admission is not durable is refused");

    assert!(
        error.to_string().contains("injected audit sync failure"),
        "{error}"
    );
    assert!(driver.forked_children().is_empty(), "nothing was forked");
    let child = runner
        .spawner
        .seen_vm
        .lock()
        .unwrap()
        .clone()
        .expect("the child was prepared beside the sync");
    assert!(
        !vm_state_dir(&child).exists(),
        "the prepared child is removed"
    );
    assert!(
        fixture
            .pool
            .load("warm-parent")
            .unwrap()
            .state
            .is_claimable(),
        "the parent is returned to the pool"
    );
}

/// A traced saved-state claim names every step, the materialize steps
/// included, and its laps sum to the claim's wall time.
#[test]
fn a_traced_saved_state_claim_laps_every_step_in_order() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    env.set(mvm_core::launch_trace::PHASE_TIMING_ENV, "1");

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let before = mvm_core::launch_trace::recorded_laps().len();
    let started = Instant::now();
    mvm_core::launch_trace::lap_reset(None);
    runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("saved-state claim");
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;

    let laps = &mvm_core::launch_trace::recorded_laps()[before..];
    let names: Vec<&str> = laps.iter().map(|lap| lap.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "warm_claim.parent_verified",
            "warm_claim.runtime_verified",
            "warm_claim.plan_and_grant_binds",
            "warm_claim.child_identity_and_lock",
            "materialize_child.verify_content",
            "materialize_child.verify_lineage",
            "materialize_child.snapshot_copy",
            "materialize_child.chunk_rebuild",
            "warm_claim.child_materialized",
            "warm_claim.endpoint_ready",
            "warm_claim.broker_registered",
            "warm_claim.admission_durability",
            "warm_claim.child_forked",
            "warm_claim.identity_verified",
            "warm_claim.commit",
        ]
    );
    let lapped_ms: f64 = laps.iter().map(|lap| lap.ms).sum();
    assert!(
        lapped_ms <= wall_ms && wall_ms - lapped_ms < 5.0_f64.max(wall_ms * 0.05),
        "laps sum to {lapped_ms:.3} ms of a {wall_ms:.3} ms claim"
    );
    drop(env);
}

/// Not decrypting is not trusting: a sealed object changed after the
/// standby was prepared still refuses the claim and quarantines the parent.
#[test]
fn a_warm_claim_refuses_a_protected_parent_whose_sealed_object_changed() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let runner = claim_runner();
    let parent = ProtectedPreloadedParent::seed(&runner);
    let object = parent.chunk_objects().pop().expect("a sealed chunk object");
    let mut bytes = std::fs::read(&object).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    // A fresh inode, as an editor or an attacker replacing the file would
    // leave; the pool's other links keep the original bytes.
    std::fs::remove_file(&object).unwrap();
    std::fs::write(&object, &bytes).unwrap();

    let error = parent
        .claim(&runner)
        .expect_err("a tampered sealed object must refuse the claim");

    assert_eq!(
        error.to_string(),
        refuse(ClaimRefusal::ParentTampered).to_string()
    );
    assert!(
        parent.pool.load("warm-parent").is_err(),
        "a tampered parent is quarantined, never returned to the pool"
    );
    assert!(runner.driver.forked_children().is_empty());
}

#[test]
fn public_claim_requires_authenticated_vm_full_runtime_observation_before_child_effects() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for failure in [
        "filesystem-only",
        "missing-observation",
        "wrong-initramfs",
        "reordered-disks",
        "reforged-metadata",
    ] {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let source = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, mut parent) =
            seed_audited_parent(home.path(), source.path(), true);
        let rootfs_digest = materialized_parent_rootfs_digest(&checkpoints, &parent);
        let original_anchor = ClaimTestAnchor::audited(&parent);
        match failure {
            "filesystem-only" => parent.class = mvm_core::checkpoint::CheckpointClass::FsQuick,
            "missing-observation" => {
                parent
                    .content
                    .retain(|blob| blob.name != "runtime-artifacts.json");
            }
            "wrong-initramfs" | "reordered-disks" => {
                let path = checkpoints
                    .content_dir(&parent_id)
                    .join("runtime-artifacts.json");
                let mut observed: mvm_vmm::runtime_artifacts::RuntimeArtifacts =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                if failure == "wrong-initramfs" {
                    observed.initramfs.as_mut().unwrap().path =
                        source.path().join("other-initramfs");
                } else {
                    observed.disks.reverse();
                }
                std::fs::write(&path, serde_json::to_vec(&observed).unwrap()).unwrap();
                parent
                    .content
                    .iter_mut()
                    .find(|blob| blob.name == "runtime-artifacts.json")
                    .unwrap()
                    .sha256 = mvm_core::crypto::image_verify::sha256_file(&path).unwrap();
            }
            "reforged-metadata" => {
                let mvm_core::protocol::runtime_release::RuntimeLaunchBinding::CliAssembly(binding) =
                    parent.runtime_launch_binding.as_mut().unwrap()
                else {
                    panic!("source assembly fixture");
                };
                binding.overlay_path = source.path().join("unauthenticated-overlay");
            }
            _ => unreachable!(),
        }
        parent.meta_digest = parent.compute_meta_digest();
        checkpoints.write_meta(&parent).unwrap();
        // The first four cases are honestly recorded invalid captures. The
        // last re-seals changed metadata without changing its audit witness.
        let anchor = if failure == "reforged-metadata" {
            original_anchor
        } else {
            ClaimTestAnchor::audited(&parent)
        };
        let pool = SupervisorStandbyPool::at(home.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &home.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = home.path().join("vm-names.json");
        let claim = admitted_child_claim(
            &source.path().join("rootfs.ext4"),
            signed_child_plan_json(&rootfs_digest),
        );
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let error = runner
            .claim_standby(
                &ClaimContext {
                    pool: &pool,
                    checkpoints: &checkpoints,
                    snapshots: &snapshots,
                    anchor: &anchor,
                    parent_checkpoint: &parent_id,
                    registry_path: &registry_path,
                    grant_issuer: None,
                    preloaded_child_lifecycle: None,
                },
                &handle,
                &claim,
            )
            .expect_err(failure);
        if failure == "reforged-metadata" {
            assert!(pool.load("warm-parent").is_err(), "{failure}: {error}");
        } else {
            let message = error.to_string();
            assert!(
                message.contains(if failure == "filesystem-only" {
                    "requires a vm_full"
                } else {
                    "verify paused runtime"
                }),
                "{failure}: {message}"
            );
            assert!(pool.load("warm-parent").unwrap().state.is_claimable());
        }
        assert!(runner.driver.forked_children().is_empty(), "{failure}");
        assert!(
            runner.spawner.seen_vm.lock().unwrap().is_none(),
            "{failure}"
        );
        assert!(runner.broker.seen.lock().unwrap().is_none(), "{failure}");
        assert_eq!(orphan_child_dirs(), 0, "{failure}");
    }
}

#[test]
fn resident_claim_accepts_a_valid_signed_bundle_manifest_without_hashing_blobs() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let manifest_digest =
        mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string();
    let snapshot_id = parent_meta.snapshot_id.as_deref().unwrap();
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().unwrap();
    mvm_core::crypto::snapshot_sign::sign_manifest(
        &snapshots.root().join(snapshot_id),
        &manifest_digest,
        &identity.signing,
    )
    .unwrap();
    let parent = parent_meta.clone();

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent);
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    verify_resident_snapshot_manifest(&ctx, &parent)
        .expect("a host-signed resident bundle manifest must verify");

    std::fs::write(
        snapshots
            .root()
            .join(snapshot_id)
            .join(mvm_core::crypto::snapshot_sign::MANIFEST_SIGNATURE_FILENAME),
        b"tampered",
    )
    .unwrap();
    assert!(
        verify_resident_snapshot_manifest(&ctx, &parent).is_err(),
        "a tampered signed manifest must fail closed"
    );
    drop(env);
}

#[test]
fn resident_claim_creates_no_child_restore_bundle() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
    let snapshot_id = parent_meta.snapshot_id.as_deref().unwrap();
    let manifest_digest =
        mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string();
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().unwrap();
    mvm_core::crypto::snapshot_sign::sign_manifest(
        &snapshots.root().join(snapshot_id),
        &manifest_digest,
        &identity.signing,
    )
    .unwrap();

    crate::base::runtime_meta::record_from_start_config(
        "warm-parent",
        StartMode::Detached,
        &VmStartConfig {
            name: "warm-parent".into(),
            rootfs_path: src.path().join("rootfs.ext4").display().to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::unaudited();
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    let runner = WorkloadRunner::new(
        MockDriver::default().with_resident_handoff(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let child = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("resident claim");
    let child_dir = vm_state_dir(&child.0);
    assert!(child_dir.is_dir());
    assert!(
        !child_dir.join("rootfs.ext4").exists(),
        "resident claims must not materialize a child restore bundle"
    );
    assert_eq!(runner.driver.forked_children().len(), 1);
    reclaim_consumed_resident_checkpoint_at(
        checkpoints.root(),
        snapshots.root(),
        &parent_meta.id,
        parent_meta.snapshot_id.as_deref(),
    )
    .expect("resident checkpoint cleanup is idempotent");
    assert!(
        !checkpoints.dir_for(&parent_id).exists(),
        "committed resident claims must reclaim the consumed checkpoint payload"
    );
    assert!(
        !snapshots.root().join(snapshot_id).exists(),
        "committed resident claims must reclaim the consumed snapshot payload"
    );
    drop(env);
}

#[test]
fn resident_claim_marks_the_consumed_parent_for_stop_time_cleanup() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
    let snapshot_id = parent_meta.snapshot_id.as_deref().unwrap();
    let manifest_digest =
        mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string();
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().unwrap();
    mvm_core::crypto::snapshot_sign::sign_manifest(
        &snapshots.root().join(snapshot_id),
        &manifest_digest,
        &identity.signing,
    )
    .unwrap();

    crate::base::runtime_meta::record_from_start_config(
        "warm-parent",
        StartMode::Detached,
        &VmStartConfig {
            name: "warm-parent".into(),
            rootfs_path: src.path().join("rootfs.ext4").display().to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::unaudited();
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    let runner = WorkloadRunner::new(
        MockDriver::default().with_resident_handoff(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let child = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("resident claim");
    let child_dir = vm_state_dir(&child.0);
    let marker = std::fs::read_to_string(child_dir.join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE))
        .expect("a committed resident claim records its consumed parent");
    assert_eq!(
        marker.trim(),
        "warm-parent",
        "the marker names the standby parent the claim consumed"
    );
    assert!(
        vm_state_dir("warm-parent").is_dir(),
        "the parent dir must outlive the claim: the child's rootfs lives in it"
    );
    drop(env);
}

#[test]
fn consumed_resident_parent_cleanup_waits_for_confirmed_exit() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _env = TestEnv::new();

    let parent_dir = vm_state_dir("standby-parent");
    std::fs::create_dir_all(&parent_dir).unwrap();
    std::fs::write(parent_dir.join("rootfs.ext4"), b"resident-rootfs").unwrap();
    let pool = SupervisorStandbyPool::open().unwrap();
    pool.record(&idle_parent_handle(
        "standby-parent",
        std::path::Path::new("/tmp/control.sock"),
    ))
    .unwrap();
    let child_dir = vm_state_dir("vm-child");
    std::fs::create_dir_all(&child_dir).unwrap();
    warm_claim::record_consumed_resident_parent(&child_dir, "standby-parent").unwrap();

    // No confirmed exit: the child may still hold the parent dir's rootfs
    // open, so nothing may be removed.
    warm_claim::cleanup_consumed_resident_parent(&child_dir, false);
    assert!(
        parent_dir.is_dir(),
        "parent dir must survive an unconfirmed stop"
    );
    assert!(
        pool.load("standby-parent").is_ok(),
        "pool record must survive an unconfirmed stop"
    );
    assert!(
        child_dir
            .join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE)
            .exists(),
        "the marker must survive an unconfirmed stop"
    );

    // Confirmed exit: parent dir, pool record, and marker all go.
    warm_claim::cleanup_consumed_resident_parent(&child_dir, true);
    assert!(
        !parent_dir.exists(),
        "confirmed child stop removes the parent dir"
    );
    assert!(
        pool.load("standby-parent").is_err(),
        "confirmed child stop removes the parent's pool record"
    );
    assert!(
        !child_dir
            .join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE)
            .exists(),
        "cleanup consumes its marker"
    );

    // NotFound-tolerant: a second cleanup (crash-mid-claim shapes) is a no-op.
    warm_claim::cleanup_consumed_resident_parent(&child_dir, true);
}

#[test]
fn consumed_resident_parent_cleanup_refuses_a_marker_that_fails_name_validation() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _env = TestEnv::new();

    let child_dir = vm_state_dir("vm-child");
    std::fs::create_dir_all(&child_dir).unwrap();
    std::fs::write(
        child_dir.join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE),
        "../escape\n",
    )
    .unwrap();

    warm_claim::cleanup_consumed_resident_parent(&child_dir, true);

    assert!(
        child_dir
            .join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE)
            .exists(),
        "an invalid parent name must leave the marker and every path in place"
    );
    assert!(child_dir.is_dir());
}

#[test]
fn saved_state_claim_marks_no_consumed_resident_parent() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let child = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("saved-state claim");
    let child_dir = vm_state_dir(&child.0);
    assert!(
        !child_dir
            .join(warm_claim::CONSUMED_RESIDENT_PARENT_FILE)
            .exists(),
        "only a resident handoff consumes the parent's state dir; a saved-state \
             claim materializes its own"
    );
    drop(env);
}

/// Build a signed, admitted child plan whose bound image digest is the
/// parent's own verified rootfs content-address (claim-8 authority), the way
/// the CLI mints it before handing the runner the claim.
fn signed_child_plan_json(image_sha256: &str) -> String {
    signed_child_plan_json_with_verbs(image_sha256, None)
}

fn signed_child_plan_json_named(image_sha256: &str, name: &str) -> String {
    let mut plan = mvm_core::plan::plan_from_admitted_json(&signed_child_plan_json(image_sha256))
        .expect("signed child fixture");
    plan.image.name = name.to_string();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test"))
        .expect("named signed child")
}

/// Record `policy` the way admission records a resolved network policy:
/// as a policy asset identity carrying its content digest.
fn record_policy_identity(plan: &mut ExecutionPlan, policy: &NetworkPolicy) {
    plan.asset_identities.push(
        mvm_core::plan::AssetIdentity::new(
            mvm_core::plan::AssetKind::Policy,
            "tenant-x:child",
            mvm_core::policy::network_policy::content_sha256(policy),
        )
        .unwrap(),
    );
}

/// A child plan admitted under `policy`, signed.
fn signed_child_plan_json_for_policy(
    image_sha256: &str,
    grants: Option<mvm_contract::grants::Grants>,
    policy: &NetworkPolicy,
) -> String {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("tenant-x")
        .grants(grants)
        .build();
    plan.image.sha256 = image_sha256.to_string();
    record_policy_identity(&mut plan, policy);
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap()
}

fn signed_child_plan_json_with_grants(
    image_sha256: &str,
    grants: Option<mvm_contract::grants::Grants>,
) -> String {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("tenant-x")
        .grants(grants)
        .build();
    plan.image.sha256 = image_sha256.to_string();
    record_policy_identity(&mut plan, &egress_allowing_policy());
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap()
}

fn signed_child_plan_json_with_verbs(
    image_sha256: &str,
    agent_verbs: Option<Vec<VerbId>>,
) -> String {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("tenant-x")
        .build();
    plan.image.sha256 = image_sha256.to_string();
    plan.agent_verbs = agent_verbs;
    record_policy_identity(&mut plan, &egress_allowing_policy());
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap()
}

#[test]
fn admitted_network_limits_are_extracted_without_defaulting() {
    let expected = mvm_core::plan::NetworkLimits::builder()
        .max_tcp_flows(7)
        .max_udp_associations(5)
        .max_dns_bindings(3)
        .max_ingress_listeners(2)
        .build()
        .unwrap();
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.network_limits = expected;
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let json = serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap();

    assert_eq!(admitted_network_limits(Some(&json)).unwrap(), expected);
    assert_eq!(
        admitted_network_limits(None).unwrap(),
        mvm_core::plan::NetworkLimits::default()
    );
}

#[derive(Default)]
struct TestChildGrantIssuer {
    seen_child: Mutex<Option<String>>,
}

impl ChildGrantIssuer for TestChildGrantIssuer {
    fn issue(&self, config: &VmStartConfig) -> Result<Option<VerbGrantEnvelope>> {
        let plan_json = config.plan_json.as_deref().context("child plan missing")?;
        let plan = mvm_core::plan::plan_from_admitted_json(plan_json)?;
        let verbs = plan.agent_verbs.unwrap_or_default();
        let drive = plan.grants.and_then(|grants| grants.drive);
        if verbs.is_empty() && drive.is_none() {
            return Ok(None);
        }
        *self.seen_child.lock().unwrap() = Some(config.name.clone());
        Ok(Some(VerbGrantEnvelope {
            pubkey_hex: "ab".repeat(32),
            plan_nonce_hex: plan.nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: mvm_core::plan::VerbGrant {
                session_id: config.name.clone(),
                plan_nonce: plan.nonce,
                not_after: plan.valid_until,
                verbs,
                drive,
                application_terminal: None,
                sig: vec![3u8; 64],
            },
        }))
    }
}

fn idle_parent_handle(id: &str, control_socket: &Path) -> StandbyHandle {
    StandbyHandle {
        id: id.to_string(),
        template_id: None,
        control_socket: control_socket.display().to_string(),
        pid: 0,
        kernel_sha256: "k".repeat(64),
        vcpus: 2,
        mem_mib: 512,
        binding_nonce: "b".repeat(64),
        spawned_unix_secs: 1,
        state: StandbyState::Idle,
        image_sha256: None,
        root_strategy: Default::default(),
        parent_checkpoint: None,
        preloaded_child_vm_name: None,
        vsock_egress: false,
    }
}

fn admitted_child_claim(rootfs: &Path, plan_json: String) -> StandbyClaim {
    StandbyClaim {
        start_config: Some(VmStartConfig {
            name: "unused-cold".into(),
            rootfs_path: rootfs.display().to_string(),
            tenant_id: Some("tenant-x".into()),
            ..checked_source_config("unused-cold", rootfs.display().to_string())
        }),
        rootfs_path: rootfs.display().to_string(),
        tenant_id: "tenant-x".into(),
        audit_dir: rootfs.with_file_name("audit"),
        gateway_audit_socket: rootfs.with_file_name("gw-audit.sock"),
        gateway_events_socket: None,
        plan_json,
        audit_context: None,
        network_policy: egress_allowing_policy(),
    }
}

/// The positive path: `claim_standby` forks a clean, audited parent into a
/// fresh, admitted child that carries a fresh identity on every axis the fork
/// controls, its own isolated endpoint, the overlay gate a cold boot runs, and
/// a fresh VMGenID delivered with the boot.
/// Seed an audited parent and claim it with `driver`, the claim's start
/// config carrying `volumes`.
fn claim_with_volumes(
    driver: MockDriver,
    volumes: Vec<mvm_core::vm_backend::VmVolume>,
) -> (
    std::result::Result<VmId, StandbyError>,
    Vec<mvm_vmm::mock::MockChildFork>,
    Vec<mvm_vmm::mock::DeliveredChildIdentity>,
) {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let mut claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    if let Some(start) = claim.start_config.as_mut() {
        start.volumes = volumes;
    }
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };
    let result = runner.claim_standby(&ctx, &handle, &claim);
    (
        result,
        runner.driver.forked_children(),
        runner.driver.delivered_child_identities(),
    )
}

fn read_only_mount(image: &str, guest: &str) -> mvm_core::vm_backend::VmVolume {
    mvm_core::vm_backend::VmVolume {
        host: "/host/project".into(),
        guest: guest.into(),
        materialized_image: Some(image.into()),
        volume_label: Some("mvmmnt0".into()),
        read_only: true,
        ..Default::default()
    }
}

/// A claim's read-only mount reaches the child through the slot its parent
/// booted: the driver points that slot at the launch's own image before the
/// child resumes, and the guest is told to mount it — read-only, by label —
/// before the claim commits.
#[test]
fn a_claim_attaches_its_read_only_mount_to_the_parents_slot_before_resume() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (result, forks, delivered) = claim_with_volumes(
        MockDriver::default().with_late_volume_slots(4),
        vec![read_only_mount("/cache/project.ext4", "/data")],
    );
    result.expect("a slotted parent serves a read-only mount");
    assert_eq!(forks.len(), 1);
    assert_eq!(
        forks[0].late_volumes,
        vec![crate::driver::LateVolumeAttach {
            // Rootfs first, then the authenticated runtime overlay and its
            // verity sidecar the claim inherits from the parent's binding,
            // so the parent's first late-volume slot is 3.
            slot: 3,
            source: PathBuf::from("/cache/project.ext4"),
        }]
    );
    assert_eq!(delivered.len(), 1);
    let mounted = &delivered[0].volumes;
    assert_eq!(mounted.len(), 1);
    assert_eq!(mounted[0].mountpoint, "/data");
    assert!(mounted[0].read_only);
    assert_eq!(mounted[0].label.as_deref(), Some("mvmmnt0"));
    assert_eq!(mounted[0].device.as_deref(), Some("/dev/vdd"));
}

/// A backend whose parents boot no slots cannot attach a volume, so the
/// claim is refused before any child is forked.
#[test]
fn a_parent_without_slots_refuses_a_volume_claim_before_forking() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let (result, forks, _) = claim_with_volumes(
        MockDriver::default(),
        vec![read_only_mount("/cache/project.ext4", "/data")],
    );
    let err = result.expect_err("no slot can serve the volume");
    assert!(err.to_string().contains("late-volume slots"), "{err}");
    assert!(
        forks.is_empty(),
        "nothing may be forked for a refused claim"
    );
}

/// A guest that does not report mounting every attached volume is refused
/// rather than committed: its workload would start without its data.
#[test]
fn a_child_that_did_not_mount_its_volumes_is_refused() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut outcome = PostRestoreOutcome {
        acknowledged: true,
        detail: None,
        reseeded: true,
        clock_resynced: true,
        reseed_shortfall: None,
        seccomp_tier: None,
        volumes_mounted: None,
    };
    let admitted_tier =
        mvm_core::plan::plan_from_admitted_json(&signed_child_plan_json(&"0".repeat(64)))
            .unwrap()
            .admission_profile
            .seccomp_tier;
    outcome.seccomp_tier = Some(admitted_tier.into());
    let (result, _, _) = claim_with_volumes(
        MockDriver::default()
            .with_late_volume_slots(4)
            .with_child_identity(outcome),
        vec![read_only_mount("/cache/project.ext4", "/data")],
    );
    let err = result.expect_err("an unmounted volume must refuse the claim");
    assert!(err.to_string().contains("mounted none of the 1"), "{err}");
}

#[test]
fn claim_produces_fresh_identity_and_isolated_endpoint() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_with_verbs(
            &parent_digest,
            Some(vec![VerbId::new("run-entrypoint").unwrap()]),
        ),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let grant_issuer = TestChildGrantIssuer::default();
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: Some(&grant_issuer),
        preloaded_child_lifecycle: None,
    };

    let mut opted_in = claim.clone();
    let config = opted_in.start_config.as_mut().unwrap();
    let plan = mvm_core::plan::plan_from_admitted_json(&claim.plan_json).unwrap();
    let installation = serde_json::from_str("\"bdf189ab-9a9a-440b-a266-e95b19e58a5e\"").unwrap();
    let identity =
        mvm_core::crypto::entrypoint_delegation::test_support::identity([3; 32], installation);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected =
        mvm_core::vm_backend::caller_registration::CallerRegistration::challenge_for_plan(
            &config.name,
            &plan,
            identity,
            now,
        )
        .unwrap();
    let proof =
        mvm_core::crypto::entrypoint_delegation::test_support::proof([3; 32], &expected, now)
            .unwrap();
    config.caller_registration = Some(
        mvm_core::vm_backend::caller_registration::CallerRegistration {
            vm: config.name.clone(),
            expected,
            proof,
        },
    );
    assert!(runner.claim_standby(&ctx, &handle, &opted_in).is_err());
    assert_eq!(pool.load("warm-parent").unwrap().state, StandbyState::Idle);
    assert!(
        !registry_path.exists(),
        "refusal must precede child identity allocation"
    );
    assert!(runner.driver.forked_children().is_empty());
    assert!(runner.spawner.seen_vm.lock().unwrap().is_none());

    let child = runner.claim_standby(&ctx, &handle, &claim).expect("claim");

    // The child records the runtime metadata a cold boot records, naming
    // its own materialized rootfs, so a step checkpoint of it resolves.
    let meta = crate::base::runtime_meta::read(&child.0)
        .expect("read child runtime metadata")
        .expect("a claimed child records its runtime metadata");
    assert_eq!(
        meta.rootfs_path.map(PathBuf::from),
        Some(vm_state_dir(&child.0).join("rootfs.ext4"))
    );

    // Fresh identity: the child differs from the parent and gets a fresh name.
    assert_ne!(child.0, handle.id, "child VmId must differ from the parent");
    assert!(
        child.0.starts_with("vm-"),
        "child gets a fresh registry name: {}",
        child.0
    );

    // Surface 5: the child's endpoint is keyed on its own fresh id, and the
    // factory parent never got one.
    let seen = runner.spawner.seen_vm.lock().unwrap().clone();
    assert_eq!(
        seen.as_deref(),
        Some(child.0.as_str()),
        "the endpoint is keyed on the child's own id"
    );
    assert_ne!(
        seen.as_deref(),
        Some(handle.id.as_str()),
        "the parent, a factory, gets no substitution endpoint"
    );

    // Surface 3: the fork delivered a fresh VMGenID bound to the child's
    // content-address, at the boot call — before any guest randomness consumer
    // runs — so the child's CSPRNG cannot share the parent's state.
    let forks = runner.driver.forked_children();
    assert_eq!(forks.len(), 1, "exactly one child fork");
    assert_eq!(forks[0].child_vm_name, child.0);
    assert_ne!(
        forks[0].genid.token, [0u8; GENID_BYTES],
        "a clean parent's baseline token is zero; the child gets a fresh non-zero one"
    );
    assert_eq!(
        forks[0].genid.content_hash, parent_digest,
        "the fresh token is bound to the child's content-address"
    );

    // The fork alone only resumes the child on the parent's saved memory, so
    // the claim also handed that same token to the child's guest agent and
    // committed only once the guest reported it had rotated onto it.
    let delivered = runner.driver.delivered_child_identities();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].child_vm_name, child.0);
    assert_eq!(delivered[0].token, forks[0].genid.token);
    // The parent booted with no plan and so holds no seccomp tier; the
    // child's comes from the plan this claim was admitted under, on the
    // same handshake, before the claim commits.
    let plan = mvm_core::plan::plan_from_admitted_json(&claim.plan_json).unwrap();
    assert_eq!(
        delivered[0].seccomp_tier,
        Some(plan.admission_profile.seccomp_tier.into()),
        "the claimed child is handed its own plan's seccomp tier"
    );
    let delivered_grant = delivered[0]
        .grant_envelope
        .as_ref()
        .expect("the child grant rides the post-restore handshake");
    assert_eq!(delivered_grant.grant.session_id, child.0);
    assert_eq!(
        delivered_grant.grant.verbs,
        vec![VerbId::new("run-entrypoint").unwrap()]
    );
    assert_eq!(
        grant_issuer.seen_child.lock().unwrap().as_deref(),
        Some(child.0.as_str())
    );

    // The runner-side overlay-contract gate ran on the materialized child:
    // its dir carries the overlay sidecar the clone rode plus the rootfs.
    let child_dir = mvm_core::config::vm_state_dir(&child.0);
    assert!(
        child_dir
            .join(mvm_build::builder_vm::SIDECAR_FILENAME)
            .exists(),
        "the overlay sidecar rode the clone into the child dir"
    );
    assert!(
        child_dir.join("rootfs.ext4").exists(),
        "the child rootfs was materialized from the parent's content"
    );

    // The parent was reserved (marked Claimed) atomically, never left idle for
    // a second claim to grab.
    assert_eq!(
        pool.load("warm-parent").unwrap().state,
        StandbyState::Claimed,
        "the parent is reserved so a concurrent claim cannot double-claim it"
    );
}

/// Where a claimed child's egress *destinations* come from: its own launch
/// policy, threaded into its own endpoint at claim time.
///
/// This is what makes keying the pool on the enablement boolean sound. The
/// parent boots only whether a guest egress client starts; every host:port a
/// workload may reach is resolved here, per child, from that child's policy —
/// so a shared parent has no launch's allow-list to hand to the next claim.
#[test]
fn a_claimed_childs_endpoint_gets_its_own_launchs_allow_list() {
    use mvm_core::network_policy::HostPort;

    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let mut handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    // The parent was warmed for an egress-enabled launch, so it is claimable
    // by one.
    handle.vsock_egress = true;
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    let policy = NetworkPolicy::allow_list(vec![
        HostPort::new("api.example.com", 443),
        HostPort::new("logs.example.com", 443),
    ]);
    let mut claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_for_policy(&parent_digest, None, &policy),
    );
    claim.network_policy = policy.clone();

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("claim an egress-enabled parent");

    let seen = runner.spawner.seen.lock().unwrap();
    let recorded = seen.as_ref().expect("the child got its own endpoint");
    assert_eq!(
        recorded.policy, policy,
        "the child's endpoint must enforce the launch's own allow-list, not the parent's"
    );
}

/// Seed an audited egress-capable parent and return what a claim needs.
struct EgressClaimFixture {
    _home: tempfile::TempDir,
    _env: TestEnv,
    store_root: tempfile::TempDir,
    src: tempfile::TempDir,
    checkpoints: CheckpointStore,
    snapshots: FsSnapshotStore,
    parent_id: CheckpointId,
    parent_digest: String,
    anchor: ClaimTestAnchor,
}

impl EgressClaimFixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
        let anchor = ClaimTestAnchor::audited(&parent_meta);
        Self {
            _home: home,
            _env: env,
            store_root,
            src,
            checkpoints,
            snapshots,
            parent_id,
            parent_digest,
            anchor,
        }
    }

    /// Claim an idle parent recorded with `parent_boots_egress_client`.
    fn claim(
        &self,
        parent_boots_egress_client: bool,
        claim: &StandbyClaim,
    ) -> (
        std::result::Result<VmId, StandbyError>,
        Option<NetworkPolicy>,
    ) {
        let pool = SupervisorStandbyPool::at(self.store_root.path().join("pool"));
        let mut handle =
            idle_parent_handle("warm-parent", &self.store_root.path().join("control.sock"));
        handle.vsock_egress = parent_boots_egress_client;
        pool.record(&handle).unwrap();
        let registry_path = self.store_root.path().join("vm-names.json");
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &self.checkpoints,
            snapshots: &self.snapshots,
            anchor: &self.anchor,
            parent_checkpoint: &self.parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
            preloaded_child_lifecycle: None,
        };
        let result = runner.claim_standby(&ctx, &handle, claim);
        let seen = runner
            .spawner
            .seen
            .lock()
            .unwrap()
            .as_ref()
            .map(|recorded| recorded.policy.clone());
        (result, seen)
    }

    fn rootfs(&self) -> PathBuf {
        self.src.path().join("rootfs.ext4")
    }
}

fn api_allow_list() -> NetworkPolicy {
    use mvm_core::network_policy::HostPort;
    NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)])
}

fn api_egress_grant() -> mvm_contract::grants::Grants {
    use mvm_core::network_policy::HostPort;
    mvm_contract::grants::Grants {
        egress: Some(mvm_contract::grants::EgressGrant {
            allow: vec![HostPort::new("api.example.com", 443)],
        }),
        ..Default::default()
    }
}

/// The policy the claim installs must be the one the claiming plan
/// recorded. A different policy beside a valid plan is refused before the
/// child's endpoint is spawned, so no endpoint ever enforces it.
#[test]
fn a_claim_carrying_a_policy_its_plan_did_not_record_is_refused_before_any_endpoint() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = EgressClaimFixture::new();
    let mut claim = admitted_child_claim(
        &fixture.rootfs(),
        signed_child_plan_json_for_policy(&fixture.parent_digest, None, &api_allow_list()),
    );
    claim.network_policy = NetworkPolicy::unrestricted();

    let (result, endpoint_policy) = fixture.claim(true, &claim);

    let err = result.expect_err("a policy the plan did not record must refuse the claim");
    assert!(
        err.to_string()
            .contains("is not the policy its admitted plan recorded"),
        "{err}"
    );
    assert_eq!(
        endpoint_policy, None,
        "no endpoint may run a refused policy"
    );
}

/// A parent booted with the egress client carries no destinations of its
/// own, so the claiming plan's admitted allow-list is what bounds the child
/// — and that same plan's policy is what its endpoint enforces.
#[test]
fn an_egress_parent_serves_a_child_under_its_own_admitted_allow_list() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = EgressClaimFixture::new();
    let policy = api_allow_list();
    let mut claim = admitted_child_claim(
        &fixture.rootfs(),
        signed_child_plan_json_for_policy(
            &fixture.parent_digest,
            Some(api_egress_grant()),
            &policy,
        ),
    );
    claim.network_policy = policy.clone();

    let (result, endpoint_policy) = fixture.claim(true, &claim);

    result.expect("an egress parent serves an egress-granted child");
    assert_eq!(endpoint_policy, Some(policy));
}

/// A parent booted without the egress client is still sealed deny-all, so
/// an egress-granted child is refused rather than restored into a guest
/// that has no client to carry its flows.
#[test]
fn a_parent_without_the_egress_client_refuses_an_egress_granted_child() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let fixture = EgressClaimFixture::new();
    let policy = api_allow_list();
    let mut claim = admitted_child_claim(
        &fixture.rootfs(),
        signed_child_plan_json_for_policy(
            &fixture.parent_digest,
            Some(api_egress_grant()),
            &policy,
        ),
    );
    claim.network_policy = policy;

    let (result, endpoint_policy) = fixture.claim(false, &claim);

    let err = result.expect_err("a deny-all parent bounds the child to no egress");
    assert!(err.to_string().contains("api.example.com"), "{err}");
    assert_eq!(endpoint_policy, None);
}

/// A channel set described independently of which VM owns it: each port's
/// number, direction, and where its host socket sits *relative to that VM's
/// own* socket and state dirs. Two VMs' descriptions compare equal exactly
/// when they carry the same channels wired to the same per-VM locations —
/// and the relativization keeps that true even when one VM's name is long
/// enough to push its sockets into the short hashed namespace.
fn channel_shape(
    channels: &[crate::driver::VsockPort],
    vm: &str,
) -> Vec<(u32, crate::driver::VsockDirection, String)> {
    // Both roots collapse to one label on purpose. A VM's socket root is its
    // state dir until the path grows long enough to overflow the Unix-socket
    // limit, at which point it becomes a short hashed namespace instead —
    // which of the two a given VM landed on is that fallback's business, not
    // a difference in the channel set. Labelling them apart would report two
    // VMs as carrying different channels whenever only one crossed the limit.
    // Longest root first so an equal-or-nested root cannot mask a deeper one.
    let mut roots = [mvm_core::config::vm_socket_dir(vm), vm_state_dir(vm)];
    roots.sort_by_key(|r| std::cmp::Reverse(r.as_os_str().len()));
    channels
        .iter()
        .map(|p| {
            let where_ = roots
                .iter()
                .find_map(|root| {
                    p.host_uds
                        .strip_prefix(root)
                        .ok()
                        .map(|rest| format!("<vm>/{}", rest.display()))
                })
                .unwrap_or_else(|| p.host_uds.display().to_string());
            (p.service.port(), p.direction, where_)
        })
        .collect()
}

/// One cold boot and one warm claim on the same runner, so the two host
/// channel sets the driver was handed can be compared directly.
struct ColdAndWarm {
    driver: MockDriver,
    broker: Option<RecordedBroker>,
    cold_vm: String,
    child: VmId,
    /// The signed plan the claim admitted the child under.
    claim_plan_json: String,
    /// Held so the assertions resolve the same `MVM_HOME` the run did.
    /// Declaration order is drop order: the home dir goes, then the env is
    /// restored, then the lock is released.
    _home: tempfile::TempDir,
    _env: TestEnv,
    _lock: std::sync::MutexGuard<'static, ()>,
}

/// Boot an admitted workload cold, then claim a child off a clean audited
/// parent seeded from the same rootfs — both through one runner, with the
/// endpoint spawner that keys its socket on the VM name (as the real one
/// does), so the two channel sets differ only where the VM identity does.
///
/// The isolated `MVM_HOME` is handed back alive, so the caller's assertions
/// resolve the same per-VM paths the run wrote.
fn cold_boot_then_claim() -> ColdAndWarm {
    let lock = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
    let rootfs = src.path().join("rootfs.ext4");

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );

    // The cold boot: an admitted launch (tenant set), so it carries the
    // broker channel a claimed child must also get.
    let cold_vm = "cold-admitted-workload".to_string();
    mapping_start(
        &runner,
        &VmStartConfig {
            name: cold_vm.clone(),
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some("/img/kernel".into()),
            tenant_id: Some("tenant-x".into()),
            network_policy: egress_allowing_policy(),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        },
    )
    .expect("the cold admitted workload boots");

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let claim = admitted_child_claim(&rootfs, signed_child_plan_json(&parent_digest));

    let child = runner
        .claim_standby(
            &ClaimContext {
                pool: &pool,
                checkpoints: &checkpoints,
                snapshots: &snapshots,
                anchor: &anchor,
                parent_checkpoint: &parent_id,
                registry_path: &registry_path,
                grant_issuer: None,
                preloaded_child_lifecycle: None,
            },
            &handle,
            &claim,
        )
        .expect("claim");

    ColdAndWarm {
        driver: runner.driver.clone(),
        broker: runner.broker.seen.lock().unwrap().take(),
        cold_vm,
        child,
        claim_plan_json: claim.plan_json.clone(),
        _home: home,
        _env: env,
        _lock: lock,
    }
}

/// The fork carries the plan the claim admitted, so a driver whose child
/// is owned by a supervisor can hand it the bounds to enforce. A resident
/// parent booted with none of its own.
#[test]
fn claim_hands_the_fork_the_plan_the_child_was_admitted_under() {
    let run = cold_boot_then_claim();
    let forks = run.driver.forked_children();
    assert_eq!(forks.len(), 1, "exactly one child fork");
    assert_eq!(
        forks[0].admitted_plan.as_deref(),
        Some(run.claim_plan_json.as_str())
    );
}

/// A claimed child must reach the same host-side channels a cold-booted
/// workload does. Asserted as an equality against the cold boot's own set
/// rather than as a list of ports: a channel added to the workload's set and
/// not to the claim's would leave a claimed child silently less capable than
/// a cold-booted one, and only an equality catches that.
#[test]
fn claim_hands_the_child_the_same_host_channels_a_cold_boot_gets() {
    use mvm_agentd::vsock::{GUEST_AGENT_PORT, WORKLOAD_EXIT_PORT};

    let run = cold_boot_then_claim();

    let booted = run.driver.booted_specs();
    assert_eq!(booted.len(), 1, "one cold workload boot");
    let cold = &booted[0].vsock;

    // Non-vacuity: the fixture must actually exercise all four standing
    // channels, or "the two match" would say nothing. These are the three
    // the fork used to drop, plus the agent RPC.
    let ports: Vec<u32> = cold.iter().map(|p| p.service.port()).collect();
    for (port, what) in [
        (EGRESS_PORT, "the gated egress endpoint"),
        (BROKER_PORT, "the admitted host-services broker"),
        (WORKLOAD_EXIT_PORT, "the guest's exit-code report"),
        (GUEST_AGENT_PORT, "the agent RPC"),
    ] {
        assert!(
            ports.contains(&port),
            "fixture must exercise {what} (port {port}), got {ports:?}"
        );
    }

    let forks = run.driver.forked_children();
    assert_eq!(forks.len(), 1, "exactly one child fork");
    assert_eq!(
        channel_shape(&forks[0].channels, &run.child.0),
        channel_shape(cold, &run.cold_vm),
        "a claimed child must be handed exactly the channel set a cold boot wires"
    );
}

/// The child's broker is registered on the very socket its `BROKER_PORT`
/// channel relays to, and under the claim's tenant — otherwise the guest
/// dials a path nothing is bound to and admitted host services are silently
/// unavailable, a real degradation versus a cold boot.
#[test]
fn claim_registers_the_childs_broker_on_the_socket_it_wired() {
    let run = cold_boot_then_claim();

    let broker = run
        .broker
        .as_ref()
        .expect("a claimed child registers a host-services broker");
    assert_eq!(
        broker.vm_name, run.child.0,
        "the broker is registered for the child's own id, never the parent's"
    );
    assert_eq!(broker.tenant.as_deref(), Some("tenant-x"));
    assert!(broker.services.is_empty());

    let wired = run.driver.forked_children()[0]
        .channels
        .iter()
        .find(|p| p.service.port() == BROKER_PORT)
        .map(|p| p.host_uds.clone())
        .expect("the child carries a broker channel");
    assert_eq!(
        broker.broker_listen_socket.as_ref(),
        Some(&wired),
        "the broker must bind the same path the child's BROKER_PORT relays to"
    );
    assert_eq!(
        wired,
        mvm_core::config::vm_vsock_port_socket_at(&vm_state_dir(&run.child.0), BROKER_PORT),
        "the broker socket lives under the child's own state dir"
    );
}

/// Count child (`vm-*`) dirs left under the VM state root — a failed claim
/// must leave none.
fn orphan_child_dirs() -> usize {
    match std::fs::read_dir(vms_dir()) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.path().is_dir() && e.file_name().to_string_lossy().starts_with("vm-"))
            .count(),
        Err(_) => 0,
    }
}

/// What a claim driven against a scripted post-restore answer left behind.
struct HandshakeClaimOutcome {
    result: std::result::Result<VmId, StandbyError>,
    /// The driver the claim ran on — an `Arc`-shared clone, so the fork,
    /// delivery, and kill records survive the runner it was moved into.
    driver: MockDriver,
    /// `None` once the claim dropped the parent from the pool.
    parent_state: Option<StandbyState>,
    orphan_child_dirs: usize,
    /// Records every `ConsoleStreamer::start`/`stop` the claim made, so a
    /// test can prove the console follower was wired into `claim_standby`
    /// itself, not only the cold-boot path — every existing caller of this
    /// helper ignores the field, so threading it through costs them nothing.
    console_streamer: Arc<RecordingConsoleStreamer>,
}

/// Drive one full claim over a clean audited parent against `driver`, whose
/// `deliver_child_identity` answer the caller has scripted. Everything the
/// claim touches (MVM_HOME, stores, pool, registry) is fresh per call, so the
/// handshake outcomes are independent of each other.
fn claim_with_scripted_handshake(driver: MockDriver) -> HandshakeClaimOutcome {
    claim_with_scripted_handshake_and_grant(driver, None, None)
}

struct GateCheckingConsoleStreamer(Arc<RecordingConsoleStreamer>);

impl ConsoleStreamer for GateCheckingConsoleStreamer {
    fn start(&self, capture: &ConsoleCapture<'_>) {
        assert!(
            crate::vm::instance_snapshot::try_lock_resume(capture.vm_name)
                .unwrap()
                .is_none(),
            "child publication must hold the lifecycle gate"
        );
        self.0.start(capture);
    }

    fn stop(&self, name: &str) {
        assert!(
            crate::vm::instance_snapshot::try_lock_resume(name)
                .unwrap()
                .is_none(),
            "failed-claim teardown must hold the lifecycle gate"
        );
        assert!(
            vm_state_dir(name).exists(),
            "cleanup has not yet removed child state"
        );
        self.0.stop(name);
    }
}

fn claim_with_scripted_handshake_and_grant(
    driver: MockDriver,
    agent_verbs: Option<Vec<VerbId>>,
    grant_issuer: Option<&dyn ChildGrantIssuer>,
) -> HandshakeClaimOutcome {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_with_verbs(&parent_digest, agent_verbs),
    );

    let probe = driver.clone();
    let streamer = Arc::new(RecordingConsoleStreamer::default());
    let runner = WorkloadRunner::new(
        driver,
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    )
    .with_console_streamer(Arc::new(GateCheckingConsoleStreamer(streamer.clone())));
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer,
        preloaded_child_lifecycle: None,
    };

    let result = runner
        .claim_standby_owned(&ctx, &handle, &claim)
        .map(|owned| {
            let (child, lifecycle) = owned.into_parts();
            assert!(
                crate::vm::instance_snapshot::try_lock_resume(&child.0)
                    .unwrap()
                    .is_none(),
                "the returned child stays gated until caller custody capture"
            );
            lifecycle
                .as_ref()
                .expect("a claim without a held gate returns its own")
                .require_name(&child.0)
                .unwrap();
            drop(lifecycle);
            assert!(
                crate::vm::instance_snapshot::try_lock_resume(&child.0)
                    .unwrap()
                    .is_some(),
                "the caller releases the original gate"
            );
            child
        });
    if result.is_err() {
        let retained = pool
            .load("warm-parent")
            .ok()
            .is_some_and(|parent| parent.state == StandbyState::Claimed);
        for fork in probe.forked_children() {
            assert_eq!(vm_state_dir(&fork.child_vm_name).exists(), retained);
            assert!(
                crate::vm::instance_snapshot::try_lock_resume(&fork.child_vm_name)
                    .unwrap()
                    .is_some(),
                "failed-claim cleanup must release the gate after rollback"
            );
        }
    }
    HandshakeClaimOutcome {
        result,
        driver: probe,
        parent_state: pool.load("warm-parent").ok().map(|h| h.state),
        orphan_child_dirs: orphan_child_dirs(),
        console_streamer: streamer,
    }
}

#[test]
fn failed_handshake_and_failed_kill_retain_child_and_parent_reservation() {
    let out = claim_with_scripted_handshake(
        MockDriver::default()
            .with_unreachable_child_agent()
            .with_failing_kill(),
    );
    let error = out
        .result
        .expect_err("failed handshake must refuse the claim");
    assert!(matches!(error, StandbyError::StopUnconfirmed(_)), "{error}");
    assert!(error.to_string().contains("child stop unconfirmed"));
    assert!(error.to_string().contains("mock child termination failed"));
    assert_eq!(out.parent_state, Some(StandbyState::Claimed));
    assert_eq!(
        out.orphan_child_dirs, 1,
        "uncertain child state must remain"
    );
    assert!(out.driver.killed_vms().is_empty());
    assert!(out.console_streamer.stopped.lock().unwrap().is_empty());
}

#[test]
fn failed_handshake_and_unavailable_handle_retain_child_and_parent_reservation() {
    let out = claim_with_scripted_handshake(
        MockDriver::default()
            .with_unreachable_child_agent()
            .refusing_attach(),
    );
    let error = out.result.expect_err("attach failure is unknown");
    assert!(matches!(error, StandbyError::StopUnconfirmed(_)), "{error}");
    assert!(error.to_string().contains("child stop unconfirmed"));
    assert_eq!(out.parent_state, Some(StandbyState::Claimed));
    assert_eq!(out.orphan_child_dirs, 1);
    assert!(out.driver.killed_vms().is_empty());
}

#[test]
fn a_parent_this_host_cannot_restore_is_dropped_not_returned_to_rotation() {
    // A standby another VMM version captured: every claim would fail the
    // same way, so returning it to claimable would cost each later launch a
    // failed fork until its TTL.
    let out = claim_with_scripted_handshake(
        MockDriver::default().refusing_fork_as_unrestorable("snapshot format v8.0.0"),
    );

    let err = out
        .result
        .expect_err("an unrestorable parent cannot be claimed");
    assert!(matches!(err, StandbyError::Unrestorable(_)), "{err}");
    assert_eq!(
        out.parent_state, None,
        "the parent must be dropped from the pool, not released"
    );
    assert_eq!(
        out.orphan_child_dirs, 0,
        "the child dir is still cleaned up"
    );
}

#[test]
fn claim_refuses_a_grant_bearing_plan_before_fork_when_no_issuer_is_configured() {
    let out = claim_with_scripted_handshake_and_grant(
        MockDriver::default(),
        Some(vec![VerbId::new("run-entrypoint").unwrap()]),
        None,
    );

    let err = out.result.expect_err("the missing issuer must fail closed");
    assert!(err.to_string().contains("no child grant issuer"));
    assert!(
        out.driver.forked_children().is_empty(),
        "grant issuance is checked before a child is resumed"
    );
    assert_eq!(out.parent_state, Some(StandbyState::Idle));
    assert_eq!(out.orphan_child_dirs, 0);
}

/// A forked child comes back resumed on its parent's saved memory, so until
/// it answers the identity handshake it is still drawing on the parent's
/// CSPRNG and reading the parent's frozen clock, and holds no seccomp tier.
/// Every way that proof can fail — the guest never answers, answers without
/// acknowledging, without rotating, without resynchronizing its clock, or
/// without holding exactly the plan's seccomp tier — must refuse the claim,
/// stop the live child, return the healthy parent to claimable, and leave no
/// child dir. Admitting on any of them would hand out a VM whose "random"
/// values match every sibling forked from the same parent.
#[test]
fn claim_refuses_a_child_that_cannot_prove_a_fresh_identity() {
    let unproven = |acknowledged: bool, reseeded: bool, clock_resynced: bool| {
        MockDriver::default().with_child_identity(PostRestoreOutcome {
            acknowledged,
            detail: None,
            reseeded,
            clock_resynced,
            reseed_shortfall: None,
            seccomp_tier: None,
            volumes_mounted: None,
        })
    };
    let cases = [
        (
            "guest never answered",
            MockDriver::default().with_unreachable_child_agent(),
        ),
        ("guest did not acknowledge", unproven(false, true, true)),
        ("guest did not reseed", unproven(true, false, true)),
        (
            "guest did not resync its clock",
            unproven(true, true, false),
        ),
        // A guest that proved a fresh identity but took no seccomp tier
        // would run the workload unfiltered; one holding a different tier
        // would run it under a filter the plan did not admit.
        ("guest holds no seccomp tier", unproven(true, true, true)),
        (
            "guest holds another seccomp tier",
            MockDriver::default().with_child_identity(PostRestoreOutcome {
                acknowledged: true,
                detail: None,
                reseeded: true,
                clock_resynced: true,
                reseed_shortfall: None,
                seccomp_tier: Some(mvm_core::crypto::seccomp::SeccompTier::Unrestricted),
                volumes_mounted: None,
            }),
        ),
    ];

    for (label, driver) in cases {
        let out = claim_with_scripted_handshake(driver);
        let err = out
            .result
            .expect_err(&format!("{label}: the claim must fail closed"));
        assert!(
            matches!(err, StandbyError::ClaimFailed(_)),
            "{label}: refusal must be a ClaimFailed: {err}"
        );

        // The refusal lands AFTER the fork — the child really was live — and
        // the child was stopped rather than left running unproven.
        let forks = out.driver.forked_children();
        assert_eq!(forks.len(), 1, "{label}: the child was forked first");
        assert!(
            out.driver.killed_vms().contains(&forks[0].child_vm_name),
            "{label}: the refused child must be stopped, not left resumed: killed {:?}",
            out.driver.killed_vms()
        );
        assert_eq!(
            out.parent_state,
            Some(StandbyState::Idle),
            "{label}: a child-side failure must return the healthy parent to claimable"
        );
        assert_eq!(
            out.orphan_child_dirs, 0,
            "{label}: a refused claim must leave no orphan child dir"
        );
    }
}

/// The delivered token reaches the child's agent even on the refusal path —
/// the claim refuses on what the guest reported, not by skipping the ask.
#[test]
fn claim_delivers_the_token_before_judging_the_child() {
    let out = claim_with_scripted_handshake(MockDriver::default().with_child_identity(
        PostRestoreOutcome {
            acknowledged: true,
            detail: None,
            reseeded: false,
            clock_resynced: true,
            reseed_shortfall: None,
            seccomp_tier: None,
            volumes_mounted: None,
        },
    ));
    assert!(out.result.is_err());
    let delivered = out.driver.delivered_child_identities();
    let forks = out.driver.forked_children();
    assert_eq!(delivered.len(), 1, "the token is delivered exactly once");
    assert_eq!(delivered[0].child_vm_name, forks[0].child_vm_name);
    assert_eq!(
        delivered[0].token, forks[0].genid.token,
        "the delivered token is the one the fork minted"
    );
}

/// The standby-fork analogue of
/// `start_workload_starts_console_streaming_and_stop_tears_it_down_without_losing_bytes`:
/// a claim that commits must have started console streaming for the
/// child's own fresh name, at the same console-log path a cold boot would
/// use.
#[test]
fn claim_standby_starts_console_streaming_for_the_committed_child() {
    let out = claim_with_scripted_handshake(MockDriver::default());
    let child = out.result.expect("a clean handshake commits the claim");

    // Not compared against a freshly-recomputed `vm_state_dir(&child.0)`:
    // that helper's `MVM_HOME` override is already unwound by the time this
    // assertion runs, so a second computation here would silently drift to
    // the real (un-isolated) home instead of proving anything. The path's
    // *shape* -- console.log directly under a dir named for the child --
    // is what `standing_sockets` actually guarantees, isolation or not.
    let started = out.console_streamer.started.lock().unwrap();
    assert_eq!(
        started.len(),
        1,
        "console streaming must start exactly once"
    );
    assert_eq!(started[0].0, child.0);
    assert_eq!(
        started[0].1.file_name(),
        Some(std::ffi::OsStr::new("console.log"))
    );
    assert_eq!(
        started[0].1.parent().and_then(|p| p.file_name()),
        Some(std::ffi::OsStr::new(child.0.as_str())),
        "the console log must live under the child's own state dir, not the parent's"
    );
    drop(started);
    assert_eq!(
        out.console_streamer
            .supervisor_owned
            .lock()
            .unwrap()
            .as_slice(),
        [false],
        "a restored child's capture ownership follows its backend, as a cold boot's does"
    );
    assert!(
        out.console_streamer.stopped.lock().unwrap().is_empty(),
        "a committed claim leaves the console streamer running for the \
             ordinary VmBackend::stop path to tear down later, exactly like a \
             cold boot"
    );
}

/// A restored child that never proves a fresh identity fails inside a real
/// window: the post-restore handshake, where the guest is already live but
/// not yet admitted. Without a console follower running through that
/// window, a hang or panic there leaves an operator with nothing but an
/// opaque `ClaimFailed` string. Also proves the follower is torn down on
/// refusal rather than leaked -- `force_stop` only kills the VMM, so
/// `claim_standby` itself must reap the streamer it started.
#[test]
fn claim_standby_stops_console_streaming_when_the_post_restore_handshake_is_refused() {
    let out = claim_with_scripted_handshake(MockDriver::default().with_unreachable_child_agent());
    let err = out
        .result
        .expect_err("an unanswered handshake must refuse the claim");
    assert!(matches!(err, StandbyError::ClaimFailed(_)));

    let forks = out.driver.forked_children();
    assert_eq!(
        forks.len(),
        1,
        "the child was forked and resumed before the handshake ran"
    );
    let child_name = forks[0].child_vm_name.clone();

    // Started while the child was live -- the only way an operator would
    // see a hang or panic inside the handshake window this refusal covers.
    let started = out.console_streamer.started.lock().unwrap();
    assert_eq!(
        started.len(),
        1,
        "console streaming must have started for the forked child"
    );
    assert_eq!(started[0].0, child_name);
    assert_eq!(
        started[0].1.parent().and_then(|p| p.file_name()),
        Some(std::ffi::OsStr::new(child_name.as_str())),
        "the console log must live under the child's own state dir"
    );
    drop(started);
    // ...and stopped once the claim gave up on it, so the follower thread
    // does not outlive a child that was never admitted.
    assert_eq!(
        out.console_streamer.stopped.lock().unwrap().as_slice(),
        [child_name]
    );
}

/// A post-materialize failure (here: the overlay-contract gate refusing a
/// child whose clone carries no overlay sidecar) must return the healthy
/// reserved parent to claimable and remove the orphaned child dir — no leaked
/// warm capacity, no orphaned state. This ALSO proves the overlay gate is
/// wired into `claim_standby`: with the gate deleted, this claim would
/// succeed.
#[test]
fn claim_releases_reserved_parent_and_removes_child_dir_on_overlay_refusal() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    // No overlay sidecar → the child clone fails the overlay-contract gate,
    // which runs AFTER materialize (so a child dir already exists).
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), false);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let err = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("the overlay-contract gate must refuse a sidecar-less child");
    assert!(
        err.to_string().contains("overlay contract") || err.to_string().contains("mvm-meta.json"),
        "refusal must name the overlay gate: {err}"
    );

    // The healthy parent is returned to claimable (not stranded `Claimed`).
    assert_eq!(
        pool.load("warm-parent").unwrap().state,
        StandbyState::Idle,
        "a non-parent-fault failure must return the parent to claimable"
    );
    // No child dir orphaned.
    assert_eq!(
        orphan_child_dirs(),
        0,
        "a failed claim must leave no orphan child dir"
    );
    // The fork never ran.
    assert!(runner.driver.forked_children().is_empty());
}

/// A failed claim destroys the preloaded child, so the record must stop
/// naming it — otherwise the standby stays `Idle` advertising a paused VMM
/// that no longer exists, and every later claim refuses on a missing control
/// socket while `idle_count_compatible` still counts it as capacity. That
/// made a standby single-use against even a retryable failure.
///
/// The parent and its checkpoint are healthy, so it demotes to saved-state
/// (the `pid == 0` sentinel) rather than being removed: warm capacity
/// survives and the next claim materializes a fresh child from the
/// checkpoint.
#[test]
fn a_failed_claim_demotes_a_preloaded_standby_instead_of_stranding_it() {
    check_preloaded_refusal_cleanup(MockDriver::default(), false, false);
}

#[test]
fn failed_preloaded_kill_retains_child_and_parent_without_demotion() {
    check_preloaded_refusal_cleanup(MockDriver::default().with_failing_kill(), true, false);
}

#[test]
fn unavailable_preloaded_handle_retains_child_and_parent_without_demotion() {
    check_preloaded_refusal_cleanup(MockDriver::default().refusing_attach(), true, false);
}

#[test]
fn confirmed_preloaded_handshake_cleanup_does_not_kill_twice() {
    check_preloaded_refusal_cleanup(
        MockDriver::default().with_unreachable_child_agent(),
        false,
        true,
    );
}

#[test]
fn failed_preloaded_resume_and_kill_retain_armed_resources() {
    check_preloaded_refusal_cleanup(
        MockDriver::default()
            .refusing_fork_as_unrestorable("mock resume refused")
            .with_failing_kill(),
        true,
        true,
    );
}

#[test]
fn failed_preloaded_handshake_kill_retains_child_without_retrying_cleanup() {
    check_preloaded_refusal_cleanup(
        MockDriver::default()
            .with_unreachable_child_agent()
            .with_failing_kill(),
        true,
        true,
    );
}

struct CleanupWitnessSpawner;

struct CleanupWitnessBroker;

impl BrokerRegistrar for CleanupWitnessBroker {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        use mvm_vmm::host::broker_services_spawn::{BROKER_PID_FILE, BrokerServicesGuard};
        // Deliberately unparseable: the real reaper removes the marker but cannot signal a process.
        std::fs::write(req.state_dir.join(BROKER_PID_FILE), b"not-a-pid")?;
        Ok(BrokerGuard::from_services_guard(
            mvm_vmm::host::host_agent_spawn::ServicesGuard::Fork(
                BrokerServicesGuard::armed_for_test(req.state_dir),
            ),
        ))
    }
}

impl NetworkEndpointSpawner for CleanupWitnessSpawner {
    fn prepare_identity(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<Option<PathBuf>> {
        KeyingSpawner::default().prepare_identity(req)
    }

    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        // A real endpoint reaper removes this file; no process or socket is started.
        std::fs::write(
            mvm_core::config::vm_substitution_env_path(req.vm_name),
            b"fixture",
        )?;
        KeyingSpawner::default().spawn(req)
    }
}

fn check_preloaded_refusal_cleanup(driver: MockDriver, retained: bool, with_overlay: bool) {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    // Without the overlay the failure precedes resume; with it the scripted
    // handshake fails after the child resumes.
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), with_overlay);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let mut handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    // A preloaded standby: the pool owns a paused child VMM instead of being
    // saved-only, so it carries the child's name and a live pid.
    let child_name = "preloaded-child".to_string();
    handle.preloaded_child_vm_name = Some(child_name.clone());
    handle.pid = std::process::id();
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    materialize_child_from_parent(
        &checkpoints,
        &snapshots,
        &parent_id,
        &anchor,
        &vm_state_dir(&child_name),
    )
    .unwrap();

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_named(&parent_digest, &child_name),
    );
    let runner = WorkloadRunner::new(
        driver.with_preloaded_standby(),
        CleanupWitnessSpawner,
        CleanupWitnessBroker,
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let error = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("the overlay or handshake gate must refuse this claim");
    if with_overlay {
        assert!(
            error.to_string().contains("handshake")
                || error.to_string().contains("mock resume refused"),
            "{error}"
        );
    }

    let after = pool.load("warm-parent").unwrap();
    assert!(
        crate::vm::instance_snapshot::try_lock_resume(&child_name)
            .unwrap()
            .is_some(),
        "rollback releases the lifecycle gate even when termination is unknown"
    );
    if retained {
        assert_eq!(after.state, StandbyState::Claimed);
        assert_eq!(
            after.preloaded_child_vm_name.as_deref(),
            Some(child_name.as_str())
        );
        assert_eq!(after.pid, handle.pid);
        assert!(vm_state_dir(&child_name).join("rootfs.ext4").exists());
        if with_overlay {
            assert_eq!(
                std::fs::read(mvm_core::config::vm_substitution_env_path(&child_name)).unwrap(),
                b"fixture",
                "unknown child termination must not run the armed endpoint reaper"
            );
            assert_eq!(
                std::fs::read(
                    vm_state_dir(&child_name)
                        .join(mvm_vmm::host::broker_services_spawn::BROKER_PID_FILE)
                )
                .unwrap(),
                b"not-a-pid",
                "unknown child termination must not run the armed broker reaper"
            );
        }
        assert!(runner.driver.killed_vms().is_empty());
        return;
    }
    assert_eq!(
        after.state,
        StandbyState::Idle,
        "a non-parent-fault failure must return the parent to claimable"
    );
    assert!(
        after.preloaded_child_vm_name.is_none(),
        "the record must stop naming a child the cleanup destroyed"
    );
    assert!(
        after.is_saved_state(),
        "a standby with no preloaded child is saved-only (pid == 0), so the next \
             claim materializes a fresh child from the checkpoint"
    );
    assert!(
        SupervisorStandbyPool::is_live_or_saved(&after),
        "the demoted parent must remain usable capacity, not read as dead"
    );
    assert_eq!(
        runner.driver.killed_vms(),
        [child_name.as_str()],
        "stop must be confirmed exactly once"
    );
    assert!(!vm_state_dir(&child_name).exists());
}

/// An un-audited parent (no signed creation entry) is quarantined by removal,
/// NOT returned to claimable — a parent that cannot be verified must never be
/// reused. The failure is caught before any child identity/dir is minted.
#[test]
fn claim_quarantines_unaudited_parent_without_releasing_it() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    // The chain carries no signed creation entry for this parent.
    let anchor = ClaimTestAnchor::unaudited();

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let err = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("an un-audited parent must be refused");
    assert!(
        err.to_string().contains("no signed audit entry"),
        "refusal must be the un-audited reason: {err}"
    );

    // Quarantined by removal — NOT returned to claimable.
    assert!(
        pool.load("warm-parent").is_err(),
        "an un-audited parent must be quarantined (removed), never released"
    );
    // Nothing was minted or booted.
    assert_eq!(
        orphan_child_dirs(),
        0,
        "no child dir on a quarantine refusal"
    );
    assert!(runner.driver.forked_children().is_empty());
}

/// A plan whose bound image digest does not match the parent's own verified
/// rootfs is refused before any child side effect: the bind gate runs right
/// after reserve, so this is a non-parent-fault failure (the parent itself
/// verified fine) and must return it to claimable, unlike an unverifiable
/// parent which is quarantined instead.
#[test]
fn claim_refuses_plan_parent_image_mismatch() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    // The plan's bound image digest is unrelated to the parent's own
    // rootfs content-address.
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&"f".repeat(64)),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let err = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("a plan bound to a different image than the parent must be refused");
    assert!(
        err.to_string()
            .contains("does not match parent rootfs digest"),
        "refusal must name the plan/parent mismatch: {err}"
    );

    // Non-parent-fault: the healthy, verified parent goes back to claimable.
    assert_eq!(
        pool.load("warm-parent").unwrap().state,
        StandbyState::Idle,
        "a plan/parent digest mismatch must return the parent to claimable"
    );
    // The refusal runs before any child identity is minted.
    assert_eq!(
        orphan_child_dirs(),
        0,
        "no child dir on a plan/parent mismatch"
    );
    assert!(runner.driver.forked_children().is_empty());
}

/// A warm claim restores a child out of a parent's saved state exactly as a
/// vm_full fork does, so it must run the same subset check. A parent sealed
/// under a tight CPU share cannot hand a claimed child a wider one.
#[test]
fn claim_refuses_a_child_whose_grants_exceed_the_parents() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) = seed_audited_parent_with_grants(
        store_root.path(),
        src.path(),
        true,
        Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
            ..Default::default()
        }),
    );
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    // Bound to the parent's own rootfs, so the image-digest bind passes and
    // the grants comparison is what refuses.
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_with_grants(
            &parent_digest,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
                ..Default::default()
            }),
        ),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let err = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("a claimed child may not widen its parent's grants");
    assert!(
        err.to_string().contains("exceeds the parent's 1000"),
        "refusal must name the widening: {err}"
    );

    // Not the parent's fault, so warm capacity is returned rather than
    // quarantined, and nothing was minted for the refused child.
    assert_eq!(
        pool.load("warm-parent").unwrap().state,
        StandbyState::Idle,
        "a child-side grant widening must return the parent to claimable"
    );
    assert_eq!(orphan_child_dirs(), 0, "no child dir on a grant widening");
    assert!(runner.driver.forked_children().is_empty());
}

/// The other side of the same check: a claimed child that narrows, or that
/// matches, is admitted. Without this the refusal test above would pass just
/// as well against a check that refused every claim.
#[test]
fn claim_admits_a_child_that_narrows_the_parents_grants() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) = seed_audited_parent_with_grants(
        store_root.path(),
        src.path(),
        true,
        Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
            ..Default::default()
        }),
    );
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_with_grants(
            &parent_digest,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
                ..Default::default()
            }),
        ),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("a narrowing child must still be claimable");
}

/// Persist a host config whose CPU ceiling is `millicores`, so a claim in
/// this test's isolated `MVM_HOME` is bounded by a known number rather than
/// by whatever the default config happens to carry.
fn host_ceiling_of(millicores: u32) {
    let cfg = mvm_core::user_config::MvmConfig {
        max_cpu_millicores: Some(millicores),
        ..Default::default()
    };
    mvm_core::user_config::save(&cfg, None).expect("write host config");
}

/// A parent-less bound: the standby parent deliberately carries no grant,
/// so the parent-subset comparison clears any share at all and the host's
/// own ceiling is what refuses. Without the ceiling check this claim boots
/// a child holding four cores on a host configured to allow two.
#[test]
fn a_claimed_child_over_the_host_ceiling_is_refused() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    host_ceiling_of(2000);

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    // A grant-less parent, which is what a factory parent actually is.
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent_with_grants(store_root.path(), src.path(), true, None);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_with_grants(
            &parent_digest,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
                ..Default::default()
            }),
        ),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let err = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("a claim over the host ceiling must be refused");
    assert!(
        err.to_string().contains("grant ceiling"),
        "refusal must read as a bound: {err}"
    );

    // The host, not the parent, refused: warm capacity goes back and
    // nothing was minted for the child.
    assert_eq!(
        pool.load("warm-parent").unwrap().state,
        StandbyState::Idle,
        "a ceiling refusal must return the parent to claimable"
    );
    assert_eq!(orphan_child_dirs(), 0, "no child dir on a ceiling refusal");
    assert!(runner.driver.forked_children().is_empty());
}

/// The other side: a claim at or under the ceiling still gets its warm
/// start. Without this the refusal witness above would pass equally well
/// against a check that refused every claim.
#[test]
fn a_claimed_child_within_the_ceiling_is_admitted() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    host_ceiling_of(2000);

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent_with_grants(store_root.path(), src.path(), true, None);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json_with_grants(
            &parent_digest,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
                ..Default::default()
            }),
        ),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    runner
        .claim_standby(&ctx, &handle, &claim)
        .expect("a claim within the host ceiling must still be claimable");
}

/// Because the bound is checked after the pool has already matched, a
/// refused claim looks superficially like a pool bug: the parent was found,
/// reserved, and then the claim died. The message is the only thing that
/// distinguishes the two, so it has to carry both numbers — what the host
/// allows and what the plan asked for.
#[test]
fn the_refusal_names_the_ceiling_and_the_request() {
    let refusal = ensure_child_grants_within_host_ceiling(
        Some(&mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
            ..Default::default()
        }),
        &mvm_contract::grants::ceiling::GrantCeiling {
            max_cpu_millicores: Some(2000),
            ..Default::default()
        },
    )
    .expect_err("4000 millicores exceeds a 2000-millicore ceiling");

    let text = refusal.to_string();
    assert!(
        text.contains("2000"),
        "refusal must name the ceiling: {text}"
    );
    assert!(
        text.contains("4000"),
        "refusal must name the request: {text}"
    );
    assert!(
        text.contains("cpu.share_millicores"),
        "refusal must name the bounded dimension: {text}"
    );
    assert!(
        text.contains("ceiling"),
        "refusal must read as a bound being enforced, not a failure: {text}"
    );
}

/// The bound is checked after matching, never folded into the pool's
/// compatibility key: keying on a grant would split one pool into a pool
/// per distinct share and cost the warm hit rate the pool exists for.
///
/// Two halves, both needed. The exhaustive destructure fails to compile the
/// day a grant dimension is added to the key — which is the move this test
/// exists to prevent — and the selection half proves the live consequence:
/// one warm parent serves claims asking for different shares.
#[test]
fn pool_matching_is_unchanged_by_the_bound() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    host_ceiling_of(2000);

    let store_root = tempfile::tempdir().unwrap();
    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();

    let mvm_core::vm_backend::StandbyCompat {
        template_id: _,
        kernel_sha256: _,
        vcpus: _,
        mem_mib: _,
        image_sha256: _,
        root_strategy: _,
        vsock_egress: _,
    } = handle.compat();

    // The key is derived from the parent's boot shape and takes no grant as
    // input, so every claim on this boot shape resolves the one warm parent
    // whatever share its plan asks for — including one the ceiling will go
    // on to refuse. Matching and bounding stay separate decisions.
    let want = handle.compat();
    let picked = pool
        .select_idle_compatible(&want)
        .unwrap()
        .expect("a claim on this boot shape must match the warm parent");
    assert_eq!(picked.id, "warm-parent");
    assert_eq!(
        picked.compat(),
        want,
        "the matched parent's key must be the one that was asked for"
    );
}

/// A parent whose sealed `meta.json` is edited after capture — without
/// recomputing its content-address — drifts from its own stored digest.
/// This is distinct from the un-audited-parent case: here the chain DOES
/// carry a signed entry, but the on-disk record no longer matches what was
/// signed, so the recompute-vs-stored check must catch it before the chain
/// lookup ever runs. Quarantined by removal, the same fail-closed posture
/// as the un-audited case, since a record that cannot be verified must
/// never be reused.
#[test]
fn claim_refuses_drift_tampered_parent() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    // Anchored to the digest the ORIGINAL sealed record carried — the chain
    // attests to what was signed, not to whatever is on disk now.
    let anchor = ClaimTestAnchor::audited(&parent_meta);

    // Tamper the on-disk record after sealing: mutate a load-bearing field
    // without touching `meta_digest`, so the stored digest goes stale.
    let mut tampered = checkpoints.read_meta(&parent_id).unwrap();
    tampered.vm_name = "attacker-renamed".into();
    checkpoints.write_meta(&tampered).unwrap();
    assert_ne!(
        tampered.compute_meta_digest(),
        tampered.meta_digest,
        "the tamper must actually drift the digest, or this test proves nothing"
    );

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    let err = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("a drift-tampered parent must be refused");
    assert!(
        err.to_string().contains("drift"),
        "refusal must name the drift reason: {err}"
    );

    // Quarantined by removal — NOT returned to claimable, mirroring the
    // un-audited case: an unverifiable record must never be reused.
    assert!(
        pool.load("warm-parent").is_err(),
        "a drift-tampered parent must be quarantined (removed), never released"
    );
    assert_eq!(
        orphan_child_dirs(),
        0,
        "no child dir on a quarantine refusal"
    );
    assert!(runner.driver.forked_children().is_empty());
}

/// Two concurrent claims against the same idle parent: the reserve step
/// (load + claimable check + `mark_claimed`) runs under the registry file
/// lock, so exactly one claim can observe the parent as claimable. Real
/// threads racing the same runner + context prove the exclusion is actually
/// enforced, not just serialized by test structure.
#[test]
fn concurrent_claims_do_not_double_claim_one_parent() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");

    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );

    // `dyn CheckpointChainAnchor` carries no `Sync` bound (real anchors are
    // the CLI's host-signer-backed audit-chain reader, never shared across
    // threads in production), so each thread gets its own owned anchor
    // instance and builds its own `ClaimContext` locally rather than
    // sharing one `&dyn CheckpointChainAnchor` across the thread boundary.
    let anchor1 = ClaimTestAnchor::audited(&parent_meta);
    let anchor2 = ClaimTestAnchor::audited(&parent_meta);

    let results: Vec<std::result::Result<VmId, StandbyError>> = std::thread::scope(|s| {
        let t1 = s.spawn(|| {
            let ctx = ClaimContext {
                pool: &pool,
                checkpoints: &checkpoints,
                snapshots: &snapshots,
                anchor: &anchor1,
                parent_checkpoint: &parent_id,
                registry_path: &registry_path,
                grant_issuer: None,
                preloaded_child_lifecycle: None,
            };
            runner.claim_standby(&ctx, &handle, &claim)
        });
        let t2 = s.spawn(|| {
            let ctx = ClaimContext {
                pool: &pool,
                checkpoints: &checkpoints,
                snapshots: &snapshots,
                anchor: &anchor2,
                parent_checkpoint: &parent_id,
                registry_path: &registry_path,
                grant_issuer: None,
                preloaded_child_lifecycle: None,
            };
            runner.claim_standby(&ctx, &handle, &claim)
        });
        vec![t1.join().unwrap(), t2.join().unwrap()]
    });

    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "exactly one concurrent claim on the same parent must succeed"
    );
    let loser = results
        .iter()
        .find(|r| r.is_err())
        .unwrap()
        .as_ref()
        .unwrap_err();
    assert!(
        matches!(loser, StandbyError::ReservationLost),
        "the losing claim must report reservation loss, not some other error: {loser}"
    );

    // Exactly one fork happened and exactly one child dir landed — never
    // two, which is what a broken exclusion would produce.
    assert_eq!(
        runner.driver.forked_children().len(),
        1,
        "the reserve race must not let both claims through to the fork"
    );
    assert_eq!(
        orphan_child_dirs(),
        1,
        "exactly one child dir must exist after the race"
    );
    assert_eq!(
        pool.load("warm-parent").unwrap().state,
        StandbyState::Claimed,
        "the winner's parent stays reserved, never returned mid-race"
    );
}

#[test]
fn selected_parent_removed_by_winner_reports_reservation_lost_before_child_effects() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    let (checkpoints, snapshots, parent_id, parent_meta) =
        seed_audited_parent(store_root.path(), src.path(), true);
    let parent_digest = materialized_parent_rootfs_digest(&checkpoints, &parent_meta);
    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let registry_path = store_root.path().join("vm-names.json");
    let anchor = ClaimTestAnchor::audited(&parent_meta);
    let claim = admitted_child_claim(
        &src.path().join("rootfs.ext4"),
        signed_child_plan_json(&parent_digest),
    );
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        KeyingSpawner::default(),
        RecordingBrokerRegistrar::new(),
    );
    let ctx = ClaimContext {
        pool: &pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_id,
        registry_path: &registry_path,
        grant_issuer: None,
        preloaded_child_lifecycle: None,
    };

    pool.remove(&handle.id)
        .expect("winner removed the selected parent");
    let error = runner
        .claim_standby(&ctx, &handle, &claim)
        .expect_err("removed selected parent loses the reservation");
    assert!(matches!(error, StandbyError::ReservationLost), "{error}");
    assert!(
        runner.driver.forked_children().is_empty(),
        "reservation loss precedes child effects"
    );
    assert_eq!(orphan_child_dirs(), 0);
}

/// There is no code path on this runner that takes an existing standby
/// parent's identity and runs a workload directly on it — the guarantee is
/// structural, not a runtime check. `claim_standby` is the only method that
/// consumes a `StandbyHandle`, and it always mints a fresh child id distinct
/// from the parent's own (see `claim_produces_fresh_identity_and_isolated_endpoint`).
/// The only OTHER way this runner produces a running `VmId` is a cold
/// `start`, which carries no reference to the standby pool at all: a parent
/// lives under the pool root, a workload under the VM state root, so naming
/// a cold boot after a live parent cannot promote it — it lands in a
/// disjoint directory and leaves the parent's own record untouched.
#[test]
fn promoting_a_parent_to_a_workload_is_refused() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let store_root = tempfile::tempdir().unwrap();
    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
    pool.record(&handle).unwrap();
    let before = pool.load("warm-parent").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    // The closest thing to "run a workload on this VmId": a cold start
    // under the parent's own name.
    let (_rootfs_dir, rootfs) = overlay_aware_rootfs("warm-parent");
    let cfg = VmStartConfig {
        name: "warm-parent".into(),
        rootfs_path: rootfs,
        ..Default::default()
    };
    let started =
        mapping_start(&runner, &cfg).expect("start is an ordinary cold boot, not a claim");
    assert_eq!(started.0, "warm-parent");

    // `start` never reads or mutates the standby pool — the parent's
    // record is byte-for-byte unchanged.
    assert_eq!(
        pool.load("warm-parent").unwrap(),
        before,
        "a cold-started workload sharing the parent's name must not touch its pool record"
    );

    // Disjoint directory roots: the parent lives under the pool root, the
    // workload under the VM state root. There is no shared resource here
    // to promote.
    let workload_dir = vm_state_dir("warm-parent");
    let parent_dir = pool.root().join("warm-parent");
    assert_ne!(
        workload_dir, parent_dir,
        "the started workload and the registered parent must not share a directory"
    );
    assert_eq!(before.state, StandbyState::Idle);
}
