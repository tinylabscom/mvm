//! Step definitions for the warm-claim guarded-fork scenario.
//!
//! Drives `mvm_runtime::workload_runner::WorkloadRunner::claim_standby` — the
//! same guarded fork seam a Firecracker warm claim runs through — against the
//! hypervisor-free `MockDriver`, so the scenario proves what the runner's
//! claim path genuinely does with no live VM: fork a clean, chain-verified
//! parent into a fresh child, and refuse a parent the chain does not attest
//! to. Admission (the signed plan itself), verity inherit, and per-service
//! confinement are minted/verified at their own layers in production (the CLI
//! caller and guest init) and are out of scope here; this scenario only
//! drives the steps the runner itself owns.

use std::sync::Mutex;

use cucumber::{given, then, when};

use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_core::crypto::vmgenid::GENID_BYTES;
use mvm_core::vm_backend::{StandbyClaim, StandbyHandle, StandbyState, VmStartConfig};
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotId, SnapshotStore};
use mvm_runtime::checkpoint::{
    CaptureFsQuickParams, CheckpointChainAnchor, CheckpointStore, capture_fs_quick,
};
use mvm_runtime::driver::MockDriver;
use mvm_runtime::standby_pool::SupervisorStandbyPool;
use mvm_runtime::workload_runner::claim::parent_rootfs_digest;
use mvm_runtime::workload_runner::{
    ChildGrantIssuer, ClaimContext, NetworkEndpointSpawnRequest, NetworkEndpointSpawner,
    RealBrokerRegistrar, WorkloadRunner,
};

use crate::world::{CliWorld, WarmClaimOutcome, WarmClaimWitness};

/// Seed a clean, pre-workload parent checkpoint recorded as an idle standby,
/// and stash every piece the `When` step needs. `chain_carries_creation_entry`
/// drives whether the claim's `CheckpointChainAnchor` double reports this
/// parent as audited — the fail-closed lineage gate the claim runs before any
/// clone.
fn seed_parent(world: &mut CliWorld, chain_carries_creation_entry: bool) {
    let store_root = tempfile::tempdir().expect("create warm-claim store tempdir");
    let src = tempfile::tempdir().expect("create warm-claim parent source tempdir");

    let checkpoints = CheckpointStore::at(store_root.path().join("checkpoints"));
    let snapshots = FsSnapshotStore::new(store_root.path().join("snapshots"))
        .expect("open warm-claim snapshot store");

    let rootfs = src.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"clean-parent-rootfs").expect("write the clean parent rootfs");
    // Overlay-aware sidecar so the cloned child clears the same host gate a
    // cold boot runs (the runner's overlay-contract admission gate).
    mvm_build::builder_vm::GuestSidecar::for_oci_run("warm-parent", false, true)
        .write_to_dir(src.path())
        .expect("write the overlay sidecar");

    let parent_id = CheckpointId::new("warm-parent-cp");
    let parent_meta = capture_fs_quick(
        &checkpoints,
        CaptureFsQuickParams {
            id: parent_id.clone(),
            vm_name: "warm-parent".into(),
            rootfs,
            supervisor_config_digest: "d".into(),
            runtime_overlay_version: None,
            tag: None,
            created_unix: 1,
            quiesced: true,
            grants: None,
        },
    )
    .expect("capture the clean parent checkpoint");
    let snapshot_id = format!(
        "checkpoint-{}-content-{}",
        parent_meta.id,
        parent_meta.compute_content_digest()
    );
    snapshots
        .create(
            &SnapshotId::new(snapshot_id.clone()),
            &checkpoints.content_dir(&parent_meta.id),
        )
        .expect("stage the clean parent snapshot");
    let parent_meta = parent_meta.with_snapshot_id(snapshot_id);
    checkpoints
        .write_meta(&parent_meta)
        .expect("bind the staged parent snapshot");

    let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
    let handle = StandbyHandle {
        id: "warm-parent".into(),
        // Not template-bound: this fixture claims by kernel identity.
        template_id: None,
        control_socket: store_root.path().join("control.sock").display().to_string(),
        pid: 0,
        kernel_sha256: "k".repeat(64),
        vcpus: 2,
        mem_mib: 512,
        binding_nonce: "b".repeat(64),
        spawned_unix_secs: 1,
        state: StandbyState::Idle,
        image_sha256: None,
        parent_checkpoint: None,
        vsock_egress: false,
        preloaded_child_vm_name: None,
    };
    pool.record(&handle).expect("record the standby parent");

    world.warm_claim_registry_path = Some(store_root.path().join("vm-names.json"));
    world.warm_claim_parent_id = Some(parent_id);
    world.warm_claim_parent_meta = Some(parent_meta);
    world.warm_claim_parent_audited = chain_carries_creation_entry;
    world.warm_claim_pool = Some(pool);
    world.warm_claim_handle = Some(handle);
    world.warm_claim_checkpoints = Some(checkpoints);
    world.warm_claim_snapshots = Some(snapshots);
    world.warm_claim_src = Some(src);
    world.warm_claim_store_root = Some(store_root);
    world.warm_claim_outcome = None;
}

#[given(expr = "a clean warm parent recorded in the pool with a signed audit-chain entry")]
fn given_audited_parent(world: &mut CliWorld) {
    seed_parent(world, true);
}

#[given(expr = "a clean warm parent recorded in the pool with no signed audit-chain entry")]
fn given_unaudited_parent(world: &mut CliWorld) {
    seed_parent(world, false);
}

/// A `CheckpointChainAnchor` double: echoes the seeded parent's own recomputed
/// creation digest (audited) or reports no chain entry at all (unaudited) —
/// driving the claim's fail-closed lineage gate without a real signed audit
/// chain.
struct WarmClaimAnchor {
    verdict: Option<(String, CheckpointDigest)>,
}

impl WarmClaimAnchor {
    fn new(meta: &CheckpointMeta, audited: bool) -> Self {
        Self {
            verdict: audited.then(|| (meta.id.to_string(), meta.compute_meta_digest())),
        }
    }
}

impl CheckpointChainAnchor for WarmClaimAnchor {
    fn recorded_creation_digest(
        &self,
        meta: &CheckpointMeta,
    ) -> anyhow::Result<Option<CheckpointDigest>> {
        Ok(self
            .verdict
            .as_ref()
            .filter(|(id, _)| *id == meta.id.to_string())
            .map(|(_, digest)| digest.clone()))
    }
}

/// An `NetworkEndpointSpawner` double: keys its returned socket on the vm name it is
/// handed (mirroring the production spawner), with no real endpoint process.
#[derive(Default)]
struct WarmClaimSpawner {
    seen_vm: Mutex<Option<String>>,
}

impl NetworkEndpointSpawner for WarmClaimSpawner {
    fn spawn(
        &self,
        req: &NetworkEndpointSpawnRequest<'_>,
    ) -> anyhow::Result<mvm_runtime::workload_runner::SpawnedEndpoint> {
        *self.seen_vm.lock().unwrap() = Some(req.vm_name.to_string());
        Ok(mvm_runtime::workload_runner::SpawnedEndpoint {
            egress_uds: mvm_core::config::vm_network_endpoint_socket(req.vm_name),
            // A warm claim attaches no drive: the restored child already holds
            // its parent's key in the memory image it woke from.
            identity_drive: None,
        })
    }
}

struct WarmClaimGrantIssuer;

impl ChildGrantIssuer for WarmClaimGrantIssuer {
    fn issue(
        &self,
        config: &VmStartConfig,
    ) -> anyhow::Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
        mvm_hostd::plan_admission::stash_plan_and_mint_verb_grant(config)
    }
}

#[when(expr = "the parent is claimed with an admitted child plan")]
fn when_claim_parent(world: &mut CliWorld) {
    // `vm_state_dir` / `vm_network_endpoint_socket` are `MVM_HOME`-rooted.
    // Serialize against any other test in this process that mutates it, and
    // restore the previous value when this step (the only place in the
    // conformance suite driving the runner's guarded claim path in-process)
    // returns.
    let _guard = mvm_runtime::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let mvm_home = tempfile::tempdir().expect("create a private MVM_HOME for this claim");
    env.set("MVM_HOME", mvm_home.path());

    let checkpoints = world
        .warm_claim_checkpoints
        .as_ref()
        .expect("a Given step must seed a warm parent first");
    let snapshots = world
        .warm_claim_snapshots
        .as_ref()
        .expect("a Given step must seed a warm parent first");
    let parent_id = world
        .warm_claim_parent_id
        .as_ref()
        .expect("a Given step must seed a warm parent first");
    let parent_meta = world
        .warm_claim_parent_meta
        .as_ref()
        .expect("a Given step must seed a warm parent first");
    let pool = world
        .warm_claim_pool
        .as_ref()
        .expect("a Given step must seed a warm parent first");
    let handle = world
        .warm_claim_handle
        .clone()
        .expect("a Given step must seed a warm parent first");
    let registry_path = world
        .warm_claim_registry_path
        .clone()
        .expect("a Given step must seed a warm parent first");
    let src = world
        .warm_claim_src
        .as_ref()
        .expect("a Given step must seed a warm parent first");

    let anchor = WarmClaimAnchor::new(parent_meta, world.warm_claim_parent_audited);
    let parent_digest = parent_rootfs_digest(parent_meta)
        .expect("the seeded parent carries a rootfs content blob")
        .to_string();

    // A fresh, signed child `ExecutionPlan` bound to the parent's own
    // verified content-address — the same shape the CLI mints via
    // `admit_plan_for_boot` before handing the runner the claim.
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("tenant-x")
        .nonce([9u8; 16])
        .build();
    plan.image.sha256 = parent_digest.clone();
    plan.agent_verbs = Some(vec![
        mvm_core::plan::VerbId::new("run-entrypoint").expect("valid verb fixture"),
    ]);
    let plan_json = serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test"))
        .expect("serialize the signed child plan");

    let rootfs_path = src.path().join("rootfs.ext4");
    let claim = StandbyClaim {
        start_config: Some(VmStartConfig {
            name: "unused-cold".into(),
            rootfs_path: rootfs_path.display().to_string(),
            tenant_id: Some("tenant-x".into()),
            ..Default::default()
        }),
        rootfs_path: rootfs_path.display().to_string(),
        tenant_id: "tenant-x".into(),
        audit_dir: rootfs_path.with_file_name("audit"),
        gateway_audit_socket: rootfs_path.with_file_name("gw-audit.sock"),
        gateway_events_socket: None,
        plan_json,
        bundle_json: None,
        network_policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
    };

    // `MockDriver` is `Clone` over an `Arc`-shared state, so cloning it before
    // handing it to the runner keeps a probe into what the guarded claim
    // actually did (booted specs, forked children) without needing access to
    // the runner's own private fields from outside its crate.
    let driver = MockDriver::default();
    let driver_probe = driver.clone();
    let runner = WorkloadRunner::new(driver, WarmClaimSpawner::default(), RealBrokerRegistrar);
    let grant_issuer = WarmClaimGrantIssuer;
    let ctx = ClaimContext {
        pool,
        checkpoints,
        snapshots,
        anchor: &anchor,
        parent_checkpoint: parent_id,
        registry_path: &registry_path,
        grant_issuer: Some(&grant_issuer),
    };

    world.warm_claim_outcome = Some(match runner.claim_standby(&ctx, &handle, &claim) {
        Ok(child) => {
            let child_dir = mvm_core::config::vm_state_dir(&child.0);
            let forked = driver_probe.forked_children();
            let fork = forked
                .iter()
                .find(|f| f.child_vm_name == child.0)
                .expect("a successful claim records exactly one fork for its child");
            let delivered = driver_probe.delivered_child_identities();
            let grant = delivered
                .first()
                .and_then(|identity| identity.grant_envelope.as_ref())
                .expect("the successful claim delivers its child grant");
            let host_key_bytes = std::fs::read(
                mvm_core::config::mvm_keys_dir()
                    .join(mvm_hostd::audit::host_keypair::PUBLIC_FILENAME),
            )
            .expect("read the host signer public key used for the child grant");
            let host_key = ed25519_dalek::VerifyingKey::from_bytes(
                &host_key_bytes
                    .try_into()
                    .expect("host signer public key is exactly 32 bytes"),
            )
            .expect("host signer public key is valid Ed25519");
            WarmClaimOutcome::Claimed(WarmClaimWitness {
                child_id: child.0.clone(),
                child_dir_has_sidecar: child_dir
                    .join(mvm_build::builder_vm::SIDECAR_FILENAME)
                    .exists(),
                child_dir_has_rootfs: child_dir.join("rootfs.ext4").exists(),
                fork_genid_nonzero: fork.genid.token != [0u8; GENID_BYTES],
                fork_genid_content_hash_matches_parent: fork.genid.content_hash == parent_digest,
                post_restore_grant_session_matches_child: grant.grant.session_id == child.0,
                post_restore_grant_verbs: grant
                    .grant
                    .verbs
                    .iter()
                    .map(|verb| verb.as_str().to_string())
                    .collect(),
                post_restore_grant_verifies_under_host_key: grant
                    .grant
                    .verify(&host_key, &child.0, &plan.nonce, plan.valid_from)
                    .is_ok(),
            })
        }
        Err(e) => WarmClaimOutcome::Refused {
            message: e.to_string(),
            any_fork_occurred: !driver_probe.forked_children().is_empty(),
        },
    });
}

/// The witness from a successful claim, or a failed assertion naming the
/// `When` step that must run first (or that unexpectedly refused).
fn claimed_witness(world: &CliWorld) -> WarmClaimWitness {
    match world
        .warm_claim_outcome
        .as_ref()
        .expect("a When step must attempt a claim first")
    {
        WarmClaimOutcome::Claimed(witness) => witness.clone(),
        WarmClaimOutcome::Refused { message, .. } => {
            panic!("expected the claim to succeed, but it was refused: {message}")
        }
    }
}

#[then(expr = "the claim yields a fresh child identity distinct from the parent")]
fn then_fresh_child_identity(world: &mut CliWorld) {
    let witness = claimed_witness(world);
    assert_ne!(
        witness.child_id, "warm-parent",
        "the claimed child must get a fresh id, never the parent's own"
    );
}

#[then(expr = "the child's rootfs is materialized from the parent's own content")]
fn then_child_rootfs_materialized(world: &mut CliWorld) {
    let witness = claimed_witness(world);
    assert!(
        witness.child_dir_has_rootfs,
        "the child's rootfs must be materialized from the verified parent's content"
    );
    assert!(
        witness.child_dir_has_sidecar,
        "the overlay sidecar must ride the clone into the child dir"
    );
}

#[then(expr = "the child is delivered a fresh, non-zero generation token bound to the parent")]
fn then_fresh_genid(world: &mut CliWorld) {
    let witness = claimed_witness(world);
    assert!(
        witness.fork_genid_nonzero,
        "a clean parent's baseline token is zero; the child must get a fresh non-zero one"
    );
    assert!(
        witness.fork_genid_content_hash_matches_parent,
        "the fresh token must be bound to the verified parent's content-address"
    );
}

#[then(expr = "the child's signed verb grant is delivered with its final identity")]
fn then_child_grant_matches_final_identity(world: &mut CliWorld) {
    let witness = claimed_witness(world);
    assert!(
        witness.post_restore_grant_session_matches_child,
        "the post-restore grant must bind the final runner-minted child identity"
    );
    assert_eq!(
        witness.post_restore_grant_verbs,
        ["run-entrypoint"],
        "the post-restore grant must carry exactly the admitted verb set"
    );
    assert!(
        witness.post_restore_grant_verifies_under_host_key,
        "the post-restore grant must verify under the host's trusted signer key"
    );
}

#[then(expr = "the claim is refused and no child is forked")]
fn then_claim_refused(world: &mut CliWorld) {
    match world
        .warm_claim_outcome
        .as_ref()
        .expect("a When step must attempt a claim first")
    {
        WarmClaimOutcome::Refused {
            message,
            any_fork_occurred,
        } => {
            assert!(
                message.contains("audit entry"),
                "an unaudited parent must be refused for lacking a signed audit entry: {message}"
            );
            assert!(
                !any_fork_occurred,
                "a fail-closed refusal must never reach the fork step"
            );
        }
        WarmClaimOutcome::Claimed(witness) => panic!(
            "expected the unaudited parent's claim to be refused, but it claimed child {}",
            witness.child_id
        ),
    }
}
