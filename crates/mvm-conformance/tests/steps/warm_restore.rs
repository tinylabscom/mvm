//! Step definitions for warm-restore security-surface witnesses.
//!
//! Hermetic scenarios exercise the pure restore guards (integrity, epoch
//! anti-rollback, no-NIC device model, page-merge confinement) with test
//! doubles, so they run without KVM. Live scenarios exercise the full CLI
//! warm-restore path and are gated by `@live` / `@firecracker`.

use std::path::Path;

use cucumber::{given, then, when};
use mvm_core::checkpoint::CheckpointId;
use mvm_core::crypto::snapshot_hmac::{MEM_FILENAME, VMSTATE_FILENAME};
use mvm_core::page_merge::{MergeDecision, PageMergeScope, may_merge};
use mvm_core::plan::{SignedImageRef, TenantId};
use mvm_runtime::microvm::{RestoredDeviceModel, assert_vsock_only_device_model};
use mvm_runtime::vm::instance_snapshot::{
    CannedIO, pause_and_seal, verify_and_resume, verify_and_resume_from_dir,
};

use crate::world::{CliWorld, MvmHomeGuard};

/// Create an isolated temp home, point `MVM_HOME` at it, and return both
/// the directory and an RAII guard that restores the previous `MVM_HOME`
/// when the scenario ends. The caller must store both in `world` so the
/// snapshot files and the override survive the `Given` step.
fn isolated_mvm_home() -> (tempfile::TempDir, MvmHomeGuard) {
    let home = tempfile::tempdir().expect("create isolated MVM_HOME");
    let guard = MvmHomeGuard::new(home.path());
    (home, guard)
}

#[given(expr = "a sealed warm snapshot for VM {string}")]
fn sealed_warm_snapshot(world: &mut CliWorld, vm_name: String) {
    let (home, guard) = isolated_mvm_home();
    let io = CannedIO::new(b"vmstate-for-seal".to_vec(), b"mem-for-seal".to_vec());
    let sidecar = pause_and_seal(&vm_name, &io).expect("seal the warm snapshot");
    let dir = mvm_runtime::vm::instance_snapshot::snapshot_dir(&vm_name);
    world.warm_restore_home_guard = Some(guard);
    world.warm_restore_home = Some(home);
    world.warm_restore_dir = Some(dir);
    world.warm_restore_result = Some(Ok(format!("sealed epoch {}", sidecar.epoch)));
    world.warm_restore_tampered_file = None;
}

#[given(expr = "a sealed warm snapshot for VM {string} captured at epoch 1")]
fn sealed_warm_snapshot_epoch_one(world: &mut CliWorld, vm_name: String) {
    // Capture the first sealed snapshot into a stable directory before a
    // second seal bumps the per-instance epoch high-water mark.
    let (home, guard) = isolated_mvm_home();
    let io = CannedIO::new(b"vmstate-epoch1".to_vec(), b"mem-epoch1".to_vec());
    let sidecar = pause_and_seal(&vm_name, &io).expect("seal the first warm snapshot");
    assert_eq!(sidecar.epoch, 1, "first seal must produce epoch 1");
    let live_dir = mvm_runtime::vm::instance_snapshot::snapshot_dir(&vm_name);
    let saved_dir = live_dir.with_file_name("epoch1-snapshot");
    copy_snapshot_dir(&live_dir, &saved_dir).expect("copy the epoch-1 snapshot");
    world.warm_restore_home_guard = Some(guard);
    world.warm_restore_home = Some(home);
    world.warm_restore_dir = Some(saved_dir);
    world.warm_restore_result = Some(Ok(format!("sealed epoch {}", sidecar.epoch)));
}

#[given(expr = "the same VM is sealed again at a newer epoch")]
fn same_vm_sealed_again(_world: &mut CliWorld) {
    let vm_name = "epoch-vm";
    let io = CannedIO::new(b"vmstate-epoch2".to_vec(), b"mem-epoch2".to_vec());
    let sidecar = pause_and_seal(vm_name, &io).expect("seal the second warm snapshot");
    assert!(
        sidecar.epoch > 1,
        "second seal must bump the epoch high-water mark"
    );
}

#[when(expr = "a byte at offset {int} of the snapshot {word} file is flipped")]
fn flip_byte(world: &mut CliWorld, offset: usize, which: String) {
    let dir = world
        .warm_restore_dir
        .as_ref()
        .expect("a Given step must create a sealed snapshot first");
    let filename = match which.as_str() {
        "vmstate" => VMSTATE_FILENAME,
        "memory" => MEM_FILENAME,
        other => panic!("unknown snapshot artifact {other:?}; use vmstate or memory"),
    };
    let path = dir.join(filename);
    let mut bytes = std::fs::read(&path).expect("read artifact to tamper");
    if offset >= bytes.len() {
        // Pad deterministically so the offset is always valid.
        bytes.resize(offset + 1, 0);
    }
    bytes[offset] = bytes[offset].wrapping_add(1);
    std::fs::write(&path, bytes).expect("write tampered artifact");
    world.warm_restore_tampered_file = Some(which);
}

#[when(expr = "warm restore is attempted from that snapshot")]
fn warm_restore_from_that_snapshot(world: &mut CliWorld) {
    let dir = world
        .warm_restore_dir
        .as_ref()
        .expect("a Given step must create a sealed snapshot first")
        .clone();
    let io = CannedIO::new(b"ignored-by-verify".to_vec(), b"ignored-by-verify".to_vec());
    world.warm_restore_result = Some(
        verify_and_resume_from_dir(&dir, &io)
            .map(|sidecar| format!("restored epoch {}", sidecar.epoch))
            .map_err(|e| e.to_string()),
    );
}

#[when(expr = "warm restore is attempted from the older-epoch snapshot")]
fn warm_restore_from_dir(world: &mut CliWorld) {
    let saved_dir = world
        .warm_restore_dir
        .as_ref()
        .expect("a Given step must create a sealed snapshot first")
        .clone();
    let vm_name = "epoch-vm";
    let live_dir = mvm_runtime::vm::instance_snapshot::snapshot_dir(vm_name);
    // Simulate an operator (or attacker) replacing the live snapshot
    // artifacts with an older-epoch copy, while the per-instance
    // high-water mark keeps advancing.
    copy_snapshot_dir(&saved_dir, &live_dir).expect("stage older-epoch snapshot over live dir");
    let io = CannedIO::new(b"ignored-by-verify".to_vec(), b"ignored-by-verify".to_vec());
    world.warm_restore_result = Some(
        verify_and_resume(vm_name, &io)
            .map(|sidecar| format!("restored epoch {}", sidecar.epoch))
            .map_err(|e| e.to_string()),
    );
}

#[then(expr = "warm restore of that snapshot is refused with an integrity error")]
fn restore_refused_integrity(world: &mut CliWorld) {
    let err = world
        .warm_restore_result
        .as_ref()
        .expect("a When step must attempt restore first")
        .as_ref()
        .expect_err("tampered snapshot must fail verification");
    assert!(
        err.contains("HMAC") || err.contains("integrity") || err.contains("verify"),
        "expected an integrity refusal, got: {err}"
    );
}

#[then(expr = "warm restore is refused with an epoch rollback error")]
fn restore_refused_epoch(world: &mut CliWorld) {
    let err = world
        .warm_restore_result
        .as_ref()
        .expect("a When step must attempt restore first")
        .as_ref()
        .expect_err("older-epoch snapshot must be refused");
    assert!(
        err.contains("epoch") || err.contains("rollback") || err.contains("high-water"),
        "expected an epoch rollback refusal, got: {err}"
    );
}

#[when(expr = "a restored device model containing a network interface is checked")]
fn device_model_with_nic(world: &mut CliWorld) {
    let model = RestoredDeviceModel {
        network_interfaces: vec![serde_json::json!({
            "iface_id": "eth0",
            "host_dev_name": "tap0",
            "guest_mac": "02:00:00:00:00:01"
        })],
    };
    world.warm_restore_device_model = Some(model);
}

#[then(expr = "the no-NIC guard refuses it")]
fn no_nic_guard_refuses(world: &mut CliWorld) {
    let model = world
        .warm_restore_device_model
        .as_ref()
        .expect("a When step must stage a device model first");
    let err = assert_vsock_only_device_model(model.network_interfaces.len())
        .expect_err("NIC-carrying model must be refused");
    assert!(
        err.to_string().contains("network") || err.to_string().contains("NIC"),
        "expected a NIC refusal, got: {err}"
    );
}

#[given(expr = "a page-merge scope named {word} for tenant {word}, image {word}, family {word}")]
fn page_merge_scope(
    world: &mut CliWorld,
    name: String,
    tenant: String,
    image: String,
    family: String,
) {
    let scope = PageMergeScope {
        tenant: TenantId(tenant),
        image: SignedImageRef {
            name: "example-image".to_string(),
            sha256: image,
            cosign_bundle: None,
            entrypoint_present: true,
        },
        fork_family: CheckpointId::new(family),
    };
    world.warm_merge_scopes.push((name, scope));
}

#[when(expr = "merge decision is computed between {word} and {word}")]
fn compute_merge_decision(world: &mut CliWorld, a: String, b: String) {
    let find = |name: &str| {
        world
            .warm_merge_scopes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.clone())
            .unwrap_or_else(|| panic!("unknown scope {name:?}"))
    };
    world.warm_merge_decision = Some(may_merge(&find(&a), &find(&b)));
}

#[then(expr = "the merge decision is {word}")]
fn merge_decision_is(world: &mut CliWorld, expected: String) {
    let decision = world
        .warm_merge_decision
        .expect("a When step must compute a merge decision first");
    let expected_decision = match expected.as_str() {
        "Permit" => MergeDecision::Permit,
        "Refuse" => MergeDecision::Refuse,
        other => panic!("unknown merge decision {other:?}"),
    };
    assert_eq!(
        decision, expected_decision,
        "unexpected same-page merge decision"
    );
}

/// Copy a sealed snapshot directory (`integrity.json`, `vmstate.bin`, `mem.bin`)
/// so an older epoch can be restored after the live high-water mark advances.
fn copy_snapshot_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for name in ["integrity.json", VMSTATE_FILENAME, MEM_FILENAME] {
        std::fs::copy(src.join(name), dst.join(name))?;
    }
    Ok(())
}

// ---- Fork memory residue prevention ----

#[given(expr = "the parent's source directory receives a post-checkpoint residue file")]
fn post_checkpoint_residue(world: &mut CliWorld) {
    let src = world
        .warm_claim_src
        .as_ref()
        .expect("a Given step must seed a warm parent first");
    let residue = src.path().join("residue-secret.txt");
    std::fs::write(&residue, b"post-checkpoint-secret").expect("write the residue file");
}

#[then(expr = "the residue file is absent from the child's rootfs")]
fn residue_absent_from_child(world: &mut CliWorld) {
    let witness = match world
        .warm_claim_outcome
        .as_ref()
        .expect("a When step must attempt a claim first")
    {
        crate::world::WarmClaimOutcome::Claimed(w) => w.clone(),
        crate::world::WarmClaimOutcome::Refused { message, .. } => {
            panic!("expected the claim to succeed, but it was refused: {message}")
        }
    };
    let child_dir = mvm_core::config::vm_state_dir(&witness.child_id);
    let residue = child_dir.join("residue-secret.txt");
    assert!(
        !residue.exists(),
        "child rootfs must not contain post-checkpoint residue: {residue:?}"
    );
}

// ---- Warm-attach plan re-verification ----

#[given(expr = "a signed execution plan for tenant {string}")]
fn signed_execution_plan(world: &mut CliWorld, tenant: String) {
    sign_plan_for(world, &tenant, "host:test");
}

#[given(expr = "a signed execution plan for tenant {string} by signer {string}")]
fn signed_execution_plan_by_signer(world: &mut CliWorld, tenant: String, signer: String) {
    sign_plan_for(world, &tenant, &signer);
}

fn sign_plan_for(world: &mut CliWorld, tenant: &str, signer: &str) {
    use mvm_core::plan::sign_plan;

    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant(tenant)
        .nonce([9u8; 16])
        .build();
    let signed = sign_plan(&plan, &key, signer);
    world.warm_restore_plan_signer = Some(signer.to_string());
    world.warm_restore_plan_json =
        Some(serde_json::to_string(&signed).expect("serialize signed plan"));
    world.warm_restore_verify_result = None;
}

#[when(expr = "the plan JSON is tampered with an extra field")]
fn tamper_plan_json(world: &mut CliWorld) {
    use mvm_core::plan::SignedExecutionPlan;

    let json = world
        .warm_restore_plan_json
        .as_ref()
        .expect("a Given step must create a signed plan first");
    let mut signed: SignedExecutionPlan = serde_json::from_str(json).expect("plan JSON parses");
    // Tamper the signed payload bytes (the canonical plan JSON), not the outer
    // envelope. The signature was computed over the original payload bytes, so
    // changing any byte inside the payload makes the signature invalid.
    let mut payload = signed.0.payload.clone();
    if payload.is_empty() {
        payload.push(b'!');
    } else {
        payload[0] = payload[0].wrapping_add(1);
    }
    signed.0.payload = payload;
    world.warm_restore_plan_json =
        Some(serde_json::to_string(&signed).expect("serialize tampered plan"));
}

#[when(expr = "the plan is verified")]
fn verify_plan_step(world: &mut CliWorld) {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_core::plan::{SignedExecutionPlan, verify_plan};

    let json = world
        .warm_restore_plan_json
        .as_ref()
        .expect("a Given step must create a signed plan first");
    let signed: SignedExecutionPlan = serde_json::from_str(json).expect("plan JSON parses");
    // The verifier trusts exactly one signer id. A valid plan from that signer
    // verifies; a tampered payload fails with a signature error; a plan from
    // any other signer fails with UnknownSigner.
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let vk: VerifyingKey = (&key).into();
    world.warm_restore_verify_result = Some(
        verify_plan(&signed, &[("host:test", &vk)])
            .map(|plan| plan.tenant.0.clone())
            .map_err(|e| e.to_string()),
    );
}

#[then(expr = "plan verification fails with a signature error")]
fn plan_verify_fails_signature(world: &mut CliWorld) {
    let err = world
        .warm_restore_verify_result
        .as_ref()
        .expect("a When step must attempt verification first")
        .as_ref()
        .expect_err("tampered plan must fail verification");
    assert!(
        err.contains("signature") || err.contains("Signature") || err.contains("plan id"),
        "expected a signature/plan-id mismatch error, got: {err}"
    );
}

#[then(expr = "plan verification fails with an unknown signer error")]
fn plan_verify_fails_unknown_signer(world: &mut CliWorld) {
    let err = world
        .warm_restore_verify_result
        .as_ref()
        .expect("a When step must attempt verification first")
        .as_ref()
        .expect_err("unknown-signer plan must fail verification");
    assert!(
        err.contains("unknown signer")
            || err.contains("UnknownSigner")
            || err.contains("no trusted key matched signer_id"),
        "expected an unknown signer error, got: {err}"
    );
}

// ---- Live warm-restore positive path ----

#[when(expr = "I capture a vm_full checkpoint from {string}")]
fn capture_vm_full_checkpoint(world: &mut CliWorld, name: String) {
    // The user-facing path that captures a vm_full checkpoint on Firecracker is
    // `machine fork`, which also auto-boots a first child. The experimental guard
    // keeps the lower-level fork path opt-in until per-child guest re-addressing
    // lands, so this live scenario explicitly enables it.
    let mut cmd = crate::steps::cli::mvmctl_command();
    let home = world
        .isolated_home
        .as_ref()
        .expect("an isolated mvm home must be created first");
    let output = cmd
        .current_dir(crate::steps::cli::workspace_root())
        .args(["machine", "fork", "--json", &name])
        .env("HOME", home.path())
        .env("MVM_HOME", home.path())
        .env("MVM_FORK_VMFULL_FC_EXPERIMENTAL", "1")
        .output()
        .expect("failed to spawn mvmctl machine fork");
    world.last_run = Some(output);
    if world.last_output().status.success() {
        let stdout = String::from_utf8_lossy(&world.last_output().stdout);
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).expect("machine fork --json must emit JSON");
        let id = parsed
            .get("parent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .expect("fork JSON must contain parent_id (the captured checkpoint id)");
        world.warm_restore_checkpoint_id = Some(id);
    }
}

#[when(expr = "I stop the parent VM {string}")]
fn stop_parent_vm(world: &mut CliWorld, name: String) {
    crate::steps::cli::run_mvmctl_isolated_live_home(world, format!("machine stop {name}"));
}

#[when(expr = "I warm-restore the checkpoint into a child named {string}")]
fn warm_restore_checkpoint(world: &mut CliWorld, child: String) {
    let id = world
        .warm_restore_checkpoint_id
        .as_ref()
        .expect("a checkpoint must be captured first")
        .clone();
    mvm_core::naming::validate_vm_name(&child).expect("child VM name must be valid");
    crate::steps::cli::run_mvmctl_isolated_live_home(
        world,
        format!("machine warm-restore {id} --name {child}"),
    );
}

#[then(expr = "the child VM {string} is running")]
fn child_vm_running(world: &mut CliWorld, child: String) {
    crate::steps::cli::run_mvmctl_isolated_live_home(world, format!("machine inspect {child}"));
    let output = world.last_output();
    assert!(
        output.status.success(),
        "machine inspect must succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Running"),
        "expected child {child:?} to be Running; got:\n{stdout}"
    );
}
