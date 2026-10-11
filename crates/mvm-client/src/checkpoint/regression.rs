//! Regressions migrated from the command checkpoint implementation.

use super::capture::lock_machine_input_cursor;
use super::*;
use crate::replay::input_journal;
use mvm_core::checkpoint::{CheckpointClass, CheckpointDigest, ContentBlob};
use mvm_core::config::{machine_state_dir, vm_state_dir};
use mvm_core::image_lineage::{
    ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
};
use mvm_runtime::checkpoint::{CheckpointChainAnchor, verify_lineage};
use mvm_runtime::image_lineage::{ImageStore, verify_image_lineage};

#[test]
fn checkpoint_cursor_reads_the_machine_exec_journal() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let home = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(home.path());
    let dir = machine_state_dir("cursor-source");
    let pending = input_journal::begin_exec(&dir, &["/bin/true".into()]).expect("begin exec");
    input_journal::finish_exec(&dir, pending, true).expect("finish exec");
    assert_ne!(dir, vm_state_dir("cursor-source"));
    let (_lock, cursor) = lock_machine_input_cursor("cursor-source").expect("cursor");
    assert_eq!(cursor, 1);
}

#[test]
fn checkpoint_cursor_refuses_unfinished_machine_exec() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let home = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(home.path());
    let dir = machine_state_dir("cursor-pending");
    input_journal::begin_exec(&dir, &["/bin/true".into()]).expect("begin exec");
    assert!(lock_machine_input_cursor("cursor-pending").is_err());
}

#[test]
fn checkpoint_cursor_is_zero_for_a_new_machine() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let home = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(home.path());
    let (_lock, cursor) = lock_machine_input_cursor("cursor-empty").expect("cursor");
    assert_eq!(cursor, 0);
}

fn checkpoint(id: &str, parent: Option<&CheckpointMeta>) -> CheckpointMeta {
    CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm-alpha")
        .parent(parent.map(|p| p.meta_digest.clone()))
        .content(vec![])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build()
}

#[test]
fn rm_refuses_a_checkpoint_pinned_by_a_parked_session() {
    use mvm_contract::protocol::agent_session::AgentSessionId;
    use mvm_runtime::agent_session::{AgentSessionRecord, AgentSessionStore, SandboxResidency};

    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let service = Checkpoints::open();
    let meta = checkpoint("ckpt-pinned", None);
    service.store.write_meta(&meta).unwrap();
    AgentSessionStore::open()
        .write(&AgentSessionRecord {
            session_id: AgentSessionId::parse("sess-parked").unwrap(),
            generation: 1,
            state: SandboxResidency::Hibernated,
            members: vec!["vm-alpha".to_string()],
            parent_checkpoint: Some(meta.meta_digest.clone()),
            created_unix: 0,
            updated_unix: 0,
            journal_cursor: 0,
            approval_head: None,
            storage_tier: None,
            park_reason: None,
            retain_until_unix: None,
            last_transition: None,
        })
        .unwrap();
    let err = service.remove(&meta.id).unwrap_err();
    assert!(
        err.to_string().contains("sess-parked"),
        "refusal must name the session holding the checkpoint: {err}"
    );
    assert!(
        service.read(&meta.id).is_ok(),
        "checkpoint must survive refusal"
    );
}

#[test]
fn rm_refuses_a_checkpoint_a_stored_descendant_restores_through() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let service = Checkpoints::open();
    let parent = checkpoint("ckpt-parent", None);
    let child = checkpoint("ckpt-child", Some(&parent));
    service.store.write_meta(&parent).unwrap();
    service.store.write_meta(&child).unwrap();
    let err = service.remove(&parent.id).unwrap_err();
    assert!(
        err.to_string().contains("ckpt-child"),
        "refusal must name the descendant that restores through it: {err}"
    );
    assert!(service.read(&parent.id).is_ok());
    service.remove(&child.id).unwrap();
    service.remove(&parent.id).unwrap();
    assert!(
        service.read(&parent.id).is_err(),
        "parent becomes removable after its child"
    );
}

#[test]
fn descendants_restoring_through_agrees_in_number() {
    // Exercise the actual catalog refusal rather than exposing its formatter.
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let service = Checkpoints::open();
    let parent = checkpoint("parent", None);
    service.store.write_meta(&parent).unwrap();
    service
        .store
        .write_meta(&checkpoint("a", Some(&parent)))
        .unwrap();
    assert_eq!(
        service.remove(&parent.id).unwrap_err().to_string(),
        "cannot remove checkpoint 'parent': checkpoint 'a' restores through it; remove it first"
    );
    service
        .store
        .write_meta(&checkpoint("b", Some(&parent)))
        .unwrap();
    assert_eq!(
        service.remove(&parent.id).unwrap_err().to_string(),
        "cannot remove checkpoint 'parent': checkpoints 'a', 'b' restore through it; remove them first"
    );
}

#[test]
fn rm_removes_a_checkpoint_no_session_pins() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let service = Checkpoints::open();
    let meta = checkpoint("ckpt-unpinned", None);
    service.store.write_meta(&meta).unwrap();
    service.remove(&meta.id).unwrap();
    assert!(
        service.read(&meta.id).is_err(),
        "an unpinned checkpoint remains removable"
    );
}

#[test]
fn stopped_vm_is_quiesced() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    assert!(
        vm_is_quiesced("no-such-vm-stopped"),
        "stopped VM must be quiesced"
    );
}

fn live_fc(name: &str) -> u32 {
    let pid = std::process::id();
    let state_dir = vm_state_dir(name);
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("fc.pid"), pid.to_string()).unwrap();
    pid
}

#[test]
fn fc_paused_vm_with_matching_marker_is_quiesced() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let pid = live_fc("fcpausedvm");
    std::fs::write(
        vm_state_dir("fcpausedvm").join("fc.paused"),
        pid.to_string(),
    )
    .unwrap();
    assert!(fc_pause_marker_matches_live_pid("fcpausedvm"));
    assert!(
        vm_is_quiesced("fcpausedvm"),
        "paused FC VM must be quiesced"
    );
}

#[test]
fn fc_running_without_marker_is_not_quiesced() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    live_fc("fcrunningvm");
    assert!(!fc_pause_marker_matches_live_pid("fcrunningvm"));
    assert!(
        !vm_is_quiesced("fcrunningvm"),
        "running FC VM without marker must not be quiesced"
    );
}

#[test]
fn fc_stale_marker_is_not_quiesced() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let pid = live_fc("fcstalevm");
    std::fs::write(
        vm_state_dir("fcstalevm").join("fc.paused"),
        pid.saturating_add(1).to_string(),
    )
    .unwrap();
    assert!(!fc_pause_marker_matches_live_pid("fcstalevm"));
    assert!(
        !vm_is_quiesced("fcstalevm"),
        "stale pause marker must not quiesce live VM"
    );
}

fn mode_rootfs(name: &str, rootfs: &Path) {
    let dir = vm_state_dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    let meta = mvm_runtime::base::runtime_meta::VmRuntimeMeta {
        mode: mvm_runtime::base::runtime_meta::StartModeKind::Detached,
        accessible: false,
        rootfs_path: Some(rootfs.to_string_lossy().into_owned()),
        runtime_overlay_version: None,
        observability_target: None,
    };
    std::fs::write(dir.join("mode.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
}

#[test]
fn resolve_rootfs_from_mode_json_when_present() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let rootfs = tmp.path().join("images/rootfs.ext4");
    std::fs::create_dir_all(rootfs.parent().unwrap()).unwrap();
    std::fs::write(&rootfs, b"fake rootfs").unwrap();
    mode_rootfs("mode-json-rootfs-vm", &rootfs);
    assert_eq!(
        resolve_quiesced_vm_rootfs("mode-json-rootfs-vm").expect("must resolve"),
        rootfs
    );
}

#[test]
fn mode_json_rootfs_path_missing_on_disk_produces_actionable_error() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let rootfs = tmp.path().join("gone/rootfs.ext4");
    mode_rootfs("mode-json-gone-vm", &rootfs);
    let err = resolve_quiesced_vm_rootfs("mode-json-gone-vm").expect_err("must error");
    let msg = err.to_string();
    assert!(
        msg.contains("pause") || msg.contains("vm-full") || msg.contains("vm_full"),
        "error must guide the user: {msg}"
    );
}

#[test]
fn live_fc_vm_is_not_quiesced() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path().join("mvm"));
    live_fc("live-fc-vm-quiesce-test");
    assert!(
        !vm_is_quiesced("live-fc-vm-quiesce-test"),
        "live fc.pid must prevent quiescence"
    );
}

#[test]
fn resolve_quiesced_vm_rootfs_refuses_live_fc_vm() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path().join("mvm"));
    let name = "live-fc-refuse-test";
    live_fc(name);
    let err = resolve_quiesced_vm_rootfs(name).expect_err("live FC VM must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("stop or pause"),
        "error must tell user to stop or pause: {msg}"
    );
    assert!(msg.contains(name), "error must name the VM: {msg}");
}

#[test]
fn stopped_fc_vm_is_quiesced() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path().join("mvm"));
    assert!(
        vm_is_quiesced("stopped-fc-vm-test"),
        "stopped FC VM must be quiesced"
    );
}

#[test]
fn save_restore_gate_error_is_backend_neutral() {
    use mvm_core::vm_backend::SnapshotCapability;
    assert!(SnapshotCapability::LiveMemory.satisfies(SnapshotCapability::SaveRestore));
    assert!(SnapshotCapability::SaveRestore.satisfies(SnapshotCapability::SaveRestore));
    assert!(!SnapshotCapability::Unsupported.satisfies(SnapshotCapability::SaveRestore));
}

fn seed_audited_checkpoint(store: &CheckpointStore, id: &str, rootfs_sha: &str) -> CheckpointMeta {
    let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: rootfs_sha.into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
    store.write_meta(&meta).unwrap();
    let signer = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
    let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing).unwrap();
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .plan_id("plan-verify")
        .build();
    mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
    meta
}

#[test]
fn signed_chain_anchor_indexes_a_real_created_entry_and_verify_passes() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let store = CheckpointStore::open();
    let meta = seed_audited_checkpoint(&store, "ckpt-anchor-1", "aa");
    let anchor = SignedChainAnchor::load().unwrap();
    assert_eq!(
        anchor.recorded_creation_digest(&meta).unwrap(),
        Some(meta.meta_digest.clone())
    );
    verify_lineage(&store, &meta.id, &anchor).unwrap();
}

#[test]
fn chain_anchor_catches_a_fully_consistent_local_reforge() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let store = CheckpointStore::open();
    seed_audited_checkpoint(&store, "ckpt-anchor-2", "aa");
    let reforged = CheckpointMeta::builder(
        CheckpointId::new("ckpt-anchor-2"),
        CheckpointClass::FsQuick,
        "vm",
    )
    .content(vec![ContentBlob {
        name: "rootfs.ext4".into(),
        sha256: "zz".into(),
    }])
    .supervisor_config_digest("d")
    .created_unix(1)
    .build();
    store.write_meta(&reforged).unwrap();
    assert_eq!(reforged.meta_digest, reforged.compute_meta_digest());
    let anchor = SignedChainAnchor::load().unwrap();
    let err = verify_lineage(&store, &reforged.id, &anchor).unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match the signed audit chain"),
        "signed chain must catch a consistent local re-forge: {err}"
    );
}

fn image_node(slot: &str, revision: &str, parent: Option<CheckpointDigest>) -> ImageNode {
    ImageNode::builder(
        ImageBuildIdentity::Flake {
            slot_hash: slot.into(),
        },
        ImageIdentity {
            canonical: ImageCanonicalId::Flake {
                revision_hash: revision.into(),
            },
            artifacts: vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: revision.into(),
            }],
        },
        ImageProvenance::Build {
            input_ref: ".#app".into(),
            lock_digest: None,
        },
    )
    .parent(parent)
    .created_unix(1)
    .build()
}

fn seed_audited_image_node(store: &ImageStore, node: &ImageNode) {
    store.save(node).unwrap();
    let signer = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
    let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing).unwrap();
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .plan_id("plan-image-verify")
        .build();
    emitter.emit_image_created(&plan, node).unwrap();
}

#[test]
fn image_lineage_verifies_against_a_real_signed_chain() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let store = ImageStore::open();
    let g0 = image_node("slot-a", "rev-1", None);
    let g1 = image_node("slot-a", "rev-2", Some(g0.node_digest.clone()));
    let g2 = image_node("slot-a", "rev-3", Some(g1.node_digest.clone()));
    seed_audited_image_node(&store, &g0);
    seed_audited_image_node(&store, &g1);
    seed_audited_image_node(&store, &g2);
    let anchor = SignedChainAnchor::load().unwrap();
    verify_image_lineage(&store, &g2.node_digest, &anchor).unwrap();
    assert_eq!(
        store
            .head_for(&ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into()
            })
            .unwrap()
            .unwrap()
            .node_digest,
        g2.node_digest
    );
}

#[test]
fn image_lineage_refuses_a_node_absent_from_the_signed_chain() {
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(tmp.path());
    let store = ImageStore::open();
    let g0 = image_node("slot-a", "rev-1", None);
    store.save(&g0).unwrap();
    let anchor = SignedChainAnchor::load().unwrap();
    let err = verify_image_lineage(&store, &g0.node_digest, &anchor).unwrap_err();
    assert!(err.to_string().contains("no signed audit entry"), "{err}");
}
