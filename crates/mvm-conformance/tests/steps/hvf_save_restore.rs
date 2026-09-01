//! Step definitions for the HVF save/restore surface.
//!
//! Hermetic: every scenario drives the real host-side seams — the launch-config
//! rewrite an HVF restore performs, the checkpoint origin classifier, and
//! `restore_checkpoint`'s fail-closed lineage gate — with no hypervisor. The
//! properties under test are refusals and what a restored machine comes up
//! holding, neither of which needs a booted guest to observe.

use std::path::PathBuf;

use cucumber::{given, then, when};

use mvm_core::checkpoint::{
    CheckpointClass, CheckpointDigest, CheckpointId, CheckpointMeta, ContentBlob, DeviceAnchors,
    HVF_FRAME_BLOB, MEMORY_BLOB, ROOTFS_BLOB, SUPERVISOR_CONFIG_BLOB, VmFullOrigin, vm_full_origin,
};
use mvm_runtime::checkpoint::{CheckpointChainAnchor, CheckpointStore, RestoreParams};
use mvm_runtime::hvf_restore::{HvfRestoreRequest, hvf_child_restore_config};
use mvm_vmm::host::hvf_supervisor::{HostDialSocket, HvfDisk, HvfSupervisorConfig};

use crate::world::CliWorld;

/// A chain anchor whose verdict is fixed per scenario: either it echoes the
/// digest the record was sealed with (audited), or it reports nothing (never
/// audited). Echoing the *sealed* digest is what makes a post-seal edit
/// detectable — the anchor keeps agreeing with the original.
struct FixedAnchor(Option<CheckpointDigest>);

impl CheckpointChainAnchor for FixedAnchor {
    fn recorded_creation_digest(
        &self,
        _meta: &CheckpointMeta,
    ) -> anyhow::Result<Option<CheckpointDigest>> {
        Ok(self.0.clone())
    }
}

/// A restore seam that records nothing and does nothing. Every scenario here
/// asserts a refusal, so reaching this double at all is the failure.
struct NeverReachedRestore;

impl mvm_runtime::checkpoint::VmFullRestore for NeverReachedRestore {
    fn restore(
        &self,
        _target_vm: &str,
        _rootfs_src: &std::path::Path,
        _memory: &std::path::Path,
        _machine_id: &std::path::Path,
        _config_src: Option<&std::path::Path>,
    ) -> anyhow::Result<()> {
        panic!("the VMM must not be started for a checkpoint that failed its gate");
    }
}

// ── the launch-config rewrite ───────────────────────────────────────────────

/// A parent config whose per-VM paths, relays and console sockets all point at
/// the parent — the shape a live, admitted, dev-console HVF workload has.
fn parent_config(state_dir: &std::path::Path) -> HvfSupervisorConfig {
    HvfSupervisorConfig {
        kernel: state_dir.join("Image"),
        cmdline: Some("console=ttyAMA0 root=/dev/vda ro".into()),
        memory_mib: 512,
        vcpus: 1,
        initramfs: None,
        disks: vec![HvfDisk {
            path: PathBuf::from("/parent/state/rootfs.ext4"),
            read_only: true,
            ephemeral: false,
        }],
        virtiofs_shares: Vec::new(),
        vsock: true,
        trusted_builder_egress: false,
        console_log: PathBuf::from("/parent/state/console.log"),
        pid_file: PathBuf::from("/parent/state/hvf.pid"),
        workload_exit: PathBuf::from("/parent/state/workload.exit"),
        pause_state: Some(PathBuf::from("/parent/state/pause.state")),
        snapshot_request: Some(PathBuf::from("/parent/state/snapshot.request")),
        snapshot_ram: Some(PathBuf::from("/parent/state/snapshot.ram")),
        snapshot_frame: Some(PathBuf::from("/parent/state/snapshot.frame")),
        restore_ram: None,
        restore_frame: None,
        timeout_secs: 0,
        plan: None,
        audit_dir: None,
        signing_key_path: None,
        agent_socket: Some(PathBuf::from("/parent/state/hvf-agent.sock")),
        substitution_socket: Some(PathBuf::from("/parent/state/substitution.sock")),
        egress_relay_socket: Some(PathBuf::from("/parent/state/egress.sock")),
        broker_socket: Some(PathBuf::from("/parent/state/broker.sock")),
        console_data_sockets: vec![HostDialSocket {
            guest_port: 20001,
            host_socket: PathBuf::from("/parent/state/vsock/vsock-20001.sock"),
        }],
        builder_control_sockets: Vec::new(),
        exclusive_image_lock: None,
        handoff_socket: Some(PathBuf::from("/parent/state/hvf-handoff.sock")),
        handoff_root: Some(PathBuf::from("/parent/vms")),
        handoff_verify_key: Some("ab".repeat(32)),
        cpu_millicores: None,
        quota_record: None,
    }
}

/// Lay down everything a restore needs in the child's state dir.
fn materialize_child_state(world: &mut CliWorld) -> PathBuf {
    let tmp = tempfile::tempdir().expect("create HVF restore scenario tempdir");
    let dir = tmp.path().to_path_buf();
    std::fs::write(dir.join("Image"), b"kernel").expect("write kernel");
    std::fs::write(dir.join(MEMORY_BLOB), b"saved-ram").expect("write saved RAM");
    std::fs::write(dir.join(HVF_FRAME_BLOB), b"saved-frame").expect("write saved frame");
    std::fs::write(dir.join(ROOTFS_BLOB), b"child-rootfs").expect("write child rootfs");
    world.hvf_restore_tmp = Some(tmp);
    dir
}

#[given(
    expr = "a captured HVF launch config carrying an egress relay, a broker and a console socket"
)]
fn captured_config_with_relays(world: &mut CliWorld) {
    let dir = materialize_child_state(world);
    world.hvf_parent_config = Some(parent_config(&dir));
}

#[given(expr = "a captured HVF launch config whose per-VM paths all point at the parent")]
fn captured_config_with_parent_paths(world: &mut CliWorld) {
    let dir = materialize_child_state(world);
    world.hvf_parent_config = Some(parent_config(&dir));
}

#[when(expr = "the captured config is rewritten for a restored child")]
fn rewrite_for_child(world: &mut CliWorld) {
    let dir = world
        .hvf_restore_tmp
        .as_ref()
        .expect("a captured config must be prepared first")
        .path()
        .to_path_buf();
    let parent = world
        .hvf_parent_config
        .as_ref()
        .expect("a captured config must be prepared first");
    let anchors = DeviceAnchors {
        rootfs: PathBuf::from("/parent/state/rootfs.ext4"),
        rootfs_verity: None,
        config: None,
        secrets: None,
        vsock: PathBuf::from("/parent/state/hvf-agent.sock"),
    };
    let child = hvf_child_restore_config(
        parent,
        &anchors,
        &HvfRestoreRequest {
            vm_name: "restored-child",
            state_dir: &dir,
            cpu_grant: None,
        },
    )
    .expect("rewrite the captured config for a restored child");
    world.hvf_child_config = Some(child);
}

fn child_config(world: &CliWorld) -> &HvfSupervisorConfig {
    world
        .hvf_child_config
        .as_ref()
        .expect("the config must be rewritten first")
}

#[then(expr = "the restored config carries no egress relay, broker or console socket")]
fn child_has_no_relays(world: &mut CliWorld) {
    let child = child_config(world);
    assert_eq!(child.egress_relay_socket, None, "egress relay survived");
    assert_eq!(child.substitution_socket, None, "substitution survived");
    assert_eq!(child.broker_socket, None, "broker survived");
    assert!(
        child.console_data_sockets.is_empty(),
        "console data sockets survived"
    );
}

#[then(expr = "the restored config carries no live-handoff control socket")]
fn child_has_no_handoff(world: &mut CliWorld) {
    let child = child_config(world);
    assert_eq!(child.handoff_socket, None, "handoff socket survived");
    assert_eq!(child.handoff_root, None, "handoff root survived");
    assert_eq!(child.handoff_verify_key, None, "handoff key survived");
}

#[then(expr = "the restored config loads the saved machine state instead of booting a kernel")]
fn child_loads_saved_state(world: &mut CliWorld) {
    let dir = world
        .hvf_restore_tmp
        .as_ref()
        .expect("scenario tempdir")
        .path();
    let child = child_config(world);
    assert_eq!(child.restore_ram, Some(dir.join(MEMORY_BLOB)));
    assert_eq!(child.restore_frame, Some(dir.join(HVF_FRAME_BLOB)));
}

#[then(expr = "every per-VM path in the restored config points at the child's own state directory")]
fn child_paths_are_rehomed(world: &mut CliWorld) {
    let dir = world
        .hvf_restore_tmp
        .as_ref()
        .expect("scenario tempdir")
        .path()
        .to_path_buf();
    let child = child_config(world);
    assert_eq!(child.pid_file, dir.join("hvf.pid"));
    assert_eq!(child.console_log, dir.join("console.log"));
    assert_eq!(child.workload_exit, dir.join("workload.exit"));
    assert_eq!(child.pause_state, Some(dir.join("pause.state")));
    assert_eq!(child.snapshot_ram, Some(dir.join("snapshot.ram")));
    assert_eq!(child.snapshot_frame, Some(dir.join("snapshot.frame")));
    assert_eq!(
        child.agent_socket,
        Some(mvm_core::config::vm_hvf_agent_socket_at(&dir))
    );
}

#[then(expr = "the restored config reads its rootfs from the child's own clone")]
fn child_rootfs_is_its_own(world: &mut CliWorld) {
    let dir = world
        .hvf_restore_tmp
        .as_ref()
        .expect("scenario tempdir")
        .path();
    let child = child_config(world);
    assert_eq!(child.disks.len(), 1, "one rootfs disk");
    assert_eq!(child.disks[0].path, dir.join(ROOTFS_BLOB));
    assert!(child.disks[0].read_only, "a restored disk stays read-only");
}

// ── checkpoint origin + the lineage gate ────────────────────────────────────

/// Seal a vm_full checkpoint carrying `content` into a scenario-local store.
fn seed_checkpoint(world: &mut CliWorld, id: &str, content: Vec<ContentBlob>) -> CheckpointMeta {
    let tmp = world
        .hvf_ckpt_tmp
        .get_or_insert_with(|| tempfile::tempdir().expect("create checkpoint scenario tempdir"));
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let content_dir = store.content_dir(&CheckpointId::new(id));
    std::fs::create_dir_all(&content_dir).expect("create checkpoint content dir");
    for blob in &content {
        std::fs::write(content_dir.join(&blob.name), blob.name.as_bytes())
            .expect("write checkpoint blob");
    }
    let content = content
        .into_iter()
        .map(|blob| ContentBlob {
            sha256: mvm_core::crypto::image_verify::sha256_file(&content_dir.join(&blob.name))
                .expect("hash checkpoint blob"),
            name: blob.name,
        })
        .collect();
    let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::VmFull, "hvf-vm")
        .created_unix(1)
        .content(content)
        .build();
    store.write_meta(&meta).expect("seal checkpoint");
    world.hvf_ckpt_store = Some(store);
    world.hvf_ckpt_meta = Some(meta.clone());
    meta
}

fn hvf_content() -> Vec<ContentBlob> {
    [
        "rootfs.ext4",
        MEMORY_BLOB,
        HVF_FRAME_BLOB,
        SUPERVISOR_CONFIG_BLOB,
    ]
    .into_iter()
    .map(|name| ContentBlob {
        name: name.into(),
        sha256: String::new(),
    })
    .collect()
}

#[given(expr = "an audited HVF vm_full checkpoint")]
fn audited_hvf_checkpoint(world: &mut CliWorld) {
    let meta = seed_checkpoint(world, "hvf-audited", hvf_content());
    world.hvf_anchor = Some(FixedAnchor(Some(meta.compute_meta_digest())).0);
}

#[given(expr = "an HVF vm_full checkpoint that no signed audit entry covers")]
fn unaudited_hvf_checkpoint(world: &mut CliWorld) {
    seed_checkpoint(world, "hvf-unaudited", hvf_content());
    world.hvf_anchor = Some(None);
}

#[given(expr = "a vm_full checkpoint carrying a launch config but no machine-state blob")]
fn retired_backend_checkpoint(world: &mut CliWorld) {
    let content = ["rootfs.ext4", MEMORY_BLOB, SUPERVISOR_CONFIG_BLOB]
        .into_iter()
        .map(|name| ContentBlob {
            name: name.into(),
            sha256: String::new(),
        })
        .collect();
    let meta = seed_checkpoint(world, "retired", content);
    world.hvf_anchor = Some(Some(meta.compute_meta_digest()));
}

#[when(expr = "the sealed record is edited after it was audited")]
fn edit_after_seal(world: &mut CliWorld) {
    let store = world.hvf_ckpt_store.as_ref().expect("a seeded checkpoint");
    let mut meta = world.hvf_ckpt_meta.clone().expect("a seeded checkpoint");
    meta.vm_name = "renamed-after-seal".into();
    store.write_meta(&meta).expect("rewrite the sealed record");
}

/// Run the full refusal ladder a `checkpoint restore` walks: resolve the VMM
/// that can load this machine state, then verify content and lineage. Either
/// gate refusing is a refusal before any VMM starts — the injected restore seam
/// panics if it is ever reached.
#[then(expr = "restoring the checkpoint is refused before the VMM is started")]
fn restore_is_refused(world: &mut CliWorld) {
    let store = world.hvf_ckpt_store.as_ref().expect("a seeded checkpoint");
    let meta = world.hvf_ckpt_meta.as_ref().expect("a seeded checkpoint");
    let anchor = FixedAnchor(world.hvf_anchor.clone().expect("a scenario anchor"));
    let error = mvm_runtime::checkpoint::vm_full_restorer_for(meta)
        .and_then(|_| {
            mvm_runtime::checkpoint::restore_checkpoint(
                store,
                RestoreParams {
                    checkpoint: meta.id.clone(),
                    target_vm: meta.vm_name.clone(),
                },
                &NeverReachedRestore,
                &anchor,
            )
        })
        .expect_err("the restore must be refused");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("drift")
            || rendered.contains("no signed audit entry")
            || rendered.contains("has been removed"),
        "expected a lineage or dispatch refusal, got: {rendered}"
    );
}

#[then(expr = "its origin is reported as a removed backend")]
fn origin_is_retired(world: &mut CliWorld) {
    let meta = world.hvf_ckpt_meta.as_ref().expect("a seeded checkpoint");
    assert_eq!(vm_full_origin(meta), Some(VmFullOrigin::Retired));
}

#[then(expr = "its origin is reported as the in-house HVF VMM")]
fn origin_is_hvf(world: &mut CliWorld) {
    let meta = world.hvf_ckpt_meta.as_ref().expect("a seeded checkpoint");
    assert_eq!(vm_full_origin(meta), Some(VmFullOrigin::Hvf));
}
