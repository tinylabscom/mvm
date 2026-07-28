//! Live integration for the Firecracker warm-pool parent/claim path.
//!
//! Drives the real `FcDriver::spawn_standby_parent` (boot + `VmFull` capture)
//! and `FcDriver::fork_standby_child` (snapshot restore into a new identity)
//! against a real KVM host. The test needs:
//!
//! * `/dev/kvm`
//! * `MVM_LIVE_KERNEL` pointing at an FC-loadable vmlinux
//! * `MVM_LIVE_ROOTFS` pointing at a writable ext4 rootfs whose `/init` binds
//!   the guest agent vsock port (5252) so `FcDriver::boot` confirms the guest
//!   is up before capturing the parent checkpoint.
//!
//! It is `#[ignore]` so CI never runs it; execute manually on a KVM box with
//! `cargo test -p mvm-runtime --test fc_warm_pool_live -- --ignored --nocapture`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Instant;

use mvm_agentd::vsock::connect_to;
use mvm_core::crypto::vmgenid::GenerationToken;
use mvm_core::vm_backend::{StandbySpec, StandbyState};
use mvm_runtime::driver::fc::FcDriver;
use mvm_runtime::driver::{ChildForkRequest, VmmDriver};

struct LiveImages {
    kernel: PathBuf,
    rootfs: PathBuf,
}

fn live_images() -> Option<LiveImages> {
    let kernel = std::env::var("MVM_LIVE_KERNEL").ok()?;
    let rootfs = std::env::var("MVM_LIVE_ROOTFS").ok()?;
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skip: /dev/kvm not present");
        return None;
    }
    Some(LiveImages {
        kernel: PathBuf::from(kernel),
        rootfs: PathBuf::from(rootfs),
    })
}

fn sha256(path: &Path) -> String {
    mvm_core::crypto::image_verify::sha256_file(path).expect("sha256 file")
}

#[test]
#[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS with /init listening on vsock agent port"]
fn fc_warm_pool_spawn_and_claim() {
    let Some(images) = live_images() else {
        eprintln!("skip: MVM_LIVE_KERNEL/ROOTFS not set or /dev/kvm missing");
        return;
    };

    let home = tempfile::tempdir().expect("tempdir");
    unsafe { std::env::set_var("MVM_HOME", home.path()) };

    let pid = std::process::id();
    let parent_id = format!("fc-warm-live-parent-{pid}");
    let child_id = format!("fc-warm-live-child-{pid}");

    let spec = StandbySpec {
        id: parent_id.clone(),
        template_id: None,
        kernel_path: images.kernel.to_string_lossy().into_owned(),
        kernel_sha256: sha256(&images.kernel),
        vcpus: 2,
        mem_mib: 512,
        signing_key_path: home
            .path()
            .join("host-signer.ed25519")
            .to_string_lossy()
            .into_owned(),
        signer_id: "host:test".into(),
        binding_nonce: format!("nonce-{pid}"),
        control_socket: home
            .path()
            .join("control.sock")
            .to_string_lossy()
            .into_owned(),
        vm_state_dir: home.path().join("state").to_string_lossy().into_owned(),
        image_path: Some(images.rootfs.to_string_lossy().into_owned()),
        image_sha256: Some(sha256(&images.rootfs)),
        parent_checkpoint: None,
    };

    let driver = FcDriver::new();
    assert!(driver.capabilities().standby_pool);

    let t_spawn = Instant::now();
    let handle = driver
        .spawn_standby_parent(&spec)
        .expect("spawn Firecracker standby parent");
    let spawn_ms = t_spawn.elapsed().as_millis();

    assert_eq!(handle.id, parent_id);
    assert_eq!(handle.state, StandbyState::Idle);
    assert_eq!(handle.pid, 0, "saved-state standby has no live parent pid");
    let parent_checkpoint = handle
        .parent_checkpoint
        .as_deref()
        .expect("handle records the parent checkpoint id");

    let store = mvm_runtime::checkpoint::CheckpointStore::open();
    let content_dir =
        store.content_dir(&mvm_core::checkpoint::CheckpointId::new(parent_checkpoint));

    println!("FC_WARM_POOL_SPAWN_MS={spawn_ms}");

    let mut claim_ms = Vec::new();
    for i in 0..5 {
        let claim_child_id = format!("{child_id}-claim-{i}");
        let claim_child_dir = mvm_core::config::vm_state_dir(&claim_child_id);
        std::fs::create_dir_all(&claim_child_dir).expect("create claim child vm dir");
        for name in [
            "memory.bin",
            "vmstate.bin",
            "rootfs.ext4",
            "device-anchors.json",
        ] {
            let src = content_dir.join(name);
            if src.exists() {
                std::fs::copy(&src, claim_child_dir.join(name))
                    .unwrap_or_else(|e| panic!("copy {} to claim child dir: {}", src.display(), e));
            }
        }

        let t_claim = Instant::now();
        let fork_result = driver.fork_standby_child(&ChildForkRequest {
            child_vm_name: &claim_child_id,
            child_dir: &claim_child_dir,
            genid: GenerationToken {
                token: [0u8; mvm_core::crypto::vmgenid::GENID_BYTES],
                content_hash: parent_checkpoint.into(),
            },
        });
        if let Err(ref e) = fork_result {
            eprintln!("fork failed: {e:#}");
            for name in ["firecracker.log", "console.log"] {
                let path = claim_child_dir.join(name);
                if path.exists() {
                    eprintln!("--- {name} ---");
                    if let Ok(bytes) = std::fs::read(&path) {
                        eprintln!("{}", String::from_utf8_lossy(&bytes));
                    }
                }
            }
        }
        fork_result.expect("fork Firecracker standby child");
        claim_ms.push(t_claim.elapsed().as_millis());

        let child_vsock =
            mvm_runtime::microvm::firecracker_vsock_uds_path(&claim_child_dir.to_string_lossy());
        let connected = connect_to(&child_vsock, 5).is_ok();
        assert!(
            connected,
            "child VM must answer on its vsock agent port after fork restore"
        );

        let _ = mvm_runtime::microvm::stop_vm(&claim_child_id);
        let _ = std::fs::remove_dir_all(&claim_child_dir);
    }

    claim_ms.sort_unstable();
    let p50 = claim_ms[claim_ms.len() / 2];
    let p99 = claim_ms[(claim_ms.len() * 99) / 100];
    println!("FC_WARM_POOL_CLAIM_MS_P50={p50}");
    println!("FC_WARM_POOL_CLAIM_MS_P99={p99}");
    println!("FC_WARM_POOL_CLAIM_MS_ALL={claim_ms:?}");
}
