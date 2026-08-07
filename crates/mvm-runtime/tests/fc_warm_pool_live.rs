//! Live integration for the Firecracker warm-pool parent/claim path.
//!
//! Drives the real driver seam end to end against a KVM host:
//! `FcDriver::spawn_standby_parent` boots a clean factory parent,
//! `capture_vm_full` takes its {rootfs, memory, vmstate} triple through the
//! driver's own `vm_full_control`, and `FcDriver::fork_standby_child` restores
//! a fresh child out of that saved memory. Those three calls are exactly what
//! the role layer strings together for a claim, so the two numbers this prints
//! bound how fast a pooled claim can be.
//!
//! It needs:
//!
//! * `/dev/kvm`
//! * `MVM_LIVE_KERNEL` pointing at an FC-loadable vmlinux
//! * `MVM_LIVE_ROOTFS` pointing at an ext4 rootfs whose `/init` binds the guest
//!   agent vsock port, because `FcDriver::boot` returns only once the agent
//!   answers — that is what makes the captured memory a fully-booted guest.
//!
//! It is `#[ignore]` so CI never runs it; execute manually on a KVM box with
//! `cargo test -p mvm-runtime --test fc_warm_pool_live -- --ignored --nocapture`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Instant;

use mvm_agentd::vsock::connect_to;
use mvm_core::checkpoint::CheckpointId;
use mvm_core::crypto::vmgenid::{GENID_BYTES, GenerationToken};
use mvm_core::vm_backend::{StandbySpec, StandbyState, StartMode};
use mvm_runtime::checkpoint::{CaptureVmFullParams, CheckpointStore, capture_vm_full};
use mvm_runtime::driver::fc::FcDriver;
use mvm_runtime::driver::{
    BlockDev, ChildForkRequest, ConsoleCapture, KernelImage, StandbyParentSpawn, VmmDriver, VmmSpec,
};

/// How long the child's agent gets to answer after the fork restore resumes it.
const CHILD_AGENT_TIMEOUT_SECS: u64 = 5;

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

/// The parent's boot recipe. A factory parent boots the same NIC-less shape a
/// workload does — one virtio-blk root, a console capture, no network device —
/// because every child restored from it inherits this device model and cmdline
/// out of the saved memory.
fn parent_boot_spec(name: &str, images: &LiveImages, state_dir: &Path) -> VmmSpec {
    VmmSpec {
        name: name.to_string(),
        kernel: KernelImage::Path(images.kernel.clone()),
        initramfs: None,
        cmdline:
            "console=ttyS0 reboot=k panic=1 net.ifnames=0 root=/dev/vda rw rootwait init=/init"
                .to_string(),
        vcpus: 2,
        memory_mib: 512,
        mem_initial_mib: None,
        blocks: vec![BlockDev {
            source: images.rootfs.clone(),
            read_only: false,
            ephemeral: true,
            slot: 0,
        }],
        virtiofs_shares: vec![],
        vsock: vec![],
        console: ConsoleCapture {
            log_path: state_dir.join("console.log"),
        },
    }
}

fn standby_spec(id: &str, images: &LiveImages, home: &Path) -> StandbySpec {
    StandbySpec {
        id: id.to_string(),
        template_id: None,
        kernel_path: images.kernel.to_string_lossy().into_owned(),
        kernel_sha256: sha256(&images.kernel),
        vcpus: 2,
        mem_mib: 512,
        signing_key_path: home
            .join("host-signer.ed25519")
            .to_string_lossy()
            .into_owned(),
        signer_id: "host:test".into(),
        binding_nonce: format!("nonce-{}", std::process::id()),
        control_socket: home.join("control.sock").to_string_lossy().into_owned(),
        vm_state_dir: mvm_core::config::vm_state_dir(id)
            .to_string_lossy()
            .into_owned(),
        image_path: Some(images.rootfs.to_string_lossy().into_owned()),
        image_sha256: Some(sha256(&images.rootfs)),
        // The live launch this parent mirrors is deny-all, so the guest boots no
        // egress client.
        vsock_egress: false,
    }
}

#[test]
#[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS with /init listening on vsock agent port"]
fn fc_warm_pool_spawn_and_claim() {
    let Some(images) = live_images() else {
        eprintln!("skip: MVM_LIVE_KERNEL/ROOTFS not set or /dev/kvm missing");
        return;
    };

    let home = tempfile::tempdir().expect("tempdir");
    // SAFETY: this harness is `#[ignore]` and runs single-threaded by hand, so
    // no other thread is reading the environment concurrently.
    unsafe { std::env::set_var("MVM_HOME", home.path()) };

    let pid = std::process::id();
    let parent_id = format!("fc-warm-live-parent-{pid}");
    let child_id = format!("fc-warm-live-child-{pid}");

    let driver = FcDriver::new();
    // The pool ships disarmed: the driver's spawn/capture/fork code is all
    // present but the capability stays off until a claim is green end to end on
    // real hardware. This harness is how that is measured, so it drives the
    // driver directly rather than through the capability-gated claim path.
    assert!(
        !driver.capabilities().standby_pool,
        "the FC standby pool must stay disarmed; this harness validates it, it does not arm it"
    );

    let spec = standby_spec(&parent_id, &images, home.path());
    let parent_state_dir = mvm_core::config::vm_state_dir(&parent_id);
    std::fs::create_dir_all(&parent_state_dir).expect("create parent state dir");
    mvm_runtime::base::runtime_meta::record_from_rootfs(
        &parent_id,
        StartMode::Detached,
        &images.rootfs,
    )
    .expect("record the parent rootfs metadata");
    let boot = parent_boot_spec(&parent_id, &images, &parent_state_dir);

    let t_spawn = Instant::now();
    let handle = driver
        .spawn_standby_parent(&StandbyParentSpawn {
            spec: &spec,
            boot: &boot,
        })
        .expect("spawn Firecracker standby parent");
    assert_eq!(handle.id, parent_id);
    assert_eq!(handle.state, StandbyState::Idle);
    assert!(handle.pid > 0, "a booted parent must expose a readable pid");

    // Capture the booted parent's whole state — the pool's actual asset. This
    // is the same call the role layer makes, through the driver's own control.
    let control = driver
        .vm_full_control(&parent_id)
        .expect("the FC driver supplies vm_full control");
    let store = CheckpointStore::open();
    let parent_checkpoint = CheckpointId::new(format!("standby-{parent_id}"));
    let meta = capture_vm_full(
        &store,
        CaptureVmFullParams {
            id: parent_checkpoint.clone(),
            vm_name: parent_id.clone(),
            supervisor_config_digest: String::new(),
            runtime_source_policy: None,
            runtime_overlay_version: None,
            // Firecracker keeps no supervisor-config blob.
            supervisor_config_src: None,
            tag: None,
            created_unix: mvm_runtime::standby_pool::now_unix_secs(),
        },
        control.as_ref(),
    )
    .expect("capture the standby parent's full state");
    let spawn_ms = t_spawn.elapsed().as_millis();

    // A captured parent costs disk, not a resident VM: release it before the
    // claim so the child cannot collide with a live parent's TAP-free device
    // paths or its pid marker.
    let _ = mvm_runtime::microvm::stop_vm(&parent_id);

    let content_dir = store.content_dir(&parent_checkpoint);
    let child_dir = mvm_core::config::vm_state_dir(&child_id);
    std::fs::create_dir_all(&child_dir).expect("create child vm dir");
    for blob in &meta.content {
        let src = content_dir.join(&blob.name);
        std::fs::copy(&src, child_dir.join(&blob.name))
            .unwrap_or_else(|e| panic!("copy {} to child dir: {}", src.display(), e));
    }

    let t_claim = Instant::now();
    let fork_result = driver.fork_standby_child(&ChildForkRequest {
        parent_vm_name: "standby-parent",
        child_vm_name: &child_id,
        child_dir: &child_dir,
        parent_vm_name: None,
        genid: GenerationToken {
            token: [0u8; GENID_BYTES],
            content_hash: parent_checkpoint.as_str().to_string(),
        },
        // This harness drives the driver seam directly and stands up none of
        // the host-side processes a claim wires channels to — no gating
        // endpoint, no broker — so it hands down the empty set the parent
        // itself booted with. What it measures is the restore, not the wiring.
        channels: &[],
    });
    if let Err(ref e) = fork_result {
        eprintln!("fork failed: {e:#}");
        for name in ["firecracker.log", "console.log"] {
            let path = child_dir.join(name);
            if let Ok(bytes) = std::fs::read(&path) {
                eprintln!("--- {name} ---");
                eprintln!("{}", String::from_utf8_lossy(&bytes));
            }
        }
    }
    fork_result.expect("fork Firecracker standby child");
    let claim_ms = t_claim.elapsed().as_millis();

    let child_vsock =
        mvm_runtime::microvm::firecracker_vsock_uds_path(&child_dir.to_string_lossy());
    assert!(
        connect_to(&child_vsock, CHILD_AGENT_TIMEOUT_SECS).is_ok(),
        "child VM must answer on its vsock agent port after the fork restore"
    );

    let _ = mvm_runtime::microvm::stop_vm(&child_id);
    let _ = std::fs::remove_dir_all(&child_dir);

    println!("FC_WARM_POOL_SPAWN_MS={spawn_ms}");
    println!("FC_WARM_POOL_CLAIM_MS={claim_ms}");
}
