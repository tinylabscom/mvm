//! Live integration for the Firecracker warm-pool parent/claim path.
//!
//! Drives the real driver seam end to end against a KVM host:
//! `FcDriver::spawn_standby_parent` boots a clean factory parent,
//! `capture_vm_full` takes its {rootfs, memory, vmstate} triple through the
//! driver's own `vm_full_control`, and the driver preloads a fresh child from
//! that saved memory in a guarded paused state before claim-time resume. Those
//! calls are exactly what the role layer strings together for a claim, so the
//! timing output bounds the pooled claim path.
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
//! Set `MVM_LIVE_HOME` to retain the VM state and console log after a failure.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Instant;

use mvm_agentd::vsock::connect_to;
use mvm_core::checkpoint::CheckpointId;
use mvm_core::crypto::vmgenid::fresh_generation_token;
use mvm_core::vm_backend::{RuntimeSourceRootStrategy, StandbySpec, StandbyState, StartMode};
use mvm_runtime::checkpoint::{CaptureVmFullParams, CheckpointStore, capture_vm_full};
use mvm_runtime::driver::fc::FcDriver;
use mvm_runtime::driver::{
    BlockDev, ChildForkRequest, ConsoleCapture, KernelImage, PreloadChildRequest,
    StandbyParentSpawn, VmmDriver, VmmSpec,
};

/// How long the child's agent gets to answer after the preloaded restore resumes it.
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

fn host_signer_pub_cmdline_token() -> String {
    let path = mvm_core::config::mvm_keys_dir().join("host-signer.pub");
    let public_key = std::fs::read(&path).expect("read live-test host signer public key");
    assert_eq!(
        public_key.len(),
        32,
        "live-test host signer public key must be exactly 32 bytes"
    );
    format!("mvm.host_signer_pub={}", hex::encode(public_key))
}

/// The parent's boot recipe. A factory parent boots the same NIC-less shape a
/// workload does — one virtio-blk root, a console capture, no network device —
/// because every child restored from it inherits this device model and cmdline
/// out of the saved memory.
fn parent_boot_spec(name: &str, images: &LiveImages, state_dir: &Path) -> VmmSpec {
    VmmSpec {
        builder_egress_endpoint: None,
        name: name.to_string(),
        kernel: KernelImage::Path(images.kernel.clone()),
        initramfs: None,
        cmdline: format!(
            "console=ttyS0 reboot=k panic=1 net.ifnames=0 root=/dev/vda rw rootwait init=/init {}",
            host_signer_pub_cmdline_token()
        ),
        vcpus: 2,
        cpu_grant: None,
        memory_mib: 512,
        mem_initial_mib: None,
        blocks: vec![BlockDev {
            source: images.rootfs.clone(),
            read_only: false,
            ephemeral: true,
            slot: 0,
        }],
        vsock: vec![],
        console: ConsoleCapture {
            log_path: state_dir.join("console.log"),
        },
        shares: Vec::new(),
        trusted_builder: false,
        // A warm-pool factory parent boots from no admitted plan — children
        // claim under their own — so it carries no wall-clock bound.
        plan_binding: None,
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
        root_strategy: RuntimeSourceRootStrategy::BlockExt4,
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

    let home_override = std::env::var_os("MVM_LIVE_HOME").map(PathBuf::from);
    let home_temp = home_override
        .is_none()
        .then(|| tempfile::tempdir().expect("tempdir"));
    let home = home_override.unwrap_or_else(|| {
        home_temp
            .as_ref()
            .expect("temporary live-test home")
            .path()
            .to_path_buf()
    });
    std::fs::create_dir_all(&home).expect("create live-test home");
    let keys = home.join("keys");
    std::fs::create_dir_all(&keys).expect("create live-test keys");
    let host_signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    std::fs::write(keys.join("host-signer.ed25519"), [7u8; 32])
        .expect("write live-test host signer");
    std::fs::write(
        keys.join("host-signer.pub"),
        host_signing_key.verifying_key().to_bytes(),
    )
    .expect("write live-test host signer public key");
    // SAFETY: this harness is `#[ignore]` and runs single-threaded by hand, so
    // no other thread is reading the environment concurrently.
    unsafe { std::env::set_var("MVM_HOME", &home) };

    let pid = std::process::id();
    let parent_id = format!("fc-warm-live-parent-{pid}");
    let child_id = format!("fc-warm-live-child-{pid}");

    let driver = FcDriver::new();
    // The live harness exercises the same driver whose capability gates the
    // production pool path: refill loads a paused child and claim resumes it
    // only after the fresh host channels are wired.
    assert!(
        driver.capabilities().standby_pool,
        "the FC standby pool must advertise the preloaded-child path"
    );

    let spec = standby_spec(&parent_id, &images, &home);
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
    let parent_vsock = mvm_runtime::microvm::firecracker_vsock_uds_path(
        &mvm_core::config::vm_state_dir(&parent_id).to_string_lossy(),
    );
    assert!(
        mvm_agentd::vsock::ping_at(&parent_vsock)
            .expect("the parent must complete an authenticated ping"),
        "the parent guest agent must answer an authenticated ping before capture"
    );

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
            runtime_overlay_version: None,
            // Firecracker keeps no supervisor-config blob.
            supervisor_config_src: None,
            tag: None,
            created_unix: mvm_core::time::now_unix_secs(),
            retain_paused: false,
            grants: None,
        },
        control.as_ref(),
    )
    .expect("capture the standby parent's full state");
    let spawn_ms = t_spawn.elapsed().as_millis();

    // A captured parent costs disk, not a resident VM: release it before the
    // preload so the child cannot collide with a live parent's TAP-free device
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

    let t_preload = Instant::now();
    let preloaded = driver
        .preload_standby_child(&PreloadChildRequest {
            child_vm_name: &child_id,
            child_dir: &child_dir,
        })
        .expect("preload Firecracker standby child");
    let preload_ms = t_preload.elapsed().as_millis();
    assert!(
        preloaded.pid > 0,
        "a preloaded child must expose its live pid"
    );

    let t_claim = Instant::now();
    let genid = fresh_generation_token(parent_checkpoint.as_str().to_string());
    let token = genid.token;
    let t_resume = Instant::now();
    let resume_result = driver.resume_preloaded_child(&ChildForkRequest {
        child_vm_name: &child_id,
        child_dir: &child_dir,
        parent_vm_name: None,
        genid,
        // This harness drives the driver seam directly and stands up none of
        // the host-side processes a claim wires channels to — no gating
        // endpoint, no broker — so it hands down the empty set the parent
        // itself booted with. This direct witness measures the resume seam, not
        // the full runner's endpoint and broker wiring.
        channels: &[],
        cpu_grant: None,
    });
    if let Err(ref e) = resume_result {
        eprintln!("preloaded child resume failed: {e:#}");
        for name in ["firecracker.log", "console.log"] {
            let path = child_dir.join(name);
            if let Ok(bytes) = std::fs::read(&path) {
                eprintln!("--- {name} ---");
                eprintln!("{}", String::from_utf8_lossy(&bytes));
            }
        }
    }
    resume_result.expect("resume preloaded Firecracker standby child");
    let resume_ms = t_resume.elapsed().as_millis();

    let t_identity = Instant::now();
    let identity = driver
        .deliver_child_identity(&child_id, token, None)
        .expect("the restored child must complete the authenticated identity handshake");
    let identity_ms = t_identity.elapsed().as_millis();
    assert!(
        identity.acknowledged,
        "the guest agent must acknowledge the post-restore identity handshake"
    );
    assert!(
        identity.reseeded,
        "the guest must reseed its identity from the fresh generation token"
    );
    assert!(
        identity.clock_resynced,
        "the guest must resynchronize its wall clock before readiness"
    );
    let claim_ms = t_claim.elapsed().as_millis();

    let child_vsock =
        mvm_runtime::microvm::firecracker_vsock_uds_path(&child_dir.to_string_lossy());
    assert!(
        connect_to(&child_vsock, CHILD_AGENT_TIMEOUT_SECS).is_ok(),
        "child VM must answer on its vsock agent port after the preloaded restore"
    );

    let _ = mvm_runtime::microvm::stop_vm(&child_id);
    let _ = std::fs::remove_dir_all(&child_dir);

    println!("FC_WARM_POOL_SPAWN_MS={spawn_ms}");
    println!("FC_WARM_POOL_CLAIM_MS={claim_ms}");
    println!("FC_WARM_POOL_PRELOAD_MS={preload_ms}");
    println!("FC_WARM_POOL_RESUME_MS={resume_ms}");
    println!("FC_WARM_POOL_IDENTITY_MS={identity_ms}");
    println!("FC_WARM_POOL_IDENTITY_HANDSHAKE=authenticated");
}
