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
//! * `MVM_LIVE_ROOTFS` pointing at an ext4 rootfs. The harness builds the
//!   source-matched universal initramfs and verity-sealed runtime overlay, then
//!   activates that rootfs through the same protocol as a production launch.
//!   The rootfs must provide `python3` so the witness can invoke `getrandom(2)`
//!   explicitly after each restore.
//!
//! It is `#[ignore]` so CI never runs it; execute manually on a KVM box with
//! `cargo test -p mvm-runtime --test fc_warm_pool_live -- --ignored --nocapture`.
//! Set `MVM_LIVE_HOME` to retain the VM state and console log after a failure.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mvm_agentd::vsock::{
    ActivateEnvironment, ExecEvent, GUEST_AGENT_PORT, RootfsConfig, RuntimeOverlayConfig,
    connect_to, connect_to_port_once, send_exec_streaming,
};
use mvm_core::arch::GuestArch;
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::crypto::vmgenid::fresh_generation_token;
use mvm_core::vm_backend::{RuntimeSourceRootStrategy, StandbySpec, StandbyState, StartMode};
use mvm_runtime::checkpoint::{
    CaptureVmFullParams, CheckpointStore, capture_vm_full, materialize_chunked_blobs,
};
use mvm_runtime::driver::fc::FcDriver;
use mvm_runtime::driver::{
    BlockDev, ChildForkRequest, ConsoleCapture, KernelImage, PreloadChildRequest,
    StandbyParentSpawn, VmmDriver, VmmSpec,
};

/// How long the child's agent gets to answer after the preloaded restore resumes it.
const CHILD_AGENT_TIMEOUT_SECS: u64 = 5;
/// Universal-initramfs boot readiness bound before activation.
const PARENT_READY_TIMEOUT_SECS: u64 = 30;

struct LiveImages {
    kernel: PathBuf,
    rootfs: PathBuf,
    initramfs: PathBuf,
    runtime_overlay: PathBuf,
    runtime_verity: PathBuf,
    runtime_roothash: String,
}

struct LiveImageInputs {
    kernel: PathBuf,
    rootfs: PathBuf,
}

fn live_image_inputs() -> Option<LiveImageInputs> {
    let kernel = std::env::var("MVM_LIVE_KERNEL").ok()?;
    let rootfs = std::env::var("MVM_LIVE_ROOTFS").ok()?;
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skip: /dev/kvm not present");
        return None;
    }
    Some(LiveImageInputs {
        kernel: PathBuf::from(kernel),
        rootfs: PathBuf::from(rootfs),
    })
}

fn resolve_live_images(inputs: LiveImageInputs, cache_root: &Path) -> LiveImages {
    let initramfs = mvm_build::initramfs::resolve_or_build_local_initramfs(
        &mvm_runtime::build_env::RuntimeBuildEnv,
        &cache_root.join("initramfs"),
        env!("CARGO_PKG_VERSION"),
        GuestArch::host(),
    )
    .expect("resolve source-matched universal initramfs");
    let overlay = mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
        &cache_root.join("runtime-overlay"),
        env!("CARGO_PKG_VERSION"),
        GuestArch::host(),
    )
    .expect("resolve source-matched runtime overlay");
    LiveImages {
        kernel: inputs.kernel,
        rootfs: inputs.rootfs,
        initramfs: initramfs.image_path,
        runtime_overlay: overlay.overlay_ext4,
        runtime_verity: overlay.sidecar,
        runtime_roothash: overlay.roothash,
    }
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
        initramfs: Some(images.initramfs.clone()),
        cmdline: format!(
            "console=ttyS0 reboot=k panic=1 net.ifnames=0 root=/dev/vda ro rootwait \
             mvm.hostepoch={} {}",
            mvm_core::time::now_unix_secs(),
            host_signer_pub_cmdline_token(),
        ),
        vcpus: 2,
        cpu_grant: None,
        memory_mib: 512,
        mem_initial_mib: None,
        blocks: vec![
            BlockDev {
                source: images.rootfs.clone(),
                read_only: true,
                ephemeral: true,
                slot: 0,
            },
            BlockDev {
                source: images.runtime_overlay.clone(),
                read_only: true,
                ephemeral: false,
                slot: 1,
            },
            BlockDev {
                source: images.runtime_verity.clone(),
                read_only: true,
                ephemeral: false,
                slot: 2,
            },
        ],
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

fn activate_parent(vsock_path: &str, images: &LiveImages) {
    let environment = ActivateEnvironment {
        rootfs: RootfsConfig {
            data_dev: "/dev/vda".to_string(),
            hash_dev: None,
            roothash: None,
            virtiofs_tag: None,
            in_place: false,
        },
        runtime: Some(RuntimeOverlayConfig {
            data_dev: "/dev/vdb".to_string(),
            hash_dev: "/dev/vdc".to_string(),
            roothash: images.runtime_roothash.clone(),
        }),
        volumes: Vec::new(),
        extensions: Vec::new(),
        verb_grant_envelope: None,
    };
    let deadline = Instant::now() + Duration::from_secs(PARENT_READY_TIMEOUT_SECS);
    loop {
        let result = connect_to_port_once(vsock_path, GUEST_AGENT_PORT, CHILD_AGENT_TIMEOUT_SECS)
            .and_then(|mut stream| {
                mvm_runtime::microvm::activate_over_stream(&mut stream, &environment)
            });
        match result {
            Ok(()) => return,
            Err(error) if Instant::now() < deadline => {
                let retryable = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<mvm_core::net::session::SessionError>()
                        .is_some_and(mvm_core::net::session::SessionError::is_peer_hangup)
                        || cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                            matches!(
                                io.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::ConnectionRefused
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::NotConnected
                                    | std::io::ErrorKind::NotFound
                                    | std::io::ErrorKind::AddrNotAvailable
                                    | std::io::ErrorKind::Interrupted
                                    | std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::BrokenPipe
                            )
                        })
                });
                assert!(retryable, "guest activation failed: {error:#}");
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!(
                "guest activation did not complete within {PARENT_READY_TIMEOUT_SECS}s: {error:#}"
            ),
        }
    }
}

fn copy_checkpoint_content(
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    meta: &CheckpointMeta,
    child_dir: &Path,
) {
    std::fs::create_dir_all(child_dir).expect("create child vm dir");
    let content_dir = store.content_dir(checkpoint);
    for blob in &meta.content {
        let src = content_dir.join(&blob.name);
        if src.is_file() {
            std::fs::copy(&src, child_dir.join(&blob.name))
                .unwrap_or_else(|e| panic!("copy {} to child dir: {}", src.display(), e));
        }
    }
    materialize_chunked_blobs(store, meta, child_dir)
        .expect("materialize the captured parent's chunked blobs");
}

fn regular_file_bytes(root: &Path) -> u64 {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0u64;
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.expect("read checkpoint storage entry");
            let file_type = entry.file_type().expect("read checkpoint storage type");
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                total = total
                    .checked_add(entry.metadata().expect("read stored file metadata").len())
                    .expect("checkpoint storage byte count fits u64");
            }
        }
    }
    total
}

fn checkpoint_own_bytes(store: &CheckpointStore, checkpoint: &CheckpointId) -> u64 {
    let content = store.content_dir(checkpoint);
    let content_bytes: u64 = std::fs::read_dir(content)
        .expect("read checkpoint content")
        .map(|entry| entry.expect("read checkpoint content entry"))
        .filter(|entry| {
            entry
                .file_type()
                .expect("read content entry type")
                .is_file()
        })
        .map(|entry| entry.metadata().expect("read content metadata").len())
        .sum();
    content_bytes
        + std::fs::metadata(store.dir_for(checkpoint).join("meta.json"))
            .expect("read checkpoint metadata size")
            .len()
}

fn read_getrandom(vsock_path: &str) -> Vec<u8> {
    let mut stream = connect_to(vsock_path, CHILD_AGENT_TIMEOUT_SECS)
        .expect("connect to restored child for randomness witness");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let terminal = send_exec_streaming(
        &mut stream,
        "python3 -c 'import os;os.write(1,os.getrandom(32))'",
        None,
        Some(CHILD_AGENT_TIMEOUT_SECS),
        |event| match event {
            ExecEvent::Stdout { chunk } => stdout.extend_from_slice(chunk),
            ExecEvent::Stderr { chunk } => stderr.extend_from_slice(chunk),
            ExecEvent::Exit { .. } | ExecEvent::TimedOut => {}
        },
    )
    .expect("read post-restore kernel randomness through the guest agent");
    assert_eq!(
        terminal,
        ExecEvent::Exit { code: 0 },
        "guest randomness command failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        stdout.len(),
        32,
        "guest randomness command returned {} bytes instead of 32: {}",
        stdout.len(),
        String::from_utf8_lossy(&stderr)
    );
    stdout
}

struct ChildObservation {
    random: Vec<u8>,
    generation_token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    preload_ms: u128,
    resume_ms: u128,
    identity_ms: u128,
    claim_ms: u128,
}

struct SiblingWitness {
    random: Vec<u8>,
    generation_token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
}

fn restore_child_and_read_random(
    driver: &FcDriver,
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    meta: &CheckpointMeta,
    child_id: &str,
) -> ChildObservation {
    let child_dir = mvm_core::config::vm_state_dir(child_id);
    copy_checkpoint_content(store, checkpoint, meta, &child_dir);

    let t_preload = Instant::now();
    let preloaded = driver
        .preload_standby_child(&PreloadChildRequest {
            child_vm_name: child_id,
            child_dir: &child_dir,
        })
        .expect("preload Firecracker standby child");
    let preload_ms = t_preload.elapsed().as_millis();
    assert!(
        preloaded.pid > 0,
        "a preloaded child must expose its live pid"
    );

    let t_claim = Instant::now();
    let genid = fresh_generation_token(checkpoint.as_str().to_string());
    let generation_token = genid.token;
    let t_resume = Instant::now();
    let resume_result = driver.resume_preloaded_child(&ChildForkRequest {
        child_vm_name: child_id,
        child_dir: &child_dir,
        parent_vm_name: None,
        genid,
        // This direct driver witness stands up no host-side gating or broker
        // endpoints, so the child inherits the parent's empty channel set.
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
        .deliver_child_identity(child_id, generation_token, None)
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
    let random = read_getrandom(&child_vsock);

    let _ = mvm_runtime::microvm::stop_vm(child_id);

    ChildObservation {
        random,
        generation_token,
        preload_ms,
        resume_ms,
        identity_ms,
        claim_ms,
    }
}

fn run_restore_child_mode() -> bool {
    let Ok(checkpoint) = std::env::var("MVM_LIVE_RESTORE_CHECKPOINT") else {
        return false;
    };
    let child_id = std::env::var("MVM_LIVE_RESTORE_CHILD").expect("restore child id");
    let witness_path = PathBuf::from(
        std::env::var("MVM_LIVE_RESTORE_WITNESS").expect("restore witness output path"),
    );
    let store = CheckpointStore::open();
    let checkpoint = CheckpointId::new(checkpoint);
    let meta = store
        .read_meta(&checkpoint)
        .expect("read captured parent metadata in restore subprocess");
    let observation =
        restore_child_and_read_random(&FcDriver::new(), &store, &checkpoint, &meta, &child_id);
    let mut witness = observation.generation_token.to_vec();
    witness.extend_from_slice(&observation.random);
    std::fs::write(&witness_path, witness).expect("write sibling restore witness");
    let _ = std::fs::remove_dir_all(mvm_core::config::vm_state_dir(&child_id));

    println!("FC_WARM_POOL_CLAIM_MS={}", observation.claim_ms);
    println!("FC_WARM_POOL_PRELOAD_MS={}", observation.preload_ms);
    println!("FC_WARM_POOL_RESUME_MS={}", observation.resume_ms);
    println!("FC_WARM_POOL_IDENTITY_MS={}", observation.identity_ms);
    true
}

fn restore_sibling_in_subprocess(
    checkpoint: &CheckpointId,
    child_id: &str,
    witness_path: &Path,
) -> SiblingWitness {
    let status = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--ignored",
            "--exact",
            "fc_warm_pool_spawn_and_claim",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MVM_LIVE_RESTORE_CHECKPOINT", checkpoint.as_str())
        .env("MVM_LIVE_RESTORE_CHILD", child_id)
        .env("MVM_LIVE_RESTORE_WITNESS", witness_path)
        .status()
        .expect("run isolated sibling restore subprocess");
    assert!(
        status.success(),
        "sibling restore subprocess failed: {status}"
    );

    let witness = std::fs::read(witness_path).expect("read sibling restore witness");
    let token_len = mvm_core::crypto::vmgenid::GENID_BYTES;
    assert_eq!(
        witness.len(),
        token_len + 32,
        "sibling witness must contain one generation token and 32 random bytes"
    );
    let generation_token = witness[..token_len]
        .try_into()
        .expect("generation token witness has fixed length");
    SiblingWitness {
        generation_token,
        random: witness[token_len..].to_vec(),
    }
}

#[test]
#[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS"]
fn fc_warm_pool_spawn_and_claim() {
    if run_restore_child_mode() {
        return;
    }
    let Some(inputs) = live_image_inputs() else {
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
    let images = resolve_live_images(inputs, &home.join("cache"));

    let pid = std::process::id();
    let parent_id = format!("fc-warm-live-parent-{pid}");
    let first_child_id = format!("fc-warm-live-child-a-{pid}");
    let second_child_id = format!("fc-warm-live-child-b-{pid}");

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
    activate_parent(&parent_vsock, &images);
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
    let pool_after_first = regular_file_bytes(&store.root().join(".objects"));
    let first_stored = pool_after_first + checkpoint_own_bytes(&store, &parent_checkpoint);

    let second_checkpoint = CheckpointId::new(format!("standby-{parent_id}-second"));
    let second_meta = capture_vm_full(
        &store,
        CaptureVmFullParams {
            id: second_checkpoint.clone(),
            vm_name: parent_id.clone(),
            supervisor_config_digest: String::new(),
            runtime_overlay_version: None,
            supervisor_config_src: None,
            tag: None,
            created_unix: mvm_core::time::now_unix_secs(),
            retain_paused: false,
            grants: None,
        },
        control.as_ref(),
    )
    .expect("capture the idle standby parent a second time");
    let pool_after_second = regular_file_bytes(&store.root().join(".objects"));
    let second_growth = pool_after_second
        .checked_sub(pool_after_first)
        .expect("the object pool does not shrink during capture")
        + checkpoint_own_bytes(&store, &second_checkpoint);
    let growth_milli_percent = second_growth
        .checked_mul(100_000)
        .expect("checkpoint growth percentage fits u64")
        .checked_div(first_stored)
        .expect("the first checkpoint stores bytes");
    let growth_percent_whole = growth_milli_percent / 1_000;
    let growth_percent_fraction = growth_milli_percent % 1_000;
    println!("FC_CHECKPOINT_FIRST_STORED_BYTES={first_stored}");
    println!("FC_CHECKPOINT_SECOND_GROWTH_BYTES={second_growth}");
    println!(
        "FC_CHECKPOINT_SECOND_GROWTH_PERCENT={growth_percent_whole}.{growth_percent_fraction:03}"
    );
    assert!(
        second_growth
            .checked_mul(10)
            .expect("checkpoint growth comparison fits u64")
            < first_stored,
        "an idle second FC checkpoint grew storage by \
         {growth_percent_whole}.{growth_percent_fraction:03}%"
    );
    mvm_runtime::checkpoint::verify_content(&store, &meta)
        .expect("the first captured checkpoint verifies");
    mvm_runtime::checkpoint::verify_content(&store, &second_meta)
        .expect("the second captured checkpoint verifies");
    let spawn_ms = t_spawn.elapsed().as_millis();

    // A captured parent costs disk, not a resident VM: release it before the
    // preload so the child cannot collide with a live parent's TAP-free device
    // paths or its pid marker.
    let _ = mvm_runtime::microvm::stop_vm(&parent_id);

    // Both children restore from the exact same captured memory. Their fresh
    // generation tokens must drive an immediate kernel rekey before either
    // child serves this first explicit randomness request.
    let first = restore_sibling_in_subprocess(
        &parent_checkpoint,
        &first_child_id,
        &home.join("sibling-a.witness"),
    );
    let second = restore_sibling_in_subprocess(
        &parent_checkpoint,
        &second_child_id,
        &home.join("sibling-b.witness"),
    );
    assert_ne!(
        first.generation_token, second.generation_token,
        "sibling clones must receive distinct generation tokens"
    );
    assert_ne!(
        first.random, second.random,
        "sibling clones returned identical kernel randomness after acknowledged reseeds"
    );
    println!("FC_WARM_POOL_SPAWN_MS={spawn_ms}");
    println!("FC_WARM_POOL_IDENTITY_HANDSHAKE=authenticated");
    println!("FC_WARM_POOL_SIBLING_RANDOMNESS=distinct");
}
