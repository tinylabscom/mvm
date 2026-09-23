//! Live integration for Firecracker live-parent fork (the `machine fork` seam).
//!
//! Drives the same driver seam the fork arm strings together, against a KVM
//! host, with the parent kept RUNNING across the whole witness: a factory
//! parent boots NIC-less (the shape every child inherits), activates over
//! vsock, is captured through the driver's own `vm_full_control` with
//! `retain_paused: false` so it resumes, and then N children restore the same
//! captured memory — each in its own subprocess, because each child's device
//! remap unshares the mount namespace of the process that launches it.
//!
//! The witness asserts the vsock-only per-child resource model: the parent
//! keeps serving while every child is up, each child answers on its own
//! state-dir-keyed vsock endpoint, egress keying (the per-VM endpoint socket)
//! is name-based rather than snapshot-based, and the fresh generation tokens
//! plus post-restore kernel randomness diverge across children.
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
//! It is `#[ignore]` so CI never runs it. On a Linux KVM host, the one-command
//! runner stages the toolchain, the hash-verified mvm workload kernel (the
//! upstream Firecracker-CI kernel has no device-mapper and cannot run this),
//! and a python3 rootfs, then executes it:
//! `scripts/live-fork-witness-remote.sh root@<kvm-host>` (or
//! `just live-fork-witness root@<kvm-host>`). Manual equivalent:
//! `cargo test -p mvm-runtime --test fc_fork_live -- --ignored --nocapture`
//! with `MVM_LIVE_KERNEL`/`MVM_LIVE_ROOTFS` set. Set `MVM_LIVE_HOME` to retain
//! the VM state and console log after a failure.

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
use mvm_core::vm_backend::{
    RuntimeSourceRootStrategy, SnapshotCapability, StandbySpec, StandbyState, StartMode,
};
use mvm_runtime::checkpoint::{CaptureVmFullParams, CheckpointStore, capture_vm_full};
use mvm_runtime::driver::fc::FcDriver;
use mvm_runtime::driver::{
    BlockDev, ConsoleCapture, KernelImage, StandbyParentSpawn, VmmDriver, VmmSpec,
};

/// How long the guest agent gets to answer a connect/exec.
const AGENT_TIMEOUT_SECS: u64 = 5;
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
        // A fork parent boots from no admitted plan — children claim under
        // their own — so it carries no wall-clock bound.
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
        let result = connect_to_port_once(vsock_path, GUEST_AGENT_PORT, AGENT_TIMEOUT_SECS)
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
    // Chunked blobs (the durable-checkpoint store) must be rebuilt from
    // their authenticated indexes; whole-file blobs clone through the
    // normal CoW path. A plain per-blob copy misses chunked content.
    mvm_runtime::checkpoint::materialize_checkpoint_blobs(store, meta, child_dir)
        .unwrap_or_else(|e| panic!("materialize checkpoint {} for {checkpoint}: {e}", meta.id));
}

fn read_getrandom(vsock_path: &str) -> Vec<u8> {
    let mut stream = connect_to(vsock_path, AGENT_TIMEOUT_SECS)
        .expect("connect to restored child for randomness witness");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let terminal = send_exec_streaming(
        &mut stream,
        "python3 -c 'import os;os.write(1,os.getrandom(32))'",
        None,
        Some(AGENT_TIMEOUT_SECS),
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
    restore_ms: u128,
}

/// Restore one forked child from the captured parent through the same seam the
/// fork arm uses (`FcForkRestorer::restore_fork`), deliver its fresh
/// generation token, and witness readiness plus kernel-randomness divergence.
///
/// The child is left RUNNING: the caller asserts the whole fork family serves
/// at once, then tears it down.
fn restore_forked_child_and_read_random(
    store: &CheckpointStore,
    checkpoint: &CheckpointId,
    meta: &CheckpointMeta,
    child_id: &str,
) -> ChildObservation {
    let child_dir = mvm_core::config::vm_state_dir(child_id);
    copy_checkpoint_content(store, checkpoint, meta, &child_dir);

    let t_restore = Instant::now();
    mvm_runtime::firecracker::FcForkRestorer
        .restore_fork(child_id, &child_dir, None)
        .unwrap_or_else(|e| {
            for name in ["firecracker.log", "console.log"] {
                let path = child_dir.join(name);
                if let Ok(bytes) = std::fs::read(&path) {
                    eprintln!("--- {name} ---");
                    eprintln!("{}", String::from_utf8_lossy(&bytes));
                }
            }
            panic!("fork restore of '{child_id}' failed: {e:#}");
        });
    let restore_ms = t_restore.elapsed().as_millis();

    // Same identity delivery the fork arm performs over vsock: a fresh
    // generation token per child, refused unless the guest acknowledges and
    // reseeds.
    let genid = fresh_generation_token(format!("{checkpoint}:{}", child_id));
    let identity = FcDriver::new()
        .deliver_child_identity(child_id, genid.token, None)
        .expect("the restored child must complete the authenticated identity handshake");
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

    let child_vsock =
        mvm_runtime::microvm::firecracker_vsock_uds_path(&child_dir.to_string_lossy());
    let random = read_getrandom(&child_vsock);

    ChildObservation {
        random,
        generation_token: genid.token,
        restore_ms,
    }
}

fn run_child_mode() -> bool {
    if std::env::var_os("MVM_LIVE_FORK_CHILD").is_none() {
        return false;
    }
    let checkpoint =
        CheckpointId::new(std::env::var("MVM_LIVE_FORK_CHECKPOINT").expect("fork checkpoint id"));
    let child_id = std::env::var("MVM_LIVE_FORK_CHILD_NAME").expect("fork child id");
    let witness_path =
        PathBuf::from(std::env::var("MVM_LIVE_FORK_WITNESS").expect("fork witness output path"));
    let store = CheckpointStore::open();
    let meta = store
        .read_meta(&checkpoint)
        .expect("read captured parent metadata in fork child subprocess");
    let observation = restore_forked_child_and_read_random(&store, &checkpoint, &meta, &child_id);
    let mut witness = observation.generation_token.to_vec();
    witness.extend_from_slice(&observation.random);
    std::fs::write(&witness_path, witness).expect("write fork child witness");
    println!("FC_FORK_RESTORE_MS={}", observation.restore_ms);
    // Deliberately no stop here: the parent and every sibling must be up at
    // once while the caller checks the family, so the child Firecracker
    // outlives this subprocess.
    true
}

struct ChildWitness {
    random: Vec<u8>,
    generation_token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
}

fn fork_child_in_subprocess(
    checkpoint: &CheckpointId,
    child_id: &str,
    witness_path: &Path,
) -> ChildWitness {
    let status = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--ignored",
            "--exact",
            "fc_live_fork_n_children_from_running_parent",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MVM_LIVE_FORK_CHILD", "1")
        .env("MVM_LIVE_FORK_CHECKPOINT", checkpoint.as_str())
        .env("MVM_LIVE_FORK_CHILD_NAME", child_id)
        .env("MVM_LIVE_FORK_WITNESS", witness_path)
        .status()
        .expect("run isolated fork child subprocess");
    assert!(status.success(), "fork child subprocess failed: {status}");

    let witness = std::fs::read(witness_path).expect("read fork child witness");
    let token_len = mvm_core::crypto::vmgenid::GENID_BYTES;
    assert_eq!(
        witness.len(),
        token_len + 32,
        "fork child witness must contain one generation token and 32 random bytes"
    );
    let generation_token = witness[..token_len]
        .try_into()
        .expect("generation token witness has fixed length");
    ChildWitness {
        generation_token,
        random: witness[token_len..].to_vec(),
    }
}

#[test]
#[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS"]
fn fc_live_fork_n_children_from_running_parent() {
    if run_child_mode() {
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
    let parent_id = format!("fc-fork-live-parent-{pid}");
    let child_ids = [
        format!("fc-fork-live-child-a-{pid}"),
        format!("fc-fork-live-child-b-{pid}"),
    ];

    let driver = FcDriver::new();
    // The capability that gates the user-facing `machine fork` verb must
    // advertise the tier this witness exercises: the advertised and wired
    // paths cannot drift.
    assert_eq!(
        driver.capabilities().snapshot_capability,
        SnapshotCapability::LiveMemory,
        "the FC runner must advertise the live-memory tier its fork path wires"
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

    let handle = driver
        .spawn_standby_parent(&StandbyParentSpawn {
            spec: &spec,
            boot: &boot,
        })
        .expect("spawn Firecracker fork parent");
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

    // Capture the RUNNING parent's whole state, then let it resume — the
    // live-parent fork the activation exists for. This is the same call the
    // `machine fork` verb makes through the driver's own control.
    let control = driver
        .vm_full_control(&parent_id)
        .expect("the FC driver supplies vm_full control");
    let store = CheckpointStore::open();
    let parent_checkpoint = CheckpointId::new(format!("fork-{parent_id}"));
    let _meta = capture_vm_full(
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
    .expect("capture the running parent's full state");

    // The parent must be back and serving on its own vsock endpoint after the
    // capture — the child restores below share no resource with it.
    assert!(
        mvm_agentd::vsock::ping_at(&parent_vsock)
            .expect("the parent must still answer after capture"),
        "the resumed parent must keep serving while children restore"
    );

    // Each child restores in its own subprocess: the fork remap unshares the
    // mount namespace of the process that launches the child VMM, so restoring
    // two children in one process would stack both bind mounts over the
    // parent's recorded paths and shadow the parent for every later lookup.
    let mut witnesses = Vec::new();
    for (i, child_id) in child_ids.iter().enumerate() {
        let witness = fork_child_in_subprocess(
            &parent_checkpoint,
            child_id,
            &home.join(format!("fork-child-{i}.witness")),
        );
        witnesses.push(witness);
    }

    // The whole fork family is up now: parent plus every child reachable at
    // once, each on its own state-dir-keyed vsock endpoint. Had any child
    // collided with the parent on a shared resource, at least one of these
    // endpoints would be shadowed or dead.
    assert!(
        mvm_agentd::vsock::ping_at(&parent_vsock)
            .expect("the parent must answer alongside its children"),
        "the parent must keep serving while the children are up"
    );
    for child_id in &child_ids {
        let child_vsock = mvm_runtime::microvm::firecracker_vsock_uds_path(
            &mvm_core::config::vm_state_dir(child_id).to_string_lossy(),
        );
        assert!(
            Path::new(&child_vsock).exists(),
            "child '{child_id}' must own a vsock endpoint inside its own state dir"
        );
        assert!(
            mvm_agentd::vsock::ping_at(&child_vsock)
                .expect("the child must answer while its parent and siblings are up"),
            "child '{child_id}' must be reachable alongside the whole fork family"
        );
    }

    // Per-child vsock endpoints resolve to distinct paths — the recorded
    // parent UDS path was remapped into each child's own state dir — and the
    // egress keying (the per-VM gating endpoint) is name-keyed, so no two
    // family members can dial the same proxy pipe.
    let mut endpoints: Vec<PathBuf> = vec![PathBuf::from(&parent_vsock)];
    for child_id in &child_ids {
        endpoints.push(PathBuf::from(
            mvm_runtime::microvm::firecracker_vsock_uds_path(
                &mvm_core::config::vm_state_dir(child_id).to_string_lossy(),
            ),
        ));
    }
    let unique: std::collections::BTreeSet<_> = endpoints.iter().collect();
    assert_eq!(
        unique.len(),
        endpoints.len(),
        "every fork family member must own a distinct vsock endpoint: {endpoints:?}"
    );
    let mut egress_keys: Vec<PathBuf> =
        vec![mvm_core::config::vm_network_endpoint_socket(&parent_id)];
    for child_id in &child_ids {
        egress_keys.push(mvm_core::config::vm_network_endpoint_socket(child_id));
    }
    let unique_keys: std::collections::BTreeSet<_> = egress_keys.iter().collect();
    assert_eq!(
        unique_keys.len(),
        egress_keys.len(),
        "egress keying must be per VM name, never shared across the fork family: {egress_keys:?}"
    );

    // Fresh generation tokens drive an immediate kernel rekey before each
    // child serves its first explicit randomness request: identical tokens or
    // identical randomness mean the children are still running on the
    // parent's saved identity.
    for (i, witness) in witnesses.iter().enumerate() {
        for (j, other) in witnesses.iter().enumerate().skip(i + 1) {
            assert_ne!(
                witness.generation_token, other.generation_token,
                "children {i} and {j} must receive distinct generation tokens"
            );
            assert_ne!(
                witness.random, other.random,
                "children {i} and {j} returned identical kernel randomness after \
                 acknowledged reseeds"
            );
        }
    }
    println!("FC_FORK_LIVE_PARENT=running");
    println!("FC_FORK_LIVE_CHILDREN={}", child_ids.len());
    println!("FC_FORK_LIVE_FAMILY_RANDOMNESS=distinct");

    // Tear the whole family down and release the clones.
    for child_id in &child_ids {
        let _ = mvm_runtime::microvm::stop_vm(child_id);
        let _ = std::fs::remove_dir_all(mvm_core::config::vm_state_dir(child_id));
    }
    let _ = mvm_runtime::microvm::stop_vm(&parent_id);
}
