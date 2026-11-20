//! Opt-in inventory witness using the real standby spawn/capture seam.
//!
//! Prepare a fresh private MVM_HOME with verified workload kernel,
//! sealed workload rootfs and signed release runtime caches for this version.
//! Set MVM_E2E_STANDBY_ROOT to that same single-use directory explicitly.
//! Set MVM_E2E_KERNEL and MVM_E2E_ROOTFS to those files, and
//! MVM_HVF_SUPERVISOR_PATH to the entitled helper beside its companion binaries.
//! No builder rootfs, artifact downloads, source builds or verification bypasses.
//!
//! MVM_E2E_STANDBY_HVF=1 cargo test -p mvm-runtime --features manifest-verify --lib \
//!   native_standby_inventory -- --ignored --nocapture --test-threads=1
//!
//! Prepare only the signed runtime pieces, without a VM or source compilation:
//! MVM_E2E_STANDBY_PREPARE=1 cargo test -p mvm-runtime --features manifest-verify --lib \
//!   prepare_native_standby_runtime -- --ignored --nocapture --test-threads=1
//! Supply the canonical signed quartet under cache/guest-runtime/releases/VERSION.
//!
//! Optional reviewed reaper witness: MVM_E2E_STANDBY_REAPER names the conformance
//! libtest binary and CARGO_BIN_EXE_mvmctl names its CLI. Only this single-use
//! diagnostic hands off the lifecycle lock; this is not a general custody API.
//!
//! standby-inventory.jsonl records metadata only (never file contents), raw
//! status error chains and authenticated teardown. The diagnostic root and
//! checkpoints are retained on success AND failure. Direct mode retains VM
//! evidence too; optional canonical reaper cleanup intentionally removes VM
//! state. No watcher runs, and this test never signals a numeric VM PID.
//! The retained observation connection can occupy the serial control listener
//! until its command deadline; a pre-capture status timeout is therefore not
//! independent failure evidence. The post-capture running status is asserted.

use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use anyhow::ensure;
use mvm_core::{atomic_io, config};
use mvm_vmm::host::hvf_control_transport as wire;
use mvm_vmm::host::hvf_stop::ConnectedInstance;
use serde_json::json;

fn fixture_path(variable: &str, home: &Path) -> Result<PathBuf> {
    let path =
        PathBuf::from(std::env::var_os(variable).context(variable.to_owned())?).canonicalize()?;
    ensure!(
        path.is_file() && path.starts_with(home),
        "{variable} must be inside isolated MVM_HOME"
    );
    Ok(path)
}

const REAPER_TEST: &str = "vmm_reaper::tests::native_authenticated_hvf_reap";
const REAPER_OUTPUT_LIMIT: u64 = 16 * 1024;

fn reaper_inputs() -> Result<Option<(PathBuf, PathBuf)>> {
    let Some(binary) = std::env::var_os("MVM_E2E_STANDBY_REAPER") else {
        return Ok(None);
    };
    let binary = PathBuf::from(binary).canonicalize()?;
    let cli = PathBuf::from(
        std::env::var_os("CARGO_BIN_EXE_mvmctl").context("explicit reaper CLI required")?,
    )
    .canonicalize()?;
    ensure!(
        binary.is_file() && cli.is_file(),
        "reaper and CLI must be files"
    );
    Ok(Some((binary, cli)))
}

fn require_reaper_test(success: bool, stdout: &str) -> Result<()> {
    ensure!(
        success
            && stdout.contains(&format!("test {REAPER_TEST} ..."))
            && stdout.contains("1 passed; 0 failed"),
        "authenticated reaper test did not execute successfully"
    );
    Ok(())
}

fn run_reaper(binary: &Path, cli: &Path, home: &Path, id: &VmId) -> Result<String> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let command = mvm_core::env_hygiene::helper_command(binary);
            let mut child = tokio::process::Command::from(command)
                .args([
                    REAPER_TEST,
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("MVM_E2E_AUTH_REAPER", "1")
                .env("MVM_E2E_EXPECTED_VM", &id.0)
                .env("MVM_HOME", home)
                .env("MVM_E2E_STANDBY_ROOT", home)
                .env("CARGO_BIN_EXE_mvmctl", cli)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .context("spawn authenticated reaper witness")?;
            let mut stdout = child
                .stdout
                .take()
                .context("reaper stdout")?
                .take(REAPER_OUTPUT_LIMIT + 1);
            let mut stderr = child
                .stderr
                .take()
                .context("reaper stderr")?
                .take(REAPER_OUTPUT_LIMIT + 1);
            let mut out = Vec::new();
            let mut err = Vec::new();
            // Bound the owned test process, not a VM PID. No retry or home removal.
            let waited = tokio::time::timeout(Duration::from_secs(90), async {
                tokio::try_join!(
                    child.wait(),
                    stdout.read_to_end(&mut out),
                    stderr.read_to_end(&mut err)
                )
            })
            .await;
            let diagnostics = format!(
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out),
                String::from_utf8_lossy(&err)
            );
            let status = match waited {
                Ok(result) => result
                    .map(|(status, _, _)| status)
                    .with_context(|| diagnostics.clone())?,
                Err(error) => {
                    let killed = child.kill().await;
                    anyhow::bail!(
                        "reaper deadline: {error}; owned child kill: {killed:?}\n{diagnostics}"
                    );
                }
            };
            ensure!(
                out.len() as u64 <= REAPER_OUTPUT_LIMIT && err.len() as u64 <= REAPER_OUTPUT_LIMIT,
                "reaper output exceeded bound\n{diagnostics}"
            );
            require_reaper_test(status.success(), &String::from_utf8_lossy(&out))
                .with_context(|| diagnostics.clone())?;
            Ok(diagnostics)
        })
}

fn observe(
    log: &mut std::fs::File,
    phase: &str,
    id: &VmId,
    status: &Result<VmStatus>,
) -> Result<()> {
    let state = config::vm_state_dir(&id.0);
    let paths = [
        state.join(wire::INSTANCE_FILE),
        state.join(wire::FINALIZED_FILE),
        state.join("hvf.pid"),
        wire::socket_path(&id.0)?,
        config::vm_hvf_handoff_socket_at(&state),
    ];
    let files: Vec<_> = paths
        .iter()
        .map(|path| {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => json!({"present": true, "bytes": metadata.len(),
                "mode": metadata.permissions().mode()}),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    json!({"present": false})
                }
                Err(error) => json!({"error": format!("{error:#}")}),
            };
            json!({"path": path, "metadata": metadata})
        })
        .collect();
    writeln!(
        log,
        "{}",
        json!({
            "phase": phase, "vm": id.0, "files": files,
            "status": match status {
                Ok(status) => json!({"ok": format!("{status:?}")}),
                Err(error) => json!({"error": format!("{error:#}")}),
            }
        })
    )?;
    log.sync_all()?;
    Ok(())
}

fn fresh_witness_home() -> Result<PathBuf> {
    let home = config::mvm_home_strict()?.canonicalize()?;
    let root = PathBuf::from(
        std::env::var_os("MVM_E2E_STANDBY_ROOT").context("explicit witness root required")?,
    );
    ensure!(
        root.is_absolute() && root.canonicalize()? == home,
        "MVM_HOME must be the explicitly selected witness root"
    );
    ensure!(
        std::fs::metadata(&home)?.permissions().mode() & 0o077 == 0,
        "MVM_HOME must be private"
    );
    ensure!(
        !config::vms_dir().exists()
            && !config::mvm_pool_dir()?.exists()
            && !home.join("standby-inventory-owned").exists(),
        "refusing existing VM or pool state"
    );
    for variable in [
        "MVM_SKIP_HASH_VERIFY",
        "MVM_SKIP_COSIGN_VERIFY",
        "MVM_HVF_BOOTARGS",
        "MVM_HVF_BOOTARGS_EXTRA",
    ] {
        ensure!(
            std::env::var_os(variable).is_none(),
            "{variable} is forbidden"
        );
    }
    Ok(home)
}

#[test]
#[ignore = "signed fixture assembly only; explicit MVM_E2E_STANDBY_PREPARE=1 required; no VM"]
fn prepare_native_standby_runtime() -> Result<()> {
    ensure!(
        std::env::var("MVM_E2E_STANDBY_PREPARE").as_deref() == Ok("1"),
        "fixture preparation opt-in required"
    );
    let home = fresh_witness_home()?;
    ensure!(
        matches!(
            atomic_io::write_private_new(
                &home.join("standby-preparation-owned"),
                b"signed-runtime-v1\n"
            )?,
            atomic_io::NewFile::Created
        ),
        "preparation root is single-use"
    );
    let cache = PathBuf::from(config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let directory = cache.join("guest-runtime/releases").join(version);
    let asset = mvm_build::guest_bins::guest_bins_archive_name(version);
    let runtime = mvm_build::guest_runtime::install_signed_guest_runtime_archive(
        &cache,
        &directory.join(&asset),
        &directory.join(format!("{asset}.sha256")),
        &directory.join(format!("{asset}.bundle")),
        version,
        arch,
    )?;
    let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        &cache, version, arch, &runtime,
    )?;
    let initramfs = mvm_build::initramfs::build_initramfs_from_guest_runtime(
        &cache.join("initramfs"),
        version,
        arch,
        &runtime,
    )?;
    atomic_io::write_private(
        &home.join("standby-preparation.json"),
        &serde_json::to_vec_pretty(&json!({
            "archive_sha256": runtime.digest,
            "overlay": overlay.overlay_ext4,
            "initramfs": initramfs.image_path,
            "native_vm_boot": false
        }))?,
    )?;
    Ok(())
}

#[test]
#[ignore = "native HVF standby witness; explicit MVM_E2E_STANDBY_HVF=1 and isolated signed fixtures required"]
fn native_standby_inventory() -> Result<()> {
    ensure!(
        std::env::var("MVM_E2E_STANDBY_HVF").as_deref() == Ok("1"),
        "native witness opt-in required"
    );
    let home = fresh_witness_home()?;
    let reaper = reaper_inputs()?;
    let kernel = fixture_path("MVM_E2E_KERNEL", &home)?;
    let rootfs = fixture_path("MVM_E2E_ROOTFS", &home)?;
    let helper = PathBuf::from(
        std::env::var_os("MVM_HVF_SUPERVISOR_PATH").context("entitled helper required")?,
    )
    .canonicalize()?;
    ensure!(helper.is_file(), "supervisor helper missing");
    mvm_vmm::host::aux_bin::declare_library_embedder();
    mvm_vmm::host::aux_bin::declare_host_binary_dir(
        helper.parent().context("helper directory")?.to_path_buf(),
    )?;
    let cache = PathBuf::from(config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let release = mvm_build::guest_runtime::cached_verified_release_runtime(&cache, version, arch)?
        .context("prepare the signed release runtime cache first")?;
    let overlay = mvm_fs::overlay::RuntimeOverlayResolver::new(cache.clone(), version.into())
        .resolve(&arch.to_string())?;
    let initramfs = mvm_fs::initramfs::InitramfsResolver::new(cache.join("initramfs"), version)
        .resolve(&arch.to_string())?;
    let (verity_path, roothash) =
        crate::microvm::probe_verity_sidecar(&rootfs.display().to_string());
    ensure!(
        verity_path.is_some() && roothash.is_some(),
        "sealed workload rootfs sidecars required"
    );
    ensure!(
        matches!(
            atomic_io::write_private_new(
                &home.join("standby-inventory-owned"),
                b"native-standby-v1\n"
            )?,
            atomic_io::NewFile::Created
        ),
        "witness home is single-use"
    );
    let mut log = atomic_io::open_private_append(&home.join("standby-inventory.jsonl"))?;
    eprintln!("Retaining native standby evidence in {}", home.display());

    config::create_private_dir(config::mvm_keys_dir())?;
    let (secret, public) = wire::root_paths()?;
    mvm_core::crypto::ed25519_keypair::load_or_init(&secret, &public)?;
    crate::vm::snapshot_key::ensure_host_snapshot_key()?;
    let id = VmId(format!("standby-{:016x}", rand::random::<u64>()));
    let launch = VmStartConfig {
        name: id.0.clone(),
        kernel_path: Some(kernel.display().to_string()),
        rootfs_path: rootfs.display().to_string(),
        verity_path,
        roothash,
        initrd_path: Some(initramfs.image_path.display().to_string()),
        runtime_overlay_path: Some(overlay.overlay_ext4.display().to_string()),
        runtime_overlay_verity_path: Some(overlay.sidecar.display().to_string()),
        runtime_overlay_roothash: Some(overlay.roothash),
        runtime_overlay_version: Some(version.into()),
        runtime_release_proof: Some(release.proof().clone()),
        cpus: 1,
        memory_mib: 256,
        ..Default::default()
    };
    let spec = StandbySpec {
        id: id.0.clone(),
        template_id: None,
        kernel_path: kernel.display().to_string(),
        kernel_sha256: mvm_core::crypto::image_verify::sha256_file(&kernel)?,
        image_path: Some(launch.rootfs_path.clone()),
        image_sha256: Some(mvm_core::crypto::image_verify::sha256_file(&rootfs)?),
        vcpus: u8::try_from(launch.cpus)?,
        mem_mib: launch.memory_mib,
        signing_key_path: secret.display().to_string(),
        signer_id: "host:local".into(),
        binding_nonce: hex::encode(rand::random::<[u8; 32]>()),
        control_socket: config::mvm_pool_dir()?
            .join(&id.0)
            .join("control.sock")
            .display()
            .to_string(),
        vm_state_dir: vm_state_dir(&id.0).display().to_string(),
        root_strategy: Default::default(),
        vsock_egress: false,
    };
    let runner = WorkloadRunner::new(
        crate::driver::HvfDriver::new(),
        RealNetworkEndpointSpawner,
        RealBrokerRegistrar,
    );
    let checkpoints = CheckpointStore::open();
    let pool = SupervisorStandbyPool::open()?;
    let ctx = SpawnContext {
        checkpoints: &checkpoints,
        launch: Some(&launch),
    };
    let _barrier = mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
    let lifecycle = crate::runtime_evidence::RuntimeLifecycleLease::acquire(&id.0)?;
    let parent = lifecycle.bind(&factory_parent_config(&launch, &spec)?)?;
    let mut observer = None;
    // The existing seam lets us arm lifetime observation before capture, without
    // introducing another boot recipe or changing the production status rule.
    let spawned = runner.spawn_bound_standby_captured_using(&ctx, &spec, &parent, |request| {
        let handle = runner.driver.spawn_standby_parent_owned(request)?;
        observer = Some(ConnectedInstance::connect(&id.0)?);
        observe(&mut log, "before-capture", &id, &runner.status(&id))?;
        Ok(handle)
    });
    let mut lifecycle = Some(lifecycle);
    let status = runner.status(&id);
    let observed = observe(&mut log, "after-capture", &id, &status);
    let recorded = match &spawned {
        Ok(handle) => pool.record(handle),
        Err(_) => Ok(()),
    };
    let reaped = reaper.as_ref().map(|(binary, cli)| {
        ensure!(
            spawned.is_ok()
                && matches!(&status, Ok(VmStatus::Running))
                && observed.is_ok()
                && recorded.is_ok(),
            "reaper requires a captured running parent with durable diagnostic and pool records"
        );
        // Test-only handoff in this fresh, single-use, watcher-free root: the
        // external canonical stop needs this lock. Keep bound artifacts and
        // activation barrier until cleanup; no general durable transfer claimed.
        drop(lifecycle.take());
        run_reaper(binary, cli, &home, &id)
    });
    let mut stop_detail = None;
    let cleanup = if matches!(&reaped, Some(Ok(_))) {
        // The exact reviewed test asserts canonical authenticated CLI cleanup.
        // That cleanup removes terminal records: socket absence is NOT proof.
        Ok(())
    } else if reaped.is_some() {
        // The external test may have a still-acting CLI child even after its
        // own exit/timeout. Do not race that owner with another cleanup attempt.
        Err(anyhow::anyhow!(
            "external reaper cleanup unconfirmed; no fallback attempted"
        ))
    } else {
        // Only direct runs use fresh stop or prearmed natural-exit proof.
        let stop = ConnectedInstance::connect(&id.0).and_then(ConnectedInstance::stop);
        stop_detail = stop.as_ref().err().map(|error| format!("{error:#}"));
        match (stop, observer) {
            (Ok(proof), _) => proof.verify_current(),
            (Err(_), Some(observer)) => observer
                .wait(Instant::now() + wire::SHUTDOWN_BUDGET)
                .and_then(|proof| proof.verify_current()),
            (Err(error), None) => Err(error),
        }
    };
    let final_observed = observe(&mut log, "after-teardown", &id, &runner.status(&id));
    let outcome = (|| -> Result<()> {
        writeln!(
            log,
            "{}",
            json!({
                "phase": "outcome", "spawn_error": spawned.as_ref().err().map(|error| format!("{error:#}")),
                "pool_error": recorded.as_ref().err().map(|error| format!("{error:#}")),
                "observation_error": observed.as_ref().err().map(|error| format!("{error:#}")),
                "final_observation_error": final_observed.as_ref().err().map(|error| format!("{error:#}")),
                "status_error": status.as_ref().err().map(|error| format!("{error:#}")),
                "stop_error": stop_detail,
                "reaper_output": reaped.as_ref().and_then(|result| result.as_ref().ok()),
                "reaper_error": reaped.as_ref().and_then(|result| result.as_ref().err()).map(|error| format!("{error:#}")),
                "cleanup_confirmed": cleanup.is_ok(),
                "cleanup_error": cleanup.as_ref().err().map(|error| format!("{error:#}")),
                "diagnostic_root_retained": true,
                "canonical_reaper_requested": reaper.is_some(),
                "lifecycle_lease_retained": lifecycle.is_some() && cleanup.is_err()
            })
        )?;
        log.sync_all()?;
        Ok(())
    })();
    retain_unconfirmed_support((lifecycle, parent, _barrier), &cleanup);
    aggregate_results([
        ("spawn/capture", spawned.map(|_| ())),
        ("after-capture observation", observed),
        ("pool record", recorded),
        ("teardown", cleanup),
        ("final observation", final_observed),
        ("outcome persistence", outcome),
        ("reaper", reaped.transpose().map(|_| ())),
        (
            "resident status",
            status.and_then(|status| {
                ensure!(
                    status == VmStatus::Running,
                    "resident standby was not running"
                );
                Ok(())
            }),
        ),
    ])
}

fn retain_unconfirmed_support<T>(support: T, cleanup: &Result<()>) {
    if cleanup.is_err() {
        // Test-only fail-closed retention: dropping the original lease/artifact
        // guards would relinquish custody while this native lifetime is unknown.
        std::mem::forget(support);
    }
}

fn aggregate_results<const N: usize>(results: [(&str, Result<()>); N]) -> Result<()> {
    let failures: Vec<_> = results
        .into_iter()
        .filter_map(|(phase, result)| result.err().map(|error| format!("{phase}: {error:#}")))
        .collect();
    if !failures.is_empty() {
        let message = failures.join("\n");
        // Also emitted if the private diagnostic file could not be persisted.
        eprintln!("{message}");
        anyhow::bail!("{message}");
    }
    Ok(())
}

#[test]
fn observation_keeps_error_causes_but_not_identity_contents() -> Result<()> {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .expect("home test lock");
    let home = tempfile::tempdir()?;
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", home.path());
    let id = VmId("standby-observation".into());
    let state = config::vm_state_dir(&id.0);
    std::fs::create_dir_all(&state)?;
    std::fs::write(state.join(wire::INSTANCE_FILE), b"do-not-log-contents")?;
    let path = home.path().join("observation.jsonl");
    let mut log = atomic_io::open_private_append(&path)?;
    observe(
        &mut log,
        "fixture",
        &id,
        &Err(anyhow::anyhow!("inner cause").context("outer status")),
    )?;
    let text = std::fs::read_to_string(path)?;
    assert!(text.contains("outer status: inner cause"), "{text}");
    assert!(!text.contains("do-not-log-contents"), "{text}");
    let record: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(record["files"][0]["metadata"]["present"], true);
    assert_eq!(record["files"][1]["metadata"]["present"], false);
    Ok(())
}

#[test]
fn aggregation_retains_lifecycle_and_diagnostic_failures() {
    let error = aggregate_results([
        (
            "spawn",
            Err(anyhow::anyhow!("boot cause").context("boot context")),
        ),
        ("cleanup", Err(anyhow::anyhow!("unknown lifetime"))),
        ("log", Err(anyhow::anyhow!("disk full"))),
        ("unrelated success", Ok(())),
    ])
    .expect_err("all failures survive");
    let text = error.to_string();
    for expected in [
        "spawn: boot context: boot cause",
        "cleanup: unknown lifetime",
        "log: disk full",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    aggregate_results([("success", Ok(()))]).expect("success remains success");
}

#[test]
fn reaper_completion_requires_the_exact_test_and_nonzero_pass_count() {
    let passed = format!("test {REAPER_TEST} ... diagnostics\nok\n1 passed; 0 failed");
    require_reaper_test(true, &passed).expect("exact successful test");
    for (success, output) in [
        (false, passed.as_str()),
        (true, "0 passed; 0 failed; 1 filtered out"),
        (true, "test unrelated ... ok\n1 passed; 0 failed"),
    ] {
        assert!(require_reaper_test(success, output).is_err(), "{output}");
    }
}

#[test]
fn support_is_released_only_after_confirmed_cleanup() {
    struct Support(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Support {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    for confirmed in [false, true] {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let support = Support(Arc::clone(&dropped));
        let cleanup = if confirmed {
            Ok(())
        } else {
            Err(anyhow::anyhow!("unknown"))
        };
        assert!(!dropped.load(std::sync::atomic::Ordering::SeqCst));
        retain_unconfirmed_support(support, &cleanup);
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), confirmed);
    }
}
