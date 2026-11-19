//! Tests for the cold start path: boot mapping, custody, activation and console.
#![cfg(test)]

use super::{test_support::*, *};
use crate::backends::hvf::HvfDriver;
use crate::driver::MockDriver;
use mvm_agentd::vsock::{BROKER_PORT, EGRESS_PORT, GUEST_AGENT_PORT};
use mvm_core::plan::{Nonce, SecretBinding, SecretSource, VerbGrant, VerbId};
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use mvm_core::util::test_env::TestEnv;

/// A guard that did register — the only inner variant a test can build
/// without a live daemon, and its Drop is a no-op.
fn registered_guard() -> BrokerGuard {
    BrokerGuard(mvm_vmm::host::host_agent_spawn::ServicesGuard::Agent(
        mvm_vmm::host::host_agent_spawn::HostAgentServicesGuard::defused(),
    ))
}

struct FailingActorBroker;

#[test]
fn runtime_no_dispatch_proof_binds_preboot_refusal_and_is_lost_before_dispatch() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .expect("home lock");
    let (_env, _home) = isolated_runtime_home();
    let root = tempfile::tempdir().unwrap();
    let rootfs = root.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"unprepared image").unwrap();
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
    let signed = mvm_core::plan::sign_plan(
        &plan,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        "host:test",
    );
    let cfg = VmStartConfig {
        name: "runtime-preboot-refusal".into(),
        rootfs_path: rootfs.display().to_string(),
        plan_json: Some(serde_json::to_string(&signed).unwrap()),
        ..Default::default()
    };
    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        FailingActorBroker,
    );
    assert!(runner.start_retaining_vm(&cfg, Vec::new(), None).is_err());
    assert!(driver.booted_specs().is_empty());
    assert!(runner.spawner.seen.lock().unwrap().is_none());
    let proof = runner
        .no_dispatch_proof(&cfg)
        .expect("original preboot refusal");
    assert!(proof.matches_launch(&cfg.name, &plan));
    assert!(!proof.matches_launch("another-vm", &plan));
    let mut other = plan.clone();
    other.nonce = Nonce::from_bytes([42; 16]);
    assert!(!proof.matches_launch(&cfg.name, &other));
    assert!(proof.signed_plan_for("another-vm").is_none());

    runner.begin_dispatch();
    assert!(runner.no_dispatch_proof(&cfg).is_none());
}

impl BrokerRegistrar for FailingActorBroker {
    fn register(&self, _request: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        anyhow::bail!("injected actor broker registration failure")
    }
}

#[test]
fn actor_postboot_broker_failure_retains_original_vm_without_best_effort_stop() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .expect("home lock");
    let (_env, _home) = isolated_runtime_home();
    let driver = MockDriver::default();
    let slot = Arc::new(std::sync::Mutex::new(None));
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        FailingActorBroker,
    )
    .with_actor_custody(Arc::clone(&slot));
    let cfg = config("actor-broker-refused");
    assert!(runner.boot_bound_workload(&launch(&cfg)).is_err());
    assert!(runner.no_dispatch_proof(&cfg).is_none());
    let original = slot
        .lock()
        .unwrap()
        .take()
        .expect("original booted VM retained");
    assert_eq!(original.id().0, cfg.name);
    assert!(
        driver.killed_vms().is_empty(),
        "failure must retain original custody"
    );
    original.kill().unwrap();
    assert_eq!(driver.killed_vms(), vec![cfg.name]);
}

#[test]
fn actor_postboot_activation_barrier_failure_retains_original_vm() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .expect("home lock");
    let (_env, _home) = isolated_runtime_home();
    let driver = MockDriver::default();
    let slot = Arc::new(std::sync::Mutex::new(None));
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    )
    .with_actor_custody(Arc::clone(&slot));
    let cfg = checked_source_launch_config(
        "actor-activation-refused",
        Some(
            mvm_core::admission_durability::AdmissionDurability::spawn(|| {
                anyhow::bail!("injected activation durability refusal")
            })
            .unwrap(),
        ),
    );
    assert!(runner.start_workload(&launch(&cfg)).is_err());
    let original = slot
        .lock()
        .unwrap()
        .take()
        .expect("original booted VM retained");
    assert_eq!(original.id().0, cfg.name);
    assert!(driver.killed_vms().is_empty());
    original.kill().unwrap();
    assert_eq!(driver.killed_vms(), vec![cfg.name]);
}

#[test]
fn a_workload_that_bound_no_host_service_is_not_degraded() {
    assert!(BrokerGuard::defused().services_healthy(&[]));
}

#[test]
fn a_bound_host_service_that_never_registered_is_degraded() {
    assert!(!BrokerGuard::defused().services_healthy(&[service("host.audit.v1")]));
}

#[test]
fn a_bound_host_service_that_registered_is_not_degraded() {
    assert!(registered_guard().services_healthy(&[service("host.audit.v1")]));
}

#[test]
fn only_the_hvf_supervisor_owns_console_capture() {
    use mvm_core::vm_backend::BackendKind;
    assert!(supervisor_owns_console(BackendKind::Hvf));
    for kind in [
        BackendKind::Firecracker,
        BackendKind::Libkrun,
        BackendKind::Qemu,
        BackendKind::Mock,
    ] {
        assert!(!supervisor_owns_console(kind), "{kind:?}");
    }
}

#[test]
fn boot_and_console_start_run_concurrently() {
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
    let booted = console_boot::boot_while_starting_console(
        || {
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .map_err(|error| anyhow::anyhow!("console start did not overlap boot: {error}"))?;
            Ok(7_u8)
        },
        || {
            let _ = started_tx.send(());
        },
        || {},
    )
    .expect("the console-start task runs while the driver boot is in progress");

    assert_eq!(booted, 7);
}

fn isolated_runtime_home() -> (TestEnv, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    (env, home)
}

#[test]
fn checked_source_cold_and_standby_boot_private_bytes_and_keep_them_after_stop() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let (_image, rootfs) = overlay_aware_rootfs("checked-source");
    let config = checked_source_config("checked-source", rootfs.clone());
    let checked = crate::runtime_evidence::verify_runtime_for_launch(
        &config,
        crate::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
    )
    .unwrap()
    .unwrap();
    assert!(
        !checked.is_release(),
        "synthetic source bytes are not signed release evidence"
    );
    let driver = MockDriver::default().with_vm_full_rootfs(Path::new(&rootfs));
    let guest = spawn_activation_guest(driver.clone(), "checked-source");
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    runner.start(&config).unwrap();
    guest.join().unwrap();
    let parent_guest = spawn_activation_guest(runner.driver.clone(), "checked-parent");
    let store = CheckpointStore::at(home.path().join("checkpoints"));
    let spec = standby_spec_for("checked-parent", &vm_state_dir("checked-parent"), &config);
    runner
        .spawn_standby_captured(
            &SpawnContext {
                checkpoints: &store,
                launch: Some(&config),
            },
            &spec,
        )
        .unwrap();
    parent_guest.join().unwrap();
    let boots = runner.driver.booted_specs();
    assert_eq!(boots.len(), 2);
    let mut retained = Vec::new();
    for (boot, name) in boots.iter().zip(["checked-source", "checked-parent"]) {
        let binding = crate::base::runtime_meta::read(name)
            .unwrap()
            .unwrap()
            .runtime_launch_binding
            .unwrap();
        crate::runtime_evidence::verify_runtime_binding(&binding).unwrap();
        let mvm_core::protocol::runtime_release::RuntimeLaunchBinding::CliAssembly(binding) =
            binding
        else {
            panic!("source assembly fixture");
        };
        assert!(binding.release_proof().is_none());
        assert_eq!(
            Some(binding.overlay_roothash.as_str()),
            config.runtime_overlay_roothash.as_deref()
        );
        assert_eq!(boot.initramfs.as_ref(), Some(&binding.initramfs_path));
        assert!(
            boot.blocks
                .iter()
                .any(|disk| disk.source == binding.overlay_path)
        );
        assert!(
            boot.blocks
                .iter()
                .any(|disk| disk.source == binding.overlay_verity_path)
        );
        assert_ne!(
            binding.overlay_path,
            PathBuf::from(config.runtime_overlay_path.as_ref().unwrap())
        );
        retained.push(binding);
    }
    assert_ne!(retained[0].overlay_path, retained[1].overlay_path);
    runner.stop(&VmId("checked-source".into())).unwrap();
    runner.stop(&VmId("checked-parent".into())).unwrap();
    std::fs::write(
        config.runtime_overlay_path.as_ref().unwrap(),
        b"changed cache output",
    )
    .unwrap();
    let before = runner.driver.booted_specs().len();
    assert!(
        runner.start(&config).is_err(),
        "changed selection must fail before spawn"
    );
    assert_eq!(runner.driver.booted_specs().len(), before);
    for binding in retained {
        crate::runtime_evidence::verify_runtime_binding(
            &mvm_core::protocol::runtime_release::RuntimeLaunchBinding::CliAssembly(binding),
        )
        .unwrap();
    }
}

fn keystore_secret() -> SecretBinding {
    SecretBinding {
        name: "API_KEY".into(),
        source: SecretSource::Keystore {
            address: "test-key".into(),
        },
        destinations: Vec::new(),
        approval_required: false,
    }
}

fn egress_host_uds(spec: &crate::driver::VmmSpec) -> &Path {
    spec.vsock
        .iter()
        .find(|p| p.service.port() == EGRESS_PORT)
        .map(|p| p.host_uds.as_path())
        .expect("spec carries an EGRESS_PORT vsock channel")
}

#[test]
fn append_cmdline_token_separates_only_a_non_empty_cmdline() {
    let mut empty = String::new();
    append_cmdline_token(&mut empty, "mvm.telemetry=1");
    assert_eq!(
        empty, "mvm.telemetry=1",
        "no leading space on an empty cmdline"
    );

    let mut non_empty = "root=/dev/vda".to_string();
    append_cmdline_token(&mut non_empty, "mvm.telemetry=1");
    assert_eq!(
        non_empty, "root=/dev/vda mvm.telemetry=1",
        "a non-empty cmdline gets exactly one space separator"
    );
}

#[test]
fn universal_activation_keeps_substitution_values_off_the_boot_cmdline() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let rootfs_dir = tempfile::tempdir().unwrap();
    let rootfs = rootfs_dir.path().join("rootfs.ext4");
    let verity = rootfs_dir.path().join("rootfs.verity");
    let initrd = rootfs_dir.path().join("rootfs.initrd");
    std::fs::write(&rootfs, b"rootfs").unwrap();
    std::fs::write(&verity, b"verity").unwrap();
    std::fs::write(&initrd, b"initrd").unwrap();
    mvm_build::builder_vm::GuestSidecar::for_oci_run(
        "runner-secret-env-cmdline-spacing",
        false,
        true,
    )
    .write_to_dir(rootfs_dir.path())
    .unwrap();

    let vm_name = "runner-secret-env-cmdline-spacing";
    seed_grant_sidecar_and_key(vm_name);
    // Substitution values belong to the host's per-entrypoint environment
    // synthesis, never the globally readable kernel command line.
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("substitution-env.json"),
        br#"[["API_KEY","mvm-secret-test"]]"#,
    )
    .unwrap();

    let cfg = VmStartConfig {
        name: vm_name.into(),
        rootfs_path: rootfs.display().to_string(),
        initrd_path: Some(mvm_vmm::host::cmdline::seed_universal_initramfs(
            home.path(),
        )),
        verity_path: Some(verity.display().to_string()),
        roothash: Some("a".repeat(64)),
        network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
        ..Default::default()
    };

    let driver = MockDriver::default();
    let guest = spawn_activation_guest(driver.clone(), vm_name);
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    mapping_start(&runner, &cfg).expect("start succeeds");
    guest.join().expect("guest thread");

    let specs = runner.driver.booted_specs();
    assert_eq!(specs.len(), 1);
    let cmdline = &specs[0].cmdline;
    assert!(!cmdline.contains("mvm.secret_env="), "{cmdline}");
    assert!(!cmdline.contains("mvm-secret-test"), "{cmdline}");
    assert!(!cmdline.contains(&hex::encode("API_KEY=")), "{cmdline}");
}

/// A blanket refusal in front of the HVF driver turns `machine run` into an
/// error on the default macOS backend before anything is checked. Both
/// entrypoints must reach the real launch checks, which refuse this
/// synthetic config for their own reasons (no rootfs, no kernel).
#[test]
fn an_hvf_runner_reaches_the_launch_checks_instead_of_a_blanket_refusal() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let runner = WorkloadRunner::new(
        mvm_backends::driver::hvf::HvfDriver::new(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = config("hvf-not-blanket-refused");
    let redaction = RedactionPolicy::default();

    let started = VmBackend::start(&runner, &cfg).expect_err("no rootfs to boot");
    let launched = runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &cfg.network_policy,
            cmdline: String::new(),
        })
        .map(|_| ())
        .expect_err("no rootfs to boot");

    for error in [format!("{started:#}"), format!("{launched:#}")] {
        assert!(
            !error.contains("native HVF"),
            "HVF was refused outright instead of reaching the launch checks: {error}"
        );
    }
}

/// A named HVF machine writes its supervisor pid file but no console log.
/// Listing only console-logged directories made `machine ls` report such a
/// running machine as stopped.
#[test]
fn list_includes_a_vm_that_has_a_pid_file_but_no_console_log() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let vms = mvm_core::config::vms_dir();
    for (name, marker) in [
        ("pid-only", Some("hvf.pid")),
        ("console-only", Some("console.log")),
        ("neither", None),
    ] {
        let dir = vms.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(marker) = marker {
            std::fs::write(dir.join(marker), "1").unwrap();
        }
    }
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let mut names: Vec<String> = VmBackend::list(&runner)
        .unwrap()
        .into_iter()
        .map(|vm| vm.name)
        .collect();
    names.sort();

    assert_eq!(names, ["console-only", "pid-only"]);
}

#[test]
fn stops_and_dropped_handles_never_reap_unproven_runtime_generations() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = config("retained-generations");
    let redaction = RedactionPolicy::default();
    let vm = runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &cfg.network_policy,
            cmdline: String::new(),
        })
        .unwrap();
    // Synthetic retained bytes test lifecycle deletion only, not signature
    // verification. Both an older launch and a newer launch must survive.
    let root = mvm_core::config::runtime_evidence_root().join(&cfg.name);
    let generations = ["runtime-old", "runtime-new"].map(|name| {
        let directory = root.join(name);
        std::fs::create_dir(&directory).unwrap();
        let artifact = directory.join("overlay.ext4");
        std::fs::write(&artifact, name).unwrap();
        artifact
    });
    drop(vm);
    for artifact in &generations {
        assert!(artifact.exists());
    }
    let id = VmId(cfg.name.clone());
    runner.stop(&id).expect("mock stop succeeds");
    for artifact in &generations {
        assert!(
            artifact.exists(),
            "PID-only success cannot authorize deletion"
        );
    }
    // A subsequent/stale stop may fail attachment, but is equally unable
    // to delete either generation.
    let _ = runner.stop(&id);
    let mut missing_proof = cfg;
    missing_proof.runtime_overlay_path = Some("/untrusted/overlay".into());
    assert!(
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &missing_proof,
                tenant: "local",
                secrets: &[],
                redaction: &redaction,
                network_policy: &missing_proof.network_policy,
                cmdline: String::new(),
            })
            .is_err()
    );
    for artifact in &generations {
        assert!(
            artifact.exists(),
            "failed replacement cannot delete retained bytes"
        );
    }
}

#[test]
fn runtime_proof_rejection_precedes_every_backend_spawn() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let mut cfg = config("proof-refused");
    cfg.runtime_overlay_path = Some("/runtime/overlay".into());
    let redaction = RedactionPolicy::default();
    for forged_development_flag in [false, true] {
        cfg.unsigned_runtime_development = forged_development_flag;
        let outcome = runner.start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &cfg.network_policy,
            cmdline: "mvm.runtime_roothash=untrusted".into(),
        });
        assert!(outcome.is_err());
        assert!(runner.driver.booted_specs().is_empty());
        assert!(runner.spawner.seen.lock().unwrap().is_none());
    }
}

#[test]
#[cfg(unix)]
fn retention_diagnostics_do_not_block_stop_but_invalid_leases_do() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let id = VmId("broken-retention".into());
    let lease = crate::runtime_evidence::RuntimeLifecycleLease::acquire(&id.0).unwrap();
    let root = mvm_core::config::runtime_evidence_root();
    let unreadable = root.join(&id.0).join("runtime-unreadable");
    std::fs::create_dir(&unreadable).unwrap();
    mvm_core::private_fs::set_mode(&unreadable, 0).unwrap();
    // Root bypasses directory DAC. Non-root host runs exercise the actual
    // diagnostic failure; both must still exercise driver termination.
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } != 0 {
        assert!(lease.report_retained().is_err());
    }
    drop(lease);
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let result = runner.stop(&id);
    mvm_core::private_fs::set_mode(&unreadable, 0o700).unwrap();
    result.expect("diagnostic failure must not block stop");
    assert_eq!(runner.driver.killed_vms(), vec![id.0.clone()]);

    let original = root.with_extension("retained");
    std::fs::rename(&root, &original).unwrap();
    std::os::unix::fs::symlink(&original, &root).unwrap();
    assert!(runner.abort_start(&id).is_err());
    assert_eq!(runner.driver.killed_vms().len(), 1);
    for invalid in ["../bad", "x/y", ""] {
        assert!(runner.stop(&VmId(invalid.into())).is_err());
    }
    assert_eq!(runner.driver.killed_vms().len(), 1);
    std::fs::remove_file(&root).unwrap();
    std::fs::rename(&original, &root).unwrap();
    let refusing = WorkloadRunner::new(
        MockDriver::default().refusing_attach(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let expected_error = refusing.driver.attach(&id).err().unwrap().to_string();
    let error = refusing.stop(&id).unwrap_err();
    assert_eq!(error.to_string(), expected_error);
}

#[test]
fn start_workload_threads_endpoint_uds_into_egress_port() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let cfg = config("w-egress");
    let vm = runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: "root=/dev/vda".into(),
        })
        .expect("start_workload succeeds against the mock driver");

    assert_eq!(vm.id().0, "w-egress");

    let specs = runner.driver.booted_specs();
    assert_eq!(specs.len(), 1);
    let spec = &specs[0];

    // The endpoint UDS the spawner returned is wired to EGRESS_PORT.
    assert_eq!(egress_host_uds(spec), Path::new("/run/ep.sock"));
    // The sealed rootfs lands at /dev/vda.
    assert_eq!(spec.blocks[0].device_node(), "/dev/vda");
    assert_eq!(spec.blocks[0].source, PathBuf::from("/img/rootfs.ext4"));
    // The write-only console capture path is set under the state dir.
    assert!(spec.console.log_path.ends_with("console.log"));
}

#[test]
fn start_workload_puts_no_secret_environment_on_the_kernel_cmdline() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let cfg = config("w-secret-env");
    let env_path = mvm_core::config::vm_substitution_env_path(&cfg.name);
    std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
    std::fs::write(
        &env_path,
        serde_json::to_vec(&vec![(
            "API_KEY".to_string(),
            "mvm-secret://opaque-placeholder".to_string(),
        )])
        .unwrap(),
    )
    .unwrap();
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();
    let secrets = vec![keystore_secret()];
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &secrets,
            redaction: &redaction,
            network_policy: &policy,
            cmdline: "root=/dev/vda".into(),
        })
        .expect("secret-bearing workload boots");

    // The placeholders reach the workload with each `RunEntrypoint`, from
    // the host's environment synthesis. Any guest process can read
    // `/proc/cmdline`, so nothing of them rides the kernel cmdline.
    let specs = runner.driver.booted_specs();
    let cmdline = &specs[0].cmdline;
    assert!(!cmdline.contains("mvm.secret_env"), "{cmdline}");
    assert!(!cmdline.contains("4150495f4b45593d"), "{cmdline}");
    assert!(!cmdline.contains("opaque-placeholder"), "{cmdline}");
}

#[test]
fn start_workload_starts_console_streaming_and_stop_tears_it_down_without_losing_bytes() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();
    let streamer = Arc::new(RecordingConsoleStreamer::default());
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    )
    .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);

    let cfg = config("w-console");
    let vm = runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: "root=/dev/vda".into(),
        })
        .expect("start_workload succeeds against the mock driver");

    // Started exactly once, unconditionally (no admission gating: the
    // hook must not inherit `BrokerRegistrar`'s tenant-gated posture),
    // and pointed at the same console-log path the boot spec carries.
    let expected_console_log = vm_state_dir(&cfg.name).join("console.log");
    {
        let started = streamer.started.lock().unwrap();
        assert_eq!(
            started.as_slice(),
            [("w-console".to_string(), expected_console_log.clone())]
        );
    }
    // The mock backend has no supervisor that owns capture, so the
    // launcher's follower is the writer and must be told so.
    assert_eq!(
        streamer.supervisor_owned.lock().unwrap().as_slice(),
        [false]
    );
    assert!(
        streamer.stopped.lock().unwrap().is_empty(),
        "must not stop before the workload ends"
    );

    // The boot-failure case this feature exists for: output that lands
    // on the console between start and stop, with no agent involved.
    std::fs::write(&expected_console_log, b"kernel panic\n")
        .expect("write to the console-log path the hook was started with");

    runner
        .stop(vm.id())
        .expect("stop succeeds against the mock driver");

    // Stopped exactly once, by name, and the snapshot taken at that stop
    // call sees the bytes written above -- proving `stop` is wired to run
    // (and, for a real follower, drain) before the caller can observe the
    // workload as torn down, not merely that the method was called.
    assert_eq!(streamer.stopped.lock().unwrap().as_slice(), ["w-console"]);
    assert_eq!(
        streamer
            .captured_at_stop
            .lock()
            .unwrap()
            .get("w-console")
            .expect("stop captured this vm's console"),
        b"kernel panic\n"
    );
}

#[test]
fn the_console_capture_outlives_the_kill_so_a_dying_guests_output_is_recorded() {
    // A guest prints its last words *during* teardown. Releasing the
    // capture before the kill leaves those bytes in the write-only
    // console file and out of the chain — which is exactly the output an
    // operator opens the transcript to find.
    let mut env = mvm_core::util::test_env::TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(tmp.path());

    let policy = NetworkPolicy::deny_all();
    let redaction = RedactionPolicy::default();
    let streamer = Arc::new(RecordingConsoleStreamer::default());
    let runner = WorkloadRunner::new(
        MockDriver::default().printing_on_kill(b"panic on the way down\n"),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    )
    .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);

    let cfg = config("w-dying");
    let vm = runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: "root=/dev/vda".into(),
        })
        .expect("start_workload succeeds against the mock driver");
    std::fs::write(
        vm_state_dir(&cfg.name).join("console.log"),
        b"while it lived\n",
    )
    .expect("write the console capture");

    runner.stop(vm.id()).expect("stop");

    // The snapshot the hook takes at `stop` is what a real follower's
    // final drain would see. It must hold the kill-time bytes.
    let captured = streamer.captured_at_stop.lock().unwrap();
    let seen = captured.get("w-dying").expect("stop captured this vm");
    assert_eq!(seen.as_slice(), b"while it lived\npanic on the way down\n");
}

#[test]
fn a_kill_that_fails_still_releases_the_console_capture() {
    let (_env, _home) = isolated_runtime_home();
    // The property the old ordering bought and this one must not lose: a
    // VM that will not die cannot strand its follower, or leave its
    // transcript unsealed.
    let streamer = Arc::new(RecordingConsoleStreamer::default());
    let runner = WorkloadRunner::new(
        MockDriver::default().refusing_attach(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    )
    .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);

    let err = runner
        .stop(&VmId("w-undead".to_string()))
        .expect_err("the driver refuses to attach");
    assert!(format!("{err:#}").contains("no such vm"), "{err:#}");
    assert_eq!(streamer.stopped.lock().unwrap().as_slice(), ["w-undead"]);
}

#[test]
fn every_cold_boot_mints_an_identity_whether_or_not_it_carries_secrets() {
    let (_env, _home) = isolated_runtime_home();
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();

    // There is one transport, so carrying secrets changes what
    // the endpoint does with a flow -- not which protocol the guest speaks.
    let raw_runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = config("w-raw");
    raw_runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .unwrap();
    assert!(
        raw_runner
            .spawner
            .seen
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .mints_identity
    );

    // A secret-bearing workload mints exactly the same way.
    let wire_runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = config("w-wire");
    let secrets = [keystore_secret()];
    wire_runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &secrets,
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .unwrap();
    let recorded = wire_runner.spawner.seen.lock().unwrap();
    let recorded = recorded.as_ref().unwrap();
    assert!(
        recorded.mints_identity,
        "a secret-bearing cold boot mints an identity too -- the protocol \
             does not fork on whether secrets are present"
    );
    assert_eq!(recorded.secrets_len, 1);
    assert_eq!(
        recorded.network_limits,
        mvm_core::plan::NetworkLimits::default()
    );
}

#[test]
fn start_workload_passes_the_network_policy_and_tenant_to_the_spawner() {
    let (_env, _home) = isolated_runtime_home();
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let cfg = config("w-policy");
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "acme",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .unwrap();

    let recorded = runner.spawner.seen.lock().unwrap();
    let recorded = recorded.as_ref().unwrap();
    assert_eq!(recorded.tenant, "acme");
    assert_eq!(recorded.policy, egress_allowing_policy());
}

fn admitted_config(name: &str) -> VmStartConfig {
    VmStartConfig {
        name: name.into(),
        rootfs_path: "/img/rootfs.ext4".into(),
        tenant_id: Some("tenant-x".into()),
        ..Default::default()
    }
}

#[test]
fn start_workload_registers_the_broker_and_wires_it_into_the_spec_when_admitted() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let policy = NetworkPolicy::deny_all();
    let redaction = RedactionPolicy::default();
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let cfg = admitted_config("w-broker-admitted");
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .expect("start_workload succeeds");

    // register saw the tenant + the resolved BROKER_PORT bind socket.
    let expected_socket = mvm_core::config::vm_vsock_port_socket("w-broker-admitted", BROKER_PORT);
    let recorded = runner.broker.seen.lock().unwrap();
    let recorded = recorded.as_ref().expect("register was called");
    assert_eq!(recorded.vm_name, "w-broker-admitted");
    assert_eq!(recorded.tenant.as_deref(), Some("tenant-x"));
    assert_eq!(
        recorded.broker_listen_socket.as_deref(),
        Some(expected_socket.as_path())
    );

    // The spec carries the same socket as a GuestDials BROKER_PORT channel, so
    // the supervisor relay target and the daemon's bind path are identical.
    let specs = runner.driver.booted_specs();
    let broker = specs[0]
        .vsock
        .iter()
        .find(|p| p.service.port() == BROKER_PORT)
        .expect("admitted spec carries a BROKER_PORT channel");
    assert_eq!(broker.direction, crate::driver::VsockDirection::GuestDials);
    assert_eq!(broker.host_uds, expected_socket);
}

#[test]
fn start_workload_broker_is_a_defused_no_op_when_unadmitted() {
    let (_env, _home) = isolated_runtime_home();
    let policy = NetworkPolicy::deny_all();
    let redaction = RedactionPolicy::default();
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    // config() sets no tenant_id ⇒ unadmitted.
    let cfg = config("w-broker-unadmitted");
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .expect("start_workload succeeds");

    // register is still called, but with no tenant + no broker socket.
    let recorded = runner.broker.seen.lock().unwrap();
    let recorded = recorded.as_ref().expect("register is still called");
    assert_eq!(recorded.tenant, None);
    assert_eq!(recorded.broker_listen_socket, None);

    // The spec carries NO BROKER_PORT channel, so a stray guest dial to
    // BROKER_PORT stays ECONNREFUSED (fail-closed).
    let specs = runner.driver.booted_specs();
    assert!(
        specs[0]
            .vsock
            .iter()
            .all(|p| p.service.port() != BROKER_PORT),
        "unadmitted VM must carry no broker port"
    );
}

#[test]
fn stop_reaps_the_host_agent_tenant_ref_marker() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let vm_name = "runner-stop-reaps-broker";
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    std::fs::create_dir_all(&state_dir).unwrap();
    // Plant the daemon-path tenant-ref marker `register` writes; the stop reap
    // must remove it, proving `reap_host_agent_services_from_state` ran.
    std::fs::write(state_dir.join("host-agent.tenant"), "tenant-x").unwrap();

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    runner.stop(&VmId(vm_name.into())).expect("stop succeeds");

    assert!(
        !state_dir.join("host-agent.tenant").exists(),
        "stop must reap the host-agent registration marker"
    );
}

#[test]
fn vmbackend_start_then_status_wait_stop_via_the_driver() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let exit = VmExitStatus {
        code: Some(0),
        success: true,
    };
    let runner = WorkloadRunner::new(
        MockDriver::with_exit(exit),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w");
    let cfg = VmStartConfig {
        name: "w".into(),
        rootfs_path: rootfs,
        ..Default::default()
    };
    let id = mapping_start(&runner, &cfg).expect("start succeeds");
    assert_eq!(id.0, "w");

    // attach hands back a MockRunningVm, so the lifecycle works with no real VM.
    assert_eq!(runner.status(&id).unwrap(), VmStatus::Running);
    assert_eq!(runner.wait(&id).unwrap(), exit);
    // stop reaps a nonexistent endpoint (no-op) then kills the attached handle.
    assert!(runner.stop(&VmId("w".into())).is_ok());
}

/// Write a `verb-grant.json` sidecar plus the host-signer public key
/// under `vm_name`'s state dir, the shape the grant cmdline tokens read.
fn seed_grant_sidecar_and_key(vm_name: &str) {
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    std::fs::create_dir_all(&state_dir).unwrap();
    let nonce = Nonce::from_bytes([9u8; 16]);
    let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
    let envelope = VerbGrantEnvelope {
        pubkey_hex: "cc".repeat(32),
        plan_nonce_hex: nonce.as_hex().to_string(),
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant: VerbGrant {
            session_id: vm_name.to_string(),
            plan_nonce: nonce,
            not_after,
            verbs: vec![VerbId::new("run-entrypoint").unwrap()],
            drive: None,
            application_terminal: None,
            sig: vec![0u8; 64],
        },
    };
    std::fs::write(
        state_dir.join("verb-grant.json"),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    let keys_dir = mvm_core::config::mvm_keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::write(keys_dir.join("host-signer.pub"), [0xEEu8; 32]).unwrap();
}

/// Seed only the host key — no verb-grant sidecar. Models the transient
/// `machine run` path, which mints no grant.
fn seed_host_key_only() {
    let keys_dir = mvm_core::config::mvm_keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::write(keys_dir.join("host-signer.pub"), [0xEEu8; 32]).unwrap();
}

/// A launch that mints no verb grant must still carry the host-signer
/// anchor, or its guest agent has no pinned key to authenticate the control
/// channel against, rejects every connection, and the run dies at its first
/// RPC.
///
/// The sibling test below covers the grant-*bearing* launch, and that was
/// exactly the gap: the anchor used to be gated on the grant sidecar, so the
/// grant-less shape shipped no anchor and nothing at this level noticed.
/// Asserting the token builder alone did not catch it either — the
/// regression only surfaced in an assembled cmdline.
#[test]
fn start_carries_the_host_anchor_without_a_grant_but_grants_no_authority() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let rootfs_dir = tempfile::tempdir().unwrap();
    let rootfs = rootfs_dir.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"rootfs").unwrap();
    let vm_name = "runner-grantless-anchor";
    mvm_build::builder_vm::GuestSidecar::for_oci_run(vm_name, false, true)
        .write_to_dir(rootfs_dir.path())
        .unwrap();

    seed_host_key_only();

    let cfg = VmStartConfig {
        name: vm_name.into(),
        rootfs_path: rootfs.display().to_string(),
        network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
        ..Default::default()
    };

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    mapping_start(&runner, &cfg).expect("start succeeds");

    let specs = runner.driver.booted_specs();
    assert_eq!(specs.len(), 1);
    let cmdline = &specs[0].cmdline;

    assert!(
        cmdline.contains("mvm.host_signer_pub="),
        "a grant-less launch must still pin the host anchor, or the agent \
             rejects every control connection: {cmdline}"
    );
    // Reachable, but no more privileged: authority stays sidecar-gated.
    assert!(
        !cmdline.contains("mvm.verb_grant="),
        "no grant was minted, so no grant token may appear: {cmdline}"
    );
    assert!(
        !cmdline.contains("mvm.require_grant="),
        "no grant was minted, so enforcement must not be demanded: {cmdline}"
    );
}

/// `WorkloadRunner::start` (the `VmBackend::start` production path) must
/// assemble the same security-bearing kernel cmdline the raw HVF backend
/// does — dm-verity, the plan-bound grant triple, vsock egress, and the
/// runtime-source-policy token — instead of booting with an empty
/// cmdline. Drives the whole trait method through a `MockDriver` and
/// inspects the booted `VmmSpec` it recorded.
#[test]
fn start_assembles_the_security_cmdline_tokens_via_the_shared_assembler() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let rootfs_dir = tempfile::tempdir().unwrap();
    let rootfs = rootfs_dir.path().join("rootfs.ext4");
    let verity = rootfs_dir.path().join("rootfs.verity");
    let initrd = rootfs_dir.path().join("rootfs.initrd");
    std::fs::write(&rootfs, b"rootfs").unwrap();
    std::fs::write(&verity, b"verity").unwrap();
    std::fs::write(&initrd, b"initrd").unwrap();
    // Overlay-aware sidecar next to the rootfs so `start`'s admission gate
    // (refuses a rootfs with no `/mvm/runtime` mount point) admits this boot.
    mvm_build::builder_vm::GuestSidecar::for_oci_run("runner-security-cmdline-tokens", false, true)
        .write_to_dir(rootfs_dir.path())
        .unwrap();

    let vm_name = "runner-security-cmdline-tokens";
    seed_grant_sidecar_and_key(vm_name);

    let cfg = VmStartConfig {
        name: vm_name.into(),
        rootfs_path: rootfs.display().to_string(),
        initrd_path: Some(mvm_vmm::host::cmdline::seed_universal_initramfs(
            home.path(),
        )),
        verity_path: Some(verity.display().to_string()),
        roothash: Some("a".repeat(64)),
        network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
        ..Default::default()
    };

    let driver = MockDriver::default();
    let guest = spawn_activation_guest(driver.clone(), vm_name);
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    mapping_start(&runner, &cfg).expect("start succeeds");
    guest.join().expect("guest thread");

    let specs = runner.driver.booted_specs();
    assert_eq!(specs.len(), 1);
    let cmdline = &specs[0].cmdline;

    let require_grant = mvm_vmm::host::egress_bridge::require_grant_cmdline_token(vm_name)
        .expect("sidecar present ⇒ enforcement token");
    // Roothash and block-device tokens travel over vsock via
    // ActivateEnvironment, so the kernel cmdline only carries egress and
    // grant tokens.
    for needle in [
        "mvm.verb_grant=",
        require_grant.as_str(),
        "mvm.host_signer_pub=",
        "mvm.vsock_egress=1",
    ] {
        assert!(
            cmdline.contains(needle),
            "booted cmdline missing {needle:?}: {cmdline}"
        );
    }
}

/// The base console/earlycon/root bootargs the runner boots with must come
/// from the driver (`VmmDriver::workload_base_bootargs`), not a hardcoded
/// HVF default — proven by driving `start` through a `MockDriver` whose
/// base uses `hvc0` rather than HVF's `ttyAMA0` and asserting the booted
/// spec's cmdline carries that base.
#[test]
fn start_uses_the_drivers_base_bootargs_not_a_hardcoded_hvf_default() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let driver = MockDriver::default();
    let (_rootfs_dir, rootfs) = overlay_aware_rootfs("runner-driver-base-bootargs");
    let cfg = VmStartConfig {
        name: "runner-driver-base-bootargs".into(),
        rootfs_path: rootfs,
        network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
        ..Default::default()
    };

    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    mapping_start(&runner, &cfg).expect("start succeeds");

    let specs = runner.driver.booted_specs();
    assert_eq!(specs.len(), 1);
    let cmdline = &specs[0].cmdline;

    let expected_base = driver.workload_base_bootargs(true);
    assert!(
        cmdline.starts_with(&expected_base),
        "cmdline did not start with the driver's base bootargs {expected_base:?}: {cmdline}"
    );
    assert!(
        !cmdline.contains("ttyAMA0"),
        "cmdline carried the hardcoded HVF console rather than the driver's: {cmdline}"
    );
}

/// A boot that attached the universal initramfs must be sent
/// `ActivateEnvironment` over the agent vsock port before the launch
/// returns — proven by driving `start_workload` through the `MockDriver`
/// loopback and answering as the guest: the host's request must BE the
/// activation verb (not an operational RPC), and the launch must succeed
/// on the ACK. This is the contract every runner driver (Firecracker,
/// libkrun, HVF, QEMU) inherits: the driver's only part is a working
/// `vsock_connect(GUEST_AGENT_PORT)`.
#[test]
fn start_workload_sends_activate_environment_for_a_universal_initramfs_boot() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    // An initramfs artifact under the shared cache is the discriminant
    // for the universal-initramfs boot path.
    let initrd = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("initramfs")
        .join("test-version")
        .join("initramfs.cpio.gz");
    std::fs::create_dir_all(initrd.parent().expect("initramfs cache parent")).unwrap();
    std::fs::write(&initrd, b"initramfs").unwrap();

    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = VmStartConfig {
        name: "runner-activation".into(),
        initrd_path: Some(initrd.to_string_lossy().into_owned()),
        ..config("runner-activation")
    };
    let policy = NetworkPolicy::deny_all();
    let redaction = RedactionPolicy::default();

    // The guest side of the loopback authenticates, verifies that the first
    // request is the activation verb, and acknowledges it.
    let guest = spawn_activation_guest(driver, "runner-activation");

    runner
        .boot_bound_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .expect("start_workload succeeds once activation is ACKed");
    guest.join().expect("guest thread");
}

/// A legacy per-rootfs initramfs boot (an initrd NOT under the shared
/// cache) is never sent `ActivateEnvironment` — the guest keeps its own
/// PID 1 and the launch proceeds without the handshake.
#[test]
fn start_workload_skips_activation_for_a_legacy_initramfs_boot() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let legacy = home.path().join("rootfs.initrd");
    std::fs::write(&legacy, b"initrd").unwrap();

    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = VmStartConfig {
        name: "runner-legacy-initrd".into(),
        initrd_path: Some(legacy.to_string_lossy().into_owned()),
        ..config("runner-legacy-initrd")
    };
    let policy = NetworkPolicy::deny_all();
    let redaction = RedactionPolicy::default();
    runner
        .boot_bound_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .expect("a legacy initramfs boot needs no activation handshake");
    // No vsock connect was ever made for activation: the loopback guest
    // end registry is empty.
    assert!(
        driver
            .take_guest_end(&VmId("runner-legacy-initrd".into()), GUEST_AGENT_PORT)
            .is_none(),
        "a legacy initramfs boot must not connect for activation"
    );
}

/// An initramfs under the shared cache: the universal-initramfs boot whose
/// guest waits for `ActivateEnvironment`.
fn checked_source_launch_config(
    vm: &str,
    admission_durability: Option<mvm_core::admission_durability::AdmissionDurability>,
) -> VmStartConfig {
    // These tests prove activation/sync ordering, not runtime
    // authentication, but the launch gate authenticates any runtime the
    // config names — so the fixture supplies a checked one rather than
    // naming an unverifiable initramfs.
    let (fixture_cfg, _binding) = crate::runtime_evidence::checked_source_runtime_fixture(
        vm,
        std::path::Path::new("/img/rootfs.ext4"),
    )
    .expect("checked-source runtime fixture");
    VmStartConfig {
        admission_durability,
        ..fixture_cfg
    }
}

/// The VMM may boot while the admission's audit sync is still running, but
/// the guest is not activated until it has finished: the sync is held well
/// past the moment the boot returns, and the guest checks it had completed
/// once `ActivateEnvironment` has been answered.
#[test]
fn activation_waits_for_the_admission_sync() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let synced = Arc::new(AtomicBool::new(false));
    let (release, held) = std::sync::mpsc::channel::<()>();
    let durability = mvm_core::admission_durability::AdmissionDurability::spawn({
        let synced = Arc::clone(&synced);
        move || {
            held.recv().expect("released");
            synced.store(true, Ordering::SeqCst);
            Ok(())
        }
    })
    .expect("spawn the sync");
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        release.send(()).expect("release the sync");
    });

    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = checked_source_launch_config("runner-durable-activation", Some(durability));

    let guest = {
        let synced = Arc::clone(&synced);
        let activation = spawn_activation_guest(driver.clone(), "runner-durable-activation");
        std::thread::spawn(move || {
            activation.join().expect("activation guest");
            synced.load(Ordering::SeqCst)
        })
    };
    // The guest thread reads the flag as soon as it has acknowledged
    // activation. A runner that did not wait would be acknowledged within
    // milliseconds, long before the sync is released.
    runner
        .start_workload(&launch(&cfg))
        .expect("the launch activates once the sync succeeds");
    assert!(
        guest.join().expect("guest thread"),
        "ActivateEnvironment was sent before the admission sync finished"
    );
    releaser.join().expect("releaser");
    assert_eq!(driver.booted_specs().len(), 1);
}

/// A sync that fails means the admission cannot be shown afterwards. The
/// booted guest is never sent `ActivateEnvironment` — the runner never
/// even connects to its agent — and the VMM is killed, not left running.
#[test]
fn a_failed_admission_sync_tears_the_guest_down_unactivated() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let vm = "runner-undurable-admission";
    let cfg = checked_source_launch_config(
        vm,
        Some(
            mvm_core::admission_durability::AdmissionDurability::spawn(|| {
                anyhow::bail!("fdatasync audit/local.jsonl: input/output error")
            })
            .expect("spawn the sync"),
        ),
    );

    let error = match runner.start_workload(&launch(&cfg)) {
        Ok(_) => panic!("a launch whose admission did not reach the log must fail"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("input/output error"),
        "the sync failure is what the launch reports: {error:#}"
    );
    assert_eq!(
        driver.booted_specs().len(),
        1,
        "the VMM booted beside the sync"
    );
    assert!(
        driver
            .take_guest_end(&VmId(vm.into()), GUEST_AGENT_PORT)
            .is_none(),
        "the runner must not connect to the agent of a guest it will not activate"
    );
    assert_eq!(
        driver.killed_vms(),
        vec![vm.to_string()],
        "the unactivated guest is killed"
    );
}

/// A guest that is not activated over vsock runs its workload on its own
/// as soon as it boots, so it waits for the admission's sync before the
/// VMM starts, and a failed sync boots nothing.
#[test]
fn a_boot_without_activation_waits_for_the_admission_sync_before_booting() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let legacy = home.path().join("rootfs.initrd");
    std::fs::write(&legacy, b"initrd").unwrap();
    let driver = MockDriver::default();
    let runner = WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let cfg = VmStartConfig {
        name: "runner-legacy-undurable".into(),
        initrd_path: Some(legacy.to_string_lossy().into_owned()),
        admission_durability: Some(
            mvm_core::admission_durability::AdmissionDurability::settled(Err(anyhow::anyhow!(
                "fdatasync failed"
            ))),
        ),
        ..config("runner-legacy-undurable")
    };

    assert!(runner.start_workload(&launch(&cfg)).is_err());
    assert!(
        driver.booted_specs().is_empty(),
        "nothing boots on an admission that is not durable"
    );
}

fn disk_volume(host: &str, guest: &str, read_only: bool) -> mvm_core::vm_backend::VmVolume {
    mvm_core::vm_backend::VmVolume {
        materialized_image: None,
        volume_label: None,
        host: host.into(),
        guest: guest.into(),
        size: String::new(),
        read_only,
        kind: mvm_core::vm_backend::VmVolumeKind::Disk,
        encrypted: false,
        share_include: Vec::new(),
        share_exclude: Vec::new(),
    }
}

/// A `--volume` disk (claim 11's sealed app-dep disk, or any other
/// `Disk`-kind volume) must reach a runner-booted guest both as an
/// attached `BlockDev` and as an `mvm.uvols=` cmdline entry naming it —
/// otherwise the guest has the bytes on `/dev/vdb` but no manifest saying
/// what they are for.
#[test]
fn start_carries_a_disk_volume_into_both_blocks_and_the_uvols_token() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w-uvol");
    let cfg = VmStartConfig {
        name: "w-uvol".into(),
        rootfs_path: rootfs,
        volumes: vec![disk_volume("/vol/data.img", "/data", true)],
        ..Default::default()
    };
    mapping_start(&runner, &cfg).expect("start succeeds");

    let specs = runner.driver.booted_specs();
    assert_eq!(specs.len(), 1);
    let spec = &specs[0];

    // The volume follows the rootfs; the private identity drive comes last.
    assert_eq!(
        spec.blocks
            .iter()
            .map(|b| b.device_node())
            .collect::<Vec<_>>(),
        vec!["/dev/vda", "/dev/vdb", "/dev/vdc"]
    );
    assert_eq!(spec.blocks[1].source, PathBuf::from("/vol/data.img"));
    assert!(spec.blocks[1].read_only);
    assert_eq!(
        spec.blocks[2].source,
        vm_state_dir("w-uvol").join(mvm_vmm::host::flowmux_identity::IDENTITY_DRIVE_FILE)
    );
    assert!(spec.blocks[2].read_only);

    assert!(
        spec.cmdline.contains("mvm.uvols=uvol0:"),
        "booted cmdline missing the uvols token: {}",
        spec.cmdline
    );
}

#[test]
fn start_emits_no_uvols_token_when_there_are_no_volumes() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w-no-uvol");
    let cfg = VmStartConfig {
        name: "w-no-uvol".into(),
        rootfs_path: rootfs,
        ..Default::default()
    };
    mapping_start(&runner, &cfg).expect("start succeeds");

    let specs = runner.driver.booted_specs();
    assert!(
        !specs[0].cmdline.contains("mvm.uvols="),
        "cmdline must carry no uvols token with no volumes: {}",
        specs[0].cmdline
    );
}

/// The lifted admission gate: `VmBackend::start` refuses a rootfs whose
/// parent dir carries no overlay-aware sidecar (no `/mvm/runtime` mount
/// point) before any endpoint spawn or boot, and on an admitted boot it
/// records the per-VM runtime metadata the console accessible/sealed gate
/// reads. Drives the whole trait method through a `MockDriver`.
#[test]
fn start_refuses_a_rootfs_without_the_overlay_sidecar_and_records_runtime_meta() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());

    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    // A rootfs whose parent dir carries no sidecar is refused before boot.
    let bare = tempfile::tempdir().unwrap();
    let bare_rootfs = bare.path().join("rootfs.ext4");
    std::fs::write(&bare_rootfs, b"rootfs").unwrap();
    let refused = VmStartConfig {
        name: "runner-gate-refused".into(),
        rootfs_path: bare_rootfs.display().to_string(),
        ..Default::default()
    };
    let err = runner
        .start(&refused)
        .expect_err("a rootfs with no overlay-aware sidecar must be refused");
    assert!(
        err.to_string().contains("mvm-meta.json"),
        "refusal must name the missing sidecar: {err}"
    );
    assert!(
        runner.driver.booted_specs().is_empty(),
        "the gate must fire before any boot"
    );

    // An overlay-aware rootfs is admitted, and start records runtime_meta so
    // the console accessible/sealed gate has a per-VM record to read.
    let (_rootfs_dir, rootfs) = overlay_aware_rootfs("runner-gate-admitted");
    let admitted = VmStartConfig {
        name: "runner-gate-admitted".into(),
        rootfs_path: rootfs,
        ..Default::default()
    };
    ClaimGuards::new(&runner.spawner)
        .admit_overlay_contract(Path::new(&admitted.rootfs_path))
        .expect("an overlay-aware rootfs is admitted");
    mapping_start(&runner, &admitted).expect("admitted shape maps to a boot");
    let meta = crate::base::runtime_meta::read("runner-gate-admitted")
        .expect("runtime_meta read")
        .expect("start records runtime_meta");
    assert_eq!(
        meta.rootfs_path.as_deref(),
        Some(admitted.rootfs_path.as_str())
    );
}

/// [`overlay_aware_rootfs`] with a real ext4 filesystem behind it, so an
/// offline checker or a journal replay run against the image would have
/// something to rewrite. `needs_recovery` sets the superblock flag a dirty
/// journal leaves behind.
fn overlay_aware_ext4_rootfs(name: &str, needs_recovery: bool) -> (tempfile::TempDir, String) {
    let (dir, rootfs) = overlay_aware_rootfs(name);
    let mut image = std::fs::File::create(&rootfs).unwrap();
    let size = 8 * 1024 * 1024;
    image.set_len(size).unwrap();
    mvm_fs::ext4::mkfs::format_empty_ext4(&mut image, size).unwrap();
    drop(image);
    if needs_recovery {
        let mut bytes = std::fs::read(&rootfs).unwrap();
        // s_feature_incompat, EXT4_FEATURE_INCOMPAT_RECOVER.
        bytes[1024 + 0x60] |= 0x4;
        std::fs::write(&rootfs, bytes).unwrap();
    }
    (dir, rootfs)
}

/// The image a launch admitted is the image the VMM boots. Admission hashes
/// the rootfs before `start`, and the cached default image is shared by
/// every later launch, so `start` must not rewrite it — not even the
/// superblock timestamps an offline filesystem check stamps on a clean
/// image.
#[test]
fn start_boots_the_admitted_rootfs_without_rewriting_it() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let (_dir, rootfs) = overlay_aware_ext4_rootfs("runner-rootfs-unchanged", false);
    let admitted = mvm_core::crypto::image_verify::sha256_file(Path::new(&rootfs)).unwrap();
    let cfg = VmStartConfig {
        name: "runner-rootfs-unchanged".into(),
        rootfs_path: rootfs.clone(),
        ..Default::default()
    };

    mapping_start(&runner, &cfg).expect("a clean rootfs boots");

    assert_eq!(
        mvm_core::crypto::image_verify::sha256_file(Path::new(&rootfs)).unwrap(),
        admitted,
        "start rewrote the rootfs after it was admitted"
    );
    let specs = runner.driver.booted_specs();
    assert_eq!(specs[0].blocks[0].source, PathBuf::from(&rootfs));
    assert!(
        specs[0].blocks[0].read_only,
        "the guest must not be able to write the shared image either"
    );
}

#[test]
fn start_refuses_a_rootfs_whose_journal_needs_replay_before_boot() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let (_dir, rootfs) = overlay_aware_ext4_rootfs("runner-rootfs-dirty", true);
    let before = std::fs::read(&rootfs).unwrap();
    let cfg = VmStartConfig {
        name: "runner-rootfs-dirty".into(),
        rootfs_path: rootfs.clone(),
        ..Default::default()
    };

    let err = runner
        .start(&cfg)
        .expect_err("a read-only guest cannot mount a journal that needs replay");

    assert!(err.to_string().contains(&rootfs), "names the image: {err}");
    assert!(
        runner.driver.booted_specs().is_empty(),
        "the refusal must come before any boot"
    );
    assert_eq!(
        std::fs::read(&rootfs).unwrap(),
        before,
        "the refused image must be left exactly as it was"
    );
}

#[test]
fn vmbackend_name_and_capabilities_delegate_to_the_driver() {
    let driver = MockDriver::default();
    let want_name = driver.name().to_string();
    let want_caps = driver.capabilities();
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    assert_eq!(runner.name(), want_name);
    assert_eq!(runner.capabilities().vsock, want_caps.vsock);
    assert!(runner.is_available().unwrap());
}

#[test]
fn vmbackend_kind_snapshot_security_and_channel_delegate_to_the_hvf_driver() {
    // Proves the runner reads these from the driver rather than the old
    // `BackendKind::Hvf` hardcode / the VmBackend trait's fail-closed
    // defaults — a runner wrapping a *different* driver would report that
    // driver's own values instead.
    let driver = HvfDriver::new();
    let want_kind = driver.kind();
    let want_snapshot = driver.snapshot_capability();
    let want_security_tier = driver.security_profile().tier;
    let id = VmId("kind-delegation-test-vm".into());
    let want_channel_err = driver.guest_channel_info(&id).is_err();
    let runner = WorkloadRunner::new(
        driver,
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    assert_eq!(runner.kind(), want_kind);
    assert_eq!(runner.kind(), BackendKind::Hvf);
    assert_eq!(runner.snapshot_capability(), want_snapshot);
    assert_eq!(runner.security_profile().tier, want_security_tier);
    assert_eq!(runner.guest_channel_info(&id).is_err(), want_channel_err);
}

#[test]
fn start_workload_with_dev_console_threads_128_console_ports_into_spec() {
    use mvm_agentd::vsock::CONSOLE_PORT_BASE;
    let (_env, _home) = isolated_runtime_home();
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let cfg = VmStartConfig {
        dev_console: true,
        ..config("w-dev-console")
    };
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "t",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .expect("start_workload with dev_console succeeds");

    let specs = runner.driver.booted_specs();
    let spec = &specs[0];

    // Four standing channels plus 128 console data channels.
    assert_eq!(spec.vsock.len(), 132);

    // Every console port is in range and routed as HostDials.
    let console: Vec<_> = spec
        .vsock
        .iter()
        .filter(|p| p.service.port() > CONSOLE_PORT_BASE)
        .collect();
    assert_eq!(console.len(), 128);
    assert!(
        console
            .iter()
            .all(|p| p.direction == crate::driver::VsockDirection::HostDials),
        "console ports must be HostDials"
    );

    // Paths live under <state_dir>/vsock/ — the shared HVF vsock convention.
    let first = &console[0];
    assert!(
        first.host_uds.to_string_lossy().contains("/vsock/vsock-"),
        "path must be under vsock/ subdir: {}",
        first.host_uds.display()
    );
}

#[test]
fn start_workload_without_dev_console_carries_only_four_vsock_entries() {
    let (_env, _home) = isolated_runtime_home();
    let policy = egress_allowing_policy();
    let redaction = RedactionPolicy::default();
    let runner = WorkloadRunner::new(
        MockDriver::default(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );

    let cfg = VmStartConfig {
        dev_console: false,
        ..config("w-sealed")
    };
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "t",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        })
        .expect("start_workload without dev_console succeeds");

    let specs = runner.driver.booted_specs();
    let spec = &specs[0];
    assert_eq!(
        spec.vsock.len(),
        4,
        "sealed prod boot must carry no console listeners"
    );
}
