use super::*;
use mvm_core::crypto::entrypoint_delegation::test_support;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::util::test_env::TestEnv;

use crate::plan_admission::{InMemoryNonceLedger, RunPosture, admit_plan_for_run};
use crate::stream::protected::{CaptureAuthority, CaptureOwner, CaptureParams};

fn isolate() -> (TestEnv, tempfile::TempDir) {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    (env, home)
}

fn admit_fixture(vm: &str, nonce: u8) -> AdmittedPlan {
    let mut plan = PlanFixture::new().workload(vm).nonce([nonce; 16]).build();
    plan.plan_id = mvm_core::plan::content_id::compute_plan_id(&plan);
    admit_plan_for_run(
        &plan,
        &mvm_core::time::SystemClock,
        &InMemoryNonceLedger::default(),
        None,
        None,
        None,
        RunPosture::without_backend(mvm_core::plan::Variant::Dev),
    )
    .unwrap()
}

fn registration_fixture(admitted: &AdmittedPlan, vm: &str, seed: u8) -> CallerRegistration {
    let installation = serde_json::from_str("\"bdf189ab-9a9a-440b-a266-e95b19e58a5e\"").unwrap();
    let identity = test_support::identity([seed; 32], installation);
    let now = unix_now().unwrap();
    let challenge =
        CallerRegistration::challenge_for_plan(vm, admitted.plan(), identity, now).unwrap();
    let proof = test_support::proof([seed; 32], &challenge, now).unwrap();
    let verified = proof.verify(&challenge, now).unwrap();
    admit_caller(admitted, vm, challenge, verified).unwrap()
}

fn launch(admitted: &AdmittedPlan, registration: &CallerRegistration) -> VerifiedCallerLaunch {
    verify_cold_start(&registration.vm, admitted.signed(), registration).unwrap()
}

fn startup_config(
    admitted: &AdmittedPlan,
    registration: &CallerRegistration,
) -> mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig {
    let state = config::vm_state_dir(&registration.vm);
    let kernel = config::mvm_home_strict().unwrap().join("fixture-kernel");
    std::fs::write(&kernel, b"synthetic kernel input").unwrap();
    serde_json::from_value(serde_json::json!({
        "console_capture": "encrypted",
        "vm_name": registration.vm,
        "kernel": kernel,
        "console_log": state.join("console.log"),
        "pid_file": state.join("supervisor.pid"),
        "workload_exit": state.join("workload.exit"),
        "timeout_secs": 0,
        "plan": admitted.signed(),
        "caller_registration": registration,
        "signing_key_path": "/caller-selected-untrusted-root"
    }))
    .unwrap()
}

#[test]
fn actual_startup_wire_uses_canonical_root_and_refuses_warm_without_state_changes() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("startup-wire", 1);
    let registration = registration_fixture(&admitted, "startup-wire", 1);
    let cfg = startup_config(&admitted, &registration);
    let bytes = serde_json::to_vec(&cfg).unwrap();
    let mut decoded: mvm_vmm::host::hvf_supervisor::HvfSupervisorConfig =
        serde_json::from_slice(&bytes).unwrap();
    assert!(!config::vm_state_dir("startup-wire").exists());
    decoded.handoff_socket = Some("/unused-handoff.sock".into());
    assert!(prepare_startup(&decoded).is_err());
    assert!(!config::vm_state_dir("startup-wire").exists());
    decoded.handoff_socket = None;
    decoded.restore_ram = Some("/unused-restore".into());
    assert!(prepare_startup(&decoded).is_err());
    decoded.restore_ram = None;
    decoded.vm_name = "retargeted".into();
    assert!(prepare_startup(&decoded).is_err());
    assert!(!config::vm_state_dir("retargeted").exists());
    decoded.vm_name = "startup-wire".into();
    assert!(prepare_startup(&decoded).unwrap().is_some());
    assert!(
        config::vm_state_dir("startup-wire")
            .join("caller-registration.used")
            .exists()
    );
    assert!(!decoded.pid_file.exists());
    assert!(prepare_startup(&decoded).is_err());
}

#[test]
fn actual_early_boot_input_failure_is_spent_before_status_or_capture_setup() {
    let (_env, _home) = isolate();
    for missing_kernel in [true, false] {
        let vm = if missing_kernel {
            "missing-kernel"
        } else {
            "missing-initramfs"
        };
        let admitted = admit_fixture(vm, 1);
        let registration = registration_fixture(&admitted, vm, 1);
        let mut cfg = startup_config(&admitted, &registration);
        let kernel = cfg.kernel.clone();
        if missing_kernel {
            cfg.kernel = kernel.with_file_name("missing-kernel-input");
        } else {
            cfg.initramfs = Some(kernel.with_file_name("missing-initramfs-input"));
        }
        let Err(error) = prepare_startup(&cfg) else {
            panic!("missing input must refuse startup")
        };
        assert!(error.to_string().contains(if missing_kernel {
            "kernel"
        } else {
            "initramfs"
        }));
        assert!(
            config::vm_state_dir(vm)
                .join("caller-registration.used")
                .exists()
        );
        assert!(!cfg.pid_file.exists());
        assert!(!config::vm_protected_stream_dir(vm).exists());
        cfg.kernel = kernel;
        cfg.initramfs = None;
        assert!(
            prepare_startup(&cfg).is_err(),
            "repair must not reuse the spent record"
        );
        mvm_runtime::vm::reconcile::remove_runtime_dirs(&config::vm_state_dir(vm)).unwrap();
        assert!(
            prepare_startup(&cfg).is_err(),
            "teardown cannot revive that record"
        );
        let fresh = admit_fixture(vm, 2);
        let fresh_registration = registration_fixture(&fresh, vm, 1);
        let fresh_cfg = startup_config(&fresh, &fresh_registration);
        assert!(prepare_startup(&fresh_cfg).unwrap().is_some());
        assert!(!fresh_cfg.pid_file.exists());
    }
}

#[test]
fn resigned_own_key_or_instance_cannot_replace_the_trusted_launch_expectation() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("expected-cold", 1);
    let original = registration_fixture(&admitted, "expected-cold", 1);
    let other = registration_fixture(&admitted, "expected-cold", 2);
    let mut substituted = original.clone();
    substituted.proof = other.proof;
    assert!(verify_cold_start("expected-cold", admitted.signed(), &substituted).is_err());
    let now = unix_now().unwrap();
    let mut wrong_instance = original.expected.clone();
    wrong_instance.binding.instance = "expected-cold/00000000-0000-0000-0000-000000000001".into();
    substituted.proof = test_support::proof([1; 32], &wrong_instance, now).unwrap();
    assert!(verify_cold_start("expected-cold", admitted.signed(), &substituted).is_err());
    let mut widened = original.expected.clone();
    widened.binding.not_after += 1000;
    substituted.expected = widened.clone();
    substituted.proof = test_support::proof([1; 32], &widened, now).unwrap();
    assert!(verify_cold_start("expected-cold", admitted.signed(), &substituted).is_err());
    assert!(!config::vm_state_dir("expected-cold").exists());
}

#[test]
fn actual_admission_installs_once_in_real_owner_without_producer_readiness() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("registered-cold", 1);
    let registration = registration_fixture(&admitted, "registered-cold", 1);
    let startup = prepare_startup(&startup_config(&admitted, &registration))
        .unwrap()
        .unwrap();
    let (owner, producer) = CaptureOwner::start(CaptureParams {
        vm: &registration.vm,
        authority: CaptureAuthority::CallerRegistered(startup.launch),
        redaction: &admitted.plan().redaction,
    })
    .unwrap();
    assert_eq!(
        owner.registered_caller().unwrap().challenge(),
        &registration.proof.challenge,
    );
    let run = mvm_core::stream_client::protected::ProtectedRun::read(
        &config::vm_protected_stream_dir(&registration.vm),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        run.run,
        registration
            .proof
            .challenge
            .binding
            .run
            .as_u128()
            .to_string()
    );
    assert!(
        !config::vm_state_dir(&registration.vm)
            .join("supervisor.pid")
            .exists()
    );
    assert!(!config::vm_console_log(&registration.vm).exists());
    let replacement = registration_fixture(&admitted, "registered-cold", 2);
    assert!(
        launch(&admitted, &replacement)
            .consume("registered-cold")
            .is_err()
    );
    assert_eq!(
        owner.registered_caller().unwrap().challenge(),
        &registration.proof.challenge,
        "another valid native identity cannot replace an installed owner",
    );
    drop(producer);
    assert!(owner.finish());
    assert!(
        launch(&admitted, &registration)
            .consume("registered-cold")
            .is_err()
    );
}

#[test]
fn wrong_root_or_missing_public_root_is_refused_without_repair_or_consumption() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("root-check", 1);
    let registration = registration_fixture(&admitted, "root-check", 1);
    let root = config::mvm_keys_dir().join(host_keypair::PUBLIC_FILENAME);
    let original = std::fs::read(&root).unwrap();
    std::fs::write(
        &root,
        ed25519_dalek::SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    assert!(verify_cold_start("root-check", admitted.signed(), &registration).is_err());
    std::fs::remove_file(&root).unwrap();
    assert!(verify_cold_start("root-check", admitted.signed(), &registration).is_err());
    assert!(
        !root.exists(),
        "verification must never generate or repair a root"
    );
    assert!(!config::vm_state_dir("root-check").exists());
    std::fs::write(root, original).unwrap();
    // Public verification needs no access to the host private signing key.
    std::fs::remove_file(config::mvm_keys_dir().join(host_keypair::SECRET_FILENAME)).unwrap();
    assert!(verify_cold_start("root-check", admitted.signed(), &registration).is_ok());
}

#[test]
fn wrong_plan_tenant_instance_stale_key_and_tampering_cannot_burn_replay_slot() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("binding-check", 1);
    let registration = registration_fixture(&admitted, "binding-check", 1);
    for mutation in 0..6 {
        let mut changed = registration.clone();
        match mutation {
            0 => changed.proof.challenge.binding.tenant = "other-tenant".into(),
            1 => changed.proof.challenge.binding.plan_id = "other-plan".into(),
            2 => {
                changed.proof.challenge.binding.instance =
                    "other-vm/00000000-0000-0000-0000-000000000001".into()
            }
            3 => changed.proof.challenge.identity.public_key = [3; 32],
            4 => changed.proof.challenge.binding.not_after = 1,
            5 => changed.proof.signature[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(verify_cold_start("binding-check", admitted.signed(), &changed).is_err());
        assert!(!config::vm_state_dir("binding-check").exists());
    }
    let other = admit_fixture("binding-check", 2);
    assert!(verify_cold_start("binding-check", other.signed(), &registration).is_err());
    assert!(verify_cold_start("renamed-child", admitted.signed(), &registration).is_err());
    assert!(
        launch(&admitted, &registration)
            .consume("binding-check")
            .is_ok()
    );
}

#[test]
fn signed_but_expired_plan_is_rejected_before_consumption() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("expired-cold", 1);
    let registration = registration_fixture(&admitted, "expired-cold", 1);
    let mut plan = admitted.plan().clone();
    plan.valid_from = chrono::Utc::now() - chrono::Duration::seconds(20);
    plan.valid_until = chrono::Utc::now() - chrono::Duration::seconds(10);
    plan.plan_id = mvm_core::plan::content_id::compute_plan_id(&plan);
    let signer = host_keypair::load_or_init().unwrap();
    let signed = mvm_core::plan::sign_plan(&plan, &signer.signing, &host_keypair::host_signer_id());
    assert!(verify_cold_start("expired-cold", &signed, &registration).is_err());
    assert!(!config::vm_state_dir("expired-cold").exists());
}

#[test]
fn concurrent_consumers_have_exactly_one_winner_and_restart_stays_spent() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("concurrent-cold", 1);
    let registration = registration_fixture(&admitted, "concurrent-cold", 1);
    let first = launch(&admitted, &registration);
    let second = launch(&admitted, &registration);
    let winners = std::thread::scope(|scope| {
        let first = scope.spawn(|| first.consume("concurrent-cold").is_ok());
        let second = scope.spawn(|| second.consume("concurrent-cold").is_ok());
        usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
    });
    assert_eq!(winners, 1);
    assert!(
        launch(&admitted, &registration)
            .consume("concurrent-cold")
            .is_err()
    );
    let state = config::vm_state_dir("concurrent-cold");
    let entries: Vec<_> = std::fs::read_dir(&state).unwrap().collect();
    assert_eq!(
        entries.len(),
        1,
        "no per-request ledger or leftover temporary files"
    );
    assert_eq!(
        mvm_core::private_fs::mode_bits(&state, &std::fs::metadata(&state).unwrap()).unwrap(),
        0o700,
    );
    let marker = state.join("caller-registration.used");
    assert_eq!(
        mvm_core::private_fs::mode_bits(&marker, &std::fs::metadata(&marker).unwrap()).unwrap(),
        0o600,
    );
}

#[test]
fn setup_failure_stays_spent_and_public_teardown_allows_fresh_admission() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("failed-cold", 1);
    let registration = registration_fixture(&admitted, "failed-cold", 1);
    let root = config::vm_protected_stream_dir("failed-cold");
    config::create_private_dir(root.parent().unwrap()).unwrap();
    std::fs::write(&root, b"force capture directory setup failure").unwrap();
    assert!(
        CaptureOwner::start(CaptureParams {
            vm: "failed-cold",
            authority: CaptureAuthority::CallerRegistered(
                launch(&admitted, &registration)
                    .consume("failed-cold")
                    .unwrap(),
            ),
            redaction: &admitted.plan().redaction,
        })
        .is_err()
    );
    assert!(
        launch(&admitted, &registration)
            .consume("failed-cold")
            .is_err()
    );
    // Repair the injected storage failure. Runtime teardown deliberately does
    // not delete independently retained diagnostic state.
    std::fs::remove_file(&root).unwrap();
    mvm_runtime::vm::reconcile::remove_runtime_dirs(&config::vm_state_dir("failed-cold")).unwrap();
    assert!(
        launch(&admitted, &registration)
            .consume("failed-cold")
            .is_err(),
        "runtime teardown must not revive the old registration"
    );
    let fresh = admit_fixture("failed-cold", 2);
    let fresh_registration = registration_fixture(&fresh, "failed-cold", 1);
    assert_ne!(
        registration.proof.challenge.binding.instance,
        fresh_registration.proof.challenge.binding.instance
    );
    let (owner, producer) = CaptureOwner::start(CaptureParams {
        vm: "failed-cold",
        authority: CaptureAuthority::CallerRegistered(
            launch(&fresh, &fresh_registration)
                .consume("failed-cold")
                .unwrap(),
        ),
        redaction: &fresh.plan().redaction,
    })
    .unwrap();
    drop(producer);
    assert!(owner.finish());
}

#[cfg(unix)]
#[test]
fn replay_slot_and_instance_symlinks_are_never_followed() {
    let (_env, _home) = isolate();
    let admitted = admit_fixture("linked-cold", 1);
    let registration = registration_fixture(&admitted, "linked-cold", 1);
    let outside = tempfile::tempdir().unwrap();
    let state = config::vm_state_dir("linked-cold");
    config::create_private_dir(state.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(outside.path(), &state).unwrap();
    assert!(
        launch(&admitted, &registration)
            .consume("linked-cold")
            .is_err()
    );
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    std::fs::remove_file(&state).unwrap();
    config::create_private_dir(&state).unwrap();
    let target = outside.path().join("unchanged");
    std::fs::write(&target, b"marker").unwrap();
    std::os::unix::fs::symlink(&target, state.join("caller-registration.used")).unwrap();
    assert!(
        launch(&admitted, &registration)
            .consume("linked-cold")
            .is_err()
    );
    assert_eq!(std::fs::read(target).unwrap(), b"marker");
}
