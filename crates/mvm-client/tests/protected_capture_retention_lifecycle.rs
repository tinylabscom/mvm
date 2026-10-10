//! Hermetic public lifecycle regression: runtime reaping must not own
//! protected diagnostic payloads. Native execution has a separate witness.
#![cfg(feature = "test-support")]

use mvm_client::{LocalBackend, MachineId};
use mvm_core::client::MvmClient;
use mvm_core::stream_client::protected::ProtectedRun;
use mvm_core::stream_client::{OutputRequest, open_vm_output};
use mvm_core::transcript::{MANIFEST_FILENAME, TranscriptManifest};
use mvm_core::{config, plan::test_support::PlanFixture, util::test_env::TestEnv};
use mvm_hostd::stream::protected::{CaptureAuthority, CaptureOwner, CaptureParams};
use std::io::Write;

#[tokio::test]
async fn public_stop_preserves_durable_history_and_restart_selects_only_new_run() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    mvm_hostd::audit::host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap();
    let plan = PlanFixture::new().tenant("lifecycle-tenant").build();
    let vm = "retained-output";
    let root = config::vm_protected_stream_dir(vm);
    let legacy = config::vm_stream_transcript_dir(vm);
    config::create_private_dir(&legacy).unwrap();
    std::fs::write(legacy.join("legacy-unenrolled"), b"legacy").unwrap();
    let (owner, mut producer) = CaptureOwner::start(CaptureParams {
        vm,
        authority: CaptureAuthority::Admitted(&plan),
        redaction: &plan.redaction,
    })
    .unwrap();
    producer.write_all(b"retained-after-public-stop").unwrap();
    drop(producer);
    assert!(owner.finish());
    let first = ProtectedRun::read(&root).unwrap().unwrap();
    let first_dir = first.directory(&root).unwrap().join("00000000000000000000");
    let original = std::fs::read(first_dir.join(MANIFEST_FILENAME)).unwrap();
    LocalBackend::with_hypervisor("mock")
        .stop_machine(&MachineId(vm.into()))
        .await
        .unwrap();
    assert!(!config::vm_state_dir(vm).exists());
    assert!(
        !legacy.exists(),
        "legacy disposable-state behavior is unchanged"
    );
    assert_eq!(
        std::fs::read(first_dir.join(MANIFEST_FILENAME)).unwrap(),
        original
    );
    let mut reader = open_vm_output(vm, OutputRequest::default()).unwrap();
    assert_eq!(
        reader.next_output().unwrap().unwrap().payload,
        b"retained-after-public-stop"
    );
    assert!(reader.next_output().unwrap().is_none());

    let other = PlanFixture::new().tenant("other-tenant").build();
    assert!(
        CaptureOwner::start(CaptureParams {
            vm,
            authority: CaptureAuthority::Admitted(&other),
            redaction: &other.redaction,
        })
        .is_err(),
        "reusing an instance name cannot adopt another tenant's retained family"
    );
    assert_eq!(ProtectedRun::read(&root).unwrap().unwrap().run, first.run);
    let (owner, mut producer) = CaptureOwner::start(CaptureParams {
        vm,
        authority: CaptureAuthority::Admitted(&plan),
        redaction: &plan.redaction,
    })
    .unwrap();
    producer.write_all(b"new-incarnation-only").unwrap();
    drop(producer);
    assert!(owner.finish());
    let second = ProtectedRun::read(&root).unwrap().unwrap();
    assert_ne!(first.run, second.run);
    assert_eq!(
        std::fs::read(first_dir.join(MANIFEST_FILENAME)).unwrap(),
        original
    );
    let mut reader = open_vm_output(vm, OutputRequest::default()).unwrap();
    assert_eq!(
        reader.next_output().unwrap().unwrap().payload,
        b"new-incarnation-only"
    );
    assert!(reader.next_output().unwrap().is_none());
}

#[tokio::test]
async fn public_stop_preserves_abandoned_opening_and_next_owner_recovers_it() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    mvm_hostd::audit::host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap();
    let plan = PlanFixture::new().tenant("abandoned-tenant").build();
    let vm = "abandoned-output";
    let (owner, producer) = CaptureOwner::start(CaptureParams {
        vm,
        authority: CaptureAuthority::Admitted(&plan),
        redaction: &plan.redaction,
    })
    .unwrap();
    let root = config::vm_protected_stream_dir(vm);
    let run = ProtectedRun::read(&root).unwrap().unwrap();
    let dir = run.directory(&root).unwrap().join("00000000000000000000");
    // Simulate storage failure at terminal staging: the real owner leaves its
    // signed opening and seed but publishes no terminal seal.
    std::fs::create_dir(dir.join(MANIFEST_FILENAME)).unwrap();
    drop(producer);
    assert!(!owner.finish());
    std::fs::remove_dir(dir.join(MANIFEST_FILENAME)).unwrap();
    let seed = std::fs::read(dir.join("capture-seed.json")).unwrap();
    LocalBackend::with_hypervisor("mock")
        .stop_machine(&MachineId(vm.into()))
        .await
        .unwrap();
    assert!(!config::vm_state_dir(vm).exists());
    assert_eq!(std::fs::read(dir.join("capture-seed.json")).unwrap(), seed);
    let (owner, producer) = CaptureOwner::start(CaptureParams {
        vm,
        authority: CaptureAuthority::Admitted(&plan),
        redaction: &plan.redaction,
    })
    .unwrap();
    let recovered: TranscriptManifest =
        serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap()).unwrap();
    assert!(recovered.adopted);
    assert!(recovered.sealed_unix_secs.is_some());
    drop(producer);
    assert!(owner.finish());
}

#[test]
fn persistent_family_path_is_contained_for_untrusted_names() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let root = config::mvm_audit_dir().join("workload-output");
    for name in ["../outside", "/absolute", "a/b", "a\\b", "normal-vm"] {
        let path = config::vm_protected_stream_dir(name);
        assert_eq!(path.parent(), Some(root.as_path()));
        assert!(!path.starts_with(config::vm_state_dir(name)));
    }
}
