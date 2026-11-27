//! Listing must report a machine whose state cannot be probed, not refuse to
//! list every other machine.
#![cfg(test)]

use super::{test_support::*, *};
use mvm_core::util::test_env::TestEnv;

#[test]
fn an_unprobeable_machine_is_listed_failed_beside_the_machines_that_probe() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    // A supervisor pid file with no recorded control identity: attach refuses
    // it as unknown rather than treating it as stopped.
    let unknown = vm_state_dir("unknown-identity");
    std::fs::create_dir_all(&unknown).unwrap();
    std::fs::write(unknown.join("hvf.pid"), "4242").unwrap();
    // A console log alone is a machine HVF never launched: plainly stopped.
    // The shape a real run left behind: a warm-pool standby whose launch lock
    // exists with no authenticated control identity.
    let standby = vm_state_dir("standby-6364723eb56ad227");
    std::fs::create_dir_all(&standby).unwrap();
    std::fs::write(standby.join("hvf-launch.lock"), "").unwrap();
    std::fs::write(standby.join("hvf.pid"), "4243").unwrap();
    let idle = vm_state_dir("never-launched");
    std::fs::create_dir_all(&idle).unwrap();
    std::fs::write(idle.join("console.log"), "").unwrap();

    let runner = WorkloadRunner::new(
        mvm_vmm::driver::hvf::HvfDriver::new(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    );
    let listed = VmBackend::list(&runner).expect("one unprobeable machine must not hide the rest");

    let status_of = |name: &str| {
        listed
            .iter()
            .find(|vm| vm.name == name)
            .unwrap_or_else(|| panic!("{name} missing from {listed:?}"))
            .status
            .clone()
    };
    assert_eq!(status_of("never-launched"), VmStatus::Stopped);
    for name in ["unknown-identity", "standby-6364723eb56ad227"] {
        let status = status_of(name);
        assert!(
            matches!(status, VmStatus::Failed { .. }),
            "{name} is reported failed, never presumed stopped: {status:?}"
        );
    }
    // Unknown is never stopped: the listing still refuses policy activation.
    let registry = crate::vm::name_registry::VmNameRegistry::default();
    assert!(
        crate::backend::require_observed_quiescence(&listed, &registry).is_err(),
        "an unprobeable machine still refuses host quiescence"
    );
}
