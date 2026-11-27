//! When a cold launch makes its lifecycle lease and runtime generation
//! durable: beside the VMM boot, and always before the guest is activated.
#![cfg(test)]

use super::{test_support::*, *};
use crate::driver::MockDriver;
use crate::runtime_evidence::durable_steps;
use mvm_agentd::vsock::GUEST_AGENT_PORT;
use mvm_core::util::test_env::TestEnv;
use std::sync::Mutex;
use std::time::Instant;

const CRASH_CHILD_ENV: &str = "MVM_LEASE_SYNC_CRASH_CHILD";
const CRASHED_BESIDE_BOOT: i32 = 67;
const SYNCED_BEFORE_BOOT: i32 = 68;

/// A launch named `vm` whose checked runtime comes from a fixture staged
/// under `source`, so the launch creates its own lease entry. An earlier
/// launch has already created the host's shared content store, whose one-off
/// creation syncs the namespace root on its own.
fn fresh_launch_config(vm: &str, source: &str) -> VmStartConfig {
    let (fixture, _) = crate::runtime_evidence::checked_source_runtime_fixture(
        source,
        Path::new("/img/rootfs.ext4"),
    )
    .expect("checked-source runtime fixture");
    let earlier = format!("{source}-earlier");
    crate::runtime_evidence::RuntimeLifecycleLease::acquire(&earlier)
        .and_then(|lease| {
            lease.bind(&VmStartConfig {
                name: earlier.clone(),
                ..fixture.clone()
            })
        })
        .expect("an earlier launch binds the shared content store");
    VmStartConfig {
        name: vm.into(),
        ..fixture
    }
}

fn evidence_root(home: &Path) -> PathBuf {
    home.canonicalize().unwrap().join("runtime-evidence")
}

fn runner(
    driver: &MockDriver,
) -> WorkloadRunner<MockDriver, RecordingSpawner, RecordingBrokerRegistrar> {
    WorkloadRunner::new(
        driver.clone(),
        RecordingSpawner::new("/run/ep.sock"),
        RecordingBrokerRegistrar::new(),
    )
}

/// Whether the driver has booted a VM within `wait`.
fn booted_within(driver: &MockDriver, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if !driver.booted_specs().is_empty() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The generation directory a launch of `vm` published (there is one).
fn generation_of(home: &Path, vm: &str) -> PathBuf {
    std::fs::read_dir(evidence_root(home).join(vm))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .expect("the launch published a generation")
}

/// Every sync of the lease and generation runs after the VMM has started and
/// before the guest is activated. Each sync waits (bounded) for the boot, so
/// on the old order, where they ran before the spawn, they are recorded as
/// having run before it.
#[test]
fn a_cold_launch_syncs_its_lease_and_generation_beside_the_boot_and_before_activation() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let vm = "lease-synced-beside-boot";
    let cfg = fresh_launch_config(vm, "beside-boot-source");
    let driver = MockDriver::default();
    let root = evidence_root(home.path());
    let lease = root.join(vm);

    let synced: Arc<Mutex<Vec<(PathBuf, bool)>>> = Arc::default();
    let _hook = durable_steps::hook({
        let (driver, synced, lease) = (driver.clone(), Arc::clone(&synced), lease.clone());
        move |path| {
            if path.starts_with(&lease) || path == lease.parent().unwrap_or(&lease) {
                let booted = booted_within(&driver, Duration::from_secs(2));
                synced.lock().unwrap().push((path.to_path_buf(), booted));
            }
            Ok(())
        }
    });
    let guest = {
        let (activation, synced) = (
            spawn_activation_guest(driver.clone(), vm),
            Arc::clone(&synced),
        );
        std::thread::spawn(move || {
            activation.join().expect("activation guest");
            synced.lock().unwrap().clone()
        })
    };

    runner(&driver)
        .start_workload(&launch(&cfg))
        .expect("the launch activates once its records are durable");
    let at_activation = guest.join().expect("guest thread");

    let generation = generation_of(home.path(), vm);
    let paths: Vec<&PathBuf> = at_activation.iter().map(|(path, _)| path).collect();
    for expected in [
        generation.join("launch.json"),
        generation.join("overlay.ext4"),
        generation.join("overlay.verity"),
        generation.join("initramfs.cpio.gz"),
        generation.clone(),
        lease.clone(),
        root.clone(),
    ] {
        assert!(
            paths.contains(&&expected),
            "{} was durable before activation: {paths:?}",
            expected.display()
        );
    }
    assert_eq!(paths.last(), Some(&&root), "the lease entry is synced last");
    assert!(
        at_activation.iter().all(|(_, booted)| *booted),
        "no lease or generation sync runs before the VMM starts: {at_activation:?}"
    );
    assert_eq!(
        *synced.lock().unwrap(),
        at_activation,
        "nothing is synced after activation"
    );
}

/// A lease or generation that cannot be made durable means the guest is never
/// activated: the VMM that booted beside the sync is killed unactivated, and
/// the generation it may have read is kept, not deleted.
#[test]
fn a_failed_lease_sync_tears_the_guest_down_unactivated_and_keeps_the_generation() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let vm = "lease-sync-fails";
    let cfg = fresh_launch_config(vm, "sync-fails-source");
    let driver = MockDriver::default();
    let lease = evidence_root(home.path()).join(vm);
    let _hook = durable_steps::hook(move |path| {
        anyhow::ensure!(
            !(path.starts_with(&lease) && path.ends_with("launch.json")),
            "fsync {}: input/output error",
            path.display()
        );
        Ok(())
    });

    let error = match runner(&driver).start_workload(&launch(&cfg)) {
        Ok(_) => panic!("a launch whose lease is not durable must not activate"),
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
    assert_eq!(driver.killed_vms(), vec![vm.to_string()]);
    assert!(
        generation_of(home.path(), vm).join("launch.json").is_file(),
        "a generation a booted VMM may have read is retained"
    );
}

/// The launcher is killed after the VMM started and before its lease and
/// generation were synced. A killed process loses nothing it wrote, so every
/// record a later reader trusts is still there; reconcile reaps only the dead
/// VM's state dir; and a relaunch under the same name binds a generation of
/// its own without touching the one the dead launch published.
#[test]
fn a_launcher_killed_between_spawn_and_sync_leaves_every_record_for_reconcile_and_relaunch() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.set("MVM_HOME", home.path());
    let vm = "lease-sync-crash";

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "workload_runner::runner::lease_sync_tests::crash_child",
            "--ignored",
            "--test-threads=1",
        ])
        .env("MVM_HOME", home.path())
        .env(CRASH_CHILD_ENV, vm)
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(CRASHED_BESIDE_BOOT),
        "the child must die inside a sync that runs after the VMM started"
    );

    let lease = evidence_root(home.path()).join(vm);
    let crashed = generation_of(home.path(), vm);
    for artifact in [
        "launch.json",
        "overlay.ext4",
        "overlay.verity",
        "initramfs.cpio.gz",
    ] {
        assert!(
            crashed.join(artifact).is_file(),
            "{artifact} survived the kill"
        );
    }

    let state_dir = vm_state_dir(vm);
    assert_eq!(
        crate::vm::reconcile::reap_unowned_state_dir_locked(&state_dir),
        Ok(true),
        "reconcile reaps the dead VM's state dir"
    );
    assert!(crashed.is_dir(), "reconcile leaves runtime evidence alone");

    let driver = MockDriver::default();
    let activation = spawn_activation_guest(driver.clone(), vm);
    runner(&driver)
        .start_workload(&launch(&fresh_launch_config(vm, "relaunch-source")))
        .expect("a relaunch of the same name takes the released lease");
    activation.join().expect("activation guest");
    let generations: Vec<PathBuf> = std::fs::read_dir(&lease)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(
        generations.len(),
        2,
        "the relaunch published its own generation"
    );
    assert!(
        crashed.join("launch.json").is_file(),
        "the relaunch never removes a generation an earlier VMM may still read"
    );
}

/// Subprocess half of the crash test: launch, and exit inside the first
/// lease or generation sync, once the VMM has started.
#[test]
#[ignore = "subprocess-only launcher crash between spawn and sync"]
fn crash_child() {
    let vm = std::env::var(CRASH_CHILD_ENV).expect("subprocess VM name");
    let home = PathBuf::from(std::env::var("MVM_HOME").expect("subprocess MVM_HOME"));
    let cfg = fresh_launch_config(&vm, "crash-source");
    let driver = MockDriver::default();
    let lease = evidence_root(&home).join(&vm);
    let _hook = durable_steps::hook({
        let driver = driver.clone();
        move |path| {
            if path.starts_with(&lease) {
                // A real process exit bypasses every destructor, as a kill does.
                std::process::exit(if booted_within(&driver, Duration::from_secs(2)) {
                    CRASHED_BESIDE_BOOT
                } else {
                    SYNCED_BEFORE_BOOT
                });
            }
            Ok(())
        }
    });
    let _activation = spawn_activation_guest(driver.clone(), &vm);
    let _ = runner(&driver).start_workload(&launch(&cfg));
    panic!("the child did not reach a lease or generation sync");
}
