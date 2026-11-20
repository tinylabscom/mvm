//! The public client operations, driven with the `mvmctl` CLI unavailable,
//! construct no host process outside an explicit allowlist.
//!
//! The process declares itself a library embedder, `PATH` names an empty
//! directory and every helper-location override is unset. Every `MvmClient`
//! operation runs against `LocalBackend` over the mock hypervisor, on a
//! machine that exists and on one that does not, and the recorder at
//! `mvm_core::env_hygiene::helper_command_with` must have seen nothing.
//!
//! Limits, stated so the result is not over-read:
//!
//! - The recorder sees construction, not execution, and not a process created
//!   any other way. The raw guest and builder sites that
//!   `check-helper-env-hygiene` classifies are outside it.
//! - The mock hypervisor never reaches the VMM launch chain a real backend
//!   runs, so what a real backend spawns is not covered here.
//! - The recorder is per thread. Operations that hand work to another thread
//!   build their processes there, unseen.
//! - The operation list is written out by hand: the trait offers no registry
//!   to derive it from. The host ABI's table, which does have one, is in
//!   `mvm-hostlib`.
#![cfg(feature = "test-support")]

use mvm_client::{
    LocalBackend, LogOpts, MachineFilter, MachineId, MachineSpec, MvmClient, MvmError, PauseOpts,
    ReconfigureRequest, ResumeOpts, TelemetryReadRequest,
};
use mvm_core::env_hygiene::helper_command;
use mvm_core::env_hygiene::spawn_recorder::SpawnScope;
use mvm_core::util::test_env::TestEnv;
use mvm_vmm::host::aux_bin::declare_library_embedder;

/// Programs the client may construct with no CLI: none.
const ALLOWED: &[&str] = &[];

fn offline_process(env: &mut TestEnv, home: &std::path::Path) {
    declare_library_embedder();
    env.isolate_mvm_home(home);
    let empty = home.join("empty-path");
    std::fs::create_dir_all(&empty).expect("an empty directory for PATH");
    env.set("PATH", &empty);
    for (name, _) in std::env::vars_os().filter(|(name, _)| {
        let name = name.to_string_lossy();
        name.starts_with("MVM_") && name.ends_with("_PATH")
    }) {
        env.remove(name);
    }
}

fn definition(name: &str) -> MachineSpec {
    MachineSpec {
        name: name.into(),
        image: "docker.io/library/alpine:3.20".parse().expect("an image"),
        cpus: 1,
        memory_mib: 256,
        env: vec![],
        grants: None,
        assurance_campaign: None,
    }
}

/// Every operation of the client trait against `id`, results discarded: only
/// what was constructed matters to the callers.
async fn exercise(client: &LocalBackend, id: &MachineId) {
    let _ = client.inspect_machine(id).await;
    let _ = client.start_machine(id).await;
    let _ = client.machine_logs(id, LogOpts::default()).await;
    let _ = client.exec_machine(id, vec!["true".into()]).await;
    let _ = client.pause_machine(id, PauseOpts::default()).await;
    let _ = client.resume_machine(id, ResumeOpts::default()).await;
    let _ = client
        .reconfigure_machine(id, ReconfigureRequest::default())
        .await;
    let _ = client.set_ttl(id, None).await;
    let _ = client.telemetry_status(id).await;
    let _ = client
        .telemetry_records(id, TelemetryReadRequest::default())
        .await;
    let _ = client.stop_machine(id).await;
    let _ = client.remove_machine(id).await;
}

#[tokio::test]
async fn the_client_surface_builds_no_process_for_a_machine_that_exists() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let scope = SpawnScope::begin();

    let created = client
        .create_machine(definition("spawn-free"))
        .await
        .expect("a definition is created");
    client
        .list_machines(MachineFilter::all())
        .await
        .expect("the machines are listed");
    client
        .backend_capabilities()
        .await
        .expect("the capability report");
    exercise(&client, &created.id).await;

    scope.assert_only(ALLOWED);
}

#[tokio::test]
async fn an_unknown_machine_is_a_typed_error_and_builds_no_process() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let scope = SpawnScope::begin();

    let id = MachineId("ghost".into());
    let err = client
        .inspect_machine(&id)
        .await
        .expect_err("no such machine");
    assert!(matches!(err, MvmError::NotFound { .. }), "{err:?}");
    exercise(&client, &id).await;

    scope.assert_only(ALLOWED);
}

#[tokio::test]
async fn a_corrupt_registry_is_a_typed_error_and_builds_no_process() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let path = mvm_runtime::vm::name_registry::registry_path();
    std::fs::create_dir_all(path.parent().expect("a registry directory")).expect("its directory");
    std::fs::write(&path, r#"{"vms":"corrupt"}"#).expect("a corrupt registry");
    let scope = SpawnScope::begin();

    let err = client
        .list_machines(MachineFilter::all())
        .await
        .expect_err("a corrupt registry is not an empty inventory");
    assert!(matches!(err, MvmError::Backend { .. }), "{err:?}");
    exercise(&client, &MachineId("ghost".into())).await;

    scope.assert_only(ALLOWED);
}

/// Negative control: the assertion every test above makes must fail when a
/// shell is built through the sanctioned constructor during a measured call.
#[tokio::test]
#[should_panic(expected = "\"sh\"")]
async fn a_shell_built_during_a_measured_call_fails_the_assertion() {
    let home = tempfile::tempdir().expect("a home");
    let mut env = TestEnv::new();
    offline_process(&mut env, home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let scope = SpawnScope::begin();

    let _ = client.list_machines(MachineFilter::all()).await;
    let _ = helper_command("sh");

    scope.assert_only(ALLOWED);
}
