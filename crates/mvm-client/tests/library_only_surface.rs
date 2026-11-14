//! The supported client operations work with no `mvmctl` and no other tool on
//! `PATH`, and the operations that need a helper refuse with a typed error
//! instead of running one.
//!
//! The process declares itself a library embedder, `PATH` names an empty
//! directory, and the helper-location overrides name a file called `mvmctl`.
//! Anything that tried to run a program would fail here, so the success
//! assertions are the evidence that the operation never needed one. This
//! proves the Rust client facade over the mock backend; it says nothing about
//! the language SDKs or any other embedder.
#![cfg(feature = "test-support")]

use mvm_client::{
    LocalBackend, MachineFilter, MachineId, MachineSpec, MachineStatus, MvmClient, MvmError,
};
use mvm_core::util::test_env::TestEnv;
use mvm_vmm::host::aux_bin::{
    AuxBin, CLI_BIN, CliSpawn, CliSpawnRefused, declare_library_embedder, resolve,
};

/// An embedder with nothing runnable anywhere: an empty `PATH`, and a
/// poisoned override that would resolve a per-VM helper to `mvmctl`.
fn library_process(env: &mut TestEnv, dir: &std::path::Path) {
    declare_library_embedder();
    let empty = dir.join("empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    env.set("PATH", &empty);
    let poisoned = dir.join("mvmctl");
    std::fs::write(&poisoned, b"#!/bin/sh\nexit 97\n").unwrap();
    env.set("MVM_QEMU_BRIDGE_PATH", &poisoned);
}

fn definition(name: &str) -> MachineSpec {
    MachineSpec {
        name: name.into(),
        image: "docker.io/library/alpine:3.20".parse().unwrap(),
        cpus: 1,
        memory_mib: 256,
        env: vec![],
        grants: None,
        assurance_campaign: None,
    }
}

#[tokio::test]
async fn machine_definitions_are_managed_with_no_cli_and_an_empty_path() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    library_process(&mut env, home.path());
    let client = LocalBackend::with_hypervisor("mock");

    let created = client.create_machine(definition("lib-only")).await.unwrap();
    let listed = client.list_machines(MachineFilter::all()).await.unwrap();
    assert_eq!(listed, vec![created.clone()]);
    let inspected = client.inspect_machine(&created.id).await.unwrap();
    assert_eq!(inspected.status, MachineStatus::Stopped);
    client.remove_machine(&created.id).await.unwrap();
    assert!(
        client
            .list_machines(MachineFilter::all())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn an_unknown_machine_is_a_typed_refusal_not_a_spawn() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    library_process(&mut env, home.path());
    let client = LocalBackend::with_hypervisor("mock");

    let id = MachineId("does-not-exist".into());
    let err = client.inspect_machine(&id).await.unwrap_err();
    assert!(matches!(err, MvmError::NotFound { .. }), "{err:?}");
}

#[test]
fn a_helper_override_that_is_mvmctl_is_refused_not_resolved() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    library_process(&mut env, home.path());

    let spec = AuxBin::new(CLI_BIN, "MVM_QEMU_BRIDGE_PATH", "mvmctl");
    let err = resolve(&spec).unwrap_err();
    let refused = err
        .downcast_ref::<CliSpawnRefused>()
        .expect("a typed CliSpawnRefused, not a path");
    assert_eq!(
        refused.spawn(),
        &CliSpawn::HostHelper {
            env_var: "MVM_QEMU_BRIDGE_PATH".into()
        }
    );
}

#[test]
fn preparing_the_guest_runtime_cold_never_runs_the_toolchain() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    library_process(&mut env, home.path());

    let cache = home.path().join("oci-cache");
    let err = mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime(&cache)
        .expect_err("a cold cache cannot be prepared without cargo, rustup, zig or curl");
    let text = format!("{err:#}");
    // Either the typed refusal, or the pointer to `mvmctl bootstrap` when no
    // source checkout is in reach: never a spawn failure.
    assert!(
        err.chain().any(|e| e.is::<CliSpawnRefused>()) || text.contains("mvmctl bootstrap"),
        "{text}"
    );
    assert!(!text.contains("No such file or directory"), "{text}");
}

#[test]
fn exporting_an_unknown_template_refuses_before_creating_a_signer_or_bundle() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    library_process(&mut env, home.path());

    let out = home.path().join("missing.mvmpkg");
    let err = mvm_client::bundle::export_template(
        "missing-template",
        mvm_client::bundle::TemplateExport::new(out.clone()),
    )
    .expect_err("no template is available to export");
    assert!(format!("{err:#}").contains("missing-template"), "{err:#}");
    assert!(!out.exists(), "an unresolved template cannot be published");
    assert!(
        !home.path().join("keys").exists(),
        "refusal must not mint a host signing identity"
    );
}

#[test]
fn the_yocto_pack_builder_refuses_a_foreign_target_without_invoking_the_cli() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    library_process(&mut env, home.path());

    let mut spec: mvm_client::yocto_pack::PackSpec =
        serde_json::from_str(include_str!("../../../examples/yocto/pack.json")).unwrap();
    spec.target = if cfg!(target_arch = "aarch64") {
        mvm_client::yocto_pack::PackTarget::X86_64Linux
    } else {
        mvm_client::yocto_pack::PackTarget::Aarch64Linux
    };
    let out = home.path().join("refused.mvmpkg");
    let err = mvm_client::yocto_pack::build_yocto_pack(mvm_client::yocto_pack::YoctoPackRequest {
        spec,
        spec_dir: home.path().to_path_buf(),
        out: out.clone(),
        label: None,
        health_timeout_secs: 120,
        hypervisor: None,
    })
    .expect_err("a foreign target is refused");
    assert!(format!("{err:#}").contains("targets"), "{err:#}");
    assert!(!out.exists());
}
