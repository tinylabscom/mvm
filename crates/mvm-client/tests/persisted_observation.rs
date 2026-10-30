//! Public facade reads observe definitions without booting or repairing state.
#![cfg(feature = "test-support")]

use mvm_client::{
    LaunchRequest, LifecycleMode, LocalBackend, MachineFilter, MachineId, MachineSpec,
    MachineState, MachineStatus, MvmClient, MvmError, TelemetryStatus,
};
use mvm_core::util::test_env::TestEnv;

fn definition(name: &str) -> MachineSpec {
    MachineSpec {
        name: name.into(),
        image: "docker.io/library/alpine:3.20".parse().unwrap(),
        cpus: 3,
        memory_mib: 768,
        env: vec![],
        grants: None,
        assurance_campaign: None,
    }
}

fn assert_definition(actual: &MachineState, created: &MachineState) {
    assert_eq!(actual, created);
    assert_eq!(actual.status, MachineStatus::Stopped);
    assert!(actual.backend.is_empty());
}

#[tokio::test]
async fn public_create_without_boot_is_listed() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client.create_machine(definition("saved")).await.unwrap();

    let listed = client.list_machines(MachineFilter::all()).await.unwrap();
    assert_eq!(listed.len(), 1, "a saved definition is a stopped machine");
    assert_definition(&listed[0], &created);
    assert!(client.list_stop_targets().is_empty());
    assert!(!mvm_runtime::vm::name_registry::registry_path().exists());
}

#[tokio::test]
async fn public_create_without_boot_is_inspectable() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client.create_machine(definition("saved")).await.unwrap();

    let inspected = client.inspect_machine(&created.id).await.unwrap();
    assert_definition(&inspected, &created);
    assert!(client.list_stop_targets().is_empty());
    assert!(!mvm_runtime::vm::name_registry::registry_path().exists());
}

fn snapshot(root: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        files: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let key = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                files.insert(key, vec![]);
                visit(root, &path, files);
            } else {
                files.insert(key, std::fs::read(path).unwrap());
            }
        }
    }
    let mut files = std::collections::BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[tokio::test]
async fn targeted_inspect_ignores_unrelated_corruption_and_rejects_invalid_ids() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client.create_machine(definition("saved")).await.unwrap();
    let unrelated = mvm_core::config::machine_spec_path("unrelated");
    std::fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
    std::fs::write(unrelated, b"{").unwrap();
    let before = snapshot(home.path());

    assert_definition(
        &client.inspect_machine(&created.id).await.unwrap(),
        &created,
    );
    for name in ["missing", "../saved", "/saved", ""] {
        assert!(matches!(
            client.inspect_machine(&MachineId(name.into())).await,
            Err(MvmError::NotFound { .. })
        ));
    }
    assert_eq!(snapshot(home.path()), before);
}

#[tokio::test]
async fn targeted_inspect_refuses_a_different_embedded_identity() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client.create_machine(definition("saved")).await.unwrap();
    let mut spec = mvm_runtime::machine::persist::load_machine_spec(&created.name).unwrap();
    let path = mvm_core::config::machine_spec_path(&created.name);
    for embedded in ["other", "../invalid", ""] {
        spec.name = embedded.into();
        std::fs::write(&path, serde_json::to_vec(&spec).unwrap()).unwrap();
        let before = snapshot(home.path());
        let error = client.inspect_machine(&created.id).await.unwrap_err();
        assert!(matches!(error, MvmError::Backend { .. }), "{error}");
        assert_eq!(snapshot(home.path()), before);
    }
}

#[tokio::test]
async fn public_request_create_reads_are_filtered_and_side_effect_free() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let request = LaunchRequest::builder(
        LifecycleMode::Persistent,
        "docker.io/library/alpine:3.20".parse().unwrap(),
    )
    .name("request-saved")
    .cpus(2)
    .memory_mib(512)
    .build()
    .unwrap();
    let created = client.create_from_request(&request).unwrap();
    let before = snapshot(home.path());

    let listed = client
        .list_machines(MachineFilter {
            name: Some(created.name.clone()),
            status: Some(MachineStatus::Stopped),
        })
        .await
        .unwrap();
    assert_eq!(listed, vec![created.clone()]);
    assert_definition(
        &client.inspect_machine(&created.id).await.unwrap(),
        &created,
    );
    for filter in [
        MachineFilter {
            name: Some("other".into()),
            status: None,
        },
        MachineFilter {
            name: None,
            status: Some(MachineStatus::Running),
        },
    ] {
        assert!(client.list_machines(filter).await.unwrap().is_empty());
    }
    let inventory = mvm_client::inventory::list_local_inventory(&client)
        .await
        .unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].id, created.id);
    assert_eq!(inventory[0].cpus, created.cpus);
    assert_eq!(inventory[0].memory_mib, created.memory_mib);
    assert_eq!(inventory[0].status, MachineStatus::Stopped);
    assert_eq!(
        client.telemetry_status(&created.id).await.unwrap(),
        TelemetryStatus::NotProvisioned
    );
    let records = client
        .telemetry_records(&created.id, Default::default())
        .await
        .unwrap();
    assert!(records.records.is_empty());
    assert!(records.exhausted);
    let unknown = MachineId("unknown".into());
    assert!(matches!(
        client.inspect_machine(&unknown).await,
        Err(MvmError::NotFound { .. })
    ));
    assert!(matches!(
        client.telemetry_status(&unknown).await,
        Err(MvmError::NotFound { .. })
    ));
    assert!(matches!(
        client.telemetry_records(&unknown, Default::default()).await,
        Err(MvmError::NotFound { .. })
    ));
    assert!(
        client
            .exec_machine(&created.id, vec!["true".into()])
            .await
            .is_err()
    );
    assert!(client.list_stop_targets().is_empty());
    assert_eq!(
        snapshot(home.path()),
        before,
        "observations must not repair state"
    );
}

#[tokio::test]
async fn corrupt_persisted_metadata_is_not_missing_or_empty_success() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client.create_machine(definition("corrupt")).await.unwrap();
    let path = mvm_core::config::machine_spec_path(&created.name);
    std::fs::write(&path, br#"{"cpus":"private-spec-content"}"#).unwrap();
    let before = snapshot(home.path());

    let list_error = client
        .list_machines(MachineFilter::all())
        .await
        .unwrap_err();
    let inspect_error = client.inspect_machine(&created.id).await.unwrap_err();
    for error in [list_error, inspect_error] {
        assert!(matches!(error, MvmError::Backend { .. }), "{error}");
        assert!(
            !error.to_string().contains("private-spec-content"),
            "{error}"
        );
    }
    assert!(client.list_stop_targets().is_empty());
    assert_eq!(snapshot(home.path()), before);
}

#[tokio::test]
async fn facade_profile_backfill_is_not_an_inventory_source() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client
        .create_machine(definition("no-source"))
        .await
        .unwrap();
    let mut spec = mvm_runtime::machine::persist::load_machine_spec(&created.name).unwrap();
    spec.image = None;
    spec.manifest = None;
    mvm_runtime::machine::persist::overwrite_machine_spec(&spec).unwrap();
    let expected = mvm_client::inventory::join_inventory(vec![spec], vec![], |_, _| {
        mvm_client::WorkloadPosture::Prod
    });
    let actual = mvm_client::inventory::list_local_inventory(&client)
        .await
        .unwrap();
    assert_eq!(actual[0].source, expected[0].source);
    let mut registry = mvm_runtime::vm::name_registry::VmNameRegistry::default();
    registry
        .register(mvm_runtime::vm::name_registry::RegisterParams::minimal(
            &created.name,
            "/unused",
            "default",
        ))
        .unwrap();
    registry
        .save(&mvm_runtime::vm::name_registry::registry_path())
        .unwrap();
    let before = snapshot(home.path());
    let actual = mvm_client::inventory::list_local_inventory(&client)
        .await
        .unwrap();
    assert_eq!(actual[0].source, expected[0].source);
    assert_eq!(snapshot(home.path()), before);
}

#[tokio::test]
async fn persisted_registry_metadata_survives_resource_backfill() {
    use mvm_runtime::vm::name_registry::{RegisterParams, VmNameRegistry, registry_path};

    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client
        .create_machine(definition("registered"))
        .await
        .unwrap();
    let mut registry = VmNameRegistry::default();
    registry
        .register(RegisterParams::minimal(&created.name, "/unused", "default"))
        .unwrap();
    let reg = registry.vms.get_mut(&created.name).unwrap();
    reg.tags.insert("purpose".into(), "saved".into());
    reg.expires_at = Some("2030-01-02T03:04:05Z".into());
    reg.auto_resume = false;
    reg.guest_ip = Some("127.0.0.1".into());
    reg.readiness = Some(mvm_core::domain::instance::InstanceReadiness::AgentReady);
    reg.last_readiness_change_at = Some("2026-01-02T03:04:05Z".into());
    registry.save(&registry_path()).unwrap();
    let before = snapshot(home.path());

    let listed = client.list_machines(MachineFilter::all()).await.unwrap();
    let inspected = client.inspect_machine(&created.id).await.unwrap();
    assert_eq!(listed, vec![inspected.clone()]);
    assert_eq!(inspected.cpus, created.cpus);
    assert_eq!(inspected.memory_mib, created.memory_mib);
    assert_eq!(inspected.profile, created.profile);
    let reg = registry.lookup(&created.name).unwrap();
    assert_eq!(inspected.tags, reg.tags);
    assert_eq!(inspected.expires_at, reg.expires_at);
    assert_eq!(inspected.auto_resume, reg.auto_resume);
    assert_eq!(inspected.guest_ip, reg.guest_ip);
    assert_eq!(inspected.readiness, reg.readiness);
    assert_eq!(
        inspected.last_readiness_change_at,
        reg.last_readiness_change_at
    );
    assert_eq!(inspected.status, MachineStatus::Stopped);
    assert!(client.list_stop_targets().is_empty());
    assert_eq!(snapshot(home.path()), before);
}

#[tokio::test]
async fn malformed_memory_keeps_the_inventory_zero_fallback() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let created = client.create_machine(definition("memory")).await.unwrap();
    let mut spec = mvm_runtime::machine::persist::load_machine_spec(&created.name).unwrap();
    spec.memory = "not-a-size".into();
    mvm_runtime::machine::persist::overwrite_machine_spec(&spec).unwrap();
    let before = snapshot(home.path());

    let listed = client.list_machines(MachineFilter::all()).await.unwrap();
    let inspected = client.inspect_machine(&created.id).await.unwrap();
    assert_eq!(listed, vec![inspected.clone()]);
    assert_eq!(inspected.cpus, 3);
    assert_eq!(inspected.memory_mib, 0);
    assert_eq!(snapshot(home.path()), before);
}

#[tokio::test]
async fn unreadable_spec_is_a_backend_error_without_repair() {
    let home = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let client = LocalBackend::with_hypervisor("mock");
    let id = MachineId("unreadable".into());
    std::fs::create_dir_all(mvm_core::config::machine_spec_path(&id.0)).unwrap();
    let before = snapshot(home.path());

    assert!(matches!(
        client.inspect_machine(&id).await,
        Err(MvmError::Backend { .. })
    ));
    assert!(matches!(
        client.list_machines(MachineFilter::all()).await,
        Err(MvmError::Backend { .. })
    ));
    assert!(client.list_stop_targets().is_empty());
    assert_eq!(snapshot(home.path()), before);
}
