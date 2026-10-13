use super::*;
use mvm_core::checkpoint::{CheckpointClass, ContentBlob};
use mvm_core::plan::{SecretSource, test_support::PlanFixture};
use mvm_core::util::test_env::TestEnv;

fn secret_binding(name: &str, address: &str) -> SecretBinding {
    SecretBinding {
        name: name.into(),
        source: SecretSource::Keystore {
            address: address.into(),
        },
        destinations: Vec::new(),
        approval_required: false,
    }
}

fn seed_checkpoint(store: &CheckpointStore, vm: &str) -> CheckpointId {
    let id = CheckpointId::new(format!("ck-{vm}"));
    let content = store.content_dir(&id);
    std::fs::create_dir_all(&content).unwrap();
    let blob = content.join("rootfs.ext4");
    std::fs::write(&blob, b"fake").unwrap();
    let meta = CheckpointMeta::builder(id.clone(), CheckpointClass::FsQuick, vm)
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: mvm_core::crypto::image_verify::sha256_file(&blob).unwrap(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
    store.write_meta(&meta).unwrap();
    id
}

fn request(id: CheckpointId) -> ForkRequest {
    ForkRequest {
        id,
        new_id: Some("child".into()),
        boot: false,
        hypervisor: "mock".into(),
        cpus: None,
        memory: None,
        declared_secrets: Vec::new(),
        allow_secret_drop: false,
        intent: ForkIntent::Ordinary,
        tenant: "local".into(),
    }
}

#[test]
fn dropped_parent_secrets_excludes_explicit_redeclarations() {
    assert_eq!(
        dropped_parent_secret_names(
            &["API_KEY".into(), "DB_KEY".into()],
            &[secret_binding("API_KEY", "child-api")]
        ),
        ["DB_KEY"]
    );
}

#[test]
fn secret_attenuation_requires_explicit_drop_permission() {
    let dropped = vec!["DB_KEY".into()];
    assert!(
        enforce_secret_attenuation(&dropped, false)
            .unwrap_err()
            .to_string()
            .contains("--allow-secret-drop")
    );
    assert!(enforce_secret_attenuation(&dropped, true).is_ok());
}

#[test]
fn fork_secret_audit_resolves_only_child_tenant_metadata() {
    use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
    let dir = tempfile::tempdir().unwrap();
    let store = FileBindingStore::with_dir(dir.path());
    store
        .put(
            "child-tenant",
            "api-address",
            &SecretBindingMeta {
                auth_type: mvm_contract::ir::AuthType::Bearer,
                allowed_hosts: vec!["api.example.com".into()],
                sigv4: None,
                inject: Default::default(),
                provider: Some("catalog-provider".into()),
                approve: Default::default(),
                oauth: None,
            },
        )
        .unwrap();
    let declared = [secret_binding("API_KEY", "api-address")];
    let audit = resolve_fork_secret_audit("child-tenant", &declared, &store).unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].name, "API_KEY");
    assert_eq!(audit[0].allowed_hosts, ["api.example.com"]);
    assert!(resolve_fork_secret_audit("other-tenant", &declared, &store).is_err());
}

#[test]
fn parent_agent_verb_override_inherits_parent_verbs() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut plan = PlanFixture::new()
        .tenant("local")
        .plan_id("parent-plan")
        .build();
    plan.agent_verbs = Some(vec![
        mvm_contract::plan::VerbId::new("ping").unwrap(),
        mvm_contract::plan::VerbId::new("run-entrypoint").unwrap(),
    ]);
    plan_persist::write_plan("parent-vm", &plan).unwrap();
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "parent-vm");
    assert_eq!(
        parent_agent_verb_override(&id, &store),
        ["ping", "run-entrypoint"]
    );
}

#[test]
fn parent_agent_verb_override_returns_empty_when_plan_missing() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "planless");
    assert!(parent_agent_verb_override(&id, &store).is_empty());
}

#[test]
fn declared_bindings_make_the_release_policy_plan_bound() {
    use crate::admission::secrets::release_for_bindings;
    assert_eq!(
        release_for_bindings(&[]),
        mvm_core::plan::SecretReleasePolicy::None
    );
    assert_eq!(
        release_for_bindings(&[secret_binding("TOKEN", "TOKEN")]),
        mvm_core::plan::SecretReleasePolicy::PlanBound
    );
}

#[test]
fn parent_secret_names_lists_the_parent_bindings_by_name() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut plan = PlanFixture::new()
        .tenant("local")
        .plan_id("parent-plan")
        .build();
    plan.secrets = vec![
        secret_binding("STRIPE_KEY", "kv/stripe"),
        SecretBinding {
            name: "DB_PASSWORD".into(),
            source: SecretSource::External {
                provider: "vault".into(),
                path: "secret/db".into(),
            },
            destinations: Vec::new(),
            approval_required: false,
        },
    ];
    plan_persist::write_plan("secretful-parent", &plan).unwrap();
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "secretful-parent");
    assert_eq!(
        parent_secret_names(&id, &store),
        ["STRIPE_KEY", "DB_PASSWORD"]
    );
}

#[test]
fn parent_secret_names_echoes_no_source_addresses() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let mut plan = PlanFixture::new().tenant("local").plan_id("p").build();
    plan.secrets = vec![SecretBinding {
        name: "TOKEN".into(),
        source: SecretSource::External {
            provider: "vault".into(),
            path: "secret/very/specific/path".into(),
        },
        destinations: Vec::new(),
        approval_required: false,
    }];
    plan_persist::write_plan("p-vm", &plan).unwrap();
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "p-vm");
    let names = parent_secret_names(&id, &store);
    assert_eq!(names, ["TOKEN"]);
    assert!(!names.join(", ").contains("vault"));
    assert!(!names.join(", ").contains("secret/"));
}

#[test]
fn parent_secret_names_is_empty_when_the_parent_plan_is_unreadable() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "planless");
    assert!(parent_secret_names(&id, &store).is_empty());
}

#[test]
fn resource_shape_no_plan_no_flags_uses_defaults() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "origin-vm");
    let (cpus, memory) = parent_plan_resources(&id, &store);
    assert_eq!((cpus, memory), (None, None));
    let defaults = mvm_core::user_config::load(None);
    assert_eq!(cpus.unwrap_or(defaults.default_cpus), 2);
    assert_eq!(memory.unwrap_or(defaults.default_memory_mib), 512);
}

#[test]
fn resource_shape_flags_override_plan() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let store = CheckpointStore::open();
    let id = seed_checkpoint(&store, "parent");
    let mut plan = PlanFixture::new().tenant("local").build();
    plan.resources.cpus = 2;
    plan.resources.mem_mib = 512;
    plan_persist::write_plan("parent", &plan).unwrap();
    let mut request = request(id);
    assert_eq!(resolve_fork_resources(&request, &store).unwrap(), (2, 512));
    request.cpus = Some(8);
    request.memory = Some("1024".into());
    assert_eq!(resolve_fork_resources(&request, &store).unwrap(), (8, 1024));
    request.memory = Some("not-memory".into());
    assert!(resolve_fork_resources(&request, &store).is_err());
}

#[test]
fn boot_arm_start_config_uses_instance_path() {
    let dir = tempfile::tempdir().unwrap();
    let instance = dir.path().join("rootfs.ext4");
    std::fs::write(&instance, b"forked").unwrap();
    let config = fork_start_config("childvm", &instance, 2, 512);
    assert_eq!(config.rootfs_path, instance.to_str().unwrap());
    let out = mvm_runtime::base::cow::prepare_instance_rootfs_inner(&instance, &config.rootfs_path)
        .unwrap();
    assert_eq!(out, instance);
    assert_eq!(std::fs::read(&instance).unwrap(), b"forked");
}

#[test]
fn bind_uses_parent_checkpoint_vm_name() {
    let dir = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(dir.path());
    let id = seed_checkpoint(&store, "parentvm");
    let recovered = store.read_meta(&id).unwrap();
    assert_eq!(recovered.vm_name, "parentvm");
    assert_ne!(recovered.vm_name, id.as_str());
}

fn seed_grant(vm: &str) -> mvm_core::protocol::vm_backend::VerbGrantEnvelope {
    let nonce = mvm_core::plan::Nonce::from_bytes([7; 16]);
    let envelope = mvm_core::protocol::vm_backend::VerbGrantEnvelope {
        pubkey_hex: "aa".repeat(32),
        plan_nonce_hex: nonce.as_hex().into(),
        predecessor_session_id: None,
        predecessor_plan_nonce_hex: None,
        grant: mvm_core::plan::VerbGrant {
            session_id: "parent-session".into(),
            plan_nonce: nonce,
            not_after: chrono::Utc::now() + chrono::Duration::hours(1),
            verbs: Vec::new(),
            drive: None,
            tool_mediation: None,
            application_terminal: None,
            sig: vec![0; 64],
        },
    };
    let dir = mvm_core::config::vm_state_dir(vm);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("verb-grant.json"),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    envelope
}

#[test]
fn read_grant_envelope_for_returns_none_when_absent() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    assert!(read_grant_envelope_for("absent").is_none());
}

#[test]
fn read_grant_envelope_for_returns_some_when_sidecar_present() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let expected = seed_grant("child");
    let got = read_grant_envelope_for("child").unwrap();
    assert_eq!(got.pubkey_hex, expected.pubkey_hex);
    assert_eq!(got.plan_nonce_hex, expected.plan_nonce_hex);
}

#[test]
fn grant_predecessor_from_vm_name_reads_session_and_nonce() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let expected = seed_grant("parent");
    let (session, nonce) = grant_predecessor_from_vm_name("parent").unwrap();
    assert_eq!(session, "parent-session");
    assert_eq!(nonce, expected.grant.plan_nonce);
}

#[test]
fn fork_verity_preserves_sidecar_identity() {
    let dir = tempfile::tempdir().unwrap();
    let rootfs = dir.path().join("rootfs.ext4");
    std::fs::write(dir.path().join("rootfs.verity"), b"tree").unwrap();
    std::fs::write(dir.path().join("rootfs.roothash"), " abcd\n").unwrap();
    let mut start = fork_start_config("child", &rootfs, 2, 512);
    populate_fork_rootfs_verity(&mut start, &rootfs).unwrap();
    assert_eq!(start.roothash.as_deref(), Some("abcd"));
    assert_eq!(
        start.verity_path.as_deref(),
        dir.path().join("rootfs.verity").to_str()
    );
}

#[test]
fn fork_requests_and_reports_roundtrip_without_runtime_types() {
    let request = request(CheckpointId::new("base"));
    let mut json = serde_json::to_value(&request).unwrap();
    let decoded: ForkRequest = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(decoded.id, request.id);
    assert_eq!(decoded.intent, ForkIntent::Ordinary);
    assert_eq!(json["intent"], "ordinary");
    json["runtime_override"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ForkRequest>(json).is_err());
    let report = ForkReport {
        schema_version: 1,
        action: "fork".into(),
        parent_id: request.id,
        child_vm_name: "child".into(),
        booted: false,
        checkpoint: CheckpointMeta::builder(
            CheckpointId::new("fork-child"),
            CheckpointClass::FsQuick,
            "child",
        )
        .build(),
    };
    let json = serde_json::to_value(&report).unwrap();
    let decoded: ForkReport = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), json);
}

#[test]
fn fork_refuses_unsafe_or_source_identity_before_creating_state() {
    let home = tempfile::tempdir().unwrap();
    let service = crate::checkpoint::Checkpoints::at(home.path());
    let id = seed_checkpoint(&service.store, "parent");
    for name in ["../escape", "parent"] {
        let mut request = request(id.clone());
        request.new_id = Some(name.into());
        assert!(
            service
                .fork(&request, &mut crate::entrypoint::CapturedOutput::default())
                .is_err()
        );
    }
}

#[test]
fn replay_refuses_fs_quick_before_admission() {
    let root = tempfile::tempdir().unwrap();
    let service = crate::checkpoint::Checkpoints::at(root.path());
    let id = seed_checkpoint(&service.store, "parent");
    let mut request = request(id);
    request.intent = ForkIntent::Replay;
    let error = service
        .fork(&request, &mut crate::entrypoint::CapturedOutput::default())
        .unwrap_err();
    assert!(error.to_string().contains("requires a vm_full"));
}

#[test]
fn fork_refuses_existing_child_without_overwriting_its_plan() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().unwrap();
    env.isolate_mvm_home(home.path());
    let service = crate::checkpoint::Checkpoints::open();
    let id = seed_checkpoint(&service.store, "parent");
    let child = mvm_core::config::vm_state_dir("child");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(child.join("plan.json"), b"existing plan").unwrap();
    let error = service
        .fork(
            &request(id),
            &mut crate::entrypoint::CapturedOutput::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("already has VM state"));
    assert_eq!(
        std::fs::read(child.join("plan.json")).unwrap(),
        b"existing plan"
    );
}
