use super::*;
use mvm_core::plan::{SecretSource, test_support::PlanFixture};
use mvm_core::util::test_env::TestEnv;
use std::collections::BTreeMap;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Fixture {
    _env: TestEnv,
    home: tempfile::TempDir,
    service: FsQuickForks,
    parent: CheckpointMeta,
    plan: ExecutionPlan,
}

fn write_private(path: &Path, bytes: &[u8]) {
    mvm_core::config::create_private_dir(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Fixture {
    fn new(secrets: Vec<SecretBinding>) -> Self {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        env.set(
            mvm_runtime::vm::snapshot_key::SNAPSHOT_TENANT_KEY_ENV,
            "19".repeat(32),
        );
        let source = home.path().join("rootfs.ext4");
        write_private(&source, b"fake-ext4-bytes");
        let store = CheckpointStore::open();
        let parent = mvm_runtime::checkpoint::capture_fs_quick(
            &store,
            mvm_runtime::checkpoint::CaptureFsQuickParams {
                id: CheckpointId::new("parent"),
                vm_name: "parentvm".into(),
                rootfs: source,
                supervisor_config_digest: "config".into(),
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
                key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
            },
        )
        .unwrap();
        let mut plan = PlanFixture::new()
            .tenant("local")
            .workload("parentvm")
            .secrets(secrets)
            .build();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        write_private(
            &home.path().join("vms/parentvm/plan.json"),
            &serde_json::to_vec(&plan).unwrap(),
        );
        let key = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
        let emitter = AuditEmitter::new(key.signing).unwrap();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &parent).unwrap();
        Self {
            _env: env,
            home,
            service: FsQuickForks::open(),
            parent,
            plan,
        }
    }

    fn request<'a>(
        &'a self,
        declared: &'a [SecretBinding],
        allow_secret_drop: bool,
    ) -> ForkRequest<'a> {
        ForkRequest {
            checkpoint: &self.parent.id,
            child_name: Some("childvm".into()),
            declared_secrets: declared,
            allow_secret_drop,
        }
    }

    fn plan_path(&self) -> PathBuf {
        self.home.path().join("vms/parentvm/plan.json")
    }

    fn persist_plan(&self, plan: &ExecutionPlan) {
        write_private(&self.plan_path(), &serde_json::to_vec(plan).unwrap());
    }

    fn emit_creation(&self, plan: &ExecutionPlan, parent: &CheckpointMeta) {
        let key = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
        let emitter = AuditEmitter::new(key.signing).unwrap();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, plan, parent).unwrap();
    }

    fn assert_refused_unchanged(&self, expected: &str) {
        let before = snapshot(self.home.path());
        let error = preparation_error(self.service.prepare_unbooted(self.request(&[], true)));
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(error.phase(), ForkPhase::Preparation);
        assert!(error.artifact().is_none());
        assert_eq!(before, snapshot(self.home.path()));
    }

    fn invoke(&self, allow_drop: bool) -> Result<MaterializedFsQuickFork> {
        self.service.classify(&self.parent.id)?;
        Ok(self
            .service
            .prepare_unbooted(self.request(&[], allow_drop))?
            .materialize_and_publish()?)
    }

    fn assert_request_refused_unchanged(&self, allow_drop: bool, expected: &str) {
        let before = snapshot(self.home.path());
        let error = match self.invoke(allow_drop) {
            Ok(_) => panic!("expected fork refusal"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(
            before,
            snapshot(self.home.path()),
            "refusal must not mutate state"
        );
    }
}

fn preparation_error(result: std::result::Result<PreparedFsQuickFork<'_>, ForkError>) -> ForkError {
    match result {
        Ok(_) => panic!("preparation unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, (u32, Vec<u8>)>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let bytes = if metadata.file_type().is_symlink() {
            std::fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else if metadata.is_file() {
            std::fs::read(path).unwrap()
        } else {
            Vec::new()
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            (metadata.permissions().mode(), bytes),
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

fn binding() -> SecretBinding {
    SecretBinding {
        name: "TOKEN".into(),
        source: SecretSource::Keystore {
            address: "token".into(),
        },
        destinations: Vec::new(),
        approval_required: true,
    }
}

#[test]
fn consuming_service_materializes_and_publishes_an_authenticated_empty_parent() {
    let fixture = Fixture::new(Vec::new());
    let artifact = fixture
        .service
        .prepare_unbooted(fixture.request(&[], false))
        .unwrap()
        .materialize_and_publish()
        .unwrap();
    assert_eq!(artifact.child_name(), "childvm");
    assert_eq!(artifact.parent_plan(), &fixture.plan);
    assert_eq!(artifact.parent_meta(), &fixture.parent);
    assert_eq!(
        artifact.checkpoint().parent.as_ref(),
        Some(&fixture.parent.meta_digest)
    );
    assert!(artifact.destination().join("rootfs.ext4").is_file());
    assert!(artifact.bindings().is_empty());
    assert!(artifact.child_tenant().is_none());
    let text = std::fs::read_to_string(fixture.home.path().join("audit/local.jsonl")).unwrap();
    assert!(text.contains("checkpoint.forked"));
}

#[test]
fn known_parent_secrets_require_explicit_drop_before_copy() {
    let fixture = Fixture::new(vec![binding()]);
    let before = snapshot(fixture.home.path());
    let error = preparation_error(
        fixture
            .service
            .prepare_unbooted(fixture.request(&[], false)),
    );
    assert!(error.to_string().contains("--allow-secret-drop"));
    assert_eq!(before, snapshot(fixture.home.path()));
    let artifact = fixture
        .service
        .prepare_unbooted(fixture.request(&[], true))
        .unwrap()
        .materialize_and_publish()
        .unwrap();
    assert!(!artifact.destination().join("plan.json").exists());
}

#[test]
fn missing_candidate_and_replaced_candidate_are_not_original_policy() {
    let fixture = Fixture::new(Vec::new());
    let bytes = std::fs::read(fixture.plan_path()).unwrap();
    std::fs::remove_file(fixture.plan_path()).unwrap();
    fixture.assert_refused_unchanged("required existing fork authority file");
    write_private(&fixture.plan_path(), &bytes);
    let mut replacement = fixture.plan.clone();
    replacement.resources.cpus += 1;
    replacement.plan_id = mvm_core::plan::compute_plan_id(&replacement);
    write_private(
        &fixture.plan_path(),
        &serde_json::to_vec(&replacement).unwrap(),
    );
    fixture.assert_refused_unchanged("does not match authenticated original");
}

#[test]
fn candidate_parse_diagnostics_do_not_echo_sensitive_bytes() {
    let fixture = Fixture::new(Vec::new());
    write_private(
        &fixture.plan_path(),
        br#"{"secret-marker-no-echo":"invalid"}"#,
    );
    let before = snapshot(fixture.home.path());
    let error = preparation_error(fixture.service.prepare_unbooted(fixture.request(&[], true)));
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#}"),
    ] {
        assert!(!rendered.contains("secret-marker-no-echo"), "{rendered}");
    }
    assert_eq!(before, snapshot(fixture.home.path()));
}

#[test]
fn preexisting_vm_directory_and_alias_are_not_overwritten() {
    let fixture = Fixture::new(Vec::new());
    let destination = fixture.home.path().join("vms/childvm");
    std::fs::create_dir(&destination).unwrap();
    fixture.assert_refused_unchanged("destination is occupied");
    std::fs::remove_dir(&destination).unwrap();
    symlink(fixture.home.path().join("missing"), &destination).unwrap();
    fixture.assert_refused_unchanged("destination is occupied");
}

#[test]
fn all_declared_sources_validate_before_missing_history_or_metadata_service() {
    let fixture = Fixture::new(Vec::new());
    std::fs::remove_file(fixture.plan_path()).unwrap();
    let unsupported = SecretBinding {
        source: SecretSource::External {
            provider: "missing".into(),
            path: "opaque".into(),
        },
        ..binding()
    };
    let before = snapshot(fixture.home.path());
    for declared in [
        vec![unsupported.clone(), binding()],
        vec![binding(), unsupported.clone()],
    ] {
        let error = preparation_error(
            fixture
                .service
                .prepare_boot(fixture.request(&declared, true))
                .and_then(|stage| stage.for_tenant("local".into())),
        );
        assert!(
            error.to_string().contains("only keystore references"),
            "{error}"
        );
    }
    assert_eq!(before, snapshot(fixture.home.path()));
}

#[test]
fn service_unbooted_fork_requires_explicit_drop_of_known_parent_bindings() {
    let fixture = Fixture::new(vec![binding()]);
    fixture.assert_request_refused_unchanged(false, "would drop parent secret bindings");
    assert!(!fixture.home.path().join("keyholder").exists());
}

#[test]
fn service_unbooted_fork_materializes_and_audits_authenticated_empty_parent() {
    let fixture = Fixture::new(Vec::new());
    fixture.invoke(false).unwrap();
    assert_eq!(
        std::fs::read(fixture.home.path().join("vms/childvm/rootfs.ext4")).unwrap(),
        b"fake-ext4-bytes"
    );
    let keys =
        mvm_core::transcript::local_store::LocalTranscriptStore::open(fixture.home.path()).unwrap();
    let (anchor, _) = guarded::load_anchor(fixture.home.path(), &keys).unwrap();
    let children = fixture
        .service
        .store
        .list()
        .unwrap()
        .into_iter()
        .filter(|meta| meta.vm_name == "childvm")
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 1);
    mvm_runtime::checkpoint::verify_lineage(&fixture.service.store, &children[0].id, &anchor)
        .unwrap();
    assert_eq!(
        anchor
            .recorded
            .get(children[0].id.as_str())
            .unwrap()
            .plan_id,
        fixture.plan.plan_id.0
    );
}

#[test]
fn canonical_audit_member_modes_are_accepted_without_chmod_or_rewrite() {
    for mode in [0o600, 0o644] {
        let fixture = Fixture::new(Vec::new());
        let path = fixture.home.path().join("audit/local.jsonl");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let before = snapshot(fixture.home.path());
        let _prepared = fixture
            .service
            .prepare_unbooted(fixture.request(&[], false))
            .unwrap();
        assert_eq!(before, snapshot(fixture.home.path()));
    }
}

#[test]
fn service_explicit_drop_materializes_without_child_plan_or_secret_lookup() {
    let fixture = Fixture::new(vec![binding()]);
    fixture.invoke(true).unwrap();
    assert!(!fixture.home.path().join("vms/childvm/plan.json").exists());
    let chain = std::fs::read_to_string(fixture.home.path().join("audit/local.jsonl")).unwrap();
    let event: mvm_hostd::supervisor::SignedEnvelope =
        serde_json::from_str(chain.lines().last().unwrap()).unwrap();
    assert_eq!(event.entry.event, "checkpoint.forked");
    assert_eq!(
        event
            .entry
            .labels
            .get("secret_bindings")
            .map(String::as_str),
        Some("[]")
    );
}

#[test]
fn service_missing_candidate_refuses_even_with_allow_drop() {
    let fixture = Fixture::new(Vec::new());
    std::fs::remove_file(fixture.plan_path()).unwrap();
    fixture.assert_request_refused_unchanged(true, "required existing fork authority file");
}

#[test]
fn envelope_candidate_is_data_bound_to_the_original_content_id() {
    let fixture = Fixture::new(Vec::new());
    let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    let envelope = mvm_core::plan::sign_plan(&fixture.plan, &key, "candidate-only");
    write_private(
        &fixture.plan_path(),
        &serde_json::to_vec(&envelope).unwrap(),
    );
    let before = snapshot(fixture.home.path());
    let _prepared = fixture
        .service
        .prepare_unbooted(fixture.request(&[], false))
        .unwrap();
    assert_eq!(before, snapshot(fixture.home.path()));
    let mut different = fixture.plan.clone();
    different.resources.cpus += 1;
    let envelope = mvm_core::plan::sign_plan(&different, &key, "candidate-only");
    write_private(
        &fixture.plan_path(),
        &serde_json::to_vec(&envelope).unwrap(),
    );
    fixture.assert_request_refused_unchanged(true, "does not match authenticated original");
}

#[test]
fn replaced_or_non_content_addressed_plan_cannot_be_original_policy() {
    for change in 0..5 {
        let fixture = Fixture::new(Vec::new());
        let mut candidate = fixture.plan.clone();
        match change {
            0 => candidate.plan_id.0 = "legacy-plan-id".into(),
            1 => candidate.tenant.0 = "other".into(),
            2 => candidate.workload.0 = "differentvm".into(),
            3 => candidate.secrets.push(binding()),
            _ => candidate.resources.cpus += 1,
        }
        if change != 0 {
            candidate.plan_id = mvm_core::plan::compute_plan_id(&candidate);
        }
        fixture.persist_plan(&candidate);
        fixture.assert_request_refused_unchanged(
            true,
            if change == 0 {
                "not content-addressed"
            } else {
                "does not match authenticated original"
            },
        );
    }
}

#[test]
fn malformed_candidate_diagnostics_do_not_echo_sensitive_bytes() {
    let fixture = Fixture::new(Vec::new());
    write_private(
        &fixture.plan_path(),
        br#"{"schema_version":"SENSITIVE_FORK_MARKER"}"#,
    );
    let error = fixture
        .invoke(true)
        .err()
        .expect("malformed candidate refusal");
    for exposed in [
        format!("{error}"),
        format!("{error:#}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        assert!(!exposed.contains("SENSITIVE_FORK_MARKER"));
        assert!(exposed.contains("malformed"));
    }
}

#[test]
fn oversized_and_unsafe_candidate_members_refuse_without_repair() {
    for kind in 0..6 {
        let fixture = Fixture::new(Vec::new());
        let path = fixture.plan_path();
        match kind {
            0 => std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(guarded::MAX_FORK_PLAN_BYTES + 1)
                .unwrap(),
            1 => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(),
            2 => std::fs::hard_link(&path, fixture.home.path().join("alias")).unwrap(),
            3 => {
                let target = fixture.home.path().join("candidate");
                std::fs::rename(&path, &target).unwrap();
                symlink(target, &path).unwrap();
            }
            4 => {
                std::fs::remove_file(&path).unwrap();
                std::fs::create_dir(&path).unwrap();
            }
            _ => {
                std::fs::remove_file(&path).unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
        fixture.assert_request_refused_unchanged(
            true,
            if kind == 0 { "4 MiB" } else { "fork authority" },
        );
    }
}

#[test]
fn duplicate_and_conflicting_signed_creation_evidence_refuse() {
    for conflicting in [false, true] {
        let fixture = Fixture::new(Vec::new());
        let mut meta = fixture.parent.clone();
        if conflicting {
            meta.supervisor_config_digest = "changed".into();
            meta.meta_digest = meta.compute_meta_digest();
        }
        fixture.emit_creation(&fixture.plan, &meta);
        fixture.assert_request_refused_unchanged(true, "duplicate or conflicting");
    }
}

#[test]
fn missing_tampered_or_wrong_tenant_history_refuses() {
    for kind in 0..3 {
        let fixture = Fixture::new(Vec::new());
        let path = fixture.home.path().join("audit/local.jsonl");
        match kind {
            0 => std::fs::remove_file(&path).unwrap(),
            1 => {
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("checkpoint.created", "checkpoint.changed");
                write_private(&path, text.as_bytes());
            }
            _ => std::fs::rename(&path, fixture.home.path().join("audit/other.jsonl")).unwrap(),
        }
        fixture.assert_request_refused_unchanged(
            true,
            match kind {
                0 => "history is missing",
                1 => "failed verification",
                _ => "tenant does not match",
            },
        );
    }
}

#[test]
fn pruned_history_refuses_even_when_original_creation_is_retained() {
    use mvm_hostd::supervisor::FileAuditSigner;
    use mvm_hostd::supervisor::audit::{AuditSigner, for_plan};
    use mvm_hostd::supervisor::audit_file::RotationPolicy;
    let fixture = Fixture::new(Vec::new());
    let audit = fixture.home.path().join("audit");
    std::fs::remove_file(audit.join("local.jsonl")).unwrap();
    let keys =
        mvm_core::transcript::local_store::LocalTranscriptStore::open(fixture.home.path()).unwrap();
    let (key, verifying) = keys.existing_host_keypair().unwrap();
    let signer = FileAuditSigner::open(key, &audit)
        .unwrap()
        .with_rotation(RotationPolicy::at_bytes(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for _ in 0..2 {
        runtime
            .block_on(signer.sign_and_emit(&for_plan(&fixture.plan, None, "plan.launched", [])))
            .unwrap();
    }
    drop(signer);
    fixture.emit_creation(&fixture.plan, &fixture.parent);
    crate::audit::prune_audit("local", 1, crate::audit::AuditPruneMode::Commit).unwrap();
    let history =
        mvm_core::audit_verify::set::read_verified_history(&audit, "local", &verifying).unwrap();
    assert!(history.pruned.is_some());
    assert!(
        history
            .segments
            .iter()
            .flat_map(|segment| segment.entries.as_ref().unwrap())
            .any(|entry| entry.event == "checkpoint.created")
    );
    fixture.assert_request_refused_unchanged(true, "pruned history");
    let before_boot = snapshot(fixture.home.path());
    let error = preparation_error(
        fixture
            .service
            .prepare_boot(fixture.request(&[], true))
            .and_then(|stage| stage.for_tenant("local".into())),
    );
    assert!(format!("{error:#}").contains("pruned history"), "{error:#}");
    assert_eq!(before_boot, snapshot(fixture.home.path()));
}

#[test]
fn missing_existing_signer_halves_never_initialize_replacements() {
    for member in ["host-signer.ed25519", "host-signer.pub"] {
        let fixture = Fixture::new(Vec::new());
        std::fs::remove_file(fixture.home.path().join("keys").join(member)).unwrap();
        fixture.assert_request_refused_unchanged(true, "authority");
    }
}

#[test]
fn unsupported_declared_source_precedes_authority_and_metadata_lookups() {
    let fixture = Fixture::new(Vec::new());
    std::fs::remove_dir_all(fixture.home.path().join("keys")).unwrap();
    let bindings = [
        binding(),
        SecretBinding {
            source: SecretSource::External {
                provider: "external".into(),
                path: "value".into(),
            },
            ..binding()
        },
    ];
    let before = snapshot(fixture.home.path());
    let error = preparation_error(
        fixture
            .service
            .prepare_unbooted(fixture.request(&bindings, true)),
    );
    assert!(format!("{error:#}").contains("unsupported secret source"));
    assert_eq!(before, snapshot(fixture.home.path()));
}

#[test]
fn static_managed_symlinks_and_unsafe_audit_members_refuse_without_repair() {
    for managed in ["audit", "keys", "vms", "vms/parentvm", "checkpoints"] {
        let fixture = Fixture::new(Vec::new());
        let path = fixture.home.path().join(managed);
        let saved = fixture.home.path().join("external-target");
        std::fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        fixture.assert_request_refused_unchanged(
            true,
            if managed == "keys" {
                "authority"
            } else {
                "fork authority"
            },
        );
    }
    for mode in [0o640, 0o666] {
        let fixture = Fixture::new(Vec::new());
        std::fs::set_permissions(
            fixture.home.path().join("audit/local.jsonl"),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        fixture.assert_request_refused_unchanged(true, "fork authority file");
    }
}

#[test]
fn nonregular_or_aliased_audit_members_and_unsafe_ancestors_refuse() {
    for kind in 0..4 {
        let fixture = Fixture::new(Vec::new());
        let path = fixture.home.path().join("audit/local.jsonl");
        match kind {
            0 => std::fs::hard_link(&path, fixture.home.path().join("audit-alias")).unwrap(),
            1 => {
                let saved = fixture.home.path().join("saved-chain");
                std::fs::rename(&path, &saved).unwrap();
                symlink(saved, &path).unwrap();
            }
            2 => {
                std::fs::remove_file(&path).unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(&path)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            _ => std::fs::set_permissions(
                fixture.home.path().join("audit"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap(),
        }
        fixture.assert_request_refused_unchanged(true, "fork authority");
    }
}

#[test]
fn parent_policy_with_unsupported_sources_refuses_without_metadata() {
    let fixture = Fixture::new(vec![SecretBinding {
        source: SecretSource::External {
            provider: "external".into(),
            path: "value".into(),
        },
        ..binding()
    }]);
    fixture.assert_request_refused_unchanged(true, "unsupported secret source");
}

#[test]
fn preexisting_vm_directory_and_dangling_alias_are_not_overwritten() {
    for alias in [false, true] {
        let fixture = Fixture::new(Vec::new());
        let path = fixture.home.path().join("vms/childvm");
        if alias {
            symlink(fixture.home.path().join("missing"), &path).unwrap();
        } else {
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("keep"), b"retained").unwrap();
        }
        fixture.assert_request_refused_unchanged(true, "occupied");
    }
}

#[test]
fn prepared_checkpoint_collision_and_changed_parent_refuse_before_copy() {
    for kind in 0..3 {
        let fixture = Fixture::new(Vec::new());
        let prepared = fixture
            .service
            .prepare_unbooted(fixture.request(&[], true))
            .unwrap();
        if kind == 0 {
            let mut parent = fixture.parent.clone();
            parent.tag = Some("changed-after-proof".into());
            fixture.service.store.write_meta(&parent).unwrap();
        } else if kind == 1 {
            symlink(
                fixture.home.path().join("missing"),
                fixture.service.store.dir_for(&prepared.child_id),
            )
            .unwrap();
        } else {
            std::fs::create_dir_all(fixture.service.store.dir_for(&prepared.child_id)).unwrap();
            std::fs::write(
                fixture
                    .service
                    .store
                    .dir_for(&prepared.child_id)
                    .join("meta.json"),
                b"malformed occupant",
            )
            .unwrap();
        }
        let before = snapshot(fixture.home.path());
        let destination = prepared.destination.clone();
        assert!(prepared.materialize_and_publish().is_err());
        assert_eq!(before, snapshot(fixture.home.path()));
        assert!(!destination.exists());
    }
}

#[test]
fn service_initial_metadata_fifo_refuses_without_blocking_or_effects() {
    let fixture = Fixture::new(Vec::new());
    let path = fixture
        .service
        .store
        .dir_for(&fixture.parent.id)
        .join("meta.json");
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    fixture.assert_request_refused_unchanged(true, "fork authority file");
}

#[test]
fn unrelated_metadata_fifo_refuses_before_canonical_ancestry_scan() {
    let fixture = Fixture::new(Vec::new());
    let path = fixture
        .service
        .store
        .dir_for(&CheckpointId::new("unrelated"))
        .join("meta.json");
    mvm_core::config::create_private_dir(path.parent().unwrap()).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    fixture.assert_request_refused_unchanged(true, "fork authority file");
}

#[test]
fn initial_and_unrelated_unsafe_or_oversized_metadata_refuse_unchanged() {
    for initial in [false, true] {
        for kind in 0..7 {
            let fixture = Fixture::new(Vec::new());
            let id = if initial {
                fixture.parent.id.clone()
            } else {
                CheckpointId::new("unrelated")
            };
            let mut meta = fixture.parent.clone();
            meta.id = id.clone();
            mvm_core::config::create_private_dir(fixture.service.store.dir_for(&id)).unwrap();
            fixture.service.store.write_meta(&meta).unwrap();
            let path = fixture.service.store.dir_for(&id).join("meta.json");
            let message = match kind {
                0 => {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_len(guarded::MAX_CHECKPOINT_META_BYTES + 1)
                        .unwrap();
                    "4 MiB"
                }
                1 => {
                    std::fs::hard_link(&path, fixture.home.path().join("meta-alias")).unwrap();
                    "fork authority"
                }
                2 => {
                    let saved = fixture.home.path().join("saved-meta");
                    std::fs::rename(&path, &saved).unwrap();
                    symlink(saved, &path).unwrap();
                    "fork authority"
                }
                3 => {
                    std::fs::remove_file(&path).unwrap();
                    std::fs::create_dir(&path).unwrap();
                    "fork authority"
                }
                4 | 5 => {
                    std::fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(if kind == 4 { 0o640 } else { 0o666 }),
                    )
                    .unwrap();
                    "fork authority"
                }
                _ => {
                    meta.id = CheckpointId::new("different");
                    write_private(&path, &serde_json::to_vec(&meta).unwrap());
                    "ID does not match"
                }
            };
            fixture.assert_request_refused_unchanged(true, message);
        }
    }
}

#[test]
fn metadata_parse_failures_are_redacted_and_do_not_initialize_authority() {
    for initial in [false, true] {
        let fixture = Fixture::new(Vec::new());
        let id = if initial {
            fixture.parent.id.clone()
        } else {
            CheckpointId::new("unrelated")
        };
        let path = fixture.service.store.dir_for(&id).join("meta.json");
        write_private(&path, br#"{"class":"SENSITIVE_META_MARKER"}"#);
        let before = snapshot(fixture.home.path());
        let error = fixture.invoke(true).err().expect("metadata refusal");
        for text in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(text.contains("malformed"), "{text}");
            assert!(!text.contains("SENSITIVE_META_MARKER"));
        }
        assert_eq!(before, snapshot(fixture.home.path()));
    }
}

#[test]
fn canonical_metadata_is_0600_and_0644_refuses_without_repair() {
    for initial in [false, true] {
        let fixture = Fixture::new(Vec::new());
        let mut meta = fixture.parent.clone();
        if !initial {
            meta.id = CheckpointId::new("unrelated");
            mvm_core::config::create_private_dir(fixture.service.store.dir_for(&meta.id)).unwrap();
            fixture.service.store.write_meta(&meta).unwrap();
        }
        let path = fixture.service.store.dir_for(&meta.id).join("meta.json");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        fixture.assert_request_refused_unchanged(true, "fork authority file");
    }
}

#[test]
fn store_entry_bound_counts_dot_names_and_ignored_files_before_filtering() {
    let fixture = Fixture::new(Vec::new());
    for n in 0..guarded::MAX_CHECKPOINT_STORE_ENTRIES {
        std::fs::write(
            fixture.service.store.root().join(format!(".ignored-{n}")),
            [],
        )
        .unwrap();
    }
    fixture.assert_request_refused_unchanged(true, "256 examined-entry");
}

#[test]
fn store_aggregate_budget_refuses_before_reading_an_excess_metadata_member() {
    let fixture = Fixture::new(Vec::new());
    for n in 0..17 {
        let mut meta = fixture.parent.clone();
        meta.id = CheckpointId::new(format!("large-{n}"));
        meta.tag = Some("x".repeat(guarded::MAX_CHECKPOINT_META_BYTES as usize - 4096));
        mvm_core::config::create_private_dir(fixture.service.store.dir_for(&meta.id)).unwrap();
        fixture.service.store.write_meta(&meta).unwrap();
        assert!(
            std::fs::metadata(fixture.service.store.dir_for(&meta.id).join("meta.json"))
                .unwrap()
                .len()
                <= guarded::MAX_CHECKPOINT_META_BYTES
        );
    }
    fixture.assert_request_refused_unchanged(true, "64 MiB aggregate");
}

#[test]
fn unknown_checkpoint_directory_names_refuse_without_lossy_aliasing() {
    let fixture = Fixture::new(Vec::new());
    let path = fixture.service.store.root().join("invalid\ncheckpoint");
    mvm_core::config::create_private_dir(&path).unwrap();
    fixture.assert_request_refused_unchanged(true, "directory ID is invalid");
}

#[test]
fn valid_vm_full_metadata_classification_does_not_boot_or_mutate_it() {
    let fixture = Fixture::new(Vec::new());
    let mut parent = fixture.parent.clone();
    parent.class = mvm_core::checkpoint::CheckpointClass::VmFull;
    parent.meta_digest = parent.compute_meta_digest();
    fixture.service.store.write_meta(&parent).unwrap();
    // Classification must not require FsQuick verification or signing custody.
    std::fs::remove_dir_all(fixture.home.path().join("keys")).unwrap();
    let before = snapshot(fixture.home.path());
    let classified = fixture.service.classify(&parent.id).unwrap();
    assert_eq!(classified, parent);
    assert_eq!(before, snapshot(fixture.home.path()));
}

#[test]
fn changed_source_refuses_through_canonical_content_verification() {
    let fixture = Fixture::new(Vec::new());
    let prepared = fixture
        .service
        .prepare_unbooted(fixture.request(&[], true))
        .unwrap();
    let content = std::fs::read_dir(fixture.service.store.content_dir(&fixture.parent.id))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_file())
        .expect("protected capture has an authenticated index");
    std::fs::write(&content, b"changed-content").unwrap();
    let destination = prepared.destination.clone();
    assert!(prepared.materialize_and_publish().is_err());
    assert!(!destination.exists());
}

#[test]
fn postcopy_audit_failure_reports_and_retains_materialized_artifacts() {
    let fixture = Fixture::new(Vec::new());
    let prepared = fixture
        .service
        .prepare_unbooted(fixture.request(&[], true))
        .unwrap();
    // Private step fault injection; public API never splits copy/publication.
    let child = prepared.materialize().unwrap();
    let chain = fixture.home.path().join("audit/local.jsonl");
    std::fs::remove_file(&chain).unwrap();
    std::fs::create_dir(&chain).unwrap();
    let error = prepared.failure(
        ForkPhase::Publication,
        prepared.publish(&child).unwrap_err(),
    );
    let message = format!("{error:#}");
    assert!(message.contains("lineage publication failed"), "{message}");
    assert!(message.contains(&prepared.destination.display().to_string()));
    assert!(message.contains(child.id.as_str()));
    assert_eq!(
        std::fs::read(prepared.destination.join("rootfs.ext4")).unwrap(),
        b"fake-ext4-bytes"
    );
    assert_eq!(fixture.service.store.read_meta(&child.id).unwrap(), child);
}

mod boot_preflight {
    use super::*;
    use crate::secret::SecretValueInput;
    use mvm_contract::ir::{AuthType, InjectionMode, Sigv4Params};
    use mvm_core::crypto::secret_binding::{
        BindingStore, FileBindingStore, SecretApproval, SecretBindingMeta,
    };
    use mvm_core::crypto::secret_store::{BACKEND_ENV, FileSecretStore, default_secrets_dir};
    use std::sync::Arc;

    fn fixture(parent_secrets: Vec<SecretBinding>) -> Fixture {
        let mut fixture = Fixture::new(parent_secrets);
        fixture._env.set(BACKEND_ENV, "file");
        fixture._env.set("MVM_TENANT", "local");
        fixture
    }

    fn binding() -> SecretBinding {
        SecretBinding {
            source: SecretSource::Keystore {
                address: "api".into(),
            },
            ..super::binding()
        }
    }

    fn metadata(auth: AuthType, inject: InjectionMode) -> SecretBindingMeta {
        SecretBindingMeta {
            auth_type: auth,
            allowed_hosts: vec!["api.example.com".into()],
            sigv4: (auth == AuthType::Sigv4).then(|| Sigv4Params {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                region: "us-east-1".into(),
                service: "s3".into(),
            }),
            inject,
            provider: None,
            approve: SecretApproval::Never,
            oauth: None,
        }
    }

    fn seed_secret(fixture: &Fixture) -> SecretService {
        // Explicit file-backed fixture; preparation never decrypts its value.
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(
                default_secrets_dir().unwrap(),
            )))
            .bindings(Arc::new(FileBindingStore::default_location().unwrap()))
            .machines_root(fixture.home.path().join("machines"))
            .audit(crate::secret::audit::SecretAudit::with_path(
                fixture.home.path().join("fixture-secret-audit.jsonl"),
            ))
            .build()
            .unwrap();
        service
            .put(
                "local",
                "api",
                SecretValueInput::new("synthetic-fixture".into()),
            )
            .unwrap();
        service
    }

    fn store_metadata(meta: &SecretBindingMeta) {
        FileBindingStore::default_location()
            .unwrap()
            .put("local", "api", meta)
            .unwrap();
    }

    fn prepare_boot<'a>(
        fixture: &'a Fixture,
        declared: &[SecretBinding],
        allow_drop: bool,
    ) -> std::result::Result<PreparedFsQuickFork<'a>, ForkError> {
        fixture
            .service
            .prepare_boot(fixture.request(declared, allow_drop))?
            .for_tenant("local".into())
    }

    fn no_child(fixture: &Fixture) {
        assert!(std::fs::symlink_metadata(fixture.home.path().join("vms/childvm")).is_err());
        for entry in std::fs::read_dir(fixture.service.store.root()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let name = entry.file_name();
                let name = name.to_str().unwrap();
                assert!(name == "parent" || name.starts_with('.'), "{name}");
            }
        }
    }

    #[test]
    fn service_unknown_original_refuses_even_allow_drop_before_service() {
        for kind in 0..3 {
            let fixture = fixture(Vec::new());
            match kind {
                0 => std::fs::remove_file(fixture.plan_path()).unwrap(),
                1 => {
                    let mut other = fixture.plan.clone();
                    other.resources.cpus += 1;
                    other.plan_id = mvm_core::plan::compute_plan_id(&other);
                    fixture.persist_plan(&other);
                }
                _ => fixture.emit_creation(&fixture.plan, &fixture.parent),
            }
            let before = snapshot(fixture.home.path());
            let error = preparation_error(prepare_boot(&fixture, &[binding()], true));
            assert!(
                format!("{error:#}").contains(match kind {
                    0 => "required existing fork authority file",
                    1 => "does not match authenticated original",
                    _ => "duplicate or conflicting",
                }),
                "{error:#}"
            );
            assert_eq!(before, snapshot(fixture.home.path()));
            no_child(&fixture);
        }
    }

    #[test]
    fn original_drop_gate_precedes_metadata_and_allows_explicit_omission_only() {
        let fixture = fixture(vec![binding()]);
        let before = snapshot(fixture.home.path());
        let error = preparation_error(prepare_boot(&fixture, &[], false));
        assert!(format!("{error:#}").contains("would drop parent secret bindings"));
        assert_eq!(before, snapshot(fixture.home.path()));
        let prepared = prepare_boot(&fixture, &[], true).unwrap();
        assert!(prepared.effective.is_empty());
        assert!(prepared.service.is_none());
        no_child(&fixture);
    }

    #[test]
    fn destination_and_existing_issuer_refuse_before_metadata_service() {
        for kind in 0..3 {
            let fixture = fixture(Vec::new());
            match kind {
                0 => std::fs::create_dir(fixture.home.path().join("vms/childvm")).unwrap(),
                1 => symlink(
                    fixture.home.path().join("missing"),
                    fixture.home.path().join("vms/childvm"),
                )
                .unwrap(),
                _ => write_private(
                    &fixture.home.path().join("keys/host-signer.ed25519"),
                    &[41; 32],
                ),
            }
            let before = snapshot(fixture.home.path());
            let error = preparation_error(prepare_boot(&fixture, &[binding()], true));
            assert!(
                format!("{error:#}").contains(if kind < 2 {
                    "occupied"
                } else {
                    "signing authority"
                }),
                "{error:#}"
            );
            assert_eq!(before, snapshot(fixture.home.path()));
        }
    }

    #[test]
    fn all_four_approval_pairs_remain_per_use_not_copy_consent() {
        for requested in [false, true] {
            for ask in [false, true] {
                let fixture = fixture(Vec::new());
                let service = seed_secret(&fixture);
                let mut stored = metadata(AuthType::Bearer, InjectionMode::Header);
                stored.approve = if ask {
                    SecretApproval::Ask
                } else {
                    SecretApproval::Never
                };
                store_metadata(&stored);
                let mut declaration = binding();
                declaration.approval_required = requested;
                let declared = [declaration];
                let audit_path = fixture.home.path().join("fixture-secret-audit.jsonl");
                let before = std::fs::read_to_string(&audit_path)
                    .unwrap()
                    .lines()
                    .count();
                let effective = effective_child_bindings(&service, "local", &declared).unwrap();
                assert_eq!(
                    std::fs::read_to_string(audit_path).unwrap().lines().count(),
                    before + 1
                );
                let prepared = prepare_boot(&fixture, &declared, false).unwrap();
                assert_eq!(prepared.effective, effective);
                assert_eq!(prepared.effective[0].approval_required, requested || ask);
                assert_eq!(prepared.effective[0].destinations, ["api.example.com"]);
                no_child(&fixture);
            }
        }
    }

    #[test]
    fn every_legal_auth_injection_pair_requires_a_nonempty_effective_host_set() {
        let mut legal = 0;
        for auth in [
            AuthType::Sigv4,
            AuthType::Hmac,
            AuthType::Bearer,
            AuthType::Basic,
        ] {
            for inject in [
                InjectionMode::Header,
                InjectionMode::QueryParam,
                InjectionMode::UrlPath,
                InjectionMode::BasicAuth,
            ] {
                if !inject.admits(auth) {
                    continue;
                }
                legal += 1;
                let fixture = fixture(Vec::new());
                let _service = seed_secret(&fixture);
                let mut stored = metadata(auth, inject);
                stored.allowed_hosts.clear();
                store_metadata(&stored);
                let declared = [binding()];
                let error = preparation_error(prepare_boot(&fixture, &declared, false));
                assert!(
                    format!("{error:#}").contains("nonempty effective"),
                    "{error:#}"
                );
                no_child(&fixture);
                stored.allowed_hosts.push("api.example.com".into());
                store_metadata(&stored);
                let prepared = prepare_boot(&fixture, &declared, false).unwrap();
                assert_eq!(prepared.effective[0].destinations, ["api.example.com"]);
                no_child(&fixture);
            }
        }
        assert_eq!(legal, 9);
    }

    #[test]
    fn missing_secret_binding_and_incompatible_injection_leave_no_child() {
        for kind in 0..3 {
            let fixture = fixture(Vec::new());
            if kind != 0 {
                let _service = seed_secret(&fixture);
                if kind == 2 {
                    store_metadata(&metadata(AuthType::Bearer, InjectionMode::BasicAuth));
                }
            }
            let error = preparation_error(prepare_boot(&fixture, &[binding()], false));
            let message = format!("{error:#}");
            assert!(
                message.contains(match kind {
                    0 => "fork secret is missing",
                    1 => "fork secret binding is missing",
                    _ => "injection mode is incompatible",
                }),
                "{message}"
            );
            // Canonical metadata auditing may write; no zero-write claim here.
            no_child(&fixture);
        }
    }

    #[test]
    fn destination_widening_refuses_at_service_entry_before_copy() {
        let fixture = fixture(Vec::new());
        let _service = seed_secret(&fixture);
        store_metadata(&metadata(AuthType::Bearer, InjectionMode::Header));
        let mut declaration = binding();
        declaration.destinations = vec!["evil.example.com".into()];
        let error = preparation_error(prepare_boot(&fixture, &[declaration], false));
        assert!(
            format!("{error:#}").contains("outside that allow-list"),
            "{error:#}"
        );
        no_child(&fixture);
    }

    #[test]
    fn captured_original_settings_survive_mutable_plan_replacement() {
        let mut fixture = fixture(Vec::new());
        fixture.plan.resources.cpus = 3;
        fixture.plan.resources.mem_mib = 640;
        fixture.plan.network_mode = mvm_contract::plan::NetworkMode::HostVsockProxy;
        fixture.plan.agent_verbs = Some(serde_json::from_str("[\"ping\"]").unwrap());
        fixture.plan.plan_id = mvm_core::plan::compute_plan_id(&fixture.plan);
        fixture.persist_plan(&fixture.plan);
        std::fs::remove_file(fixture.home.path().join("audit/local.jsonl")).unwrap();
        fixture.emit_creation(&fixture.plan, &fixture.parent);
        let prepared = prepare_boot(&fixture, &[], false).unwrap();
        write_private(
            &fixture.plan_path(),
            b"replacement is not original authority",
        );
        assert_eq!(prepared.plan.resources.cpus, 3);
        assert_eq!(prepared.plan.resources.mem_mib, 640);
        assert_eq!(prepared.plan.network_mode, fixture.plan.network_mode);
        assert_eq!(prepared.plan.agent_verbs, fixture.plan.agent_verbs);
        assert!(
            crate::admission::InheritedBundle::from_parent_plan(&prepared.plan)
                .unwrap()
                .is_none()
        );
        no_child(&fixture);
    }

    #[test]
    fn metadata_drift_revalidates_before_copy_and_cannot_erase_signed_ask() {
        for kind in 0..5 {
            let fixture = fixture(Vec::new());
            let service = seed_secret(&fixture);
            let mut stored = metadata(AuthType::Bearer, InjectionMode::Header);
            store_metadata(&stored);
            let mut declaration = binding();
            declaration.approval_required = kind == 0;
            let declared = [declaration];
            let prepared = prepare_boot(&fixture, &declared, false).unwrap();
            if kind == 0 {
                stored.allowed_hosts.push("new.example.com".into());
                store_metadata(&stored);
                prepared.revalidate().unwrap();
                assert!(prepared.effective[0].approval_required);
                assert_eq!(prepared.effective[0].destinations, ["api.example.com"]);
            } else {
                match kind {
                    1 => stored.approve = SecretApproval::Ask,
                    2 => stored.allowed_hosts = vec!["different.example.com".into()],
                    3 => {
                        service.unbind("local", "api").unwrap();
                    }
                    _ => stored.inject = InjectionMode::BasicAuth,
                }
                if kind != 3 {
                    store_metadata(&stored);
                }
                assert!(prepared.materialize_and_publish().is_err());
            }
            no_child(&fixture);
        }
    }

    #[test]
    fn admitted_child_must_retain_exact_effective_bindings_and_identity() {
        let fixture = fixture(Vec::new());
        let _service = seed_secret(&fixture);
        let mut stored = metadata(AuthType::Bearer, InjectionMode::Header);
        stored.approve = SecretApproval::Ask;
        store_metadata(&stored);
        let declared = [binding()];
        let prepared = prepare_boot(&fixture, &declared, false).unwrap();
        // Synthetic comparison data only; public API requires &AdmittedPlan.
        let check = |child: &ExecutionPlan| {
            validate_child_data(
                child,
                &prepared.name,
                prepared.child_tenant.as_deref(),
                &prepared.effective,
                prepared.service.as_ref(),
            )
        };
        let mut child = fixture.plan.clone();
        child.workload.0 = prepared.name.clone();
        child.tenant.0 = prepared.child_tenant.clone().unwrap();
        child.secrets = prepared.effective.clone();
        check(&child).unwrap();
        for kind in 0..4 {
            let mut changed = child.clone();
            match kind {
                0 => changed.secrets[0].approval_required = false,
                1 => changed.secrets[0].destinations.clear(),
                2 => changed.tenant.0 = "different".into(),
                _ => changed.workload.0 = "different".into(),
            }
            assert!(check(&changed).is_err());
        }
        no_child(&fixture);
    }

    #[test]
    fn selected_child_tenant_is_captured_once_not_inherited_or_reread() {
        let mut fixture = fixture(Vec::new());
        fixture.plan.tenant.0 = "parenttenant".into();
        fixture.plan.plan_id = mvm_core::plan::compute_plan_id(&fixture.plan);
        fixture.persist_plan(&fixture.plan);
        std::fs::remove_file(fixture.home.path().join("audit/local.jsonl")).unwrap();
        fixture.emit_creation(&fixture.plan, &fixture.parent);
        let _service = seed_secret(&fixture);
        store_metadata(&metadata(AuthType::Bearer, InjectionMode::Header));
        let declared = [binding()];
        let stage = fixture
            .service
            .prepare_boot(ForkRequest {
                checkpoint: &fixture.parent.id,
                child_name: Some("childvm".into()),
                declared_secrets: &declared,
                allow_secret_drop: false,
            })
            .unwrap();
        let prepared = stage.for_tenant("local".into()).unwrap();
        assert_eq!(prepared.plan.tenant.0, "parenttenant");
        assert_eq!(prepared.child_tenant.as_deref(), Some("local"));
        fixture._env.set("MVM_TENANT", "different");
        prepared.revalidate().unwrap();
        no_child(&fixture);
    }

    #[test]
    fn authenticated_stage_defers_metadata_until_consuming_tenant_selection() {
        let fixture = fixture(Vec::new());
        let declared = [binding()];
        let before = snapshot(fixture.home.path());
        let stage = fixture
            .service
            .prepare_boot(fixture.request(&declared, false))
            .unwrap();
        assert_eq!(before, snapshot(fixture.home.path()));
        assert!(stage.prepared.service.is_none());
        assert!(stage.prepared.effective.is_empty());
        assert!(stage.prepared.child_tenant.is_none());
        assert_eq!(stage.declared, declared);
        no_child(&fixture);
        // The missing reference is resolved only by this consuming step.
        // Canonical metadata miss auditing can write after prerequisites.
        let error = preparation_error(stage.for_tenant("local".into()));
        assert!(format!("{error:#}").contains("fork secret is missing"));
        no_child(&fixture);
    }

    #[test]
    fn audit_failure_before_copy_refuses_and_publication_failure_retains_artifacts() {
        let fixture = fixture(Vec::new());
        let chain = fixture.home.path().join("audit/local.jsonl");
        let original = std::fs::read(&chain).unwrap();
        std::fs::remove_file(&chain).unwrap();
        std::fs::create_dir(&chain).unwrap();
        let before = snapshot(fixture.home.path());
        assert!(prepare_boot(&fixture, &[], false).is_err());
        assert_eq!(before, snapshot(fixture.home.path()));
        no_child(&fixture);
        std::fs::remove_dir(&chain).unwrap();
        write_private(&chain, &original);
        let prepared = prepare_boot(&fixture, &[], false).unwrap();
        // Private test-only fault injection between the exact production steps;
        // there is no public split transaction or callback.
        let child = prepared.materialize().unwrap();
        std::fs::remove_file(&chain).unwrap();
        std::fs::create_dir(&chain).unwrap();
        let error = prepared.failure(
            ForkPhase::Publication,
            prepared.publish(&child).unwrap_err(),
        );
        let message = format!("{error:#}");
        assert!(message.contains("lineage publication failed"));
        assert!(message.contains(&prepared.destination.display().to_string()));
        assert_eq!(fixture.service.store.read_meta(&child.id).unwrap(), child);
        assert_eq!(
            std::fs::read(prepared.destination.join("rootfs.ext4")).unwrap(),
            b"fake-ext4-bytes"
        );
        assert_eq!(error.phase(), ForkPhase::Publication);
        assert!(error.artifact().is_some());
    }

    #[test]
    fn signed_fork_audit_uses_the_same_effective_vector_not_later_widening() {
        let fixture = fixture(Vec::new());
        let _service = seed_secret(&fixture);
        let mut stored = metadata(AuthType::Bearer, InjectionMode::Header);
        store_metadata(&stored);
        let declared = [binding()];
        let prepared = prepare_boot(&fixture, &declared, false).unwrap();
        stored.allowed_hosts.push("later.example.com".into());
        store_metadata(&stored);
        let artifact = prepared.materialize_and_publish().unwrap();
        let keys =
            mvm_core::transcript::local_store::LocalTranscriptStore::open(fixture.home.path())
                .unwrap();
        let history = mvm_core::audit_verify::set::read_verified_history(
            &fixture.home.path().join("audit"),
            "local",
            &keys.existing_host_public_key().unwrap(),
        )
        .unwrap();
        let entry = history
            .segments
            .iter()
            .flat_map(|segment| segment.entries.as_ref().unwrap())
            .find(|entry| entry.event == "checkpoint.forked")
            .expect("authenticated fork event");
        let bindings: serde_json::Value =
            serde_json::from_str(entry.labels.get("secret_bindings").unwrap()).unwrap();
        assert_eq!(
            bindings,
            serde_json::json!([{
                "name": artifact.bindings()[0].name,
                "allowed_hosts": artifact.bindings()[0].destinations,
            }])
        );
        assert!(!bindings.to_string().contains("later.example.com"));
        // Filesystem/audit evidence only, not native boot or approval use.
    }

    #[test]
    fn boot_metadata_fifo_refuses_before_class_dispatch() {
        let fixture = fixture(Vec::new());
        let path = fixture
            .service
            .store
            .dir_for(&fixture.parent.id)
            .join("meta.json");
        std::fs::remove_file(&path).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let before = snapshot(fixture.home.path());
        assert!(fixture.service.classify(&fixture.parent.id).is_err());
        assert_eq!(before, snapshot(fixture.home.path()));
        no_child(&fixture);
    }
}
