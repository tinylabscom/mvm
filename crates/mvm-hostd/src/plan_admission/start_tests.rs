#![cfg(test)]

use super::rollback::{UndoLaunch, undo_cli_launch};
use super::start::cli_rollback_error;
use super::test_support::*;
use super::*;

#[test]
fn selector_original_admission_refuses_before_host_launch_preparation() {
    assert_selector_refuses_before_host_launch_preparation(false);
}

#[test]
fn selector_original_admission_refuses_before_persistent_readiness() {
    assert_selector_refuses_before_host_launch_preparation(true);
}

fn assert_selector_refuses_before_host_launch_preparation(persistent: bool) {
    use crate::assurance_session::{CampaignDeclaration, CampaignRequest, default_policy_ceiling};
    use mvm_contract::assurance::{ApprovalSet, AssuranceId, RequestedAuthority, Sha256Digest};
    let (_env, home) = host_with_ceiling(Default::default());
    let keys = mvm_core::config::mvm_keys_dir_at(home.path());
    std::fs::create_dir_all(&keys).unwrap();
    let key_names = || {
        std::fs::read_dir(&keys)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let selector =
        mvm_contract::protocol::mailbox::service_blind::LaunchProfile::new([1; 32], [2; 32])
            .unwrap();
    for projection in 0..4 {
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let mut plan = plan_binding(&[]);
        plan.mailbox = Some(MailboxGrant {
            mailbox: MailboxId::from_bytes([4; 32]),
            authority_key: [8; 32],
            epoch: ExecutionEpoch::new(1).unwrap(),
            report: None,
            retention: None,
            service_blind: Some(selector),
        });
        let signed = sign_plan(&plan, &SigningKey::from_bytes(&[7; 32]), "test");
        let plan = verify_plan(
            &signed,
            &[("test", &SigningKey::from_bytes(&[7; 32]).verifying_key())],
        )
        .unwrap();
        let admitted = AdmittedPlan::for_test(plan.clone(), "test".into(), signed);
        let mut stripped = plan.clone();
        stripped.mailbox.as_mut().unwrap().service_blind = None;
        let mut replaced = plan.clone();
        replaced.mailbox = None;
        let config = VmStartConfig {
            name: plan.image.name.clone(),
            plan_json: match projection {
                0 => None,
                1 => Some(serde_json::to_string(&stripped).unwrap()),
                2 => Some(serde_json::to_string(&replaced).unwrap()),
                _ => Some("malformed".into()),
            },
            ..Default::default()
        };
        let audit = tempfile::tempdir().unwrap();
        let emitter = std::sync::Arc::new(
            crate::audit::emitter::AuditEmitter::with_dir(
                SigningKey::from_bytes(&[41; 32]),
                audit.path(),
            )
            .unwrap(),
        );
        let campaign = CampaignRequest {
            declaration: CampaignDeclaration {
                request_id: AssuranceId::parse("selector-request").unwrap(),
                idempotency_key: AssuranceId::parse("selector-retry").unwrap(),
                campaign_id: AssuranceId::parse("selector-campaign").unwrap(),
                trial_id: AssuranceId::parse("selector-trial").unwrap(),
                source_run_id: AssuranceId::parse("selector-source").unwrap(),
                source_digest: Sha256Digest::parse(format!("sha256:{}", "5".repeat(64))).unwrap(),
                artifact_digest: Sha256Digest::parse(format!("sha256:{}", "6".repeat(64))).unwrap(),
                edges: Vec::new(),
                approvals: ApprovalSet::none(),
                requested: RequestedAuthority {
                    allowed_tools: Vec::new(),
                    observation_scopes: Vec::new(),
                    max_steps: 1,
                    max_output_bytes: 1024,
                    deadline_unix_ms: 0,
                },
                grant_ttl_ms: 1000,
            },
            emitter: std::sync::Arc::clone(&emitter),
            policy_ceiling: default_policy_ceiling(),
            policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            backend: "mock".into(),
            now_unix_ms: 1_800_000_000_000,
        };
        let original_keys = key_names();
        super::start::TRAP_LAUNCH_PREPARATION.set(true);
        let params = StartAdmittedParams {
            backend: &backend,
            admitted,
            config,
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: Some(&campaign),
        };
        let result = if persistent {
            start_persistent(params, None, Vec::new()).map(|_| ())
        } else {
            start_admitted(params).map(|_| ())
        };
        let error = result.unwrap_err();
        super::start::TRAP_LAUNCH_PREPARATION.set(false);
        assert_eq!(
            error.to_string(),
            "admission gate refused (mailbox-profile)"
        );
        assert!(format!("{error:#}").contains("service-blind V3 mailbox launch is unavailable"));
        assert!(!matches!(
            backend.status(&VmId(plan.image.name.clone())),
            Ok(mvm_core::vm_backend::VmStatus::Running)
        ));
        let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
        assert_eq!(
            chain
                .lines()
                .filter(|line| line.contains("\"plan.failed\""))
                .count(),
            1
        );
        assert!(!chain.contains("\"plan.launched\""));
        assert!(chain.contains("mailbox-profile"));
        assert_eq!(key_names(), original_keys, "no legacy key material minted");
    }
}

#[test]
fn assurance_proxy_attachment_refuses_a_duplicate_service() {
    let proxy = mvm_contract::protocol::broker_control::ServiceProxyBinding {
        service: mvm_contract::protocol::broker::ServiceId::parse(
            mvm_contract::assurance::HOST_ASSURANCE_SERVICE,
        )
        .expect("valid assurance service"),
        endpoint: "/tmp/mvm-assurance-test.sock".to_string(),
        capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
    };
    let mut config = mvm_core::vm_backend::VmStartConfig::default();
    config.service_proxies.push(proxy.clone());
    let error = attach_assurance_proxy(&mut config, proxy)
        .expect_err("the same controller service must not be attached twice");
    assert!(error.to_string().contains("already configured"));
}

// ───────────────────────────────────────────────────────────────
// admit_and_start: the shared admitted-boot entrypoint
// ───────────────────────────────────────────────────────────────

fn baked_assurance_config(directory: &std::path::Path) -> VmStartConfig {
    mvm_runtime::signed_legacy_runtime_fixture(
        directory,
        std::path::Path::new(&mvm_core::config::mvm_home()),
        false,
    )
}

#[test]
fn an_unsigned_release_proof_cannot_mint_an_assurance_binding() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("runtime.tar.gz");
    let checksum = directory.path().join("runtime.tar.gz.sha256");
    let signature = directory.path().join("runtime.tar.gz.bundle");
    std::fs::write(&archive, b"unsigned archive").unwrap();
    let digest = mvm_core::crypto::image_verify::sha256_file(&archive).unwrap();
    std::fs::write(&checksum, format!("{digest}  runtime.tar.gz\n")).unwrap();
    std::fs::write(&signature, b"{}").unwrap();
    let config = VmStartConfig {
        runtime_release_proof: Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
            archive,
            checksum,
            signature_bundle: signature,
            archive_sha256: digest,
            version: "1.2.3".into(),
            arch: mvm_core::arch::GuestArch::host(),
        }),
        runtime_overlay_version: Some("1.2.3".into()),
        runtime_overlay_path: Some(directory.path().join("overlay").display().to_string()),
        runtime_overlay_verity_path: Some(directory.path().join("verity").display().to_string()),
        runtime_overlay_roothash: Some("a".repeat(64)),
        initrd_path: Some(directory.path().join("initramfs").display().to_string()),
        ..Default::default()
    };
    assert!(AssuranceRuntimeBinding::verify(&config, &plan_binding(&[]), None).is_err());
}

#[test]
fn changed_runtime_after_admission_records_failure_without_starting_backend() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let directory = tempfile::tempdir().unwrap();
    let audit = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let config = VmStartConfig {
        name: "changed-assurance-runtime".into(),
        ..baked_assurance_config(directory.path())
    };
    let image_sha256 =
        mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
            .unwrap();
    let mut synthesis = fixture_input(&config.name);
    synthesis.image_sha256 = &image_sha256;
    synthesis
        .services
        .push(mvm_core::protocol::broker::ServiceId::parse("host.assurance.v1").unwrap());
    let admitted = admit_for_run(
        &synthesis,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(directory.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .unwrap();
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[41; 32]),
        audit.path(),
    )
    .unwrap();
    crate::audit::durability::record_admission(
        Some(&emitter),
        admitted.plan(),
        admitted.signer_id(),
        crate::audit::durability::AuditDurability::BestEffort,
    )
    .unwrap();
    std::fs::write(&config.rootfs_path, b"changed after admission").unwrap();
    let vm_id = mvm_core::vm_backend::VmId(config.name.clone());
    start_admitted(StartAdmittedParams {
        backend: &backend,
        admitted,
        config,
        policy_bundle: None,
        emitter: Some(&emitter),
        assurance: None,
    })
    .expect_err("admitted artifact substitution must refuse before spawn");
    assert!(!matches!(
        backend.status(&vm_id),
        Ok(mvm_core::vm_backend::VmStatus::Running)
    ));
    let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
    assert!(chain.contains("plan.admitted"), "{chain}");
    assert!(chain.contains("plan.failed"), "{chain}");
    assert!(chain.contains("assurance-runtime"), "{chain}");
    assert!(!chain.contains("plan.launched"), "{chain}");
}

#[test]
fn assurance_binding_requires_matching_image_and_unchanged_launch_bytes() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let directory = tempfile::tempdir().unwrap();
    let kernel = directory.path().join("kernel");
    std::fs::write(&kernel, b"original kernel").unwrap();
    let config = VmStartConfig {
        name: "assurance-bound".into(),
        kernel_path: Some(kernel.display().to_string()),
        ..baked_assurance_config(directory.path())
    };
    let mut plan = plan_binding(&[]);
    assert!(AssuranceRuntimeBinding::verify(&config, &plan, None).is_err());
    plan.image.sha256 =
        mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
            .unwrap();
    let signer_id = "host:test".to_string();
    let signed = sign_plan(
        &plan,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        &signer_id,
    );
    let unchecked = AdmittedPlan::for_test(plan, signer_id, signed);
    assert!(unchecked.require_assurance_runtime(&config.name).is_err());
    let admitted = unchecked.with_assurance_runtime_for_test(&config);
    admitted.require_assurance_runtime(&config.name).unwrap();
    assert!(
        admitted
            .require_assurance_runtime("different-machine")
            .is_err()
    );
    admitted.verify_assurance_launch(&config, None).unwrap();

    let renamed = VmStartConfig {
        name: "different-machine".into(),
        ..config.clone()
    };
    assert!(admitted.verify_assurance_launch(&renamed, None).is_err());
    std::fs::write(&kernel, b"replacement kernel").unwrap();
    assert!(admitted.verify_assurance_launch(&config, None).is_err());
    std::fs::write(&config.rootfs_path, b"replacement rootfs").unwrap();
    assert!(AssuranceRuntimeBinding::verify(&config, admitted.plan(), None).is_err());
}

#[test]
fn portable_assurance_capability_binds_original_proof_and_manifest_after_admission() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let directory = tempfile::tempdir().unwrap();
    let config = mvm_runtime::signed_legacy_portable_runtime_fixture(directory.path());
    let mut plan = plan_binding(&[]);
    plan.image.sha256 =
        mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
            .unwrap();
    let signer_id = "host:test".to_string();
    let signed = sign_plan(
        &plan,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        &signer_id,
    );
    let admitted =
        AdmittedPlan::for_test(plan, signer_id, signed).with_assurance_runtime_for_test(&config);
    admitted.verify_assurance_launch(&config, None).unwrap();
    for mutation in 0..3 {
        let mut changed = config.clone();
        let proof = changed.legacy_portable_runtime.as_mut().unwrap();
        match mutation {
            0 => proof.pin.bundle_sha256 = "0".repeat(64),
            1 => proof.manifest_sha256 = "0".repeat(64),
            2 => {
                let copy = directory.path().join("same-signed-archive.mvmpkg");
                std::fs::copy(&proof.archive, &copy).unwrap();
                proof.archive = copy;
                // An independently valid proof at another location still
                // changes the selection this capability admitted.
                AssuranceRuntimeBinding::verify(&changed, admitted.plan(), None).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            admitted.verify_assurance_launch(&changed, None).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn entrypoint_portable_selection_rechecks_original_closure_before_mock_dispatch() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let directory = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let mut config = mvm_runtime::signed_legacy_portable_runtime_fixture(directory.path());
    config.name = "entrypoint-portable".into();
    let image_sha =
        mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
            .expect("fixture rootfs");
    let mut synthesis = fixture_input(&config.name);
    synthesis.image_sha256 = &image_sha;
    let admitted = admit_for_run(
        &synthesis,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("portable closure admitted");
    let started = start_entrypoint(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config: config.clone(),
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
    )
    .expect("original portable selection starts through admitted executor");
    assert_eq!(started.vm_id.0, config.name);
    backend.stop(&started.vm_id).expect("stop mock");

    config.name = "entrypoint-portable-tampered".into();
    let mut synthesis = fixture_input(&config.name);
    synthesis.image_sha256 = &image_sha;
    let admitted = admit_for_run(
        &synthesis,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("second portable closure admitted");
    config
        .legacy_portable_runtime
        .as_mut()
        .expect("portable proof")
        .manifest_sha256 = "0".repeat(64);
    let refused = start_entrypoint(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config: config.clone(),
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
    )
    .expect_err("tampered portable manifest must refuse before mock start");
    assert!(
        format!("{refused:#}").contains("guest-runtime"),
        "{refused:#}"
    );
    assert!(
        !matches!(
            backend.status(&VmId(config.name)),
            Ok(mvm_core::vm_backend::VmStatus::Running)
        ),
        "refusal cannot boot an unverified portable selection"
    );
}

#[test]
fn admit_and_start_admits_then_boots_on_mock() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-boot".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let started = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-boot"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: None,
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect("admit + boot");

    // Admission ran (claim 8): a signed plan id under the host signer.
    assert!(!started.admitted.plan_id().0.is_empty());
    assert!(started.admitted.signer_id().starts_with("host:"));
    // The backend actually started the VM and reports it running.
    assert_eq!(started.vm_id.0, "vm-boot");
    assert!(matches!(
        backend.status(&started.vm_id).unwrap(),
        mvm_core::vm_backend::VmStatus::Running
    ));
}

#[test]
fn pre_reserved_admission_consumes_the_same_final_host_slot() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let config = mvm_core::user_config::MvmConfig {
        host_budget_memory_mib: Some(256),
        ..Default::default()
    };
    mvm_core::user_config::save(&config, None).unwrap();
    let permit = crate::admission_budget::HostBudgetPermit::reserve(
        "preheld",
        crate::admission_budget::charge_for(256, &Default::default()),
    )
    .unwrap();
    permit.bind_coordinator(&"a".repeat(64)).unwrap();
    let id = permit.id().to_owned();
    let plan = mvm_core::plan::synthesize_plan(&fixture_input("preheld")).unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let keys = tempfile::tempdir().unwrap();
    let ledger = InMemoryNonceLedger::new();
    let admitted = admit_plan_for_run_with_host_permit(HostPermitAdmission {
        plan: &plan,
        clock: &SystemClock,
        ledger: &ledger,
        host_signer_keys_dir: Some(keys.path()),
        bundle_ctx: None,
        extension_ctx: None,
        posture: RunPosture::on_backend(Variant::Dev, backend.kind()),
        host_permit: permit,
    })
    .expect("the existing hold, not a second charge, admits the child");
    assert_eq!(admitted.host_budget_id(), id);
    let started = start_admitted(StartAdmittedParams {
        backend: &backend,
        admitted,
        config: VmStartConfig {
            name: "preheld".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        },
        policy_bundle: None,
        emitter: None,
        assurance: None,
    })
    .unwrap();
    assert_eq!(started.admitted.host_budget_id(), id);
    assert!(
        crate::admission_budget::HostBudgetPermit::reserve(
            "ordinary",
            crate::admission_budget::charge_for(256, &Default::default()),
        )
        .is_err(),
        "ordinary launches see the actor's host hold"
    );
}

#[test]
fn one_signed_admission_cannot_start_a_second_backend() {
    // `start_admitted` hands the admitted plan back on `StartedMachine`.
    // Nothing may turn that into a second launch under the same admission.
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let first = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let second = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let config = VmStartConfig {
        name: "single-use-admission".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, first.kind()),
    )
    .unwrap();
    let started = start_entrypoint(
        StartAdmittedParams {
            backend: &first,
            admitted,
            config: config.clone(),
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
    )
    .expect("the entrypoint consumes the original admission on the first backend");
    let persisted = crate::audit::plan_persist::read_plan(&config.name)
        .expect("entrypoint lifecycle plan is persisted even without a bridge");
    assert_eq!(persisted.plan_id, started.admitted.plan_id().clone());

    // A different backend instance, so a duplicate-name refusal cannot
    // mask a second dispatch under the original admission.
    let error = start_admitted(StartAdmittedParams {
        backend: &second,
        admitted: started.admitted,
        config,
        policy_bundle: None,
        emitter: None,
        assurance: None,
    })
    .expect_err("a spent admission must refuse a second dispatch");
    assert!(
        error.to_string().contains("already dispatched"),
        "{error:#}"
    );
    assert!(!matches!(
        second.status(&started.vm_id),
        Ok(mvm_core::vm_backend::VmStatus::Running)
    ));
}

#[test]
fn entrypoint_failed_grant_rollback_remains_unsealed_when_stop_is_unconfirmed() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();
    let audit = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::Mock(
        mvm_runtime::mock::MockBackend::new()
            .with_failing_apply_grants()
            .with_failing_stop(),
    );
    let config = VmStartConfig {
        name: "entrypoint-uncertain-stop".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()),
    )
    .unwrap();
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[51; 32]),
        audit.path(),
    )
    .unwrap();
    let error = start_entrypoint(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config: config.clone(),
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: None,
        },
        None,
    )
    .expect_err("grant application and rollback both fail");
    assert!(matches!(
        error.downcast_ref::<CliStartFailure>(),
        Some(CliStartFailure::UncertainStop(_))
    ));
    assert!(matches!(
        backend.status(&mvm_core::vm_backend::VmId(config.name)),
        Ok(mvm_core::vm_backend::VmStatus::Running)
    ));
    let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap_or_default();
    assert!(!chain.contains("plan.failed"), "{chain}");
    assert!(!chain.contains("session.sealed"), "{chain}");
    assert!(!chain.contains("plan.launched"), "{chain}");
}

#[test]
fn owned_entrypoint_refuses_a_mock_without_spending_or_losing_admission() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let mut config = VmStartConfig {
        name: "owned-refuses-mock".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let mut admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()),
    )
    .expect("mock admission");
    let original_id = admitted.plan_id().clone();
    let mut built = None;
    let mut runtime = None;
    let error = start_owned_entrypoint(
        &backend,
        &mut admitted,
        &mut config,
        None,
        None,
        &mut built,
        &mut runtime,
    )
    .expect_err("a mock backend cannot impersonate an owned HVF runtime");
    assert!(error.to_string().contains("requires HVF"), "{error:#}");
    assert_eq!(admitted.plan_id(), &original_id);
    assert!(runtime.is_none(), "refusal must not create a native child");
    assert!(built.is_none(), "refusal must not freeze an image");
    let started = start_admitted(StartAdmittedParams {
        backend: &backend,
        admitted,
        config,
        policy_bundle: None,
        emitter: None,
        assurance: None,
    })
    .expect("pre-dispatch refusal must not spend the original admission");
    assert_eq!(started.vm_id.0, "owned-refuses-mock");
}

#[test]
fn persistent_dispatch_defers_acceptance_and_spends_the_admission() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let audit = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let second = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let config = VmStartConfig {
        name: "persistent-dispatch".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()),
    )
    .unwrap();
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[42; 32]),
        audit.path(),
    )
    .unwrap();
    let started = start_persistent(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config: config.clone(),
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: None,
        },
        None,
        Vec::new(),
    )
    .expect("persistent dispatch starts without accepting");
    assert_eq!(started.vm_id.0, config.name);
    assert!(
        config.plan_json.is_none(),
        "the source config is not yet bound to the admitted plan"
    );
    let dispatched_plan =
        mvm_core::plan::plan_from_admitted_json(started.config.plan_json.as_deref().unwrap())
            .expect("the backend and post-start mailbox receive the admitted envelope");
    assert_eq!(dispatched_plan.plan_id, started.admitted.plan_id().clone());
    assert!(matches!(
        backend.status(&started.vm_id).unwrap(),
        mvm_core::vm_backend::VmStatus::Running
    ));
    let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap_or_default();
    assert!(!chain.contains("plan.launched"), "{chain}");

    let error = match start_persistent(
        StartAdmittedParams {
            backend: &second,
            admitted: started.admitted,
            config,
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: None,
        },
        None,
        Vec::new(),
    ) {
        Ok(_) => panic!("a persistent admission cannot dispatch again"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("already dispatched"),
        "{error:#}"
    );
    assert!(!matches!(
        second.status(&started.vm_id),
        Ok(mvm_core::vm_backend::VmStatus::Running)
    ));
}

#[test]
fn persistent_dispatch_refuses_a_share_added_after_admission() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let mut config = VmStartConfig {
        name: "persistent-unadmitted-share".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()),
    )
    .unwrap();
    config.volumes.push(mvm_core::vm_backend::VmVolume {
        host: "/store/unadmitted-share".into(),
        guest: "/mnt/unadmitted".into(),
        read_only: true,
        kind: mvm_core::vm_backend::VmVolumeKind::Disk,
        ..Default::default()
    });
    let vm_id = mvm_core::vm_backend::VmId(config.name.clone());
    let error = match start_persistent(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config,
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
        Vec::new(),
    ) {
        Ok(_) => panic!("an unadmitted share must refuse before dispatch"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("admitted-shares"), "{error:#}");
    assert!(!matches!(
        backend.status(&vm_id),
        Ok(mvm_core::vm_backend::VmStatus::Running)
    ));
}

#[test]
fn a_campaign_that_cannot_open_rolls_the_launch_back() {
    // The session opens *after* the backend start, so a failure there used
    // to return with the workload still running.
    //
    // The campaign declares no destination, which `open` refuses whether or
    // not a plane happens to be installed. Asserting on the absence of the
    // process-global plane instead would make this test depend on run
    // order — a `OnceLock` admits one value and the neighbouring test
    // installs it, so it would pass under nextest and flake under
    // `cargo test`.
    use std::sync::Arc;

    use mvm_contract::assurance::{
        ApprovalSet, AssuranceId, ObservationScope, RequestedAuthority, Sha256Digest, ToolId,
    };

    use crate::assurance_session::{CampaignDeclaration, CampaignRequest, default_policy_ceiling};

    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let audit = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let emitter = Arc::new(
        crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]),
            audit.path(),
        )
        .expect("emitter"),
    );
    let id = |raw: &str| AssuranceId::parse(raw).expect("identifier");
    let declaration = CampaignDeclaration {
        request_id: id("mvm-request-rollback"),
        idempotency_key: id("trial-retry-rollback"),
        campaign_id: id("mvm-campaign-9"),
        trial_id: id("trial-9"),
        source_run_id: id("scout-9"),
        source_digest: Sha256Digest::parse(format!("sha256:{}", "5".repeat(64))).expect("digest"),
        artifact_digest: Sha256Digest::parse(format!("sha256:{}", "6".repeat(64)))
            .expect("artifact digest"),
        edges: Vec::new(),
        approvals: ApprovalSet::none().with(ToolId::CampaignProbeV1),
        requested: RequestedAuthority {
            allowed_tools: vec![ToolId::CampaignProbeV1],
            observation_scopes: vec![ObservationScope::HostAuditRefs],
            max_steps: 4,
            max_output_bytes: 4096,
            deadline_unix_ms: 0,
        },
        grant_ttl_ms: 600_000,
    };
    let campaign = CampaignRequest {
        declaration,
        emitter: Arc::clone(&emitter),
        policy_ceiling: default_policy_ceiling(),
        policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
        backend: "mock".to_string(),
        now_unix_ms: 1_800_000_000_000,
    };

    let service =
        mvm_core::protocol::broker::ServiceId::parse("host.assurance.v1").expect("service id");
    let mut synthesis = fixture_input("vm-rollback");
    synthesis.services = vec![service];
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-rollback".into(),
        ..baked_assurance_config(dir.path())
    };
    let image_sha256 =
        mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
            .expect("fixture digest");
    synthesis.image_sha256 = &image_sha256;

    let err = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &synthesis,
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: Some(&campaign),
        },
    )
    .expect_err("a campaign declaring no destination cannot open");
    // Deliberately not asserted on the message: which refusal fires
    // depends on whether a neighbouring test installed the process-global
    // plane first (`NoPlane`) or not (`NoEdges`). Both roll the launch
    // back, and the rollback is the property under test.
    let _ = &err;

    // The whole point: no workload is left running behind the failure.
    assert!(
        !matches!(
            backend.status(&mvm_core::vm_backend::VmId("vm-rollback".into())),
            Ok(mvm_core::vm_backend::VmStatus::Running)
        ),
        "a campaign that could not open must not leave the VM up"
    );
}

#[test]
fn a_declared_campaign_opens_its_session_on_the_boot_path() {
    // The production seam: `admit_and_start` is what a run goes through,
    // and a declared campaign has to become a live session there rather
    // than in a test that hand-built one. The broker-handler tests may
    // already have installed the process-global plane, so this test uses
    // that legitimate instance when running in parallel.
    use std::sync::Arc;

    use mvm_contract::assurance::{
        ApprovalSet, AssuranceId, ObservationScope, RequestedAuthority, Sha256Digest, ToolId,
    };

    use crate::assurance_session::{
        CampaignDeclaration, CampaignRequest, DeclaredEdge, default_policy_ceiling,
        host_assurance_plane, install_host_assurance_plane,
    };
    use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;

    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let audit = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();

    let plane = Arc::new(HostAssuranceV1Handler::new());
    let _ = install_host_assurance_plane(Arc::clone(&plane));

    let emitter = Arc::new(
        crate::audit::emitter::AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]),
            audit.path(),
        )
        .expect("emitter")
        .with_receipts(),
    );
    let id = |raw: &str| AssuranceId::parse(raw).expect("identifier");
    let declaration = CampaignDeclaration {
        request_id: id("mvm-request-1"),
        idempotency_key: id("trial-retry-1"),
        campaign_id: id("mvm-campaign-1"),
        trial_id: id("trial-1"),
        source_run_id: id("scout-1"),
        source_digest: Sha256Digest::parse(format!("sha256:{}", "3".repeat(64))).expect("digest"),
        artifact_digest: Sha256Digest::parse(format!("sha256:{}", "b".repeat(64)))
            .expect("artifact digest"),
        edges: vec![DeclaredEdge {
            label: id("undeclared.synthetic.destination"),
            host: "attacker.example.com".to_string(),
            port: 443,
        }],
        approvals: ApprovalSet::none().with(ToolId::CampaignProbeV1),
        requested: RequestedAuthority {
            allowed_tools: vec![ToolId::CampaignProbeV1],
            observation_scopes: vec![ObservationScope::HostAuditRefs],
            max_steps: 4,
            max_output_bytes: 4096,
            deadline_unix_ms: 0,
        },
        grant_ttl_ms: 600_000,
    };
    let now_unix_ms = 1_800_000_000_000;
    let campaign = CampaignRequest {
        declaration,
        emitter: Arc::clone(&emitter),
        policy_ceiling: default_policy_ceiling(),
        policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
        backend: "mock".to_string(),
        now_unix_ms,
    };

    let service =
        mvm_core::protocol::broker::ServiceId::parse("host.assurance.v1").expect("service id");
    let mut synthesis = fixture_input("vm-assurance");
    synthesis.services = vec![service];
    struct Trust(ed25519_dalek::VerifyingKey);
    impl mvm_core::packs::PackTrustStore for Trust {
        fn verifying_key(
            &self,
            _key_id: &mvm_core::plan::bundle::KeyId,
        ) -> Option<ed25519_dalek::VerifyingKey> {
            Some(self.0)
        }
    }
    struct Revocations;
    impl mvm_core::packs::PackRevocationChecker for Revocations {
        fn status(
            &self,
            _key_id: &mvm_core::plan::bundle::KeyId,
            _pack_hash: &mvm_core::packs::Sha256Hex,
        ) -> mvm_core::packs::RevocationStatus {
            mvm_core::packs::RevocationStatus::Good
        }
    }
    let staged = tempfile::tempdir().expect("extension staging");
    std::fs::write(
        staged.path().join("extension.ext4"),
        b"fixture extension filesystem",
    )
    .expect("write extension artifact");
    let pack_key = ed25519_dalek::SigningKey::from_bytes(&[45; 32]);
    let pack_policy_hash = mvm_core::packs::Sha256Hex::from_bytes(b"extension-policy");
    let pack_metadata = mvm_core::packs::PackMetadata {
        kind: mvm_core::packs::PackKind::Extension,
        target_arch: mvm_core::arch::GuestArch::host(),
        backend_compatibility: vec![mvm_core::packs::PackBackend::Firecracker],
        required_host_capabilities: vec![mvm_core::packs::HostCapability("vsock".to_string())],
        policy_compatibility: mvm_core::packs::PolicyCompatibility {
            policy_hash: pack_policy_hash.clone(),
            local_rebuild_required: false,
            allowed_channels: vec!["stable".to_string()],
        },
        inputs: mvm_core::packs::PackInputs {
            flake_locks: Vec::new(),
            derivations: Vec::new(),
            nar_hashes: Vec::new(),
            oci_images: Vec::new(),
            setup_commands: Vec::new(),
            source_revisions: Vec::new(),
            toolchain_versions: Default::default(),
        },
        provenance: mvm_core::packs::PackProvenanceMeta {
            builder_identity: "assurance-release".to_string(),
            build_environment_identity: "test".to_string(),
            build_timestamp: Utc::now(),
            reproducibility: mvm_core::packs::ReproducibilityStatus::NotChecked,
            sbom: mvm_core::packs::SbomReference {
                uri: "urn:sbom:extension".to_string(),
                sha256: mvm_core::packs::Sha256Hex::from_bytes(b"sbom"),
            },
        },
        trust: mvm_core::packs::PackTrustMeta {
            expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            revocation_channel: "https://example.invalid/revocations".to_string(),
            channel_identity: "stable".to_string(),
            mirror_identity: None,
            transparency_log: None,
        },
        signature: mvm_core::packs::SignatureValidity {
            signed_at: Utc::now(),
            expires_at: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
        },
    };
    let extension_budgets = mvm_contract::protocol::extension_pack::ExtensionBudgets {
        cpu_millis: 500,
        memory_bytes: 128 * 1024 * 1024,
        duration_ms: 600_000,
        max_steps: 12,
        max_concurrency: 1,
        max_payload_bytes: 16 * 1024,
        max_output_bytes: 16 * 1024,
        max_artifact_bytes: 1024 * 1024,
    };
    let contract = mvm_contract::protocol::extension_pack::ExtensionPackContract {
        schema: mvm_contract::protocol::extension_pack::EXTENSION_PACK_SCHEMA.to_string(),
        extension_id: mvm_contract::protocol::extension_pack::ExtensionId::parse(
            "org.example.assurance-extension",
        )
        .expect("extension id"),
        version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse("1.0.0")
            .expect("extension version"),
        protocol: mvm_contract::protocol::extension_pack::ExtensionProtocolRange {
            min_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(
                "0.18.0",
            )
            .expect("minimum version"),
            max_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(env!(
                "CARGO_PKG_VERSION"
            ))
            .expect("maximum version"),
            min_protocol: 1,
            max_protocol: 1,
        },
        placement: mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
        artifact: "extension.ext4".to_string(),
        entrypoint: "bin/assurance-extension".to_string(),
        capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
        budgets: extension_budgets,
        revocation_identity: "org.example.assurance-extension.release".to_string(),
        permission_delta: "May execute one declared assurance probe.".to_string(),
    };
    let manifest = mvm_core::packs::PackBuilder::new(staged.path(), pack_metadata, &pack_key)
        .file("extension.ext4")
        .extension(contract)
        .build()
        .expect("build signed extension pack");
    let pack_policy = mvm_core::packs::LocalPackPolicy {
        host_arch: mvm_core::arch::GuestArch::host(),
        backend: mvm_core::packs::PackBackend::Firecracker,
        host_capabilities: [mvm_core::packs::HostCapability("vsock".to_string())]
            .into_iter()
            .collect(),
        policy_hash: pack_policy_hash,
        allowed_channels: ["stable".to_string()].into_iter().collect(),
        now: Utc::now(),
    };
    let trust = Trust(pack_key.verifying_key());
    let revocations = Revocations;
    let verify = mvm_core::pack_cache::PackVerifyCtx::ed25519(&pack_policy, &trust, &revocations);
    let promoted = mvm_core::pack_cache::promote(staged.path(), &manifest, &verify)
        .expect("promote extension pack");
    let capability = mvm_contract::assurance::probe_capability_descriptor().id;
    let authority = std::collections::HashSet::from([capability]);
    let placements = std::collections::BTreeSet::from([
        mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
    ]);
    let extension = crate::extension_admission::admit_extension(
        &manifest,
        &promoted.verified,
        crate::extension_admission::ExtensionAuthority {
            requested: &authority,
            policy_ceiling: &authority,
            session_grant: &authority,
            explicit_approval: &authority,
        },
        crate::extension_admission::ExtensionAdmissionPolicy {
            placements: &placements,
            budgets: extension_budgets,
        },
    )
    .expect("admit extension authority");
    synthesis.extensions = vec![extension];
    synthesis.agent_verbs = Some(vec![
        mvm_contract::plan::VerbId::new("run-extension").expect("extension verb"),
        mvm_contract::plan::VerbId::new("cancel-extension").expect("extension verb"),
    ]);
    synthesis
        .audit_labels
        .insert("assurance.source_run_id".to_string(), "scout-1".to_string());
    synthesis.audit_labels.insert(
        "assurance.source_digest".to_string(),
        format!("sha256:{}", "3".repeat(64)),
    );
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-assurance".into(),
        ..baked_assurance_config(dir.path())
    };
    let image_sha256 =
        mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(&config.rootfs_path))
            .expect("fixture digest");
    synthesis.image_sha256 = &image_sha256;

    let started = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &synthesis,
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: Some(&ExtensionAdmissionContext::ambient(&verify)),
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: Some(&campaign),
        },
    )
    .expect("admit + boot with a declared campaign");

    let plane = host_assurance_plane().expect("the plane this test installed");
    let binding = plane
        .binding_for(&started.vm_id.0)
        .expect("the boot path opened a session for this VM");
    // The binding renders the content address in the counterparty's
    // identifier grammar; it still names exactly this plan.
    assert_eq!(
        binding.plan_id.as_str(),
        started.admitted.plan_id().0.replace(':', "-")
    );
    assert_eq!(binding.runtime.backend.as_str(), "mock");
    // Its citations came from real emission on the boot path.
    assert!(!binding.audit_refs.is_empty());
    assert!(!binding.receipt_refs.is_empty());

    let mut refused_synthesis = synthesis.clone();
    refused_synthesis.vm_name = "vm-assurance-refused";
    refused_synthesis
        .audit_labels
        .remove("assurance.source_digest");
    let refusal = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &refused_synthesis,
            config: mvm_core::vm_backend::VmStartConfig {
                name: "vm-assurance-refused".into(),
                ..baked_assurance_config(dir.path())
            },
            clock: &SystemClock,
            ledger: &InMemoryNonceLedger::new(),
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: Some(&ExtensionAdmissionContext::ambient(&verify)),
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: Some(&campaign),
        },
    )
    .expect_err("an assurance launch without its admitted service must fail");
    assert!(
        refusal
            .to_string()
            .contains("does not bind the campaign source identity")
    );
    assert!(
        matches!(
            backend.status(&mvm_core::vm_backend::VmId(
                "vm-assurance-refused".to_string()
            )),
            Ok(mvm_core::vm_backend::VmStatus::Stopped)
        ),
        "a post-start assurance refusal must roll the VM back"
    );
}

/// The bound the backend spawns under comes off the signed plan, and only
/// off the signed plan. A caller-supplied one would be a bound chosen
/// outside the admission that just measured it against the host's ceiling.
#[test]
fn the_admitted_grant_reaches_the_launch_config_and_a_caller_supplied_one_does_not() {
    use mvm_core::vm_backend::VmStartConfig;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let mut input = fixture_input("vm-grant-threaded");
    let grants = mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
        ..Default::default()
    };
    input.grants = Some(grants);
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("admit");

    let mut cfg = VmStartConfig {
        // A bound nobody admitted, planted by the caller.
        cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
        ..VmStartConfig::default()
    };
    thread_cpu_grant(&mut cfg, &admitted);
    assert_eq!(
        cfg.cpu_grant,
        Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
        "the launch must carry the admitted bound, not the caller's"
    );
}

/// An uncapped plan must clear a planted bound rather than leave it: a
/// launch config is not a place to smuggle a control past admission.
#[test]
fn an_ungranted_plan_clears_a_caller_supplied_bound() {
    use mvm_core::vm_backend::VmStartConfig;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let admitted = admit_for_run(
        &fixture_input("vm-no-grant"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("admit");

    let mut cfg = VmStartConfig {
        cpu_grant: Some(mvm_contract::grants::CpuGrant::Share { millicores: 64_000 }),
        ..VmStartConfig::default()
    };
    thread_cpu_grant(&mut cfg, &admitted);
    assert_eq!(cfg.cpu_grant, None);
}

/// Every admitted boot leaves a record of what actually bounded it. Before
/// this, `apply_grants` was reachable only from a launch path with no
/// production implementation, so a real boot recorded nothing at all — and
/// a bound nobody reports is indistinguishable from a bound nobody applied.
#[test]
fn an_admitted_boot_records_the_tier_that_bounded_it() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-tiers".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let started = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-tiers"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: None,
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect("admit + boot");

    // The mock bounds nothing, and says so rather than claiming a tier it
    // has no mechanism for.
    assert_eq!(started.enforced_grants, EnforcedGrants::all_declared());
    assert!(!started.enforced_grants.cpu.is_enforced());
}

/// The budget gate every later admission measures against sums these
/// per-VM records; a boot that never wrote one was invisible to it. The
/// charge is the plan's configured memory — the same figure the balloon
/// may not exceed — and a plan that declared no CPU bound commits none.
#[test]
fn an_admitted_boot_records_its_charge_for_the_host_budget() {
    let (_env, home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-charge".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-charge"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: None,
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect("admit + boot");

    let record =
        mvm_core::config::vm_state_dir_at(home.path(), "vm-charge").join("admitted-charge.json");
    let bytes = std::fs::read(&record).expect("the charge record is written");
    let charge: mvm_contract::grants::budget::MachineCharge =
        serde_json::from_slice(&bytes).expect("the charge record parses");
    assert_eq!(
        charge.memory_mib, 256,
        "the fixture plan grants 256 MiB: {charge:?}"
    );
    assert_eq!(
        charge.cpu_millicores, 0,
        "the fixture declares no CPU bound: {charge:?}"
    );
}

/// A boot whose charge cannot be recorded must not stay up: the host's
/// committed total would undercount by exactly the machine nobody can
/// see. The VM is stopped and the refusal lands on the chain at the
/// host-budget stage.
#[test]
fn a_boot_whose_charge_cannot_be_recorded_rolls_back() {
    let (_env, home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let audit = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]),
        audit.path(),
    )
    .expect("emitter");
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-charge-blocked".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };

    let admitted = admit_for_run(
        &fixture_input("vm-charge-blocked"),
        &SystemClock,
        &ledger,
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()),
    )
    .expect("reserve host capacity before the write failure");
    // Allow shared launch preparation to persist the plan, but block the
    // post-start charge record: that failure must still stop the VM.
    let record = mvm_core::config::vm_state_dir_at(home.path(), "vm-charge-blocked")
        .join("admitted-charge.json");
    std::fs::create_dir_all(&record).expect("charge record blocker");
    start_admitted(StartAdmittedParams {
        backend: &backend,
        admitted,
        config,
        policy_bundle: None,
        emitter: Some(&emitter),
        assurance: None,
    })
    .expect_err("a boot whose charge cannot be recorded must not proceed");

    // The whole point: no workload is left running behind the failure.
    assert!(
        !matches!(
            backend.status(&mvm_core::vm_backend::VmId("vm-charge-blocked".into())),
            Ok(mvm_core::vm_backend::VmStatus::Running)
        ),
        "the VM whose charge could not be recorded is stopped"
    );
    let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).expect("chain written");
    assert!(
        chain.contains("plan.failed") && chain.contains("host-budget"),
        "the refusal is on the chain, naming the host-budget stage: {chain}"
    );
}

/// The achieved tier reaches the chain-signed log, not just the return
/// value — an operator answering "was this run bounded?" from the audit
/// trail alone must not have to take the caller's word for it.
#[test]
fn an_admitted_boot_writes_the_achieved_tier_to_the_audit_chain() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-tier-audit".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let audit_dir = dir.path().join("audit");
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&seed),
        &audit_dir,
    )
    .expect("emitter");

    admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-tier-audit"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect("admit + boot");

    let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("chain written");
    assert!(
        chain.contains("plan.grants_enforced"),
        "the achieved tier must be on the chain: {chain}"
    );
    assert!(
        chain.contains("grants_cpu_tier"),
        "the CPU dimension must be named: {chain}"
    );
    // The spawn ceilings are written beside the CPU tier even when nothing
    // held them: the mock backend has no scope, so both say `declared` and
    // neither carries a number that could be read as a bound.
    assert!(
        chain.contains("grants_memory_tier") && chain.contains("grants_tasks_tier"),
        "the memory and task dimensions must be named: {chain}"
    );
    assert!(
        !chain.contains("grants_memory_max_bytes") && !chain.contains("grants_tasks_max"),
        "a declared ceiling must not carry a value: {chain}"
    );
}

#[cfg(unix)]
#[test]
fn cli_transient_defers_launch_narrative_without_readmitting() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    let backend = mvm_runtime::AnyBackend::Mock(
        mvm_runtime::mock::MockBackend::new().with_failing_apply_grants(),
    );
    let config = VmStartConfig {
        name: "cli-transient-deferred".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission");
    let vm_name = config.name.clone();
    let audit_dir = dir.path().join("audit");
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[42; 32]),
        &audit_dir,
    )
    .expect("emitter");
    crate::audit::durability::record_admission(
        Some(&emitter),
        admitted.plan(),
        admitted.signer_id(),
        crate::audit::durability::AuditDurability::BestEffort,
    )
    .expect("admission record");
    let started = start_cli_transient(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config,
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: None,
        },
        None,
        Vec::new(),
    )
    .expect("start without another admission");
    assert_eq!(started, VmId(vm_name.clone()));
    let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("audit chain");
    assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
    assert!(!chain.contains("plan.launched"), "{chain}");
    assert!(!chain.contains("plan.grants_enforced"), "{chain}");
    assert!(
        !mvm_core::config::vm_state_dir(&vm_name)
            .join("admitted-charge.json")
            .exists(),
        "CLI cold start does not add a host-budget charge"
    );
    backend.stop(&started).expect("stop mock VM");
}

#[cfg(unix)]
#[test]
fn a_placed_cli_transient_whose_scope_reads_back_no_cpuset_is_stopped() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    // The mock reports every dimension declared, so its read-back holds no
    // cpuset: exactly what a scope that ignored `AllowedCPUs=` looks like.
    let backend = mvm_runtime::AnyBackend::Mock(mvm_runtime::mock::MockBackend::new());
    let config = VmStartConfig {
        name: "cli-transient-placed".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission")
    .with_allowed_cpus_for_test(mvm_contract::protocol::cpu_set::CpuSet::parse("2-3").unwrap());
    let vm_name = config.name.clone();
    let error = start_cli_transient(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config,
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
        Vec::new(),
    )
    .expect_err("a placement that did not hold refuses the start");
    assert!(
        format!("{error:#}").contains("reads back no cpuset"),
        "{error:#}"
    );
    assert_eq!(
        backend.status(&VmId(vm_name)).expect("status"),
        mvm_core::vm_backend::VmStatus::Stopped,
        "the started VM is rolled back"
    );
}

#[cfg(unix)]
#[test]
fn fs_quick_fork_spends_one_admission_without_immediate_acceptance() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    let backend = mvm_runtime::AnyBackend::Mock(
        mvm_runtime::mock::MockBackend::new().with_failing_apply_grants(),
    );
    let config = VmStartConfig {
        name: "fs-quick-one-use".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission");
    let vm_name = config.name.clone();
    let started = start_fs_quick_fork(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config,
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
    )
    .expect("fork reaches mock without calling immediate grant acceptance");
    assert_eq!(started, VmId(vm_name.clone()));
    assert!(
        !mvm_core::config::vm_state_dir(&vm_name)
            .join("admitted-charge.json")
            .exists(),
        "fork does not introduce immediate host budget charging"
    );
    backend.stop(&started).expect("stop mock VM");
}

#[cfg(unix)]
#[test]
fn fs_quick_fork_refuses_unadmitted_share_before_backend_start() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let config = VmStartConfig {
        name: "fs-quick-refusal".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission");
    let changed = VmStartConfig {
        volumes: vec![mvm_core::vm_backend::VmVolume {
            host: "/store/unadmitted-share".into(),
            guest: "/mnt/unadmitted".into(),
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            materialized_image: None,
            volume_label: None,
            encrypted: false,
            share_include: Vec::new(),
            share_exclude: Vec::new(),
        }],
        ..config
    };
    let error = start_fs_quick_fork(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config: changed,
            policy_bundle: None,
            emitter: None,
            assurance: None,
        },
        None,
    )
    .expect_err("unadmitted share refuses before backend start");
    assert!(
        error.to_string().contains("admission gate refused"),
        "{error:#}"
    );
    assert!(
        backend.list().expect("mock list").is_empty(),
        "refused fork must not start the backend"
    );
}

#[cfg(unix)]
#[test]
fn cli_transient_gate_refusal_leaves_cli_failure_audit_to_the_caller() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let config = VmStartConfig {
        name: "cli-transient-refusal".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission");
    let audit_dir = dir.path().join("audit");
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[43; 32]),
        &audit_dir,
    )
    .expect("emitter");
    crate::audit::durability::record_admission(
        Some(&emitter),
        admitted.plan(),
        admitted.signer_id(),
        crate::audit::durability::AuditDurability::BestEffort,
    )
    .expect("admission record");
    let changed = VmStartConfig {
        volumes: vec![mvm_core::vm_backend::VmVolume {
            host: "/store/unadmitted-share".into(),
            guest: "/mnt/unadmitted".into(),
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            materialized_image: None,
            volume_label: None,
            encrypted: false,
            share_include: Vec::new(),
            share_exclude: Vec::new(),
        }],
        ..config
    };
    let error = start_cli_transient(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config: changed,
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: None,
        },
        None,
        Vec::new(),
    )
    .expect_err("unadmitted share must refuse");
    assert!(error.is::<CliStartFailure>(), "{error:#}");
    let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("audit chain");
    assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
    assert_eq!(chain.matches("plan.failed").count(), 0, "{chain}");
    assert!(!chain.contains("plan.launched"), "{chain}");
}

#[cfg(unix)]
#[test]
fn admitted_cli_cold_backends_refuse_unadmitted_shares_before_any_boot() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    for selector in ["wasm", "web-linux", "apple-container", "qemu"] {
        let backend = mvm_runtime::AnyBackend::from_hypervisor(selector);
        let config = VmStartConfig {
            name: format!("cli-cold-{selector}"),
            rootfs_path: "/store/rootfs.ext4".into(),
            volumes: vec![mvm_core::vm_backend::VmVolume {
                host: "/store/unadmitted-share".into(),
                guest: "/mnt/unadmitted".into(),
                read_only: true,
                kind: mvm_core::vm_backend::VmVolumeKind::Disk,
                ..Default::default()
            }],
            ..Default::default()
        };
        let admitted = admit_for_run(
            &fixture_input(&config.name),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(dir.path()),
            None,
            RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
        )
        .expect("signed admission");
        let error = start_cli_transient(
            StartAdmittedParams {
                backend: &backend,
                admitted,
                config: config.clone(),
                policy_bundle: None,
                emitter: None,
                assurance: None,
            },
            None,
            Vec::new(),
        )
        .expect_err("unadmitted share must refuse before backend dispatch");
        assert!(
            format!("{error:#}").contains("admitted-shares"),
            "{selector}: {error:#}"
        );
        assert!(
            !mvm_core::config::vm_state_dir(&config.name)
                .join("plan.json")
                .exists(),
            "{selector} must not reach bridge or backend start"
        );
    }
}

#[cfg(unix)]
#[test]
fn cli_transient_backend_start_refusal_leaves_cli_failure_audit_to_the_caller() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let config = VmStartConfig {
        name: "cli-transient-start-refusal".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let already_running = backend.start(&config).expect("mock occupied name");
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission");
    let audit_dir = dir.path().join("audit");
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[45; 32]),
        &audit_dir,
    )
    .expect("emitter");
    crate::audit::durability::record_admission(
        Some(&emitter),
        admitted.plan(),
        admitted.signer_id(),
        crate::audit::durability::AuditDurability::BestEffort,
    )
    .expect("admission record");
    let error = start_cli_transient(
        StartAdmittedParams {
            backend: &backend,
            admitted,
            config,
            policy_bundle: None,
            emitter: Some(&emitter),
            assurance: None,
        },
        None,
        Vec::new(),
    )
    .expect_err("backend duplicate start must refuse");
    assert!(
        matches!(
            error.downcast_ref::<CliStartFailure>(),
            Some(CliStartFailure::Unrecorded(_))
        ),
        "{error:#}"
    );
    let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("audit chain");
    assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
    assert_eq!(chain.matches("plan.failed").count(), 0, "{chain}");
    assert!(!chain.contains("plan.launched"), "{chain}");
    backend.stop(&already_running).expect("stop mock VM");
}

#[cfg(unix)]
#[test]
fn cli_transient_uncertain_rollback_never_records_completed_failure() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().expect("test directory");
    let backend =
        mvm_runtime::AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_failing_stop());
    let config = VmStartConfig {
        name: "cli-transient-uncertain".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let admitted = admit_for_run(
        &fixture_input(&config.name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::on_backend(Variant::Dev, backend.kind()).with_runtime(Some(&config)),
    )
    .expect("one admission");
    let audit_dir = dir.path().join("audit");
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&[44; 32]),
        &audit_dir,
    )
    .expect("emitter");
    crate::audit::durability::record_admission(
        Some(&emitter),
        admitted.plan(),
        admitted.signer_id(),
        crate::audit::durability::AuditDurability::BestEffort,
    )
    .expect("admission record");
    let vm_id = backend.start(&config).expect("mock started");
    let error = cli_rollback_error(undo_cli_launch(UndoLaunch {
        backend: &backend,
        vm_id: &vm_id,
        admitted: &admitted,
        emitter: None,
        stage: "mailbox-process",
        reason: "mailbox could not be served",
        err: anyhow::anyhow!("mock mailbox refusal"),
    }));
    assert!(
        matches!(
            error.downcast_ref::<CliStartFailure>(),
            Some(CliStartFailure::UncertainStop(_))
        ),
        "{error:#}"
    );
    let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("audit chain");
    assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
    assert!(!chain.contains("plan.failed"), "{chain}");
    assert!(!chain.contains("plan.launched"), "{chain}");
    assert!(
        matches!(
            backend.status(&VmId(config.name)),
            Ok(mvm_core::vm_backend::VmStatus::Running)
        ),
        "failed rollback retains the VM for custody"
    );
}

/// A backend that cannot apply the admitted grants to the VM it just
/// started must not leave that VM running, and must not leave a
/// `plan.grants_enforced` entry behind: the boot fails at the `grants`
/// stage and the chain says so.
#[test]
fn a_grant_that_cannot_be_applied_undoes_the_launch() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let mock = mvm_runtime::MockBackend::new().with_failing_apply_grants();
    let backend = mvm_runtime::AnyBackend::Mock(mock.clone());
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-grants-fail".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let audit_dir = dir.path().join("audit");
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&seed),
        &audit_dir,
    )
    .expect("emitter");

    let err = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-grants-fail"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect_err("a boot whose grants could not be applied must fail");

    assert!(
        format!("{err:#}").contains("applying the admitted plan's grants"),
        "{err:#}"
    );
    assert_eq!(mock.count(), 0, "the started VM must have been stopped");
    let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("chain written");
    assert!(chain.contains("plan.failed"), "{chain}");
    assert!(
        chain.contains("\"grants\""),
        "the failing stage is named: {chain}"
    );
    assert!(
        !chain.contains("plan.grants_enforced"),
        "no enforcement may be recorded for grants that were never applied: {chain}"
    );
}

/// The end-to-end half of the tier question: `admit_and_start` holds the
/// backend object, so the grant gate must be measuring against *its* kind
/// and not against whatever the plan's profile says.
///
/// The fixture's plan is labelled `firecracker` while the backend booting
/// it is the mock. With a grant declared, that disagreement has to surface
/// — and, because the refusal precedes signing, no VM may exist afterwards.
#[test]
fn admit_and_start_measures_grants_against_the_backend_that_boots() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let mut synthesis = fixture_input("vm-tier-mismatch");
    synthesis.grants = Some(cpu_share(1500));
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-tier-mismatch".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };

    let err = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &synthesis,
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Prod,
            policy_bundle: None,
            emitter: None,
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect_err("the plan's profile and the booting backend disagree");
    let msg = err.to_string();
    assert!(msg.contains("firecracker") && msg.contains("mock"), "{msg}");
    assert_eq!(
        backend
            .status(&mvm_core::vm_backend::VmId("vm-tier-mismatch".into()))
            .expect("the mock reports a status for any name"),
        mvm_core::vm_backend::VmStatus::Stopped,
        "no VM may exist behind a refused admission"
    );
}

/// The point of `AuditDurability::Required`: a run that cannot record its
/// admission does not reach the backend at all.
///
/// Asserting the error is not enough — what matters is that no VM booted,
/// because the failure mode being closed is a workload that ran while
/// leaving no evidence it was ever admitted.
#[test]
fn a_required_admission_record_that_cannot_be_written_stops_the_boot() {
    use crate::audit::durability::AuditDurability;

    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-unauditable".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };

    // A chain whose tenant file cannot be written: a directory sits where
    // the JSONL belongs.
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir(audit_dir.join("local.jsonl")).unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&seed),
        &audit_dir,
    )
    .expect("the emitter opens; writing the tenant file is what fails");

    let err = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-unauditable"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: AuditDurability::Required,
            assurance: None,
        },
    )
    .expect_err("an unauditable sealed run must not boot");
    assert!(
        format!("{err:#}").contains("cannot be proven"),
        "the refusal must explain itself: {err:#}"
    );

    assert!(
        backend.list().expect("mock list").is_empty(),
        "no VM may exist for a run whose admission could not be recorded"
    );
}

/// The same broken chain under the dev tier boots and warns.
#[test]
fn a_best_effort_admission_record_does_not_stop_the_boot() {
    use crate::audit::durability::AuditDurability;

    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-dev-unauditable".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };

    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    std::fs::create_dir(audit_dir.join("local.jsonl")).unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let emitter = crate::audit::emitter::AuditEmitter::with_dir(
        ed25519_dalek::SigningKey::from_bytes(&seed),
        &audit_dir,
    )
    .expect("emitter");

    let started = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-dev-unauditable"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: Some(&emitter),
            audit_durability: AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect("a dev run is not blocked by a broken audit chain");
    assert_eq!(started.vm_id.0, "vm-dev-unauditable");
}

#[test]
fn admit_and_start_refuses_unadmitted_volume_before_boot() {
    use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    // The synthesized plan admits no shares, but the launch config carries a
    // volume — claim 1 must refuse before the backend ever starts.
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-badvol".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        volumes: vec![VmVolume {
            host: "/etc".into(),
            guest: "/data".into(),
            read_only: true,
            kind: VmVolumeKind::Disk,
            materialized_image: Some("/state/mount.ext4".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &fixture_input("vm-badvol"),
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: None,
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect_err("unadmitted volume must refuse");
    assert!(
        err.chain()
            .any(|e| e.to_string().contains("not named in the signed")),
        "expected admitted-shares refusal; got: {err:#}"
    );
    // Crucially: no VM was started (the gate fired before backend.start).
    assert!(matches!(
        backend.status(&VmId("vm-badvol".into())),
        Ok(mvm_core::vm_backend::VmStatus::Stopped)
    ));
}

#[test]
fn admit_and_start_refuses_a_grant_over_the_host_ceiling_and_boots_nothing() {
    let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
        max_cpu_millicores: Some(2000),
        ..Default::default()
    });
    let dir = tempfile::tempdir().unwrap();
    let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
    let ledger = InMemoryNonceLedger::new();
    let mut synthesis = fixture_input("vm-denied");
    synthesis.grants = Some(cpu_share(64_000));
    let config = mvm_core::vm_backend::VmStartConfig {
        name: "vm-denied".into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        ..Default::default()
    };
    let err = admit_and_start(
        &backend,
        AdmitAndStartParams {
            synthesis: &synthesis,
            config,
            clock: &SystemClock,
            ledger: &ledger,
            host_signer_keys_dir: Some(dir.path()),
            bundle_ctx: None,
            extension_ctx: None,
            variant: Variant::Dev,
            policy_bundle: None,
            emitter: None,
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: None,
        },
    )
    .expect_err("a grant over the host ceiling must be refused at admission");
    assert!(
        err.chain().any(|e| e.to_string().contains("ceiling")),
        "expected a ceiling refusal; got: {err:#}"
    );
    assert!(matches!(
        backend.status(&VmId("vm-denied".into())),
        Ok(mvm_core::vm_backend::VmStatus::Stopped)
    ));
    assert!(
        !dir.path()
            .join(crate::audit::host_keypair::SECRET_FILENAME)
            .exists(),
        "a refused launch must not be signed"
    );
}
