#![cfg(test)]

use super::test_support::*;
use super::*;

fn extension_binding(
    placement: mvm_contract::protocol::extension_pack::ExtensionPlacement,
) -> mvm_contract::protocol::extension_pack::ExtensionPlanBinding {
    mvm_contract::protocol::extension_pack::ExtensionPlanBinding {
        extension_id: mvm_contract::protocol::extension_pack::ExtensionId::parse(
            "org.example.generic-extension",
        )
        .expect("valid fixture extension id"),
        version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse("1.0.0")
            .expect("valid fixture extension version"),
        pack_digest: [7; 32],
        contract_digest: [8; 32],
        placement,
        artifact: "extension.ext4".to_string(),
        entrypoint: "bin/extension".to_string(),
        capabilities: vec![mvm_contract::assurance::probe_capability_descriptor().binding()],
        budgets: mvm_contract::protocol::extension_pack::ExtensionBudgets {
            cpu_millis: 500,
            memory_bytes: 128 * 1024 * 1024,
            duration_ms: 30_000,
            max_steps: 12,
            max_concurrency: 1,
            max_payload_bytes: 16 * 1024,
            max_output_bytes: 16 * 1024,
            max_artifact_bytes: 1024 * 1024,
        },
    }
}

fn extension_contract(
    binding: &mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
) -> mvm_contract::protocol::extension_pack::ExtensionPackContract {
    mvm_contract::protocol::extension_pack::ExtensionPackContract {
        schema: mvm_contract::protocol::extension_pack::EXTENSION_PACK_SCHEMA.to_string(),
        extension_id: binding.extension_id.clone(),
        version: binding.version.clone(),
        protocol: mvm_contract::protocol::extension_pack::ExtensionProtocolRange {
            min_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(
                "0.18.0",
            )
            .expect("valid minimum extension version"),
            max_mvm_version: mvm_contract::protocol::extension_pack::ExtensionVersion::parse(env!(
                "CARGO_PKG_VERSION"
            ))
            .expect("valid maximum extension version"),
            min_protocol: 1,
            max_protocol: 1,
        },
        placement: binding.placement,
        artifact: binding.artifact.clone(),
        entrypoint: binding.entrypoint.clone(),
        capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
        budgets: binding.budgets,
        revocation_identity: "org.example.generic-extension.release".to_string(),
        permission_delta: "May execute one declared assurance probe.".to_string(),
    }
}

fn admitted_with_extension(
    binding: mvm_contract::protocol::extension_pack::ExtensionPlanBinding,
    root: &std::path::Path,
) -> AdmittedPlan {
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .extensions(vec![binding.clone()])
        .build();
    let signer_id = "host:extension-test".to_string();
    let signed = mvm_core::plan::signing::sign_plan(
        &plan,
        &ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
        &signer_id,
    );
    let mut admitted = AdmittedPlan::for_test(plan, signer_id, signed);
    admitted.extensions.push(AdmittedExtension {
        binding,
        root: root.to_path_buf(),
    });
    admitted
}

#[test]
fn extension_budget_comparison_requires_every_dimension() {
    let maximum = extension_binding(
        mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
    )
    .budgets;
    assert!(budgets_are_narrower(maximum, maximum));

    let mut candidates = Vec::new();
    let mut candidate = maximum;
    candidate.cpu_millis += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.memory_bytes += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.duration_ms += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.max_steps += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.max_concurrency += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.max_payload_bytes += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.max_output_bytes += 1;
    candidates.push(candidate);
    let mut candidate = maximum;
    candidate.max_artifact_bytes += 1;
    candidates.push(candidate);

    for candidate in candidates {
        assert!(
            !budgets_are_narrower(candidate, maximum),
            "one widened budget dimension must refuse the whole binding"
        );
    }
}

#[test]
fn extension_binding_identity_requires_every_verified_field() {
    let mut binding = extension_binding(
        mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
    );
    let contract = extension_contract(&binding);
    let contract_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&contract).expect("encode extension contract fixture"))
            .into();
    binding.contract_digest = contract_digest;
    assert!(extension_binding_matches_contract(
        &binding,
        &contract,
        contract_digest
    ));

    let mut mismatches = Vec::new();
    let mut mismatch = binding.clone();
    mismatch.extension_id =
        mvm_contract::protocol::extension_pack::ExtensionId::parse("org.example.other")
            .expect("valid alternate extension id");
    mismatches.push(mismatch);
    let mut mismatch = binding.clone();
    mismatch.version = mvm_contract::protocol::extension_pack::ExtensionVersion::parse("1.0.1")
        .expect("valid alternate extension version");
    mismatches.push(mismatch);
    let mut mismatch = binding.clone();
    mismatch.contract_digest[0] ^= 1;
    mismatches.push(mismatch);
    let mut mismatch = binding.clone();
    mismatch.placement =
        mvm_contract::protocol::extension_pack::ExtensionPlacement::IsolatedController;
    mismatches.push(mismatch);
    let mut mismatch = binding.clone();
    mismatch.artifact.push_str(".other");
    mismatches.push(mismatch);
    let mut mismatch = binding.clone();
    mismatch.entrypoint.push_str("-other");
    mismatches.push(mismatch);

    for mismatch in mismatches {
        assert!(
            !extension_binding_matches_contract(&mismatch, &contract, contract_digest),
            "one mismatched identity field must refuse the whole binding"
        );
    }
}

#[test]
fn extension_artifact_budget_is_inclusive_at_the_exact_limit() {
    assert!(!extension_artifact_exceeds_budget(7, 8));
    assert!(!extension_artifact_exceeds_budget(8, 8));
    assert!(extension_artifact_exceeds_budget(9, 8));
}

#[test]
fn extension_attachment_sets_plan_identity_and_refuses_controller_placement() {
    let root = tempfile::tempdir().expect("extension root");
    let guest_binding = extension_binding(
        mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
    );
    let admitted = admitted_with_extension(guest_binding.clone(), root.path());
    let mut config = mvm_core::vm_backend::VmStartConfig::default();
    final_gates::attach_admitted_extensions(&mut config, &admitted)
        .expect("an admitted guest extension attaches");
    assert_eq!(
        config.extension_plan_id.as_deref(),
        Some(admitted.plan_id().0.as_str())
    );
    assert_eq!(config.extensions, vec![guest_binding]);
    assert_eq!(config.volumes.len(), 1);
    let error = final_gates::attach_admitted_extensions(&mut config, &admitted)
        .expect_err("the same guest mountpoint must not attach twice");
    assert!(error.to_string().contains("mountpoint collision"));

    let controller_binding = extension_binding(
        mvm_contract::protocol::extension_pack::ExtensionPlacement::IsolatedController,
    );
    let admitted = admitted_with_extension(controller_binding, root.path());
    let error = final_gates::attach_admitted_extensions(
        &mut mvm_core::vm_backend::VmStartConfig::default(),
        &admitted,
    )
    .expect_err("a controller extension must never reach guest attachment");
    assert!(error.to_string().contains("isolated_controller"));
}

#[test]
fn extension_binding_requires_the_signed_dispatch_verb() {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .services(vec![
            mvm_contract::protocol::broker::ServiceId::parse(
                mvm_contract::assurance::HOST_ASSURANCE_SERVICE,
            )
            .expect("valid fixture service"),
        ])
        .extensions(vec![extension_binding(
            mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload,
        )])
        .build();

    let error = validate_extension_bindings(&plan)
        .expect_err("an extension plan without the dispatch verb must be refused");
    assert!(error.to_string().contains("run-extension"));

    plan.agent_verbs = Some(vec![
        mvm_contract::plan::VerbId::new("run-extension").expect("valid fixture verb"),
    ]);
    let error = validate_extension_bindings(&plan)
        .expect_err("an extension plan without the cancellation verb must be refused");
    assert!(error.to_string().contains("cancel-extension"));

    plan.agent_verbs = Some(vec![
        mvm_contract::plan::VerbId::new("run-extension").expect("valid fixture verb"),
        mvm_contract::plan::VerbId::new("cancel-extension").expect("valid fixture verb"),
    ]);
    validate_extension_bindings(&plan).expect("the exact signed verb admits dispatch");
}

#[test]
fn unsupported_extension_placement_fails_closed() {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new()
        .services(vec![
            mvm_contract::protocol::broker::ServiceId::parse(
                mvm_contract::assurance::HOST_ASSURANCE_SERVICE,
            )
            .expect("valid fixture service"),
        ])
        .extensions(vec![extension_binding(
            mvm_contract::protocol::extension_pack::ExtensionPlacement::IsolatedController,
        )])
        .build();
    plan.agent_verbs = Some(vec![
        mvm_contract::plan::VerbId::new("run-extension").expect("valid fixture verb"),
        mvm_contract::plan::VerbId::new("cancel-extension").expect("valid fixture verb"),
    ]);

    let error = validate_extension_bindings(&plan)
        .expect_err("an unimplemented placement must never fall through to guest dispatch");
    assert!(error.to_string().contains("not executable"));
}
