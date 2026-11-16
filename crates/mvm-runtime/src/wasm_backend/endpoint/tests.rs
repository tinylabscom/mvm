use super::*;

// Decision + params only — no subprocess is ever spawned in this module.

// Mirrors `libkrun_substitution_not_spawned_when_no_secrets_and_no_egress`:
// a fresh state dir (no plan.json) plus the default deny-all policy has
// nothing to mediate, so the plan must skip.
#[test]
fn wasm_endpoint_plan_is_none_when_no_secrets_and_no_egress() {
    let dir = tempfile::tempdir().unwrap();
    let config = VmStartConfig {
        name: "no-secrets-wasm-vm".to_string(),
        ..Default::default()
    };
    let plan = wasm_endpoint_plan(&config, dir.path()).unwrap();
    assert!(
        plan.is_none(),
        "deny-all policy with no bound secrets must skip the endpoint spawn"
    );
}

// A policy that allows egress must still produce a spawn plan even with
// no bound secrets — the endpoint runs in wire mode regardless and gates
// the destination itself, mirroring libkrun's own skip condition.
#[test]
fn wasm_endpoint_plan_is_some_when_policy_allows_egress_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let config = VmStartConfig {
        name: "policy-allow-wasm-vm".to_string(),
        audit_context: Some(mvm_core::audit_sink::AuditContext::Workload {
            plan: Box::new(mvm_core::plan::test_support::PlanFixture::new().build()),
        }),
        network_policy: mvm_core::network_policy::NetworkPolicy::preset(
            mvm_core::network_policy::NetworkPreset::Dev,
        ),
        ..Default::default()
    };
    let plan = wasm_endpoint_plan(&config, dir.path())
        .unwrap()
        .expect("a policy allowing egress must produce a spawn plan");
    assert!(plan.secrets.is_empty());
    assert_eq!(plan.tenant, "local");
}

#[test]
fn wasm_endpoint_plan_rejects_builder_identity_for_a_workload() {
    let dir = tempfile::tempdir().unwrap();
    let config = VmStartConfig {
        name: "wasm-workload".into(),
        audit_context: Some(mvm_core::audit_sink::AuditContext::Builder {
            tenant: mvm_core::plan::TenantId("local".into()),
            name: "wasm-workload".into(),
        }),
        network_policy: mvm_core::network_policy::NetworkPolicy::preset(
            mvm_core::network_policy::NetworkPreset::Dev,
        ),
        ..Default::default()
    };
    assert!(wasm_endpoint_plan(&config, dir.path()).is_err());
}

// Secrets present (even under a deny-all `VmStartConfig::network_policy`,
// since the endpoint itself gates per-destination) must produce a spawn
// plan whose params mirror libkrun/hvf except for the wasm-only
// deviations: always `Uds`, no TLS, and — the one field
// that must NOT mirror libkrun — the wasm tier never carries an identity.
#[test]
fn wasm_endpoint_plan_params_mirror_libkrun_with_wasm_deviations() {
    let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let dir = tempfile::tempdir().unwrap();
    let secret = mvm_core::plan::SecretBinding {
        name: "API_KEY".to_string(),
        source: mvm_core::plan::SecretSource::Keystore {
            address: "addr".to_string(),
        },
        destinations: Vec::new(),
        approval_required: false,
    };
    let admitted = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("acme")
        .secrets(vec![secret.clone()])
        .build();
    std::fs::write(
        dir.path().join("plan.json"),
        serde_json::to_string(&admitted).unwrap(),
    )
    .unwrap();

    let config = VmStartConfig {
        name: "secret-wasm-vm".to_string(),
        audit_context: Some(mvm_core::audit_sink::AuditContext::Workload {
            plan: Box::new(admitted),
        }),
        ..Default::default()
    };
    let plan = wasm_endpoint_plan(&config, dir.path())
        .unwrap()
        .expect("bound secrets must produce a spawn plan");

    assert_eq!(plan.vm_name, "secret-wasm-vm");
    assert_eq!(plan.state_dir, dir.path().to_path_buf());
    assert_eq!(plan.tenant, "acme");
    assert_eq!(plan.secrets, vec![secret]);
    assert_eq!(
        plan.socket_path,
        mvm_core::config::vm_network_endpoint_socket("secret-wasm-vm")
    );

    let params = wasm_network_endpoint_spawn_params(&plan, &config.network_policy);
    assert_eq!(params.vm_name, "secret-wasm-vm");
    assert_eq!(
        params.transport,
        crate::network_endpoint_spawn::EndpointTransport::Uds {
            path: plan.socket_path.clone(),
        }
    );
    assert!(
        params.tls_intermediate.is_none(),
        "http-only POC; HTTPS termination is a later phase"
    );
    assert!(
        params.network_policy.is_some(),
        "the endpoint must gate the destination itself"
    );
    assert!(
        params.flowmux_identity.is_none(),
        "wasm always speaks WireRequest wire mode, never libkrun's raw pass-through"
    );
}
