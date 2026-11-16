use super::*;
use mvm_core::plan::TenantId;
use mvm_vmm::host::audit_control::AuditBinding;

fn config(audit: AuditContext) -> EndpointConfig {
    let (tenant, instance) = match &audit {
        AuditContext::Workload { plan, .. } => (&plan.tenant.0, &plan.workload.0),
        AuditContext::Builder { tenant, name } => (&tenant.0, name),
    };
    serde_json::from_value(serde_json::json!({
        "tenant_id": tenant,
        "instance_id": instance,
        "secrets": [],
        "transport": { "kind": "uds", "path": "/tmp/audit-start-test.sock" },
        "egress_mode": "flow_mux",
        "audit": audit,
    }))
    .unwrap()
}

fn workload(mode: AuditFailureMode) -> EndpointConfig {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.execution_epoch = 7;
    config(AuditContext::Workload {
        plan: Box::new(plan),
        mode,
    })
}

fn control(cfg: &EndpointConfig) -> AuditBinding {
    let plan = cfg.audit.as_ref().unwrap().plan().unwrap();
    AuditBinding {
        tenant_id: plan.tenant.0.clone(),
        instance_id: cfg.instance_id.clone(),
        workload_id: plan.workload.0.clone(),
        plan_id: plan.plan_id.0.clone(),
        epoch: plan.execution_epoch,
        generation: [1; 32],
    }
}

#[test]
fn missing_identity_is_refused_even_in_development() {
    let mut cfg = workload(AuditFailureMode::Development);
    cfg.audit = None;
    assert!(validate(&cfg, false).is_err());
}

#[test]
fn a_workload_cannot_borrow_another_tenants_audit_binding() {
    let mut cfg = workload(AuditFailureMode::Development);
    assert!(validate(&cfg, false).is_ok());
    cfg.tenant_id = "another-tenant".into();
    assert!(validate(&cfg, false).is_err());
}

#[test]
fn production_requires_both_the_control_binding_and_inherited_channel() {
    let mut cfg = workload(AuditFailureMode::Production);
    assert!(validate(&cfg, false).is_err());
    assert!(validate(&cfg, true).is_err());
    cfg.audit_control = Some(control(&cfg));
    assert!(validate(&cfg, false).is_err());
    assert!(validate(&cfg, true).is_ok());
}

#[test]
fn stale_epoch_and_wrong_plan_or_physical_instance_are_refused() {
    let mut cfg = workload(AuditFailureMode::Production);
    let binding = control(&cfg);
    for field in ["epoch", "plan", "instance", "workload", "tenant"] {
        let mut stale = binding.clone();
        match field {
            "epoch" => stale.epoch -= 1,
            "plan" => stale.plan_id.push_str("-other"),
            "instance" => stale.instance_id.push_str("-other"),
            "workload" => stale.workload_id.push_str("-other"),
            "tenant" => stale.tenant_id.push_str("-other"),
            _ => unreachable!(),
        }
        cfg.audit_control = Some(stale);
        assert!(validate(&cfg, true).is_err(), "{field}");
    }
}

#[test]
fn a_warm_instance_alias_does_not_rebind_the_logical_workload() {
    let mut cfg = workload(AuditFailureMode::Production);
    cfg.instance_id = "claimed-child-instance".into();
    cfg.audit_control = Some(control(&cfg));
    assert!(validate(&cfg, true).is_ok());
    assert_ne!(
        cfg.audit.as_ref().unwrap().plan().unwrap().workload.0,
        cfg.instance_id
    );
}

#[test]
fn builder_identity_is_explicit_and_has_no_workload_stop_authority() {
    let cfg = config(AuditContext::Builder {
        tenant: TenantId("builder".into()),
        name: "build-one".into(),
    });
    assert!(validate(&cfg, false).is_ok());
    assert!(validate(&cfg, true).is_err());
    let mut wrong = cfg;
    wrong.instance_id = "build-two".into();
    assert!(validate(&wrong, false).is_err());
}

#[test]
fn development_must_not_accidentally_receive_a_production_stop_capability() {
    let mut cfg = workload(AuditFailureMode::Development);
    cfg.audit_control = Some(control(&cfg));
    assert!(validate(&cfg, true).is_err());
}
