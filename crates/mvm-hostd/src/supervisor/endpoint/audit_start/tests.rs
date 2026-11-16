use super::*;
use mvm_core::plan::TenantId;

fn config(audit: AuditContext) -> EndpointConfig {
    let (tenant, instance) = match &audit {
        AuditContext::Workload { plan } => (&plan.tenant.0, &plan.workload.0),
        AuditContext::Builder { tenant, name } => (&tenant.0, name),
    };
    serde_json::from_value(serde_json::json!({
        "tenant_id": tenant,
        "instance_id": instance,
        "secrets": [],
        "transport": { "kind": "uds", "path": "unused-network.sock" },
        "egress_mode": "flow_mux",
        "audit": audit,
    }))
    .unwrap()
}

fn workload() -> EndpointConfig {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.execution_epoch = 7;
    config(AuditContext::Workload {
        plan: Box::new(plan),
    })
}

#[test]
fn missing_identity_is_refused_before_startup() {
    let mut cfg = workload();
    cfg.audit = None;
    assert!(validate(&cfg).is_err());
}

#[test]
fn a_workload_cannot_borrow_another_tenants_audit_binding() {
    let mut cfg = workload();
    assert!(validate(&cfg).is_ok());
    cfg.tenant_id = "another-tenant".into();
    assert!(validate(&cfg).is_err());
}

#[test]
fn valid_workload_identity_needs_no_lifecycle_control() {
    assert!(validate(&workload()).is_ok());
}

#[test]
fn invalid_workload_plan_or_epoch_is_refused() {
    for field in ["epoch", "plan"] {
        let mut cfg = workload();
        if let Some(AuditContext::Workload { plan }) = cfg.audit.as_mut() {
            match field {
                "epoch" => plan.execution_epoch = 0,
                "plan" => plan.plan_id.0.clear(),
                _ => unreachable!(),
            }
        }
        assert!(validate(&cfg).is_err(), "{field}");
    }
}

#[test]
fn a_warm_instance_alias_does_not_rebind_the_logical_workload() {
    let mut cfg = workload();
    cfg.instance_id = "claimed-child-instance".into();
    assert!(validate(&cfg).is_ok());
    assert_ne!(
        cfg.audit.as_ref().unwrap().plan().unwrap().workload.0,
        cfg.instance_id
    );
}

#[test]
fn builder_identity_is_explicit_and_matches_its_instance() {
    let cfg = config(AuditContext::Builder {
        tenant: TenantId("builder".into()),
        name: "build-one".into(),
    });
    assert!(validate(&cfg).is_ok());
    let mut wrong = cfg;
    wrong.instance_id = "build-two".into();
    assert!(validate(&wrong).is_err());
}

#[test]
fn an_empty_builder_tenant_is_not_an_audit_identity() {
    let cfg = config(AuditContext::Builder {
        tenant: TenantId(String::new()),
        name: "build-one".into(),
    });
    assert!(validate(&cfg).is_err());
}

#[test]
fn obsolete_shutdown_binding_is_rejected_instead_of_ignored() {
    let cfg = workload();
    let plan = cfg.audit.as_ref().unwrap().plan().unwrap();
    let binding = serde_json::json!({
        "tenant_id": plan.tenant.0,
        "instance_id": cfg.instance_id,
        "workload_id": plan.workload.0,
        "plan_id": plan.plan_id.0,
        "epoch": plan.execution_epoch,
        "generation": vec![1_u8; 32],
    });
    let mut encoded = serde_json::to_value(&cfg).unwrap();
    encoded["audit_control"] = binding;
    assert!(serde_json::from_value::<EndpointConfig>(encoded).is_err());
}
