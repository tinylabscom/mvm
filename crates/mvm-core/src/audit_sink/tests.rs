use super::{AuditContext, AuditFailureMode, AuditHealth};

#[test]
fn workload_binding_rejects_the_wrong_tenant_machine_or_zero_epoch() {
    let mut plan = crate::plan::test_support::PlanFixture::new().build();
    let context = AuditContext::Workload {
        plan: Box::new(plan.clone()),
        mode: AuditFailureMode::Production,
    };
    assert!(
        context
            .validate_for(&plan.tenant.0, &plan.workload.0)
            .is_ok()
    );
    assert!(
        context
            .validate_for("another-tenant", &plan.workload.0)
            .is_err()
    );
    assert!(
        context
            .validate_for(&plan.tenant.0, "another-machine")
            .is_err()
    );
    plan.execution_epoch = 0;
    assert!(
        AuditContext::Workload {
            plan: Box::new(plan.clone()),
            mode: AuditFailureMode::Production,
        }
        .validate_for(&plan.tenant.0, &plan.workload.0)
        .is_err()
    );
}

#[test]
fn builder_binding_is_explicit_and_never_claims_a_workload_plan() {
    let context = AuditContext::Builder {
        tenant: crate::plan::TenantId("builder".into()),
        name: "builder-one".into(),
    };
    assert!(context.plan().is_none());
    assert_eq!(context.mode(), AuditFailureMode::Development);
    assert!(context.validate_for("builder", "builder-one").is_ok());
    assert!(context.validate_for("local", "builder-one").is_err());
    assert!(context.validate_for("builder", "other-builder").is_err());
    let bytes = serde_json::to_vec(&context).unwrap();
    let decoded: AuditContext = serde_json::from_slice(&bytes).unwrap();
    assert!(decoded.validate_for("builder", "builder-one").is_ok());
    assert!(serde_json::from_str::<AuditContext>(r#"{"kind":"builder"}"#).is_err());
}

#[test]
fn a_new_epoch_has_no_record_loss_or_suppression() {
    let health = AuditHealth::default();
    assert!(!health.host_record_incomplete());
    assert!(!health.must_stop(AuditFailureMode::Production));
    assert_eq!(health.denials_suppressed, 0);
}

#[test]
fn production_stops_on_the_third_consecutive_failure_not_before() {
    let mut health = AuditHealth::default();
    for failures in 1..=4 {
        health.record_failure();
        assert_eq!(health.consecutive_write_failures, failures);
        assert!(health.host_record_incomplete());
        assert_eq!(
            health.must_stop(AuditFailureMode::Production),
            failures >= 3
        );
        assert!(!health.must_stop(AuditFailureMode::Development));
    }
}

#[test]
fn success_resets_the_streak_but_does_not_repair_missing_evidence() {
    let mut health = AuditHealth::default();
    health.record_failure();
    health.record_failure();
    health.record_success();
    health.record_failure();
    assert_eq!(health.consecutive_write_failures, 1);
    assert_eq!(health.write_failures, 3);
    assert!(health.host_record_incomplete());
    assert!(!health.must_stop(AuditFailureMode::Production));
}

#[test]
fn suppression_neither_resets_nor_advances_the_write_failure_streak() {
    let mut health = AuditHealth::default();
    health.record_failure();
    health.suppress_denial();
    health.suppress_denial();
    assert_eq!(health.denials_suppressed, 2);
    assert_eq!(health.consecutive_write_failures, 1);
    assert_eq!(health.write_failures, 1);
}

#[test]
fn counters_saturate_instead_of_wrapping_back_to_healthy() {
    let mut health = AuditHealth {
        consecutive_write_failures: u64::MAX,
        write_failures: u64::MAX,
        denials_suppressed: u64::MAX,
    };
    health.record_failure();
    health.suppress_denial();
    assert!(health.must_stop(AuditFailureMode::Production));
    assert!(health.host_record_incomplete());
    assert_eq!(health.write_failures, u64::MAX);
    assert_eq!(health.denials_suppressed, u64::MAX);
}

#[test]
fn health_and_failure_mode_round_trip_without_changing_the_policy() {
    let mut health = AuditHealth::default();
    health.record_failure();
    health.suppress_denial();
    let encoded = serde_json::to_vec(&health).unwrap();
    assert_eq!(
        serde_json::from_slice::<AuditHealth>(&encoded).unwrap(),
        health
    );
    for mode in [AuditFailureMode::Development, AuditFailureMode::Production] {
        let encoded = serde_json::to_vec(&mode).unwrap();
        assert_eq!(
            serde_json::from_slice::<AuditFailureMode>(&encoded).unwrap(),
            mode
        );
    }
}
