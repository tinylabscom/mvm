use mvm_contract::plan::{Nonce, PlanId};
use mvm_contract::protocol::mailbox::{ContentType, MessageId};
use mvm_contract::protocol::workload_report::{
    ReportError, ReportErrorCode, ReportIdentity, ReportKind, WORKLOAD_REPORT_CONTENT_TYPE,
    WORKLOAD_REPORT_VERSION, WorkloadReport,
};

fn identity() -> ReportIdentity {
    ReportIdentity {
        plan_id: PlanId("sha256:".to_owned() + &"a".repeat(64)),
        plan_nonce: Nonce::from_bytes([7; 16]),
        message_id: MessageId::from_bytes([8; 32]),
    }
}

fn content_type() -> ContentType {
    ContentType::parse("application/json", 1).expect("static content type")
}

#[test]
fn result_and_error_are_distinct_versioned_mailbox_values() {
    let result = WorkloadReport::new(
        identity(),
        ReportKind::Result,
        content_type(),
        b"\0binary result".to_vec(),
    )
    .expect("bounded result");
    assert_eq!(result.payload(), b"\0binary result");
    assert_eq!(result.identity(), &identity());
    assert_eq!(result.verify_identity(&identity()), Ok(()));
    let mut different_message = identity();
    different_message.message_id = MessageId::from_bytes([9; 32]);
    assert_eq!(
        result.verify_identity(&different_message),
        Err(ReportError::WrongIdentity)
    );
    let mut different_plan = identity();
    different_plan.plan_id = PlanId("another-plan".into());
    assert_eq!(
        result.verify_identity(&different_plan),
        Err(ReportError::WrongIdentity)
    );
    assert_eq!(result.kind(), &ReportKind::Result);
    let wire = result.encode().expect("encode result");
    assert_eq!(
        WorkloadReport::decode(&wire).expect("decode result"),
        result
    );
    assert_eq!(
        serde_json::from_slice::<WorkloadReport>(&wire).expect("serde decode"),
        result
    );
    assert!(
        !format!("{result:?}").contains("binary result"),
        "debug output must not disclose application payload"
    );

    let error = WorkloadReport::new(
        identity(),
        ReportKind::Error {
            code: ReportErrorCode::parse("dependency_unavailable").expect("static code"),
        },
        content_type(),
        b"{\"reason\":\"try later\"}".to_vec(),
    )
    .expect("bounded error");
    assert_eq!(
        WorkloadReport::decode(&error.encode().expect("encode error")).expect("decode error"),
        error
    );
    assert!(!format!("{error:?}").contains("dependency_unavailable"));
    assert!(!format!("{error:?}").contains("try later"));
    assert_ne!(result, error);
    assert_eq!(WORKLOAD_REPORT_VERSION, 1);
    assert_eq!(
        WORKLOAD_REPORT_CONTENT_TYPE,
        "application/vnd.mvm.workload-report"
    );
}

#[test]
fn invalid_version_code_payload_and_unknown_fields_fail_closed() {
    let report = WorkloadReport::new(identity(), ReportKind::Result, content_type(), vec![9])
        .expect("bounded result");
    let mut wire: serde_json::Value =
        serde_json::from_slice(&report.encode().expect("encode")).expect("JSON");
    wire["schema_version"] = 2.into();
    assert_eq!(
        WorkloadReport::decode(&serde_json::to_vec(&wire).expect("serialize")).unwrap_err(),
        ReportError::UnsupportedVersion
    );
    wire["schema_version"] = 1.into();
    wire["unexpected"] = true.into();
    assert_eq!(
        WorkloadReport::decode(&serde_json::to_vec(&wire).expect("serialize")).unwrap_err(),
        ReportError::Malformed
    );
    wire.as_object_mut().expect("object").remove("unexpected");
    wire["payload_b64"] = "***".into();
    assert_eq!(
        WorkloadReport::decode(&serde_json::to_vec(&wire).expect("serialize")).unwrap_err(),
        ReportError::Malformed
    );
    assert_eq!(
        ReportErrorCode::parse("contains a secret: value").unwrap_err(),
        ReportError::InvalidErrorCode
    );
}

#[test]
fn encoded_report_is_bounded_before_parsing_or_publication() {
    let too_large = WorkloadReport::new(
        identity(),
        ReportKind::Result,
        content_type(),
        vec![0; 1024 * 1024],
    );
    assert_eq!(too_large.unwrap_err(), ReportError::Oversized);
    assert_eq!(
        WorkloadReport::decode(&vec![b'x'; 1024 * 1024 + 1]).unwrap_err(),
        ReportError::Oversized
    );
}
