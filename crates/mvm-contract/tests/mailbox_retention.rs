use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MailboxContractError, MailboxGrant, MailboxId, MailboxRetentionPolicy,
};
use serde::Serialize;

#[derive(Serialize)]
struct LegacyGrant {
    mailbox: MailboxId,
    authority_key: [u8; 32],
    epoch: ExecutionEpoch,
}

fn grant() -> MailboxGrant {
    MailboxGrant {
        mailbox: MailboxId::from_bytes([1; 32]),
        authority_key: [2; 32],
        epoch: ExecutionEpoch::new(3).expect("epoch"),
        report: None,
        retention: None,
    }
}

#[test]
fn absent_retention_preserves_legacy_signed_grant_bytes() {
    let grant = grant();
    let old = LegacyGrant {
        mailbox: grant.mailbox,
        authority_key: grant.authority_key,
        epoch: grant.epoch,
    };
    assert_eq!(
        serde_json::to_vec(&grant).expect("grant"),
        serde_json::to_vec(&old).expect("legacy grant")
    );
    let decoded: MailboxGrant =
        serde_json::from_slice(&serde_json::to_vec(&old).expect("old bytes"))
            .expect("old grant decodes");
    assert_eq!(decoded.retention, None);
}

#[test]
fn a_finite_signed_window_roundtrips_without_becoming_a_default() {
    let mut declared = grant();
    declared.retention = Some(MailboxRetentionPolicy::new(10_000).expect("finite window"));
    let encoded = serde_json::to_value(declared).expect("encode");
    assert_eq!(encoded["retention"]["version"], 1);
    assert_eq!(encoded["retention"]["retention_ms"], 10_000);
    assert_eq!(
        serde_json::from_value::<MailboxGrant>(encoded).expect("decode"),
        declared
    );
    assert_eq!(
        declared
            .retention
            .expect("retention")
            .retained_until(50_000),
        Ok(60_000)
    );
    assert_eq!(grant().retention, None);
}

#[test]
fn malformed_or_unbounded_retention_cannot_enter_a_signed_grant() {
    assert_eq!(
        MailboxRetentionPolicy::new(0),
        Err(MailboxContractError::InvalidRetentionPolicyBounds)
    );
    assert_eq!(
        MailboxRetentionPolicy::new(u64::MAX),
        Err(MailboxContractError::InvalidRetentionPolicyBounds)
    );
    let window = MailboxRetentionPolicy::new(1).expect("one millisecond");
    assert_eq!(
        window.retained_until(i64::MAX),
        Err(MailboxContractError::InvalidRetentionPolicyBounds)
    );
    assert_eq!(
        window.retained_until(-1),
        Err(MailboxContractError::InvalidRetentionPolicyBounds)
    );
    for raw in [
        r#"{"version":2,"retention_ms":1000}"#,
        r#"{"version":1,"retention_ms":0}"#,
        r#"{"version":1,"retention_ms":1000,"unexpected":true}"#,
    ] {
        assert!(
            serde_json::from_str::<MailboxRetentionPolicy>(raw).is_err(),
            "{raw}"
        );
    }
}
