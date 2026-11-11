use mvm_contract::protocol::mailbox::{
    AuthorizationDomainId, DeliveryId, DeliveryOutcome, DestinationReceipt, ExecutionEpoch,
    MailboxAddress, MailboxContractError, MailboxId, MessageId, PrincipalId, ProtocolVersion,
    SignatureAlgorithm, TenantId,
};

fn receipt(outcome: DeliveryOutcome, protocol_version: ProtocolVersion) -> DestinationReceipt {
    DestinationReceipt {
        protocol_version,
        signature_algorithm: SignatureAlgorithm::ED25519,
        delivery_id: DeliveryId::from_bytes([1; 32]),
        message_id: MessageId::from_bytes([2; 32]),
        address: MailboxAddress {
            tenant: TenantId::from_bytes([3; 32]),
            authorization_domain: AuthorizationDomainId::from_bytes([4; 32]),
            mailbox: MailboxId::from_bytes([5; 32]),
            recipient: PrincipalId::from_bytes([6; 32]),
        },
        execution_epoch: ExecutionEpoch::new(1).expect("nonzero epoch"),
        outcome,
        observed_at_unix_ms: 100,
        ciphertext_commitment: [7; 32],
    }
}

#[test]
fn local_durable_is_a_distinct_v2_receipt_not_a_v1_durable_alias() {
    let local = receipt(DeliveryOutcome::AcceptedLocalDurable, ProtocolVersion::V2);
    let wire = serde_json::to_vec(&local).expect("encode local receipt");
    assert_eq!(
        serde_json::from_slice::<DestinationReceipt>(&wire).expect("decode local receipt"),
        local
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wire).expect("inspect local receipt")["outcome"],
        "accepted_local_durable"
    );
    assert_ne!(
        local.outcome,
        DeliveryOutcome::AcceptedDurable,
        "a local crash witness is not independent rollback evidence"
    );
}

#[test]
fn old_v1_receipts_keep_their_bytes_and_reject_a_local_claim() {
    let old = receipt(DeliveryOutcome::AcceptedDurable, ProtocolVersion::V1);
    let wire = serde_json::to_string(&old).expect("encode old receipt");
    assert!(wire.starts_with("{\"protocol_version\":1,\"signature_algorithm\":1,\"delivery_id\":"));
    assert!(wire.contains("\"outcome\":\"accepted_durable\""));
    assert_eq!(
        serde_json::from_str::<DestinationReceipt>(&wire).expect("decode old receipt"),
        old
    );

    let mut forged = old.clone();
    forged.outcome = DeliveryOutcome::AcceptedLocalDurable;
    assert_eq!(
        forged.validate_versioned_outcome(),
        Err(MailboxContractError::InvalidReceiptVersion)
    );
    assert!(
        serde_json::to_vec(&forged).is_err(),
        "do not sign a V1 local claim"
    );
    let mut value: serde_json::Value = serde_json::from_str(&wire).expect("old JSON");
    value["outcome"] = "accepted_local_durable".into();
    assert!(serde_json::from_value::<DestinationReceipt>(value).is_err());
}

#[test]
fn v2_cannot_relabel_an_old_outcome_or_admit_unknown_versions() {
    let mut local = receipt(DeliveryOutcome::AcceptedLocalDurable, ProtocolVersion::V2);
    local.outcome = DeliveryOutcome::AcceptedDurable;
    assert!(serde_json::to_vec(&local).is_err());

    let mut value = serde_json::to_value(receipt(
        DeliveryOutcome::AcceptedLocalDurable,
        ProtocolVersion::V2,
    ))
    .expect("valid V2");
    value["outcome"] = "accepted_durable".into();
    assert!(serde_json::from_value::<DestinationReceipt>(value.clone()).is_err());
    value["outcome"] = "accepted_local_durable".into();
    value["protocol_version"] = 3.into();
    assert!(serde_json::from_value::<DestinationReceipt>(value).is_err());
}
