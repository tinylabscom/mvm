use super::*;
use crate::mailbox::journal::receipt::ReceiptFault;

struct Fixture {
    dir: tempfile::TempDir,
    envelope: MailboxEnvelope,
    capability: SignedMailboxCapability,
    context: OpenContext,
    payload_key: Key,
    sender_key: VerifyingKey,
    signer: SigningKey,
    reference: HistoryKeyRef,
    custody: TestCustody,
    anchor_key: [u8; 32],
}

impl Fixture {
    fn new() -> Self {
        let (envelope, capability, context, payload_key, sender_key, signer) = message();
        let (reference, mut custody) = versioned_custody();
        custody.bytes = Some(rand::random());
        Self {
            dir: tempfile::tempdir().expect("test-purpose storage"),
            envelope,
            capability,
            context,
            payload_key,
            sender_key,
            signer,
            reference,
            custody,
            anchor_key: rand::random(),
        }
    }

    fn root(&self) -> PathBuf {
        self.dir.path().join("journal")
    }

    fn anchor(&self) -> FileJournalAnchor {
        FileJournalAnchor::open(
            &self.dir.path().join("anchor").join("tip"),
            address(),
            self.anchor_key,
        )
        .expect("test-purpose anchor")
    }

    fn open(
        &self,
        anchor: &FileJournalAnchor,
        limits: JournalLimits,
    ) -> Result<MailboxJournal, JournalError> {
        MailboxJournal::open_local_with_custody(
            &self.root(),
            self.reference,
            self.signer.verifying_key(),
            limits,
            &self.custody,
            anchor,
            local_retention(),
        )
    }

    fn request(&self) -> JournalAdmission<'_> {
        admission(
            &self.envelope,
            &self.capability,
            &self.context,
            &self.payload_key,
            &self.sender_key,
            &self.signer,
        )
    }
}

fn spacious() -> JournalLimits {
    JournalLimits {
        max_records: 64,
        max_bytes: 1024 * 1024,
    }
}

#[test]
fn pending_then_retained_reopens_without_signing_or_redebiting() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    assert_eq!(journal.tip().cursor, 1, "acceptance is committed");
    assert_eq!(journal.seen.len(), 1, "one acceptance debit");
    assert_eq!(journal.receipt_sign_attempts, 0);
    journal.receipt_fault = None;
    let first = journal
        .recover_local_encoded(fixture.request(), &anchor)
        .expect("complete committed body")
        .expect("known operation");
    let exact = first.encoded().to_vec();
    assert_eq!(journal.receipt_sign_attempts, 1);
    assert_eq!(journal.tip().cursor, 2);
    drop(journal);
    drop(anchor);

    let anchor = fixture.anchor();
    let mut journal = fixture
        .open(&anchor, spacious())
        .expect("reopen exact history");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    let recovered = journal
        .recover_local_encoded(fixture.request(), &anchor)
        .expect("retained result needs no signer invocation")
        .expect("known operation");
    assert_eq!(recovered.encoded(), exact);
    assert_eq!(journal.receipt_sign_attempts, 0);
    assert_eq!(journal.tip().cursor, 2, "no recovery append");
    assert_eq!(journal.seen.len(), 1, "no recovery debit");
}

#[test]
fn completion_publication_and_anchor_ambiguity_reconcile_exact_bytes() {
    for fault in [ReceiptFault::AfterPublication, ReceiptFault::AfterAnchor] {
        let fixture = Fixture::new();
        let anchor = fixture.anchor();
        let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
        journal.receipt_fault = Some(fault);
        assert!(matches!(
            journal.admit_local(fixture.request(), &anchor),
            Err(JournalError::Uncertain)
        ));
        assert!(journal.poisoned);
        let completed =
            read_record(&record_path(&fixture.root(), 2)).expect("published completion");
        let first = read_record(&record_path(&fixture.root(), 1)).expect("accepted prefix");
        let body = aead::open(
            &journal.record_key(),
            &completed[32..],
            &[DOMAIN, &first[..32]].concat(),
        )
        .expect("completion body");
        let record: Record = serde_json::from_slice(&body).expect("completion record");
        let JournalEvent::ReceiptCompleted {
            encoded_receipt, ..
        } = record.event
        else {
            panic!("second record must retain the signed receipt");
        };
        let exact = STANDARD_NO_PAD
            .decode(encoded_receipt)
            .expect("retained encoding");
        drop(journal);
        drop(anchor);

        let anchor = fixture.anchor();
        let mut journal = fixture
            .open(&anchor, spacious())
            .expect("reconcile intact completion");
        assert_eq!(anchor.tip().cursor, 2);
        journal.receipt_fault = Some(ReceiptFault::BeforeSign);
        let recovered = journal
            .recover_local_encoded(fixture.request(), &anchor)
            .expect("recover retained result")
            .expect("known operation");
        assert_eq!(recovered.encoded(), exact);
        assert_eq!(journal.receipt_sign_attempts, 0);
    }
}

#[test]
fn completion_and_checkpoint_capacity_is_reserved_before_acceptance() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture
        .open(
            &anchor,
            JournalLimits {
                max_records: 2,
                max_bytes: 1024 * 1024,
            },
        )
        .expect("bounded journal");
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::Full)
    ));
    assert_eq!(journal.tip(), JournalTip::genesis());
    assert_eq!(anchor.tip(), JournalTip::genesis());
    assert!(journal.seen.is_empty());
    assert!(!record_path(&fixture.root(), 1).exists());
}

#[test]
fn acceptance_reserves_completion_and_checkpoint_cursor_space() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    legacy_accepted(&fixture, &anchor);
    let journal = fixture.open(&anchor, spacious()).expect("legacy body");
    let state = journal
        .checkpoint_state(fixture.context.now_unix_ms)
        .expect("snapshot");
    let receipt = state.entries[0].seen.accepted_receipt.clone();
    let identity = state.entries[0].identity;
    let frame = STANDARD_NO_PAD
        .encode(frame::encode_frame(&fixture.capability, &fixture.envelope).expect("frame"));
    let record = Record {
        version: 4,
        cursor: u64::MAX - 1,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(fixture.reference),
        event: JournalEvent::Accepted {
            identity,
            frame,
            receipt: Box::new(receipt),
            authorization_signature: vec![0; 64],
        },
    };
    let mut projected = journal;
    projected.tip.cursor = u64::MAX - 2;
    assert!(
        matches!(
            projected.check_append_capacity(&record),
            Err(JournalError::Full)
        ),
        "acceptance must reserve future cursor space, not only bytes and slots"
    );
    projected.tip.cursor -= 1;
    projected
        .check_append_capacity(&record)
        .expect("exactly enough future cursor space is usable");
    let mut pending_state = state;
    pending_state.entries[0].seen.receipt_completion = Some(
        projected
            .pending_receipt(identity, &pending_state.entries[0].seen.accepted_receipt)
            .expect("pending reservation"),
    );
    projected.tip.cursor = u64::MAX - 2;
    assert!(
        matches!(
            projected.check_checkpoint_capacity(&pending_state, 1024),
            Err(JournalError::Full)
        ),
        "checkpoint cannot spend another pending outcome's remaining cursor"
    );
    projected.tip.cursor -= 1;
    projected
        .check_checkpoint_capacity(&pending_state, 1024)
        .expect("checkpoint with exact cursor headroom");
}

#[test]
fn checkpoint_preserves_pending_and_retained_receipt_states() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    journal
        .compact_local(fixture.context.now_unix_ms, &fixture.signer, &anchor)
        .expect("pending checkpoint");
    drop(journal);
    let mut journal = fixture.open(&anchor, spacious()).expect("pending restored");
    assert_eq!(journal.receipt_sign_attempts, 0, "reopen never signs");
    let exact = journal
        .recover_local_encoded(fixture.request(), &anchor)
        .expect("complete pending after authorization")
        .expect("known operation")
        .encoded()
        .to_vec();
    journal
        .compact_local(fixture.context.now_unix_ms, &fixture.signer, &anchor)
        .expect("retained checkpoint");
    drop(journal);
    let mut journal = fixture
        .open(&anchor, spacious())
        .expect("retained restored");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert_eq!(
        journal
            .recover_local_encoded(fixture.request(), &anchor)
            .expect("retained recovery")
            .expect("known operation")
            .encoded(),
        exact,
    );
    assert_eq!(journal.receipt_sign_attempts, 0);
}

#[test]
fn missing_anchored_completion_cannot_be_regenerated() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal
        .admit_local(fixture.request(), &anchor)
        .expect("completed acceptance");
    drop(journal);
    fs::remove_file(record_path(&fixture.root(), 2)).expect("simulate lost anchored completion");
    assert!(matches!(
        fixture.open(&anchor, spacious()),
        Err(JournalError::Rollback)
    ));
    assert_eq!(anchor.tip().cursor, 2, "refusal cannot rewind the anchor");
}

// These are the old persisted shapes, deliberately independent of the current
// Seen/CheckpointState serializer so compatibility cannot prove itself.
#[derive(Serialize)]
struct LegacySeen<'a> {
    envelope: &'a MailboxEnvelope,
    capability: &'a SignedMailboxCapability,
    accepted_receipt: &'a DestinationReceipt,
    acknowledged: bool,
    expired_at_unix_ms: Option<i64>,
    lease: Option<&'a LeaseState>,
    signed_ack: Option<&'a SignedMailboxDeliveryAck>,
}

#[derive(Serialize)]
struct LegacyCheckpointEntry<'a> {
    identity: ReplayIdentity,
    seen: LegacySeen<'a>,
}

#[derive(Serialize)]
struct LegacyCheckpointState<'a> {
    source: JournalTip,
    address: MailboxAddress,
    history_key: HistoryKeyRef,
    retention: MailboxRetentionPolicy,
    created_at_unix_ms: i64,
    entries: Vec<LegacyCheckpointEntry<'a>>,
    used_challenges: Vec<([u8; 32], ReplayIdentity)>,
}

fn publish_test_record(
    journal: &MailboxJournal,
    cursor: u64,
    body: &[u8],
    checkpoint: bool,
) -> JournalTip {
    let encrypted = aead::seal(
        &journal.record_key(),
        body,
        &[DOMAIN, &journal.tip.head].concat(),
    );
    let tag = journal.mac(&encrypted);
    let mut bytes = if checkpoint {
        journal.tip.head.to_vec()
    } else {
        Vec::new()
    };
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(&encrypted);
    let path = if checkpoint {
        checkpoint_path(&journal.root, cursor)
    } else {
        record_path(&journal.root, cursor)
    };
    atomic_write_new(&path, &bytes).expect("test record");
    sync_dir(&journal.root).expect("test record directory");
    JournalTip { cursor, head: tag }
}

fn legacy_accepted(fixture: &Fixture, anchor: &FileJournalAnchor) {
    let journal = fixture.open(anchor, spacious()).expect("empty fixture");
    let identity = journal
        .verify_admission(&fixture.request(), AcceptanceTier::Local)
        .expect("authorized fixture");
    let encoded_frame = STANDARD_NO_PAD
        .encode(frame::encode_frame(&fixture.capability, &fixture.envelope).expect("legacy frame"));
    let receipt = DestinationReceipt {
        protocol_version: ProtocolVersion::V2,
        signature_algorithm: SignatureAlgorithm::ED25519,
        delivery_id: fixture.envelope.routing.delivery_id,
        message_id: identity.message_id,
        address: address(),
        execution_epoch: identity.execution_epoch,
        outcome: DeliveryOutcome::AcceptedLocalDurable,
        observed_at_unix_ms: fixture.context.now_unix_ms,
        ciphertext_commitment: fixture.envelope.ciphertext_commitment,
    };
    let signature = fixture
        .signer
        .sign(
            &acceptance_intent_bytes(identity, &encoded_frame, &receipt, Some(&fixture.reference))
                .expect("original acceptance purpose"),
        )
        .to_bytes()
        .to_vec();
    let old_record = serde_json::json!({
        "version": 3, "cursor": 1, "previous": JournalTip::genesis().head, "address": address(),
        "history_key": fixture.reference,
        "event": {
            "kind": "accepted", "identity": identity, "frame": encoded_frame,
            "receipt": receipt, "authorization_signature": signature
        }
    });
    let next = publish_test_record(
        &journal,
        1,
        &serde_json::to_vec(&old_record).expect("old record shape"),
        false,
    );
    anchor.advance(next).expect("legacy acceptance anchor");
}

#[test]
fn legacy_body_is_first_retained_only_after_current_authorization_and_capacity() {
    let mut fixture = Fixture::new();
    let anchor = fixture.anchor();
    legacy_accepted(&fixture, &anchor);
    let mut journal = fixture.open(&anchor, spacious()).expect("legacy body");
    assert_eq!(journal.format_version, 3);
    assert!(
        journal
            .seen
            .values()
            .all(|entry| entry.receipt_completion.is_none())
    );
    let original_body = journal
        .seen
        .values()
        .next()
        .expect("accepted")
        .accepted_receipt
        .clone();
    fixture
        .context
        .revoked_capabilities
        .push(fixture.capability.grant.revocation_id);
    assert!(matches!(
        journal.recover_local_encoded(fixture.request(), &anchor),
        Err(JournalError::Mailbox(MailboxError::CapabilityRevoked))
    ));
    fixture.context.revoked_capabilities.clear();
    journal.limits.max_records = 2;
    assert!(matches!(
        journal.recover_local_encoded(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    assert_eq!(
        journal.receipt_sign_attempts, 0,
        "capacity precedes first retention signing"
    );
    assert_eq!(journal.tip().cursor, 1);
    journal.limits = spacious();
    let retained = journal
        .recover_local_encoded(fixture.request(), &anchor)
        .expect("first retained completion")
        .expect("known legacy body");
    assert_eq!(retained.into_signed().receipt, original_body);
    assert_eq!(journal.receipt_sign_attempts, 1);
    assert_eq!(journal.tip().cursor, 2);
    assert_eq!(journal.seen.len(), 1);
    assert_eq!(journal.format_version, 4);
}

#[test]
fn old_shape_checkpoint_signature_survives_upgrade_and_pruning() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    legacy_accepted(&fixture, &anchor);
    let journal = fixture
        .open(&anchor, spacious())
        .expect("old accepted prefix");
    let old_state = LegacyCheckpointState {
        source: journal.tip,
        address: address(),
        history_key: fixture.reference,
        retention: local_retention(),
        created_at_unix_ms: fixture.context.now_unix_ms,
        entries: journal
            .order
            .iter()
            .map(|identity| {
                let seen = journal.seen.get(identity).expect("legacy entry");
                LegacyCheckpointEntry {
                    identity: *identity,
                    seen: LegacySeen {
                        envelope: &seen.envelope,
                        capability: &seen.capability,
                        accepted_receipt: &seen.accepted_receipt,
                        acknowledged: seen.acknowledged,
                        expired_at_unix_ms: seen.expired_at_unix_ms,
                        lease: seen.lease.as_ref(),
                        signed_ack: seen.signed_ack.as_ref(),
                    },
                }
            })
            .collect(),
        used_challenges: Vec::new(),
    };
    let old_bytes = serde_jcs::to_vec(&old_state).expect("old checkpoint canonical bytes");
    assert_eq!(
        old_bytes,
        serde_jcs::to_vec(
            &journal
                .checkpoint_state(fixture.context.now_unix_ms)
                .expect("current decoded shape")
        )
        .expect("current canonical bytes"),
        "absent optional state must not change old signed bytes",
    );
    let signature = fixture
        .signer
        .sign(
            &[
                b"mvm.mailbox.local-checkpoint.v1\0".as_slice(),
                old_bytes.as_slice(),
            ]
            .concat(),
        )
        .to_bytes()
        .to_vec();
    let old_record = serde_json::json!({
        "version":3,"cursor":2,"previous":journal.tip.head,"address":address(),
        "history_key":fixture.reference,
        "event":{"kind":"checkpoint","state":old_state,"authorization_signature":signature}
    });
    let tip = publish_test_record(
        &journal,
        2,
        &serde_json::to_vec(&old_record).expect("old checkpoint record"),
        true,
    );
    anchor.advance(tip).expect("old checkpoint anchor");
    drop(journal);
    let mut journal = fixture
        .open(&anchor, spacious())
        .expect("old-shape signature validates");
    assert_eq!(journal.format_version, 3);
    assert!(
        journal
            .seen
            .values()
            .all(|entry| entry.receipt_completion.is_none())
    );
    journal
        .recover_local_encoded(fixture.request(), &anchor)
        .expect("first retained completion")
        .expect("legacy acceptance");
    journal
        .compact_local(fixture.context.now_unix_ms, &fixture.signer, &anchor)
        .expect("v4 checkpoint");
    drop(journal);
    let journal = fixture
        .open(&anchor, spacious())
        .expect("v4 checkpoint reopens");
    assert_eq!(
        journal.format_version, 4,
        "pruning preserves the format barrier"
    );
}

#[test]
fn first_v4_completion_can_reconcile_but_v3_cannot_follow_it() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    legacy_accepted(&fixture, &anchor);
    let mut journal = fixture.open(&anchor, spacious()).expect("legacy prefix");
    journal.receipt_fault = Some(ReceiptFault::AfterPublication);
    assert!(matches!(
        journal.recover_local_encoded(fixture.request(), &anchor),
        Err(JournalError::Uncertain)
    ));
    assert_eq!(anchor.tip().cursor, 1);
    drop(journal);
    let journal = fixture
        .open(&anchor, spacious())
        .expect("first v4 suffix reconciles");
    assert_eq!(journal.format_version, 4);
    assert_eq!(anchor.tip().cursor, 2);
    let identity = journal.order[0];
    let entry = journal.seen.get(&identity).expect("accepted");
    let time = entry.envelope.routing.expires_at_unix_ms;
    let signature = fixture
        .signer
        .sign(&expiry_intent_bytes(address(), identity, entry, time).expect("expiry intent"))
        .to_bytes()
        .to_vec();
    let downgraded = Record {
        version: 3,
        cursor: 3,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(fixture.reference),
        event: JournalEvent::Expired {
            identity,
            expired_at_unix_ms: time,
            authorization_signature: signature,
        },
    };
    publish_test_record(
        &journal,
        3,
        &serde_json::to_vec(&downgraded).expect("valid v3 event"),
        false,
    );
    drop(journal);
    assert!(matches!(
        fixture.open(&anchor, spacious()),
        Err(JournalError::Corrupt)
    ));
    assert_eq!(anchor.tip().cursor, 2, "downgrade must not be reconciled");
}

#[test]
fn forged_completion_with_valid_history_mac_never_advances_anchor() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    let identity = journal.order[0];
    let entry = journal.seen.get(&identity).expect("accepted");
    let mut signed =
        sign_receipt(entry.accepted_receipt.clone(), &fixture.signer).expect("test receipt");
    signed.signature[0] ^= 1;
    let forged = Record {
        version: 4,
        cursor: 2,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(fixture.reference),
        event: JournalEvent::ReceiptCompleted {
            identity,
            encoded_receipt: STANDARD_NO_PAD
                .encode(serde_json::to_vec(&signed).expect("forged encoding")),
        },
    };
    publish_test_record(
        &journal,
        2,
        &serde_json::to_vec(&forged).expect("forged record"),
        false,
    );
    drop(journal);
    assert!(matches!(
        fixture.open(&anchor, spacious()),
        Err(JournalError::Corrupt)
    ));
    assert_eq!(
        anchor.tip().cursor,
        1,
        "validate completion before advancing anchor"
    );
}

#[test]
fn completion_with_valid_signature_cannot_change_the_committed_outcome_body() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    let identity = journal.order[0];
    let mut body = journal
        .seen
        .get(&identity)
        .expect("accepted")
        .accepted_receipt
        .clone();
    body.observed_at_unix_ms += 1;
    let signed = sign_receipt(body, &fixture.signer).expect("valid but different signed body");
    let forged = Record {
        version: 4,
        cursor: 2,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(fixture.reference),
        event: JournalEvent::ReceiptCompleted {
            identity,
            encoded_receipt: STANDARD_NO_PAD.encode(serde_json::to_vec(&signed).expect("encoding")),
        },
    };
    publish_test_record(
        &journal,
        2,
        &serde_json::to_vec(&forged).expect("record"),
        false,
    );
    drop(journal);
    assert!(matches!(
        fixture.open(&anchor, spacious()),
        Err(JournalError::Corrupt)
    ));
    assert_eq!(anchor.tip().cursor, 1);
}

#[test]
fn v3_checkpoint_cannot_smuggle_completion_state() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal
        .admit_local(fixture.request(), &anchor)
        .expect("retained acceptance");
    let state = journal
        .checkpoint_state(fixture.context.now_unix_ms)
        .expect("current state");
    let signature = fixture
        .signer
        .sign(
            &canonical_bytes(b"mvm.mailbox.local-checkpoint.v1\0", &state)
                .expect("checkpoint purpose"),
        )
        .to_bytes()
        .to_vec();
    let record = Record {
        version: 3,
        cursor: 3,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(fixture.reference),
        event: JournalEvent::Checkpoint {
            state: Box::new(state),
            authorization_signature: signature,
        },
    };
    let tip = publish_test_record(
        &journal,
        3,
        &serde_json::to_vec(&record).expect("checkpoint"),
        true,
    );
    anchor.advance(tip).expect("fixture anchor");
    drop(journal);
    assert!(matches!(
        fixture.open(&anchor, spacious()),
        Err(JournalError::Corrupt)
    ));
}

#[test]
fn ack_and_checkpoint_preserve_pending_completion_capacity() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture
        .open(&anchor, limits())
        .expect("tight local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    let identity = journal.order[0];
    let mut grant = fixture.capability.grant.clone();
    grant.subject = address().recipient;
    grant.operations = CapabilityOperations::from_operations(&[MailboxOperation::Receive]);
    let receive = crate::mailbox::sign_capability(grant, &fixture.signer).expect("test Receive");
    let mut context = fixture.context.clone();
    context.acting_principal = address().recipient;
    context.required_operation = MailboxOperation::Receive;
    journal
        .acknowledge(
            identity,
            JournalReceive {
                capability: &receive,
                context: &context,
                encryption_key: &fixture.payload_key,
                sender_key: &fixture.sender_key,
            },
            |tip| anchor.advance(tip),
        )
        .expect("ACK preserves reserved completion");
    journal
        .compact_local(context.now_unix_ms, &fixture.signer, &anchor)
        .expect("checkpoint preserves reserved completion");
    journal.receipt_fault = None;
    journal
        .recover_local_encoded(fixture.request(), &anchor)
        .expect("completion still fits")
        .expect("known acceptance");
    assert_eq!(journal.seen.len(), 1);
    assert!(journal.seen.get(&identity).expect("retained").acknowledged);
}

#[test]
fn completion_and_checkpoint_bounds_cover_maximum_width_fields() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    let identity = journal.order[0];
    let entry = journal.seen.get(&identity).expect("accepted");
    let sample = crate::mailbox::journal::receipt::receipt_size_sample(&entry.accepted_receipt)
        .expect("size sample");
    let maximum = journal.sizing_record(JournalEvent::ReceiptCompleted {
        identity,
        encoded_receipt: sample,
    });
    let size = crate::mailbox::journal::receipt::record_bytes(&maximum, 32).expect("record bound");
    assert!(matches!(
        entry.receipt_completion,
        Some(ReceiptCompletion::Pending { reserved_bytes }) if reserved_bytes == size
    ));
    let pending = journal
        .checkpoint_state(i64::MAX)
        .expect("pending checkpoint");
    let bound = journal
        .checkpoint_bound(&pending)
        .expect("checkpoint bound");
    for completion in [
        ReceiptCompletion::Pending {
            reserved_bytes: u64::MAX,
        },
        ReceiptCompletion::Retained {
            encoded_receipt: crate::mailbox::journal::receipt::receipt_size_sample(
                &entry.accepted_receipt,
            )
            .expect("future retained length"),
        },
    ] {
        let mut state = pending.clone();
        state.source = JournalTip {
            cursor: u64::MAX,
            head: [u8::MAX; 32],
        };
        state.entries[0].seen.receipt_completion = Some(completion);
        let record = journal.sizing_record(JournalEvent::Checkpoint {
            state: Box::new(state),
            authorization_signature: vec![u8::MAX; 64],
        });
        assert!(
            crate::mailbox::journal::receipt::record_bytes(&record, 64)
                .expect("maximum-width snapshot")
                <= bound,
            "future pending/retained snapshots both fit the checkpoint reserve",
        );
    }
}

#[test]
fn duplicate_and_orphan_completions_refuse_without_anchor_advance() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    let signed = journal
        .admit_local(fixture.request(), &anchor)
        .expect("retained acceptance");
    let identity = journal.order[0];
    let encoded = STANDARD_NO_PAD.encode(serde_json::to_vec(&signed).expect("exact receipt"));
    let duplicate = Record {
        version: 4,
        cursor: 3,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(fixture.reference),
        event: JournalEvent::ReceiptCompleted {
            identity,
            encoded_receipt: encoded.clone(),
        },
    };
    publish_test_record(
        &journal,
        3,
        &serde_json::to_vec(&duplicate).expect("duplicate record"),
        false,
    );
    drop(journal);
    assert!(matches!(
        fixture.open(&anchor, spacious()),
        Err(JournalError::Corrupt)
    ));
    assert_eq!(anchor.tip().cursor, 2);

    let empty = Fixture::new();
    let empty_anchor = empty.anchor();
    let journal = empty
        .open(&empty_anchor, spacious())
        .expect("empty journal");
    let orphan = Record {
        version: 4,
        cursor: 1,
        previous: journal.tip.head,
        address: address(),
        history_key: Some(empty.reference),
        event: JournalEvent::ReceiptCompleted {
            identity,
            encoded_receipt: encoded,
        },
    };
    publish_test_record(
        &journal,
        1,
        &serde_json::to_vec(&orphan).expect("orphan record"),
        false,
    );
    drop(journal);
    assert!(matches!(
        empty.open(&empty_anchor, spacious()),
        Err(JournalError::Corrupt)
    ));
    assert_eq!(empty_anchor.tip(), JournalTip::genesis());
}

#[test]
fn pending_receipt_retires_only_after_committed_terminal_retention() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    journal.receipt_fault = Some(ReceiptFault::BeforeSign);
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::ReceiptPending)
    ));
    let expiry = fixture.envelope.routing.expires_at_unix_ms;
    let horizon = local_retention()
        .retained_until(expiry)
        .expect("signed horizon");
    journal
        .expire_next(expiry, &fixture.signer, |tip| anchor.advance(tip))
        .expect("committed terminal expiry")
        .expect("expired message");
    journal
        .compact_local(horizon, &fixture.signer, &anchor)
        .expect("checkpoint at exact horizon");
    assert_eq!(
        journal.seen.len(),
        1,
        "terminal evidence survives the full signed horizon"
    );
    assert!(matches!(
        journal
            .seen
            .values()
            .next()
            .expect("pending entry")
            .receipt_completion,
        Some(ReceiptCompletion::Pending { .. })
    ));
    journal
        .compact_local(horizon + 1, &fixture.signer, &anchor)
        .expect("checkpoint after the signed horizon");
    assert!(
        journal.seen.is_empty(),
        "expired pending receipt must not reserve capacity forever"
    );
    assert!(
        !journal
            .local_compaction_due(horizon + 1)
            .expect("maintenance due")
    );
    drop(journal);
    let journal = fixture
        .open(&anchor, spacious())
        .expect("reopen retired obligations");
    assert!(journal.seen.is_empty());
    assert_eq!(
        journal
            .completion_reservations(
                &journal
                    .checkpoint_state(horizon + 1)
                    .expect("retained snapshot")
            )
            .expect("completion accounting"),
        (0, 0),
        "retiring the terminal obligation releases its completion reserve",
    );
    assert!(
        !journal
            .local_compaction_due(horizon + 1)
            .expect("no repeated maintenance")
    );
}

fn tip_at(cursor: u64) -> JournalTip {
    JournalTip {
        cursor,
        head: [cursor as u8; 32],
    }
}

type Calls = std::sync::Arc<Mutex<Vec<(JournalTip, JournalTip)>>>;

fn recording(calls: &Calls, refuse: bool) -> FinalCommit {
    let calls = std::sync::Arc::clone(calls);
    Box::new(move |current, next| {
        calls.lock().expect("calls").push((current, next));
        if refuse {
            Err(JournalError::Rollback)
        } else {
            Ok(())
        }
    })
}

#[test]
fn a_refusing_final_commit_leaves_the_anchor_file_and_tip_unchanged() {
    let fixture = Fixture::new();
    let path = fixture.dir.path().join("anchor").join("tip");
    let calls = Calls::default();
    let anchor = fixture.anchor().with_final_commit(recording(&calls, true));
    assert!(matches!(
        anchor.advance(tip_at(1)),
        Err(JournalError::Rollback)
    ));
    assert_eq!(anchor.tip(), JournalTip::genesis());
    assert!(!path.exists());
    drop(anchor);

    let anchor = fixture.anchor().with_final_commit(recording(&calls, false));
    anchor.advance(tip_at(1)).expect("hook then local write");
    assert_eq!(anchor.tip(), tip_at(1));
    assert!(path.exists());
    assert_eq!(
        *calls.lock().expect("calls"),
        vec![
            (JournalTip::genesis(), tip_at(1)),
            (JournalTip::genesis(), tip_at(1))
        ]
    );
}

#[test]
fn a_journal_poisoned_by_a_refusing_hook_reconciles_through_the_same_hook_call() {
    let fixture = Fixture::new();
    let path = fixture.dir.path().join("anchor").join("tip");
    let calls = Calls::default();
    let anchor = fixture.anchor().with_final_commit(recording(&calls, true));
    let mut journal = fixture.open(&anchor, spacious()).expect("local journal");
    assert!(journal.admit_local(fixture.request(), &anchor).is_err());
    assert!(matches!(
        journal.admit_local(fixture.request(), &anchor),
        Err(JournalError::Uncertain)
    ));
    let refused = calls.lock().expect("calls").clone();
    assert_eq!(refused.len(), 1);
    drop(journal);
    drop(anchor);
    assert!(!path.exists());

    let anchor = fixture.anchor().with_final_commit(recording(&calls, true));
    assert!(fixture.open(&anchor, spacious()).is_err());
    assert!(!path.exists(), "a refused reconcile writes nothing");
    assert_eq!(anchor.tip(), JournalTip::genesis());
    drop(anchor);

    let anchor = fixture.anchor().with_final_commit(recording(&calls, false));
    fixture.open(&anchor, spacious()).expect("reconcile");
    assert_eq!(anchor.tip(), refused[0].1);
    let all = calls.lock().expect("calls").clone();
    assert_eq!(all.last(), refused.first());
}
