//! Test-only co-commit journal model with a real host-signed audit chain.
//! Stop points are deterministic interruptions, not process-kill or power-loss tests.

#[path = "mailbox_audit_handshake/fixture.rs"]
mod fixture;

use fixture::{Endpoint, Event, Fixture, Kind, Outcome, Request, Stop};

#[test]
fn interruptions_reconstruct_disk_and_never_acknowledge_pending_acceptance() {
    for stop in [
        Stop::BeforeCommit,
        Stop::AfterCommit,
        Stop::AfterAudit,
        Stop::AuditSyncUnknown,
        Stop::AfterCompletion,
    ] {
        let fixture = Fixture::new();
        let request = Request::sample(1);
        let result = fixture.open().submit(&request, stop);
        assert!(!matches!(result, Outcome::Complete(_)));
        let reopened = fixture.open();
        if stop == Stop::BeforeCommit {
            assert_eq!(result, Outcome::Refused("before commit"));
            assert_eq!(reopened.record_count(), 0);
        } else {
            assert!(matches!(result, Outcome::Pending(_)));
            assert_eq!(reopened.record_count(), 1);
        }
        let visible = reopened.visible().unwrap();
        assert_eq!(visible.len(), usize::from(stop == Stop::AfterCompletion));
        let evidence = reopened.submit(&request, Stop::None).complete();
        assert_eq!(
            fixture.open().submit(&request, Stop::None).complete(),
            evidence,
            "exact retry must reuse the same evidence"
        );
        assert_eq!(fixture.open().audit_entries().unwrap().len(), 1);
        assert_eq!(fixture.open().visible().unwrap().len(), 1);
    }
}

#[test]
fn exact_retry_repairs_ambiguous_sync_before_success() {
    let fixture = Fixture::new();
    let request = Request::sample(1);
    assert!(matches!(
        fixture.open().submit(&request, Stop::AuditSyncUnknown),
        Outcome::Pending(_)
    ));
    let before = fixture.sync_repairs();
    fixture.open().submit(&request, Stop::None).complete();
    assert!(fixture.sync_repairs() > before);
    let bytes = std::fs::read(fixture.audit_path()).unwrap();
    let before = fixture.sync_repairs();
    fixture.open().submit(&request, Stop::None).complete();
    assert!(fixture.sync_repairs() > before);
    assert_eq!(std::fs::read(fixture.audit_path()).unwrap(), bytes);
}

#[test]
fn same_identity_with_different_request_or_signed_evidence_is_not_reused() {
    let fixture = Fixture::new();
    let request = Request::sample(1);
    fixture.open().submit(&request, Stop::AfterCommit);
    let mut conflict = request.clone();
    conflict.ciphertext[0] ^= 1;
    assert_eq!(
        fixture.open().submit(&conflict, Stop::None),
        Outcome::Refused("request conflict")
    );
    let mut entry = fixture.open().obligation(0);
    entry.labels.insert("recipient".into(), "forged".into());
    fixture.append_signed(&entry);
    let bytes = std::fs::read(fixture.audit_path()).unwrap();
    assert_eq!(
        fixture.open().submit(&request, Stop::None),
        Outcome::Pending("conflicting audit evidence")
    );
    assert_eq!(std::fs::read(fixture.audit_path()).unwrap(), bytes);
    assert!(fixture.open().visible().unwrap().is_empty());
}

#[test]
fn corrupt_wrong_key_and_missing_completed_evidence_are_never_absence() {
    for mode in ["corrupt", "wrong-key", "missing-complete"] {
        let fixture = Fixture::new();
        let request = Request::sample(1);
        if mode == "missing-complete" {
            fixture.open().submit(&request, Stop::None).complete();
            std::fs::write(fixture.audit_path(), []).unwrap();
        } else {
            fixture.open().submit(&request, Stop::AfterCommit);
            if mode == "wrong-key" {
                fixture.append_with_wrong_key(&fixture.open().obligation(0));
            } else {
                std::fs::write(fixture.audit_path(), b"not a signed chain\n").unwrap();
            }
        }
        let before = std::fs::read(fixture.audit_path()).unwrap();
        assert!(matches!(
            fixture.open().submit(&request, Stop::None),
            Outcome::Pending(_)
        ));
        assert_eq!(std::fs::read(fixture.audit_path()).unwrap(), before);
        assert!(fixture.open().visible().is_err() || fixture.open().visible().unwrap().is_empty());
    }
}

#[test]
fn wrong_completion_digest_never_repairs_or_exposes_valid_signed_evidence() {
    let fixture = Fixture::new();
    let request = Request::sample(1);
    fixture.open().submit(&request, Stop::None).complete();
    fixture.corrupt_completion();
    let audit = std::fs::read(fixture.audit_path()).unwrap();
    let journal = fixture.snapshot_bytes();
    assert_eq!(fixture.open().audit_entries().unwrap().len(), 1);
    assert_eq!(
        fixture.open().submit(&request, Stop::None),
        Outcome::Pending("conflicting audit evidence")
    );
    assert_eq!(fixture.open().visible(), Err("conflicting audit evidence"));
    assert_eq!(std::fs::read(fixture.audit_path()).unwrap(), audit);
    assert_eq!(fixture.snapshot_bytes(), journal);
}

#[test]
fn concurrent_conflicting_requests_admit_only_one_transition() {
    let fixture = Fixture::new();
    let first = Request::sample(1);
    let mut second = first.clone();
    second.ciphertext[0] ^= 1;
    let start = std::sync::Barrier::new(2);
    let (left, right) = std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            start.wait();
            fixture.open().submit(&first, Stop::None)
        });
        let right = scope.spawn(|| {
            start.wait();
            fixture.open().submit(&second, Stop::None)
        });
        (left.join().unwrap(), right.join().unwrap())
    });
    let winner = match (left, right) {
        (Outcome::Complete(_), Outcome::Refused("request conflict")) => &first,
        (Outcome::Refused("request conflict"), Outcome::Complete(_)) => &second,
        outcomes => panic!("exactly one request must win: {outcomes:?}"),
    };
    assert_eq!(fixture.open().record_count(), 1);
    let entries = fixture.open().audit_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].labels["ciphertext_commitment"],
        fixture::commitment(&winner.ciphertext)
    );
    assert_eq!(fixture.open().visible().unwrap().len(), 1);
}

#[test]
fn concurrent_exact_retries_publish_once_and_do_not_hold_journal_over_audit_wait() {
    let fixture = Fixture::new();
    let request = Request::sample(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| fixture.open().submit(&request, Stop::None).complete()))
            .collect();
        let evidence: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(evidence.windows(2).all(|pair| pair[0] == pair[1]));
    });
    assert_eq!(fixture.open().record_count(), 1);
    assert_eq!(fixture.open().audit_entries().unwrap().len(), 1);
    fixture.assert_journal_available_while_publication_waits(Request::sample(2));
}

#[test]
fn bounded_full_refuses_before_mutation_but_pending_work_has_completion_headroom() {
    let fixture = Fixture::new();
    let requests: Vec<_> = (0..fixture::CAPACITY as u64).map(Request::sample).collect();
    for request in &requests {
        assert!(matches!(
            fixture.open().submit(request, Stop::AfterCommit),
            Outcome::Pending(_)
        ));
    }
    let before = fixture.snapshot_bytes();
    assert_eq!(
        fixture.open().submit(&Request::sample(99), Stop::None),
        Outcome::Refused("full")
    );
    assert_eq!(fixture.snapshot_bytes(), before);
    for request in &requests {
        fixture.open().submit(request, Stop::None).complete();
    }
    assert_eq!(fixture.open().visible().unwrap().len(), fixture::CAPACITY);
    assert_eq!(
        fixture.open().audit_entries().unwrap().len(),
        fixture::CAPACITY
    );
}

#[test]
fn unavailable_audit_keeps_jointly_committed_work_pending_and_hidden() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.audit_path()).unwrap();
    let request = Request::sample(1);
    assert!(matches!(
        fixture.open().submit(&request, Stop::None),
        Outcome::Pending(_)
    ));
    assert_eq!(fixture.open().record_count(), 1);
    assert!(fixture.open().visible().unwrap().is_empty());
    std::fs::remove_dir(fixture.audit_path()).unwrap();
    fixture.open().submit(&request, Stop::None).complete();
}

#[test]
fn calls_replies_casts_and_coordination_have_ciphertext_only_evidence() {
    for kind in [Kind::Call, Kind::Reply, Kind::Cast] {
        for (sender, recipient) in [
            (Endpoint::Host, Endpoint::VmA),
            (Endpoint::VmA, Endpoint::VmB),
            (Endpoint::VmB, Endpoint::Host),
            (Endpoint::VmA, Endpoint::AuditService),
            (Endpoint::AuditService, Endpoint::VmA),
        ] {
            let fixture = Fixture::new();
            let mut request = Request::sample(7);
            request.kind = kind;
            request.sender = sender;
            request.recipient = recipient;
            let accepted = fixture.open().submit(&request, Stop::None).complete();
            request.event = Event::Expired;
            let expired = fixture.open().submit(&request, Stop::None).complete();
            assert_ne!(
                accepted, expired,
                "MessageId alone is not a transition identity"
            );
            let entries = fixture.open().audit_entries().unwrap();
            assert_eq!(entries.len(), 2);
            let audit = std::fs::read_to_string(fixture.audit_path()).unwrap();
            assert!(!audit.contains(fixture::PLAINTEXT));
            assert!(!audit.contains(&fixture::plaintext_hash()));
            assert!(entries.iter().all(|entry| {
                entry.labels["ciphertext_commitment"] == fixture::commitment(&request.ciphertext)
                    && entry.labels.contains_key("history")
                    && entry.labels.contains_key("cursor")
                    && entry.labels.contains_key("transition_hash")
            }));
        }
    }
}

#[test]
fn oversized_requests_and_bounded_recovery_scans_refuse_without_mutation() {
    let fixture = Fixture::new();
    let mut request = Request::sample(1);
    request.ciphertext = vec![0; fixture::MAX_CIPHERTEXT + 1];
    let before = fixture.snapshot_bytes();
    assert_eq!(
        fixture.open().submit(&request, Stop::None),
        Outcome::Refused("oversized")
    );
    assert_eq!(fixture.snapshot_bytes(), before);
    let request = Request::sample(1);
    fixture.open().submit(&request, Stop::AfterCommit);
    std::fs::write(fixture.audit_path(), vec![0; fixture::MAX_AUDIT_BYTES + 1]).unwrap();
    assert_eq!(
        fixture.open().submit(&request, Stop::None),
        Outcome::Pending("bounded audit read")
    );
    assert_eq!(fixture.open().record_count(), 1);
}
