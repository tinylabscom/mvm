use std::path::Path;

use mvm_core::host_interface::workload::{CanonicalLedger, WorkloadChange, read_ledger_bytes_at};
use mvm_core::mailbox::journal::FileJournalAnchor;

use super::*;
use crate::policy_generation::workload_store::{
    DestinationRefusal, OwnedWorkloadStore, is_commit_unresolved,
};

impl DestinationAuthority for OwnedWorkloadStore {
    fn enroll(&self, enrollment: &DestinationEnrollment) -> DestinationOutcome {
        outcome(self.enroll_destination(enrollment))
    }

    fn commit(&self, prepared: &SignedPreparedHead) -> DestinationOutcome {
        outcome(self.commit_destination(prepared))
    }

    fn recover(&self) {
        let _ = OwnedWorkloadStore::recover(self);
    }
}

fn outcome(result: anyhow::Result<DestinationCommit>) -> DestinationOutcome {
    match result {
        Ok(commit) => DestinationOutcome::Committed(commit),
        Err(error) => match error.downcast_ref::<DestinationRefusal>() {
            Some(refusal) if refusal.is_not_enrolled() => {
                DestinationOutcome::NotEnrolled(format!("{error:#}"))
            }
            Some(_) => DestinationOutcome::Refused(format!("{error:#}")),
            None => DestinationOutcome::Unknown {
                message: format!("{error:#}"),
                needs_recovery: is_commit_unresolved(&error),
            },
        },
    }
}

fn address() -> mvm_contract::protocol::mailbox::MailboxAddress {
    use mvm_contract::protocol::mailbox::{
        AuthorizationDomainId, MailboxAddress, MailboxId, PrincipalId, TenantId,
    };
    MailboxAddress {
        tenant: TenantId::from_bytes([1; 32]),
        authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
        mailbox: MailboxId::from_bytes([3; 32]),
        recipient: PrincipalId::from_bytes([4; 32]),
    }
}

fn tip(cursor: u64) -> JournalTip {
    JournalTip {
        cursor,
        head: [cursor as u8; 32],
    }
}

const ID: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

fn destination() -> Destination {
    Destination {
        id: ID.into(),
        workload: "w".into(),
        epoch: ExecutionEpoch::new(1).unwrap(),
        key: SigningKey::from_bytes(&[9; 32]),
    }
}

struct Fixture {
    home: tempfile::TempDir,
    store: Arc<OwnedWorkloadStore>,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let store = Arc::new(OwnedWorkloadStore::open(home.path()).unwrap());
        Self { home, store }
    }

    fn anchor_path(&self) -> std::path::PathBuf {
        self.home.path().join("anchors").join("tip")
    }

    fn anchor(&self) -> FileJournalAnchor {
        FileJournalAnchor::open(&self.anchor_path(), address(), [3; 32]).unwrap()
    }

    fn coordinate(&self) -> Result<Coordinated, JournalError> {
        coordinate(self.anchor(), self.store.clone(), destination())
    }

    fn ledger(&self) -> CanonicalLedger {
        let bytes = read_ledger_bytes_at(self.home.path()).unwrap().unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn coordinator_cursor(&self) -> u64 {
        self.ledger().destinations[ID].tip.cursor
    }
}

fn bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn an_advance_moves_the_coordinator_tip_before_the_local_anchor() {
    let fixture = Fixture::new();
    let coordinated = fixture.coordinate().unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    coordinated.anchor.advance(tip(2)).unwrap();
    assert_eq!(coordinated.anchor.tip(), tip(2));
    assert_eq!(fixture.coordinator_cursor(), 2);
    assert!(!coordinated.refused.load(Ordering::SeqCst));
}

#[test]
fn after_a_quarantine_the_next_advance_fails_without_touching_the_anchor() {
    let fixture = Fixture::new();
    let coordinated = fixture.coordinate().unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    let anchor_before = bytes(&fixture.anchor_path());
    fixture
        .store
        .commit(&WorkloadChange::Quarantine {
            workload: "w".into(),
        })
        .unwrap();

    assert!(coordinated.anchor.advance(tip(2)).is_err());
    assert!(coordinated.refused.load(Ordering::SeqCst));
    assert_eq!(bytes(&fixture.anchor_path()), anchor_before);
    assert_eq!(coordinated.anchor.tip(), tip(1));
    assert_eq!(
        fixture.coordinator_cursor(),
        1,
        "the commit before the quarantine keeps its tip"
    );
    drop(coordinated);
    // The same binding is answered after a quarantine, so a commit that landed
    // first is anchored; no further commit is.
    let again = fixture.coordinate().unwrap();
    assert_eq!(again.anchor.tip(), tip(1));
    assert!(again.anchor.advance(tip(2)).is_err());
    assert!(again.refused.load(Ordering::SeqCst));
    assert_eq!(bytes(&fixture.anchor_path()), anchor_before);
}

#[test]
fn a_commit_the_owner_took_before_the_local_write_is_replayed_not_refused() {
    let fixture = Fixture::new();
    let first = fixture.coordinate().unwrap();
    // The owner moves, then the helper dies before writing its anchor.
    let prepared = PreparedHead {
        destination: ID.into(),
        workload: "w".into(),
        epoch: ExecutionEpoch::new(1).unwrap(),
        expected: wire(JournalTip::genesis()),
        next: wire(tip(1)),
        retention: false,
    }
    .sign(&destination().key)
    .unwrap();
    assert!(matches!(
        DestinationAuthority::commit(&*fixture.store, &prepared),
        DestinationOutcome::Committed(_)
    ));
    drop(first);

    let again = fixture.coordinate().unwrap();
    assert_eq!(again.anchor.tip(), JournalTip::genesis());
    again.anchor.advance(tip(1)).unwrap();
    assert_eq!(again.anchor.tip(), tip(1));
    assert_eq!(fixture.coordinator_cursor(), 1);
}

#[test]
fn a_coordinator_more_than_one_commit_ahead_refuses_to_open() {
    let fixture = Fixture::new();
    let coordinated = fixture.coordinate().unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    coordinated.anchor.advance(tip(2)).unwrap();
    drop(coordinated);
    std::fs::remove_file(fixture.anchor_path()).unwrap();
    assert!(matches!(fixture.coordinate(), Err(JournalError::Rollback)));
}

struct Scripted {
    replies: std::sync::Mutex<Vec<DestinationOutcome>>,
    commits: std::sync::Mutex<Vec<SignedPreparedHead>>,
    recovers: std::sync::atomic::AtomicUsize,
}

impl DestinationAuthority for Scripted {
    fn enroll(&self, enrollment: &DestinationEnrollment) -> DestinationOutcome {
        DestinationOutcome::Committed(DestinationCommit {
            sequence: 1,
            tip: enrollment.tip.clone(),
        })
    }

    fn commit(&self, prepared: &SignedPreparedHead) -> DestinationOutcome {
        self.commits.lock().unwrap().push(prepared.clone());
        self.replies.lock().unwrap().remove(0)
    }

    fn recover(&self) {
        self.recovers.fetch_add(1, Ordering::SeqCst);
    }
}

fn unresolved() -> DestinationOutcome {
    DestinationOutcome::Unknown {
        message: "unresolved".into(),
        needs_recovery: true,
    }
}

#[test]
fn an_unknown_answer_resubmits_the_same_signed_head_then_gives_up_without_a_refusal() {
    let fixture = Fixture::new();
    let scripted = Arc::new(Scripted {
        replies: std::sync::Mutex::new(vec![unresolved(), unresolved(), unresolved()]),
        commits: Default::default(),
        recovers: Default::default(),
    });
    let coordinated = coordinate(fixture.anchor(), scripted.clone(), destination()).unwrap();
    let error = coordinated.anchor.advance(tip(1)).unwrap_err();
    assert!(matches!(error, JournalError::Storage(_)), "{error}");
    let commits = scripted.commits.lock().unwrap();
    assert_eq!(commits.len(), 3);
    assert!(commits.iter().all(|head| *head == commits[0]));
    assert_eq!(scripted.recovers.load(Ordering::SeqCst), 2);
    assert!(!coordinated.refused.load(Ordering::SeqCst));
    assert!(coordinated.unknown.load(Ordering::SeqCst));
    assert_eq!(coordinated.anchor.tip(), JournalTip::genesis());
    assert!(
        !fixture.anchor_path().exists(),
        "an unknown outcome writes no local anchor"
    );
}

#[test]
fn a_late_success_after_an_unknown_answer_commits_the_anchor() {
    let fixture = Fixture::new();
    let scripted = Arc::new(Scripted {
        replies: std::sync::Mutex::new(vec![
            unresolved(),
            DestinationOutcome::Committed(DestinationCommit {
                sequence: 2,
                tip: wire(tip(1)),
            }),
        ]),
        commits: Default::default(),
        recovers: Default::default(),
    });
    let coordinated = coordinate(fixture.anchor(), scripted, destination()).unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    assert_eq!(coordinated.anchor.tip(), tip(1));
}

#[test]
fn the_retention_flag_is_copied_into_the_head_the_owner_receives() {
    let fixture = Fixture::new();
    let scripted = Arc::new(Scripted {
        replies: std::sync::Mutex::new(vec![
            DestinationOutcome::Committed(DestinationCommit {
                sequence: 2,
                tip: wire(tip(1)),
            }),
            DestinationOutcome::Committed(DestinationCommit {
                sequence: 3,
                tip: wire(tip(2)),
            }),
        ]),
        commits: Default::default(),
        recovers: Default::default(),
    });
    let coordinated = coordinate(fixture.anchor(), scripted.clone(), destination()).unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    coordinated.retention.store(true, Ordering::SeqCst);
    coordinated.anchor.advance(tip(2)).unwrap();
    let commits = scripted.commits.lock().unwrap();
    assert!(!commits[0].head.retention);
    assert!(commits[1].head.retention);
}

/// Remove the destination from the ledger, as retirement does.
fn evict(fixture: &Fixture) {
    let mut ledger = fixture.ledger();
    ledger.destinations.remove(ID);
    std::fs::write(
        mvm_core::host_interface::workload::canonical_dir_at(fixture.home.path())
            .join(mvm_core::host_interface::workload::LEDGER_FILE),
        serde_json::to_vec(&ledger).unwrap(),
    )
    .unwrap();
}

#[test]
fn an_evicted_destination_enrolls_again_at_its_current_tip_and_its_commit_lands() {
    let fixture = Fixture::new();
    let coordinated = fixture.coordinate().unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    evict(&fixture);
    coordinated.anchor.advance(tip(2)).unwrap();
    assert_eq!(coordinated.anchor.tip(), tip(2));
    assert_eq!(fixture.coordinator_cursor(), 2);
    assert!(!coordinated.refused.load(Ordering::SeqCst));
}

#[test]
fn an_evicted_destination_of_a_quarantined_workload_is_refused_and_sets_the_refused_flag() {
    let fixture = Fixture::new();
    let coordinated = fixture.coordinate().unwrap();
    coordinated.anchor.advance(tip(1)).unwrap();
    evict(&fixture);
    fixture
        .store
        .commit(&WorkloadChange::Quarantine {
            workload: "w".into(),
        })
        .unwrap();
    assert!(coordinated.anchor.advance(tip(2)).is_err());
    assert!(coordinated.refused.load(Ordering::SeqCst));
    assert!(!coordinated.unknown.load(Ordering::SeqCst));
    assert_eq!(coordinated.anchor.tip(), tip(1));
}

#[test]
fn the_post_open_check_requires_the_anchor_to_have_reached_the_enrolled_tip() {
    let fixture = Fixture::new();
    let anchor = fixture.anchor();
    // The owner is one commit ahead and the journal had no suffix to explain it.
    assert!(matches!(
        require_reached(&anchor, &wire(tip(1))),
        Err(JournalError::Rollback)
    ));
    assert!(require_reached(&anchor, &wire(JournalTip::genesis())).is_ok());
    anchor.advance(tip(1)).unwrap();
    assert!(require_reached(&anchor, &wire(tip(1))).is_ok());
    // Reopening committed a record the owner had not seen at enrollment.
    assert!(require_reached(&anchor, &wire(JournalTip::genesis())).is_ok());
    // The same cursor under another head is a fork, not progress.
    let mut other = wire(tip(1));
    other.head = hex::encode([0xEE; 32]);
    assert!(matches!(
        require_reached(&anchor, &other),
        Err(JournalError::Rollback)
    ));
}

#[test]
fn coordinating_reports_the_tip_the_owner_enrolled() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.coordinate().unwrap().enrolled,
        wire(JournalTip::genesis())
    );
}

#[test]
fn an_actor_destination_id_is_stable_and_differs_by_purpose_and_message() {
    use mvm_contract::protocol::mailbox::ExecutionEpoch as ContractEpoch;
    let epoch = ContractEpoch::new(1).unwrap();
    let id = |journal, message: u8| {
        actor_destination_id(
            &address(),
            &epoch,
            journal,
            &MessageId::from_bytes([message; 32]),
        )
        .unwrap()
    };
    let call = id(ActorJournal::Call, 0);
    assert_eq!(call, id(ActorJournal::Call, 0));
    assert_eq!(call.len(), 64);
    assert!(call.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_ne!(call, id(ActorJournal::Control, 0));
    assert_ne!(call, id(ActorJournal::Call, 1));
    assert_eq!(
        call, "08d67bec8b7fcb32edefcd37a167cf4d92de1e1dc90764062def62262ba89b73",
        "the derivation is part of what a ledger remembers"
    );
}
