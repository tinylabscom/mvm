use std::sync::atomic::AtomicUsize;

use ed25519_dalek::SigningKey;
use mvm_contract::policy::approval::ApprovalState;
use mvm_core::plan::TenantId;

use super::*;
use crate::supervisor::audit_file::FileAuditSigner;
use crate::supervisor::runtime_approval::BrokerError;

/// How a [`Scripted`] broker answers one prompt.
type Script = Box<dyn Fn(&ApprovalPrompt) -> Result<ApprovalAnswer, BrokerError> + Send + Sync>;

/// A broker that answers from a script and counts how often it was asked.
struct Scripted {
    answer: Script,
    delay: Duration,
    asked: AtomicUsize,
    last: Mutex<Option<ApprovalPrompt>>,
}

#[async_trait]
impl ApprovalBroker for Scripted {
    async fn ask(&self, prompt: &ApprovalPrompt) -> Result<ApprovalAnswer, BrokerError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(prompt.clone());
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        (self.answer)(prompt)
    }
}

fn scripted(
    answer: impl Fn(&ApprovalPrompt) -> Result<ApprovalAnswer, BrokerError> + Send + Sync + 'static,
) -> Arc<Scripted> {
    Arc::new(Scripted {
        answer: Box::new(answer),
        delay: Duration::ZERO,
        asked: AtomicUsize::new(0),
        last: Mutex::new(None),
    })
}

fn approve(scope: ApprovalScope) -> Arc<Scripted> {
    scripted(move |p| Ok(ApprovalAnswer::approved(p.request_id.clone(), scope, "tty")))
}

struct Harness {
    supervisor: ApprovalSupervisor,
    time: Arc<AtomicU64>,
    audit_path: std::path::PathBuf,
    audit_key: ed25519_dalek::VerifyingKey,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn chain(&self) -> String {
        crate::supervisor::audit_file::verify_audit_chain(&self.audit_path, &self.audit_key)
            .expect("audit chain verifies");
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }

    fn advance(&self, ms: u64) {
        self.time.fetch_add(ms, Ordering::SeqCst);
    }
}

fn harness(
    broker: Option<Arc<dyn ApprovalBroker>>,
    edit: impl FnOnce(ApprovalSupervisorBuilder) -> ApprovalSupervisorBuilder,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let audit_key = signing_key.verifying_key();
    let audit_path = dir.path().join("audit.jsonl");
    let signer = FileAuditSigner::open_file(signing_key, &audit_path).unwrap();
    let recorder = Arc::new(Recorder::new(
        Arc::new(signer),
        TenantId("approval-tenant".into()),
    ));
    let time = Arc::new(AtomicU64::new(1_800_000_000_000));
    let clock_time = Arc::clone(&time);
    let mut builder = ApprovalSupervisor::builder("vm-Test_1")
        .recorder(Some(recorder))
        .clock(Arc::new(move || clock_time.load(Ordering::SeqCst)));
    if let Some(broker) = broker {
        builder = builder.broker(broker);
    }
    Harness {
        supervisor: edit(builder).build().unwrap(),
        time,
        audit_path,
        audit_key,
        _dir: dir,
    }
}

fn egress(method: &str, path: &str) -> ApprovalSubject {
    ApprovalSubject::Egress {
        route_id: "github".into(),
        rule: "rule-2".into(),
        destination: "api.github.com:443".into(),
        method: method.into(),
        path: path.into(),
    }
}

fn events(chain: &str, event: &str) -> usize {
    chain.matches(&format!("\"event\":\"{event}\"")).count()
}

#[tokio::test]
async fn an_approval_is_granted_recorded_in_the_ledger_and_audited() {
    let broker = approve(ApprovalScope::Once);
    let h = harness(Some(broker.clone()), |b| b);
    let verdict = h
        .supervisor
        .decide(&egress("POST", "/repos/o/r/issues"))
        .await;
    assert_eq!(verdict, ApprovalVerdict::Approved);

    let prompt = broker.last.lock().unwrap().clone().unwrap();
    assert_eq!(
        h.supervisor.ledger_state(&prompt.request_id),
        Some(ApprovalState::Approved)
    );
    let chain = h.chain();
    assert_eq!(events(&chain, "approval.requested"), 1, "{chain}");
    assert_eq!(events(&chain, "approval.granted"), 1, "{chain}");
    assert!(chain.contains(prompt.request_id.as_str()), "{chain}");
    assert!(chain.contains("\"route\":\"github\""), "{chain}");
    assert!(
        !chain.contains("/repos/o/r/issues"),
        "no path on the chain: {chain}"
    );
}

#[tokio::test]
async fn a_denial_is_a_denial_and_is_recorded() {
    let broker = scripted(|p| Ok(ApprovalAnswer::denied(p.request_id.clone(), "tty")));
    let h = harness(Some(broker.clone()), |b| b);
    assert!(matches!(
        h.supervisor.decide(&egress("POST", "/x")).await,
        ApprovalVerdict::Denied { .. }
    ));
    let prompt = broker.last.lock().unwrap().clone().unwrap();
    assert_eq!(
        h.supervisor.ledger_state(&prompt.request_id),
        Some(ApprovalState::Denied)
    );
    assert_eq!(events(&h.chain(), "approval.denied"), 1);
}

#[tokio::test]
async fn a_timeout_denies_expires_the_request_and_is_recorded_as_timed_out() {
    let broker = Arc::new(Scripted {
        answer: Box::new(|p| {
            Ok(ApprovalAnswer::approved(
                p.request_id.clone(),
                ApprovalScope::Once,
                "late",
            ))
        }),
        delay: Duration::from_secs(5),
        asked: AtomicUsize::new(0),
        last: Mutex::new(None),
    });
    let h = harness(Some(broker.clone()), |b| {
        b.timeout(Duration::from_millis(50))
    });
    // The clock the ledger reads must have passed the deadline too.
    let supervisor = &h.supervisor;
    let subject = egress("POST", "/x");
    let decide = supervisor.decide(&subject);
    let advance = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        h.advance(1_000);
    };
    let (verdict, ()) = tokio::join!(decide, advance);
    assert_eq!(
        verdict,
        ApprovalVerdict::Denied {
            reason: "timed_out"
        }
    );
    let prompt = broker.last.lock().unwrap().clone().unwrap();
    assert_eq!(
        supervisor.ledger_state(&prompt.request_id),
        Some(ApprovalState::Expired)
    );
    assert_eq!(events(&h.chain(), "approval.timed_out"), 1);
}

#[tokio::test]
async fn no_broker_an_unreachable_broker_or_a_wrong_answer_is_a_denial() {
    let h = harness(None, |b| b);
    assert_eq!(
        h.supervisor.decide(&egress("GET", "/")).await,
        ApprovalVerdict::Denied {
            reason: REASON_APPROVAL_UNAVAILABLE
        }
    );

    let unreachable = scripted(|_| Err(BrokerError::Unavailable));
    let h = harness(Some(unreachable), |b| b);
    assert_eq!(
        h.supervisor.decide(&egress("GET", "/")).await,
        ApprovalVerdict::Denied {
            reason: REASON_APPROVAL_UNAVAILABLE
        }
    );

    let wrong = scripted(|_| {
        Ok(ApprovalAnswer::approved(
            ApprovalRequestId::parse("appr-someone-else").unwrap(),
            ApprovalScope::Session,
            "tty",
        ))
    });
    let h = harness(Some(wrong), |b| b);
    assert_eq!(
        h.supervisor.decide(&egress("GET", "/")).await,
        ApprovalVerdict::Denied {
            reason: "answer_mismatch"
        }
    );
    // The mismatched approval granted nothing for later.
    assert!(matches!(
        h.supervisor.decide(&egress("GET", "/")).await,
        ApprovalVerdict::Denied { .. }
    ));
}

#[tokio::test]
async fn a_session_approval_covers_the_same_question_until_its_ttl_and_no_other() {
    let broker = approve(ApprovalScope::Session);
    let h = harness(Some(broker.clone()), |b| {
        b.session_ttl(Duration::from_secs(60))
    });
    assert_eq!(
        h.supervisor.decide(&egress("POST", "/a")).await,
        ApprovalVerdict::Approved
    );
    // Same rule and method, a different path: covered.
    assert_eq!(
        h.supervisor.decide(&egress("POST", "/b")).await,
        ApprovalVerdict::Approved
    );
    assert_eq!(broker.asked.load(Ordering::SeqCst), 1);
    // A different method is a different question.
    h.supervisor.decide(&egress("DELETE", "/a")).await;
    assert_eq!(broker.asked.load(Ordering::SeqCst), 2);
    // Past the TTL the question is asked again.
    h.advance(61_000);
    h.supervisor.decide(&egress("POST", "/a")).await;
    assert_eq!(broker.asked.load(Ordering::SeqCst), 3);
    assert!(h.chain().contains("session_grant"));
}

#[tokio::test]
async fn a_once_approval_covers_nothing_after_it() {
    let broker = approve(ApprovalScope::Once);
    let h = harness(Some(broker.clone()), |b| b);
    h.supervisor.decide(&egress("POST", "/a")).await;
    h.supervisor.decide(&egress("POST", "/a")).await;
    assert_eq!(broker.asked.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn past_the_rate_limit_a_question_is_denied_unasked_and_recorded() {
    let broker = approve(ApprovalScope::Once);
    let h = harness(Some(broker.clone()), |b| b.prompts_per_minute(2));
    h.supervisor.decide(&egress("POST", "/1")).await;
    h.supervisor.decide(&egress("POST", "/2")).await;
    assert_eq!(
        h.supervisor.decide(&egress("POST", "/3")).await,
        ApprovalVerdict::Denied {
            reason: "rate_limited"
        }
    );
    assert_eq!(
        broker.asked.load(Ordering::SeqCst),
        2,
        "the third was never put"
    );
    assert!(h.chain().contains("rate_limited"));
    h.advance(60_000);
    assert_eq!(
        h.supervisor.decide(&egress("POST", "/4")).await,
        ApprovalVerdict::Approved
    );
}

#[tokio::test]
async fn guest_fields_are_bounded_before_they_are_sent() {
    let broker = approve(ApprovalScope::Once);
    let h = harness(Some(broker.clone()), |b| b);
    let long = "/".to_string() + &"a".repeat(5_000);
    h.supervisor.decide(&egress("POST", &long)).await;
    let prompt = broker.last.lock().unwrap().clone().unwrap();
    let ApprovalSubject::Egress { path, .. } = prompt.subject else {
        unreachable!()
    };
    assert_eq!(path.chars().count(), MAX_SUBJECT_FIELD_CHARS);
}

#[test]
fn a_session_id_is_contract_legal_for_any_instance_name() {
    for instance in [
        "vm-Test_1",
        "",
        "a/b..c",
        "  weird name  ",
        &"x".repeat(300),
    ] {
        let id = session_id_for(instance);
        assert!(
            AgentSessionId::parse(id.clone()).is_ok(),
            "{instance:?} -> {id:?}"
        );
    }
}
