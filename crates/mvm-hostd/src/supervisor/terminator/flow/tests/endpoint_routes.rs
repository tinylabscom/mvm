//! Endpoint routes decide requests on a terminated flow.
//!
//! The allow-list admits the destination; a route narrows what a request may
//! do there by method and path. Each decision is on the chain with the route
//! id and the rule that decided, an `ask` is refused until an approver answers
//! it, and a destination no secret is bound to is terminated for its rules
//! only when the route grants interception.

use super::*;
use crate::supervisor::runtime_approval::{
    ApprovalSubject, ApprovalVerdict, REASON_APPROVAL_UNAVAILABLE, RuntimeApprover,
};
use mvm_contract::policy::routes::{EgressRoute, EndpointRule, RouteOutcome};

fn recording() -> Arc<RecordingForwarder> {
    Arc::new(RecordingForwarder {
        seen: Mutex::new(None),
        body: b"{\"ok\":true}".to_vec(),
        fail_after_send: std::sync::atomic::AtomicBool::new(false),
    })
}

fn rule(method: &str, path: &str, outcome: RouteOutcome) -> EndpointRule {
    EndpointRule {
        id: None,
        method: Some(method.to_string()),
        path: path.to_string(),
        outcome,
    }
}

fn route(host: &str, rules: Vec<EndpointRule>, intercept: bool) -> EgressRoute {
    EgressRoute {
        id: "model-api".into(),
        host: host.to_string(),
        port: 443,
        rules,
        otherwise: RouteOutcome::Deny,
        intercept,
    }
}

/// One secret bound to [`BOUND_HOST`], its route carrying `rules`.
fn bound_with(
    rules: Vec<EndpointRule>,
    approver: Option<Arc<dyn RuntimeApprover>>,
) -> (Assembled, Arc<RecordingForwarder>) {
    let forwarder = recording();
    let vm = assemble_with(
        &[Bound {
            secret: "model-api",
            pattern: BOUND_HOST,
        }],
        &[BOUND_HOST],
        forwarder.clone(),
        Routing {
            routes: vec![route(BOUND_HOST, rules, false)],
            approver,
            ..Routing::default()
        },
    );
    (vm, forwarder)
}

fn send(
    vm: &Assembled,
    host: &str,
    method: &str,
    path: &str,
    placeholder: Option<&str>,
) -> Vec<u8> {
    let auth = placeholder
        .map(|p| format!("authorization: Bearer {p}\r\n"))
        .unwrap_or_default();
    let request =
        format!("{method} {path} HTTP/1.1\r\nhost: {host}\r\n{auth}content-length: 0\r\n\r\n");
    exchange_with(vm, host, &vm.intermediate_pem, request.as_bytes())
        .expect("the guest's tls client completes its handshake")
}

fn route_entries(chain: &str) -> Vec<&str> {
    chain
        .lines()
        .filter(|line| line.contains("host.route.decided"))
        .collect()
}

#[test]
fn an_allowed_get_is_forwarded_and_a_denied_post_is_refused_and_both_are_recorded() {
    let (vm, forwarder) = bound_with(
        vec![rule("GET", "/v1/models/**", RouteOutcome::Allow)],
        None,
    );
    let placeholder = vm.placeholders[0].clone();

    let allowed = send(&vm, BOUND_HOST, "GET", "/v1/models", Some(&placeholder));
    assert!(
        status_line(&allowed).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&allowed)
    );
    assert!(forwarder.seen.lock().unwrap().take().is_some());

    let refused = send(&vm, BOUND_HOST, "POST", "/v1/models", Some(&placeholder));
    assert!(
        status_line(&refused).starts_with("HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&refused)
    );
    assert!(
        forwarder.seen.lock().unwrap().is_none(),
        "a refused request never reaches the forward leg"
    );
    let chain = vm.audit_chain();
    let entries = route_entries(&chain);
    assert_eq!(entries.len(), 2, "{chain}");
    assert!(entries[0].contains("\"route\":\"model-api\""), "{chain}");
    assert!(entries[0].contains("\"rule\":\"rule-1\""), "{chain}");
    assert!(entries[0].contains("\"outcome\":\"allow\""), "{chain}");
    assert!(entries[0].contains("\"method\":\"GET\""), "{chain}");
    assert!(entries[1].contains("\"rule\":\"otherwise\""), "{chain}");
    assert!(entries[1].contains("\"outcome\":\"deny\""), "{chain}");
    assert!(
        entries[1].contains("\"reason\":\"route_denied\""),
        "{chain}"
    );
    assert!(
        !chain.contains("/v1/models"),
        "no path reaches the chain: {chain}"
    );
}

#[test]
fn an_ask_is_refused_until_an_approver_answers_it() {
    let (vm, forwarder) = bound_with(vec![rule("POST", "/v1/messages", RouteOutcome::Ask)], None);
    let refused = send(
        &vm,
        BOUND_HOST,
        "POST",
        "/v1/messages",
        Some(&vm.placeholders[0]),
    );
    assert!(status_line(&refused).starts_with("HTTP/1.1 502"));
    assert!(forwarder.seen.lock().unwrap().is_none());
    let chain = vm.audit_chain();
    assert!(chain.contains(REASON_APPROVAL_UNAVAILABLE), "{chain}");
    assert!(chain.contains("\"outcome\":\"ask\""), "{chain}");

    struct Approves;
    #[async_trait]
    impl RuntimeApprover for Approves {
        async fn decide(&self, subject: &ApprovalSubject) -> ApprovalVerdict {
            let ApprovalSubject::Egress {
                route_id,
                method,
                path,
                ..
            } = subject
            else {
                panic!("an egress question: {subject:?}");
            };
            assert_eq!(route_id, "model-api");
            assert_eq!(method, "POST");
            assert_eq!(path, "/v1/messages", "the prompt carries the path");
            ApprovalVerdict::Approved
        }
    }
    let (vm, forwarder) = bound_with(
        vec![rule("POST", "/v1/messages", RouteOutcome::Ask)],
        Some(Arc::new(Approves)),
    );
    let approved = send(
        &vm,
        BOUND_HOST,
        "POST",
        "/v1/messages",
        Some(&vm.placeholders[0]),
    );
    assert!(status_line(&approved).starts_with("HTTP/1.1 200"));
    assert!(forwarder.seen.lock().unwrap().is_some());
}

#[test]
fn a_path_that_cannot_be_canonicalised_is_refused_before_forwarding() {
    let (vm, forwarder) = bound_with(
        vec![rule("GET", "/v1/models/**", RouteOutcome::Allow)],
        None,
    );
    let refused = send(
        &vm,
        BOUND_HOST,
        "GET",
        "/v1/models%2f..%2fadmin",
        Some(&vm.placeholders[0]),
    );
    assert!(status_line(&refused).starts_with("HTTP/1.1 502"));
    assert!(forwarder.seen.lock().unwrap().is_none());
    assert!(vm.audit_chain().contains("ambiguous_path"));
}

#[test]
fn an_unbound_host_is_terminated_for_its_rules_only_when_the_route_grants_interception() {
    let forwarder = recording();
    let routes = vec![route(
        OTHER_HOST,
        vec![rule("GET", "/public/**", RouteOutcome::Allow)],
        true,
    )];
    let vm = assemble_with(
        &[Bound {
            secret: "model-api",
            pattern: BOUND_HOST,
        }],
        &[BOUND_HOST, OTHER_HOST],
        forwarder.clone(),
        Routing {
            routes,
            ..Routing::default()
        },
    );
    assert_eq!(
        vm.service.terminable(OTHER_HOST, 443),
        Some(TerminationMode::Tls),
        "the grant makes the unbound host terminable"
    );
    let allowed = send(&vm, OTHER_HOST, "GET", "/public/readme", None);
    assert!(status_line(&allowed).starts_with("HTTP/1.1 200"));
    let refused = send(&vm, OTHER_HOST, "DELETE", "/public/readme", None);
    assert!(status_line(&refused).starts_with("HTTP/1.1 502"));

    // Without the grant the host is not terminated, and an opaque flow to it
    // is refused rather than relayed with its rules unenforced.
    let ungranted = assemble_with(
        &[Bound {
            secret: "model-api",
            pattern: BOUND_HOST,
        }],
        &[BOUND_HOST, OTHER_HOST],
        recording(),
        Routing {
            routes: vec![route(
                OTHER_HOST,
                vec![rule("GET", "/public/**", RouteOutcome::Allow)],
                false,
            )],
            ..Routing::default()
        },
    );
    assert_eq!(ungranted.service.terminable(OTHER_HOST, 443), None);
    assert_eq!(
        ungranted.service.route_refusal_reason(OTHER_HOST, 443),
        Some("endpoint_rules_unenforceable")
    );
    // A host with no route is neither terminated nor refused.
    assert_eq!(
        ungranted.service.route_refusal_reason("unrouted.test", 443),
        None
    );
}

/// Answers every question with a fixed verdict and remembers the last one.
struct Fixed {
    verdict: ApprovalVerdict,
    asked: Mutex<Vec<ApprovalSubject>>,
}

#[async_trait]
impl RuntimeApprover for Fixed {
    async fn decide(&self, subject: &ApprovalSubject) -> ApprovalVerdict {
        self.asked.lock().unwrap().push(subject.clone());
        self.verdict
    }
}

fn secret_asking(verdict: ApprovalVerdict) -> (Assembled, Arc<RecordingForwarder>, Arc<Fixed>) {
    let forwarder = recording();
    let approver = Arc::new(Fixed {
        verdict,
        asked: Mutex::new(Vec::new()),
    });
    let vm = assemble_with(
        &[Bound {
            secret: "model-api",
            pattern: BOUND_HOST,
        }],
        &[BOUND_HOST],
        forwarder.clone(),
        Routing {
            approver: Some(approver.clone()),
            approval_required: ["model-api".to_string()].into_iter().collect(),
            ..Routing::default()
        },
    );
    (vm, forwarder, approver)
}

#[test]
fn a_secret_that_needs_approval_is_held_and_refused_when_denied() {
    let (vm, forwarder, approver) = secret_asking(ApprovalVerdict::Denied {
        reason: "approval_denied",
    });
    let refused = send(
        &vm,
        BOUND_HOST,
        "GET",
        "/v1/models",
        Some(&vm.placeholders[0]),
    );
    assert!(status_line(&refused).starts_with("HTTP/1.1 502"));
    assert!(
        forwarder.seen.lock().unwrap().is_none(),
        "nothing was substituted or sent"
    );
    assert_eq!(
        approver.asked.lock().unwrap().as_slice(),
        [ApprovalSubject::SecretUse {
            secret: "model-api".into(),
            destination: BOUND_HOST.into(),
        }]
    );
    let chain = vm.audit_chain();
    assert!(chain.contains("approval_denied"), "{chain}");
    assert!(!chain.contains("secret.substituted"), "{chain}");
}

#[test]
fn a_secret_that_needs_approval_is_substituted_once_approved() {
    let (vm, forwarder, approver) = secret_asking(ApprovalVerdict::Approved);
    let allowed = send(
        &vm,
        BOUND_HOST,
        "GET",
        "/v1/models",
        Some(&vm.placeholders[0]),
    );
    assert!(status_line(&allowed).starts_with("HTTP/1.1 200"));
    assert!(forwarder.seen.lock().unwrap().is_some());
    assert_eq!(approver.asked.lock().unwrap().len(), 1);

    // A request without the placeholder asks nothing.
    send(&vm, BOUND_HOST, "GET", "/v1/models", None);
    assert_eq!(approver.asked.lock().unwrap().len(), 1);
}
