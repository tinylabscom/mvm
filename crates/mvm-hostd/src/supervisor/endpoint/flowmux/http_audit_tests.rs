//! Typed HTTP must not open or dispatch while its decision write has failed.

use super::audit_tests::CapturingSink;
use super::tests::{gate_pinning_name, read_flowmux_frame, run_session_on_runtime, write_frame};
use super::*;
use crate::keyholder::LocalResolver;
use crate::keyholder::substitution::SubstitutionRegistry;
use crate::supervisor::endpoint::network_endpoint_proxy::{
    ForwardError, ForwardResponse, Forwarder, PreparedRequest, SubstitutionService,
};
use mvm_core::crypto::secret_store::FileSecretStore;
use std::sync::atomic::AtomicUsize;

struct WitnessForwarder {
    sink: Arc<CapturingSink>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Forwarder for WitnessForwarder {
    async fn forward(&self, _: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        assert!(
            self.sink
                .records
                .lock()
                .unwrap()
                .iter()
                .any(|(event, labels)| {
                    event == "host.flow.allowed"
                        && labels.get("phase").is_some_and(|v| v == "forward")
                })
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ForwardError::Failed("fixture observed forwarding".into()))
    }
}

fn service(
    sink: Arc<CapturingSink>,
    calls: Arc<AtomicUsize>,
) -> (tempfile::TempDir, Arc<SubstitutionService>) {
    let directory = tempfile::tempdir().unwrap();
    let resolver = LocalResolver::new(
        "flow-audit",
        Arc::new(FileSecretStore::with_dir(directory.path())),
    );
    let gate = gate_pinning_name("http.test", "93.184.216.34".parse().unwrap(), 443);
    let service = SubstitutionService::new(
        Arc::new(SubstitutionRegistry::new()),
        Arc::new(resolver),
        Arc::new(WitnessForwarder { sink, calls }),
        Arc::new(gate),
    );
    (directory, Arc::new(service))
}

fn request_head() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "method": "GET",
        "url": "https://http.test/",
        "headers": [],
        "body_len": 0,
    }))
    .unwrap()
}

#[test]
fn a_failed_http_open_is_refused_without_dispatch() {
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    let (_directory, service) = service(Arc::clone(&sink), Arc::clone(&calls));
    let supplied = Arc::clone(&sink);
    let (mut guest, mut session, host) = run_session_on_runtime(move |id, key, anchor, limits| {
        FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
            .with_audit_sink(supplied)
            .with_substitution(Some(service))
    });
    write_frame(&mut guest, &mut session, Opcode::OpenHttp, 1, b"");
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Refused
    );
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn a_failed_http_forward_write_never_dispatches_the_request() {
    let sink = Arc::new(CapturingSink::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (_directory, service) = service(Arc::clone(&sink), Arc::clone(&calls));
    let supplied = Arc::clone(&sink);
    let (mut guest, mut session, host) = run_session_on_runtime(move |id, key, anchor, limits| {
        FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
            .with_audit_sink(supplied)
            .with_substitution(Some(service))
    });
    write_frame(&mut guest, &mut session, Opcode::OpenHttp, 1, b"");
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    sink.fail.store(true, Ordering::SeqCst);
    write_frame(
        &mut guest,
        &mut session,
        Opcode::HttpRequestHead,
        1,
        &request_head(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Reset
    );
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn an_http_forward_is_recorded_before_dispatch() {
    let sink = Arc::new(CapturingSink::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (_directory, service) = service(Arc::clone(&sink), Arc::clone(&calls));
    let supplied = Arc::clone(&sink);
    let (mut guest, mut session, host) = run_session_on_runtime(move |id, key, anchor, limits| {
        FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
            .with_audit_sink(supplied)
            .with_substitution(Some(service))
    });
    write_frame(&mut guest, &mut session, Opcode::OpenHttp, 1, b"");
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    write_frame(
        &mut guest,
        &mut session,
        Opcode::HttpRequestHead,
        1,
        &request_head(),
    );
    let response = read_flowmux_frame(&mut guest, &mut session);
    assert_eq!(response.0, Opcode::HttpResponseHead);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!sink.incomplete.load(Ordering::SeqCst));
    drop(guest);
    host.join().unwrap().unwrap();
}

/// Records the request it is asked to forward, then fails it.
struct RecordingForwarder {
    seen: Arc<std::sync::Mutex<Option<PreparedRequest>>>,
}

#[async_trait::async_trait]
impl Forwarder for RecordingForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        *self.seen.lock().unwrap() = Some(req);
        Err(ForwardError::Failed("fixture recorded the request".into()))
    }
}

/// A typed HTTP flow is decided by its canonical destination: a dotted,
/// upper-case or IPv4-mapped spelling of a host whose request body is
/// replaced has its body replaced exactly like the canonical spelling, and
/// the audit names the canonical host only.
#[test]
fn every_spelling_of_a_replaced_destination_has_its_request_body_replaced() {
    use super::tests::gate_allowing_addr;
    use mvm_core::policy::{
        ReversibleReplacementAction, ReversibleReplacementPolicy, ReversibleReplacementProfile,
    };
    const PHONE: &str = "+14155550123";
    let ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    for (profile_host, url) in [
        ("api.example.com", "https://api.example.com/v1"),
        ("api.example.com", "https://api.example.com./v1"),
        ("api.example.com", "https://API.Example.COM./v1"),
        ("93.184.216.34", "https://93.184.216.34/v1"),
        ("93.184.216.34", "https://[::ffff:93.184.216.34]/v1"),
    ] {
        let gate = if profile_host == "api.example.com" {
            gate_pinning_name(profile_host, ip, 443)
        } else {
            gate_allowing_addr(ip, 443, None)
        };
        let seen = Arc::new(std::sync::Mutex::new(None));
        let directory = tempfile::tempdir().unwrap();
        let resolver = LocalResolver::new(
            "flow-replacement",
            Arc::new(FileSecretStore::with_dir(directory.path())),
        );
        let service = SubstitutionService::new(
            Arc::new(SubstitutionRegistry::new()),
            Arc::new(resolver),
            Arc::new(RecordingForwarder {
                seen: Arc::clone(&seen),
            }),
            Arc::new(gate),
        )
        .with_reversible_replacement_policy(ReversibleReplacementPolicy {
            default: Default::default(),
            profiles: vec![ReversibleReplacementProfile {
                host: profile_host.into(),
                action: ReversibleReplacementAction {
                    enabled: true,
                    ..Default::default()
                },
            }],
        });
        let sink = Arc::new(CapturingSink::default());
        let supplied = Arc::clone(&sink);
        let (mut guest, mut session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
                    .with_audit_sink(supplied)
                    .with_substitution(Some(Arc::new(service)))
            });
        let body = format!("call {PHONE} now");
        write_frame(&mut guest, &mut session, Opcode::OpenHttp, 1, b"");
        assert_eq!(
            read_flowmux_frame(&mut guest, &mut session).0,
            Opcode::Opened,
            "{url}"
        );
        let head = serde_json::to_vec(&serde_json::json!({
            "method": "POST",
            "url": url,
            "headers": [],
            "body_len": body.len(),
        }))
        .unwrap();
        write_frame(&mut guest, &mut session, Opcode::HttpRequestHead, 1, &head);
        write_frame(
            &mut guest,
            &mut session,
            Opcode::HttpRequestBody,
            1,
            body.as_bytes(),
        );
        let answer = read_flowmux_frame(&mut guest, &mut session);
        drop(guest);
        host.join().unwrap().unwrap();

        let sent = seen
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| panic!("{url}: not forwarded: {answer:?}"));
        let sent_body = String::from_utf8_lossy(&sent.body);
        // Replacement leaves a reversible token; the streaming redactor alone
        // would only mask the value, which is not what the profile asks for.
        assert!(
            !sent_body.contains(PHONE) && sent_body.contains("mvmr1_"),
            "{url}: body not replaced: {sent_body}"
        );
        assert_eq!(sent.url, format!("https://{profile_host}/v1"), "{url}");
        let audited = format!("{:?}", sink.records.lock().unwrap());
        for raw in ["example.com.", "Example", "::ffff"] {
            assert!(
                !audited.contains(raw),
                "{url}: audit names {raw:?}: {audited}"
            );
        }
    }
}

/// A typed HTTP flow whose URL host names no destination (two trailing dots)
/// is refused at its head and never forwarded.
#[test]
fn a_typed_http_flow_to_a_host_that_names_nothing_is_refused() {
    let ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    for url in [
        "https://api.example.com../v1",
        "https://API.Example.COM../v1",
    ] {
        let seen = Arc::new(std::sync::Mutex::new(None));
        let directory = tempfile::tempdir().unwrap();
        let resolver = LocalResolver::new(
            "flow-nothing",
            Arc::new(FileSecretStore::with_dir(directory.path())),
        );
        let service = SubstitutionService::new(
            Arc::new(SubstitutionRegistry::new()),
            Arc::new(resolver),
            Arc::new(RecordingForwarder {
                seen: Arc::clone(&seen),
            }),
            Arc::new(gate_pinning_name("api.example.com", ip, 443)),
        );
        let sink = Arc::new(CapturingSink::default());
        let supplied = Arc::clone(&sink);
        let (mut guest, mut session, host) =
            run_session_on_runtime(move |id, key, anchor, limits| {
                FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
                    .with_audit_sink(supplied)
                    .with_substitution(Some(Arc::new(service)))
            });
        write_frame(&mut guest, &mut session, Opcode::OpenHttp, 1, b"");
        assert_eq!(
            read_flowmux_frame(&mut guest, &mut session).0,
            Opcode::Opened
        );
        let head = serde_json::to_vec(&serde_json::json!({
            "method": "GET",
            "url": url,
            "headers": [],
            "body_len": 0,
        }))
        .unwrap();
        write_frame(&mut guest, &mut session, Opcode::HttpRequestHead, 1, &head);
        // The refusal is answered as a response head; what matters is that no
        // request reached the forward leg.
        let _answer = read_flowmux_frame(&mut guest, &mut session);
        drop(guest);
        host.join().unwrap().unwrap();
        assert!(seen.lock().unwrap().is_none(), "{url} forwarded");
    }
}
