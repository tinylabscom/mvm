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
