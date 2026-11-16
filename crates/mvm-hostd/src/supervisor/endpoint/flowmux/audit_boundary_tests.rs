//! Additional refusal and cleanup witnesses through authenticated sessions.

use super::audit_tests::CapturingSink;
use super::tests::{
    build_dns_query, fresh_keys, gate_allowing_addr, gate_pinning_name, local_test_ip,
    read_flowmux_frame, run_session_from, write_frame,
};
use super::*;

struct FailedFlush(CapturingSink);

impl AuditSink for FailedFlush {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.0.record(event, labels)
    }

    fn suppress_denial(&self) {
        self.0.suppress_denial();
    }

    fn flush_health(&self) -> std::io::Result<()> {
        Err(std::io::Error::other("injected health flush failure"))
    }
}

struct CleanupWitness {
    sink: CapturingSink,
    upstream: Mutex<Option<std::net::TcpStream>>,
}

impl AuditSink for CleanupWitness {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.sink.record(event, labels)
    }

    fn suppress_denial(&self) {
        self.sink.suppress_denial();
    }

    fn flush_health(&self) -> std::io::Result<()> {
        let mut guard = self.upstream.lock().unwrap();
        let upstream = guard
            .as_mut()
            .expect("the flow was opened before completion");
        upstream.set_read_timeout(Some(Duration::from_secs(1)))?;
        assert_eq!(
            upstream.read(&mut [0; 1])?,
            0,
            "upstream must close before health flush"
        );
        Ok(())
    }
}

#[test]
fn session_completion_closes_tcp_before_flushing_health() {
    let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
    let target = listener.local_addr().unwrap();
    let gate = gate_allowing_addr(target.ip(), target.port(), None);
    let sink = Arc::new(CleanupWitness {
        sink: CapturingSink::default(),
        upstream: Mutex::new(None),
    });
    let supplied = Arc::clone(&sink);
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(supplied)
        });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        1,
        target.to_string().as_bytes(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    *sink.upstream.lock().unwrap() = Some(listener.accept().unwrap().0);
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn a_failed_completion_flush_is_not_reported_as_a_clean_session() {
    let (guest, _, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
                .with_audit_sink(Arc::new(FailedFlush(CapturingSink::default())))
        });
    drop(guest);
    assert!(matches!(host.join().unwrap(), Err(FlowMuxError::Audit(_))));
}

#[test]
fn a_failed_dns_allow_returns_no_answer() {
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let supplied = Arc::clone(&sink);
    let gate = gate_pinning_name("dns.test", "93.184.216.34".parse().unwrap(), 443);
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(supplied)
        });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Resolve,
        1,
        &build_dns_query("dns.test", 1, 123),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::ResolveRefused
    );
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert_eq!(sink.records.lock().unwrap()[0].0, "dns.resolved");
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn a_failed_ingress_allow_releases_resources_without_opening_the_guest() {
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let supplied = Arc::clone(&sink);
    let (host_key, host_verify) = fresh_keys();
    let (guest_key, guest_verify) = fresh_keys();
    let (host_stream, mut guest) = UnixStream::pair().unwrap();
    let (send_ingress, ingress) = std::sync::mpsc::channel();
    let host = std::thread::spawn(move || {
        let mut host = FlowMuxSession::accept_with(
            host_stream,
            FlowMuxAccept::new(
                "failed-ingress",
                host_key,
                guest_verify,
                RegistryLimits::default(),
                EgressGate::default_deny(),
            )
            .with_audit_sink(supplied)
            .with_ingress_mappings([17]),
        )
        .unwrap();
        send_ingress.send(host.ingress_handle()).unwrap();
        host.serve()
    });
    let (mut session, _) = Session::guest(&mut guest, guest_key, &host_verify).unwrap();
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Hello,
        0,
        &Handshake::local("audit-test").encode(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::HelloAck
    );
    let ingress = ingress.recv().unwrap();
    let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
    let mut external = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    assert!(matches!(
        ingress.open_tcp(17, accepted),
        Err(FlowMuxError::Audit(_))
    ));
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert!(lock_pending_ingress(&ingress.pending).is_empty());
    assert!(lock_tcp_streams(&ingress.streams).is_empty());
    assert!(lock_registry(&ingress.registry).get(2).is_none());
    external
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(external.read(&mut [0; 1]).unwrap(), 0);
    guest
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(guest.read(&mut [0; 1]).is_err_and(|e| matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )));
    drop(guest);
    host.join().unwrap().unwrap();
    let (accepted, _) = {
        let _external = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        listener.accept().unwrap()
    };
    assert!(
        ingress.open_tcp(17, accepted).is_err(),
        "completed sessions cannot reopen ingress"
    );
}
