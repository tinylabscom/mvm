//! Failure and ordering witnesses at the authenticated flow boundary.

use std::io::Read;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use super::tests::{
    fresh_keys, gate_allowing_addr, local_test_ip, read_flowmux_frame, run_session_from,
    run_session_on_runtime, write_frame,
};
use super::*;
use mvm_core::audit_sink::AuditSink;

#[derive(Default)]
pub(super) struct CapturingSink {
    pub(super) records: Mutex<Vec<(String, BTreeMap<String, String>)>>,
    pub(super) fail: AtomicBool,
    pub(super) incomplete: AtomicBool,
    pub(super) suppressed: std::sync::atomic::AtomicU64,
    observed: Mutex<Option<mpsc::Sender<()>>>,
    flushed: AtomicBool,
}

impl AuditSink for CapturingSink {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.records
            .lock()
            .unwrap()
            .push((event.to_string(), labels));
        if self.fail.load(Ordering::SeqCst) {
            self.incomplete.store(true, Ordering::SeqCst);
            if let Some(sender) = self.observed.lock().unwrap().as_ref() {
                let _ = sender.send(());
            }
            return Err(std::io::Error::other("injected journal failure"));
        }
        if let Some(sender) = self.observed.lock().unwrap().as_ref() {
            let _ = sender.send(());
        }
        Ok(())
    }

    fn suppress_denial(&self) {
        self.suppressed.fetch_add(1, Ordering::SeqCst);
    }

    fn flush_health(&self) -> std::io::Result<()> {
        self.flushed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

pub(super) fn capturing_sink() -> Arc<dyn AuditSink> {
    Arc::new(CapturingSink::default())
}

#[test]
fn a_session_without_an_audit_sink_is_refused() {
    let (host_key, host_verify) = fresh_keys();
    let (guest_key, guest_verify) = fresh_keys();
    let (host_stream, mut guest_stream) = UnixStream::pair().unwrap();
    let host = std::thread::spawn(move || {
        FlowMuxSession::accept_with(
            host_stream,
            FlowMuxAccept::new(
                "missing-audit",
                host_key,
                guest_verify,
                RegistryLimits::default(),
                EgressGate::default_deny(),
            ),
        )
    });
    // A constructor may refuse before or after authenticating, but may not
    // return a serving session without its required recorder.
    let _ = Session::guest(&mut guest_stream, guest_key, &host_verify);
    assert!(
        host.join().unwrap().is_err(),
        "unaudited session was accepted"
    );
}

struct HeldWrite {
    entered: mpsc::SyncSender<()>,
    released: Arc<(Mutex<bool>, Condvar)>,
}

impl AuditSink for HeldWrite {
    fn record(&self, _event: &str, _labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.entered.send(()).unwrap();
        let (released, wake) = &*self.released;
        drop(
            wake.wait_while(released.lock().unwrap(), |ready| !*ready)
                .unwrap(),
        );
        Ok(())
    }

    fn suppress_denial(&self) {
        panic!("this test sends no repeated denial");
    }

    fn flush_health(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_denial_is_not_returned_while_its_journal_write_is_pending() {
    let (entered, writing) = mpsc::sync_channel(1);
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let sink = Arc::new(HeldWrite {
        entered,
        released: Arc::clone(&released),
    });
    let (mut guest, mut session, host) = run_session_on_runtime(move |id, key, anchor, limits| {
        FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
            .with_audit_sink(sink)
    });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        1,
        b"denied.example:443",
    );
    writing.recv_timeout(Duration::from_secs(5)).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let response = guest.read(&mut [0u8; 1]);
    let (ready, wake) = &*released;
    *ready.lock().unwrap() = true;
    wake.notify_one();
    drop(guest);
    // The peer can close immediately after the write; either clean EOF or a
    // broken response transport is valid, but a write must never be skipped.
    let _ = host.join().unwrap();
    assert!(
        response.is_err_and(|error| matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )),
        "the guest received a refusal before its audit write completed"
    );
}

#[test]
fn a_dns_answer_waits_for_its_audit_write() {
    let (entered, writing) = mpsc::sync_channel(1);
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let sink = Arc::new(HeldWrite {
        entered,
        released: Arc::clone(&released),
    });
    let gate = tests::gate_pinning_name("dns.test", "93.184.216.34".parse().unwrap(), 443);
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(sink)
        });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Resolve,
        1,
        &tests::build_dns_query("dns.test", 1, 123),
    );
    writing.recv_timeout(Duration::from_secs(5)).unwrap();
    guest
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let response = guest.read(&mut [0; 1]);
    *released.0.lock().unwrap() = true;
    released.1.notify_one();
    assert!(response.is_err_and(|error| matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )));
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Resolved
    );
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn a_failed_allow_write_never_dials_tcp() {
    let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let gate = gate_allowing_addr(address.ip(), address.port(), None);
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
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
        address.to_string().as_bytes(),
    );
    let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut session);
    assert_eq!(opcode, Opcode::Refused);
    assert_eq!(sink.records.lock().unwrap()[0].0, "host.flow.allowed");
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert!(
        listener
            .accept()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
    );
    drop(guest);
    host.join().unwrap().unwrap();
    assert!(sink.flushed.load(Ordering::SeqCst));
}

#[test]
fn a_failed_denial_marks_incomplete_before_the_refusal_arrives() {
    let sink = Arc::new(CapturingSink::default());
    sink.fail.store(true, Ordering::SeqCst);
    let supplied = Arc::clone(&sink);
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, EgressGate::default_deny())
                .with_audit_sink(supplied)
        });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        1,
        b"denied.example:443",
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Refused
    );
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert_eq!(sink.records.lock().unwrap()[0].0, "host.flow.denied");
    drop(guest);
    host.join().unwrap().unwrap();
}

#[test]
fn a_failed_udp_send_write_never_sends_a_datagram() {
    let peer = std::net::UdpSocket::bind((local_test_ip(), 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let address = peer.local_addr().unwrap();
    let sink = Arc::new(CapturingSink::default());
    let supplied = Arc::clone(&sink);
    let gate = gate_allowing_addr(address.ip(), 0, Some(address.port()));
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(supplied)
        });
    write_frame(&mut guest, &mut session, Opcode::OpenUdp, 1, b"");
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::UdpOpened
    );
    sink.fail.store(true, Ordering::SeqCst);
    let (written, writes) = mpsc::channel();
    *sink.observed.lock().unwrap() = Some(written);
    let mut payload = udp_relay::encode_udp_addr(address.ip(), address.port());
    payload.extend_from_slice(b"must-not-arrive");
    write_frame(&mut guest, &mut session, Opcode::UdpSend, 1, &payload);
    writes.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(sink.incomplete.load(Ordering::SeqCst));
    assert!(peer.recv_from(&mut [0; 64]).is_err_and(|e| matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )));
    drop(guest);
    host.join().unwrap().unwrap();
    assert!(sink.flushed.load(Ordering::SeqCst));
}

#[test]
fn an_allowed_tcp_record_precedes_dial_and_the_flow_still_relays() {
    let listener = std::net::TcpListener::bind((local_test_ip(), 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let gate = gate_allowing_addr(address.ip(), address.port(), None);
    let (entered, writing) = mpsc::sync_channel(1);
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    let sink = Arc::new(HeldWrite {
        entered,
        released: Arc::clone(&released),
    });
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(sink)
        });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        1,
        address.to_string().as_bytes(),
    );
    writing.recv_timeout(Duration::from_secs(5)).unwrap();
    let before_write = listener.accept();
    *released.0.lock().unwrap() = true;
    released.1.notify_one();
    assert!(before_write.is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    let (mut upstream, _) = listener.accept().unwrap();
    upstream.set_nonblocking(false).unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write_frame(&mut guest, &mut session, Opcode::Data, 1, b"recorded");
    let mut bytes = [0; 8];
    upstream.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"recorded");
    drop(guest);
    host.join().unwrap().unwrap();
    assert_eq!(
        upstream.read(&mut bytes).unwrap(),
        0,
        "completion must close the upstream owner"
    );
}

#[test]
fn repeated_udp_denials_count_suppression_but_failed_writes_are_retried() {
    let sink = CapturingSink::default();
    let cache = decision_audit::UdpDenials::default();
    let target = "192.0.2.7:1234".parse().unwrap();
    sink.fail.store(true, Ordering::SeqCst);
    cache.record(&sink, 1, target, "policy_denied", 2);
    cache.record(&sink, 1, target, "policy_denied", 2);
    assert_eq!(
        sink.records.lock().unwrap().len(),
        2,
        "failed first write must not enter the cache"
    );
    assert_eq!(sink.suppressed.load(Ordering::SeqCst), 0);
    sink.fail.store(false, Ordering::SeqCst);
    cache.record(&sink, 1, target, "policy_denied", 2);
    for _ in 0..20 {
        cache.record(&sink, 1, target, "policy_denied", 2);
    }
    assert_eq!(sink.records.lock().unwrap().len(), 3);
    assert_eq!(sink.suppressed.load(Ordering::SeqCst), 20);
    assert!(sink.incomplete.load(Ordering::SeqCst));
}

#[test]
fn authenticated_udp_repeats_are_counted_without_another_journal_write() {
    let sink = Arc::new(CapturingSink::default());
    let supplied = Arc::clone(&sink);
    let gate = gate_allowing_addr(local_test_ip(), 0, Some(9));
    let (mut guest, mut session, host) =
        run_session_from(RegistryLimits::default(), move |id, key, anchor, limits| {
            FlowMuxAccept::new(id, key, anchor, limits, gate).with_audit_sink(supplied)
        });
    write_frame(&mut guest, &mut session, Opcode::OpenUdp, 1, b"");
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::UdpOpened
    );
    let refused = udp_relay::encode_udp_addr("203.0.113.55".parse().unwrap(), 53);
    for _ in 0..20 {
        write_frame(&mut guest, &mut session, Opcode::UdpSend, 1, &refused);
    }
    // An answered request on this same stream transport is the processing barrier.
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        3,
        b"203.0.113.56:443",
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Refused
    );
    assert_eq!(sink.suppressed.load(Ordering::SeqCst), 19);
    assert_eq!(
        sink.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(event, labels)| {
                event == "host.flow.denied"
                    && labels
                        .get("target")
                        .is_some_and(|target| target == "203.0.113.55:53")
            })
            .count(),
        1
    );
    drop(guest);
    host.join().unwrap().unwrap();
}
