//! Cancellation witnesses with a full guest writer and continuously readable UDP.

use std::net::UdpSocket;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc;

use super::tests::{
    fresh_keys, gate_allowing_addr, local_test_ip, read_flowmux_frame, write_frame,
};
use super::*;

struct AuditProbe {
    arm_response: AtomicBool,
    response: mpsc::SyncSender<()>,
    suppression: mpsc::SyncSender<()>,
    flushed: mpsc::SyncSender<u64>,
    suppressed: AtomicU64,
    completed: AtomicBool,
    after_flush: AtomicBool,
    flood_enabled: AtomicBool,
    flood: Mutex<Option<(UdpSocket, SocketAddr)>>,
}

struct AuditEvents {
    response: mpsc::Receiver<()>,
    suppression: mpsc::Receiver<()>,
    flushed: mpsc::Receiver<u64>,
}

impl AuditProbe {
    fn new() -> (Arc<Self>, AuditEvents) {
        let (response, response_rx) = mpsc::sync_channel(1);
        let (suppression, suppression_rx) = mpsc::sync_channel(1);
        let (flushed, flushed_rx) = mpsc::sync_channel(1);
        (
            Arc::new(Self {
                arm_response: AtomicBool::new(false),
                response,
                suppression,
                flushed,
                suppressed: AtomicU64::new(0),
                completed: AtomicBool::new(false),
                after_flush: AtomicBool::new(false),
                flood_enabled: AtomicBool::new(false),
                flood: Mutex::new(None),
            }),
            AuditEvents {
                response: response_rx,
                suppression: suppression_rx,
                flushed: flushed_rx,
            },
        )
    }

    fn update(&self) {
        if self.completed.load(Ordering::SeqCst) {
            self.after_flush.store(true, Ordering::SeqCst);
        }
    }

    fn feed_flood(&self) {
        if self.flood_enabled.load(Ordering::SeqCst)
            && let Some((socket, destination)) = self.flood.lock().unwrap().as_ref()
        {
            socket.send_to(b"denied", destination).unwrap();
        }
    }
}

impl AuditSink for AuditProbe {
    fn record(&self, event: &str, labels: BTreeMap<String, String>) -> std::io::Result<()> {
        self.update();
        if event == "host.flow.allowed"
            && labels.contains_key("target")
            && self.arm_response.swap(false, Ordering::SeqCst)
        {
            self.response.send(()).unwrap();
        }
        if labels
            .get("reason")
            .is_some_and(|v| v == "unsolicited_or_peer_limit")
        {
            self.feed_flood();
        }
        Ok(())
    }

    fn suppress_denial(&self) {
        self.update();
        self.suppressed.fetch_add(1, Ordering::SeqCst);
        let _ = self.suppression.try_send(());
        // Queue another datagram before the current one finishes, so the socket
        // never becomes empty just because the test's producer was descheduled.
        self.feed_flood();
    }

    fn flush_health(&self) -> std::io::Result<()> {
        self.completed.store(true, Ordering::SeqCst);
        self.flushed
            .send(self.suppressed.load(Ordering::SeqCst))
            .unwrap();
        Ok(())
    }
}

fn accepted_session(
    sink: Arc<dyn AuditSink>,
    gate: EgressGate,
    limits: RegistryLimits,
) -> (FlowMuxSession, UnixStream, Session) {
    let (host_key, host_verify) = fresh_keys();
    let (guest_key, guest_verify) = fresh_keys();
    let (host, mut guest) = UnixStream::pair().unwrap();
    let accepted = std::thread::spawn(move || {
        FlowMuxSession::accept_with(
            host,
            FlowMuxAccept::new("udp-shutdown", host_key, guest_verify, limits, gate)
                .with_audit_sink(sink),
        )
        .unwrap()
    });
    let (session, _) = Session::guest(&mut guest, guest_key, &host_verify).unwrap();
    (accepted.join().unwrap(), guest, session)
}

fn open_and_observe(guest: &mut UnixStream, session: &mut Session, peer: &UdpSocket) -> SocketAddr {
    write_frame(guest, session, Opcode::OpenUdp, 1, b"");
    assert_eq!(read_flowmux_frame(guest, session).0, Opcode::UdpOpened);
    let address = peer.local_addr().unwrap();
    let payload = udp_relay::encode_udp_addr(address.ip(), address.port());
    write_frame(guest, session, Opcode::UdpSend, 1, &payload);
    peer.recv_from(&mut [0; 16]).unwrap().1
}

fn full_writer(writer: &Mutex<UnixStream>) {
    let mut writer = writer.lock().unwrap();
    let original_timeout = writer.write_timeout().unwrap();
    // A write deadline fills the queue without changing the shared reader's flags.
    writer
        .set_write_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let bytes = [0_u8; 8192];
    let mut full = false;
    for _ in 0..512 {
        if let Err(error) = writer.write(&bytes) {
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            full = true;
            break;
        }
    }
    writer.set_write_timeout(original_timeout).unwrap();
    assert!(
        full,
        "fixture could not fill the guest's outgoing socket buffer"
    );
}

fn udp_peer() -> UdpSocket {
    let socket = UdpSocket::bind((local_test_ip(), 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

#[test]
fn close_udp_reaches_final_shutdown_with_an_unread_response() {
    let peer = udp_peer();
    let address = peer.local_addr().unwrap();
    let (sink, events) = AuditProbe::new();
    let (mut host, mut guest, mut session) = accepted_session(
        sink.clone(),
        gate_allowing_addr(address.ip(), 0, Some(address.port())),
        RegistryLimits {
            credit_wait: Duration::from_millis(100),
            ..RegistryLimits::default()
        },
    );
    let writer = Arc::clone(&host.writer);
    let associations = Arc::clone(&host.udp_associations);
    let closed = Arc::clone(&host.session_closed);
    let crypto = Arc::clone(&host.session);
    let rescue = host.reader.stream().try_clone().unwrap();
    let (finished, done) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = finished.send(host.serve());
    });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Hello,
        0,
        &Handshake::local("test").encode(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::HelloAck
    );
    let destination = open_and_observe(&mut guest, &mut session, &peer);
    let denied = udp_peer();
    denied.send_to(b"denied", destination).unwrap();
    denied.send_to(b"denied", destination).unwrap();
    events
        .suppression
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    // These filler bytes are intentionally never read; they saturate this
    // direction without preventing authenticated guest-to-host CloseUdp.
    full_writer(&writer);
    sink.arm_response.store(true, Ordering::SeqCst);
    peer.send_to(b"response", destination).unwrap();
    events
        .response
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    write_frame(&mut guest, &mut session, Opcode::CloseUdp, 1, b"");
    guest.shutdown(std::net::Shutdown::Write).unwrap();
    let completed = done.recv_timeout(Duration::from_secs(2));
    let closing = associations.try_lock().ok().map(|owners| {
        owners.get(&1).map(|owner| {
            (
                owner.cancelled.load(Ordering::Acquire),
                owner
                    .relay
                    .as_ref()
                    .is_some_and(std::thread::JoinHandle::is_finished),
            )
        })
    });
    let state = (
        closed.load(Ordering::Acquire),
        crypto.try_lock().is_ok(),
        closing,
    );
    // Always release a broken implementation's blocked write before asserting.
    let _ = rescue.shutdown(std::net::Shutdown::Both);
    drop(guest);
    worker.join().unwrap();
    assert!(
        completed.is_ok(),
        "CloseUdp prevented final transport shutdown: closed/session_available/owner={state:?}"
    );
    completed.unwrap().unwrap();
    assert!(lock_udp_associations(&associations).is_empty());
    assert!(events.flushed.recv_timeout(Duration::from_secs(2)).unwrap() >= 1);
    assert!(!sink.after_flush.load(Ordering::SeqCst));
}

#[test]
fn closed_udp_owners_keep_their_budget_until_joined() {
    let (sink, events) = AuditProbe::new();
    let (mut host, guest, _) = accepted_session(
        sink.clone(),
        EgressGate::default_deny(),
        RegistryLimits {
            max_udp: 1,
            ..RegistryLimits::default()
        },
    );
    let rescue = host.reader.stream().try_clone().unwrap();
    lock_registry(&host.registry)
        .open_guest(1, registry::FlowClass::Udp)
        .unwrap();
    let socket = udp_peer();
    let (_, waker) = udp_event_sources(&socket).unwrap();
    let (sender, receiver) = mpsc::channel();
    let mut owner = UdpAssociationHandle::new(
        sender,
        waker,
        UdpPeerAdmission::GuestMayIntroduce,
        Arc::new(decision_audit::UdpDenials::default()),
    );
    let (release, released) = mpsc::sync_channel(1);
    let rescue_release = release.clone();
    let (started, start) = mpsc::sync_channel(1);
    owner.relay = Some(std::thread::spawn(move || {
        let _receiver = receiver;
        started.send(()).unwrap();
        released.recv().unwrap();
    }));
    lock_udp_associations(&host.udp_associations).insert(1, owner);
    start.recv_timeout(Duration::from_secs(2)).unwrap();
    let (finished, done) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        host.remove_udp_association(1);
        host.remove_udp_association(1);
        host.reset_stream(1).unwrap();
        assert!(
            lock_udp_associations(&host.udp_associations)
                .get(&1)
                .unwrap()
                .tx
                .is_none(),
            "a canceled owner cannot accept guest sends"
        );
        let retained = lock_udp_associations(&host.udp_associations).len();
        let budget_held = lock_registry(&host.registry)
            .open_guest(3, registry::FlowClass::Udp)
            .is_err();
        release.send(()).unwrap();
        let result = host.finish_session(Ok(()));
        assert!(lock_udp_associations(&host.udp_associations).is_empty());
        assert_eq!(
            lock_registry(&host.registry).live_in_class(registry::FlowClass::Udp),
            0
        );
        let _ = finished.send((retained, budget_held, result));
    });
    let completed = done.recv_timeout(Duration::from_secs(2));
    let _ = rescue_release.try_send(());
    let _ = rescue.shutdown(std::net::Shutdown::Both);
    drop(guest);
    worker.join().unwrap();
    let (retained, budget_held, result) =
        completed.expect("closing an owner must not join a blocked relay");
    assert_eq!(
        retained, 1,
        "closing ownership stays in the existing bounded map"
    );
    assert!(
        budget_held,
        "close/open must not evade the association ceiling"
    );
    result.unwrap();
    events.flushed.recv_timeout(Duration::from_secs(2)).unwrap();
}

#[test]
fn continuous_denied_packets_cannot_prevent_udp_cancellation_or_flush() {
    let peer = udp_peer();
    let address = peer.local_addr().unwrap();
    let (sink, events) = AuditProbe::new();
    let (mut host, mut guest, mut session) = accepted_session(
        sink.clone(),
        gate_allowing_addr(address.ip(), 0, Some(address.port())),
        RegistryLimits::default(),
    );
    let (finished, done) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = finished.send(host.serve());
    });
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Hello,
        0,
        &Handshake::local("test").encode(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::HelloAck
    );
    let destination = open_and_observe(&mut guest, &mut session, &peer);
    *sink.flood.lock().unwrap() = Some((udp_peer(), destination));
    sink.flood_enabled.store(true, Ordering::SeqCst);
    sink.feed_flood();
    events
        .suppression
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    write_frame(&mut guest, &mut session, Opcode::CloseUdp, 1, b"");
    guest.shutdown(std::net::Shutdown::Write).unwrap();
    let completed = done.recv_timeout(Duration::from_secs(2));
    sink.flood_enabled.store(false, Ordering::SeqCst);
    let _ = guest.shutdown(std::net::Shutdown::Both);
    drop(guest);
    worker.join().unwrap();
    assert!(
        completed.is_ok(),
        "a continuously readable denied source prevented cancellation"
    );
    completed.unwrap().unwrap();
    let flushed = events.flushed.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(flushed, sink.suppressed.load(Ordering::SeqCst));
    assert!(!sink.after_flush.load(Ordering::SeqCst));
}

#[test]
fn ordinary_udp_close_keeps_an_unrelated_tcp_flow_alive() {
    let peer = udp_peer();
    let tcp = tests::tcp_echo_server();
    let (sink, _events) = AuditProbe::new();
    let (mut host, mut guest, mut session) = accepted_session(
        sink,
        gate_allowing_addr(
            tcp.ip(),
            tcp.port(),
            Some(peer.local_addr().unwrap().port()),
        ),
        RegistryLimits::default(),
    );
    let worker = std::thread::spawn(move || host.serve());
    guest
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write_frame(
        &mut guest,
        &mut session,
        Opcode::Hello,
        0,
        &Handshake::local("test").encode(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::HelloAck
    );
    open_and_observe(&mut guest, &mut session, &peer);
    write_frame(
        &mut guest,
        &mut session,
        Opcode::OpenTcp,
        3,
        tcp.to_string().as_bytes(),
    );
    assert_eq!(
        read_flowmux_frame(&mut guest, &mut session).0,
        Opcode::Opened
    );
    write_frame(&mut guest, &mut session, Opcode::CloseUdp, 1, b"");
    write_frame(&mut guest, &mut session, Opcode::Data, 3, b"still-live");
    let mut echoed = false;
    for _ in 0..3 {
        let (opcode, id, payload) = read_flowmux_frame(&mut guest, &mut session);
        if opcode == Opcode::Data {
            assert_eq!(id, 3);
            assert_eq!(payload, b"still-live");
            echoed = true;
            break;
        }
    }
    assert!(
        echoed,
        "UDP cancellation must not shut down an unrelated TCP flow"
    );
    drop(guest);
    worker.join().unwrap().unwrap();
}

#[test]
fn invalid_write_budgets_are_refused_before_handshake() {
    for credit_wait in [Duration::ZERO, Duration::MAX] {
        let (host, _guest) = UnixStream::pair().unwrap();
        let (host_key, _) = fresh_keys();
        let (_, guest_key) = fresh_keys();
        let accepted = FlowMuxSession::accept_with(
            host,
            FlowMuxAccept::new(
                "invalid-write-budget",
                host_key,
                guest_key,
                RegistryLimits {
                    credit_wait,
                    ..RegistryLimits::default()
                },
                EgressGate::default_deny(),
            )
            .with_audit_sink(super::audit_tests::capturing_sink()),
        );
        assert!(
            accepted.is_err(),
            "invalid write budget must refuse before waiting on a guest"
        );
    }
}
