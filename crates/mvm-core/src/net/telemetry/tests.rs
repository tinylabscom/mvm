use std::{io::Cursor, os::unix::net::UnixStream, thread, time::Duration};

use super::*;
use crate::protocol::telemetry::{CoverageState, ProducerEpoch, RecordBody, SourceKind};

fn sockets() -> (UnixStream, UnixStream) {
    let (a, b) = UnixStream::pair().unwrap();
    for s in [&a, &b] {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    }
    (a, b)
}

fn pair() -> (TelemetryReceiver, TelemetrySender) {
    let (mut h, mut g) = sockets();
    let host_key = SigningKey::from_bytes(&[7; 32]);
    let guest_key = SigningKey::from_bytes(&[9; 32]);
    let host_anchor = host_key.verifying_key();
    let guest_anchor = guest_key.verifying_key();
    let guest =
        thread::spawn(move || TelemetrySender::connect(&mut g, guest_key, &host_anchor).unwrap());
    let receiver = TelemetryReceiver::connect(&mut h, host_key, &guest_anchor).unwrap();
    (receiver, guest.join().unwrap())
}

fn record() -> TelemetryRecord {
    TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).unwrap())
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Coverage {
            state: CoverageState::Started,
            code: "secret-sentinel".try_into().unwrap(),
        })
        .build()
        .unwrap()
}

fn encoded(sender: &mut TelemetrySender) -> Vec<u8> {
    let mut bytes = Vec::new();
    sender.send(&mut bytes, &record()).unwrap();
    bytes
}

#[test]
fn encrypted_roundtrip_sends_without_any_application_ack() {
    let (mut receiver, mut sender) = pair();
    // A write-only Vec cannot receive ACKs; both sends complete nevertheless.
    let first = encoded(&mut sender);
    let second = encoded(&mut sender);
    assert!(
        !first
            .windows(b"secret-sentinel".len())
            .any(|s| s == b"secret-sentinel")
    );
    assert_eq!(receiver.receive(&mut Cursor::new(first)).unwrap(), record());
    assert_eq!(
        receiver.receive(&mut Cursor::new(second)).unwrap(),
        record()
    );
}

#[test]
fn replay_tampering_wrong_session_and_plaintext_fail_closed() {
    let (mut receiver, mut sender) = pair();
    let frame = encoded(&mut sender);
    receiver.receive(&mut Cursor::new(&frame)).unwrap();
    assert_eq!(
        receiver.receive(&mut Cursor::new(&frame)),
        Err(TelemetryError::Rejected)
    );
    assert_eq!(
        receiver.receive(&mut Cursor::new(&frame)),
        Err(TelemetryError::Closed)
    );

    let (mut receiver, mut sender) = pair();
    let mut frame = encoded(&mut sender);
    *frame.last_mut().unwrap() ^= 1;
    assert_eq!(
        receiver.receive(&mut Cursor::new(&frame)),
        Err(TelemetryError::Rejected)
    );

    let (mut receiver, _) = pair();
    let (_, mut other) = pair();
    assert_eq!(
        receiver.receive(&mut Cursor::new(encoded(&mut other))),
        Err(TelemetryError::Rejected)
    );

    let (mut receiver, _) = pair();
    let plaintext = record().encode().unwrap();
    let mut unsealed = u32::try_from(plaintext.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    unsealed.extend(plaintext);
    assert_eq!(
        receiver.receive(&mut Cursor::new(unsealed)),
        Err(TelemetryError::Rejected)
    );
}

#[test]
fn expected_guest_key_is_required_even_for_a_valid_handshake() {
    let (mut h, mut g) = sockets();
    let host_key = SigningKey::from_bytes(&[7; 32]);
    let anchor = host_key.verifying_key();
    let wrong_guest = SigningKey::from_bytes(&[10; 32]).verifying_key();
    let guest = thread::spawn(move || {
        TelemetrySender::connect(&mut g, SigningKey::from_bytes(&[9; 32]), &anchor)
    });
    assert!(matches!(
        TelemetryReceiver::connect(&mut h, host_key, &wrong_guest),
        Err(TelemetryError::Authentication)
    ));
    assert!(guest.join().unwrap().is_ok());
}

#[test]
fn wrong_host_anchor_and_wrong_service_are_refused() {
    let (mut h, mut g) = sockets();
    let guest = thread::spawn(move || {
        TelemetrySender::connect(
            &mut g,
            SigningKey::from_bytes(&[9; 32]),
            &SigningKey::from_bytes(&[11; 32]).verifying_key(),
        )
    });
    let result = TelemetryReceiver::connect(
        &mut h,
        SigningKey::from_bytes(&[7; 32]),
        &SigningKey::from_bytes(&[9; 32]).verifying_key(),
    );
    assert!(matches!(result, Err(TelemetryError::Authentication)));
    assert!(matches!(
        guest.join().unwrap(),
        Err(TelemetryError::Authentication)
    ));

    let (mut h, mut g) = sockets();
    let guest = thread::spawn(move || {
        TelemetrySender::connect(
            &mut g,
            SigningKey::from_bytes(&[9; 32]),
            &SigningKey::from_bytes(&[7; 32]).verifying_key(),
        )
    });
    Session::host(&mut h, "machine-control", SigningKey::from_bytes(&[7; 32])).unwrap();
    assert!(matches!(
        guest.join().unwrap(),
        Err(TelemetryError::Authentication)
    ));
}

#[test]
fn oversize_and_partial_frames_end_the_connection_before_body_allocation() {
    for (bytes, expected) in [
        (u32::MAX.to_be_bytes().to_vec(), TelemetryError::Rejected),
        (vec![0, 0], TelemetryError::Transport),
        (vec![0, 0, 0, 9, 1], TelemetryError::Transport),
    ] {
        let (mut receiver, _) = pair();
        let mut input = Cursor::new(bytes);
        assert_eq!(receiver.receive(&mut input), Err(expected));
        assert_eq!(receiver.receive(&mut input), Err(TelemetryError::Closed));
    }
}

#[test]
fn invalid_decrypted_payload_is_redacted_and_terminates_session() {
    let (mut receiver, mut sender) = pair();
    let frame = sender
        .session
        .as_mut()
        .unwrap()
        .seal(b"secret-sentinel-malformed-json")
        .unwrap();
    let mut bytes = Vec::new();
    write_sealed_frame(&mut bytes, &frame).unwrap();
    let error = receiver.receive(&mut Cursor::new(bytes)).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
    assert_eq!(
        receiver.receive(&mut Cursor::new([])),
        Err(TelemetryError::Closed)
    );
}

#[test]
fn failed_send_cannot_reuse_a_spent_sequence() {
    struct Failure;
    impl Write for Failure {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_, mut sender) = pair();
    assert_eq!(
        sender.send(&mut Failure, &record()),
        Err(TelemetryError::Transport)
    );
    assert_eq!(
        sender.send(&mut Vec::new(), &record()),
        Err(TelemetryError::Closed)
    );
}

#[test]
fn local_oversize_does_not_spend_a_sequence_or_invalidate_the_connection() {
    use crate::protocol::telemetry::{
        Attribute, AttributeValue, BoundedList, Level, MAX_ATTRIBUTES, Text,
    };
    let (mut receiver, mut sender) = pair();
    let attributes = (0..MAX_ATTRIBUTES)
        .map(|_| Attribute {
            key: "field".try_into().unwrap(),
            value: AttributeValue::Text(Text::new(&"\0".repeat(2048)).unwrap()),
        })
        .collect();
    let large = TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).unwrap())
        .producer(1)
        .sequence(1)
        .source(SourceKind::GuestAgent)
        .body(RecordBody::Event {
            context: None,
            level: Level::Info,
            name: "large".try_into().unwrap(),
            attributes: BoundedList::new(attributes).unwrap(),
        })
        .build()
        .unwrap();
    let mut wire = Vec::new();
    assert_eq!(
        sender.send(&mut wire, &large),
        Err(TelemetryError::Record(RecordError::Capacity))
    );
    assert!(wire.is_empty());
    sender.send(&mut wire, &record()).unwrap();
    assert_eq!(receiver.receive(&mut Cursor::new(wire)).unwrap(), record());
}

#[test]
fn unauthenticated_handshake_payloads_are_refused_without_quoting_input() {
    use crate::net::session::{read_json_frame, write_json_frame};

    let (mut host, mut peer) = sockets();
    let fake_guest = thread::spawn(move || {
        let _: serde_json::Value = read_json_frame(&mut peer, 65536).unwrap();
        write_json_frame(
            &mut peer,
            &serde_json::json!({"secret-sentinel": "payload"}),
            65536,
        )
        .unwrap();
    });
    let error = TelemetryReceiver::connect(
        &mut host,
        SigningKey::from_bytes(&[7; 32]),
        &SigningKey::from_bytes(&[9; 32]).verifying_key(),
    )
    .err()
    .expect("an unsigned arbitrary object cannot authenticate as a guest");
    fake_guest.join().unwrap();
    assert_eq!(error, TelemetryError::Authentication);
    assert!(!format!("{error:?} {error}").contains("secret-sentinel"));

    let (mut guest, mut peer) = sockets();
    let fake_host = thread::spawn(move || {
        write_json_frame(
            &mut peer,
            &serde_json::json!({"secret-sentinel": "payload"}),
            65536,
        )
        .unwrap();
    });
    let error = TelemetrySender::connect(
        &mut guest,
        SigningKey::from_bytes(&[9; 32]),
        &SigningKey::from_bytes(&[7; 32]).verifying_key(),
    )
    .err()
    .expect("an unsigned arbitrary object cannot authenticate as a host");
    fake_host.join().unwrap();
    assert_eq!(error, TelemetryError::Authentication);
    assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
}
