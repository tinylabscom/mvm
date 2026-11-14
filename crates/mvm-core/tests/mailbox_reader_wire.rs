use mvm_contract::protocol::mailbox::PrincipalId;
use mvm_core::mailbox::frame::OutboxMessage;
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader_wire::{
    ApplicationReaderRequest, ReaderRequest, ReaderResponse, decode_request_body, is_reader_frame,
    read_application_request, read_request, read_response, write_application_request,
    write_request, write_response,
};

const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[test]
fn reader_request_is_versioned_and_bounded_before_parsing() {
    let mut frame = Vec::new();
    write_request(&mut frame, &ReaderRequest::Receive).unwrap();
    assert_eq!(
        read_request(&mut frame.as_slice()),
        Ok(ReaderRequest::Receive)
    );
    assert!(is_reader_frame(&frame[4..]));
    assert_eq!(decode_request_body(&frame[4..]), Ok(ReaderRequest::Receive));

    let mut bad_version = frame.clone();
    let one = bad_version
        .windows(b"\"version\":1".len())
        .position(|w| w == b"\"version\":1")
        .unwrap();
    bad_version[one + b"\"version\":".len()] = b'2';
    assert_eq!(
        read_request(&mut bad_version.as_slice()),
        Err(Refusal::Malformed)
    );
    assert!(is_reader_frame(&bad_version[4..]));
    assert_eq!(
        decode_request_body(&bad_version[4..]),
        Err(Refusal::Malformed)
    );

    let mut wrong_plane = frame.clone();
    wrong_plane[4] = b'X';
    assert_eq!(
        read_request(&mut wrong_plane.as_slice()),
        Err(Refusal::Malformed)
    );
    assert_eq!(
        read_request(&mut ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes().as_slice()),
        Err(Refusal::Oversized(MAX_REQUEST_BYTES))
    );
    assert_eq!(
        decode_request_body(&vec![0; MAX_REQUEST_BYTES + 1]),
        Err(Refusal::Oversized(MAX_REQUEST_BYTES))
    );
    assert!(!is_reader_frame(b"MVMO"));
    let mut recipient = [7u8; 32];
    recipient[..5].copy_from_slice(b"MVMR\x01");
    let send = OutboxMessage::new(PrincipalId::from_bytes(recipient), b"send".to_vec());
    assert!(
        !is_reader_frame(&send.encode()),
        "a legacy Send recipient with the same magic prefix is still Send"
    );
}

#[test]
fn truncation_and_large_requests_refuse_without_writing_a_prefix() {
    assert_eq!(
        read_request(&mut [0, 0, 0, 1].as_slice()),
        Err(Refusal::Oversized(MAX_REQUEST_BYTES))
    );
    let mut frame = Vec::new();
    write_request(
        &mut frame,
        &ReaderRequest::Possession {
            signature: vec![4; 64],
        },
    )
    .unwrap();
    frame.pop();
    assert_eq!(read_request(&mut frame.as_slice()), Err(Refusal::Malformed));

    let mut huge = Vec::new();
    assert_eq!(
        write_request(
            &mut huge,
            &ReaderRequest::Possession {
                signature: vec![4; MAX_REQUEST_BYTES]
            }
        ),
        Err(Refusal::Oversized(MAX_REQUEST_BYTES)),
    );
    assert!(huge.is_empty(), "oversized request must not write a prefix");
}

#[test]
fn a_refusal_is_not_an_ack_or_an_empty_mailbox() {
    let mut frame = Vec::new();
    write_response(
        &mut frame,
        &ReaderResponse::Refused {
            reason: Refusal::NotAuthorized,
        },
    )
    .unwrap();
    assert_eq!(
        read_response(&mut frame.as_slice()),
        Ok(ReaderResponse::Refused {
            reason: Refusal::NotAuthorized
        })
    );
    frame.clear();
    write_response(&mut frame, &ReaderResponse::Empty).unwrap();
    assert_eq!(
        read_response(&mut frame.as_slice()),
        Ok(ReaderResponse::Empty)
    );
}

#[test]
fn application_receive_is_bounded_and_does_not_carry_an_ack_key() {
    let mut frame = Vec::new();
    write_application_request(&mut frame, &ApplicationReaderRequest::Receive).unwrap();
    assert_eq!(
        read_application_request(&mut frame.as_slice()),
        Ok(ApplicationReaderRequest::Receive)
    );
    frame[4] = b'X';
    assert_eq!(
        read_application_request(&mut frame.as_slice()),
        Err(Refusal::Malformed)
    );
}
