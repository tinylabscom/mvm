use super::*;
use crate::crypto::aead::KEY_SIZE;

fn tenant(name: &str) -> CheckpointKeyDomain {
    CheckpointKeyDomain::tenant(name).unwrap()
}

/// Keys built from fixed bytes, so two calls give equal keys (neither key
/// type is `Clone`, deliberately).
fn keys(domain: CheckpointKeyDomain, wrap: u8, reference: u8) -> DomainKeys {
    DomainKeys::new(
        domain,
        aead::Key::from_bytes([wrap; KEY_SIZE]),
        ReferenceKey::from_bytes([reference; REFERENCE_LEN]),
    )
    .unwrap()
}

fn alice() -> DomainKeys {
    keys(tenant("alice"), 1, 2)
}

fn expect(sealed: &SealedObject, kind: ObjectKind) -> ObjectExpectation {
    ObjectExpectation::new(kind, sealed.reference)
}

/// Offset of the first wrapped-key byte for a frame in `alice()`'s domain.
fn wrapped_key_at() -> usize {
    9 + "tenant:alice".len() + REFERENCE_LEN + 8
}

#[test]
fn chunk_and_index_round_trip() {
    let k = alice();
    for (kind, body) in [
        (ObjectKind::Chunk, b"chunk bytes".as_slice()),
        (ObjectKind::Index, b"{\"chunks\":[]}".as_slice()),
        (ObjectKind::Chunk, b"".as_slice()),
    ] {
        let sealed = seal(&k, kind, body).unwrap();
        let opened = open(
            &k,
            &expect(&sealed, kind).plaintext_len(body.len() as u64),
            &sealed.bytes,
        );
        assert_eq!(opened.unwrap(), body);
    }
}

#[test]
fn a_chunk_at_the_bound_round_trips() {
    let k = alice();
    let body = vec![0xa5; MAX_CHUNK_LEN as usize];
    let sealed = seal(&k, ObjectKind::Chunk, &body).unwrap();
    assert_eq!(
        open(&k, &expect(&sealed, ObjectKind::Chunk), &sealed.bytes).unwrap(),
        body
    );
}

#[test]
fn frame_size_is_header_plus_wrapped_key_plus_payload() {
    let sealed = seal(&alice(), ObjectKind::Chunk, b"12345").unwrap();
    assert_eq!(
        sealed.bytes.len(),
        wrapped_key_at() + WRAPPED_KEY_LEN + 5 + PAYLOAD_OVERHEAD
    );
}

#[test]
fn equal_plaintext_in_one_domain_shares_a_reference_but_not_ciphertext() {
    let k = alice();
    let a = seal(&k, ObjectKind::Chunk, b"same").unwrap();
    let b = seal(&k, ObjectKind::Chunk, b"same").unwrap();
    assert_eq!(a.reference, b.reference, "dedup inside a domain");
    assert_ne!(a.bytes, b.bytes, "fresh data key and nonces every seal");
    assert_eq!(
        k.reference_for(ObjectKind::Chunk, b"same").unwrap(),
        a.reference
    );
}

#[test]
fn references_never_match_across_domains_kinds_or_keys() {
    let r = |k: &DomainKeys, kind| k.reference_for(kind, b"same").unwrap();
    let base = r(&alice(), ObjectKind::Chunk);
    // Same key bytes, another domain: the domain is inside the MAC.
    assert_ne!(base, r(&keys(tenant("bob"), 1, 2), ObjectKind::Chunk));
    assert_ne!(
        base,
        r(&keys(CheckpointKeyDomain::host(), 1, 2), ObjectKind::Chunk)
    );
    assert_ne!(base, r(&alice(), ObjectKind::Index));
    assert_ne!(base, r(&keys(tenant("alice"), 1, 3), ObjectKind::Chunk));
}

#[test]
fn a_wrong_wrapping_key_refuses() {
    let sealed = seal(&alice(), ObjectKind::Chunk, b"secret").unwrap();
    let err = open(
        &keys(tenant("alice"), 9, 2),
        &expect(&sealed, ObjectKind::Chunk),
        &sealed.bytes,
    );
    assert_eq!(err, Err(CheckpointObjectError::WrappedKeyAuth));
}

#[test]
fn a_wrong_reference_key_refuses_after_decryption() {
    let sealed = seal(&alice(), ObjectKind::Chunk, b"secret").unwrap();
    let err = open(
        &keys(tenant("alice"), 1, 9),
        &expect(&sealed, ObjectKind::Chunk),
        &sealed.bytes,
    );
    assert_eq!(err, Err(CheckpointObjectError::ReferenceMismatch));
}

#[test]
fn every_flipped_byte_refuses() {
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"tamper target").unwrap();
    let expected = expect(&sealed, ObjectKind::Chunk);
    for i in 0..sealed.bytes.len() {
        let mut bytes = sealed.bytes.clone();
        bytes[i] ^= 0x01;
        assert!(
            open(&k, &expected, &bytes).is_err(),
            "flip at {i} was accepted"
        );
    }
}

#[test]
fn tampering_names_the_layer_that_caught_it() {
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"tamper target").unwrap();
    let expected = expect(&sealed, ObjectKind::Chunk);
    let flip = |i: usize| {
        let mut bytes = sealed.bytes.clone();
        bytes[i] ^= 0x80;
        open(&k, &expected, &bytes)
    };
    let last = sealed.bytes.len() - 1;
    // Header: plaintext length is bounded and checked against the frame size.
    assert!(matches!(
        flip(wrapped_key_at() - 1),
        Err(CheckpointObjectError::LengthMismatch { .. })
    ));
    // Header: the reference contradicts what the caller expects.
    assert_eq!(
        flip(wrapped_key_at() - 9),
        Err(CheckpointObjectError::ContextMismatch(
            ContextField::Reference
        ))
    );
    assert_eq!(
        flip(wrapped_key_at()),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
    // The payload's fingerprint is inside the wrap AAD, so a payload change
    // is caught when the data key is unwrapped.
    assert_eq!(flip(last - 20), Err(CheckpointObjectError::WrappedKeyAuth));
    assert_eq!(flip(last), Err(CheckpointObjectError::WrappedKeyAuth));
}

#[test]
fn a_header_rewritten_consistently_still_refuses() {
    // An attacker who also controls the caller's expectation (say, a forged
    // index) rewrites the reference everywhere it appears. The AEAD binding
    // and the reference check refuse it.
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"original").unwrap();
    let mut bytes = sealed.bytes.clone();
    let at = 9 + "tenant:alice".len();
    bytes[at] ^= 0x01;
    let forged = ObjectFrame::parse(&bytes).unwrap().reference();
    let err = open(
        &k,
        &ObjectExpectation::new(ObjectKind::Chunk, forged),
        &bytes,
    );
    assert_eq!(err, Err(CheckpointObjectError::WrappedKeyAuth));
}

#[test]
fn every_truncation_and_any_extension_refuses() {
    let k = alice();
    let sealed = seal(&k, ObjectKind::Index, b"index body").unwrap();
    let expected = expect(&sealed, ObjectKind::Index);
    for len in 0..sealed.bytes.len() {
        let err = open(&k, &expected, &sealed.bytes[..len]).unwrap_err();
        assert!(
            matches!(
                err,
                CheckpointObjectError::Truncated { .. }
                    | CheckpointObjectError::LengthMismatch { .. }
            ),
            "prefix of {len} bytes: {err:?}"
        );
    }
    let mut longer = sealed.bytes.clone();
    longer.push(0);
    assert!(matches!(
        open(&k, &expected, &longer),
        Err(CheckpointObjectError::LengthMismatch { .. })
    ));
}

#[test]
fn a_frame_that_contradicts_the_expectation_refuses_before_any_key_is_used() {
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"body").unwrap();
    let other = k.reference_for(ObjectKind::Chunk, b"other").unwrap();
    let cases = [
        (
            ObjectExpectation::new(ObjectKind::Index, sealed.reference),
            ContextField::Kind,
        ),
        (
            ObjectExpectation::new(ObjectKind::Chunk, other),
            ContextField::Reference,
        ),
        (
            expect(&sealed, ObjectKind::Chunk).plaintext_len(5),
            ContextField::PlaintextLen,
        ),
    ];
    for (expected, field) in cases {
        assert_eq!(
            open(&k, &expected, &sealed.bytes),
            Err(CheckpointObjectError::ContextMismatch(field))
        );
    }
}

#[test]
fn another_domains_keys_refuse_the_object() {
    let sealed = seal(&alice(), ObjectKind::Chunk, b"alice only").unwrap();
    let expected = expect(&sealed, ObjectKind::Chunk);
    // Even with identical key bytes: the domain is the first thing checked.
    for other in [
        keys(tenant("bob"), 1, 2),
        keys(CheckpointKeyDomain::host(), 1, 2),
    ] {
        assert_eq!(
            open(&other, &expected, &sealed.bytes),
            Err(CheckpointObjectError::ContextMismatch(ContextField::Domain))
        );
    }
}

#[test]
fn relabelling_an_object_into_another_domain_refuses_even_with_shared_keys() {
    // tenant:alice and tenant:carol have equal length, so the relabelled
    // frame still parses. Even if both domains were (wrongly) given the same
    // key bytes, the domain is authenticated.
    let sealed = seal(&alice(), ObjectKind::Chunk, b"alice only").unwrap();
    let mut bytes = sealed.bytes.clone();
    bytes[9..9 + "tenant:carol".len()].copy_from_slice(b"tenant:carol");
    let carol = keys(tenant("carol"), 1, 2);
    let err = open(&carol, &expect(&sealed, ObjectKind::Chunk), &bytes);
    assert_eq!(err, Err(CheckpointObjectError::WrappedKeyAuth));
}

#[test]
fn a_wrapped_key_moved_onto_another_payload_refuses() {
    let k = alice();
    let a = seal(&k, ObjectKind::Chunk, b"payload a").unwrap();
    let b = seal(&k, ObjectKind::Chunk, b"payload b").unwrap();
    let range = wrapped_key_at()..wrapped_key_at() + WRAPPED_KEY_LEN;
    let mut spliced = b.bytes.clone();
    spliced[range.clone()].copy_from_slice(&a.bytes[range]);
    assert_eq!(
        open(&k, &expect(&b, ObjectKind::Chunk), &spliced),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
}

#[test]
fn a_payload_moved_under_another_header_refuses() {
    let k = alice();
    let a = seal(&k, ObjectKind::Chunk, b"same len a").unwrap();
    let b = seal(&k, ObjectKind::Chunk, b"same len b").unwrap();
    let at = wrapped_key_at();
    let mut spliced = a.bytes[..at].to_vec();
    spliced.extend_from_slice(&b.bytes[at..]);
    assert_eq!(
        open(&k, &expect(&a, ObjectKind::Chunk), &spliced),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
}

#[test]
fn replaying_an_object_under_its_own_reference_yields_the_same_plaintext() {
    // An older copy of an object is the same plaintext by construction:
    // the reference is a keyed hash of it.
    let k = alice();
    let first = seal(&k, ObjectKind::Chunk, b"stable").unwrap();
    let second = seal(&k, ObjectKind::Chunk, b"stable").unwrap();
    let expected = expect(&second, ObjectKind::Chunk);
    assert_eq!(open(&k, &expected, &first.bytes).unwrap(), b"stable");
}

#[test]
fn header_fields_are_validated_strictly() {
    let sealed = seal(&alice(), ObjectKind::Chunk, b"x").unwrap();
    let with = |i: usize, v: u8| {
        let mut bytes = sealed.bytes.clone();
        bytes[i] = v;
        ObjectFrame::parse(&bytes).map(|_| ())
    };
    assert_eq!(with(0, b'X'), Err(CheckpointObjectError::BadMagic));
    assert_eq!(
        with(4, 2),
        Err(CheckpointObjectError::UnsupportedVersion(2))
    );
    assert_eq!(
        with(4, 0),
        Err(CheckpointObjectError::UnsupportedVersion(0))
    );
    assert_eq!(with(5, 0), Err(CheckpointObjectError::UnknownKind(0)));
    assert_eq!(with(5, 3), Err(CheckpointObjectError::UnknownKind(3)));
    assert_eq!(with(6, 1), Err(CheckpointObjectError::ReservedBitsSet));
    assert_eq!(with(7, 0x80), Err(CheckpointObjectError::ReservedBitsSet));
    assert_eq!(with(8, 0), Err(CheckpointObjectError::EmptyDomain));
    assert_eq!(with(9, 0xff), Err(CheckpointObjectError::DomainNotUtf8));
}

#[test]
fn oversized_plaintext_refuses_to_seal() {
    let k = alice();
    let chunk = vec![0; MAX_CHUNK_LEN as usize + 1];
    assert_eq!(
        seal(&k, ObjectKind::Chunk, &chunk),
        Err(CheckpointObjectError::TooLarge {
            kind: ObjectKind::Chunk,
            len: MAX_CHUNK_LEN + 1,
            max: MAX_CHUNK_LEN,
        })
    );
    // The same bytes are a legal index.
    assert!(seal(&k, ObjectKind::Index, &chunk).is_ok());
}

#[test]
fn a_header_declaring_a_huge_payload_refuses_before_reading_it() {
    let sealed = seal(&alice(), ObjectKind::Index, b"x").unwrap();
    let mut bytes = sealed.bytes.clone();
    let at = wrapped_key_at() - 8;
    bytes[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        ObjectFrame::parse(&bytes),
        Err(CheckpointObjectError::TooLarge {
            kind: ObjectKind::Index,
            len: u64::MAX,
            max: MAX_INDEX_LEN,
        })
    );
}

#[test]
fn a_domain_too_long_to_frame_is_refused_up_front() {
    let long = tenant(&"x".repeat(MAX_DOMAIN_LEN));
    let err = DomainKeys::new(long, aead::Key::random(), ReferenceKey::random()).err();
    assert_eq!(
        err,
        Some(CheckpointObjectError::DomainTooLong {
            len: MAX_DOMAIN_LEN + "tenant:".len()
        })
    );
    let fits = tenant(&"x".repeat(MAX_DOMAIN_LEN - "tenant:".len()));
    let k = DomainKeys::new(fits, aead::Key::random(), ReferenceKey::random()).unwrap();
    let sealed = seal(&k, ObjectKind::Chunk, b"x").unwrap();
    assert_eq!(
        open(&k, &expect(&sealed, ObjectKind::Chunk), &sealed.bytes).unwrap(),
        b"x"
    );
}

#[test]
fn rewrap_keeps_header_payload_and_fingerprint() {
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"rotate me").unwrap();
    let expected = expect(&sealed, ObjectKind::Chunk);
    let new_wrapping = aead::Key::from_bytes([7; KEY_SIZE]);
    let rewrapped = rewrap(&k, &new_wrapping, &expected, &sealed.bytes).unwrap();

    let at = wrapped_key_at();
    assert_eq!(rewrapped.len(), sealed.bytes.len());
    assert_eq!(rewrapped[..at], sealed.bytes[..at], "header unchanged");
    assert_eq!(
        rewrapped[at + WRAPPED_KEY_LEN..],
        sealed.bytes[at + WRAPPED_KEY_LEN..]
    );
    assert_ne!(
        rewrapped[at..at + WRAPPED_KEY_LEN],
        sealed.bytes[at..at + WRAPPED_KEY_LEN]
    );
    assert_eq!(
        ObjectFrame::parse(&rewrapped).unwrap().fingerprint(),
        ObjectFrame::parse(&sealed.bytes).unwrap().fingerprint()
    );

    let rotated = keys(tenant("alice"), 7, 2);
    assert_eq!(open(&rotated, &expected, &rewrapped).unwrap(), b"rotate me");
    assert_eq!(
        open(&k, &expected, &rewrapped),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
    // Not a revocation: the old copy still opens under the old key.
    assert_eq!(open(&k, &expected, &sealed.bytes).unwrap(), b"rotate me");
}

#[test]
fn rewrap_refuses_a_wrong_key_a_wrong_context_and_tampering() {
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"rotate me").unwrap();
    let expected = expect(&sealed, ObjectKind::Chunk);
    let new_wrapping = aead::Key::random();
    assert_eq!(
        rewrap(
            &keys(tenant("alice"), 9, 2),
            &new_wrapping,
            &expected,
            &sealed.bytes
        ),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
    assert_eq!(
        rewrap(
            &k,
            &new_wrapping,
            &ObjectExpectation::new(ObjectKind::Index, sealed.reference),
            &sealed.bytes
        ),
        Err(CheckpointObjectError::ContextMismatch(ContextField::Kind))
    );
    let mut tampered = sealed.bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        rewrap(&k, &new_wrapping, &expected, &tampered),
        Err(CheckpointObjectError::WrappedKeyAuth),
        "a tampered payload is refused, not rewrapped"
    );
}

#[test]
fn rewrap_is_rotation_not_revocation() {
    // The old wrapping key still yields the data key, and that key still
    // decrypts the rewrapped payload: an old-key holder is not locked out.
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"rotate me").unwrap();
    let expected = expect(&sealed, ObjectKind::Chunk);
    let rewrapped = rewrap(
        &k,
        &aead::Key::from_bytes([7; KEY_SIZE]),
        &expected,
        &sealed.bytes,
    )
    .unwrap();
    let at = wrapped_key_at();
    let mut with_old_wrap = rewrapped.clone();
    with_old_wrap[at..at + WRAPPED_KEY_LEN]
        .copy_from_slice(&sealed.bytes[at..at + WRAPPED_KEY_LEN]);
    assert_eq!(open(&k, &expected, &with_old_wrap).unwrap(), b"rotate me");
    // Re-sealing is the revocation path: a new data key and a new payload.
    let resealed = seal(
        &k,
        ObjectKind::Chunk,
        &open(&k, &expected, &sealed.bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(resealed.reference, sealed.reference);
    assert_ne!(
        ObjectFrame::parse(&resealed.bytes).unwrap().fingerprint(),
        ObjectFrame::parse(&sealed.bytes).unwrap().fingerprint()
    );
}

#[test]
fn repeated_rewraps_open_only_under_the_latest_key() {
    let mut current = alice();
    let sealed = seal(&current, ObjectKind::Index, b"index").unwrap();
    let expected = expect(&sealed, ObjectKind::Index);
    let mut bytes = sealed.bytes.clone();
    for wrap in [10u8, 11, 12] {
        let next = keys(tenant("alice"), wrap, 2);
        bytes = rewrap(
            &current,
            &aead::Key::from_bytes([wrap; KEY_SIZE]),
            &expected,
            &bytes,
        )
        .unwrap();
        assert_eq!(
            open(&current, &expected, &bytes),
            Err(CheckpointObjectError::WrappedKeyAuth)
        );
        assert_eq!(open(&next, &expected, &bytes).unwrap(), b"index");
        current = next;
    }
}

#[test]
fn rewrap_refuses_a_wrapped_key_moved_onto_another_payload() {
    let k = alice();
    let a = seal(&k, ObjectKind::Chunk, b"payload a").unwrap();
    let b = seal(&k, ObjectKind::Chunk, b"payload b").unwrap();
    let range = wrapped_key_at()..wrapped_key_at() + WRAPPED_KEY_LEN;
    let mut spliced = b.bytes.clone();
    spliced[range.clone()].copy_from_slice(&a.bytes[range]);
    assert_eq!(
        rewrap(
            &k,
            &aead::Key::random(),
            &expect(&b, ObjectKind::Chunk),
            &spliced
        ),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
}

#[test]
fn one_secret_is_never_both_the_wrapping_and_the_reference_key() {
    let shared = DomainKeys::new(
        tenant("alice"),
        aead::Key::from_bytes([5; KEY_SIZE]),
        ReferenceKey::from_bytes([5; REFERENCE_LEN]),
    );
    assert_eq!(shared.err(), Some(CheckpointObjectError::SharedKeyMaterial));
    let k = alice();
    let sealed = seal(&k, ObjectKind::Chunk, b"x").unwrap();
    assert_eq!(
        rewrap(
            &k,
            &aead::Key::from_bytes([2; KEY_SIZE]),
            &expect(&sealed, ObjectKind::Chunk),
            &sealed.bytes
        ),
        Err(CheckpointObjectError::SharedKeyMaterial)
    );
}

#[test]
fn a_chunk_never_opens_as_an_index_of_the_same_bytes() {
    let k = alice();
    let chunk = seal(&k, ObjectKind::Chunk, b"same").unwrap();
    let index_ref = k.reference_for(ObjectKind::Index, b"same").unwrap();
    let mut relabelled = chunk.bytes.clone();
    relabelled[5] = 2;
    assert_eq!(
        open(
            &k,
            &ObjectExpectation::new(ObjectKind::Index, chunk.reference),
            &relabelled
        ),
        Err(CheckpointObjectError::WrappedKeyAuth)
    );
    assert_eq!(
        open(
            &k,
            &ObjectExpectation::new(ObjectKind::Index, index_ref),
            &relabelled
        ),
        Err(CheckpointObjectError::ContextMismatch(
            ContextField::Reference
        ))
    );
}

#[test]
fn object_refs_render_as_lowercase_hex_and_parse_strictly() {
    let r = alice().reference_for(ObjectKind::Chunk, b"x").unwrap();
    let text = r.to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(text.parse::<ObjectRef>().unwrap(), r);
    let json = serde_json::to_string(&r).unwrap();
    assert_eq!(serde_json::from_str::<ObjectRef>(&json).unwrap(), r);
    for bad in [
        &text[..63],
        &text.to_uppercase(),
        &format!("{text}0"),
        &format!("g{}", &text[1..]),
    ] {
        assert_eq!(
            bad.parse::<ObjectRef>(),
            Err(CheckpointObjectError::InvalidReference)
        );
    }
    assert!(serde_json::from_str::<ObjectRef>("\"sha256:00\"").is_err());
}

/// The binding header for fixed inputs. Changing the layout breaks this test,
/// and so it must: stored objects would stop opening.
#[test]
fn binding_header_layout_is_frozen() {
    let header = frame::Binding {
        kind: ObjectKind::Index,
        domain: "host",
        reference: ObjectRef::from_bytes([0x11; REFERENCE_LEN]),
        plaintext_len: 0x0102,
    }
    .encode();
    let expected = format!(
        "4d56434f{}{}{}{}{}{}{}",
        "01",
        "02",
        "0000",
        "04",
        "686f7374",
        "11".repeat(REFERENCE_LEN),
        "0000000000000102"
    );
    assert_eq!(hex::encode(header), expected);
}

/// A version 1 object sealed once with fixed keys. Every later build must
/// keep opening it.
#[test]
fn a_recorded_version_1_object_still_opens() {
    let k = keys(tenant("vector"), 0x42, 0x24);
    let bytes = hex::decode(RECORDED_V1_CHUNK).unwrap();
    let frame = ObjectFrame::parse(&bytes).unwrap();
    let expected = ObjectExpectation::new(ObjectKind::Chunk, frame.reference()).plaintext_len(11);
    assert_eq!(open(&k, &expected, &bytes).unwrap(), b"hello world");
    assert_eq!(
        frame.reference(),
        k.reference_for(ObjectKind::Chunk, b"hello world").unwrap()
    );
}

const RECORDED_V1_CHUNK: &str = concat!(
    "4d56434f010100000d74656e616e743a766563746f72668089aeef8c086fb4ce",
    "1c2b97625c46cde48a2f82df1fdc8eeefd633336bb34000000000000000b43e3",
    "18cc2119cd7cdb28dfe47cd8e1521093c9ccf98d6e1e652f9b7a4cfa765ca63a",
    "778ef37ed3b14b9d6dc42d7540c0bcfe633ac96b0e102d2b2e9645739580bc31",
    "af9ef7b8a13249d1e8b318008413c2329df267e04e6e0fd4e2ed7557da8a5e1a",
    "a5",
);
