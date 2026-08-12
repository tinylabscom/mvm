//! Fuzz the FlowMux frame decoder.
//!
//! The bytes reaching this decoder are entirely guest-controlled, and it is
//! the first thing on the workload networking path that touches them. The
//! contract it must hold for *any* input:
//!
//! - never panic, and never abort on an allocation the input asked for;
//! - never report a payload larger than the protocol cap;
//! - never claim to have consumed more bytes than it was given;
//! - re-encode what it decoded to exactly the bytes it decoded from.
//!
//! The last one is the interesting one: it makes a decoder that "helpfully"
//! normalizes a malformed field — the classic request-smuggling primitive —
//! a fuzz failure rather than a subtle behaviour difference between the two
//! ends of the connection.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::protocol::network_flow::{
    FrameError, LENGTH_PREFIX_LEN, MAX_PAYLOAD_LEN, MAX_WIRE_LEN, decode, encode, peek_frame_len,
};

fuzz_target!(|data: &[u8]| {
    // `peek_frame_len` is the pre-allocation gate: whatever it returns has
    // to be a length the reader can safely size a buffer to.
    if let Ok(len) = peek_frame_len(data) {
        assert!(
            LENGTH_PREFIX_LEN + len <= MAX_WIRE_LEN,
            "peek admitted {len}, past the wire ceiling"
        );
    }

    let Ok(parsed) = decode(data) else {
        return;
    };

    assert!(
        parsed.payload.len() <= MAX_PAYLOAD_LEN,
        "decoded a payload past the cap"
    );
    assert_eq!(
        parsed.payload.len(),
        parsed.header.payload_len as usize,
        "header and payload disagree after a successful decode"
    );
    assert!(
        parsed.consumed <= data.len(),
        "consumed more than it was given"
    );
    assert!(parsed.consumed >= LENGTH_PREFIX_LEN);

    // Round-trip: a frame that decoded must re-encode to the same bytes.
    // Any divergence is a normalization, and a normalization is a place
    // where two peers can disagree about what they just exchanged.
    match encode(
        parsed.header.opcode,
        parsed.header.stream_id,
        parsed.payload,
    ) {
        Ok(re) => assert_eq!(
            re.as_slice(),
            &data[..parsed.consumed],
            "decode/encode round trip changed the bytes"
        ),
        Err(e) => panic!("a frame that decoded failed to re-encode: {e:?}"),
    }

    // Decoding the re-encoded bytes must reach the same header, so the
    // decoder is idempotent over its own output.
    let again = decode(&data[..parsed.consumed]).expect("re-decode");
    assert_eq!(again.header, parsed.header);

    // Anything after the frame is the next frame's problem, and must not
    // have been consumed. Feeding the remainder back in must not panic.
    let rest = &data[parsed.consumed..];
    match decode(rest) {
        Ok(_) | Err(_) => {}
    }

    // A truncation of a decodable frame is always `Incomplete`, never a
    // different error and never a success — otherwise a short read would
    // change how a frame is interpreted.
    if parsed.consumed > LENGTH_PREFIX_LEN {
        let short = &data[..parsed.consumed - 1];
        match decode(short) {
            Err(e) if e.is_incomplete() => {}
            other => panic!("truncated frame did not report incomplete: {other:?}"),
        }
    }

    // Nudging the version must always be refused, never negotiated down.
    if parsed.consumed >= LENGTH_PREFIX_LEN + 5 {
        let mut tampered = data[..parsed.consumed].to_vec();
        tampered[LENGTH_PREFIX_LEN + 4] = tampered[LENGTH_PREFIX_LEN + 4].wrapping_add(1);
        match decode(&tampered) {
            Err(FrameError::UnsupportedVersion { .. }) => {}
            other => panic!("a bumped version was not refused: {other:?}"),
        }
    }
});
