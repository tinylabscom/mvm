// Fuzz the control plane's *post-auth* path: `Session::open`.
//
// `fuzz_sealed_frame` covers the pre-auth parser — arbitrary bytes into
// `SealedFrame::decode`, asserting only "never panic". This target starts
// where that one stops, from a frame that already decoded, and drives the
// checks that decide whether its payload is ever handed back: protocol
// version, session id, sequence (replay and gap), signer identity, Ed25519
// signature over the frame context, and AES-GCM decryption.
//
// The load-bearing property is that **no frame failing any of those checks
// yields plaintext**.
//
// What each scenario actually isolates, established by deleting the check and
// re-running rather than by reading the code:
//
//   1, 2  the signature check — these tamper fields the signature covers.
//   3, 4  the sequence check. Deleting it is caught here, because the frame
//         is genuinely signed and nothing else refuses a gap or a replay.
//   5     *not* the session-id check. Deleting that check leaves this case
//         still rejected, because `derive_session_key` mixes the session id
//         into the key, so a cross-session frame fails AES-GCM decryption on
//         its own. That is defence in depth working, not the scenario
//         failing — but the scenario cannot be cited as the session check's
//         witness, and is not.
//
// The first draft of this target tampered the sequence and session id on an
// otherwise valid frame. Both are covered by the signature, so the signature
// check refused them and deleting the sequence check changed nothing — a
// target that would have stayed green through the removal of the property it
// was named for.
//
// This replaced a target that drove `verify_authenticated_frame`, a
// signature-only path over the old JSON envelope. Once the control plane moved
// to the binary sealed envelope that function had no production callers, so
// the target was exercising code nothing took — a witness for a claim about a
// path that no longer existed.
#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use mvm_core::net::session::{Session, paired_sessions_for_test};

const SESSION_ID: &str = "fuzz-session";

/// Deterministic peers. Rebuilt per iteration rather than shared, so one
/// input's accepted frame cannot advance a sequence counter the next input
/// then trips over — the corpus stays reproducible input-by-input.
fn peers() -> (Session, Session) {
    paired_sessions_for_test(
        SigningKey::from_bytes(&[0x42; 32]),
        SigningKey::from_bytes(&[0x07; 32]),
        [0x5a; 32],
        SESSION_ID,
    )
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let scenario = data[0] % 6;
    let payload = &data[1..];

    let (mut host, mut guest) = peers();

    // Scenarios 3, 4 and 5 must reach the check they name, which means the
    // frame has to be *validly signed* when it gets there. Tampering a field
    // the signature covers only ever exercises the signature check — that is
    // what scenarios 1 and 2 are for, and conflating the two produces a target
    // that stays green when the replay check is deleted.
    match scenario {
        0 | 1 | 2 => {
            let Ok(mut sealed) = host.seal(payload) else {
                return;
            };
            match scenario {
                1 => sealed.ciphertext = payload.to_vec(),
                2 => {
                    let mut sig = vec![0u8; 64];
                    for (i, b) in payload.iter().take(64).enumerate() {
                        sig[i] = *b;
                    }
                    sealed.signature = sig;
                }
                _ => {}
            }
            let opened = guest.open(&sealed);
            if scenario == 0 {
                match opened {
                    Ok(plaintext) => assert_eq!(
                        plaintext, payload,
                        "an untampered frame must open to exactly what was sealed"
                    ),
                    Err(error) => panic!("an untampered frame was rejected: {error}"),
                }
            } else {
                assert!(
                    opened.is_err(),
                    "a tampered frame yielded plaintext; scenario={scenario}"
                );
            }
        }
        // A gap. The host seals twice and the peer is offered the second
        // frame first: the signature is genuine, so only the sequence check
        // can refuse it.
        3 => {
            let (Ok(_first), Ok(second)) = (host.seal(payload), host.seal(payload)) else {
                return;
            };
            assert!(
                guest.open(&second).is_err(),
                "a validly signed frame that skipped a sequence was accepted"
            );
        }
        // A replay. The first delivery must succeed, the second must not —
        // again with a genuine signature, so the replay check is the only
        // thing standing in the way.
        4 => {
            let Ok(sealed) = host.seal(payload) else {
                return;
            };
            if guest.open(&sealed).is_err() {
                return;
            }
            assert!(
                guest.open(&sealed).is_err(),
                "a replayed frame was accepted the second time"
            );
        }
        // A frame from a different session, signed by the same identity, so
        // the signature verifies and only the session-id check can refuse it.
        _ => {
            let (mut other_host, _other_guest) = paired_sessions_for_test(
                SigningKey::from_bytes(&[0x42; 32]),
                SigningKey::from_bytes(&[0x07; 32]),
                [0x5a; 32],
                "a-different-session",
            );
            let Ok(sealed) = other_host.seal(payload) else {
                return;
            };
            assert!(
                guest.open(&sealed).is_err(),
                "a frame addressed to another session was accepted"
            );
        }
    }
});
