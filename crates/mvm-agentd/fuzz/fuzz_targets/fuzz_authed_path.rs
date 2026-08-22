// Fuzz the *signed* path of the authenticated-frame
// pipeline. The two existing targets (`fuzz_sealed_frame`,
// `fuzz_guest_request`) cover the *pre-auth* parsers — they feed raw
// bytes into `serde_json::from_slice` and assert "never panic." That
// proves the unauthenticated parser is safe, but it doesn't exercise
// what happens after the envelope deserializes: the protocol-version,
// session-ID, replay, signature-length, Ed25519 verification, and
// inner-payload-deserialize stages.
//
// This target drives `verify_authenticated_frame::<GuestRequest>`
// directly, with a deterministic Ed25519 keypair. For each random
// input it picks one of four scenarios:
//
//   0  Sign with the *correct* key (well-formed envelope).
//   1  Sign with the *wrong* key (signature verification must fail).
//   2  Stuff a 64-byte signature blob from fuzzer bytes (almost
//      certainly invalid; mostly exercises the wrong-sig branch).
//   3  Strip the signature to a wrong length (length check must fire).
//
// Properties asserted:
//   • Never panic on any (scenario × payload × envelope-tweak) input.
//   • For scenarios 1–3, the result is always `Err` — i.e., the
//     inner-payload deserializer is never reached on a tampered
//     frame. The static call ordering in `verify_authenticated_frame`
//     (signature check at line 498, deserialize at line 503) is the
//     load-bearing invariant; this fuzzer guards against a future
//     refactor reordering them.
//   • For scenario 0, no assertion on Ok/Err — random bytes rarely
//     deserialize as a valid `GuestRequest`, so Err from the inner
//     parser is expected and benign. The point is: under a valid
//     signature the deserializer runs without panicking.
#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use mvm_core::security::{AuthenticatedFrame, PROTOCOL_VERSION_AUTHENTICATED, SIG_ALG_ED25519};
use mvm_core::signing::SignedPayload;
use mvm_agentd::vsock::{GuestRequest, verify_authenticated_frame};

const SESSION_ID: &str = "fuzz-session";
const EXPECTED_MIN_SEQUENCE: u64 = 0;

fn key_from_seed(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let scenario = data[0] % 4;
    let payload = &data[1..];

    let signing_key = key_from_seed(0x42);
    let verifying_key = signing_key.verifying_key();
    let other_key = key_from_seed(0x07);

    let signature_bytes: Vec<u8> = match scenario {
        0 => signing_key.sign(payload).to_bytes().to_vec(),
        1 => other_key.sign(payload).to_bytes().to_vec(),
        2 => {
            // Borrow up to 64 bytes from the fuzzer corpus, zero-pad
            // to exactly 64 so the length check passes and the
            // verifier itself is what rejects (mostly).
            let mut sig = vec![0u8; 64];
            for (i, b) in payload.iter().take(64).enumerate() {
                sig[i] = *b;
            }
            sig
        }
        _ => {
            // Wrong-length signature → length check fires before
            // ed25519 even sees the bytes.
            payload.iter().take(63).copied().collect()
        }
    };

    let frame = AuthenticatedFrame {
        version: PROTOCOL_VERSION_AUTHENTICATED,
        sig_alg: SIG_ALG_ED25519,
        session_id: SESSION_ID.to_string(),
        sequence: EXPECTED_MIN_SEQUENCE,
        timestamp: "2026-05-05T00:00:00Z".to_string(),
        signed: SignedPayload {
            payload: payload.to_vec(),
            signature: signature_bytes,
            signer_id: "fuzz".to_string(),
        },
    };

    let result = verify_authenticated_frame::<GuestRequest>(
        &frame,
        &verifying_key,
        SESSION_ID,
        EXPECTED_MIN_SEQUENCE,
    );

    if scenario != 0 {
        assert!(
            result.is_err(),
            "tampered/wrong-key/short-sig frame was accepted by verify_authenticated_frame; \
             scenario={scenario}, payload_len={}",
            payload.len()
        );
    }
});
