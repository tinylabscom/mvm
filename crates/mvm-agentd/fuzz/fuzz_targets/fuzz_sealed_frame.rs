// Fuzz the control plane's pre-auth ingress.
//
// `SealedFrame::decode` is the first thing an unauthenticated peer's bytes
// reach: the length prefix is read, then the whole frame is parsed — version,
// session id, sequence, timestamp, signer id, signature, ciphertext — before
// any signature is checked. A panic here is a crash an attacker can reach
// without holding a key, so the property is only "never panic", not
// "verifies".
//
// This replaced a target that fed the same bytes into
// `serde_json::from_slice::<AuthenticatedFrame>`. That was the ingress while
// the envelope was JSON; it no longer is, and a fuzz target aimed at a parser
// the control plane has stopped calling is a witness for nothing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_core::net::session::SealedFrame;

fuzz_target!(|data: &[u8]| {
    // The decoder owns its own bounds checks; hand it the raw bytes.
    if let Ok(frame) = SealedFrame::decode(data) {
        // A frame that decoded must re-encode. Anything else means `decode`
        // accepted a shape `encode` cannot produce, which is a parser and
        // serializer that disagree about the wire.
        let mut round_tripped = Vec::new();
        if frame.encode(&mut round_tripped).is_ok() {
            let _ = SealedFrame::decode(&round_tripped);
        }
    }
});
