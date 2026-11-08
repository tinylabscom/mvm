//! Guest side of the mailbox port: when the host dials it, send the one sealed
//! frame the workload left in the outbox and return the host's verdict.
//!
//! The agent never holds a key and never builds an envelope. The workload
//! seals its own message and writes the frame body (`encode_frame`) to the
//! outbox; the agent only forwards it through the shared codec, so the host
//! service stays the sole admission decision.

use std::io::{Read, Write};
use std::path::Path;

use mvm_contract::protocol::mailbox::MAX_ENCODED_ENVELOPE_BYTES;
use mvm_core::mailbox::frame::{Refusal, decode_frame, send_frame};

/// Room for the capability JSON beside the largest accepted envelope.
const MAX_OUTBOX_BYTES: u64 = MAX_ENCODED_ENVELOPE_BYTES as u64 + 64 * 1024;

/// Forward the outbox frame over `stream`. An absent, oversized or malformed
/// outbox is refused here, before a byte is sent to the host.
pub fn forward_outbox<S: Read + Write>(stream: &mut S, outbox: &Path) -> Result<(), Refusal> {
    let mut body = Vec::new();
    std::fs::File::open(outbox)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut body))
        .map_err(|_| Refusal::Malformed)?;
    if body.len() as u64 > MAX_OUTBOX_BYTES {
        return Err(Refusal::Oversized(MAX_OUTBOX_BYTES as usize));
    }
    let (capability, envelope) = decode_frame(&body)?;
    send_frame(stream, &capability, &envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_malformed_outbox_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            forward_outbox(&mut ours, &dir.path().join("none")),
            Err(Refusal::Malformed)
        );
        let junk = dir.path().join("junk");
        std::fs::write(&junk, b"not a frame").unwrap();
        assert_eq!(forward_outbox(&mut ours, &junk), Err(Refusal::Malformed));
        drop(ours);
        let mut seen = Vec::new();
        theirs.read_to_end(&mut seen).unwrap();
        assert!(seen.is_empty(), "nothing reached the host");
    }
}
