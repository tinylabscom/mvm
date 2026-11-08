//! Guest side of the mailbox port: when the host dials it, send the one
//! plaintext message the workload left in the outbox and return the host's
//! verdict.
//!
//! The guest holds no key and seals nothing. The outbox carries a recipient
//! and a body; the host seals and signs it under the capability the signed
//! plan granted, then admits it. Encryption is host to host.

use std::io::{Read, Write};
use std::path::Path;

use mvm_contract::protocol::mailbox::MAX_MAILBOX_PAYLOAD_BYTES;
use mvm_core::mailbox::frame::{OutboxMessage, Refusal, send_outbox_message};

/// The recipient bytes beside the largest body the host will seal.
const MAX_OUTBOX_BYTES: u64 = MAX_MAILBOX_PAYLOAD_BYTES as u64 + 32;

/// Forward the outbox message over `stream`. An absent, oversized or
/// malformed outbox is refused here, before a byte is sent to the host.
pub fn forward_outbox<S: Read + Write>(stream: &mut S, outbox: &Path) -> Result<(), Refusal> {
    let mut bytes = Vec::new();
    std::fs::File::open(outbox)
        .and_then(|file| file.take(MAX_OUTBOX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::Malformed)?;
    send_outbox_message(stream, &OutboxMessage::decode(&bytes)?)
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
        std::fs::write(&junk, b"short").unwrap();
        assert_eq!(forward_outbox(&mut ours, &junk), Err(Refusal::Malformed));
        let big = dir.path().join("big");
        std::fs::write(&big, vec![1u8; MAX_OUTBOX_BYTES as usize + 8]).unwrap();
        assert!(matches!(
            forward_outbox(&mut ours, &big),
            Err(Refusal::Oversized(_))
        ));
        drop(ours);
        let mut seen = Vec::new();
        theirs.read_to_end(&mut seen).unwrap();
        assert!(seen.is_empty(), "nothing reached the host");
    }

    /// The wire carries the plaintext message and nothing else: no
    /// capability, envelope, signature or key, and this path names no key
    /// type to build one from.
    #[test]
    fn the_frame_on_the_wire_is_exactly_the_plaintext_message() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let message = [&[9u8; 32][..], b"hello"].concat();
        std::fs::write(&outbox, &message).unwrap();
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let host = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut body).unwrap();
            theirs.write_all(b"{\"Ok\":null}").unwrap();
            body
        });
        assert_eq!(forward_outbox(&mut ours, &outbox), Ok(()));
        assert_eq!(host.join().unwrap(), message);
        let source = include_str!("mailbox_outbox.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for key_type in [
            "SigningKey",
            "aead::Key",
            "seal_envelope",
            "sign_capability",
        ] {
            assert!(!code.contains(key_type), "guest outbox names {key_type}");
        }
    }
}
