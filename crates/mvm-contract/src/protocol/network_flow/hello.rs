//! What the two peers tell each other in `Hello`/`HelloAck`.
//!
//! [`frame::PROTOCOL_VERSION`](super::frame) covers the byte layout: change
//! the header and a mismatched peer's frames stop decoding. It does not
//! cover the layer above it — which opcodes a peer emits, which it expects
//! an answer to, what it does when one never arrives. Two builds can agree
//! on every byte of the framing and still disagree about all of that, and
//! the failure looks like a hang or a bare `ECONNREFUSED`, with nothing
//! naming the two halves that disagree.
//!
//! So each peer states its [`BEHAVIOR_REVISION`] and a label for its own
//! build, and [`agree`] refuses a session whose halves were built against
//! different revisions — naming both, because the whole difficulty of this
//! failure is finding out which side is stale.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The revision of what the peers expect of each other, beyond the framing.
///
/// Bump this in the same change that alters the expectation: a new opcode
/// either side must answer, a changed meaning for an existing one, a
/// different fail-closed rule. Leave it alone for changes a peer cannot
/// observe. It is a declaration, not a derivation — nothing computes it,
/// which is exactly why the bump belongs in the diff that earns it.
pub const BEHAVIOR_REVISION: u32 = 3;

/// The longest build label a peer may send. Long enough for a crate name
/// and a version, short enough that it can never be the interesting part
/// of a frame.
pub const MAX_BUILD_LEN: usize = 128;

/// A peer's self-description, carried on `Hello` and `HelloAck`.
///
/// The `build` label is diagnostic only — [`agree`] never decides anything
/// from it. It exists so the refusal can say *which* two builds disagreed
/// rather than that two builds did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The peer's [`BEHAVIOR_REVISION`] at compile time.
    pub behavior_revision: u32,
    /// A human-readable name for the peer's build. Untrusted, bounded,
    /// and used only in messages.
    pub build: String,
}

impl Handshake {
    /// Describe this build. `build` is truncated to [`MAX_BUILD_LEN`] on a
    /// character boundary rather than refused: a label too long to send is
    /// a worse reason to fail a session than no label at all.
    #[must_use]
    pub fn local(build: &str) -> Self {
        let mut build = build.to_string();
        if build.len() > MAX_BUILD_LEN {
            let mut end = MAX_BUILD_LEN;
            while end > 0 && !build.is_char_boundary(end) {
                end -= 1;
            }
            build.truncate(end);
        }
        Self {
            behavior_revision: BEHAVIOR_REVISION,
            build,
        }
    }

    /// Serialize for a `Hello`/`HelloAck` payload: `u32` revision, `u16`
    /// label length, then the label's UTF-8 bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let bytes = self.build.as_bytes();
        let mut out = Vec::with_capacity(6 + bytes.len());
        out.extend_from_slice(&self.behavior_revision.to_be_bytes());
        // `local` bounds this to MAX_BUILD_LEN, which fits a u16.
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// Parse a peer's payload. Every field is peer-controlled, so the length
    /// is checked against the buffer before it is trusted and against
    /// [`MAX_BUILD_LEN`] before the label is kept.
    pub fn decode(payload: &[u8]) -> Result<Self, HandshakeError> {
        if payload.len() < 6 {
            return Err(HandshakeError::Malformed {
                why: format!(
                    "handshake payload is {} bytes, need at least 6",
                    payload.len()
                ),
            });
        }
        let behavior_revision =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let build_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
        if build_len > MAX_BUILD_LEN {
            return Err(HandshakeError::Malformed {
                why: format!("build label is {build_len} bytes, over the {MAX_BUILD_LEN} limit"),
            });
        }
        let rest = &payload[6..];
        if rest.len() != build_len {
            return Err(HandshakeError::Malformed {
                why: format!(
                    "build label announced {build_len} bytes, {} follow the header",
                    rest.len()
                ),
            });
        }
        let build = core::str::from_utf8(rest)
            .map_err(|e| HandshakeError::Malformed {
                why: format!("build label is not UTF-8: {e}"),
            })?
            .to_string();
        Ok(Self {
            behavior_revision,
            build,
        })
    }
}

/// Why a handshake was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The payload was not a handshake. Fatal: the peer is either a
    /// different protocol or a different framing of this one.
    #[error("malformed FlowMux handshake: {why}")]
    Malformed {
        /// What was wrong with the bytes.
        why: String,
    },
    /// The two halves were built against different behavior revisions.
    #[error(
        "FlowMux behavior revision mismatch: this side is revision {local_revision} \
         (built from {local_build}), the peer is revision {peer_revision} \
         (built from {peer_build}) — the two halves are from different builds, \
         so rebuild and restage whichever is stale"
    )]
    RevisionMismatch {
        /// This side's compiled-in [`BEHAVIOR_REVISION`].
        local_revision: u32,
        /// This side's build label.
        local_build: String,
        /// The revision the peer announced.
        peer_revision: u32,
        /// The build label the peer announced.
        peer_build: String,
    },
}

/// Decide whether two peers can talk.
///
/// Refuses on any revision difference rather than trying to serve the
/// older one: every legitimate deployment builds both halves from the same
/// tree — the host binary embeds the guest's — so a difference is a stale
/// artifact, never a supported configuration.
pub fn agree(local: &Handshake, peer: &Handshake) -> Result<(), HandshakeError> {
    if local.behavior_revision == peer.behavior_revision {
        return Ok(());
    }
    Err(HandshakeError::RevisionMismatch {
        local_revision: local.behavior_revision,
        local_build: local.build.clone(),
        peer_revision: peer.behavior_revision,
        peer_build: peer.build.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handshake_round_trips_through_its_payload() {
        let h = Handshake::local("mvm-egress-client 0.1.0");
        assert_eq!(Handshake::decode(&h.encode()).expect("decode"), h);
    }

    #[test]
    fn an_empty_build_label_round_trips() {
        let h = Handshake::local("");
        assert_eq!(Handshake::decode(&h.encode()).expect("decode"), h);
    }

    #[test]
    fn an_over_long_label_is_truncated_rather_than_refused() {
        let h = Handshake::local(&"x".repeat(MAX_BUILD_LEN * 3));
        assert_eq!(h.build.len(), MAX_BUILD_LEN);
        assert_eq!(Handshake::decode(&h.encode()).expect("decode"), h);
    }

    #[test]
    fn truncation_lands_on_a_character_boundary() {
        // A label of 3-byte characters cannot be cut at MAX_BUILD_LEN itself.
        let h = Handshake::local(&"€".repeat(MAX_BUILD_LEN));
        assert!(h.build.len() <= MAX_BUILD_LEN);
        assert_eq!(Handshake::decode(&h.encode()).expect("decode"), h);
    }

    #[test]
    fn matching_revisions_agree() {
        let a = Handshake::local("host");
        let b = Handshake::local("guest");
        agree(&a, &b).expect("same revision must agree");
    }

    #[test]
    fn a_revision_mismatch_names_both_builds() {
        let local = Handshake {
            behavior_revision: 7,
            build: "mvm-network-endpoint 0.1.0".into(),
        };
        let peer = Handshake {
            behavior_revision: 4,
            build: "mvm-egress-client 0.1.0".into(),
        };
        let e = agree(&local, &peer).expect_err("differing revisions must refuse");
        let msg = e.to_string();
        assert!(msg.contains("mvm-network-endpoint 0.1.0"), "{msg}");
        assert!(msg.contains("mvm-egress-client 0.1.0"), "{msg}");
        assert!(msg.contains('7') && msg.contains('4'), "{msg}");
    }

    #[test]
    fn a_short_payload_is_malformed_not_a_panic() {
        for len in 0..6 {
            let e = Handshake::decode(&vec![0u8; len]).expect_err("short payload");
            assert!(matches!(e, HandshakeError::Malformed { .. }));
        }
    }

    #[test]
    fn an_empty_payload_is_refused() {
        // The shape a peer that predates this handshake sends.
        assert!(Handshake::decode(b"").is_err());
    }

    #[test]
    fn a_lying_length_is_refused_without_reading_past_the_buffer() {
        let mut bytes = Handshake::local("guest").encode();
        bytes[4] = 0xff;
        bytes[5] = 0xff;
        let e = Handshake::decode(&bytes).expect_err("over-long announced label");
        assert!(matches!(e, HandshakeError::Malformed { .. }));
    }

    #[test]
    fn a_short_announced_length_is_refused() {
        let mut bytes = Handshake::local("guest").encode();
        bytes[5] = 1;
        assert!(Handshake::decode(&bytes).is_err());
    }

    #[test]
    fn a_non_utf8_label_is_refused() {
        let mut bytes = 1u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&[0xff, 0xfe]);
        assert!(Handshake::decode(&bytes).is_err());
    }

    #[test]
    fn a_handshake_payload_fits_a_frame() {
        let biggest = Handshake::local(&"x".repeat(MAX_BUILD_LEN)).encode();
        assert!(biggest.len() <= super::super::limits::MAX_PAYLOAD_LEN);
    }
}
