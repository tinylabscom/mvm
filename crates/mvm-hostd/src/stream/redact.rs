//! The single seam every captured byte crosses before it is chained,
//! persisted, or shown.
//!
//! The broker redacts *before* it hashes, so the chain proves what was
//! shown rather than what the workload wrote — and the pre-redaction bytes
//! become unprovable. That is the price of having one seam: the alternative,
//! storing raw and redacting per consumer, makes every new consumer a new
//! leak path. One decision point, the same posture the egress gate takes.
//!
//! The seam is fallible even though today's detector is not. A detector that
//! *can* give up (a model-backed classifier, a subprocess, anything with a
//! timeout) is the reason the trait exists in this shape: with a fallible
//! signature the broker's fail-closed path is written and tested now, rather
//! than bolted on the day such a detector lands.

use mvm_protocol::stream::{StreamKind, StreamSource};
use serde::Serialize;

use crate::supervisor::pii_redactor::PiiRedactor;

/// Wire name of the marker record the broker substitutes for a chunk the
/// seam could not check. Shared so the emitter and any reader agree on the
/// string.
pub const REDACTION_FAILED_EVENT: &str = "stream.redaction_failed";

/// What came back out of the seam: the bytes that may be shown, plus the
/// rule names that fired. Names only — a value that fired a rule is exactly
/// the value that must not travel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    /// Bytes cleared for the chain, the transcript, and every reader.
    pub body: Vec<u8>,
    /// Rule names that matched, stable order, no duplicates.
    pub rules_fired: Vec<&'static str>,
}

/// The detector could not decide whether a chunk was safe to show.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("stream redaction failed: {reason}")]
pub struct RedactionFailed {
    /// Why the detector gave up. Describes the *detector*, never the bytes:
    /// a reason quoting the payload would reopen the leak the seam closes.
    pub reason: String,
}

impl RedactionFailed {
    /// Build a failure from a detector-side description.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// The redaction seam. One implementation runs per broker, and every
/// captured chunk goes through it exactly once.
pub trait StreamRedactor: Send + Sync {
    /// Clear `body` for display, or refuse to vouch for it.
    fn redact(&self, body: &[u8]) -> Result<Redacted, RedactionFailed>;
}

impl StreamRedactor for PiiRedactor {
    fn redact(&self, body: &[u8]) -> Result<Redacted, RedactionFailed> {
        // The inherent curated-regex pass; it masks in place and cannot fail.
        let (body, rules_fired) = PiiRedactor::redact(self, body);
        Ok(Redacted { body, rules_fired })
    }
}

/// Payload of the `Trace` record that stands in for a chunk the seam could
/// not check.
///
/// Carries the *shape* of what was dropped and nothing from it. Failing
/// closed means those bytes do not ship; a marker that quoted them would
/// ship them anyway.
pub fn redaction_failure_marker(
    source: StreamSource,
    kind: StreamKind,
    dropped_bytes: u64,
) -> Vec<u8> {
    let marker = RedactionFailureMarker {
        event: REDACTION_FAILED_EVENT,
        source,
        kind,
        dropped_bytes,
    };
    // Fixed field set of plain scalars — serialization cannot fail. The
    // fallback keeps the record honest rather than empty if it ever does.
    serde_json::to_vec(&marker).unwrap_or_else(|_| REDACTION_FAILED_EVENT.as_bytes().to_vec())
}

#[derive(Debug, Serialize)]
struct RedactionFailureMarker {
    event: &'static str,
    /// Which source produced the unshippable chunk.
    source: StreamSource,
    /// Which channel it would have gone out on, before the marker retagged
    /// the record as `Trace`.
    kind: StreamKind,
    dropped_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Luhn-valid test card number; the curated ruleset masks it.
    const TEST_CARD: &[u8] = b"4111111111111111";

    #[test]
    fn the_default_ruleset_masks_a_card_number_and_names_the_rule() {
        let redactor = PiiRedactor::with_default_rules();
        let out = StreamRedactor::redact(&redactor, b"card 4111111111111111 end")
            .expect("curated regex pass cannot fail");
        assert!(
            !out.body.windows(TEST_CARD.len()).any(|w| w == TEST_CARD),
            "the raw card must not survive the seam"
        );
        assert!(out.rules_fired.contains(&"credit_card"));
    }

    #[test]
    fn clean_bytes_pass_through_byte_for_byte() {
        let redactor = PiiRedactor::with_default_rules();
        let out = StreamRedactor::redact(&redactor, b"nothing to see here")
            .expect("curated regex pass cannot fail");
        assert_eq!(out.body, b"nothing to see here");
        assert!(out.rules_fired.is_empty());
    }

    #[test]
    fn the_failure_marker_names_the_dropped_shape_but_none_of_its_bytes() {
        let marker = redaction_failure_marker(StreamSource::Console, StreamKind::Stderr, 4_096);
        let text = String::from_utf8(marker).expect("marker is json");
        assert!(text.contains(REDACTION_FAILED_EVENT));
        assert!(text.contains("console"));
        assert!(text.contains("stderr"));
        assert!(text.contains("4096"));
    }

    #[test]
    fn a_failure_reason_renders_without_the_payload() {
        let err = RedactionFailed::new("detector timed out");
        assert_eq!(
            err.to_string(),
            "stream redaction failed: detector timed out"
        );
    }
}
