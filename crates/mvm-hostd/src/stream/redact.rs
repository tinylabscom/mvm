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

use mvm_contract::stream::{StreamKind, StreamSource};
use mvm_core::policy::RedactionPolicy;
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

/// The seam a [`StreamBroker`](crate::stream::StreamBroker) is built over —
/// and the only way to build one.
///
/// A trait alone would not close the hole it opens: a `PiiRedactor` carrying
/// an empty ruleset satisfies [`StreamRedactor`] exactly as well as the real
/// one, so a broker constructed from a bare seam can be silently
/// non-redacting. Wrapping the seam in a type whose field is private and
/// whose only production constructor is [`StreamRedaction::curated`] moves
/// that from a convention nobody can see broken into something the compiler
/// refuses to build. `xtask check-stream-redaction-seam` pins the same
/// property at the call sites.
pub struct StreamRedaction(Box<dyn StreamRedactor>);

impl StreamRedaction {
    /// The shipped ruleset, read through the workload's own redaction policy.
    /// The only way to obtain a `StreamRedaction` outside this crate's own
    /// tests.
    ///
    /// The policy is the same one the launch already hands the substitution
    /// endpoint, so a workload that narrows PII categories gets one answer on
    /// egress and the same answer in its transcript. Only `default` applies:
    /// the per-host profiles select by destination, and recorded output has no
    /// destination to select on.
    ///
    /// **It can only ever install curated rules.** A policy naming categories
    /// picks among them; a policy that would leave nothing scanning —
    /// `pii.mode = "disabled"`, or a category name that does not resolve —
    /// falls back to the full set rather than to an empty one. The transcript
    /// is the operator's copy of what a workload said, and a workload does not
    /// get to opt its own record out of the seam.
    pub fn curated(policy: &RedactionPolicy) -> Self {
        let scanner = PiiRedactor::from_policy(&policy.default.pii)
            .ok()
            .flatten()
            .unwrap_or_else(PiiRedactor::with_default_rules);
        Self(Box::new(scanner))
    }

    /// A seam that is not the curated ruleset — a stricter detector, or one
    /// that refuses. Test-only: the fail-closed path needs a detector that
    /// *can* fail, and `PiiRedactor` cannot, but a production build must not
    /// be able to reach past `curated`.
    #[cfg(test)]
    pub(in crate::stream) fn from_seam(seam: Box<dyn StreamRedactor>) -> Self {
        Self(seam)
    }
}

impl StreamRedactor for StreamRedaction {
    fn redact(&self, body: &[u8]) -> Result<Redacted, RedactionFailed> {
        self.0.redact(body)
    }
}

impl StreamRedactor for PiiRedactor {
    fn redact(&self, body: &[u8]) -> Result<Redacted, RedactionFailed> {
        // The inherent curated-regex pass; it masks in place and cannot fail.
        let (body, rules_fired) = PiiRedactor::redact(self, body);
        Ok(Redacted { body, rules_fired })
    }
}

/// One chunk after the seam has ruled on it: the bytes that may be shown, the
/// channel they go out on, and what the seam decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClearedChunk {
    /// The channel the bytes go out on — the one they arrived on, or
    /// [`StreamKind::Trace`] when a marker stands in for them.
    pub kind: StreamKind,
    /// Bytes cleared for the chain, the transcript, and every consumer.
    pub body: Vec<u8>,
    /// What the seam decided, for the caller's own bookkeeping.
    pub outcome: ClearOutcome,
}

/// What the seam decided about one chunk.
///
/// Public because it is also the broker's answer to whoever handed it the
/// bytes: [`StreamBroker::ingest`](crate::stream::StreamBroker::ingest)
/// returns it so a producer that is *also* showing those bytes to somebody can
/// say how the copy it recorded differs from the copy it showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearOutcome {
    /// Nothing matched; the bytes are the workload's own, unchanged.
    Clean,
    /// At least one rule fired. Names only — a value that fired a rule is
    /// exactly the value that must not travel.
    Redacted { rules_fired: Vec<&'static str> },
    /// The seam would not vouch for the chunk, so a marker took its place.
    Withheld {
        /// Why the detector gave up. Describes the detector, never the bytes.
        reason: String,
        /// How much was dropped, for a caller that wants to say so.
        dropped_bytes: usize,
    },
}

/// Run one chunk through the seam, substituting a marker for anything it will
/// not vouch for.
///
/// The one implementation of that policy, kept out of the broker so it is
/// stated and tested in one place rather than spelled out at each ingest as
/// "redact, and on failure emit a `Trace` marker". A second copy of the
/// fail-closed substitution would be a second chance to ship a byte nobody
/// checked, and the two would drift the first time either changed.
pub(crate) fn clear_for_display(
    seam: &StreamRedaction,
    source: StreamSource,
    kind: StreamKind,
    bytes: &[u8],
) -> ClearedChunk {
    match seam.redact(bytes) {
        Ok(redacted) if redacted.rules_fired.is_empty() => ClearedChunk {
            kind,
            body: redacted.body,
            outcome: ClearOutcome::Clean,
        },
        Ok(redacted) => ClearedChunk {
            kind,
            body: redacted.body,
            outcome: ClearOutcome::Redacted {
                rules_fired: redacted.rules_fired,
            },
        },
        // Fail closed: a byte nobody could check does not ship. The marker
        // keeps the gap visible — a reader learns output was suppressed
        // instead of silently seeing less than the workload wrote.
        Err(err) => ClearedChunk {
            kind: StreamKind::Trace,
            body: redaction_failure_marker(source, kind, bytes.len() as u64),
            outcome: ClearOutcome::Withheld {
                reason: err.reason,
                dropped_bytes: bytes.len(),
            },
        },
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
    fn the_curated_seam_is_the_full_ruleset_not_an_empty_one() {
        // The hole this type closes: an empty ruleset satisfies the trait just
        // as well as the real one, so `curated` must demonstrably redact.
        let seam = StreamRedaction::curated(&RedactionPolicy::default());
        let out = seam
            .redact(b"card 4111111111111111 end")
            .expect("the curated pass cannot fail");
        assert!(!out.body.windows(TEST_CARD.len()).any(|w| w == TEST_CARD));
        assert!(out.rules_fired.contains(&"credit_card"));
    }

    /// The policy shape a workload uses to say "scan only these categories".
    fn pii_policy(mode: Option<&str>, categories: &[&str]) -> RedactionPolicy {
        RedactionPolicy {
            default: mvm_core::policy::RedactionAction {
                pii: mvm_core::policy::PiiPolicy {
                    mode: mode.map(str::to_string),
                    categories: categories.iter().map(|c| (*c).to_string()).collect(),
                },
                ..Default::default()
            },
            profiles: Vec::new(),
        }
    }

    #[test]
    fn a_policy_that_names_categories_scans_those_and_leaves_the_rest() {
        // The point of reading the policy at all: an operator who narrowed
        // egress scanning to one category gets the same answer in the
        // transcript instead of two different ones.
        let seam = StreamRedaction::curated(&pii_policy(None, &["email"]));
        let out = seam
            .redact(b"a@b.com card 4111111111111111")
            .expect("the curated pass cannot fail");
        assert_eq!(out.rules_fired, ["email"]);
        assert!(
            out.body.windows(TEST_CARD.len()).any(|w| w == TEST_CARD),
            "a category the policy left out must not be scanned"
        );
    }

    #[test]
    fn a_policy_that_would_disable_scanning_still_gets_the_full_ruleset() {
        // `pii.mode = "disabled"` skips the inspector on egress. Here there is
        // no inspector to skip — every byte must cross the seam — so the
        // fallback is the curated set, never an empty one.
        for policy in [
            pii_policy(Some("disabled"), &[]),
            pii_policy(None, &["no-such-category"]),
            pii_policy(Some("no-such-mode"), &[]),
        ] {
            let seam = StreamRedaction::curated(&policy);
            let out = seam
                .redact(b"card 4111111111111111 end")
                .expect("the curated pass cannot fail");
            assert!(
                !out.body.windows(TEST_CARD.len()).any(|w| w == TEST_CARD),
                "a workload must not be able to opt its own transcript out of the seam"
            );
            assert!(out.rules_fired.contains(&"credit_card"));
        }
    }

    #[test]
    fn a_clean_chunk_keeps_its_channel_and_reports_nothing_fired() {
        let cleared = clear_for_display(
            &StreamRedaction::curated(&RedactionPolicy::default()),
            StreamSource::Entrypoint,
            StreamKind::Stderr,
            b"nothing to see here",
        );
        assert_eq!(cleared.kind, StreamKind::Stderr);
        assert_eq!(cleared.body, b"nothing to see here");
        assert_eq!(cleared.outcome, ClearOutcome::Clean);
    }

    #[test]
    fn a_match_is_masked_in_place_and_names_the_rule_without_quoting_the_value() {
        let cleared = clear_for_display(
            &StreamRedaction::curated(&RedactionPolicy::default()),
            StreamSource::Entrypoint,
            StreamKind::Stdout,
            b"card 4111111111111111 end",
        );
        assert_eq!(cleared.kind, StreamKind::Stdout);
        assert!(
            !cleared
                .body
                .windows(TEST_CARD.len())
                .any(|w| w == TEST_CARD)
        );
        match cleared.outcome {
            ClearOutcome::Redacted { rules_fired } => assert!(rules_fired.contains(&"credit_card")),
            other => panic!("expected a redaction, got {other:?}"),
        }
    }

    /// A seam that cannot decide — the shape a detector with a timeout or a
    /// crashed subprocess presents, which the curated regex pass never can.
    struct FailingRedactor;

    impl StreamRedactor for FailingRedactor {
        fn redact(&self, _body: &[u8]) -> Result<Redacted, RedactionFailed> {
            Err(RedactionFailed::new("detector unavailable"))
        }
    }

    #[test]
    fn a_chunk_the_seam_cannot_vouch_for_is_retagged_and_replaced_by_a_marker() {
        // The whole reason this decision is shared rather than written once
        // per ingest path: fail-closed is the policy, and a second copy of it
        // is a second chance to get it wrong.
        let cleared = clear_for_display(
            &StreamRedaction::from_seam(Box::new(FailingRedactor)),
            StreamSource::Entrypoint,
            StreamKind::Stdout,
            b"unscannable",
        );
        assert_eq!(
            cleared.kind,
            StreamKind::Trace,
            "a marker on the stdout channel would look like the workload's own bytes"
        );
        assert!(!cleared.body.windows(11).any(|w| w == b"unscannable"));
        assert_eq!(
            cleared.outcome,
            ClearOutcome::Withheld {
                reason: "detector unavailable".to_string(),
                dropped_bytes: 11,
            }
        );
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
