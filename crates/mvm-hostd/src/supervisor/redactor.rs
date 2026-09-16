//! Undeclared secret and PII redaction for bytes crossing the host egress
//! and ingress transforms.
//!
//! One redactor definition serves the substitution endpoint's outbound
//! requests and response bodies and the declared-ingress HTTP transform, so
//! both scrub identically. `StreamingRedactor` applies it across chunk
//! boundaries without releasing a prefix that a later chunk could turn into a
//! match.

use zeroize::Zeroizing;

use crate::supervisor::pii_redactor::{PiiRedactor, REDACTION_MASK};
use crate::supervisor::secrets_scanner::SecretsScanner;
use crate::supervisor::sensitive_detector::{
    LeakGuardCredentialDetector, SensitiveDetector, mask_matches,
};

/// The egress secret/PII redactor. A rewrite, **not** a drop: an *undeclared*
/// secret-shaped or PII run on outbound bytes is masked in place (replaced with
/// [`REDACTION_MASK`]) and the request continues, rather than refusing the whole
/// flow. This is the backstop for the no-secret-on-the-guest invariant when a
/// secret reaches the guest by some path *other* than a declared
/// `mvm.secret(...)` (baked in, hardcoded, fetched) — declared secrets are
/// substituted host-side via the endpoint and never on the guest in the first
/// place. A declared placeholder is not secret-shaped and is not masked here.
pub struct RedactingSubstitution {
    supplemental: LeakGuardCredentialDetector,
    secrets: SecretsScanner,
    pii: PiiRedactor,
}

/// The rule categories that fired during a [`RedactingSubstitution::redact_bytes`]
/// pass — secret-pattern names then PII-rule names. Names only, never the matched
/// bytes (claim-13 discipline), so this is safe to carry into an audit entry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RedactionHits {
    pub secrets: Vec<&'static str>,
    pub pii: Vec<&'static str>,
    /// Count of high-entropy runs that fired (entropy carries no stable rule
    /// name — it's a shape, not a labeled pattern — so it's a count, not a
    /// `Vec<&'static str>`).
    pub entropy: usize,
    /// Count of name spans that fired.
    pub names: usize,
    /// Count of detector invariant failures. Callers refuse the request or
    /// stream when this is non-zero.
    pub detector_failures: usize,
}

impl RedactionHits {
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
            && self.pii.is_empty()
            && self.entropy == 0
            && self.names == 0
            && self.detector_failures == 0
    }

    /// Fold another pass's categories in (used when redacting several fields —
    /// e.g. each header value + the body — of one request).
    pub fn merge(&mut self, other: RedactionHits) {
        self.secrets.extend(other.secrets);
        self.pii.extend(other.pii);
        self.entropy += other.entropy;
        self.names += other.names;
        self.detector_failures += other.detector_failures;
    }
}

impl RedactingSubstitution {
    /// The curated secret-pattern + PII rulesets (`DEFAULT_RULES`).
    pub fn with_default_rules() -> Self {
        Self {
            supplemental: LeakGuardCredentialDetector::new(),
            secrets: SecretsScanner::with_default_rules(),
            pii: PiiRedactor::with_default_rules(),
        }
    }

    /// Mask undeclared secret-shaped + PII runs in `payload`, returning the
    /// rewritten bytes and the categories that fired. Returns `None` when the
    /// payload is clean (the caller forwards it unchanged). Secret-shaped first,
    /// then PII; both mask to [`REDACTION_MASK`].
    ///
    /// This is the destination-independent pass, with no entropy or name
    /// detection. The endpoint and the ingress transform call
    /// [`Self::redact_bytes_for`] with the destination's resolved action.
    pub fn redact_bytes(&self, payload: &[u8]) -> Option<(Vec<u8>, RedactionHits)> {
        let (after_supplemental, mut secrets, detector_failures) =
            self.supplemental_pass(payload, true);
        let (after_secrets, curated_secrets) =
            self.secrets.redact(&after_supplemental, REDACTION_MASK);
        secrets.extend(curated_secrets);
        let (after_pii, pii) = self.pii.redact(&after_secrets);
        let hits = RedactionHits {
            secrets,
            pii,
            detector_failures,
            ..Default::default()
        };
        if hits.is_empty() {
            return None; // clean payload — pass through unchanged.
        }
        Some((after_pii, hits))
    }

    fn supplemental_pass(
        &self,
        payload: &[u8],
        redact: bool,
    ) -> (Vec<u8>, Vec<&'static str>, usize) {
        let matches = match self.supplemental.detect(payload) {
            Ok(matches) => matches,
            Err(error) => {
                tracing::error!(error = %error, "supplemental detector failed closed");
                let output = if redact {
                    REDACTION_MASK.to_vec()
                } else {
                    payload.to_vec()
                };
                return (output, Vec::new(), 1);
            }
        };
        let categories = matches.iter().map(|matched| matched.category).collect();
        if !redact {
            return (payload.to_vec(), categories, 0);
        }
        match mask_matches(payload, &matches, REDACTION_MASK) {
            Ok(output) => (output, categories, 0),
            Err(error) => {
                tracing::error!(error = %error, "supplemental detector rewrite failed closed");
                (REDACTION_MASK.to_vec(), Vec::new(), 1)
            }
        }
    }

    /// Per-destination redaction. Curated secrets always run; entropy and names
    /// run only when the resolved action opts in. Returns `None` when nothing
    /// fired. `secrets`/`pii` come from the existing curated rulesets; entropy
    /// + names from the new detectors.
    pub fn redact_bytes_for(
        &self,
        payload: &[u8],
        action: &mvm_core::policy::RedactionAction,
    ) -> Option<(Vec<u8>, RedactionHits)> {
        use crate::supervisor::entropy_scanner::EntropyScanner;
        use crate::supervisor::name_scanner::NameScanner;
        use crate::supervisor::pii_redactor::PiiRedactor;
        use mvm_core::policy::{EntropyMode, NameMode, SecretAction};

        // Curated secrets: default Block masks (today's behavior); a per-destination
        // Audit downgrade observes a trusted sink without masking.
        let (mut buf, secrets, detector_failures) = match action.secrets {
            SecretAction::Block | SecretAction::Redact => {
                let (supplemented, supplemental_hits, failures) =
                    self.supplemental_pass(payload, true);
                let (curated, curated_hits) = self.secrets.redact(&supplemented, REDACTION_MASK);
                let mut combined = supplemental_hits;
                combined.extend(curated_hits);
                (curated, combined, failures)
            }
            SecretAction::Audit => {
                let (_, mut supplemental_hits, failures) = self.supplemental_pass(payload, false);
                supplemental_hits.extend(self.secrets.scan(payload));
                (payload.to_vec(), supplemental_hits, failures)
            }
        };

        // The name detector's co-occurrence signal needs the positions of other
        // PII. Compute them on the current (pre-PII-mask) buffer, then run the name
        // pass BEFORE masking PII so the offsets line up. Always the curated
        // ruleset — co-occurrence is a detection signal, independent of the
        // per-destination PII masking policy.
        let names_active = !matches!(action.names, NameMode::Off);
        let pii_spans = if names_active {
            self.pii.match_spans(&buf)
        } else {
            Vec::new()
        };

        let mut hits = RedactionHits {
            secrets,
            pii: Vec::new(),
            entropy: 0,
            names: 0,
            detector_failures,
        };

        // Names first, on the pre-PII-mask buffer with real PII spans. Names and
        // structured PII never overlap, so masking names here doesn't disturb the
        // PII re-scan below.
        match action.names {
            NameMode::Off => {}
            NameMode::Audit => {
                let (_, n) = NameScanner::with_defaults().redact(&buf, &pii_spans);
                hits.names += n;
            }
            NameMode::Redact => {
                let (out, n) = NameScanner::with_defaults().redact(&buf, &pii_spans);
                buf = out;
                hits.names += n;
            }
        }

        // Structured PII: a default (empty) action runs the always-on ruleset;
        // an explicit per-destination policy overrides — `disabled` skips it, a
        // category list restricts it. A malformed policy fails safe to always-on.
        let pii_is_default = action.pii.mode.is_none() && action.pii.categories.is_empty();
        hits.pii = if pii_is_default {
            let (out, p) = self.pii.redact(&buf);
            buf = out;
            p
        } else {
            match PiiRedactor::from_policy(&action.pii) {
                Ok(None) => Vec::new(),
                Ok(Some(r)) => {
                    let (out, p) = r.redact(&buf);
                    buf = out;
                    p
                }
                Err(_) => {
                    let (out, p) = self.pii.redact(&buf);
                    buf = out;
                    p
                }
            }
        };

        match &action.entropy {
            EntropyMode::Off => {}
            EntropyMode::Audit {
                min_bits_per_char,
                min_run_len,
            } => {
                // Audit: counted, not masked.
                hits.entropy += EntropyScanner::new(*min_run_len, *min_bits_per_char)
                    .scan(&buf)
                    .len();
            }
            EntropyMode::Redact {
                min_bits_per_char,
                min_run_len,
            } => {
                let (out, n) = EntropyScanner::new(*min_run_len, *min_bits_per_char).redact(&buf);
                buf = out;
                hits.entropy += n;
            }
        }

        if hits.is_empty() {
            None
        } else {
            Some((buf, hits))
        }
    }
}

/// A detector violated the validated-span contract. No matched bytes or
/// dependency error text cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sensitive-data detector failed closed")]
pub(crate) struct SensitiveDetectionError;

/// Raw suffix retained between transform chunks. A 64 KiB window is larger
/// than every configured secret/PII fingerprint; an adversarial pattern that
/// still cannot reach a stable cut by twice that bound fails closed.
pub(crate) const STREAM_TRANSFORM_OVERLAP: usize = 64 * 1024;
const MAX_STREAM_TRANSFORM_PENDING: usize = STREAM_TRANSFORM_OVERLAP * 2;

pub(crate) struct StreamingRedactor {
    pending: Zeroizing<Vec<u8>>,
}

impl StreamingRedactor {
    pub(crate) fn new() -> Self {
        Self {
            pending: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn push(
        &mut self,
        redactor: &RedactingSubstitution,
        action: &mvm_core::policy::RedactionAction,
        chunk: &[u8],
    ) -> Result<(Vec<u8>, RedactionHits), SensitiveDetectionError> {
        self.pending.extend_from_slice(chunk);
        if self.pending.len() <= STREAM_TRANSFORM_OVERLAP {
            return Ok((Vec::new(), RedactionHits::default()));
        }

        let safe_len = self.pending.len() - STREAM_TRANSFORM_OVERLAP;
        let (prefix, prefix_hits) = redact_or_copy(redactor, action, &self.pending[..safe_len])?;
        let (whole, _) = redact_or_copy(redactor, action, &self.pending)?;
        if whole.starts_with(&prefix) {
            let suffix = self.pending.split_off(safe_len);
            *self.pending = suffix;
            return Ok((prefix, prefix_hits));
        }
        if self.pending.len() > MAX_STREAM_TRANSFORM_PENDING {
            return Err(SensitiveDetectionError);
        }
        Ok((Vec::new(), RedactionHits::default()))
    }

    pub(crate) fn finish(
        &mut self,
        redactor: &RedactingSubstitution,
        action: &mvm_core::policy::RedactionAction,
    ) -> Result<(Vec<u8>, RedactionHits), SensitiveDetectionError> {
        let pending = std::mem::take(&mut *self.pending);
        redact_or_copy(redactor, action, &pending)
    }
}

fn redact_or_copy(
    redactor: &RedactingSubstitution,
    action: &mvm_core::policy::RedactionAction,
    bytes: &[u8],
) -> Result<(Vec<u8>, RedactionHits), SensitiveDetectionError> {
    match redactor.redact_bytes_for(bytes, action) {
        Some((_redacted, hits)) if hits.detector_failures > 0 => Err(SensitiveDetectionError),
        Some((redacted, hits)) => Ok((redacted, hits)),
        None => Ok((bytes.to_vec(), RedactionHits::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacting_substitution_masks_secret_and_passes_clean() {
        let r = RedactingSubstitution::with_default_rules();
        // A clean payload passes through (None — no rewrite).
        assert_eq!(r.redact_bytes(b"GET / nothing here"), None);
        // A payload carrying an undeclared secret-shaped token is rewritten with
        // the mask, and the original token is gone.
        let key = "sk-".to_owned() + &"z".repeat(48);
        let body = format!("POST {{\"k\":\"{key}\"}}").into_bytes();
        let (out, _) = r
            .redact_bytes(&body)
            .expect("secret-bearing payload must be rewritten");
        let masked = String::from_utf8_lossy(&out);
        assert!(
            !masked.contains(&key),
            "secret survived redaction: {masked}"
        );
        assert!(masked.contains("XXX"), "no mask present: {masked}");
    }

    #[test]
    fn redacting_substitution_masks_supplemental_credentials_in_binary_payload() {
        let redactor = RedactingSubstitution::with_default_rules();
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "signature1234"
        );
        let azure = format!(
            "DefaultEndpointsProtocol=https;AccountName=storage;AccountKey={};EndpointSuffix=core.windows.net",
            "A".repeat(88)
        );
        let mut payload = vec![0xff, 0xfe];
        payload.extend_from_slice(format!("jwt={jwt}\nazure={azure}").as_bytes());

        let (masked, hits) = redactor
            .redact_bytes(&payload)
            .expect("supplemental credentials must be detected");
        assert!(
            !masked
                .windows(jwt.len())
                .any(|window| window == jwt.as_bytes())
        );
        assert!(
            !masked
                .windows(azure.len())
                .any(|window| window == azure.as_bytes())
        );
        assert!(hits.secrets.contains(&"jwt"), "hits={hits:?}");
        assert!(
            hits.secrets.contains(&"azure_connection_string"),
            "hits={hits:?}"
        );
        assert_eq!(&masked[..2], &[0xff, 0xfe]);
    }

    #[test]
    fn redacting_substitution_masks_the_entire_private_key_block() {
        let redactor = RedactingSubstitution::with_default_rules();
        let payload = b"before -----BEGIN PRIVATE KEY-----\nSUPERSECRETPAYLOAD\n-----END PRIVATE KEY----- after";

        let (masked, hits) = redactor
            .redact_bytes(payload)
            .expect("private key block must be detected");
        let masked = String::from_utf8(masked).expect("fixture is UTF-8");
        assert!(!masked.contains("SUPERSECRETPAYLOAD"), "masked={masked}");
        assert!(masked.contains("before XXX after"), "masked={masked}");
        assert!(hits.secrets.contains(&"pem_private_key"), "hits={hits:?}");
    }

    #[test]
    fn redact_bytes_for_applies_entropy_when_action_opts_in() {
        use mvm_core::policy::{EntropyMode, RedactionAction};
        let r = RedactingSubstitution::with_default_rules();
        let body = b"k=Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9 e";
        // default action: entropy off → no hit
        let off = RedactionAction::default();
        assert!(r.redact_bytes_for(body, &off).is_none());
        // opt in → entropy redacts the run
        let on = RedactionAction {
            entropy: EntropyMode::Redact {
                min_bits_per_char: 4.0,
                min_run_len: 20,
            },
            ..Default::default()
        };
        let (out, hits) = r.redact_bytes_for(body, &on).expect("entropy hit");
        assert_eq!(hits.entropy, 1);
        assert!(!String::from_utf8_lossy(&out).contains("Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9"));
    }

    #[test]
    fn default_action_still_masks_email_and_curated_secrets() {
        // Regression guard: a default (no-profile) action preserves today's
        // always-on behavior — structured PII + curated secrets are masked.
        use mvm_core::policy::RedactionAction;
        let r = RedactingSubstitution::with_default_rules();
        let body = b"contact alice@example.com key AKIAIOSFODNN7EXAMPLE end";
        let (out, hits) = r
            .redact_bytes_for(body, &RedactionAction::default())
            .expect("default masks pii+secrets");
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("alice@example.com"), "email not masked: {s}");
        assert!(
            !s.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret not masked: {s}"
        );
        assert!(hits.pii.contains(&"email"));
        assert!(!hits.secrets.is_empty());
    }

    #[test]
    fn pii_disabled_for_destination_leaves_email() {
        // A trusted sink can disable PII masking; the email survives while a
        // default destination would mask it.
        use mvm_core::policy::{PiiPolicy, RedactionAction};
        let r = RedactingSubstitution::with_default_rules();
        let body = b"contact alice@example.com end";
        let action = RedactionAction {
            pii: PiiPolicy {
                mode: Some("disabled".into()),
                categories: vec![],
            },
            ..Default::default()
        };
        // Nothing else opts in, so the whole pass is a no-op → None.
        assert!(
            r.redact_bytes_for(body, &action).is_none(),
            "pii=disabled should leave the email and mask nothing"
        );
    }

    #[test]
    fn name_co_occurrence_fires_on_the_live_path() {
        // "Zephyr Quibblesworth" is neither labeled nor in the gazetteer, so it
        // only gets masked via the co-occurrence signal — a capitalized pair next
        // to other PII (the SSN). This proves the live path now threads real PII
        // spans into the name detector (it would survive with empty spans).
        use mvm_core::policy::{NameMode, RedactionAction};
        let r = RedactingSubstitution::with_default_rules();
        let body = b"Zephyr Quibblesworth ssn 123-45-6789 end";
        let action = RedactionAction {
            names: NameMode::Redact,
            ..Default::default()
        };
        let (out, hits) = r
            .redact_bytes_for(body, &action)
            .expect("name + ssn should fire");
        let s = String::from_utf8_lossy(&out);
        assert!(
            !s.contains("Zephyr Quibblesworth"),
            "co-occurrence name not masked: {s}"
        );
        assert!(hits.names >= 1, "expected a name hit, got {hits:?}");
        // The SSN is still masked by the PII pass.
        assert!(!s.contains("123-45-6789"), "ssn not masked: {s}");
    }

    #[test]
    fn secrets_audit_counts_without_masking() {
        // A per-destination secrets=audit downgrade observes but does not mask.
        use mvm_core::policy::{RedactionAction, SecretAction};
        let r = RedactingSubstitution::with_default_rules();
        let body = b"key AKIAIOSFODNN7EXAMPLE end";
        let action = RedactionAction {
            secrets: SecretAction::Audit,
            ..Default::default()
        };
        let (out, hits) = r
            .redact_bytes_for(body, &action)
            .expect("audit still reports the hit");
        assert!(
            String::from_utf8_lossy(&out).contains("AKIAIOSFODNN7EXAMPLE"),
            "audit mode must not mask the secret"
        );
        assert!(
            !hits.secrets.is_empty(),
            "audit mode must still count the hit"
        );
    }

    /// `merge` folds two passes' counts together, and the counters are what
    /// the audit record reports. Every arithmetic mutation of the five
    /// folds survived, because nothing merged two non-trivial hit sets.
    #[test]
    fn merging_redaction_hits_sums_every_category() {
        let mut a = RedactionHits {
            secrets: vec!["a"],
            pii: vec!["p1"],
            entropy: 2,
            names: 3,
            detector_failures: 11,
        };
        a.merge(RedactionHits {
            secrets: vec!["b"],
            pii: vec!["p2"],
            entropy: 5,
            names: 7,
            detector_failures: 13,
        });

        assert_eq!(a.secrets, vec!["a", "b"]);
        assert_eq!(a.pii, vec!["p1", "p2"]);
        // Sums, not differences and not products: 2+5 and 3+7 are distinct
        // from 2-5, 2*5, 3-7 and 3*7.
        assert_eq!(a.entropy, 7);
        assert_eq!(a.names, 10);
        assert_eq!(a.detector_failures, 24);

        // Merging an empty set is the identity.
        let before = (
            a.entropy,
            a.names,
            a.detector_failures,
            a.secrets.len(),
            a.pii.len(),
        );
        a.merge(RedactionHits::default());
        assert_eq!(
            (
                a.entropy,
                a.names,
                a.detector_failures,
                a.secrets.len(),
                a.pii.len(),
            ),
            before,
            "folding in an empty set must change nothing"
        );
    }

    /// Audit mode counts without masking, and it is a separate arm from
    /// Redact — the existing entropy test opts into Redact, so the Audit
    /// arm's counter had no coverage and every arithmetic mutation of it
    /// survived. The distinguishing assertion is that the payload comes
    /// back *unmasked* while the count still rises.
    #[test]
    fn audit_mode_counts_entropy_and_names_without_masking() {
        use mvm_core::policy::{EntropyMode, NameMode, RedactionAction};
        let r = RedactingSubstitution::with_default_rules();

        let body = b"k=Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9 e";
        let audit_entropy = RedactionAction {
            entropy: EntropyMode::Audit {
                min_bits_per_char: 4.0,
                min_run_len: 20,
            },
            ..Default::default()
        };
        let (out, hits) = r
            .redact_bytes_for(body, &audit_entropy)
            .expect("an audited entropy run is still a hit");
        assert_eq!(hits.entropy, 1, "the audit arm must count the run");
        assert!(
            String::from_utf8_lossy(&out).contains("Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9"),
            "audit counts but must not mask"
        );

        let named = b"a message from Alice Johnson to Bob Smith";
        let audit_names = RedactionAction {
            names: NameMode::Audit,
            ..Default::default()
        };
        // `expect`, not `if let`: a zeroed counter makes `hits` empty, which
        // makes `redact_bytes_for` return None — so an `if let` skips the
        // assertions entirely and the test passes for the very mutation it
        // is meant to catch.
        let (out, hits) = r
            .redact_bytes_for(named, &audit_names)
            .expect("an audited name span is still a hit");
        assert!(hits.names > 0, "the audit arm must count name spans");
        assert!(
            String::from_utf8_lossy(&out).contains("Alice Johnson"),
            "audit counts but must not mask"
        );
    }

    /// `redact_bytes` reports both categories it fired. Dropping the `pii`
    /// field from the constructed hits leaves it defaulted to empty, so a
    /// payload masked for PII is reported as having matched nothing — the
    /// bytes are still scrubbed, but the audit record loses the reason.
    #[test]
    fn redact_bytes_reports_the_pii_it_fired_on() {
        let r = RedactingSubstitution::with_default_rules();
        let (out, hits) = r
            .redact_bytes(b"contact alice@example.com please")
            .expect("an email is PII and must be redacted");

        assert!(
            !hits.pii.is_empty(),
            "a PII-only payload must report which PII rule fired"
        );
        assert!(
            hits.secrets.is_empty(),
            "no secret pattern is present in this payload"
        );
        assert!(!String::from_utf8_lossy(&out).contains("alice@example.com"));
    }

    #[test]
    fn a_secret_split_across_chunks_is_withheld_and_redacted() {
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let split = 17;
        let mut first = vec![b'x'; STREAM_TRANSFORM_OVERLAP - split];
        first.extend_from_slice(&secret[..split]);

        let redactor = RedactingSubstitution::with_default_rules();
        let action = mvm_core::policy::RedactionAction::default();
        let mut stream = StreamingRedactor::new();
        let (ready, _) = stream.push(&redactor, &action, &first).unwrap();
        assert!(ready.is_empty(), "the possible prefix must stay withheld");
        let (ready, _) = stream.push(&redactor, &action, &secret[split..]).unwrap();
        let (tail, hits) = stream.finish(&redactor, &action).unwrap();
        let output = [ready, tail].concat();
        assert!(!output.windows(secret.len()).any(|window| window == secret));
        assert!(!hits.secrets.is_empty(), "the split token must be detected");
    }

    #[test]
    fn clean_streams_release_every_byte_in_order_with_bounded_carry() {
        let redactor = RedactingSubstitution::with_default_rules();
        let action = mvm_core::policy::RedactionAction::default();
        let mut stream = StreamingRedactor::new();
        let input = vec![b'x'; STREAM_TRANSFORM_OVERLAP + 123];
        let (ready, _) = stream.push(&redactor, &action, &input).unwrap();
        assert_eq!(ready.len(), 123);
        assert!(stream.pending.len() <= STREAM_TRANSFORM_OVERLAP);
        let (tail, _) = stream.finish(&redactor, &action).unwrap();
        assert_eq!([ready, tail].concat(), input);
    }

    #[test]
    fn a_long_clean_stream_never_grows_the_overlap_buffer() {
        let redactor = RedactingSubstitution::with_default_rules();
        let action = mvm_core::policy::RedactionAction::default();
        let mut stream = StreamingRedactor::new();
        let chunk = vec![b'x'; 8 * 1024];
        let mut emitted = 0usize;

        for _ in 0..1024 {
            let (ready, hits) = stream.push(&redactor, &action, &chunk).unwrap();
            assert!(hits.is_empty());
            emitted = emitted.saturating_add(ready.len());
            assert!(stream.pending.len() <= STREAM_TRANSFORM_OVERLAP);
        }
        let (tail, hits) = stream.finish(&redactor, &action).unwrap();
        assert!(hits.is_empty());
        emitted = emitted.saturating_add(tail.len());
        assert_eq!(emitted, chunk.len() * 1024);
    }
}
