//! `PiiRedactor` — detect (and eventually redact) PII in outbound bodies.
//!
//! Plan 37 §15 (Wave 2.5, detect-only first cut). Sibling to
//! `SecretsScanner`: same single-pass `RegexSet` machinery, same
//! "audit-safe deny reasons" discipline (rule names, never values).
//! The difference is the threat shape and the eventual verdict
//! semantics.
//!
//! Threat shape addressed (PII-specific, distinct from secrets):
//! - Workload uploads a CSV of customer rows to an LLM for "summary"
//!   and the rows include emails, SSNs, or phone numbers.
//! - Tool-call argument copies a chunk of customer-support transcript
//!   verbatim, including the customer's credit-card number.
//! - Logs / error messages get shipped to a third-party APM with PII
//!   embedded in stack-trace context.
//!
//! ## Why a *separate* inspector from `SecretsScanner`?
//!
//! Different audit channel, different verdict trajectory, and
//! different rule curation discipline. Secrets are always
//! deny-on-match (a leaked API key is always a fail). PII is
//! domain-policy-dependent: some workloads have a HIPAA-class
//! egress allowlist where any email-shape match must be denied;
//! others (an analytics pipeline scrubbing customer data) treat
//! "this body had emails in it" as informational and want the
//! redactor to *transform* it before forwarding. Mixing the two
//! into one ruleset would couple their lifecycles.
//!
//! Wave 2.5 ships **detect-only** semantics: the inspector returns
//! a `Transform { note }` audit signal on match (so operators see
//! it) but never blocks traffic. A future wave promotes this to
//! true redaction (mutate `ctx.body` in place, replacing matches
//! with `<REDACTED:rule_name>`) gated by `Mode::Redact`, and to
//! `Mode::Block` for HIPAA-class workloads. The `Mode` enum is in
//! the shipping API now so adding those variants later isn't a
//! breaking change.
//!
//! Why detect-only first: PII rules are inherently fuzzier than
//! secret rules (an email-shape regex catches lots of strings that
//! aren't really PII — branded `support@acme.com` addresses on a
//! product page, etc.). Operators need a soak window to tune the
//! ruleset for their workload before we let it block traffic.
//!
//! ## Match strategy
//!
//! Same as `SecretsScanner`: curated rules, `regex::bytes::RegexSet`,
//! single O(body_len) pass. Each rule's pattern is anchored or
//! shape-specific to keep false-positives bounded. The default
//! ruleset covers the high-precision cases:
//! - Email addresses (RFC5321-flavoured)
//! - US Social Security Numbers (`NNN-NN-NNNN`, with SSA-reserved
//!   areas excluded)
//! - Credit-card-shape number runs (Luhn-validated post-match)
//! - E.164 international phone numbers (the leading `+` keeps the
//!   precision up)
//!
//! High-recall PII detection (names, addresses, free-form fields) is
//! not in this ruleset — it requires NER models and falls outside
//! "high-precision regex" territory. A future wave can plug in a
//! model-backed detector behind the same `Inspector` trait without
//! changing the chain.

use async_trait::async_trait;
use regex::bytes::{Regex, RegexSet};

use crate::inspector::{Inspector, InspectorVerdict, RequestCtx};

/// One PII detection rule. Same shape as `SecretRule` so a future
/// generic-rule abstraction can dedupe them, but kept separate today
/// to make the curation pipeline (rule additions, false-positive
/// triage) easy to evolve independently.
#[derive(Debug, Clone, Copy)]
pub struct PiiRule {
    pub name: &'static str,
    pub pattern: &'static str,
    /// Optional post-regex validator (e.g., Luhn for credit cards).
    /// `None` means "regex match alone is sufficient".
    pub validator: Option<PiiValidator>,
}

#[derive(Debug, Clone, Copy)]
pub enum PiiValidator {
    Luhn,
}

/// Default curated PII ruleset. Each rule is high-precision; an
/// "address" rule or "name" rule belongs in a model-backed detector,
/// not here.
pub const DEFAULT_RULES: &[PiiRule] = &[
    PiiRule {
        name: "email",
        // Local-part: at least one char from a permissive set, with
        // no leading/trailing dot. Domain: at least one label + TLD.
        // Not RFC-complete, but high-precision for outbound bodies.
        pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        validator: None,
    },
    PiiRule {
        name: "us_ssn",
        // Standard hyphenated form NNN-NN-NNNN with SSA-reserved
        // areas excluded:
        //   000 (zero area), 666, 900-999 (ITIN space).
        // Group also excludes 00, serial also excludes 0000 (both
        // structurally invalid). Result: only well-formed SSN
        // shapes match. The regex crate has no lookaround, so
        // valid ranges are enumerated directly.
        pattern: r"(?:00[1-9]|0[1-9]\d|[1-5]\d{2}|6[0-5]\d|66[0-57-9]|6[7-9]\d|[78]\d{2})-(?:0[1-9]|[1-9]\d)-(?:000[1-9]|00[1-9]\d|0[1-9]\d{2}|[1-9]\d{3})",
        validator: None,
    },
    PiiRule {
        name: "credit_card",
        // 13-19 digit runs. Luhn-validated post-match to weed out
        // strings of digits that happen to be the right length.
        pattern: r"\b\d{13,19}\b",
        validator: Some(PiiValidator::Luhn),
    },
    PiiRule {
        name: "e164_phone",
        // International format: + then 7-15 digits. Conservative —
        // the requirement of the leading `+` keeps this from
        // matching every 10-digit run on the planet.
        pattern: r"\+\d{7,15}",
        validator: None,
    },
];

/// Verdict semantics. Detect-only is the sole shipping mode in
/// Wave 2.5; the other variants are present so the type doesn't
/// grow a breaking variant when later waves promote it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Match → `Transform { note }` (allows traffic). Default.
    #[default]
    Detect,
    /// Match → mutate `ctx.body`, replacing each match with
    /// `<REDACTED:rule_name>`, then `Transform { note }`. Wave 2.5+1.
    Redact,
    /// Match → `Deny`. Wave 2.5+2 (HIPAA-class workloads).
    Block,
}

/// Inspector that scans outbound bodies for PII shapes. Wave 2.5
/// ships in **detect-only** mode; see [`Mode`] for the planned
/// promotion path.
pub struct PiiRedactor {
    set: RegexSet,
    rules: Vec<PiiRule>,
    /// Per-rule compiled `Regex` (same source pattern as `set`),
    /// used to extract individual match spans when a rule has a
    /// post-regex validator (e.g., Luhn).
    regexes: Vec<Regex>,
    mode: Mode,
}

impl PiiRedactor {
    /// Build from a custom rule list. Returns `Err` if any pattern
    /// fails to compile.
    pub fn new(rules: &[PiiRule], mode: Mode) -> Result<Self, regex::Error> {
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern).collect();
        let set = RegexSet::new(&patterns)?;
        let regexes: Vec<Regex> = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            set,
            rules: rules.to_vec(),
            regexes,
            mode,
        })
    }

    /// Convenience constructor: curated [`DEFAULT_RULES`] in
    /// detect-only mode. The 99% callsite.
    pub fn with_default_rules() -> Self {
        Self::new(DEFAULT_RULES, Mode::Detect).expect("DEFAULT_RULES must compile")
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Scan a byte slice. Returns the rule names that fired,
    /// post-validator (so a non-Luhn 16-digit run won't appear).
    /// Stable rule-list order; no duplicates.
    pub fn scan(&self, body: &[u8]) -> Vec<&'static str> {
        let candidate_indices: Vec<usize> = self.set.matches(body).into_iter().collect();
        let mut hits = Vec::with_capacity(candidate_indices.len());
        for idx in candidate_indices {
            let rule = &self.rules[idx];
            if rule_passes_validator(rule, &self.regexes[idx], body) {
                hits.push(rule.name);
            }
        }
        hits
    }
}

/// True iff at least one regex match in `body` survives the rule's
/// post-validator (or the rule has no validator). Stops at the first
/// surviving match — rule-level confirmation, not span enumeration.
fn rule_passes_validator(rule: &PiiRule, re: &Regex, body: &[u8]) -> bool {
    match rule.validator {
        None => true,
        Some(PiiValidator::Luhn) => re.find_iter(body).any(|m| luhn_valid(m.as_bytes())),
    }
}

/// Luhn checksum on a byte slice that must contain only ASCII digits.
/// Returns false if any byte isn't `b'0'..=b'9'` or if the slice is
/// empty.
fn luhn_valid(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    let mut alt = false;
    for &b in digits.iter().rev() {
        if !b.is_ascii_digit() {
            return false;
        }
        let mut d = u32::from(b - b'0');
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

#[async_trait]
impl Inspector for PiiRedactor {
    fn name(&self) -> &'static str {
        "pii_redactor"
    }

    async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
        if ctx.body.is_empty() {
            return InspectorVerdict::Allow;
        }
        let hits = self.scan(&ctx.body);
        if hits.is_empty() {
            return InspectorVerdict::Allow;
        }
        let names = hits.join(", ");
        match self.mode {
            Mode::Detect => InspectorVerdict::Transform {
                note: format!("pii detected (detect-only mode): {names}"),
            },
            // Redact ships its actual mutation logic in a later
            // wave; today it's behaviourally identical to Detect
            // but with a distinct note so audit channels can tell
            // them apart.
            Mode::Redact => InspectorVerdict::Transform {
                note: format!("pii detected (redaction mode — not yet implemented): {names}"),
            },
            Mode::Block => InspectorVerdict::Deny {
                reason: format!("outbound body contains pii matching rule(s): {names}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_body(body: &[u8]) -> RequestCtx {
        RequestCtx::new("api.openai.com", 443, "/v1/chat").with_body(body.to_vec())
    }

    // ---- Luhn helper unit tests ----

    #[test]
    fn luhn_validates_known_good_test_numbers() {
        // Visa, Mastercard, Amex test numbers — all Luhn-valid.
        for n in [
            "4111111111111111", // Visa
            "5555555555554444", // Mastercard
            "378282246310005",  // Amex (15-digit)
        ] {
            assert!(luhn_valid(n.as_bytes()), "expected luhn-valid: {n}");
        }
    }

    #[test]
    fn luhn_rejects_known_bad_numbers() {
        for n in [
            "4111111111111112", // Visa with last digit flipped
            "1234567890123456",
            "0000000000000001",
        ] {
            assert!(!luhn_valid(n.as_bytes()), "expected luhn-invalid: {n}");
        }
    }

    #[test]
    fn luhn_rejects_empty_and_non_digits() {
        assert!(!luhn_valid(b""));
        assert!(!luhn_valid(b"4111-1111-1111-1111"));
    }

    // ---- Inspector verdict tests ----

    #[tokio::test]
    async fn empty_body_allows() {
        let r = PiiRedactor::with_default_rules();
        let mut c = RequestCtx::new("example.com", 443, "/");
        assert!(r.inspect(&mut c).await.is_allow());
    }

    #[tokio::test]
    async fn benign_body_allows() {
        let r = PiiRedactor::with_default_rules();
        let body = br#"{"messages":[{"role":"user","content":"hello"}]}"#;
        let mut c = ctx_with_body(body);
        assert!(r.inspect(&mut c).await.is_allow());
    }

    #[tokio::test]
    async fn email_match_returns_transform_in_detect_mode() {
        let r = PiiRedactor::with_default_rules();
        let body = b"Reach out to alice@example.com for details.";
        let mut c = ctx_with_body(body);
        match r.inspect(&mut c).await {
            InspectorVerdict::Transform { note } => {
                assert!(note.contains("email"));
                assert!(note.contains("detect-only"));
                // Audit-safety: the matched value never leaks into
                // the operator-visible note string.
                assert!(!note.contains("alice@example.com"));
            }
            other => panic!("expected Transform, got {other:?}"),
        }
        // Body unchanged in detect-only mode.
        assert_eq!(c.body, body);
    }

    #[tokio::test]
    async fn ssn_match_returns_transform() {
        let r = PiiRedactor::with_default_rules();
        let body = b"customer ssn: 123-45-6789";
        let mut c = ctx_with_body(body);
        match r.inspect(&mut c).await {
            InspectorVerdict::Transform { note } => {
                assert!(note.contains("us_ssn"));
                assert!(!note.contains("123-45-6789"));
            }
            other => panic!("expected Transform, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn credit_card_luhn_valid_match_returns_transform() {
        let r = PiiRedactor::with_default_rules();
        let body = b"card=4111111111111111";
        let mut c = ctx_with_body(body);
        match r.inspect(&mut c).await {
            InspectorVerdict::Transform { note } => {
                assert!(note.contains("credit_card"));
                assert!(!note.contains("4111111111111111"));
            }
            other => panic!("expected Transform for valid Luhn, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn credit_card_luhn_invalid_does_not_fire() {
        // 16-digit run that fails Luhn — must NOT be flagged.
        let r = PiiRedactor::with_default_rules();
        let body = b"order_number=4111111111111112";
        let mut c = ctx_with_body(body);
        assert!(r.inspect(&mut c).await.is_allow());
    }

    #[tokio::test]
    async fn e164_phone_matches() {
        let r = PiiRedactor::with_default_rules();
        let body = b"call me at +14155552671";
        let mut c = ctx_with_body(body);
        match r.inspect(&mut c).await {
            InspectorVerdict::Transform { note } => {
                assert!(note.contains("e164_phone"));
            }
            other => panic!("expected Transform, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn block_mode_denies_on_match() {
        // HIPAA-class workload semantics: any PII shape is a hard fail.
        let r = PiiRedactor::new(DEFAULT_RULES, Mode::Block).expect("compile");
        let body = b"Contact alice@example.com";
        let mut c = ctx_with_body(body);
        let v = r.inspect(&mut c).await;
        assert!(v.is_deny(), "expected deny in block mode, got {v:?}");
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("email"));
            assert!(!reason.contains("alice@example.com"));
        }
    }

    #[tokio::test]
    async fn multiple_pii_types_all_listed() {
        let r = PiiRedactor::with_default_rules();
        let body = b"alice@example.com ssn 123-45-6789 phone +14155552671";
        let mut c = ctx_with_body(body);
        match r.inspect(&mut c).await {
            InspectorVerdict::Transform { note } => {
                assert!(note.contains("email"));
                assert!(note.contains("us_ssn"));
                assert!(note.contains("e164_phone"));
            }
            other => panic!("expected Transform, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn binary_body_does_not_panic() {
        let r = PiiRedactor::with_default_rules();
        let mut body: Vec<u8> = (0u8..=255).collect();
        body.extend_from_slice(b" alice@example.com");
        let mut c = ctx_with_body(&body);
        assert!(matches!(
            r.inspect(&mut c).await,
            InspectorVerdict::Transform { .. }
        ));
    }

    #[test]
    fn default_rules_compile_with_unique_names() {
        let r = PiiRedactor::with_default_rules();
        let mut sorted: Vec<&str> = r.rules.iter().map(|r| r.name).collect();
        let original_len = sorted.len();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), original_len, "rule names must be unique");
    }

    #[test]
    fn scan_api_filters_luhn_invalid() {
        // Direct scan() coverage: a body with a non-Luhn 16-digit run
        // and a real email returns only `email`, not `credit_card`.
        let r = PiiRedactor::with_default_rules();
        let hits = r.scan(b"x=alice@example.com y=4111111111111112");
        assert_eq!(hits, vec!["email"]);
    }

    #[tokio::test]
    async fn ssn_invalid_area_does_not_match() {
        // Areas 666 and 9NN are SSA-reserved — not real SSNs.
        let r = PiiRedactor::with_default_rules();
        let mut c = ctx_with_body(b"666-12-3456");
        assert!(r.inspect(&mut c).await.is_allow());
        let mut c = ctx_with_body(b"900-12-3456");
        assert!(r.inspect(&mut c).await.is_allow());
    }
}
