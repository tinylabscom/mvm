//! `PiiRedactor` as an egress [`Inspector`].
//!
//! The detector itself lives in [`mvm_core::pii`]: rules, validators, and the
//! `RegexSet` machinery have no dependency on this crate, and the console
//! reader in `mvm-core` needs them, so they sit below the inspector rather
//! than inside it. What stays here is the part that is genuinely about
//! outbound-request inspection — the verdict mapping.

use async_trait::async_trait;

pub use mvm_core::pii::{
    DEFAULT_RULES, Mode, PII_CATEGORY_NAMES, PiiMatch, PiiPolicyError, PiiRedactor, PiiRule,
    PiiValidator, REDACTION_MASK,
};

use crate::supervisor::inspector::{Inspector, InspectorVerdict, RequestCtx};

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
        match self.mode() {
            Mode::Detect => InspectorVerdict::Transform {
                note: format!("pii detected (detect-only mode): {names}"),
            },
            // Redact's actual mutation logic ships later; today it's
            // behaviourally identical to Detect but with a distinct
            // note so audit channels can tell them apart.
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
