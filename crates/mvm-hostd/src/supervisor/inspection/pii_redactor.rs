//! The PII detector, re-exported where the supervisor's redaction code
//! reaches it.
//!
//! The detector itself lives in [`mvm_core::pii`]: rules, validators, and the
//! `RegexSet` machinery have no dependency on this crate, and the console
//! reader in `mvm-core` needs them, so they sit below the supervisor.

pub use mvm_core::pii::{
    DEFAULT_RULES, Mode, PII_CATEGORY_NAMES, PiiMatch, PiiPolicyError, PiiRedactor, PiiRule,
    PiiValidator, REDACTION_MASK,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn default_hits(body: &[u8]) -> Vec<&'static str> {
        PiiRedactor::with_default_rules().scan(body)
    }

    #[test]
    fn empty_and_benign_bodies_have_no_hits() {
        assert!(default_hits(b"").is_empty());
        assert!(default_hits(br#"{"messages":[{"role":"user","content":"hello"}]}"#).is_empty());
    }

    #[test]
    fn each_default_category_fires_on_its_shape() {
        let cases: [(&str, &[u8]); 4] = [
            ("email", b"Reach out to alice@example.com for details."),
            ("us_ssn", b"customer ssn: 123-45-6789"),
            ("credit_card", b"card=4111111111111111"),
            ("e164_phone", b"call me at +14155552671"),
        ];
        for (name, body) in cases {
            let hits = default_hits(body);
            assert!(hits.contains(&name), "{name} did not fire; hits={hits:?}");
        }
    }

    #[test]
    fn credit_card_luhn_invalid_does_not_fire() {
        // 16-digit run that fails Luhn — must NOT be flagged.
        assert!(default_hits(b"order_number=4111111111111112").is_empty());
    }

    #[test]
    fn block_mode_detects_the_same_shapes() {
        let r = PiiRedactor::new(DEFAULT_RULES, Mode::Block).expect("compile");
        assert_eq!(r.mode(), Mode::Block);
        assert_eq!(r.scan(b"Contact alice@example.com"), vec!["email"]);
    }

    #[test]
    fn multiple_pii_types_all_listed() {
        let hits = default_hits(b"alice@example.com ssn 123-45-6789 phone +14155552671");
        for name in ["email", "us_ssn", "e164_phone"] {
            assert!(hits.contains(&name), "{name} missing; hits={hits:?}");
        }
    }

    #[test]
    fn binary_body_does_not_panic() {
        let mut body: Vec<u8> = (0u8..=255).collect();
        body.extend_from_slice(b" alice@example.com");
        assert!(default_hits(&body).contains(&"email"));
    }

    #[test]
    fn scan_api_filters_luhn_invalid() {
        // A body with a non-Luhn 16-digit run and a real email returns
        // only `email`, not `credit_card`.
        assert_eq!(
            default_hits(b"x=alice@example.com y=4111111111111112"),
            vec!["email"]
        );
    }

    #[test]
    fn ssn_invalid_area_does_not_match() {
        // Areas 666 and 9NN are SSA-reserved — not real SSNs.
        assert!(default_hits(b"666-12-3456").is_empty());
        assert!(default_hits(b"900-12-3456").is_empty());
    }

    #[test]
    fn from_policy_preserves_redact_mode() {
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("redact".to_string()),
            categories: vec![],
        };
        let red = PiiRedactor::from_policy(&pii)
            .expect("ok")
            .expect("not disabled");
        assert_eq!(red.mode(), Mode::Redact);
    }

    #[test]
    fn from_policy_refuses_unknown_mode() {
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("paranoid".to_string()),
            categories: vec![],
        };
        match PiiRedactor::from_policy(&pii)
            .map(|_| ())
            .expect_err("typo")
        {
            PiiPolicyError::UnknownMode { value, valid } => {
                assert_eq!(value, "paranoid");
                assert!(valid.contains(&"detect"));
                assert!(valid.contains(&"disabled"));
            }
            other => panic!("expected UnknownMode, got {other:?}"),
        }
    }

    #[test]
    fn from_policy_refuses_unknown_category() {
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("detect".to_string()),
            categories: vec!["email".to_string(), "license_plate".to_string()],
        };
        match PiiRedactor::from_policy(&pii)
            .map(|_| ())
            .expect_err("typo")
        {
            PiiPolicyError::UnknownCategory { index, name, valid } => {
                assert_eq!(index, 1);
                assert_eq!(name, "license_plate");
                assert!(valid.contains(&"email"));
                assert!(valid.contains(&"us_ssn"));
            }
            other => panic!("expected UnknownCategory, got {other:?}"),
        }
    }
}
