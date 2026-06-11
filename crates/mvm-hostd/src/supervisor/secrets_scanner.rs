//! `SecretsScanner` — block outbound requests carrying secrets.
//!
//! Second-line defence. The destination allowlist
//! (`DestinationPolicy`) refuses traffic to unauthorised hosts; this
//! inspector refuses traffic to *authorised* hosts when the body
//! looks like it's smuggling out a credential.
//!
//! Threat shape addressed:
//! - LLM agent reads `~/.aws/credentials` (or a `.env` file the
//!   workload mounted) and includes it verbatim in a tool-call
//!   request to `api.openai.com`. The destination is on the
//!   allowlist, so DestinationPolicy passes — but the body should
//!   not.
//! - Sloppy shell-out logs that interpolate secrets into a request.
//! - Prompt-injected exfiltration where the model is tricked into
//!   copying environment variables or session tokens.
//!
//! Match strategy: a small, curated set of high-precision patterns,
//! compiled into a single `regex::bytes::RegexSet`. Bytes (not str)
//! because bodies can be binary (multipart, protobuf, gzip-streaming
//! though we'll learn we can't usefully scan compressed bodies and
//! defer that to a later wave). On match, deny with a reason that
//! names the **rule** that fired but **never** echoes the matched
//! value — audit logs land in operator dashboards and we can't leak
//! the secret we just blocked.
//!
//! Design choices:
//! - Curated rules, not a kitchen-sink list. Each rule must be
//!   high-precision (low false-positive rate) so we don't train
//!   operators to ignore us. Generic "looks like base64" is too
//!   noisy; AWS access key IDs (`AKIA[0-9A-Z]{16}`) are not.
//! - `RegexSet` runs all patterns in a single pass. O(body_len)
//!   instead of O(n_rules × body_len).
//! - Patterns are compiled once at construction and amortised across
//!   every inspect() call.
//! - No body-length cap here — that belongs in the proxy layer,
//!   which will refuse oversized requests outright. This inspector
//!   trusts the proxy to hand it bounded bytes.

use async_trait::async_trait;
use regex::bytes::{Regex, RegexSet};

use crate::supervisor::inspector::{Inspector, InspectorVerdict, RequestCtx};

/// One curated detection rule. The `name` lands verbatim in the
/// deny reason; `pattern` is the regex compiled into the `RegexSet`.
#[derive(Debug, Clone, Copy)]
pub struct SecretRule {
    pub name: &'static str,
    pub pattern: &'static str,
}

/// Default curated ruleset. Each rule's pattern is anchored to a
/// distinctive prefix to keep false-positives low. Add/remove as the
/// threat model evolves; the order doesn't matter for matching but
/// is preserved for stable rule names in audit output.
///
/// Sources cross-checked against gitleaks/trufflehog defaults; only
/// patterns with vendor-published prefixes are included (avoiding
/// generic "long base64-like string" rules that drown operators in
/// false-positives).
pub const DEFAULT_RULES: &[SecretRule] = &[
    SecretRule {
        name: "aws_access_key_id",
        pattern: r"AKIA[0-9A-Z]{16}",
    },
    SecretRule {
        name: "github_personal_access_token",
        pattern: r"ghp_[A-Za-z0-9]{36}",
    },
    SecretRule {
        name: "github_oauth_token",
        pattern: r"gho_[A-Za-z0-9]{36}",
    },
    SecretRule {
        name: "github_server_to_server_token",
        pattern: r"ghs_[A-Za-z0-9]{36}",
    },
    SecretRule {
        name: "github_user_to_server_token",
        pattern: r"ghu_[A-Za-z0-9]{36}",
    },
    SecretRule {
        name: "github_refresh_token",
        pattern: r"ghr_[A-Za-z0-9]{36}",
    },
    SecretRule {
        name: "openai_api_key",
        pattern: r"sk-[A-Za-z0-9]{48}",
    },
    SecretRule {
        name: "openai_project_api_key",
        pattern: r"sk-proj-[A-Za-z0-9_-]{40,}",
    },
    SecretRule {
        name: "anthropic_api_key",
        pattern: r"sk-ant-[A-Za-z0-9_-]{32,}",
    },
    SecretRule {
        name: "slack_token",
        pattern: r"xox[abprs]-[A-Za-z0-9-]{10,48}",
    },
    SecretRule {
        name: "stripe_live_secret_key",
        pattern: r"sk_live_[A-Za-z0-9]{24,}",
    },
    SecretRule {
        name: "google_api_key",
        pattern: r"AIza[0-9A-Za-z_-]{35}",
    },
    // PEM private-key blocks — covers RSA, EC, OpenSSH, plain.
    SecretRule {
        name: "pem_private_key",
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    },
];

/// Inspector that scans outbound bodies for known secret patterns.
/// Construct with [`SecretsScanner::with_default_rules`] for the
/// curated ruleset, or [`SecretsScanner::new`] to bring your own
/// (e.g., add a workload-specific custom-token shape).
pub struct SecretsScanner {
    set: RegexSet,
    rule_names: Vec<&'static str>,
    /// Per-rule compiled `Regex` (same source pattern as `set`) — used by
    /// [`Self::redact`] to extract match spans for in-place masking.
    regexes: Vec<Regex>,
}

impl SecretsScanner {
    /// Build a scanner from a custom rule list. Returns `Err` if any
    /// pattern fails to compile (a programming error — patterns are
    /// `&'static str` so this should fail at startup, never at
    /// runtime).
    pub fn new(rules: &[SecretRule]) -> Result<Self, regex::Error> {
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern).collect();
        let set = RegexSet::new(&patterns)?;
        let rule_names = rules.iter().map(|r| r.name).collect();
        let regexes = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            set,
            rule_names,
            regexes,
        })
    }

    /// Convenience constructor with the curated [`DEFAULT_RULES`]
    /// ruleset. Panics only on a programming error in the default
    /// patterns (the test suite covers compilation).
    pub fn with_default_rules() -> Self {
        Self::new(DEFAULT_RULES).expect("DEFAULT_RULES must compile")
    }

    /// Scan a byte slice. Returns the names of every rule that
    /// matched, in stable rule-list order. Empty Vec means no match.
    pub fn scan(&self, body: &[u8]) -> Vec<&'static str> {
        self.set
            .matches(body)
            .into_iter()
            .map(|idx| self.rule_names[idx])
            .collect()
    }

    /// Replace every secret-pattern match in `body` with
    /// `mask`, returning the redacted bytes + the rule names that fired
    /// (stable order). Mask-and-continue: an undeclared secret-shaped
    /// blob on egress is scrubbed in place rather than dropping the
    /// request. `(body.to_vec(), [])` unchanged when nothing matches.
    pub fn redact(&self, body: &[u8], mask: &[u8]) -> (Vec<u8>, Vec<&'static str>) {
        let candidate_indices: Vec<usize> = self.set.matches(body).into_iter().collect();
        if candidate_indices.is_empty() {
            return (body.to_vec(), Vec::new());
        }
        let mut out = body.to_vec();
        let mut fired: Vec<&'static str> = Vec::with_capacity(candidate_indices.len());
        for idx in candidate_indices {
            // Every match of a secret rule is masked (no validators here).
            out = self.regexes[idx].replace_all(&out, mask).into_owned();
            fired.push(self.rule_names[idx]);
        }
        (out, fired)
    }
}

#[async_trait]
impl Inspector for SecretsScanner {
    fn name(&self) -> &'static str {
        "secrets_scanner"
    }

    async fn inspect(&self, ctx: &mut RequestCtx) -> InspectorVerdict {
        // Empty body → no work, no risk. Common case for GET/DELETE.
        if ctx.body.is_empty() {
            return InspectorVerdict::Allow;
        }
        let hits = self.scan(&ctx.body);
        if hits.is_empty() {
            InspectorVerdict::Allow
        } else {
            // Stable, deduplicated rule list in the deny reason.
            // Never include the matched bytes — operator dashboards
            // and audit logs are downstream of this string.
            let names = hits.join(", ");
            InspectorVerdict::Deny {
                reason: format!("outbound body contains secrets matching rule(s): {names}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_body(body: &[u8]) -> RequestCtx {
        RequestCtx::new("api.openai.com", 443, "/v1/chat").with_body(body.to_vec())
    }

    #[tokio::test]
    async fn empty_body_allows() {
        let scanner = SecretsScanner::with_default_rules();
        let mut c = RequestCtx::new("example.com", 443, "/");
        assert!(scanner.inspect(&mut c).await.is_allow());
    }

    #[test]
    fn redact_masks_secret_match_and_passes_clean_body() {
        let s = SecretsScanner::with_default_rules();
        let key = "sk-".to_owned() + &"a".repeat(48); // openai_api_key shape
        let body = format!("auth Bearer {key} trailing").into_bytes();
        let (out, fired) = s.redact(&body, b"XXX");
        let masked = String::from_utf8_lossy(&out);
        assert!(!masked.contains(&key), "secret not masked: {masked}");
        assert!(
            masked.contains("XXX") && masked.contains("trailing"),
            "got {masked}"
        );
        assert!(fired.contains(&"openai_api_key"), "fired={fired:?}");

        let (clean, none) = s.redact(b"no secrets here", b"XXX");
        assert_eq!(clean, b"no secrets here");
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn benign_body_allows() {
        let scanner = SecretsScanner::with_default_rules();
        let body = br#"{"messages":[{"role":"user","content":"hello world"}]}"#;
        let mut c = ctx_with_body(body);
        assert!(scanner.inspect(&mut c).await.is_allow());
    }

    #[tokio::test]
    async fn aws_access_key_denies() {
        let scanner = SecretsScanner::with_default_rules();
        let body = br#"{"key":"AKIAIOSFODNN7EXAMPLE","note":"test"}"#;
        let mut c = ctx_with_body(body);
        match scanner.inspect(&mut c).await {
            InspectorVerdict::Deny { reason } => {
                assert!(reason.contains("aws_access_key_id"));
                // Crucial: the matched value must NOT leak into the
                // reason string (audit logs are operator-visible).
                assert!(!reason.contains("AKIAIOSFODNN7EXAMPLE"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn github_pat_denies() {
        let scanner = SecretsScanner::with_default_rules();
        let body = format!("Authorization: token ghp_{}", "a".repeat(36));
        let mut c = ctx_with_body(body.as_bytes());
        let v = scanner.inspect(&mut c).await;
        assert!(v.is_deny(), "expected deny, got {v:?}");
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("github_personal_access_token"));
        }
    }

    #[tokio::test]
    async fn anthropic_key_denies() {
        let scanner = SecretsScanner::with_default_rules();
        let body = format!("X-Api-Key: sk-ant-{}", "x".repeat(64));
        let mut c = ctx_with_body(body.as_bytes());
        let v = scanner.inspect(&mut c).await;
        assert!(v.is_deny(), "expected deny, got {v:?}");
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("anthropic_api_key"));
        }
    }

    #[tokio::test]
    async fn pem_private_key_denies() {
        let scanner = SecretsScanner::with_default_rules();
        let body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n";
        let mut c = ctx_with_body(body);
        let v = scanner.inspect(&mut c).await;
        assert!(v.is_deny(), "expected deny, got {v:?}");
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("pem_private_key"));
        }
    }

    #[tokio::test]
    async fn multiple_secrets_all_listed() {
        let scanner = SecretsScanner::with_default_rules();
        let body = format!("aws=AKIAIOSFODNN7EXAMPLE github=ghp_{}", "z".repeat(36));
        let mut c = ctx_with_body(body.as_bytes());
        match scanner.inspect(&mut c).await {
            InspectorVerdict::Deny { reason } => {
                assert!(reason.contains("aws_access_key_id"));
                assert!(reason.contains("github_personal_access_token"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn binary_body_does_not_panic() {
        // Bodies can be binary (protobuf, gzip, image upload). The
        // scanner must accept arbitrary bytes without choking on
        // non-UTF-8 input.
        let scanner = SecretsScanner::with_default_rules();
        let mut body: Vec<u8> = (0u8..=255).collect();
        body.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        let mut c = ctx_with_body(&body);
        let v = scanner.inspect(&mut c).await;
        assert!(v.is_deny());
    }

    #[tokio::test]
    async fn short_aws_like_string_does_not_match() {
        // High-precision claim: random base64-ish strings shouldn't
        // trigger. AWS rule requires `AKIA` + exactly 16 [0-9A-Z].
        let scanner = SecretsScanner::with_default_rules();
        // 15 chars after AKIA — too short to match.
        let body = b"AKIASHORTSTRING1";
        let mut c = ctx_with_body(body);
        assert!(scanner.inspect(&mut c).await.is_allow());
    }

    #[test]
    fn default_rules_compile_and_have_unique_names() {
        let scanner = SecretsScanner::with_default_rules();
        let mut sorted: Vec<&str> = scanner.rule_names.clone();
        sorted.sort();
        let original_len = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            original_len,
            "DEFAULT_RULES must have unique names"
        );
        assert_eq!(scanner.rule_names.len(), DEFAULT_RULES.len());
    }

    #[test]
    fn scan_returns_rule_names_directly() {
        // The `scan()` API is also useful outside the Inspector
        // path (e.g., for tests / CLI verification tooling), so it
        // gets its own coverage.
        let scanner = SecretsScanner::with_default_rules();
        let hits = scanner.scan(b"plain body, nothing here");
        assert!(hits.is_empty());
        let hits = scanner.scan(b"AKIAIOSFODNN7EXAMPLE");
        assert_eq!(hits, vec!["aws_access_key_id"]);
    }

    #[tokio::test]
    async fn custom_ruleset_works() {
        // Workloads with custom token shapes can plug their own
        // rules in alongside the defaults.
        let custom = [SecretRule {
            name: "internal_token",
            pattern: r"acmecorp_[A-Za-z0-9]{20}",
        }];
        let scanner = SecretsScanner::new(&custom).expect("compile");
        let mut c = ctx_with_body(b"X-Token: acmecorp_abcdefghij1234567890");
        let v = scanner.inspect(&mut c).await;
        assert!(v.is_deny(), "expected deny, got {v:?}");
        if let InspectorVerdict::Deny { reason } = v {
            assert!(reason.contains("internal_token"));
        }
    }
}
