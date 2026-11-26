//! `SecretsScanner` — block outbound requests carrying secrets.
//!
//! Finds credential-shaped bytes in a body, so a caller can refuse or mask
//! a body that looks like it is smuggling out a credential.
//!
//! Threat shape addressed:
//! - LLM agent reads `~/.aws/credentials` (or a `.env` file the
//!   workload mounted) and includes it verbatim in a tool-call
//!   request to `api.openai.com`. The destination is allowed, but the
//!   body should not be.
//! - Sloppy shell-out logs that interpolate secrets into a request.
//! - Prompt-injected exfiltration where the model is tricked into
//!   copying environment variables or session tokens.
//!
//! Match strategy: a small, curated set of high-precision patterns,
//! compiled into a single `regex::bytes::RegexSet`. Bytes (not str)
//! because bodies can be binary (multipart, protobuf, gzip-streaming
//! though we'll learn we can't usefully scan compressed bodies and
//! defer that to a later wave). A match reports the **rule** that fired,
//! never the matched value — audit logs land in operator dashboards and
//! we can't leak the secret we just blocked.
//!
//! Design choices:
//! - Curated rules, not a kitchen-sink list. Each rule must be
//!   high-precision (low false-positive rate) so we don't train
//!   operators to ignore us. Generic "looks like base64" is too
//!   noisy; AWS access key IDs (`AKIA[0-9A-Z]{16}`) are not.
//! - `RegexSet` runs all patterns in a single pass. O(body_len)
//!   instead of O(n_rules × body_len).
//! - Patterns are compiled once at construction and amortised across
//!   every scan.
//! - No body-length cap here — callers hand the scanner bounded bytes.

use regex::bytes::{Regex, RegexSet};

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
    SecretRule {
        name: "google_oauth_client_secret",
        pattern: r"GOCSPX-[A-Za-z0-9_-]{28}",
    },
    SecretRule {
        name: "github_fine_grained_pat",
        pattern: r"github_pat_[A-Za-z0-9_]{82}",
    },
    SecretRule {
        name: "gitlab_personal_access_token",
        pattern: r"glpat-[A-Za-z0-9_-]{20}",
    },
    SecretRule {
        name: "gitlab_pipeline_trigger_token",
        pattern: r"glptt-[0-9a-f]{40}",
    },
    SecretRule {
        name: "stripe_test_secret_key",
        pattern: r"sk_test_[A-Za-z0-9]{24,}",
    },
    SecretRule {
        name: "stripe_restricted_key",
        pattern: r"rk_live_[A-Za-z0-9]{24,}",
    },
    SecretRule {
        name: "sendgrid_api_key",
        pattern: r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    },
    SecretRule {
        name: "npm_access_token",
        pattern: r"npm_[A-Za-z0-9]{36}",
    },
    SecretRule {
        name: "pypi_api_token",
        pattern: r"pypi-[A-Za-z0-9_-]{50,}",
    },
    SecretRule {
        name: "square_access_token",
        pattern: r"sq0atp-[A-Za-z0-9_-]{22}",
    },
    SecretRule {
        name: "shopify_access_token",
        pattern: r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}",
    },
    SecretRule {
        name: "digitalocean_pat",
        pattern: r"dop_v1_[a-f0-9]{64}",
    },
    SecretRule {
        name: "hashicorp_vault_token",
        pattern: r"hvs\.[A-Za-z0-9_-]{90,}",
    },
    SecretRule {
        name: "postman_api_key",
        pattern: r"PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}",
    },
    SecretRule {
        name: "linear_api_key",
        pattern: r"lin_api_[A-Za-z0-9]{40}",
    },
    SecretRule {
        name: "figma_personal_access_token",
        pattern: r"figd_[A-Za-z0-9_-]{40,}",
    },
    SecretRule {
        name: "slack_webhook_url",
        pattern: r"https://hooks\.slack\.com/services/[A-Za-z0-9+/]{43,}",
    },
    // PEM private-key blocks — covers RSA, EC, OpenSSH, plain.
    SecretRule {
        name: "pem_private_key",
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    },
];

/// Scans bodies for known secret patterns.
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

/// One validated secret match span.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretMatch {
    pub name: &'static str,
    pub start: usize,
    pub end: usize,
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

    /// Validated match byte ranges with the rule name that fired.
    pub fn match_spans(&self, body: &[u8]) -> Vec<SecretMatch> {
        let candidate_indices: Vec<usize> = self.set.matches(body).into_iter().collect();
        let mut spans = Vec::new();
        for idx in candidate_indices {
            for m in self.regexes[idx].find_iter(body) {
                spans.push(SecretMatch {
                    name: self.rule_names[idx],
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
        spans
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

#[cfg(test)]
mod tests {
    use super::*;

    fn default_hits(body: &[u8]) -> Vec<&'static str> {
        SecretsScanner::with_default_rules().scan(body)
    }

    #[test]
    fn empty_body_has_no_hits() {
        assert!(default_hits(b"").is_empty());
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

    #[test]
    fn benign_body_has_no_hits() {
        assert!(
            default_hits(br#"{"messages":[{"role":"user","content":"hello world"}]}"#).is_empty()
        );
    }

    #[test]
    fn aws_access_key_is_named_by_rule() {
        let hits = default_hits(br#"{"key":"AKIAIOSFODNN7EXAMPLE","note":"test"}"#);
        assert_eq!(hits, vec!["aws_access_key_id"]);
    }

    #[test]
    fn vendor_keys_are_named_by_rule() {
        let cases = [
            (
                "github_personal_access_token",
                format!("Authorization: token ghp_{}", "a".repeat(36)),
            ),
            (
                "anthropic_api_key",
                format!("X-Api-Key: sk-ant-{}", "x".repeat(64)),
            ),
            (
                "pem_private_key",
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n".to_string(),
            ),
        ];
        for (name, body) in cases {
            let hits = default_hits(body.as_bytes());
            assert!(hits.contains(&name), "{name} did not fire; hits={hits:?}");
        }
    }

    #[test]
    fn multiple_secrets_all_listed() {
        let body = format!("aws=AKIAIOSFODNN7EXAMPLE github=ghp_{}", "z".repeat(36));
        let hits = default_hits(body.as_bytes());
        assert!(hits.contains(&"aws_access_key_id"), "hits={hits:?}");
        assert!(
            hits.contains(&"github_personal_access_token"),
            "hits={hits:?}"
        );
    }

    #[test]
    fn binary_body_does_not_panic() {
        // Bodies can be binary (protobuf, gzip, image upload). The
        // scanner must accept arbitrary bytes without choking on
        // non-UTF-8 input.
        let mut body: Vec<u8> = (0u8..=255).collect();
        body.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        assert_eq!(default_hits(&body), vec!["aws_access_key_id"]);
    }

    #[test]
    fn short_aws_like_string_does_not_match() {
        // High-precision claim: random base64-ish strings shouldn't
        // trigger. AWS rule requires `AKIA` + exactly 16 [0-9A-Z].
        // 15 chars after AKIA — too short to match.
        assert!(default_hits(b"AKIASHORTSTRING1").is_empty());
    }

    #[test]
    fn curated_vendor_patterns_fire_on_representative_samples() {
        let s = SecretsScanner::with_default_rules();
        let cases: &[(&str, String)] = &[
            (
                "google_oauth_client_secret",
                format!("GOCSPX-{}", "a".repeat(28)),
            ),
            (
                "github_fine_grained_pat",
                format!("github_pat_{}", "A".repeat(82)),
            ),
            (
                "gitlab_personal_access_token",
                format!("glpat-{}", "a".repeat(20)),
            ),
            (
                "gitlab_pipeline_trigger_token",
                format!("glptt-{}", "a".repeat(40)),
            ),
            (
                "stripe_test_secret_key",
                format!("sk_test_{}", "a".repeat(24)),
            ),
            (
                "stripe_restricted_key",
                format!("rk_live_{}", "a".repeat(24)),
            ),
            (
                "sendgrid_api_key",
                format!("SG.{}.{}", "a".repeat(22), "b".repeat(43)),
            ),
            ("npm_access_token", format!("npm_{}", "a".repeat(36))),
            ("pypi_api_token", format!("pypi-{}", "A".repeat(50))),
            ("square_access_token", format!("sq0atp-{}", "a".repeat(22))),
            ("shopify_access_token", format!("shpat_{}", "a".repeat(32))),
            ("digitalocean_pat", format!("dop_v1_{}", "a".repeat(64))),
            ("hashicorp_vault_token", format!("hvs.{}", "A".repeat(90))),
            (
                "postman_api_key",
                format!("PMAK-{}-{}", "a".repeat(24), "b".repeat(34)),
            ),
            ("linear_api_key", format!("lin_api_{}", "a".repeat(40))),
            (
                "figma_personal_access_token",
                format!("figd_{}", "a".repeat(40)),
            ),
            (
                "slack_webhook_url",
                format!("https://hooks.slack.com/services/{}", "A".repeat(44)),
            ),
        ];
        for (name, sample) in cases {
            let hits = s.scan(sample.as_bytes());
            assert!(hits.contains(name), "{name} did not fire; hits={hits:?}");
        }
    }

    #[test]
    fn enriched_rules_do_not_fire_on_benign_prose() {
        // The curated list stays high-precision: ordinary prose mentioning
        // keys/tokens/npm must not trip any rule.
        let s = SecretsScanner::with_default_rules();
        let hits = s.scan(b"installing npm packages and rotating api keys with the gitlab cli");
        assert!(hits.is_empty(), "false positive on prose: {hits:?}");
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
        let scanner = SecretsScanner::with_default_rules();
        let hits = scanner.scan(b"plain body, nothing here");
        assert!(hits.is_empty());
        let hits = scanner.scan(b"AKIAIOSFODNN7EXAMPLE");
        assert_eq!(hits, vec!["aws_access_key_id"]);
    }

    #[test]
    fn custom_ruleset_works() {
        // Workloads with custom token shapes can plug their own
        // rules in alongside the defaults.
        let custom = [SecretRule {
            name: "internal_token",
            pattern: r"acmecorp_[A-Za-z0-9]{20}",
        }];
        let scanner = SecretsScanner::new(&custom).expect("compile");
        assert_eq!(
            scanner.scan(b"X-Token: acmecorp_abcdefghij1234567890"),
            vec!["internal_token"]
        );
    }
}
