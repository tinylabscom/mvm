//! Per-destination egress redaction policy. Pure data; the destination
//! resolver lives in mvm-hostd (it needs `mvm_sdk::ir::host_matches`, which
//! sits above mvm-core). Default is today's curated-only baseline: structured
//! PII per the workload `PiiPolicy`, curated secrets block, entropy + names off.

use serde::{Deserialize, Serialize};

use crate::policy::PiiPolicy;

/// Entropy detection disposition for a destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntropyMode {
    /// No entropy scanning (default everywhere unless a profile opts in).
    #[default]
    Off,
    /// Detect + audit, never mask (the safe first opt-in).
    Audit {
        min_bits_per_char: f64,
        min_run_len: usize,
    },
    /// Detect + mask.
    Redact {
        min_bits_per_char: f64,
        min_run_len: usize,
    },
}

/// Name detection disposition. Names never block (false-positive risk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NameMode {
    #[default]
    Off,
    Audit,
    Redact,
}

/// Curated `SecretsScanner` disposition. Default Block — a known secret prefix
/// on egress is always a fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecretAction {
    Audit,
    Redact,
    #[default]
    Block,
}

/// What to do at one destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RedactionAction {
    pub entropy: EntropyMode,
    /// Structured-regex PII (email/ssn/cc/phone/iban) — reuse the existing knob.
    pub pii: PiiPolicy,
    pub names: NameMode,
    pub secrets: SecretAction,
}

/// One host-pattern → action mapping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionProfile {
    /// Host or `*.`-wildcard, matched by `host_matches` at resolve time.
    pub host: String,
    pub action: RedactionAction,
}

/// A workload's per-destination redaction policy. Absent / default ⇒ the
/// `default` curated-only action applies to every destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RedactionPolicy {
    pub default: RedactionAction,
    pub profiles: Vec<RedactionProfile>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_policy_roundtrips_and_defaults_to_curated_only() {
        let json = r#"{
            "default": { "entropy": {"action":"off"}, "names": "off" },
            "profiles": [
              { "host": "*.untrusted.example",
                "action": { "entropy": {"action":"redact","min_bits_per_char":4.0,"min_run_len":20},
                            "names": "audit" } }
            ]
        }"#;
        let p: RedactionPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(p.profiles.len(), 1);
        assert_eq!(p.profiles[0].host, "*.untrusted.example");
        // default action: entropy off, names off — today's curated-only baseline.
        assert!(matches!(p.default.entropy, EntropyMode::Off));
        assert!(matches!(p.default.names, NameMode::Off));
        // round-trip
        let s = serde_json::to_string(&p).unwrap();
        let p2: RedactionPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{ "default": {}, "bogus": 1 }"#;
        assert!(serde_json::from_str::<RedactionPolicy>(json).is_err());
    }

    #[test]
    fn empty_policy_default_is_all_off() {
        let p = RedactionPolicy::default();
        assert!(p.profiles.is_empty());
        assert!(matches!(p.default.entropy, EntropyMode::Off));
        assert!(matches!(p.default.names, NameMode::Off));
    }
}
