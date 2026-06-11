//! Parse `--redact HOST[=audit]` flags into a per-destination RedactionPolicy.

use anyhow::{Result, bail};
use mvm_core::policy::{EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile};

/// Default entropy threshold + run length (mirror EntropyScanner::with_defaults).
const ENTROPY_BITS: f64 = 4.0;
const ENTROPY_RUN: usize = 20;

/// Build a RedactionPolicy from repeatable `--redact HOST[=audit]` flags. A bare
/// `HOST` opts that destination into masking undeclared secrets/PII (entropy +
/// names redact); `HOST=audit` reports without masking. Empty input → all-off.
pub fn parse_redaction_flags(flags: &[String]) -> Result<RedactionPolicy> {
    let mut profiles = Vec::with_capacity(flags.len());
    for raw in flags {
        let (host, mode) = match raw.split_once('=') {
            Some((h, m)) => (h.trim(), m.trim()),
            None => (raw.trim(), "redact"),
        };
        if host.is_empty() {
            bail!("--redact: empty host in {raw:?}");
        }
        let (entropy, names) = match mode {
            "redact" => (
                EntropyMode::Redact {
                    min_bits_per_char: ENTROPY_BITS,
                    min_run_len: ENTROPY_RUN,
                },
                NameMode::Redact,
            ),
            "audit" => (
                EntropyMode::Audit {
                    min_bits_per_char: ENTROPY_BITS,
                    min_run_len: ENTROPY_RUN,
                },
                NameMode::Audit,
            ),
            other => bail!(
                "--redact: unknown mode {other:?} for host {host:?}; use `=audit` or omit for masking"
            ),
        };
        profiles.push(RedactionProfile {
            host: host.to_string(),
            action: RedactionAction {
                entropy,
                names,
                ..Default::default()
            },
        });
    }
    Ok(RedactionPolicy {
        default: RedactionAction::default(),
        profiles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_flags_yield_all_off_default() {
        let p = parse_redaction_flags(&[]).unwrap();
        assert!(p.profiles.is_empty());
    }

    #[test]
    fn bare_host_opts_into_redact() {
        let p = parse_redaction_flags(&["api.openai.com".to_string()]).unwrap();
        assert_eq!(p.profiles.len(), 1);
        assert_eq!(p.profiles[0].host, "api.openai.com");
        assert!(matches!(
            p.profiles[0].action.entropy,
            EntropyMode::Redact { .. }
        ));
        assert!(matches!(p.profiles[0].action.names, NameMode::Redact));
    }

    #[test]
    fn audit_suffix_downgrades_to_audit() {
        let p = parse_redaction_flags(&["api.openai.com=audit".to_string()]).unwrap();
        assert!(matches!(
            p.profiles[0].action.entropy,
            EntropyMode::Audit { .. }
        ));
        assert!(matches!(p.profiles[0].action.names, NameMode::Audit));
    }

    #[test]
    fn unknown_mode_errors() {
        assert!(parse_redaction_flags(&["h=bogus".to_string()]).is_err());
    }

    #[test]
    fn empty_host_errors() {
        assert!(parse_redaction_flags(&["=audit".to_string()]).is_err());
    }

    #[test]
    fn multiple_hosts() {
        let p = parse_redaction_flags(&["a.com".into(), "b.com=audit".into()]).unwrap();
        assert_eq!(p.profiles.len(), 2);
    }
}
