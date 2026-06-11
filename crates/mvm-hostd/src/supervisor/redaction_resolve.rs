//! Resolve a destination host to its `RedactionAction`. Lives here, not in
//! mvm-core, because host matching is `mvm_sdk::ir::host_matches` and mvm-sdk
//! sits above mvm-core in the dependency graph.

use mvm_core::policy::{RedactionAction, RedactionPolicy};
use mvm_sdk::ir::host_matches;

/// First profile whose `host` pattern matches `dest` wins; else the policy
/// default. First-match-wins gives operators precedence control by ordering.
pub fn resolve<'a>(policy: &'a RedactionPolicy, dest: &str) -> &'a RedactionAction {
    policy
        .profiles
        .iter()
        .find(|p| host_matches(&p.host, dest))
        .map(|p| &p.action)
        .unwrap_or(&policy.default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::{
        EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile,
    };

    fn entropy_redact() -> RedactionAction {
        RedactionAction {
            entropy: EntropyMode::Redact {
                min_bits_per_char: 4.0,
                min_run_len: 20,
            },
            names: NameMode::Redact,
            ..Default::default()
        }
    }

    #[test]
    fn first_matching_wildcard_wins_else_default() {
        let pol = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "*.openai.com".into(),
                action: entropy_redact(),
            }],
        };
        // matches the wildcard
        assert!(matches!(
            resolve(&pol, "api.openai.com").entropy,
            EntropyMode::Redact { .. }
        ));
        // no match → default (Off)
        assert!(matches!(
            resolve(&pol, "example.com").entropy,
            EntropyMode::Off
        ));
    }

    #[test]
    fn earlier_profile_wins_on_overlap() {
        let pol = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![
                RedactionProfile {
                    host: "api.openai.com".into(),
                    action: entropy_redact(),
                },
                RedactionProfile {
                    host: "*.openai.com".into(),
                    action: RedactionAction::default(),
                },
            ],
        };
        assert!(matches!(
            resolve(&pol, "api.openai.com").entropy,
            EntropyMode::Redact { .. }
        ));
    }
}
