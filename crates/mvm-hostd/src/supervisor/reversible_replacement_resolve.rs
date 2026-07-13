//! Resolve a destination host to its reversible replacement action.

use mvm_core::policy::{ReversibleReplacementAction, ReversibleReplacementPolicy};
use mvm_sdk::ir::host_matches;

/// First matching profile wins; else the default action.
pub fn resolve<'a>(
    policy: &'a ReversibleReplacementPolicy,
    dest: &str,
) -> &'a ReversibleReplacementAction {
    policy
        .profiles
        .iter()
        .find(|profile| host_matches(&profile.host, dest))
        .map(|profile| &profile.action)
        .unwrap_or(&policy.default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::{
        ReversibleReplacementAction, ReversibleReplacementPolicy, ReversibleReplacementProfile,
    };

    #[test]
    fn first_match_wins_else_default() {
        let policy = ReversibleReplacementPolicy {
            default: ReversibleReplacementAction::default(),
            profiles: vec![ReversibleReplacementProfile {
                host: "*.openai.com".into(),
                action: ReversibleReplacementAction {
                    enabled: true,
                    ..Default::default()
                },
            }],
        };
        assert!(resolve(&policy, "api.openai.com").enabled);
        assert!(!resolve(&policy, "example.com").enabled);
    }
}
