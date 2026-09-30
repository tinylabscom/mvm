//! Profiles and groups shipped inside `mvmctl`.
//!
//! Kept as TOML, embedded at build time, so what `mvmctl policy show` prints
//! and what a user copies into their own directory is exactly what runs. The
//! network allow-lists restate the maintained presets host for host; a test
//! below fails if either drifts from the other.

/// Built-in groups: `(name, TOML)`.
pub const GROUPS: &[(&str, &str)] = &[
    ("github", include_str!("builtin/groups/github.toml")),
    ("llm-apis", include_str!("builtin/groups/llm-apis.toml")),
    ("offline", include_str!("builtin/groups/offline.toml")),
    ("registries", include_str!("builtin/groups/registries.toml")),
];

/// Built-in profiles: `(name, TOML)`.
pub const PROFILES: &[(&str, &str)] = &[
    (
        "agent-apis",
        include_str!("builtin/profiles/agent-apis.toml"),
    ),
    ("default", include_str!("builtin/profiles/default.toml")),
    (
        "dev-network",
        include_str!("builtin/profiles/dev-network.toml"),
    ),
    ("offline", include_str!("builtin/profiles/offline.toml")),
];

/// The built-in group named `name`.
#[must_use]
pub fn group(name: &str) -> Option<&'static str> {
    lookup(GROUPS, name)
}

/// The built-in profile named `name`.
#[must_use]
pub fn profile(name: &str) -> Option<&'static str> {
    lookup(PROFILES, name)
}

fn lookup(table: &[(&str, &'static str)], name: &str) -> Option<&'static str> {
    table
        .iter()
        .find_map(|(candidate, text)| (*candidate == name).then_some(*text))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mvm_core::network_policy::NetworkPreset;

    use super::*;
    use crate::policy_profiles::model::{GroupFile, ProfileFile};

    fn hosts(group_names: &[&str]) -> BTreeSet<String> {
        group_names
            .iter()
            .flat_map(|name| {
                let doc: GroupFile = toml::from_str(group(name).unwrap()).unwrap();
                doc.network.allow
            })
            .collect()
    }

    fn preset(preset: NetworkPreset) -> BTreeSet<String> {
        preset.rules().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn every_built_in_parses() {
        for (name, text) in GROUPS {
            toml::from_str::<GroupFile>(text).unwrap_or_else(|e| panic!("group {name}: {e}"));
        }
        for (name, text) in PROFILES {
            toml::from_str::<ProfileFile>(text).unwrap_or_else(|e| panic!("profile {name}: {e}"));
        }
    }

    /// The built-in groups restate the maintained presets. If a preset gains
    /// a host and a group does not, `dev-network` quietly stops meaning what
    /// `--network-preset registries` means.
    #[test]
    fn built_in_groups_match_the_network_presets() {
        assert_eq!(hosts(&["registries"]), preset(NetworkPreset::Registries));
        assert_eq!(hosts(&["llm-apis", "github"]), preset(NetworkPreset::Agent));
        assert_eq!(
            hosts(&["registries", "llm-apis", "github"]),
            preset(NetworkPreset::Dev)
        );
    }

    #[test]
    fn the_offline_group_is_required_and_blocks() {
        let offline: GroupFile = toml::from_str(group("offline").unwrap()).unwrap();
        assert!(offline.required);
        assert_eq!(offline.network.block, Some(true));
    }

    #[test]
    fn unknown_names_are_not_built_in() {
        assert!(group("nope").is_none());
        assert!(profile("nope").is_none());
    }
}
