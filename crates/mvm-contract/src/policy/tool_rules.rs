//! Resolved per-tool rules that ride the signed `ExecutionPlan` inline.
//!
//! Authored `[tools]` policy narrows through composition in
//! `mvm_client::policy_profiles`; what survives is carried here, next to
//! `redaction` and `secrets`, so the per-VM endpoint can decide tool
//! questions at spawn and answer guest mediation over vsock without
//! resolving a policy bundle. The default is the all-empty section: no
//! tool is named, which the endpoint reads as "the dimension is not in
//! use" and admits everything (the dimension is opt-in).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Per-tool restrictions under `detail`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRuleDetail {
    /// Argv patterns permitted for this tool (glob-style, matched against
    /// the command line). Empty means any argv.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Argv patterns refused whatever `argv` allows. Beats `argv`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Destinations (`HOST[:PORT]`) this tool may reach through the one
    /// egress gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// Secret names bound to this tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
}

/// Whole-tool decisions plus per-tool detail, after composition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRules {
    /// Tool names admitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Tool names where every call asks the runtime approver first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,
    /// Tool names refused whatever `allow` or `ask` say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Per-tool restrictions, keyed by tool name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, ToolRuleDetail>,
}

impl ToolRules {
    /// Whether the section names no tool at all — the dimension is unused.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.ask.is_empty()
            && self.deny.is_empty()
            && self.detail.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rules_are_empty_and_serialize_away() {
        let rules = ToolRules::default();
        assert!(rules.is_empty());
        let json = serde_json::to_string(&rules).expect("serialize");
        assert_eq!(json, "{}");
    }

    #[test]
    fn rules_round_trip_with_detail() {
        let mut detail = BTreeMap::new();
        detail.insert(
            "bash".to_string(),
            ToolRuleDetail {
                argv: vec!["git *".to_string()],
                deny: vec!["rm *".to_string()],
                routes: vec!["github.com:443".to_string()],
                secrets: vec!["GITHUB_TOKEN".to_string()],
            },
        );
        let rules = ToolRules {
            allow: vec!["bash".to_string()],
            ask: vec!["git".to_string()],
            deny: vec!["curl".to_string()],
            detail,
        };
        assert!(!rules.is_empty());
        let json = serde_json::to_string(&rules).expect("serialize");
        let back: ToolRules = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rules, back);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let json = r#"{"allow":[],"unexpected":true}"#;
        assert!(serde_json::from_str::<ToolRules>(json).is_err());
    }
}
