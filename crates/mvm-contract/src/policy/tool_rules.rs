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

    /// Decide one tool invocation. `argv` is the command line when the
    /// caller has one (the in-guest mediation); a caller without argv (the
    /// MCP surface) passes `None` and the whole-tool decision stands.
    ///
    /// An empty section admits everything — the dimension is opt-in. A
    /// non-empty section fails closed: a tool no list names is denied.
    #[must_use]
    pub fn decide(&self, tool: &str, argv: Option<&str>) -> ToolDecision {
        if self.is_empty() {
            return ToolDecision::Allow;
        }
        if self.deny.iter().any(|listed| listed == tool) {
            return ToolDecision::Deny("tools.deny names this tool");
        }
        let asks = self.ask.iter().any(|listed| listed == tool);
        if !asks && !self.allow.iter().any(|listed| listed == tool) {
            return ToolDecision::Deny("tools.allow does not name this tool");
        }
        if let (Some(argv), Some(detail)) = (argv, self.detail.get(tool)) {
            if detail.deny.iter().any(|pattern| glob_match(pattern, argv)) {
                return ToolDecision::Deny(
                    "an argv pattern this tool denies matches the command line",
                );
            }
            if !detail.argv.is_empty()
                && !detail.argv.iter().any(|pattern| glob_match(pattern, argv))
            {
                return ToolDecision::Deny("no permitted argv pattern matches the command line");
            }
        }
        if asks {
            ToolDecision::Ask
        } else {
            ToolDecision::Allow
        }
    }
}

/// The outcome of one tool decision, for any enforcement seam to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDecision {
    /// Admitted.
    Allow,
    /// Refused; the reason is operator-safe text naming the rule.
    Deny(&'static str),
    /// The runtime approver must answer before the call proceeds; every
    /// error and silence denies.
    Ask,
}

/// Glob match: `*` any sequence (including empty), `?` exactly one
/// character, everything else literal. Iterative two-pointer, linear scans.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let (mut star, mut star_t) = (usize::MAX, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = p;
            star_t = t;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
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

#[cfg(test)]
mod decide_tests {
    use super::*;

    fn rules() -> ToolRules {
        let mut detail = BTreeMap::new();
        detail.insert(
            "bash".to_string(),
            ToolRuleDetail {
                argv: vec!["git *".to_string(), "cargo *".to_string()],
                deny: vec!["* --force*".to_string()],
                routes: Vec::new(),
                secrets: Vec::new(),
            },
        );
        ToolRules {
            allow: vec!["bash".to_string(), "read".to_string()],
            ask: vec!["write".to_string()],
            deny: vec!["admin".to_string()],
            detail,
        }
    }

    #[test]
    fn empty_rules_admit_everything() {
        assert_eq!(
            ToolRules::default().decide("anything", Some("x")),
            ToolDecision::Allow
        );
    }

    #[test]
    fn unlisted_tools_fail_closed_when_rules_exist() {
        assert_eq!(
            rules().decide("other", None),
            ToolDecision::Deny("tools.allow does not name this tool")
        );
    }

    #[test]
    fn deny_beats_ask_and_allow() {
        let mut r = rules();
        r.ask.push("admin".to_string());
        r.allow.push("admin".to_string());
        assert_eq!(
            r.decide("admin", None),
            ToolDecision::Deny("tools.deny names this tool")
        );
    }

    #[test]
    fn ask_tools_ask_with_or_without_argv() {
        assert_eq!(rules().decide("write", None), ToolDecision::Ask);
        assert_eq!(rules().decide("write", Some("write x")), ToolDecision::Ask);
    }

    #[test]
    fn ask_cannot_override_argv_restrictions() {
        let mut rules = rules();
        rules.ask.push("bash".to_string());
        assert_eq!(rules.decide("bash", Some("git status")), ToolDecision::Ask);
        assert_eq!(
            rules.decide("bash", Some("git push --force")),
            ToolDecision::Deny("an argv pattern this tool denies matches the command line")
        );
        assert_eq!(
            rules.decide("bash", Some("rm -rf /")),
            ToolDecision::Deny("no permitted argv pattern matches the command line")
        );
    }

    #[test]
    fn argv_must_match_a_permitted_pattern() {
        let r = rules();
        assert_eq!(r.decide("bash", Some("git status")), ToolDecision::Allow);
        assert_eq!(r.decide("bash", Some("cargo build")), ToolDecision::Allow);
        assert_eq!(
            r.decide("bash", Some("rm -rf /")),
            ToolDecision::Deny("no permitted argv pattern matches the command line")
        );
    }

    #[test]
    fn per_tool_deny_beats_a_permitted_pattern() {
        assert_eq!(
            rules().decide("bash", Some("git push --force")),
            ToolDecision::Deny("an argv pattern this tool denies matches the command line")
        );
    }

    #[test]
    fn allowed_tools_without_detail_pass_any_argv() {
        assert_eq!(
            rules().decide("read", Some("anything at all")),
            ToolDecision::Allow
        );
    }

    #[test]
    fn glob_matches_star_and_question_mark() {
        assert!(glob_match("*", ""));
        assert!(glob_match("git *", "git status"));
        assert!(!glob_match("git *", "git"));
        assert!(glob_match("git*", "git"));
        assert!(!glob_match("git *", "gix status"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*.*", "a.b.c"));
        assert!(!glob_match("*.*", "abc"));
        assert!(glob_match("**", "anything"));
        assert!(glob_match("literal", "literal"));
        assert!(!glob_match("literal", "literals"));
    }
}
