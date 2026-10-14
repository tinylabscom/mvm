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
    /// Exact guest executable path for command mediation. No path aliases or
    /// basename inference are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Argv patterns permitted for this tool (glob-style, matched against
    /// the command line). Empty means any argv.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// Argv patterns refused whatever `argv` allows. Beats `argv`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Destinations (`HOST[:PORT]`) that belong to this tool. Only flows
    /// attributed to an invocation of it may reach them, and its invocations
    /// may reach only these. The egress gate must still admit each one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// Stored secret names that belong to this tool. Only flows attributed to
    /// an invocation of it have them substituted, and its invocations may use
    /// only these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
}

/// Canonical spelling required for a signed guest executable path. The guest
/// still resolves and verifies the actual file before spawning it.
#[must_use]
pub fn normalized_executable_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && path != "/"
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !path.chars().any(char::is_control)
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
    /// Exact executable mapping admitted for guest command mediation:
    /// tool name to the exact guest path, for every allow- or ask-listed
    /// tool whose detail names one. A deny-only tool is omitted: `deny` wins
    /// at decision time, so substituting its path would intercept every
    /// invocation only to refuse it.
    #[must_use]
    pub fn command_executables(&self) -> BTreeMap<String, String> {
        self.detail
            .iter()
            .filter(|(tool, _)| self.allow.contains(*tool) || self.ask.contains(*tool))
            .filter_map(|(tool, detail)| {
                detail
                    .executable
                    .as_ref()
                    .map(|path| (tool.clone(), path.clone()))
            })
            .collect()
    }

    /// Decide a command only when its executable matches the path the signed
    /// plan assigned to the declared tool. MCP calls use [`Self::decide`].
    #[must_use]
    pub fn decide_command(&self, tool: &str, executable: &str, argv: &str) -> ToolDecision {
        let Some(expected) = self
            .detail
            .get(tool)
            .and_then(|detail| detail.executable.as_deref())
        else {
            return ToolDecision::Deny("this tool has no signed executable path");
        };
        if !normalized_executable_path(executable)
            || !normalized_executable_path(expected)
            || executable != expected
        {
            return ToolDecision::Deny("the executable does not match this tool's signed path");
        }
        self.decide(tool, Some(argv))
    }

    /// Whether any rule scopes routes or secrets to a tool, which the endpoint
    /// enforces against flows attributed to an admitted invocation.
    #[must_use]
    pub fn has_endpoint_scope(&self) -> bool {
        self.detail
            .values()
            .any(|detail| !detail.routes.is_empty() || !detail.secrets.is_empty())
    }

    /// Decide whether a flow to `port` on one of `hosts` may use that
    /// destination, given the tool invocation the flow is attributed to.
    ///
    /// `hosts` is every name the destination answers to as far as the caller
    /// can tell: the name the flow used, plus any declared route host whose
    /// admitted addresses include a literal address the flow dialled.
    ///
    /// A route declared by a tool belongs to that tool: a flow that is not an
    /// invocation of it is refused there. A tool that declares routes may
    /// reach only those. Everything else is left to the egress gate.
    #[must_use]
    pub fn route_scope(&self, tool: Option<&str>, hosts: &[&str], port: u16) -> RouteScope {
        let declared = tool.and_then(|tool| self.detail.get(tool));
        if let Some(detail) = declared.filter(|detail| !detail.routes.is_empty()) {
            return match matching_route(&detail.routes, hosts, port) {
                Some(route) => RouteScope::Owned {
                    route: route.clone(),
                },
                None => RouteScope::Refused {
                    route: None,
                    reason: "the invocation's tool declares routes and none names this destination",
                },
            };
        }
        let scoped = self
            .detail
            .values()
            .find_map(|detail| matching_route(&detail.routes, hosts, port));
        match scoped {
            Some(route) => RouteScope::Refused {
                route: Some(route.clone()),
                reason: "this destination is a tool's route and the flow is not that tool's invocation",
            },
            None => RouteScope::Unscoped,
        }
    }

    /// Decide whether a flow attributed to `tool` may use the stored secret
    /// named `secret`. A secret a tool declares belongs to that tool, and a
    /// tool that declares secrets may use only those.
    pub fn secret_scope(&self, tool: Option<&str>, secret: &str) -> Result<(), &'static str> {
        let declared = tool.and_then(|tool| self.detail.get(tool));
        if let Some(detail) = declared.filter(|detail| !detail.secrets.is_empty()) {
            return if detail.secrets.iter().any(|listed| listed == secret) {
                Ok(())
            } else {
                Err("the invocation's tool declares secrets and this is not one of them")
            };
        }
        if self
            .detail
            .values()
            .any(|detail| detail.secrets.iter().any(|listed| listed == secret))
        {
            Err("this secret is a tool's and the flow is not that tool's invocation")
        } else {
            Ok(())
        }
    }

    /// Every declared route, parsed: `(host, port)` for each `HOST[:PORT]`.
    /// A route that does not parse names no destination and is skipped.
    pub fn declared_routes(&self) -> impl Iterator<Item = (&str, Option<u16>)> {
        self.detail
            .values()
            .flat_map(|detail| detail.routes.iter())
            .filter_map(|route| parse_route(route))
    }

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

/// How a declared tool route bears on one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteScope {
    /// No tool route names the destination; the egress gate alone decides.
    Unscoped,
    /// The flow is an invocation of the tool whose route this is.
    Owned {
        /// The declared route that matched.
        route: String,
    },
    /// Refused: the destination is another tool's route, or the flow's tool
    /// declares routes and none of them names it.
    Refused {
        /// The declared route that matched, when one did.
        route: Option<String>,
        /// Operator-safe text naming the rule.
        reason: &'static str,
    },
}

/// Split a declared `HOST[:PORT]` route. A bracketed IPv6 literal may carry a
/// port after the bracket. `None` for an empty host or an unparseable port.
#[must_use]
pub fn parse_route(route: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if let Some(rest) = route.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after {
            "" => (host, None),
            _ => (host, Some(after.strip_prefix(':')?.parse().ok()?)),
        }
    } else {
        match route.split_once(':') {
            Some((host, port)) => (host, Some(port.parse().ok()?)),
            None => (route, None),
        }
    };
    (!host.is_empty()).then_some((host, port))
}

fn route_matches(route: &str, hosts: &[&str], port: u16) -> bool {
    let Some((route_host, route_port)) = parse_route(route) else {
        return false;
    };
    route_port.is_none_or(|route_port| route_port == port)
        && hosts.iter().any(|host| {
            host.trim_end_matches('.')
                .eq_ignore_ascii_case(route_host.trim_end_matches('.'))
        })
}

fn matching_route<'a>(routes: &'a [String], hosts: &[&str], port: u16) -> Option<&'a String> {
    routes
        .iter()
        .find(|route| route_matches(route, hosts, port))
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
        assert!(!rules.has_endpoint_scope());
        let json = serde_json::to_string(&rules).expect("serialize");
        assert_eq!(json, "{}");
    }

    #[test]
    fn rules_round_trip_with_detail() {
        let mut detail = BTreeMap::new();
        detail.insert(
            "bash".to_string(),
            ToolRuleDetail {
                executable: Some("/bin/bash".to_string()),
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
        assert!(back.has_endpoint_scope());
    }

    #[test]
    fn unknown_fields_are_refused() {
        let json = r#"{"allow":[],"unexpected":true}"#;
        assert!(serde_json::from_str::<ToolRules>(json).is_err());
        let detail: ToolRuleDetail = serde_json::from_str("{}").expect("legacy detail");
        assert_eq!(detail.executable, None);
    }

    #[test]
    fn secret_only_detail_also_requires_endpoint_binding() {
        let mut rules = ToolRules::default();
        rules.detail.insert(
            "fetch".to_string(),
            ToolRuleDetail {
                secrets: vec!["api_token".to_string()],
                ..Default::default()
            },
        );
        assert!(rules.has_endpoint_scope());
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
                executable: None,
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
    fn command_executable_must_match_signed_exact_path() {
        let mut rules = rules();
        rules
            .detail
            .get_mut("bash")
            .expect("bash detail")
            .executable = Some("/bin/bash".to_string());
        assert_eq!(
            rules.decide_command("bash", "/bin/bash", "git status"),
            ToolDecision::Allow
        );
        assert_eq!(
            rules.decide_command("bash", "/tmp/bash", "git status"),
            ToolDecision::Deny("the executable does not match this tool's signed path")
        );
        assert_eq!(
            rules.decide_command("bash", "/bin/../bin/bash", "git status"),
            ToolDecision::Deny("the executable does not match this tool's signed path")
        );
    }

    #[test]
    fn command_without_signed_executable_is_refused() {
        assert_eq!(
            rules().decide_command("read", "/bin/read", "read x"),
            ToolDecision::Deny("this tool has no signed executable path")
        );
        assert_eq!(
            ToolRules::default().decide_command("read", "/bin/read", "read x"),
            ToolDecision::Deny("this tool has no signed executable path")
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

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn rules() -> ToolRules {
        let mut detail = BTreeMap::new();
        detail.insert(
            "gh".to_string(),
            ToolRuleDetail {
                routes: alloc::vec!["api.github.com:443".to_string()],
                secrets: alloc::vec!["github_token".to_string()],
                ..Default::default()
            },
        );
        detail.insert(
            "fetch".to_string(),
            ToolRuleDetail {
                routes: alloc::vec!["example.com".to_string()],
                ..Default::default()
            },
        );
        detail.insert("plain".to_string(), ToolRuleDetail::default());
        ToolRules {
            allow: alloc::vec!["gh".to_string(), "fetch".to_string(), "plain".to_string()],
            detail,
            ..Default::default()
        }
    }

    #[test]
    fn routes_parse_with_and_without_ports() {
        assert_eq!(
            parse_route("github.com:443"),
            Some(("github.com", Some(443)))
        );
        assert_eq!(parse_route("github.com"), Some(("github.com", None)));
        assert_eq!(parse_route("[::1]:8080"), Some(("::1", Some(8080))));
        assert_eq!(parse_route("[::1]"), Some(("::1", None)));
        assert_eq!(parse_route("github.com:https"), None);
        assert_eq!(parse_route(":443"), None);
        assert_eq!(parse_route("[::1]8080"), None);
    }

    #[test]
    fn a_tool_route_is_refused_to_a_flow_that_is_not_its_invocation() {
        let rules = rules();
        for tool in [None, Some("plain")] {
            assert_eq!(
                rules.route_scope(tool, &["api.github.com"], 443),
                RouteScope::Refused {
                    route: Some("api.github.com:443".to_string()),
                    reason: "this destination is a tool's route and the flow is not that tool's invocation",
                }
            );
        }
    }

    #[test]
    fn the_owning_invocation_may_use_its_route() {
        assert_eq!(
            rules().route_scope(Some("gh"), &["API.GitHub.com."], 443),
            RouteScope::Owned {
                route: "api.github.com:443".to_string()
            }
        );
    }

    #[test]
    fn a_tool_with_routes_reaches_only_those() {
        let refused = rules().route_scope(Some("gh"), &["example.com"], 443);
        assert!(matches!(refused, RouteScope::Refused { route: None, .. }));
        let other_port = rules().route_scope(Some("gh"), &["api.github.com"], 80);
        assert!(matches!(
            other_port,
            RouteScope::Refused { route: None, .. }
        ));
    }

    #[test]
    fn a_portless_route_scopes_every_port() {
        assert!(matches!(
            rules().route_scope(None, &["example.com"], 8443),
            RouteScope::Refused { .. }
        ));
        assert_eq!(
            rules().route_scope(Some("fetch"), &["example.com"], 8443),
            RouteScope::Owned {
                route: "example.com".to_string()
            }
        );
    }

    #[test]
    fn destinations_no_tool_names_are_left_to_the_gate() {
        assert_eq!(
            rules().route_scope(None, &["crates.io"], 443),
            RouteScope::Unscoped
        );
        assert_eq!(
            rules().route_scope(Some("plain"), &["crates.io"], 443),
            RouteScope::Unscoped
        );
        assert_eq!(
            ToolRules::default().route_scope(None, &["anything"], 443),
            RouteScope::Unscoped
        );
    }

    #[test]
    fn any_name_the_destination_answers_to_can_match() {
        assert!(matches!(
            rules().route_scope(None, &["140.82.112.6", "api.github.com"], 443),
            RouteScope::Refused { route: Some(_), .. }
        ));
    }

    #[test]
    fn a_tool_secret_belongs_to_its_tool() {
        let rules = rules();
        assert!(rules.secret_scope(Some("gh"), "github_token").is_ok());
        assert!(rules.secret_scope(None, "github_token").is_err());
        assert!(rules.secret_scope(Some("plain"), "github_token").is_err());
        assert!(rules.secret_scope(Some("gh"), "openai").is_err());
        assert!(rules.secret_scope(None, "openai").is_ok());
        assert!(rules.secret_scope(Some("fetch"), "openai").is_ok());
    }

    #[test]
    fn declared_routes_skip_unparseable_entries() {
        let mut rules = rules();
        rules
            .detail
            .get_mut("plain")
            .expect("plain")
            .routes
            .push("bad:port".to_string());
        let mut routes: alloc::vec::Vec<_> = rules.declared_routes().collect();
        routes.sort_unstable();
        assert_eq!(
            routes,
            [("api.github.com", Some(443)), ("example.com", None)]
        );
    }
}
