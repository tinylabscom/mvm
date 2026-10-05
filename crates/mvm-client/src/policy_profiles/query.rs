//! Dry-run questions against an already resolved authored policy.
//!
//! This module does no discovery, signing, admission, or I/O. The CLI resolves
//! a profile or manifest first and asks one question here, so `mvmctl why`
//! cannot accidentally grow a second policy resolver.

use std::path::{Path, PathBuf};

use mvm_contract::policy::restricted_address::{RestrictedClass, classify};
use mvm_contract::policy::routes::{RouteOutcome, RouteSet};
use mvm_contract::policy::tool_rules::ToolDecision;
use serde::Serialize;

use super::merge::{ResolvedPolicy, canonical_allow, deny_covers, split_host_port};

/// The policy subject being queried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyQuery {
    Host(String),
    Http {
        host: String,
        method: String,
        path: String,
    },
    Path(PathBuf),
    Tool(String),
    Secret(String),
}

/// A deterministic answer from a resolved policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyAnswer {
    pub subject: &'static str,
    pub value: String,
    pub allowed: bool,
    /// Whether the current runtime enforces this authored-policy dimension.
    pub enforced: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
}

impl PolicyAnswer {
    fn allow(
        subject: &'static str,
        value: String,
        enforced: bool,
        reason: impl Into<String>,
        matched: impl Into<Option<String>>,
    ) -> Self {
        Self {
            subject,
            value,
            allowed: true,
            enforced,
            reason: reason.into(),
            matched: matched.into(),
        }
    }

    fn deny(
        subject: &'static str,
        value: String,
        enforced: bool,
        reason: impl Into<String>,
        matched: impl Into<Option<String>>,
    ) -> Self {
        Self {
            subject,
            value,
            allowed: false,
            enforced,
            reason: reason.into(),
            matched: matched.into(),
        }
    }
}

/// Answer `query` from `resolved` without starting a workload.
///
/// # Errors
///
/// A host that is not valid `HOST[:PORT]` syntax.
pub fn answer(resolved: &ResolvedPolicy, query: PolicyQuery) -> Result<PolicyAnswer, String> {
    match query {
        PolicyQuery::Host(value) => answer_host(resolved, &value),
        PolicyQuery::Http { host, method, path } => answer_http(resolved, &host, &method, &path),
        PolicyQuery::Path(value) => Ok(answer_path(resolved, &value)),
        PolicyQuery::Tool(value) => Ok(answer_tool(resolved, &value)),
        PolicyQuery::Secret(value) => Ok(answer_secret(resolved, &value)),
    }
}

fn answer_host(resolved: &ResolvedPolicy, raw: &str) -> Result<PolicyAnswer, String> {
    answer_host_request(resolved, raw, None)
}

fn answer_http(
    resolved: &ResolvedPolicy,
    raw: &str,
    method: &str,
    path: &str,
) -> Result<PolicyAnswer, String> {
    answer_host_request(resolved, raw, Some((method, path)))
}

fn answer_host_request(
    resolved: &ResolvedPolicy,
    raw: &str,
    request: Option<(&str, &str)>,
) -> Result<PolicyAnswer, String> {
    if let Some((host, port)) = raw.trim().rsplit_once(':')
        && !host.is_empty()
        && port == "22"
    {
        return Ok(PolicyAnswer::deny(
            "host",
            raw.trim().to_ascii_lowercase(),
            true,
            "SSH (TCP/22) never reaches a workload",
            Some("runtime absolute deny".to_string()),
        ));
    }
    let canonical = canonical_allow(raw)?;
    let (host, port) = split_host_port(&canonical);
    let network = &resolved.policy.network;
    if network.block == Some(true) {
        return Ok(PolicyAnswer::deny(
            "host",
            canonical,
            true,
            "the resolved policy blocks all network access",
            Some("network.block".to_string()),
        ));
    }
    if let Ok(address) = host.trim_matches(['[', ']']).parse()
        && let Some(class) = classify(address)
        && !class.readmittable()
    {
        return Ok(PolicyAnswer::deny(
            "host",
            canonical,
            true,
            format!("{} is an absolute runtime deny", class.describe()),
            Some("runtime absolute deny".to_string()),
        ));
    }
    if let Some(rule) = network
        .deny
        .iter()
        .find(|rule| deny_covers(rule, host, port))
    {
        return Ok(PolicyAnswer::deny(
            "host",
            canonical,
            true,
            "a network deny rule covers this destination",
            Some(format!("network.deny = {rule:?}")),
        ));
    }
    let allow_rule = network.allow.iter().find(|rule| *rule == &canonical);
    let routes = RouteSet::new(network.routes.clone()).map_err(|error| error.to_string())?;
    if let Some(route) = routes.route_for(host, port) {
        if allow_rule.is_none() && route.host.starts_with("*.") {
            return Ok(PolicyAnswer::deny(
                "host",
                canonical,
                true,
                "a wildcard route does not grant network access without an allow-list entry",
                Some(format!("network.routes.{}", route.id)),
            ));
        }
        if route.inspects() && !route.intercept {
            return Ok(PolicyAnswer::deny(
                "host",
                canonical,
                true,
                "this route needs request inspection but does not grant interception; a runtime secret binding may separately permit termination",
                Some(format!("network.routes.{}", route.id)),
            ));
        }
        let decision = request.map(|(method, path)| route.decide(method, path));
        let (outcome, label) = match decision {
            Some(decision) => (
                decision.outcome,
                format!(
                    "network.routes.{}.{}",
                    route.id,
                    decision.decided_by.label()
                ),
            ),
            None if route.rules.is_empty() => (
                route.otherwise,
                format!("network.routes.{}.otherwise", route.id),
            ),
            None => {
                return Ok(PolicyAnswer::deny(
                    "host",
                    canonical,
                    true,
                    "this route depends on HTTP method and path; query with both to determine a request outcome",
                    Some(format!("network.routes.{}", route.id)),
                ));
            }
        };
        return Ok(match outcome {
            RouteOutcome::Allow => PolicyAnswer::allow(
                "host",
                canonical,
                true,
                "the endpoint route allows this request",
                Some(label),
            ),
            RouteOutcome::Deny => PolicyAnswer::deny(
                "host",
                canonical,
                true,
                "the endpoint route denies this request",
                Some(label),
            ),
            RouteOutcome::Ask => PolicyAnswer::deny(
                "host",
                canonical,
                true,
                "the endpoint route requires runtime approval; the request is not pre-authorized",
                Some(label),
            ),
        });
    }
    if let Some(rule) = allow_rule {
        return Ok(PolicyAnswer::allow(
            "host",
            canonical,
            true,
            "the network allow-list names this destination",
            Some(format!("network.allow = {rule:?}")),
        ));
    }
    let restricted = host
        .trim_matches(['[', ']'])
        .parse()
        .ok()
        .and_then(classify)
        .is_some_and(RestrictedClass::readmittable);
    Ok(PolicyAnswer::deny(
        "host",
        canonical,
        true,
        if restricted {
            "this restricted address is denied unless the policy names it exactly"
        } else {
            "the resolved policy does not allow this destination"
        },
        None,
    ))
}

fn answer_path(resolved: &ResolvedPolicy, path: &Path) -> PolicyAnswer {
    let value = path.display().to_string();
    if let Some(share) = resolved
        .policy
        .shares
        .mount
        .iter()
        .find(|share| path.starts_with(&share.host))
    {
        return PolicyAnswer::allow(
            "path",
            value,
            true,
            format!(
                "the policy shares it into {} as {}",
                share.guest,
                if share.writable {
                    "read-write"
                } else {
                    "read-only"
                }
            ),
            Some(format!("shares.mount = {:?}", share.host)),
        );
    }
    if let Some(deny) = resolved
        .policy
        .shares
        .deny
        .iter()
        .find(|deny| path.starts_with(deny))
    {
        return PolicyAnswer::deny(
            "path",
            value,
            true,
            "a share-source deny prefix covers this path",
            Some(format!("shares.deny = {deny:?}")),
        );
    }
    PolicyAnswer::deny(
        "path",
        value,
        true,
        "the resolved policy does not share this host path",
        None,
    )
}

fn answer_tool(resolved: &ResolvedPolicy, value: &str) -> PolicyAnswer {
    let tools = &resolved.policy.tools;
    let rules = tools.to_tool_rules();
    let detail = tools.detail.get(value);
    match rules.decide(value, None) {
        ToolDecision::Allow => PolicyAnswer::allow(
            "tool",
            value.to_string(),
            true,
            if rules.is_empty() {
                "the tool dimension is not in use; calls are admitted by default"
            } else if detail.is_some() {
                "the tool is named, subject to its per-call restrictions"
            } else {
                "the resolved policy allows this tool"
            },
            tools
                .allow
                .iter()
                .any(|tool| tool == value)
                .then(|| format!("tools.allow = {value:?}")),
        ),
        ToolDecision::Ask => PolicyAnswer::deny(
            "tool",
            value.to_string(),
            true,
            "this tool requires runtime approval before each call; it is not pre-authorized",
            Some(format!("tools.ask = {value:?}")),
        ),
        ToolDecision::Deny(reason) => PolicyAnswer::deny(
            "tool",
            value.to_string(),
            true,
            reason,
            tools
                .deny
                .iter()
                .any(|tool| tool == value)
                .then(|| format!("tools.deny = {value:?}")),
        ),
    }
}

fn answer_secret(resolved: &ResolvedPolicy, value: &str) -> PolicyAnswer {
    if resolved
        .policy
        .secrets
        .deny
        .iter()
        .any(|secret| secret == value)
    {
        return PolicyAnswer::deny(
            "secret",
            value.to_string(),
            true,
            "the resolved policy explicitly denies this secret",
            Some(format!("secrets.deny = {value:?}")),
        );
    }
    if let Some(binding) = resolved
        .policy
        .secrets
        .bind
        .iter()
        .find(|binding| binding.name == value)
    {
        return PolicyAnswer::allow(
            "secret",
            value.to_string(),
            true,
            if binding.hosts.is_empty() {
                "the policy binds this secret using its stored destination ceiling".to_string()
            } else {
                format!(
                    "the policy binds this secret to {}",
                    binding.hosts.join(", ")
                )
            },
            Some(format!("secrets.bind.{}", binding.name)),
        );
    }
    PolicyAnswer::deny(
        "secret",
        value.to_string(),
        true,
        "the resolved policy does not bind this secret",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_profiles::model::{
        NetworkSection, PolicyBody, SecretGrant, SecretsSection, ShareGrant, SharesSection,
        ToolsSection,
    };

    fn resolved(policy: PolicyBody) -> ResolvedPolicy {
        ResolvedPolicy {
            policy,
            layers: Vec::new(),
            provenance: Default::default(),
            notes: Vec::new(),
            backend_conditioned: false,
        }
    }

    #[test]
    fn host_answers_allow_deny_default_and_malformed() {
        let policy = resolved(PolicyBody {
            network: NetworkSection {
                allow: vec!["api.example.com:443".into()],
                deny: vec!["*.internal".into()],
                ..NetworkSection::default()
            },
            ..PolicyBody::default()
        });
        assert!(
            answer(&policy, PolicyQuery::Host("api.example.com".into()))
                .unwrap()
                .allowed
        );
        let denied = answer(&policy, PolicyQuery::Host("db.internal:5432".into())).unwrap();
        assert!(!denied.allowed && denied.matched.unwrap().contains("network.deny"));
        assert!(
            !answer(&policy, PolicyQuery::Host("other.example:443".into()))
                .unwrap()
                .allowed
        );
        assert!(answer(&policy, PolicyQuery::Host(":443".into())).is_err());
    }

    #[test]
    fn metadata_and_ssh_are_denied_even_if_authored_as_allowed() {
        let policy = resolved(PolicyBody {
            network: NetworkSection {
                allow: vec!["169.254.169.254:80".into(), "example.com:22".into()],
                ..NetworkSection::default()
            },
            ..PolicyBody::default()
        });
        for host in ["169.254.169.254:80", "example.com:22"] {
            let answer = answer(&policy, PolicyQuery::Host(host.into())).unwrap();
            assert!(!answer.allowed, "{host}: {answer:?}");
            assert_eq!(answer.matched.as_deref(), Some("runtime absolute deny"));
        }
    }

    #[test]
    fn path_tool_and_secret_answers_name_defaults_and_enforcement() {
        let policy = resolved(PolicyBody {
            shares: SharesSection {
                mount: vec![ShareGrant {
                    host: "/work".into(),
                    guest: "/workspace".into(),
                    writable: false,
                }],
                deny: vec!["/work/private".into()],
            },
            tools: ToolsSection {
                allow: vec!["read".into()],
                deny: vec!["shell".into()],
                ..ToolsSection::default()
            },
            secrets: SecretsSection {
                bind: vec![SecretGrant {
                    name: "API_TOKEN".into(),
                    hosts: vec!["api.example.com".into()],
                }],
                deny: vec!["ROOT_TOKEN".into()],
            },
            ..PolicyBody::default()
        });
        assert!(
            answer(&policy, PolicyQuery::Path("/work/src".into()))
                .unwrap()
                .allowed
        );
        let private = answer(&policy, PolicyQuery::Path("/work/private/key".into())).unwrap();
        assert!(private.allowed);
        assert_eq!(private.matched.as_deref(), Some("shares.mount = \"/work\""));
        let tool = answer(&policy, PolicyQuery::Tool("read".into())).unwrap();
        assert!(tool.allowed && tool.enforced);
        assert!(
            !answer(&policy, PolicyQuery::Tool("other".into()))
                .unwrap()
                .allowed
        );
        assert!(
            answer(&policy, PolicyQuery::Secret("API_TOKEN".into()))
                .unwrap()
                .allowed
        );
        assert!(
            !answer(&policy, PolicyQuery::Secret("ROOT_TOKEN".into()))
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn tool_query_uses_runtime_decision_including_ask_and_opt_in_default() {
        let empty = resolved(PolicyBody::default());
        let default = answer(&empty, PolicyQuery::Tool("shell".into())).unwrap();
        assert!(default.allowed && default.enforced);

        let policy = resolved(PolicyBody {
            tools: ToolsSection {
                allow: vec!["read".into()],
                ask: vec!["shell".into()],
                deny: vec!["remove".into()],
                ..ToolsSection::default()
            },
            ..PolicyBody::default()
        });
        let asked = answer(&policy, PolicyQuery::Tool("shell".into())).unwrap();
        assert!(!asked.allowed && asked.enforced);
        assert!(asked.reason.contains("approval"));
        let denied = answer(&policy, PolicyQuery::Tool("remove".into())).unwrap();
        assert!(!denied.allowed && denied.enforced);
        let unknown = answer(&policy, PolicyQuery::Tool("unknown".into())).unwrap();
        assert!(!unknown.allowed && unknown.enforced);
    }

    #[test]
    fn routed_host_needs_request_context_and_uses_route_decision() {
        use mvm_contract::policy::routes::{EgressRoute, EndpointRule, RouteOutcome};

        let policy = resolved(PolicyBody {
            network: NetworkSection {
                allow: vec!["api.example.com:443".into()],
                routes: vec![EgressRoute {
                    id: "api".into(),
                    host: "api.example.com".into(),
                    port: 443,
                    rules: vec![EndpointRule {
                        id: Some("read".into()),
                        method: Some("GET".into()),
                        path: "/public/**".into(),
                        outcome: RouteOutcome::Allow,
                    }],
                    otherwise: RouteOutcome::Deny,
                    intercept: true,
                }],
                ..NetworkSection::default()
            },
            ..PolicyBody::default()
        });
        let host_only = answer(&policy, PolicyQuery::Host("api.example.com".into())).unwrap();
        assert!(!host_only.allowed, "route decision needs method and path");
        let allowed = answer(
            &policy,
            PolicyQuery::Http {
                host: "api.example.com".into(),
                method: "GET".into(),
                path: "/public/x".into(),
            },
        )
        .unwrap();
        assert!(allowed.allowed);
        assert_eq!(allowed.matched.as_deref(), Some("network.routes.api.read"));
        let denied = answer(
            &policy,
            PolicyQuery::Http {
                host: "api.example.com".into(),
                method: "POST".into(),
                path: "/public/x".into(),
            },
        )
        .unwrap();
        assert!(!denied.allowed);
        assert_eq!(
            denied.matched.as_deref(),
            Some("network.routes.api.otherwise")
        );

        let mut ungranted = policy.clone();
        ungranted.policy.network.routes[0].intercept = false;
        let result = answer(
            &ungranted,
            PolicyQuery::Http {
                host: "api.example.com".into(),
                method: "GET".into(),
                path: "/public/x".into(),
            },
        )
        .unwrap();
        assert!(!result.allowed, "an uninspectable route is not a grant");
    }
}
