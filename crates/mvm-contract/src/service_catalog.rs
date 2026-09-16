//! The curated set of named service providers a secret can be bound to.
//!
//! `mvmctl secret set` records where a credential may go (`allowed_hosts`) and
//! how it authenticates (`AuthType`). Typed by hand, the destination is the most
//! dangerous field in the secrets path, and it does not fail loudly when it is
//! wrong: a typo withholds the credential, which surfaces as an unrelated auth
//! error, and a wrong-but-plausible host sends a live credential somewhere the
//! operator never intended. Nothing downstream can distinguish the host that was
//! typed from the host that was meant.
//!
//! A provider entry removes the choice. `--provider openai` resolves to that
//! entry's hosts and auth type, so the dangerous field is not hand-written at
//! all for anything catalogued.
//!
//! # Resolved at authoring time, never on the forward path
//!
//! An entry is expanded once, when `secret set` runs, and the literal hosts are
//! what get stored and enforced. The catalog is not consulted when a request is
//! substituted. Two reasons, both load-bearing: the egress path stays free of
//! catalog lookups, and a later edit to an entry cannot silently widen a binding
//! that already exists. A binding means what it meant the day it was written.
//!
//! The provider name is recorded alongside the hosts for display and audit, and
//! is not an input to any decision.
//!
//! # Why this ships in the binary
//!
//! The catalog is code, not configuration: versioned with the release, reviewed
//! like code, with no file to parse and no fetch to fail. Putting a network
//! dependency on the authoring path for a security-critical field would trade a
//! typo for an outage.
//!
//! An operator whose provider is not catalogued keeps the explicit
//! `--host`/`--type` form. A catalog that cannot express your destination must
//! not become a wall.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::ir::AuthType;

/// One named provider: where its credential may go, and how it authenticates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProvider {
    /// Selector an operator types (`--provider openai`). Lowercase, `a-z0-9-`.
    pub name: String,
    /// One line, shown by `mvmctl secret providers`.
    pub description: String,
    /// Destinations the credential may reach, in `allowed_hosts` form —
    /// exact hosts or `*.suffix` wildcards, as [`crate::ir::host_matches`]
    /// reads them.
    pub hosts: Vec<String>,
    /// How the credential authenticates outbound requests.
    pub auth: AuthType,
    /// The AWS credential-scope service (`s3`, `execute-api`). Set exactly
    /// when `auth` is [`AuthType::Sigv4`]: it is a property of the provider,
    /// unlike the region and access-key id, which belong to the operator's
    /// account and stay on the command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigv4_service: Option<String>,
    /// The environment variable the provider's own SDK/CLI conventionally
    /// reads its credential from (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`).
    /// A run binding a secret authored under this provider surfaces its
    /// opaque placeholder to the guest under this name, so the workload's
    /// stock tooling picks it up with no configuration. Naming only — never
    /// an input to any destination or substitution decision. `None` when the
    /// provider has no single conventional variable (SigV4's credential is
    /// two halves).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Searchable tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Why a [`ServiceProvider`] entry is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderInvalid {
    /// The selector is empty.
    EmptyName,
    /// No destination: an entry that binds nothing would produce a binding
    /// that fails closed on every request, which is not a useful entry.
    NoHosts,
    /// A blank entry in the host list.
    EmptyHost,
    /// `auth = Sigv4` without a scope service, or a scope service on an
    /// auth type that has no use for one. Either way the entry claims
    /// something it cannot deliver.
    Sigv4ScopeMismatch,
    /// `env_var` is present but not a well-formed environment variable name
    /// (`[A-Za-z_][A-Za-z0-9_]*`). A malformed name would surface a
    /// placeholder under a variable no tool can read.
    BadEnvVar,
}

impl ProviderInvalid {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ProviderInvalid::EmptyName => "empty provider name",
            ProviderInvalid::NoHosts => "provider declares no destination host",
            ProviderInvalid::EmptyHost => "provider host list contains an empty entry",
            ProviderInvalid::Sigv4ScopeMismatch => {
                "sigv4_service must be set for sigv4 auth and absent otherwise"
            }
            ProviderInvalid::BadEnvVar => "env_var must be a well-formed environment variable name",
        }
    }
}

/// Whether `name` is a well-formed environment variable name:
/// `[A-Za-z_][A-Za-z0-9_]*`. Shared by the catalog's own validation and by
/// callers deriving a guest-facing variable for an uncatalogued secret.
#[must_use]
pub fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl ServiceProvider {
    /// Whether this entry is internally consistent.
    ///
    /// # Errors
    ///
    /// [`ProviderInvalid`] naming the first problem found.
    pub fn validate(&self) -> Result<(), ProviderInvalid> {
        if self.name.is_empty() {
            return Err(ProviderInvalid::EmptyName);
        }
        if self.hosts.is_empty() {
            return Err(ProviderInvalid::NoHosts);
        }
        if self.hosts.iter().any(|h| h.trim().is_empty()) {
            return Err(ProviderInvalid::EmptyHost);
        }
        // The two must agree in both directions: a SigV4 entry that cannot
        // name its scope is unusable, and a scope on a bearer entry is a
        // value that would be silently dropped.
        if matches!(self.auth, AuthType::Sigv4) != self.sigv4_service.is_some() {
            return Err(ProviderInvalid::Sigv4ScopeMismatch);
        }
        if let Some(var) = &self.env_var
            && !is_valid_env_var_name(var)
        {
            return Err(ProviderInvalid::BadEnvVar);
        }
        Ok(())
    }
}

/// A set of provider entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCatalog {
    /// Schema version for forward compatibility.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// The provider entries.
    pub providers: Vec<ServiceProvider>,
}

const fn default_schema_version() -> u32 {
    1
}

impl ServiceCatalog {
    /// Exact lookup by selector. `None` is a refusal, not a fallback: an
    /// unrecognised provider name must never resolve to a permissive default.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&ServiceProvider> {
        self.providers.iter().find(|p| p.name == name)
    }

    /// Case-insensitive substring search over name, description and tags.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&ServiceProvider> {
        let q = query.to_lowercase();
        self.providers
            .iter()
            .filter(|p| {
                p.name.to_lowercase().contains(&q)
                    || p.description.to_lowercase().contains(&q)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Every entry, in catalog order.
    #[must_use]
    pub fn all(&self) -> &[ServiceProvider] {
        &self.providers
    }

    /// Whether every entry is internally consistent.
    ///
    /// # Errors
    ///
    /// The offending provider's name and its [`ProviderInvalid`].
    pub fn validate(&self) -> Result<(), (String, ProviderInvalid)> {
        let mut seen: Vec<&str> = Vec::new();
        for p in &self.providers {
            p.validate().map_err(|e| (p.name.clone(), e))?;
            // A duplicate selector makes `find` order-dependent, which is a
            // silent way for one entry to shadow another's destinations.
            if seen.contains(&p.name.as_str()) {
                return Err((p.name.clone(), ProviderInvalid::EmptyName));
            }
            seen.push(&p.name);
        }
        Ok(())
    }
}

fn provider(
    name: &str,
    description: &str,
    hosts: &[&str],
    auth: AuthType,
    sigv4_service: Option<&str>,
    tags: &[&str],
) -> ServiceProvider {
    ServiceProvider {
        name: name.to_string(),
        description: description.to_string(),
        hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
        auth,
        sigv4_service: sigv4_service.map(ToString::to_string),
        env_var: None,
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
    }
}

fn with_env_var(mut p: ServiceProvider, var: &str) -> ServiceProvider {
    p.env_var = Some(var.to_string());
    p
}

/// The catalog shipped with this build.
///
/// Deliberately short. Every entry is a destination someone has to keep
/// correct, and a wrong entry is worse than an absent one: an absent provider
/// sends the operator to the explicit `--host` form, where they at least know
/// they are choosing, while a wrong one is trusted silently.
#[must_use]
pub fn builtin() -> ServiceCatalog {
    ServiceCatalog {
        schema_version: default_schema_version(),
        providers: vec![
            with_env_var(
                provider(
                    "openai",
                    "OpenAI HTTP API",
                    &["api.openai.com"],
                    AuthType::Bearer,
                    None,
                    &["llm", "ai"],
                ),
                "OPENAI_API_KEY",
            ),
            with_env_var(
                provider(
                    "anthropic",
                    "Anthropic HTTP API",
                    &["api.anthropic.com"],
                    AuthType::Bearer,
                    None,
                    &["llm", "ai"],
                ),
                "ANTHROPIC_API_KEY",
            ),
            with_env_var(
                provider(
                    "github",
                    "GitHub REST + GraphQL API",
                    &["api.github.com"],
                    AuthType::Bearer,
                    None,
                    &["git", "forge", "vcs"],
                ),
                "GITHUB_TOKEN",
            ),
            with_env_var(
                provider(
                    "stripe",
                    "Stripe HTTP API",
                    &["api.stripe.com"],
                    AuthType::Bearer,
                    None,
                    &["payments"],
                ),
                "STRIPE_API_KEY",
            ),
            provider(
                "aws-s3",
                "Amazon S3 (SigV4; region and access-key id are yours to supply)",
                &["s3.amazonaws.com", "*.s3.amazonaws.com"],
                AuthType::Sigv4,
                Some("s3"),
                &["storage", "aws", "object-store"],
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_catalog_is_internally_consistent() {
        builtin().validate().expect("shipped catalog must validate");
    }

    #[test]
    fn every_builtin_entry_declares_at_least_one_host() {
        for p in builtin().all() {
            assert!(!p.hosts.is_empty(), "{} declares no host", p.name);
        }
    }

    #[test]
    fn find_is_exact_and_absent_names_refuse() {
        let c = builtin();
        assert!(c.find("openai").is_some());
        // No prefix match, no case folding, no nearest-neighbour: an
        // unrecognised name has to be a refusal at the call site.
        assert!(c.find("openai-").is_none());
        assert!(c.find("OpenAI").is_none());
        assert!(c.find("").is_none());
        assert!(c.find("definitely-not-a-provider").is_none());
    }

    #[test]
    fn search_matches_name_description_and_tags() {
        let c = builtin();
        assert!(!c.search("llm").is_empty(), "tag match");
        assert!(!c.search("SigV4").is_empty(), "description match");
        assert!(!c.search("githu").is_empty(), "name substring");
        assert!(c.search("zzz-no-such-thing").is_empty());
    }

    #[test]
    fn a_sigv4_entry_without_a_scope_service_is_invalid() {
        let p = provider("x", "d", &["h.example"], AuthType::Sigv4, None, &[]);
        assert_eq!(p.validate(), Err(ProviderInvalid::Sigv4ScopeMismatch));
    }

    #[test]
    fn a_scope_service_on_a_bearer_entry_is_invalid() {
        // Would be silently dropped at resolution, masking an authoring error.
        let p = provider("x", "d", &["h.example"], AuthType::Bearer, Some("s3"), &[]);
        assert_eq!(p.validate(), Err(ProviderInvalid::Sigv4ScopeMismatch));
    }

    #[test]
    fn an_entry_with_no_hosts_or_a_blank_host_is_invalid() {
        let none = provider("x", "d", &[], AuthType::Bearer, None, &[]);
        assert_eq!(none.validate(), Err(ProviderInvalid::NoHosts));
        let blank = provider("x", "d", &["  "], AuthType::Bearer, None, &[]);
        assert_eq!(blank.validate(), Err(ProviderInvalid::EmptyHost));
    }

    #[test]
    fn an_unnamed_entry_is_invalid() {
        let p = provider("", "d", &["h.example"], AuthType::Bearer, None, &[]);
        assert_eq!(p.validate(), Err(ProviderInvalid::EmptyName));
    }

    #[test]
    fn a_duplicate_selector_is_rejected() {
        let c = ServiceCatalog {
            schema_version: 1,
            providers: vec![
                provider("dup", "a", &["a.example"], AuthType::Bearer, None, &[]),
                provider("dup", "b", &["b.example"], AuthType::Bearer, None, &[]),
            ],
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let c = builtin();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<ServiceCatalog>(&json).unwrap(), c);
    }

    #[test]
    fn a_catalog_serialized_before_env_var_existed_still_deserializes() {
        // The field is additive: an entry without it reads back as `None`.
        let json = r#"{"schema_version":1,"providers":[{
            "name":"openai","description":"d","hosts":["api.openai.com"],
            "auth":"bearer","tags":[]}]}"#;
        let c: ServiceCatalog = serde_json::from_str(json).unwrap();
        assert_eq!(c.providers[0].env_var, None);
    }

    #[test]
    fn bearer_api_providers_name_their_conventional_env_var() {
        let c = builtin();
        let var = |name: &str| c.find(name).unwrap().env_var.clone();
        assert_eq!(var("anthropic").as_deref(), Some("ANTHROPIC_API_KEY"));
        assert_eq!(var("openai").as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(var("github").as_deref(), Some("GITHUB_TOKEN"));
        assert_eq!(var("stripe").as_deref(), Some("STRIPE_API_KEY"));
        // SigV4 credentials are two halves; no single conventional variable.
        assert_eq!(var("aws-s3"), None);
    }

    #[test]
    fn a_malformed_env_var_name_is_invalid() {
        let mut p = provider("x", "d", &["h.example"], AuthType::Bearer, None, &[]);
        for bad in ["", "9KEY", "API-KEY", "API KEY", "K\u{e9}Y"] {
            p.env_var = Some(bad.to_string());
            assert_eq!(p.validate(), Err(ProviderInvalid::BadEnvVar), "{bad:?}");
        }
        p.env_var = Some("ANTHROPIC_API_KEY".to_string());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn is_valid_env_var_name_accepts_the_posix_shape_only() {
        assert!(is_valid_env_var_name("ANTHROPIC_API_KEY"));
        assert!(is_valid_env_var_name("_X9"));
        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1X"));
        assert!(!is_valid_env_var_name("A-B"));
        assert!(!is_valid_env_var_name("A B"));
    }
}
