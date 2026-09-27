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
    /// The environment variable the provider's own SDK or CLI reads its
    /// credential from (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`). A run binding a
    /// secret authored under this provider hands the guest its placeholder
    /// under this name, so stock tooling picks it up unconfigured. Naming
    /// only: no destination or substitution decision reads it. `None` when
    /// the provider has no single conventional variable (a SigV4 credential
    /// is two halves).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// The request header the provider reads its credential from, and the
    /// scheme word in front of it (`Authorization: Bearer`, `x-api-key`,
    /// `x-goog-api-key`). This is where the guest's client has to put the
    /// placeholder for substitution to find it. Set exactly when the value
    /// goes on the wire (`Bearer`/`Basic`); a signing credential leaves as a
    /// signature and has no header of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<CredentialHeader>,
    /// Searchable tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Where a provider reads its credential in a request.
// allow(secret-debug): a header name and scheme word from the compiled-in catalog; never a credential
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialHeader {
    /// The header name, as the provider documents it.
    pub name: String,
    /// The word before the credential in the header value (`Bearer`), when
    /// the provider wants one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

impl core::fmt::Display for CredentialHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.scheme {
            Some(scheme) => write!(f, "{}: {scheme} <credential>", self.name),
            None => write!(f, "{}: <credential>", self.name),
        }
    }
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
    /// `env_var` is present but not a shell identifier, so no tool could
    /// read a placeholder handed to the guest under it.
    BadEnvVar,
    /// A credential that goes on the wire names no header, a signing
    /// credential names one, or the header name is not an HTTP token.
    HeaderMismatch,
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
            ProviderInvalid::BadEnvVar => "env_var must be a shell identifier",
            ProviderInvalid::HeaderMismatch => {
                "header must be set, as an HTTP token, exactly when the credential goes on the wire"
            }
        }
    }
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
        if self
            .env_var
            .as_deref()
            .is_some_and(|var| !crate::protocol::vm_backend::is_secret_env_name(var))
        {
            return Err(ProviderInvalid::BadEnvVar);
        }
        let on_the_wire = matches!(self.auth, AuthType::Bearer | AuthType::Basic);
        let header_ok = match &self.header {
            Some(header) => on_the_wire && is_http_token(&header.name),
            None => !on_the_wire,
        };
        if !header_ok {
            return Err(ProviderInvalid::HeaderMismatch);
        }
        Ok(())
    }
}

/// Whether `name` is an HTTP header field name (an RFC 9110 token).
fn is_http_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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
        header: None,
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
    }
}

impl ServiceProvider {
    /// Name the variable the provider's own tooling reads its credential from.
    #[must_use]
    fn reading(mut self, env_var: &str) -> Self {
        self.env_var = Some(env_var.to_string());
        self
    }

    /// Name the header the provider reads the credential from, and its
    /// scheme word if it has one.
    #[must_use]
    fn sent_in(mut self, name: &str, scheme: Option<&str>) -> Self {
        self.header = Some(CredentialHeader {
            name: name.to_string(),
            scheme: scheme.map(ToString::to_string),
        });
        self
    }
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
            provider(
                "openai",
                "OpenAI HTTP API",
                &["api.openai.com"],
                AuthType::Bearer,
                None,
                &["llm", "ai"],
            )
            .reading("OPENAI_API_KEY")
            .sent_in("Authorization", Some("Bearer")),
            provider(
                "anthropic",
                "Anthropic HTTP API",
                &["api.anthropic.com"],
                AuthType::Bearer,
                None,
                &["llm", "ai"],
            )
            .reading("ANTHROPIC_API_KEY")
            .sent_in("x-api-key", None),
            provider(
                "gemini",
                "Google Gemini API (API-key auth)",
                &["generativelanguage.googleapis.com"],
                AuthType::Bearer,
                None,
                &["llm", "ai", "google"],
            )
            .reading("GEMINI_API_KEY")
            .sent_in("x-goog-api-key", None),
            provider(
                "github",
                "GitHub REST + GraphQL API",
                &["api.github.com"],
                AuthType::Bearer,
                None,
                &["git", "forge", "vcs"],
            )
            .reading("GITHUB_TOKEN")
            .sent_in("Authorization", Some("Bearer")),
            provider(
                "gitlab",
                "GitLab.com REST + GraphQL API",
                &["gitlab.com"],
                AuthType::Bearer,
                None,
                &["git", "forge", "vcs"],
            )
            .reading("GITLAB_TOKEN")
            .sent_in("PRIVATE-TOKEN", None),
            provider(
                "stripe",
                "Stripe HTTP API",
                &["api.stripe.com"],
                AuthType::Bearer,
                None,
                &["payments"],
            )
            .reading("STRIPE_API_KEY")
            .sent_in("Authorization", Some("Bearer")),
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
    fn bearer_api_providers_name_their_conventional_variable() {
        let c = builtin();
        let var = |name: &str| c.find(name).and_then(|p| p.env_var.clone());
        assert_eq!(var("anthropic").as_deref(), Some("ANTHROPIC_API_KEY"));
        assert_eq!(var("openai").as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(var("github").as_deref(), Some("GITHUB_TOKEN"));
        assert_eq!(var("stripe").as_deref(), Some("STRIPE_API_KEY"));
        assert_eq!(var("gemini").as_deref(), Some("GEMINI_API_KEY"));
        assert_eq!(var("gitlab").as_deref(), Some("GITLAB_TOKEN"));
        // A SigV4 credential is two halves; no single variable carries it.
        assert_eq!(var("aws-s3"), None);
    }

    #[test]
    fn an_env_var_that_is_not_a_shell_identifier_is_invalid() {
        for bad in ["", "9KEY", "API-KEY", "API KEY", "A=B"] {
            let p = provider("x", "d", &["h.example"], AuthType::Bearer, None, &[]).reading(bad);
            assert_eq!(p.validate(), Err(ProviderInvalid::BadEnvVar), "{bad:?}");
        }
    }

    #[test]
    fn an_entry_serialized_without_an_env_var_reads_back_as_none() {
        let json = r#"{"name":"x","description":"d","hosts":["h.example"],"auth":"bearer"}"#;
        let p: ServiceProvider = serde_json::from_str(json).unwrap();
        assert_eq!(p.env_var, None);
        assert!(!serde_json::to_string(&p).unwrap().contains("env_var"));
    }

    #[test]
    fn each_provider_names_the_header_its_api_reads() {
        let c = builtin();
        let header = |name: &str| {
            c.find(name)
                .and_then(|p| p.header.clone())
                .map(|h| h.to_string())
        };
        let bearer = "Authorization: Bearer <credential>";
        assert_eq!(header("openai").as_deref(), Some(bearer));
        assert_eq!(header("github").as_deref(), Some(bearer));
        assert_eq!(header("stripe").as_deref(), Some(bearer));
        assert_eq!(
            header("anthropic").as_deref(),
            Some("x-api-key: <credential>")
        );
        assert_eq!(
            header("gemini").as_deref(),
            Some("x-goog-api-key: <credential>")
        );
        assert_eq!(
            header("gitlab").as_deref(),
            Some("PRIVATE-TOKEN: <credential>")
        );
        assert_eq!(
            header("aws-s3"),
            None,
            "a signature has no credential header"
        );
    }

    #[test]
    fn a_header_is_required_exactly_when_the_credential_goes_on_the_wire() {
        let bare = provider("x", "d", &["h.example"], AuthType::Bearer, None, &[]);
        assert_eq!(bare.validate(), Err(ProviderInvalid::HeaderMismatch));
        let signed = provider("x", "d", &["h.example"], AuthType::Sigv4, Some("s3"), &[])
            .sent_in("Authorization", None);
        assert_eq!(signed.validate(), Err(ProviderInvalid::HeaderMismatch));
        let bad_name = provider("x", "d", &["h.example"], AuthType::Bearer, None, &[])
            .sent_in("x api key", None);
        assert_eq!(bad_name.validate(), Err(ProviderInvalid::HeaderMismatch));
    }

    #[test]
    fn serde_roundtrip() {
        let c = builtin();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<ServiceCatalog>(&json).unwrap(), c);
    }
}
