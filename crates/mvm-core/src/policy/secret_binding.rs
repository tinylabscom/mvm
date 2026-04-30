use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A secret binding maps an environment variable to a target domain,
/// optionally specifying which HTTP header carries the credential.
///
/// When injected into a microVM, the secret value is written to the
/// secrets drive (readable only by the guest agent). A placeholder
/// value is set in the guest environment so tools that check for the
/// variable's existence pass their preflight checks.
///
/// Combined with [`NetworkPolicy`](crate::network_policy::NetworkPolicy)
/// allowlists, secrets can only be sent to their bound domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBinding {
    /// Environment variable name (e.g., `OPENAI_API_KEY`).
    pub env_var: String,
    /// Domain this secret is scoped to (e.g., `api.openai.com`).
    pub target_host: String,
    /// HTTP header name for the credential. Defaults to `Authorization`.
    #[serde(default = "default_header")]
    pub header: String,
    /// The secret value. If `None`, read from the host environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

fn default_header() -> String {
    "Authorization".to_string()
}

/// Placeholder value set in guest env vars so tools pass existence checks.
pub const PLACEHOLDER_PREFIX: &str = "mvm-managed:";

impl SecretBinding {
    pub fn new(env_var: impl Into<String>, target_host: impl Into<String>) -> Self {
        Self {
            env_var: env_var.into(),
            target_host: target_host.into(),
            header: default_header(),
            value: None,
        }
    }

    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        self.header = header.into();
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Resolve the secret value: use the explicit value if set,
    /// otherwise read from the host environment.
    pub fn resolve_value(&self) -> anyhow::Result<String> {
        if let Some(ref v) = self.value {
            Ok(v.clone())
        } else {
            std::env::var(&self.env_var).map_err(|_| {
                anyhow::anyhow!(
                    "secret {:?} not set in host environment and no explicit value provided",
                    self.env_var
                )
            })
        }
    }

    /// Generate the placeholder value for the guest environment.
    pub fn placeholder(&self) -> String {
        format!("{}{}", PLACEHOLDER_PREFIX, self.env_var)
    }

    /// Generate a secret file entry for the secrets drive.
    /// The file is named after the env var (lowercase, dots replaced).
    pub fn secret_filename(&self) -> String {
        self.env_var.to_lowercase().replace('.', "_")
    }
}

impl fmt::Display for SecretBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.env_var, self.target_host)?;
        if self.header != "Authorization" {
            write!(f, ":{}", self.header)?;
        }
        Ok(())
    }
}

/// Parse a secret binding from CLI syntax:
/// - `KEY:host` — read KEY from env, inject as Authorization header to host
/// - `KEY:host:header` — custom header name
/// - `KEY=value:host` — explicit value
/// - `KEY=value:host:header` — explicit value + custom header
impl FromStr for SecretBinding {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split on first ':' to get key_part and rest
        let (key_part, rest) = s
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("expected KEY:host or KEY=value:host, got {:?}", s))?;

        // key_part is either "KEY" or "KEY=value"
        let (env_var, value) = if let Some((k, v)) = key_part.split_once('=') {
            (k.to_string(), Some(v.to_string()))
        } else {
            (key_part.to_string(), None)
        };

        if env_var.is_empty() {
            anyhow::bail!("empty environment variable name in {:?}", s);
        }

        // rest is either "host" or "host:header"
        let (target_host, header) = if let Some((h, hdr)) = rest.split_once(':') {
            (h.to_string(), hdr.to_string())
        } else {
            (rest.to_string(), default_header())
        };

        if target_host.is_empty() {
            anyhow::bail!("empty target host in {:?}", s);
        }

        Ok(Self {
            env_var,
            target_host,
            header,
            value,
        })
    }
}

/// Resolved secret bindings ready for injection into a microVM.
/// Contains the actual secret values (resolved from env or explicit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedSecrets {
    pub bindings: Vec<ResolvedBinding>,
}

/// A single resolved secret binding with its actual value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedBinding {
    pub env_var: String,
    pub target_host: String,
    pub header: String,
    pub value: String,
}

impl ResolvedSecrets {
    /// Resolve all bindings, reading values from environment where needed.
    pub fn resolve(bindings: &[SecretBinding]) -> anyhow::Result<Self> {
        let resolved = bindings
            .iter()
            .map(|b| {
                let value = b.resolve_value()?;
                Ok(ResolvedBinding {
                    env_var: b.env_var.clone(),
                    target_host: b.target_host.clone(),
                    header: b.header.clone(),
                    value,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { bindings: resolved })
    }

    /// Generate secret files for the secrets drive.
    /// Each binding produces a JSON file with the secret metadata + value.
    pub fn to_secret_files(&self) -> Vec<(String, String)> {
        self.bindings
            .iter()
            .map(|b| {
                let filename = b.env_var.to_lowercase().replace('.', "_");
                let content = serde_json::json!({
                    "env_var": b.env_var,
                    "target_host": b.target_host,
                    "header": b.header,
                    "value": b.value,
                });
                (filename, content.to_string())
            })
            .collect()
    }

    /// Generate placeholder environment variable entries for the config drive.
    /// These let tools pass "is API key set?" checks without exposing real values.
    pub fn placeholder_env_vars(&self) -> Vec<(String, String)> {
        self.bindings
            .iter()
            .map(|b| {
                (
                    b.env_var.clone(),
                    format!("{}{}", PLACEHOLDER_PREFIX, b.env_var),
                )
            })
            .collect()
    }

    /// Generate a manifest summarizing which secrets are bound to which domains.
    /// Written to the config drive for the guest agent to read on boot.
    pub fn manifest_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .bindings
            .iter()
            .map(|b| {
                serde_json::json!({
                    "env_var": b.env_var,
                    "target_host": b.target_host,
                    "header": b.header,
                    "secret_file": b.env_var.to_lowercase().replace('.', "_"),
                })
            })
            .collect();
        serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_binding() {
        let b: SecretBinding = "OPENAI_API_KEY:api.openai.com".parse().unwrap();
        assert_eq!(b.env_var, "OPENAI_API_KEY");
        assert_eq!(b.target_host, "api.openai.com");
        assert_eq!(b.header, "Authorization");
        assert!(b.value.is_none());
    }

    #[test]
    fn parse_with_header() {
        let b: SecretBinding = "ANTHROPIC_KEY:api.anthropic.com:x-api-key".parse().unwrap();
        assert_eq!(b.env_var, "ANTHROPIC_KEY");
        assert_eq!(b.target_host, "api.anthropic.com");
        assert_eq!(b.header, "x-api-key");
    }

    #[test]
    fn parse_with_value() {
        let b: SecretBinding = "MY_KEY=sk-123:api.example.com".parse().unwrap();
        assert_eq!(b.env_var, "MY_KEY");
        assert_eq!(b.value, Some("sk-123".to_string()));
        assert_eq!(b.target_host, "api.example.com");
    }

    #[test]
    fn parse_with_value_and_header() {
        let b: SecretBinding = "KEY=val:host.com:x-token".parse().unwrap();
        assert_eq!(b.env_var, "KEY");
        assert_eq!(b.value, Some("val".to_string()));
        assert_eq!(b.target_host, "host.com");
        assert_eq!(b.header, "x-token");
    }

    #[test]
    fn parse_missing_host() {
        assert!("KEY".parse::<SecretBinding>().is_err());
    }

    #[test]
    fn parse_empty_key() {
        assert!(":host.com".parse::<SecretBinding>().is_err());
    }

    #[test]
    fn parse_empty_host() {
        assert!("KEY:".parse::<SecretBinding>().is_err());
    }

    #[test]
    fn display_simple() {
        let b = SecretBinding::new("KEY", "host.com");
        assert_eq!(b.to_string(), "KEY:host.com");
    }

    #[test]
    fn display_with_header() {
        let b = SecretBinding::new("KEY", "host.com").with_header("x-token");
        assert_eq!(b.to_string(), "KEY:host.com:x-token");
    }

    #[test]
    fn placeholder() {
        let b = SecretBinding::new("OPENAI_API_KEY", "api.openai.com");
        assert_eq!(b.placeholder(), "mvm-managed:OPENAI_API_KEY");
    }

    #[test]
    fn serde_roundtrip() {
        let b = SecretBinding::new("KEY", "host.com")
            .with_header("x-token")
            .with_value("secret");
        let json = serde_json::to_string(&b).unwrap();
        let parsed: SecretBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, b);
    }

    #[test]
    fn serde_without_value_omits_field() {
        let b = SecretBinding::new("KEY", "host.com");
        let json = serde_json::to_string(&b).unwrap();
        assert!(!json.contains("value"));
    }

    #[test]
    fn resolve_value_explicit() {
        let b = SecretBinding::new("NONEXISTENT_VAR", "host.com").with_value("explicit");
        assert_eq!(b.resolve_value().unwrap(), "explicit");
    }

    #[test]
    fn resolve_value_from_env() {
        unsafe { std::env::set_var("MVM_TEST_SECRET_42", "from-env") };
        let b = SecretBinding::new("MVM_TEST_SECRET_42", "host.com");
        assert_eq!(b.resolve_value().unwrap(), "from-env");
        unsafe { std::env::remove_var("MVM_TEST_SECRET_42") };
    }

    #[test]
    fn resolve_value_missing_env() {
        let b = SecretBinding::new("DEFINITELY_NOT_SET_XYZ", "host.com");
        assert!(b.resolve_value().is_err());
    }

    #[test]
    fn resolved_secrets_files() {
        let resolved = ResolvedSecrets {
            bindings: vec![ResolvedBinding {
                env_var: "OPENAI_API_KEY".to_string(),
                target_host: "api.openai.com".to_string(),
                header: "Authorization".to_string(),
                value: "sk-test".to_string(),
            }],
        };
        let files = resolved.to_secret_files();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "openai_api_key");
        assert!(files[0].1.contains("sk-test"));
    }

    #[test]
    fn resolved_secrets_placeholders() {
        let resolved = ResolvedSecrets {
            bindings: vec![
                ResolvedBinding {
                    env_var: "KEY_A".to_string(),
                    target_host: "a.com".to_string(),
                    header: "Authorization".to_string(),
                    value: "val-a".to_string(),
                },
                ResolvedBinding {
                    env_var: "KEY_B".to_string(),
                    target_host: "b.com".to_string(),
                    header: "x-token".to_string(),
                    value: "val-b".to_string(),
                },
            ],
        };
        let placeholders = resolved.placeholder_env_vars();
        assert_eq!(placeholders.len(), 2);
        assert_eq!(placeholders[0].0, "KEY_A");
        assert_eq!(placeholders[0].1, "mvm-managed:KEY_A");
    }

    #[test]
    fn resolved_secrets_manifest() {
        let resolved = ResolvedSecrets {
            bindings: vec![ResolvedBinding {
                env_var: "KEY".to_string(),
                target_host: "host.com".to_string(),
                header: "x-token".to_string(),
                value: "secret".to_string(),
            }],
        };
        let manifest = resolved.manifest_json();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&manifest).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["env_var"], "KEY");
        assert_eq!(parsed[0]["target_host"], "host.com");
        // Manifest should NOT contain the actual secret value
        assert!(parsed[0].get("value").is_none());
    }
}
