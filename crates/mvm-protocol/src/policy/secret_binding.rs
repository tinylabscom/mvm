//! Secret binding DTO + CLI parse/format.
//!
//! A secret binding maps an environment variable to a target domain,
//! optionally specifying which HTTP header carries the credential.
//!
//! The secret value **never enters the microVM.** The guest only ever sees an
//! opaque placeholder (set in its environment so tools that check the variable's
//! existence pass their preflight checks). The real value lives only host-side
//! and is substituted into the outbound request by the host egress broker, bound
//! to [`target_host`](SecretBinding::target_host) — see
//! `mvm_core::egress_substitution`. There is no path that delivers the value to
//! the guest.
//!
//! Resolving the value (reading the host environment) needs `std::env` and
//! stays in `mvm_core::policy::secret_binding` as the `resolve_value` free
//! function, which re-exports this module's [`SecretBinding`].

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

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

    /// Generate the placeholder value for the guest environment.
    pub fn placeholder(&self) -> String {
        format!("{}{}", PLACEHOLDER_PREFIX, self.env_var)
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

/// Errors parsing a [`SecretBinding`] from CLI syntax.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretBindingParseError {
    /// No `:` separator between the key part and the target host.
    #[error("expected KEY:host or KEY=value:host, got {0:?}")]
    MissingHostSeparator(String),
    /// The environment variable name was empty.
    #[error("empty environment variable name in {0:?}")]
    EmptyEnvVar(String),
    /// The target host was empty.
    #[error("empty target host in {0:?}")]
    EmptyTargetHost(String),
}

/// Parse a secret binding from CLI syntax:
/// - `KEY:host` — read KEY from env, inject as Authorization header to host
/// - `KEY:host:header` — custom header name
/// - `KEY=value:host` — explicit value
/// - `KEY=value:host:header` — explicit value + custom header
impl FromStr for SecretBinding {
    type Err = SecretBindingParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split on first ':' to get key_part and rest
        let (key_part, rest) = s
            .split_once(':')
            .ok_or_else(|| SecretBindingParseError::MissingHostSeparator(s.to_string()))?;

        // key_part is either "KEY" or "KEY=value"
        let (env_var, value) = if let Some((k, v)) = key_part.split_once('=') {
            (k.to_string(), Some(v.to_string()))
        } else {
            (key_part.to_string(), None)
        };

        if env_var.is_empty() {
            return Err(SecretBindingParseError::EmptyEnvVar(s.to_string()));
        }

        // rest is either "host" or "host:header"
        let (target_host, header) = if let Some((h, hdr)) = rest.split_once(':') {
            (h.to_string(), hdr.to_string())
        } else {
            (rest.to_string(), default_header())
        };

        if target_host.is_empty() {
            return Err(SecretBindingParseError::EmptyTargetHost(s.to_string()));
        }

        Ok(Self {
            env_var,
            target_host,
            header,
            value,
        })
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
}
