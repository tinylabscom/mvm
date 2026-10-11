use super::oci_types::CosignIdentity;
use anyhow::{Result, bail};
use mvm_fs::oci::{ImageReference, RegistryAuthConfig};

pub(super) fn default_require_signatures() -> bool {
    true
}

pub(super) trait CosignVerifier {
    fn verify(&self, reference: &str, identity: &CosignIdentity) -> Result<(), CosignVerifyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CosignVerifyError {
    MissingSignature(String),
    InvalidSignature(String),
    ToolUnavailable(String),
    AcquisitionFailed(String),
}

impl std::fmt::Display for CosignVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature(msg) => write!(f, "missing signature: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {msg}"),
            Self::ToolUnavailable(msg) => write!(f, "keyless verifier unavailable: {msg}"),
            Self::AcquisitionFailed(msg) => write!(f, "signature acquisition failed: {msg}"),
        }
    }
}

impl std::error::Error for CosignVerifyError {}

/// The prepared-only path checks the host-signed receipt, never the registry.
/// Refuse if a future caller accidentally requests live verification here.
pub(super) struct NoNetworkVerifier;

impl CosignVerifier for NoNetworkVerifier {
    fn verify(
        &self,
        _reference: &str,
        _identity: &CosignIdentity,
    ) -> Result<(), CosignVerifyError> {
        Err(CosignVerifyError::ToolUnavailable(
            "cached resolution requires a preparation receipt; run `mvmctl image pull`".to_string(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct OciRegistryAuthDecision {
    pub auth: RegistryAuthConfig,
    pub source: String,
}

pub fn registry_auth_for(image_ref: &ImageReference) -> Result<OciRegistryAuthDecision> {
    registry_auth_from_lookup(image_ref, |name| std::env::var(name).ok())
}

pub fn registry_auth_from_lookup(
    image_ref: &ImageReference,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<OciRegistryAuthDecision> {
    let registry_key = registry_env_key(&image_ref.registry)?;
    let registry_var = format!("MVM_OCI_BEARER_TOKEN_{registry_key}");
    if let Some(token) = nonempty_lookup(&registry_var, &mut lookup) {
        return Ok(OciRegistryAuthDecision {
            auth: RegistryAuthConfig::bearer(&image_ref.registry, token),
            source: format!("env:{registry_var}"),
        });
    }
    // The global token is offered to whatever registry a reference names,
    // including public ones it was never meant for. A refusal there falls
    // back to the anonymous exchange rather than failing a public pull.
    if let Some(token) = nonempty_lookup("MVM_OCI_BEARER_TOKEN", &mut lookup) {
        return Ok(OciRegistryAuthDecision {
            auth: RegistryAuthConfig::bearer(&image_ref.registry, token).with_anonymous_fallback(),
            source: "env:MVM_OCI_BEARER_TOKEN".to_string(),
        });
    }
    Ok(OciRegistryAuthDecision {
        auth: RegistryAuthConfig::Anonymous,
        source: "anonymous".to_string(),
    })
}

fn nonempty_lookup(name: &str, lookup: &mut impl FnMut(&str) -> Option<String>) -> Option<String> {
    lookup(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn registry_env_key(registry: &str) -> Result<String> {
    let mut key = String::with_capacity(registry.len());
    for ch in registry.chars() {
        if ch.is_ascii_alphanumeric() {
            key.push(ch.to_ascii_uppercase());
        } else if matches!(ch, '.' | '-' | ':') {
            key.push('_');
        } else {
            bail!("OCI registry host contains unsupported env-var character: {registry:?}");
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn registry_env_key_normalizes_registry_host() {
        assert_eq!(registry_env_key("ghcr.io").expect("key"), "GHCR_IO");
        assert_eq!(
            registry_env_key("registry.example.test:5000").expect("key"),
            "REGISTRY_EXAMPLE_TEST_5000"
        );
    }

    #[test]
    fn registry_auth_prefers_registry_specific_bearer_token() {
        let image_ref: ImageReference = "ghcr.io/acme/app:latest".parse().expect("image ref");
        let auth = registry_auth_from_lookup(&image_ref, |name| match name {
            "MVM_OCI_BEARER_TOKEN_GHCR_IO" => Some("registry-token".to_string()),
            "MVM_OCI_BEARER_TOKEN" => Some("global-token".to_string()),
            _ => None,
        })
        .expect("auth resolution");

        assert_eq!(auth.source, "env:MVM_OCI_BEARER_TOKEN_GHCR_IO");
        assert!(auth.auth.is_authenticated());
        assert_eq!(auth.auth.kind(), "bearer");
        assert_eq!(auth.auth.registry(), Some("ghcr.io"));
        // A token set for this registry is reported when refused.
        assert_eq!(
            auth.auth.bearer_refusal(),
            Some(mvm_fs::oci::BearerRefusal::Fail)
        );
    }

    #[test]
    fn registry_auth_falls_back_to_global_bearer_token() {
        let image_ref: ImageReference = "ghcr.io/acme/app:latest".parse().expect("image ref");
        let auth = registry_auth_from_lookup(&image_ref, |name| match name {
            "MVM_OCI_BEARER_TOKEN" => Some("global-token".to_string()),
            _ => None,
        })
        .expect("auth resolution");

        assert_eq!(auth.source, "env:MVM_OCI_BEARER_TOKEN");
        assert_eq!(auth.auth.kind(), "bearer");
        assert_eq!(auth.auth.registry(), Some("ghcr.io"));
        // The global token reaches registries it was not meant for, so a
        // refusal falls back to the anonymous exchange.
        assert_eq!(
            auth.auth.bearer_refusal(),
            Some(mvm_fs::oci::BearerRefusal::AnonymousExchange)
        );
    }

    #[test]
    fn registry_auth_has_no_docker_config_dependency() {
        let image_ref: ImageReference = "ghcr.io/acme/app:latest".parse().expect("image ref");
        let requested = RefCell::new(Vec::new());
        let auth = registry_auth_from_lookup(&image_ref, |name| {
            requested.borrow_mut().push(name.to_string());
            None
        })
        .expect("auth resolution");

        assert_eq!(auth.source, "anonymous");
        assert!(!auth.auth.is_authenticated());
        assert_eq!(
            requested.into_inner(),
            vec![
                "MVM_OCI_BEARER_TOKEN_GHCR_IO".to_string(),
                "MVM_OCI_BEARER_TOKEN".to_string()
            ]
        );
    }
}
