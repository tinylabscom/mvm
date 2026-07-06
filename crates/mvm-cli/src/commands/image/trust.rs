use super::*;

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
}

impl std::fmt::Display for CosignVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature(msg) => write!(f, "missing signature: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {msg}"),
            Self::ToolUnavailable(msg) => write!(f, "cosign unavailable: {msg}"),
        }
    }
}

pub(super) struct CosignCommandVerifier;

impl CosignVerifier for CosignCommandVerifier {
    fn verify(&self, reference: &str, identity: &CosignIdentity) -> Result<(), CosignVerifyError> {
        let cosign = which::which("cosign").map_err(|e| {
            CosignVerifyError::ToolUnavailable(format!(
                "cosign is required for production OCI policy; install cosign or run without --prod ({e})"
            ))
        })?;
        let output = std::process::Command::new(cosign)
            .args([
                "verify",
                "--certificate-identity",
                &identity.certificate_identity,
                "--certificate-oidc-issuer",
                &identity.certificate_oidc_issuer,
                reference,
            ])
            .output()
            .map_err(|e| CosignVerifyError::ToolUnavailable(e.to_string()))?;
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if detail.is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            detail
        };
        let detail = if detail.is_empty() {
            format!("cosign exited with status {}", output.status)
        } else {
            detail
        };
        if detail
            .to_ascii_lowercase()
            .contains("no matching signatures")
            || detail.to_ascii_lowercase().contains("no signatures")
        {
            Err(CosignVerifyError::MissingSignature(detail))
        } else {
            Err(CosignVerifyError::InvalidSignature(detail))
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct OciRegistryAuthDecision {
    pub(super) auth: RegistryAuthConfig,
    pub(super) source: String,
}

pub(super) fn registry_auth_for(image_ref: &ImageReference) -> Result<OciRegistryAuthDecision> {
    registry_auth_from_lookup(image_ref, |name| std::env::var(name).ok())
}

pub(super) fn registry_auth_from_lookup(
    image_ref: &ImageReference,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<OciRegistryAuthDecision> {
    let registry_key = registry_env_key(&image_ref.registry)?;
    let registry_var = format!("MVM_OCI_BEARER_TOKEN_{registry_key}");
    if let Some(token) = nonempty_lookup(&registry_var, &mut lookup) {
        return Ok(OciRegistryAuthDecision {
            auth: RegistryAuthConfig::bearer(token),
            source: format!("env:{registry_var}"),
        });
    }
    if let Some(token) = nonempty_lookup("MVM_OCI_BEARER_TOKEN", &mut lookup) {
        return Ok(OciRegistryAuthDecision {
            auth: RegistryAuthConfig::bearer(token),
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
