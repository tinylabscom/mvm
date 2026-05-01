//! Keystore releaser slot. Wave 3 — attestation-gated key release.
//!
//! Plan 37 §12.2: per-run secret grants. The supervisor releases a
//! plan's `secrets: Vec<SecretBinding>` only after `attestation`
//! passes (Wave 3 wires Tpm2 / SevSnp / Tdx providers). Grants are
//! revoked on plan exit; an audit entry is emitted on grant + revoke.

use async_trait::async_trait;
use mvm_plan::SecretBinding;
use thiserror::Error;

/// A live secret grant — name (workload-visible) + opaque value the
/// supervisor surfaces via the secrets-mount filesystem
/// (`/run/mvm-secrets/<name>`). The `value` is wrapped in a
/// zeroize-on-drop type in Wave 3; today it's a plain String stub
/// for shape only.
#[derive(Debug, Clone)]
pub struct SecretGrant {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("keystore releaser not wired (Noop slot)")]
    NotWired,

    #[error("attestation requirement not satisfied: {0}")]
    AttestationFailed(String),

    #[error("secret {name} not found in resolver")]
    NotFound { name: String },
}

#[async_trait]
pub trait KeystoreReleaser: Send + Sync {
    /// Resolve a `SecretBinding` to a live grant. Wave 3's real impl
    /// gates this on attestation evidence collected during launch;
    /// the trait signature is intentionally loose so Wave 3 can pass
    /// the attestation evidence without changing this method's
    /// shape.
    async fn release(&self, binding: &SecretBinding) -> Result<SecretGrant, KeystoreError>;

    /// Revoke a previously-released grant. Called on plan teardown.
    async fn revoke(&self, name: &str) -> Result<(), KeystoreError>;
}

pub struct NoopKeystoreReleaser;

#[async_trait]
impl KeystoreReleaser for NoopKeystoreReleaser {
    async fn release(&self, _binding: &SecretBinding) -> Result<SecretGrant, KeystoreError> {
        Err(KeystoreError::NotWired)
    }

    async fn revoke(&self, _name: &str) -> Result<(), KeystoreError> {
        Err(KeystoreError::NotWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_keystore_releaser_is_constructable() {
        let _: Box<dyn KeystoreReleaser> = Box::new(NoopKeystoreReleaser);
    }
}
