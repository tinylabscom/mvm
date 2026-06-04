//! Keystore releaser slot. Wave 3 — attestation-gated key release.
//!
//! Plan 37 §12.2: per-run secret grants. The supervisor releases a
//! plan's `secrets: Vec<SecretBinding>` only after `attestation`
//! passes (Wave 3 wires Tpm2 / SevSnp / Tdx providers). Grants are
//! revoked on plan exit; an audit entry is emitted on grant + revoke.
//!
//! ## Three states
//!
//! - **`NoopKeystoreReleaser`** — `local-default` policy refs, no
//!   bundle on disk. Every method returns `NotWired`. The
//!   fail-closed default.
//! - **`LiveKeystoreReleaser`** — a tenant-scoped bundle parsed
//!   cleanly; `rotation_interval_days` was loaded but the
//!   attestation-gated release / per-tenant revoke flow lives in
//!   the mvm-hostd supervisor lift. Methods return
//!   `NotImplemented` (distinct from `NotWired`) so operators can
//!   tell "no bundle" from "bundle present, consumer pending".
//! - **The real impl (mvm-hostd Wave 3)** — actually mints
//!   `SecretGrant`s, gates on attestation, emits audit. Not in
//!   this crate yet.

use async_trait::async_trait;
use mvm_core::plan::SecretBinding;
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

    #[error(
        "keystore releaser configured ({rotation_interval_days}-day rotation interval) \
         but the attestation-gated release path is not yet implemented in this build \
         (pending mvm-hostd lift)"
    )]
    NotImplemented { rotation_interval_days: u32 },

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

/// Carries the parsed bundle's keystore configuration. The trait
/// methods return `NotImplemented` until the mvm-hostd supervisor
/// lift wires the attestation-gated release flow; the configuration
/// is loaded off the public fields so an in-process consumer can
/// downcast and read the rotation policy today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveKeystoreReleaser {
    /// 0 = no rotation required; the supervisor warns but accepts.
    /// Plan 37 §12.2's per-tenant secret rotation hint.
    pub rotation_interval_days: u32,
}

impl LiveKeystoreReleaser {
    /// Construct from a parsed `mvm_core::policy::KeyPolicy`.
    pub fn from_policy(policy: &mvm_core::policy::KeyPolicy) -> Self {
        Self {
            rotation_interval_days: policy.rotation_interval_days,
        }
    }
}

#[async_trait]
impl KeystoreReleaser for LiveKeystoreReleaser {
    async fn release(&self, _binding: &SecretBinding) -> Result<SecretGrant, KeystoreError> {
        Err(KeystoreError::NotImplemented {
            rotation_interval_days: self.rotation_interval_days,
        })
    }

    async fn revoke(&self, _name: &str) -> Result<(), KeystoreError> {
        Err(KeystoreError::NotImplemented {
            rotation_interval_days: self.rotation_interval_days,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::SecretBinding;

    #[test]
    fn noop_keystore_releaser_is_constructable() {
        let _: Box<dyn KeystoreReleaser> = Box::new(NoopKeystoreReleaser);
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn fixture_binding() -> SecretBinding {
        SecretBinding {
            name: "api-token".to_string(),
            source: mvm_core::plan::SecretSource::Keystore {
                address: "acme/api-token".to_string(),
            },
        }
    }

    #[test]
    fn noop_release_and_revoke_error_not_wired() {
        let n = NoopKeystoreReleaser;
        let r_err = block_on(n.release(&fixture_binding())).expect_err("noop release");
        assert!(matches!(r_err, KeystoreError::NotWired));
        let v_err = block_on(n.revoke("api-token")).expect_err("noop revoke");
        assert!(matches!(v_err, KeystoreError::NotWired));
    }

    #[test]
    fn live_collector_carries_rotation_from_policy() {
        let policy = mvm_core::policy::KeyPolicy {
            rotation_interval_days: 30,
        };
        let k = LiveKeystoreReleaser::from_policy(&policy);
        assert_eq!(k.rotation_interval_days, 30);
    }

    #[test]
    fn live_release_errors_not_implemented_with_rotation_interval() {
        let policy = mvm_core::policy::KeyPolicy {
            rotation_interval_days: 90,
        };
        let k = LiveKeystoreReleaser::from_policy(&policy);
        let err = block_on(k.release(&fixture_binding())).expect_err("live release");
        match err {
            KeystoreError::NotImplemented {
                rotation_interval_days,
            } => assert_eq!(rotation_interval_days, 90),
            other => panic!("expected NotImplemented, got {other:?}"),
        }
        let v_err = block_on(k.revoke("api-token")).expect_err("live revoke");
        match v_err {
            KeystoreError::NotImplemented {
                rotation_interval_days,
            } => assert_eq!(rotation_interval_days, 90),
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn live_with_zero_rotation_still_distinguishes_from_noop() {
        // A bundle that parses but specifies no rotation interval
        // (0 = warn-but-accept) is still distinct from "no bundle
        // at all" — the live releaser reports NotImplemented{0};
        // the noop reports NotWired.
        let policy = mvm_core::policy::KeyPolicy {
            rotation_interval_days: 0,
        };
        let k = LiveKeystoreReleaser::from_policy(&policy);
        let err = block_on(k.release(&fixture_binding())).expect_err("live");
        assert!(
            matches!(
                err,
                KeystoreError::NotImplemented {
                    rotation_interval_days: 0
                }
            ),
            "expected NotImplemented{{0}}, got {err:?}"
        );
    }
}
