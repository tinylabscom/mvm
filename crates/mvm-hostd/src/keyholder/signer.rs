//! The signing keyholder (gold path).
//!
//! For signing-based auth (AWS SigV4, HMAC webhooks) the secret key never
//! goes on the wire: the signer resolves the key into confined memory,
//! computes a signature over a caller-prepared canonical request, and
//! zeroizes. The returned [`Signature`] carries the digest only — no key
//! material — so a leaked signature reveals nothing about the key.
//!
//! Software-first, hardware-optional: the default path is
//! pure software (key encrypted at rest, decrypted only here, wiped after
//! use). A Secure Enclave / TPM, when present, strengthens this to "host
//! never sees the key" through the *same* interface — no DX change.

use hmac::{Hmac, Mac};
use mvm_sdk::ir::{AuthType, SecretRef};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::resolver::{ResolveError, SecretResolver};

type HmacSha256 = Hmac<Sha256>;

/// A computed signature, hex-encoded. Carries **no** key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub hex: String,
}

/// Errors from the signing keyholder.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// The signer handles only signing schemes; bearer/basic go to the
    /// injector. Guards against a caller routing a transmitted-value
    /// secret through the key-never-leaves path.
    #[error("signer handles sigv4/hmac only, not {0:?}; use the injector")]
    WrongAuthType(AuthType),
}

/// What to sign, by scheme. The SDK builds the canonical request (SigV4) or
/// supplies the payload (HMAC webhook); the signer returns a signature. Lets
/// the endpoint take one signing call and dispatch to the right `Signer` method.
pub enum SigningInput {
    SigV4(SigV4Input),
    Hmac { payload: Vec<u8> },
}

/// Inputs for an AWS SigV4 signature. The caller prepares the canonical
/// request — the signer signs, it does not build requests. Holds only the
/// canonical request + scope (no key material), so Debug can't leak a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Input {
    pub canonical_request: String,
    /// `yyyymmddThhmmssZ`.
    pub amz_date: String,
    /// `yyyymmdd` — the credential-scope date.
    pub date_stamp: String,
    pub region: String,
    pub service: String,
}

impl SigV4Input {
    /// `<date>/<region>/<service>/aws4_request` — public, for the caller's
    /// `Authorization` header.
    pub fn credential_scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date_stamp, self.region, self.service
        )
    }

    fn string_to_sign(&self) -> String {
        let hashed = hex::encode(Sha256::digest(self.canonical_request.as_bytes()));
        format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            self.amz_date,
            self.credential_scope(),
            hashed
        )
    }
}

/// The signing keyholder. Borrows a [`SecretResolver`] for the key source.
pub struct Signer<'a> {
    resolver: &'a dyn SecretResolver,
}

impl<'a> Signer<'a> {
    pub fn new(resolver: &'a dyn SecretResolver) -> Self {
        Self { resolver }
    }

    /// HMAC-SHA256 over `payload` (webhook signing). The key is resolved,
    /// used, and zeroized within this call.
    pub fn sign_hmac(&self, r: &SecretRef, payload: &[u8]) -> Result<Signature, SignError> {
        if r.auth_type != AuthType::Hmac {
            return Err(SignError::WrongAuthType(r.auth_type));
        }
        let key = self.resolver.resolve(r)?;
        let sig = hmac_sha256(key.expose_secret(), payload);
        // `key` (SecretBox) and `sig` (Zeroizing) wipe on drop at scope end.
        Ok(Signature {
            hex: hex::encode(&*sig),
        })
    }

    /// AWS SigV4 signature. The key is resolved, the signing key derived
    /// in zeroizing buffers, and all of it wiped on return.
    pub fn sign_sigv4(&self, r: &SecretRef, input: &SigV4Input) -> Result<Signature, SignError> {
        if r.auth_type != AuthType::Sigv4 {
            return Err(SignError::WrongAuthType(r.auth_type));
        }
        let key = self.resolver.resolve(r)?;
        let signing_key = derive_sigv4_signing_key(
            key.expose_secret(),
            &input.date_stamp,
            &input.region,
            &input.service,
        );
        let sig = hmac_sha256(&signing_key, input.string_to_sign().as_bytes());
        Ok(Signature {
            hex: hex::encode(&*sig),
        })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// AWS SigV4 four-step signing-key derivation. Every intermediate is a
/// zeroizing buffer so no derived key lingers on the heap after the sign.
fn derive_sigv4_signing_key(
    secret: &[u8],
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let mut seed = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    seed.extend_from_slice(b"AWS4");
    seed.extend_from_slice(secret);
    let k_date = hmac_sha256(&seed, date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::SecretMount;
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn resolver_with(name: &str, value: &str) -> (tempfile::TempDir, LocalResolver) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        (dir, LocalResolver::new("local", store))
    }

    fn secret_ref(name: &str, auth_type: AuthType, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    #[test]
    fn hmac_matches_rfc4231_case2() {
        // RFC 4231 §4.3: key="Jefe", data="what do ya want for nothing?".
        let (_dir, resolver) = resolver_with("webhook", "Jefe");
        let signer = Signer::new(&resolver);
        let sig = signer
            .sign_hmac(
                &secret_ref("webhook", AuthType::Hmac, &["hooks.example.com"]),
                b"what do ya want for nothing?",
            )
            .unwrap();
        assert_eq!(
            sig.hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn sigv4_matches_aws_get_vanilla_vector() {
        // aws-sig-v4-test-suite `get-vanilla`: the published signature for
        // the canonical example. Proves the full derive + string-to-sign.
        let (_dir, resolver) = resolver_with("aws", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let signer = Signer::new(&resolver);
        let input = SigV4Input {
            canonical_request: "GET\n/\n\nhost:example.amazonaws.com\n\
                 x-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
                 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            amz_date: "20150830T123600Z".into(),
            date_stamp: "20150830".into(),
            region: "us-east-1".into(),
            service: "service".into(),
        };
        let sig = signer
            .sign_sigv4(
                &secret_ref("aws", AuthType::Sigv4, &["example.amazonaws.com"]),
                &input,
            )
            .unwrap();
        assert_eq!(
            sig.hex,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn sign_hmac_rejects_non_hmac_auth_type() {
        let (_dir, resolver) = resolver_with("aws", "k");
        let signer = Signer::new(&resolver);
        let err = signer
            .sign_hmac(
                &secret_ref("aws", AuthType::Sigv4, &["api.example.com"]),
                b"x",
            )
            .unwrap_err();
        assert!(matches!(err, SignError::WrongAuthType(AuthType::Sigv4)));
    }

    #[test]
    fn sign_sigv4_rejects_non_sigv4_auth_type() {
        let (_dir, resolver) = resolver_with("webhook", "k");
        let signer = Signer::new(&resolver);
        let input = SigV4Input {
            canonical_request: "GET\n/\n\n\n\n".into(),
            amz_date: "20150830T123600Z".into(),
            date_stamp: "20150830".into(),
            region: "us-east-1".into(),
            service: "service".into(),
        };
        let err = signer
            .sign_sigv4(
                &secret_ref("webhook", AuthType::Bearer, &["api.example.com"]),
                &input,
            )
            .unwrap_err();
        assert!(matches!(err, SignError::WrongAuthType(AuthType::Bearer)));
    }

    #[test]
    fn unbound_secret_never_signs() {
        // The resolver's claim-12 backstop: an empty allow-list refuses to
        // resolve, so the signer can't sign for an unbound secret.
        let (_dir, resolver) = resolver_with("webhook", "Jefe");
        let signer = Signer::new(&resolver);
        let err = signer
            .sign_hmac(&secret_ref("webhook", AuthType::Hmac, &[]), b"x")
            .unwrap_err();
        assert!(matches!(
            err,
            SignError::Resolve(ResolveError::Unbound { .. })
        ));
    }
}
