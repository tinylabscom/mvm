//! The signing half of writing a bundle, kept apart from the archive format so
//! a signer that holds no key bytes can stand in for one that does.

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Produces the detached Ed25519 signature over a bundle's canonical manifest.
///
/// A key held in memory implements it directly. A signer that never releases
/// its private half — a KMS, an HSM, a remote signing service — implements it
/// by forwarding the bytes, which is why signing can fail and why the key is
/// only ever named by its public half here.
pub trait ManifestSigner {
    /// The public half the signature must verify under.
    fn verifying_key(&self) -> VerifyingKey;

    /// Sign `canonical_manifest`, the exact bytes written as `manifest.json`.
    fn sign_manifest(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]>;
}

impl ManifestSigner for SigningKey {
    fn verifying_key(&self) -> VerifyingKey {
        SigningKey::verifying_key(self)
    }

    fn sign_manifest(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]> {
        let signature: Signature = self.sign(canonical_manifest);
        Ok(signature.to_bytes())
    }
}
