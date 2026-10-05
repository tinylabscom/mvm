//! Who a bundle is signed by.

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use mvm_core::plan::bundle::{KeyId, ManifestSigner, key_id_from_pubkey};

/// The identity a bundle is published under and the key that signs it.
///
/// Exporting takes this instead of reaching for the host key so the same
/// export serves any publisher: the host signer, a release key, a test key, or
/// a KMS that signs on request and never releases its private half. Nothing
/// here asks for private key bytes.
pub trait BundleSigner {
    /// The publisher recorded in the manifest, for example `host:<hostname>`.
    fn publisher_id(&self) -> String;

    /// The public half the manifest signature must verify under.
    fn verifying_key(&self) -> VerifyingKey;

    /// Sign the canonical manifest bytes and return the 64-byte Ed25519
    /// signature. A remote signer that fails returns the error; a signature
    /// that does not verify under [`verifying_key`](Self::verifying_key) is
    /// refused before anything is written.
    fn sign(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]>;

    /// The id a consumer looks this publisher's key up by.
    ///
    /// Derived from [`verifying_key`](Self::verifying_key) unless overridden.
    /// An override that disagrees with the key is refused when the bundle is
    /// sealed, so a manifest can never name a key it was not signed under.
    fn key_id(&self) -> KeyId {
        key_id_from_pubkey(&self.verifying_key())
    }
}

/// Presents a [`BundleSigner`] to the archive writer, which only needs the
/// signing half.
pub(crate) struct AsManifestSigner<'a>(pub(crate) &'a dyn BundleSigner);

impl ManifestSigner for AsManifestSigner<'_> {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    fn sign_manifest(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]> {
        self.0.sign(canonical_manifest)
    }
}
