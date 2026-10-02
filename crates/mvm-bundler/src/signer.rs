//! Who a bundle is signed by.

use ed25519_dalek::SigningKey;
use mvm_core::plan::bundle::{KeyId, key_id_from_pubkey};

/// The identity a bundle is published under and the key that signs it.
///
/// Exporting takes this instead of reaching for the host key so the same
/// export serves any publisher: the host signer, a release key, a test key.
pub trait BundleSigner {
    /// The publisher recorded in the manifest, for example `host:<hostname>`.
    fn publisher_id(&self) -> String;

    /// The key the manifest is signed under.
    fn signing_key(&self) -> &SigningKey;

    /// The id a consumer looks this publisher's key up by.
    ///
    /// Derived from [`signing_key`](Self::signing_key) unless overridden. An
    /// override that disagrees with the key is refused when the bundle is
    /// sealed, so a manifest can never name a key it was not signed under.
    fn key_id(&self) -> KeyId {
        key_id_from_pubkey(&self.signing_key().verifying_key())
    }
}
