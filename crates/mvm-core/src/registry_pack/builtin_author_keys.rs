//! Official bundle-author keys pinned in the client release.
//!
//! An application pack's archive is signed by an Ed25519 author key that is a
//! second root, independent of the keyless publish identity that signs the
//! descriptor. Under the built-in publisher policy this release also pins the
//! official author keys, so the official packs verify without a manual
//! `mvmctl trust add`. The list is chosen by a client release, never by a
//! descriptor: a descriptor's `key_id` only selects among keys already here.

use ed25519_dalek::VerifyingKey;

use crate::plan::bundle::{KeyId, TrustStore, key_id_from_pubkey};
use crate::registry_pack_store::{LoadedPublisherPolicy, PublisherPolicySource};

/// Raw Ed25519 public keys of the official bundle author(s).
pub const OFFICIAL_BUNDLE_AUTHOR_KEYS: &[[u8; 32]] = &[
    // key_id b29ae91c7cbf09b08c3e9291d0a6655b (agent/claude)
    [
        0x7b, 0x69, 0x64, 0x27, 0xbc, 0xdd, 0xb3, 0x40, 0x0d, 0xd3, 0xe3, 0xfc, 0x58, 0x4c, 0x5d,
        0xb4, 0x75, 0x0e, 0x8d, 0x55, 0xfd, 0x43, 0xb0, 0x38, 0x6b, 0xfc, 0xe6, 0x76, 0x2a, 0x29,
        0x6d, 0xe2,
    ],
];

/// Built-in author key ids a client release has disabled. Checked before trust,
/// so a compromised key is dropped by shipping a release.
pub const REVOKED_OFFICIAL_BUNDLE_AUTHOR_KEY_IDS: &[&str] = &[];

impl<T: TrustStore + ?Sized> TrustStore for &T {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        (**self).lookup(key_id)
    }
}

/// Test-only registry so a fixture signed by a throwaway key can stand in for
/// the pinned author, through the real call sites. Never holds a real key.
#[cfg(any(test, feature = "test-support"))]
// Never cleared: process-global by design. Tests rely on nextest running each
// test in its own process, and the keys are throwaway public halves.
static TEST_AUTHOR_KEYS: std::sync::Mutex<Vec<[u8; 32]>> = std::sync::Mutex::new(Vec::new());

/// Pin a throwaway public key as if the release carried it (tests only).
#[cfg(any(test, feature = "test-support"))]
pub fn register_test_author_key(key: [u8; 32]) {
    TEST_AUTHOR_KEYS.lock().unwrap().push(key);
}

fn pinned_keys() -> Vec<[u8; 32]> {
    #[allow(unused_mut)]
    let mut keys = OFFICIAL_BUNDLE_AUTHOR_KEYS.to_vec();
    #[cfg(any(test, feature = "test-support"))]
    keys.extend(TEST_AUTHOR_KEYS.lock().unwrap().iter().copied());
    keys
}

/// The consumer trust store plus the built-in author keys, in memory only.
/// Nothing is written to the consumer store, which stays the one place an
/// operator enrolls or removes keys. A revoked pinned key id is refused first,
/// even when an operator enrolled a copy of it.
pub struct BuiltinAuthorTrust<T> {
    inner: T,
    builtin: Vec<[u8; 32]>,
    revoked: &'static [&'static str],
}

impl<T: TrustStore> BuiltinAuthorTrust<T> {
    /// Compose the view for an application verified under `policy`. An operator
    /// policy file replaces built-in trust wholesale, author keys included.
    pub fn for_policy(inner: T, policy: &LoadedPublisherPolicy) -> Self {
        Self::with_lists(
            inner,
            if policy.source == PublisherPolicySource::OfficialDefault {
                pinned_keys()
            } else {
                Vec::new()
            },
            REVOKED_OFFICIAL_BUNDLE_AUTHOR_KEY_IDS,
        )
    }

    /// Raw store with no pinned keys: the fail-closed view.
    pub fn without_builtin(inner: T) -> Self {
        Self::with_lists(inner, Vec::new(), REVOKED_OFFICIAL_BUNDLE_AUTHOR_KEY_IDS)
    }

    pub(crate) fn with_lists(
        inner: T,
        builtin: Vec<[u8; 32]>,
        revoked: &'static [&'static str],
    ) -> Self {
        Self {
            inner,
            builtin,
            revoked,
        }
    }
}

impl<T: TrustStore> TrustStore for BuiltinAuthorTrust<T> {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        if self.revoked.contains(&key_id.0.as_str()) {
            return None;
        }
        if let Some(key) = self.inner.lookup(key_id) {
            return Some(key);
        }
        self.builtin
            .iter()
            .filter_map(|raw| VerifyingKey::from_bytes(raw).ok())
            .find(|key| &key_id_from_pubkey(key) == key_id)
    }
}

#[cfg(test)]
mod tests;
