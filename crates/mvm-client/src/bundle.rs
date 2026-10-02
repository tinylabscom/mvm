//! Sealing built artifacts into a signed `.mvmpkg`.
//!
//! The export is `mvm-bundler`'s, re-exported here so a caller names this
//! crate alone. [`HostBundleSigner`] signs under this host's key, which is the
//! key `mvmctl bundle export` signs under.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mvm_hostd::audit::host_keypair::{self, HostSigner};

pub use mvm_bundler::{
    BundleExportInputs, BundleSigner, DebugFormat, DebugOutput, ExportedBundle,
    export_bundle_with_signer,
};

/// Signs bundles as this host: the Ed25519 key under the mvm home's `keys/`,
/// published as `host:<hostname>`.
#[derive(Debug)]
pub struct HostBundleSigner {
    inner: HostSigner,
}

impl HostBundleSigner {
    /// Load the host key, creating it on first use.
    pub fn load() -> Result<Self> {
        host_keypair::load_or_init()
            .map(Self::from)
            .context("loading host signer for bundle sign")
    }

    /// Same as [`load`](Self::load), from an explicit keys directory.
    pub fn load_at(keys_dir: &Path) -> Result<Self> {
        host_keypair::load_or_init_at(keys_dir)
            .map(Self::from)
            .context("loading host signer for bundle sign")
    }
}

impl From<HostSigner> for HostBundleSigner {
    fn from(inner: HostSigner) -> Self {
        Self { inner }
    }
}

impl BundleSigner for HostBundleSigner {
    fn publisher_id(&self) -> String {
        host_keypair::host_signer_id()
    }

    fn signing_key(&self) -> &SigningKey {
        &self.inner.signing
    }
}

#[cfg(test)]
mod tests {
    use mvm_core::plan::bundle::key_id_from_pubkey;

    use super::*;

    #[test]
    fn signs_as_the_host_key_in_the_keys_dir() {
        let keys = tempfile::tempdir().expect("tempdir");

        let signer = HostBundleSigner::load_at(keys.path()).expect("load");

        let host = host_keypair::load_or_init_at(keys.path()).expect("reload");
        assert_eq!(
            signer.signing_key().to_bytes(),
            host.signing.to_bytes(),
            "the bundle signer is the host key, not a key of its own"
        );
        assert_eq!(signer.key_id(), key_id_from_pubkey(&host.verifying));
        assert_eq!(signer.publisher_id(), host_keypair::host_signer_id());
    }

    #[test]
    fn debug_output_does_not_print_the_key() {
        let keys = tempfile::tempdir().expect("tempdir");
        let signer = HostBundleSigner::load_at(keys.path()).expect("load");

        let rendered = format!("{signer:?}");

        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
