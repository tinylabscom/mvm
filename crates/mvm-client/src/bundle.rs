//! Sealing built artifacts into a signed `.mvmpkg`.
//!
//! The export is `mvm-bundler`'s, re-exported here so a caller names this
//! crate alone. [`HostBundleSigner`] signs under this host's key, which is the
//! key `mvmctl build` signs under.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, VerifyingKey};
use mvm_hostd::audit::host_keypair::{self, HostSigner};

pub use mvm_bundler::{
    BundleExportInputs, BundleSigner, DebugFormat, DebugOutput, ExportedBundle, PostureInputs,
    StagedBundle, export_bundle_with_signer, stage_bundle_with_signer,
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

    fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying
    }

    fn sign(&self, canonical_manifest: &[u8]) -> Result<[u8; 64]> {
        Ok(self.inner.signing.sign(canonical_manifest).to_bytes())
    }
}

/// This host's bundle-signing public key, when the keypair exists.
///
/// The read-only sibling of [`HostBundleSigner::load`]: asking whether a
/// bundle was signed by this host must not mint a host identity to find out,
/// so a missing key reads as `None` where `load` would create one.
pub fn existing_host_verifying_key() -> Result<Option<VerifyingKey>> {
    existing_host_verifying_key_at(&host_keypair::default_keys_dir()?)
}

/// Same as [`existing_host_verifying_key`], from an explicit keys directory.
/// Test seam.
pub fn existing_host_verifying_key_at(keys_dir: &Path) -> Result<Option<VerifyingKey>> {
    let path = keys_dir.join(host_keypair::PUBLIC_FILENAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is not a 32-byte Ed25519 public key", path.display()))?;
    VerifyingKey::from_bytes(&bytes)
        .map(Some)
        .with_context(|| format!("parsing {}", path.display()))
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
            signer.verifying_key(),
            host.verifying,
            "the bundle signer is the host key, not a key of its own"
        );
        let signature = signer.sign(b"manifest").expect("sign");
        assert!(
            ed25519_dalek::Verifier::verify(
                &host.verifying,
                b"manifest",
                &ed25519_dalek::Signature::from_bytes(&signature)
            )
            .is_ok(),
            "a host-key signature verifies under the host's public key"
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

    #[test]
    fn a_host_keypair_that_was_never_created_reads_as_none() {
        let keys = tempfile::tempdir().expect("tempdir");

        assert!(
            existing_host_verifying_key_at(keys.path())
                .expect("read")
                .is_none()
        );
        assert!(
            !keys.path().join(host_keypair::PUBLIC_FILENAME).exists(),
            "the read-only path must not mint a key"
        );
    }

    #[test]
    fn an_existing_host_keypair_reads_as_its_public_half() {
        let keys = tempfile::tempdir().expect("tempdir");
        let signer = host_keypair::load_or_init_at(keys.path()).expect("init");

        let key = existing_host_verifying_key_at(keys.path())
            .expect("read")
            .expect("a created keypair is present");

        assert_eq!(key, signer.verifying);
    }

    #[test]
    fn a_truncated_public_key_is_an_error() {
        let keys = tempfile::tempdir().expect("tempdir");
        std::fs::write(keys.path().join(host_keypair::PUBLIC_FILENAME), [0u8; 16])
            .expect("write truncated key");

        let err = existing_host_verifying_key_at(keys.path()).expect_err("must refuse");

        assert!(
            err.to_string().contains("32-byte"),
            "error names the expected length: {err}"
        );
    }
}

/// SHA-256 of each artifact a template slot's current revision points at, by
/// the role a bundle sealed from it records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateArtifactDigests {
    pub kernel: String,
    pub initrd: Option<String>,
    pub rootfs: String,
    /// The dm-verity hash tree beside the rootfs, when the slot has one.
    pub verity: Option<String>,
}

/// Hash the artifacts `template` (a slot or an installed bundle) resolves to,
/// as they are on disk now.
pub fn template_artifact_digests(template: &str) -> Result<TemplateArtifactDigests> {
    let (_, vmlinux, initrd, rootfs, _) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_dispatched(template)
            .with_context(|| format!("resolving the artifacts of {template}"))?;
    let (verity, _) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);
    let digest = |path: &str| {
        mvm_core::crypto::image_verify::sha256_file(Path::new(path))
            .with_context(|| format!("hashing {path}"))
    };
    Ok(TemplateArtifactDigests {
        kernel: digest(&vmlinux)?,
        initrd: initrd.as_deref().map(digest).transpose()?,
        rootfs: digest(&rootfs)?,
        verity: verity.as_deref().map(digest).transpose()?,
    })
}

/// Give the rootfs of `template`'s current revision the dm-verity pair its
/// guest sidecar asks for, computed here over the installed bytes with the
/// same writer every sealed image uses. Returns the root hash, or `None` when
/// the sidecar does not declare the image sealed.
///
/// A template slot keeps only the rootfs a build produced, so an image that is
/// to be exported as sealed is sealed here, over exactly the bytes the export
/// will read.
pub fn seal_template_rootfs(template: &str) -> Result<Option<String>> {
    let (_, _, _, rootfs, _) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_dispatched(template)
            .with_context(|| format!("resolving the artifacts of {template}"))?;
    let dir = Path::new(&rootfs)
        .parent()
        .with_context(|| format!("rootfs {rootfs} has no parent directory"))?;
    mvm_build::builder_output::seal_declared_rootfs(dir)
        .map_err(|e| anyhow::anyhow!("sealing the rootfs of {template}: {e}"))
}

/// The argv the image of `template`'s current revision runs, as its guest
/// sidecar records it: the same resolution launch admission measures a
/// bundle's signed environment against.
pub fn template_entrypoint(template: &str) -> Result<Vec<String>> {
    let (_, _, _, rootfs, _) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_dispatched(template)
            .with_context(|| format!("resolving the artifacts of {template}"))?;
    match crate::admission::entrypoint_resolve::resolve_for_rootfs(Path::new(&rootfs)) {
        crate::admission::entrypoint_resolve::ResolvedEntrypoint::Known { argv, .. } => Ok(argv),
        unresolved => {
            anyhow::bail!("the image of {template} records no entrypoint: {unresolved:?}")
        }
    }
}
