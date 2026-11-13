//! Sealing built artifacts into a signed `.mvmpkg`.
//!
//! The export is `mvm-bundler`'s, re-exported here so a caller names this
//! crate alone. [`HostBundleSigner`] signs under this host's key, which is the
//! key `mvmctl build` signs under.
//! Template export alone does not perform a pack's health boot; a caller must
//! not represent an exported template as a health-checked pack.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, VerifyingKey};
use mvm_contract::pack_spec::PackSpec;
use mvm_core::plan::bundle::{
    ArtifactRole, BundleManifest, ENVIRONMENT_DESCRIPTOR_VERSION, EnvironmentEntrypoint,
};
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::plan::{BundleResources, EnvironmentDescriptor};
use mvm_hostd::audit::host_keypair::{self, HostSigner};

use crate::portable_boot_assets::PreparedPortableBootAssets;

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

    #[test]
    fn provenance_is_recorded_only_for_a_locally_built_template() {
        let local = template_provenance("github:org/app#default", false).unwrap();
        assert_eq!(local.input_kind, InputKind::NixFlake);
        assert_eq!(local.input_ref, "github:org/app#default");
        assert!(template_provenance("github:org/app#default", true).is_none());
        assert!(template_provenance("  ", false).is_none());
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

/// Metadata and retained boot inputs for exporting a template as a signed bundle.
pub struct TemplateExport {
    /// New destination for the signed archive.
    pub out: PathBuf,
    /// Human-readable name recorded in the bundle manifest.
    pub label: Option<String>,
    /// Kernel command line recorded for inspection, not boot-time authority.
    pub cmdline: Option<String>,
    /// Maximum capabilities a later launch may request.
    pub posture: Option<PostureInputs>,
    /// Sizing to record instead of the template's own.
    pub resources: Option<BundleResources>,
    /// Producer input identity bound to the sealed artifact digests.
    pub provenance: Option<BuildProvenance>,
    /// Signed entrypoint and environment requirements.
    pub environment: Option<EnvironmentDescriptor>,
    /// Additional producer documents retained under their archive names.
    pub supplemental_artifacts: Vec<(String, PathBuf)>,
    /// Mark an archive produced under this host's local signing identity.
    pub local_build: bool,
    /// Owned verified boot closure shared with a preceding health boot.
    pub portable_boot_assets: Option<Arc<PreparedPortableBootAssets>>,
}

impl TemplateExport {
    /// Begin an export to a new archive path.
    pub fn new(out: PathBuf) -> Self {
        Self {
            out,
            label: None,
            cmdline: None,
            posture: None,
            resources: None,
            provenance: None,
            environment: None,
            supplemental_artifacts: Vec::new(),
            local_build: false,
            portable_boot_assets: None,
        }
    }
}

fn template_provenance(flake_ref: &str, is_installed_bundle: bool) -> Option<BuildProvenance> {
    if is_installed_bundle || flake_ref.trim().is_empty() {
        return None;
    }
    Some(BuildProvenance {
        input_kind: InputKind::NixFlake,
        input_ref: flake_ref.to_string(),
        lock_digest: None,
        builder_id: None,
        artifacts: Default::default(),
    })
}

/// Stage a signed archive without publishing it; the caller may validate the
/// staged manifest against a health-checked image before calling `publish`.
///
/// # Errors
///
/// Refuses unverifiable installed bundles, mismatched boot assets, or an
/// invalid or incomplete template before writing the destination.
pub fn stage_template(template: &str, export: TemplateExport) -> Result<StagedBundle> {
    let (spec, vmlinux, initrd, rootfs, _rev) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_dispatched(template)
            .with_context(|| format!("loading template {template:?}"))?;

    // An installed bundle carries its own architecture. Re-export may not
    // restamp it as the architecture of this host or discard protected members.
    let installed_arch = match mvm_runtime::vm::template::lifecycle::installed_bundle_archive(
        template,
    )? {
        Some(archive) => {
            let verified = mvm_core::plan::bundle::verify_bundle_file(
                &archive,
                &mvm_core::plan::bundle::FsTrustStore::default_path()?,
            )
            .context("verifying the original bundle before re-export")?;
            anyhow::ensure!(
                !verified.manifest.members.iter().any(|member| matches!(
                    member,
                    mvm_core::plan::bundle::BundleMember::EmbeddedBootAssets { .. }
                        | mvm_core::plan::bundle::BundleMember::EmbeddedCliBootAssets(_)
                        | mvm_core::plan::bundle::BundleMember::CanonicalLinuxProof(_)
                        | mvm_core::plan::bundle::BundleMember::EmbeddedImageSet { .. }
                )),
                "re-export of protected boot members requires original closure custody; refusing to drop publisher evidence"
            );
            Some(verified.manifest.arch)
        }
        None => None,
    };
    let installed_export = installed_arch.is_some();
    let provenance = export
        .provenance
        .or_else(|| template_provenance(&spec.flake_ref, installed_export));
    let source_arch =
        installed_arch.unwrap_or_else(|| mvm_core::arch::GuestArch::host().to_string());
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);
    let verity_bytes = verity_path
        .as_deref()
        .map(|path| {
            std::fs::read(path).with_context(|| format!("reading verity sidecar at {path}"))
        })
        .transpose()?;

    if let Some(assets) = &export.portable_boot_assets {
        anyhow::ensure!(
            !installed_export,
            "cannot replace an installed bundle's closure"
        );
        assets.verify_build_kernel(Path::new(&vmlinux))?;
    }
    let selected_initrd = export
        .portable_boot_assets
        .as_ref()
        .map(|assets| {
            assets
                .initramfs_path()
                .to_str()
                .context("portable initramfs path is not UTF-8")
        })
        .transpose()?
        .or(initrd.as_deref());
    let signer = HostBundleSigner::load()?;
    let supplemental_artifacts: Vec<(&str, &Path)> = export
        .supplemental_artifacts
        .iter()
        .map(|(name, path)| (name.as_str(), path.as_path()))
        .collect();
    let inputs = BundleExportInputs {
        vmlinux: &vmlinux,
        initrd: selected_initrd,
        rootfs: &rootfs,
        verity_bytes: verity_bytes.as_deref(),
        roothash: roothash.as_deref(),
        profile: Some(&spec.profile),
        resources: Some(export.resources.unwrap_or(BundleResources {
            vcpus: u32::from(spec.vcpus),
            mem_mib: spec.mem_mib,
        })),
        arch_label: &source_arch,
        label: export.label,
        cmdline: export.cmdline.as_deref(),
        posture: export.posture,
        provenance,
        environment: export.environment,
        local_build: export.local_build,
        boot_assets: None,
        cli_boot_assets: None,
        canonical_linux_proof: None,
        supplemental_artifacts: &supplemental_artifacts,
        local_composition: None,
        out: &export.out,
        debug_out: None,
    };
    match &export.portable_boot_assets {
        Some(assets) => assets.stage(&inputs, &signer),
        None => stage_bundle_with_signer(&inputs, &signer),
    }
}

/// Seal and publish a template or installed bundle with this host's signing key.
///
/// # Errors
///
/// Refuses invalid inputs or a destination that cannot be published safely.
pub fn export_template(template: &str, export: TemplateExport) -> Result<ExportedBundle> {
    stage_template(template, export)?.publish()
}

/// The sealed pack environment names the exact entrypoint checked at build time.
pub fn pack_environment(spec: &PackSpec, image_argv: Vec<String>) -> EnvironmentDescriptor {
    EnvironmentDescriptor {
        descriptor_version: ENVIRONMENT_DESCRIPTOR_VERSION,
        pack: Some(spec.identity.clone()),
        target: spec.target,
        entrypoint: EnvironmentEntrypoint {
            argv: image_argv,
            working_dir: None,
        },
        resources: Some(spec.resources.clone()),
        policy: None,
        volumes: Vec::new(),
        secret_slots: Vec::new(),
        capabilities: Vec::new(),
        services: Vec::new(),
    }
}

/// Comparable digest set for a health-checked slot and its staged pack archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackArtifactDigests {
    files: Vec<(&'static str, Option<String>)>,
}

impl PackArtifactDigests {
    /// Select the retained release initramfs without changing the slot's own digest.
    ///
    /// # Errors
    ///
    /// Refuses an unavailable or unreadable retained initramfs.
    pub fn selecting_initrd(mut self, path: &Path) -> Result<Self> {
        let digest = mvm_core::crypto::image_verify::sha256_file(path)
            .with_context(|| format!("hashing {}", path.display()))?;
        for (name, value) in &mut self.files {
            if *name == "initrd" {
                *value = Some(digest.clone());
            }
        }
        Ok(self)
    }

    /// Read the current slot's artifact digests before or after a health boot.
    ///
    /// # Errors
    ///
    /// Refuses an incomplete or unreadable slot.
    pub fn read(slot: &str) -> Result<Self> {
        let digests = template_artifact_digests(slot)?;
        Ok(Self::from_digests(
            Some(digests.kernel),
            digests.initrd,
            Some(digests.rootfs),
            digests.verity,
        ))
    }

    /// Extract what the signed staged manifest records for each artifact role.
    pub fn from_manifest(manifest: &BundleManifest) -> Self {
        let digest = |role: ArtifactRole| {
            manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .map(|artifact| artifact.sha256.clone())
        };
        Self::from_digests(
            digest(ArtifactRole::Kernel),
            digest(ArtifactRole::Initrd),
            digest(ArtifactRole::Rootfs),
            digest(ArtifactRole::VerityHashSidecar),
        )
    }

    /// Construct a digest set, including absent roles for refusal tests.
    pub fn from_digests(
        kernel: Option<String>,
        initrd: Option<String>,
        rootfs: Option<String>,
        verity: Option<String>,
    ) -> Self {
        Self {
            files: vec![
                ("kernel", kernel),
                ("initrd", initrd),
                ("rootfs", rootfs),
                ("verity", verity),
            ],
        }
    }

    /// Whether the named artifact is missing.
    pub fn missing(&self, name: &str) -> bool {
        self.files
            .iter()
            .any(|(file, digest)| *file == name && digest.is_none())
    }

    /// Names of artifacts whose health-checked and sealed digests differ.
    pub fn changed(&self, other: &Self) -> Vec<&'static str> {
        self.files
            .iter()
            .zip(&other.files)
            .filter(|(a, b)| a != b)
            .map(|((name, _), _)| *name)
            .collect()
    }
}
