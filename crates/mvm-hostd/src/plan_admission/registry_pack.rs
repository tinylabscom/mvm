//! Reverification of signed registry-pack identities at host admission.

use anyhow::{Context, Result};
use mvm_core::plan::{AssetKind, ExecutionPlan};
use mvm_core::vm_backend::{BackendKind, VmStartConfig};

/// Ownership of the authenticated archive for a checked runtime selection.
/// The normal runtime lifecycle rechecks and owns payload snapshots before
/// backend effects, and retains their authenticated closure for the VM.
pub struct PreparedBuiltPackRuntime {
    _manifest: mvm_build::guest_runtime::evidence::VerifiedRuntimeManifest,
    application: Option<PreparedApplicationRuntime>,
    boot_images: Option<mvm_vmm::host::boot_images::FrozenBootImageBytes>,
}

struct PreparedApplicationRuntime {
    candidate: mvm_core::registry_pack::application_bundle::VerifiedApplicationBundle,
    plan: ExecutionPlan,
}

impl std::fmt::Debug for PreparedBuiltPackRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedBuiltPackRuntime")
            .finish_non_exhaustive()
    }
}

impl PreparedBuiltPackRuntime {
    /// Move original snapshots into the concrete runtime before launch.
    /// This transfers bytes, never the original admission's authority.
    pub fn take_boot_images(&mut self) -> Result<mvm_vmm::host::boot_images::FrozenBootImageBytes> {
        self.boot_images
            .take()
            .context("owned native boot requires original frozen image bytes")
    }

    /// Recheck the actual selection immediately before dispatch. This cannot
    /// turn the earlier checked release into a source or alternate release.
    pub fn verify_config(&self, config: &VmStartConfig) -> Result<()> {
        let current = checked_release_runtime(config)?;
        anyhow::ensure!(
            current._manifest.archive_sha256() == self._manifest.archive_sha256(),
            "built pack runtime changed after its final admission check"
        );
        if let Some(application) = &self.application {
            mvm_core::registry_pack_boot::AuthenticatedBootImageExpectations::for_application(
                &application.candidate,
                &application.plan,
                config,
            )?;
        }
        Ok(())
    }
}

/// One-use final image expectations copied from a genuinely admitted plan.
/// This cannot admit a plan, be deserialized, or authorize another launch.
pub struct BuiltPackBootCheck {
    plan: ExecutionPlan,
    plan_json: String,
    backend: BackendKind,
}

impl std::fmt::Debug for BuiltPackBootCheck {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BuiltPackBootCheck")
            .field("plan_id", &self.plan.plan_id)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl super::AdmittedPlan {
    /// Carry only admitted image expectations across a preparation callback.
    /// No unsigned JSON is parsed, and the original admission remains the
    /// authority for grants, replay protection and the audit lifecycle.
    pub fn built_pack_boot_check(&self) -> Result<Option<BuiltPackBootCheck>> {
        if !self
            .plan()
            .asset_identities
            .iter()
            .any(|asset| asset.kind == AssetKind::RegistryPack)
        {
            return Ok(None);
        }
        Ok(Some(BuiltPackBootCheck {
            plan: self.plan().clone(),
            plan_json: serde_json::to_string(self.signed())?,
            backend: self
                .backend
                .context("pack boot handoff requires an admitted backend")?,
        }))
    }
}

impl BuiltPackBootCheck {
    /// Consume the expectations against the actual final configuration. Keep
    /// any returned runtime owner through the normal lifecycle handoff.
    pub fn prepare(
        self,
        config: &mut VmStartConfig,
        backend: BackendKind,
    ) -> Result<Option<PreparedBuiltPackRuntime>> {
        self.check_original_config(config, backend)?;
        verify_registry_pack_boot(&self.plan, config, backend)
    }

    /// Freeze only the original admitted native image, never caller digests.
    pub fn freeze_native_boot(
        self,
        config: &mut VmStartConfig,
        backend: BackendKind,
    ) -> Result<Option<PreparedBuiltPackRuntime>> {
        self.check_original_config(config, backend)?;
        anyhow::ensure!(
            backend == BackendKind::Hvf,
            "image freezing requires owned HVF"
        );
        finalize_registry_images(&self.plan, config, backend, ImagePreparation::Freeze)
    }

    fn check_original_config(&self, config: &VmStartConfig, backend: BackendKind) -> Result<()> {
        anyhow::ensure!(
            backend == self.backend,
            "registry pack backend differs from the admitted backend"
        );
        anyhow::ensure!(
            config.plan_json.as_deref() == Some(self.plan_json.as_str())
                && config.tenant_id.as_deref() == Some(self.plan.tenant.0.as_str()),
            "registry pack final configuration differs from its admitted plan"
        );
        Ok(())
    }
}

/// Check a final admitted image while the normal runtime lifecycle retains
/// payload snapshots and authenticated evidence for the VM lifetime.
pub fn prepare_built_pack_start(
    admitted: &super::AdmittedPlan,
    config: &mut VmStartConfig,
    backend: BackendKind,
) -> Result<Option<PreparedBuiltPackRuntime>> {
    match admitted.built_pack_boot_check()? {
        Some(check) => check.prepare(config, backend),
        None => Ok(None),
    }
}

pub(super) fn verify_runtime_at_dispatch(
    runtime: Option<&PreparedBuiltPackRuntime>,
    config: &VmStartConfig,
    admitted: &super::AdmittedPlan,
    emitter: Option<&crate::audit::emitter::AuditEmitter>,
) -> Result<()> {
    if let Some(runtime) = runtime {
        runtime.verify_config(config).inspect_err(|error| {
            if let Some(emitter) = emitter
                && let Err(audit_error) = emitter.emit_failed(
                    admitted.plan(),
                    "registry-pack-runtime",
                    &format!("{error:#}"),
                )
            {
                tracing::warn!(error = %audit_error, "audit emit_failed failed (non-fatal)");
            }
        })?;
    }
    Ok(())
}

/// Re-open every pack identity under the host's current publisher trust and
/// lock state. A signed plan alone cannot establish that an installed payload
/// is still present, unmodified, and published by a trusted identity.
pub(super) fn verify_registry_pack_assets(plan: &ExecutionPlan) -> Result<()> {
    use mvm_core::registry_pack::AuthenticatedRegistryManifest as _;

    let packs = plan
        .asset_identities
        .iter()
        .filter(|identity| identity.kind == AssetKind::RegistryPack)
        .collect::<Vec<_>>();
    if packs.is_empty() {
        return Ok(());
    }
    let lock =
        mvm_core::registry_pack_store::load_pack_lockfile(&mvm_core::config::pack_lockfile_path())
            .context("loading registry pack lockfile for admission")?;
    let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )
    .context("loading registry pack publisher trust for admission")?
    .policy;
    let cache = mvm_core::config::registry_pack_cache_dir();
    for identity in packs {
        let reference: mvm_core::registry_pack::PackReference = identity
            .name
            .parse()
            .context("invalid registry pack reference in signed plan")?;
        anyhow::ensure!(
            reference.version().is_some(),
            "registry pack identity in signed plan must name an exact version"
        );
        let (_, verified) = mvm_core::registry_pack_store::open_installed_registry_manifest(
            &cache, &lock, &publisher, &reference,
        )
        .with_context(|| format!("verifying registry pack {reference} at admission"))?;
        anyhow::ensure!(
            verified.manifest_sha256().as_str() == identity.digest,
            "registry pack {reference} does not match its signed-plan digest"
        );
    }
    Ok(())
}

/// Revalidate built workload bytes against the final configuration, not just
/// the pack identity admitted earlier. Source packs keep their existing path.
pub(super) fn verify_registry_pack_boot(
    plan: &ExecutionPlan,
    config: &mut VmStartConfig,
    backend: BackendKind,
) -> Result<Option<PreparedBuiltPackRuntime>> {
    finalize_registry_images(plan, config, backend, ImagePreparation::Legacy)
}

enum ImagePreparation {
    Legacy,
    Freeze,
}

fn finalize_registry_images(
    plan: &ExecutionPlan,
    config: &mut VmStartConfig,
    backend: BackendKind,
    preparation: ImagePreparation,
) -> Result<Option<PreparedBuiltPackRuntime>> {
    use mvm_core::registry_pack::{
        AuthenticatedRegistryManifest as _, PackPin, RegistryPackImage, VerifiedRegistryManifest,
    };
    use mvm_core::registry_pack_boot::{AuthenticatedBootImageExpectations, BuiltPackBootContract};

    let mut built = false;
    let mut boot_images = None;
    let mut application = None;
    for identity in plan
        .asset_identities
        .iter()
        .filter(|identity| identity.kind == AssetKind::RegistryPack)
    {
        let reference = identity
            .name
            .parse()
            .context("invalid registry pack reference at final boot verification")?;
        let pin = PackPin::new(
            reference,
            mvm_core::packs::Sha256Hex::new(&identity.digest)?,
        )?;
        let lock = mvm_core::registry_pack_store::load_pack_lockfile(
            &mvm_core::config::pack_lockfile_path(),
        )?;
        let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
            &mvm_core::config::registry_pack_publisher_policy_path(),
        )?
        .policy;
        let (_, verified) = mvm_core::registry_pack_store::open_installed_registry_manifest(
            &mvm_core::config::registry_pack_cache_dir(),
            &lock,
            &publisher,
            pin.reference(),
        )?;
        anyhow::ensure!(
            verified.manifest_sha256() == pin.manifest_sha256(),
            "registry pack no longer matches the admitted pin at backend handoff"
        );
        match verified {
            VerifiedRegistryManifest::Legacy(verified) => {
                if matches!(verified.manifest().image, Some(RegistryPackImage::Built(_))) {
                    anyhow::ensure!(
                        !built,
                        "more than one admitted registry pack declares a boot image"
                    );
                    built = true;
                    let contract = BuiltPackBootContract::open_for_admission(
                        &pin,
                        &mvm_build::stage0_kernel::current_image_set_protocol_support(),
                    )?;
                    contract.verify_image_config(
                        plan,
                        config,
                        mvm_core::arch::GuestArch::host(),
                        backend,
                    )?;
                    if matches!(preparation, ImagePreparation::Freeze) {
                        boot_images =
                            Some(freeze_admitted_images(&contract, plan, config, backend)?);
                    }
                }
            }
            VerifiedRegistryManifest::Application(_) => {
                anyhow::ensure!(
                    !built,
                    "more than one admitted registry pack declares a boot image"
                );
                built = true;
                let registry = mvm_core::plan::bundle::BundleRegistry::default_path()?;
                let store =
                    mvm_core::registry_pack::application_bundle::ApplicationInstallStore::new(
                        mvm_core::config::registry_pack_cache_dir(),
                        mvm_core::config::pack_lockfile_path(),
                        registry.root(),
                    );
                let trust = mvm_core::plan::bundle::FsTrustStore::default_path()?;
                let held = mvm_core::registry_pack::application_bundle::resolve_installed_application_bundle(
                    pin.reference(),
                    &store,
                    &mvm_core::config::registry_pack_publisher_policy_path(),
                    &trust,
                )?;
                let expectations =
                    AuthenticatedBootImageExpectations::for_application(&held, plan, config)?;
                if matches!(preparation, ImagePreparation::Freeze) {
                    boot_images = Some(freeze_image_sources(config, |_| Ok(expectations))?);
                }
                application = Some(PreparedApplicationRuntime {
                    candidate: held,
                    plan: plan.clone(),
                });
            }
        }
    }
    if !built {
        return Ok(None);
    }
    let mut runtime = checked_release_runtime(config)?;
    runtime.application = application;
    runtime.boot_images = boot_images;
    Ok(Some(runtime))
}

fn freeze_admitted_images(
    contract: &mvm_core::registry_pack_boot::BuiltPackBootContract,
    plan: &ExecutionPlan,
    config: &VmStartConfig,
    backend: BackendKind,
) -> Result<mvm_vmm::host::boot_images::FrozenBootImageBytes> {
    freeze_image_sources(config, |root_hash| {
        contract.capture_image_expectations(
            plan,
            config,
            mvm_core::arch::GuestArch::host(),
            backend,
            root_hash,
        )
    })
}

fn freeze_image_sources(
    config: &VmStartConfig,
    capture: impl FnOnce(
        &mut std::fs::File,
    )
        -> Result<mvm_core::registry_pack_boot::AuthenticatedBootImageExpectations>,
) -> Result<mvm_vmm::host::boot_images::FrozenBootImageBytes> {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    let open = |path: &Path| -> Result<std::fs::File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "boot source must be a regular file"
        );
        Ok(file)
    };
    let root_path = Path::new(&config.rootfs_path);
    let directory = root_path.parent().context("rootfs directory missing")?;
    let rootfs = open(root_path)?;
    let verity = open(Path::new(
        config
            .verity_path
            .as_deref()
            .context("verity source missing")?,
    ))?;
    let metadata = open(&directory.join("mvm-meta.json"))?;
    let mut root_hash = open(&directory.join("rootfs.roothash"))?;
    root_hash.seek(SeekFrom::Start(0))?;
    // Acquire every original input before capturing facts; no hash-sidecar reopen.
    let expectations = capture(&mut root_hash)?;
    let private = mvm_core::config::vm_state_dir(&config.name).join("boot-images");
    mvm_core::config::create_private_dir(&private)?;
    mvm_vmm::host::boot_images::FrozenBootImageBytes::prepare(
        expectations,
        mvm_vmm::host::boot_images::BootImageSources {
            rootfs: &rootfs,
            verity: &verity,
            metadata: &metadata,
            root_hash: &root_hash,
            private_dir: &private,
        },
    )
}

fn checked_release_runtime(config: &VmStartConfig) -> Result<PreparedBuiltPackRuntime> {
    anyhow::ensure!(
        !config
            .volumes
            .iter()
            .any(|volume| volume.guest == mvm_core::plan::SDK_SIDECAR_GUEST_PATH),
        "built registry images require signed SDK assembly evidence for SDK sidecar attachments"
    );
    let manifest = mvm_runtime::runtime_evidence::verify_release_runtime_for_launch(
        config,
        mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
    )?;
    Ok(PreparedBuiltPackRuntime {
        _manifest: manifest,
        application: None,
        boot_images: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_runtime_refuses_unsigned_development_and_unbound_sdk() {
        let mut config = VmStartConfig {
            unsigned_runtime_development: true,
            ..Default::default()
        };
        assert!(checked_release_runtime(&config).is_err());
        config.unsigned_runtime_development = false;
        config.volumes.push(mvm_core::vm_backend::VmVolume {
            guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
            ..Default::default()
        });
        assert!(
            checked_release_runtime(&config)
                .unwrap_err()
                .to_string()
                .contains("signed SDK assembly evidence")
        );
    }
}
