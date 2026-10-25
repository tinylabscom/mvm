//! Verify and classify a bundle pin before plan synthesis.

use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{BackendImageSupport, HostProtocolSupport};
use mvm_core::plan::bundle::{BundleOrigin, LocalBundleTrustStore, bundle_origin};
use mvm_core::plan::{EnvironmentDescriptor, FsTrustStore, PlanArtifact};

use super::bundle_binding::{BundlePin, PinnedBundle};
use super::policy::{InMemoryBundleResolver, bundle_pin_from_archive};

pub(super) type BundleTrust = LocalBundleTrustStore<FsTrustStore>;

pub(super) struct PreparePinnedBundleParams<'a> {
    pub pin: BundlePin<'a>,
    pub keys_dir: Option<&'a std::path::Path>,
    pub backend_kind: Option<mvm_core::vm_backend::BackendKind>,
    pub image_support: Option<&'a BackendImageSupport>,
    pub host_protocols: &'a HostProtocolSupport,
}

pub(super) struct PreparedPinnedBundle<'a> {
    pub plan_pin: PlanArtifact,
    pub resolver: InMemoryBundleResolver,
    pub trust: BundleTrust,
    pub has_embedded_images: bool,
    pub pinned: PinnedBundle<'a>,
    pub origin: BundleOrigin,
    pub posture: Option<mvm_core::plan::BundleSecurityPosture>,
    pub environment: Option<EnvironmentDescriptor>,
}

pub(super) fn prepare_pinned_bundle(
    params: PreparePinnedBundleParams<'_>,
) -> Result<PreparedPinnedBundle<'_>> {
    let pin = params.pin;
    let path = pin.archive();
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading bundle archive at {}", path.display()))?;
    let release_trust = FsTrustStore::default_path()
        .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?;
    let host_signer = match params.keys_dir {
        Some(dir) => mvm_hostd::audit::host_keypair::load_or_init_at(dir),
        None => mvm_hostd::audit::host_keypair::load_or_init(),
    }
    .context("loading host signer for bundle admission")?;
    let host_key_id = mvm_core::plan::bundle::key_id_from_pubkey(&host_signer.verifying);
    let trust = BundleTrust::new(release_trust, host_key_id.clone(), host_signer.verifying);
    let verified = mvm_core::plan::read_and_verify_bundle(&bytes, &trust)
        .with_context(|| format!("verifying bundle at {}", path.display()))?;
    let origin = bundle_origin(&verified.manifest, &host_key_id, trust.release());
    match origin {
        BundleOrigin::LocalBuild => anyhow::ensure!(
            !pin.is_production(),
            "refusing a local build for a production run: local builds are not release-verified"
        ),
        BundleOrigin::ReleaseVerified => {}
        BundleOrigin::Untrusted => anyhow::bail!(
            "refusing bundle {}: its signed origin is neither release-verified nor a local build signed by this host",
            path.display()
        ),
    }

    if !verified.embedded_image_sets.is_empty() {
        let kind = params.backend_kind.ok_or_else(|| {
            anyhow::anyhow!(
                "bundle {} embeds an image set but no boot backend was selected",
                path.display()
            )
        })?;
        let support = params.image_support.ok_or_else(|| {
            anyhow::anyhow!(
                "backend {} has no Linux-direct embedded image-set contract",
                kind.as_str()
            )
        })?;
        for embedded in &verified.embedded_image_sets {
            mvm_core::plan::check_embedded_image_set_for_backend(
                embedded,
                GuestArch::host(),
                support,
                params.host_protocols,
            )
            .with_context(|| {
                format!(
                    "backend {} refuses embedded image set in {}",
                    kind.as_str(),
                    path.display()
                )
            })?;
        }
    }

    let has_embedded_images = !verified.embedded_image_sets.is_empty();
    let posture = verified.manifest.security_posture().copied();
    let environment = verified.manifest.environment().cloned();
    let plan_pin = bundle_pin_from_archive(&bytes, verified.key_id.clone())
        .with_context(|| format!("extracting signature from bundle at {}", path.display()))?;
    let pinned = PinnedBundle {
        pin,
        sha256: plan_pin.bundle_sha256.clone(),
        signed: verified.manifest,
    };

    Ok(PreparedPinnedBundle {
        plan_pin,
        resolver: InMemoryBundleResolver::new(bytes),
        trust,
        has_embedded_images,
        pinned,
        origin,
        posture,
        environment,
    })
}
