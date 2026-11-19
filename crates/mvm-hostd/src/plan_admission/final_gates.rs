//! Host checks and prepared attachments performed after plan admission.

use anyhow::Result;
use mvm_core::policy::PolicyBundle;
use mvm_core::vm_backend::{BackendKind, VmStartConfig};

use super::{
    AdmittedPlan, PreparedBuiltPackRuntime, enforce_admitted_environment, enforce_admitted_shares,
    enforce_sdk_sidecar_attachment, enforce_sdk_sidecar_backend_compatibility,
    populate_audit_substrate, prepare_built_pack_start,
};

/// The post-admission gates between `plan.admitted` and backend start, run in
/// order. On refusal, return the failing stage label for the terminal audit
/// record.
pub(super) fn run_post_admission_gates(
    mut config: VmStartConfig,
    admitted: &AdmittedPlan,
    backend: BackendKind,
    policy_bundle: Option<&PolicyBundle>,
) -> std::result::Result<
    (VmStartConfig, Option<PreparedBuiltPackRuntime>),
    (&'static str, anyhow::Error),
> {
    run_post_admission_gates_for_source(
        &mut config,
        admitted,
        backend,
        policy_bundle,
        ImageSource::Ordinary,
    )
    .map(|runtime| (config, runtime))
}

pub(super) enum ImageSource {
    Ordinary,
    OwnedNative,
}

/// The same admitted checks apply to both ordinary and original-owner starts;
/// only the final image custody differs for a cold native child.
pub(super) fn run_post_admission_gates_for_source(
    config: &mut VmStartConfig,
    admitted: &AdmittedPlan,
    backend: BackendKind,
    policy_bundle: Option<&PolicyBundle>,
    source: ImageSource,
) -> std::result::Result<Option<PreparedBuiltPackRuntime>, (&'static str, anyhow::Error)> {
    if let Err(error) = populate_audit_substrate(config, admitted, policy_bundle) {
        return Err(("audit-substrate", error));
    }
    if let Err(error) = enforce_admitted_shares(&config.volumes, admitted.plan()) {
        return Err(("admitted-shares", error));
    }
    if let Err(error) = enforce_admitted_environment(
        config.kernel_path.as_deref().map(std::path::Path::new),
        admitted.plan(),
    ) {
        return Err(("admitted-environment", error));
    }
    if let Err(error) = enforce_sdk_sidecar_backend_compatibility(backend, admitted.plan()) {
        return Err(("sdk-sidecar", error.into()));
    }
    if let Err(error) = enforce_sdk_sidecar_attachment(
        &config.volumes,
        admitted.plan(),
        mvm_build::guest_libc::recorded_image_libc(std::path::Path::new(&config.rootfs_path)),
    ) {
        return Err(("sdk-sidecar", error));
    }
    if let Err(error) = attach_admitted_extensions(config, admitted) {
        return Err(("extension-attachment", error));
    }
    let runtime = match source {
        ImageSource::Ordinary => prepare_built_pack_start(admitted, config, backend),
        ImageSource::OwnedNative => admitted.built_pack_boot_check().and_then(|check| {
            check
                .map(|check| check.freeze_native_boot(config, backend))
                .transpose()
                .map(Option::flatten)
        }),
    }
    .map_err(|error| ("registry-pack-boot", error))?;
    // Direct admitted callers need the same signed on-disk material as CLI boots.
    super::stash_plan_for_bridge(config).map_err(|error| ("launch-substrate", error))?;
    Ok(runtime)
}

pub(super) fn attach_admitted_extensions(
    config: &mut VmStartConfig,
    admitted: &AdmittedPlan,
) -> Result<()> {
    if !admitted.extensions().is_empty() {
        config.extension_plan_id = Some(admitted.plan_id().0.clone());
    }
    for extension in admitted.extensions() {
        if extension.binding.placement
            != mvm_contract::protocol::extension_pack::ExtensionPlacement::GuestWorkload
        {
            anyhow::bail!(
                "extension placement isolated_controller reached guest attachment after admission"
            );
        }
        let digest = hex::encode(extension.binding.pack_digest);
        let guest = format!("/run/mvm/extensions/{digest}");
        if config.volumes.iter().any(|volume| volume.guest == guest) {
            anyhow::bail!("extension mountpoint collision at {guest}");
        }
        config.volumes.push(mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            volume_label: None,
            host: extension
                .root
                .join(&extension.binding.artifact)
                .display()
                .to_string(),
            guest,
            size: String::new(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
            share_include: Vec::new(),
            share_exclude: Vec::new(),
        });
        config.extensions.push(extension.binding.clone());
    }
    Ok(())
}
