//! Host checks and prepared attachments performed after plan admission.

use super::*;

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
    if let Err(error) = populate_audit_substrate(&mut config, admitted, policy_bundle) {
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
    if let Err(error) = attach_admitted_extensions(&mut config, admitted) {
        return Err(("extension-attachment", error));
    }
    let runtime = prepare_built_pack_start(admitted, &mut config, backend)
        .map_err(|error| ("registry-pack-boot", error))?;
    Ok((config, runtime))
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
        });
        config.extensions.push(extension.binding.clone());
    }
    Ok(())
}
