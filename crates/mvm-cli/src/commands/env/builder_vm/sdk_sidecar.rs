#[cfg(feature = "builder-vm")]
use super::*;

/// Build the checkout's SDK sidecar inside Stage 0 and atomically install it
/// into the same cache layout the launch resolver reads.
#[cfg(feature = "builder-vm")]
pub(crate) fn build_sdk_sidecar_via_stage0(
    workspace_root: &std::path::Path,
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    verbose: bool,
) -> Result<mvm_fs::sdk_sidecar::SdkSidecarArtifact> {
    if arch != mvm_core::arch::GuestArch::host() {
        anyhow::bail!(
            "Stage 0 builds SDK sidecars for its host architecture only: requested {arch}, host is {}",
            mvm_core::arch::GuestArch::host()
        );
    }

    let fingerprint = mvm_build::guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)
        .context("fingerprinting SDK sidecar source inputs")?;
    let arch_dir = arch.to_string();
    let stage0_lock_scope = cache_root.join("builder-vm").join(&arch_dir);
    let lock_scope = stage0_lock_scope.to_string_lossy();
    let _stage0_guard = acquire_stage0_lock(&lock_scope)?;
    let removed = sweep_stage0_staging_siblings(&stage0_lock_scope)?;
    if removed > 0 {
        ui::info(&format!(
            "Removed {removed} incomplete Stage 0 artifact build director{} from an earlier interruption.",
            if removed == 1 { "y" } else { "ies" }
        ));
    }

    let staging_dir = unique_builder_vm_stage0_staging_dir(&stage0_lock_scope)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let request =
        super::stage0_artifact::Stage0ArtifactBuild::builder(workspace_root, &staging_dir)
            .build_attr("sdk-sidecar-image")
            .output_mode("sdk-sidecar")
            .verbose(verbose)
            .build()?;

    ui::info(&format!(
        "Building SDK sidecar for {arch} via Stage 0 from {}...",
        workspace_root.display()
    ));
    if let Err(error) = request.run() {
        let _ = std::fs::remove_dir_all(&staging_dir);
        return Err(error.context("building SDK sidecar via Stage 0"));
    }

    let installed = mvm_build::sdk_sidecar::install_source_built_sidecar(
        &staging_dir,
        cache_root,
        version,
        arch,
        &fingerprint,
    )
    .context("validating and installing the source-built SDK sidecar");
    let _ = std::fs::remove_dir_all(&staging_dir);
    installed
}
