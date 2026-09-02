use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_fs::overlay::RuntimeOverlayArtifact;
use std::path::{Path, PathBuf};

pub(crate) struct RuntimeOverlayAcquireParams<'a> {
    pub(crate) cache_root: &'a Path,
    pub(crate) expected_version: &'a str,
    pub(crate) arch: GuestArch,
    pub(crate) source_checkout_root: Option<&'a Path>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeOverlayAcquireMode {
    BuildFromSourceCheckout,
    DownloadPublishedArtifact,
}

pub(crate) const RUNTIME_OVERLAY_ACQUIRE_MODE_ENV: &str = "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE";

pub(crate) fn runtime_overlay_source_checkout_root() -> Option<PathBuf> {
    if !mvm_build::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        return None;
    }
    if let Ok(override_root) = std::env::var("MVM_RUNTIME_OVERLAY_SOURCE_ROOT") {
        let path = PathBuf::from(override_root);
        if path
            .join("nix")
            .join("images")
            .join("runtime-overlay")
            .join("flake.nix")
            .is_file()
        {
            return Some(path);
        }
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    workspace_root
        .join("nix")
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix")
        .is_file()
        .then(|| workspace_root.to_path_buf())
}

pub(crate) fn runtime_overlay_acquire_mode() -> RuntimeOverlayAcquireMode {
    let channel = mvm_build::artifact_acquisition::compiled_channel();
    if let Ok(value) = std::env::var(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV) {
        match value.trim() {
            "build" => return RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
            "download" => return RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            _ => {}
        }
    }
    default_runtime_overlay_mode(channel, runtime_overlay_source_checkout_root().is_some())
}

fn default_runtime_overlay_mode(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    source_available: bool,
) -> RuntimeOverlayAcquireMode {
    match mvm_build::artifact_acquisition::default_acquisition(channel, source_available) {
        mvm_build::artifact_acquisition::DefaultAcquisition::Build => {
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        }
        mvm_build::artifact_acquisition::DefaultAcquisition::Download => {
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        }
    }
}

pub(crate) fn acquire_runtime_overlay(
    params: &RuntimeOverlayAcquireParams<'_>,
) -> Result<RuntimeOverlayArtifact> {
    if let Some(workspace_root) = params.source_checkout_root {
        return build_runtime_overlay_from_source_checkout(
            workspace_root,
            params.cache_root,
            params.expected_version,
            params.arch,
        )
        .with_context(|| {
            format!(
                "build runtime overlay {} for {} from source checkout {}",
                params.expected_version,
                params.arch,
                workspace_root.display()
            )
        });
    }
    mvm_build::runtime_overlay::download_runtime_overlay(
        params.expected_version,
        params.arch,
        params.cache_root,
    )
    .with_context(|| {
        format!(
            "download runtime overlay {} for {} into {}",
            params.expected_version,
            params.arch,
            params.cache_root.display()
        )
    })
}

/// Prepare the channel-appropriate OCI guest runtime before a command reaches
/// materialization. Official binaries acquire published shims; contributor
/// binaries perform a clearly named, source-keyed cold build.
pub(crate) fn prepare_oci_guest_runtime(oci_cache_root: &Path) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    match mvm_build::guest_agent_build::guest_binary_source()? {
        mvm_build::guest_agent_build::GuestBinarySource::SourceCheckout {
            workspace_root,
            cache_key,
        } => {
            if mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, &cache_key, arch)
                .is_some()
            {
                return Ok(());
            }
            crate::ui::notice(
                "Preparing guest runtime from local sources \
                 (cold build for this checkout; cached afterward; use -v for Cargo output)…",
            );
            let started = std::time::Instant::now();
            let spinner = crate::ui::spinner("Compiling guest runtime from local sources…");
            let result = mvm_build::guest_agent_build::resolve_or_build_guest_binaries(
                oci_cache_root,
                &cache_key,
                arch,
                &workspace_root,
            );
            spinner.finish_and_clear();
            result?;
            crate::ui::notice(&format!(
                "Guest runtime ready ({:.1}s; cached for this checkout).",
                started.elapsed().as_secs_f64()
            ));
            return Ok(());
        }
        mvm_build::guest_agent_build::GuestBinarySource::EmbeddedVersion { cache_key } => {
            if mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, &cache_key, arch)
                .is_some()
            {
                return Ok(());
            }
        }
    }

    let cache_root = oci_cache_root.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "OCI cache root {} has no parent for shared release artifacts",
            oci_cache_root.display()
        )
    })?;

    crate::ui::notice(
        "Preparing published guest runtime (first use; downloaded and cached afterward)…",
    );
    acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
        cache_root,
        expected_version: version,
        arch,
        source_checkout_root: None,
    })?;
    if mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, version, arch).is_none()
    {
        anyhow::bail!(
            "published runtime overlay {version} for {arch} did not install the OCI guest runtime"
        );
    }
    Ok(())
}

fn build_runtime_overlay_from_source_checkout(
    workspace_root: &Path,
    cache_root: &Path,
    expected_version: &str,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact> {
    let bins = mvm_build::guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
        cache_root,
        expected_version,
        arch,
        workspace_root,
    )
    .context("build guest binaries for the direct runtime-overlay path")?;
    mvm_build::runtime_overlay::build_runtime_overlay_from_guest_binaries(
        cache_root,
        expected_version,
        arch,
        &bins,
    )
    .context("assemble direct runtime-overlay artifact from source-built guest binaries")
}

#[cfg(test)]
mod acquisition_policy_tests {
    use super::*;

    #[test]
    fn release_channel_defaults_to_download_even_inside_a_checkout() {
        assert_eq!(
            default_runtime_overlay_mode(
                mvm_build::artifact_acquisition::DistributionChannel::Release,
                true,
            ),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }
}
