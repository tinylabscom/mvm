use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_fs::overlay::RuntimeOverlayArtifact;
use std::path::{Path, PathBuf};

pub struct RuntimeOverlayAcquireParams<'a> {
    pub cache_root: &'a Path,
    pub expected_version: &'a str,
    pub arch: GuestArch,
    pub source_checkout_root: Option<&'a Path>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeOverlayAcquireMode {
    BuildFromSourceCheckout,
    DownloadPublishedArtifact,
}

pub const RUNTIME_OVERLAY_ACQUIRE_MODE_ENV: &str = "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE";

const COLD_SOURCE_RUNTIME_NOTICE: &str = "Preparing the MVM guest runtime from local sources (not the OCI base image): \
     building one guest archive for the overlay, initramfs, SDK sidecar, and OCI path; \
     cached afterward. Use -v for Cargo output…";

pub fn runtime_overlay_source_checkout_root() -> Option<PathBuf> {
    mvm_build::image_source::guest_runtime_source_checkout()
}

pub fn runtime_overlay_acquire_mode() -> RuntimeOverlayAcquireMode {
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

/// How one overlay acquisition gets its bytes. Only a source build is a cold
/// build; a published download is never gated by the cold-build policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayAcquisition<'a> {
    BuildFromSource { workspace_root: &'a Path },
    Download,
}

impl OverlayAcquisition<'_> {
    fn for_params<'a>(params: &RuntimeOverlayAcquireParams<'a>) -> OverlayAcquisition<'a> {
        match params.source_checkout_root {
            Some(workspace_root) => OverlayAcquisition::BuildFromSource { workspace_root },
            None => OverlayAcquisition::Download,
        }
    }

    /// The artifact name the cold-build gate is consulted for, if any.
    fn cold_build_artifact(&self) -> Option<&'static str> {
        match self {
            OverlayAcquisition::BuildFromSource { .. } => {
                Some("the MVM guest runtime (runtime overlay)")
            }
            OverlayAcquisition::Download => None,
        }
    }
}

pub fn acquire_runtime_overlay(
    params: &RuntimeOverlayAcquireParams<'_>,
) -> Result<RuntimeOverlayArtifact> {
    let acquisition = OverlayAcquisition::for_params(params);
    if let OverlayAcquisition::BuildFromSource { workspace_root } = acquisition
        && mvm_build::guest_runtime::cached_source_guest_runtime(
            params.cache_root,
            params.expected_version,
            params.arch,
            workspace_root,
        )?
        .is_none()
        && let Some(artifact) = acquisition.cold_build_artifact()
    {
        mvm_runtime::ui::admit_cold_build(artifact).map_err(anyhow::Error::msg)?;
    }
    match acquisition {
        OverlayAcquisition::BuildFromSource { workspace_root } => {
            build_runtime_overlay_from_source_checkout(
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
            })
        }
        OverlayAcquisition::Download => {
            let runtime = mvm_build::guest_runtime::resolve_or_download_guest_runtime(
                params.cache_root,
                params.expected_version,
                params.arch,
            )
            .context("resolve signed released guest runtime for the runtime overlay")?;
            mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
                params.cache_root,
                params.expected_version,
                params.arch,
                &runtime,
            )
            .context("assemble runtime overlay from the signed released guest runtime")
        }
    }
}

/// Prepare the channel-appropriate OCI guest runtime before a command reaches
/// materialization. Official binaries acquire published shims; contributor
/// binaries perform a clearly named, source-keyed cold build.
pub fn prepare_oci_guest_runtime(oci_cache_root: &Path) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    let cache_root = shared_guest_runtime_cache_root(oci_cache_root)?;
    match mvm_build::guest_agent_build::guest_binary_source()? {
        mvm_build::guest_agent_build::GuestBinarySource::SourceCheckout {
            workspace_root,
            cache_key,
        } => {
            let cached_runtime = mvm_build::guest_runtime::cached_source_guest_runtime(
                cache_root,
                version,
                arch,
                &workspace_root,
            )?;
            if cached_runtime.is_none()
                && mvm_build::guest_agent_build::cached_guest_binaries(
                    oci_cache_root,
                    &cache_key,
                    arch,
                )
                .is_some()
            {
                return Ok(());
            }
            let cold = cached_runtime.is_none();
            if cold {
                mvm_runtime::ui::admit_cold_build("the OCI guest runtime")
                    .map_err(anyhow::Error::msg)?;
                // Status goes to stderr: stdout belongs to the workload's own output.
                mvm_runtime::ui::activity::println_above(&format!(
                    "[mvm] {COLD_SOURCE_RUNTIME_NOTICE}"
                ));
            }
            let phase = mvm_runtime::ui::activity::start(if cold {
                "Compiling the guest runtime from local sources"
            } else {
                "Using the cached guest runtime for OCI"
            });
            mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
                cache_root,
                version,
                arch,
                &workspace_root,
            )
            .context("prepare the shared source-built guest runtime for OCI")?;
            phase.finish();
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

    let phase = mvm_runtime::ui::activity::start(
        "Preparing the published guest runtime (first use; downloaded and cached afterward)",
    );
    acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
        cache_root,
        expected_version: version,
        arch,
        source_checkout_root: None,
    })?;
    phase.finish();
    if mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, version, arch).is_none()
    {
        anyhow::bail!(
            "published runtime overlay {version} for {arch} did not install the OCI guest runtime"
        );
    }
    Ok(())
}

fn shared_guest_runtime_cache_root(oci_cache_root: &Path) -> Result<&Path> {
    match oci_cache_root.file_name() {
        Some(name) if name == "oci" => oci_cache_root.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "OCI cache root {} has no parent for shared guest runtime artifacts",
                oci_cache_root.display()
            )
        }),
        Some(_) => Ok(oci_cache_root),
        None => anyhow::bail!(
            "OCI cache root {} does not identify an isolated cache directory",
            oci_cache_root.display()
        ),
    }
}

fn build_runtime_overlay_from_source_checkout(
    workspace_root: &Path,
    cache_root: &Path,
    expected_version: &str,
    arch: GuestArch,
) -> Result<RuntimeOverlayArtifact> {
    let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
        cache_root,
        expected_version,
        arch,
        workspace_root,
    )
    .context("resolve shared guest runtime for the direct runtime-overlay path")?;
    mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        cache_root,
        expected_version,
        arch,
        &runtime,
    )
    .context("assemble direct runtime-overlay artifact from shared guest runtime")
}

#[cfg(test)]
mod acquisition_policy_tests {
    use super::*;

    #[test]
    fn oci_uses_the_same_guest_runtime_cache_root_as_overlay() {
        let base = Path::new("/isolated/mvm/cache");
        let oci = base.join("oci");
        assert_eq!(shared_guest_runtime_cache_root(&oci).unwrap(), base);
        assert_eq!(shared_guest_runtime_cache_root(base).unwrap(), base);
        assert!(shared_guest_runtime_cache_root(Path::new("/")).is_err());
    }

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

    fn params(source_checkout_root: Option<&Path>) -> RuntimeOverlayAcquireParams<'_> {
        RuntimeOverlayAcquireParams {
            cache_root: Path::new("/cache"),
            expected_version: "0.0.0",
            arch: GuestArch::host(),
            source_checkout_root,
        }
    }

    #[test]
    fn a_published_download_is_never_a_cold_build() {
        let acquisition = OverlayAcquisition::for_params(&params(None));
        assert_eq!(acquisition, OverlayAcquisition::Download);
        assert_eq!(acquisition.cold_build_artifact(), None);
    }

    #[test]
    fn a_source_build_consults_the_cold_build_gate() {
        let root = Path::new("/checkout");
        let acquisition = OverlayAcquisition::for_params(&params(Some(root)));
        assert_eq!(
            acquisition,
            OverlayAcquisition::BuildFromSource {
                workspace_root: root
            }
        );
        assert!(
            acquisition
                .cold_build_artifact()
                .is_some_and(|name| name.contains("runtime overlay"))
        );
    }

    #[test]
    fn cold_source_runtime_notice_names_the_artifacts_and_caching() {
        assert!(COLD_SOURCE_RUNTIME_NOTICE.contains("not the OCI base image"));
        assert!(COLD_SOURCE_RUNTIME_NOTICE.contains("one guest archive"));
        assert!(COLD_SOURCE_RUNTIME_NOTICE.contains("overlay, initramfs, SDK sidecar, and OCI"));
        assert!(COLD_SOURCE_RUNTIME_NOTICE.contains("cached afterward"));
        // The prewarm pointer belongs to the one first-run notice the cold
        // build gate prints before this line; repeating it here is noise.
        assert!(!COLD_SOURCE_RUNTIME_NOTICE.contains("bootstrap"));
    }
}
