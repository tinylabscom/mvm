use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_fs::overlay::RuntimeOverlayArtifact;
use std::path::{Path, PathBuf};

/// One assembly of the runtime overlay from a source checkout's guest
/// runtime. A release binary assembles its overlay in `mvmctl bootstrap` from
/// its release's guest runtime instead; there is no published overlay to
/// download.
pub struct RuntimeOverlayAcquireParams<'a> {
    pub cache_root: &'a Path,
    pub expected_version: &'a str,
    pub arch: GuestArch,
    pub source_checkout_root: &'a Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeOverlayAcquireMode {
    BuildFromSourceCheckout,
    DownloadPublishedArtifact,
}

pub const RUNTIME_OVERLAY_ACQUIRE_MODE_ENV: &str =
    mvm_build::artifact_acquisition::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV;

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

/// The artifact the cold-build gate is consulted for when the overlay has to
/// be compiled.
const OVERLAY_COLD_BUILD_ARTIFACT: &str = "the MVM guest runtime (runtime overlay)";

/// Assemble the runtime overlay from the checkout's guest runtime, building
/// the archive first when it is not cached (behind the cold-build gate).
pub fn acquire_runtime_overlay(
    params: &RuntimeOverlayAcquireParams<'_>,
) -> Result<RuntimeOverlayArtifact> {
    let workspace_root = params.source_checkout_root;
    if mvm_build::guest_runtime::cached_source_guest_runtime(
        params.cache_root,
        params.expected_version,
        params.arch,
        workspace_root,
    )?
    .is_none()
    {
        mvm_runtime::ui::admit_cold_build(OVERLAY_COLD_BUILD_ARTIFACT)
            .map_err(anyhow::Error::msg)?;
    }
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

/// The selected overlay and evidence for the archive that produced its bytes.
pub struct AcquiredRuntimeOverlay {
    pub artifact: RuntimeOverlayArtifact,
    pub release_proof: Option<mvm_core::protocol::runtime_release::RuntimeReleaseProof>,
    pub unsigned_source: bool,
    pub source_archive_sha256: Option<String>,
}

/// Read prepared artifacts only. Acquisition belongs to explicit preparation,
/// never to startup. A rejected release must not fall through to source.
pub fn acquire_runtime_overlay_for_launch(
    resolver: &mvm_fs::overlay::RuntimeOverlayResolver,
    arch: GuestArch,
) -> Result<AcquiredRuntimeOverlay> {
    let version = resolver.expected_version();
    let proof = mvm_build::guest_runtime::cached_runtime_release_proof(
        resolver.cache_root(),
        version,
        arch,
    )?;
    let (declaration, source_archive_sha256) = if let Some(proof) = &proof {
        (
            mvm_build::guest_runtime::evidence::verify_runtime_release_proof(proof, version, arch)?
                .declaration(arch)?
                .clone(),
            None,
        )
    } else {
        let checked = mvm_build::guest_runtime::source::check_source_runtime(
            resolver.cache_root(),
            version,
            arch,
        )?;
        (
            checked.declaration(arch)?.clone(),
            Some(checked.archive_sha256().to_owned()),
        )
    };
    let artifact = mvm_build::runtime_overlay::resolve_or_seed_from_default_cache(resolver, arch)?;
    anyhow::ensure!(
        artifact.roothash == declaration.overlay_roothash
            && mvm_core::crypto::verified_digest::sha256_file_verified(&artifact.overlay_ext4)?
                == declaration.overlay_sha256
            && mvm_core::crypto::verified_digest::sha256_file_verified(&artifact.sidecar)?
                == declaration.overlay_verity_sha256,
        "prepared runtime overlay differs from the selected archive"
    );
    Ok(AcquiredRuntimeOverlay {
        artifact,
        unsigned_source: proof.is_none(),
        release_proof: proof,
        source_archive_sha256,
    })
}

/// Prepare the explicitly selected OCI guest runtime.
///
/// This is an acquisition API for `bootstrap` and `image pull`, never for the
/// latency-sensitive launch path. With `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build`
/// a source-built CLI compiles it from its checkout, keyed by the source.
/// Otherwise it is keyed by this CLI's version: a source build assembles it
/// from its own tree, and a release binary has it from `mvmctl bootstrap`,
/// which installs it from the guest runtime its release ships. The image set
/// carries no guest runtime, so nothing is downloaded from it.
pub fn prepare_oci_guest_runtime(oci_cache_root: &Path) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    let cache_root = shared_guest_runtime_cache_root(oci_cache_root)?;
    if runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout {
        return prepare_source_oci_guest_runtime(oci_cache_root, cache_root, version, arch);
    }

    if mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, version, arch).is_some()
    {
        return Ok(());
    }
    if let Some(workspace_root) = runtime_overlay_source_checkout_root() {
        return prepare_versioned_source_oci_guest_runtime(
            cache_root,
            &workspace_root,
            version,
            arch,
        );
    }
    anyhow::bail!(
        "the guest runtime of mvmctl {version} is not prepared; run `mvmctl bootstrap` first, \
         which installs it from the guest runtime this release ships"
    )
}

/// A source build's OCI guest runtime under its version key, assembled from
/// the guest-runtime archive its own tree builds: the one guest runtime a
/// source build has, now that the image set carries none.
fn prepare_versioned_source_oci_guest_runtime(
    cache_root: &Path,
    workspace_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<()> {
    let cold = mvm_build::guest_runtime::cached_source_guest_runtime(
        cache_root,
        version,
        arch,
        workspace_root,
    )?
    .is_none();
    if cold {
        mvm_runtime::ui::admit_cold_build("the OCI guest runtime").map_err(anyhow::Error::msg)?;
        mvm_runtime::ui::activity::println_above(&format!("[mvm] {COLD_SOURCE_RUNTIME_NOTICE}"));
    }
    let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
        cache_root,
        version,
        arch,
        workspace_root,
    )
    .context("prepare the source-built guest runtime for OCI")?;
    mvm_build::runtime_pieces::install_oci_guest_runtime(cache_root, version, arch, &runtime)
        .context("install the OCI guest runtime from this checkout's guest runtime")?;
    Ok(())
}

/// Require the OCI guest runtime without compiling or downloading anything.
///
/// Every launch call uses this boundary. A missing runtime is preparation work,
/// so the command fails with the explicit acquisition verb instead of hiding
/// an unbounded build or download inside `machine run`.
pub fn require_prepared_oci_guest_runtime(oci_cache_root: &Path) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    if runtime_overlay_acquire_mode() == RuntimeOverlayAcquireMode::BuildFromSourceCheckout {
        let cache_root = shared_guest_runtime_cache_root(oci_cache_root)?;
        let source = mvm_build::guest_agent_build::guest_binary_source()?;
        if let mvm_build::guest_agent_build::GuestBinarySource::SourceCheckout {
            workspace_root,
            cache_key,
        } = source
            && (mvm_build::guest_runtime::cached_source_guest_runtime(
                cache_root,
                version,
                arch,
                &workspace_root,
            )?
            .is_some()
                || mvm_build::guest_agent_build::cached_guest_binaries(
                    oci_cache_root,
                    &cache_key,
                    arch,
                )
                .is_some())
        {
            return Ok(());
        }
        anyhow::bail!(
            "the local OCI guest runtime is not prepared; run \
             `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap` first"
        );
    }

    if mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, version, arch).is_some()
    {
        return Ok(());
    }
    anyhow::bail!("the published OCI guest runtime is not prepared; run `mvmctl bootstrap` first")
}

fn prepare_source_oci_guest_runtime(
    oci_cache_root: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<()> {
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
        mvm_build::guest_agent_build::GuestBinarySource::EmbeddedVersion { .. } => {}
    }
    anyhow::bail!(
        "a local OCI guest runtime build requires a source-built mvmctl; \
         unset {RUNTIME_OVERLAY_ACQUIRE_MODE_ENV} or set it to `download`"
    )
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

    /// Outside an explicit source build, a prepared OCI guest runtime is
    /// reused from its version key with nothing compiled or downloaded, and
    /// nothing is installed from the image set.
    #[test]
    fn a_prepared_versioned_oci_guest_runtime_is_reused_without_the_image_set() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            "file:///nonexistent/mvm-image-set",
        );
        let home = tempfile::tempdir().expect("temporary home");
        let oci = home.path().join("cache/oci");
        let staged = home.path().join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        for name in [
            "mvm-guest-agent",
            "mvm-guest-netinit",
            "mvm-egress-client",
            "mvm-oci-entrypoint",
        ] {
            std::fs::write(
                staged.join(name),
                mvm_build::guest_agent_build::fake_static_elf(GuestArch::host(), name.as_bytes()),
            )
            .unwrap();
        }
        mvm_build::guest_agent_build::install_into_cache(
            mvm_build::guest_agent_build::GuestRuntimeBinaryPaths {
                agent: &staged.join("mvm-guest-agent"),
                netinit: &staged.join("mvm-guest-netinit"),
                egress_client: &staged.join("mvm-egress-client"),
                entrypoint_runner: &staged.join("mvm-oci-entrypoint"),
            },
            &oci,
            env!("CARGO_PKG_VERSION"),
            GuestArch::host(),
        )
        .unwrap();

        prepare_oci_guest_runtime(&oci).expect("a prepared runtime is reused");
        assert!(
            !home.path().join("cache/image-set").exists(),
            "no image-set member may be installed"
        );
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

    #[test]
    fn source_channel_defaults_to_download_even_inside_a_checkout() {
        assert_eq!(
            default_runtime_overlay_mode(
                mvm_build::artifact_acquisition::DistributionChannel::Source,
                true,
            ),
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        );
    }

    #[test]
    fn launch_refuses_an_unprepared_published_runtime_without_acquiring_it() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        let home = tempfile::tempdir().expect("temporary home");
        let oci = home.path().join("cache/oci");
        std::fs::create_dir_all(&oci).expect("create OCI cache");
        let started = std::time::Instant::now();
        let error =
            require_prepared_oci_guest_runtime(&oci).expect_err("a launch cache miss must fail");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(300),
            "runtime cache refusal exceeded the startup budget"
        );
        let message = error.to_string();
        assert!(message.contains("mvmctl bootstrap"), "{message}");
    }

    #[test]
    fn the_overlay_cold_build_gate_names_the_runtime_overlay() {
        assert!(OVERLAY_COLD_BUILD_ARTIFACT.contains("runtime overlay"));
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
