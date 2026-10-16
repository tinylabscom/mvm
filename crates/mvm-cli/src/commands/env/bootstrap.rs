//! `mvmctl bootstrap` — full environment setup from scratch.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::bootstrap;
use crate::ui;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::setup::run_setup_steps;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Production mode (skip Homebrew, assume Linux with apt)
    #[arg(long)]
    pub production: bool,

    /// Allow building the builder VM image from a local `mvm-images` checkout for this invocation.
    /// Sets MVM_ALLOW_LOCAL_BUILDER_BUILD=1 for the process.
    #[arg(long)]
    pub allow_local_builder_build: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    bootstrap_environment(args.production)
}

/// Full environment bootstrap: host tooling plus every shared artifact needed
/// before an OCI workload can launch.
pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    // Warm standbys and paused machines are encrypted at rest; a host that
    // has never held a snapshot key gets one here rather than at its first
    // pause.
    crate::commands::shared::ensure_snapshot_key()?;
    let mode = mvm_client::launch::runtime_overlay::runtime_overlay_acquire_mode();
    // A release binary's guest runtime is the one its release ships, acquired
    // once up front. A source build has its tree; the image set has none.
    let release =
        if publishes_its_guest_runtime(mvm_build::artifact_acquisition::compiled_channel(), mode) {
            Some(
                crate::release_guest_runtime::prepare_for_running_binary()
                    .context("preparing the release guest runtime")?,
            )
        } else {
            None
        };
    let local_build_requested = mode
        == mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        || mvm_build::image_source::configured_images_dir().is_some();
    let kernel = acquire_bootstrap_artifacts_with(
        || {
            if local_build_requested {
                super::builder_vm::bootstrap_builder_vm_image()
            } else {
                Ok(())
            }
        },
        prewarm_host_aux_helpers,
        || prepare_launch_runtime_artifacts(release.as_ref()),
        prepare_pair_launch_artifacts,
        super::builder_vm::prepare_workload_kernel,
    )?;
    ui::success(&format!(
        "\nBootstrap complete. Builder VM, host helpers, workload kernel, runtime overlay, initramfs, and OCI guest shims are ready.\nSDK sidecars for glibc and musl are ready. Future machine runs will reuse prepared artifacts.\nWorkload kernel: {kernel}"
    ));
    Ok(())
}

fn acquire_bootstrap_artifacts_with<B, A, R, P, K>(
    builder: B,
    host_helpers: A,
    runtime: R,
    pair: P,
    workload_kernel: K,
) -> Result<String>
where
    B: FnOnce() -> Result<()>,
    A: FnOnce() -> Result<()>,
    K: FnOnce() -> Result<String>,
    R: FnOnce() -> Result<()>,
    P: FnOnce() -> Result<()>,
{
    ui::info("Preparing builder VM...");
    builder().context("preparing builder VM")?;
    ui::success("Builder VM ready.");

    ui::info("Preparing host helper binaries...");
    host_helpers().context("preparing host helper binaries")?;
    ui::success("Host helper binaries ready.");

    ui::info("Preparing shared guest runtime...");
    runtime().context("preparing shared guest runtime")?;
    ui::success("Shared guest runtime ready.");

    // Announced inside the step: only a selected image checkout gives it work.
    pair().context("preparing pair-stamped launch artifacts")?;

    ui::info("Preparing workload kernel...");
    let kernel = workload_kernel().context("preparing workload kernel")?;
    ui::success("Workload kernel ready.");
    Ok(kernel)
}

/// Whether this binary takes its guest runtime from a release: a release
/// binary does, unless it was explicitly asked to build one (which then fails
/// for want of a checkout). A source build always assembles its own tree's.
fn publishes_its_guest_runtime(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    mode: mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode,
) -> bool {
    channel == mvm_build::artifact_acquisition::DistributionChannel::Release
        && mode
            == mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode::DownloadPublishedArtifact
}

/// Where bootstrap's launch-time pieces — the runtime overlay, the initramfs,
/// both SDK sidecars and the OCI guest runtime — come from. The image set
/// carries none of them, so there are exactly two answers.
#[derive(Debug, Clone, Copy)]
enum PiecesSource<'a> {
    /// Assembled from this checkout's guest-runtime archive.
    SourceCheckout,
    /// Assembled from the guest runtime this release binary's own release
    /// ships, already authenticated.
    ReleaseArchive(&'a mvm_build::guest_bins::release::ReleaseGuestRuntime),
}

/// A release binary assembles from the guest runtime bootstrap acquired; every
/// other build assembles from its tree.
fn pieces_source(
    release: Option<&mvm_build::guest_bins::release::ReleaseGuestRuntime>,
) -> PiecesSource<'_> {
    match release {
        Some(release) => PiecesSource::ReleaseArchive(release),
        None => PiecesSource::SourceCheckout,
    }
}

fn prepare_launch_runtime_artifacts(
    release: Option<&mvm_build::guest_bins::release::ReleaseGuestRuntime>,
) -> Result<()> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let oci =
        || mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime(&cache_root.join("oci"));
    prepare_runtime_pieces_with(
        pieces_source(release),
        || {
            oci()?;
            prewarm_pieces_from_source(&cache_root, version, arch)
        },
        |release| prewarm_pieces_from_release(&cache_root, version, arch, release),
    )
}

/// Assemble every piece from the published guest runtime, and install the OCI
/// guest runtime from it. An archive that fails here fails bootstrap; there is
/// no other source to fall back to.
fn prewarm_pieces_from_release(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    release: &mvm_build::guest_bins::release::ReleaseGuestRuntime,
) -> Result<()> {
    let assembly = mvm_build::runtime_pieces::assemble_release_runtime_pieces(
        cache_root,
        version,
        arch,
        &release.archive,
    )
    .with_context(|| {
        format!(
            "assembling the launch pieces from the release guest runtime {}",
            release.archive.display()
        )
    })?;
    ui::notice(&release_assembly_line(release, &assembly.runtime.digest));
    Ok(())
}

/// What bootstrap says once a release binary's pieces are assembled. Printed
/// whatever the verbosity, because the fresh-install smoke greps a plain
/// `mvmctl bootstrap` for it.
fn release_assembly_line(
    release: &mvm_build::guest_bins::release::ReleaseGuestRuntime,
    digest: &str,
) -> String {
    let name = release
        .archive
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(
        "Runtime overlay, initramfs and SDK sidecars assembled from release guest runtime {name} ({}).",
        mvm_build::runtime_pieces::short_digest(digest)
    )
}

/// Assemble the overlay, the initramfs and both SDK sidecars from this
/// checkout's guest-runtime archive, resolved once.
fn prewarm_pieces_from_source(
    cache_root: &std::path::Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> Result<()> {
    let workspace_root =
        mvm_client::launch::runtime_overlay::runtime_overlay_source_checkout_root()
            .context("the source guest runtime needs an mvm source checkout")?;
    let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
        cache_root,
        version,
        arch,
        &workspace_root,
    )
    .context("resolving the shared guest runtime")?;
    mvm_build::runtime_pieces::assemble_runtime_pieces(cache_root, version, arch, &runtime)?;
    ui::info(&format!(
        "Runtime overlay, initramfs and SDK sidecars assembled from guest runtime archive {}.",
        mvm_build::runtime_pieces::short_digest(&runtime.digest)
    ));
    Ok(())
}

/// Run exactly one acquisition for `source`: a source build never downloads,
/// and a published runtime is assembled from its own archive only.
fn prepare_runtime_pieces_with<'a, S, R>(
    source: PiecesSource<'a>,
    from_source: S,
    from_release: R,
) -> Result<()>
where
    S: FnOnce() -> Result<()>,
    R: FnOnce(&'a mvm_build::guest_bins::release::ReleaseGuestRuntime) -> Result<()>,
{
    match source {
        PiecesSource::SourceCheckout => from_source(),
        PiecesSource::ReleaseArchive(release) => from_release(release),
    }
}

/// Resolve every per-VM host helper the launch path probes at spawn. Published
/// helpers are the default; source compilation requires the same explicit
/// local-build selectors as the rest of bootstrap.
fn prewarm_host_aux_helpers() -> Result<()> {
    let host = mvm_vmm::host::aux_bin::HostProcess::current();
    let local_build_requested =
        mvm_build::artifact_acquisition::local_guest_runtime_build_requested()
            || mvm_build::image_source::configured_images_dir().is_some();
    if !local_build_requested {
        let source_identity_mismatch =
            !crate::update::published_host_helpers_match_current_build()?;
        let missing = source_identity_mismatch
            || launch_helper_specs()
                .iter()
                .any(|spec| mvm_vmm::host::aux_bin::resolve_verified_for(spec, &host).is_err());
        if missing {
            crate::update::prepare_release_host_binaries().with_context(|| {
                format!(
                    "published host helpers are unavailable; explicitly compile local helpers with \
                     `{}=build mvmctl bootstrap`",
                    mvm_build::artifact_acquisition::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV
                )
            })?;
        }
    }
    prewarm_host_aux_helpers_for(&host);
    Ok(())
}

fn prewarm_host_aux_helpers_for(host: &mvm_vmm::host::aux_bin::HostProcess) {
    use mvm_vmm::host::aux_bin;

    // A release binary, a library embedder, or any process that did not
    // declare source helper builds ships or manages its own helpers: nothing
    // this process may build, so nothing to prewarm.
    if !host.builds_helpers_from_source() {
        return;
    }
    for spec in launch_helper_specs() {
        let bin = spec.bin;
        // `available` is the resolver's own gate: true only when resolution
        // succeeds or a source build can produce the helper. Skipping a false
        // answer keeps this a no-op wherever the resolver would decline
        // rather than build.
        if !aux_bin::available(&spec) {
            continue;
        }
        // Prewarm is best-effort: a helper whose source build cannot succeed
        // on this host (e.g. the libkrun supervisor without libkrun headers)
        // must not abort bootstrap for launches that never spawn it. The
        // launch that actually needs the helper surfaces the build error at
        // spawn time, where the failure is on the path that required it.
        if let Err(error) = aux_bin::resolve_verified_for(&spec, host) {
            crate::ui::warn(&format!(
                "prewarming the {bin} helper failed: {error:#} — it builds when a                  launch that needs it runs"
            ));
        }
    }
}

/// The per-VM host helper binaries a launch probes at spawn, limited to the
/// ones this platform's backends spawn: the network endpoint everywhere, and
/// on macOS the supervisors the libkrun default path and the HVF builder path
/// spawn.
fn launch_helper_specs() -> Vec<mvm_vmm::host::aux_bin::AuxBin<'static>> {
    use mvm_vmm::host::aux_bin::AuxBin;
    use mvm_vmm::host::codesign::RequiredEntitlement;

    let mut specs = vec![AuxBin::new(
        "mvm-network-endpoint",
        "MVM_SUBSTITUTION_ENDPOINT_PATH",
        "mvm-hostd",
    )];
    if cfg!(target_os = "macos") {
        specs.push(
            AuxBin::new("mvm-hvf-supervisor", "MVM_HVF_SUPERVISOR_PATH", "mvm-hostd")
                .signed_with(RequiredEntitlement::Hypervisor),
        );
        specs.push(
            AuxBin::new(
                "mvm-libkrun-supervisor",
                "MVM_LIBKRUN_SUPERVISOR_PATH",
                "mvm-hostd",
            )
            .requiring_features(&["libkrun-sys"])
            .signed_with(RequiredEntitlement::Hypervisor),
        );
    }
    specs
}

/// Under a selected image checkout, install the pair-stamped runtime overlay
/// and SDK sidecars the boot path's stamp checks look for. Without a selected
/// checkout the pair arms never run at boot, so there is nothing to do.
fn prepare_pair_launch_artifacts() -> Result<()> {
    super::builder_vm::with_pair_artifact_source(|pair| match pair {
        Some(pair) => {
            ui::info("Preparing pair-stamped runtime overlay...");
            mvm_client::launch::runtime_source::prepare_pair_launch_artifacts(pair)
                .context("installing the pair-stamped runtime overlay")?;
            ui::success("Pair-stamped runtime overlay ready.");
            Ok(())
        }
        None => Ok(()),
    })
}

/// Run the host-tooling bootstrap steps only (no builder-image prefetch) —
/// exposed so `dev` can re-bootstrap without going through the dispatcher.
pub(super) fn run_steps(production: bool) -> Result<()> {
    ui::info("Bootstrapping full environment...\n");

    if !production {
        bootstrap::check_package_manager()?;
    }

    // Dev mode is libkrun/HVF on Apple Silicon macOS or
    // native Firecracker on Linux KVM. There is no Lima VM to provision
    // here; setup_steps below handles the remaining assets.
    bootstrap::hint_libkrun_if_useful();

    // Default sizing for the builder VM; CLI-level overrides ride the
    // setup path.
    run_setup_steps(false, 8, 16)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PiecesSource, acquire_bootstrap_artifacts_with, launch_helper_specs, pieces_source,
        prepare_runtime_pieces_with, prewarm_host_aux_helpers_for, prewarm_pieces_from_release,
        publishes_its_guest_runtime, release_assembly_line,
    };
    use mvm_build::guest_bins::release::{ReleaseGuestRuntime, ReleaseGuestRuntimeOrigin};
    use mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode;
    use std::cell::RefCell;

    fn release_runtime(archive: std::path::PathBuf) -> ReleaseGuestRuntime {
        ReleaseGuestRuntime {
            archive,
            manifest: mvm_build::guest_bins::GuestBinsManifest {
                schema_version: mvm_build::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
                version: "9.9.9".to_string(),
                guest_source_fingerprint: "a".repeat(64),
                sdk_cdylib_source_fingerprint: "b".repeat(64),
                source: mvm_build::image_source::RepoIdentity {
                    commit: mvm_core::image_set::GitCommit::new("c".repeat(40)).unwrap(),
                    worktree: mvm_core::image_set::WorktreeState::Clean,
                },
                files: Default::default(),
                assemblies: Default::default(),
            },
            origin: ReleaseGuestRuntimeOrigin::Installed,
        }
    }

    /// Run the acquisition `source` selects and say which one ran.
    fn ran(source: PiecesSource<'_>) -> Vec<&'static str> {
        let calls = RefCell::new(Vec::new());
        prepare_runtime_pieces_with(
            source,
            || {
                calls.borrow_mut().push("source archive");
                Ok(())
            },
            |_| {
                calls.borrow_mut().push("release archive");
                Ok(())
            },
        )
        .unwrap();
        calls.into_inner()
    }

    #[test]
    fn source_bootstrap_assembles_from_the_archive_and_downloads_nothing() {
        assert_eq!(ran(pieces_source(None)), ["source archive"]);
    }

    #[test]
    fn a_release_binary_assembles_from_its_own_guest_runtime_and_never_the_image_set() {
        let release = release_runtime("/r/mvm-guest-bins-v9.9.9.tar.gz".into());
        assert_eq!(ran(pieces_source(Some(&release))), ["release archive"]);
    }

    /// Only a release binary in its default mode acquires a published guest
    /// runtime. A source build assembles its tree's in either mode — the image
    /// set it used to install from in download mode carries none — and a
    /// release binary asked to build has no tree, which the source arm reports.
    #[test]
    fn only_a_release_binary_takes_a_published_guest_runtime() {
        use mvm_build::artifact_acquisition::DistributionChannel;
        assert!(publishes_its_guest_runtime(
            DistributionChannel::Release,
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact
        ));
        assert!(!publishes_its_guest_runtime(
            DistributionChannel::Release,
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout
        ));
        for mode in [
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
        ] {
            assert!(!publishes_its_guest_runtime(
                DistributionChannel::Source,
                mode
            ));
        }
    }

    /// A release archive that does not verify fails the bootstrap step, and
    /// leaves nothing a launch would read as adopted.
    #[test]
    fn a_release_archive_that_fails_verification_fails_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("mvm-guest-bins-v9.9.9.tar.gz");
        std::fs::write(&archive, b"not a guest runtime").unwrap();
        let cache = dir.path().join("cache");
        let arch = mvm_core::arch::GuestArch::host();
        let error = prewarm_pieces_from_release(&cache, "9.9.9", arch, &release_runtime(archive))
            .expect_err("an unverifiable archive must refuse");
        assert!(
            format!("{error:#}").contains("release guest runtime"),
            "{error:#}"
        );
        assert_eq!(
            mvm_build::runtime_pieces::adopted_release_archive(&cache, "9.9.9", arch).unwrap(),
            None
        );
    }

    #[test]
    fn the_release_assembly_line_names_the_archive_and_its_digest() {
        let line = release_assembly_line(
            &release_runtime("/r/guest-runtime/mvm-guest-bins-v9.9.9.tar.gz".into()),
            &"f".repeat(64),
        );
        assert_eq!(
            line,
            "Runtime overlay, initramfs and SDK sidecars assembled from release guest runtime \
             mvm-guest-bins-v9.9.9.tar.gz (ffffffffffff)."
        );
    }

    #[test]
    fn bootstrap_acquires_every_artifact_in_launch_path_order() {
        let calls = RefCell::new(Vec::new());
        let kernel = acquire_bootstrap_artifacts_with(
            || {
                calls.borrow_mut().push("builder");
                Ok(())
            },
            || {
                calls.borrow_mut().push("helpers");
                Ok(())
            },
            || {
                calls.borrow_mut().push("runtime");
                Ok(())
            },
            || {
                calls.borrow_mut().push("pair");
                Ok(())
            },
            || {
                calls.borrow_mut().push("workload");
                Ok("/cache/workload/vmlinux".to_string())
            },
        )
        .unwrap();

        assert_eq!(
            calls.into_inner(),
            ["builder", "helpers", "runtime", "pair", "workload"]
        );
        assert_eq!(kernel, "/cache/workload/vmlinux");
    }

    #[test]
    fn bootstrap_never_reports_ready_after_builder_failure() {
        let runtime_called = std::cell::Cell::new(false);
        let result = acquire_bootstrap_artifacts_with(
            || anyhow::bail!("builder failed"),
            || Ok(()),
            || {
                runtime_called.set(true);
                Ok(())
            },
            || Ok(()),
            || Ok("/cache/workload/vmlinux".to_string()),
        );

        assert!(result.is_err());
        assert!(!runtime_called.get());
    }

    #[test]
    fn bootstrap_fails_when_workload_kernel_is_not_ready() {
        let result = acquire_bootstrap_artifacts_with(
            || Ok(()),
            || Ok(()),
            || Ok(()),
            || Ok(()),
            || anyhow::bail!("kernel acquisition failed"),
        );

        let err = result.unwrap_err().to_string();
        assert!(err.contains("workload kernel"), "unexpected error: {err}");
    }

    #[test]
    fn bootstrap_fails_when_shared_runtime_is_not_ready() {
        let workload_called = std::cell::Cell::new(false);
        let result = acquire_bootstrap_artifacts_with(
            || Ok(()),
            || Ok(()),
            || anyhow::bail!("overlay unavailable"),
            || Ok(()),
            || {
                workload_called.set(true);
                Ok("/cache/workload/vmlinux".to_string())
            },
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("shared guest runtime"),
            "unexpected error: {err}"
        );
        assert!(!workload_called.get());
    }

    #[test]
    fn bootstrap_fails_when_host_helpers_are_not_ready() {
        let runtime_called = std::cell::Cell::new(false);
        let helpers_called = std::cell::Cell::new(false);
        let error = acquire_bootstrap_artifacts_with(
            || Ok(()),
            || {
                helpers_called.set(true);
                anyhow::bail!("helper unavailable")
            },
            || {
                runtime_called.set(true);
                Ok(())
            },
            || Ok(()),
            || Ok("/cache/workload/vmlinux".to_string()),
        )
        .expect_err("missing host helpers must fail bootstrap");

        assert!(helpers_called.get());
        assert!(!runtime_called.get());
        assert!(error.to_string().contains("host helper"));
    }

    #[test]
    fn helper_prewarm_is_a_no_op_for_a_process_that_may_not_build_helpers() {
        let host = mvm_vmm::host::aux_bin::HostProcess::undeclared();
        assert!(!host.builds_helpers_from_source());
        // The decline must be a quiet no-op.
        prewarm_host_aux_helpers_for(&host);
    }

    #[test]
    fn helper_specs_cover_this_platforms_spawn_paths() {
        let bins: Vec<&str> = launch_helper_specs().iter().map(|spec| spec.bin).collect();
        assert!(bins.contains(&"mvm-network-endpoint"), "{bins:?}");
        if cfg!(target_os = "macos") {
            assert!(bins.contains(&"mvm-hvf-supervisor"), "{bins:?}");
            assert!(bins.contains(&"mvm-libkrun-supervisor"), "{bins:?}");
        }
    }

    /// Probe-answering scripts stand in for installed helpers through the
    /// per-helper path override: prewarming verifies them and must not try
    /// to build.
    #[cfg(unix)]
    #[test]
    fn helper_prewarm_verifies_installed_helpers_without_building() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        for spec in launch_helper_specs() {
            let helper = dir.path().join(spec.bin);
            std::fs::write(
                &helper,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' '{}'",
                    mvm_vmm::host::helper_contract::probe_response(spec.bin).trim_end()
                ),
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
            env.set(spec.env_var, &helper);
        }

        let host =
            mvm_vmm::host::aux_bin::HostProcess::undeclared().allowing_helper_builds_from_source();
        // Installed helpers verify without a build.
        prewarm_host_aux_helpers_for(&host);
    }
}
