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
    crate::release_guest_runtime::prepare_for_running_binary()
        .context("preparing the release guest runtime")?;
    let local_build_requested = mvm_client::launch::runtime_overlay::runtime_overlay_acquire_mode()
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
        prepare_launch_runtime_artifacts,
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

fn prepare_launch_runtime_artifacts() -> Result<()> {
    use mvm_client::launch::runtime_overlay::{
        RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
        runtime_overlay_acquire_mode,
    };

    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let oci_cache_root = cache_root.join("oci");
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime(&oci_cache_root)?;
    let mode = runtime_overlay_acquire_mode();
    match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
                &cache_root,
                version,
                arch,
            )?;
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            let resolver = mvm_fs::overlay::RuntimeOverlayResolver::new(
                cache_root.clone(),
                version.to_string(),
            );
            let overlay_ready =
                mvm_build::runtime_overlay::resolve_cached_runtime_overlay(&resolver, arch).is_ok();
            if !overlay_ready {
                acquire_runtime_overlay(&RuntimeOverlayAcquireParams {
                    cache_root: &cache_root,
                    expected_version: version,
                    arch,
                    source_checkout_root: None,
                })?;
            }
        }
    }

    prepare_initramfs_for_mode_with(
        mode,
        || {
            let workspace_root =
                mvm_client::launch::runtime_overlay::runtime_overlay_source_checkout_root()
                    .context("source guest runtime checkout is unavailable for initramfs")?;
            let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
                &cache_root,
                version,
                arch,
                &workspace_root,
            )
            .context("resolving shared guest runtime for initramfs")?;
            mvm_build::initramfs::build_initramfs_from_guest_runtime(
                &cache_root.join("initramfs"),
                version,
                arch,
                &runtime,
            )
            .context("assembling initramfs from shared guest runtime")?;
            Ok(())
        },
        || {
            let initramfs_cache = cache_root.join("initramfs");
            let set = mvm_build::published_image_set::SetMemberCache::locked();
            if mvm_build::initramfs::resolve_image_set_initramfs(&initramfs_cache, &set, arch)
                .is_err()
            {
                mvm_build::initramfs::download_initramfs(arch, &initramfs_cache)?;
            }
            Ok(())
        },
    )?;
    let libcs = [
        mvm_contract::guest_libc::GuestLibc::Musl,
        mvm_contract::guest_libc::GuestLibc::Glibc,
    ];
    match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            let workspace_root =
                mvm_client::launch::runtime_overlay::runtime_overlay_source_checkout_root()
                    .context("source guest runtime checkout is unavailable for SDK sidecars")?;
            let runtime = mvm_build::guest_runtime::resolve_or_build_source_guest_runtime(
                &cache_root,
                version,
                arch,
                &workspace_root,
            )
            .context("resolving shared guest runtime for SDK sidecars")?;
            for libc in libcs {
                mvm_build::sdk_sidecar::build_sdk_sidecar_from_guest_runtime(
                    &cache_root,
                    version,
                    arch,
                    libc,
                    &runtime,
                )?;
            }
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            let set = mvm_build::published_image_set::SetMemberCache::locked();
            for libc in libcs {
                let ready = mvm_build::sdk_sidecar::image_set_sidecar_resolver(
                    &cache_root,
                    &set,
                    arch,
                    libc,
                )
                .and_then(|resolver| {
                    resolver
                        .resolve(&arch.to_string(), libc)
                        .map_err(mvm_build::sdk_sidecar::SdkSidecarBuildError::from)
                })
                .is_ok();
                if !ready {
                    mvm_build::sdk_sidecar::download_sdk_sidecar(arch, libc, &cache_root)?;
                }
            }
        }
    }
    Ok(())
}

fn prepare_initramfs_for_mode_with<S, P>(
    mode: mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode,
    source: S,
    published: P,
) -> Result<()>
where
    S: FnOnce() -> Result<()>,
    P: FnOnce() -> Result<()>,
{
    use mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode;

    match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => source(),
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => published(),
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
        acquire_bootstrap_artifacts_with, launch_helper_specs, prepare_initramfs_for_mode_with,
        prewarm_host_aux_helpers_for,
    };
    use mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode;
    use std::cell::RefCell;

    #[test]
    fn source_bootstrap_uses_archive_initramfs_without_legacy_builder() {
        let calls = RefCell::new(Vec::new());
        prepare_initramfs_for_mode_with(
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
            || {
                calls.borrow_mut().push("archive initramfs");
                Ok(())
            },
            || {
                calls.borrow_mut().push("legacy cargo builder");
                anyhow::bail!("legacy initramfs builder must not run for source checkout")
            },
        )
        .unwrap();
        assert_eq!(calls.into_inner(), ["archive initramfs"]);
    }

    #[test]
    fn published_bootstrap_retains_published_initramfs_resolution() {
        let calls = RefCell::new(Vec::new());
        prepare_initramfs_for_mode_with(
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            || anyhow::bail!("source guest runtime must not build in published mode"),
            || {
                calls.borrow_mut().push("published initramfs");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.into_inner(), ["published initramfs"]);
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
