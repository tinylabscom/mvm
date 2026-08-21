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
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    bootstrap_environment(args.production)
}

/// Full environment bootstrap: host tooling plus every shared artifact needed
/// before an OCI workload can launch.
pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    let kernel = acquire_bootstrap_artifacts_with(
        super::builder_vm::bootstrap_builder_vm_image,
        prepare_launch_runtime_artifacts,
        super::builder_vm::ensure_workload_kernel,
    )?;
    ui::success(&format!(
        "\nBootstrap complete. Builder VM, workload kernel, runtime overlay, initramfs, and OCI guest shims are ready.\nFuture machine runs will reuse these artifacts.\nWorkload kernel: {kernel}"
    ));
    Ok(())
}

fn acquire_bootstrap_artifacts_with<B, R, K>(
    builder: B,
    runtime: R,
    workload_kernel: K,
) -> Result<String>
where
    B: FnOnce() -> Result<()>,
    K: FnOnce() -> Result<String>,
    R: FnOnce() -> Result<()>,
{
    ui::info("Preparing builder VM...");
    builder().context("preparing builder VM")?;
    ui::success("Builder VM ready.");

    ui::info("Preparing shared guest runtime...");
    runtime().context("preparing shared guest runtime")?;
    ui::success("Shared guest runtime ready.");
    ui::info("Preparing workload kernel...");
    let kernel = workload_kernel().context("preparing workload kernel")?;
    ui::success("Workload kernel ready.");
    Ok(kernel)
}

fn prepare_launch_runtime_artifacts() -> Result<()> {
    use crate::commands::runtime_overlay::{
        RuntimeOverlayAcquireMode, RuntimeOverlayAcquireParams, acquire_runtime_overlay,
        runtime_overlay_acquire_mode,
    };

    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let oci_cache_root = cache_root.join("oci");
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    crate::commands::runtime_overlay::prepare_oci_guest_runtime(&oci_cache_root)?;
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
                mvm_build::runtime_overlay::resolve_or_seed_from_default_cache(&resolver, arch)
                    .is_ok();
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

    mvm_build::initramfs::resolve_or_build_local_initramfs(
        &mvm_runtime::build_env::RuntimeBuildEnv,
        &cache_root.join("initramfs"),
        version,
        arch,
    )?;
    Ok(())
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
    use super::acquire_bootstrap_artifacts_with;
    use std::cell::RefCell;

    #[test]
    fn bootstrap_acquires_runtime_before_workload_kernel() {
        let calls = RefCell::new(Vec::new());
        let kernel = acquire_bootstrap_artifacts_with(
            || {
                calls.borrow_mut().push("builder");
                Ok(())
            },
            || {
                calls.borrow_mut().push("runtime");
                Ok(())
            },
            || {
                calls.borrow_mut().push("workload");
                Ok("/cache/workload/vmlinux".to_string())
            },
        )
        .unwrap();

        assert_eq!(calls.into_inner(), ["builder", "runtime", "workload"]);
        assert_eq!(kernel, "/cache/workload/vmlinux");
    }

    #[test]
    fn bootstrap_never_reports_ready_after_builder_failure() {
        let runtime_called = std::cell::Cell::new(false);
        let result = acquire_bootstrap_artifacts_with(
            || anyhow::bail!("builder failed"),
            || {
                runtime_called.set(true);
                Ok(())
            },
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
            || anyhow::bail!("overlay unavailable"),
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
}
