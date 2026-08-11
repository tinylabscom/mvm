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

/// Full environment bootstrap: host tooling plus the builder VM image and
/// workload kernel. Completion means the next `machine run` does not discover
/// a builder-image or workload-kernel build on its hot path.
pub(in crate::commands) fn bootstrap_environment(production: bool) -> Result<()> {
    run_steps(production)?;
    let kernel = acquire_bootstrap_artifacts_with(
        super::builder_vm::bootstrap_builder_vm_image,
        super::builder_vm::ensure_workload_kernel,
    )?;
    ui::success(&format!(
        "\nBootstrap complete. Builder VM and workload kernel are ready.\nFuture machine runs will reuse these artifacts.\nWorkload kernel: {kernel}"
    ));
    Ok(())
}

fn acquire_bootstrap_artifacts_with<B, K>(builder: B, workload_kernel: K) -> Result<String>
where
    B: FnOnce() -> Result<()>,
    K: FnOnce() -> Result<String>,
{
    ui::info("Preparing builder VM...");
    builder().context("preparing builder VM")?;
    ui::success("Builder VM ready.");

    ui::info("Preparing workload kernel...");
    let kernel = workload_kernel().context("preparing workload kernel")?;
    ui::success("Workload kernel ready.");
    Ok(kernel)
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
    fn bootstrap_acquires_builder_then_workload_kernel() {
        let calls = RefCell::new(Vec::new());
        let kernel = acquire_bootstrap_artifacts_with(
            || {
                calls.borrow_mut().push("builder");
                Ok(())
            },
            || {
                calls.borrow_mut().push("workload");
                Ok("/cache/workload/vmlinux".to_string())
            },
        )
        .unwrap();

        assert_eq!(calls.into_inner(), ["builder", "workload"]);
        assert_eq!(kernel, "/cache/workload/vmlinux");
    }

    #[test]
    fn bootstrap_never_reports_ready_after_builder_failure() {
        let workload_called = std::cell::Cell::new(false);
        let result = acquire_bootstrap_artifacts_with(
            || anyhow::bail!("builder failed"),
            || {
                workload_called.set(true);
                Ok("/cache/workload/vmlinux".to_string())
            },
        );

        assert!(result.is_err());
        assert!(!workload_called.get());
    }

    #[test]
    fn bootstrap_fails_when_workload_kernel_is_not_ready() {
        let result = acquire_bootstrap_artifacts_with(
            || Ok(()),
            || anyhow::bail!("kernel acquisition failed"),
        );

        let err = result.unwrap_err().to_string();
        assert!(err.contains("workload kernel"), "unexpected error: {err}");
    }
}
