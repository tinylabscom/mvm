//! Internal: run a shell script inside the Linux builder VM.
//!
//! This command exposes the existing `BuilderShellJob` / `run_shell_script`
//! machinery to arbitrary in-tree scripts. It is hidden from the user-facing
//! CLI because the builder VM is headless and the contract (`/work` in,
//! `/out` out, `/job/cmd.sh` executed by `mvm-host-vm-init`) is an internal
//! build boundary, not a public shell.
//!
//! Primary use case: running Linux-only cargo gates (`cargo test` / `cargo
//! clippy`) on hosts whose default build backend is the HVF or libkrun
//! builder VM, where there is otherwise no interactive project builder-VM
//! command path.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_build::builder_backend_select::{BuilderBackendChoice, resolve_choice};
use mvm_build::builder_vm::BuilderVmError;
use mvm_build::libkrun_builder::{BuilderShellJob, LibkrunBuilderVm};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    /// Path to the shell script to stage as `/job/cmd.sh` inside the builder VM.
    #[arg(long, value_name = "PATH")]
    pub script: PathBuf,
    /// Host directory bound read-only at `/work` inside the builder VM.
    /// Defaults to the current working directory.
    #[arg(long, value_name = "DIR")]
    pub work_dir: Option<PathBuf>,
    /// Host directory bound read-write at `/out` inside the builder VM.
    /// Defaults to a fresh temporary directory.
    #[arg(long, value_name = "DIR")]
    pub artifact_out: Option<PathBuf>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let script = std::fs::read_to_string(&args.script)
        .with_context(|| format!("reading script {}", args.script.display()))?;
    let work_dir = match args.work_dir {
        Some(p) => p,
        None => std::env::current_dir().context("resolving current working directory")?,
    };
    let artifact_out = match args.artifact_out {
        Some(p) => p,
        None => tempfile::tempdir()
            .context("creating temporary artifact-out directory")?
            .keep(),
    };
    std::fs::create_dir_all(&artifact_out)
        .with_context(|| format!("creating artifact-out {}", artifact_out.display()))?;

    let job = BuilderShellJob {
        work_dir,
        artifact_out,
        script,
        extra_disks: Vec::new(),
    };

    let choice = resolve_choice();
    let result = match choice {
        BuilderBackendChoice::Libkrun => LibkrunBuilderVm::default()
            .run_shell_script(&job)
            .map_err(builder_vm_err)?,
        BuilderBackendChoice::Hvf => {
            let (kernel, rootfs, _closure_nar) =
                crate::commands::build::hvf_builder_image::resolve_hvf_builder_image()
                    .map_err(builder_vm_err)?;
            mvm_runtime::builder_runner::hvf_builder::HvfBuilderVm::new(kernel, rootfs)
                .run_shell_script(&job)
                .map_err(builder_vm_err)?
        }
        BuilderBackendChoice::Qemu => {
            bail!(
                "builder shell jobs are not yet wired for the QEMU backend; \
                 use --builder hvf or --builder libkrun"
            )
        }
    };

    let console_log = result.vm_state_dir.join("console.log");
    if console_log.is_file()
        && let Ok(console) = std::fs::read_to_string(&console_log)
        && !console.is_empty()
    {
        println!("--- builder VM console ---");
        print!("{console}");
        println!("--- end builder VM console ---");
    }

    println!(
        "Shell job succeeded.\n  job_dir: {}\n  vm_state_dir: {}",
        result.job_dir.display(),
        result.vm_state_dir.display()
    );
    Ok(())
}

fn builder_vm_err(e: BuilderVmError) -> anyhow::Error {
    anyhow::anyhow!("builder VM shell job failed: {e}")
}
