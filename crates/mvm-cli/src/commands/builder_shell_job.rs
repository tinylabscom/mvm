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

pub(in crate::commands) fn run(cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
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
    admit_source_builder_image(choice, || {
        crate::commands::env::builder_vm::bootstrap_builder_vm_image()
    })?;
    let result = match choice {
        BuilderBackendChoice::Libkrun => libkrun_shell_builder(cli.verbose)
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
        BuilderBackendChoice::WebLinux => {
            bail!(
                "builder shell jobs are not available for the WebLinux backend; \
                 WebLinux is browser-only; use --builder hvf or --builder libkrun"
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

fn libkrun_shell_builder(verbosity: u8) -> LibkrunBuilderVm {
    LibkrunBuilderVm::default().with_verbose(verbosity > 0)
}

fn admit_source_builder_image(
    choice: BuilderBackendChoice,
    bootstrap: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if choice == BuilderBackendChoice::Libkrun {
        bootstrap().context("admitting the current source builder VM image")?;
    }
    Ok(())
}

fn builder_vm_err(e: BuilderVmError) -> anyhow::Error {
    anyhow::anyhow!("builder VM shell job failed: {e}")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn libkrun_shell_jobs_admit_the_current_source_image() {
        let called = Cell::new(false);
        admit_source_builder_image(BuilderBackendChoice::Libkrun, || {
            called.set(true);
            Ok(())
        })
        .expect("source image admission");
        assert!(called.get());
    }

    #[test]
    fn source_image_admission_failure_refuses_the_shell_job() {
        let err = admit_source_builder_image(BuilderBackendChoice::Libkrun, || {
            anyhow::bail!("fingerprint mismatch")
        })
        .expect_err("admission failure must propagate");
        assert!(err.to_string().contains("admitting the current source"));
    }

    #[test]
    fn hvf_uses_its_dedicated_image_resolver() {
        let called = Cell::new(false);
        admit_source_builder_image(BuilderBackendChoice::Hvf, || {
            called.set(true);
            Ok(())
        })
        .expect("hvf skips source builder bootstrap");
        assert!(!called.get());
    }

    #[test]
    fn verbose_cli_streams_the_libkrun_guest_console() {
        assert!(!libkrun_shell_builder(0).verbose);
        assert!(libkrun_shell_builder(1).verbose);
        assert!(libkrun_shell_builder(u8::MAX).verbose);
    }
}
