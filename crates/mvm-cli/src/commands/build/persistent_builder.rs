//! Argument translation and presentation for the client-owned builder lifecycle.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use mvm_client::builder::{
    self, PersistentBuilderResult, PersistentBuilderStart, PersistentBuilderSubmit,
};

use crate::commands::Cli;

pub(crate) use mvm_client::builder::start_session_for_contended_build;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[command(subcommand)]
    pub command: Sub,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Sub {
    /// Spawn the persistent builder VM and record the session.
    Start(StartArgs),
    /// Dispatch one flake build into the running persistent VM.
    Submit(SubmitArgs),
    /// Shut down the persistent builder VM.
    Stop(StopArgs),
    /// Print the current session record (if any).
    Status,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct StartArgs {
    /// Host directory bound at `/work`. Defaults to the current directory.
    #[arg(long)]
    pub workspace: Option<PathBuf>,
    /// Guest memory in MiB for the persistent Nix builder.
    #[arg(long, default_value_t = PersistentBuilderStart::default().memory_mib)]
    pub memory_mib: u32,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct SubmitArgs {
    /// Flake reference to build (e.g. `path:/work#packages.default`).
    #[arg(long)]
    pub flake: String,
    /// Flake attribute path. Defaults to `packages.<host_arch>-linux.default`.
    #[arg(long)]
    pub attr: Option<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct StopArgs {}

pub fn run(_cli: &Cli, args: Args) -> Result<()> {
    match args.command {
        Sub::Start(args) => {
            let record = builder::start_persistent_builder(PersistentBuilderStart {
                workspace: args.workspace,
                memory_mib: args.memory_mib,
            })?;
            println!("session_id: {}", record.session_id);
            println!("dispatch_socket: {}", record.dispatch_socket_path.display());
            println!("supervisor_pid: {}", record.supervisor_pid);
        }
        Sub::Submit(args) => {
            print_result(builder::submit_persistent_builder(
                PersistentBuilderSubmit {
                    flake: args.flake,
                    attr: args.attr,
                },
            )?);
        }
        Sub::Stop(_) => {
            for warning in builder::stop_persistent_builder()? {
                eprintln!("{warning}");
            }
        }
        Sub::Status => match builder::persistent_builder_status() {
            Ok(record) => {
                println!("session_id: {}", record.session_id);
                println!("workspace_root: {}", record.workspace_root.display());
                println!("dispatch_socket: {}", record.dispatch_socket_path.display());
                println!(
                    "supervisor_pid: {} ({})",
                    record.supervisor_pid,
                    if record.alive { "alive" } else { "stale" }
                );
                if let Some(last) = record.last_activity_unix_secs {
                    println!("last_activity_unix_secs: {last}");
                }
            }
            Err(error) => println!("no persistent-builder session ({error})"),
        },
    }
    Ok(())
}

fn print_result(result: PersistentBuilderResult) {
    println!("job_id: {}", result.job_id);
    println!("exit_code: {}", result.exit_code);
    println!("build_ms: {}", result.build_ms);
    if !result.stderr_chunks.is_empty() {
        println!("stderr_chunks ({}):", result.stderr_chunks.len());
        for line in result.stderr_chunks {
            println!("  {line}");
        }
    }
    if !result.stderr_tail.is_empty() {
        println!("stderr_tail:");
        println!("{}", result.stderr_tail);
    }
    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }
    if let Some(dir) = result.artifact_dir {
        println!("artifact_dir: {}", dir.display());
    }
    if let Some(summary) = result.artifacts {
        println!(
            "vmlinux: {} ({} bytes)",
            summary.vmlinux.display(),
            summary.vmlinux_bytes
        );
        println!(
            "rootfs.ext4: {} ({} bytes)",
            summary.rootfs.display(),
            summary.rootfs_bytes
        );
        if let Some(manifest) = summary.manifest {
            println!("manifest.json: {}", manifest.display());
        }
    }
}
