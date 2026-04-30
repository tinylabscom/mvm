//! `mvmctl exec` — boot a transient microVM, run a single command, tear down.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;

use super::super::env::apple_container::ensure_default_microvm_image;
use super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Pre-built template to boot. If omitted, the bundled
    /// `nix/images/default-tenant/` image is used (built via Nix on first use,
    /// cached at `~/.cache/mvm/default-microvm/`). Each invocation boots a
    /// fresh transient microVM — never the long-running `mvmctl dev` VM.
    #[arg(long)]
    pub template: Option<String>,
    /// vCPU cores (default: 2)
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Memory (supports human-readable: 512M, 1G, …)
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Share a host directory into the guest. Format: `HOST_PATH:/GUEST_PATH[:MODE]`
    /// where MODE is `ro` (default, writes are discarded) or `rw` (writes are
    /// rsynced back to the host directory after the command exits — see ADR-002). Repeatable
    #[arg(short = 'd', long)]
    pub add_dir: Vec<String>,
    /// Environment variable to inject (KEY=VALUE). Repeatable. Overrides any env vars
    /// carried by `--launch-plan`.
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Per-command timeout in seconds (default: 60)
    #[arg(long, default_value = "60")]
    pub timeout: u64,
    /// Path to an mvmforge document — either the `launch.json` artifact
    /// from `mvmforge compile` (top-level `entrypoint`) or the Workload IR
    /// manifest from `mvmforge emit` (top-level `apps[]`). The resolved
    /// entrypoint (command, working_dir, env) is invoked instead of a
    /// trailing argv. Mutually exclusive with the trailing `<ARGV>...`.
    #[arg(long, value_name = "PATH", conflicts_with = "argv")]
    pub launch_plan: Option<String>,
    /// Argv to run inside the guest (use `--` to separate). Required unless
    /// `--launch-plan` is supplied.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "launch_plan"
    )]
    pub argv: Vec<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let target = match (args.launch_plan.as_ref(), args.argv.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--launch-plan and a trailing argv are mutually exclusive");
        }
        (Some(path), true) => {
            let entrypoint = crate::exec::load_launch_plan(std::path::Path::new(path))?;
            crate::exec::ExecTarget::LaunchPlan { entrypoint }
        }
        (None, true) => {
            anyhow::bail!("`mvmctl exec` requires a command (after `--`) or `--launch-plan <PATH>`")
        }
        (None, false) => crate::exec::ExecTarget::Inline { argv: args.argv },
    };
    let memory_mib = parse_human_size(&args.memory).context("Invalid --memory")?;
    let mut add_dirs = Vec::with_capacity(args.add_dir.len());
    for spec in &args.add_dir {
        add_dirs.push(crate::exec::AddDir::parse(spec)?);
    }
    let mut env_pairs = Vec::with_capacity(args.env.len());
    for kv in &args.env {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--env '{kv}': expected KEY=VALUE"))?;
        if k.is_empty() {
            anyhow::bail!("--env '{kv}': KEY must not be empty");
        }
        if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || k.starts_with(|c: char| c.is_ascii_digit())
        {
            anyhow::bail!("--env '{kv}': KEY must match [A-Za-z_][A-Za-z0-9_]* (got '{k}')");
        }
        env_pairs.push((k.to_string(), v.to_string()));
    }
    let image = match args.template {
        Some(name) => crate::exec::ImageSource::Template(name),
        None => {
            ui::info("No --template specified; using bundled default microVM image.");
            let (kernel_path, rootfs_path) = ensure_default_microvm_image()?;
            crate::exec::ImageSource::Prebuilt {
                kernel_path,
                rootfs_path,
                initrd_path: None,
                label: "default-microvm".to_string(),
            }
        }
    };
    let req = crate::exec::ExecRequest {
        image,
        cpus: args.cpus,
        memory_mib,
        add_dirs,
        env: env_pairs,
        target,
        timeout_secs: args.timeout,
    };
    let exit_code = crate::exec::run(req)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}
