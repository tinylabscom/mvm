//! `mvmctl machine` — the beginner-facing microVM command group.
//!
//! `machine` is a thin UX layer over mvm's existing primitives, not a parallel
//! runtime. Every subcommand translates into an already-admitted, already-audited
//! execution path so the security posture (signed `ExecutionPlan`, default-deny
//! egress, OCI provenance, receipts) is identical to the lower-level verbs.
//!
//! The flagship verb is `machine run`: boot a fresh VM from an OCI image, run a
//! command, tear down. It routes straight into `vm::exec::run_secure` (the same
//! code path as `mvmctl run --image`), so it inherits deny-all networking by
//! default. Ergonomic opt-in egress (`--net` / `--allow-host`), persistent named
//! machines (`create`/`start`/`exec`/`shell`/`stop`), and `pack` land on top of
//! this group in follow-up work; they are deliberately absent rather than stubbed.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use std::path::PathBuf;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::vm::exec::{RunArgs, RunProfile, run_secure};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: MachineAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum MachineAction {
    /// Boot an OCI image, run a command, then tear the VM down
    Run(MachineRunArgs),
}

/// Ephemeral image-backed run. Mirrors the relevant subset of `mvmctl run`'s
/// flags and translates into the same admitted execution path.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineRunArgs {
    /// OCI image reference to boot (pulled or reused from the local cache).
    #[arg(long, value_name = "REF")]
    pub image: String,
    /// Enable dev-tier outbound networking (broad egress + DNS). Off by
    /// default (deny-all). Narrow it with `--allow-host`.
    #[arg(long)]
    pub net: bool,
    /// Allow egress only to these hosts: `HOST[:PORT]` (PORT defaults to
    /// 443), repeatable. Implies networking and **wins over `--net`**.
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// vCPU cores.
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Memory (supports human-readable: 512M, 1G, ...).
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Security profile for the run.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: RunProfile,
    /// Share a host directory into the guest: `HOST_PATH:/GUEST_PATH[:MODE]`.
    /// MODE defaults to `ro`; `rw` needs `--profile dev` or `permissive`.
    #[arg(short = 'd', long)]
    pub add_dir: Vec<String>,
    /// Explicit environment variable to inject (KEY=VALUE). Repeatable.
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Per-command timeout in seconds. Unset ⇒ no per-command kill.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Write a signed execution receipt to this path.
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Print a redacted machine-readable JSON summary instead of streaming output.
    #[arg(long)]
    pub json: bool,
    /// Validate and explain the effective run plan without booting a VM.
    #[arg(long)]
    pub dry_run: bool,
    /// Argv to run inside the guest (use `--` to separate).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub argv: Vec<String>,
}

impl MachineRunArgs {
    /// Translate into the canonical `mvmctl run` argument shape. `machine run` is
    /// always an image-backed transient run, so the manifest, launch-plan, and
    /// SDK-transport (`--mode`/`--dev`/`--prod`) surfaces are pinned off here —
    /// they are not part of the beginner contract.
    fn into_run_args(self) -> RunArgs {
        RunArgs {
            manifest: None,
            image: Some(self.image),
            net: self.net,
            allow_host: self.allow_host,
            cpus: self.cpus,
            memory: self.memory,
            profile: self.profile,
            add_dir: self.add_dir,
            env: self.env,
            timeout: self.timeout,
            receipt: self.receipt,
            json: self.json,
            dry_run: self.dry_run,
            launch_plan: None,
            mode: None,
            dev: false,
            prod: false,
            argv: self.argv,
            ack_divergence: Vec::new(),
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        MachineAction::Run(run_args) => run_secure(cli, run_args.into_run_args(), cfg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands};
    use clap::Parser;

    /// Minimal standalone parser so `MachineAction` can be exercised without
    /// dragging the whole top-level CLI in for unit-level assertions.
    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        action: MachineAction,
    }

    fn parse(argv: &[&str]) -> Result<MachineRunArgs, clap::Error> {
        let mut full = vec!["machine"];
        full.extend_from_slice(argv);
        TestCli::try_parse_from(full).map(|cli| match cli.action {
            MachineAction::Run(r) => r,
        })
    }

    #[test]
    fn run_parses_image_and_trailing_argv() {
        let args = parse(&["run", "--image", "alpine", "--", "echo", "hello"]).expect("parse");
        assert_eq!(args.image, "alpine");
        assert_eq!(args.argv, vec!["echo", "hello"]);
    }

    #[test]
    fn run_parses_and_forwards_net_flags() {
        let args = parse(&[
            "run",
            "--image",
            "alpine",
            "--net",
            "--allow-host",
            "a.com",
            "--allow-host",
            "b.com:8443",
            "--",
            "true",
        ])
        .expect("parse");
        assert!(args.net);
        assert_eq!(args.allow_host, vec!["a.com", "b.com:8443"]);
        // The flags ride through into the canonical run args unchanged.
        let run = args.into_run_args();
        assert!(run.net);
        assert_eq!(run.allow_host, vec!["a.com", "b.com:8443"]);
    }

    #[test]
    fn run_net_flags_default_off() {
        let args = parse(&["run", "--image", "alpine", "--", "true"]).expect("parse");
        assert!(!args.net);
        assert!(args.allow_host.is_empty());
    }

    #[test]
    fn run_requires_image() {
        let err = parse(&["run", "--", "echo", "hi"]).expect_err("image is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn run_requires_argv() {
        let err = parse(&["run", "--image", "alpine"]).expect_err("argv is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn run_defaults_match_the_lower_level_runner() {
        let args = parse(&["run", "--image", "alpine", "--", "true"]).expect("parse");
        assert_eq!(args.cpus, 2);
        assert_eq!(args.memory, "512M");
        assert_eq!(args.profile, RunProfile::Standard);
        assert!(!args.json);
        assert!(!args.dry_run);
        assert!(args.add_dir.is_empty());
        assert!(args.env.is_empty());
    }

    #[test]
    fn run_accepts_passthrough_flags() {
        let args = parse(&[
            "run",
            "--image",
            "alpine",
            "--cpus",
            "4",
            "--memory",
            "1G",
            "--profile",
            "dev",
            "-d",
            "/host:/work:rw",
            "-e",
            "FOO=bar",
            "--timeout",
            "30",
            "--json",
            "--dry-run",
            "--",
            "uname",
            "-a",
        ])
        .expect("parse");
        assert_eq!(args.cpus, 4);
        assert_eq!(args.memory, "1G");
        assert_eq!(args.profile, RunProfile::Dev);
        assert_eq!(args.add_dir, vec!["/host:/work:rw"]);
        assert_eq!(args.env, vec!["FOO=bar"]);
        assert_eq!(args.timeout, Some(30));
        assert!(args.json);
        assert!(args.dry_run);
        assert_eq!(args.argv, vec!["uname", "-a"]);
    }

    #[test]
    fn translation_is_an_image_backed_transient_run() {
        let args = parse(&[
            "run",
            "--image",
            "alpine",
            "--json",
            "--dry-run",
            "--",
            "echo",
            "hi",
        ])
        .expect("parse");
        let run = args.into_run_args();
        // Image-backed: never a manifest, never a launch plan.
        assert_eq!(run.image.as_deref(), Some("alpine"));
        assert!(run.manifest.is_none());
        assert!(run.launch_plan.is_none());
        // SDK transport surfaces stay off — `machine run` is not an SDK verb.
        assert!(run.mode.is_none());
        assert!(!run.dev);
        assert!(!run.prod);
        assert!(run.ack_divergence.is_empty());
        // User-facing flags flow through untouched.
        assert!(run.json);
        assert!(run.dry_run);
        assert_eq!(run.argv, vec!["echo", "hi"]);
    }

    #[test]
    fn top_level_cli_routes_machine_run() {
        let cli = Cli::try_parse_from([
            "mvmctl", "machine", "run", "--image", "alpine", "--", "echo", "hi",
        ])
        .expect("top-level parse");
        match cli.command {
            Commands::Machine(args) => match args.action {
                MachineAction::Run(run) => {
                    assert_eq!(run.image, "alpine");
                    assert_eq!(run.argv, vec!["echo", "hi"]);
                }
            },
            other => panic!("expected Commands::Machine, got {other:?}"),
        }
    }
}
