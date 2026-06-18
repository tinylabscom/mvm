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
//! default. Persistent machine specs (`create`/`ls`/`inspect`/`rm`) store the
//! declarative image/network/profile shape for later lifecycle starts; `start`
//! boots that spec through the same admitted OCI-backed substrate as the
//! transient runner, while `exec` / `shell` / `stop` stay thin wrappers over
//! the existing running-VM surfaces.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use mvm_core::atomic_io::atomic_write;
use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;
use mvm_core::{config, naming};

use super::Cli;
use super::vm::exec::{RunArgs, RunProfile, run_secure};
use super::vm::{console, down};

const MACHINE_SPEC_SCHEMA_VERSION: u32 = 1;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: MachineAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum MachineAction {
    /// Boot an OCI image, run a command, then tear the VM down
    Run(MachineRunArgs),
    /// Create or update a persistent named machine spec without booting it
    Create(MachineCreateArgs),
    /// List persistent named machine specs
    #[command(name = "ls")]
    Ls(MachineListArgs),
    /// Show one persistent named machine spec
    Inspect(MachineInspectArgs),
    /// Remove one persistent named machine spec
    #[command(name = "rm")]
    Rm(MachineRemoveArgs),
    /// Boot a persistent named machine without running a one-shot command
    Start(MachineStartArgs),
    /// Run a command inside an already-started named machine
    Exec(MachineExecArgs),
    /// Attach an interactive shell/console to an already-started named machine
    Shell(MachineShellArgs),
    /// Stop an already-started named machine
    Stop(MachineStopArgs),
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

/// Declarative persistent machine spec. Runtime state lives elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineSpec {
    schema_version: u32,
    name: String,
    image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_digest: Option<String>,
    net: bool,
    allow_host: Vec<String>,
    cpus: u32,
    memory: String,
    profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_started_at: Option<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineCreateArgs {
    /// Persistent machine name. Lowercase alphanumeric plus hyphens.
    #[arg(long)]
    pub name: String,
    /// OCI image reference to boot when the machine lifecycle starts.
    #[arg(long, value_name = "REF")]
    pub image: String,
    /// Enable dev-tier outbound networking for this machine.
    #[arg(long)]
    pub net: bool,
    /// Allow egress only to these hosts: `HOST[:PORT]` (repeatable).
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// vCPU cores for lifecycle starts.
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Memory for lifecycle starts (supports human-readable: 512M, 1G, ...).
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Security profile for lifecycle starts.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: RunProfile,
    /// Overwrite an existing machine spec.
    #[arg(long)]
    pub force: bool,
    /// Print the persisted spec as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineListArgs {
    /// Print machine specs as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineInspectArgs {
    /// Persistent machine name.
    pub name: String,
    /// Print the machine spec as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineRemoveArgs {
    /// Persistent machine name.
    pub name: String,
    /// Confirm deletion.
    #[arg(long)]
    pub yes: bool,
    /// Print a JSON deletion summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineStartArgs {
    /// Persistent machine name.
    #[arg(long)]
    pub name: String,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineExecArgs {
    /// Persistent machine name.
    #[arg(long)]
    pub name: String,
    /// Bypass the sealed-image accessibility check.
    #[arg(long)]
    pub force: bool,
    /// Argv to run inside the guest (use `--` to separate).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub argv: Vec<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineShellArgs {
    /// Persistent machine name.
    #[arg(long)]
    pub name: String,
    /// Bypass the sealed-image accessibility check.
    #[arg(long)]
    pub force: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineStopArgs {
    /// Persistent machine name.
    #[arg(long)]
    pub name: String,
}

#[derive(Debug, Serialize)]
struct MachineRemoveSummary {
    name: String,
    removed: bool,
}

impl MachineCreateArgs {
    fn into_spec(self) -> Result<MachineSpec> {
        validate_machine_name(&self.name)?;
        super::shared::resolve_run_network_policy(self.net, &self.allow_host)?;
        let _ = parse_human_size(&self.memory).context("invalid machine memory")?;
        Ok(MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: self.name,
            image: self.image,
            resolved_digest: None,
            net: self.net,
            allow_host: self.allow_host,
            cpus: self.cpus,
            memory: self.memory,
            profile: run_profile_name(self.profile).to_string(),
            created_at: Some(mvm_core::time::utc_now()),
            last_started_at: None,
        })
    }
}

fn run_profile_name(profile: RunProfile) -> &'static str {
    match profile {
        RunProfile::Restrictive => "restrictive",
        RunProfile::Standard => "standard",
        RunProfile::Dev => "dev",
        RunProfile::Permissive => "permissive",
    }
}

fn validate_machine_name(name: &str) -> Result<()> {
    naming::validate_id(name, "machine name")
}

fn save_machine_spec(spec: &MachineSpec, force: bool) -> Result<()> {
    let path = config::machine_spec_path(&spec.name);
    if path.exists() && !force {
        bail!(
            "machine {:?} already exists; pass --force to overwrite",
            spec.name
        );
    }
    let bytes = serde_json::to_vec_pretty(spec).context("serializing machine spec")?;
    atomic_write(&path, &bytes)
        .with_context(|| format!("writing machine spec {}", path.display()))?;
    Ok(())
}

fn overwrite_machine_spec(spec: &MachineSpec) -> Result<()> {
    let path = config::machine_spec_path(&spec.name);
    let bytes = serde_json::to_vec_pretty(spec).context("serializing machine spec")?;
    atomic_write(&path, &bytes)
        .with_context(|| format!("writing machine spec {}", path.display()))?;
    Ok(())
}

fn load_machine_spec(name: &str) -> Result<MachineSpec> {
    validate_machine_name(name)?;
    load_machine_spec_from_path(&config::machine_spec_path(name))
}

fn load_machine_spec_from_path(path: &Path) -> Result<MachineSpec> {
    let bytes =
        fs::read(path).with_context(|| format!("reading machine spec {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing machine spec {}", path.display()))
}

fn list_machine_specs() -> Result<Vec<MachineSpec>> {
    let root = config::machine_state_root();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut specs = Vec::new();
    for entry in fs::read_dir(&root).with_context(|| format!("listing {}", root.display()))? {
        let entry = entry.with_context(|| format!("reading entry in {}", root.display()))?;
        if !entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?
            .is_dir()
        {
            continue;
        }
        let spec_path = entry.path().join("machine.json");
        if spec_path.exists() {
            specs.push(load_machine_spec_from_path(&spec_path)?);
        }
    }
    specs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(specs)
}

fn remove_machine_spec(name: &str, yes: bool) -> Result<MachineRemoveSummary> {
    validate_machine_name(name)?;
    if !yes {
        bail!("refusing to remove machine {:?} without --yes", name);
    }
    let dir = config::machine_state_dir(name);
    if !dir.exists() {
        bail!("machine {:?} does not exist", name);
    }
    fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    Ok(MachineRemoveSummary {
        name: name.to_string(),
        removed: true,
    })
}

fn create_machine(args: MachineCreateArgs) -> Result<()> {
    let json = args.json;
    let force = args.force;
    let spec = args.into_spec()?;
    save_machine_spec(&spec, force)?;
    mvm_core::audit_emit!(
        ConfigChange,
        vm: &spec.name,
        "action=machine.create force={force}"
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&spec)?);
    } else {
        println!("created machine {}", spec.name);
    }
    Ok(())
}

fn list_machines(args: MachineListArgs) -> Result<()> {
    let specs = list_machine_specs()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&specs)?);
    } else if specs.is_empty() {
        println!("no machines");
    } else {
        for spec in specs {
            println!("{}\t{}", spec.name, spec.image);
        }
    }
    Ok(())
}

fn inspect_machine(args: MachineInspectArgs) -> Result<()> {
    let spec = load_machine_spec(&args.name)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&spec)?);
    } else {
        println!("name: {}", spec.name);
        println!("image: {}", spec.image);
        if let Some(resolved_digest) = spec.resolved_digest.as_deref() {
            println!("resolved-digest: {resolved_digest}");
        }
        println!("net: {}", spec.net);
        println!("allow-host: {}", spec.allow_host.join(","));
        println!("cpus: {}", spec.cpus);
        println!("memory: {}", spec.memory);
        println!("profile: {}", spec.profile);
        if let Some(created_at) = spec.created_at.as_deref() {
            println!("created-at: {created_at}");
        }
        if let Some(last_started_at) = spec.last_started_at.as_deref() {
            println!("last-started-at: {last_started_at}");
        }
    }
    Ok(())
}

fn remove_machine(args: MachineRemoveArgs) -> Result<()> {
    let json = args.json;
    let summary = remove_machine_spec(&args.name, args.yes)?;
    mvm_core::audit_emit!(ConfigChange, vm: &summary.name, "action=machine.rm");
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("removed machine {}", summary.name);
    }
    Ok(())
}

fn ensure_machine_spec_exists(name: &str) -> Result<MachineSpec> {
    load_machine_spec(name).with_context(|| format!("loading machine spec for {name:?}"))
}

fn mark_machine_started(spec: &mut MachineSpec, resolved_digest: String) {
    spec.resolved_digest = Some(resolved_digest);
    spec.last_started_at = Some(mvm_core::time::utc_now());
}

fn start_machine(args: MachineStartArgs) -> Result<()> {
    let mut spec = ensure_machine_spec_exists(&args.name)?;
    let network_policy = super::shared::resolve_run_network_policy(spec.net, &spec.allow_host)?;
    let memory_mib = parse_human_size(&spec.memory).context("invalid machine memory")?;
    let cached = super::image::resolve_or_pull_run_image(
        &super::image::oci_cache_root(),
        &spec.image,
        false,
    )?;
    if cached.pulled {
        let auth_source = cached.auth_source.as_deref().unwrap_or("unknown");
        mvm_core::audit_emit!(
            ImageFetch,
            "source=machine_start reference={} digest={} prod=false layers={} trust_policy={} verification_status={} auth_source={}",
            cached.reference,
            cached.resolved_digest,
            cached.provenance.layer_digests.len(),
            cached.provenance.trust_policy,
            cached.provenance.verification_status,
            auth_source
        );
    }
    super::vm::up::start_persistent_oci_machine(super::vm::up::PersistentImageStartParams {
        name: &spec.name,
        image_label: &cached.reference,
        resolved_digest: &cached.resolved_digest,
        rootfs_path: &cached.rootfs_path,
        cpus: spec.cpus,
        memory_mib,
        mem_initial_mib: None,
        network_policy,
    })?;
    mark_machine_started(&mut spec, cached.resolved_digest);
    if let Err(err) = overwrite_machine_spec(&spec) {
        tracing::warn!(error = %err, machine = %spec.name, "updating machine start metadata failed (non-fatal)");
    }
    println!("started machine {}", spec.name);
    Ok(())
}

fn machine_exec_command(argv: &[String]) -> String {
    let quoted = argv
        .iter()
        .map(|arg| crate::exec::shell_quote(arg))
        .collect::<Vec<_>>();
    format!("exec {}", quoted.join(" "))
}

fn exec_machine(cli: &Cli, args: MachineExecArgs, cfg: &MvmConfig) -> Result<()> {
    ensure_machine_spec_exists(&args.name)?;
    console::run(
        cli,
        console::Args {
            name: args.name,
            command: Some(machine_exec_command(&args.argv)),
            force: args.force,
        },
        cfg,
    )
}

fn shell_machine(cli: &Cli, args: MachineShellArgs, cfg: &MvmConfig) -> Result<()> {
    ensure_machine_spec_exists(&args.name)?;
    console::run(
        cli,
        console::Args {
            name: args.name,
            command: None,
            force: args.force,
        },
        cfg,
    )
}

fn stop_machine(cli: &Cli, args: MachineStopArgs, cfg: &MvmConfig) -> Result<()> {
    ensure_machine_spec_exists(&args.name)?;
    down::run(
        cli,
        down::Args {
            name: Some(args.name),
        },
        cfg,
    )
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        MachineAction::Run(run_args) => run_secure(cli, run_args.into_run_args(), cfg),
        MachineAction::Create(create_args) => create_machine(create_args),
        MachineAction::Ls(list_args) => list_machines(list_args),
        MachineAction::Inspect(inspect_args) => inspect_machine(inspect_args),
        MachineAction::Rm(remove_args) => remove_machine(remove_args),
        MachineAction::Start(start_args) => start_machine(start_args),
        MachineAction::Exec(exec_args) => exec_machine(cli, exec_args, cfg),
        MachineAction::Shell(shell_args) => shell_machine(cli, shell_args, cfg),
        MachineAction::Stop(stop_args) => stop_machine(cli, stop_args, cfg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands};
    use clap::Parser;
    use mvm_core::util::test_env::TestEnv;

    /// Minimal standalone parser so `MachineAction` can be exercised without
    /// dragging the whole top-level CLI in for unit-level assertions.
    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        action: MachineAction,
    }

    struct IsolatedMachineState {
        _env: TestEnv,
        _tmp: tempfile::TempDir,
    }

    impl IsolatedMachineState {
        fn new() -> Self {
            let mut env = TestEnv::new();
            let tmp = tempfile::tempdir().expect("tempdir");
            env.set("MVM_DATA_DIR", tmp.path());
            Self {
                _env: env,
                _tmp: tmp,
            }
        }
    }

    fn parse(argv: &[&str]) -> Result<MachineAction, clap::Error> {
        let mut full = vec!["machine"];
        full.extend_from_slice(argv);
        TestCli::try_parse_from(full).map(|cli| cli.action)
    }

    fn parse_run(argv: &[&str]) -> Result<MachineRunArgs, clap::Error> {
        parse(argv).map(|action| match action {
            MachineAction::Run(r) => r,
            other => panic!("expected run action, got {other:?}"),
        })
    }

    #[test]
    fn run_parses_image_and_trailing_argv() {
        let args = parse_run(&["run", "--image", "alpine", "--", "echo", "hello"]).expect("parse");
        assert_eq!(args.image, "alpine");
        assert_eq!(args.argv, vec!["echo", "hello"]);
    }

    #[test]
    fn run_parses_and_forwards_net_flags() {
        let args = parse_run(&[
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
        let args = parse_run(&["run", "--image", "alpine", "--", "true"]).expect("parse");
        assert!(!args.net);
        assert!(args.allow_host.is_empty());
    }

    #[test]
    fn run_requires_image() {
        let err = parse_run(&["run", "--", "echo", "hi"]).expect_err("image is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn run_requires_argv() {
        let err = parse_run(&["run", "--image", "alpine"]).expect_err("argv is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn run_defaults_match_the_lower_level_runner() {
        let args = parse_run(&["run", "--image", "alpine", "--", "true"]).expect("parse");
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
        let args = parse_run(&[
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
        let args = parse_run(&[
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
    fn create_parses_persistent_spec_flags() {
        let action = parse(&[
            "create",
            "--name",
            "web",
            "--image",
            "ghcr.io/acme/web:latest",
            "--net",
            "--allow-host",
            "api.example.com:443",
            "--cpus",
            "4",
            "--memory",
            "1G",
            "--profile",
            "dev",
            "--json",
            "--force",
        ])
        .expect("parse");
        match action {
            MachineAction::Create(args) => {
                assert_eq!(args.name, "web");
                assert_eq!(args.image, "ghcr.io/acme/web:latest");
                assert!(args.net);
                assert_eq!(args.allow_host, vec!["api.example.com:443"]);
                assert_eq!(args.cpus, 4);
                assert_eq!(args.memory, "1G");
                assert_eq!(args.profile, RunProfile::Dev);
                assert!(args.json);
                assert!(args.force);
            }
            other => panic!("expected create action, got {other:?}"),
        }
    }

    #[test]
    fn list_inspect_and_remove_parse() {
        match parse(&["ls", "--json"]).expect("parse") {
            MachineAction::Ls(args) => assert!(args.json),
            other => panic!("expected ls action, got {other:?}"),
        }
        match parse(&["start", "--name", "web"]).expect("parse") {
            MachineAction::Start(args) => assert_eq!(args.name, "web"),
            other => panic!("expected start action, got {other:?}"),
        }
        match parse(&["inspect", "web", "--json"]).expect("parse") {
            MachineAction::Inspect(args) => {
                assert_eq!(args.name, "web");
                assert!(args.json);
            }
            other => panic!("expected inspect action, got {other:?}"),
        }
        match parse(&["rm", "web", "--yes", "--json"]).expect("parse") {
            MachineAction::Rm(args) => {
                assert_eq!(args.name, "web");
                assert!(args.yes);
                assert!(args.json);
            }
            other => panic!("expected rm action, got {other:?}"),
        }
    }

    #[test]
    fn exec_shell_and_stop_parse() {
        match parse(&["exec", "--name", "web", "--", "echo", "hello world"]).expect("parse") {
            MachineAction::Exec(args) => {
                assert_eq!(args.name, "web");
                assert_eq!(args.argv, vec!["echo", "hello world"]);
                assert!(!args.force);
            }
            other => panic!("expected exec action, got {other:?}"),
        }
        match parse(&["shell", "--name", "web", "--force"]).expect("parse") {
            MachineAction::Shell(args) => {
                assert_eq!(args.name, "web");
                assert!(args.force);
            }
            other => panic!("expected shell action, got {other:?}"),
        }
        match parse(&["stop", "--name", "web"]).expect("parse") {
            MachineAction::Stop(args) => assert_eq!(args.name, "web"),
            other => panic!("expected stop action, got {other:?}"),
        }
    }

    #[test]
    fn exec_requires_argv() {
        let err = parse(&["exec", "--name", "web"]).expect_err("argv is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn machine_exec_command_quotes_argv_for_guest_exec() {
        let argv = vec![
            "printf".to_string(),
            "hello %s\n".to_string(),
            "it's ok".to_string(),
        ];
        assert_eq!(
            machine_exec_command(&argv),
            "exec 'printf' 'hello %s\n' 'it'\\''s ok'"
        );
    }

    #[test]
    fn mark_machine_started_sets_digest_and_timestamp() {
        let mut spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "alpine:latest".to_string(),
            resolved_digest: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            profile: "standard".to_string(),
            created_at: Some("2026-06-18T00:00:00Z".to_string()),
            last_started_at: None,
        };
        mark_machine_started(&mut spec, "sha256:abc".to_string());
        assert_eq!(spec.resolved_digest.as_deref(), Some("sha256:abc"));
        assert!(spec.last_started_at.is_some());
    }

    #[test]
    fn create_persists_machine_spec_under_data_dir() {
        let _state = IsolatedMachineState::new();
        let args = MachineCreateArgs {
            name: "web".to_string(),
            image: "alpine:latest".to_string(),
            net: true,
            allow_host: vec!["api.example.com".to_string()],
            cpus: 4,
            memory: "1G".to_string(),
            profile: RunProfile::Dev,
            force: false,
            json: false,
        };
        let spec = args.into_spec().expect("spec");
        save_machine_spec(&spec, false).expect("save");

        let path = config::machine_spec_path("web");
        assert!(path.exists(), "spec path should exist: {}", path.display());
        let loaded = load_machine_spec("web").expect("load");
        assert_eq!(loaded, spec);
        assert_eq!(loaded.schema_version, MACHINE_SPEC_SCHEMA_VERSION);
        assert!(loaded.created_at.is_some());
        assert!(loaded.last_started_at.is_none());
    }

    #[test]
    fn create_rejects_unsafe_machine_name() {
        let args = MachineCreateArgs {
            name: "../web".to_string(),
            image: "alpine:latest".to_string(),
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            profile: RunProfile::Standard,
            force: false,
            json: false,
        };
        let err = args.into_spec().expect_err("unsafe name rejected");
        assert!(err.to_string().contains("machine name ID"));
    }

    #[test]
    fn create_refuses_overwrite_without_force() {
        let _state = IsolatedMachineState::new();
        let spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "alpine:latest".to_string(),
            resolved_digest: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            profile: "standard".to_string(),
            created_at: Some(mvm_core::time::utc_now()),
            last_started_at: None,
        };
        save_machine_spec(&spec, false).expect("first save");
        let err = save_machine_spec(&spec, false).expect_err("overwrite rejected");
        assert!(err.to_string().contains("already exists"));
        save_machine_spec(&spec, true).expect("force overwrites");
    }

    #[test]
    fn list_machine_specs_returns_sorted_specs() {
        let _state = IsolatedMachineState::new();
        for name in ["zeta", "alpha"] {
            let spec = MachineSpec {
                schema_version: MACHINE_SPEC_SCHEMA_VERSION,
                name: name.to_string(),
                image: format!("example/{name}:latest"),
                resolved_digest: None,
                net: false,
                allow_host: Vec::new(),
                cpus: 2,
                memory: "512M".to_string(),
                profile: "standard".to_string(),
                created_at: Some(mvm_core::time::utc_now()),
                last_started_at: None,
            };
            save_machine_spec(&spec, false).expect("save");
        }
        let names = list_machine_specs()
            .expect("list")
            .into_iter()
            .map(|spec| spec.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn inspect_rejects_unknown_spec_fields() {
        let _state = IsolatedMachineState::new();
        let path = config::machine_spec_path("web");
        atomic_write(
            &path,
            br#"{
              "schema_version": 1,
              "name": "web",
              "image": "alpine:latest",
              "resolved_digest": null,
              "net": false,
              "allow_host": [],
              "cpus": 2,
              "memory": "512M",
              "profile": "standard",
              "created_at": "2026-06-18T00:00:00Z",
              "last_started_at": null,
              "unexpected": true
            }"#,
        )
        .expect("write");
        let err = load_machine_spec("web").expect_err("unknown field rejected");
        assert!(err.to_string().contains("parsing machine spec"));
    }

    #[test]
    fn remove_machine_spec_requires_confirmation_and_deletes_dir() {
        let _state = IsolatedMachineState::new();
        let spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "alpine:latest".to_string(),
            resolved_digest: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            profile: "standard".to_string(),
            created_at: Some(mvm_core::time::utc_now()),
            last_started_at: None,
        };
        save_machine_spec(&spec, false).expect("save");
        let err = remove_machine_spec("web", false).expect_err("confirmation required");
        assert!(err.to_string().contains("without --yes"));

        let summary = remove_machine_spec("web", true).expect("remove");
        assert_eq!(summary.name, "web");
        assert!(summary.removed);
        assert!(!config::machine_state_dir("web").exists());
    }

    #[test]
    fn running_vm_wrappers_require_a_persisted_machine_spec() {
        let _state = IsolatedMachineState::new();
        let err = ensure_machine_spec_exists("web").expect_err("missing spec rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("loading machine spec for \"web\""));
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
                other => panic!("expected run action, got {other:?}"),
            },
            other => panic!("expected Commands::Machine, got {other:?}"),
        }
    }

    #[test]
    fn top_level_cli_routes_machine_create() {
        let cli = Cli::try_parse_from([
            "mvmctl", "machine", "create", "--name", "web", "--image", "alpine",
        ])
        .expect("top-level parse");
        match cli.command {
            Commands::Machine(args) => match args.action {
                MachineAction::Create(create) => {
                    assert_eq!(create.name, "web");
                    assert_eq!(create.image, "alpine");
                }
                other => panic!("expected create action, got {other:?}"),
            },
            other => panic!("expected Commands::Machine, got {other:?}"),
        }
    }

    #[test]
    fn top_level_cli_routes_machine_start() {
        let cli = Cli::try_parse_from(["mvmctl", "machine", "start", "--name", "web"])
            .expect("top-level parse");
        match cli.command {
            Commands::Machine(args) => match args.action {
                MachineAction::Start(start) => assert_eq!(start.name, "web"),
                other => panic!("expected start action, got {other:?}"),
            },
            other => panic!("expected Commands::Machine, got {other:?}"),
        }
    }

    #[test]
    fn top_level_cli_routes_machine_exec() {
        let cli = Cli::try_parse_from([
            "mvmctl", "machine", "exec", "--name", "web", "--", "echo", "hi",
        ])
        .expect("top-level parse");
        match cli.command {
            Commands::Machine(args) => match args.action {
                MachineAction::Exec(exec) => {
                    assert_eq!(exec.name, "web");
                    assert_eq!(exec.argv, vec!["echo", "hi"]);
                }
                other => panic!("expected exec action, got {other:?}"),
            },
            other => panic!("expected Commands::Machine, got {other:?}"),
        }
    }
}
