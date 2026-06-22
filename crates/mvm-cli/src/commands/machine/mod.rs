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

mod portable;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use clap::{Args as ClapArgs, Subcommand};
use ed25519_dalek::Signer;
#[cfg(test)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mvm_backend::backend::AnyBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use mvm_core::atomic_io::atomic_write;
use mvm_core::manifest::{Manifest, ManifestMachineWorkflow, resolve_manifest_config_path};
use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;
use mvm_core::vm_backend::{VmId, VmStatus};
use mvm_core::{config, naming};

use super::Cli;
use super::vm::exec::{RunArgs, RunProfile, run_secure};
#[cfg(test)]
use super::vm::host_signer::PUBLIC_FILENAME;
use super::vm::host_signer::{host_signer_id, load_or_init};
use super::vm::{console, down};
use crate::commands::ssh_agent_proxy::{
    SSH_AGENT_GUEST_SOCKET, SshAgentProxyListen, reap_proxy, spawn_proxy, ssh_auth_sock_from_env,
};

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
    /// Verify a portable `.mvm` artifact and preview how `machine run` would
    /// admit it (arch, profile, seccomp, egress, volumes). Read-only: no
    /// extraction, no boot.
    #[command(name = "check-artifact")]
    CheckArtifact(portable::CheckArtifactArgs),
}

/// Ephemeral image-backed run. Mirrors the relevant subset of `mvmctl run`'s
/// flags and translates into the same admitted execution path.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineRunArgs {
    /// OCI image reference to boot (pulled or reused from the local cache).
    /// Required for a fresh boot; optional when reconnecting to an existing
    /// persistent machine by `--name`.
    #[arg(long, value_name = "REF")]
    pub image: Option<String>,
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
    /// (No short flag: `-v` is the global verbosity counter and `-d` is
    /// `--detach`.)
    #[arg(long = "volume")]
    pub volume: Vec<String>,
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
    /// Persist the machine under this name: it survives the command and is
    /// reconnectable via `machine shell/exec/stop`. Implies persistence.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Boot a persistent machine and return immediately. Auto-names the machine
    /// when `--name` is absent (the chosen name is printed). Implies persistence.
    #[arg(short = 'd', long)]
    pub detach: bool,
    /// Attach an interactive PTY shell (dev-only; refused for `--prod`/sealed
    /// images). Does not affect persistence: `-t` alone is a transient
    /// interactive machine, gone when the shell exits.
    #[arg(short = 't', long)]
    pub tty: bool,
    /// Accepted as an alias for `-t` so the conventional `-it` bundle parses.
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,
    /// Argv to run inside the guest (use `--` to separate). Optional for
    /// persistent (`-d`/`--name`) and interactive (`-t`) modes; required for a
    /// plain transient run.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
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
            image: self.image,
            net: self.net,
            allow_host: self.allow_host,
            cpus: self.cpus,
            memory: self.memory,
            profile: self.profile,
            add_dir: self.volume,
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

    /// `-t`/`--tty` or its `-i` alias requests an interactive PTY shell.
    fn interactive(&self) -> bool {
        self.tty || self.interactive
    }

    /// `--name` or `-d`/`--detach` makes the machine survive the command.
    /// `--tty` is deliberately NOT consulted here — persistence and
    /// interactivity are independent axes.
    fn persistent(&self) -> bool {
        self.name.is_some() || self.detach
    }

    /// Resolve the lifecycle mode purely from the flags. The only validation is
    /// that a plain transient run carries a command; persistent and interactive
    /// modes default to "just boot" / "default shell" respectively.
    fn resolve_mode(&self) -> Result<MachineRunMode> {
        let mode = match (self.interactive(), self.persistent()) {
            // Persistent modes may reconnect to an existing machine by name, so
            // `--image` is optional here (validated against spec existence in the
            // persistent path).
            (true, true) => MachineRunMode::InteractivePersistent,
            (false, true) => MachineRunMode::Persistent,
            // Fresh-boot modes always materialize a new VM and need an image.
            (true, false) => {
                self.require_image_for_fresh_boot()?;
                MachineRunMode::InteractiveTransient
            }
            (false, false) => {
                self.require_image_for_fresh_boot()?;
                if self.argv.is_empty() {
                    bail!(
                        "machine run needs a command: pass `-- <cmd>`, \
                         or `-d`/`--name <N>` to boot a persistent machine, \
                         or `-t` for an interactive shell"
                    );
                }
                MachineRunMode::Transient
            }
        };
        Ok(mode)
    }

    /// Fresh-boot modes (transient, interactive-transient) have no spec to fall
    /// back on, so an image is mandatory.
    fn require_image_for_fresh_boot(&self) -> Result<()> {
        if self.image.is_none() {
            bail!("machine run needs `--image <ref>` to boot a new machine");
        }
        Ok(())
    }
}

/// The lifecycle `machine run` resolves to, computed purely from the parsed
/// flags. Persistence (`--name`/`-d`) and interactivity (`-t`/`-i`) are
/// independent axes, so the interactive variants record whether the machine
/// also persists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachineRunMode {
    /// Default one-shot: boot, run argv, tear down. Unchanged `run_secure`.
    Transient,
    /// Persistent (named or detached), non-interactive.
    Persistent,
    /// Interactive PTY shell on a throwaway machine (gone on shell exit).
    InteractiveTransient,
    /// Interactive PTY shell on a persistent machine (left up on exit).
    InteractivePersistent,
}

/// What the persistent path should do with the on-disk spec for the target name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SpecReconcile {
    /// No spec on disk — write `desired` and boot.
    Create,
    /// A spec with the same launch config already exists — keep it.
    Reuse,
    /// A spec with a different config exists — stop the old instance, overwrite,
    /// and reboot. `changed` is a human summary of the differing fields for the
    /// loud notice.
    Recreate { changed: String },
}

/// An auto-generated machine name for `-d` without `--name`. Reuses the
/// `mvm-core` instance-ID helper so there is one naming scheme, not two; the
/// `i-<hex>` shape satisfies `validate_vm_name`.
fn auto_machine_name() -> String {
    naming::generate_instance_id()
}

/// Resolve the persistent machine's name: the explicit `--name`, or an
/// auto-generated one for bare `-d`/`--detach`.
fn resolve_machine_run_name(args: &MachineRunArgs) -> Result<String> {
    match args.name.as_deref() {
        Some(name) => {
            validate_machine_name(name)?;
            Ok(name.to_string())
        }
        None => Ok(auto_machine_name()),
    }
}

/// Two specs share a launch config when every boot-affecting field matches.
/// Runtime metadata (resolved digest, timestamps) is deliberately excluded —
/// it changes on every start and must not trigger a collision.
fn machine_config_matches(a: &MachineSpec, b: &MachineSpec) -> bool {
    a.image == b.image
        && a.net == b.net
        && a.allow_host == b.allow_host
        && a.cpus == b.cpus
        && a.memory == b.memory
        && a.mem_initial == b.mem_initial
        && a.profile == b.profile
        && a.volumes == b.volumes
        && a.init == b.init
        && a.ssh_agent == b.ssh_agent
}

/// Human summary of which boot-affecting fields differ, for the loud
/// "config changed, recreating" notice. Mirrors [`machine_config_matches`].
fn machine_config_diff(current: &MachineSpec, desired: &MachineSpec) -> String {
    let mut changed = Vec::new();
    if current.image != desired.image {
        changed.push("image");
    }
    if current.net != desired.net {
        changed.push("net");
    }
    if current.allow_host != desired.allow_host {
        changed.push("allow-host");
    }
    if current.cpus != desired.cpus {
        changed.push("cpus");
    }
    if current.memory != desired.memory || current.mem_initial != desired.mem_initial {
        changed.push("memory");
    }
    if current.profile != desired.profile {
        changed.push("profile");
    }
    if current.volumes != desired.volumes {
        changed.push("volumes");
    }
    if current.init != desired.init {
        changed.push("init");
    }
    if current.ssh_agent != desired.ssh_agent {
        changed.push("ssh-agent");
    }
    changed.join(", ")
}

/// Decide how to reconcile a desired spec against what's on disk. A
/// same-config spec is reused; a different-config spec **auto-recreates**
/// (the caller stops the old instance, overwrites the spec, and reboots) so a
/// config change converges like `compose up`. The machine is cattle —
/// durable data belongs in `--volume` host shares, which live on the host and
/// survive the recreate. The recreate is announced loudly by the caller (never
/// silent) so an unintended clobber (e.g. a typo'd `--image`) is observable.
fn reconcile_machine_spec(existing: Option<&MachineSpec>, desired: &MachineSpec) -> SpecReconcile {
    match existing {
        None => SpecReconcile::Create,
        Some(current) if machine_config_matches(current, desired) => SpecReconcile::Reuse,
        Some(current) => SpecReconcile::Recreate {
            changed: machine_config_diff(current, desired),
        },
    }
}

/// A writable (`:rw`) host share needs a dev-capable profile, matching the
/// transient-run gate and the `dev.init` / `ssh_agent` rule.
fn profile_allows_writable_volume(profile: &str) -> bool {
    matches!(profile, "dev" | "permissive")
}

/// Validate `--volume` specs and normalise them for storage in a managed
/// `MachineSpec`. Each spec is run through the shared
/// `vm_volume_from_spec_validated` choke point (protected-dir deny-list +
/// guest-mount validation, claim 1) and its host path is canonicalised to an
/// **absolute** path so a later reconnect from a different working directory
/// still resolves the same share. `:rw` requires a dev-capable profile. The
/// boot path re-validates via `build_machine_volume_cfg`, so this is the
/// early, user-facing gate, not the only one.
fn machine_run_volume_specs(args: &MachineRunArgs) -> Result<Vec<String>> {
    let profile = run_profile_name(args.profile);
    let mut out = Vec::with_capacity(args.volume.len());
    for raw in &args.volume {
        let spec = super::shared::parse_volume_spec(raw)?;
        let vmv = super::shared::vm_volume_from_spec_validated(&spec)
            .with_context(|| format!("volume {raw:?}"))?;
        if !vmv.read_only && !profile_allows_writable_volume(profile) {
            bail!(
                "volume {raw:?} requests ':rw', which needs --profile dev or --profile permissive"
            );
        }
        // Pin the canonical absolute host path; keep the guest[:size][:mode]
        // tail verbatim so disk volumes and modifiers survive the round-trip.
        let (_, tail) = raw
            .split_once(':')
            .expect("parse_volume_spec guarantees a host:guest separator");
        out.push(format!("{}:{}", vmv.host, tail));
    }
    Ok(out)
}

/// Interactive attach needs a real terminal: the console bridges raw-mode
/// stdin. Refuse up front when stdin is not a TTY so the command fails with a
/// clear message instead of hanging on an EOF'd stdin.
fn require_tty(stdin_is_tty: bool) -> Result<()> {
    if !stdin_is_tty {
        bail!(
            "interactive `-t`/`--tty` needs a terminal on stdin; \
             run it from an interactive shell, or drop `-t` for a non-interactive run"
        );
    }
    Ok(())
}

/// An interactive machine is torn down on shell exit only when it is transient
/// (no `--name`/`-d`); a persistent one is left up.
fn should_teardown_after_interactive(args: &MachineRunArgs) -> bool {
    !args.persistent()
}

/// Build a persistent `MachineSpec` from the `run` flags. Mirrors the
/// validation `machine create` applies (network policy, memory, profile) so the
/// two entry points produce identical specs. The `run` surface intentionally
/// omits disk volumes / init / ssh-agent — those stay manifest-driven.
fn machine_run_spec(args: &MachineRunArgs, name: String) -> Result<MachineSpec> {
    validate_machine_name(&name)?;
    let image = args
        .image
        .clone()
        .ok_or_else(|| anyhow!("machine run needs `--image <ref>` to create machine {name:?}"))?;
    super::shared::resolve_run_network_policy(args.net, &args.allow_host)?;
    let _ = validate_machine_memory(&args.memory, None)?;
    let profile = run_profile_name(args.profile).to_string();
    Ok(MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name,
        image,
        resolved_digest: None,
        net: args.net,
        allow_host: args.allow_host.clone(),
        cpus: args.cpus,
        memory: args.memory.clone(),
        mem_initial: None,
        profile,
        volumes: machine_run_volume_specs(args)?,
        init: Vec::new(),
        ssh_agent: false,
        created_at: Some(mvm_core::time::utc_now()),
        last_started_at: None,
    })
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mem_initial: Option<String>,
    profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    init: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    ssh_agent: bool,
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
    /// Image-backed machine manifest (`mvm.toml`, its directory, or
    /// `Mvmfile.toml`) to source defaults from. If omitted and `--image` is not
    /// set, the current directory is searched.
    #[arg(long, value_name = "PATH")]
    pub manifest: Option<String>,
    /// OCI image reference to boot when the machine lifecycle starts.
    #[arg(long, value_name = "REF", conflicts_with = "manifest")]
    pub image: Option<String>,
    /// Enable dev-tier outbound networking for this machine.
    #[arg(long)]
    pub net: bool,
    /// Allow egress only to these hosts: `HOST[:PORT]` (repeatable).
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// vCPU cores for lifecycle starts.
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Memory for lifecycle starts (supports human-readable: 512M, 1G, ...).
    #[arg(long)]
    pub memory: Option<String>,
    /// Optional initial host memory commitment for lifecycle starts.
    #[arg(long, value_name = "SIZE")]
    pub mem_initial: Option<String>,
    /// Security profile for lifecycle starts.
    #[arg(long, value_enum)]
    pub profile: Option<RunProfile>,
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
    /// Write a signed machine-start receipt to this path.
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Print a machine-readable, redacted start summary as JSON.
    #[arg(long)]
    pub json: bool,
    /// Validate and explain the effective start without booting a VM.
    #[arg(long)]
    pub dry_run: bool,
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

#[derive(Debug)]
struct MachineManifestSource {
    workflow: ManifestMachineWorkflow,
    base_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartReceiptInput {
    machine_name: String,
    image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_digest: Option<String>,
    cpus: u32,
    memory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mem_initial: Option<String>,
    profile: String,
    network_posture: String,
    egress_enforcement: String,
    auth: MachineStartAuthPolicy,
    volumes: Vec<MachineStartVolumePolicy>,
    init: MachineStartInitPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartAuthPolicy {
    mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartVolumePolicy {
    kind: String,
    host_path_sha256: String,
    guest_path: String,
    read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartInitPolicy {
    command_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    script_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartJsonSummary {
    schema_version: u32,
    invocation: MachineStartReceiptInput,
    outcome: MachineStartReceiptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartPreflightSummary {
    schema_version: u32,
    dry_run: bool,
    will_execute: bool,
    machine: MachineStartPreflightMachine,
    invocation: MachineStartReceiptInput,
    resources: MachineStartPreflightResources,
    receipt: MachineStartPreflightReceipt,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartPreflightMachine {
    name: String,
    image_reference_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartPreflightResources {
    cpus: u32,
    memory: String,
    memory_mib: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mem_initial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mem_initial_mib: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartPreflightReceipt {
    requested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartReceiptPayload {
    schema_version: u32,
    receipt_id: String,
    recorded_at: String,
    invocation: MachineStartReceiptInput,
    outcome: MachineStartReceiptOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartReceiptOutcome {
    resolved_digest: String,
    started_at: String,
    init_commands_executed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedMachineStartReceipt {
    payload: MachineStartReceiptPayload,
    signature: MachineStartReceiptSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachineStartReceiptSignature {
    algorithm: String,
    signer_id: String,
    public_key_sha256: String,
    signature_base64: String,
}

impl MachineCreateArgs {
    fn into_spec(self) -> Result<MachineSpec> {
        validate_machine_name(&self.name)?;
        let manifest_source = match (self.image.is_none(), self.manifest.as_deref()) {
            (_, Some(arg)) => Some(load_machine_manifest_source(Path::new(arg))?),
            (true, None) => Some(load_machine_manifest_source(Path::new(".")).with_context(
                || {
                    "machine create requires --image or an image-backed mvm.toml in the current directory"
                },
            )?),
            (false, None) => None,
        };
        let workflow = manifest_source.as_ref().map(|source| &source.workflow);
        let image = match (self.image, workflow) {
            (Some(image), _) => image,
            (None, Some(workflow)) => workflow.image.clone(),
            (None, None) => {
                bail!("machine create requires either --image <ref> or --manifest <path>")
            }
        };
        let net = self.net || workflow.is_some_and(|workflow| workflow.net);
        let allow_host = if self.allow_host.is_empty() {
            workflow
                .map(|workflow| workflow.allow_hosts.clone())
                .unwrap_or_default()
        } else {
            self.allow_host
        };
        super::shared::resolve_run_network_policy(net, &allow_host)?;
        let cpus = self
            .cpus
            .or_else(|| workflow.map(|workflow| workflow.cpus))
            .unwrap_or(2);
        if cpus == 0 {
            bail!("machine CPUs must be >= 1");
        }
        let memory = self
            .memory
            .or_else(|| workflow.map(|workflow| workflow.mem.clone()))
            .unwrap_or_else(|| "512M".to_string());
        let mem_initial = self
            .mem_initial
            .or_else(|| workflow.and_then(|workflow| workflow.mem_initial.clone()));
        let _ = validate_machine_memory(&memory, mem_initial.as_deref())?;
        let profile = self.profile.unwrap_or(RunProfile::Standard);
        let profile_name = run_profile_name(profile).to_string();
        let init = workflow
            .map(|workflow| workflow.init.clone())
            .unwrap_or_default();
        enforce_dev_init_profile(&profile_name, &init)?;
        let ssh_agent = workflow.is_some_and(|workflow| workflow.ssh_agent);
        enforce_ssh_agent_profile(&profile_name, ssh_agent)?;
        let volumes = workflow
            .map(|workflow| workflow.volumes.clone())
            .unwrap_or_default();
        let volumes = match manifest_source.as_ref() {
            Some(source) => source
                .workflow
                .volumes
                .iter()
                .map(|spec| absolutize_manifest_volume_spec(spec, &source.base_dir))
                .collect::<Result<Vec<_>>>()?,
            None => volumes,
        };
        Ok(MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: self.name,
            image,
            resolved_digest: None,
            net,
            allow_host,
            cpus,
            memory,
            mem_initial,
            profile: profile_name,
            volumes,
            init,
            ssh_agent,
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

fn is_false(value: &bool) -> bool {
    !*value
}

fn load_machine_manifest_source(arg: &Path) -> Result<MachineManifestSource> {
    let manifest_path = resolve_manifest_config_path(arg)
        .with_context(|| format!("resolving machine manifest {}", arg.display()))?;
    let manifest = Manifest::read_file(&manifest_path)
        .with_context(|| format!("reading machine manifest {}", manifest_path.display()))?;
    let workflow = manifest.machine_workflow().ok_or_else(|| {
        anyhow!(
            "machine create --manifest requires an image-backed manifest; flake-backed manifests belong to `mvmctl up`"
        )
    })?;
    let base_dir = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    Ok(MachineManifestSource { workflow, base_dir })
}

fn absolutize_manifest_volume_spec(spec: &str, base_dir: &Path) -> Result<String> {
    fn simplify_path(path: PathBuf) -> PathBuf {
        let mut simplified = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    simplified.pop();
                }
                other => simplified.push(other.as_os_str()),
            }
        }
        simplified
    }

    let absolute_host = |host: &str| -> String {
        let path = Path::new(host);
        if path.is_absolute() {
            host.to_string()
        } else {
            simplify_path(base_dir.join(path))
                .to_string_lossy()
                .into_owned()
        }
    };

    match super::shared::parse_volume_spec(spec)? {
        super::shared::VolumeSpec::DirShare {
            host_dir,
            guest_mount,
            read_only,
        } => Ok(format!(
            "{}:{guest_mount}:{}",
            absolute_host(&host_dir),
            if read_only { "ro" } else { "rw" }
        )),
        super::shared::VolumeSpec::Disk {
            host,
            guest,
            size,
            read_only,
            encrypted,
        } => {
            let mut rendered = format!(
                "{}:{guest}:{size}:{}",
                absolute_host(&host),
                if read_only { "ro" } else { "rw" }
            );
            if encrypted {
                rendered.push_str(":enc");
            }
            Ok(rendered)
        }
    }
}

fn validate_machine_memory(memory: &str, mem_initial: Option<&str>) -> Result<(u32, Option<u32>)> {
    let memory_mib = parse_human_size(memory).context("invalid machine memory")?;
    let mem_initial_mib = match mem_initial {
        Some(value) => {
            let parsed = parse_human_size(value).context("invalid machine mem_initial")?;
            if parsed == 0 {
                bail!("machine mem_initial must be > 0 when set");
            }
            if parsed >= memory_mib {
                bail!(
                    "machine mem_initial ({parsed} MiB) must be strictly less than memory ({memory_mib} MiB)"
                );
            }
            Some(parsed)
        }
        None => None,
    };
    Ok((memory_mib, mem_initial_mib))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn machine_start_auth_policy(spec: &MachineSpec) -> MachineStartAuthPolicy {
    let mode = machine_start_plan_auth_policy(spec).mode.as_str();
    MachineStartAuthPolicy {
        mode: mode.to_string(),
    }
}

fn machine_start_plan_auth_policy(spec: &MachineSpec) -> mvm_core::plan::AuthPolicy {
    if spec.ssh_agent {
        mvm_core::plan::AuthPolicy::ssh_agent_socket()
    } else {
        mvm_core::plan::AuthPolicy::none()
    }
}

fn machine_start_init_policy(spec: &MachineSpec) -> MachineStartInitPolicy {
    let script_sha256 =
        (!spec.init.is_empty()).then(|| sha256_hex(spec.init.join("\n").as_bytes()));
    MachineStartInitPolicy {
        command_count: spec.init.len(),
        script_sha256,
    }
}

fn machine_start_volume_policy(spec: &MachineSpec) -> Result<Vec<MachineStartVolumePolicy>> {
    let mut volumes = Vec::with_capacity(spec.volumes.len());
    for volume in &spec.volumes {
        let parsed = super::shared::parse_volume_spec(volume)?;
        let (kind, host_path, guest_path, read_only) = match parsed {
            super::shared::VolumeSpec::DirShare {
                host_dir,
                guest_mount,
                read_only,
            } => ("dir_share", host_dir, guest_mount, read_only),
            super::shared::VolumeSpec::Disk {
                host,
                guest,
                read_only,
                ..
            } => ("disk", host, guest, read_only),
        };
        volumes.push(MachineStartVolumePolicy {
            kind: kind.to_string(),
            host_path_sha256: sha256_hex(host_path.as_bytes()),
            guest_path,
            read_only,
        });
    }
    Ok(volumes)
}

fn machine_start_receipt_input(
    spec: &MachineSpec,
    backend: &str,
) -> Result<MachineStartReceiptInput> {
    enforce_ssh_agent_profile(&spec.profile, spec.ssh_agent)?;
    let network_policy = super::shared::resolve_run_network_policy(spec.net, &spec.allow_host)?;
    let _ = validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let volumes = machine_start_volume_policy(spec)?;
    Ok(MachineStartReceiptInput {
        machine_name: spec.name.clone(),
        image: spec.image.clone(),
        resolved_digest: spec.resolved_digest.clone(),
        cpus: spec.cpus,
        memory: spec.memory.clone(),
        mem_initial: spec.mem_initial.clone(),
        profile: spec.profile.clone(),
        network_posture: network_policy.posture_label(),
        egress_enforcement: super::shared::egress_enforcement_label(backend, &network_policy),
        auth: machine_start_auth_policy(spec),
        volumes,
        init: machine_start_init_policy(spec),
    })
}

fn machine_start_volume_summary(volumes: &[MachineStartVolumePolicy]) -> &'static str {
    if volumes.is_empty() {
        "none"
    } else if volumes.iter().all(|volume| volume.read_only) {
        "ro-only"
    } else {
        "contains-rw"
    }
}

fn machine_start_preflight_summary(
    spec: &MachineSpec,
    receipt: Option<&Path>,
) -> Result<MachineStartPreflightSummary> {
    let backend = super::shared::resolve_effective_hypervisor("firecracker");
    let invocation = machine_start_receipt_input(spec, &backend)?;
    let (memory_mib, mem_initial_mib) =
        validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let mut notes = vec![
        "preflight only; no image was resolved, pulled, booted, or executed".to_string(),
        "raw host paths are intentionally omitted from policy output".to_string(),
    ];
    if receipt.is_some() {
        notes.push("receipt path is hashed, but no receipt is written during dry-run".to_string());
    }
    Ok(MachineStartPreflightSummary {
        schema_version: 1,
        dry_run: true,
        will_execute: false,
        machine: MachineStartPreflightMachine {
            name: spec.name.clone(),
            image_reference_sha256: sha256_hex(spec.image.as_bytes()),
            resolved_digest: spec.resolved_digest.clone(),
        },
        invocation,
        resources: MachineStartPreflightResources {
            cpus: spec.cpus,
            memory: spec.memory.clone(),
            memory_mib,
            mem_initial: spec.mem_initial.clone(),
            mem_initial_mib,
        },
        receipt: MachineStartPreflightReceipt {
            requested: receipt.is_some(),
            path_sha256: receipt.map(|path| sha256_hex(path.to_string_lossy().as_bytes())),
        },
        notes,
    })
}

fn print_machine_start_preflight_human(summary: &MachineStartPreflightSummary) {
    println!("mvmctl machine start dry-run: no VM will be booted");
    println!("machine: {}", summary.machine.name);
    println!(
        "image: OCI reference sha256={}{}",
        summary.machine.image_reference_sha256,
        summary
            .machine
            .resolved_digest
            .as_deref()
            .map(|digest| format!(" last_resolved_digest={digest}"))
            .unwrap_or_default()
    );
    println!(
        "resources: cpus={} memory={} ({} MiB)",
        summary.resources.cpus, summary.resources.memory, summary.resources.memory_mib
    );
    if let Some(mem_initial) = summary.resources.mem_initial.as_deref() {
        let mem_initial_mib = summary.resources.mem_initial_mib.unwrap_or_default();
        println!("mem-initial: {mem_initial} ({mem_initial_mib} MiB)");
    }
    println!("profile: {}", summary.invocation.profile);
    println!("network: {}", summary.invocation.network_posture);
    println!("enforced: {}", summary.invocation.egress_enforcement);
    println!("auth: {}", summary.invocation.auth.mode);
    if summary.invocation.init.command_count == 0 {
        println!("dev.init: none");
    } else {
        println!(
            "dev.init: {} command(s) script_sha256={}",
            summary.invocation.init.command_count,
            summary
                .invocation
                .init
                .script_sha256
                .as_deref()
                .unwrap_or("missing")
        );
    }
    if summary.invocation.volumes.is_empty() {
        println!("host shares: none");
    } else {
        println!("host shares:");
        for volume in &summary.invocation.volumes {
            println!(
                "  kind={} host_sha256={} -> {} ({})",
                volume.kind,
                volume.host_path_sha256,
                volume.guest_path,
                if volume.read_only { "ro" } else { "rw" }
            );
        }
    }
    if summary.receipt.requested {
        if let Some(path_sha256) = &summary.receipt.path_sha256 {
            println!("receipt: requested path_sha256={path_sha256} (not written in dry-run)");
        } else {
            println!("receipt: requested (not written in dry-run)");
        }
    }
}

impl MachineStartJsonSummary {
    fn from_parts(
        invocation: MachineStartReceiptInput,
        outcome: MachineStartReceiptOutcome,
        receipt_path: Option<PathBuf>,
    ) -> Self {
        Self {
            schema_version: 1,
            invocation,
            outcome,
            receipt_path,
        }
    }
}

fn write_machine_start_receipt(
    path: &Path,
    invocation: MachineStartReceiptInput,
    outcome: MachineStartReceiptOutcome,
) -> Result<()> {
    let payload = MachineStartReceiptPayload {
        schema_version: 1,
        receipt_id: uuid::Uuid::new_v4().to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        invocation,
        outcome,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).context("serializing machine-start receipt payload")?;
    let signer = load_or_init().context("loading host signer for machine-start receipt")?;
    let signature = signer.signing.sign(&payload_bytes);
    let public_key = signer.verifying.to_bytes();
    let receipt = SignedMachineStartReceipt {
        payload,
        signature: MachineStartReceiptSignature {
            algorithm: "ed25519".to_string(),
            signer_id: host_signer_id(),
            public_key_sha256: sha256_hex(&public_key),
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        },
    };

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating receipt directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(&receipt).context("serializing machine-start receipt")?;
    std::fs::write(path, bytes)
        .with_context(|| format!("writing machine-start receipt {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
fn verify_machine_start_receipt(
    path: &Path,
    pubkey_path: Option<&Path>,
) -> Result<SignedMachineStartReceipt> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading machine-start receipt {}", path.display()))?;
    let receipt: SignedMachineStartReceipt = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing machine-start receipt {}", path.display()))?;
    if receipt.payload.schema_version != 1 {
        bail!(
            "unsupported machine-start receipt schema_version {}; this build supports 1",
            receipt.payload.schema_version
        );
    }
    if !receipt.signature.algorithm.eq_ignore_ascii_case("ed25519") {
        bail!(
            "unsupported machine-start receipt signature algorithm '{}'",
            receipt.signature.algorithm
        );
    }
    let verifying = load_machine_start_receipt_pubkey(pubkey_path)?;
    let public_key = verifying.to_bytes();
    let actual_key_hash = sha256_hex(&public_key);
    if actual_key_hash != receipt.signature.public_key_sha256 {
        bail!(
            "machine-start receipt public key hash mismatch: receipt={}, supplied={actual_key_hash}",
            receipt.signature.public_key_sha256
        );
    }
    let payload_bytes = serde_json::to_vec(&receipt.payload)
        .context("serializing machine-start receipt payload for verify")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature.signature_base64)
        .context("decoding machine-start receipt signature")?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "machine-start receipt signature is {} bytes; expected 64",
            sig_bytes.len()
        )
    })?;
    let signature = Signature::from_bytes(&sig_arr);
    verifying
        .verify(&payload_bytes, &signature)
        .context("verifying machine-start receipt signature")?;
    Ok(receipt)
}

#[cfg(test)]
fn load_machine_start_receipt_pubkey(pubkey_path: Option<&Path>) -> Result<VerifyingKey> {
    let path = match pubkey_path {
        Some(path) => path.to_path_buf(),
        None => super::vm::host_signer::default_keys_dir()?.join(PUBLIC_FILENAME),
    };
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading machine-start receipt pubkey {}", path.display()))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "receipt pubkey {} is {} bytes; expected 32",
            path.display(),
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&arr).context("parsing machine-start receipt pubkey")
}

fn profile_allows_dev_init(profile: &str) -> bool {
    matches!(profile, "dev" | "permissive")
}

fn profile_allows_ssh_agent(profile: &str) -> bool {
    matches!(profile, "dev" | "permissive")
}

fn enforce_dev_init_profile(profile: &str, init: &[String]) -> Result<()> {
    if !init.is_empty() && !profile_allows_dev_init(profile) {
        bail!(
            "machine dev.init requires a dev-capable profile; use --profile dev or --profile permissive"
        );
    }
    Ok(())
}

fn enforce_ssh_agent_profile(profile: &str, enabled: bool) -> Result<()> {
    if enabled && !profile_allows_ssh_agent(profile) {
        bail!(
            "machine ssh_agent requires a dev-capable profile; use --profile dev or --profile permissive"
        );
    }
    Ok(())
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
        if let Some(mem_initial) = spec.mem_initial.as_deref() {
            println!("mem-initial: {mem_initial}");
        }
        println!("profile: {}", spec.profile);
        println!("ssh-agent: {}", spec.ssh_agent);
        if !spec.volumes.is_empty() {
            println!("volumes: {}", spec.volumes.join(","));
        }
        if !spec.init.is_empty() {
            println!("init: {}", spec.init.join(" && "));
        }
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
    if args.dry_run {
        let summary = machine_start_preflight_summary(&spec, args.receipt.as_deref())?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            print_machine_start_preflight_human(&summary);
        }
        return Ok(());
    }
    enforce_dev_init_profile(&spec.profile, &spec.init)?;
    let backend = super::shared::resolve_effective_hypervisor("firecracker");
    let receipt_input = machine_start_receipt_input(&spec, &backend)?;
    let ssh_auth_sock = if spec.ssh_agent {
        Some(ssh_auth_sock_from_env()?)
    } else {
        None
    };
    let network_policy = super::shared::resolve_run_network_policy(spec.net, &spec.allow_host)?;
    let (memory_mib, mem_initial_mib) =
        validate_machine_memory(&spec.memory, spec.mem_initial.as_deref())?;
    let volume_cfg = build_machine_volume_cfg(&spec.volumes)?;
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
        profile: &spec.profile,
        cpus: spec.cpus,
        memory_mib,
        mem_initial_mib,
        volumes: &volume_cfg,
        network_policy,
        auth: machine_start_plan_auth_policy(&spec),
    })?;
    if let Some(host_sock) = ssh_auth_sock.as_deref()
        && let Err(err) = configure_machine_ssh_agent_forwarding(&spec.name, &backend, host_sock)
    {
        stop_failed_machine_start(&spec.name);
        return Err(err);
    }
    if !spec.init.is_empty()
        && let Err(err) = run_machine_init_commands(&spec.name, &spec.init, spec.ssh_agent)
    {
        stop_failed_machine_start(&spec.name);
        return Err(err);
    }
    mark_machine_started(&mut spec, cached.resolved_digest);
    let started_at = spec
        .last_started_at
        .clone()
        .expect("mark_machine_started always stamps last_started_at");
    if let Err(err) = overwrite_machine_spec(&spec) {
        tracing::warn!(error = %err, machine = %spec.name, "updating machine start metadata failed (non-fatal)");
    }
    let outcome = MachineStartReceiptOutcome {
        resolved_digest: spec
            .resolved_digest
            .clone()
            .expect("mark_machine_started always stamps resolved_digest"),
        started_at,
        init_commands_executed: spec.init.len(),
    };
    if let Some(path) = args.receipt.as_deref() {
        write_machine_start_receipt(path, receipt_input.clone(), outcome.clone())?;
    }
    mvm_core::audit_emit!(VmStart, vm: &spec.name, "{}", machine_start_audit_detail(&receipt_input));
    if args.json {
        let summary = MachineStartJsonSummary::from_parts(receipt_input, outcome, args.receipt);
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("started machine {}", spec.name);
    }
    Ok(())
}

fn machine_start_audit_detail(input: &MachineStartReceiptInput) -> String {
    format!(
        "source=machine.start network={} enforced={} auth={} shares={} init_commands={}",
        input.network_posture,
        input.egress_enforcement,
        input.auth.mode,
        machine_start_volume_summary(&input.volumes),
        input.init.command_count
    )
}

fn ssh_agent_proxy_listen_for_backend(vm_name: &str, backend: &str) -> SshAgentProxyListen {
    match backend {
        "firecracker" => SshAgentProxyListen::Uds(mvm_core::config::vm_vsock_port_socket(
            vm_name,
            mvm_guest::vsock::SSH_AGENT_PORT,
        )),
        "vz" => SshAgentProxyListen::Uds(mvm_core::config::vm_vz_vsock_port_socket(
            vm_name,
            mvm_guest::vsock::SSH_AGENT_PORT,
        )),
        "libkrun" => SshAgentProxyListen::Uds(mvm_core::config::vm_vsock_port_socket(
            vm_name,
            mvm_guest::vsock::SSH_AGENT_PORT,
        )),
        _ => SshAgentProxyListen::Vsock(mvm_guest::vsock::SSH_AGENT_PORT),
    }
}

fn configure_machine_ssh_agent_forwarding(
    vm_name: &str,
    backend: &str,
    host_sock: &Path,
) -> Result<()> {
    spawn_proxy(
        vm_name,
        host_sock,
        ssh_agent_proxy_listen_for_backend(vm_name, backend),
    )?;
    if !super::shared::wait_for_guest_agent(vm_name, 30) {
        reap_proxy(vm_name);
        bail!("guest agent for {vm_name:?} not reachable while configuring ssh-agent forwarding");
    }
    let transport = mvm::vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    start_guest_ssh_agent_socket_forwarding(vm_name, &mut stream)?;
    Ok(())
}

fn start_guest_ssh_agent_socket_forwarding(
    vm_name: &str,
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<()> {
    mvm_guest::vsock::require_capabilities(
        stream,
        &[mvm_guest::vsock::GuestCapability::UnixSocketForward],
    )
    .context("guest agent does not support ssh-agent socket forwarding")?;
    let req = mvm_guest::vsock::GuestRequest::StartUnixSocketForward {
        guest_path: SSH_AGENT_GUEST_SOCKET.to_string(),
        host_vsock_port: mvm_guest::vsock::SSH_AGENT_PORT,
        socket_mode: 0o600,
    };
    super::shared::emit_vsock_rpc_audit(vm_name, &req);
    match mvm_guest::vsock::call_unary(&mut *stream, &req)? {
        mvm_guest::vsock::GuestResponse::UnixSocketForwardStarted { .. } => {
            mvm_core::audit_emit!(
                NetworkPolicyAllow,
                vm: vm_name,
                "scope=auth,direction=in,kind=ssh-agent-socket,guest_socket={SSH_AGENT_GUEST_SOCKET}"
            );
            Ok(())
        }
        mvm_guest::vsock::GuestResponse::Error { message } => {
            reap_proxy(vm_name);
            bail!("guest refused ssh-agent forwarding: {message}")
        }
        other => {
            reap_proxy(vm_name);
            bail!("unexpected response to ssh-agent forwarding request: {other:?}")
        }
    }
}

fn machine_console_env(ssh_agent: bool) -> Vec<(String, String)> {
    if ssh_agent {
        vec![(
            "SSH_AUTH_SOCK".to_string(),
            SSH_AGENT_GUEST_SOCKET.to_string(),
        )]
    } else {
        Vec::new()
    }
}

fn machine_exec_command(argv: &[String]) -> String {
    let quoted = argv
        .iter()
        .map(|arg| crate::exec::shell_quote(arg))
        .collect::<Vec<_>>();
    format!("exec {}", quoted.join(" "))
}

fn build_machine_volume_cfg(
    volume_specs: &[String],
) -> Result<Vec<mvm_backend::image::RuntimeVolume>> {
    let mut volume_cfg = Vec::with_capacity(volume_specs.len());
    for volume in volume_specs {
        let spec = super::shared::parse_volume_spec(volume)?;
        let vmv = super::shared::vm_volume_from_spec_validated(&spec)
            .with_context(|| format!("volume {volume:?}"))?;
        super::shared::materialize_disk_volume(&vmv)
            .with_context(|| format!("volume {volume:?}"))?;
        volume_cfg.push(mvm_backend::image::RuntimeVolume::from(&vmv));
    }
    Ok(volume_cfg)
}

fn run_machine_init_commands(name: &str, commands: &[String], ssh_agent: bool) -> Result<()> {
    if commands.is_empty() {
        return Ok(());
    }
    let session = crate::exec::SessionVm {
        vm_name: name.to_string(),
    };
    let mut script = "set -e\n".to_string();
    if ssh_agent {
        script.push_str(&format!("export SSH_AUTH_SOCK={SSH_AGENT_GUEST_SOCKET}\n"));
    }
    script.push_str(&commands.join("\n"));
    let output = crate::exec::dispatch_in_session(&session, script, None)
        .with_context(|| format!("running dev.init in machine {name:?}"))?;
    if output.exit_code != 0 {
        bail!(
            "machine {:?} dev.init failed with exit code {}:\nstdout:\n{}\nstderr:\n{}",
            name,
            output.exit_code,
            output.stdout,
            output.stderr
        );
    }
    Ok(())
}

fn stop_failed_machine_start(name: &str) {
    reap_proxy(name);
    let backend =
        AnyBackend::from_hypervisor(&super::shared::resolve_effective_hypervisor("firecracker"));
    if let Err(err) = backend.stop(&VmId(name.to_string())) {
        tracing::warn!(error = %err, machine = name, "stopping machine after failed init failed");
    }
}

fn exec_machine(cli: &Cli, args: MachineExecArgs, cfg: &MvmConfig) -> Result<()> {
    let spec = ensure_machine_spec_exists(&args.name)?;
    console::run(
        cli,
        console::Args {
            name: args.name,
            command: Some(machine_exec_command(&args.argv)),
            force: args.force,
            env: machine_console_env(spec.ssh_agent),
        },
        cfg,
    )
}

fn shell_machine(cli: &Cli, args: MachineShellArgs, cfg: &MvmConfig) -> Result<()> {
    let spec = ensure_machine_spec_exists(&args.name)?;
    console::run(
        cli,
        console::Args {
            name: args.name,
            command: None,
            force: args.force,
            env: machine_console_env(spec.ssh_agent),
        },
        cfg,
    )
}

fn stop_machine(cli: &Cli, args: MachineStopArgs, cfg: &MvmConfig) -> Result<()> {
    ensure_machine_spec_exists(&args.name)?;
    reap_proxy(&args.name);
    down::run(
        cli,
        down::Args {
            name: Some(args.name),
        },
        cfg,
    )
}

/// Resolve the spec a persistent run should boot, reconciling the desired
/// config (when `--image` is given) against any on-disk spec. Does **no** IO
/// beyond loading: persistence happens in the caller, keyed off the returned
/// action. With no `--image` this is a pure reconnect to an existing machine.
fn resolve_persistent_spec(
    args: &MachineRunArgs,
    name: &str,
    existing: Option<MachineSpec>,
) -> Result<(MachineSpec, SpecReconcile)> {
    match args.image {
        None => match existing {
            Some(spec) => Ok((spec, SpecReconcile::Reuse)),
            None => bail!("machine {name:?} does not exist; pass --image to create it"),
        },
        Some(_) => {
            let desired = machine_run_spec(args, name.to_string())?;
            let action = reconcile_machine_spec(existing.as_ref(), &desired);
            let spec = match action {
                SpecReconcile::Reuse => existing.expect("reuse implies an existing spec"),
                SpecReconcile::Create | SpecReconcile::Recreate { .. } => desired,
            };
            Ok((spec, action))
        }
    }
}

/// `kill(pid,0)`-cheap liveness probe via the active backend.
fn machine_is_running(name: &str) -> bool {
    let backend =
        AnyBackend::from_hypervisor(&super::shared::resolve_effective_hypervisor("firecracker"));
    matches!(
        backend.status(&VmId(name.to_string())),
        Ok(VmStatus::Running)
    )
}

/// Stop a running machine before recreating it under a new config.
fn stop_running_machine(name: &str) {
    reap_proxy(name);
    let backend =
        AnyBackend::from_hypervisor(&super::shared::resolve_effective_hypervisor("firecracker"));
    if let Err(err) = backend.stop(&VmId(name.to_string())) {
        tracing::warn!(error = %err, machine = name, "stopping machine before recreate failed");
    }
}

/// The persistent lifecycle: `machine run --name <N>` / `-d`. Composes the
/// existing create + start (+ exec) verbs — no new lifecycle code — so the
/// signed-`ExecutionPlan` admission and default-deny egress are identical to
/// `machine create` + `machine start`.
fn run_persistent(cli: &Cli, args: MachineRunArgs, cfg: &MvmConfig) -> Result<()> {
    let name = resolve_machine_run_name(&args)?;
    let existing = load_machine_spec(&name).ok();
    let (spec, action) = resolve_persistent_spec(&args, &name, existing)?;

    // Dry-run: explain the effective start without persisting or booting.
    if args.dry_run {
        let summary = machine_start_preflight_summary(&spec, args.receipt.as_deref())?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            print_machine_start_preflight_human(&summary);
        }
        return Ok(());
    }

    let booted = persist_and_boot_machine(
        &name,
        &spec,
        action,
        MachineStartArgs {
            name: name.clone(),
            receipt: args.receipt.clone(),
            json: args.json,
            dry_run: false,
        },
    )?;
    if !booted && !args.json {
        println!("machine {name} already running");
    }

    run_persistent_post_start(cli, cfg, &args, &name, &spec)
}

/// Persist the reconciled spec and boot the machine if it isn't already up.
/// Shared by the persistent and interactive lifecycles. Returns whether a boot
/// happened (`false` ⇒ the machine was already running).
fn persist_and_boot_machine(
    name: &str,
    spec: &MachineSpec,
    action: SpecReconcile,
    start: MachineStartArgs,
) -> Result<bool> {
    match action {
        SpecReconcile::Reuse => {}
        SpecReconcile::Create => save_machine_spec(spec, false)?,
        SpecReconcile::Recreate { changed } => {
            // Loud, never silent: a config change converges by replacing the VM,
            // so an unintended clobber (typo'd flag) is at least observable.
            eprintln!(
                "machine {name:?}: config changed ({changed}) — stopping the old instance and recreating it"
            );
            stop_running_machine(name);
            overwrite_machine_spec(spec)?;
        }
    }
    if machine_is_running(name) {
        Ok(false)
    } else {
        start_machine(start)?;
        Ok(true)
    }
}

/// The interactive lifecycle: `machine run -t`/`--tty`. Boots (or reconnects to)
/// the machine via the same managed path as the persistent lifecycle, attaches
/// a PTY shell through `console::run`, and tears the machine down on exit only
/// when it is transient. Dev-only: claim 15's `enforce_accessible_gate` refuses
/// a sealed machine before attach, and a non-TTY stdin is refused up front.
fn run_interactive(cli: &Cli, args: MachineRunArgs, cfg: &MvmConfig) -> Result<()> {
    use std::io::IsTerminal as _;
    require_tty(std::io::stdin().is_terminal())?;

    let teardown = should_teardown_after_interactive(&args);
    let name = resolve_machine_run_name(&args)?;
    let existing = load_machine_spec(&name).ok();

    // Claim 15, before boot: a previously-started machine carries runtime meta,
    // so a sealed one is refused here; a fresh boot is re-checked by
    // `console::run` post-boot. The recreate `--force` must not bypass this
    // security gate, so it is not threaded in.
    super::vm::console::enforce_accessible_gate(&name, false)?;

    let (spec, action) = resolve_persistent_spec(&args, &name, existing)?;

    if args.dry_run {
        let summary = machine_start_preflight_summary(&spec, args.receipt.as_deref())?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        } else {
            print_machine_start_preflight_human(&summary);
        }
        return Ok(());
    }

    persist_and_boot_machine(
        &name,
        &spec,
        action,
        MachineStartArgs {
            name: name.clone(),
            receipt: None,
            json: false,
            dry_run: false,
        },
    )?;

    // Attach the interactive PTY (command: None ⇒ a shell). `force: false`
    // keeps claim 15 strict on the post-boot re-check.
    let attached = console::run(
        cli,
        console::Args {
            name: name.clone(),
            command: None,
            force: false,
            env: machine_console_env(spec.ssh_agent),
        },
        cfg,
    );

    if teardown {
        stop_running_machine(&name);
        // Best-effort: drop the throwaway spec we created for this session.
        let _ = remove_machine_spec(&name, true);
    }
    attached
}

/// After the machine is up: run the command (streamed, machine left up), or —
/// with no command — print the name (`-d`) or a reconnect hint.
fn run_persistent_post_start(
    cli: &Cli,
    cfg: &MvmConfig,
    args: &MachineRunArgs,
    name: &str,
    spec: &MachineSpec,
) -> Result<()> {
    if !args.argv.is_empty() {
        if !super::shared::wait_for_guest_agent(name, 30) {
            bail!("guest agent for {name:?} not reachable to run the command");
        }
        return console::run(
            cli,
            console::Args {
                name: name.to_string(),
                command: Some(machine_exec_command(&args.argv)),
                force: false,
                env: machine_console_env(spec.ssh_agent),
            },
            cfg,
        );
    }
    if !args.json {
        if args.detach {
            // `-d`: the name is the handle. `start_machine` already printed it;
            // echo it once more so it is the last line on stdout.
            println!("{name}");
        } else {
            println!("machine {name} is up; attach with `machine shell {name}`");
        }
    }
    Ok(())
}

/// Dispatch `machine run` to one of the three flag-selected lifecycles. The
/// transient default routes into the unchanged `run_secure`; persistence and
/// interactivity compose the existing machine verbs.
fn run_dispatch(cli: &Cli, args: MachineRunArgs, cfg: &MvmConfig) -> Result<()> {
    match args.resolve_mode()? {
        MachineRunMode::Transient => run_secure(cli, args.into_run_args(), cfg),
        MachineRunMode::Persistent => run_persistent(cli, args, cfg),
        MachineRunMode::InteractiveTransient | MachineRunMode::InteractivePersistent => {
            run_interactive(cli, args, cfg)
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        MachineAction::Run(run_args) => run_dispatch(cli, run_args, cfg),
        MachineAction::Create(create_args) => create_machine(create_args),
        MachineAction::Ls(list_args) => list_machines(list_args),
        MachineAction::Inspect(inspect_args) => inspect_machine(inspect_args),
        MachineAction::Rm(remove_args) => remove_machine(remove_args),
        MachineAction::Start(start_args) => start_machine(start_args),
        MachineAction::Exec(exec_args) => exec_machine(cli, exec_args, cfg),
        MachineAction::Shell(shell_args) => shell_machine(cli, shell_args, cfg),
        MachineAction::Stop(stop_args) => stop_machine(cli, stop_args, cfg),
        MachineAction::CheckArtifact(a) => portable::run_check_artifact(a),
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

    fn parse_owned(argv: &[String]) -> Result<MachineAction, clap::Error> {
        let full = std::iter::once("machine".to_string())
            .chain(argv.iter().cloned())
            .collect::<Vec<_>>();
        TestCli::try_parse_from(full).map(|cli| cli.action)
    }

    fn parse_run(argv: &[&str]) -> Result<MachineRunArgs, clap::Error> {
        parse(argv).map(|action| match action {
            MachineAction::Run(r) => r,
            other => panic!("expected run action, got {other:?}"),
        })
    }

    fn parse_owned_run(argv: &[String]) -> Result<MachineRunArgs, clap::Error> {
        parse_owned(argv).map(|action| match action {
            MachineAction::Run(r) => r,
            other => panic!("expected run action, got {other:?}"),
        })
    }

    fn sdk_machine_fixture(name: &str) -> Vec<String> {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../sdks/machine-fixtures")
                .join(format!("{name}.argv")),
        )
        .expect("read shared SDK machine argv fixture")
        .lines()
        .map(std::string::ToString::to_string)
        .collect()
    }

    fn assert_sdk_run_admission_inputs(summary: super::super::vm::exec::RunSecuritySummary) {
        assert!(summary.dry_run);
        assert!(!summary.will_execute);
        assert_eq!(summary.image_kind, "oci");
        assert_eq!(summary.cpus, 4);
        assert_eq!(summary.memory, "1G");
        assert_eq!(summary.memory_mib, 1024);
        assert_eq!(summary.profile, "dev");
        assert!(summary.receipt_requested);
        assert_eq!(
            summary.preflight_network_posture,
            "allow-list:api.example.com:443"
        );
        assert_eq!(
            summary.receipt_network_posture,
            summary.preflight_network_posture
        );
        assert_eq!(
            summary.receipt_egress_enforcement,
            "firecracker:l4-host-port"
        );
        assert_eq!(summary.preflight_command, summary.receipt_command);
        assert!(summary.preflight_command.contains("argv_len=3"));
        assert!(!summary.preflight_command.contains("echo ok"));
        assert_eq!(summary.preflight_env_keys, ["MODE", "TOKEN"]);
        assert_eq!(summary.receipt_env_keys, summary.preflight_env_keys);
        assert_eq!(summary.preflight_add_dirs, summary.receipt_add_dirs);
        assert_eq!(summary.preflight_add_dirs.len(), 1);
        let add_dir = &summary.preflight_add_dirs[0];
        assert_eq!(add_dir.guest_path, "/workspace");
        assert!(add_dir.read_only);
        assert!(!add_dir.host_path_sha256.contains("/tmp/mvm-sdk-src"));
        assert_eq!(summary.preflight_timeout_secs, 30);
        assert_eq!(summary.receipt_timeout_secs, 30);
    }

    fn assert_manifest_fixture_reaches_unknown_key_gate(mut sdk_args: Vec<String>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("mvm.toml");
        std::fs::write(
            &manifest,
            "image = \"alpine:latest\"\nnetwork_typo = true\n",
        )
        .expect("manifest");
        let manifest_slot = sdk_args
            .iter()
            .position(|arg| arg == "mvm.toml")
            .expect("fixture carries manifest path");
        sdk_args[manifest_slot] = manifest.display().to_string();

        let action = parse_owned(&sdk_args).expect("sdk args parse as CLI machine create");
        let MachineAction::Create(args) = action else {
            panic!("expected create action");
        };
        let err = args
            .into_spec()
            .expect_err("CLI manifest parser must reject unknown SDK-provided keys");
        let chain = err
            .chain()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            chain.contains("unknown field") || chain.contains("unknown key"),
            "unexpected error chain: {chain}"
        );
    }

    #[test]
    fn run_parses_image_and_trailing_argv() {
        let args = parse_run(&["run", "--image", "alpine", "--", "echo", "hello"]).expect("parse");
        assert_eq!(args.image.as_deref(), Some("alpine"));
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
    fn fresh_boot_without_image_is_rejected_at_dispatch() {
        // `--image` is no longer clap-required (a persistent run can reconnect
        // by name), so a fresh transient boot with no image parses and is
        // refused at mode resolution with a clear message.
        let args = parse_run(&["run", "--", "echo", "hi"]).expect("parse");
        let err = args.resolve_mode().expect_err("fresh boot needs an image");
        assert!(err.to_string().contains("image"), "unexpected error: {err}");
    }

    #[test]
    fn transient_run_without_argv_is_rejected_at_dispatch() {
        // Argv is no longer clap-required (persistent/interactive modes boot
        // without a command), so a bare transient run parses and is refused at
        // mode resolution with a clear message — not a hang, not a silent exit.
        let args = parse_run(&["run", "--image", "alpine"]).expect("parse");
        let err = args
            .resolve_mode()
            .expect_err("transient run needs a command");
        assert!(
            err.to_string().contains("command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_defaults_match_the_lower_level_runner() {
        let args = parse_run(&["run", "--image", "alpine", "--", "true"]).expect("parse");
        assert_eq!(args.cpus, 2);
        assert_eq!(args.memory, "512M");
        assert_eq!(args.profile, RunProfile::Standard);
        assert!(!args.json);
        assert!(!args.dry_run);
        assert!(args.volume.is_empty());
        assert!(args.env.is_empty());
        assert!(args.name.is_none());
        assert!(!args.detach);
        assert!(!args.tty);
        assert!(!args.interactive);
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
            "--volume",
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
        assert_eq!(args.volume, vec!["/host:/work:rw"]);
        assert_eq!(args.env, vec!["FOO=bar"]);
        assert_eq!(args.timeout, Some(30));
        assert!(args.json);
        assert!(args.dry_run);
        assert_eq!(args.argv, vec!["uname", "-a"]);
    }

    #[test]
    fn volume_flag_carries_dir_share_and_d_is_no_longer_a_share() {
        let args = parse_run(&[
            "run",
            "--image",
            "alpine",
            "--volume",
            "/host:/work:rw",
            "--",
            "true",
        ])
        .expect("parse");
        assert_eq!(args.volume, vec!["/host:/work:rw"]);
        // `-d` now means --detach, so it must NOT consume the following value as
        // a dir share.
        let detached = parse_run(&["run", "--image", "alpine", "-d"]).expect("parse");
        assert!(detached.detach);
        assert!(detached.volume.is_empty());
    }

    #[test]
    fn detach_short_and_long_imply_persistence() {
        for argv in [
            &["run", "--image", "alpine", "-d"][..],
            &["run", "--image", "alpine", "--detach"][..],
        ] {
            let args = parse_run(argv).expect("parse");
            assert!(args.detach, "argv {argv:?}");
            assert!(args.persistent(), "argv {argv:?}");
            assert!(!args.interactive());
        }
    }

    #[test]
    fn name_implies_persistence_without_detach() {
        let args =
            parse_run(&["run", "--image", "alpine", "--name", "web", "--", "true"]).expect("parse");
        assert_eq!(args.name.as_deref(), Some("web"));
        assert!(args.persistent());
        assert!(!args.detach);
        assert!(!args.interactive());
    }

    #[test]
    fn tty_long_short_alias_and_it_bundle_request_interactivity() {
        for argv in [
            &["run", "--image", "alpine", "--tty"][..],
            &["run", "--image", "alpine", "-t"][..],
            &["run", "--image", "alpine", "-i"][..],
            &["run", "--image", "alpine", "-it"][..],
        ] {
            let args = parse_run(argv).expect("parse");
            assert!(args.interactive(), "argv {argv:?}");
            // Interactivity alone never implies persistence.
            assert!(!args.persistent(), "argv {argv:?}");
        }
    }

    #[test]
    fn resolve_mode_covers_the_behavior_matrix() {
        let cases: &[(&[&str], MachineRunMode)] = &[
            (
                &["run", "--image", "X", "--", "cmd"],
                MachineRunMode::Transient,
            ),
            (
                &["run", "-it", "--image", "X", "--", "/bin/sh"],
                MachineRunMode::InteractiveTransient,
            ),
            (
                &["run", "--name", "web", "--image", "X", "--", "cmd"],
                MachineRunMode::Persistent,
            ),
            (
                &[
                    "run", "-it", "--name", "web", "--image", "X", "--", "/bin/sh",
                ],
                MachineRunMode::InteractivePersistent,
            ),
            (&["run", "-d", "--image", "X"], MachineRunMode::Persistent),
            (
                &["run", "-d", "--name", "web", "--image", "X"],
                MachineRunMode::Persistent,
            ),
            (
                &["run", "-t", "--image", "X"],
                MachineRunMode::InteractiveTransient,
            ),
            (
                &["run", "--name", "web", "--image", "X"],
                MachineRunMode::Persistent,
            ),
        ];
        for (argv, expected) in cases {
            let args = parse_run(argv).expect("parse");
            let mode = args.resolve_mode().expect("resolve");
            assert_eq!(mode, *expected, "argv {argv:?}");
        }
    }

    #[test]
    fn auto_generated_machine_name_is_a_valid_vm_name() {
        let name = auto_machine_name();
        mvm_core::naming::validate_vm_name(&name)
            .unwrap_or_else(|e| panic!("auto name {name:?} invalid: {e}"));
    }

    #[test]
    fn detach_resolves_to_an_auto_name_and_named_uses_the_given_name() {
        let named = parse_run(&["run", "--image", "x", "--name", "web"]).expect("parse");
        assert_eq!(resolve_machine_run_name(&named).expect("name"), "web");

        let detached = parse_run(&["run", "--image", "x", "-d"]).expect("parse");
        let auto = resolve_machine_run_name(&detached).expect("name");
        mvm_core::naming::validate_vm_name(&auto).expect("auto name valid");
        assert_ne!(auto, "web");
    }

    fn spec_fixture(name: &str) -> MachineSpec {
        MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: name.to_string(),
            image: "alpine:latest".to_string(),
            resolved_digest: None,
            net: false,
            allow_host: vec![],
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: vec![],
            init: vec![],
            ssh_agent: false,
            created_at: None,
            last_started_at: None,
        }
    }

    #[test]
    fn config_match_ignores_runtime_metadata_but_not_launch_config() {
        let mut a = spec_fixture("web");
        let mut b = spec_fixture("web");
        // Runtime metadata differs — still the same launch config.
        a.resolved_digest = Some("sha256:aaa".to_string());
        a.created_at = Some("t0".to_string());
        b.last_started_at = Some("t1".to_string());
        assert!(machine_config_matches(&a, &b));
        // A launch-config field differs — no longer a match.
        b.cpus = 4;
        assert!(!machine_config_matches(&a, &b));
    }

    #[test]
    fn reconcile_creates_reuses_and_auto_recreates_on_config_change() {
        let desired = spec_fixture("web");

        assert_eq!(
            reconcile_machine_spec(None, &desired),
            SpecReconcile::Create
        );

        let same = spec_fixture("web");
        assert_eq!(
            reconcile_machine_spec(Some(&same), &desired),
            SpecReconcile::Reuse
        );

        // A different config auto-recreates (no --force) and reports what changed.
        let mut different = spec_fixture("web");
        different.image = "ubuntu:24.04".to_string();
        different.cpus += 1;
        match reconcile_machine_spec(Some(&different), &desired) {
            SpecReconcile::Recreate { changed } => {
                assert!(changed.contains("image"), "changed: {changed}");
                assert!(changed.contains("cpus"), "changed: {changed}");
            }
            other => panic!("expected Recreate, got {other:?}"),
        }
    }

    #[test]
    fn run_spec_maps_run_args_into_a_machine_spec() {
        let args = parse_run(&[
            "run",
            "--image",
            "alpine:3.20",
            "--name",
            "web",
            "--cpus",
            "4",
            "--memory",
            "1G",
            "--profile",
            "dev",
            "--net",
            "--allow-host",
            "api.example.com:443",
        ])
        .expect("parse");
        let spec = machine_run_spec(&args, "web".to_string()).expect("spec");
        assert_eq!(spec.name, "web");
        assert_eq!(spec.image, "alpine:3.20");
        assert_eq!(spec.cpus, 4);
        assert_eq!(spec.memory, "1G");
        assert_eq!(spec.profile, "dev");
        assert!(spec.net);
        assert_eq!(spec.allow_host, vec!["api.example.com:443"]);
        // Disk volumes / init / ssh-agent are not part of the `run` surface.
        assert!(spec.volumes.is_empty());
        assert!(spec.init.is_empty());
        assert!(!spec.ssh_agent);
    }

    #[test]
    fn run_volume_is_threaded_into_managed_spec_with_absolute_host() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let host = dir.path().to_string_lossy().into_owned();
        let args = parse_run(&[
            "run",
            "--image",
            "x",
            "--name",
            "web",
            "--volume",
            &format!("{host}:/work:ro"),
        ])
        .expect("parse");
        let spec = machine_run_spec(&args, "web".to_string()).expect("spec");
        assert_eq!(spec.volumes.len(), 1);
        let stored = &spec.volumes[0];
        // Host pinned to an absolute (canonicalized) path so a reconnect from a
        // different cwd still resolves; the guest+mode tail is preserved verbatim.
        let host_part = stored.split(':').next().unwrap();
        assert!(
            std::path::Path::new(host_part).is_absolute(),
            "host not absolute: {stored}"
        );
        assert!(stored.ends_with(":/work:ro"), "stored: {stored}");
    }

    #[test]
    fn run_rw_volume_requires_dev_profile() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let host = dir.path().to_string_lossy().into_owned();
        // Default profile is `standard` → :rw refused.
        let std_args = parse_run(&[
            "run",
            "--image",
            "x",
            "--name",
            "web",
            "--volume",
            &format!("{host}:/work:rw"),
        ])
        .expect("parse");
        let err = machine_run_spec(&std_args, "web".to_string())
            .expect_err(":rw needs a dev-capable profile");
        assert!(err.to_string().contains("profile dev"), "msg: {err}");

        // With --profile dev the writable share is accepted.
        let dev_args = parse_run(&[
            "run",
            "--image",
            "x",
            "--name",
            "web",
            "--profile",
            "dev",
            "--volume",
            &format!("{host}:/work:rw"),
        ])
        .expect("parse");
        let spec = machine_run_spec(&dev_args, "web".to_string()).expect("dev profile allows :rw");
        assert!(
            spec.volumes[0].ends_with(":/work:rw"),
            "stored: {}",
            spec.volumes[0]
        );
    }

    #[test]
    fn persistent_spec_reconnects_without_image_and_errors_when_absent() {
        // No `--image`: reconnect to the existing spec verbatim.
        let reconnect = parse_run(&["run", "--name", "web"]).expect("parse");
        let existing = spec_fixture("web");
        let (spec, action) =
            resolve_persistent_spec(&reconnect, "web", Some(existing.clone())).expect("reconnect");
        assert_eq!(action, SpecReconcile::Reuse);
        assert_eq!(spec, existing);

        // No `--image` and no on-disk spec: a clear "does not exist" error.
        let err = resolve_persistent_spec(&reconnect, "web", None)
            .expect_err("reconnect to a missing machine errors");
        assert!(err.to_string().contains("does not exist"), "msg: {err}");
    }

    #[test]
    fn interactive_requires_a_host_tty() {
        require_tty(true).expect("a host TTY is allowed");
        let err = require_tty(false).expect_err("no TTY must be refused, not left to hang");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("tty") || msg.contains("terminal") || msg.contains("interactive"),
            "msg: {msg}"
        );
    }

    #[test]
    fn interactive_tears_down_only_the_transient_machine() {
        let transient = parse_run(&["run", "-t", "--image", "x"]).expect("parse");
        assert!(should_teardown_after_interactive(&transient));

        let named = parse_run(&["run", "-it", "--name", "web", "--image", "x"]).expect("parse");
        assert!(!should_teardown_after_interactive(&named));

        let detached = parse_run(&["run", "-it", "-d", "--image", "x"]).expect("parse");
        assert!(!should_teardown_after_interactive(&detached));
    }

    #[test]
    fn interactive_refuses_a_sealed_machine_via_the_claim15_gate() {
        let _guard = mvm::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("HOME", tmp.path());
        env.set("MVM_DATA_DIR", tmp.path().join(".mvm"));
        let name = "sealed-machine";
        mvm::vm::runtime_meta::write(
            name,
            &mvm::vm::runtime_meta::VmRuntimeMeta {
                mode: mvm::vm::runtime_meta::StartModeKind::Detached,
                accessible: false,
            },
        )
        .expect("write sealed runtime meta");
        // The interactive path reuses console's claim-15 gate before attaching.
        let err = super::super::vm::console::enforce_accessible_gate(name, false)
            .expect_err("a sealed machine must be refused");
        assert!(err.to_string().contains("sealed image"), "msg: {err}");
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
    fn rust_sdk_machine_run_uses_cli_default_deny_preflight() {
        let sdk_args = mvm_sdk::MachineRun::builder()
            .image("alpine:latest")
            .command(["true"])
            .dry_run(true)
            .json(true)
            .machine_args()
            .expect("sdk machine run args");

        let run = parse_owned_run(&sdk_args)
            .expect("sdk args parse as CLI machine run")
            .into_run_args();
        let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
            .expect("CLI preflight accepts SDK args");

        assert!(summary.dry_run);
        assert!(!summary.will_execute);
        assert_eq!(summary.image_kind, "oci");
        assert_eq!(summary.preflight_network_posture, "deny-all");
        assert_eq!(summary.preflight_egress_enforcement, "flow-drop");
        assert_eq!(summary.receipt_network_posture, "deny-all");
        assert_eq!(summary.receipt_egress_enforcement, "flow-drop");
    }

    #[test]
    fn rust_sdk_machine_run_allow_host_matches_cli_receipt_posture() {
        let sdk_args = mvm_sdk::MachineRun::builder()
            .image("alpine:latest")
            .allow_host("api.example.com")
            .receipt("/tmp/mvm-sdk-machine.receipt.json")
            .dry_run(true)
            .json(true)
            .command(["true"])
            .machine_args()
            .expect("sdk machine run args");

        let run = parse_owned_run(&sdk_args)
            .expect("sdk args parse as CLI machine run")
            .into_run_args();
        let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
            .expect("CLI receipt input accepts SDK args");

        assert_eq!(
            summary.preflight_network_posture,
            "allow-list:api.example.com:443"
        );
        assert!(summary.receipt_requested);
        assert_eq!(
            summary.receipt_network_posture,
            summary.preflight_network_posture
        );
        assert_eq!(
            summary.receipt_egress_enforcement,
            "firecracker:l4-host-port"
        );
    }

    #[test]
    fn rust_sdk_machine_run_matches_cli_admission_and_receipt_inputs() {
        let sdk_args = mvm_sdk::MachineRun::builder()
            .image("alpine:latest")
            .allow_host("api.example.com")
            .cpus(4)
            .memory("1G")
            .profile("dev")
            .volume("/tmp/mvm-sdk-src:/workspace:ro")
            .env("TOKEN=secret")
            .env("MODE=test")
            .timeout(30)
            .receipt("/tmp/mvm-sdk-machine.receipt.json")
            .json(true)
            .dry_run(true)
            .command(["sh", "-lc", "echo ok"])
            .machine_args()
            .expect("sdk machine run args");
        assert_eq!(sdk_args, sdk_machine_fixture("run-admission"));

        let run = parse_owned_run(&sdk_args)
            .expect("sdk args parse as CLI machine run")
            .into_run_args();
        let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
            .expect("CLI receipt input accepts SDK args");

        assert_sdk_run_admission_inputs(summary);
    }

    #[test]
    fn python_typescript_machine_run_default_fixture_uses_cli_default_deny_preflight() {
        let sdk_args = sdk_machine_fixture("run-default");
        let run = parse_owned_run(&sdk_args)
            .expect("Python/TypeScript SDK fixture parses as CLI machine run")
            .into_run_args();
        let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
            .expect("CLI preflight accepts Python/TypeScript SDK fixture");

        assert!(summary.dry_run);
        assert!(!summary.will_execute);
        assert_eq!(summary.image_kind, "oci");
        assert_eq!(summary.preflight_network_posture, "deny-all");
        assert_eq!(summary.preflight_egress_enforcement, "flow-drop");
        assert_eq!(summary.receipt_network_posture, "deny-all");
        assert_eq!(summary.receipt_egress_enforcement, "flow-drop");
    }

    #[test]
    fn python_typescript_machine_run_allow_host_fixture_matches_cli_receipt_posture() {
        let sdk_args = sdk_machine_fixture("run-allow-host-receipt");
        let run = parse_owned_run(&sdk_args)
            .expect("Python/TypeScript SDK fixture parses as CLI machine run")
            .into_run_args();
        let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
            .expect("CLI receipt input accepts Python/TypeScript SDK fixture");

        assert_eq!(
            summary.preflight_network_posture,
            "allow-list:api.example.com:443"
        );
        assert!(summary.receipt_requested);
        assert_eq!(
            summary.receipt_network_posture,
            summary.preflight_network_posture
        );
        assert_eq!(
            summary.receipt_egress_enforcement,
            "firecracker:l4-host-port"
        );
    }

    #[test]
    fn python_typescript_machine_run_fixture_matches_cli_admission_and_receipt_inputs() {
        let sdk_args = sdk_machine_fixture("run-admission");
        let run = parse_owned_run(&sdk_args)
            .expect("Python/TypeScript SDK fixture parses as CLI machine run")
            .into_run_args();
        let summary = super::super::vm::exec::test_run_security_summary(&run, "firecracker")
            .expect("CLI receipt input accepts Python/TypeScript SDK fixture");

        assert_sdk_run_admission_inputs(summary);
    }

    #[test]
    fn rust_sdk_machine_create_manifest_reaches_cli_unknown_key_gate() {
        let sdk_args = mvm_sdk::MachineCreate::builder("web")
            .manifest("mvm.toml")
            .profile("dev")
            .force(true)
            .json(true)
            .machine_args()
            .expect("sdk machine create args");
        assert_eq!(sdk_args, sdk_machine_fixture("create-manifest"));

        assert_manifest_fixture_reaches_unknown_key_gate(sdk_args);
    }

    #[test]
    fn python_typescript_machine_create_manifest_fixture_reaches_cli_unknown_key_gate() {
        assert_manifest_fixture_reaches_unknown_key_gate(sdk_machine_fixture("create-manifest"));
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
                assert_eq!(args.image.as_deref(), Some("ghcr.io/acme/web:latest"));
                assert!(args.net);
                assert_eq!(args.allow_host, vec!["api.example.com:443"]);
                assert_eq!(args.cpus, Some(4));
                assert_eq!(args.memory.as_deref(), Some("1G"));
                assert_eq!(args.profile, Some(RunProfile::Dev));
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
        match parse(&[
            "start",
            "--name",
            "web",
            "--receipt",
            "/tmp/web.receipt.json",
            "--json",
            "--dry-run",
        ])
        .expect("parse")
        {
            MachineAction::Start(args) => {
                assert_eq!(args.name, "web");
                assert_eq!(
                    args.receipt.as_deref(),
                    Some(Path::new("/tmp/web.receipt.json"))
                );
                assert!(args.json);
                assert!(args.dry_run);
            }
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
        assert_eq!(
            machine_console_env(true),
            vec![(
                "SSH_AUTH_SOCK".to_string(),
                "/run/mvm/ssh-agent.sock".to_string()
            )]
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
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            ssh_agent: false,
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
            manifest: None,
            image: Some("alpine:latest".to_string()),
            net: true,
            allow_host: vec!["api.example.com".to_string()],
            cpus: Some(4),
            memory: Some("1G".to_string()),
            mem_initial: None,
            profile: Some(RunProfile::Dev),
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
    fn create_sources_machine_defaults_from_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("src dir");
        std::fs::write(
            dir.path().join("mvm.toml"),
            r#"
image = "python:3.12-alpine"
net = true
cpus = 4
mem = "2G"
mem_initial = "512M"

[network]
allow_hosts = ["api.example.com"]

[dev]
init = ["pip install -r requirements.txt"]
volumes = ["./src:/work:rw"]

[auth]
ssh_agent = true
"#,
        )
        .expect("manifest");

        let spec = MachineCreateArgs {
            name: "web".to_string(),
            manifest: Some(dir.path().join("mvm.toml").display().to_string()),
            image: None,
            net: false,
            allow_host: Vec::new(),
            cpus: None,
            memory: None,
            mem_initial: None,
            profile: Some(RunProfile::Dev),
            force: false,
            json: false,
        }
        .into_spec()
        .expect("manifest-backed spec");

        assert_eq!(spec.image, "python:3.12-alpine");
        assert!(spec.net);
        assert_eq!(spec.allow_host, vec!["api.example.com"]);
        assert_eq!(spec.cpus, 4);
        assert_eq!(spec.memory, "2G");
        assert_eq!(spec.mem_initial.as_deref(), Some("512M"));
        assert_eq!(spec.profile, "dev");
        assert!(spec.ssh_agent);
        assert_eq!(spec.init, vec!["pip install -r requirements.txt"]);
        assert_eq!(
            spec.volumes,
            vec![format!("{}:/work:rw", dir.path().join("src").display())]
        );
    }

    #[test]
    fn create_rejects_flake_backed_manifest_for_machine_specs() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("mvm.toml"), "flake = \".\"\n").expect("manifest");
        let err = MachineCreateArgs {
            name: "web".to_string(),
            manifest: Some(dir.path().join("mvm.toml").display().to_string()),
            image: None,
            net: false,
            allow_host: Vec::new(),
            cpus: None,
            memory: None,
            mem_initial: None,
            profile: None,
            force: false,
            json: false,
        }
        .into_spec()
        .expect_err("flake manifest rejected");
        assert!(
            err.to_string()
                .contains("requires an image-backed manifest")
        );
    }

    #[test]
    fn create_requires_dev_profile_when_manifest_declares_dev_init() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("mvm.toml"),
            "image = \"alpine:latest\"\n[dev]\ninit = [\"echo hi\"]\n",
        )
        .expect("manifest");
        let err = MachineCreateArgs {
            name: "web".to_string(),
            manifest: Some(dir.path().join("mvm.toml").display().to_string()),
            image: None,
            net: false,
            allow_host: Vec::new(),
            cpus: None,
            memory: None,
            mem_initial: None,
            profile: None,
            force: false,
            json: false,
        }
        .into_spec()
        .expect_err("standard profile should refuse dev.init");
        assert!(
            err.to_string()
                .contains("dev.init requires a dev-capable profile")
        );
    }

    #[test]
    fn create_requires_dev_profile_when_manifest_declares_ssh_agent() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("mvm.toml"),
            "image = \"alpine:latest\"\n[auth]\nssh_agent = true\n",
        )
        .expect("manifest");
        let err = MachineCreateArgs {
            name: "web".to_string(),
            manifest: Some(dir.path().join("mvm.toml").display().to_string()),
            image: None,
            net: false,
            allow_host: Vec::new(),
            cpus: None,
            memory: None,
            mem_initial: None,
            profile: None,
            force: false,
            json: false,
        }
        .into_spec()
        .expect_err("standard profile should refuse ssh-agent");
        assert!(
            err.to_string()
                .contains("ssh_agent requires a dev-capable profile")
        );
    }

    #[test]
    fn machine_start_preflight_redacts_host_paths_and_surfaces_policy() {
        let spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "ghcr.io/acme/web:latest".to_string(),
            resolved_digest: Some("sha256:abc".to_string()),
            net: false,
            allow_host: vec!["api.example.com".to_string()],
            cpus: 4,
            memory: "2G".to_string(),
            mem_initial: Some("512M".to_string()),
            profile: "dev".to_string(),
            volumes: vec!["/Users/example/src:/work:rw".to_string()],
            init: vec!["pip install -r requirements.txt".to_string()],
            ssh_agent: false,
            created_at: Some("2026-06-18T00:00:00Z".to_string()),
            last_started_at: None,
        };

        let summary =
            machine_start_preflight_summary(&spec, Some(Path::new("/tmp/web.receipt.json")))
                .expect("preflight summary");
        assert_eq!(
            summary.invocation.network_posture,
            "allow-list:api.example.com:443"
        );
        assert_eq!(summary.invocation.auth.mode, "none");
        assert_eq!(summary.invocation.volumes.len(), 1);
        assert_eq!(summary.invocation.volumes[0].kind, "dir_share");
        assert!(!summary.invocation.volumes[0].host_path_sha256.is_empty());
        assert_eq!(summary.invocation.volumes[0].guest_path, "/work");
        assert!(!summary.invocation.volumes[0].read_only);
        assert_eq!(summary.invocation.init.command_count, 1);
        let json = serde_json::to_string(&summary).expect("summary json");
        assert!(!json.contains("/Users/example/src"));
        assert!(json.contains("allow-list:api.example.com:443"));
    }

    #[test]
    fn machine_start_preflight_surfaces_ssh_agent_auth_mode() {
        let spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "ghcr.io/acme/web:latest".to_string(),
            resolved_digest: Some("sha256:abc".to_string()),
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "dev".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            ssh_agent: true,
            created_at: Some("2026-06-18T00:00:00Z".to_string()),
            last_started_at: None,
        };

        let summary = machine_start_preflight_summary(&spec, None).expect("preflight summary");
        assert_eq!(summary.invocation.auth.mode, "ssh-agent-socket");
        let json = serde_json::to_string(&summary).expect("summary json");
        assert!(json.contains("ssh-agent-socket"));
    }

    #[test]
    fn machine_start_receipt_is_signed_and_verifiable() {
        let _state = IsolatedMachineState::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("machine-start.receipt.json");
        let invocation = MachineStartReceiptInput {
            machine_name: "web".to_string(),
            image: "ghcr.io/acme/web:latest".to_string(),
            resolved_digest: Some("sha256:abc".to_string()),
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            network_posture: "deny-all".to_string(),
            egress_enforcement: "flow-drop".to_string(),
            auth: MachineStartAuthPolicy {
                mode: "none".to_string(),
            },
            volumes: Vec::new(),
            init: MachineStartInitPolicy {
                command_count: 0,
                script_sha256: None,
            },
        };
        let outcome = MachineStartReceiptOutcome {
            resolved_digest: "sha256:abc".to_string(),
            started_at: "2026-06-18T00:00:00Z".to_string(),
            init_commands_executed: 0,
        };

        write_machine_start_receipt(&path, invocation.clone(), outcome.clone()).expect("receipt");
        let verified = verify_machine_start_receipt(&path, None).expect("verified receipt");
        assert_eq!(
            verified.payload.invocation.machine_name,
            invocation.machine_name
        );
        assert_eq!(
            verified.payload.outcome.resolved_digest,
            outcome.resolved_digest
        );
        assert_eq!(verified.signature.signer_id, host_signer_id());
    }

    #[test]
    fn machine_start_receipt_input_records_ssh_agent_socket_for_dev_profiles() {
        let spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "ghcr.io/acme/web:latest".to_string(),
            resolved_digest: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "dev".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            ssh_agent: true,
            created_at: Some("2026-06-18T00:00:00Z".to_string()),
            last_started_at: None,
        };
        let input = machine_start_receipt_input(&spec, "firecracker").expect("receipt input");
        assert_eq!(input.auth.mode, "ssh-agent-socket");
        assert_eq!(
            machine_start_plan_auth_policy(&spec),
            mvm_core::plan::AuthPolicy::ssh_agent_socket()
        );
        assert!(machine_start_audit_detail(&input).contains("auth=ssh-agent-socket"));
    }

    #[test]
    fn ssh_agent_socket_forwarding_negotiates_capability_before_request() {
        let (mut host, mut guest) = std::os::unix::net::UnixStream::pair().expect("stream pair");

        let guest_thread = std::thread::spawn(move || {
            let hello: mvm_guest::vsock::GuestRequest =
                mvm_guest::vsock::read_frame(&mut guest).expect("read hello");
            match hello {
                mvm_guest::vsock::GuestRequest::ProtocolHello {
                    requested_capabilities,
                    ..
                } => assert_eq!(
                    requested_capabilities,
                    vec![mvm_guest::vsock::GuestCapability::UnixSocketForward]
                ),
                other => panic!("expected ProtocolHello before forwarding request, got {other:?}"),
            }
            mvm_guest::vsock::write_frame(
                &mut guest,
                &mvm_guest::vsock::GuestResponse::ProtocolHelloAck {
                    agent_protocol_version: mvm_guest::vsock::PROTOCOL_VERSION,
                    min_supported_version: mvm_guest::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
                    agent_version: "test".to_string(),
                    capabilities: vec![mvm_guest::vsock::GuestCapability::UnixSocketForward],
                },
            )
            .expect("write hello ack");

            let req: mvm_guest::vsock::GuestRequest =
                mvm_guest::vsock::read_frame(&mut guest).expect("read forward request");
            match req {
                mvm_guest::vsock::GuestRequest::StartUnixSocketForward {
                    guest_path,
                    host_vsock_port,
                    socket_mode,
                } => {
                    assert_eq!(guest_path, SSH_AGENT_GUEST_SOCKET);
                    assert_eq!(host_vsock_port, mvm_guest::vsock::SSH_AGENT_PORT);
                    assert_eq!(socket_mode, 0o600);
                    mvm_guest::vsock::write_frame(
                        &mut guest,
                        &mvm_guest::vsock::GuestResponse::UnixSocketForwardStarted {
                            guest_path,
                            host_vsock_port,
                        },
                    )
                    .expect("write forward response");
                }
                other => panic!("expected StartUnixSocketForward, got {other:?}"),
            }
        });

        start_guest_ssh_agent_socket_forwarding("devbox", &mut host)
            .expect("ssh-agent forwarding request succeeds");
        guest_thread.join().expect("guest thread");
    }

    #[test]
    fn ssh_agent_socket_forwarding_refuses_guest_without_capability() {
        let (mut host, mut guest) = std::os::unix::net::UnixStream::pair().expect("stream pair");

        let guest_thread = std::thread::spawn(move || {
            let hello: mvm_guest::vsock::GuestRequest =
                mvm_guest::vsock::read_frame(&mut guest).expect("read hello");
            assert!(
                matches!(hello, mvm_guest::vsock::GuestRequest::ProtocolHello { .. }),
                "expected ProtocolHello, got {hello:?}"
            );
            mvm_guest::vsock::write_frame(
                &mut guest,
                &mvm_guest::vsock::GuestResponse::ProtocolHelloAck {
                    agent_protocol_version: mvm_guest::vsock::PROTOCOL_VERSION,
                    min_supported_version: mvm_guest::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
                    agent_version: "test".to_string(),
                    capabilities: Vec::new(),
                },
            )
            .expect("write hello ack");
        });

        let err = start_guest_ssh_agent_socket_forwarding("devbox", &mut host)
            .expect_err("missing capability is refused");
        let msg = err.to_string();
        assert!(
            msg.contains("ssh-agent socket forwarding"),
            "unexpected error: {msg}"
        );
        guest_thread.join().expect("guest thread");
    }

    #[test]
    fn ssh_agent_proxy_uses_backend_socket_transport_for_firecracker_and_in_process_vmms() {
        let cases = [
            (
                "firecracker",
                mvm_core::config::vm_vsock_port_socket("devbox", mvm_guest::vsock::SSH_AGENT_PORT),
            ),
            (
                "libkrun",
                mvm_core::config::vm_vsock_port_socket("devbox", mvm_guest::vsock::SSH_AGENT_PORT),
            ),
            (
                "vz",
                mvm_core::config::vm_vz_vsock_port_socket(
                    "devbox",
                    mvm_guest::vsock::SSH_AGENT_PORT,
                ),
            ),
        ];

        for (backend, expected) in cases {
            match ssh_agent_proxy_listen_for_backend("devbox", backend) {
                SshAgentProxyListen::Uds(path) => assert_eq!(path, expected),
                SshAgentProxyListen::Vsock(port) => {
                    panic!("{backend} unexpectedly selected AF_VSOCK port {port}")
                }
            }
        }
    }

    #[test]
    fn ssh_agent_proxy_keeps_qemu_on_raw_vsock_transport() {
        match ssh_agent_proxy_listen_for_backend("devbox", "qemu") {
            SshAgentProxyListen::Vsock(port) => {
                assert_eq!(port, mvm_guest::vsock::SSH_AGENT_PORT);
            }
            SshAgentProxyListen::Uds(path) => {
                panic!("qemu unexpectedly selected UDS {}", path.display())
            }
        }
    }

    #[test]
    fn machine_start_receipt_input_refuses_ssh_agent_on_standard_profile() {
        let spec = MachineSpec {
            schema_version: MACHINE_SPEC_SCHEMA_VERSION,
            name: "web".to_string(),
            image: "ghcr.io/acme/web:latest".to_string(),
            resolved_digest: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            ssh_agent: true,
            created_at: Some("2026-06-18T00:00:00Z".to_string()),
            last_started_at: None,
        };
        let err = machine_start_receipt_input(&spec, "firecracker")
            .expect_err("standard profile must refuse ssh-agent");
        assert!(err.to_string().contains("dev-capable profile"));
    }

    #[test]
    fn ssh_agent_auth_is_dev_tier_only() {
        assert!(!profile_allows_ssh_agent("restrictive"));
        assert!(!profile_allows_ssh_agent("standard"));
        assert!(profile_allows_ssh_agent("dev"));
        assert!(profile_allows_ssh_agent("permissive"));
    }

    #[test]
    fn create_rejects_unsafe_machine_name() {
        let args = MachineCreateArgs {
            name: "../web".to_string(),
            manifest: None,
            image: Some("alpine:latest".to_string()),
            net: false,
            allow_host: Vec::new(),
            cpus: Some(2),
            memory: Some("512M".to_string()),
            mem_initial: None,
            profile: Some(RunProfile::Standard),
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
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            ssh_agent: false,
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
                mem_initial: None,
                profile: "standard".to_string(),
                volumes: Vec::new(),
                init: Vec::new(),
                ssh_agent: false,
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
            mem_initial: None,
            profile: "standard".to_string(),
            volumes: Vec::new(),
            init: Vec::new(),
            ssh_agent: false,
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
                    assert_eq!(run.image.as_deref(), Some("alpine"));
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
                    assert_eq!(create.image.as_deref(), Some("alpine"));
                }
                other => panic!("expected create action, got {other:?}"),
            },
            other => panic!("expected Commands::Machine, got {other:?}"),
        }
    }

    #[test]
    fn top_level_cli_routes_machine_start() {
        let cli = Cli::try_parse_from([
            "mvmctl",
            "machine",
            "start",
            "--name",
            "web",
            "--receipt",
            "/tmp/web.receipt.json",
            "--json",
            "--dry-run",
        ])
        .expect("top-level parse");
        match cli.command {
            Commands::Machine(args) => match args.action {
                MachineAction::Start(start) => {
                    assert_eq!(start.name, "web");
                    assert_eq!(
                        start.receipt.as_deref(),
                        Some(Path::new("/tmp/web.receipt.json"))
                    );
                    assert!(start.json);
                    assert!(start.dry_run);
                }
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
