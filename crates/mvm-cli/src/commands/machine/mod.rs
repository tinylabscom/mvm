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
use mvm_core::vm_backend::VmId;
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
    let mode = if spec.ssh_agent {
        "ssh-agent-socket"
    } else {
        "none"
    };
    MachineStartAuthPolicy {
        mode: mode.to_string(),
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
    mvm_core::audit_emit!(
        VmStart,
        vm: &spec.name,
        "source=machine.start network={} enforced={} auth={} shares={} init_commands={}",
        receipt_input.network_posture,
        receipt_input.egress_enforcement,
        receipt_input.auth.mode,
        machine_start_volume_summary(&receipt_input.volumes),
        receipt_input.init.command_count
    );
    if args.json {
        let summary = MachineStartJsonSummary::from_parts(receipt_input, outcome, args.receipt);
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("started machine {}", spec.name);
    }
    Ok(())
}

fn ssh_agent_proxy_listen_for_backend(vm_name: &str, backend: &str) -> SshAgentProxyListen {
    match backend {
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
    let req = mvm_guest::vsock::GuestRequest::StartUnixSocketForward {
        guest_path: SSH_AGENT_GUEST_SOCKET.to_string(),
        host_vsock_port: mvm_guest::vsock::SSH_AGENT_PORT,
        socket_mode: 0o600,
    };
    super::shared::emit_vsock_rpc_audit(vm_name, &req);
    match mvm_guest::vsock::call_unary(&mut stream, &req)? {
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
    fn rust_sdk_machine_create_manifest_reaches_cli_unknown_key_gate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("mvm.toml");
        std::fs::write(
            &manifest,
            "image = \"alpine:latest\"\nnetwork_typo = true\n",
        )
        .expect("manifest");
        let sdk_args = mvm_sdk::MachineCreate::builder("web")
            .manifest(manifest.display().to_string())
            .machine_args()
            .expect("sdk machine create args");

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
