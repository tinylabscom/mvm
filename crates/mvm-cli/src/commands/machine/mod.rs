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

mod checkpoint;
mod lifecycle;
mod list;
mod portable;
mod receipt;
mod runtime;
mod spec_ops;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use clap::{Args as ClapArgs, Subcommand};
use ed25519_dalek::Signer;
#[cfg(test)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use mvm_core::manifest::{Manifest, ManifestMachineWorkflow, resolve_manifest_config_path};
use mvm_core::user_config::MvmConfig;
use mvm_core::{config, naming};

use mvm_runtime::machine::persist::{
    MACHINE_SPEC_SCHEMA_VERSION, MachineSpec, ReconfigurePatch, SpecReconcile, apply_patch,
    list_machine_specs, load_machine_spec, machine_config_diff, overwrite_machine_spec,
    reconcile_machine_spec, save_machine_spec, validate_machine_memory,
};

use super::Cli;
use super::build::build;
use super::vm::exec::{RunArgs, RunProfile, run_secure, run_secure_with_source};
use super::vm::group::VmCmd;
#[cfg(test)]
use super::vm::host_signer::PUBLIC_FILENAME;
use super::vm::host_signer::{host_signer_id, load_or_init};
use super::vm::{console, down};
use crate::ui;
use checkpoint::{ForkVmFullMachineInput, fork_vm_full_machine};
use lifecycle::{exec_machine, run_restart, run_start, shell_machine, stop_machine};
#[cfg(test)]
use receipt::verify_machine_start_receipt;
use receipt::{
    MachineStartJsonSummary, MachineStartReceiptInput, MachineStartReceiptOutcome,
    machine_start_preflight_summary, machine_start_receipt_input, machine_start_volume_summary,
    print_machine_start_preflight_human, write_machine_start_receipt,
};
pub(in crate::commands) use runtime::boot_persistent_by_name;
use runtime::run_dispatch;
use spec_ops::{create_machine, inspect_machine, remove_machine, run_reconfigure};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: MachineAction,
}

#[derive(Subcommand, Debug, Clone)]
// Run carries the full machine-run CLI surface (source + lifecycle + action
// axes); boxing it breaks the Clap `Subcommand` derive, same as `Commands`.
#[allow(clippy::large_enum_variant)]
pub(in crate::commands) enum MachineAction {
    /// Boot an OCI image, run a command, then tear the VM down
    #[command(display_order = 1)]
    Run(MachineRunArgs),
    /// Build a microVM image from a manifest or Nix flake
    #[command(display_order = 2)]
    Build(build::Args),
    /// Create or update a persistent named machine spec without booting it
    #[command(display_order = 3)]
    Create(MachineCreateArgs),
    /// Boot one or more persistent named machines without running a one-shot command
    #[command(display_order = 4)]
    Start(MachineStartCmd),
    /// Restart one or more named machines (stop if running, then start)
    #[command(display_order = 5)]
    Restart(MachineStartCmd),
    /// Stop a running VM by name, or all running VMs with --all
    #[command(display_order = 5)]
    Stop(MachineStopArgs),
    /// Patch a persistent machine's config and relaunch it
    #[command(display_order = 5)]
    Reconfigure(MachineReconfigureArgs),
    /// Remove one or more persistent named machine specs (or --all)
    #[command(name = "rm", display_order = 6)]
    Rm(MachineRemoveArgs),
    /// List every microVM: persistent machines and running transients (alias: `ps`)
    #[command(name = "ls", visible_alias = "ps", display_order = 7)]
    Ls(MachineListArgs),
    /// Show one persistent named machine spec
    #[command(display_order = 8)]
    Inspect(MachineInspectArgs),
    /// Attach an interactive shell/console to an already-started named machine
    #[command(display_order = 9)]
    Shell(MachineShellArgs),
    /// Run a command inside an already-started named machine
    #[command(display_order = 10)]
    Exec(MachineExecArgs),
    /// Update the runtime idle timeout for a running machine
    #[command(name = "set-timeout", display_order = 11)]
    SetTimeout(MachineSetTimeoutArgs),
    /// Show console logs from a running VM
    #[command(display_order = 12)]
    Logs(super::vm::logs::Args),
    /// Interactive PTY console to a running VM (dev images only; claim-15 gated)
    #[command(display_order = 13)]
    Console(super::vm::console::Args),
    /// Verify a portable `.mvm` artifact and preview how `machine run` would
    /// admit it (arch, profile, seccomp, egress, volumes). Read-only: no
    /// extraction, no boot.
    #[command(name = "check-artifact", display_order = 13)]
    CheckArtifact(portable::CheckArtifactArgs),
    /// Render a checkpoint or image's lineage (ancestors to genesis + immediate
    /// children), verifying each hop against the signed audit chain. Read-only:
    /// no restore, no admission, no boot.
    #[command(display_order = 14)]
    Timeline(super::vm::checkpoint::TimelineArgs),
    /// Restore a prior state: launch a fresh, re-admitted VM at the checkpoint or
    /// image node the target names. Verifies the target against the signed audit
    /// chain first and fails closed on an un-audited, tampered, or dangling
    /// record.
    #[command(display_order = 15)]
    Revert(super::vm::checkpoint::RevertArgs),
    /// Rewind one step: restore the target's parent in the lineage.
    #[command(display_order = 16)]
    Rewind(super::vm::checkpoint::RevertArgs),
    /// Advance one step: restore a child of the target (a fork needs `--to`).
    #[command(display_order = 17)]
    Advance(super::vm::checkpoint::AdvanceArgs),
    /// Warm-restore a vm_full checkpoint into a fresh child VM.
    /// The child inherits the saved machine state and receives a fresh
    /// generation token; the parent must be stopped.
    #[command(name = "warm-restore", display_order = 18)]
    WarmRestore(MachineWarmRestoreArgs),
    /// Advanced single-VM operations (pause, snapshot, cp, fs, …). Hidden; use `machine <verb>` directly.
    #[command(flatten)]
    Vm(VmCmd),
}

impl MachineAction {
    /// The `<verb>` slot in `cmd.<verb>.*` audit events. The folded advanced
    /// ops keep their own per-op verbs (`cmd.pause.*`, `cmd.set-ttl.*`, …) so
    /// the audit taxonomy is unchanged by the move from `vm` to `machine`; the
    /// native lifecycle verbs report as `machine`, as they always have.
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            MachineAction::Vm(cmd) => cmd.verb_name(),
            MachineAction::Run(_)
            | MachineAction::Build(_)
            | MachineAction::Create(_)
            | MachineAction::Start(_)
            | MachineAction::Restart(_)
            | MachineAction::Stop(_)
            | MachineAction::Reconfigure(_)
            | MachineAction::Rm(_)
            | MachineAction::Ls(_)
            | MachineAction::Inspect(_)
            | MachineAction::Shell(_)
            | MachineAction::Exec(_)
            | MachineAction::SetTimeout(_)
            | MachineAction::Logs(_)
            | MachineAction::Console(_)
            | MachineAction::CheckArtifact(_) => "machine",
            MachineAction::Timeline(_) => "timeline",
            MachineAction::Revert(_) => "revert",
            MachineAction::Rewind(_) => "rewind",
            MachineAction::Advance(_) => "advance",
            MachineAction::WarmRestore(_) => "warm-restore",
        }
    }
}

/// Ephemeral image-backed run. Mirrors the relevant subset of `mvmctl run`'s
/// flags and translates into the same admitted execution path.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineRunArgs {
    /// Boot an OCI image.
    #[arg(long, value_name = "REF", conflicts_with_all = ["manifest", "flake", "runtime_pack"])]
    pub image: Option<String>,
    /// Boot a pre-built manifest.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["image", "flake", "runtime_pack"])]
    pub manifest: Option<String>,
    /// Build and boot a Nix flake.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["image", "manifest", "runtime_pack"])]
    pub flake: Option<String>,
    /// Boot a verified runtime pack.
    #[arg(long, conflicts_with_all = ["image", "manifest", "flake"])]
    pub runtime_pack: bool,
    /// Select a flake package.
    #[arg(long, value_name = "PROFILE", requires = "flake")]
    pub flake_profile: Option<String>,
    /// Enable outbound networking (off by default).
    #[arg(long)]
    pub net: bool,
    /// Allow outbound access to HOST[:PORT] (repeatable).
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// Set the vCPU count.
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Set memory (for example, 512M or 1G).
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Select a security profile.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: RunProfile,
    /// Allow a production-safe guest-agent verb (repeatable).
    #[arg(long = "agent-verb", value_name = "VERB")]
    pub agent_verb: Vec<String>,
    /// Bind a host service the workload may call (repeatable).
    #[arg(long = "host-service", value_name = "SERVICE")]
    pub host_service: Vec<String>,
    /// Mount HOST_PATH at GUEST_PATH[:MODE].
    #[arg(long = "mount", visible_alias = "volume")]
    pub volume: Vec<String>,
    /// Set a guest environment variable (KEY=VALUE; repeatable).
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Set the command timeout in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Write a signed execution receipt.
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Print a redacted JSON summary.
    #[arg(long)]
    pub json: bool,
    /// Show the run plan without booting.
    #[arg(long)]
    pub dry_run: bool,
    /// Set the machine name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Keep the machine running and return.
    #[arg(short = 'd', long)]
    pub detach: bool,
    /// Return machine startup details as JSON.
    #[arg(long = "up-json")]
    pub up_json: bool,
    /// Stop the machine after DURATION (for example, 30s or 2h).
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
    /// Use CMD to check service health (exit 0 is healthy).
    #[arg(long, value_name = "CMD")]
    pub healthcheck: Option<String>,
    /// Record check interval in seconds (not yet enforced).
    #[arg(long = "health-interval", default_value_t = 30)]
    pub health_interval: u32,
    /// Record check timeout in seconds (not yet enforced).
    #[arg(long = "health-timeout", default_value_t = 5)]
    pub health_timeout: u32,
    /// Record failures before unhealthy (not yet enforced).
    #[arg(long = "health-retries", default_value_t = 3)]
    pub health_retries: u32,
    /// Record the initial grace period (not yet enforced).
    #[arg(long = "health-start-period", default_value_t = 0)]
    pub health_start_period: u32,
    /// Attach the command to an interactive PTY.
    #[arg(short = 't', long, conflicts_with_all = ["detach", "up_json", "ttl"])]
    pub tty: bool,
    /// Alias for `--tty` (supports the conventional `-it`).
    #[arg(
        short = 'i',
        long = "interactive",
        conflicts_with_all = ["detach", "up_json", "ttl"]
    )]
    pub interactive: bool,
    /// Recreate a named machine when its config changed.
    #[arg(long)]
    pub force: bool,
    /// Select the VMM (firecracker, hvf, libkrun, or qemu).
    #[arg(long, value_name = "HYPERVISOR")]
    pub hypervisor: Option<String>,
    /// Skip plan-admission signing (hidden; for testing only).
    #[arg(long, hide = true)]
    pub no_supervisor: bool,
    /// Boot the locally-built workload kernel from the mvm cache instead of the
    /// image's own kernel. Presence is the signal; the value is a label only.
    /// (Hidden — primarily threaded by `vm rekernel`.)
    #[arg(long = "kernel-pin", value_name = "PIN", hide = true)]
    pub kernel_pin: Option<String>,
    // ── Action axis: --entrypoint dispatches the image's baked entrypoint ──
    /// Run the image's baked entrypoint.
    #[arg(long, conflicts_with_all = ["argv", "tty", "interactive"])]
    pub entrypoint: bool,
    /// Boot a fresh VM for the entrypoint.
    #[arg(long, requires = "entrypoint", conflicts_with = "reset")]
    pub fresh: bool,
    /// Reset the VM before the entrypoint (currently a no-op).
    #[arg(long, requires = "entrypoint")]
    pub reset: bool,
    /// Load entrypoint secrets from workload IR.
    #[arg(long, value_name = "PATH", requires = "entrypoint")]
    pub from_workload_ir: Option<PathBuf>,
    /// Run the entrypoint on an existing named machine.
    #[arg(
        long,
        requires_all = ["entrypoint", "name"],
        conflicts_with_all = ["image", "manifest", "flake", "fresh", "reset", "detach"]
    )]
    pub attach: bool,
    /// Command and arguments to run in the guest.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

impl MachineRunArgs {
    /// Translate into the canonical transient-run argument shape. The
    /// launch-plan and OCI prod-pin surfaces are pinned off — they are not
    /// part of the beginner contract (the SDK live/plan/record transport was
    /// retired with the top-level `run` verb).
    /// Test-visible alias for [`Self::into_run_args`] so the flag-forwarding
    /// contract can be asserted from the transient-run module that consumes it.
    #[cfg(test)]
    pub(crate) fn into_run_args_for_test(self) -> RunArgs {
        self.into_run_args()
    }

    fn into_run_args(self) -> RunArgs {
        RunArgs {
            manifest: self.manifest,
            // Default off; `run_dispatch` sets it for the warm-claim-eligible
            // transient mode.
            warm_pool_size: 0,
            pty: false,
            vm_name: self.name,
            image: self.image,
            runtime_pack: self.runtime_pack,
            net: self.net,
            allow_host: self.allow_host,
            cpus: self.cpus,
            memory: self.memory,
            profile: self.profile,
            agent_verb: self.agent_verb,
            add_dir: self.volume,
            env: self.env,
            timeout: self.timeout,
            receipt: self.receipt,
            json: self.json,
            dry_run: self.dry_run,
            launch_plan: None,
            prod: false,
            // SDK-transport surface (`--mode`/`--dev`/`--ack-divergence`) stays
            // off — `machine run` is the beginner contract; that transport lives
            // on the hidden `run` verb the SDKs shell to.
            mode: None,
            dev: false,
            ack_divergence: Vec::new(),
            argv: self.argv,
            stdin: Vec::new(),
            healthcheck: crate::exec::build_healthcheck(
                self.healthcheck.as_deref(),
                self.health_interval,
                self.health_timeout,
                self.health_retries,
                self.health_start_period,
            ),
            hypervisor: self.hypervisor,
            host_service: self.host_service,
        }
    }

    /// `-t`/`--tty` or its `-i` alias requests an interactive PTY shell.
    fn interactive(&self) -> bool {
        self.tty || self.interactive
    }

    /// `-d`/`--detach`, `--up-json`, `--ttl`, or a declared `--healthcheck`
    /// makes the machine survive the command. `--tty`/`--name` are deliberately
    /// not consulted — persistence, interactivity, and identity are independent
    /// axes.
    fn persistent(&self) -> bool {
        self.detach || self.up_json || self.ttl.is_some() || self.healthcheck.is_some()
    }

    /// Resolve the lifecycle mode purely from the flags. Fresh foreground runs
    /// need an image source and an argv; persistent runs just boot and return.
    fn resolve_mode(&self) -> Result<MachineRunMode> {
        let mode = match (self.interactive(), self.persistent()) {
            (true, true) => bail!(
                "`machine run -it` is foreground-only; use `machine exec <name> -it -- <cmd>` for an interactive command in a long-lived machine"
            ),
            (false, true) => MachineRunMode::Persistent,
            // Fresh-boot modes always materialize a new VM and need an image.
            (true, false) => {
                self.require_image_for_fresh_boot()?;
                if self.argv.is_empty() {
                    bail!("machine run -it needs a command after `--`, for example `-- /bin/sh`");
                }
                MachineRunMode::InteractiveTransient
            }
            (false, false) => {
                self.require_image_for_fresh_boot()?;
                if self.argv.is_empty() {
                    bail!(
                        "machine run needs a command: pass `-- <cmd>`, \
                         or `-d`/`--detach` to boot a persistent machine, \
                         or `-it -- /bin/sh` for an interactive shell"
                    );
                }
                MachineRunMode::Transient
            }
        };
        Ok(mode)
    }

    /// Fresh-boot modes (transient, interactive-transient) have no spec to fall
    /// back on, so an image, manifest, flake, or runtime pack is mandatory.
    fn require_image_for_fresh_boot(&self) -> Result<()> {
        if self.image.is_none()
            && self.manifest.is_none()
            && self.flake.is_none()
            && !self.runtime_pack
        {
            bail!(
                "machine run needs `--image <ref>`, `--manifest <path>`, `--flake <path>`, or \
                 `--runtime-pack` to boot a new machine"
            );
        }
        Ok(())
    }
}

/// The lifecycle `machine run` resolves to, computed purely from the parsed
/// flags. Persistence (`-d`/`--up-json`/`--ttl`) and interactivity
/// (`-t`/`-i`) are independent axes; `--name` is only an identity unless one of
/// the persistence flags is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachineRunMode {
    /// Default one-shot: boot, run argv, tear down. Unchanged `run_secure`.
    Transient,
    /// Persistent (detached or lifecycle-managed), non-interactive.
    Persistent,
    /// Foreground command attached to a PTY on a transient machine.
    InteractiveTransient,
}

impl MachineRunMode {
    /// Warm-pool size for this run mode. Only unnamed foreground transient
    /// runs are throwaway cattle — eligible to claim a pre-booted standby and
    /// to replenish the pool. A named foreground run has an observable VM
    /// identity, and persistent machines are long-lived, so both cold-boot
    /// under the requested identity.
    fn warm_pool_size(self, explicit: Option<u32>, has_name: bool) -> u32 {
        match (self, has_name) {
            (MachineRunMode::Transient | MachineRunMode::InteractiveTransient, false) => {
                mvm_core::residency::effective_warm_pool_size(explicit)
            }
            (MachineRunMode::Transient | MachineRunMode::InteractiveTransient, true) => 0,
            (MachineRunMode::Persistent, _) => 0,
        }
    }
}

/// An auto-generated machine name for `-d` without `--name`. Reuses the
/// `mvm-core` helper so foreground and persistent generated names share one
/// human-friendly naming scheme.
fn auto_machine_name() -> String {
    naming::generate_machine_name()
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

/// A writable (`:rw`) host share needs a dev-capable profile, matching the
/// transient-run gate and the `dev.init` rule.
fn profile_allows_writable_volume(profile: &str) -> bool {
    matches!(profile, "dev" | "permissive")
}

/// Validate `--mount`/`--volume` specs and normalise them for storage in a managed
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

/// Build a persistent `MachineSpec` from the `run` flags. Mirrors the
/// validation `machine create` applies (network policy, memory, profile) so the
/// two entry points produce identical specs. The `run` surface intentionally
/// omits disk volumes / init — those stay manifest-driven.
///
/// For flake sources, `resolved_manifest_slot` must already contain the
/// built slot hash (the caller builds the flake before calling this function).
fn machine_run_spec(
    args: &MachineRunArgs,
    name: String,
    resolved_manifest_slot: Option<&str>,
) -> Result<MachineSpec> {
    validate_machine_name(&name)?;
    let (image, manifest) = if let Some(slot) = resolved_manifest_slot {
        // Flake was pre-built; store the slot hash as the manifest source.
        (None, Some(slot.to_string()))
    } else if let Some(m) = &args.manifest {
        // Manifest-backed: store the manifest ref.
        (None, Some(m.clone()))
    } else if let Some(img) = &args.image {
        // Image-backed: store the OCI ref.
        (Some(img.clone()), None)
    } else if args.runtime_pack {
        // The verified runtime pack is its own source; recorded via
        // `runtime_pack: true` below, not `image`/`manifest`.
        (None, None)
    } else if std::env::var("MVM_DIRECT_BOOT").as_deref() == Ok("1") {
        // Test escape: kernel + rootfs from env vars; no persistent source.
        (None, None)
    } else {
        bail!(
            "machine run needs `--image <ref>`, `--manifest <path>`, `--flake <path>`, or \
             `--runtime-pack` to create machine {name:?}"
        );
    };
    super::shared::resolve_run_network_policy(args.net, &args.allow_host)?;
    let _ = validate_machine_memory(&args.memory, None)?;
    let profile = run_profile_name(args.profile).to_string();
    Ok(MachineSpec {
        schema_version: MACHINE_SPEC_SCHEMA_VERSION,
        name,
        image,
        manifest,
        resolved_digest: None,
        runtime_pack: args.runtime_pack,
        net: args.net,
        allow_host: args.allow_host.clone(),
        cpus: args.cpus,
        memory: args.memory.clone(),
        mem_initial: None,
        profile,
        volumes: machine_run_volume_specs(args)?,
        init: Vec::new(),
        agent_verb: args.agent_verb.clone(),
        created_at: Some(mvm_core::time::utc_now()),
        last_started_at: None,
        health_check: crate::exec::build_healthcheck(
            args.healthcheck.as_deref(),
            args.health_interval,
            args.health_timeout,
            args.health_retries,
            args.health_start_period,
        ),
    })
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineCreateArgs {
    /// Persistent machine name (auto-generated and printed if omitted).
    /// Lowercase alphanumeric plus hyphens.
    #[arg(long)]
    pub name: Option<String>,
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
    /// Print the listing as JSON.
    #[arg(long)]
    pub json: bool,
    /// Include transient machines that are no longer running.
    #[arg(short, long)]
    pub all: bool,
    /// Filter by sandbox tag (`KEY=VALUE`). Repeatable; all must match.
    #[arg(long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    /// Include machines whose TTL has expired but the reaper has not yet
    /// torn down. By default these are hidden from the listing.
    #[arg(long)]
    pub show_expired: bool,
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
#[command(group(
    clap::ArgGroup::new("target")
        .required(true)
        .args(["names", "all"])
))]
pub(in crate::commands) struct MachineRemoveArgs {
    /// Persistent machine name(s).
    #[arg(value_name = "NAME")]
    pub names: Vec<String>,
    /// Remove all persistent machine specs.
    #[arg(long, conflicts_with = "names")]
    pub all: bool,
    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Stop a running machine before removing it. Without this, removing a
    /// running machine is refused (its VM would be orphaned).
    #[arg(long)]
    pub force: bool,
    /// Print a JSON deletion summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineStartArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
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
    /// Suppress the human `started machine <name>` banner — set internally
    /// when an interactive shell attach follows. Not a CLI flag.
    #[arg(skip)]
    pub quiet: bool,
    /// Workload VMM backend. Defaults to the host's best supported backend
    /// (Linux+KVM → firecracker; macOS 26+ → hvf; macOS 13-25 → libkrun). On a
    /// Linux+KVM host, `--hypervisor libkrun` opts into the libkrun runtime instead
    /// of the firecracker default — both require `/dev/kvm` and enforce claim-10
    /// egress (qemu is a no-`/dev/kvm` dev/test fallback only). `MVM_HYPERVISOR` is
    /// the env equivalent.
    #[arg(long, value_name = "HYPERVISOR")]
    pub hypervisor: Option<String>,
    /// Skip plan-admission signing (hidden; for testing only).
    #[arg(long, hide = true)]
    pub no_supervisor: bool,
    /// Boot the locally-built workload kernel from the mvm cache instead of the
    /// image's own kernel. Presence is the signal; the value is a label only.
    /// (Hidden — primarily threaded by `vm rekernel`.)
    #[arg(long = "kernel-pin", value_name = "PIN", hide = true)]
    pub kernel_pin: Option<String>,
    /// True when the caller will exec a trailing argv command after the machine
    /// is up. Not a CLI flag — set programmatically by `run_persistent`.
    #[arg(skip)]
    pub has_ad_hoc_argv: bool,
}

/// CLI surface for `machine start`: one or more machine names plus the shared
/// start flags. Each name is booted through the single-machine
/// [`MachineStartArgs`] path, so the internal persistent-run caller and
/// `start_machine` are untouched. `--receipt`/`--json`/`--dry-run` are
/// single-machine outputs and are refused when more than one name is given.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineStartCmd {
    /// Persistent machine name(s) to boot.
    #[arg(value_name = "NAME", required = true)]
    pub names: Vec<String>,
    /// Write a signed machine-start receipt to this path (single machine only).
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Print a machine-readable, redacted start summary as JSON (single machine only).
    #[arg(long)]
    pub json: bool,
    /// Validate and explain the effective start without booting a VM (single machine only).
    #[arg(long)]
    pub dry_run: bool,
    /// Workload VMM backend. Defaults to the host's best supported backend
    /// (Linux+KVM → firecracker; macOS 26+ → hvf; macOS 13-25 → libkrun). On a
    /// Linux+KVM host, `--hypervisor libkrun` opts into the libkrun runtime instead
    /// of the firecracker default — both require `/dev/kvm` and enforce claim-10
    /// egress (qemu is a no-`/dev/kvm` dev/test fallback only). `MVM_HYPERVISOR` is
    /// the env equivalent.
    #[arg(long, value_name = "HYPERVISOR")]
    pub hypervisor: Option<String>,
    /// Skip plan-admission signing (hidden; for testing only).
    #[arg(long, hide = true)]
    pub no_supervisor: bool,
    /// Boot the locally-built workload kernel from the mvm cache instead of the
    /// image's own kernel. (Hidden — primarily threaded by `vm rekernel`.)
    #[arg(long = "kernel-pin", value_name = "PIN", hide = true)]
    pub kernel_pin: Option<String>,
}

impl MachineStartCmd {
    /// Build the single-machine [`MachineStartArgs`] for one name, cloning the
    /// shared flags. Interactive-only fields (`quiet`, `has_ad_hoc_argv`) stay
    /// off — those are set by the internal persistent-run path, not the CLI.
    fn start_args_for(&self, name: &str) -> MachineStartArgs {
        MachineStartArgs {
            name: name.to_string(),
            receipt: self.receipt.clone(),
            json: self.json,
            dry_run: self.dry_run,
            quiet: false,
            hypervisor: self.hypervisor.clone(),
            no_supervisor: self.no_supervisor,
            kernel_pin: self.kernel_pin.clone(),
            has_ad_hoc_argv: false,
        }
    }
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineExecArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Bypass the sealed-image accessibility check.
    #[arg(long)]
    pub force: bool,
    /// Attach the command to an interactive PTY.
    #[arg(short = 't', long)]
    pub tty: bool,
    /// Accepted as an alias for `-t` so `-it` parses.
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,
    /// Argv to run inside the guest (use `--` to separate). Omit to drop into
    /// an interactive shell, like `machine shell`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineShellArgs {
    /// Persistent machine name.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Bypass the sealed-image accessibility check.
    #[arg(long)]
    pub force: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineSetTimeoutArgs {
    /// Running VM name.
    pub name: String,
    /// New runtime idle timeout in seconds. Must be > 0.
    pub seconds: u64,
}

#[derive(ClapArgs, Debug, Clone)]
#[command(group(
    clap::ArgGroup::new("target")
        .required(true)
        .args(["names", "all"])
))]
pub(in crate::commands) struct MachineStopArgs {
    /// VM name(s) to stop.
    #[arg(value_name = "NAME")]
    pub names: Vec<String>,
    /// Stop all running VMs.
    #[arg(long, conflicts_with = "names")]
    pub all: bool,
    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

/// Patch a persistent machine's config and relaunch it. Only the flags
/// passed change; every other field is inherited (patch semantics).
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineReconfigureArgs {
    /// Persistent machine name to reconfigure.
    #[arg(value_name = "NAME")]
    pub name: String,
    /// Enable dev-tier outbound networking (broad egress + DNS).
    #[arg(long, conflicts_with = "no_net")]
    pub net: bool,
    /// Disable outbound networking (deny-all).
    #[arg(long = "no-net", conflicts_with = "net")]
    pub no_net: bool,
    /// Replace the egress allowlist with these hosts: `HOST[:PORT]`
    /// (repeatable). Omit to inherit the current allowlist.
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// Clear the egress allowlist (remove all entries).
    #[arg(long = "clear-allow-host", conflicts_with = "allow_host")]
    pub clear_allow_host: bool,
    /// New vCPU count.
    #[arg(long)]
    pub cpus: Option<u32>,
    /// New memory (human-readable: 512M, 1G, ...).
    #[arg(long)]
    pub memory: Option<String>,
    /// New initial host memory commitment (human-readable).
    #[arg(long = "mem-initial")]
    pub mem_initial: Option<String>,
    /// Workload VMM backend for the relaunch (defaults to the host's best).
    #[arg(long, value_name = "HYPERVISOR")]
    pub hypervisor: Option<String>,
}
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct MachineWarmRestoreArgs {
    /// vm_full checkpoint id to restore.
    #[arg(value_name = "CHECKPOINT_ID")]
    pub checkpoint: String,
    /// Name for the fresh child VM (auto-generated if omitted).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Output the result as JSON.
    #[arg(long)]
    pub json: bool,
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

impl MachineCreateArgs {
    fn into_spec(self) -> Result<MachineSpec> {
        // Auto-generate a name when `--name` is omitted, mirroring `machine run
        // -d` (`create_machine` prints the chosen name).
        let name = match self.name {
            Some(name) => {
                validate_machine_name(&name)?;
                name
            }
            None => auto_machine_name(),
        };
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
            name,
            image: Some(image),
            manifest: None,
            resolved_digest: None,
            runtime_pack: false,
            net,
            allow_host,
            cpus,
            memory,
            mem_initial,
            profile: profile_name,
            volumes,
            init,
            agent_verb: Vec::new(),
            created_at: Some(mvm_core::time::utc_now()),
            last_started_at: None,
            health_check: None,
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn profile_allows_dev_init(profile: &str) -> bool {
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

fn validate_machine_name(name: &str) -> Result<()> {
    naming::validate_id(name, "machine name")
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

/// Live status label for a persisted machine, resolved through the backend.
fn machine_status_label(name: &str) -> &'static str {
    if lifecycle::machine_is_running(name) {
        "running"
    } else {
        "stopped"
    }
}

/// Health label for a machine's readiness, as shown in `machine ls`'s HEALTH
/// column and `machine inspect`'s `health:` line. `None` covers both a
/// registry entry with no readiness signal yet and a machine absent from the
/// registry entirely.
fn health_cell(readiness: Option<&mvm_core::domain::instance::InstanceReadiness>) -> &'static str {
    use mvm_core::domain::instance::InstanceReadiness;
    match readiness {
        Some(InstanceReadiness::ServicesReady) => "healthy",
        Some(InstanceReadiness::Degraded { .. }) => "unhealthy",
        Some(InstanceReadiness::ServicesStarting { .. }) => "starting",
        _ => "-",
    }
}

/// Coarse, human-friendly age of a machine from its `created_at` timestamp,
/// relative to `now`. `-` when absent/unparseable. Takes `now` explicitly so
/// the buckets are unit-testable.
fn humanize_age(created: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> String {
    let Some(created) = created else {
        return "-".to_string();
    };
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(created) else {
        return "-".to_string();
    };
    let secs = (now - then.with_timezone(&chrono::Utc)).num_seconds();
    match secs {
        s if s < 0 => "-".to_string(),
        s if s < 60 => "just now".to_string(),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

/// Resolve the concrete set of machine names a `rm` invocation targets. With
/// `--all` this is every persisted spec (already name-sorted); otherwise it is
/// the positional names, de-duplicated while preserving argument order.
fn resolve_remove_targets(all: bool, names: &[String]) -> Result<Vec<String>> {
    if all {
        return Ok(list_machine_specs()?
            .into_iter()
            .map(|spec| spec.name)
            .collect());
    }
    let mut targets = Vec::with_capacity(names.len());
    for name in names {
        if !targets.contains(name) {
            targets.push(name.clone());
        }
    }
    Ok(targets)
}

/// Refusal message when `machine rm` targets running machines without
/// `--force`. Returns `None` when nothing is running (so removal proceeds).
/// Pure so the wording is unit-testable.
fn rm_running_refusal(running: &[String]) -> Option<String> {
    if running.is_empty() {
        return None;
    }
    Some(format!(
        "refusing to remove running machine(s) {}: their VMs would be orphaned. \
         Stop them first (`mvmctl machine stop {}`), or pass `--force` to stop and remove.",
        running.join(", "),
        running.join(" ")
    ))
}

fn ensure_machine_spec_exists(name: &str) -> Result<MachineSpec> {
    // `load_machine_spec` already emits an actionable "does not exist" message
    // for a missing spec, so no extra context wrapper is needed here.
    load_machine_spec(name)
}

fn mark_machine_started(spec: &mut MachineSpec, resolved_digest: String) {
    spec.resolved_digest = Some(resolved_digest);
    spec.last_started_at = Some(mvm_core::time::utc_now());
}

/// Human/JSON notice printed when `machine start` targets a machine that is
/// already running. Pure so the wording is unit-testable; the liveness probe
/// itself lives in [`machine_is_running`].
fn already_running_notice(name: &str, json: bool) -> String {
    if json {
        serde_json::json!({ "machine": name, "already_running": true }).to_string()
    } else {
        format!("machine {name} is already running")
    }
}

fn machine_start_audit_detail(input: &MachineStartReceiptInput) -> String {
    format!(
        "source=machine.start network={} enforced={} shares={} init_commands={}",
        input.network_posture,
        input.egress_enforcement,
        machine_start_volume_summary(&input.volumes),
        input.init.command_count
    )
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
) -> Result<Vec<mvm_runtime::image::RuntimeVolume>> {
    let mut volume_cfg = Vec::with_capacity(volume_specs.len());
    for volume in volume_specs {
        let spec = super::shared::parse_volume_spec(volume)?;
        let vmv = super::shared::vm_volume_from_spec_validated(&spec)
            .with_context(|| format!("volume {volume:?}"))?;
        super::shared::materialize_disk_volume(&vmv)
            .with_context(|| format!("volume {volume:?}"))?;
        volume_cfg.push(mvm_runtime::image::RuntimeVolume::from(&vmv));
    }
    Ok(volume_cfg)
}

fn run_machine_init_commands(name: &str, commands: &[String]) -> Result<()> {
    if commands.is_empty() {
        return Ok(());
    }
    let session = crate::exec::SessionVm {
        vm_name: name.to_string(),
    };
    let mut script = "set -e\n".to_string();
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

fn stop_failed_machine_start(name: &str, backend_name: &str) {
    if let Err(err) = mvm_client::backend_stop_by_name(backend_name, name) {
        tracing::warn!(error = %err, machine = name, "stopping machine after failed init failed");
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        MachineAction::Run(run_args) => run_dispatch(cli, run_args, cfg),
        MachineAction::Build(build_args) => build::run(cli, build_args, cfg),
        MachineAction::Create(create_args) => create_machine(create_args),
        MachineAction::Ls(list_args) => list::list_machines(list_args),
        MachineAction::Inspect(inspect_args) => inspect_machine(inspect_args),
        MachineAction::Rm(remove_args) => remove_machine(remove_args),
        MachineAction::Start(start_cmd) => run_start(start_cmd),
        MachineAction::Restart(restart_cmd) => run_restart(restart_cmd),
        MachineAction::Exec(exec_args) => exec_machine(cli, exec_args, cfg),
        MachineAction::Shell(shell_args) => shell_machine(cli, shell_args, cfg),
        MachineAction::SetTimeout(timeout_args) => set_machine_timeout(timeout_args),
        MachineAction::Stop(stop_args) => stop_machine(cli, stop_args, cfg),
        MachineAction::Reconfigure(args) => run_reconfigure(args),
        MachineAction::Logs(log_args) => super::vm::logs::run(cli, log_args, cfg),
        MachineAction::Console(console_args) => super::vm::console::run(cli, console_args, cfg),
        MachineAction::CheckArtifact(a) => portable::run_check_artifact(a),
        MachineAction::Timeline(a) => super::vm::checkpoint::run_timeline(a),
        MachineAction::Revert(a) => {
            complete_revert(cli, cfg, super::vm::checkpoint::run_revert(a)?)
        }
        MachineAction::Rewind(a) => {
            complete_revert(cli, cfg, super::vm::checkpoint::run_rewind(a)?)
        }
        MachineAction::Advance(a) => {
            complete_revert(cli, cfg, super::vm::checkpoint::run_advance(a)?)
        }
        MachineAction::WarmRestore(args) => run_warm_restore(args),
        MachineAction::Vm(cmd) => {
            super::vm::group::run(cli, super::vm::group::Args { action: cmd }, cfg)
        }
    }
}

/// Run `machine warm-restore`: fork a vm_full checkpoint into a fresh child VM.
fn run_warm_restore(args: MachineWarmRestoreArgs) -> Result<()> {
    fork_vm_full_machine(ForkVmFullMachineInput {
        checkpoint_id: args.checkpoint,
        child_vm_name: args.name,
        json: args.json,
    })?;
    Ok(())
}

/// Finish a restore. A checkpoint restore completes inside the engine (the fork
/// re-admits + boots). An image-node restore re-runs the reconstructed reference
/// through the normal admitted `machine run` path so it re-admits identically.
fn complete_revert(
    cli: &Cli,
    cfg: &MvmConfig,
    outcome: super::vm::checkpoint::RevertOutcome,
) -> Result<()> {
    match outcome {
        super::vm::checkpoint::RevertOutcome::Done => Ok(()),
        super::vm::checkpoint::RevertOutcome::RunImage(run) => {
            let (args, source) = run_args_for_image_revert(run);
            run_secure_with_source(cli, args.into_run_args(), cfg, source)
        }
    }
}

/// Build the transient-run args and exact image source for an image-node restore. The restore
/// re-derives the current network policy at launch and never bakes the
/// snapshot-era posture: outbound networking stays off (`net = false`). On the
/// default `firecracker` backend that resolves to enforced default-deny; note
/// the pre-existing caveat that a libkrun transient run does not enforce
/// per-run egress, so "off" is a request the FC path enforces, not a blanket
/// guarantee on every backend.
fn run_args_for_image_revert(
    run: super::vm::checkpoint::RevertRunImage,
) -> (MachineRunArgs, Option<crate::exec::ImageSource>) {
    let (image, manifest, source) = match run.source {
        super::vm::checkpoint::RevertImageSource::Oci(reference) => (Some(reference), None, None),
        super::vm::checkpoint::RevertImageSource::Flake {
            slot_hash,
            revision_hash,
        } => (
            None,
            Some(format!("slot:{slot_hash}@{revision_hash}")),
            Some(crate::exec::ImageSource::PinnedTemplate {
                slot_hash,
                revision_hash,
            }),
        ),
    };
    (
        MachineRunArgs {
            image,
            flake: None,
            hypervisor: run.hypervisor,
            json: run.json,
            name: None,
            manifest,
            runtime_pack: false,
            flake_profile: None,
            net: false,
            allow_host: Vec::new(),
            cpus: 2,
            memory: "512M".to_string(),
            profile: RunProfile::Standard,
            agent_verb: Vec::new(),
            volume: Vec::new(),
            env: Vec::new(),
            timeout: None,
            receipt: None,
            dry_run: false,
            tty: false,
            interactive: false,
            force: false,
            no_supervisor: false,
            up_json: false,
            ttl: None,
            healthcheck: None,
            health_interval: 30,
            health_timeout: 5,
            health_retries: 3,
            health_start_period: 0,
            entrypoint: false,
            fresh: false,
            reset: false,
            from_workload_ir: None,
            attach: false,
            detach: false,
            kernel_pin: None,
            argv: Vec::new(),
            host_service: Vec::new(),
        },
        source,
    )
}

fn set_machine_timeout(args: MachineSetTimeoutArgs) -> Result<()> {
    if args.seconds == 0 {
        bail!("seconds must be > 0");
    }

    let (previous_secs, applied_secs) =
        super::vm::session::dispatch_update_idle_timeout(&args.name, args.seconds)?;
    ui::info(&format!(
        "substrate idle timeout: {previous_secs}s -> {applied_secs}s"
    ));
    Ok(())
}

/// Resolve CLI flags into a patch, validating memory eagerly so a bad
/// size fails before we overwrite anything or bounce the VM.
fn patch_from_args(args: &MachineReconfigureArgs) -> Result<ReconfigurePatch> {
    let net = if args.net {
        Some(true)
    } else if args.no_net {
        Some(false)
    } else {
        None
    };
    let allow_host = if args.clear_allow_host {
        Some(Vec::new())
    } else if !args.allow_host.is_empty() {
        Some(args.allow_host.clone())
    } else {
        None
    };
    // Validate memory (and mem_initial) against the same parser the run
    // path uses; store the human string, not the parsed MiB.
    if let Some(mem) = args.memory.as_deref() {
        validate_machine_memory(mem, args.mem_initial.as_deref())?;
    }
    Ok(ReconfigurePatch {
        net,
        allow_host,
        cpus: args.cpus,
        memory: args.memory.clone(),
        mem_initial: args.mem_initial.clone(),
    })
}

#[cfg(test)]
mod tests;
