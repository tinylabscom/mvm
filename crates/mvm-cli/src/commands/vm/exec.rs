//! `mvmctl run` — boot a transient microVM, run a single command, tear down.
//!
//! The former bare `mvmctl exec` was folded into `run`: `run` was already a
//! strict superset (see `RunArgs::into_exec_args`), so `exec` is gone and
//! `run --profile dev -- <argv>` covers its interactive case. The `Args`
//! struct + internal request machinery stay — `run_secure` reuses them.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::super::env::builder_vm::{
    assert_workload_kernel_supports_verity, ensure_default_microvm_image, ensure_workload_kernel,
};
use super::Cli;
use super::host_signer::{PUBLIC_FILENAME, host_signer_id, load_or_init};
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Boot a pre-built manifest (path to `mvm.toml`, its directory, or a
    /// legacy slot name). If omitted, the bundled
    /// `nix/images/default-tenant/` image is used (built via Nix on first use,
    /// cached at `~/.mvm/cache/default-microvm/`). Each invocation boots a
    /// fresh transient microVM — never the long-running builder VM.
    #[arg(short = 'm', long)]
    pub manifest: Option<String>,
    /// Internal (not a CLI flag): warm-pool size for this run, carried
    /// from `machine run` dispatch. `> 0` ⇒ eligible to claim a warm standby.
    #[arg(skip)]
    pub warm_pool_size: u32,
    /// Internal (not a CLI flag): attach the command to a PTY.
    #[arg(skip)]
    pub pty: bool,
    /// Internal (not a CLI flag): optional foreground transient VM identity.
    #[arg(skip)]
    pub vm_name: Option<String>,
    /// vCPU cores (default: 2)
    #[arg(long, default_value_t = crate::commands::shared::default_vcpus())]
    pub cpus: u32,
    /// Memory (supports human-readable: 512M, 1G, …)
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Internal (not a CLI flag): live directory shares forwarded from
    /// `machine run --mount` or the public `run --mount` surface.
    #[arg(skip)]
    pub mounts: Vec<String>,
    /// Environment variable to inject (KEY=VALUE). Repeatable. Overrides any env vars
    /// carried by `--launch-plan`.
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Per-command timeout in seconds. Unset ⇒ no per-command kill.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Path to an mvmforge document — either the `launch.json` artifact
    /// from `mvmforge compile` (top-level `entrypoint`) or the Workload IR
    /// manifest from `mvmforge emit` (top-level `apps[]`). The resolved
    /// entrypoint (command, working_dir, env) is invoked instead of a
    /// trailing argv. Mutually exclusive with the trailing `<ARGV>...`.
    #[arg(long, value_name = "PATH", conflicts_with = "argv")]
    pub launch_plan: Option<String>,
    /// Argv to run inside the guest (use `--` to separate). Required unless
    /// `--launch-plan` is supplied.
    // No `allow_hyphen_values`: it turns an unrecognized flag into a silent
    // argv element, so a typo fails inside the guest shell instead of here.
    #[arg(trailing_var_arg = true, required_unless_present = "launch_plan")]
    pub argv: Vec<String>,
    /// Internal (not a CLI flag): stdin bytes to forward into the guest `Exec`
    /// frame. Empty ⇒ no stdin (`Exec.stdin = None`). Populated at the
    /// dispatch site when the host stdin pipe is non-empty.
    #[arg(skip)]
    pub stdin: Vec<u8>,
    /// Internal (not a CLI flag): the resolved healthcheck declaration,
    /// forwarded from `machine run`'s `--healthcheck` + tuning flags.
    #[arg(skip)]
    pub healthcheck: Option<mvm_contract::ir::HealthCheck>,
    /// Internal (not a CLI flag): requested workload hypervisor, forwarded from
    /// `RunArgs::hypervisor` via `into_exec_args`.
    #[arg(skip)]
    pub hypervisor: Option<String>,
    /// Internal (not a CLI flag): raw `--host-service` values forwarded from
    /// `RunArgs::host_service` via `into_exec_args`.
    #[arg(skip)]
    pub host_service: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RunProfile {
    /// No environment variables or host shares.
    Restrictive,
    /// Environment variables and read-only host shares.
    Standard,
    /// As standard, plus a writable share on a persistent machine and the dev
    /// guest profile for a sealed-image entrypoint run.
    Dev,
    /// Local escape hatch; requires MVM_ACK_PERMISSIVE_RUN=1.
    Permissive,
}

/// What one profile permits.
///
/// The presets used to be spelled out in four places — the transient
/// validator, a stringly-typed `matches!(profile, "dev" | "permissive")` for
/// writable volumes, another for dev init, and prose in the docs. Four
/// declarations of one policy is four chances to disagree, and the one a
/// reader would check is not necessarily the one that runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProfileGrants {
    /// `--env` is accepted.
    pub env: bool,
    /// `--mount` is accepted at all.
    pub host_shares: bool,
    /// A `:rw` share is accepted **on a persistent machine**. A transient
    /// run's live share is read-only under every profile, which is why this
    /// is not simply "writable shares".
    pub writable_shares_when_persistent: bool,
    /// The guest gets the dev profile — a dev-shell agent, and DevOnly verbs
    /// on an image that would otherwise be sealed.
    pub dev_guest: bool,
    /// Refuses unless `MVM_ACK_PERMISSIVE_RUN=1` is set.
    pub needs_acknowledgement: bool,
}

impl RunProfile {
    /// Every profile, in increasing order of what it permits.
    pub(crate) const ALL: [Self; 4] = [
        Self::Restrictive,
        Self::Standard,
        Self::Dev,
        Self::Permissive,
    ];

    /// The name the CLI, the receipt, and the docs all use.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Restrictive => "restrictive",
            Self::Standard => "standard",
            Self::Dev => "dev",
            Self::Permissive => "permissive",
        }
    }

    /// Parse the name a persisted machine spec stored.
    ///
    /// Returns `None` for anything else rather than falling back to a
    /// default: a spec carrying a profile nobody recognises should stop the
    /// boot and say so, not be silently treated as whichever preset the
    /// comparison happened to miss.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == name)
    }

    /// The single declaration of what this profile permits.
    pub(crate) const fn grants(self) -> ProfileGrants {
        match self {
            Self::Restrictive => ProfileGrants {
                env: false,
                host_shares: false,
                writable_shares_when_persistent: false,
                dev_guest: false,
                needs_acknowledgement: false,
            },
            Self::Standard => ProfileGrants {
                env: true,
                host_shares: true,
                writable_shares_when_persistent: false,
                dev_guest: false,
                needs_acknowledgement: false,
            },
            Self::Dev => ProfileGrants {
                env: true,
                host_shares: true,
                writable_shares_when_persistent: true,
                dev_guest: true,
                needs_acknowledgement: false,
            },
            Self::Permissive => ProfileGrants {
                env: true,
                host_shares: true,
                writable_shares_when_persistent: true,
                dev_guest: true,
                needs_acknowledgement: true,
            },
        }
    }

    /// One line describing what this profile permits, for `doctor` and help.
    pub(crate) fn summary(self) -> String {
        let g = self.grants();
        let mut parts = Vec::new();
        parts.push(if g.env { "env allowed" } else { "no env" });
        parts.push(match (g.host_shares, g.writable_shares_when_persistent) {
            (false, _) => "no host shares",
            (true, false) => "read-only host shares",
            (true, true) => "host shares, writable on a persistent machine",
        });
        if g.dev_guest {
            parts.push("dev guest profile");
        }
        if g.needs_acknowledgement {
            parts.push("requires MVM_ACK_PERMISSIVE_RUN=1");
        }
        parts.join("; ")
    }
}

/// A run boots from exactly one source. Spelling the other four at each flag is
/// what let `run` and `machine run` disagree about which sources exist at all.
const SOURCES_EXCEPT_IMAGE: [&str; 4] = ["manifest", "flake", "runtime_pack", "deployment"];
const SOURCES_EXCEPT_MANIFEST: [&str; 4] = ["image", "flake", "runtime_pack", "deployment"];
const SOURCES_EXCEPT_FLAKE: [&str; 4] = ["image", "manifest", "runtime_pack", "deployment"];
const SOURCES_EXCEPT_RUNTIME_PACK: [&str; 4] = ["image", "manifest", "flake", "deployment"];
const SOURCES_EXCEPT_DEPLOYMENT: [&str; 4] = ["image", "manifest", "flake", "runtime_pack"];
const SOURCES_EXCEPT_RUNTIME: [&str; 5] =
    ["image", "manifest", "flake", "runtime_pack", "deployment"];

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RunArgs {
    /// The transport this launch derived, carried to admission so the signed
    /// plan records the mode the workload actually gets. Not a flag: the
    /// machine surface derives it from what the workload declares it needs.
    #[arg(skip)]
    pub network_mode: mvm_contract::plan::NetworkMode,
    /// Boot a pre-built manifest (mvm.toml, a directory, or a slot).
    #[arg(short = 'm', long, value_name = "PATH", conflicts_with_all = SOURCES_EXCEPT_MANIFEST)]
    pub manifest: Option<String>,
    /// Boot an OCI image (resolved through the local cache first).
    #[arg(long, value_name = "REF", conflicts_with_all = SOURCES_EXCEPT_IMAGE)]
    pub image: Option<String>,
    /// Build and boot a Nix flake.
    #[arg(long, value_name = "PATH", conflicts_with_all = SOURCES_EXCEPT_FLAKE)]
    pub flake: Option<String>,
    /// Select a flake package variant.
    #[arg(long, value_name = "PROFILE", requires = "flake")]
    pub flake_profile: Option<String>,
    /// Boot a local attested deployment (deploy.json plus rootfs.ext4).
    #[arg(long, value_name = "DIR", conflicts_with_all = SOURCES_EXCEPT_DEPLOYMENT)]
    pub deployment: Option<PathBuf>,
    /// Internal (not a CLI flag): warm-pool size for this run, set by
    /// `machine run` dispatch from the resolved run mode. `> 0` ⇒ eligible to
    /// claim a pre-booted standby + replenish the pool.
    #[arg(skip)]
    pub warm_pool_size: u32,
    /// Internal (not a CLI flag): attach the command to a PTY.
    #[arg(skip)]
    pub pty: bool,
    /// Internal (not a CLI flag): optional foreground transient VM identity.
    #[arg(skip)]
    pub vm_name: Option<String>,
    /// Boot a verified attested runtime pack.
    #[arg(long, conflicts_with_all = SOURCES_EXCEPT_RUNTIME_PACK)]
    pub runtime_pack: bool,
    /// Boot a named runtime from the built-in catalog.
    #[arg(long, value_name = "NAME", conflicts_with_all = SOURCES_EXCEPT_RUNTIME)]
    pub runtime: Option<String>,
    /// Do not infer a runtime from the command or working directory.
    #[arg(long, conflicts_with = "runtime")]
    pub no_detect: bool,
    /// Enable outbound networking (off by default).
    #[arg(long)]
    pub net: bool,
    /// Allow outbound access to HOST[:PORT] (repeatable).
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// Bind a peer route this workload may dial (repeatable).
    #[arg(long = "peer", value_name = "NAME:PORT=ADDR:PORT")]
    pub peer: Vec<String>,
    /// Set how many vCPUs the guest sees (not a host CPU share).
    #[arg(long, default_value_t = crate::commands::shared::default_vcpus())]
    pub cpus: u32,
    /// Cap host CPU time in millicores (1500 = 1.5 cores); not `--cpus`.
    #[arg(long = "cpu-limit", value_name = "MILLICORES")]
    pub cpu_limit: Option<u32>,
    /// Read grants (CPU, wall clock, egress) from a JSON file.
    #[arg(long = "grants-file", value_name = "PATH")]
    pub grants_file: Option<PathBuf>,
    /// Set memory (for example, 512M or 1G).
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Select a security profile.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: RunProfile,
    /// Attach a read-only host directory (HOST:/GUEST:ro, repeatable).
    #[arg(long = "mount", visible_alias = "volume", value_name = "HOST:GUEST:ro")]
    pub mounts: Vec<String>,
    /// Inject an environment variable (KEY=VALUE, repeatable).
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Set a per-command timeout in seconds.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Write a signed execution receipt to this path.
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Print a redacted JSON execution summary (no guest output).
    #[arg(long)]
    pub json: bool,
    /// Validate the run plan without booting a VM.
    #[arg(long)]
    pub dry_run: bool,
    /// Path to a launch document (excludes trailing argv).
    #[arg(long, value_name = "PATH", conflicts_with = "argv")]
    pub launch_plan: Option<String>,
    /// Require production policy (digest-pinned, verified images).
    #[arg(long = "prod")]
    pub prod: bool,
    /// Command to run inside the guest (after `--`).
    // No `allow_hyphen_values` — see `Args::argv` above.
    #[arg(trailing_var_arg = true)]
    pub argv: Vec<String>,
    /// Allow a production-safe guest-agent verb (repeatable).
    #[arg(long = "agent-verb", value_name = "VERB")]
    pub agent_verb: Vec<String>,
    /// Bind a host service this workload may call (repeatable).
    #[arg(long = "host-service", value_name = "SERVICE")]
    pub host_service: Vec<String>,
    /// Internal (not a CLI flag): stdin bytes to forward into the guest `Exec`
    /// frame. Empty ⇒ no stdin (`Exec.stdin = None`). Populated at the
    /// dispatch site when the host stdin pipe is non-empty.
    #[arg(skip)]
    pub stdin: Vec<u8>,
    /// Internal (not a CLI flag): the resolved healthcheck declaration,
    /// forwarded from `machine run`'s `--healthcheck` + tuning flags.
    #[arg(skip)]
    pub healthcheck: Option<mvm_contract::ir::HealthCheck>,
    /// Select the VMM (firecracker, hvf, libkrun, qemu, or web-linux).
    #[arg(long, value_name = "HYPERVISOR")]
    pub hypervisor: Option<String>,
}

/// Whether a verb infers a boot source it was not given.
///
/// `run` is the one-shot where "just run this" is the whole point, so it infers.
/// `machine run` creates a named — possibly persistent — machine, and guessing
/// its base image from whatever directory you happened to be standing in is a
/// footgun there: `machine run` inside any Rust checkout would silently build a
/// machine on `rust:1-alpine`. It keeps its own error, which names every way to
/// supply a source. `--runtime` still works on both, because that is the user
/// naming one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum Inference {
    /// Infer from `mvm.toml`, then argv[0], then a project file.
    Enabled,
    /// Only an explicit `--runtime` resolves.
    ExplicitOnly,
}

/// Where a run's boot source came from once every rule has had its say.
///
/// Returned rather than logged from inside the resolver so the caller decides
/// how to say it: a boot the user did not explicitly ask for must not be silent
/// about why it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum ResolvedSource {
    /// The user named a source; nothing was inferred.
    Explicit,
    /// An `mvm.toml` in or above the working directory supplied it.
    ProjectManifest(PathBuf),
    /// The command or the working directory selected a catalog runtime.
    Runtime(mvm_core::runtime_catalog::Detection),
    /// Nothing matched; the bundled default image is used.
    BundledDefault,
}

impl ResolvedSource {
    /// Say what was inferred, on stderr.
    ///
    /// Not `ui::info`, which is opt-in chatter shown only under `--verbose`: a
    /// boot whose image the user did not choose has to announce itself every
    /// time, or the first they learn of it is a "command not found" from a
    /// guest they never picked. stderr keeps `--json` stdout machine-readable.
    pub(in crate::commands) fn announce(&self) {
        if let Some(note) = self.note() {
            eprintln!("[mvm] {note}");
        }
    }

    /// The line to print before booting, or `None` when the user already knows
    /// what they asked for.
    pub(in crate::commands) fn note(&self) -> Option<String> {
        match self {
            ResolvedSource::Explicit | ResolvedSource::BundledDefault => None,
            ResolvedSource::ProjectManifest(path) => Some(format!(
                "using {} from the project directory",
                path.display()
            )),
            ResolvedSource::Runtime(d) => Some(format!(
                "detected {} from {} — booting {}",
                d.runtime,
                d.via.describe(),
                d.image
            )),
        }
    }
}

/// Settle which source a run boots from, filling `args` in place.
///
/// One resolver for both verbs. The order is the whole contract:
///
/// 1. An explicit `--image` / `--manifest` / `--flake` / `--deployment` /
///    `--runtime-pack` wins and nothing is inferred.
/// 2. `--runtime <name>` resolves against the built-in catalog. An unknown name
///    refuses — it never falls through to a default.
/// 3. `--no-detect`, or a verb that only takes explicit sources, stops here.
/// 4. An `mvm.toml` in or above the working directory, found by the same
///    walk-up `mvmctl build` already uses.
/// 5. The command being run, then a project file in the working directory.
/// 6. The bundled default image.
///
/// Inference only ever picks a *source*. It does not touch policy: a detected
/// run admits through the same signed `ExecutionPlan` with the same default-deny
/// egress as one that named its image, which is what
/// `a_detected_run_is_still_deny_all_and_admitted` pins.
pub(in crate::commands) fn resolve_run_source(
    args: &mut RunArgs,
    cwd: &std::path::Path,
    inference: Inference,
) -> Result<ResolvedSource> {
    if args.image.is_some()
        || args.manifest.is_some()
        || args.flake.is_some()
        || args.deployment.is_some()
        || args.runtime_pack
    {
        return Ok(ResolvedSource::Explicit);
    }

    let catalog = mvm_core::runtime_catalog::RuntimeCatalog::builtin();

    if let Some(name) = args.runtime.clone() {
        let detection = catalog
            .resolve_named(&name)
            .map_err(|e| anyhow::anyhow!(e))?;
        args.image = Some(detection.image.clone());
        adopt_declared_bindings(args, &detection);
        return Ok(ResolvedSource::Runtime(detection));
    }

    if args.no_detect || inference == Inference::ExplicitOnly {
        return Ok(ResolvedSource::BundledDefault);
    }

    if let Some(manifest) = mvm_core::domain::manifest::discover_manifest_from_dir(cwd)
        .context("looking for an mvm.toml in the working directory")?
    {
        args.manifest = Some(manifest.display().to_string());
        return Ok(ResolvedSource::ProjectManifest(manifest));
    }

    let present = project_files_in(cwd);
    if let Some(detection) = catalog
        .detect(args.argv.first().map(String::as_str), &present)
        .map_err(|e| anyhow::anyhow!(e))?
    {
        args.image = Some(detection.image.clone());
        adopt_declared_bindings(args, &detection);
        return Ok(ResolvedSource::Runtime(detection));
    }

    Ok(ResolvedSource::BundledDefault)
}

/// Merge a catalog entry's declared host-service bindings into the run args.
///
/// The entry declares what the runtime needs; `--host-service` is what the
/// operator asked for. Both end up in the signed plan, so this is a union
/// rather than a default: an operator who passes the flag is adding to the
/// entry's declaration, not replacing it, and neither can silently drop the
/// other's binding.
///
/// Duplicates are dropped here rather than left for
/// `parse_host_service_bindings`, so the count the user sees matches the count
/// the plan carries.
fn adopt_declared_bindings(args: &mut RunArgs, detection: &mvm_core::runtime_catalog::Detection) {
    for service in &detection.services {
        let raw = service.as_str().to_string();
        if !args.host_service.contains(&raw) {
            args.host_service.push(raw);
        }
    }
}

/// The plain filenames directly in `cwd`.
///
/// Detection reads names only — never contents — so a directory the user merely
/// stood in cannot influence anything but which image is chosen. An unreadable
/// directory detects nothing rather than failing the run.
fn project_files_in(cwd: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(cwd) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// The SDK transport surface, carried by `mvmctl run` alone.
///
/// These are kept out of [`RunArgs`] deliberately. `RunArgs` is flattened into
/// both `run` and `machine run` so a shared flag is declared exactly once;
/// `--mode`/`--dev`/`--ack-divergence` are not shared — `machine run` is the
/// beginner contract and has no business growing an SDK transport — so putting
/// them here is what lets the rest be flattened.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct SdkTransportArgs {
    /// SDK transport mode for `mvmctl run`.
    ///
    /// - `--mode plan`: synthesize an ExecutionPlan per Sandbox call
    ///   and route through `mvm_hostd::supervisor::admit_for_run`; no
    ///   microVM ever boots.
    /// - `--mode live`: spawn the user's script with `MVM_SDK_MODE=live`
    ///   so the SDK shells each `Sandbox` operation to existing
    ///   `mvmctl` verbs against a real microVM.
    /// - `--mode record` redirects users to `mvmctl build compile` (where
    ///   record is the default mode).
    ///
    /// When unset, the verb behaves as a transient-sandbox runner
    /// over the trailing argv.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<RunMode>,
    /// Friendly alias for `--mode live`.
    #[arg(long = "dev", conflicts_with_all = ["prod", "mode"])]
    pub dev: bool,
    /// Acknowledge a divergence class on the plan-mode admission
    /// path (repeatable). Unacknowledged divergence refuses
    /// admission: what you previewed is not what would ship.
    #[arg(long = "ack-divergence", value_name = "KIND")]
    pub ack_divergence: Vec<String>,
}

/// `mvmctl run` — the shared execution surface plus the SDK transport.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct TransientRunArgs {
    #[command(flatten)]
    pub run: RunArgs,
    #[command(flatten)]
    pub sdk: SdkTransportArgs,
}

/// The same values clap fills in when a flag is absent.
///
/// Two consumers want a `RunArgs` without spelling thirty fields: the
/// `machine` dispatch sites that build one programmatically, and the tests.
/// Writing them out by hand meant every new field edited every one of those
/// sites, so they drifted toward whatever the author happened to type rather
/// than toward what the CLI actually does.
///
/// The risk this introduces is that these values and the `#[arg(default_value)]`
/// attributes above disagree. `parsed_defaults_match_the_default_impl` is the
/// witness: it parses a bare `run -- x` and compares the result field by field.
impl Default for RunArgs {
    fn default() -> Self {
        Self {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            manifest: None,
            image: None,
            flake: None,
            flake_profile: None,
            deployment: None,
            warm_pool_size: 0,
            pty: false,
            vm_name: None,
            runtime_pack: false,
            runtime: None,
            no_detect: false,
            net: false,
            allow_host: Vec::new(),
            peer: Vec::new(),
            // Must track the clap default, which is resolved from the backend
            // this host selects — a test pins the two together, because a
            // `Default` that disagrees with the parsed default is a silent
            // difference between constructing args and parsing them.
            cpus: crate::commands::shared::default_vcpus(),
            cpu_limit: None,
            grants_file: None,
            memory: "512M".to_string(),
            profile: RunProfile::Standard,
            mounts: Vec::new(),
            env: Vec::new(),
            timeout: None,
            receipt: None,
            json: false,
            dry_run: false,
            launch_plan: None,
            prod: false,
            argv: Vec::new(),
            agent_verb: Vec::new(),
            host_service: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
        }
    }
}

/// SDK transport modes for `mvmctl run`. Mirrors the `Mode` enum on
/// `mvmctl build compile` but specialises the rejection messages to point
/// users at the right verb when they pick the wrong default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(in crate::commands) enum RunMode {
    /// Live transport — Sandbox calls shell out to existing mvmctl
    /// up / proc start / fs write / down against a real microVM.
    Live,
    /// Plan transport — synthesise one ExecutionPlan per Sandbox
    /// operation and route through `mvm_hostd::supervisor::admit_for_run`.
    /// No microVM boots. Useful for dry-running admission gates.
    Plan,
    /// Record transport — capture Sandbox operations into a
    /// recording and lower to a Workload. `mvmctl run --mode
    /// record` redirects users to `mvmctl build compile`, whose default
    /// mode is record.
    Record,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ReceiptArgs {
    #[command(subcommand)]
    pub action: ReceiptAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ReceiptAction {
    /// Verify a signed execution receipt emitted by `mvmctl run --receipt`.
    Verify {
        /// Receipt JSON path.
        path: PathBuf,
        /// Raw 32-byte Ed25519 public key to trust. Defaults to
        /// `~/.mvm/keys/host-signer.pub`.
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },
}

impl RunArgs {
    fn into_exec_args(self) -> Args {
        Args {
            manifest: self.manifest,
            warm_pool_size: self.warm_pool_size,
            pty: self.pty,
            vm_name: self.vm_name,
            cpus: self.cpus,
            memory: self.memory,
            mounts: self.mounts,
            env: self.env,
            timeout: self.timeout,
            launch_plan: self.launch_plan,
            argv: self.argv,
            stdin: self.stdin,
            healthcheck: self.healthcheck,
            hypervisor: self.hypervisor,
            host_service: self.host_service,
        }
    }
}

pub(in crate::commands) fn run_receipt(
    _cli: &Cli,
    args: ReceiptArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    match args.action {
        ReceiptAction::Verify { path, pubkey } => {
            let receipt = verify_run_receipt(&path, pubkey.as_deref())?;
            println!(
                "OK receipt={} signer_id={} exit_code={}",
                receipt.payload.receipt_id,
                receipt.signature.signer_id,
                receipt.payload.outcome.exit_code
            );
            Ok(())
        }
    }
}

pub(in crate::commands) fn run_secure(cli: &Cli, args: RunArgs, cfg: &MvmConfig) -> Result<()> {
    run_secure_with_source(cli, args, cfg, None)
}

/// `mvmctl run`: peel off the SDK transport, then fall through to the ordinary
/// transient run every other caller uses.
///
/// The peel happens here rather than inside `run_secure_with_source` so the
/// shared execution path never sees the transport flags, which is what lets
/// `RunArgs` be flattened into `machine run` without dragging them along.
pub(in crate::commands) fn run_transient(
    cli: &Cli,
    mut args: TransientRunArgs,
    cfg: &MvmConfig,
) -> Result<()> {
    if let Some(mode) = resolve_run_mode(&args.sdk, &args.run)? {
        return super::run_plan::dispatch_sdk_mode(mode, &args.run, &args.sdk);
    }
    // `argv` used to be `required_unless_present_any` over `launch_plan` /
    // `mode` / `dev` / `prod`. It cannot stay a clap attribute now that the
    // field is shared: `machine run -d` legitimately boots with no command, and
    // naming `mode`/`dev` from the shared struct would reference args that do
    // not exist on the `machine` side. So the one verb that needs it checks it.
    let cwd = std::env::current_dir().context("resolving the working directory")?;
    resolve_run_source(&mut args.run, &cwd, Inference::Enabled)?.announce();
    if args.run.argv.is_empty() && args.run.launch_plan.is_none() {
        anyhow::bail!(
            "`mvmctl run` needs a command: `mvmctl run -- <cmd>`. Use `--launch-plan <path>` \
             for a launch document, or `mvmctl machine run -d` to boot a machine with no command."
        );
    }
    run_secure(cli, args.run, cfg)
}

/// Run a transient workload through the normal admitted path, optionally
/// overriding the user-facing image lookup with an already-verified source.
/// The override is used only by content-addressed restore, where following a
/// mutable template pointer would boot the wrong revision.
pub(in crate::commands) fn run_secure_with_source(
    cli: &Cli,
    args: RunArgs,
    cfg: &MvmConfig,
    source_override: Option<crate::exec::ImageSource>,
) -> Result<()> {
    // When an SDK transport mode is requested, peel off the
    // SDK-shaped surface before the sandbox-runner validation kicks
    // in. `--dev` (alias for live) is refused in v1; `--prod` (alias
    // for record) redirects to `mvmctl build compile`; `--mode plan` routes
    // through the plan-mode admission dry-run.
    validate_run_profile(&args)?;
    if args.dry_run {
        let summary = RunPreflightSummary::from_args(&args)?;
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary)
                    .context("serializing run preflight JSON summary")?
            );
        } else {
            print_run_preflight_human(&summary);
        }
        return Ok(());
    }
    // One policy model for every backend: resolve the grant surfaces here —
    // which settles the egress policy in the same step — and thread the result
    // down both the json/receipt and the streaming paths.
    let host_config = mvm_core::user_config::load(None);
    let resolved_grants = super::shared::resolve_run_grants(super::shared::GrantInputs {
        cpu_limit_millicores: args.cpu_limit,
        timeout_secs: args.timeout,
        allow_host: &args.allow_host,
        peer: &args.peer,
        net: args.net,
        grants_file: args.grants_file.as_deref(),
        // A transient run names its image on the command line and reads no
        // project manifest; `machine create` is the verb that sources a
        // `[grants]` table.
        manifest: None,
        config: &host_config,
        ai: None,
    })?;
    let network_policy = resolved_grants.network_policy.clone();

    // Every transient run is admitted as a locally-signed workload (uniform
    // with `up`): a signed `ExecutionPlan` sets `tenant_id`, which makes the
    // libkrun/HVF supervisor spawn the enforcing gateway bridge (so the egress
    // policy is enforced and the run is chain-audited) instead of the legacy
    // unfiltered path. The closure runs inside the boot path with the resolved
    // rootfs + generated vm_name. cpus/mem are captured here because `args` is
    // consumed by `into_exec_args()` below.
    let selected_backend = crate::exec::select_exec_backend(
        args.image.is_some(),
        &network_policy,
        args.hypervisor.as_deref(),
    )?;
    // The typed kind, taken off the backend object itself: admission measures a
    // declared grant against the mechanisms this tier really has, and a name
    // parsed back into a tier would be measuring against whatever was typed.
    let admit_backend_kind = selected_backend.kind();
    let admit_backend = selected_backend.name().to_string();
    // The closure below moves `admit_backend`; keep a copy for the receipt's
    // honest per-backend enforcement tier.
    let receipt_backend = admit_backend.clone();
    let admit_network_mode = args.network_mode;
    let admit_grants = resolved_grants.plan_grants.clone();
    let admit_cpus = args.cpus;
    let admit_mem_mib = u64::from(parse_human_size(&args.memory).context("Invalid --memory")?);
    let admit_network_policy = network_policy.clone();
    let admit_agent_verb = args.agent_verb.clone();
    let (admit_host_services, admit_sidecar) =
        super::host_services::resolve_bindings_and_sidecar(&args.host_service)?;
    let admit_sdk_sidecar_grant = admit_sidecar.map(|a| a.grant);
    let admit_pty = args.pty;
    let admit_has_argv = !args.argv.is_empty();
    let admit_is_dev = matches!(args.profile, RunProfile::Dev);
    // The audit substrate carries no emitter, so stash the AdmissionContext here
    // as the closure runs (during boot) and emit launched/failed after `run`
    // returns — mirroring `up.rs`, so the claim-8 admitted/launched/failed
    // narrative holds on the transient-run path too.
    let admit_ctx: std::rc::Rc<std::cell::RefCell<Option<super::up::AdmissionContext>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let ctx_sink = std::rc::Rc::clone(&admit_ctx);
    // Written by image resolution below, read inside the closure once the real
    // plan exists, so the provenance entry binds to the plan that booted.
    let oci_provenance: OciProvenanceSink = std::rc::Rc::new(std::cell::RefCell::new(None));
    let provenance_for_admit = std::rc::Rc::clone(&oci_provenance);
    let admit = move |rootfs: &std::path::Path,
                      kernel: Option<&std::path::Path>,
                      vm_name: &str|
          -> Result<Option<crate::exec::SessionAuditSubstrate>> {
        let ledger = mvm_hostd::plan_admission::InMemoryNonceLedger::default();
        let ctx = super::up::admit_plan_for_boot(super::up::AdmitPlanForBootParams {
            network_mode: admit_network_mode,
            tenant: "local",
            vm_name,
            kernel_path: kernel,
            backend_name: &admit_backend,
            rootfs_path: rootfs,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: admit_cpus,
            mem_mib: admit_mem_mib,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            // No secrets on the plain transient path; deny secret release.
            secret_release: mvm_core::plan::SecretReleasePolicy::default(),
            secrets: vec![],
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: None,
            audit_dir: None,
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: admit_sdk_sidecar_grant.clone().into_iter().collect(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: admit_network_policy.clone(),
            agent_verb_override: admit_agent_verb.clone(),
            restrict_agent_verbs: crate::commands::vm::agent_verbs::grant_eligible(
                admit_pty,
                admit_has_argv,
                admit_is_dev,
            ),
            services: admit_host_services.clone(),
            grants: admit_grants.clone(),
            backend_kind: Some(admit_backend_kind),
            entrypoint: crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint::unresolved(
                "an ad-hoc argv run replaces the image entrypoint",
            ),
        })?;
        let Some(c) = ctx else { return Ok(None) };
        // Persist the bare plan so the pre-start moat / endpoint can read it
        // on the backends that consume it from disk (mirrors the invoke path).
        if super::up::persists_plan_before_start(&admit_backend) {
            super::plan_persist::write_plan(vm_name, c.admitted.plan())
                .context("persisting admitted plan for the transient run")?;
        }
        let guest_profile = super::up::guest_profile_for_boot(admit_is_dev, rootfs);
        let mut start_config = mvm_core::vm_backend::VmStartConfig::default();
        super::up::attach_guest_boot_config_for_plan(
            &mut start_config,
            c.admitted.plan(),
            &c.host_signer_public_path,
            guest_profile,
        )?;
        let plan_json = serde_json::to_string(c.admitted.signed())
            .context("serializing admitted plan for the transient run")?;
        let bundle_json = c
            .policy_bundle
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .context("serializing admitted policy bundle for the transient run")?;
        let substrate = crate::exec::SessionAuditSubstrate {
            tenant_id: c.admitted.plan().tenant.0.clone(),
            plan_json,
            bundle_json,
            config_files: start_config.config_files,
        };
        // Bind the OCI provenance to the plan that was just admitted, before
        // the backend starts. Claim 14 wants the image's origin in the chain
        // for the admission that booted it, and this is the first point where
        // that plan exists.
        if let Some(labels) = provenance_for_admit.borrow_mut().take() {
            c.emitter
                .emit_oci_provenance(c.admitted.plan(), labels)
                .context("recording OCI image provenance on the admitted plan")?;
        }

        // Hand the admission context (with its emitter) to the command layer so
        // it can emit `plan.launched` / `plan.failed` once the boot resolves.
        *ctx_sink.borrow_mut() = Some(c);
        Ok(Some(substrate))
    };

    let receipt_path = args.receipt.clone();
    if args.json || receipt_path.is_some() {
        let receipt_input = ReceiptInput::from_run_args(&args, &receipt_backend)?;
        let json_requested = args.json;
        let selection = ImageSelection {
            image_ref: args.image.clone(),
            prod: args.prod,
            runtime_pack: args.runtime_pack,
        };
        let req = build_exec_request(
            args.into_exec_args(),
            "`mvmctl run`",
            selection,
            network_policy,
            source_override.clone(),
            &oci_provenance,
        )?;
        let posture = crate::exec::PostureSink::new(mvm_build::run_image::RootStrategy::BlockExt4);
        let output = match crate::exec::run_captured_with_posture(req, Some(&admit), &posture) {
            Ok(o) => {
                let ctx = admit_ctx.borrow_mut().take();
                super::up::emit_launched_if(&ctx, &receipt_backend, false);
                super::up::emit_boot_posture_if(&ctx, posture.get());
                o
            }
            Err(e) => {
                let ctx = admit_ctx.borrow_mut().take();
                super::up::emit_failed_if(&ctx, "launch", &e);
                return Err(e);
            }
        };
        if !json_requested && !output.stdout.is_empty() {
            print!("{}", output.stdout);
        }
        if !json_requested && !output.stderr.is_empty() {
            eprint!("{}", output.stderr);
        }
        if !json_requested && let Some(timing) = output.phase_timing.as_ref() {
            eprintln!("{}", timing.render_table());
        }
        let summary = RunJsonSummary::from_parts(receipt_input.clone(), &output, receipt_path);
        if let Some(path) = summary.receipt_path.as_deref() {
            write_run_receipt(path, receipt_input, &output)?;
        }
        if json_requested {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).context("serializing run JSON summary")?
            );
        }
        if output.exit_code != 0 {
            std::process::exit(output.exit_code);
        }
        return Ok(());
    }
    let selection = ImageSelection {
        image_ref: args.image.clone(),
        prod: args.prod,
        runtime_pack: args.runtime_pack,
    };
    run_run_args(
        cli,
        args.into_exec_args(),
        cfg,
        selection,
        network_policy,
        source_override,
        RunAudit {
            admit: Some(&admit),
            ctx: &admit_ctx,
            backend: &receipt_backend,
            oci_provenance: &oci_provenance,
        },
    )
}

/// Resolve the `mvmctl run` transport mode from the explicit
/// `--mode` flag, the friendly `--dev` / `--prod` aliases, and the
/// `MVM_SDK_MODE` env-var override. Returns `Ok(None)` when no SDK
/// mode was requested — in that case the verb falls back to the
/// transient-sandbox runner over the trailing argv.
///
/// Env-var precedence matches `mvmctl build compile`: `MVM_SDK_MODE`
/// supersedes any flag-only override so a wrapper script can pin a
/// mode without the user retyping `--mode`.
pub(in crate::commands) fn resolve_run_mode(
    sdk: &SdkTransportArgs,
    run: &RunArgs,
) -> Result<Option<RunMode>> {
    if let Ok(env_mode) = std::env::var(mvm_sdk::env::MVM_SDK_MODE_ENV) {
        return Ok(Some(parse_env_run_mode(&env_mode)?));
    }
    if sdk.dev {
        return Ok(Some(RunMode::Live));
    }
    if run.prod {
        if run.image.is_some() {
            return Ok(None);
        }
        anyhow::bail!(
            "`mvmctl run --prod` (alias for --mode record) redirects to `mvmctl build compile`, where \
             record is the default mode. Re-run as `mvmctl build compile <script>` (the trailing argv \
             on `mvmctl run` is for the live sandbox runner, not for SDK record-mode)."
        );
    }
    match sdk.mode {
        None => Ok(None),
        Some(RunMode::Live) => Ok(Some(RunMode::Live)),
        Some(RunMode::Record) => anyhow::bail!(
            "`mvmctl run --mode record` is unsupported — `mvmctl build compile` is the record-mode verb \
             (record is the default; pass the script as the positional entry)."
        ),
        Some(RunMode::Plan) => Ok(Some(RunMode::Plan)),
    }
}

fn parse_env_run_mode(raw: &str) -> Result<RunMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "live" => Ok(RunMode::Live),
        "plan" => Ok(RunMode::Plan),
        "record" => anyhow::bail!(
            "MVM_SDK_MODE=record on `mvmctl run` is unsupported — `mvmctl build compile` is the \
             record-mode verb (record is its default)."
        ),
        other => anyhow::bail!(
            "MVM_SDK_MODE={other:?} is not recognized; expected one of: live, plan, record"
        ),
    }
}

fn validate_run_profile(args: &RunArgs) -> Result<()> {
    let grants = args.profile.grants();
    let name = args.profile.as_str();

    if grants.needs_acknowledgement && std::env::var_os("MVM_ACK_PERMISSIVE_RUN").is_none() {
        anyhow::bail!(
            "--profile permissive requires MVM_ACK_PERMISSIVE_RUN=1 so broad local execution is explicit"
        );
    }

    if !grants.env && !args.env.is_empty() {
        anyhow::bail!("--profile {name} does not allow --env");
    }
    if !grants.host_shares && !args.mounts.is_empty() {
        anyhow::bail!("--profile {name} does not allow --mount");
    }

    for spec in &args.mounts {
        let share = crate::commands::parse_dir_share_spec(spec)?;
        if !share.read_only {
            anyhow::bail!("--mount '{spec}' requests rw, but transient live shares are read-only");
        }
    }

    Ok(())
}

/// The boot-time admission hook plus the plumbing needed to chain-audit the
/// run after it resolves: the cell the hook fills with the `AdmissionContext`
/// (the audit emitter lives inside it) and the resolved backend name for the
/// audit `backend` label.
struct RunAudit<'a> {
    admit: Option<&'a crate::exec::SessionAdmit<'a>>,
    ctx: &'a std::cell::RefCell<Option<super::up::AdmissionContext>>,
    backend: &'a str,
    /// Filled by image resolution, read by the admission that boots it.
    oci_provenance: &'a OciProvenanceSink,
}

/// Carries the OCI provenance labels from image resolution to the admission
/// that boots the image.
///
/// The labels are discovered in `build_exec_request`, which runs before the
/// plan exists; the entry they belong on is emitted from the admit closure,
/// which runs after. Same shape as the `AdmissionContext` hand-off directly
/// above it: written on one side of the boot, read on the other.
pub(in crate::commands) type OciProvenanceSink =
    std::rc::Rc<std::cell::RefCell<Option<Vec<(String, String)>>>>;

/// The inputs that decide which `ImageSource` a run boots from: the OCI
/// reference (`--image`), the prod/dev posture that gates it, and whether to
/// boot from a verified attested runtime pack instead. Grouped so
/// `build_exec_request` and its callers don't grow a loose bool/Option
/// parameter apiece.
struct ImageSelection {
    image_ref: Option<String>,
    prod: bool,
    runtime_pack: bool,
}

fn run_run_args(
    _cli: &Cli,
    args: Args,
    _cfg: &MvmConfig,
    selection: ImageSelection,
    network_policy: mvm_core::network_policy::NetworkPolicy,
    source_override: Option<crate::exec::ImageSource>,
    audit: RunAudit<'_>,
) -> Result<()> {
    let req = build_exec_request(
        args,
        "`mvmctl run`",
        selection,
        network_policy,
        source_override,
        audit.oci_provenance,
    )?;
    let posture = crate::exec::PostureSink::new(mvm_build::run_image::RootStrategy::BlockExt4);
    let exit_code = match crate::exec::run_with_posture(req, audit.admit, &posture) {
        Ok(code) => {
            // The VM booted and the command ran (whatever its exit code), so the
            // admission launched — emit `plan.launched` plus the resolved boot
            // posture (virtiofs-root vs block-ext4) against the same plan.
            let ctx = audit.ctx.borrow_mut().take();
            super::up::emit_launched_if(&ctx, audit.backend, false);
            super::up::emit_boot_posture_if(&ctx, posture.get());
            code
        }
        Err(e) => {
            super::up::emit_failed_if(&audit.ctx.borrow_mut().take(), "launch", &e);
            return Err(e);
        }
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Resolve the [`crate::exec::ImageSource`] a launch boots from: the OCI image
/// named by `--image`, or — when none was named — the same verified runtime pack
/// or bundled default microVM a bare `machine run` falls back to.
///
/// Shared by the run path and by `pool warm`, because a warm parent must boot
/// the same rootfs a claim will be matched against: the pool keys on that
/// rootfs's digest, so resolving the image a second way is how the pool fills
/// with parents nothing claims. `provenance` is `None` for the warm path — a
/// factory parent is admitted under no workload plan, so there is no plan for
/// the claim-14 provenance entry to bind to.
pub(in crate::commands) fn resolve_launch_image_source(
    image_ref: Option<&str>,
    prod: bool,
    provenance: Option<&OciProvenanceSink>,
) -> Result<crate::exec::ImageSource> {
    let Some(reference) = image_ref else {
        return resolve_default_image_source(prod);
    };
    let oci_cache_root = super::super::image::oci_cache_root();
    // A prod run refuses a mutable OCI tag before ANY work — the
    // digest-pin policy refusal must be what the user sees, not an
    // incidental missing-kernel error from the local resolution
    // below. The pull path re-checks it, so this only reorders the
    // refusal ahead of the workload-kernel resolution.
    super::super::image::ensure_prod_digest_pin(reference, prod)?;
    // Resolve the workload kernel BEFORE the pull. An `--image` run
    // boots the materialized OCI rootfs (with its injected agent), so
    // it needs only a workload kernel — a cached workload/default-image
    // kernel, a local build (source checkout), or the published
    // download — rather than building/downloading a whole default image
    // whose rootfs we'd discard. Resolving it first makes a missing or
    // cold-cache kernel fail fast with an actionable error instead of
    // surfacing only after a full pull + rootfs materialization. The
    // rootfs boots verity-sealed, so the kernel must carry dm-verity;
    // the builder kernel (which drops it) is never a stand-in.
    let kernel_path = ensure_workload_kernel()?;
    // Enforce that invariant host-side: a kernel with no dm-verity
    // support would panic the guest in early init opening
    // /dev/mapper/control, with no host signal. Fail fast instead.
    assert_workload_kernel_supports_verity(&kernel_path)?;
    let cached = super::super::image::resolve_or_pull_run_image(&oci_cache_root, reference, prod)?;
    ui::info(&format!(
        "Using OCI image {} ({})",
        cached.reference, cached.resolved_digest
    ));
    // Hand the provenance to the real admission rather than
    // minting a plan here to hang it on. This used to synthesize a
    // throwaway `ExecutionPlan` and emit `plan.admitted` for it,
    // so one launch wrote two `plan.admitted` entries with
    // different plan ids — and the first authorized nothing, since
    // no VM ever booted under it. A reader of the chain could not
    // tell which of the two was the admission that mattered.
    if let Some(sink) = provenance {
        *sink.borrow_mut() = Some(cached.provenance.audit_labels());
    }
    if cached.pulled {
        let auth_source = cached.auth_source.as_deref().unwrap_or("unknown");
        mvm_core::audit_emit!(
            ImageFetch,
            "source=run_image reference={} digest={} prod={} layers={} trust_policy={} verification_status={} auth_source={}",
            cached.reference,
            cached.resolved_digest,
            prod,
            cached.provenance.layer_digests.len(),
            cached.provenance.trust_policy,
            cached.provenance.verification_status,
            auth_source
        );
    }
    Ok(crate::exec::ImageSource::Prebuilt {
        kernel_path,
        rootfs_path: cached.rootfs_path.display().to_string(),
        initrd_path: None,
        label: format!("oci:{}", cached.resolved_digest),
        // Offer the unpacked+injected tree as a virtiofs-root candidate;
        // the run-path tier gate (backend cap × prod × sealed) decides.
        virtiofs_oci_root: cached
            .unpacked_root
            .as_ref()
            .map(|tree| crate::exec::VirtiofsOciRoot {
                tree_dir: tree.display().to_string(),
                prod,
            }),
    })
}

/// The image a launch boots when the caller named none: a verified runtime pack
/// if one is cached for this host, else the bundled default microVM built in the
/// builder VM.
fn resolve_default_image_source(prod: bool) -> Result<crate::exec::ImageSource> {
    if let Some(src) = super::runtime_pack::try_runtime_pack_image_source(prod) {
        let label = match &src {
            crate::exec::ImageSource::Prebuilt { label, .. } => label.clone(),
            crate::exec::ImageSource::Template(name) => name.clone(),
            crate::exec::ImageSource::PinnedTemplate {
                slot_hash,
                revision_hash,
            } => format!("{slot_hash}@{revision_hash}"),
            crate::exec::ImageSource::WasmModule { label, .. } => label.clone(),
        };
        ui::info(&format!(
            "Instant boot from verified runtime pack ({label}); skipping the build."
        ));
        return Ok(src);
    }
    let reason = super::runtime_pack::runtime_pack_diagnosis()
        .ok()
        .and_then(|d| super::runtime_pack::not_instant_reason(&d))
        .unwrap_or_else(|| "no verified runtime pack is cached for this host".to_string());
    ui::info(&format!(
        "{reason}; building the bundled default microVM in the builder VM."
    ));
    let (kernel_path, rootfs_path) =
        ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Dev)?;
    Ok(crate::exec::ImageSource::Prebuilt {
        kernel_path,
        rootfs_path,
        initrd_path: None,
        label: "default-microvm".to_string(),
        virtiofs_oci_root: None,
    })
}

fn build_exec_request(
    args: Args,
    command_name: &str,
    selection: ImageSelection,
    network_policy: mvm_core::network_policy::NetworkPolicy,
    source_override: Option<crate::exec::ImageSource>,
    oci_provenance: &OciProvenanceSink,
) -> Result<crate::exec::ExecRequest> {
    let ImageSelection {
        image_ref,
        prod,
        runtime_pack,
    } = selection;
    let is_wasm = args.hypervisor.as_deref() == Some("wasm");
    let target = match (args.launch_plan.as_ref(), args.argv.is_empty(), is_wasm) {
        (Some(_), false, _) => {
            anyhow::bail!("--launch-plan and a trailing argv are mutually exclusive");
        }
        (Some(path), true, _) => {
            let entrypoint = crate::exec::load_launch_plan(std::path::Path::new(path))?;
            crate::exec::ExecTarget::LaunchPlan { entrypoint }
        }
        (None, true, true) => crate::exec::ExecTarget::Inline { argv: Vec::new() },
        (None, true, false) => {
            anyhow::bail!(
                "{command_name} requires a command (after `--`) or `--launch-plan <PATH>`"
            )
        }
        (None, false, _) => crate::exec::ExecTarget::Inline { argv: args.argv },
    };
    let memory_mib = parse_human_size(&args.memory).context("Invalid --memory")?;
    let mut dir_shares = Vec::with_capacity(args.mounts.len());
    for spec in &args.mounts {
        let share = crate::commands::parse_dir_share_spec(spec)?;
        if !share.read_only {
            anyhow::bail!("--mount '{spec}' requests rw, but transient live shares are read-only");
        }
        dir_shares.push(share);
    }
    let mut env_pairs = Vec::with_capacity(args.env.len());
    for kv in &args.env {
        env_pairs.push(parse_env_pair(kv)?);
    }
    let selected_backend = crate::exec::select_exec_backend(
        image_ref.is_some(),
        &network_policy,
        args.hypervisor.as_deref(),
    )?;
    let mut effective_env =
        oci_vsock_proxy_env_for_backend(&selected_backend, image_ref.is_some(), &network_policy);
    effective_env.extend(env_pairs);
    // --manifest <PATH> accepts a manifest path / dir in addition to
    // legacy names. Resolve up front so the downstream
    // ImageSource::Template carries either a name (legacy) or a slot
    // hash (manifest), and the dispatched lifecycle helpers handle
    // both keys transparently.
    //
    // --runtime-pack is its own image source, mutually exclusive with
    // --manifest/--image at the clap layer, so it short-circuits the match
    // below entirely rather than adding a third leg to it.
    let image = if runtime_pack {
        super::runtime_pack::resolve_runtime_pack_image_source(prod)
            .context("resolving --runtime-pack image source")?
    } else if let Some(source) = source_override {
        source
    } else {
        match (args.manifest, image_ref) {
            (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents --manifest + --image"),
            (Some(arg), None) => match super::shared::resolve_manifest_arg(&arg)? {
                super::shared::ManifestArgRef::Slot { slot_hash } => {
                    crate::exec::ImageSource::Template(slot_hash)
                }
                super::shared::ManifestArgRef::WasmModule {
                    manifest_path,
                    module_path,
                } => crate::exec::ImageSource::WasmModule {
                    module_path: module_path.display().to_string(),
                    label: format!(
                        "wasm:{}",
                        std::path::Path::new(&manifest_path)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("wasm")
                    ),
                },
            },
            (None, image_ref) => {
                resolve_launch_image_source(image_ref.as_deref(), prod, Some(oci_provenance))?
            }
        }
    };
    let (_, sdk_sidecar) = super::host_services::resolve_bindings_and_sidecar(&args.host_service)?;
    Ok(crate::exec::ExecRequest {
        name: args.vm_name,
        image,
        cpus: args.cpus,
        memory_mib,
        // mvmctl exec is a one-shot transient; no balloon plumbing
        // here yet. The manifest-driven path on mvmctl up is where
        // mem_initial gets sourced for long-running workloads.
        mem_initial_mib: None,
        dir_shares,
        env: effective_env,
        target,
        timeout_secs: args.timeout,
        pty: args.pty,
        network_policy,
        warm_pool_size: args.warm_pool_size,
        stdin: args.stdin,
        healthcheck: args.healthcheck,
        hypervisor: args.hypervisor,
        sdk_sidecar,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedRunReceipt {
    payload: RunReceiptPayload,
    signature: RunReceiptSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunReceiptPayload {
    schema_version: u32,
    receipt_id: String,
    recorded_at: String,
    invocation: ReceiptInput,
    outcome: ReceiptOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReceiptInput {
    manifest: Option<String>,
    image: Option<String>,
    cpus: u32,
    memory: String,
    profile: String,
    /// Requested egress posture (`deny-all`, `preset:dev`,
    /// `allow-list:host:port,...`). Non-sensitive; the signature covers it.
    network_posture: String,
    /// How faithfully the resolved backend actually enforces that posture
    /// (`flow-drop`, `open`, `<backend>:l4-host-port`). Recorded so the signed
    /// receipt cannot overstate enforcement fidelity — a host:port allow-list is
    /// now port-gated on every backend (Firecracker nftables; libkrun/HVF via the
    /// admission-time DNS pin → L4 scan). See `shared::egress_enforcement_label`.
    egress_enforcement: String,
    command: ReceiptCommand,
    env_keys: Vec<String>,
    mounts: Vec<ReceiptMount>,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ReceiptCommand {
    Inline {
        argv_len: usize,
        argv_sha256: String,
    },
    LaunchPlan {
        path_sha256: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReceiptMount {
    host_path_sha256: String,
    guest_path: String,
    read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReceiptOutcome {
    exit_code: i32,
    success: bool,
    stdout_sha256: String,
    stderr_sha256: String,
    stdout_bytes: usize,
    stderr_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunReceiptSignature {
    algorithm: String,
    signer_id: String,
    public_key_sha256: String,
    signature_base64: String,
}

mod preflight;
#[cfg(test)]
use preflight::RunPreflightImage;
use preflight::{RunJsonSummary, RunPreflightSummary, print_run_preflight_human};

impl ReceiptInput {
    fn from_run_args(args: &RunArgs, backend: &str) -> Result<Self> {
        // Resolve the egress policy once: the requested posture and the honest
        // per-backend enforcement tier are two views of the same policy.
        let policy = super::shared::resolve_run_network_policy_with_peers(
            args.net,
            &args.allow_host,
            &args.peer,
        )?;
        let command = if let Some(path) = &args.launch_plan {
            ReceiptCommand::LaunchPlan {
                path_sha256: sha256_hex(path.as_bytes()),
            }
        } else {
            let argv_bytes =
                serde_json::to_vec(&args.argv).context("serializing argv for receipt hash")?;
            ReceiptCommand::Inline {
                argv_len: args.argv.len(),
                argv_sha256: sha256_hex(&argv_bytes),
            }
        };

        mvm_runtime::backend::AnyBackend::require_hypervisor_selectable(backend)?;
        let selected_backend = mvm_runtime::backend::AnyBackend::from_hypervisor(backend);
        crate::exec::validate_image_egress_backend(
            &selected_backend,
            args.image.is_some(),
            &policy,
        )?;
        let mut env_keys =
            oci_vsock_proxy_env_for_backend(&selected_backend, args.image.is_some(), &policy)
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>();
        env_keys.reserve(args.env.len());
        for kv in &args.env {
            let (key, _) = kv
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--env '{kv}': expected KEY=VALUE"))?;
            env_keys.push(key.to_string());
        }
        env_keys.sort();
        env_keys.dedup();

        let mut mounts = Vec::with_capacity(args.mounts.len());
        for spec in &args.mounts {
            let parsed = crate::commands::parse_dir_share_spec(spec)?;
            mounts.push(ReceiptMount {
                host_path_sha256: sha256_hex(parsed.host_dir.as_bytes()),
                guest_path: parsed.guest_mount,
                read_only: parsed.read_only,
            });
        }

        Ok(Self {
            manifest: args.manifest.clone(),
            image: args.image.clone(),
            cpus: args.cpus,
            memory: args.memory.clone(),
            profile: args
                .profile
                .to_possible_value()
                .expect("value enum")
                .get_name()
                .to_string(),
            network_posture: policy.posture_label(),
            egress_enforcement: super::shared::egress_enforcement_label(backend, &policy),
            command,
            env_keys,
            mounts,
            timeout_secs: args.timeout.unwrap_or(60),
        })
    }
}

impl ReceiptCommand {
    fn describe(&self) -> String {
        match self {
            Self::Inline {
                argv_len,
                argv_sha256,
            } => format!("inline argv_len={argv_len} argv_sha256={argv_sha256}"),
            Self::LaunchPlan { path_sha256 } => {
                format!("launch_plan path_sha256={path_sha256}")
            }
        }
    }
}

impl ReceiptOutcome {
    fn from_exec_output(output: &crate::exec::ExecOutput) -> Self {
        Self {
            exit_code: output.exit_code,
            success: output.exit_code == 0,
            stdout_sha256: sha256_hex(output.stdout.as_bytes()),
            stderr_sha256: sha256_hex(output.stderr.as_bytes()),
            stdout_bytes: output.stdout.len(),
            stderr_bytes: output.stderr.len(),
        }
    }
}

fn parse_env_pair(kv: &str) -> Result<(String, String)> {
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
    Ok((k.to_string(), v.to_string()))
}

fn oci_vsock_proxy_env_for_capabilities(
    caps: &mvm_core::vm_backend::VmCapabilities,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Vec<(String, String)> {
    if !image_requested || !network_policy.allows_egress() {
        return Vec::new();
    }
    if !(caps.vsock && caps.no_routable_guest_nic && caps.host_vsock_proxy) {
        return Vec::new();
    }
    mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN)
}

fn oci_vsock_proxy_env_for_backend(
    backend: &mvm_runtime::backend::AnyBackend,
    image_requested: bool,
    network_policy: &mvm_core::network_policy::NetworkPolicy,
) -> Vec<(String, String)> {
    let caps = backend.capabilities();
    oci_vsock_proxy_env_for_capabilities(&caps, image_requested, network_policy)
}

fn write_run_receipt(
    path: &Path,
    invocation: ReceiptInput,
    output: &crate::exec::ExecOutput,
) -> Result<()> {
    let payload = RunReceiptPayload {
        schema_version: 1,
        receipt_id: uuid::Uuid::new_v4().to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        invocation,
        outcome: ReceiptOutcome::from_exec_output(output),
    };
    let payload_bytes = serde_json::to_vec(&payload).context("serializing run receipt payload")?;
    let signer = load_or_init().context("loading host signer for run receipt")?;
    let signature = signer.signing.sign(&payload_bytes);
    let public_key = signer.verifying.to_bytes();
    let receipt = SignedRunReceipt {
        payload,
        signature: RunReceiptSignature {
            algorithm: "ed25519".to_string(),
            signer_id: host_signer_id(),
            public_key_sha256: sha256_hex(&public_key),
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
        },
    };

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating receipt directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(&receipt).context("serializing run receipt")?;
    std::fs::write(path, bytes).with_context(|| format!("writing receipt {}", path.display()))?;
    Ok(())
}

fn verify_run_receipt(path: &Path, pubkey_path: Option<&Path>) -> Result<SignedRunReceipt> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading receipt {}", path.display()))?;
    let receipt: SignedRunReceipt = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing receipt {}", path.display()))?;
    if receipt.payload.schema_version != 1 {
        anyhow::bail!(
            "unsupported receipt schema_version {}; this build supports 1",
            receipt.payload.schema_version
        );
    }
    if !receipt.signature.algorithm.eq_ignore_ascii_case("ed25519") {
        anyhow::bail!(
            "unsupported receipt signature algorithm '{}'",
            receipt.signature.algorithm
        );
    }
    let verifying = load_receipt_pubkey(pubkey_path)?;
    let public_key = verifying.to_bytes();
    let actual_key_hash = sha256_hex(&public_key);
    if actual_key_hash != receipt.signature.public_key_sha256 {
        anyhow::bail!(
            "receipt was signed by public key {}; trusted key is {}",
            receipt.signature.public_key_sha256,
            actual_key_hash
        );
    }

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature.signature_base64)
        .context("decoding receipt signature")?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid receipt signature bytes: {e}"))?;
    let payload_bytes =
        serde_json::to_vec(&receipt.payload).context("serializing receipt payload")?;
    verifying
        .verify(&payload_bytes, &signature)
        .map_err(|e| anyhow::anyhow!("receipt signature verification failed: {e}"))?;
    Ok(receipt)
}

fn load_receipt_pubkey(path: Option<&Path>) -> Result<VerifyingKey> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => super::host_signer::default_keys_dir()?.join(PUBLIC_FILENAME),
    };
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading trusted receipt public key {}", path.display()))?;
    let key: [u8; super::host_signer::KEY_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display()))?;
    VerifyingKey::from_bytes(&key).with_context(|| format!("parsing {}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct RunSecuritySummary {
    pub dry_run: bool,
    pub will_execute: bool,
    pub image_kind: &'static str,
    pub cpus: u32,
    pub memory: String,
    pub memory_mib: u32,
    pub profile: String,
    pub receipt_requested: bool,
    pub preflight_network_posture: String,
    pub preflight_egress_enforcement: String,
    pub receipt_network_posture: String,
    pub receipt_egress_enforcement: String,
    pub preflight_command: String,
    pub receipt_command: String,
    pub preflight_env_keys: Vec<String>,
    pub receipt_env_keys: Vec<String>,
    pub preflight_mounts: Vec<RunSecurityMount>,
    pub receipt_mounts: Vec<RunSecurityMount>,
    pub preflight_timeout_secs: u64,
    pub receipt_timeout_secs: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct RunSecurityMount {
    pub host_path_sha256: String,
    pub guest_path: String,
    pub read_only: bool,
}

#[cfg(test)]
impl From<ReceiptMount> for RunSecurityMount {
    fn from(dir: ReceiptMount) -> Self {
        Self {
            host_path_sha256: dir.host_path_sha256,
            guest_path: dir.guest_path,
            read_only: dir.read_only,
        }
    }
}

#[cfg(test)]
pub(in crate::commands) fn test_run_security_summary(
    args: &RunArgs,
    receipt_backend: &str,
) -> Result<RunSecuritySummary> {
    let preflight = RunPreflightSummary::from_args(args)?;
    let receipt = ReceiptInput::from_run_args(args, receipt_backend)?;
    test_run_security_summary_from_parts(preflight, receipt)
}

#[cfg(test)]
pub(in crate::commands) fn test_run_security_summary_with_preflight_backend(
    args: &RunArgs,
    preflight_backend: &str,
    receipt_backend: &str,
) -> Result<RunSecuritySummary> {
    let preflight =
        RunPreflightSummary::from_args_with_backend_override(args, Some(preflight_backend))?;
    let receipt = ReceiptInput::from_run_args(args, receipt_backend)?;
    test_run_security_summary_from_parts(preflight, receipt)
}

#[cfg(test)]
fn test_run_security_summary_from_parts(
    preflight: RunPreflightSummary,
    receipt: ReceiptInput,
) -> Result<RunSecuritySummary> {
    let image_kind = match preflight.image {
        RunPreflightImage::DefaultMicrovm => "default-microvm",
        RunPreflightImage::Manifest { .. } => "manifest",
        RunPreflightImage::Oci { .. } => "oci",
        RunPreflightImage::RuntimePack => "runtime-pack",
    };
    Ok(RunSecuritySummary {
        dry_run: preflight.dry_run,
        will_execute: preflight.will_execute,
        image_kind,
        cpus: preflight.resources.cpus,
        memory: preflight.resources.memory,
        memory_mib: preflight.resources.memory_mib,
        profile: preflight.invocation.profile,
        receipt_requested: preflight.receipt.requested,
        preflight_network_posture: preflight.invocation.network_posture,
        preflight_egress_enforcement: preflight.invocation.egress_enforcement,
        receipt_network_posture: receipt.network_posture,
        receipt_egress_enforcement: receipt.egress_enforcement,
        preflight_command: preflight.invocation.command.describe(),
        receipt_command: receipt.command.describe(),
        preflight_env_keys: preflight.invocation.env_keys,
        receipt_env_keys: receipt.env_keys,
        preflight_mounts: preflight
            .invocation
            .mounts
            .into_iter()
            .map(Into::into)
            .collect(),
        receipt_mounts: receipt.mounts.into_iter().map(Into::into).collect(),
        preflight_timeout_secs: preflight.invocation.timeout_secs,
        receipt_timeout_secs: receipt.timeout_secs,
    })
}

#[cfg(test)]
mod host_service_flag_tests {
    #[test]
    fn machine_run_forwards_the_flag_into_the_transient_run_args() {
        use clap::Parser as _;
        let cli = crate::commands::Cli::try_parse_from([
            "mvmctl",
            "machine",
            "run",
            "--host-service",
            "host.audit.v1",
            "--host-service",
            "host.time.v1",
            "--",
            "true",
        ])
        .expect("machine run --host-service parses");
        let crate::commands::Commands::Machine(group) = cli.command else {
            panic!("expected the machine group");
        };
        let crate::commands::machine::MachineAction::Run(run) = group.action else {
            panic!("expected machine run");
        };
        assert_eq!(run.run.host_service, ["host.audit.v1", "host.time.v1"]);
        let forwarded = run.into_run_args_for_test().into_exec_args();
        assert_eq!(forwarded.host_service, ["host.audit.v1", "host.time.v1"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn dry_run_posture_reflects_resolved_policy() {
        // Default: deny-all.
        let mut args = run_args(RunProfile::Standard);
        let s = RunPreflightSummary::from_args(&args).expect("preflight");
        assert_eq!(s.invocation.network_posture, "deny-all");

        // --net → dev preset.
        args.net = true;
        let s = RunPreflightSummary::from_args(&args).expect("preflight");
        assert_eq!(s.invocation.network_posture, "preset:dev");

        // --allow-host wins over --net and defaults the port.
        args.allow_host = vec!["a.com".into(), "b.com:8443".into()];
        let s = RunPreflightSummary::from_args(&args).expect("preflight");
        assert_eq!(
            s.invocation.network_posture,
            "allow-list:a.com:443,b.com:8443"
        );
    }

    #[test]
    fn dry_run_preflight_honors_requested_hypervisor() {
        // A `RunArgs` carrying `--hypervisor libkrun` (as `machine run` threads
        // it via `into_run_args`) must make the dry-run receipt's resolved
        // backend agree — the same `select_exec_backend` call the admit/build/
        // boot sites use. Deny-all policy reports a uniform "flow-drop" label
        // regardless of backend, so use an allow-list posture (which is
        // `<backend>:l4-host-port`) to make the resolved backend observable.
        let mut args = run_args(RunProfile::Standard);
        args.allow_host = vec!["a.com".into()];
        args.hypervisor = Some("libkrun".to_string());
        let s = RunPreflightSummary::from_args(&args).expect("preflight");
        assert_eq!(s.invocation.egress_enforcement, "libkrun:l4-host-port");
    }

    #[test]
    fn receipt_records_resolved_posture() {
        let mut args = run_args(RunProfile::Standard);
        args.allow_host = vec!["api.example.com".into()];
        let r = ReceiptInput::from_run_args(&args, "firecracker").expect("receipt input");
        assert_eq!(r.network_posture, "allow-list:api.example.com:443");
    }

    #[test]
    fn receipt_enforcement_tier_is_uniform_l4_host_port() {
        // The signed receipt records the REQUESTED posture and, separately, the
        // enforcement fidelity. host:port is now L4-enforced on every backend, so
        // the tier is uniformly `<backend>:l4-host-port` (the backend is still
        // named so the receipt records which substrate enforced).
        let mut args = run_args(RunProfile::Standard);
        args.allow_host = vec!["api.example.com".into()];
        let fc = ReceiptInput::from_run_args(&args, "firecracker").expect("receipt input");
        assert_eq!(fc.egress_enforcement, "firecracker:l4-host-port");
        let krun = ReceiptInput::from_run_args(&args, "libkrun").expect("receipt input");
        assert_eq!(krun.egress_enforcement, "libkrun:l4-host-port");

        // deny-all is uniform across backends.
        let deny = run_args(RunProfile::Standard);
        let r = ReceiptInput::from_run_args(&deny, "hvf").expect("receipt input");
        assert_eq!(r.network_posture, "deny-all");
        assert_eq!(r.egress_enforcement, "flow-drop");
    }

    #[test]
    fn oci_vsock_proxy_env_requires_image_egress_and_vsock_proxy_backend() {
        let hvf_proxy_caps = mvm_core::vm_backend::VmCapabilities {
            vsock: true,
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            ..mvm_core::vm_backend::VmCapabilities::default()
        };
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        assert!(oci_vsock_proxy_env_for_capabilities(&hvf_proxy_caps, true, &deny_all).is_empty());

        assert!(
            oci_vsock_proxy_env_for_capabilities(
                &hvf_proxy_caps,
                false,
                &mvm_core::network_policy::NetworkPolicy::preset(
                    mvm_core::network_policy::NetworkPreset::Dev,
                ),
            )
            .is_empty()
        );
        assert!(
            oci_vsock_proxy_env_for_capabilities(
                &mvm_core::vm_backend::VmCapabilities::default(),
                true,
                &mvm_core::network_policy::NetworkPolicy::preset(
                    mvm_core::network_policy::NetworkPreset::Dev,
                ),
            )
            .is_empty()
        );

        let vars = oci_vsock_proxy_env_for_capabilities(
            &hvf_proxy_caps,
            true,
            &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                mvm_core::network_policy::HostPort::new("example.com", 443),
            ]),
        );
        assert!(
            vars.iter()
                .any(|(k, v)| k == "ALL_PROXY" && v == "socks5h://127.0.0.1:1080")
        );
        assert!(
            vars.iter()
                .any(|(k, v)| k == "HTTP_PROXY" && v == "http://127.0.0.1:1080")
        );
        assert!(
            vars.iter()
                .any(|(k, v)| k == "NO_PROXY" && v == "localhost,127.0.0.1,::1")
        );
    }

    #[test]
    fn receipt_accepts_oci_egress_on_libkrun_and_records_uniform_l4_enforcement() {
        let mut args = run_args(RunProfile::Standard);
        args.image = Some("docker.io/library/alpine:latest".to_string());
        args.allow_host = vec!["example.com".to_string()];

        let receipt = ReceiptInput::from_run_args(&args, "libkrun")
            .expect("libkrun OCI allow-host receipts should follow the active uniform L4 contract");
        assert_eq!(receipt.network_posture, "allow-list:example.com:443");
        assert_eq!(receipt.egress_enforcement, "libkrun:l4-host-port");
    }

    #[test]
    fn receipt_env_keys_include_injected_oci_proxy_vars() {
        let mut args = run_args(RunProfile::Standard);
        args.image = Some("docker.io/library/alpine:latest".to_string());
        args.allow_host = vec!["example.com".to_string()];
        args.env.push("HTTP_PROXY=override".to_string());
        args.env.push("APP_MODE=dev".to_string());

        let receipt = ReceiptInput::from_run_args(&args, "libkrun").expect("receipt input");
        let mut env_keys = std::collections::BTreeSet::from_iter(receipt.env_keys.clone());
        env_keys.extend(
            oci_vsock_proxy_env_for_capabilities(
                &mvm_core::vm_backend::VmCapabilities {
                    vsock: true,
                    no_routable_guest_nic: true,
                    host_vsock_proxy: true,
                    ..mvm_core::vm_backend::VmCapabilities::default()
                },
                true,
                &mvm_core::network_policy::NetworkPolicy::allow_list(vec![
                    mvm_core::network_policy::HostPort::new("example.com", 443),
                ]),
            )
            .into_iter()
            .map(|(k, _)| k),
        );
        assert!(env_keys.contains("ALL_PROXY"));
        assert!(env_keys.contains("HTTP_PROXY"));
        assert!(env_keys.contains("APP_MODE"));
        assert_eq!(
            env_keys
                .iter()
                .filter(|k| k.as_str() == "HTTP_PROXY")
                .count(),
            1
        );
    }

    fn run_args(profile: RunProfile) -> RunArgs {
        RunArgs {
            profile,
            timeout: Some(60),
            argv: vec!["/bin/true".to_string()],
            ..Default::default()
        }
    }

    /// The resolver decides which *source* a run boots from. These pin the
    /// order, because the order is the whole contract — and pin that inference
    /// never reaches policy.
    mod source_resolution {
        use super::*;

        fn touch(dir: &std::path::Path, name: &str) {
            std::fs::write(dir.join(name), b"").expect("write fixture file");
        }

        /// A directory with no `.git` above it, so the manifest walk-up stops
        /// there rather than finding this repo's own `mvm.toml`.
        fn sealed_dir() -> tempfile::TempDir {
            let dir = tempfile::tempdir().expect("tmpdir");
            std::fs::create_dir(dir.path().join(".git")).expect("git boundary");
            dir
        }

        #[test]
        fn an_explicit_image_is_never_second_guessed() {
            let dir = sealed_dir();
            touch(dir.path(), "package.json");
            let mut args = RunArgs {
                image: Some("alpine:3.20".to_string()),
                argv: vec!["npm".to_string()],
                ..Default::default()
            };
            let resolved =
                resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
            assert_eq!(resolved, ResolvedSource::Explicit);
            assert_eq!(args.image.as_deref(), Some("alpine:3.20"));
            assert!(
                resolved.note().is_none(),
                "nothing was inferred to announce"
            );
        }

        #[test]
        fn a_named_runtime_sets_its_image() {
            let dir = sealed_dir();
            let mut args = RunArgs {
                runtime: Some("go".to_string()),
                ..Default::default()
            };
            let resolved =
                resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
            assert!(matches!(resolved, ResolvedSource::Runtime(_)));
            assert_eq!(args.image.as_deref(), Some("golang:1-alpine"));
        }

        #[test]
        fn an_unknown_named_runtime_refuses_rather_than_falling_through() {
            let dir = sealed_dir();
            let mut args = RunArgs {
                runtime: Some("pyhton".to_string()),
                ..Default::default()
            };
            let err = resolve_run_source(&mut args, dir.path(), Inference::Enabled)
                .expect_err("must refuse");
            assert!(err.to_string().contains("unknown runtime"), "{err}");
            assert!(
                args.image.is_none(),
                "a refused run must not have chosen an image anyway"
            );
        }

        #[test]
        fn no_detect_leaves_the_bundled_default_even_in_a_project() {
            let dir = sealed_dir();
            touch(dir.path(), "Cargo.toml");
            let mut args = RunArgs {
                no_detect: true,
                argv: vec!["cargo".to_string()],
                ..Default::default()
            };
            let resolved =
                resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
            assert_eq!(resolved, ResolvedSource::BundledDefault);
            assert!(args.image.is_none());
            assert!(args.manifest.is_none());
        }

        #[test]
        fn a_project_manifest_beats_the_runtime_catalog() {
            // The project said what it is; the command is only a hint.
            let dir = sealed_dir();
            std::fs::write(
                dir.path().join("mvm.toml"),
                b"schema_version = 1\nname = \"demo\"\nimage = \"alpine:3.20\"\n",
            )
            .expect("write manifest");
            touch(dir.path(), "package.json");
            let mut args = RunArgs {
                argv: vec!["npm".to_string()],
                ..Default::default()
            };
            let resolved =
                resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
            assert!(matches!(resolved, ResolvedSource::ProjectManifest(_)));
            assert!(args.manifest.is_some());
            assert!(args.image.is_none(), "the manifest supplies the image");
        }

        #[test]
        fn the_catalog_runs_when_there_is_no_manifest() {
            let dir = sealed_dir();
            touch(dir.path(), "Cargo.toml");
            let mut args = RunArgs::default();
            let resolved =
                resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
            assert!(matches!(resolved, ResolvedSource::Runtime(_)));
            assert_eq!(args.image.as_deref(), Some("rust:1-alpine"));
        }

        #[test]
        fn nothing_recognised_falls_back_to_the_bundled_default() {
            let dir = sealed_dir();
            touch(dir.path(), "README.md");
            let mut args = RunArgs {
                argv: vec!["./mystery".to_string()],
                ..Default::default()
            };
            let resolved =
                resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");
            assert_eq!(resolved, ResolvedSource::BundledDefault);
            assert!(args.image.is_none());
        }

        /// Inference picks a source. It must not pick a posture: a detected run
        /// carries the same profile and the same deny-all egress as one that
        /// named its image, or "convenience" would be a policy bypass.
        #[test]
        fn a_detected_run_is_still_deny_all_and_standard_profile() {
            let dir = sealed_dir();
            touch(dir.path(), "package.json");
            let mut args = RunArgs::default();
            let before = (args.profile, args.net, args.allow_host.clone());

            resolve_run_source(&mut args, dir.path(), Inference::Enabled).expect("resolves");

            assert_eq!(args.image.as_deref(), Some("node:22-alpine"));
            assert_eq!(
                (args.profile, args.net, args.allow_host.clone()),
                before,
                "detection changed a policy field"
            );
            assert_eq!(args.profile, RunProfile::Standard);
            assert!(!args.net, "detected runs stay deny-all");
            assert!(args.allow_host.is_empty());
        }

        /// The verb that creates a named machine must not pick its base image
        /// from whatever directory the user happened to be standing in. Before
        /// this split, `machine run` inside any Rust checkout silently chose
        /// `rust:1-alpine`.
        #[test]
        fn explicit_only_ignores_the_working_directory() {
            let dir = sealed_dir();
            touch(dir.path(), "Cargo.toml");
            let mut args = RunArgs {
                argv: vec!["cargo".to_string(), "test".to_string()],
                ..Default::default()
            };
            let resolved = resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly)
                .expect("resolves");
            assert_eq!(resolved, ResolvedSource::BundledDefault);
            assert!(
                args.image.is_none() && args.manifest.is_none(),
                "explicit-only inferred a source anyway"
            );
        }

        /// …but naming one is the user speaking, so it resolves on both verbs.
        #[test]
        fn explicit_only_still_resolves_a_named_runtime() {
            let dir = sealed_dir();
            let mut args = RunArgs {
                runtime: Some("python".to_string()),
                ..Default::default()
            };
            let resolved = resolve_run_source(&mut args, dir.path(), Inference::ExplicitOnly)
                .expect("resolves");
            assert!(matches!(resolved, ResolvedSource::Runtime(_)));
            assert_eq!(args.image.as_deref(), Some("python:3.12-alpine"));
        }

        #[test]
        fn an_unreadable_directory_detects_nothing_instead_of_failing() {
            let mut args = RunArgs {
                argv: vec!["./mystery".to_string()],
                ..Default::default()
            };
            let missing = std::path::Path::new("/nonexistent-mvm-detect-fixture");
            // The manifest walk-up canonicalises, so a missing dir is an error
            // there; what must not happen is a panic or a silent image choice.
            let result = resolve_run_source(&mut args, missing, Inference::Enabled);
            assert!(args.image.is_none());
            assert!(result.is_err() || result.expect("ok") == ResolvedSource::BundledDefault);
        }
    }

    /// The signed receipt has to record which profile ran. Without it the
    /// artifact says what was executed but not what it was permitted to do,
    /// which is the half an auditor is reading it for.
    #[test]
    fn the_receipt_records_the_profile_that_ran() {
        for profile in RunProfile::ALL {
            let args = run_args(profile);
            let receipt = ReceiptInput::from_run_args(&args, "firecracker").expect("receipt");
            assert_eq!(
                receipt.profile,
                profile.as_str(),
                "the receipt must name the profile it ran under"
            );
        }
    }

    /// The preset table, asserted as a table. Phase 3's "preset-to-policy
    /// mapping" is exactly this: what each profile permits, written once and
    /// checked once, so a change to `grants()` has to be a deliberate edit to
    /// a row here rather than something that slips through four call sites.
    #[test]
    fn each_preset_grants_exactly_what_the_contract_says() {
        // (profile, env, host_shares, writable_when_persistent, dev_guest, ack)
        let expected = [
            (RunProfile::Restrictive, false, false, false, false, false),
            (RunProfile::Standard, true, true, false, false, false),
            (RunProfile::Dev, true, true, true, true, false),
            (RunProfile::Permissive, true, true, true, true, true),
        ];
        assert_eq!(
            expected.len(),
            RunProfile::ALL.len(),
            "a profile was added without a row here"
        );
        for (profile, env, shares, writable, dev_guest, ack) in expected {
            let g = profile.grants();
            let name = profile.as_str();
            assert_eq!(g.env, env, "{name}: --env");
            assert_eq!(g.host_shares, shares, "{name}: --mount");
            assert_eq!(
                g.writable_shares_when_persistent, writable,
                "{name}: :rw on a persistent machine"
            );
            assert_eq!(g.dev_guest, dev_guest, "{name}: dev guest profile");
            assert_eq!(g.needs_acknowledgement, ack, "{name}: acknowledgement");
        }
    }

    /// Permissions must only widen as the presets loosen. A preset that
    /// permitted something a looser one refuses would make "stricter" a
    /// meaningless word in the docs and the help.
    #[test]
    fn the_presets_are_ordered_from_strictest_to_loosest() {
        let mut prev = RunProfile::Restrictive.grants();
        for profile in RunProfile::ALL.into_iter().skip(1) {
            let g = profile.grants();
            for (label, was, now) in [
                ("env", prev.env, g.env),
                ("host_shares", prev.host_shares, g.host_shares),
                (
                    "writable_shares",
                    prev.writable_shares_when_persistent,
                    g.writable_shares_when_persistent,
                ),
                ("dev_guest", prev.dev_guest, g.dev_guest),
            ] {
                assert!(
                    now || !was,
                    "{} revokes `{label}`, which a looser preset granted",
                    profile.as_str()
                );
            }
            prev = g;
        }
    }

    #[test]
    fn a_profile_name_round_trips_and_an_unknown_one_refuses() {
        for profile in RunProfile::ALL {
            assert_eq!(RunProfile::from_name(profile.as_str()), Some(profile));
        }
        assert_eq!(RunProfile::from_name("dev-mode"), None);
        assert_eq!(RunProfile::from_name(""), None);
    }

    /// The validator must read the table rather than restate it, or the
    /// refusals and the contract can disagree.
    #[test]
    fn the_validator_refuses_exactly_what_the_table_withholds() {
        for profile in RunProfile::ALL {
            let g = profile.grants();
            if g.needs_acknowledgement {
                continue; // Its own witness; needs an env var.
            }

            let mut with_env = run_args(profile);
            with_env.env.push("FOO=bar".to_string());
            assert_eq!(
                validate_run_profile(&with_env).is_ok(),
                g.env,
                "{}: --env acceptance must match the table",
                profile.as_str()
            );

            let mut with_mount = run_args(profile);
            with_mount.mounts.push(".:/work:ro".to_string());
            assert_eq!(
                validate_run_profile(&with_mount).is_ok(),
                g.host_shares,
                "{}: --mount acceptance must match the table",
                profile.as_str()
            );
        }
    }

    /// `Default` is hand-written, so it can drift from the `default_value`
    /// attributes clap actually applies. Parse a bare invocation and compare.
    #[test]
    fn parsed_defaults_match_the_default_impl() {
        use clap::Parser;

        let parsed = crate::commands::Cli::try_parse_from(["mvmctl", "run", "--", "x"])
            .expect("bare `run -- x` parses");
        let crate::commands::Commands::Run(parsed) = parsed.command else {
            panic!("expected Commands::Run");
        };
        let expected = TransientRunArgs {
            run: RunArgs {
                argv: vec!["x".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(parsed.run.cpus, expected.run.cpus, "--cpus default");
        assert_eq!(parsed.run.memory, expected.run.memory, "--memory default");
        assert_eq!(
            parsed.run.profile, expected.run.profile,
            "--profile default"
        );
        assert_eq!(parsed.run.net, expected.run.net, "--net default");
        assert_eq!(parsed.run.json, expected.run.json, "--json default");
        assert_eq!(
            parsed.run.dry_run, expected.run.dry_run,
            "--dry-run default"
        );
        assert_eq!(parsed.run.prod, expected.run.prod, "--prod default");
        assert_eq!(
            parsed.run.timeout, expected.run.timeout,
            "--timeout default"
        );
        assert_eq!(
            parsed.run.cpu_limit, expected.run.cpu_limit,
            "--cpu-limit default"
        );
        assert_eq!(
            parsed.run.allow_host, expected.run.allow_host,
            "--allow-host default"
        );
        assert_eq!(parsed.run.mounts, expected.run.mounts, "--mount default");
        assert_eq!(parsed.run.env, expected.run.env, "--env default");
        assert_eq!(parsed.run.argv, expected.run.argv, "trailing argv");
        assert_eq!(parsed.sdk.mode, expected.sdk.mode, "--mode default");
        assert_eq!(parsed.sdk.dev, expected.sdk.dev, "--dev default");
        assert_eq!(
            parsed.sdk.ack_divergence, expected.sdk.ack_divergence,
            "--ack-divergence default"
        );
    }

    /// The shared half of `machine run` is the same `RunArgs`, so its defaults
    /// are the same values — including `--profile`, which the two verbs used to
    /// disagree about.
    #[test]
    fn machine_run_parsed_defaults_match_the_default_impl() {
        use clap::Parser;

        let parsed = crate::commands::Cli::try_parse_from(["mvmctl", "machine", "run", "--", "x"])
            .expect("bare `machine run -- x` parses");
        let crate::commands::Commands::Machine(machine) = parsed.command else {
            panic!("expected Commands::Machine");
        };
        let crate::commands::machine::MachineAction::Run(parsed) = machine.action else {
            panic!("expected MachineAction::Run");
        };
        let expected = crate::commands::machine::MachineRunArgs::default();

        assert_eq!(parsed.run.cpus, expected.run.cpus, "--cpus default");
        assert_eq!(parsed.run.memory, expected.run.memory, "--memory default");
        assert_eq!(
            parsed.run.profile, expected.run.profile,
            "--profile default must match `mvmctl run`"
        );
        assert_eq!(parsed.detach, expected.detach, "--detach default");
        assert_eq!(parsed.tty, expected.tty, "--tty default");
        assert_eq!(
            parsed.entrypoint, expected.entrypoint,
            "--entrypoint default"
        );
        assert_eq!(
            parsed.health_interval, expected.health_interval,
            "--health-interval default"
        );
        assert_eq!(
            parsed.health_timeout, expected.health_timeout,
            "--health-timeout default"
        );
        assert_eq!(
            parsed.health_retries, expected.health_retries,
            "--health-retries default"
        );
        assert_eq!(
            parsed.health_start_period, expected.health_start_period,
            "--health-start-period default"
        );
    }

    /// `resolve_run_mode` now reads the transport off `SdkTransportArgs` and the
    /// shared `RunArgs` separately, so each case names which half it exercises.
    fn sdk(mode: Option<RunMode>, dev: bool) -> SdkTransportArgs {
        SdkTransportArgs {
            mode,
            dev,
            ack_divergence: Vec::new(),
        }
    }

    #[test]
    fn resolve_run_mode_returns_none_when_no_mode_flag() {
        let args = run_args(RunProfile::Standard);
        let mode = resolve_run_mode(&sdk(None, false), &args).expect("no flag resolves to None");
        assert!(mode.is_none());
    }

    #[test]
    fn resolve_run_mode_returns_plan_when_mode_plan() {
        let args = run_args(RunProfile::Standard);
        let mode = resolve_run_mode(&sdk(Some(RunMode::Plan), false), &args)
            .expect("plan resolves")
            .unwrap();
        assert_eq!(mode, RunMode::Plan);
    }

    #[test]
    fn resolve_run_mode_returns_live_for_dev_alias() {
        let args = run_args(RunProfile::Standard);
        let mode = resolve_run_mode(&sdk(None, true), &args)
            .expect("--dev resolves to Some(Live)")
            .expect("must be Some(Live)");
        assert_eq!(mode, RunMode::Live);
    }

    #[test]
    fn resolve_run_mode_bails_redirect_for_prod_alias() {
        let mut args = run_args(RunProfile::Standard);
        args.prod = true;
        let err = resolve_run_mode(&sdk(None, false), &args).expect_err("--prod must bail");
        assert!(err.to_string().contains("mvmctl build compile"));
    }

    #[test]
    fn resolve_run_mode_leaves_image_prod_for_oci_policy() {
        let mut args = run_args(RunProfile::Standard);
        args.image = Some(
            "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        );
        args.prod = true;
        let mode = resolve_run_mode(&sdk(None, false), &args).expect("image prod is not SDK mode");
        assert!(mode.is_none());
    }

    #[test]
    fn resolve_run_mode_returns_live_for_mode_live() {
        let args = run_args(RunProfile::Standard);
        let mode = resolve_run_mode(&sdk(Some(RunMode::Live), false), &args)
            .expect("--mode live resolves to Some(Live)")
            .expect("must be Some(Live)");
        assert_eq!(mode, RunMode::Live);
    }

    #[test]
    fn resolve_run_mode_bails_redirect_for_mode_record() {
        let args = run_args(RunProfile::Standard);
        let err = resolve_run_mode(&sdk(Some(RunMode::Record), false), &args)
            .expect_err("--mode record must bail");
        assert!(err.to_string().contains("mvmctl build compile"));
    }

    #[test]
    fn standard_profile_rejects_writable_host_share() {
        let mut args = run_args(RunProfile::Standard);
        args.mounts.push(".:/work:rw".to_string());

        let err = validate_run_profile(&args).expect_err("standard rejects rw share");
        assert!(err.to_string().contains("requests rw"));
    }

    #[test]
    fn restrictive_profile_rejects_env() {
        let mut args = run_args(RunProfile::Restrictive);
        args.env.push("FOO=bar".to_string());

        let err = validate_run_profile(&args).expect_err("restrictive rejects env");
        assert!(err.to_string().contains("does not allow --env"));
    }

    #[test]
    fn restrictive_profile_rejects_host_share() {
        let mut args = run_args(RunProfile::Restrictive);
        args.mounts.push(".:/work".to_string());

        let err = validate_run_profile(&args).expect_err("restrictive rejects shares");
        assert!(err.to_string().contains("does not allow --mount"));
    }

    #[test]
    fn dev_profile_rejects_writable_host_share() {
        let mut args = run_args(RunProfile::Dev);
        args.mounts.push(".:/work:rw".to_string());

        let err = validate_run_profile(&args).expect_err("transient shares are always read-only");
        assert!(err.to_string().contains("requests rw"));
    }

    #[test]
    fn receipt_input_hashes_sensitive_fields() {
        let mut args = run_args(RunProfile::Dev);
        args.argv = vec!["curl".to_string(), "token-secret".to_string()];
        args.env.push("API_TOKEN=secret-value".to_string());
        args.mounts.push("/private/project:/work:ro".to_string());

        let receipt = ReceiptInput::from_run_args(&args, "firecracker").expect("receipt input");
        let json = serde_json::to_string(&receipt).expect("json");

        assert!(!json.contains("token-secret"));
        assert!(!json.contains("secret-value"));
        assert!(!json.contains("/private/project"));
        assert!(json.contains("API_TOKEN"));
        assert!(json.contains("/work"));
    }

    #[test]
    fn receipt_outcome_hashes_output_without_storing_output() {
        let output = crate::exec::ExecOutput {
            exit_code: 7,
            stdout: "secret stdout".to_string(),
            stderr: "secret stderr".to_string(),
            phase_timing: None,
        };

        let outcome = ReceiptOutcome::from_exec_output(&output);
        let json = serde_json::to_string(&outcome).expect("json");

        assert_eq!(outcome.exit_code, 7);
        assert!(!json.contains("secret stdout"));
        assert!(!json.contains("secret stderr"));
        assert_eq!(outcome.stdout_bytes, "secret stdout".len());
        assert_eq!(outcome.stderr_bytes, "secret stderr".len());
    }

    #[test]
    fn run_json_summary_omits_raw_output() {
        let args = run_args(RunProfile::Standard);
        let output = crate::exec::ExecOutput {
            exit_code: 0,
            stdout: "sensitive stdout".to_string(),
            stderr: "sensitive stderr".to_string(),
            phase_timing: Some(
                crate::commands::vm::phase_timing::RunPhaseTimingReport::new(
                    crate::commands::vm::phase_timing::RunPhaseTimings {
                        launch_mode: crate::commands::vm::phase_timing::LaunchMode::Cold,
                        resolve_ms: 1.0,
                        drives_ms: 2.0,
                        admit_ms: 3.0,
                        pool_wait_ms: 0.0,
                        claim_ms: 0.0,
                        backend_start_ms: 4.0,
                        vsock_wait_ms: 5.0,
                        warm_window_ms: 9.0,
                        command_ms: 6.0,
                        teardown_ms: 7.0,
                        total_ms: 28.0,
                    },
                    crate::commands::vm::launch_sample::LaunchSubTimings::default(),
                    Vec::new(),
                    Vec::new(),
                ),
            ),
        };
        let summary = RunJsonSummary::from_parts(
            ReceiptInput::from_run_args(&args, "firecracker").expect("receipt input"),
            &output,
            Some(PathBuf::from("/tmp/receipt.json")),
        );
        let json = serde_json::to_string(&summary).expect("serialize summary");
        assert!(json.contains("stdout_sha256"));
        assert!(json.contains("stderr_sha256"));
        assert!(json.contains("/tmp/receipt.json"));
        assert!(json.contains("\"phase_timing\""));
        assert!(json.contains("\"total_ms\":28.0"));
        assert!(!json.contains("sensitive stdout"));
        assert!(!json.contains("sensitive stderr"));
    }

    #[test]
    fn run_preflight_summary_is_redacted_and_does_not_execute() {
        let mut args = run_args(RunProfile::Dev);
        args.dry_run = true;
        args.json = true;
        args.manifest = Some("/private/manifest/mvm.toml".to_string());
        args.argv = vec!["curl".to_string(), "token-secret".to_string()];
        args.env.push("API_TOKEN=secret-value".to_string());
        args.mounts.push("/private/project:/work:ro".to_string());
        args.receipt = Some(PathBuf::from("/tmp/run-receipt.json"));

        let summary = RunPreflightSummary::from_args(&args).expect("preflight summary");
        let json = serde_json::to_string(&summary).expect("serialize summary");

        assert!(summary.dry_run);
        assert!(!summary.will_execute);
        assert_eq!(summary.resources.memory_mib, 512);
        assert!(json.contains("\"kind\":\"manifest\""));
        assert!(json.contains("API_TOKEN"));
        assert!(json.contains("/work"));
        assert!(json.contains("\"requested\":true"));
        assert!(!json.contains("/tmp/run-receipt.json"));
        assert!(!json.contains("/private/manifest/mvm.toml"));
        assert!(!json.contains("token-secret"));
        assert!(!json.contains("secret-value"));
        assert!(!json.contains("/private/project"));
    }

    #[test]
    fn run_preflight_validates_env_keys() {
        let mut args = run_args(RunProfile::Standard);
        args.dry_run = true;
        args.env.push("1BAD=value".to_string());

        let err = RunPreflightSummary::from_args(&args).expect_err("invalid env key");
        assert!(err.to_string().contains("KEY must match"));
    }

    #[test]
    fn verify_run_receipt_accepts_valid_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let receipt_path = dir.path().join("receipt.json");
        let pubkey_path = dir.path().join("host.pub");
        let signing = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        std::fs::write(&pubkey_path, signing.verifying_key().to_bytes()).expect("pubkey");

        let args = run_args(RunProfile::Standard);
        let payload = RunReceiptPayload {
            schema_version: 1,
            receipt_id: "receipt-1".to_string(),
            recorded_at: "2026-05-14T00:00:00Z".to_string(),
            invocation: ReceiptInput::from_run_args(&args, "firecracker").expect("receipt input"),
            outcome: ReceiptOutcome {
                exit_code: 0,
                success: true,
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(b""),
                stdout_bytes: 0,
                stderr_bytes: 0,
            },
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("payload");
        let signature = signing.sign(&payload_bytes);
        let receipt = SignedRunReceipt {
            payload,
            signature: RunReceiptSignature {
                algorithm: "ed25519".to_string(),
                signer_id: "host:test".to_string(),
                public_key_sha256: sha256_hex(&signing.verifying_key().to_bytes()),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(signature.to_bytes()),
            },
        };
        std::fs::write(
            &receipt_path,
            serde_json::to_vec_pretty(&receipt).expect("receipt json"),
        )
        .expect("write receipt");

        verify_run_receipt(&receipt_path, Some(&pubkey_path)).expect("valid receipt");
    }

    #[test]
    fn verify_run_receipt_rejects_tampered_payload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let receipt_path = dir.path().join("receipt.json");
        let pubkey_path = dir.path().join("host.pub");
        let signing = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        };
        std::fs::write(&pubkey_path, signing.verifying_key().to_bytes()).expect("pubkey");

        let args = run_args(RunProfile::Standard);
        let mut payload = RunReceiptPayload {
            schema_version: 1,
            receipt_id: "receipt-1".to_string(),
            recorded_at: "2026-05-14T00:00:00Z".to_string(),
            invocation: ReceiptInput::from_run_args(&args, "firecracker").expect("receipt input"),
            outcome: ReceiptOutcome {
                exit_code: 0,
                success: true,
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(b""),
                stdout_bytes: 0,
                stderr_bytes: 0,
            },
        };
        let payload_bytes = serde_json::to_vec(&payload).expect("payload");
        let signature = signing.sign(&payload_bytes);
        payload.outcome.exit_code = 1;
        let receipt = SignedRunReceipt {
            payload,
            signature: RunReceiptSignature {
                algorithm: "ed25519".to_string(),
                signer_id: "host:test".to_string(),
                public_key_sha256: sha256_hex(&signing.verifying_key().to_bytes()),
                signature_base64: base64::engine::general_purpose::STANDARD
                    .encode(signature.to_bytes()),
            },
        };
        std::fs::write(
            &receipt_path,
            serde_json::to_vec_pretty(&receipt).expect("receipt json"),
        )
        .expect("write receipt");

        let err = verify_run_receipt(&receipt_path, Some(&pubkey_path))
            .expect_err("tampered receipt rejected");
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn transient_grant_eligibility_matches_run_mode() {
        use crate::commands::vm::agent_verbs::grant_eligible;
        // Interactive transient (pty) issues ConsoleOpen → not eligible.
        assert!(!grant_eligible(true, false, false));
        // Ad-hoc transient (argv) issues Exec → not eligible.
        assert!(!grant_eligible(false, true, false));
        // Transient baked-entrypoint (no pty, no argv, prod profile) → eligible.
        assert!(grant_eligible(false, false, false));
        // Dev profile stays permissive by contract.
        assert!(!grant_eligible(false, false, true));
    }
}

#[cfg(test)]
mod declared_binding_tests {
    use super::*;

    fn detection(services: &[&str]) -> mvm_core::runtime_catalog::Detection {
        mvm_core::runtime_catalog::Detection {
            runtime: "svc".to_string(),
            image: "example:1".to_string(),
            via: mvm_core::runtime_catalog::DetectedVia::Command("svc".to_string()),
            services: services
                .iter()
                .map(|s| {
                    mvm_contract::protocol::broker::ServiceId::parse(*s).expect("valid service id")
                })
                .collect(),
            peers: Vec::new(),
        }
    }

    #[test]
    fn a_declared_binding_reaches_the_run_args() {
        let mut args = RunArgs::default();
        adopt_declared_bindings(&mut args, &detection(&["host.kv.v1"]));
        assert_eq!(args.host_service, vec!["host.kv.v1".to_string()]);
    }

    /// The entry declares what the runtime needs; the flag is what the
    /// operator asked for. Both reach the signed plan, so neither may drop
    /// the other's binding.
    #[test]
    fn a_declared_binding_and_an_operator_flag_are_unioned() {
        let mut args = RunArgs {
            host_service: vec!["host.time.v1".to_string()],
            ..RunArgs::default()
        };
        adopt_declared_bindings(&mut args, &detection(&["host.kv.v1"]));
        assert_eq!(
            args.host_service,
            vec!["host.time.v1".to_string(), "host.kv.v1".to_string()]
        );
    }

    /// Deduped here rather than downstream, so the count the user sees is the
    /// count the plan carries.
    #[test]
    fn a_binding_declared_and_also_passed_appears_once() {
        let mut args = RunArgs {
            host_service: vec!["host.kv.v1".to_string()],
            ..RunArgs::default()
        };
        adopt_declared_bindings(&mut args, &detection(&["host.kv.v1"]));
        assert_eq!(args.host_service, vec!["host.kv.v1".to_string()]);
    }

    /// The common case: an entry that declares nothing changes nothing, so
    /// every existing `--runtime` invocation keeps its exact posture.
    #[test]
    fn an_entry_declaring_nothing_leaves_the_args_untouched() {
        let mut args = RunArgs::default();
        adopt_declared_bindings(&mut args, &detection(&[]));
        assert!(args.host_service.is_empty());
    }
}
