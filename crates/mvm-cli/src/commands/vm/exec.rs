//! `mvmctl run` — boot a transient microVM, run a single command, tear down.
//!
//! The former bare `mvmctl exec` was folded into `run`: `run` was already a
//! strict superset (see `RunArgs::into_exec_args`), so `exec` is gone and
//! `run --profile dev -- <argv>` covers its dev-shell case. The `Args`
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

use super::super::env::dev_vz::ensure_default_microvm_image;
use super::Cli;
use super::audit_chain::AuditEmitter;
use super::host_signer::{PUBLIC_FILENAME, host_signer_id, load_or_init};
use super::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};
use super::plan_builder::SynthesisInput;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Boot a pre-built manifest (path to `mvm.toml`, its directory, or a
    /// legacy slot name). If omitted, the bundled
    /// `nix/images/default-tenant/` image is used (built via Nix on first use,
    /// cached at `~/.cache/mvm/default-microvm/`). Each invocation boots a
    /// fresh transient microVM — never the long-running `mvmctl dev` VM.
    #[arg(short = 'm', long)]
    pub manifest: Option<String>,
    /// vCPU cores (default: 2)
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Memory (supports human-readable: 512M, 1G, …)
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Share a host directory into the guest. Format: `HOST_PATH:/GUEST_PATH[:MODE]`
    /// where MODE is `ro` (default, writes are discarded) or `rw` (writes are
    /// rsynced back to the host directory after the command exits). Repeatable
    #[arg(short = 'd', long)]
    pub add_dir: Vec<String>,
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
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "launch_plan"
    )]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(in crate::commands) enum RunProfile {
    /// No env injection and no host directory shares.
    Restrictive,
    /// Explicit env is allowed; host directory shares must stay read-only.
    Standard,
    /// Dev-mode ergonomics: explicit env and writable host shares are allowed.
    Dev,
    /// Escape hatch for local experiments; requires MVM_ACK_PERMISSIVE_RUN=1.
    Permissive,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct RunArgs {
    /// Boot a pre-built manifest (path to `mvm.toml`, its directory, or a
    /// legacy slot name). If omitted, the bundled default microVM image is used.
    #[arg(short = 'm', long, conflicts_with = "image")]
    pub manifest: Option<String>,
    /// Pull or reuse a cached OCI image reference and boot its materialized rootfs.
    ///
    /// The image is resolved through the local OCI cache first. A cache miss
    /// performs the existing verified OCI pull and rootfs materialization path.
    #[arg(long, value_name = "REF")]
    pub image: Option<String>,
    /// vCPU cores (default: 2)
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Memory (supports human-readable: 512M, 1G, ...)
    #[arg(long, default_value = "512M")]
    pub memory: String,
    /// Security profile for the transient run.
    #[arg(long, value_enum, default_value = "standard")]
    pub profile: RunProfile,
    /// Share a host directory into the guest. Format: `HOST_PATH:/GUEST_PATH[:MODE]`.
    /// MODE defaults to `ro`; `rw` is allowed only with `--profile dev` or `permissive`.
    #[arg(short = 'd', long)]
    pub add_dir: Vec<String>,
    /// Explicit environment variable to inject (KEY=VALUE). Repeatable.
    /// Disabled by `--profile restrictive`.
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Per-command timeout in seconds. Unset ⇒ no per-command kill.
    #[arg(long)]
    pub timeout: Option<u64>,
    /// Write a signed execution receipt to this path. The receipt records
    /// command/env/mount hashes, output hashes, and exit status; it never
    /// stores raw argv, env values, stdout, or stderr.
    #[arg(long, value_name = "PATH")]
    pub receipt: Option<PathBuf>,
    /// Print a machine-readable, redacted execution summary as JSON.
    ///
    /// Guest stdout/stderr are not streamed in this mode; the JSON carries
    /// only byte counts and hashes. Combine with `--receipt` when a signed
    /// artifact is needed.
    #[arg(long)]
    pub json: bool,
    /// Validate and explain the effective run plan without booting a VM.
    ///
    /// This preflight never resolves, builds, or starts the selected image. It
    /// reports hashes and policy-relevant metadata only; raw argv, env values,
    /// and host paths are omitted.
    #[arg(long)]
    pub dry_run: bool,
    /// Path to an mvmforge launch document. Mutually exclusive with trailing argv.
    #[arg(long, value_name = "PATH", conflicts_with = "argv")]
    pub launch_plan: Option<String>,
    /// SDK transport mode for `mvmctl run`.
    ///
    /// - `--mode plan`: synthesize an ExecutionPlan per Sandbox call
    ///   and route through `mvm_hostd::supervisor::admit_for_run`; no
    ///   microVM ever boots.
    /// - `--mode live`: spawn the user's script with `MVM_SDK_MODE=live`
    ///   so the SDK shells each `Sandbox` operation to existing
    ///   `mvmctl up` / `proc start` / `fs write` / `down` against a
    ///   real microVM.
    /// - `--mode record` redirects users to `mvmctl compile` (where
    ///   record is the default mode).
    ///
    /// When unset, the verb behaves as a transient-sandbox runner
    /// over the trailing argv.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<RunMode>,
    /// Friendly alias for `--mode live`.
    #[arg(long = "dev", conflicts_with_all = ["prod", "mode"])]
    pub dev: bool,
    /// Friendly alias for `--mode record`. `mvmctl run --prod`
    /// redirects users to `mvmctl compile`, where record is the
    /// default.
    #[arg(long = "prod", conflicts_with_all = ["dev", "mode"])]
    pub prod: bool,
    /// Argv to run inside the guest (use `--` to separate). Required unless
    /// `--launch-plan` is supplied. Under `--mode plan`, the first
    /// argv element is a `.py`/`.ts`/`.js` script path.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present_any = ["launch_plan", "mode", "dev", "prod"]
    )]
    pub argv: Vec<String>,
}

/// SDK transport modes for `mvmctl run`. Mirrors the `Mode` enum on
/// `mvmctl compile` but specialises the rejection messages to point
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
    /// record` redirects users to `mvmctl compile`, whose default
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
            cpus: self.cpus,
            memory: self.memory,
            add_dir: self.add_dir,
            env: self.env,
            timeout: self.timeout,
            launch_plan: self.launch_plan,
            argv: self.argv,
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
    // When an SDK transport mode is requested, peel off the
    // SDK-shaped surface before the sandbox-runner validation kicks
    // in. `--dev` (alias for live) is refused in v1; `--prod` (alias
    // for record) redirects to `mvmctl compile`; `--mode plan` routes
    // through the plan-mode admission dry-run.
    if let Some(mode) = resolve_run_mode(&args)? {
        return super::run_plan::dispatch_sdk_mode(mode, &args);
    }
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
    let receipt_path = args.receipt.clone();
    if args.json || receipt_path.is_some() {
        let receipt_input = ReceiptInput::from_run_args(&args)?;
        let json_requested = args.json;
        let image = args.image.clone();
        let prod = args.prod;
        let req = build_exec_request(args.into_exec_args(), "`mvmctl run`", image, prod)?;
        let output = crate::exec::run_captured(req)?;
        if !json_requested && !output.stdout.is_empty() {
            print!("{}", output.stdout);
        }
        if !json_requested && !output.stderr.is_empty() {
            eprint!("{}", output.stderr);
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
    let image = args.image.clone();
    let prod = args.prod;
    run_run_args(cli, args.into_exec_args(), cfg, image, prod)
}

/// Resolve the `mvmctl run` transport mode from the explicit
/// `--mode` flag, the friendly `--dev` / `--prod` aliases, and the
/// `MVM_SDK_MODE` env-var override. Returns `Ok(None)` when no SDK
/// mode was requested — in that case the verb falls back to the
/// transient-sandbox runner over the trailing argv.
///
/// Env-var precedence matches `mvmctl compile`: `MVM_SDK_MODE`
/// supersedes any flag-only override so a wrapper script can pin a
/// mode without the user retyping `--mode`.
pub(in crate::commands) fn resolve_run_mode(args: &RunArgs) -> Result<Option<RunMode>> {
    if let Ok(env_mode) = std::env::var("MVM_SDK_MODE") {
        return Ok(Some(parse_env_run_mode(&env_mode)?));
    }
    if args.dev {
        return Ok(Some(RunMode::Live));
    }
    if args.prod {
        if args.image.is_some() {
            return Ok(None);
        }
        anyhow::bail!(
            "`mvmctl run --prod` (alias for --mode record) redirects to `mvmctl compile`, where \
             record is the default mode. Re-run as `mvmctl compile <script>` (the trailing argv \
             on `mvmctl run` is for the live sandbox runner, not for SDK record-mode)."
        );
    }
    match args.mode {
        None => Ok(None),
        Some(RunMode::Live) => Ok(Some(RunMode::Live)),
        Some(RunMode::Record) => anyhow::bail!(
            "`mvmctl run --mode record` is unsupported — `mvmctl compile` is the record-mode verb \
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
            "MVM_SDK_MODE=record on `mvmctl run` is unsupported — `mvmctl compile` is the \
             record-mode verb (record is its default)."
        ),
        other => anyhow::bail!(
            "MVM_SDK_MODE={other:?} is not recognized; expected one of: live, plan, record"
        ),
    }
}

fn validate_run_profile(args: &RunArgs) -> Result<()> {
    if args.profile == RunProfile::Permissive
        && std::env::var_os("MVM_ACK_PERMISSIVE_RUN").is_none()
    {
        anyhow::bail!(
            "--profile permissive requires MVM_ACK_PERMISSIVE_RUN=1 so broad local execution is explicit"
        );
    }

    if args.profile == RunProfile::Restrictive {
        if !args.env.is_empty() {
            anyhow::bail!("--profile restrictive does not allow --env");
        }
        if !args.add_dir.is_empty() {
            anyhow::bail!("--profile restrictive does not allow --add-dir");
        }
    }

    if matches!(args.profile, RunProfile::Restrictive | RunProfile::Standard) {
        for spec in &args.add_dir {
            if !crate::exec::AddDir::parse(spec)?.read_only {
                anyhow::bail!(
                    "--add-dir '{spec}' requests rw; use --profile dev for writable host shares"
                );
            }
        }
    }

    Ok(())
}

fn run_run_args(
    _cli: &Cli,
    args: Args,
    _cfg: &MvmConfig,
    image: Option<String>,
    prod: bool,
) -> Result<()> {
    let req = build_exec_request(args, "`mvmctl run`", image, prod)?;
    let exit_code = crate::exec::run(req)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn build_exec_request(
    args: Args,
    command_name: &str,
    image_ref: Option<String>,
    prod: bool,
) -> Result<crate::exec::ExecRequest> {
    let target = match (args.launch_plan.as_ref(), args.argv.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--launch-plan and a trailing argv are mutually exclusive");
        }
        (Some(path), true) => {
            let entrypoint = crate::exec::load_launch_plan(std::path::Path::new(path))?;
            crate::exec::ExecTarget::LaunchPlan { entrypoint }
        }
        (None, true) => {
            anyhow::bail!(
                "{command_name} requires a command (after `--`) or `--launch-plan <PATH>`"
            )
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
        env_pairs.push(parse_env_pair(kv)?);
    }
    // --manifest <PATH> accepts a manifest path / dir in addition to
    // legacy names. Resolve up front so the downstream
    // ImageSource::Template carries either a name (legacy) or a slot
    // hash (manifest), and the dispatched lifecycle helpers handle
    // both keys transparently.
    let image = match (args.manifest, image_ref) {
        (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents --manifest + --image"),
        (Some(arg), None) => {
            let resolved = match super::shared::resolve_manifest_arg(&arg)? {
                super::shared::ManifestArgRef::Name(n) => n,
                super::shared::ManifestArgRef::Slot { slot_hash } => slot_hash,
            };
            crate::exec::ImageSource::Template(resolved)
        }
        (None, Some(reference)) => {
            let cached = super::super::image::resolve_or_pull_run_image(
                &super::super::image::oci_cache_root(),
                &reference,
                prod,
            )?;
            ui::info(&format!(
                "Using OCI image {} ({})",
                cached.reference, cached.resolved_digest
            ));
            emit_oci_run_admission(
                &cached,
                args.cpus,
                u64::from(memory_mib),
                args.timeout.unwrap_or(60),
            )
            .context("admitting OCI image provenance for mvmctl run --image")?;
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
            // `exec` is interactive (dev): a sealed prod image refuses
            // console/exec, so the default image must be the dev variant.
            let (kernel_path, _default_rootfs_path) =
                ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Dev)?;
            crate::exec::ImageSource::Prebuilt {
                kernel_path,
                rootfs_path: cached.rootfs_path.display().to_string(),
                initrd_path: None,
                label: format!("oci:{}", cached.resolved_digest),
            }
        }
        (None, None) => {
            ui::info("No --manifest specified; using bundled default microVM image.");
            let (kernel_path, rootfs_path) =
                ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Dev)?;
            crate::exec::ImageSource::Prebuilt {
                kernel_path,
                rootfs_path,
                initrd_path: None,
                label: "default-microvm".to_string(),
            }
        }
    };
    Ok(crate::exec::ExecRequest {
        image,
        cpus: args.cpus,
        memory_mib,
        // mvmctl exec is a one-shot transient; no balloon plumbing
        // here yet. The manifest-driven path on mvmctl up is where
        // mem_initial gets sourced for long-running workloads.
        mem_initial_mib: None,
        add_dirs,
        env: env_pairs,
        target,
        timeout_secs: args.timeout,
    })
}

fn emit_oci_run_admission(
    image: &super::super::image::ResolvedOciRunImage,
    cpus: u32,
    mem_mib: u64,
    timeout_secs: u64,
) -> Result<()> {
    let image_sha256 = mvm_core::crypto::image_verify::sha256_file(&image.rootfs_path)
        .with_context(|| {
            format!(
                "hashing OCI rootfs at {} for run --image admission",
                image.rootfs_path.display()
            )
        })?;
    let exec_timeout_secs = u32::try_from(timeout_secs).unwrap_or(u32::MAX);
    let input = SynthesisInput {
        vm_name: "run-oci",
        tenant: None,
        backend_name: "transient-run",
        image_name: &image.provenance.canonical_reference,
        image_sha256: &image_sha256,
        image_cosign_bundle: None,
        intent: Some("vm:run"),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: mvm_core::plan::SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus,
        mem_mib,
        disk_mib: 0,
        boot_timeout_secs: 60,
        exec_timeout_secs,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
    };
    let ledger = InMemoryNonceLedger::new();
    let admitted = admit_for_run(&input, &SystemClock, &ledger, None, None)?;
    let signer = load_or_init().context("loading host signer for OCI provenance audit")?;
    let emitter =
        AuditEmitter::new(signer.signing).context("opening audit chain for OCI provenance")?;
    emitter.emit_admitted(&admitted.plan, &admitted.signer_id)?;
    emitter.emit_oci_provenance(&admitted.plan, image.provenance.audit_labels())?;
    Ok(())
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
    command: ReceiptCommand,
    env_keys: Vec<String>,
    add_dirs: Vec<ReceiptAddDir>,
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
struct ReceiptAddDir {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunJsonSummary {
    schema_version: u32,
    invocation: ReceiptInput,
    outcome: ReceiptOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunPreflightSummary {
    schema_version: u32,
    dry_run: bool,
    will_execute: bool,
    invocation: RunPreflightInvocation,
    resources: RunPreflightResources,
    image: RunPreflightImage,
    receipt: RunPreflightReceipt,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunPreflightReceipt {
    requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunPreflightInvocation {
    profile: String,
    command: ReceiptCommand,
    env_keys: Vec<String>,
    add_dirs: Vec<ReceiptAddDir>,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunPreflightResources {
    cpus: u32,
    memory: String,
    memory_mib: u32,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RunPreflightImage {
    DefaultMicrovm,
    Manifest { argument_sha256: String },
    Oci { reference_sha256: String },
}

impl RunJsonSummary {
    fn from_parts(
        invocation: ReceiptInput,
        output: &crate::exec::ExecOutput,
        receipt_path: Option<PathBuf>,
    ) -> Self {
        Self {
            schema_version: 1,
            invocation,
            outcome: ReceiptOutcome::from_exec_output(output),
            receipt_path,
        }
    }
}

impl RunPreflightSummary {
    fn from_args(args: &RunArgs) -> Result<Self> {
        let memory_mib = parse_human_size(&args.memory).context("Invalid --memory")?;
        for kv in &args.env {
            parse_env_pair(kv)?;
        }
        // Force mount parsing now so dry-run rejects the same malformed or
        // disallowed host-share specs as an actual run, without resolving an
        // image or touching the VM runtime.
        for spec in &args.add_dir {
            crate::exec::AddDir::parse(spec)?;
        }
        let image = match args.manifest.as_ref() {
            Some(manifest) if args.image.is_none() => RunPreflightImage::Manifest {
                argument_sha256: sha256_hex(manifest.as_bytes()),
            },
            None if args.image.is_some() => RunPreflightImage::Oci {
                reference_sha256: sha256_hex(
                    args.image
                        .as_deref()
                        .expect("matched image presence")
                        .as_bytes(),
                ),
            },
            None => RunPreflightImage::DefaultMicrovm,
            Some(_) => unreachable!("clap conflicts_with prevents --manifest + --image"),
        };
        let mut notes = vec![
            "preflight only; no image was resolved, built, booted, or executed".to_string(),
            "raw argv, env values, and host paths are intentionally omitted".to_string(),
        ];
        if args.receipt.is_some() {
            notes.push(
                "receipt path is hashed, but no receipt is written during dry-run".to_string(),
            );
        }

        let receipt_input = ReceiptInput::from_run_args(args)?;

        Ok(Self {
            schema_version: 1,
            dry_run: true,
            will_execute: false,
            invocation: RunPreflightInvocation {
                profile: receipt_input.profile,
                command: receipt_input.command,
                env_keys: receipt_input.env_keys,
                add_dirs: receipt_input.add_dirs,
                timeout_secs: receipt_input.timeout_secs,
            },
            resources: RunPreflightResources {
                cpus: args.cpus,
                memory: args.memory.clone(),
                memory_mib,
                timeout_secs: args.timeout.unwrap_or(60),
            },
            image,
            receipt: RunPreflightReceipt {
                requested: args.receipt.is_some(),
                path_sha256: args
                    .receipt
                    .as_ref()
                    .map(|path| sha256_hex(path.to_string_lossy().as_bytes())),
            },
            notes,
        })
    }
}

fn print_run_preflight_human(summary: &RunPreflightSummary) {
    println!("mvmctl run dry-run: no VM will be booted");
    match &summary.image {
        RunPreflightImage::DefaultMicrovm => {
            println!("image: bundled default microVM (not resolved)");
        }
        RunPreflightImage::Manifest { argument_sha256 } => {
            println!("image: manifest/template argument sha256={argument_sha256} (not resolved)");
        }
        RunPreflightImage::Oci { reference_sha256 } => {
            println!("image: OCI reference sha256={reference_sha256} (not resolved)");
        }
    }
    println!(
        "resources: cpus={} memory={} ({} MiB) timeout={}s",
        summary.resources.cpus,
        summary.resources.memory,
        summary.resources.memory_mib,
        summary.resources.timeout_secs
    );
    println!("profile: {}", summary.invocation.profile);
    println!("command: {}", summary.invocation.command.describe());
    if summary.invocation.env_keys.is_empty() {
        println!("env: none");
    } else {
        println!("env keys: {}", summary.invocation.env_keys.join(","));
    }
    if summary.invocation.add_dirs.is_empty() {
        println!("host shares: none");
    } else {
        println!("host shares:");
        for dir in &summary.invocation.add_dirs {
            println!(
                "  host_sha256={} -> {} ({})",
                dir.host_path_sha256,
                dir.guest_path,
                if dir.read_only { "ro" } else { "rw" }
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

impl ReceiptInput {
    fn from_run_args(args: &RunArgs) -> Result<Self> {
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

        let mut env_keys = Vec::with_capacity(args.env.len());
        for kv in &args.env {
            let (key, _) = kv
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--env '{kv}': expected KEY=VALUE"))?;
            env_keys.push(key.to_string());
        }
        env_keys.sort();

        let mut add_dirs = Vec::with_capacity(args.add_dir.len());
        for spec in &args.add_dir {
            let parsed = crate::exec::AddDir::parse(spec)?;
            add_dirs.push(ReceiptAddDir {
                host_path_sha256: sha256_hex(parsed.host_path.as_bytes()),
                guest_path: parsed.guest_path,
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
            command,
            env_keys,
            add_dirs,
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
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args(profile: RunProfile) -> RunArgs {
        RunArgs {
            manifest: None,
            image: None,
            cpus: 2,
            memory: "512M".to_string(),
            profile,
            add_dir: Vec::new(),
            env: Vec::new(),
            timeout: Some(60),
            receipt: None,
            json: false,
            dry_run: false,
            launch_plan: None,
            mode: None,
            dev: false,
            prod: false,
            argv: vec!["/bin/true".to_string()],
        }
    }

    #[test]
    fn resolve_run_mode_returns_none_when_no_mode_flag() {
        let args = run_args(RunProfile::Standard);
        let mode = resolve_run_mode(&args).expect("no flag resolves to None");
        assert!(mode.is_none());
    }

    #[test]
    fn resolve_run_mode_returns_plan_when_mode_plan() {
        let mut args = run_args(RunProfile::Standard);
        args.mode = Some(RunMode::Plan);
        let mode = resolve_run_mode(&args).expect("plan resolves").unwrap();
        assert_eq!(mode, RunMode::Plan);
    }

    #[test]
    fn resolve_run_mode_returns_live_for_dev_alias() {
        let mut args = run_args(RunProfile::Standard);
        args.dev = true;
        let mode = resolve_run_mode(&args)
            .expect("--dev resolves to Some(Live) post-H-live")
            .expect("must be Some(Live)");
        assert_eq!(mode, RunMode::Live);
    }

    #[test]
    fn resolve_run_mode_bails_redirect_for_prod_alias() {
        let mut args = run_args(RunProfile::Standard);
        args.prod = true;
        let err = resolve_run_mode(&args).expect_err("--prod must bail");
        let msg = err.to_string();
        assert!(msg.contains("mvmctl compile"));
    }

    #[test]
    fn resolve_run_mode_leaves_image_prod_for_oci_policy() {
        let mut args = run_args(RunProfile::Standard);
        args.image = Some(
            "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        );
        args.prod = true;
        let mode = resolve_run_mode(&args).expect("image prod is not SDK mode");
        assert!(mode.is_none());
    }

    #[test]
    fn resolve_run_mode_returns_live_for_mode_live() {
        let mut args = run_args(RunProfile::Standard);
        args.mode = Some(RunMode::Live);
        let mode = resolve_run_mode(&args)
            .expect("--mode live resolves to Some(Live) post-H-live")
            .expect("must be Some(Live)");
        assert_eq!(mode, RunMode::Live);
    }

    #[test]
    fn resolve_run_mode_bails_redirect_for_mode_record() {
        let mut args = run_args(RunProfile::Standard);
        args.mode = Some(RunMode::Record);
        let err = resolve_run_mode(&args).expect_err("--mode record must bail");
        let msg = err.to_string();
        assert!(msg.contains("mvmctl compile"));
    }

    #[test]
    fn standard_profile_rejects_writable_host_share() {
        let mut args = run_args(RunProfile::Standard);
        args.add_dir.push(".:/work:rw".to_string());

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
        args.add_dir.push(".:/work".to_string());

        let err = validate_run_profile(&args).expect_err("restrictive rejects shares");
        assert!(err.to_string().contains("does not allow --add-dir"));
    }

    #[test]
    fn dev_profile_allows_writable_host_share() {
        let mut args = run_args(RunProfile::Dev);
        args.add_dir.push(".:/work:rw".to_string());

        validate_run_profile(&args).expect("dev allows rw share");
    }

    #[test]
    fn receipt_input_hashes_sensitive_fields() {
        let mut args = run_args(RunProfile::Dev);
        args.argv = vec!["curl".to_string(), "token-secret".to_string()];
        args.env.push("API_TOKEN=secret-value".to_string());
        args.add_dir.push("/private/project:/work:ro".to_string());

        let receipt = ReceiptInput::from_run_args(&args).expect("receipt input");
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
        };
        let summary = RunJsonSummary::from_parts(
            ReceiptInput::from_run_args(&args).expect("receipt input"),
            &output,
            Some(PathBuf::from("/tmp/receipt.json")),
        );
        let json = serde_json::to_string(&summary).expect("serialize summary");
        assert!(json.contains("stdout_sha256"));
        assert!(json.contains("stderr_sha256"));
        assert!(json.contains("/tmp/receipt.json"));
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
        args.add_dir.push("/private/project:/work:ro".to_string());
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
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        std::fs::write(&pubkey_path, signing.verifying_key().to_bytes()).expect("pubkey");

        let args = run_args(RunProfile::Standard);
        let payload = RunReceiptPayload {
            schema_version: 1,
            receipt_id: "receipt-1".to_string(),
            recorded_at: "2026-05-14T00:00:00Z".to_string(),
            invocation: ReceiptInput::from_run_args(&args).expect("receipt input"),
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
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        std::fs::write(&pubkey_path, signing.verifying_key().to_bytes()).expect("pubkey");

        let args = run_args(RunProfile::Standard);
        let mut payload = RunReceiptPayload {
            schema_version: 1,
            receipt_id: "receipt-1".to_string(),
            recorded_at: "2026-05-14T00:00:00Z".to_string(),
            invocation: ReceiptInput::from_run_args(&args).expect("receipt input"),
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
}
