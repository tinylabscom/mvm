//! `mvmctl capture` — project-environment capture frontend.
//!
//! Commands:
//! - `mvmctl capture project <path> --run <cmd> --output capture.json`
//! - `mvmctl capture resolve capture.json --output environment.json`
//! - `mvmctl capture verify environment.json --manifest-dir <dir> --run <cmd>`

use crate::commands::Cli;
use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use mvm_core::user_config::MvmConfig;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: CaptureCmd,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum CaptureCmd {
    /// Inspect a project directory and emit a versioned capture report.
    Project(ProjectArgs),
    /// Resolve a capture report into the canonical MVM IR.
    Resolve(ResolveArgs),
    /// Verify a canonical IR by rendering Nix and replaying a command.
    Verify(VerifyArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ProjectArgs {
    /// Project directory to inspect.
    pub path: PathBuf,
    /// Explicit command to record for later tracing (can be repeated).
    #[arg(long = "run")]
    pub run: Vec<String>,
    /// Output file for the capture report.
    #[arg(long, short)]
    pub output: PathBuf,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct ResolveArgs {
    /// Capture report to resolve.
    pub report: PathBuf,
    /// Output file for the canonical MVM IR.
    #[arg(long, short)]
    pub output: PathBuf,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct VerifyArgs {
    /// Canonical MVM IR to verify.
    pub environment: PathBuf,
    /// Directory containing the project source (defaults to current directory).
    #[arg(long)]
    pub manifest_dir: Option<PathBuf>,
    /// Explicit verification command to replay.
    #[arg(long = "run")]
    pub run: Vec<String>,
    /// Output directory for rendered Nix artifacts.
    #[arg(long, short)]
    pub out_dir: Option<PathBuf>,
    /// Execute the verification command inside the Linux builder VM by
    /// dispatching a `mvmctl __builder-shell-job` that builds the rendered flake.
    #[arg(long)]
    pub exec_in_builder_vm: bool,
    /// Boot a microVM inside the Linux builder VM and replay the verification
    /// command as the guest entrypoint. Requires a bootstrapped builder VM with
    /// working nested virtualization or a supported fallback hypervisor.
    #[arg(long)]
    pub boot_and_replay: bool,
}

impl CaptureCmd {
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            CaptureCmd::Project(_) => "capture-project",
            CaptureCmd::Resolve(_) => "capture-resolve",
            CaptureCmd::Verify(_) => "capture-verify",
        }
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        CaptureCmd::Project(a) => run_project(a),
        CaptureCmd::Resolve(a) => run_resolve(a),
        CaptureCmd::Verify(a) => run_verify(a),
    }
}

fn run_project(args: ProjectArgs) -> Result<()> {
    let options = mvm_capture::collect::CollectOptions {
        project_path: args.path.clone(),
        explicit_commands: args.run,
        ..Default::default()
    };
    let report = mvm_capture::collect::collect_project(&options)
        .with_context(|| format!("capturing project {}", args.path.display()))?;
    let json = serde_json::to_string_pretty(&report).context("serializing capture report")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent).context("creating output directory")?;
    }
    fs::write(&args.output, json).with_context(|| format!("writing {}", args.output.display()))?;
    tracing::info!(path = %args.output.display(), "wrote capture report");
    Ok(())
}

fn run_resolve(args: ResolveArgs) -> Result<()> {
    let text = fs::read_to_string(&args.report)
        .with_context(|| format!("reading {}", args.report.display()))?;
    let report: mvm_capture::report::CaptureReportV1 =
        serde_json::from_str(&text).context("parsing capture report")?;
    let result =
        mvm_capture::resolve::resolve_report(&report).context("resolving capture report")?;
    let json = serde_json::to_string_pretty(&result).context("serializing resolved workload")?;
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent).context("creating output directory")?;
    }
    fs::write(&args.output, json).with_context(|| format!("writing {}", args.output.display()))?;
    tracing::info!(
        path = %args.output.display(),
        unresolved = result.unresolved.len(),
        "wrote canonical IR"
    );
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let text = fs::read_to_string(&args.environment)
        .with_context(|| format!("reading {}", args.environment.display()))?;
    let mut result: mvm_capture::resolve::ResolutionResult =
        serde_json::from_str(&text).context("parsing canonical IR")?;

    let manifest_dir = args
        .manifest_dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("current directory"));
    let out_dir = args
        .out_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("mvm-capture-verify"));
    if out_dir.exists() {
        let _ = fs::remove_dir_all(&out_dir);
    }
    fs::create_dir_all(&out_dir).context("creating verify output directory")?;

    mvm_sdk::compile::compile(&result.workload, &out_dir, &manifest_dir)
        .map_err(|e| anyhow::anyhow!("Nix render failed: {e}"))?;

    tracing::info!(dir = %out_dir.display(), "rendered Nix artifacts");

    if !args.run.is_empty() {
        result.verification = run_verification_records(
            &args.run,
            &out_dir,
            args.exec_in_builder_vm,
            args.boot_and_replay,
        )
        .context("running verification")?;
    }

    let verification_json = out_dir.join("verification.json");
    let json = serde_json::to_string_pretty(&result).context("serializing verification result")?;
    fs::write(&verification_json, json)
        .with_context(|| format!("writing {}", verification_json.display()))?;
    tracing::info!(path = %verification_json.display(), "wrote verification report");

    Ok(())
}

fn run_verification_records(
    commands: &[String],
    out_dir: &Path,
    exec_in_builder_vm: bool,
    boot_and_replay: bool,
) -> Result<Vec<mvm_capture::report::VerificationRecord>> {
    use mvm_capture::verify::{
        BootReplayVerifier, BuilderVmConfig, BuilderVmVerifier, RecordOnlyVerifier,
        VerificationRequest, Verifier,
    };

    let mut records = Vec::new();
    for cmd in commands {
        let request = VerificationRequest {
            command: cmd.split_whitespace().map(str::to_owned).collect(),
        };

        let config = BuilderVmConfig {
            work_dir: out_dir.to_path_buf(),
            mvmctl_path: None,
        };

        let record = if boot_and_replay {
            let verifier = BootReplayVerifier {
                config,
                max_seconds: 300,
            };
            run_or_record(verifier, request)
        } else if exec_in_builder_vm {
            let verifier = BuilderVmVerifier { config };
            run_or_record(verifier, request)
        } else {
            RecordOnlyVerifier
                .verify(&request)
                .expect("record-only never fails")
        };
        records.push(record);
    }
    Ok(records)
}

fn run_or_record<V>(
    verifier: V,
    request: mvm_capture::verify::VerificationRequest,
) -> mvm_capture::report::VerificationRecord
where
    V: mvm_capture::verify::Verifier,
{
    use mvm_capture::report::{VerificationRecord, VerificationStatus};

    verifier
        .verify(&request)
        .unwrap_or_else(|e| VerificationRecord {
            command: request.command,
            status: VerificationStatus::Failed {
                reason: format!("{}", e),
            },
            exit_code: None,
            stdout: None,
            stderr: None,
        })
}
