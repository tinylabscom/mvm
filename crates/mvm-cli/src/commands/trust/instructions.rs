//! `mvmctl trust instructions` — provenance for agent instruction files.
//!
//! `CLAUDE.md`, `AGENTS.md`, `SKILL.md` and friends are instructions to an
//! agent, so a poisoned one is a prompt injection that needs no code. These
//! verbs manage the trust policy that says who may sign them, sign them with a
//! local key, and verify a tree the way admission will before a boot copies it
//! into a guest. The policy, scan and verification live in
//! `mvm_client::instruction_trust`; this module is argument handling and
//! output.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use mvm_client::instruction_trust::gate::{Decision, PolicyLocations, ScanReport};
use mvm_client::instruction_trust::operations::{self, InitRequest, SignRequest, VerifyRequest};
use mvm_client::instruction_trust::policy::{Enforcement, PublisherSummary};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;
use crate::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: InstructionsAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum InstructionsAction {
    /// Write a starter instruction trust policy (user, or --project)
    Init(InitArgs),
    /// Sign instruction files with an Ed25519 key (default: this host's)
    Sign(SignArgs),
    /// Verify the instruction files under a path against the policy
    Verify(VerifyArgs),
    /// Show the effective instruction trust policy
    Policy(PolicyArgs),
}

/// Enforcement modes, as flags spell them.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum EnforcementArg {
    Deny,
    Warn,
    Audit,
}

impl From<EnforcementArg> for Enforcement {
    fn from(value: EnforcementArg) -> Self {
        match value {
            EnforcementArg::Deny => Enforcement::Deny,
            EnforcementArg::Warn => Enforcement::Warn,
            EnforcementArg::Audit => Enforcement::Audit,
        }
    }
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct InitArgs {
    /// Write `<DIR>/.mvm/instruction-trust.toml` instead of the user policy
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,
    /// Enforcement mode to write
    #[arg(long, value_enum, default_value = "deny")]
    pub enforcement: EnforcementArg,
    /// Overwrite an existing policy file
    #[arg(long)]
    pub force: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct SignArgs {
    /// Files to sign, or directories whose instruction files to sign
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,
    /// Raw 32-byte Ed25519 secret key file (default: the host signing key)
    #[arg(long, value_name = "FILE")]
    pub key: Option<PathBuf>,
    /// List the files that would be signed, one per line, and sign nothing
    #[arg(long)]
    pub dry_run: bool,
    /// User policy to read instead of the configured one
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct VerifyArgs {
    /// File or directory to verify (default: the current directory)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// User policy to read instead of the configured one
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct PolicyArgs {
    /// Merge in the project policy under DIR
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,
    /// User policy to read instead of the configured one
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        InstructionsAction::Init(a) => init(a),
        InstructionsAction::Sign(a) => sign_paths(a),
        InstructionsAction::Verify(a) => verify(a),
        InstructionsAction::Policy(a) => policy(a),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let outcome = operations::init(&InitRequest {
        project: args.project,
        enforcement: args.enforcement.into(),
        force: args.force,
    })?;
    ui::success(&format!(
        "Wrote {} (enforcement: {})",
        outcome.path.display(),
        outcome.enforcement.as_str()
    ));
    if outcome.project {
        ui::info("A project policy only tightens a user policy; alone it is advisory.");
    } else {
        ui::info(
            "Sign instruction files with `mvmctl trust instructions sign <path>`; \
             every boot now verifies the instruction files it copies into the guest.",
        );
    }
    Ok(())
}

fn sign_paths(args: SignArgs) -> Result<()> {
    let outcome = operations::sign(&SignRequest {
        paths: args.paths,
        key: args.key,
        dry_run: args.dry_run,
        policy: args.policy,
    })?;
    if args.dry_run {
        for file in &outcome.selected {
            println!("{}", file.display());
        }
        return Ok(());
    }
    let Some(key_id) = outcome.key_id else {
        ui::info("No instruction files found; nothing signed.");
        return Ok(());
    };
    for file in &outcome.signed {
        println!(
            "signed {} -> {}",
            file.path.display(),
            file.sidecar.display()
        );
    }
    ui::success(&format!(
        "Signed {} instruction file(s) with key {}",
        outcome.signed.len(),
        key_id
    ));
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let report = operations::verify(&VerifyRequest {
        path: args.path.unwrap_or_else(|| PathBuf::from(".")),
        policy: args.policy,
    })?;
    if args.json {
        crate::json_out::emit_json(&report)?;
    } else {
        print_report(&report);
    }
    match report.decision() {
        Decision::Refuse(message) => anyhow::bail!(message),
        Decision::Admit | Decision::Warn(_) => Ok(()),
    }
}

fn print_report(report: &ScanReport) {
    for note in &report.notes {
        ui::warn(note);
    }
    for file in &report.files {
        let mark = if file.verdict.is_verified() {
            "✓"
        } else {
            "✗"
        };
        println!(
            "  {mark} {}  {}",
            file.file.path.display(),
            file.verdict.describe()
        );
    }
    let failed = report.failures().count();
    println!(
        "{} instruction file(s): {} verified, {} failed (enforcement: {}, policy: {})",
        report.files.len(),
        report.files.len() - failed,
        failed,
        report.enforcement.as_str(),
        report.origin.as_str()
    );
}

fn policy(args: PolicyArgs) -> Result<()> {
    let locations = PolicyLocations {
        user: args.policy.clone(),
        project_root: args.project.clone(),
    };
    let summary = operations::policy(&locations)?;
    if args.json {
        return crate::json_out::emit_json(&summary);
    }
    ui::status_line("origin:", summary.origin.as_str());
    ui::status_line("enforcement:", summary.enforcement.as_str());
    let sources = if summary.sources.is_empty() {
        "(none — built-in defaults, record only)".to_string()
    } else {
        summary
            .sources
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    ui::status_line("sources:", &sources);
    println!("includes:");
    for pattern in &summary.includes {
        println!("  {pattern}");
    }
    println!("publishers:");
    if summary.publishers.is_empty() {
        println!("  (none — no file can verify)");
    }
    for publisher in &summary.publishers {
        match publisher {
            PublisherSummary::Keyless {
                name,
                issuer,
                identity,
            } => println!("  {name}: keyless {identity} (issuer {issuer})"),
            PublisherSummary::Keyed { name, key_id } => {
                println!("  {name}: ed25519 key {key_id}")
            }
        }
    }
    if !summary.blocklist.is_empty() {
        println!("blocklist:");
        for entry in &summary.blocklist {
            match &entry.reason {
                Some(reason) => println!("  {}  {reason}", entry.sha256),
                None => println!("  {}", entry.sha256),
            }
        }
    }
    for note in &summary.notes {
        ui::warn(note);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_flags_map_to_policy_modes() {
        assert_eq!(Enforcement::from(EnforcementArg::Deny), Enforcement::Deny);
        assert_eq!(Enforcement::from(EnforcementArg::Warn), Enforcement::Warn);
        assert_eq!(Enforcement::from(EnforcementArg::Audit), Enforcement::Audit);
    }

    #[test]
    fn a_key_file_must_be_exactly_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short.key");
        std::fs::write(&short, [1u8; 31]).unwrap();
        let file = dir.path().join("CLAUDE.md");
        std::fs::write(&file, b"x").unwrap();
        let mut request = SignRequest {
            paths: vec![file],
            key: Some(short),
            dry_run: false,
            policy: None,
        };
        let err = operations::sign(&request).unwrap_err();
        assert!(format!("{err:#}").contains("32-byte"), "{err:#}");
        let good = dir.path().join("good.key");
        std::fs::write(&good, [1u8; 32]).unwrap();
        request.key = Some(good);
        assert!(operations::sign(&request).unwrap().key_id.is_some());
    }

    #[test]
    fn named_files_are_signed_as_given_and_directories_by_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), b"x").unwrap();
        std::fs::write(dir.path().join("README.md"), b"x").unwrap();
        let explicit = dir.path().join("notes.txt");
        std::fs::write(&explicit, b"x").unwrap();
        let absent_policy = dir.path().join("absent.toml");
        let args = SignRequest {
            paths: vec![dir.path().to_path_buf(), explicit.clone()],
            key: None,
            dry_run: true,
            policy: Some(absent_policy),
        };
        let files = operations::sign(&args).unwrap().selected;
        assert_eq!(files, vec![dir.path().join("CLAUDE.md"), explicit]);
    }

    #[test]
    fn a_missing_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let args = SignRequest {
            paths: vec![dir.path().join("absent")],
            key: None,
            dry_run: true,
            policy: None,
        };
        assert!(operations::sign(&args).is_err());
    }
}
