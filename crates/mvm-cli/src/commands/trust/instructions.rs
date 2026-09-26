//! `mvmctl trust instructions` — provenance for agent instruction files.
//!
//! `CLAUDE.md`, `AGENTS.md`, `SKILL.md` and friends are instructions to an
//! agent, so a poisoned one is a prompt injection that needs no code. These
//! verbs manage the trust policy that says who may sign them, sign them with a
//! local key, and verify a tree the way admission will before a boot copies it
//! into a guest. The policy, scan and verification live in
//! `mvm_client::instruction_trust`; this module is argument handling and
//! output.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;

use mvm_client::instruction_trust::gate::{
    Decision, PolicyLocations, ScanReport, default_trust_store, load_effective_policy, scan_roots,
};
use mvm_client::instruction_trust::policy::{EffectivePolicy, Enforcement, PublisherSummary};
use mvm_client::instruction_trust::scan::{RootKind, ScanRoot, find_instruction_files};
use mvm_client::instruction_trust::{sign, templates};
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
    let enforcement = Enforcement::from(args.enforcement);
    let (path, body) = match &args.project {
        Some(dir) => (
            mvm_core::config::project_instruction_trust_policy_path(dir),
            templates::project_policy(enforcement),
        ),
        None => {
            let signer = mvm_hostd::audit::host_keypair::load_or_init()
                .context("loading this host's signing key for the starter policy")?;
            (
                mvm_core::config::instruction_trust_policy_path(),
                templates::user_policy(enforcement, &hex::encode(signer.verifying.to_bytes())),
            )
        }
    };
    if path.exists() && !args.force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite it",
            path.display()
        );
    }
    let parent = path
        .parent()
        .context("a policy path always has a parent directory")?;
    if args.project.is_some() {
        std::fs::create_dir_all(parent)
    } else {
        mvm_core::config::create_private_dir(parent)
    }
    .with_context(|| format!("creating {}", parent.display()))?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    mvm_core::audit_emit!(
        TrustInstructionsInit,
        "path={},enforcement={}",
        path.display(),
        enforcement.as_str()
    );
    ui::success(&format!(
        "Wrote {} (enforcement: {})",
        path.display(),
        enforcement.as_str()
    ));
    if args.project.is_some() {
        ui::info("A project policy only tightens a user policy; alone it is advisory.");
    } else {
        ui::info(
            "Sign instruction files with `mvmctl trust instructions sign <path>`; \
             every boot now verifies the instruction files it copies into the guest.",
        );
    }
    Ok(())
}

/// The effective policy for `root`: the user policy (or `--policy`), plus
/// the project policy under `root` when it is a directory.
fn policy_for(root: &Path, user_policy: Option<&Path>) -> Result<EffectivePolicy> {
    let locations = PolicyLocations {
        user: user_policy.map(Path::to_path_buf),
        project_root: root.is_dir().then(|| root.to_path_buf()),
    };
    Ok(load_effective_policy(&locations, &default_trust_store()?)?)
}

/// Every file `sign` would sign: an explicitly named file as-is, and the
/// instruction files under a named directory.
fn files_to_sign(args: &SignArgs) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in &args.paths {
        if path.is_dir() {
            let policy = policy_for(path, args.policy.as_deref())?;
            let found = find_instruction_files(&ScanRoot::new(path, RootKind::Explicit), &policy)
                .with_context(|| format!("scanning {}", path.display()))?;
            files.extend(found.into_iter().map(|f| f.path));
        } else if path.is_file() {
            files.push(path.clone());
        } else {
            anyhow::bail!("{} is not a file or directory", path.display());
        }
    }
    Ok(files)
}

fn load_signing_key(path: Option<&Path>) -> Result<SigningKey> {
    let Some(path) = path else {
        return Ok(mvm_hostd::audit::host_keypair::load_or_init()
            .context("loading this host's signing key")?
            .signing);
    };
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).with_context(|| format!("reading key {}", path.display()))?,
    );
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "key {} is {} bytes; expected a raw 32-byte Ed25519 secret key",
            path.display(),
            bytes.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign_paths(args: SignArgs) -> Result<()> {
    let files = files_to_sign(&args)?;
    if args.dry_run {
        for file in &files {
            println!("{}", file.display());
        }
        return Ok(());
    }
    if files.is_empty() {
        ui::info("No instruction files found; nothing signed.");
        return Ok(());
    }
    let key = load_signing_key(args.key.as_deref())?;
    let key_id = mvm_core::plan::bundle::key_id_from_pubkey(&key.verifying_key());
    for file in &files {
        let sidecar = sign::sign_file(file, &key)?;
        let sha256 = mvm_core::crypto::image_verify::sha256_file(file)
            .with_context(|| format!("hashing {}", file.display()))?;
        mvm_core::audit_emit!(
            TrustInstructionsSign,
            "path={},sha256={},key_id={}",
            file.display(),
            sha256,
            key_id.0
        );
        println!("signed {} -> {}", file.display(), sidecar.display());
    }
    ui::success(&format!(
        "Signed {} instruction file(s) with key {}",
        files.len(),
        key_id.0
    ));
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let root = args.path.unwrap_or_else(|| PathBuf::from("."));
    let policy = policy_for(&root, args.policy.as_deref())?;
    let report = scan_roots(&[ScanRoot::new(&root, RootKind::Explicit)], &policy)?;
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
    let summary = load_effective_policy(&locations, &default_trust_store()?)?.summary();
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
        let err = load_signing_key(Some(&short)).unwrap_err();
        assert!(format!("{err:#}").contains("32-byte"), "{err:#}");
        let good = dir.path().join("good.key");
        std::fs::write(&good, [1u8; 32]).unwrap();
        assert_eq!(
            load_signing_key(Some(&good)).unwrap().to_bytes(),
            SigningKey::from_bytes(&[1u8; 32]).to_bytes()
        );
    }

    #[test]
    fn named_files_are_signed_as_given_and_directories_by_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CLAUDE.md"), b"x").unwrap();
        std::fs::write(dir.path().join("README.md"), b"x").unwrap();
        let explicit = dir.path().join("notes.txt");
        std::fs::write(&explicit, b"x").unwrap();
        let absent_policy = dir.path().join("absent.toml");
        let args = SignArgs {
            paths: vec![dir.path().to_path_buf(), explicit.clone()],
            key: None,
            dry_run: true,
            policy: Some(absent_policy),
        };
        let files = files_to_sign(&args).unwrap();
        assert_eq!(files, vec![dir.path().join("CLAUDE.md"), explicit]);
    }

    #[test]
    fn a_missing_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let args = SignArgs {
            paths: vec![dir.path().join("absent")],
            key: None,
            dry_run: true,
            policy: None,
        };
        assert!(files_to_sign(&args).is_err());
    }
}
