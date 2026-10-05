//! `mvm explain <run-id>` — render a run's attestation from the
//! chain-signed audit log.
//!
//! `mvm_client::explain` reads the chain, selects the run and verifies it;
//! this command renders the result, with a loud footer when the chain fails
//! verification, and optionally turns grantable refusals into `mvm.toml`
//! grants. No new storage or signing surface.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Args as ClapArgs;
use mvm_client::explain::{RunExplanation, explain_local_run, label_join};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Run identity to explain: the plan id (or a unique prefix), or the
    /// workload/VM image name recorded in the audit log.
    pub run_id: String,
    /// Tenant whose audit chain to read (default: the local single-host tenant).
    #[arg(long, default_value = "local")]
    pub tenant: String,
    /// Emit a machine-readable JSON object instead of the human summary.
    #[arg(long)]
    pub json: bool,
    /// Review grantable denials and, after confirmation, update mvm.toml
    #[arg(long, conflicts_with = "json")]
    pub review: bool,
    /// Project directory whose mvm.toml receives reviewed grants (default: .)
    #[arg(long, value_name = "DIR", requires = "review")]
    pub project: Option<PathBuf>,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let explanation = explain_local_run(&args.tenant, &args.run_id)?;
    if args.json {
        return crate::json_out::emit_json(&explanation);
    }
    render(&explanation);
    if args.review {
        if !explanation.chain_verified {
            bail!("refusing to draft grants from an audit chain that does not verify");
        }
        let project = args.project.as_deref().unwrap_or_else(|| Path::new("."));
        let manifest = super::denial_review::manifest_path(project)?;
        super::denial_review::review_destinations(&explanation.egress_denials, &manifest)?;
    }
    Ok(())
}

fn render(explanation: &RunExplanation) {
    println!(
        "Run {}  image {} (sha256:{})  tenant {}",
        explanation.plan_id,
        explanation.image_name,
        short_sha256(&explanation.image_sha256),
        explanation.tenant
    );
    println!();
    for ev in &explanation.events {
        let labels = label_join(&ev.labels);
        if labels.is_empty() {
            println!("{}  {}", ev.timestamp, ev.event);
        } else {
            println!("{}  {}  [{}]", ev.timestamp, ev.event, labels);
        }
    }
    println!();
    println!("outcome: {}", explanation.outcome());
    if let Some(backend) = explanation.backend() {
        println!("backend: {backend}");
    }
    if let Some(provenance) = explanation.provenance_summary() {
        println!("source provenance: {provenance}");
    }
    render_denials(explanation);
    println!();
    match (explanation.chain_verified, &explanation.verify_error) {
        (true, _) => println!(
            "\u{2713} audit chain verifies clean ({} entries)",
            explanation.chain_entry_count
        ),
        (false, Some(e)) => println!(
            "\u{26a0} audit chain FAILED verification: {e} — this run's record may be tampered"
        ),
        (false, None) => println!("\u{26a0} audit chain verification could not be confirmed"),
    }
}

/// One line per refused destination, with its count and remedy.
fn render_denials(explanation: &RunExplanation) {
    if explanation.egress_denials.is_empty() {
        return;
    }
    println!("egress denied:");
    for denied in &explanation.egress_denials {
        println!(
            "  {}  {}×  {} — {}",
            denied.destination, denied.count, denied.description, denied.hint
        );
    }
}

/// First 12 hex chars of an image sha256 — enough to disambiguate at a
/// glance without cluttering the header line with the full 64.
fn short_sha256(sha256: &str) -> &str {
    let end = sha256.len().min(12);
    &sha256[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sha256_truncates_to_twelve_chars() {
        assert_eq!(short_sha256(&"a".repeat(64)), "aaaaaaaaaaaa");
        assert_eq!(short_sha256("short"), "short");
    }
}
