//! `mvmctl bundle gc` — prune installed bundles from the local
//! registry.
//!
//! Two modes, mutually exclusive:
//!
//! - `mvmctl bundle gc <SHA>` — remove a specific bundle by its
//!   64-hex sha256.
//! - `mvmctl bundle gc --all` — remove every installed bundle.
//!
//! `--unused` (remove only bundles no plan references) would need
//! a host-side "last used" tracker — deferred to a future commit.
//!
//! Removal is symmetric to `mvmctl bundle install`: both the
//! cached `<sha>.mvmpkg` and the extracted `<sha>/` directory are
//! unlinked. Successful sweeps emit a single
//! `LocalAuditKind::BundleGc` audit line with the removed count
//! and the truncated sha list.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::BundleRegistry;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Bundle sha256 to remove (64 lowercase hex chars). Mutually
    /// exclusive with `--all`.
    #[arg(value_name = "SHA", conflicts_with = "all")]
    pub sha: Option<String>,
    /// Remove every installed bundle.
    #[arg(long)]
    pub all: bool,
    /// Override the bundle registry root. Defaults to
    /// `~/.mvm/bundles/`.
    #[arg(long, value_name = "DIR")]
    pub registry: Option<PathBuf>,
    /// Skip the "are you sure?" prompt for `--all`. Mirrors the
    /// pattern other destructive verbs use; in non-interactive
    /// contexts (CI, scripts) the prompt is suppressed automatically
    /// so `--yes` is mostly a no-op there.
    #[arg(long)]
    pub yes: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if args.sha.is_none() && !args.all {
        anyhow::bail!(
            "specify a bundle sha256 to remove, or pass --all to wipe every installed bundle"
        );
    }

    let registry = match args.registry {
        Some(p) => BundleRegistry::new(p),
        None => BundleRegistry::default_path()
            .context("resolving default bundle registry root (~/.mvm/bundles/)")?,
    };

    let mut removed: Vec<String> = Vec::new();

    if let Some(sha) = args.sha.as_deref() {
        // Validate the shape up front so an obvious typo doesn't
        // become a "no such bundle" miss.
        if sha.len() != 64
            || !sha
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        {
            anyhow::bail!("bundle sha {sha:?} is malformed (expected 64 lowercase hex chars)");
        }
        let touched = registry
            .remove(sha)
            .with_context(|| format!("removing bundle {sha}"))?;
        if !touched {
            anyhow::bail!("no installed bundle for {sha}");
        }
        removed.push(sha.to_string());
    } else {
        // --all path.
        let bundles = registry.list().context("listing installed bundles")?;
        if bundles.is_empty() {
            println!("No installed bundles to remove.");
            return Ok(());
        }
        if !args.yes && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            println!(
                "About to remove {} installed bundle(s) from {}",
                bundles.len(),
                registry.root().display()
            );
            for sha in &bundles {
                println!("  {sha}");
            }
            anyhow::bail!(
                "refusing without confirmation — re-run with --yes to remove these bundles"
            );
        }
        for sha in &bundles {
            if registry.remove(sha)? {
                removed.push(sha.clone());
            }
        }
    }

    // Audit emit — single line per `gc` invocation. Detail
    // truncates the sha list to the first 5 entries so an `--all`
    // sweep of a large registry doesn't blow out the log line.
    let detail = {
        let count = removed.len();
        let preview: Vec<&str> = removed.iter().take(5).map(String::as_str).collect();
        let mut s = format!("removed={count},shas={}", preview.join(","));
        if removed.len() > 5 {
            s.push_str(",...");
        }
        s
    };
    mvm_core::audit_emit!(BundleGc, "{detail}");

    println!("Removed {} bundle(s).", removed.len());
    for sha in &removed {
        println!("  {sha}");
    }
    Ok(())
}
