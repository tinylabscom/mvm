//! `mvmctl bundle install <SOURCE>` — verify a `.mvmpkg` archive
//! and extract it into the local bundle registry so subsequent
//! `mvmctl up <bundle-sha256>` calls can launch from it.
//!
//! Reuses the source-parsing + transport rules from
//! [`super::fetch::BundleSource`] (local path or `https://` URL,
//! plain HTTP refused unless `--allow-http`). After verification
//! the archive is atomically installed under
//! `~/.mvm/bundles/<bundle_sha256>/` via
//! [`mvm_core::plan::BundleRegistry::install`]; the archive bytes are
//! also written to `<bundle_sha256>.mvmpkg` so the
//! `FsBundleResolver` admit-time path finds them too.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::{BundleRegistry, FsTrustStore};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;
use super::fetch::load_bundle_bytes;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Local path to a `.mvmpkg` archive, or an `https://` URL
    /// (HTTP is opt-in via `--allow-http`).
    #[arg(value_name = "SOURCE")]
    pub source: String,
    /// Override the trust store directory. Defaults to
    /// `~/.mvm/trusted-publishers/`.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Override the bundle registry root. Defaults to
    /// `~/.mvm/bundles/`.
    #[arg(long, value_name = "DIR")]
    pub registry: Option<PathBuf>,
    /// Allow plain-HTTP downloads. The Ed25519 signature still
    /// catches tampering, but HTTP exposes traffic metadata. Off
    /// by default.
    #[arg(long)]
    pub allow_http: bool,
    /// Overwrite an existing install with the same bundle_sha256
    /// instead of erroring. Bundles are content-addressed so a
    /// matching sha256 means the contents are byte-identical
    /// anyway; `--force` just makes that explicit.
    #[arg(long)]
    pub force: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let bytes = load_bundle_bytes(&args.source, args.allow_http)
        .with_context(|| format!("loading bundle archive from {}", args.source))?;

    let trust = match args.trust_store {
        Some(p) => FsTrustStore::new(p),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?,
    };
    let registry = match args.registry {
        Some(p) => BundleRegistry::new(p),
        None => BundleRegistry::default_path()
            .context("resolving default bundle registry root (~/.mvm/bundles/)")?,
    };

    let installed = registry
        .install(&bytes, &trust, args.force)
        .with_context(|| format!("installing bundle from {}", args.source))?;

    mvm_core::audit_emit!(
        BundleInstall,
        "bundle_sha256={},key_id={}",
        installed.sha256,
        installed.manifest.key_id.0,
    );

    println!(
        "Installed bundle {} ({} artifacts, publisher key_id={})",
        installed.sha256,
        installed.manifest.artifacts.len(),
        installed.manifest.key_id.0,
    );
    println!("  registry root: {}", installed.root.display());
    println!(
        "  launch with:   mvmctl machine run --manifest {}",
        installed.sha256
    );
    Ok(())
}
