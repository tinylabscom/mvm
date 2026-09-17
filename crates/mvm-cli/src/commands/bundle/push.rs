//! `mvmctl bundle push <FILE> <REFERENCE>` — publish a signed `.mvmpkg`
//! archive to an image registry.
//!
//! The archive is verified against the local trust store before anything is
//! sent, then stored as one artifact manifest whose single layer is the
//! archive. The command prints the digest-pinned `oci://` reference, which
//! `bundle fetch` and `bundle install` accept (and which `--prod` requires).
//! Credentials come from the same environment variables `image pull` reads.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::bundle::{FsTrustStore, bundle_sha256};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;
use super::registry::{
    RegistryTransport, display_reference, parse_registry_reference, publish_bundle,
};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Local path to the `.mvmpkg` archive to publish.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
    /// Registry reference to push to, `[oci://]<registry>/<repository>:<tag>`.
    /// Without a tag the manifest is stored under its own digest.
    #[arg(value_name = "REFERENCE")]
    pub reference: String,
    /// Override the trust store directory used to verify the bundle
    /// before publishing. Defaults to `~/.mvm/trusted-publishers/`.
    #[arg(long, value_name = "DIR")]
    pub trust_store: Option<PathBuf>,
    /// Talk to the registry over plain HTTP. Credentials and traffic are
    /// visible on the wire. Off by default.
    #[arg(long)]
    pub allow_http: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let reference = parse_registry_reference(&args.reference)?;
    let archive = std::fs::read(&args.file)
        .with_context(|| format!("reading bundle archive at {}", args.file.display()))?;
    let trust = match args.trust_store {
        Some(p) => FsTrustStore::new(p),
        None => FsTrustStore::default_path()
            .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?,
    };
    let transport = RegistryTransport::for_reference(&reference, args.allow_http)?;

    let (verified, pushed) = publish_bundle(&archive, &reference, &transport, &trust)?;
    let pinned = display_reference(&pushed.reference);

    mvm_core::audit_emit!(
        BundlePush,
        "bundle_sha256={},key_id={},reference={}",
        bundle_sha256(&archive),
        verified.key_id.0,
        pinned,
    );

    crate::ui::success(&format!(
        "Pushed bundle {} (publisher key_id={}){}",
        bundle_sha256(&archive),
        verified.key_id.0,
        if pushed.layer_uploaded {
            ""
        } else {
            "; the registry already held the archive"
        }
    ));
    println!("{pinned}");
    Ok(())
}
