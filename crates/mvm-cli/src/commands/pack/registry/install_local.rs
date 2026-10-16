//! Thin local-acquisition frontend; authentication lives in the client/Core.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_client::registry_pack_local::{LocalRegistryPackPaths, install_local_registry_pack};
use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::{PackPin, PackReference};
use std::path::PathBuf;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Exact expected namespace/name@version (no registry version lookup)
    pub reference: PackReference,
    /// Required SHA-256 of the exact signed manifest bytes
    #[arg(long, value_parser = parse_manifest_sha256)]
    pub manifest_sha256: Sha256Hex,
    /// Local signed manifest JSON, at most 1 MiB
    #[arg(long)]
    pub manifest: PathBuf,
    /// Local Sigstore bundle, at most 1 MiB
    #[arg(long)]
    pub bundle: PathBuf,
    /// Exact complete signed payload root (including built-image assets)
    #[arg(long)]
    pub files: PathBuf,
}

fn parse_manifest_sha256(value: &str) -> std::result::Result<Sha256Hex, String> {
    Sha256Hex::new(value).map_err(|error| error.to_string())
}

pub(super) fn run(args: Args) -> Result<()> {
    let expected = PackPin::new(args.reference, args.manifest_sha256)?;
    let paths = LocalRegistryPackPaths::new(args.manifest, args.bundle, args.files)?;
    let installed = install_local_registry_pack(&expected, &paths)?;
    println!(
        "installed {} manifest_sha256={} at {}",
        expected.reference(),
        expected.manifest_sha256().as_str(),
        installed.root().display()
    );
    Ok(())
}
