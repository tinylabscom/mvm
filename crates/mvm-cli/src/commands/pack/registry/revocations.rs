//! Local, signature-verified registry-pack revocation feed update.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::commands::shared::read_signed_input;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug, Clone)]
enum Action {
    /// Verify a signed document and advance the durable local checkpoint
    Update(UpdateArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct UpdateArgs {
    /// Revocation document in JSON format
    #[arg(long)]
    document: PathBuf,
    /// Signature bundle for the exact document bytes
    #[arg(long)]
    bundle: PathBuf,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    match args.action {
        Action::Update(args) => update(args),
    }
}

fn update(args: UpdateArgs) -> Result<()> {
    let document = read_signed_input(&args.document)?;
    let bundle = read_signed_input(&args.bundle)?;
    let checkpoint =
        mvm_core::registry_pack_store::update_registry_pack_revocations(&document, &bundle)?;
    println!(
        "verified registry-pack revocations at sequence {} (sha256 {})",
        checkpoint.sequence,
        checkpoint.sha256.as_str()
    );
    Ok(())
}
