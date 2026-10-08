//! Local, signature-verified registry-pack revocation feed update.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

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
    let document = read_limited(&args.document)?;
    let bundle = read_limited(&args.bundle)?;
    let checkpoint =
        mvm_core::registry_pack_store::update_registry_pack_revocations(&document, &bundle)?;
    println!(
        "verified registry-pack revocations at sequence {} (sha256 {})",
        checkpoint.sequence,
        checkpoint.sha256.as_str()
    );
    Ok(())
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    const MAX_BYTES: u64 = 1024 * 1024;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("checking revocation input {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_BYTES {
        bail!(
            "revocation input {} must be a regular file no larger than 1 MiB",
            path.display()
        );
    }
    let file =
        File::open(path).with_context(|| format!("opening revocation input {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading revocation input {}", path.display()))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("revocation input {} exceeds 1 MiB", path.display());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_oversized_inputs_are_refused() {
        let home = tempfile::tempdir().expect("tempdir");
        assert!(read_limited(&home.path().join("missing")).is_err());
        let oversized = home.path().join("oversized");
        std::fs::write(&oversized, vec![0; 1024 * 1024 + 1]).expect("write input");
        assert!(read_limited(&oversized).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_input_is_refused() {
        let home = tempfile::tempdir().expect("tempdir");
        let document = home.path().join("document");
        std::fs::write(&document, b"{}").expect("write document");
        let link = home.path().join("link");
        std::os::unix::fs::symlink(&document, &link).expect("link");
        assert!(read_limited(&link).is_err());
    }
}
