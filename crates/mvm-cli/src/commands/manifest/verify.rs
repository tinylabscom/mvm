//! `mvmctl manifest verify` — checksum verification (and, once
//! cosign-signed builder images land, signatures) for a built slot.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest::{self, VerifyRequest};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Manifest path (file or directory). Defaults to walking up from cwd.
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
    /// Verify a specific revision instead of the slot's current symlink.
    #[arg(long)]
    pub revision: Option<String>,
    /// Verify cosign signatures in addition to checksums. Reserved
    /// for the sealed-signed-builder-image work; today returns
    /// "not yet implemented" if passed.
    #[arg(long)]
    pub check_signature: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let verified = manifest::verify(&VerifyRequest {
        path: args.path,
        revision: args.revision,
        check_signature: args.check_signature,
    })?;
    let slot_hash = verified.slot_hash;
    println!(
        "OK: slot {} ({}) verified",
        &slot_hash[..slot_hash.len().min(12)],
        verified.manifest_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn verify_parser_preserves_revision_and_signature_refusal_request() {
        let args = Command::try_parse_from([
            "verify",
            "project",
            "--revision",
            "abc12345",
            "--check-signature",
        ])
        .unwrap()
        .args;
        assert_eq!(args.path.as_deref(), Some("project"));
        assert_eq!(args.revision.as_deref(), Some("abc12345"));
        assert!(args.check_signature);
        let defaults = Command::try_parse_from(["verify"]).unwrap().args;
        assert!(
            defaults.path.is_none() && defaults.revision.is_none() && !defaults.check_signature
        );
    }
}
