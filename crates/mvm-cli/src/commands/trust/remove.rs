//! `mvmctl trust remove <KEY_ID>` — unlink a trusted publisher.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::plan::bundle::KeyId;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// 32-char hex `key_id` to remove. Get the list via
    /// `mvmctl trust list`.
    #[arg(value_name = "KEY_ID")]
    pub key_id: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let id = KeyId(args.key_id.clone());
    if !id.is_well_formed() {
        anyhow::bail!(
            "key_id {:?} is malformed (expected 32 lowercase hex characters)",
            args.key_id
        );
    }
    let dir = super::ensure_trust_dir()?;
    let path = dir.join(format!("{}.pub", id.0));
    match std::fs::remove_file(&path) {
        Ok(()) => {
            mvm_core::audit_emit!(TrustRemove, "key_id={}", id.0);
            println!("Removed key_id {}", id.0);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("no trusted entry for key_id {}", id.0)
        }
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}
