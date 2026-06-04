//! `mvmctl trust add <PUBKEY>` — enrol a publisher's Ed25519
//! public key as trusted.
//!
//! Reads 32 raw bytes from the path, validates that they form a
//! valid Ed25519 verifying key, derives `key_id =
//! sha256(pubkey)[..32hex]`, and writes the bytes to
//! `~/.mvm/trusted-publishers/<key_id>.pub`. Refuses to overwrite
//! an existing entry without `--force` — a publisher key
//! collision under truncation would still need a full Ed25519
//! collision to forge a signature, but loud-failing surfaces the
//! mistake.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use ed25519_dalek::VerifyingKey;

use mvm_core::plan::bundle::KeyId;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Path to a 32-byte Ed25519 public-key file. No PEM, no
    /// headers — raw bytes only. Bundles publish this format via
    /// `~/.mvm/keys/host-signer.pub` after `host_signer::load_or_init`.
    #[arg(value_name = "PUBKEY")]
    pub pubkey: PathBuf,
    /// Overwrite an existing entry with the same `key_id`.
    #[arg(long)]
    pub force: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let bytes = std::fs::read(&args.pubkey)
        .with_context(|| format!("reading pubkey at {}", args.pubkey.display()))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "pubkey at {} is {} bytes; expected exactly 32 (raw Ed25519)",
            args.pubkey.display(),
            bytes.len()
        );
    }
    let arr: [u8; 32] = bytes.as_slice().try_into().expect("checked length");
    let vk = VerifyingKey::from_bytes(&arr).with_context(|| {
        format!(
            "pubkey bytes at {} do not decode as a valid Ed25519 verifying key",
            args.pubkey.display()
        )
    })?;
    let key_id = KeyId::from_pubkey(&vk);

    let dir = super::ensure_trust_dir()?;
    let dst = dir.join(format!("{}.pub", key_id.0));
    if dst.exists() && !args.force {
        anyhow::bail!(
            "trust store already has an entry for key_id {}; pass --force to overwrite",
            key_id.0
        );
    }
    std::fs::write(&dst, vk.to_bytes())
        .with_context(|| format!("writing pubkey to {}", dst.display()))?;
    // World-readable is fine — public keys are not secrets — but
    // mirror the existing host-signer.pub mode (0644) for
    // consistency with the rest of `~/.mvm/keys/`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dst)?.permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&dst, perms)?;
    }
    mvm_core::audit_emit!(TrustAdd, "key_id={}", key_id.0);

    println!("Trusted key_id {}", key_id.0);
    Ok(())
}
