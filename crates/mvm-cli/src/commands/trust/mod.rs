//! `mvmctl trust` — manage the local bundle-publisher trust store
//! at `~/.mvm/trusted-publishers/<key_id>.pub`.
//!
//! Sprint 52 W2: a bundle's publisher key never lives in the
//! bundle itself; consumers establish trust out-of-band by
//! enrolling a publisher's Ed25519 public key under a derived
//! `key_id` filename. This command makes that enrolment a
//! first-class verb instead of a "drop bytes at a path" trick.
//!
//! Pubkey files hold 32 raw Ed25519 public-key bytes (no PEM, no
//! header). `<key_id>.pub` filenames are derived from the key
//! itself (sha256 of pubkey bytes, truncated to 32 hex chars) so
//! a malicious publisher can't fake another publisher's `key_id`
//! at the filesystem level.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

mod add;
mod list;
mod remove;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: TrustAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TrustAction {
    /// Enrol a publisher's Ed25519 public key as trusted. Reads
    /// 32 raw bytes from `<PUBKEY>` and writes them to
    /// `~/.mvm/trusted-publishers/<key_id>.pub` (mode 0644).
    Add(add::Args),
    /// List currently-trusted publisher key_ids.
    #[command(alias = "ls")]
    List(list::Args),
    /// Remove a publisher by `key_id`. The file is unlinked but
    /// not zeroed — pubkeys aren't secrets, just lookup tokens.
    #[command(alias = "rm")]
    Remove(remove::Args),
    /// Emit or verify host attestation reports
    Attest(super::ops::attest::Args),
    /// Verify signed execution receipts emitted by `mvmctl run --receipt`
    Receipt(super::vm::exec::ReceiptArgs),
    /// View and verify the local audit log (~/.mvm/log/audit.jsonl)
    Audit(super::ops::audit::Args),
}

impl TrustAction {
    /// Audit verb name. The provenance verbs folded in by Plan 178
    /// (attest/receipt/audit) keep their own `cmd.<verb>.*` names; the
    /// publisher-store verbs (add/list/remove) keep the existing `trust`.
    pub(in crate::commands) fn verb_name(&self) -> &'static str {
        match self {
            TrustAction::Add(_) | TrustAction::List(_) | TrustAction::Remove(_) => "trust",
            TrustAction::Attest(_) => "attest",
            TrustAction::Receipt(_) => "receipt",
            TrustAction::Audit(_) => "audit",
        }
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        TrustAction::Add(a) => add::run(cli, a, cfg),
        TrustAction::List(a) => list::run(cli, a, cfg),
        TrustAction::Remove(a) => remove::run(cli, a, cfg),
        TrustAction::Attest(a) => super::ops::attest::run(cli, a, cfg),
        TrustAction::Receipt(a) => super::vm::exec::run_receipt(cli, a, cfg),
        TrustAction::Audit(a) => super::ops::audit::run(cli, a, cfg),
    }
}

/// Resolve the trust-store directory, creating it (mode 0700) if
/// it doesn't already exist. Centralised so add/list/remove agree
/// on the path and on the create-on-first-use behaviour.
pub(super) fn ensure_trust_dir() -> Result<std::path::PathBuf> {
    use mvm_core::plan::bundle::FsTrustStore;
    let store = FsTrustStore::default_path()?;
    let dir = store.root().to_path_buf();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(anyhow::Error::from)?;
        // Tighten parent permissions on POSIX. Tests on macOS/Linux
        // hit this path; on platforms without unix perms (Windows
        // CI someday) the cfg-gate makes it a no-op.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dir)?.permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&dir, perms)?;
        }
    }
    Ok(dir)
}
