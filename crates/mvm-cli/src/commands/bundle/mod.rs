//! `mvmctl bundle` — content-addressed, publisher-signed
//! `.mvmpkg` portable image archives.
//!
//! A bundle pairs `manifest.json` + `manifest.sig` +
//! the artifact bytes inside one tar archive. The manifest declares
//! a per-artifact SHA-256, an architecture, the publisher's
//! `key_id`, and a workload label. The signature is detached
//! Ed25519 over the canonical-JSON manifest bytes.
//!
//! Trust model lives at the consumer: the publisher pubkey is
//! looked up via `~/.mvm/trusted-publishers/<key_id>.pub` (managed
//! by `mvmctl trust`). An unknown `key_id` is refused before
//! reading artifact bytes; a tampered manifest fails signature
//! verification; a tampered artifact fails the post-signature
//! sha256 re-check. See `mvm_core::plan::bundle` module rustdoc for the
//! full rejection ladder.
//!
//! ## Scope
//!
//! `export` and `fetch` over local filesystem paths. HTTP fetch
//! and supervisor admit-time re-verify (`ExecutionPlan::PlanArtifact`)
//! are deferred follow-ups — both touch larger surfaces (a wire
//! client and an `ExecutionPlan` schema bump respectively).

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

mod export;
pub(super) mod fetch;
mod gc;
mod install;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: BundleAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BundleAction {
    /// Seal a built template into a signed `.mvmpkg` archive.
    /// Signs with the host signer at `~/.mvm/keys/host-signer.ed25519`
    /// (the same key that signs `ExecutionPlan` envelopes).
    Export(export::Args),
    /// Verify a `.mvmpkg` archive against the local trust store.
    /// Reports the parsed manifest on success; rejects on any of
    /// the failure modes in `BundleVerifyError`.
    Fetch(fetch::Args),
    /// Verify and atomically install a `.mvmpkg` archive into the
    /// local bundle registry (`~/.mvm/bundles/<sha>/`). Once
    /// installed, `mvmctl up --manifest <sha>` launches from it.
    Install(install::Args),
    /// Prune installed bundles from the registry. Either a specific
    /// `<SHA>` or `--all` to wipe everything. Emits
    /// `LocalAuditKind::BundleGc` on success.
    Gc(gc::Args),
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    match args.action {
        BundleAction::Export(a) => export::run(cli, a, cfg),
        BundleAction::Fetch(a) => fetch::run(cli, a, cfg),
        BundleAction::Install(a) => install::run(cli, a, cfg),
        BundleAction::Gc(a) => gc::run(cli, a, cfg),
    }
}
