//! `mvmctl deps` — user-facing CLI for the sealed deps-volume cache.
//!
//! Three verbs over the sealed-volume primitives in
//! `mvm_sdk::compile::deps_audit` and the host orchestrator in
//! `mvm_build::app_deps`:
//!
//! - **`mvmctl deps inspect <volume_hash>`** — pretty-print the four
//!   sealed sidecars (SBOM, fetch.log, cve.json, meta.json) so a user
//!   can see what landed in `~/.mvm/volumes/deps/<hash>/`. Read-only.
//! - **`mvmctl deps audit [--all | <volume_hash>]`** — re-run the CVE
//!   scan against the current `pip-audit` / `pnpm audit` feed, rewrite
//!   `cve.json`, bump `meta.json.last_audit_at`, reseal the volume,
//!   and atomically rename the directory to the new hash (since
//!   `cve.json` changed → `meta.json` changed → `volume_hash`
//!   changed). Emits `LocalAuditKind::DepsAudit` per volume processed.
//! - **`mvmctl build --deps`** — force a rebuild of the deps volume
//!   even on cache hit (handled in `crates/mvm-cli/src/commands/build/build.rs`,
//!   not here).
//!
//! ## Module layout
//!
//! - `mod.rs` — `Args` / `Action` enum, dispatch, shared types.
//! - `inspect.rs` — pretty-printer for sealed artifacts.
//! - `audit.rs` — re-audit logic + `AuditRunner` trait for testing.
//!
//! Cache root resolution always routes through
//! [`mvm_build::app_deps::resolve_cache_root`] so the supervisor's
//! admission gate and this CLI agree on where volumes
//! live. The optional `--cache-root` flag exists for tests + the
//! `MVM_DEPS_VOLUMES_DIR` env var; production users have no reason
//! to override.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};
use std::path::PathBuf;

use mvm_core::user_config::MvmConfig;

use super::Cli;

pub(super) mod audit;
pub(super) mod inspect;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: DepsAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum DepsAction {
    /// Pretty-print the sealed artifacts of one deps volume. Read-only.
    ///
    /// Resolves `~/.mvm/volumes/deps/<volume_hash>/` (honoring
    /// `MVM_DEPS_VOLUMES_DIR`), reads SBOM / fetch.log / cve.json /
    /// meta.json, and prints a human-readable summary. Useful for
    /// `--dev` users who want to see what landed without inspecting
    /// the raw JSON by hand.
    Inspect {
        /// The 64-hex volume hash (the directory name under the
        /// deps-volumes root). Pass the value printed by `mvmctl
        /// build` or by `meta.json.annotations`.
        volume_hash: String,
        /// Override the deps-volumes cache root. Defaults to
        /// `mvm_core::config::mvm_deps_volumes_dir()`. Mostly used by
        /// tests + integration harnesses; production users should set
        /// `MVM_DEPS_VOLUMES_DIR` instead.
        #[arg(long)]
        cache_root: Option<PathBuf>,
        /// Emit a machine-readable JSON object on stdout instead of
        /// the human-readable summary. The shape mirrors the inspect
        /// dataclasses; downstream tooling can introspect specific
        /// fields without parsing the pretty-print.
        #[arg(long)]
        json: bool,
    },
    /// Re-run the CVE scan against the current pip-audit / pnpm audit
    /// feed and reseal the volume.
    ///
    /// For each volume processed:
    ///   1. Verify the volume currently seals cleanly (refuses to
    ///      operate on a tampered cache entry — same posture as
    ///      `mvm_build::app_deps::install_app_deps`).
    ///   2. Recover the language from the volume's
    ///      `meta.json.annotations.language` (the sealer records it there).
    ///   3. Dispatch `pip-audit` or `pnpm audit --json` on the host.
    ///   4. Write the fresh result to `cve.json`, bump
    ///      `meta.json.last_audit_at`, and reseal.
    ///   5. Since the volume hash baked in the old `cve.json`, the
    ///      new hash differs — atomically rename the directory.
    ///   6. Emit `LocalAuditKind::DepsAudit` with the prior + new
    ///      hashes + the count of high/critical findings surfaced.
    ///
    /// Bring `pip-audit` / `pnpm` if they aren't already on PATH; the
    /// runner surfaces a clear error pointing at install instructions.
    Audit(audit::Args),
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        DepsAction::Inspect {
            volume_hash,
            cache_root,
            json,
        } => inspect::run(&volume_hash, cache_root.as_deref(), json),
        DepsAction::Audit(a) => audit::run(a),
    }
}
