//! `mvmctl image` - pull, inspect, and prune the local OCI image cache.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args as ClapArgs, Subcommand};

// Kept here (rather than folded into a submodule's own imports) so the
// unmoved `trust` sibling's `use super::*;` glob keeps resolving these
// without touching its call sites.
use mvm_fs::oci::{ImageReference, RegistryAuthConfig};

use mvm_core::user_config::MvmConfig;

use super::Cli;

pub(crate) mod boot;
mod cache;
mod ingest;
mod inspect;
mod ls;
mod materialize;
mod oci_types;
mod pull;
mod pull_core;
mod rm;
mod source;
mod trust;
mod trust_policy;

// Re-exports preserve two frozen call-site shapes without editing them: the
// sibling verb modules' `super::<name>` calls, and
// `crate::commands::vm::exec`'s `super::super::image::<name>` reach-in.
use cache::{inspect_image, list_rows, remove_image, render_inspect, render_list};
use oci_types::CosignIdentity;
pub(in crate::commands) use pull_core::ensure_prod_digest_pin;
use pull_core::pull_image_with_trust;
pub(in crate::commands) use pull_core::resolve_or_pull_run_image;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: ImageAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ImageAction {
    /// Pull, unpack, and materialize an OCI image into the local cache
    Pull {
        /// OCI image reference
        reference: String,
        /// Production policy: require an immutable digest-pinned reference
        #[arg(long)]
        prod: bool,
    },
    /// List cached OCI images
    Ls {
        /// Filter cached images by registry host
        #[arg(long, value_name = "HOST")]
        registry: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Inspect a cached OCI image by reference or resolved digest
    Inspect {
        /// Image reference or resolved digest
        reference: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove a cached OCI image and garbage-collect unreferenced layers
    Rm {
        /// Image reference or resolved digest
        reference: String,
    },
    /// Inspect, compare, and update the cached default boot image
    Boot {
        #[command(subcommand)]
        action: boot::BootAction,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let cache_root = oci_cache_root();
    match args.action {
        ImageAction::Pull { reference, prod } => pull::run(&cache_root, reference, prod),
        ImageAction::Ls { registry, json } => ls::run(&cache_root, registry.as_deref(), json),
        ImageAction::Inspect { reference, json } => inspect::run(&cache_root, &reference, json),
        ImageAction::Rm { reference } => rm::run(&cache_root, &reference),
        ImageAction::Boot { action } => boot::run(action),
    }
}

pub(in crate::commands) fn oci_cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join("oci")
}
