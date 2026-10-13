//! `mvmctl image` - pull, inspect, and prune the local OCI image cache.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use mvm_core::user_config::MvmConfig;

use super::Cli;

pub(crate) mod boot;
mod build_layer;
mod cache;
pub(in crate::commands) mod dev;
mod inspect;
mod ls;
mod pull;
mod revocations;
mod rm;

// Re-exports preserve two frozen call-site shapes without editing them: the
// sibling verb modules' `super::<name>` calls, and
// `crate::commands::vm::exec`'s `super::super::image::<name>` reach-in.
use cache::{render_inspect, render_list};
pub(in crate::commands) use mvm_client::image_admin::recent_image_references;
#[cfg(test)]
pub(in crate::commands) use mvm_client::image_admin::registry_auth_from_lookup;
pub(in crate::commands) use mvm_client::image_admin::resolve_or_pull_run_image;
pub(in crate::commands) use mvm_client::image_admin::{OciRegistryAuthDecision, registry_auth_for};
pub(in crate::commands) use mvm_client::image_admin::{
    ensure_prod_digest_pin, ensure_prod_registry_allowed, require_prod_digest_pin,
};
use mvm_client::image_admin::{inspect_image, list_rows, remove_image};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: ImageAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum ImageAction {
    /// Build unsigned ext4 and verity assets from a staged application tree
    BuildLayer {
        /// Complete staged application root filesystem directory
        #[arg(long, value_name = "DIR")]
        source: PathBuf,
        /// New directory for the three assets and their digest report
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Pull, unpack, and materialize an OCI image into the local cache
    Pull {
        /// OCI image reference
        reference: String,
        /// Production policy: require an immutable digest-pinned reference
        #[arg(long)]
        prod: bool,
        /// After a successful, verified pull, prepare one warm standby of the
        /// image at the default sizing — the same as
        /// `mvmctl pool warm --image <REF>`. A failed pull, or a rootfs
        /// directory that carries no provenance to verify, warms nothing.
        #[arg(long)]
        warm: bool,
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
    /// Ensure the writable dev default-tenant image is installed locally
    Dev {
        #[command(subcommand)]
        action: dev::DevAction,
    },
    /// Apply and inspect the signed image-set revocation list admission reads
    Revocations(revocations::Args),
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let cache_root = oci_cache_root();
    match args.action {
        ImageAction::BuildLayer { source, output } => build_layer::run(&source, &output),
        ImageAction::Pull {
            reference,
            prod,
            warm,
        } => {
            let pulled = pull::run(&cache_root, reference.clone(), prod);
            pull::warm_after_pull(pulled, &reference, warm, |reference| {
                super::pool::warm_request(&super::pool::WarmRequest::one_at_default_sizing(
                    Some(reference),
                    cfg,
                ))
            })
        }
        ImageAction::Ls { registry, json } => ls::run(&cache_root, registry.as_deref(), json),
        ImageAction::Inspect { reference, json } => inspect::run(&cache_root, &reference, json),
        ImageAction::Rm { reference } => rm::run(&cache_root, &reference),
        ImageAction::Boot { action } => boot::run(action),
        ImageAction::Dev { action } => dev::run(action, cfg),
        ImageAction::Revocations(args) => revocations::run(args.action),
    }
}

pub(in crate::commands) fn oci_cache_root() -> PathBuf {
    mvm_client::image_admin::oci_cache_root()
}
