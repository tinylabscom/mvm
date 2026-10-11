//! `mvmctl manifest export-oci` — copy a slot's OCI tarball to a
//! user-supplied path.
//!
//! The OCI tarball (`image.tar.gz`) is produced by `mkGuest`'s
//! `dockerTools.streamLayeredImage` when the flake opts in. After
//! `template_build_from_manifest` lands a slot, the tarball is
//! copied alongside the kernel and rootfs into the slot's current
//! revision directory. This verb makes that artifact user-facing:
//! `mvmctl manifest export-oci <template> --out ./foo.tar.gz`
//! produces a Docker/Podman-loadable image, extending mvm-built
//! workloads to hosts without KVM.
//!
//! Failure modes (each surfaces with a clear message):
//! - Template doesn't exist → "no slot named X; run mvmctl build"
//! - Slot exists but no current revision → "no current revision"
//! - Revision exists but no image.tar.gz → "this template wasn't
//!   built with the OCI output enabled — rebuild after wiring
//!   `dockerTools.streamLayeredImage` into mkGuest"
//! - Parent directory of `--out` doesn't exist → propagated I/O
//!   error pointing at the bad path

use std::path::PathBuf;

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest::{self, ExportOciRequest};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Template — either a 64-char hex slot hash, a manifest path
    /// (file or directory), or a legacy name-keyed template id.
    #[arg(value_name = "TEMPLATE")]
    pub template: String,
    /// Output path for the `image.tar.gz` archive. Parent directory
    /// must exist; the file is overwritten if present.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let report = manifest::export_oci(&ExportOciRequest {
        template: args.template,
        out: args.out,
    })?;
    println!(
        "Exported OCI tarball to {} ({} bytes)",
        report.path.display(),
        report.size_bytes
    );
    println!("Load on a Docker / Podman host with:");
    println!("  docker load -i {}", report.path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn verb_registered_in_cli_command_tree() {
        // Smoke test that `mvmctl manifest export-oci` is present
        // in the top-level clap tree. Walks the command tree the
        // same way `audit_total_coverage` does so a future rename
        // gets caught here too.
        let root = crate::commands::cli_command();
        let manifest_sub = root
            .find_subcommand("manifest")
            .expect("manifest subcommand present");
        let names: Vec<&str> = manifest_sub
            .get_subcommands()
            .map(|s| s.get_name())
            .collect();
        assert!(
            names.contains(&"export-oci"),
            "export-oci missing from manifest subcommands: {names:?}"
        );
    }
}
