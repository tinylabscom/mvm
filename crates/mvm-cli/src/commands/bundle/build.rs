//! OCI acquisition and materialization finish before the host signer is loaded.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_client::bundle::{DebugOutput, HostBundleSigner};
use mvm_client::{OciBundleRequest, export_materialized_oci_bundle, materialize_oci_bundle};
use mvm_core::arch::GuestArch;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// OCI registry image to resolve and package.
    #[arg(long, value_name = "OCI_REF")]
    image: String,
    /// Destination signed archive.
    #[arg(long, value_name = "FILE.mvmpkg")]
    out: PathBuf,
    /// Guest architecture; defaults to this host. Cross-architecture builds are refused.
    #[arg(long)]
    arch: Option<GuestArch>,
    /// Seal with dm-verity and production posture; requires a digest-qualified image.
    #[arg(long)]
    production: bool,
    /// Optional human-readable workload label.
    #[arg(long)]
    label: Option<String>,
    /// Write the shared bundler's JSON debug report.
    #[arg(long, value_name = "FILE.json")]
    debug_out: Option<PathBuf>,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let mut request = OciBundleRequest::new(args.image, args.out)
        .arch(args.arch.unwrap_or_else(GuestArch::host))
        .production(args.production);
    if let Some(label) = args.label {
        request = request.label(label);
    }
    if let Some(path) = args.debug_out {
        request = request.debug_out(DebugOutput::json(path));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create OCI materialization runtime")?;
    let materialized = runtime.block_on(materialize_oci_bundle(&request))?;
    let signer = HostBundleSigner::load()?;
    let exported = export_materialized_oci_bundle(&materialized, &signer)?;
    println!("OCI digest: {}", exported.resolved_digest);
    println!("Bundle SHA-256: {}", exported.bundle_sha256);
    println!("Signer key ID: {}", exported.signer_key_id);
    println!("Architecture: {}", exported.arch);
    println!("Output: {}", exported.bundle_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn image_and_output_are_required() {
        assert!(Harness::try_parse_from(["build", "--image", "alpine"]).is_err());
        assert!(Harness::try_parse_from(["build", "--out", "alpine.mvmpkg"]).is_err());
    }

    #[test]
    fn parses_architecture_production_and_debug_report() {
        let parsed = Harness::try_parse_from([
            "build",
            "--image",
            "alpine",
            "--out",
            "alpine.mvmpkg",
            "--arch",
            "arm64",
            "--production",
            "--debug-out",
            "report.json",
        ])
        .unwrap();
        assert_eq!(parsed.args.arch, Some(GuestArch::Aarch64));
        assert!(parsed.args.production);
        assert_eq!(parsed.args.debug_out, Some("report.json".into()));
    }
}
