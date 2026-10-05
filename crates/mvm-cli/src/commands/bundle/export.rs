//! `mvmctl bundle export <template> --out <path>` — seal a built
//! template into a signed `.mvmpkg`.
//!
//! Resolves the template's current revision artifacts (kernel,
//! rootfs, optional initrd, optional dm-verity sidecar) and hands
//! them to the shared exporter, which hashes each, builds the
//! manifest, signs it under the host signer, and writes the archive
//! to `--out`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_client::bundle::{BundleExportInputs, HostBundleSigner, export_bundle_with_signer};

use mvm_core::plan::BundleResources;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Template name or 64-char slot hash to export.
    #[arg(value_name = "TEMPLATE")]
    pub template: String,
    /// Output path for the `.mvmpkg` archive. Parent directory must
    /// exist; the file is overwritten if it already exists.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Optional human-readable workload label baked into the
    /// manifest. Surfaced by `mvmctl bundle fetch` for diagnostics.
    #[arg(long)]
    pub label: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // ---- 1. Resolve the template's artifact paths ----
    let (spec, vmlinux, initrd, rootfs, _rev) = tmpl::template_artifacts_dispatched(&args.template)
        .with_context(|| {
            format!(
                "loading template {:?} — does it exist? Try `mvmctl manifest ls`",
                args.template
            )
        })?;

    // Carry a re-exported bundle's own architecture through rather than
    // re-stamping this host's. `template_artifacts_dispatched` resolves an
    // installed bundle as happily as a local slot, so an aarch64 bundle
    // re-exported from an x86_64 host would otherwise be relabelled x86_64
    // while still containing an aarch64 rootfs — and the label is what the
    // boot-time gate trusts. A slot built here has no manifest, so it takes
    // the host arch, which is correct for that case.
    let source_arch = tmpl::installed_bundle_arch_for_export(&args.template)
        .unwrap_or_else(|| mvm_core::arch::GuestArch::host().to_string());

    // Verity sidecar lives next to the rootfs by convention; the
    // backend's probe is the source of truth.
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    let verity_bytes = match verity_path.as_deref() {
        Some(p) => {
            Some(std::fs::read(p).with_context(|| format!("reading verity sidecar at {p}"))?)
        }
        None => None,
    };

    // ---- 2. Seal, sign under the host key, and write the archive ----
    let signer = HostBundleSigner::load()?;
    let exported = export_bundle_with_signer(
        &BundleExportInputs {
            vmlinux: &vmlinux,
            initrd: initrd.as_deref(),
            rootfs: &rootfs,
            verity_bytes: verity_bytes.as_deref(),
            roothash: roothash.as_deref(),
            profile: Some(&spec.profile),
            // The template's declared resources travel with the bundle so a
            // launch on another host starts from them without rediscovering
            // them. `--cpus` / `--memory` still override at launch time.
            resources: Some(BundleResources {
                vcpus: u32::from(spec.vcpus),
                mem_mib: spec.mem_mib,
            }),
            arch_label: &source_arch,
            label: args.label,
            out: &args.out,
            debug_out: None,
        },
        &signer,
    )?;

    println!(
        "Exported bundle to {} ({} bytes, key_id={})",
        exported.path.display(),
        exported.size_bytes,
        exported.key_id.0,
    );

    Ok(())
}
