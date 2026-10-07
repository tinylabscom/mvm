//! `mvmctl bundle export <template> --out <path>` — seal a built
//! template into a signed `.mvmpkg`.
//!
//! Resolves the template's current revision artifacts (kernel,
//! rootfs, optional initrd, optional dm-verity sidecar) and hands
//! them to the shared exporter, which hashes each, builds the
//! manifest, signs it under the host signer, and writes the archive
//! to `--out`.
//!
//! The manifest can also declare the kernel command line the workload was
//! built with (`--cmdline`) and a security posture (`--posture` plus the
//! `--allow-*` flags) that any launch of the bundle may only narrow. A
//! template built on this host also records its build provenance: the flake
//! it came from, bound to the digests of the kernel and rootfs sealed.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_client::bundle::{
    BundleExportInputs, HostBundleSigner, PostureInputs, export_bundle_with_signer,
};

use mvm_core::plan::BundleResources;
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::security::AgentProfile;
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
    /// Text file holding the kernel command line the workload was built
    /// and tested with. Recorded for inspection; the launcher still
    /// derives the command line it boots with.
    #[arg(long, value_name = "FILE")]
    pub cmdline: Option<PathBuf>,
    /// Declare the workload's security posture for this guest profile.
    /// A launch of the bundle may only narrow it. `sealed-prod` requires
    /// the template to carry a dm-verity rootfs.
    #[arg(long, value_enum, value_name = "PROFILE")]
    pub posture: Option<PostureProfile>,
    /// Let a launch of the bundle use a network policy other than deny-all.
    #[arg(long, requires = "posture")]
    pub allow_egress: bool,
    /// Let a launch of the bundle attach host shares or volumes.
    #[arg(long, requires = "posture")]
    pub allow_volumes: bool,
    /// Declare that the guest agent accepts unauthenticated vsock frames.
    /// Refused for `--posture sealed-prod`.
    #[arg(long, requires = "posture")]
    pub allow_unauthenticated: bool,
}

/// Guest profile named by `--posture`.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub(in crate::commands) enum PostureProfile {
    SealedProd,
    Dev,
    Builder,
}

impl From<PostureProfile> for AgentProfile {
    fn from(profile: PostureProfile) -> Self {
        match profile {
            PostureProfile::SealedProd => AgentProfile::SealedProd,
            PostureProfile::Dev => AgentProfile::Dev,
            PostureProfile::Builder => AgentProfile::Builder,
        }
    }
}

impl Args {
    fn posture_inputs(&self) -> Option<PostureInputs> {
        self.posture.map(|profile| {
            PostureInputs::new(profile.into())
                .requires_auth(!self.allow_unauthenticated)
                .allows_volumes(self.allow_volumes)
                .allows_egress(self.allow_egress)
        })
    }
}

/// Provenance for a template built on this host: the flake it was built
/// from. An installed bundle being re-exported records none, since this host
/// did not build it; the exporter fills in the sealed artifacts' digests.
fn template_provenance(flake_ref: &str, is_installed_bundle: bool) -> Option<BuildProvenance> {
    if is_installed_bundle || flake_ref.trim().is_empty() {
        return None;
    }
    Some(BuildProvenance {
        input_kind: InputKind::NixFlake,
        input_ref: flake_ref.to_string(),
        lock_digest: None,
        builder_id: None,
        artifacts: Default::default(),
    })
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
    let installed_arch = tmpl::installed_bundle_arch_for_export(&args.template);
    let provenance = template_provenance(&spec.flake_ref, installed_arch.is_some());
    let source_arch =
        installed_arch.unwrap_or_else(|| mvm_core::arch::GuestArch::host().to_string());

    // Verity sidecar lives next to the rootfs by convention; the
    // backend's probe is the source of truth.
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    let verity_bytes = match verity_path.as_deref() {
        Some(p) => {
            Some(std::fs::read(p).with_context(|| format!("reading verity sidecar at {p}"))?)
        }
        None => None,
    };

    let cmdline = args
        .cmdline
        .as_deref()
        .map(|path| {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading kernel command line at {}", path.display()))
        })
        .transpose()?;

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
            label: args.label.clone(),
            cmdline: cmdline.as_deref(),
            posture: args.posture_inputs(),
            provenance,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Harness {
        #[command(flatten)]
        args: Args,
    }

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        let mut full = vec!["export", "tmpl", "--out", "app.mvmpkg"];
        full.extend_from_slice(argv);
        Harness::try_parse_from(full).map(|h| h.args)
    }

    #[test]
    fn no_posture_flag_declares_no_posture() {
        assert_eq!(parse(&[]).unwrap().posture_inputs(), None);
    }

    #[test]
    fn a_posture_starts_closed() {
        let posture = parse(&["--posture", "sealed-prod"])
            .unwrap()
            .posture_inputs()
            .unwrap();
        assert_eq!(posture, PostureInputs::new(AgentProfile::SealedProd));
    }

    #[test]
    fn allow_flags_open_only_what_they_name() {
        let posture = parse(&[
            "--posture",
            "dev",
            "--allow-egress",
            "--allow-unauthenticated",
        ])
        .unwrap()
        .posture_inputs()
        .unwrap();
        assert!(posture.allows_egress);
        assert!(!posture.allows_volumes);
        assert!(!posture.requires_auth);
        assert_eq!(posture.profile, AgentProfile::Dev);
    }

    #[test]
    fn allow_flags_require_a_posture() {
        assert!(parse(&["--allow-egress"]).is_err());
        assert!(parse(&["--allow-volumes"]).is_err());
    }

    #[test]
    fn provenance_is_recorded_only_for_a_locally_built_template() {
        let local = template_provenance("github:org/app#default", false).unwrap();
        assert_eq!(local.input_kind, InputKind::NixFlake);
        assert_eq!(local.input_ref, "github:org/app#default");
        assert!(template_provenance("github:org/app#default", true).is_none());
        assert!(template_provenance("  ", false).is_none());
    }
}
