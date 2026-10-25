//! Shared template-to-bundle implementation for `mvmctl build` and the hidden
//! `mvmctl dev export-template` fixture command.
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
//!
//! `--environment FILE.json` seals a signed environment descriptor: the
//! entrypoint, advisory resources, volumes, secret slot names, required
//! capabilities and application services a launch of the bundle is held to.
//! Every capability it requires must be permitted by `--posture`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_client::bundle::{
    BundleExportInputs, HostBundleSigner, PostureInputs, StagedBundle, stage_bundle_with_signer,
};

use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::plan::{BundleResources, EnvironmentDescriptor};
use mvm_core::security::AgentProfile;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Template name or 64-char slot hash to export.
    #[arg(value_name = "TEMPLATE")]
    pub template: String,
    /// New output path for the `.mvmpkg` archive. Missing parent directories
    /// are created; existing destinations are refused without overwriting.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    #[command(flatten)]
    pub options: ExportOptions,
}

/// Archive metadata shared by every source accepted by the build front door.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct ExportOptions {
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
    /// JSON file holding the environment descriptor to seal: entrypoint,
    /// advisory resources, volumes, secret slot names, required capabilities
    /// and application services. Capabilities need a `--posture` that
    /// permits them.
    #[arg(long, value_name = "FILE.json")]
    pub environment: Option<PathBuf>,
}

/// Read and check the descriptor at `path` before any artifact is hashed, so
/// a malformed file is refused with its own name rather than as a verifier
/// error about the sealed manifest.
pub(in crate::commands) fn read_environment(
    path: &std::path::Path,
) -> Result<EnvironmentDescriptor> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading environment descriptor at {}", path.display()))?;
    let descriptor: EnvironmentDescriptor = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing environment descriptor at {}", path.display()))?;
    descriptor
        .validate()
        .with_context(|| format!("checking environment descriptor at {}", path.display()))?;
    Ok(descriptor)
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

impl ExportOptions {
    pub(in crate::commands) fn posture_inputs(&self) -> Option<PostureInputs> {
        self.posture.map(|profile| {
            PostureInputs::new(profile.into())
                .requires_auth(!self.allow_unauthenticated)
                .allows_volumes(self.allow_volumes)
                .allows_egress(self.allow_egress)
        })
    }

    pub(in crate::commands) fn apply(self, mut export: TemplateExport) -> Result<TemplateExport> {
        let posture = self.posture_inputs();
        if let Some(label) = self.label {
            export.label = Some(label);
        }
        if let Some(path) = self.cmdline {
            export.cmdline =
                Some(std::fs::read_to_string(&path).with_context(|| {
                    format!("reading kernel command line at {}", path.display())
                })?);
        }
        if posture.is_some() {
            export.posture = posture;
        }
        if let Some(path) = self.environment {
            export.environment = Some(read_environment(&path)?);
        }
        Ok(export)
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

/// What one export of a built template records beyond its artifacts.
pub(in crate::commands) struct TemplateExport {
    /// Where the archive is written.
    pub out: PathBuf,
    /// Human-readable workload label.
    pub label: Option<String>,
    /// The kernel command line the workload was built and tested with.
    pub cmdline: Option<String>,
    /// The ceilings the publisher places on any launch.
    pub posture: Option<PostureInputs>,
    /// Sizing to record instead of the template's own.
    pub resources: Option<BundleResources>,
    /// Provenance to record instead of the template's flake reference. The
    /// exporter still replaces its artifact digests with the sealed bytes'.
    pub provenance: Option<BuildProvenance>,
    /// The signed environment descriptor to seal beside the artifacts.
    pub environment: Option<EnvironmentDescriptor>,
    /// Whether the host signer must mark this archive as local build output.
    pub local_build: bool,
    /// Owned verified producer closure, shared with the preceding health call.
    pub portable_boot_assets:
        Option<std::sync::Arc<mvm_client::portable_boot_assets::PreparedPortableBootAssets>>,
}

impl TemplateExport {
    pub(in crate::commands) fn new(out: PathBuf) -> Self {
        Self {
            out,
            label: None,
            cmdline: None,
            posture: None,
            resources: None,
            provenance: None,
            environment: None,
            local_build: false,
            portable_boot_assets: None,
        }
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let export = args.options.apply(TemplateExport::new(args.out))?;
    let exported = export_template(&args.template, export)?;
    println!(
        "Exported bundle to {} ({} bytes, key_id={})",
        exported.path.display(),
        exported.size_bytes,
        exported.key_id.0,
    );
    Ok(())
}

/// Seal a built template (or an installed bundle) into a signed archive under
/// the host signer.
pub(in crate::commands) fn export_template(
    template: &str,
    export: TemplateExport,
) -> Result<mvm_client::bundle::ExportedBundle> {
    stage_template(template, export)?.publish()
}

pub(in crate::commands) fn stage_template(
    template: &str,
    export: TemplateExport,
) -> Result<StagedBundle> {
    // ---- 1. Resolve the template's artifact paths ----
    let (spec, vmlinux, initrd, rootfs, _rev) = tmpl::template_artifacts_dispatched(template)
        .with_context(|| {
            format!("loading template {template:?} — does it exist? Try `mvmctl manifest ls`")
        })?;

    // Carry a re-exported bundle's own architecture through rather than
    // re-stamping this host's. `template_artifacts_dispatched` resolves an
    // installed bundle as happily as a local slot, so an aarch64 bundle
    // re-exported from an x86_64 host would otherwise be relabelled x86_64
    // while still containing an aarch64 rootfs — and the label is what the
    // boot-time gate trusts. A slot built here has no manifest, so it takes
    // the host arch, which is correct for that case.
    let installed_arch = match tmpl::installed_bundle_archive(template)? {
        Some(archive) => {
            let verified = mvm_core::plan::bundle::verify_bundle_file(
                &archive,
                &mvm_core::plan::bundle::FsTrustStore::default_path()?,
            )
            .context("verifying the original bundle before re-export")?;
            anyhow::ensure!(
                !verified.manifest.members.iter().any(|member| matches!(
                    member,
                    mvm_core::plan::bundle::BundleMember::EmbeddedBootAssets { .. }
                        | mvm_core::plan::bundle::BundleMember::EmbeddedCliBootAssets(_)
                        | mvm_core::plan::bundle::BundleMember::CanonicalLinuxProof(_)
                        | mvm_core::plan::bundle::BundleMember::EmbeddedImageSet { .. }
                )),
                "re-export of protected boot members requires original closure custody; refusing to drop publisher evidence"
            );
            Some(verified.manifest.arch)
        }
        None => None,
    };
    let installed_export = installed_arch.is_some();
    let provenance = export
        .provenance
        .or_else(|| template_provenance(&spec.flake_ref, installed_arch.is_some()));
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

    if let Some(assets) = &export.portable_boot_assets {
        anyhow::ensure!(
            !installed_export,
            "cannot replace an installed bundle's closure"
        );
        assets.verify_build_kernel(std::path::Path::new(&vmlinux))?;
    }
    // ---- 2. Seal, sign under the host key, and write the archive ----
    let selected_initrd = export
        .portable_boot_assets
        .as_ref()
        .map(|assets| {
            assets
                .initramfs_path()
                .to_str()
                .context("portable initramfs path is not UTF-8")
        })
        .transpose()?
        .or(initrd.as_deref());
    let signer = HostBundleSigner::load()?;
    let inputs = BundleExportInputs {
        vmlinux: &vmlinux,
        initrd: selected_initrd,
        rootfs: &rootfs,
        verity_bytes: verity_bytes.as_deref(),
        roothash: roothash.as_deref(),
        profile: Some(&spec.profile),
        // The template's declared resources travel with the bundle so a
        // launch on another host starts from them without rediscovering
        // them. `--cpus` / `--memory` still override at launch time.
        resources: Some(export.resources.unwrap_or(BundleResources {
            vcpus: u32::from(spec.vcpus),
            mem_mib: spec.mem_mib,
        })),
        arch_label: &source_arch,
        label: export.label,
        cmdline: export.cmdline.as_deref(),
        posture: export.posture,
        provenance,
        environment: export.environment,
        local_build: export.local_build,
        boot_assets: None,
        cli_boot_assets: None,
        canonical_linux_proof: None,
        out: &export.out,
        debug_out: None,
    };
    match &export.portable_boot_assets {
        Some(assets) => assets.stage(&inputs, &signer),
        None => stage_bundle_with_signer(&inputs, &signer),
    }
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
        assert_eq!(parse(&[]).unwrap().options.posture_inputs(), None);
    }

    #[test]
    fn a_posture_starts_closed() {
        let posture = parse(&["--posture", "sealed-prod"])
            .unwrap()
            .options
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
        .options
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
    fn environment_flag_names_a_file() {
        let args = parse(&["--environment", "env.json"]).unwrap();
        assert_eq!(args.options.environment, Some(PathBuf::from("env.json")));
        assert_eq!(parse(&[]).unwrap().options.environment, None);
    }

    #[test]
    fn an_environment_file_is_parsed_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.json");
        std::fs::write(
            &good,
            br#"{"descriptor_version":1,"target":"x86_64-linux","entrypoint":{"argv":["/bin/app"]}}"#,
        )
        .unwrap();
        assert_eq!(
            read_environment(&good).unwrap().entrypoint.argv,
            vec!["/bin/app".to_string()]
        );

        let unknown = dir.path().join("unknown.json");
        std::fs::write(
            &unknown,
            br#"{"descriptor_version":1,"target":"x86_64-linux","entrypoint":{"argv":["/bin/app"]},"capabilities":["root"]}"#,
        )
        .unwrap();
        assert!(read_environment(&unknown).is_err());

        let empty = dir.path().join("empty.json");
        std::fs::write(
            &empty,
            br#"{"descriptor_version":1,"target":"x86_64-linux","entrypoint":{"argv":[]}}"#,
        )
        .unwrap();
        let err = read_environment(&empty).unwrap_err();
        assert!(format!("{err:#}").contains("argv"), "{err:#}");
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
