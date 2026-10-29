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
//!
//! `--environment FILE.json` seals a signed environment descriptor: the
//! entrypoint, advisory resources, volumes, secret slot names, required
//! capabilities and application services a launch of the bundle is held to.
//! Every capability it requires must be permitted by `--posture`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use mvm_client::bundle::{
    BundleExportInputs, HostBundleSigner, PostureInputs, export_bundle_with_signer,
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
    /// Output path for the `.mvmpkg` archive. Parent directory must
    /// exist; the file is overwritten if it already exists.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Private directory for the existing archive signer. Defaults to the
    /// current state's keys; use a separate directory for a publisher key.
    #[arg(long, value_name = "DIR")]
    pub signing_keys: Option<PathBuf>,
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
    /// Seal the exact package policy profile beside its environment.
    #[arg(long, value_name = "FILE", requires = "environment")]
    pub application_policy: Option<PathBuf>,
    /// Embed authenticated boot archives from a signed image-set directory.
    #[arg(long, value_name = "DIR")]
    pub boot_assets: Option<PathBuf>,
}

struct ExportBootAssets {
    manifest_bytes: Vec<u8>,
    manifest_sha256: mvm_core::packs::Sha256Hex,
    runtime_overlay: PathBuf,
    initramfs: PathBuf,
    signed_initrd: PathBuf,
    _cache: tempfile::TempDir,
}

impl ExportBootAssets {
    fn read(directory: &std::path::Path, arch: &str) -> Result<Self> {
        use mvm_core::image_set::{
            ImageSetVerification, image_train_lock, verify_image_set_artifacts,
            verify_image_set_root,
        };
        use mvm_core::plan::bundle::{
            BOOT_ASSET_INITRAMFS_ROLE, BOOT_ASSET_OVERLAY_ROLE, select_boot_asset_members,
        };
        let manifest_bytes = std::fs::read(directory.join("image-set.json"))
            .context("reading the boot image-set manifest")?;
        let signature = std::fs::read(directory.join("image-set.json.bundle"))
            .context("reading the boot image-set signature")?;
        let host = mvm_build::stage0_kernel::current_image_set_protocol_support();
        let revocations = mvm_core::image_set_revocation::load_image_set_revocations()
            .context("loading current image-set revocations before export")?;
        let request = ImageSetVerification::new(
            &manifest_bytes,
            &signature,
            &image_train_lock().image_set,
            directory,
        )
        .with_host_protocols(&host)
        .with_revocations(&revocations);
        let root = verify_image_set_root(&request).context("authenticating boot image-set root")?;
        let arch = match arch {
            "aarch64" => mvm_core::arch::GuestArch::Aarch64,
            "x86_64" => mvm_core::arch::GuestArch::X86_64,
            _ => anyhow::bail!("unsupported boot-assets architecture {arch}"),
        };
        let members = select_boot_asset_members(root.manifest(), arch)?;
        let selected = members
            .iter()
            .flat_map(|member| &member.artifacts)
            .map(|artifact| artifact.name.clone())
            .collect::<Vec<_>>();
        let verified = verify_image_set_artifacts(&request, &selected)
            .context("verifying selected boot archive bytes")?;
        let path = |role| {
            verified
                .artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .map(|artifact| artifact.path.clone())
                .context("verified boot archive is missing")
        };
        let runtime_overlay = path(BOOT_ASSET_OVERLAY_ROLE)?;
        let initramfs = path(BOOT_ASSET_INITRAMFS_ROLE)?;
        let cache = tempfile::tempdir().context("staging verified boot initramfs")?;
        let (_, ramdisk) = mvm_build::published_image_set::install_boot_archives(
            &runtime_overlay,
            &initramfs,
            &verified.manifest_sha256,
            arch,
            cache.path(),
        )
        .context("validating the authenticated boot payloads before signing")?;
        let signed_initrd = ramdisk.image_path;
        Ok(Self {
            manifest_bytes,
            manifest_sha256: verified.manifest_sha256,
            runtime_overlay,
            initramfs,
            signed_initrd,
            _cache: cache,
        })
    }

    fn inputs(&self) -> mvm_client::bundle::BootAssetsInputs<'_> {
        mvm_client::bundle::BootAssetsInputs {
            manifest_bytes: &self.manifest_bytes,
            manifest_sha256: &self.manifest_sha256,
            runtime_overlay: &self.runtime_overlay,
            initramfs: &self.initramfs,
        }
    }
}

fn read_application_policy(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let limit = mvm_core::registry_pack::MAX_APPLICATION_POLICY_BYTES;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("opening application policy at {}", path.display()))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "application policy at {} must contain between 1 and {limit} bytes",
        path.display()
    );
    let _: mvm_client::policy_profiles::ProfileFile = toml::from_str(std::str::from_utf8(&bytes)?)
        .context("parsing application policy profile")?;
    Ok(bytes)
}

/// Read and check the descriptor at `path` before any artifact is hashed, so
/// a malformed file is refused with its own name rather than as a verifier
/// error about the sealed manifest.
fn read_environment(path: &std::path::Path) -> Result<EnvironmentDescriptor> {
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
    let (spec, vmlinux, mut initrd, rootfs, _rev) =
        tmpl::template_artifacts_dispatched(&args.template).with_context(|| {
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
    let environment = args
        .environment
        .as_deref()
        .map(read_environment)
        .transpose()?;
    let application_policy = args
        .application_policy
        .as_deref()
        .map(read_application_policy)
        .transpose()?;
    let boot_assets = args
        .boot_assets
        .as_deref()
        .map(|directory| ExportBootAssets::read(directory, &source_arch))
        .transpose()?;
    if let Some(boot) = &boot_assets {
        if let Some(template_initrd) = &initrd {
            anyhow::ensure!(
                mvm_core::crypto::image_verify::sha256_file(std::path::Path::new(template_initrd))?
                    == mvm_core::crypto::image_verify::sha256_file(&boot.signed_initrd)?,
                "template initrd differs from the authenticated boot initramfs"
            );
        }
        initrd = Some(
            boot.signed_initrd
                .to_str()
                .context("verified initrd path must be UTF-8")?
                .to_owned(),
        );
    }

    // ---- 2. Seal, sign under the host key, and write the archive ----
    let signer = match args.signing_keys.as_deref() {
        Some(keys) => HostBundleSigner::load_at(keys)?,
        None => HostBundleSigner::load()?,
    };
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
            environment,
            application_policy: application_policy.as_deref(),
            boot_assets: boot_assets.as_ref().map(ExportBootAssets::inputs),
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
    fn publisher_key_selection_does_not_grant_a_posture_or_capabilities() {
        assert!(parse(&[]).unwrap().signing_keys.is_none());
        let args = parse(&["--signing-keys", "/private/publisher-keys"]).unwrap();
        assert_eq!(
            args.signing_keys,
            Some(PathBuf::from("/private/publisher-keys"))
        );
        assert_eq!(args.posture_inputs(), None);
        assert!(!args.allow_egress);
        assert!(!args.allow_volumes);
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
    fn environment_flag_names_a_file() {
        let args = parse(&["--environment", "env.json"]).unwrap();
        assert_eq!(args.environment, Some(PathBuf::from("env.json")));
        assert_eq!(parse(&[]).unwrap().environment, None);
    }

    #[test]
    fn an_application_policy_requires_an_environment() {
        assert!(parse(&["--application-policy", "profile.toml"]).is_err());
        let args = parse(&[
            "--environment",
            "env.json",
            "--application-policy",
            "profile.toml",
        ])
        .unwrap();
        assert_eq!(args.application_policy, Some(PathBuf::from("profile.toml")));
    }

    #[test]
    fn boot_assets_are_an_explicit_directory_input() {
        assert_eq!(parse(&[]).unwrap().boot_assets, None);
        assert_eq!(
            parse(&["--boot-assets", "/tmp/boot-assets"])
                .unwrap()
                .boot_assets,
            Some(PathBuf::from("/tmp/boot-assets"))
        );
    }

    #[test]
    fn boot_assets_fail_closed_without_current_revocation_trust() {
        let directory = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        std::fs::write(directory.path().join("image-set.json"), b"{}").unwrap();
        std::fs::write(directory.path().join("image-set.json.bundle"), b"{}").unwrap();
        let error = ExportBootAssets::read(directory.path(), "aarch64")
            .err()
            .expect("unconfigured trust must refuse export");
        assert!(format!("{error:#}").contains("revocations"));
    }

    #[test]
    fn application_profile_input_is_bounded_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile.toml");
        let bytes = b"description = \"agent environment\"\n";
        std::fs::write(&profile, bytes).unwrap();
        assert_eq!(read_application_policy(&profile).unwrap(), bytes);
        std::fs::write(&profile, b"").unwrap();
        assert!(read_application_policy(&profile).is_err());
        std::fs::write(&profile, b"unknown_field = true\n").unwrap();
        assert!(read_application_policy(&profile).is_err());
        std::fs::write(
            &profile,
            vec![b' '; mvm_core::registry_pack::MAX_APPLICATION_POLICY_BYTES + 1],
        )
        .unwrap();
        assert!(read_application_policy(&profile).is_err());
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
