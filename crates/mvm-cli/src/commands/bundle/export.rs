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
use mvm_client::bundle::PostureInputs;
pub(in crate::commands) use mvm_client::bundle::{TemplateExport, export_template, stage_template};

use mvm_core::plan::EnvironmentDescriptor;
use mvm_core::security::AgentProfile;
use mvm_core::user_config::MvmConfig;

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
}
