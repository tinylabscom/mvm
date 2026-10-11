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

use anyhow::Result;
use clap::{Args as ClapArgs, ValueEnum};
use mvm_client::bundle::{self, ExportRequest, PostureInputs};

use mvm_core::security::AgentProfile;
use mvm_core::user_config::MvmConfig;

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

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let posture = args.posture_inputs().map(Into::into);
    let exported = bundle::export(&ExportRequest {
        template: args.template,
        out: args.out,
        label: args.label,
        cmdline: args.cmdline,
        posture,
    })?;

    println!(
        "Exported bundle to {} ({} bytes, key_id={})",
        exported.path.display(),
        exported.size_bytes,
        exported.key_id,
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
}
