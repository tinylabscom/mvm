//! `mvmctl build guest-bins` — assemble the publishable `mvm-guest-bins`
//! artifact from this source checkout.
//!
//! The archive carries every guest artifact mvm owns: the static guest
//! executables, the initramfs agent, the host-services and GPU shared objects
//! for both libcs, and the Python SDK. The executables come from the same
//! host-side guest builds the runtime overlay and the OCI runtime already use,
//! so a warm cache makes this a packaging step and a cold one compiles each
//! requested architecture once.
//!
//! Its consumer is `mvmctl`: the archive is the guest runtime each CLI release
//! publishes as a signed asset, and the release workflow produces it with this
//! command. A downloaded `mvmctl` acquires its own version's copy;
//! `mvm-images` does not consume it.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_build::guest_bins::{GuestBinsBuild, WrittenGuestBins, build_guest_bins};
use mvm_core::arch::GuestArch;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Directory to write mvm-guest-bins-v<version>.tar.gz and its .sha256 into
    #[arg(long, value_name = "DIR", default_value = ".")]
    pub out: PathBuf,

    /// Guest architecture to include (repeatable: aarch64, x86_64). Defaults
    /// to both
    #[arg(long = "arch", value_name = "ARCH")]
    pub arches: Vec<GuestArch>,
}

/// Both guest architectures, which is what a published artifact carries.
const ALL_ARCHES: [GuestArch; 2] = [GuestArch::Aarch64, GuestArch::X86_64];

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let workspace =
        mvm_build::guest_agent_build::detect_source_workspace().ok_or_else(no_source_checkout)?;
    let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let request = build_request(&args, workspace, cache_root);
    // A cold cache compiles every guest artifact per architecture, which takes
    // many minutes; the live line keeps that from looking like a hang.
    let phase = crate::ui::activity::start(format!(
        "Building the guest artifacts for {} from {}",
        arch_list(&request.arches),
        request.workspace_root.display()
    ));
    let written = build_guest_bins(&request).context("assemble the guest-bins artifact")?;
    phase.finish();
    println!("{}", render_summary(&written));
    Ok(())
}

fn no_source_checkout() -> anyhow::Error {
    anyhow::anyhow!(
        "`mvmctl build guest-bins` builds from an mvm source checkout, and none was found; \
         run it from a clone of the mvm repository"
    )
}

/// The build the arguments describe. No `--arch` means every architecture.
fn build_request(args: &Args, workspace_root: PathBuf, cache_root: PathBuf) -> GuestBinsBuild {
    let arches = if args.arches.is_empty() {
        ALL_ARCHES.to_vec()
    } else {
        args.arches.clone()
    };
    GuestBinsBuild {
        workspace_root,
        cache_root,
        version: env!("CARGO_PKG_VERSION").to_string(),
        arches,
        out_dir: args.out.clone(),
    }
}

fn arch_list(arches: &[GuestArch]) -> String {
    arches
        .iter()
        .map(GuestArch::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_summary(written: &WrittenGuestBins) -> String {
    let manifest = &written.manifest;
    [
        format!(
            "mvm-guest-bins {}: {}",
            manifest.version,
            written.archive.display()
        ),
        format!("  sha256:                        {}", written.sha256),
        format!("  members:                       {}", manifest.files.len()),
        format!("  source:                        {}", manifest.source),
        format!(
            "  guest_source_fingerprint:      {}",
            manifest.guest_source_fingerprint
        ),
        format!(
            "  sdk_cdylib_source_fingerprint: {}",
            manifest.sdk_cdylib_source_fingerprint
        ),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_set::{GitCommit, RepoIdentity, WorktreeState};
    use std::collections::BTreeMap;

    fn args(arches: Vec<GuestArch>) -> Args {
        Args {
            out: PathBuf::from("/tmp/out"),
            arches,
        }
    }

    #[test]
    fn no_arch_flag_builds_both_architectures() {
        let request = build_request(&args(vec![]), "/ws".into(), "/cache".into());
        assert_eq!(request.arches, ALL_ARCHES.to_vec());
        assert_eq!(request.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(request.out_dir, PathBuf::from("/tmp/out"));
        assert_eq!(request.cache_root, PathBuf::from("/cache"));
    }

    #[test]
    fn an_arch_flag_narrows_the_build() {
        let request = build_request(
            &args(vec![GuestArch::X86_64]),
            "/ws".into(),
            "/cache".into(),
        );
        assert_eq!(request.arches, vec![GuestArch::X86_64]);
    }

    #[test]
    fn the_summary_names_the_pin_the_source_and_both_fingerprints() {
        let written = WrittenGuestBins {
            archive: PathBuf::from("/out/mvm-guest-bins-v1.2.3.tar.gz"),
            checksum: PathBuf::from("/out/mvm-guest-bins-v1.2.3.tar.gz.sha256"),
            sha256: "ab".repeat(32),
            manifest: mvm_build::guest_bins::GuestBinsManifest {
                schema_version: 1,
                version: "1.2.3".into(),
                guest_source_fingerprint: "g".repeat(64),
                sdk_cdylib_source_fingerprint: "c".repeat(64),
                source: RepoIdentity {
                    commit: GitCommit::new("e".repeat(40)).unwrap(),
                    worktree: WorktreeState::Clean,
                },
                files: BTreeMap::from([("x86_64/bin/mvm-guest-agent".into(), "d".repeat(64))]),
            },
        };
        let summary = render_summary(&written);
        for expected in [
            "mvm-guest-bins-v1.2.3.tar.gz".to_string(),
            "ab".repeat(32),
            "g".repeat(64),
            "c".repeat(64),
            format!("{} (clean)", "e".repeat(40)),
        ] {
            assert!(summary.contains(&expected), "{summary}");
        }
    }
}
