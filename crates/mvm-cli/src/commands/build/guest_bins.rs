//! `mvmctl dev guest-bins` — assemble the publishable `mvm-guest-bins`
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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_build::guest_bins::{
    GuestBinsBuild, GuestBinsManifest, WrittenGuestBins, build_guest_bins,
};
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

    /// Check an existing complete release archive without building or acquiring artifacts
    #[arg(long, value_name = "FILE", conflicts_with_all = ["out", "arches"])]
    pub check_release_archive: Option<PathBuf>,
}

/// Both guest architectures, which is what a published artifact carries.
const ALL_ARCHES: [GuestArch; 2] = [GuestArch::Aarch64, GuestArch::X86_64];

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if let Some(archive) = &args.check_release_archive {
        return check_archive_to_stdout(archive);
    }
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
    validate_complete_runtime(&written.manifest, &request.arches, &request.version)?;
    phase.finish();
    println!("{}", render_summary(&written));
    Ok(())
}

pub(in crate::commands) fn check_archive_to_stdout(archive: &Path) -> Result<()> {
    let manifest = check_existing_release(archive)?;
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(())
}

fn check_existing_release(archive: &Path) -> Result<GuestBinsManifest> {
    let version = env!("CARGO_PKG_VERSION");
    let manifest = mvm_build::guest_bins::release::check_release_archive(archive, version)
        .context("checking the original release runtime archive")?;
    mvm_build::guest_runtime::validate_release_guest_runtime_manifest(&manifest, version)
        .context("checking complete release runtime boot assemblies")?;
    Ok(manifest)
}

fn validate_complete_runtime(
    manifest: &GuestBinsManifest,
    arches: &[GuestArch],
    version: &str,
) -> Result<()> {
    if ALL_ARCHES.iter().all(|arch| arches.contains(arch)) {
        // The archive writer already verified the original payload's hashes.
        // A complete publishing inventory also needs the canonical runtime
        // version, required members and both deterministic boot assemblies.
        mvm_build::guest_runtime::validate_release_guest_runtime_manifest(manifest, version)
            .context("validating the complete release runtime before upload")?;
    }
    Ok(())
}

fn no_source_checkout() -> anyhow::Error {
    anyhow::anyhow!(
        "`mvmctl dev guest-bins` builds from an mvm source checkout, and none was found; \
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
            check_release_archive: None,
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
    fn existing_archive_check_refuses_missing_or_malformed_inputs_without_building() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.tar.gz");
        assert!(check_existing_release(&missing).is_err());
        let malformed = directory.path().join("malformed.tar.gz");
        std::fs::write(&malformed, b"not an archive").unwrap();
        assert!(check_existing_release(&malformed).is_err());
        assert!(!directory.path().join("cache").exists());
        assert!(!directory.path().join("vms").exists());
    }

    fn written_fixture() -> WrittenGuestBins {
        WrittenGuestBins {
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
                assemblies: Default::default(),
            },
        }
    }

    #[test]
    fn complete_publishing_inventory_uses_the_canonical_runtime_validator() {
        let mut written = written_fixture();
        written.manifest.schema_version = mvm_build::guest_bins::GUEST_BINS_MANIFEST_SCHEMA;
        let error = validate_complete_runtime(&written.manifest, &ALL_ARCHES, "1.2.3")
            .expect_err("a partial legacy manifest must not become a release runtime");
        assert!(format!("{error:#}").contains("complete release runtime"));
        let wrong_version = validate_complete_runtime(&written.manifest, &ALL_ARCHES, "9.9.9")
            .expect_err("the canonical validator must refuse the wrong runtime version");
        assert!(format!("{wrong_version:#}").contains("9.9.9"));
    }

    #[test]
    fn explicit_single_arch_development_build_remains_partial() {
        let written = written_fixture();
        validate_complete_runtime(&written.manifest, &[GuestArch::X86_64], "1.2.3").unwrap();
    }

    #[test]
    fn the_summary_names_the_pin_the_source_and_both_fingerprints() {
        let written = written_fixture();
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
