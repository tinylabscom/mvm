//! Offline release-only diagnostics for the runtime selected in a VM config.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::Args as ClapArgs;
use mvm_build::guest_runtime::evidence::{
    RuntimeArtifactSelection, RuntimeReleaseProof, verify_runtime_release_proof,
};
use mvm_core::arch::GuestArch;
use serde::{Deserialize, Serialize};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// JSON file containing runtime-selection fields from the launch configuration
    #[arg(long)]
    pub config: PathBuf,
    /// Exact expected runtime release version (no automatic tag normalization)
    #[arg(long)]
    pub version: String,
    /// Expected guest architecture, independent of this host
    #[arg(long, value_parser = ["x86_64", "aarch64"])]
    pub arch: String,
    /// Emit a diagnostic JSON report only after successful verification
    #[arg(long, required = true)]
    pub json: bool,
}

// VmStartConfig is not a serde DTO. Read its runtime fields without requiring
// unrelated machine settings or creating a separately supplied binding.
#[derive(Debug, Deserialize)]
struct RuntimeConfig {
    runtime_release_proof: Option<RuntimeReleaseProof>,
    runtime_overlay_version: Option<String>,
    runtime_overlay_path: Option<PathBuf>,
    runtime_overlay_verity_path: Option<PathBuf>,
    runtime_overlay_roothash: Option<String>,
    initrd_path: Option<PathBuf>,
    #[serde(default)]
    unsigned_runtime_development: bool,
    source_runtime_archive_sha256: Option<String>,
    legacy_bundle_runtime: Option<serde_json::Value>,
    legacy_portable_runtime: Option<serde_json::Value>,
    bundle_boot_assets: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    expected_version: String,
    expected_arch: GuestArch,
    provenance: &'static str,
    archive_sha256: String,
    checked_overlay_sha256: String,
    checked_overlay_verity_sha256: String,
    checked_initramfs_sha256: String,
    checked_overlay_roothash: String,
    protocol_version: u32,
    min_supported_protocol_version: u32,
}

pub(in crate::commands) fn run(args: Args) -> Result<()> {
    let bytes = std::fs::read(&args.config).context("reading runtime config JSON")?;
    let config: RuntimeConfig =
        serde_json::from_slice(&bytes).context("decoding VmStartConfig runtime selection")?;
    let report = verify(&config, &args.version, args.arch.parse()?)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn selection<'a>(
    config: &'a RuntimeConfig,
    version: &str,
    arch: GuestArch,
) -> Result<RuntimeArtifactSelection<'a>> {
    ensure!(
        !config.unsigned_runtime_development
            && config.source_runtime_archive_sha256.is_none()
            && config.legacy_bundle_runtime.is_none()
            && config.legacy_portable_runtime.is_none()
            && config.bundle_boot_assets.is_none(),
        "verify-runtime accepts only CLI release runtime; conflicting source, developer, legacy or bundle declaration"
    );
    let proof = config
        .runtime_release_proof
        .as_ref()
        .context("runtime_release_proof is required")?;
    ensure!(
        proof.version == version
            && proof.arch == arch
            && config.runtime_overlay_version.as_deref() == Some(version),
        "runtime selection does not match expected release version and architecture"
    );
    Ok(RuntimeArtifactSelection {
        arch,
        overlay: config
            .runtime_overlay_path
            .as_deref()
            .context("runtime_overlay_path is required")?,
        overlay_verity: config
            .runtime_overlay_verity_path
            .as_deref()
            .context("runtime_overlay_verity_path is required")?,
        overlay_roothash: config
            .runtime_overlay_roothash
            .as_deref()
            .context("runtime_overlay_roothash is required")?,
        initramfs: config
            .initrd_path
            .as_deref()
            .context("initrd_path is required")?,
        minimum_protocol: mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
        host_protocol: mvm_agentd::vsock::PROTOCOL_VERSION,
    })
}

fn verify(config: &RuntimeConfig, version: &str, arch: GuestArch) -> Result<Report> {
    let selected = selection(config, version, arch)?;
    let proof = config
        .runtime_release_proof
        .as_ref()
        .context("runtime_release_proof is required")?;
    let checked = verify_runtime_release_proof(proof, version, arch)?;
    checked.verify_selected_artifacts(&selected)?;
    let declaration = checked.declaration(arch)?;
    // The shared verifier checked these hashes against the actual selected file
    // streams. The report is a diagnostic, not retained ownership or authority.
    Ok(Report {
        schema_version: 1,
        expected_version: version.to_owned(),
        expected_arch: arch,
        provenance: "cli-release",
        archive_sha256: checked.archive_sha256().to_owned(),
        checked_overlay_sha256: declaration.overlay_sha256.clone(),
        checked_overlay_verity_sha256: declaration.overlay_verity_sha256.clone(),
        checked_initramfs_sha256: declaration.initramfs_sha256.clone(),
        checked_overlay_roothash: declaration.overlay_roothash.clone(),
        protocol_version: declaration.protocol_version,
        min_supported_protocol_version: declaration.min_supported_protocol_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::path::Path;

    fn config() -> RuntimeConfig {
        serde_json::from_value(serde_json::json!({
            "runtime_release_proof": {
                "archive": "/release/archive", "checksum": "/release/checksum",
                "signature_bundle": "/release/signature", "archive_sha256": "a".repeat(64),
                "version": "1.2.3", "arch": "x86_64"
            },
            "runtime_overlay_version": "1.2.3",
            "runtime_overlay_path": "/selected/overlay",
            "runtime_overlay_verity_path": "/selected/verity",
            "runtime_overlay_roothash": "b".repeat(64),
            "initrd_path": "/selected/initramfs"
        }))
        .unwrap()
    }

    #[test]
    fn missing_proof_is_rejected() {
        let mut config = config();
        config.runtime_release_proof = None;
        assert!(verify(&config, "1.2.3", GuestArch::X86_64).is_err());
    }

    #[test]
    fn source_developer_legacy_and_bundle_are_rejected_before_reading_files() {
        for field in [
            "source_runtime_archive_sha256",
            "unsigned_runtime_development",
            "legacy_bundle_runtime",
            "legacy_portable_runtime",
            "bundle_boot_assets",
        ] {
            let mut config = config();
            match field {
                "source_runtime_archive_sha256" => {
                    config.source_runtime_archive_sha256 = Some("a".repeat(64));
                }
                "unsigned_runtime_development" => config.unsigned_runtime_development = true,
                "legacy_bundle_runtime" => config.legacy_bundle_runtime = Some(true.into()),
                "legacy_portable_runtime" => config.legacy_portable_runtime = Some(true.into()),
                "bundle_boot_assets" => config.bundle_boot_assets = Some(true.into()),
                _ => unreachable!(),
            }
            let error = verify(&config, "1.2.3", GuestArch::X86_64).unwrap_err();
            assert!(
                error.to_string().contains("conflicting"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn expected_version_arch_and_selected_version_must_match_exactly() {
        let mut config = config();
        assert!(selection(&config, "1.2.4", GuestArch::X86_64).is_err());
        assert!(selection(&config, "v1.2.3", GuestArch::X86_64).is_err());
        assert!(selection(&config, "1.2.3", GuestArch::Aarch64).is_err());
        config.runtime_overlay_version = Some("1.2.4".into());
        assert!(selection(&config, "1.2.3", GuestArch::X86_64).is_err());
    }

    #[test]
    fn partial_selections_and_wrong_field_types_are_rejected() {
        let mut config = config();
        config.initrd_path = None;
        assert!(selection(&config, "1.2.3", GuestArch::X86_64).is_err());
        assert!(
            serde_json::from_value::<RuntimeConfig>(
                serde_json::json!({"unsigned_runtime_development": "false"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<RuntimeConfig>(
                serde_json::json!({"runtime_overlay_path": 123})
            )
            .is_err()
        );
    }

    #[test]
    fn report_schema_is_diagnostic_only() {
        let report = Report {
            schema_version: 1,
            expected_version: "1.2.3".into(),
            expected_arch: GuestArch::X86_64,
            provenance: "cli-release",
            archive_sha256: "a".repeat(64),
            checked_overlay_sha256: "b".repeat(64),
            checked_overlay_verity_sha256: "c".repeat(64),
            checked_initramfs_sha256: "d".repeat(64),
            checked_overlay_roothash: "e".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 1,
        };
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 11);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["expected_version"], "1.2.3");
        assert_eq!(value["expected_arch"], "x86_64");
        assert_eq!(value["provenance"], "cli-release");
        for field in [
            "archive_sha256",
            "checked_overlay_sha256",
            "checked_overlay_verity_sha256",
            "checked_initramfs_sha256",
            "checked_overlay_roothash",
        ] {
            assert_eq!(value[field].as_str().unwrap().len(), 64);
        }
        assert_eq!(value["protocol_version"], 2);
        assert_eq!(value["min_supported_protocol_version"], 1);
    }

    #[derive(Debug, Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn parser_requires_all_options_and_exposes_help() {
        let options = [
            "verify-runtime",
            "--config",
            "/config.json",
            "--version",
            "1.2.3",
            "--arch",
            "aarch64",
            "--json",
        ];
        let parsed = Command::try_parse_from(options).unwrap();
        assert_eq!(parsed.args.config, Path::new("/config.json"));
        assert!(parsed.args.json);
        assert!(Command::try_parse_from(&options[..7]).is_err());
        let help = Command::try_parse_from(["verify-runtime", "--help"]).unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        for flag in ["--config", "--version", "--arch", "--json"] {
            assert!(help.to_string().contains(flag));
        }
    }
}
