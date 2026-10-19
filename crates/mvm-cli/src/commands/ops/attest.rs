//! `mvmctl trust attest` formatting and file-output adapters.
//!
//! Verification, bounded input reads, key loading and redacted diagnostics
//! belong to the client facade. Explicit public-key trust does not resolve or
//! initialize the verifier's local identity. Default/self trust, export and
//! status retain their documented identity initialization behavior.
//!
//! The current report has a zero boot measurement and no hardware measurement;
//! it is not evidence of native boot attestation or workload execution.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use std::path::PathBuf;

use mvm_client::attestation::{self, Trust};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: AttestAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum AttestAction {
    /// Emit a fresh attestation report signed by this host.
    Export {
        /// Write the JSON report to this file. Defaults to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a previously emitted attestation report.
    Verify {
        /// Path to the JSON report to verify.
        report: PathBuf,
        /// Path to a 32-byte raw Ed25519 public key trusted to sign
        /// reports. Mutually exclusive with `--trust-self`.
        #[arg(long, conflicts_with = "trust_self")]
        trust: Option<PathBuf>,
        /// Trust the host's own identity public key (the default if
        /// neither flag is set). Convenient for "did I just emit a
        /// valid report?" round-trips.
        #[arg(long)]
        trust_self: bool,
    },
    /// Show the host identity public key + provider availability.
    Status,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.action {
        AttestAction::Export { output } => export(output),
        AttestAction::Verify {
            report,
            trust,
            trust_self,
        } => verify(report, trust, trust_self),
        AttestAction::Status => status(),
    }
}

fn export(output: Option<PathBuf>) -> Result<()> {
    let report = attestation::export()?;
    let json =
        serde_json::to_string_pretty(&report).context("serializing attestation report to JSON")?;

    match output {
        Some(path) => {
            std::fs::write(&path, &json)
                .with_context(|| format!("writing report to {}", path.display()))?;
            eprintln!("wrote attestation report to {}", path.display());
        }
        None => {
            println!("{json}");
        }
    }
    Ok(())
}

fn verify(report_path: PathBuf, trust: Option<PathBuf>, _trust_self: bool) -> Result<()> {
    // Preserve the operator-facing default while passing an explicit trust
    // decision into the facade. The key-file branch never resolves identity.
    let (trust, source_label) = if let Some(path) = trust {
        let label = format!("file {}", path.display());
        (Trust::PublicKeyFile(path), label)
    } else {
        (Trust::SelfIdentity, "self".to_string())
    };
    let verified = attestation::verify(&report_path, trust)?;
    let signer_id = verified.signer_id;
    let body = verified.body;

    println!("OK  signer_id={signer_id}  trusted_by={source_label}");
    println!(
        "    schema_version={}  boot_measurement={}",
        body.schema_version, body.boot_measurement
    );
    println!("    identity_pubkey={}", body.identity_pubkey_hex);
    println!("    nonce={}", body.nonce_hex);
    if let Some(hw) = body.hw_measurement {
        println!("    hw_measurement.provider={:?}", hw.provider);
        println!("    hw_measurement.bytes={}", hw.measurement_hex);
    }
    Ok(())
}

fn status() -> Result<()> {
    let status = attestation::status()?;
    println!("identity.signer_id   = {}", status.signer_id);
    println!("identity.pubkey_hex  = {}", status.pubkey_hex);
    println!("identity.secret_path = {}", status.secret_path.display());
    println!("identity.public_path = {}", status.public_path.display());
    println!();
    println!("hardware providers:");
    for provider in status.providers {
        let state = if provider.compiled {
            "compiled"
        } else {
            "not compiled (rebuild with feature flag to enable)"
        };
        println!(
            "  {:<8} feature={:<22}  {state}",
            provider.name, provider.feature
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::dispatch::TopLevelCommand;
    use clap::Parser;
    use mvm_client::attestation::PLACEHOLDER_BOOT_MEASUREMENT;
    use mvm_core::crypto::attestation::{
        AttestationBody, AttestationReport, IdentityKey, SCHEMA_VERSION, identity, sign_report,
        verify_report,
    };

    fn invoke(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<()> {
        let cli = Cli::try_parse_from(
            ["mvmctl".into(), "trust".into(), "attest".into()]
                .into_iter()
                .chain(args),
        )?;
        cli.command.clone().run(&cli, &MvmConfig::default())
    }

    fn signed_fixture() -> (tempfile::TempDir, IdentityKey, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let key = identity::load_or_init_at(&root.path().join("producer")).unwrap();
        let body = AttestationBody::new(
            mvm_client::attestation::PLACEHOLDER_BOOT_MEASUREMENT,
            &key.verifying,
            None,
        );
        let report = sign_report(&body, &key.signing, &identity::identity_signer_id());
        let path = root.path().join("report.json");
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        (root, key, path)
    }

    fn verify_explicit(report: &std::path::Path, public: &std::path::Path) -> Result<()> {
        invoke([
            "verify".into(),
            report.as_os_str().into(),
            "--trust".into(),
            public.as_os_str().into(),
        ])
    }

    fn assert_redacted(error: anyhow::Error, marker: &str) {
        for diagnostic in [
            format!("{error}"),
            format!("{error:#}"),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!diagnostic.contains(marker), "{diagnostic}");
        }
        for source in error.chain() {
            assert!(!format!("{source} {source:?}").contains(marker));
        }
        let contextual = error.context("command adapter verification refused");
        assert!(!format!("{contextual:#} {contextual:#?}").contains(marker));
    }

    #[test]
    fn cli_adapter_explicit_trust_does_not_require_local_identity_location() {
        let (_producer, key, report) = signed_fixture();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.remove("HOME");
        env.remove("MVM_HOME");
        verify_explicit(&report, &key.public_path).unwrap();
    }

    #[test]
    fn cli_adapter_refuses_oversized_valid_json_before_identity_effects() {
        let (_producer, key, report) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut bytes = vec![b' '; mvm_client::attestation::MAX_REPORT_BYTES + 1];
        bytes.extend(std::fs::read(&report).unwrap());
        std::fs::write(&report, bytes).unwrap();
        assert!(verify_explicit(&report, &key.public_path).is_err());
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn cli_adapter_outer_parse_diagnostics_do_not_echo_payload() {
        let (_producer, key, report) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let marker = "private-cli-outer-payload-must-not-escape";
        std::fs::write(&report, format!(r#"{{"payload":"{marker}"}}"#)).unwrap();
        assert_redacted(
            verify_explicit(&report, &key.public_path).unwrap_err(),
            marker,
        );
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn cli_adapter_authenticated_inner_parse_diagnostics_do_not_echo_payload() {
        use ed25519_dalek::Signer;
        let (_producer, key, report_path) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let original = std::fs::read(&report_path).unwrap();
        let marker = "private-cli-authenticated-body-must-not-escape";
        for field in ["schema_version", "hw_measurement"] {
            let mut report: AttestationReport = serde_json::from_slice(&original).unwrap();
            let mut body: serde_json::Value = serde_json::from_slice(&report.0.payload).unwrap();
            body[field] = serde_json::json!(marker);
            report.0.payload = serde_json::to_vec(&body).unwrap();
            report.0.signature = key.signing.sign(&report.0.payload).to_bytes().to_vec();
            assert!(matches!(
                verify_report(&report, &[(report.0.signer_id.as_str(), &key.verifying)]),
                Err(mvm_core::crypto::attestation::AttestationError::Parse(_))
            ));
            std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
            assert_redacted(
                verify_explicit(&report_path, &key.public_path).unwrap_err(),
                marker,
            );
            assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn export_then_verify_self_round_trips_through_disk() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let report_dir = tempfile::tempdir().unwrap();
        let report_path = report_dir.path().join("report.json");

        invoke([
            "export".into(),
            "--output".into(),
            report_path.as_os_str().into(),
        ])
        .unwrap();
        invoke(["verify".into(), report_path.as_os_str().into()]).unwrap();
        invoke([
            "verify".into(),
            report_path.as_os_str().into(),
            "--trust-self".into(),
        ])
        .unwrap();

        let bytes = std::fs::read(&report_path).unwrap();
        let report: AttestationReport = serde_json::from_slice(&bytes).unwrap();
        let body: AttestationBody =
            serde_json::from_slice(&report.0.payload).expect("inner body parses");
        assert_eq!(body.schema_version, SCHEMA_VERSION);
        assert_eq!(body.boot_measurement, PLACEHOLDER_BOOT_MEASUREMENT);
        assert!(body.hw_measurement.is_none(), "v0 emits no hw measurement");
    }

    #[test]
    fn verify_fails_on_tampered_payload() {
        let (_producer, key, report_path) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());

        // Flip one byte inside the payload. The envelope sig must
        // refuse on verify.
        let bytes = std::fs::read(&report_path).unwrap();
        let mut report: AttestationReport = serde_json::from_slice(&bytes).unwrap();
        report.0.payload[0] ^= 0x01;
        std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();

        let err = verify_explicit(&report_path, &key.public_path)
            .expect_err("must refuse tampered report");
        let msg = err.to_string();
        assert!(msg.contains("verify"), "error mentions verify: {msg}");
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn verify_fails_when_trust_file_is_wrong_key() {
        let (producer, _key, report_path) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let other = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
        let trust_path = producer.path().join("trust.pub");
        std::fs::write(&trust_path, other.to_bytes()).unwrap();

        let err = verify_explicit(&report_path, &trust_path)
            .expect_err("must refuse with wrong trust key");
        let msg = err.to_string();
        assert!(msg.contains("verify"), "error mentions verify: {msg}");
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn load_pubkey_file_refuses_wrong_length() {
        let (producer, _key, report) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let path = producer.path().join("bad.pub");
        for length in [16, 33, 1024 * 1024] {
            std::fs::write(&path, vec![0u8; length]).unwrap();
            assert!(verify_explicit(&report, &path).is_err());
            assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn status_runs_against_fresh_identity_dir() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        invoke(["status".into()]).unwrap();
        let identity_dir = identity::default_identity_dir().unwrap();
        assert!(identity_dir.join(identity::SECRET_FILENAME).is_file());
        assert!(identity_dir.join(identity::PUBLIC_FILENAME).is_file());
    }

    #[test]
    fn cli_adapter_valid_explicit_trust_is_read_only_and_future_schema_refuses() {
        let (_producer, key, path) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        verify_explicit(&path, &key.public_path).unwrap();
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
        let report: AttestationReport =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut body: AttestationBody = serde_json::from_slice(&report.0.payload).unwrap();
        body.schema_version = SCHEMA_VERSION + 1;
        let report = sign_report(&body, &key.signing, &identity::identity_signer_id());
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        let error = verify_explicit(&path, &key.public_path).unwrap_err();
        assert!(format!("{error:#}").contains("schema"));
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn cli_adapter_trust_flags_remain_mutually_exclusive() {
        let (_producer, key, report) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let error = invoke([
            "verify".into(),
            report.as_os_str().into(),
            "--trust".into(),
            key.public_path.as_os_str().into(),
            "--trust-self".into(),
        ])
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<clap::Error>().unwrap().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn cli_adapter_nonregular_report_refuses_without_blocking_or_identity_effects() {
        let (producer, key, report) = signed_fixture();
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        std::fs::remove_file(&report).unwrap();
        std::fs::create_dir(&report).unwrap();
        assert!(verify_explicit(&report, &key.public_path).is_err());
        std::fs::remove_dir(&report).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&report)
                .status()
                .unwrap()
                .success()
        );
        assert!(verify_explicit(&report, &key.public_path).is_err());
        let alias = producer.path().join("report-link");
        std::os::unix::fs::symlink(&report, &alias).unwrap();
        assert!(verify_explicit(&alias, &key.public_path).is_err());
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }
}
