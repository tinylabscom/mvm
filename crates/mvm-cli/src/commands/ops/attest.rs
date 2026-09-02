//! `mvmctl attest` subcommand handlers.
//!
//! Two verbs:
//!
//! - `mvmctl attest export [--output FILE]`
//!   Generates a fresh attestation report signed by the host identity
//!   key (creating one if none exists) and writes JSON to `FILE` or
//!   stdout. The report carries the boot measurement, a fresh random
//!   nonce, the identity public key, and an optional hardware
//!   measurement when a feature-gated provider is wired in and
//!   answers `measure()` (v0 providers return `NotYetImplemented`, so
//!   v0 reports carry `hw_measurement: None`).
//!
//! - `mvmctl attest verify <REPORT> [--trust KEYFILE] [--trust-self]`
//!   Reads `REPORT` (file path), validates the Ed25519 signature
//!   against either an explicit `KEYFILE` (32-byte raw public key) or
//!   the host's own identity public key (`--trust-self`), and prints
//!   a one-line OK summary on success. Returns nonzero on signature,
//!   parse, or schema failure.
//!
//! The CLI surface is intentionally narrow — programmatic verifiers
//! (mvmd, customer auditors) consume `mvm_core::crypto::attestation`
//! directly. This module is the operator-facing path: "did this host
//! just sign a report I can show someone?"
//!
//! ## Why an explicit boot-measurement placeholder
//!
//! Boot attestation (via dm-verity root hash) is sequenced *after*
//! runtime identity in the current implementation order — the
//! identity-key plumbing
//! has to exist before there's anywhere to put the boot hash. v0 fills
//! `boot_measurement` with a deterministic placeholder string
//! (`PLACEHOLDER_BOOT_MEASUREMENT`) and warns the operator that the
//! real measurement pipeline is pending. The format stays stable
//! across the transition: future builds replace the placeholder with
//! the live dm-verity hash without changing the report schema.

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};
use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;

use mvm_core::crypto::attestation::{
    AttestationBody, AttestationReport, IdentityKey, identity, sign_report, verify_report,
};
use mvm_core::user_config::MvmConfig;

use super::Cli;

/// Placeholder boot measurement until the dm-verity root hash is
/// wired in. SHA-256-shaped (64 hex chars) so downstream
/// verifiers see a well-formed value and can detect-and-warn against
/// it the same way they would a stale measurement.
pub const PLACEHOLDER_BOOT_MEASUREMENT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
    let dir = identity::default_identity_dir().context("resolving identity dir")?;
    match args.action {
        AttestAction::Export { output } => export_at(&dir, output),
        AttestAction::Verify {
            report,
            trust,
            trust_self,
        } => verify_at(&dir, report, trust, trust_self),
        AttestAction::Status => status_at(&dir),
    }
}

fn export_at(identity_dir: &std::path::Path, output: Option<PathBuf>) -> Result<()> {
    let key = identity::load_or_init_at(identity_dir).context("loading host identity key")?;
    let report = build_report(&key);
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

fn verify_at(
    identity_dir: &std::path::Path,
    report_path: PathBuf,
    trust: Option<PathBuf>,
    _trust_self: bool,
) -> Result<()> {
    let bytes = std::fs::read(&report_path)
        .with_context(|| format!("reading {}", report_path.display()))?;
    let report: AttestationReport = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing {} as JSON attestation report",
            report_path.display()
        )
    })?;

    let signer_id = report.0.signer_id.clone();

    // Resolve the trusted key. `--trust FILE` and `--trust-self` are
    // mutually exclusive via Clap's `conflicts_with`. If neither is
    // set we default to self — this is the right behavior for the
    // "smoke-test my own host" path; programmatic verifiers (mvmd,
    // customer auditors) should always pass an explicit `--trust`
    // so a misconfigured host can't self-validate against a key it
    // also produced.
    let (trusted_key, source_label): (VerifyingKey, String) = if let Some(path) = trust {
        let pk = load_pubkey_file(&path)?;
        (pk, format!("file {}", path.display()))
    } else {
        let key = identity::load_or_init_at(identity_dir).context("loading host identity key")?;
        (key.verifying, "self".to_string())
    };

    let trusted = [(signer_id.as_str(), &trusted_key)];
    let body = verify_report(&report, &trusted).map_err(|e| anyhow::anyhow!("verify: {e}"))?;

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

fn status_at(identity_dir: &std::path::Path) -> Result<()> {
    let key = identity::load_or_init_at(identity_dir).context("loading host identity key")?;
    let pubkey_hex = hex_lower(&key.verifying.to_bytes());
    println!("identity.signer_id   = {}", identity::identity_signer_id());
    println!("identity.pubkey_hex  = {pubkey_hex}");
    println!("identity.secret_path = {}", key.secret_path.display());
    println!("identity.public_path = {}", key.public_path.display());
    println!();
    println!("hardware providers:");
    for kind in [
        mvm_core::crypto::attestation::HwProviderKind::Tpm2,
        mvm_core::crypto::attestation::HwProviderKind::SevSnp,
        mvm_core::crypto::attestation::HwProviderKind::Tdx,
        mvm_core::crypto::attestation::HwProviderKind::AppleDeviceAttestation,
    ] {
        let state = if kind.compiled_in() {
            "compiled (stub returns NotYetImplemented)"
        } else {
            "not compiled (rebuild with feature flag to enable)"
        };
        println!(
            "  {:<8} feature={:<22}  {state}",
            kind.as_str(),
            kind.cargo_feature()
        );
    }
    Ok(())
}

fn build_report(key: &IdentityKey) -> AttestationReport {
    let body = AttestationBody::new(PLACEHOLDER_BOOT_MEASUREMENT, &key.verifying, None);
    sign_report(&body, &key.signing, &identity::identity_signer_id())
}

fn load_pubkey_file(path: &std::path::Path) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() != mvm_core::crypto::attestation::KEY_BYTES {
        bail!(
            "{} is {} bytes; expected a {}-byte raw Ed25519 public key",
            path.display(),
            bytes.len(),
            mvm_core::crypto::attestation::KEY_BYTES
        );
    }
    let array: [u8; 32] = bytes.as_slice().try_into().expect("len-checked above");
    VerifyingKey::from_bytes(&array)
        .with_context(|| format!("parsing {} as Ed25519 public key", path.display()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::attestation::SCHEMA_VERSION;
    use rand::Rng;

    #[test]
    fn export_then_verify_self_round_trips_through_disk() {
        let identity_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let report_path = report_dir.path().join("report.json");

        export_at(identity_dir.path(), Some(report_path.clone())).expect("export");
        verify_at(identity_dir.path(), report_path.clone(), None, true)
            .expect("verify --trust-self");

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
        let identity_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let report_path = report_dir.path().join("report.json");
        export_at(identity_dir.path(), Some(report_path.clone())).expect("export");

        // Flip one byte inside the payload. The envelope sig must
        // refuse on verify.
        let bytes = std::fs::read(&report_path).unwrap();
        let mut report: AttestationReport = serde_json::from_slice(&bytes).unwrap();
        report.0.payload[0] ^= 0x01;
        std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();

        let err = verify_at(identity_dir.path(), report_path, None, true)
            .expect_err("must refuse tampered report");
        let msg = err.to_string();
        assert!(msg.contains("verify"), "error mentions verify: {msg}");
    }

    #[test]
    fn verify_fails_when_trust_file_is_wrong_key() {
        let identity_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let report_path = report_dir.path().join("report.json");
        export_at(identity_dir.path(), Some(report_path.clone())).expect("export");

        let other = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            ed25519_dalek::SigningKey::from_bytes(&__ed_seed)
        }
        .verifying_key();
        let trust_path = report_dir.path().join("trust.pub");
        std::fs::write(&trust_path, other.to_bytes()).unwrap();

        let err = verify_at(identity_dir.path(), report_path, Some(trust_path), false)
            .expect_err("must refuse with wrong trust key");
        let msg = err.to_string();
        assert!(msg.contains("verify"), "error mentions verify: {msg}");
    }

    #[test]
    fn load_pubkey_file_refuses_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pub");
        std::fs::write(&path, [0u8; 16]).unwrap();
        let err = load_pubkey_file(&path).expect_err("must refuse");
        assert!(err.to_string().contains("16 bytes"), "{err}");
    }

    #[test]
    fn status_runs_against_fresh_identity_dir() {
        // Smoke: status prints; we just assert it produces no error
        // when the identity is auto-initialised. Stdout content is
        // not asserted here — that's the operator-facing surface,
        // not a contract.
        let identity_dir = tempfile::tempdir().unwrap();
        status_at(identity_dir.path()).expect("status");
    }
}
