//! Host-identity attestation operations. v0 reports contain a zero boot
//! measurement and no hardware measurement; a valid signature is not evidence
//! of a measured boot. No operation accepts caller-authored signing bytes.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ed25519_dalek::VerifyingKey;
pub use mvm_core::crypto::attestation::{AttestationBody, AttestationReport};
use mvm_core::crypto::attestation::{HwProviderKind, identity, sign_report, verify_report};

/// The existing v0 sentinel, not a measured boot hash.
pub const PLACEHOLDER_BOOT_MEASUREMENT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Maximum serialized report size accepted by verification.
pub const MAX_REPORT_BYTES: usize = 1024 * 1024;

/// Trust is explicit; the report's embedded key never establishes trust.
#[derive(Debug, Clone)]
pub enum Trust {
    SelfIdentity,
    PublicKeyFile(PathBuf),
}

/// Authenticated public report contents and the selected trust source.
#[derive(Debug)]
pub struct VerifiedAttestation {
    pub signer_id: String,
    pub body: AttestationBody,
    pub trust: Trust,
}

/// Public identity metadata. Paths describe storage, not signing authority.
#[derive(Debug)]
pub struct AttestationStatus {
    pub signer_id: String,
    pub pubkey_hex: String,
    pub secret_path: PathBuf,
    pub public_path: PathBuf,
    pub providers: Vec<ProviderStatus>,
}

#[derive(Debug)]
pub struct ProviderStatus {
    pub name: &'static str,
    pub feature: &'static str,
    pub compiled: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("{0:#}")]
pub struct AttestationError(#[from] anyhow::Error);

type Result<T> = std::result::Result<T, AttestationError>;

/// Produce a fresh, host-signed v0 report, initializing identity if needed.
pub fn export() -> Result<AttestationReport> {
    export_at(&identity::default_identity_dir().map_err(AttestationError::from)?)
        .map_err(Into::into)
}

/// Verify a bounded regular-file report. Explicit trust does not resolve,
/// create, or load the local identity, even on a host without an identity.
pub fn verify(report_path: &Path, trust: Trust) -> Result<VerifiedAttestation> {
    verify_with(report_path, trust, identity::default_identity_dir).map_err(Into::into)
}

/// Return public identity metadata, initializing identity if needed.
pub fn status() -> Result<AttestationStatus> {
    status_at(&identity::default_identity_dir().map_err(AttestationError::from)?)
        .map_err(Into::into)
}

fn export_at(dir: &Path) -> anyhow::Result<AttestationReport> {
    let key = identity::load_or_init_at(dir).context("loading host identity key")?;
    let body = AttestationBody::new(PLACEHOLDER_BOOT_MEASUREMENT, &key.verifying, None);
    Ok(sign_report(
        &body,
        &key.signing,
        &identity::identity_signer_id(),
    ))
}

fn verify_with(
    report_path: &Path,
    trust: Trust,
    identity_dir: impl FnOnce() -> anyhow::Result<PathBuf>,
) -> anyhow::Result<VerifiedAttestation> {
    let bytes = read_regular(report_path, MAX_REPORT_BYTES)?;
    let report: AttestationReport = serde_json::from_slice(&bytes).map_err(|error| {
        // Serde type errors can quote file contents. A mistaken input must
        // not copy potentially sensitive bytes into logs or SDK errors.
        anyhow::anyhow!(
            "invalid JSON attestation report at line {}, column {}",
            error.line(),
            error.column()
        )
    })?;
    let signer_id = report.0.signer_id.clone();
    let trusted_key = match &trust {
        Trust::PublicKeyFile(path) => load_pubkey_file(path)?,
        Trust::SelfIdentity => {
            identity::load_or_init_at(&identity_dir()?)
                .context("loading host identity key")?
                .verifying
        }
    };
    let trusted = [(signer_id.as_str(), &trusted_key)];
    let body = verify_report(&report, &trusted).map_err(|error| match error {
        // Parse errors can contain authenticated payload bytes. Drop the raw
        // error rather than retaining it as the source of a sanitized context.
        mvm_core::crypto::attestation::AttestationError::Parse(_) => {
            anyhow::anyhow!("verify: malformed attestation report body")
        }
        other => anyhow::anyhow!("verify: {other}"),
    })?;
    Ok(VerifiedAttestation {
        signer_id,
        body,
        trust,
    })
}

fn status_at(dir: &Path) -> anyhow::Result<AttestationStatus> {
    let key = identity::load_or_init_at(dir).context("loading host identity key")?;
    let kind = HwProviderKind::Tpm2;
    Ok(AttestationStatus {
        signer_id: identity::identity_signer_id(),
        pubkey_hex: hex::encode(key.verifying.to_bytes()),
        secret_path: key.secret_path,
        public_path: key.public_path,
        providers: vec![ProviderStatus {
            name: kind.as_str(),
            feature: kind.cargo_feature(),
            compiled: kind.compiled_in(),
        }],
    })
}

fn load_pubkey_file(path: &Path) -> anyhow::Result<VerifyingKey> {
    let bytes = read_regular(path, mvm_core::crypto::attestation::KEY_BYTES)?;
    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "{} is {} bytes; expected a 32-byte raw Ed25519 public key",
            path.display(),
            bytes.len()
        )
    })?;
    VerifyingKey::from_bytes(&array)
        .with_context(|| format!("parsing {} as Ed25519 public key", path.display()))
}

fn read_regular(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let before =
        std::fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if !before.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let file = options
        .open(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if metadata.len() > limit as u64 {
        bail!("{} exceeds {limit} byte limit", path.display());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("{} exceeds {limit} byte limit", path.display());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::attestation::SCHEMA_VERSION;

    fn write_report(dir: &Path, identity_dir: &Path) -> PathBuf {
        let path = dir.join("report.json");
        let report = export_at(identity_dir).unwrap();
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        path
    }

    #[test]
    fn export_then_verify_self_round_trips_through_disk() {
        let identity_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let path = write_report(report_dir.path(), identity_dir.path());
        let verified = verify_with(&path, Trust::SelfIdentity, || {
            Ok(identity_dir.path().into())
        })
        .unwrap();
        assert_eq!(verified.body.schema_version, SCHEMA_VERSION);
        assert_eq!(verified.body.boot_measurement, PLACEHOLDER_BOOT_MEASUREMENT);
        assert!(
            verified.body.hw_measurement.is_none(),
            "v0 emits no hw measurement"
        );
    }

    #[test]
    fn verify_fails_on_tampered_payload() {
        let identity_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let path = write_report(report_dir.path(), identity_dir.path());
        let mut report: AttestationReport =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        report.0.payload[0] ^= 0x01;
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        let err = verify_with(&path, Trust::SelfIdentity, || {
            Ok(identity_dir.path().into())
        })
        .unwrap_err();
        assert!(err.to_string().contains("verify"), "{err}");
    }

    #[test]
    fn explicit_trust_never_resolves_or_initializes_identity() {
        let identity_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let path = write_report(report_dir.path(), identity_dir.path());
        let public = identity_dir.path().join(identity::PUBLIC_FILENAME);
        let result = verify_with(&path, Trust::PublicKeyFile(public), || {
            panic!("explicit trust must not resolve local identity")
        })
        .unwrap();
        assert_eq!(result.body.boot_measurement, PLACEHOLDER_BOOT_MEASUREMENT);
    }

    #[test]
    fn verify_fails_when_trust_file_is_wrong_key() {
        let identity_dir = tempfile::tempdir().unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let report_dir = tempfile::tempdir().unwrap();
        let path = write_report(report_dir.path(), identity_dir.path());
        status_at(other_dir.path()).unwrap();
        let err = verify_with(
            &path,
            Trust::PublicKeyFile(other_dir.path().join(identity::PUBLIC_FILENAME)),
            || panic!("explicit trust must not load identity"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("verify"), "{err}");
    }

    #[test]
    fn load_pubkey_file_refuses_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pub");
        std::fs::write(&path, [0u8; 16]).unwrap();
        let err = load_pubkey_file(&path).unwrap_err();
        assert!(err.to_string().contains("16 bytes"), "{err}");
        std::fs::write(&path, [0u8; 33]).unwrap();
        assert!(load_pubkey_file(&path).is_err());
    }

    #[test]
    fn status_runs_against_fresh_identity_dir() {
        let dir = tempfile::tempdir().unwrap();
        let status = status_at(dir.path()).unwrap();
        assert!(status.signer_id.starts_with("attest:"));
        assert_eq!(status.pubkey_hex.len(), 64);
        assert!(status.secret_path.exists());
        assert!(status.public_path.exists());
        assert_eq!(status_at(dir.path()).unwrap().pubkey_hex, status.pubkey_hex);
    }

    #[test]
    fn fresh_reports_have_distinct_nonces_and_stable_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first = export_at(dir.path()).unwrap();
        let second = export_at(dir.path()).unwrap();
        let first: AttestationBody = serde_json::from_slice(&first.0.payload).unwrap();
        let second: AttestationBody = serde_json::from_slice(&second.0.payload).unwrap();
        assert_eq!(first.identity_pubkey_hex, second.identity_pubkey_hex);
        assert_ne!(first.nonce_hex, second.nonce_hex);
        assert!(first.hw_measurement.is_none());
        assert!(second.hw_measurement.is_none());
    }

    #[test]
    fn malformed_report_and_future_schema_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(
            verify_with(&path, Trust::SelfIdentity, || panic!(
                "parse must fail first"
            ))
            .is_err()
        );
        let key = identity::load_or_init_at(&dir.path().join("identity")).unwrap();
        let mut body = AttestationBody::new(PLACEHOLDER_BOOT_MEASUREMENT, &key.verifying, None);
        body.schema_version = SCHEMA_VERSION + 1;
        let report = sign_report(&body, &key.signing, &identity::identity_signer_id());
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        let err = verify_with(&path, Trust::PublicKeyFile(key.public_path), || {
            panic!("explicit trust must not resolve local identity")
        })
        .unwrap_err();
        assert!(err.to_string().contains("verify"), "{err}");
    }

    #[test]
    fn malformed_report_diagnostics_do_not_echo_input_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let marker = "private-input-must-not-be-logged";
        std::fs::write(&path, serde_json::to_vec(marker).unwrap()).unwrap();
        let error = verify_with(&path, Trust::SelfIdentity, || {
            panic!("malformed input must not resolve local identity")
        })
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("invalid JSON attestation report"));
        assert!(!diagnostic.contains(marker), "{diagnostic}");
    }

    #[test]
    fn authenticated_inner_parse_diagnostics_do_not_echo_payload() {
        use ed25519_dalek::Signer;
        use mvm_core::crypto::attestation::AttestationError as CoreError;

        let root = tempfile::tempdir().unwrap();
        let identity_dir = root.path().join("identity");
        let key = identity::load_or_init_at(&identity_dir).unwrap();
        let marker = "private-authenticated-body-must-not-be-logged";
        for field in ["schema_version", "hw_measurement"] {
            let mut report = export_at(&identity_dir).unwrap();
            let mut body: serde_json::Value = serde_json::from_slice(&report.0.payload).unwrap();
            body[field] = serde_json::json!(marker);
            report.0.payload = serde_json::to_vec(&body).unwrap();
            report.0.signature = key.signing.sign(&report.0.payload).to_bytes().to_vec();
            assert!(matches!(
                verify_report(&report, &[(report.0.signer_id.as_str(), &key.verifying)]),
                Err(CoreError::Parse(_))
            ));
            let path = root.path().join("report.json");
            std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
            let trust = Trust::PublicKeyFile(key.public_path.clone());
            let inner = verify_with(&path, trust.clone(), || {
                panic!("explicit trust must not resolve local identity")
            })
            .unwrap_err();
            let error = verify(&path, trust).unwrap_err();
            for diagnostic in [
                format!("{inner}"),
                format!("{inner:#}"),
                format!("{inner:?}"),
                format!("{inner:#?}"),
                format!("{error}"),
                format!("{error:#}"),
                format!("{error:?}"),
                format!("{error:#?}"),
            ] {
                assert!(!diagnostic.contains(marker), "{field}: {diagnostic}");
            }
            let mut source = std::error::Error::source(&error);
            while let Some(current) = source {
                assert!(!format!("{current} {current:?}").contains(marker));
                source = current.source();
            }
            let contextual = anyhow::Error::new(error).context("verifying attestation facade");
            assert!(!format!("{contextual:#} {contextual:#?}").contains(marker));
        }
    }

    #[test]
    fn bounded_regular_files_only() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_regular(dir.path(), MAX_REPORT_BYTES).is_err());
        let path = dir.path().join("large");
        std::fs::write(&path, vec![0; MAX_REPORT_BYTES + 1]).unwrap();
        assert!(
            verify_with(&path, Trust::SelfIdentity, || panic!(
                "read must fail first"
            ))
            .is_err()
        );
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_regular(&link, MAX_REPORT_BYTES).is_err());
            let fifo = dir.path().join("fifo");
            let status = std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(status.success());
            assert!(read_regular(&fifo, MAX_REPORT_BYTES).is_err());
        }
    }
}
