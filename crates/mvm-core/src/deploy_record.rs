//! Host-side deploy-record storage and exact-byte boot verification.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::Digest as _;

pub use mvm_contract::deploy_record::{
    ArtifactDigests, BootArtifactIdentity, DEPLOY_RECORD_SCHEMA_VERSION, DependencyVolumeRecord,
    DeployRecord, EnvironmentPin,
};

/// Failures reading, writing, or verifying a local deploy record.
#[derive(Debug, thiserror::Error)]
pub enum DeployRecordError {
    #[error("deploy io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serializing mvmd-spec.json: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("deploy record {} has schema version {found}, expected {expected}", path.display())]
    SchemaVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
    #[error("boot artifact {} is not attested: {reason}", path.display())]
    BootArtifact { path: PathBuf, reason: String },
}

/// Compute both identity digests of a sealed archive using one streaming read.
pub fn digest_artifact(path: &Path) -> Result<ArtifactDigests, DeployRecordError> {
    let mut file = std::fs::File::open(path)?;
    let mut blake3 = blake3::Hasher::new();
    let mut sha256 = sha2::Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        blake3.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
        size_bytes = size_bytes
            .checked_add(u64::try_from(read).expect("buffer length fits in u64"))
            .expect("artifact size must fit in u64");
    }
    Ok(ArtifactDigests {
        blake3: blake3.finalize().to_hex().to_string(),
        sha256: hex::encode(sha256.finalize()),
        size_bytes,
    })
}

/// Hash the exact filesystem image selected for the boot path.
pub fn digest_boot_artifact(path: &Path) -> Result<BootArtifactIdentity, DeployRecordError> {
    let digest = digest_artifact(path)?;
    Ok(BootArtifactIdentity {
        kind: "rootfs.ext4".to_string(),
        blake3: digest.blake3,
        sha256: digest.sha256,
        size_bytes: digest.size_bytes,
    })
}

/// Verify that a selected boot path still contains the bytes named by a
/// deploy record. This is intentionally a full rehash: path names and cached
/// metadata are not artifact identity.
pub fn verify_boot_artifact(
    path: &Path,
    expected: &BootArtifactIdentity,
) -> Result<(), DeployRecordError> {
    validate_boot_artifact_identity(path, expected)?;
    let actual = digest_boot_artifact(path)?;
    if actual != *expected {
        return Err(DeployRecordError::BootArtifact {
            path: path.to_path_buf(),
            reason: format!(
                "boot artifact identity mismatch for {}: expected {} / {}, got {} / {}",
                path.display(),
                expected.blake3,
                expected.sha256,
                actual.blake3,
                actual.sha256
            ),
        });
    }
    Ok(())
}

/// Write a deploy record as private, human-readable JSON.
pub fn write_deploy_record(record: &DeployRecord, path: &Path) -> Result<(), DeployRecordError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(record)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Read a deploy record and reject stale or future schemas before any of its
/// fields can influence admission.
pub fn read_deploy_record(path: &Path) -> Result<DeployRecord, DeployRecordError> {
    let record: DeployRecord = serde_json::from_slice(&std::fs::read(path)?)?;
    if record.schema_version != DEPLOY_RECORD_SCHEMA_VERSION {
        return Err(DeployRecordError::SchemaVersion {
            path: path.to_path_buf(),
            found: record.schema_version,
            expected: DEPLOY_RECORD_SCHEMA_VERSION,
        });
    }
    validate_boot_artifact_identity(path, &record.boot_artifact)?;
    Ok(record)
}

fn validate_boot_artifact_identity(
    path: &Path,
    identity: &BootArtifactIdentity,
) -> Result<(), DeployRecordError> {
    if identity.kind != "rootfs.ext4" {
        return Err(DeployRecordError::BootArtifact {
            path: path.to_path_buf(),
            reason: format!("unsupported boot artifact kind {:?}", identity.kind),
        });
    }
    for (label, value) in [("BLAKE3", &identity.blake3), ("SHA-256", &identity.sha256)] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DeployRecordError::BootArtifact {
                path: path.to_path_buf(),
                reason: format!("{label} must be 64 hexadecimal characters"),
            });
        }
    }
    Ok(())
}
