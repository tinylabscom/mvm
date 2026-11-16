//! Deployment records remain byte-stable when shared with runtime admission.

use mvm_core::deploy_record::{
    DeployRecord, DeployRecordError, digest_artifact, digest_boot_artifact, read_deploy_record,
    verify_boot_artifact, write_deploy_record,
};

const RECORD: &[u8] = include_bytes!("fixtures/deploy-record-v2.json");

#[test]
fn record_bytes_and_empty_artifact_digests_are_stable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deploy.json");
    std::fs::write(&path, RECORD).unwrap();
    let record = read_deploy_record(&path).unwrap();
    let output = dir.path().join("written/deploy.json");
    write_deploy_record(&record, &output).unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), RECORD);

    let artifact = dir.path().join("rootfs.ext4");
    std::fs::write(&artifact, b"").unwrap();
    assert_eq!(digest_artifact(&artifact).unwrap(), record.image);
    assert_eq!(
        digest_boot_artifact(&artifact).unwrap(),
        record.boot_artifact
    );
    verify_boot_artifact(&artifact, &record.boot_artifact).unwrap();
}

#[test]
fn absent_optional_fields_stay_absent() {
    let mut record: DeployRecord = serde_json::from_slice(RECORD).unwrap();
    record.environment = None;
    record.dependency_volume = None;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deploy.json");
    write_deploy_record(&record, &path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("environment").is_none());
    assert!(value.get("dependency_volume").is_none());
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert_eq!(read_deploy_record(&path).unwrap(), record);
}

#[test]
fn record_reader_refuses_unknown_schemas_and_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deploy.json");
    for version in [0, 1, 3, u32::MAX] {
        let mut record: serde_json::Value = serde_json::from_slice(RECORD).unwrap();
        record["schema_version"] = version.into();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            matches!(
                read_deploy_record(&path),
                Err(DeployRecordError::SchemaVersion { found, expected: 2, .. }) if found == version
            ),
            "schema version {version} must be refused"
        );
    }
    for pointer in [
        "",
        "/boot_artifact",
        "/image",
        "/environment",
        "/dependency_volume",
    ] {
        let mut record: serde_json::Value = serde_json::from_slice(RECORD).unwrap();
        record.pointer_mut(pointer).unwrap()["unexpected"] = true.into();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(
            matches!(
                read_deploy_record(&path),
                Err(DeployRecordError::Serialize(_))
            ),
            "unknown field at {pointer:?} must be refused"
        );
    }
    std::fs::write(&path, b"{").unwrap();
    assert!(matches!(
        read_deploy_record(&path),
        Err(DeployRecordError::Serialize(_))
    ));
    assert!(matches!(
        read_deploy_record(&dir.path().join("missing")),
        Err(DeployRecordError::Io(_))
    ));
}

#[test]
fn malformed_identities_are_refused_before_admission() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deploy.json");
    for field in ["blake3", "sha256"] {
        for invalid in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "z".repeat(64),
        ] {
            let mut record: serde_json::Value = serde_json::from_slice(RECORD).unwrap();
            record["boot_artifact"][field] = invalid.into();
            std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(matches!(
                read_deploy_record(&path),
                Err(DeployRecordError::BootArtifact { .. })
            ));
        }
    }
    let mut record: serde_json::Value = serde_json::from_slice(RECORD).unwrap();
    record["boot_artifact"]["kind"] = "image.tar.gz".into();
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(matches!(
        read_deploy_record(&path),
        Err(DeployRecordError::BootArtifact { .. })
    ));
}

#[test]
fn verification_rehashes_bytes_and_checks_every_identity_component() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rootfs.ext4");
    std::fs::write(&path, b"rootfs bytes").unwrap();
    let identity = digest_boot_artifact(&path).unwrap();
    verify_boot_artifact(&path, &identity).unwrap();

    for field in ["kind", "blake3", "sha256", "size_bytes"] {
        let mut wrong = identity.clone();
        match field {
            "kind" => wrong.kind = "image.tar.gz".into(),
            "blake3" => wrong.blake3 = "0".repeat(64),
            "sha256" => wrong.sha256 = "0".repeat(64),
            "size_bytes" => wrong.size_bytes += 1,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                verify_boot_artifact(&path, &wrong),
                Err(DeployRecordError::BootArtifact { .. })
            ),
            "changed {field} must be refused"
        );
    }
    // Same-length tampering cannot pass by retaining the recorded file size.
    std::fs::write(&path, b"ROOTFS bytes").unwrap();
    assert!(matches!(
        verify_boot_artifact(&path, &identity),
        Err(DeployRecordError::BootArtifact { .. })
    ));
    assert!(matches!(
        verify_boot_artifact(&dir.path().join("missing"), &identity),
        Err(DeployRecordError::Io(_))
    ));
}
