#![cfg(feature = "deploy")]

//! Authoring and execution use the same record types and preserve SDK errors.

use mvm_sdk::deploy::{self, DeployError};

const RECORD: &[u8] = include_bytes!("../../mvm-core/tests/fixtures/deploy-record-v2.json");

#[test]
fn authoring_and_execution_preserve_record_bytes_and_type_identity() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("deploy.json");
    std::fs::write(&source, RECORD).unwrap();
    let record: mvm_contract::deploy_record::DeployRecord =
        deploy::read_deploy_record(&source).unwrap();
    let sdk_output = dir.path().join("sdk.json");
    let core_output = dir.path().join("core.json");
    deploy::write_deploy_record(&record, &sdk_output).unwrap();
    mvm_core::deploy_record::write_deploy_record(&record, &core_output).unwrap();
    assert_eq!(std::fs::read(sdk_output).unwrap(), RECORD);
    assert_eq!(std::fs::read(core_output).unwrap(), RECORD);

    let rootfs = dir.path().join("rootfs.ext4");
    std::fs::write(&rootfs, b"").unwrap();
    let identity = deploy::digest_boot_artifact(&rootfs).unwrap();
    assert_eq!(identity, record.boot_artifact);
    mvm_core::deploy_record::verify_boot_artifact(&rootfs, &identity).unwrap();
    deploy::verify_boot_artifact(&rootfs, &identity).unwrap();
}

#[test]
fn sdk_preserves_public_error_variants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deploy.json");
    assert!(matches!(
        deploy::read_deploy_record(&path),
        Err(DeployError::Io(_))
    ));
    std::fs::write(&path, b"{").unwrap();
    assert!(matches!(
        deploy::read_deploy_record(&path),
        Err(DeployError::Serialize(_))
    ));
    let mut record: deploy::DeployRecord = serde_json::from_slice(RECORD).unwrap();
    record.schema_version = 1;
    deploy::write_deploy_record(&record, &path).unwrap();
    assert!(matches!(
        deploy::read_deploy_record(&path),
        Err(DeployError::SchemaVersion {
            found: 1,
            expected: 2,
            ..
        })
    ));
    record.schema_version = 2;
    record.boot_artifact.kind = "image.tar.gz".into();
    deploy::write_deploy_record(&record, &path).unwrap();
    assert!(matches!(
        deploy::read_deploy_record(&path),
        Err(DeployError::BootArtifact { .. })
    ));
}
