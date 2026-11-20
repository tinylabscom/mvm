//! Disconnected read-only seams from commissioned owner deployment state.
//!
//! This module opens no IPC endpoint, initializes no journal, and performs no
//! native operation. It does not connect the refusal-only owner executable to a
//! positive factory.

use std::path::Path;
use std::sync::Arc;

use mvm_core::hvf_owner_deployment_receipt::LoadedHvfOwnerDeploymentReceipt;
use mvm_vmm::host::hvf_stop::HvfControlRoots;

use crate::hvf_owner_grants::{OwnerGrantClock, OwnerGrantStore, OwnerGrantStoreError};

/// Derive the two typed native-control verifier roles without opening a connection.
#[must_use]
pub fn hvf_control_roots(receipt: &LoadedHvfOwnerDeploymentReceipt) -> HvfControlRoots {
    HvfControlRoots::new(
        receipt.native_control_root().to_owned(),
        receipt.provider_stop_root().to_owned(),
    )
}

/// Open receipt-matching commissioned journal state without creating a lock.
///
/// This binds provider identity only. Protected ancestry, provider-UID custody,
/// and stable lock-file naming remain deployment prerequisites. The returned
/// store can perform normal authorized journal mutations.
///
/// # Errors
/// Refuses missing/unsafe lock or journal objects and provider/state mismatch.
pub fn open_owner_grant_store(
    path: &Path,
    receipt: &LoadedHvfOwnerDeploymentReceipt,
    clock: Arc<dyn OwnerGrantClock>,
) -> Result<OwnerGrantStore, OwnerGrantStoreError> {
    OwnerGrantStore::attach_existing(path, receipt.provider_id(), clock)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;
    use mvm_core::crypto::hvf_owner_grant::provider_identity;
    use mvm_core::hvf_owner_deployment_receipt::{
        LoadedHvfOwnerDeploymentReceipt, load_test_hvf_owner_deployment_receipt,
    };
    use serde::Serialize;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::hvf_owner_grants::SystemOwnerGrantClock;

    const COHORT_DOMAIN: &[u8] = b"mvm.hvf-owner.code-cohort.v1\0";

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    #[derive(Serialize)]
    struct OwnerComponent<'a> {
        schema_version: u8,
        component: &'a str,
        sha256: &'a str,
        version: &'a str,
        target: &'a str,
        source_commit: &'a str,
        bootstrap_protocol_version: u8,
    }

    fn receipt() -> (tempfile::TempDir, LoadedHvfOwnerDeploymentReceipt) {
        let component = OwnerComponent {
            schema_version: 1,
            component: "mvm-hvf-run-owner",
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            version: "0.28.0-rc.11",
            target: "aarch64-apple-darwin",
            source_commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            bootstrap_protocol_version: 1,
        };
        let mut hasher = Sha256::new();
        hasher.update(COHORT_DOMAIN);
        hasher.update(serde_json::to_vec(&component).expect("serialize component"));
        let digest: [u8; 32] = hasher.finalize().into();
        let value = serde_json::json!({
            "schema_version": 1,
            "deployment_id": "test-deployment",
            "deployment_epoch": 9,
            "provider": {
                "issuer": "test-provider",
                "ed25519_public_key": key(1),
            },
            "control_roots": {
                "native_challenge_and_finalization_ed25519": key(2),
                "provider_stop_ed25519": key(3),
            },
            "protected_roles": {
                "authority": {
                    "uid": 501,
                    "gid": 501,
                    "executable": "/Library/PrivilegedHelperTools/mvm-authority",
                    "designated_requirement": "identifier \"dev.mvm.authority\"",
                },
                "runtime": {
                    "uid": 502,
                    "gid": 502,
                    "executable": "/Library/PrivilegedHelperTools/mvm-hvf-run-owner",
                    "designated_requirement": "identifier \"dev.mvm.owner\"",
                },
            },
            "approved_owner_code_cohort": {
                "digest": digest,
                "owner_component": component,
            },
        });
        let root = tempfile::tempdir().expect("create root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("protect root");
        let deployment = root.path().join("mvm");
        fs::create_dir(&deployment).expect("create deployment");
        fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
            .expect("set deployment mode");
        let path = deployment.join("deployment-receipt.json");
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("serialize receipt"),
        )
        .expect("write receipt");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set receipt mode");
        let metadata = fs::metadata(root.path()).expect("root metadata");
        let loaded = load_test_hvf_owner_deployment_receipt(
            File::open(root.path()).expect("open root"),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("load receipt");
        (root, loaded)
    }

    #[test]
    fn conversion_preserves_distinct_typed_roots_and_provider_identity() {
        let (_root, receipt) = receipt();
        let roots = hvf_control_roots(&receipt);
        assert_eq!(
            roots.challenge_and_finalization().to_bytes(),
            key(2),
            "native root"
        );
        assert_eq!(roots.stop().to_bytes(), key(3), "provider stop root");
        assert_eq!(
            receipt.provider_id(),
            provider_identity("test-provider", receipt.provider_key(), 9),
            "provider identity"
        );
    }

    #[test]
    fn journal_open_requires_existing_lock_and_never_repairs_it() {
        let (_root, receipt) = receipt();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner-grants.json");
        let clock: Arc<dyn OwnerGrantClock> = Arc::new(SystemOwnerGrantClock);
        OwnerGrantStore::initialize(&path, receipt.provider_id(), clock.clone()).unwrap();
        let before_bytes = fs::read(&path).unwrap();
        let before_mode = fs::metadata(&path).unwrap().mode();
        let opened = open_owner_grant_store(&path, &receipt, clock.clone()).unwrap();
        let cloned = opened.clone();
        assert_eq!(fs::read(&path).unwrap(), before_bytes);
        assert_eq!(fs::metadata(&path).unwrap().mode(), before_mode);

        let lock = path.with_extension("lock");
        fs::remove_file(&lock).unwrap();
        assert!(opened.disposition([1; 32]).is_err());
        assert!(cloned.disposition([1; 32]).is_err());
        assert!(open_owner_grant_store(&path, &receipt, clock.clone()).is_err());
        assert!(
            !lock.exists(),
            "open-only path must not recreate a missing lock"
        );

        let mismatched = directory.path().join("mismatched.json");
        OwnerGrantStore::initialize(&mismatched, [9; 32], clock.clone()).unwrap();
        let mut before: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        before.sort();
        let mismatched_bytes = fs::read(&mismatched).unwrap();
        assert!(open_owner_grant_store(&mismatched, &receipt, clock.clone()).is_err());
        let mut after: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        after.sort();
        assert_eq!(before, after);
        assert_eq!(fs::read(&mismatched).unwrap(), mismatched_bytes);

        let corrupt = directory.path().join("corrupt.json");
        OwnerGrantStore::initialize(&corrupt, receipt.provider_id(), clock.clone()).unwrap();
        fs::write(&corrupt, b"{").unwrap();
        assert!(open_owner_grant_store(&corrupt, &receipt, clock).is_err());
        assert!(corrupt.with_extension("lock").is_file());

        let missing = directory.path().join("missing.json");
        let missing_lock = missing.with_extension("lock");
        fs::write(&missing_lock, b"").unwrap();
        fs::set_permissions(&missing_lock, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            open_owner_grant_store(&missing, &receipt, Arc::new(SystemOwnerGrantClock)).is_err()
        );
        assert_eq!(fs::read(&missing_lock).unwrap(), b"");
        assert!(!missing.exists());
    }
}
