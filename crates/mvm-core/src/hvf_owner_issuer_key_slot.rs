//! Read-only observation of the fixed protected owner issuer seed slot.
//!
//! The seed is opened only beneath a validated [`ProtectedAuthorityRoot`],
//! validated as one exact object, and used locally to derive public evidence.
//! This module creates, repairs, signs, retries, and advances commissioning
//! state nothing.

use std::fs::{File, Metadata};
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::hvf_owner_commissioning_intent::{LoadedHvfOwnerCommissioningIntent, has_extended_acl};
use crate::hvf_owner_protected_authority_root::ProtectedAuthorityRoot;

/// Fixed descriptor-relative issuer seed child.
pub const OWNER_ISSUER_SEED_NAME: &str = "owner-issuer-ed25519.seed";

const SEED_BYTES: usize = 32;
const EVIDENCE_DOMAIN: &[u8] = b"mvm.hvf-owner.issuer-public-key-evidence.v1\0";

/// Public evidence derived from a strictly validated protected issuer seed.
///
/// The private seed, open file, signing key, and raw descriptor never leave the
/// observation call. Accessors return copies of the two public byte arrays.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct ObservedOwnerIssuerPublicKey {
    verifying_key: [u8; 32],
    evidence_digest: [u8; 32],
}

impl ObservedOwnerIssuerPublicKey {
    /// Ed25519 verifying key derived from the observed seed.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key
    }

    /// Domain-separated SHA-256 evidence digest of the verifying key.
    #[must_use]
    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }
}

/// Result of observing the fixed protected issuer seed child.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum OwnerIssuerKeySlotObservation {
    /// The exact fixed child was absent at the instant it was opened.
    Absent,
    /// The exact fixed child passed policy and yielded only public evidence.
    Present(ObservedOwnerIssuerPublicKey),
}

/// Refusal from observing the fixed protected issuer seed child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OwnerIssuerKeySlotError {
    /// The production observation contract is available only on macOS.
    #[error("protected HVF owner issuer seed observation requires macOS")]
    Unsupported,
    /// The fixed child or its metadata could not be observed exactly.
    #[error("protected HVF owner issuer seed is unavailable")]
    Unavailable,
    /// The fixed child violated the complete seed-object policy.
    #[error("protected HVF owner issuer seed filesystem policy failed")]
    FilesystemPolicy,
    /// The opened object changed during the bounded observation.
    #[error("protected HVF owner issuer seed changed while being observed")]
    Changed,
}

/// Observe public evidence for the fixed production issuer seed child.
///
/// `Absent` means only exact `ENOENT` from the descriptor-relative child open.
/// It establishes neither permission to create the slot nor namespace freshness.
///
/// # Errors
///
/// Refuses unsupported hosts, every non-absence open failure, policy mismatch,
/// read failure, and metadata or policy change during observation.
#[cfg(target_os = "macos")]
pub fn observe_owner_issuer_key_slot(
    root: &ProtectedAuthorityRoot,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
    observe_from_root(root, intent)
}

/// Unsupported platforms cannot establish the production observation contract.
///
/// # Errors
///
/// Always returns [`OwnerIssuerKeySlotError::Unsupported`] without filesystem
/// access or mutation.
#[cfg(not(target_os = "macos"))]
pub fn observe_owner_issuer_key_slot(
    _root: &ProtectedAuthorityRoot,
    _intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
    Err(OwnerIssuerKeySlotError::Unsupported)
}

/// Observe through an injected, validated authority root for hermetic tests.
///
/// # Errors
///
/// Refuses the same object-policy, exact-read, and change failures as production.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn observe_test_owner_issuer_key_slot(
    root: &ProtectedAuthorityRoot,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
    observe_from_root(root, intent)
}

fn observe_from_root(
    root: &ProtectedAuthorityRoot,
    intent: &LoadedHvfOwnerCommissioningIntent,
) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
    let file = match root.open_owner_issuer_seed() {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) => return Ok(OwnerIssuerKeySlotObservation::Absent),
        Err(_) => return Err(OwnerIssuerKeySlotError::Unavailable),
    };
    observe_open_file(file, intent, || {})
}

#[derive(Debug, PartialEq, Eq)]
struct SeedPolicySnapshot {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    links: u64,
    mode: u32,
    flags: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl SeedPolicySnapshot {
    fn capture(
        file: &File,
        intent: &LoadedHvfOwnerCommissioningIntent,
    ) -> Result<Self, OwnerIssuerKeySlotError> {
        let metadata = file
            .metadata()
            .map_err(|_| OwnerIssuerKeySlotError::Unavailable)?;
        let snapshot = Self::from_metadata(&metadata);
        if !metadata.is_file()
            || snapshot.uid != intent.authority_role().uid()
            || snapshot.gid != intent.authority_role().gid()
            || snapshot.mode & 0o7777 != 0o600
            || snapshot.links != 1
            || snapshot.length != SEED_BYTES as u64
            || snapshot.flags != 0
            || has_extended_acl(file).map_err(|_| OwnerIssuerKeySlotError::Unavailable)?
        {
            return Err(OwnerIssuerKeySlotError::FilesystemPolicy);
        }
        Ok(snapshot)
    }

    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.nlink(),
            mode: metadata.permissions().mode(),
            flags: metadata_flags(metadata),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn observe_open_file(
    file: File,
    intent: &LoadedHvfOwnerCommissioningIntent,
    after_read: impl FnOnce(),
) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
    observe_open_file_with_hooks(file, intent, || {}, after_read)
}

fn observe_open_file_with_hooks(
    mut file: File,
    intent: &LoadedHvfOwnerCommissioningIntent,
    before_extra_read: impl FnOnce(),
    after_read: impl FnOnce(),
) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
    let initial = SeedPolicySnapshot::capture(&file, intent)?;
    let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
    if let Err(error) = file.read_exact(seed.as_mut()) {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Err(OwnerIssuerKeySlotError::Changed)
        } else {
            Err(OwnerIssuerKeySlotError::Unavailable)
        };
    }
    before_extra_read();
    let mut extra = Zeroizing::new([0_u8; 1]);
    match file.read(extra.as_mut()) {
        Ok(0) => {}
        Ok(_) => return Err(OwnerIssuerKeySlotError::Changed),
        Err(_) => return Err(OwnerIssuerKeySlotError::Unavailable),
    }

    after_read();
    let final_snapshot =
        SeedPolicySnapshot::capture(&file, intent).map_err(|error| match error {
            OwnerIssuerKeySlotError::FilesystemPolicy => OwnerIssuerKeySlotError::Changed,
            other => other,
        })?;
    if final_snapshot != initial {
        return Err(OwnerIssuerKeySlotError::Changed);
    }

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let evidence_digest = Sha256::new()
        .chain_update(EVIDENCE_DOMAIN)
        .chain_update(verifying_key)
        .finalize()
        .into();
    Ok(OwnerIssuerKeySlotObservation::Present(
        ObservedOwnerIssuerPublicKey {
            verifying_key,
            evidence_digest,
        },
    ))
}

#[cfg(target_os = "macos")]
fn metadata_flags(metadata: &Metadata) -> u32 {
    use std::os::macos::fs::MetadataExt as _;

    metadata.st_flags()
}

#[cfg(not(target_os = "macos"))]
fn metadata_flags(_metadata: &Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use serde_json::json;

    use super::*;
    use crate::hvf_owner_commissioning_intent::load_test_hvf_owner_commissioning_intent;
    use crate::hvf_owner_deployment_receipt::{OwnerComponentPinV1, cohort_digest};
    use crate::hvf_owner_protected_authority_root::validate_test_protected_authority_root;

    const RFC_8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC_8032_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    // Independently computed as SHA-256(domain || RFC_8032_PUBLIC_KEY).
    const RFC_8032_EVIDENCE: [u8; 32] = [
        0xb1, 0x75, 0x95, 0x84, 0x9b, 0xbf, 0xe8, 0x69, 0x4d, 0x8f, 0x72, 0xaa, 0x34, 0x48, 0xf8,
        0x6b, 0x53, 0x38, 0x3e, 0xa6, 0x9c, 0xb2, 0x7d, 0x44, 0x4d, 0x4d, 0xab, 0x72, 0x10, 0xf7,
        0xcf, 0xd1,
    ];

    struct Fixture {
        root: tempfile::TempDir,
        installer_uid: u32,
        installer_gid: u32,
        authority_uid: u32,
        authority_gid: u32,
        intent: LoadedHvfOwnerCommissioningIntent,
        authority: ProtectedAuthorityRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create protected root");
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                .expect("set root mode");
            let metadata = fs::metadata(root.path()).expect("root metadata");
            let installer_uid = metadata.uid();
            let installer_gid = metadata.gid();
            let authority_uid = installer_uid;
            let authority_gid = installer_gid;
            let deployment = root.path().join("mvm");
            fs::create_dir(&deployment).expect("create deployment");
            fs::set_permissions(&deployment, fs::Permissions::from_mode(0o755))
                .expect("set deployment mode");
            let authority_path = deployment.join("authority");
            fs::create_dir(&authority_path).expect("create authority");
            fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o700))
                .expect("set authority mode");
            write_intent(&deployment, authority_uid, authority_gid);
            let intent = load_test_hvf_owner_commissioning_intent(
                File::open(root.path()).expect("open db root"),
                installer_uid,
                installer_gid,
            )
            .expect("load intent");
            let authority = validate_test_protected_authority_root(
                &intent,
                File::open(root.path()).expect("open db root"),
                installer_uid,
                installer_gid,
            )
            .expect("validate authority");
            Self {
                root,
                installer_uid,
                installer_gid,
                authority_uid,
                authority_gid,
                intent,
                authority,
            }
        }

        fn deployment_path(&self) -> PathBuf {
            self.root.path().join("mvm")
        }

        fn authority_path(&self) -> PathBuf {
            self.deployment_path().join("authority")
        }

        fn seed_path(&self) -> PathBuf {
            self.authority_path().join(OWNER_ISSUER_SEED_NAME)
        }

        fn write_seed(&self, bytes: &[u8]) {
            fs::write(self.seed_path(), bytes).expect("write seed fixture");
            fs::set_permissions(self.seed_path(), fs::Permissions::from_mode(0o600))
                .expect("set seed mode");
        }

        fn observe(&self) -> Result<OwnerIssuerKeySlotObservation, OwnerIssuerKeySlotError> {
            observe_test_owner_issuer_key_slot(&self.authority, &self.intent)
        }

        fn mismatched_intent(
            &self,
            authority_uid: u32,
            authority_gid: u32,
        ) -> LoadedHvfOwnerCommissioningIntent {
            let intent_path = self
                .deployment_path()
                .join("owner-commissioning-intent.json");
            fs::remove_file(intent_path).expect("remove original intent");
            write_intent(&self.deployment_path(), authority_uid, authority_gid);
            load_test_hvf_owner_commissioning_intent(
                File::open(self.root.path()).expect("open db root"),
                self.installer_uid,
                self.installer_gid,
            )
            .expect("load mismatched intent")
        }
    }

    fn write_intent(deployment: &Path, authority_uid: u32, authority_gid: u32) {
        let component = OwnerComponentPinV1 {
            schema_version: 1,
            component: "mvm-hvf-run-owner".into(),
            sha256: "a".repeat(64),
            version: "0.28.0-rc.11".into(),
            target: "aarch64-apple-darwin".into(),
            source_commit: "b".repeat(40),
            bootstrap_protocol_version: 1,
        };
        let digest = cohort_digest(&component);
        let intent = json!({
            "schema_version": 1,
            "deployment_id": "production-issuer-slot",
            "deployment_epoch": 7,
            "protected_roles": {
                "authority": {
                    "uid": authority_uid,
                    "gid": authority_gid,
                    "executable": "/Library/PrivilegedHelperTools/mvm-authority",
                    "designated_requirement":
                        "identifier \"dev.mvm.authority\" and anchor apple generic"
                },
                "runtime": {
                    "uid": authority_uid.checked_add(1).expect("test uid has room"),
                    "gid": authority_gid.checked_add(1).expect("test gid has room"),
                    "executable": "/Library/PrivilegedHelperTools/mvm-hvf-run-owner",
                    "designated_requirement":
                        "identifier \"dev.mvm.owner\" and anchor apple generic"
                }
            },
            "approved_owner_code_cohort": {
                "digest": digest,
                "owner_component": component
            }
        });
        let path = deployment.join("owner-commissioning-intent.json");
        fs::write(
            &path,
            serde_json::to_vec(&intent).expect("serialize intent"),
        )
        .expect("write intent");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("set intent mode");
    }

    fn present(observation: OwnerIssuerKeySlotObservation) -> ObservedOwnerIssuerPublicKey {
        match observation {
            OwnerIssuerKeySlotObservation::Present(observed) => observed,
            OwnerIssuerKeySlotObservation::Absent => panic!("expected present issuer slot"),
        }
    }

    #[test]
    fn absence_does_not_create_or_change_the_authority_directory() {
        let fixture = Fixture::new();
        let before = directory_snapshot(&fixture.authority_path());
        assert_eq!(
            fixture.observe().expect("observe absent slot"),
            OwnerIssuerKeySlotObservation::Absent
        );
        assert_eq!(directory_snapshot(&fixture.authority_path()), before);
        assert!(
            !fixture.seed_path().exists(),
            "absence must not create seed"
        );
    }

    #[test]
    fn derives_only_known_public_bytes_and_independent_evidence() {
        let fixture = Fixture::new();
        fixture.write_seed(&RFC_8032_SEED);
        let before = object_snapshot(&fixture.seed_path());
        let observed = present(fixture.observe().expect("observe known seed"));
        assert_eq!(observed.verifying_key_bytes(), RFC_8032_PUBLIC_KEY);
        assert_eq!(observed.evidence_digest(), RFC_8032_EVIDENCE);
        assert_eq!(object_snapshot(&fixture.seed_path()), before);

        let _: fn(&ObservedOwnerIssuerPublicKey) -> [u8; 32] =
            ObservedOwnerIssuerPublicKey::verifying_key_bytes;
        let _: fn(&ObservedOwnerIssuerPublicKey) -> [u8; 32] =
            ObservedOwnerIssuerPublicKey::evidence_digest;
    }

    #[test]
    fn refuses_symlink_directory_fifo_and_hardlink() {
        let fixture = Fixture::new();
        let target = fixture.authority_path().join("elsewhere");
        fs::write(&target, RFC_8032_SEED).expect("write symlink target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("set target mode");
        symlink(&target, fixture.seed_path()).expect("create seed symlink");
        assert!(fixture.observe().is_err(), "symlink must be refused");
        fs::remove_file(fixture.seed_path()).expect("remove symlink");

        fs::create_dir(fixture.seed_path()).expect("create seed directory");
        fs::set_permissions(fixture.seed_path(), fs::Permissions::from_mode(0o600))
            .expect("set directory mode");
        assert_eq!(
            fixture.observe(),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );
        fs::remove_dir(fixture.seed_path()).expect("remove seed directory");

        let status = std::process::Command::new("mkfifo")
            .arg(fixture.seed_path())
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo fixture must succeed");
        fs::set_permissions(fixture.seed_path(), fs::Permissions::from_mode(0o600))
            .expect("set fifo mode");
        assert_eq!(
            fixture.observe(),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );
        fs::remove_file(fixture.seed_path()).expect("remove fifo");

        fixture.write_seed(&RFC_8032_SEED);
        fs::hard_link(fixture.seed_path(), fixture.authority_path().join("alias"))
            .expect("create hardlink");
        assert_eq!(
            fixture.observe(),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );
    }

    #[test]
    fn refuses_wrong_uid_gid_modes_and_special_bits() {
        let fixture = Fixture::new();
        fixture.write_seed(&RFC_8032_SEED);
        let wrong_uid = fixture.mismatched_intent(
            fixture.authority_uid.checked_add(1).expect("uid has room"),
            fixture.authority_gid,
        );
        let file = File::open(fixture.seed_path()).expect("open seed");
        assert_eq!(
            observe_open_file(file, &wrong_uid, || {}),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );

        let wrong_gid = fixture.mismatched_intent(
            fixture.authority_uid,
            fixture.authority_gid.checked_add(1).expect("gid has room"),
        );
        let file = File::open(fixture.seed_path()).expect("open seed");
        assert_eq!(
            observe_open_file(file, &wrong_gid, || {}),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );

        for mode in [
            0o000, 0o400, 0o640, 0o660, 0o644, 0o700, 0o1600, 0o2600, 0o4600,
        ] {
            fs::set_permissions(fixture.seed_path(), fs::Permissions::from_mode(mode))
                .expect("set invalid seed mode");
            assert!(fixture.observe().is_err(), "mode {mode:o} must be refused");
        }
    }

    #[test]
    fn refuses_short_long_and_zero_length_objects() {
        for length in [0, 1, 31, 33, 64] {
            let fixture = Fixture::new();
            fixture.write_seed(&vec![7_u8; length]);
            assert_eq!(
                fixture.observe(),
                Err(OwnerIssuerKeySlotError::FilesystemPolicy),
                "length {length} must be refused"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_extended_acl_and_every_nonzero_bsd_flag() {
        let fixture = Fixture::new();
        fixture.write_seed(&RFC_8032_SEED);
        let status = std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(fixture.seed_path())
            .status()
            .expect("run chmod ACL fixture");
        assert!(status.success(), "chmod must install ACL fixture");
        assert_eq!(
            fixture.observe(),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );

        let clean = Fixture::new();
        clean.write_seed(&RFC_8032_SEED);
        let status = std::process::Command::new("chflags")
            .arg("hidden")
            .arg(clean.seed_path())
            .status()
            .expect("run chflags fixture");
        assert!(status.success(), "chflags must install BSD flag fixture");
        assert_ne!(
            metadata_flags(&fs::metadata(clean.seed_path()).expect("flagged metadata")),
            0,
            "fixture must carry a BSD flag"
        );
        assert_eq!(
            clean.observe(),
            Err(OwnerIssuerKeySlotError::FilesystemPolicy)
        );
    }

    #[test]
    fn detects_growth_and_retains_open_object_across_path_substitution() {
        let fixture = Fixture::new();
        fixture.write_seed(&RFC_8032_SEED);
        let seed_path = fixture.seed_path();

        let file = File::open(&seed_path).expect("open seed for same-length mutation");
        let overwrite_path = seed_path.clone();
        assert_eq!(
            observe_open_file(file, &fixture.intent, || {
                fs::write(overwrite_path, [7_u8; 32]).expect("overwrite seed in place");
            }),
            Err(OwnerIssuerKeySlotError::Changed)
        );

        fixture.write_seed(&RFC_8032_SEED);
        let file = File::open(&seed_path).expect("open seed for EOF growth");
        let growth_before_eof = seed_path.clone();
        assert_eq!(
            observe_open_file_with_hooks(
                file,
                &fixture.intent,
                || {
                    use std::io::Write as _;

                    let mut growing = fs::OpenOptions::new()
                        .append(true)
                        .open(growth_before_eof)
                        .expect("open seed for EOF growth");
                    growing.write_all(&[0]).expect("grow seed before EOF probe");
                },
                || {},
            ),
            Err(OwnerIssuerKeySlotError::Changed)
        );

        fixture.write_seed(&RFC_8032_SEED);
        let file = File::open(&seed_path).expect("open seed");
        let growth_path = seed_path.clone();
        assert_eq!(
            observe_open_file(file, &fixture.intent, || {
                use std::io::Write as _;

                let mut growing = fs::OpenOptions::new()
                    .append(true)
                    .open(growth_path)
                    .expect("open seed for growth");
                growing.write_all(&[0]).expect("grow seed");
            }),
            Err(OwnerIssuerKeySlotError::Changed)
        );

        fixture.write_seed(&RFC_8032_SEED);
        let file = File::open(&seed_path).expect("open retained seed");
        let replacement_path = seed_path.clone();
        let result = observe_open_file(file, &fixture.intent, || {
            fs::rename(&replacement_path, fixture.authority_path().join("old-seed"))
                .expect("retain old seed");
            fs::write(&replacement_path, [0_u8; 32]).expect("write replacement seed");
            fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600))
                .expect("set replacement mode");
        });
        match result {
            Ok(OwnerIssuerKeySlotObservation::Present(observed)) => {
                assert_eq!(observed.verifying_key_bytes(), RFC_8032_PUBLIC_KEY);
            }
            Err(OwnerIssuerKeySlotError::Changed) => {}
            Ok(OwnerIssuerKeySlotObservation::Absent) => {
                panic!("retained descriptor cannot become absent")
            }
            Err(error) => panic!("unexpected retained-descriptor refusal: {error:?}"),
        }
    }

    #[test]
    fn observation_never_mutates_seed_or_siblings() {
        let fixture = Fixture::new();
        fixture.write_seed(&RFC_8032_SEED);
        let sibling = fixture.authority_path().join("unrelated");
        fs::write(&sibling, b"retain").expect("write sibling");
        let before_directory = directory_snapshot(&fixture.authority_path());
        let before_seed = object_snapshot(&fixture.seed_path());
        let _ = fixture.observe().expect("observe seed");
        assert_eq!(object_snapshot(&fixture.seed_path()), before_seed);
        assert_eq!(
            directory_snapshot(&fixture.authority_path()),
            before_directory
        );
        assert_eq!(fs::read(sibling).expect("read sibling"), b"retain");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn production_observer_refuses_unsupported_platform() {
        let fixture = Fixture::new();
        assert_eq!(
            observe_owner_issuer_key_slot(&fixture.authority, &fixture.intent),
            Err(OwnerIssuerKeySlotError::Unsupported)
        );
    }

    fn object_snapshot(path: &Path) -> (Vec<u8>, u64, u32, u64, u64, u64) {
        let metadata = fs::metadata(path).expect("object metadata");
        (
            fs::read(path).expect("object bytes"),
            metadata.len(),
            metadata.mode(),
            metadata.nlink(),
            metadata.dev(),
            metadata.ino(),
        )
    }

    fn directory_snapshot(path: &Path) -> Vec<(String, u64, u32, u64)> {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read authority directory")
            .map(|entry| {
                let entry = entry.expect("read directory entry");
                let metadata = fs::symlink_metadata(entry.path()).expect("entry metadata");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    metadata.len(),
                    metadata.mode(),
                    metadata.nlink(),
                )
            })
            .collect();
        entries.sort_unstable();
        entries
    }
}
