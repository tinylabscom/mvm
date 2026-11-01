//! Reusable local encrypted-volume lifecycle service.
//!
//! Composes the existing volume backend, encryption, registry, admission,
//! and attachment primitives behind one object-safe service so local
//! presentation surfaces never duplicate policy or cleanup logic.
//!
//! The canonical behavior preserved here:
//!
//! - **Encrypted at rest.** An mvm-managed block volume is an ext4 image
//!   sealed as authenticated ciphertext (`MVSE` whole-file AES-256-GCM); its
//!   data key is wrapped under a versioned local master KEK and bound to the
//!   ciphertext content hash, so a swapped or tampered archive is refused
//!   before decryption is attempted.
//! - **Typed attachments.** Guest mount paths are restricted to the mount
//!   allow-roots (`/mnt`, `/data`, `/work`); attachments default to
//!   read-only, and read-write is refused unless the admitted profile grants
//!   writable disk images (`standard`, `dev`, `permissive`; see
//!   [`crate::profile::ProfileGrants`]). Every managed volume is an ext4
//!   image the guest writes into, never a live host directory.
//! - **Exclusive leases.** A block volume attaches to at most one VM at a
//!   time; leases persist across restarts and roll back leak-free (RAII) on
//!   a failed launch. With [`dto::UnlockPolicy::JustInTime`] the service
//!   unlocks a locked volume under the launch's lifecycle lock and re-seals
//!   it after the final lease release.
//! - **Fail-closed resolution.** Missing, locked, changed, unencrypted,
//!   tampered, cross-scope, and unsupported attachments are refused before
//!   any VM boots; interrupted lifecycle transitions are recovered
//!   idempotently before every operation.
//!
//! No DTO, log line, error message, or audit field produced by this module
//! carries key material or plaintext volume bytes.

pub mod dto;
mod lease;
mod lifecycle;
mod service;
mod snapshot;
#[cfg(test)]
pub(crate) mod test_support;

pub use dto::{
    AccessMode, AdmittedProfile, AttachmentRecord, AttachmentRequest, AttachmentRequestBuilder,
    AttachmentSource, CreateBlockVolumeRequest, CreateBlockVolumeRequestBuilder, EncryptionState,
    HostSnapshotRecord, LaunchLeaseRequest, LaunchLeaseRequestBuilder, ReleaseOutcome,
    UnlockPolicy, VolumeRecord, VolumeSourceKind,
};
pub use lease::LaunchLease;
pub use mvm_runtime::image::RuntimeVolume;
pub use mvm_runtime::machine::persist::load_machine_spec;
pub use service::{
    DenyAllHostEncryptionProbe, HostEncryptionProbe, LaunchPreparation, LocalVolumeService,
    VolumeService, default_block_volume_root, probe_from_fn,
};

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    use mvm_runtime::vm::volume_registry::{
        LocalVolumeCatalog, LocalVolumeEncryption, LocalVolumeState,
    };

    use super::dto::*;
    use super::lease::AttachmentLeaseCatalog;
    use super::service::{LocalVolumeService, VolumeService};
    use super::test_support::{TEST_VOLUME_MIB, TestVolumeHome};
    use crate::profile::RunProfile;

    fn service() -> LocalVolumeService {
        super::test_support::service()
    }

    // --- storage policy for managed volume plaintext -------------------------

    use super::test_support::unverified_service;

    fn files_in(dir: &Path) -> Vec<PathBuf> {
        match fs::read_dir(dir) {
            Ok(entries) => entries.map(|e| e.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn append_byte(path: &Path, byte: u8) -> Vec<u8> {
        let mut image = fs::OpenOptions::new().write(true).open(path).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        image.write_all(&[byte]).unwrap();
        image.sync_all().unwrap();
        fs::read(path).unwrap()
    }

    fn jit_launch(owner: &str) -> LaunchLeaseRequest {
        LaunchLeaseRequest::builder(owner)
            .unwrap()
            .profile(RunProfile::Dev)
            .unlock(UnlockPolicy::JustInTime)
            .build()
    }

    #[test]
    fn create_refuses_default_and_custom_roots_without_verified_storage() {
        let home = TestVolumeHome::new();
        for custom in [false, true] {
            let mut builder = CreateBlockVolumeRequest::builder("work")
                .unwrap()
                .capacity_mib(TEST_VOLUME_MIB);
            let root = if custom {
                let root = home.path().join("custom");
                builder = builder.root(&root);
                root
            } else {
                super::lifecycle::default_mvm_volume_root()
            };
            let request = builder.build().unwrap();
            for svc in [LocalVolumeService::new(), unverified_service()] {
                let error = svc.create_block_volume(&request).unwrap_err();
                let message = format!("{error:#}");
                assert!(message.contains("not verified encrypted"), "{message}");
                assert!(
                    message
                        .contains(mvm_core::host_storage_encryption::ALLOW_UNVERIFIED_STORAGE_ENV),
                    "the refusal names the override: {message}"
                );
                assert!(LocalVolumeCatalog::load().unwrap().get("work").is_none());
                assert!(
                    !super::lifecycle::local_master_key_dir().exists(),
                    "no key minted"
                );
                assert!(files_in(&root.join("unlocked")).is_empty(), "no plaintext");
                assert!(
                    files_in(&root.join("encrypted")).is_empty(),
                    "no ciphertext"
                );
            }
        }
    }

    #[test]
    fn create_and_unlock_probe_the_private_plaintext_directory_of_a_custom_root() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::{Arc, Mutex};

        let home = TestVolumeHome::new();
        let root = home.path().join("custom");
        let unlocked = root.join("unlocked");
        fs::create_dir_all(&unlocked).unwrap();
        // Directories that already exist loosely are tightened before the probe.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&unlocked, fs::Permissions::from_mode(0o755)).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let observed = seen.clone();
        let svc =
            LocalVolumeService::with_host_encryption_probe(super::probe_from_fn(move |path| {
                assert_eq!(mode(path), 0o700, "probed only once private");
                observed.lock().unwrap().push(path.to_path_buf());
                Ok(())
            }));
        let request = CreateBlockVolumeRequest::builder("work")
            .unwrap()
            .capacity_mib(TEST_VOLUME_MIB)
            .root(&root)
            .build()
            .unwrap();
        svc.create_block_volume(&request).unwrap();
        svc.unlock_volume("work").unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![unlocked.clone(), unlocked]);
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&host_path("work")), 0o600);
    }

    #[test]
    fn unlock_on_unverified_storage_keeps_the_volume_locked_and_its_ciphertext_intact() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        let ciphertext = fs::read(ciphertext_path("work")).unwrap();
        for svc in [LocalVolumeService::new(), unverified_service()] {
            let error = svc.unlock_volume("work").unwrap_err();
            assert!(
                format!("{error:#}").contains("not verified encrypted"),
                "{error:#}"
            );
            assert_eq!(managed_state("work"), LocalVolumeState::Locked);
            assert!(!host_path("work").exists(), "no plaintext");
            assert!(!super::lifecycle::unlock_staging_path(&host_path("work")).exists());
            assert_eq!(fs::read(ciphertext_path("work")).unwrap(), ciphertext);
        }
    }

    #[test]
    fn attach_rechecks_storage_and_never_loses_writable_data() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        let bytes = append_byte(&host_path("work"), 0x7a);

        let error = unverified_service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadWrite))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("not verified encrypted"),
            "{error:#}"
        );
        assert!(service().list_attachments("vm-1").unwrap().is_empty());
        assert_eq!(fs::read(host_path("work")).unwrap(), bytes);

        // Sealing needs no probe: it writes only ciphertext. The data survives
        // the round trip.
        unverified_service().lock_volume("work").unwrap();
        service().unlock_volume("work").unwrap();
        assert_eq!(fs::read(host_path("work")).unwrap(), bytes);
    }

    #[test]
    fn attach_tightens_an_unlocked_image_another_user_could_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        fs::set_permissions(host_path("work"), fs::Permissions::from_mode(0o644)).unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        assert_eq!(mode(&host_path("work")), 0o600);
    }

    #[test]
    fn launch_rechecks_an_explicitly_unlocked_volume_before_leasing() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        let bytes = fs::read(host_path("work")).unwrap();
        for svc in [LocalVolumeService::new(), unverified_service()] {
            let error = svc.acquire_launch_lease(&dev_launch("vm-1")).unwrap_err();
            assert!(format!("{error:#}").contains("storage policy"), "{error:#}");
            assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
            assert_eq!(
                managed_state("work"),
                LocalVolumeState::Unlocked,
                "explicit unlock persists"
            );
            assert_eq!(fs::read(host_path("work")).unwrap(), bytes);
        }
    }

    #[test]
    fn a_just_in_time_failure_relocks_the_volumes_unlocked_before_it() {
        let home = TestVolumeHome::new();
        for name in ["first", "second"] {
            let request = CreateBlockVolumeRequest::builder(name)
                .unwrap()
                .capacity_mib(TEST_VOLUME_MIB)
                .root(home.path().join(name))
                .build()
                .unwrap();
            service().create_block_volume(&request).unwrap();
            service().unlock_volume(name).unwrap();
            service()
                .prepare_attachment(&attach(
                    "vm-1",
                    name,
                    &format!("/data/{name}"),
                    AccessMode::ReadOnly,
                ))
                .unwrap();
            service().lock_volume(name).unwrap();
        }
        let denied_root = home.path().join("second");
        let svc =
            LocalVolumeService::with_host_encryption_probe(super::probe_from_fn(move |path| {
                if path.starts_with(&denied_root) {
                    anyhow::bail!("synthetic failed backing probe");
                }
                Ok(())
            }));
        let error = svc.acquire_launch_lease(&jit_launch("vm-1")).unwrap_err();
        assert!(
            format!("{error:#}").contains("synthetic failed backing probe"),
            "{error:#}"
        );
        for name in ["first", "second"] {
            assert_eq!(managed_state(name), LocalVolumeState::Locked, "{name}");
            assert!(!host_path(name).exists(), "{name} has no plaintext left");
        }
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    #[test]
    fn release_recovery_and_sealing_need_no_probe() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadWrite))
            .unwrap();
        service().lock_volume("work").unwrap();
        let mut prepared = service().acquire_launch_lease(&jit_launch("vm-1")).unwrap();
        prepared.commit();
        drop(prepared);
        let bytes = append_byte(&host_path("work"), 0x5a);

        let denied = LocalVolumeService::new();
        let released = denied.release_owner_leases("vm-1").unwrap();
        assert_eq!(released.relocked, vec!["work"]);
        service().unlock_volume("work").unwrap();
        assert_eq!(fs::read(host_path("work")).unwrap(), bytes);

        // An interrupted seal recovers to the writable image without a probe.
        let mut catalog = LocalVolumeCatalog::load().unwrap();
        super::lifecycle::set_local_volume_state(&mut catalog, "work", LocalVolumeState::Locking)
            .unwrap();
        catalog.save().unwrap();
        denied.recover().unwrap();
        assert_eq!(managed_state("work"), LocalVolumeState::Unlocked);
        assert_eq!(fs::read(host_path("work")).unwrap(), bytes);
    }

    #[test]
    fn sealing_leaves_nothing_but_ciphertext_beside_the_archive() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        append_byte(&host_path("work"), 0x33);
        service().lock_volume("work").unwrap();
        let ciphertext = ciphertext_path("work");
        let beside = files_in(ciphertext.parent().unwrap());
        assert_eq!(
            beside,
            vec![ciphertext.clone()],
            "only the archive: {beside:?}"
        );
        assert_eq!(mode(&ciphertext), 0o600);
    }

    #[test]
    fn the_override_admits_every_entry_point_and_audits_each_use() {
        let mut home = TestVolumeHome::new();
        home.allow_unverified_storage();
        let svc = unverified_service();
        let request = CreateBlockVolumeRequest::builder("work")
            .unwrap()
            .capacity_mib(TEST_VOLUME_MIB)
            .build()
            .unwrap();
        svc.create_block_volume(&request).expect("create");
        svc.unlock_volume("work").expect("unlock");
        svc.prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .expect("attach");
        let mut prepared = svc
            .acquire_launch_lease(&dev_launch("vm-1"))
            .expect("launch");
        prepared.commit();
        drop(prepared);
        svc.release_owner_leases("vm-1").unwrap();

        let log = fs::read_to_string(mvm_core::policy::audit::default_audit_log()).unwrap();
        let uses = log
            .lines()
            .filter(|line| line.contains("\"volume_storage_override\""))
            .count();
        assert_eq!(uses, 4, "create, unlock, attach, launch:\n{log}");
        assert!(log.contains("purpose=managed volume"), "{log}");
    }

    fn attach(owner: &str, volume: &str, guest: &str, access: AccessMode) -> AttachmentRequest {
        AttachmentRequest::builder(owner, volume)
            .unwrap()
            .guest_path(guest)
            .access(access)
            .profile(RunProfile::Dev)
            .build()
            .unwrap()
    }

    fn dev_launch(owner: &str) -> LaunchLeaseRequest {
        LaunchLeaseRequest::builder(owner)
            .unwrap()
            .profile(RunProfile::Dev)
            .build()
    }

    fn ciphertext_path(name: &str) -> PathBuf {
        let catalog = LocalVolumeCatalog::load().unwrap();
        match &catalog.get(name).unwrap().encryption {
            LocalVolumeEncryption::MvmManaged(enc) => PathBuf::from(&enc.ciphertext_path),
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        }
    }

    fn managed_state(name: &str) -> LocalVolumeState {
        let catalog = LocalVolumeCatalog::load().unwrap();
        match &catalog.get(name).unwrap().encryption {
            LocalVolumeEncryption::MvmManaged(enc) => enc.state,
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        }
    }

    fn host_path(name: &str) -> PathBuf {
        PathBuf::from(
            &LocalVolumeCatalog::load()
                .unwrap()
                .get(name)
                .unwrap()
                .host_path,
        )
    }

    fn create_ext4_image(path: &Path, size_mib: u32) {
        let mut image = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .expect("create ext4 image");
        let size_bytes = u64::from(size_mib) * 1024 * 1024;
        image.set_len(size_bytes).expect("size ext4 image");
        mvm_fs::ext4::mkfs::format_empty_ext4(&mut image, size_bytes).expect("format ext4 image");
        image.sync_all().expect("sync ext4 image");
    }

    #[test]
    fn create_and_list_report_locked_block_volume_without_secrets() {
        let _home = TestVolumeHome::new();
        let request = CreateBlockVolumeRequest::builder("work")
            .unwrap()
            .capacity_mib(TEST_VOLUME_MIB)
            .build()
            .unwrap();
        let record = service().create_block_volume(&request).unwrap();
        assert_eq!(record.name, "work");
        assert_eq!(
            record.source,
            VolumeSourceKind::ManagedBlock {
                capacity_mib: TEST_VOLUME_MIB
            }
        );
        assert_eq!(record.encryption, EncryptionState::Locked);
        assert_eq!(record.host_artifact, None);
        assert_eq!(record.attached_to, None);
        assert!(ciphertext_path("work").is_file());

        let listed = service().list_volumes().unwrap();
        assert_eq!(listed, vec![record]);

        let described = service().describe_volume("work").unwrap();
        assert_eq!(described.name, "work");
    }

    #[test]
    fn volume_records_never_carry_key_material() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        let record = service().describe_volume("work").unwrap();

        // The on-disk catalog knows the wrapped DEK; the DTO must not.
        let catalog_json =
            fs::read_to_string(LocalVolumeCatalog::path()).expect("catalog persisted");
        assert!(catalog_json.contains("wrapped"), "fixture lost its key");

        let dto_json = serde_json::to_string(&record).unwrap();
        for forbidden in ["wrapped", "master_key", "dek", "ciphertext_path"] {
            assert!(
                !dto_json.contains(forbidden),
                "volume DTO leaked {forbidden:?}: {dto_json}"
            );
        }
        let debug = format!("{record:?}");
        assert!(
            !debug.contains("wrapped"),
            "Debug leaked key field: {debug}"
        );
    }

    #[test]
    fn unlock_lock_roundtrip_preserves_bytes_and_states() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);

        let unlocked = service().unlock_volume("work").unwrap();
        assert_eq!(unlocked.encryption, EncryptionState::Unlocked);
        let artifact = PathBuf::from(unlocked.host_artifact.clone().unwrap());
        assert!(artifact.is_file());

        let mut image = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&artifact)
            .unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        image.write_all(&[0x7a]).unwrap();
        image.sync_all().unwrap();

        let locked = service().lock_volume("work").unwrap();
        assert_eq!(locked.encryption, EncryptionState::Locked);
        assert!(!artifact.exists());

        service().unlock_volume("work").unwrap();
        let mut image = File::open(host_path("work")).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        let mut marker = [0u8; 1];
        image.read_exact(&mut marker).unwrap();
        assert_eq!(marker, [0x7a]);
    }

    #[test]
    fn tampered_ciphertext_is_refused_at_unlock() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        let ciphertext = ciphertext_path("work");
        let mut bytes = fs::read(&ciphertext).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&ciphertext, bytes).unwrap();

        let err = service().unlock_volume("work").unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("DEK binding mismatch")
                || chain.contains("decrypting")
                || chain.contains("authentication"),
            "got: {chain}"
        );
    }

    #[test]
    fn dek_bound_to_different_artifact_is_refused() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        let mut catalog = LocalVolumeCatalog::load().unwrap();
        if let LocalVolumeEncryption::MvmManaged(enc) =
            &mut catalog.get_mut("work").unwrap().encryption
        {
            enc.wrapped_key.rebind_content("0".repeat(64));
        }
        catalog.save().unwrap();
        let err = service().unlock_volume("work").unwrap_err();
        assert!(
            format!("{err:#}").contains("DEK binding mismatch"),
            "got: {err:#}"
        );
    }

    #[test]
    fn attach_defaults_read_only_and_resolves_for_launch() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        let record = service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        assert_eq!(record.access, AccessMode::ReadOnly);
        assert_eq!(record.guest_path, "/data/work");
        assert_eq!(record.source, AttachmentSource::ManagedCatalog);

        let described = service().describe_volume("work").unwrap();
        assert_eq!(described.attached_to, None, "no lease before launch");

        let prepared = service().acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert_eq!(prepared.volumes[0].guest, "/data/work");
        assert!(prepared.volumes[0].read_only);
        assert!(matches!(
            prepared.volumes[0].kind,
            mvm_core::vm_backend::VmVolumeKind::Disk
        ));
    }

    #[test]
    fn permitted_read_write_attachment_resolves_writable() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadWrite))
            .unwrap();
        let prepared = service().acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        assert!(!prepared.volumes[0].read_only);
    }

    #[test]
    fn sealed_profile_refuses_read_write_launch() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadWrite))
            .unwrap();
        let request = LaunchLeaseRequest::builder("vm-1").unwrap().build();
        let err = service().acquire_launch_lease(&request).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not permit writable"),
            "got: {err:#}"
        );
        // The refusal must not leak a lease.
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    /// A writable managed block volume is a disk image the guest writes
    /// into, so every profile that grants a writable `--mount` disk image
    /// leases it read-write — the default `standard` included.
    #[test]
    fn a_writable_managed_volume_leases_under_every_granting_profile() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(
                &AttachmentRequest::builder("vm-1", "work")
                    .unwrap()
                    .guest_path("/data/work")
                    .access(AccessMode::ReadWrite)
                    .profile(RunProfile::Standard)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        for profile in [
            RunProfile::Standard,
            RunProfile::Dev,
            RunProfile::Permissive,
        ] {
            let request = LaunchLeaseRequest::builder("vm-1")
                .unwrap()
                .profile(profile)
                .build();
            let prepared = service()
                .acquire_launch_lease(&request)
                .unwrap_or_else(|e| panic!("{}: {e:#}", profile.as_str()));
            assert_eq!(prepared.volumes.len(), 1);
            assert!(!prepared.volumes[0].read_only, "{}", profile.as_str());
            // Dropped uncommitted: the lease rolls back for the next profile.
        }
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    /// `restrictive` grants no writable disk image, so it refuses the same
    /// registration and takes no lease.
    #[test]
    fn restrictive_profile_refuses_read_write_launch() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadWrite))
            .unwrap();
        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .profile(RunProfile::Restrictive)
            .build();
        let err = service().acquire_launch_lease(&request).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("does not permit writable"), "{message}");
        assert!(message.contains("profile \"restrictive\""), "{message}");
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    #[test]
    fn duplicate_guest_path_between_explicit_and_registered_is_refused() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        let explicit = mvm_runtime::image::RuntimeVolume {
            host: "/explicit.ext4".to_string(),
            guest: "/data/work".to_string(),
            size: "1G".to_string(),
            read_only: true,
            materialized_image: None,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        };
        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .explicit_volumes(vec![explicit])
            .profile(RunProfile::Dev)
            .build();
        let err = service().acquire_launch_lease(&request).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate guest mount path"),
            "got: {err:#}"
        );
    }

    #[test]
    fn materialized_directory_grant_does_not_take_a_direct_disk_lease() {
        let _home = TestVolumeHome::new();
        let materialized = mvm_runtime::image::RuntimeVolume {
            host: "/granted/directory".to_string(),
            guest: "/work".to_string(),
            size: "1G".to_string(),
            read_only: true,
            materialized_image: Some("/state/mount.ext4".to_string()),
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        };
        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .explicit_volumes(vec![materialized])
            .profile(RunProfile::Dev)
            .build();

        let prepared = service().acquire_launch_lease(&request).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    #[test]
    fn duplicate_registered_guest_path_is_refused_at_attach() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        home.create_block("other", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service().unlock_volume("other").unwrap();
        service()
            .prepare_attachment(&attach(
                "vm-1",
                "work",
                "/data/shared",
                AccessMode::ReadOnly,
            ))
            .unwrap();
        let err = service()
            .prepare_attachment(&attach(
                "vm-1",
                "other",
                "/data/shared",
                AccessMode::ReadOnly,
            ))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("already has a volume mount"),
            "got: {err:#}"
        );
    }

    #[test]
    fn lease_is_exclusive_until_released_and_rolls_back_uncommitted() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        service()
            .prepare_attachment(&attach("vm-2", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();

        // Failed launch: uncommitted guard drop releases the lease.
        let prepared = service().acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        drop(prepared);
        assert!(service().acquire_launch_lease(&dev_launch("vm-2")).is_ok());

        // Committed launch: the lease persists and excludes both a second
        // attachment and a lifecycle seal.
        let mut prepared = service().acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        prepared.commit();
        drop(prepared);
        assert_eq!(
            service().describe_volume("work").unwrap().attached_to,
            Some("vm-1".to_string())
        );
        let lock_err = service().lock_volume("work").unwrap_err();
        assert!(
            format!("{lock_err:#}").contains("attached to VM \"vm-1\""),
            "got: {lock_err:#}"
        );
        let err = service()
            .acquire_launch_lease(&dev_launch("vm-2"))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("already attached to VM \"vm-1\""),
            "got: {err:#}"
        );

        // Release (the stop path) frees it for the next owner; a second
        // release is an idempotent no-op.
        let outcome = service().release_owner_leases("vm-1").unwrap();
        assert_eq!(outcome.released, 1);
        assert_eq!(outcome.relocked, Vec::<String>::new());
        let outcome = service().release_owner_leases("vm-1").unwrap();
        assert_eq!(outcome.released, 0);
        assert!(service().acquire_launch_lease(&dev_launch("vm-2")).is_ok());
    }

    #[test]
    fn launch_refuses_volume_locked_after_registration() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        service().lock_volume("work").unwrap();
        let err = service()
            .acquire_launch_lease(&dev_launch("vm-1"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("locked"), "got: {err:#}");
    }

    #[test]
    fn attach_refuses_locked_missing_and_unknown_volumes() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        let err = service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap_err();
        assert!(format!("{err:#}").contains("is locked"), "got: {err:#}");

        let err = service()
            .prepare_attachment(&attach(
                "vm-1",
                "ghost",
                "/data/ghost",
                AccessMode::ReadOnly,
            ))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("no managed local volume"),
            "got: {err:#}"
        );
    }

    #[test]
    fn just_in_time_unlock_then_final_release_relocks() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        // Register while unlocked (the registration gate), then re-seal so
        // the launch meets a locked volume.
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        service().lock_volume("work").unwrap();
        assert_eq!(managed_state("work"), LocalVolumeState::Locked);

        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .profile(RunProfile::Dev)
            .unlock(UnlockPolicy::JustInTime)
            .build();
        let mut prepared = service().acquire_launch_lease(&request).unwrap();
        assert_eq!(managed_state("work"), LocalVolumeState::Unlocked);
        assert_eq!(prepared.volumes.len(), 1);
        prepared.commit();
        drop(prepared);

        // Still unlocked while the committed lease lives.
        assert_eq!(managed_state("work"), LocalVolumeState::Unlocked);

        // The final release re-seals the volume and reports it.
        let outcome = service().release_owner_leases("vm-1").unwrap();
        assert_eq!(outcome.released, 1);
        assert_eq!(outcome.relocked, vec!["work".to_string()]);
        assert_eq!(managed_state("work"), LocalVolumeState::Locked);
        assert!(!host_path("work").exists(), "plaintext artifact leaked");
    }

    #[test]
    fn failed_launch_rolls_back_a_just_in_time_unlock() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        service().lock_volume("work").unwrap();

        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .profile(RunProfile::Dev)
            .unlock(UnlockPolicy::JustInTime)
            .build();
        let prepared = service().acquire_launch_lease(&request).unwrap();
        // Backend start fails: the guard drops uncommitted.
        drop(prepared);

        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
        assert_eq!(
            managed_state("work"),
            LocalVolumeState::Locked,
            "failed launch must re-seal the just-in-time unlock"
        );
        assert!(!host_path("work").exists(), "plaintext artifact leaked");
    }

    #[test]
    fn refused_resolution_relocks_a_just_in_time_unlock() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadWrite))
            .unwrap();
        service().lock_volume("work").unwrap();

        // Sealed profile refuses the writable attachment after the JIT
        // unlock already happened; the refusal must re-seal.
        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .unlock(UnlockPolicy::JustInTime)
            .build();
        let err = service().acquire_launch_lease(&request).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not permit writable"),
            "got: {err:#}"
        );
        assert_eq!(managed_state("work"), LocalVolumeState::Locked);
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    #[test]
    fn detach_removes_the_registration_and_reports_it() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        assert_eq!(service().list_attachments("vm-1").unwrap().len(), 1);

        let dropped = service().detach("vm-1", "/data/work").unwrap();
        assert_eq!(dropped.volume, "work");
        assert!(service().list_attachments("vm-1").unwrap().is_empty());

        let err = service().detach("vm-1", "/data/work").unwrap_err();
        assert!(
            format!("{err:#}").contains("no volume mount"),
            "got: {err:#}"
        );
    }

    #[test]
    fn orphaned_lease_recovery_after_process_crash_is_idempotent() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        let mut prepared = service().acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        prepared.commit();
        // Simulate the owning process crashing: the guard is forgotten, the
        // lease survives on disk.
        std::mem::forget(prepared);
        assert!(!AttachmentLeaseCatalog::load().unwrap().leases.is_empty());

        // A fresh service instance (new process) reconciles the orphan.
        let outcome = LocalVolumeService::new()
            .release_owner_leases("vm-1")
            .unwrap();
        assert_eq!(outcome.released, 1);
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
        let outcome = LocalVolumeService::new()
            .release_owner_leases("vm-1")
            .unwrap();
        assert_eq!(outcome.released, 0);
    }

    #[test]
    fn leases_persist_across_service_restarts() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        service()
            .prepare_attachment(&attach("vm-2", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        let mut prepared = service().acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        prepared.commit();
        drop(prepared);

        // A brand-new service instance sees the persisted lease.
        let fresh = service();
        assert_eq!(
            fresh.describe_volume("work").unwrap().attached_to,
            Some("vm-1".to_string())
        );
        let err = fresh.acquire_launch_lease(&dev_launch("vm-2")).unwrap_err();
        assert!(
            format!("{err:#}").contains("already attached"),
            "got: {err:#}"
        );
        fresh.release_owner_leases("vm-1").unwrap();
        assert!(fresh.acquire_launch_lease(&dev_launch("vm-2")).is_ok());
    }

    #[test]
    fn interrupted_seal_recovers_without_losing_plaintext() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().unlock_volume("work").unwrap();

        let mut catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap().clone();
        if let LocalVolumeEncryption::MvmManaged(enc) =
            &mut catalog.get_mut("work").unwrap().encryption
        {
            enc.state = LocalVolumeState::Locking;
        }
        catalog.save().unwrap();
        let staging = ciphertext_path("work").with_extension("locking");
        fs::write(&staging, b"partial").unwrap();
        let _ = entry;

        service().recover().unwrap();
        assert_eq!(managed_state("work"), LocalVolumeState::Unlocked);
        assert!(host_path("work").is_file());
        assert!(!staging.exists());
    }

    #[test]
    fn host_directory_encryption_check_fails_closed_without_a_probe() {
        let home = TestVolumeHome::new();
        let root = home.path().join("plain");
        fs::create_dir(&root).unwrap();
        let err = LocalVolumeService::new()
            .require_host_encryption(&root)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("no host encryption probe"),
            "got: {err:#}"
        );
    }

    #[test]
    fn host_directory_encryption_check_uses_the_injected_probe() {
        let home = TestVolumeHome::new();
        let root = home.path().join("encrypted-backing");
        fs::create_dir(&root).unwrap();
        let probe = super::probe_from_fn(|_path: &Path| Ok(()));
        let svc = LocalVolumeService::with_host_encryption_probe(probe);
        svc.require_host_encryption(&root).unwrap();
    }

    #[test]
    fn ad_hoc_image_attachment_registers_a_block_image() {
        let home = TestVolumeHome::new();
        let source_dir = home.path().join("adhoc-source");
        fs::create_dir(&source_dir).unwrap();
        let image = home.path().join("adhoc.ext4");
        create_ext4_image(&image, TEST_VOLUME_MIB);
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(RunProfile::Dev)
            .build()
            .unwrap();

        let record = service()
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                TEST_VOLUME_MIB,
            )
            .unwrap();
        assert_eq!(record.source, AttachmentSource::AdHocHost);
        assert_eq!(record.host_path, image.display().to_string());
    }

    #[test]
    fn ad_hoc_ext4_image_registers_and_resolves_as_a_block_volume() {
        let home = TestVolumeHome::new();
        let source_dir = home.path().join("adhoc-source");
        fs::create_dir(&source_dir).unwrap();
        home.create_block("source", TEST_VOLUME_MIB);
        service().unlock_volume("source").unwrap();
        let image = host_path("source");
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(RunProfile::Dev)
            .build()
            .unwrap();
        let svc = LocalVolumeService::with_host_encryption_probe(super::probe_from_fn(|_| Ok(())));

        let record = svc
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                TEST_VOLUME_MIB,
            )
            .unwrap();
        assert_eq!(record.source, AttachmentSource::AdHocHost);

        let prepared = svc.acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert_eq!(
            prepared.instruction_images,
            vec![fs::canonicalize(&image).unwrap()]
        );
        assert_eq!(
            PathBuf::from(&prepared.volumes[0].host),
            fs::canonicalize(&image).unwrap()
        );
        assert_eq!(
            prepared.volumes[0]
                .materialized_image
                .as_deref()
                .map(PathBuf::from),
            Some(fs::canonicalize(&image).unwrap())
        );
        assert!(matches!(
            prepared.volumes[0].kind,
            mvm_core::vm_backend::VmVolumeKind::Disk
        ));
    }

    #[test]
    fn ad_hoc_image_attachment_refuses_non_ext4_bytes() {
        let home = TestVolumeHome::new();
        let source_dir = home.path().join("adhoc-source");
        fs::create_dir(&source_dir).unwrap();
        let image = home.path().join("not-ext4.img");
        fs::write(&image, b"not an ext4 image").unwrap();
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(RunProfile::Dev)
            .build()
            .unwrap();
        let svc = LocalVolumeService::with_host_encryption_probe(super::probe_from_fn(|_| Ok(())));

        let error = svc
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                1,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("is not a valid ext4 image"),
            "got: {error:#}"
        );
    }

    #[test]
    fn ad_hoc_image_attachment_refuses_invalid_volume_names() {
        let home = TestVolumeHome::new();
        let source_dir = home.path().join("adhoc-source");
        fs::create_dir(&source_dir).unwrap();
        let image = home.path().join("adhoc.ext4");
        create_ext4_image(&image, TEST_VOLUME_MIB);
        let svc = service();

        // Accepted by the general name type but too loose for the conservative
        // local-volume identity rule.
        for name in ["input_data", &"a".repeat(33)] {
            let request = AttachmentRequest::builder("vm-1", name)
                .unwrap()
                .guest_path("/work/input")
                .profile(RunProfile::Dev)
                .build()
                .unwrap();
            let err = svc
                .prepare_ad_hoc_snapshot_attachment(
                    &request,
                    &source_dir,
                    &image,
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    TEST_VOLUME_MIB,
                )
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("volume name"),
                "expected a volume-name refusal for {name:?}, got: {err:#}"
            );
        }
    }

    #[test]
    fn launch_reprobes_ad_hoc_image_attachments() {
        let home = TestVolumeHome::new();
        let source_dir = home.path().join("adhoc-source");
        fs::create_dir(&source_dir).unwrap();
        let image = home.path().join("adhoc.ext4");
        create_ext4_image(&image, TEST_VOLUME_MIB);
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(RunProfile::Dev)
            .build()
            .unwrap();
        service()
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                TEST_VOLUME_MIB,
            )
            .unwrap();

        // The launch-time recheck runs with the deny-all probe: the host
        // backing can no longer be verified, so the launch is refused.
        let err = LocalVolumeService::new()
            .acquire_launch_lease(&dev_launch("vm-1"))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("no longer has encrypted host backing"),
            "got: {err:#}"
        );
    }

    #[test]
    fn lease_error_messages_never_carry_key_material() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        let err = service().unlock_volume("missing").unwrap_err();
        let chain = format!("{err:#}");
        let ciphertext = fs::read(ciphertext_path("work")).unwrap();
        // No error chain in this module embeds ciphertext or key bytes; spot
        // check the refusal shape here.
        assert!(!chain.contains(&hex::encode(&ciphertext[..16.min(ciphertext.len())])));
        assert!(chain.contains("no managed local volume"), "got: {chain}");
    }

    #[test]
    fn snapshot_and_restore_surface_through_the_service() {
        let home = TestVolumeHome::new();
        home.create_block("work", TEST_VOLUME_MIB);
        service().snapshot_volume("work", "baseline").unwrap();
        service().restore_volume("work", "baseline").unwrap();
        assert_eq!(managed_state("work"), LocalVolumeState::Locked);
    }
}
