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
//!   read-only, and read-write is refused unless the admitted profile is
//!   dev-tier.
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
mod test_support;

pub use dto::{
    AccessMode, AdmittedProfile, AttachmentRecord, AttachmentRequest, AttachmentRequestBuilder,
    AttachmentSource, CreateBlockVolumeRequest, CreateBlockVolumeRequestBuilder, EncryptionState,
    HostSnapshotRecord, LaunchLeaseRequest, LaunchLeaseRequestBuilder, ReleaseOutcome,
    UnlockPolicy, VolumeRecord, VolumeSourceKind,
};
pub use lease::LaunchLease;
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
    use super::test_support::TestVolumeHome;

    fn service() -> LocalVolumeService {
        LocalVolumeService::new()
    }

    fn attach(owner: &str, volume: &str, guest: &str, access: AccessMode) -> AttachmentRequest {
        AttachmentRequest::builder(owner, volume)
            .unwrap()
            .guest_path(guest)
            .access(access)
            .profile(AdmittedProfile::Dev)
            .build()
            .unwrap()
    }

    fn dev_launch(owner: &str) -> LaunchLeaseRequest {
        LaunchLeaseRequest::builder(owner)
            .unwrap()
            .profile(AdmittedProfile::Dev)
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
            .capacity_mib(16)
            .build()
            .unwrap();
        let record = service().create_block_volume(&request).unwrap();
        assert_eq!(record.name, "work");
        assert_eq!(
            record.source,
            VolumeSourceKind::ManagedBlock { capacity_mib: 16 }
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);

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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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

    #[test]
    fn duplicate_guest_path_between_explicit_and_registered_is_refused() {
        let home = TestVolumeHome::new();
        home.create_block("work", 16);
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
            .profile(AdmittedProfile::Dev)
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
            .profile(AdmittedProfile::Dev)
            .build();

        let prepared = service().acquire_launch_lease(&request).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert!(AttachmentLeaseCatalog::load().unwrap().leases.is_empty());
    }

    #[test]
    fn duplicate_registered_guest_path_is_refused_at_attach() {
        let home = TestVolumeHome::new();
        home.create_block("work", 16);
        home.create_block("other", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
            .profile(AdmittedProfile::Dev)
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
        home.create_block("work", 16);
        service().unlock_volume("work").unwrap();
        service()
            .prepare_attachment(&attach("vm-1", "work", "/data/work", AccessMode::ReadOnly))
            .unwrap();
        service().lock_volume("work").unwrap();

        let request = LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .profile(AdmittedProfile::Dev)
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
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
        let fresh = LocalVolumeService::new();
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
        home.create_block("work", 16);
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
        let err = service().require_host_encryption(&root).unwrap_err();
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
        create_ext4_image(&image, 16);
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(AdmittedProfile::Dev)
            .build()
            .unwrap();

        let record = service()
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                16,
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
        home.create_block("source", 16);
        service().unlock_volume("source").unwrap();
        let image = host_path("source");
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(AdmittedProfile::Dev)
            .build()
            .unwrap();
        let svc = LocalVolumeService::with_host_encryption_probe(super::probe_from_fn(|_| Ok(())));

        let record = svc
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                16,
            )
            .unwrap();
        assert_eq!(record.source, AttachmentSource::AdHocHost);

        let prepared = svc.acquire_launch_lease(&dev_launch("vm-1")).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert_eq!(
            PathBuf::from(&prepared.volumes[0].host),
            fs::canonicalize(&image).unwrap()
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
            .profile(AdmittedProfile::Dev)
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
        create_ext4_image(&image, 16);
        let svc = service();

        // Accepted by the general name type but too loose for the conservative
        // local-volume identity rule.
        for name in ["input_data", &"a".repeat(33)] {
            let request = AttachmentRequest::builder("vm-1", name)
                .unwrap()
                .guest_path("/work/input")
                .profile(AdmittedProfile::Dev)
                .build()
                .unwrap();
            let err = svc
                .prepare_ad_hoc_snapshot_attachment(
                    &request,
                    &source_dir,
                    &image,
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    16,
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
        create_ext4_image(&image, 16);
        let request = AttachmentRequest::builder("vm-1", "input")
            .unwrap()
            .guest_path("/work/input")
            .profile(AdmittedProfile::Dev)
            .build()
            .unwrap();
        service()
            .prepare_ad_hoc_snapshot_attachment(
                &request,
                &source_dir,
                &image,
                "0000000000000000000000000000000000000000000000000000000000000000",
                16,
            )
            .unwrap();

        // The launch-time recheck runs with the deny-all probe: the host
        // backing can no longer be verified, so the launch is refused.
        let err = service()
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
        home.create_block("work", 16);
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
        home.create_block("work", 16);
        service().snapshot_volume("work", "baseline").unwrap();
        service().restore_volume("work", "baseline").unwrap();
        assert_eq!(managed_state("work"), LocalVolumeState::Locked);
    }
}
