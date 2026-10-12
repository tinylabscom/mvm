//! Materialize and refresh registered host snapshots before admission.

use super::{AttachmentRecord, AttachmentRequest, LocalVolumeService, VolumeService};
use crate::workspace_apply::cache::MountImageCache;
use anyhow::{Context, Result, ensure};
use mvm_runtime::vm::volume_registry::{
    HostSnapshotSource, LocalVolumeKind, VolumeMountEntry, VolumeMountRegistry, VolumeMountSource,
};
use std::path::{Path, PathBuf};

pub fn host_snapshot_image(vm: &str, volume: &str) -> Result<PathBuf> {
    crate::validate_vm_name(vm)?;
    mvm_core::domain::volume::VolumeName::new(volume)?;
    Ok(mvm_core::config::volumes_dir()
        .join("host-snapshots")
        .join(vm)
        .join(format!("{volume}.ext4")))
}

pub fn image_size_mib(image: &Path) -> Result<u32> {
    let bytes = std::fs::metadata(image)
        .with_context(|| format!("stat snapshot image {}", image.display()))?
        .len();
    u32::try_from(bytes.div_ceil(1024 * 1024).max(1))
        .with_context(|| format!("snapshot image {} is too large", image.display()))
}

impl LocalVolumeService {
    /// Materialize a host directory and register only the resulting block image.
    pub fn mount_host_snapshot(
        &self,
        request: &AttachmentRequest,
        host: &Path,
        cache: &MountImageCache,
    ) -> Result<AttachmentRecord> {
        ensure!(
            host.is_absolute(),
            "--host path must be absolute, got {:?}",
            host.display()
        );
        let _lock = super::lifecycle::acquire_volume_lifecycle_lock()?;
        let target = host_snapshot_image(&request.owner, request.volume.as_str())?;
        preflight(request, &target)?;
        let fingerprint = cache.fingerprint(host, &format!("mvmvol{}", request.volume.as_str()))?;
        self.require_host_encryption(fingerprint.source())?;
        let image = cache.lookup(fingerprint)?.resolve()?;
        let register = |attachment_image: &Path| {
            self.prepare_ad_hoc_snapshot_attachment_locked(
                request,
                image.fingerprint().source(),
                attachment_image,
                image.fingerprint().cache_key(),
                image_size_mib(attachment_image)?,
            )
        };
        if request.access.is_read_only() {
            register(image.path())
        } else {
            let staging = snapshot_staging(&target)?;
            ensure_image_unleased(&target)?;
            let staged = image.writable_image(&staging.path().join("image.ext4"))?;
            publish_new_snapshot(&staged, &target, || register(&target))
        }
    }

    /// Open the encrypted cache lazily, only when a registration needs it.
    pub fn refresh_host_snapshots(
        &self,
        vm: &str,
        open_cache: impl FnOnce() -> Result<MountImageCache>,
    ) -> Result<()> {
        let _lock = super::lifecycle::acquire_volume_lifecycle_lock()?;
        let attachments = self.list_attachments(vm)?;
        if !attachments.iter().any(|a| a.host_snapshot.is_some()) {
            return Ok(());
        }
        let cache = open_cache()?;
        for attachment in attachments {
            let Some(snapshot) = attachment.host_snapshot else {
                continue;
            };
            let image_path = host_snapshot_image(vm, &attachment.volume)?;
            let fingerprint = cache
                .fingerprint(
                    Path::new(&snapshot.source_path),
                    &format!("mvmvol{}", attachment.volume),
                )
                .with_context(|| {
                    format!(
                        "refreshing host snapshot for volume {:?}",
                        attachment.volume
                    )
                })?;
            self.require_host_encryption(fingerprint.source())
                .with_context(|| {
                    format!(
                        "rechecking host snapshot source for {:?}",
                        attachment.volume
                    )
                })?;
            let unchanged = fingerprint.cache_key() == snapshot.fingerprint;
            if !attachment.access.is_read_only()
                && unchanged
                && Path::new(&attachment.host_path).is_file()
            {
                continue;
            }
            ensure_image_unleased(Path::new(&attachment.host_path))?;
            let cached = cache.lookup(fingerprint)?.resolve()?;
            let register = |attachment_image: &Path| {
                self.refresh_ad_hoc_snapshot_attachment_locked(
                    vm,
                    &attachment.guest_path,
                    attachment_image,
                    cached.fingerprint().cache_key(),
                    image_size_mib(attachment_image)?,
                )
            };
            if attachment.access.is_read_only() {
                register(cached.path())?;
            } else {
                ensure_image_unleased(&image_path)?;
                let staging = snapshot_staging(&image_path)?;
                let staged = cached.writable_image(&staging.path().join("image.ext4"))?;
                if image_path.try_exists()? {
                    replace_snapshot(
                        staging,
                        &staged,
                        &image_path,
                        || register(&image_path),
                        |backup, target| std::fs::rename(backup, target),
                    )?;
                } else {
                    publish_new_snapshot(&staged, &image_path, || register(&image_path))?;
                }
            }
        }
        Ok(())
    }
}

/// Called while holding the same lifecycle exclusion as registration and launch.
fn preflight(request: &AttachmentRequest, image: &Path) -> Result<()> {
    let guest_path = mvm_core::crypto::policy::validate_mount_path(&request.guest_path)?;
    let mut registry = VolumeMountRegistry::load(&request.owner)?;
    registry.add(VolumeMountEntry {
        volume_name: request.volume.as_str().to_owned(),
        host_path: image.to_string_lossy().into_owned(),
        guest_path,
        read_only: request.access.is_read_only(),
        kind: LocalVolumeKind::BlockImage { size_mib: 1 },
        attached_at: String::new(),
        source: VolumeMountSource::AdHocHost,
        host_snapshot: Some(HostSnapshotSource {
            source_path: String::new(),
            fingerprint: String::new(),
        }),
    })?;
    if !request.access.is_read_only() {
        ensure!(
            image
                .symlink_metadata()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "snapshot image {} already exists or cannot be inspected; refusing to replace it",
            image.display()
        );
    }
    Ok(())
}

fn snapshot_staging(target: &Path) -> Result<tempfile::TempDir> {
    let parent = target.parent().context("snapshot image has no parent")?;
    mvm_core::config::create_private_dir(parent)?;
    tempfile::Builder::new()
        .prefix(".host-snapshot-")
        .tempdir_in(parent)
        .context("creating private host snapshot staging directory")
}

fn replace_snapshot<T>(
    staging: tempfile::TempDir,
    staged: &Path,
    target: &Path,
    register: impl FnOnce() -> Result<T>,
    restore: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<T> {
    let backup = staging.path().join("previous.ext4");
    std::fs::hard_link(target, &backup)?;
    std::fs::rename(staged, target)?;
    match register() {
        Ok(record) => Ok(record),
        Err(error) => {
            if let Err(restore_error) = restore(&backup, target) {
                // The backup may be the only copy of guest edits. Do not let
                // TempDir cleanup delete it when automatic rollback fails.
                let retained = staging.keep();
                return Err(error.context(format!(
                    "restoring snapshot after rejected refresh failed: {restore_error}; \
                     original image retained at {}; restore it to {} before retrying; \
                     remove retained directory {} only after recovery",
                    backup.display(),
                    target.display(),
                    retained.display()
                )));
            }
            Err(error)
        }
    }
}

fn publish_new_snapshot<T>(
    staged: &Path,
    target: &Path,
    register: impl FnOnce() -> Result<T>,
) -> Result<T> {
    // No-clobber publication: even an unregistered orphan is never overwritten.
    std::fs::hard_link(staged, target)
        .with_context(|| format!("publishing new snapshot {}", target.display()))?;
    match register() {
        Ok(record) => Ok(record),
        Err(error) => {
            remove_published_snapshot(staged, target)?;
            Err(error)
        }
    }
}

fn remove_published_snapshot(staged: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let owned = staged.metadata()?;
    let published = target.symlink_metadata()?;
    ensure!(
        owned.dev() == published.dev() && owned.ino() == published.ino(),
        "unregistered snapshot was replaced outside lifecycle exclusion; leaving it untouched"
    );
    std::fs::remove_file(target).context("rolling back unregistered snapshot")
}

pub(super) fn ensure_image_unleased(image: &Path) -> Result<()> {
    if image.exists() || image.parent().is_some_and(Path::is_dir) {
        let key = super::lease::lease_key(image)?;
        ensure!(
            !super::lease::AttachmentLeaseCatalog::load()?
                .leases
                .contains_key(&key),
            "cannot refresh leased host snapshot {}",
            image.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::dto::{AccessMode, AdmittedProfile};
    use crate::volume::service::probe_from_fn;
    use crate::volume::test_support::TestVolumeHome;
    use std::io::{Read, Write};

    fn request(guest: &str) -> AttachmentRequest {
        AttachmentRequest::builder("vm-1", "work")
            .unwrap()
            .guest_path(guest)
            .access(AccessMode::ReadWrite)
            .profile(AdmittedProfile::from_profile_name("dev"))
            .build()
            .unwrap()
    }

    fn service() -> LocalVolumeService {
        LocalVolumeService::with_host_encryption_probe(probe_from_fn(|_| Ok(())))
    }

    /// The encrypted-backing verification lives behind the mount-image cache,
    /// so the cache must open only when a registration actually carries a host
    /// snapshot: opening it eagerly would demand an encrypted home on a host
    /// without one, for a cache the launch would never write to.
    #[test]
    fn a_refresh_with_no_host_snapshots_never_opens_the_mount_cache() {
        let _home = TestVolumeHome::new();
        let service = service();
        service
            .refresh_host_snapshots("vm-no-mounts", || {
                panic!(
                    "the mount-image cache must not be opened for a launch with no host snapshots"
                )
            })
            .expect("a launch that mounts nothing must not be refused");
    }

    fn duplicate_is_unchanged(guest: &str) {
        let home = TestVolumeHome::new();
        let source = home.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), b"host original").unwrap();
        let cache = MountImageCache::with_encryption_probe(|_| Ok(())).unwrap();
        let service = service();
        let first = service
            .mount_host_snapshot(&request("/data/work"), &source, &cache)
            .unwrap();
        let registry = VolumeMountRegistry::path_for("vm-1");
        let before = std::fs::read(&registry).unwrap();
        let mut image = std::fs::OpenOptions::new()
            .write(true)
            .open(&first.host_path)
            .unwrap();
        image.write_all(b"guest edited bytes").unwrap();
        drop(image);
        std::fs::write(source.join("file"), b"host changed").unwrap();
        assert!(
            service
                .mount_host_snapshot(&request(guest), &source, &cache)
                .is_err()
        );
        let mut bytes = [0; 18];
        std::fs::File::open(&first.host_path)
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"guest edited bytes");
        assert_eq!(std::fs::read(registry).unwrap(), before);
        assert_eq!(service.list_attachments("vm-1").unwrap(), vec![first]);
    }

    #[test]
    fn duplicate_same_path_preserves_image_baseline_and_registry() {
        duplicate_is_unchanged("/data/work");
    }

    #[test]
    fn same_volume_other_path_preserves_image_baseline_and_registry() {
        duplicate_is_unchanged("/data/other");
    }

    #[test]
    fn successful_mount_registers_private_image_and_refreshes() {
        let home = TestVolumeHome::new();
        let source = home.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), b"first").unwrap();
        let cache = MountImageCache::with_encryption_probe(|_| Ok(())).unwrap();
        let service = service();
        let mounted = service
            .mount_host_snapshot(&request("/data/work"), &source, &cache)
            .unwrap();
        assert_eq!(
            Path::new(&mounted.host_path),
            host_snapshot_image("vm-1", "work").unwrap()
        );
        assert!(Path::new(&mounted.host_path).is_file());
        std::fs::write(source.join("file"), b"second").unwrap();
        service
            .refresh_host_snapshots("vm-1", || Ok(cache))
            .unwrap();
        let refreshed = service.list_attachments("vm-1").unwrap().remove(0);
        assert_eq!(refreshed.host_path, mounted.host_path);
        assert_ne!(refreshed.host_snapshot, mounted.host_snapshot);
        assert_eq!(
            std::fs::read_dir(Path::new(&mounted.host_path).parent().unwrap())
                .unwrap()
                .count(),
            1,
            "successful refresh removes its staging directory and backup"
        );
    }

    /// Refresh keys on content, not mtime: bytes changed while the timestamp
    /// was held still must still publish a new snapshot before a launch.
    #[test]
    fn changed_host_bytes_with_equal_mtime_refresh() {
        let home = TestVolumeHome::new();
        let source = home.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let marker = source.join("marker");
        std::fs::write(&marker, b"before").unwrap();
        let original_mtime = std::fs::metadata(&marker).unwrap().modified().unwrap();
        let cache = MountImageCache::with_encryption_probe(|_| Ok(())).unwrap();
        let service = service();
        let mounted = service
            .mount_host_snapshot(&request("/data/work"), &source, &cache)
            .unwrap();

        std::fs::write(&marker, b"after!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        service
            .refresh_host_snapshots("vm-1", || Ok(cache))
            .unwrap();
        let refreshed = service.list_attachments("vm-1").unwrap().remove(0);
        assert_ne!(refreshed.host_snapshot, mounted.host_snapshot);
    }

    /// A source that disappeared refuses the refresh, and the last published
    /// image stays put for the next launch to see.
    #[test]
    fn missing_host_snapshot_source_refuses_refresh_and_keeps_last_image() {
        let home = TestVolumeHome::new();
        let source = home.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("marker"), b"last-known").unwrap();
        let cache = MountImageCache::with_encryption_probe(|_| Ok(())).unwrap();
        let service = service();
        let mounted = service
            .mount_host_snapshot(&request("/data/work"), &source, &cache)
            .unwrap();
        std::fs::remove_dir_all(&source).unwrap();

        let error = service
            .refresh_host_snapshots("vm-1", || Ok(cache))
            .expect_err("a missing source must refuse the refresh");
        assert!(format!("{error:#}").contains("does not exist"), "{error:#}");
        let kept = service.list_attachments("vm-1").unwrap().remove(0);
        assert_eq!(kept.host_path, mounted.host_path);
        assert_eq!(kept.host_snapshot, mounted.host_snapshot);
    }

    fn rejected_refresh(restore_fails: bool) {
        use std::os::unix::fs::PermissionsExt;

        let home = TestVolumeHome::new();
        let source = home.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), b"first").unwrap();
        let cache = MountImageCache::with_encryption_probe(|_| Ok(())).unwrap();
        let service = service();
        let mounted = service
            .mount_host_snapshot(&request("/data/work"), &source, &cache)
            .unwrap();
        let target = Path::new(&mounted.host_path);
        std::fs::OpenOptions::new()
            .write(true)
            .open(target)
            .unwrap()
            .write_all(b"guest edited bytes")
            .unwrap();
        let original = std::fs::read(target).unwrap();
        let registry = VolumeMountRegistry::path_for("vm-1");
        let registry_before = std::fs::read(&registry).unwrap();
        std::fs::write(source.join("file"), b"changed host source").unwrap();
        let fingerprint = cache.fingerprint(&source, "mvmvolwork").unwrap();
        assert_ne!(
            fingerprint.cache_key(),
            mounted.host_snapshot.as_ref().unwrap().fingerprint
        );
        let cached = cache.lookup(fingerprint).unwrap().resolve().unwrap();
        let staging = snapshot_staging(target).unwrap();
        let staging_path = staging.path().to_path_buf();
        let backup = staging_path.join("previous.ext4");
        let staged = cached
            .writable_image(&staging_path.join("image.ext4"))
            .unwrap();
        let replacement = std::fs::read(&staged).unwrap();
        assert_ne!(replacement, original);
        let error = replace_snapshot(
            staging,
            &staged,
            target,
            || -> Result<()> {
                assert_eq!(std::fs::read(target).unwrap(), replacement);
                anyhow::bail!("injected registry rejection")
            },
            |from, to| {
                assert_eq!(from, backup);
                assert_eq!(to, target);
                assert_eq!(std::fs::read(from).unwrap(), original);
                if restore_fails {
                    Err(std::io::Error::other("injected restore failure"))
                } else {
                    std::fs::rename(from, to)
                }
            },
        )
        .unwrap_err();
        let diagnosis = format!("{error:#}");
        assert!(
            diagnosis.contains("injected registry rejection"),
            "{diagnosis}"
        );
        assert_eq!(std::fs::read(registry).unwrap(), registry_before);
        assert_eq!(
            service.list_attachments("vm-1").unwrap(),
            vec![mounted.clone()]
        );
        assert!(!staged.exists());
        if restore_fails {
            assert!(
                diagnosis.contains("injected restore failure"),
                "{diagnosis}"
            );
            assert!(
                diagnosis.contains(&backup.display().to_string()),
                "{diagnosis}"
            );
            assert!(
                diagnosis.contains(&target.display().to_string()),
                "{diagnosis}"
            );
            assert_eq!(std::fs::read(&backup).unwrap(), original);
            assert_eq!(std::fs::read(target).unwrap(), replacement);
            assert_eq!(
                std::fs::metadata(&staging_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            // The helper has returned and dropped its guards. Recovery still works.
            std::fs::rename(&backup, target).unwrap();
            assert_eq!(std::fs::read(target).unwrap(), original);
            std::fs::remove_dir(&staging_path).unwrap();
        } else {
            assert_eq!(std::fs::read(target).unwrap(), original);
            assert!(!staging_path.exists(), "successful rollback cleans staging");
            assert!(!backup.exists());
        }
    }

    #[test]
    fn rejected_refresh_restores_guest_image_and_cleans_backup() {
        rejected_refresh(false);
    }

    #[test]
    fn rejected_refresh_with_failed_restore_retains_recoverable_private_backup() {
        rejected_refresh(true);
    }

    #[test]
    fn registration_failure_removes_only_newly_published_image() {
        let home = TestVolumeHome::new();
        let staged = home.path().join("staged");
        let target = home.path().join("new.ext4");
        std::fs::write(&staged, b"new image").unwrap();
        let registry = VolumeMountRegistry::path_for("vm-1");
        mvm_core::config::create_private_dir(&registry).unwrap();
        let marker = registry.join("existing");
        std::fs::write(&marker, b"registry untouched").unwrap();
        let result = publish_new_snapshot(&staged, &target, || {
            VolumeMountRegistry::default().save("vm-1")
        });
        assert!(result.is_err());
        assert!(!target.exists());
        assert_eq!(std::fs::read(marker).unwrap(), b"registry untouched");
        assert_eq!(std::fs::read(staged).unwrap(), b"new image");
    }

    #[test]
    fn leased_refresh_preserves_image_baseline_and_registry() {
        let home = TestVolumeHome::new();
        let source = home.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), b"first").unwrap();
        let cache = MountImageCache::with_encryption_probe(|_| Ok(())).unwrap();
        let service = service();
        let mounted = service
            .mount_host_snapshot(&request("/data/work"), &source, &cache)
            .unwrap();
        let launch = crate::volume::dto::LaunchLeaseRequest::builder("vm-1")
            .unwrap()
            .profile(AdmittedProfile::from_profile_name("dev"))
            .build();
        let lease = service.acquire_launch_lease(&launch).unwrap();
        let registry = VolumeMountRegistry::path_for("vm-1");
        let before = std::fs::read(&registry).unwrap();
        use std::os::unix::fs::MetadataExt;
        let inode = std::fs::metadata(&mounted.host_path).unwrap().ino();
        std::fs::write(source.join("file"), b"second").unwrap();
        let error = service
            .refresh_host_snapshots("vm-1", || Ok(cache))
            .unwrap_err();
        assert!(error.to_string().contains("leased host snapshot"));
        assert_eq!(std::fs::read(registry).unwrap(), before);
        assert_eq!(std::fs::metadata(&mounted.host_path).unwrap().ino(), inode);
        drop(lease);
    }

    #[test]
    fn publication_failure_never_replaces_an_existing_image() {
        let home = TestVolumeHome::new();
        let staged = home.path().join("staged");
        let target = home.path().join("existing.ext4");
        std::fs::write(&staged, b"new image").unwrap();
        std::fs::write(&target, b"guest edits").unwrap();
        let result = publish_new_snapshot(&staged, &target, || -> Result<()> {
            panic!("registration must not run after failed publication")
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"guest edits");
    }
}
