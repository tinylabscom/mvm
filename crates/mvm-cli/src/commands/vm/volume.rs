//! `mvmctl volume` — encrypted local block-volume lifecycle and VM attachment.
//!
//! Thin presentation shim over the reusable local volume service
//! (`mvm_client::volume::LocalVolumeService`). The service owns the canonical
//! lifecycle — encrypted create, unlock/lock, typed attachment registration,
//! exclusive launch leases, and crash recovery — while this module owns only
//! clap parsing, terminal output, and the host-encryption probe (the doctor's
//! platform diagnostics).
//!
//! Registrations are resolved immediately before launch, included in the same
//! admitted volume set handed to the VMM and guest activation payload, and
//! rejected before boot when their encrypted state or local artifact changes.
//!
//! ## `--remote` mode (mvmd proxy)
//!
//! `--remote` routes operations through mvmd's authenticated REST API rather
//! than executing locally. Configuration is read from `MVM_GATEWAY_URL`,
//! `MVM_GATEWAY_TOKEN`, and `MVM_TENANT_ID`; the bearer token is retained only
//! in memory and is redacted from debug output.

use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Args as ClapArgs, Subcommand};

use mvm_client::volume::{
    AccessMode, AdmittedProfile, AttachmentRecord, AttachmentRequest, CreateBlockVolumeRequest,
    EncryptionState, LaunchLeaseRequest, LocalVolumeService, VolumeRecord, VolumeService,
    VolumeSourceKind, probe_from_fn,
};
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::clap_vm_name;

mod remote;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub command: VolumeCmd,
}

/// Help for `--guest`. Kept in one place because it restates
/// [`mvm_core::crypto::policy::MOUNT_ALLOW_ROOTS`], and the two drifted apart
/// once already: this string still offered `/mnt` after the allow-root was
/// removed, which is the shape that let a share mount over the runtime's
/// config and secret drives. A doc comment cannot read the constant it
/// restates, so a test asserts the two agree.
const GUEST_MOUNT_HELP: &str = "Mount point inside the VM (must be under /data \
     or /work; never /mnt, /etc, /usr, /lib, /proc, or /nix)";

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum VolumeCmd {
    /// Create a managed encrypted local volume.
    Create {
        /// Logical volume name.
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        volume: String,
        /// Root directory under which encrypted volume state
        /// will be created. Defaults to ~/.mvm/volumes/local.
        #[arg(long)]
        root: Option<String>,
        /// Use the previous host-backed encryption gate instead of
        /// an mvm-managed encrypted archive.
        #[arg(long)]
        host_backed: bool,
        /// Capacity of a new portable ext4 block volume.
        #[arg(long, default_value = "1G")]
        size: String,
        /// Create through the authenticated mvmd tenant API.
        #[arg(long)]
        remote: bool,
        /// Durable StorageBucket ID used for encrypted checkpoints.
        #[arg(long, requires = "remote")]
        bucket: Option<String>,
        /// Remote storage-class policy name.
        #[arg(long, requires = "remote")]
        storage_class: Option<String>,
    },
    /// Decrypt a managed volume into its private local attachment artifact.
    Unlock { volume: String },
    /// Seal a managed volume and remove its plaintext attachment artifact.
    Lock { volume: String },
    /// List managed local volumes.
    Catalog {
        #[arg(long)]
        json: bool,
        /// List volumes through the authenticated mvmd tenant API.
        #[arg(long)]
        remote: bool,
    },
    /// Create an immutable encrypted snapshot of a locked managed volume.
    #[command(visible_alias = "checkpoint")]
    Snapshot {
        volume: String,
        snapshot: String,
        #[arg(long)]
        remote: bool,
    },
    /// Restore a locked managed volume from an immutable local snapshot.
    Restore {
        volume: String,
        snapshot: String,
        /// Name of the new remote volume created from the checkpoint.
        #[arg(long, requires = "remote")]
        target: Option<String>,
        #[arg(long)]
        remote: bool,
    },
    /// Delete a detached remote volume.
    Delete {
        volume: String,
        #[arg(long)]
        remote: bool,
    },
    /// Mount a virtio-fs volume into a VM.
    ///
    /// Operations against provider-backed (S3 / Hetzner / R2 / GCS /
    /// Azure) volumes route through mvmd via `--remote`. v1 mvm-side
    /// `mount` handles only local volumes (host directory exposed via
    /// virtio-fs).
    Mount {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Logical volume name.
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        #[arg(long)]
        volume: String,
        /// Absolute host directory, snapshotted into an ext4 image at
        /// registration and attached as a block device. A snapshot, not a live
        /// view: re-register to refresh it. Managed volumes omit this.
        #[arg(long)]
        host: Option<String>,
        #[arg(long, help = GUEST_MOUNT_HELP)]
        guest: String,
        /// Mount the volume read-write (default: read-only).
        #[arg(long)]
        rw: bool,
        /// Route through mvmd REST instead of writing the local
        /// registry.
        #[arg(long)]
        remote: bool,
    },
    /// List registered volume mounts for a VM.
    Ls {
        #[arg(value_parser = clap_vm_name)]
        name: String,
        #[arg(long)]
        json: bool,
        /// Route through mvmd REST instead of reading the local
        /// registry.
        #[arg(long)]
        remote: bool,
    },
    /// Unmount a registered volume.
    Unmount {
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Guest mount path to detach.
        guest_path: String,
        /// Route through mvmd REST instead of editing the local
        /// registry.
        #[arg(long)]
        remote: bool,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.command {
        VolumeCmd::Create {
            volume,
            root,
            host_backed,
            size,
            remote,
            bucket,
            storage_class,
        } => {
            if remote {
                if root.is_some() || host_backed {
                    bail!("--root and --host-backed are local-only volume options");
                }
                return remote::create(&volume, &size, bucket.as_deref(), storage_class.as_deref());
            }
            create(&volume, root.as_deref(), host_backed, &size)
        }
        VolumeCmd::Unlock { volume } => unlock(&volume),
        VolumeCmd::Lock { volume } => lock(&volume),
        VolumeCmd::Catalog { json, remote } => {
            if remote {
                return remote::catalog(json);
            }
            catalog(json)
        }
        VolumeCmd::Snapshot {
            volume,
            snapshot,
            remote,
        } => {
            if remote {
                return remote::snapshot(&volume, &snapshot);
            }
            service().snapshot_volume(&volume, &snapshot)?;
            println!("created snapshot {snapshot:?} for volume {volume:?}");
            Ok(())
        }
        VolumeCmd::Restore {
            volume,
            snapshot,
            target,
            remote,
        } => {
            if remote {
                let target = target.unwrap_or_else(|| format!("{volume}-restored"));
                return remote::restore(&volume, &snapshot, &target);
            }
            if target.is_some() {
                bail!("--target is only valid with --remote");
            }
            service().restore_volume(&volume, &snapshot)?;
            println!("restored volume {volume:?} from snapshot {snapshot:?}");
            Ok(())
        }
        VolumeCmd::Delete { volume, remote } => {
            if !remote {
                bail!("local volume deletion is not implicit; use --remote for tenant volumes");
            }
            remote::delete(&volume)
        }
        VolumeCmd::Mount {
            name,
            volume,
            host,
            guest,
            rw,
            remote,
        } => {
            if remote {
                if host.is_some() {
                    bail!("--host is a local-only volume option");
                }
                return remote::mount(&name, &volume, &guest, rw);
            }
            mount(&name, &volume, host.as_deref(), &guest, rw)
        }
        VolumeCmd::Ls { name, json, remote } => {
            if remote {
                return remote::ls(&name, json);
            }
            ls(&name, json)
        }
        VolumeCmd::Unmount {
            name,
            guest_path,
            remote,
        } => {
            if remote {
                return remote::unmount(&name, &guest_path);
            }
            unmount(&name, &guest_path)
        }
    }
}

/// The local volume service, wired to the doctor's host-encryption
/// diagnostics so host-backed directory volumes keep their encrypted-backing
/// verification.
fn service() -> LocalVolumeService {
    LocalVolumeService::with_host_encryption_probe(probe_from_fn(|path| {
        crate::doctor::require_local_volume_host_path_encrypted(path)
    }))
}

fn create(volume_name: &str, root: Option<&str>, host_backed: bool, size: &str) -> Result<()> {
    if host_backed {
        let record = service()
            .create_host_backed_volume(volume_name, root.map(Path::new))
            .with_context(|| format!("creating host-backed volume {volume_name:?}"))?;
        println!(
            "created encrypted local volume {volume_name:?} at {}",
            record.host_artifact.as_deref().unwrap_or("<unknown>")
        );
        return Ok(());
    }
    let size_mib = mvm_core::util::parse_human_size(size)
        .with_context(|| format!("invalid volume size {size:?}"))?;
    let mut builder = CreateBlockVolumeRequest::builder(volume_name)
        .with_context(|| format!("Invalid volume name: {volume_name:?}"))?
        .capacity_mib(size_mib);
    if let Some(root) = root {
        builder = builder.root(root);
    }
    service().create_block_volume(&builder.build()?)?;
    println!("created locked mvm-managed encrypted volume {volume_name:?}");
    Ok(())
}

fn unlock(volume_name: &str) -> Result<()> {
    let record = service().unlock_volume(volume_name)?;
    println!(
        "unlocked volume {volume_name:?} at {}",
        record.host_artifact.as_deref().unwrap_or("<unknown>")
    );
    Ok(())
}

fn lock(volume_name: &str) -> Result<()> {
    service().lock_volume(volume_name)?;
    println!("locked volume {volume_name:?}");
    Ok(())
}

fn catalog(json: bool) -> Result<()> {
    let records = service().list_volumes()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }
    if records.is_empty() {
        println!("(no managed local volumes)");
        return Ok(());
    }
    println!(
        "{:<22} {:<10} {:<12} {:<12} HOST",
        "VOLUME", "ENCRYPTED", "STATE", "KIND"
    );
    for record in &records {
        println!(
            "{:<22} {:<10} {:<12} {:<12} {}",
            record.name,
            true,
            state_label(record),
            kind_label(record),
            record.host_artifact.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn state_label(record: &VolumeRecord) -> &'static str {
    match record.encryption {
        EncryptionState::HostBacked => "host-backed",
        EncryptionState::Locked => "locked",
        EncryptionState::Unlocked => "unlocked",
        EncryptionState::Recovering => "recovering",
    }
}

fn kind_label(record: &VolumeRecord) -> String {
    match &record.source {
        VolumeSourceKind::ManagedBlock { capacity_mib } => format!("block-{capacity_mib}M"),
        VolumeSourceKind::ManagedDirectory | VolumeSourceKind::AdHocHostDirectory => {
            "directory".to_string()
        }
    }
}

/// Where a `--host` snapshot image lives: one per (machine, volume), so two
/// registrations never write the same file and removing a machine's directory
/// takes its snapshots with it.
fn host_snapshot_image(vm_name: &str, volume_name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_home())
        .join("volumes")
        .join("host-snapshots")
        .join(vm_name)
        .join(format!("{volume_name}.ext4"))
}

fn ensure_private_snapshot_parent(output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .with_context(|| format!("snapshot path {} has no parent", output.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating snapshot dir {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting snapshot dir {}", parent.display()))?;
    }
    Ok(())
}

/// Materialize `host_dir` into an ext4 image for registration.
///
/// The same pure-Rust writer `--mount` uses — no `mkfs`, no subprocess, and it
/// reads host bytes rather than guest requests, so it is not a surface a guest
/// can reach.
fn materialize_host_snapshot(
    vm_name: &str,
    volume_name: &str,
    host_dir: &Path,
) -> Result<std::path::PathBuf> {
    let output = host_snapshot_image(vm_name, volume_name);
    ensure_private_snapshot_parent(&output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&output)
            .with_context(|| format!("creating private snapshot image {}", output.display()))?;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting snapshot image {}", output.display()))?;
    }
    crate::exec::materialize_directory_snapshot(host_dir, &output, "mvmvol")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting snapshot image {}", output.display()))?;
    }
    Ok(output)
}

/// The registered size, in MiB, rounded up so a sub-MiB image is not recorded
/// as zero.
fn image_size_mib(image: &Path) -> Result<u32> {
    let bytes = std::fs::metadata(image)
        .with_context(|| format!("stat snapshot image {}", image.display()))?
        .len();
    let mib = bytes.div_ceil(1024 * 1024).max(1);
    u32::try_from(mib).with_context(|| format!("snapshot image {} is too large", image.display()))
}

fn mount(
    vm_name: &str,
    volume_name: &str,
    host: Option<&str>,
    guest: &str,
    rw: bool,
) -> Result<()> {
    // The mvmctl volume surface is the interactive dev lane; the launch path
    // re-applies the access gate against the machine's admitted profile.
    let request = AttachmentRequest::builder(vm_name, volume_name)?
        .guest_path(guest)
        .access(if rw {
            AccessMode::ReadWrite
        } else {
            AccessMode::ReadOnly
        })
        .profile(AdmittedProfile::Dev)
        .build()?;
    let record = match host {
        Some(host) => {
            let host = Path::new(host);
            if !host.is_absolute() {
                bail!("--host path must be absolute, got {:?}", host.display());
            }
            // Snapshot the directory into an image and register that.
            //
            // A live host-directory share cannot be served — no workload
            // backend has a virtio-fs device, so `machine start` refused one at
            // boot and `machine run` ignored it. Registering the directory
            // as-is recorded an attachment no launch could honour.
            //
            // `--mount HOST:/GUEST` already solved the same problem for a
            // transient run by materializing the directory into an ext4 image,
            // so this reuses that rather than inventing a second answer. The
            // cost is the semantic the old docs claimed and never delivered:
            // the image is a snapshot taken now, not a live view of the
            // directory. Re-register to refresh it.
            let host_encrypted_check = service();
            host_encrypted_check.require_host_encryption(host)?;
            let output = host_snapshot_image(vm_name, volume_name);
            ensure_private_snapshot_parent(&output)?;
            let output_parent = output
                .parent()
                .context("host snapshot output has no parent directory")?;
            host_encrypted_check
                .require_host_encryption(output_parent)
                .context("host snapshot destination is not on encrypted backing storage")?;
            let image = materialize_host_snapshot(vm_name, volume_name, host)?;
            let size_mib = image_size_mib(&image)?;
            service().prepare_ad_hoc_image_attachment(&request, &image, size_mib)?
        }
        None => service().prepare_attachment(&request)?,
    };
    println!(
        "{vm_name}: registered volume {volume_name:?} → {} (host={}, ro={})",
        record.guest_path,
        record.host_path,
        record.access.is_read_only()
    );
    Ok(())
}

fn ls(vm_name: &str, json: bool) -> Result<()> {
    let records = service().list_attachments(vm_name)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }
    if records.is_empty() {
        println!("(no volume mounts)");
        return Ok(());
    }
    println!(
        "{:<22} {:<22} {:<14} {:<4} HOST",
        "GUEST", "VOLUME", "ATTACHED", "RO"
    );
    for record in &records {
        println!(
            "{:<22} {:<22} {:<14} {:<4} {}",
            record.guest_path,
            record.volume,
            &record.attached_at[..record.attached_at.len().min(14)],
            if record.access.is_read_only() {
                "yes"
            } else {
                "no"
            },
            record.host_path,
        );
    }
    Ok(())
}

fn unmount(vm_name: &str, guest_path: &str) -> Result<()> {
    let dropped: AttachmentRecord = service().detach(vm_name, guest_path)?;
    println!(
        "{vm_name}: unmounted volume {} from {} (host={})",
        dropped.volume, dropped.guest_path, dropped.host_path
    );
    Ok(())
}

/// Release every attachment lease `vm_name` holds (the stop/down path),
/// re-sealing any volume the service unlocked just in time. Idempotent.
pub(in crate::commands) fn release_volume_leases_for_vm(vm_name: &str) -> Result<()> {
    service().release_owner_leases(vm_name).map(|_| ())
}

/// The resolved, leased volume set handed to admission and the backend.
/// Commit only after the backend start succeeds — dropping uncommitted rolls
/// the leases back so a failed launch leaks nothing.
pub(super) type PreparedLaunchVolumes = mvm_client::volume::LaunchPreparation;

/// Merge persisted local registrations into the volume list used to construct
/// both signed admission grants and the backend launch configuration.
/// The attachments registered against `vm_name`, without taking a lease.
///
/// Distinct from [`merge_registered_volumes_for_launch`], which acquires the
/// exclusive launch lease. This is for callers that only need to *know*
/// registrations exist — a transient run that will not attach them, for
/// instance — and must not disturb a persistent machine that holds them.
pub(crate) fn list_registered_attachments(
    vm_name: &str,
) -> Result<Vec<mvm_client::volume::AttachmentRecord>> {
    service().list_attachments(vm_name)
}

pub(super) fn merge_registered_volumes_for_launch(
    vm_name: &str,
    explicit: &[mvm_runtime::image::RuntimeVolume],
) -> Result<PreparedLaunchVolumes> {
    // Persistent named machines are dev-accessible for their lifetime, so
    // the dev-tier access gate applies here; locked managed volumes keep
    // failing closed (the operator unlocks explicitly before launch).
    let request = LaunchLeaseRequest::builder(vm_name)
        .with_context(|| format!("Invalid VM name: {vm_name:?}"))?
        .explicit_volumes(explicit.to_vec())
        .profile(AdmittedProfile::Dev)
        .build();
    service()
        .acquire_launch_lease(&request)
        .context("resolving registered local volumes for launch")
}

#[cfg(test)]
mod tests {

    /// The `--guest` help restates the allow-root policy, and a doc comment
    /// cannot read the constant it restates. The two drifted once: the help
    /// kept offering `/mnt` after it was removed from the allow-roots, and
    /// four documentation pages copied the CLI and taught mounts that fail.
    #[test]
    fn the_guest_mount_help_matches_the_shipped_allow_roots() {
        for root in mvm_core::crypto::policy::MOUNT_ALLOW_ROOTS {
            assert!(
                super::GUEST_MOUNT_HELP.contains(root),
                "allow-root `{root}` is shipped but `--guest` help does not name it: {}",
                super::GUEST_MOUNT_HELP
            );
        }
        for reserved in ["/mnt/config", "/mnt/secrets"] {
            let root = reserved
                .split('/')
                .nth(1)
                .expect("reserved path has a root");
            assert!(
                !mvm_core::crypto::policy::MOUNT_ALLOW_ROOTS
                    .iter()
                    .any(|r| r.trim_start_matches('/') == root),
                "/{root} became an allow-root again; a share there can shadow {reserved}"
            );
        }
    }
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    use mvm_runtime::vm::volume_registry::{
        LocalVolumeCatalog, LocalVolumeEncryption, LocalVolumeState, MvmManagedVolumeEncryption,
    };

    use super::*;

    struct DataDirGuard {
        _env: mvm_core::util::test_env::TestEnv,
        tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let mut env = mvm_core::util::test_env::TestEnv::new();
            let tmp = tempfile::tempdir().expect("tempdir");
            env.set("MVM_HOME", tmp.path());
            Self { _env: env, tmp }
        }

        fn path(&self) -> &Path {
            self.tmp.path()
        }
    }

    #[test]
    fn mvm_managed_volume_create_unlock_lock_roundtrip() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();

        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(!Path::new(&entry.host_path).exists());
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => {
                assert_eq!(enc.state, LocalVolumeState::Locked);
                PathBuf::from(&enc.ciphertext_path)
            }
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        };
        assert!(ciphertext.is_file());

        unlock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(Path::new(&entry.host_path).is_file());

        let mut image = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&entry.host_path)
            .unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        image.write_all(&[0x7a]).unwrap();
        image.sync_all().unwrap();
        lock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        assert!(!Path::new(&entry.host_path).exists());
        assert!(matches!(
            &entry.encryption,
            LocalVolumeEncryption::MvmManaged(MvmManagedVolumeEncryption {
                state: LocalVolumeState::Locked,
                ..
            })
        ));

        unlock("work").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        let mut image = File::open(&entry.host_path).unwrap();
        image.seek(SeekFrom::End(-1)).unwrap();
        let mut marker = [0u8; 1];
        image.read_exact(&mut marker).unwrap();
        assert_eq!(marker, [0x7a]);
    }

    #[test]
    fn host_snapshot_helpers_materialize_a_namespaced_ext4_image() {
        let guard = DataDirGuard::new();
        let source = guard.path().join("source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/marker"), b"snapshot-visible\n").unwrap();

        let image = materialize_host_snapshot("vm-1", "input", &source).unwrap();
        assert_eq!(
            image,
            guard.path().join("volumes/host-snapshots/vm-1/input.ext4")
        );
        assert!(image_size_mib(&image).unwrap() >= 1);
        let fs = ext4_view::Ext4::load_from_path(&image).unwrap();
        assert!(fs.exists("/nested/marker").unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(image.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&image).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn image_size_refuses_a_missing_snapshot() {
        let guard = DataDirGuard::new();
        let missing = guard.path().join("missing.ext4");
        let error = image_size_mib(&missing).unwrap_err();
        assert!(
            format!("{error:#}").contains("stat snapshot image"),
            "got: {error:#}"
        );
    }

    #[test]
    fn registered_managed_mount_is_consumed_by_launch_resolution() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", true).unwrap();

        let prepared = merge_registered_volumes_for_launch("vm-1", &[]).unwrap();
        assert_eq!(prepared.volumes.len(), 1);
        assert_eq!(prepared.volumes[0].guest, "/data/work");
        assert!(!prepared.volumes[0].read_only);
        assert!(matches!(
            prepared.volumes[0].kind,
            mvm_core::vm_backend::VmVolumeKind::Disk
        ));
        assert!(Path::new(&prepared.volumes[0].host).is_file());
    }

    #[test]
    fn block_attachment_lease_is_exclusive_and_released_on_stop() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", true).unwrap();
        mount("vm-2", "work", None, "/data/work", true).unwrap();

        let prepared = merge_registered_volumes_for_launch("vm-1", &[]).unwrap();
        drop(prepared);
        assert!(merge_registered_volumes_for_launch("vm-2", &[]).is_ok());

        let mut prepared = merge_registered_volumes_for_launch("vm-1", &[]).unwrap();
        prepared.commit();
        drop(prepared);
        let lock_error = lock("work").unwrap_err();
        assert!(
            format!("{lock_error:#}").contains("attached to VM \"vm-1\""),
            "got: {lock_error:#}"
        );
        let error = match merge_registered_volumes_for_launch("vm-2", &[]) {
            Ok(_) => panic!("second VM must not acquire an active block lease"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("already attached to VM \"vm-1\""),
            "got: {error:#}"
        );

        release_volume_leases_for_vm("vm-1").unwrap();
        assert!(merge_registered_volumes_for_launch("vm-2", &[]).is_ok());
    }

    #[test]
    fn launch_resolution_refuses_volume_locked_after_registration() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", false).unwrap();
        lock("work").unwrap();

        let err = merge_registered_volumes_for_launch("vm-1", &[]).unwrap_err();
        assert!(format!("{err:#}").contains("locked"), "got: {err:#}");
    }

    #[test]
    fn launch_resolution_refuses_explicit_guest_path_collision() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        unlock("work").unwrap();
        mount("vm-1", "work", None, "/data/work", false).unwrap();
        let explicit = mvm_runtime::image::RuntimeVolume {
            host: "/explicit.ext4".to_string(),
            guest: "/data/work".to_string(),
            size: "1G".to_string(),
            read_only: true,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        };

        let err = merge_registered_volumes_for_launch("vm-1", &[explicit]).unwrap_err();
        assert!(
            format!("{err:#}").contains("duplicate guest mount path"),
            "got: {err:#}"
        );
    }

    #[test]
    fn mvm_managed_mount_refuses_locked_volume() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        let err = mount("vm-1", "work", None, "/data/work", false).unwrap_err();
        assert!(format!("{err:#}").contains("is locked"), "got: {err:#}");
    }

    #[test]
    fn mvm_managed_unlock_rejects_tampered_ciphertext() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), false, "16M").unwrap();
        let catalog = LocalVolumeCatalog::load().unwrap();
        let entry = catalog.get("work").unwrap();
        let ciphertext = match &entry.encryption {
            LocalVolumeEncryption::MvmManaged(enc) => PathBuf::from(&enc.ciphertext_path),
            LocalVolumeEncryption::HostBacked => panic!("expected mvm-managed encryption"),
        };
        let mut bytes = fs::read(&ciphertext).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&ciphertext, bytes).unwrap();
        let err = unlock("work").unwrap_err();
        // The DEK binding catches a flipped byte at admit (the ciphertext
        // hash no longer matches the bound artifact), before the archive is
        // even decrypted. Either gate is a valid rejection.
        let chain = format!("{err:#}");
        assert!(
            chain.contains("DEK binding mismatch")
                || chain.contains("decrypting")
                || chain.contains("authentication"),
            "got: {chain}"
        );
    }
}
