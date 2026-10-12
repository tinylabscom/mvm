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
    EncryptionState, LocalVolumeService, VolumeRecord, VolumeService, VolumeSourceKind,
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
    /// Register a local block volume with a VM.
    ///
    /// Operations against provider-backed (S3 / Hetzner / R2 / GCS /
    /// Azure) volumes route through mvmd via `--remote`. v1 mvm-side
    /// `mount` handles only local volumes. A host directory is snapshotted to
    /// an ext4 block image rather than shared directly with the guest.
    Mount {
        /// Name of the VM
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Logical volume name.
        /// Must be lowercase alphanumeric + hyphens, ≤32 chars.
        #[arg(long)]
        volume: String,
        /// Absolute host directory, snapshotted into an ext4 image before each
        /// machine start and attached as a block device. Host edits made while
        /// the machine runs become visible after its next stop/start.
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
            size,
            remote,
            bucket,
            storage_class,
        } => {
            if remote {
                if root.is_some() {
                    bail!("--root is a local-only volume option");
                }
                return remote::create(&volume, &size, bucket.as_deref(), storage_class.as_deref());
            }
            create(&volume, root.as_deref(), &size)
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

/// The local volume service, bound to the same storage detector `mvmctl
/// doctor` reports from: managed volume plaintext and a directory snapshotted
/// by `--host` are both checked before anything is written or read.
#[cfg(not(test))]
fn service() -> LocalVolumeService {
    LocalVolumeService::with_system_host_encryption_probe()
}

#[cfg(test)]
fn service() -> LocalVolumeService {
    LocalVolumeService::with_host_encryption_probe(mvm_client::volume::probe_from_fn(|_| Ok(())))
}

fn create(volume_name: &str, root: Option<&str>, size: &str) -> Result<()> {
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

#[cfg(test)]
use mvm_client::volume::image_size_mib;

pub(in crate::commands) fn mount(
    vm_name: &str,
    volume_name: &str,
    host: Option<&str>,
    guest: &str,
    rw: bool,
) -> Result<()> {
    mount_with_service(&service(), vm_name, volume_name, host, guest, rw)
}

fn mount_with_service(
    volume_service: &LocalVolumeService,
    vm_name: &str,
    volume_name: &str,
    host: Option<&str>,
    guest: &str,
    rw: bool,
) -> Result<()> {
    let request = AttachmentRequest::builder(vm_name, volume_name)?
        .guest_path(guest)
        .access(if rw {
            AccessMode::ReadWrite
        } else {
            AccessMode::ReadOnly
        })
        .profile(registration_profile(vm_name)?)
        .build()?;
    let record = match host {
        Some(host) => {
            let cache = crate::mount_cache::MountImageCache::new()?;
            volume_service.mount_host_snapshot(&request, Path::new(host), &cache)?
        }
        None => volume_service.prepare_attachment(&request)?,
    };
    println!(
        "{vm_name}: registered volume {volume_name:?} → {} (host={}, requested_ro={}; \
         launch may harden a host snapshot to read-only)",
        record.guest_path,
        record.host_path,
        record.access.is_read_only()
    );
    Ok(())
}

/// The profile a registration is checked against.
///
/// A machine that already has a stored spec is checked against the profile
/// that spec names, so a writable registration its start would refuse is
/// refused here, with the same message. A registration may also come before
/// the machine exists; there is no profile to check yet, so it registers as
/// the dev lane, and the machine's start applies its own profile.
fn registration_profile(vm_name: &str) -> Result<AdmittedProfile> {
    mvm_client::volume::registration_profile(vm_name)
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
        "{:<22} {:<22} {:<14} {:<12} HOST",
        "GUEST", "VOLUME", "ATTACHED", "REQUESTED_RO"
    );
    for record in &records {
        println!(
            "{:<22} {:<22} {:<14} {:<12} {}",
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

/// The attachments registered against `vm_name`, without taking a lease.
///
/// This is for callers that only need to *know* registrations exist — a
/// transient run that will not attach them, for instance — and must not
/// disturb a persistent machine that holds them. Launch-time lease acquisition
/// lives in `mvm_client::volume`.
pub(crate) fn list_registered_attachments(
    vm_name: &str,
) -> Result<Vec<mvm_client::volume::AttachmentRecord>> {
    service().list_attachments(vm_name)
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
        create("work", Some(root.to_str().unwrap()), "16M").unwrap();

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
    fn mvm_managed_mount_refuses_locked_volume() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), "16M").unwrap();
        let err = mount("vm-1", "work", None, "/data/work", false).unwrap_err();
        assert!(format!("{err:#}").contains("is locked"), "got: {err:#}");
    }

    #[test]
    fn mvm_managed_unlock_rejects_tampered_ciphertext() {
        let guard = DataDirGuard::new();
        let root = guard.path().join("vol-root");
        create("work", Some(root.to_str().unwrap()), "16M").unwrap();
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
