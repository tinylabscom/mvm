//! The object-safe volume service contract and its local implementation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::crypto::policy::validate_mount_path;
use mvm_core::naming::validate_vm_name;
use mvm_runtime::image::RuntimeVolume;
use mvm_runtime::vm::volume_registry::{
    HostSnapshotSource, LocalVolumeEncryption, LocalVolumeEntry, LocalVolumeKind, LocalVolumeState,
    ResolvedVolumeSource, VolumeMountEntry, VolumeMountRegistry, VolumeMountSource,
};

use super::dto::{
    AccessMode, AttachmentRecord, AttachmentRequest, AttachmentSource, CreateBlockVolumeRequest,
    EncryptionState, HostSnapshotRecord, LaunchLeaseRequest, ReleaseOutcome, UnlockPolicy,
    VolumeRecord, VolumeSourceKind,
};
use super::lease::{self, AttachmentLeaseCatalog, AttachmentLeaseRecord, LaunchLease, LeaseIntent};
use super::lifecycle;

/// Verifies that a host path lives on encrypted backing storage.
///
/// mvm-managed volumes carry their own encryption lifecycle, so they never
/// consult the probe. An ad-hoc source directory is plaintext while being
/// snapshotted and must sit on encrypted host storage. The check is diagnostic
/// work (platform tooling like `diskutil` / `lsblk`), so the presentation
/// surface that owns those diagnostics injects it.
pub trait HostEncryptionProbe: Send + Sync {
    /// Return `Ok(())` only when `path` is confirmed to live on encrypted
    /// backing storage; unknown must fail closed.
    fn require_encrypted(&self, path: &Path) -> Result<()>;
}

/// Fail-closed default probe: refuses every host-backed path, keeping
/// consumers without host diagnostics restricted to mvm-managed volumes.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllHostEncryptionProbe;

impl HostEncryptionProbe for DenyAllHostEncryptionProbe {
    fn require_encrypted(&self, path: &Path) -> Result<()> {
        bail!(
            "cannot verify encrypted host backing for {}: this consumer has no host \
             encryption probe; use an mvm-managed encrypted volume instead",
            path.display()
        )
    }
}

struct FnProbe<F>(F);

impl<F> HostEncryptionProbe for FnProbe<F>
where
    F: Fn(&Path) -> Result<()> + Send + Sync,
{
    fn require_encrypted(&self, path: &Path) -> Result<()> {
        (self.0)(path)
    }
}

/// Wrap a closure as a [`HostEncryptionProbe`].
pub fn probe_from_fn<F>(probe: F) -> Box<dyn HostEncryptionProbe>
where
    F: Fn(&Path) -> Result<()> + Send + Sync + 'static,
{
    Box::new(FnProbe(probe))
}

/// The resolved, leased volume set for one launch.
///
/// Holds the exclusive attachment leases; drop it uncommitted (failed
/// launch, error unwind) and the leases roll back — re-sealing any volume the
/// service unlocked just in time — with nothing leaked. Call
/// [`LaunchPreparation::commit`] only after the backend start succeeds.
#[derive(Debug)]
pub struct LaunchPreparation {
    /// The merged launch volume list: explicit volumes plus every resolved
    /// registered attachment, in admission order.
    pub volumes: Vec<RuntimeVolume>,
    lease: LaunchLease,
}

impl LaunchPreparation {
    /// Persist the leases beyond this guard: the launch succeeded, and the
    /// owner's stop path releases them later.
    pub fn commit(&mut self) {
        self.lease.commit();
    }
}

/// Object-safe contract for the local encrypted-volume lifecycle.
///
/// Composes creation, unlock/lock, typed attachment preparation, exclusive
/// attachment leases, and metadata reporting behind one seam so every local
/// presentation surface shares a single policy and cleanup implementation.
/// All refusal paths fail closed before any VM boots: missing, locked,
/// changed, unencrypted, tampered, cross-scope, and unsupported attachments
/// are rejected during resolution.
pub trait VolumeService: Send + Sync {
    /// Drive any interrupted lifecycle transition back to a terminal state.
    /// Idempotent; every other operation also runs this first.
    fn recover(&self) -> Result<()>;

    /// List every managed local volume, without key material.
    fn list_volumes(&self) -> Result<Vec<VolumeRecord>>;

    /// Describe one managed local volume.
    fn describe_volume(&self, name: &str) -> Result<VolumeRecord>;

    /// Create a managed encrypted block volume (registered locked).
    fn create_block_volume(&self, request: &CreateBlockVolumeRequest) -> Result<VolumeRecord>;

    /// Decrypt a managed volume into its private attachment artifact.
    fn unlock_volume(&self, name: &str) -> Result<VolumeRecord>;

    /// Seal a managed volume and remove its plaintext attachment artifact.
    fn lock_volume(&self, name: &str) -> Result<VolumeRecord>;

    /// Register a typed attachment of a managed volume for an owner VM.
    fn prepare_attachment(&self, request: &AttachmentRequest) -> Result<AttachmentRecord>;

    /// Remove a registered attachment.
    fn detach(&self, owner: &str, guest_path: &str) -> Result<AttachmentRecord>;

    /// List an owner's registered attachments.
    fn list_attachments(&self, owner: &str) -> Result<Vec<AttachmentRecord>>;

    /// Resolve an owner's registered attachments against the catalog, apply
    /// the access-mode profile gate, optionally unlock just in time, and take
    /// exclusive block-attachment leases.
    fn acquire_launch_lease(&self, request: &LaunchLeaseRequest) -> Result<LaunchPreparation>;

    /// Release every lease `owner` holds and re-seal any just-in-time
    /// unlocked volume. Idempotent and safe after a crash.
    fn release_owner_leases(&self, owner: &str) -> Result<ReleaseOutcome>;
}

/// Local implementation composing the volume catalog, encryption lifecycle,
/// per-VM mount registry, lease catalog, and launch-time admission checks.
pub struct LocalVolumeService {
    probe: Box<dyn HostEncryptionProbe>,
}

impl std::fmt::Debug for LocalVolumeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalVolumeService").finish_non_exhaustive()
    }
}

impl Default for LocalVolumeService {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalVolumeService {
    /// Service with the fail-closed host-encryption probe: managed encrypted
    /// volumes only.
    #[must_use]
    pub fn new() -> Self {
        Self {
            probe: Box::new(DenyAllHostEncryptionProbe),
        }
    }

    /// Service with a caller-supplied host-encryption probe, enabling ad-hoc
    /// directory snapshotting.
    #[must_use]
    pub fn with_host_encryption_probe(probe: Box<dyn HostEncryptionProbe>) -> Self {
        Self { probe }
    }

    /// Run the host-encryption policy against a path.
    ///
    /// Exposed because snapshotting a directory into an image moves the
    /// materialization to the caller, and the *source* directory still has to
    /// satisfy the same at-rest policy it did when it was attached directly.
    /// Dropping that check silently would be a posture change hiding inside a
    /// refactor.
    pub fn require_host_encryption(&self, path: &Path) -> Result<()> {
        self.probe.require_encrypted(path)
    }

    /// Register an already-materialized host-directory snapshot.
    ///
    /// A host *directory* cannot be served, so the caller snapshots it into an
    /// image and registers that block-image shape for launch.
    pub fn prepare_ad_hoc_snapshot_attachment(
        &self,
        request: &AttachmentRequest,
        source_dir: &Path,
        image: &Path,
        fingerprint: &str,
        size_mib: u32,
    ) -> Result<AttachmentRecord> {
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        lifecycle::recover_local_volume_catalog()?;
        lifecycle::validate_volume_name(request.volume.as_str())?;
        validate_snapshot_source(source_dir, fingerprint)?;
        validate_snapshot_image(image)?;
        register_attachment(
            request,
            image.to_string_lossy().into_owned(),
            LocalVolumeKind::BlockImage { size_mib },
            VolumeMountSource::AdHocHost,
            Some(HostSnapshotSource {
                source_path: source_dir.to_string_lossy().into_owned(),
                fingerprint: fingerprint.to_string(),
            }),
        )
    }

    /// Point an existing ad-hoc snapshot registration at freshly selected
    /// image bytes and persist the source fingerprint that selected them.
    pub fn refresh_ad_hoc_snapshot_attachment(
        &self,
        owner: &str,
        guest_path: &str,
        image: &Path,
        fingerprint: &str,
        size_mib: u32,
    ) -> Result<AttachmentRecord> {
        validate_vm_name(owner).with_context(|| format!("invalid VM name: {owner:?}"))?;
        validate_snapshot_fingerprint(fingerprint)?;
        validate_snapshot_image(image)?;
        let canonical_guest = validate_mount_path(guest_path)
            .with_context(|| format!("registered guest path {guest_path:?} rejected"))?;
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let mut registry = VolumeMountRegistry::load(owner)?;
        let entry = registry
            .mounts
            .get_mut(&canonical_guest)
            .with_context(|| format!("VM {owner:?} has no volume mount at {canonical_guest:?}"))?;
        if entry.source != VolumeMountSource::AdHocHost || entry.host_snapshot.is_none() {
            bail!(
                "volume {:?} at {:?} is not a refreshable host snapshot",
                entry.volume_name,
                entry.guest_path
            );
        }
        entry.host_path = image.to_string_lossy().into_owned();
        entry.kind = LocalVolumeKind::BlockImage { size_mib };
        entry
            .host_snapshot
            .as_mut()
            .expect("host snapshot presence checked above")
            .fingerprint = fingerprint.to_string();
        let refreshed = entry.clone();
        registry.save(owner)?;
        Ok(attachment_record(owner, &refreshed))
    }

    /// Create an immutable encrypted snapshot of a locked managed volume.
    pub fn snapshot_volume(&self, name: &str, snapshot: &str) -> Result<()> {
        super::snapshot::create(name, snapshot)
    }

    /// Restore a locked managed volume from an immutable local snapshot.
    pub fn restore_volume(&self, name: &str, snapshot: &str) -> Result<()> {
        super::snapshot::restore(name, snapshot)
    }
}

impl VolumeService for LocalVolumeService {
    fn recover(&self) -> Result<()> {
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        lifecycle::recover_local_volume_catalog()?;
        Ok(())
    }

    fn list_volumes(&self) -> Result<Vec<VolumeRecord>> {
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let catalog = lifecycle::recover_local_volume_catalog()?;
        let leases = AttachmentLeaseCatalog::load()?;
        catalog
            .iter()
            .map(|(_, entry)| volume_record(entry, &leases))
            .collect()
    }

    fn describe_volume(&self, name: &str) -> Result<VolumeRecord> {
        lifecycle::validate_volume_name(name)
            .with_context(|| format!("invalid volume name: {name:?}"))?;
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let catalog = lifecycle::recover_local_volume_catalog()?;
        let entry = catalog
            .get(name)
            .with_context(|| format!("no managed local volume named {name:?}"))?;
        volume_record(entry, &AttachmentLeaseCatalog::load()?)
    }

    fn create_block_volume(&self, request: &CreateBlockVolumeRequest) -> Result<VolumeRecord> {
        lifecycle::validate_volume_name(request.name())
            .with_context(|| format!("invalid volume name: {:?}", request.name()))?;
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        lifecycle::recover_local_volume_catalog()?;
        let entry = lifecycle::create_mvm_managed(
            request.name(),
            request.root.as_deref(),
            request.capacity_mib,
        )?;
        volume_record(&entry, &AttachmentLeaseCatalog::load()?)
    }

    fn unlock_volume(&self, name: &str) -> Result<VolumeRecord> {
        lifecycle::validate_volume_name(name)
            .with_context(|| format!("invalid volume name: {name:?}"))?;
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let mut catalog = lifecycle::recover_local_volume_catalog()?;
        lifecycle::unlock_volume_locked(&mut catalog, name)?;
        let entry = catalog
            .get(name)
            .with_context(|| format!("volume {name:?} disappeared after unlock"))?;
        volume_record(entry, &AttachmentLeaseCatalog::load()?)
    }

    fn lock_volume(&self, name: &str) -> Result<VolumeRecord> {
        lifecycle::validate_volume_name(name)
            .with_context(|| format!("invalid volume name: {name:?}"))?;
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let mut catalog = lifecycle::recover_local_volume_catalog()?;
        lifecycle::lock_volume_locked(&mut catalog, name)?;
        let entry = catalog
            .get(name)
            .with_context(|| format!("volume {name:?} disappeared after lock"))?;
        volume_record(entry, &AttachmentLeaseCatalog::load()?)
    }

    fn prepare_attachment(&self, request: &AttachmentRequest) -> Result<AttachmentRecord> {
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let catalog = lifecycle::recover_local_volume_catalog()?;
        let entry = catalog
            .get(request.volume.as_str())
            .with_context(|| {
                format!(
                    "no managed local volume named {:?}; create it before attaching",
                    request.volume.as_str()
                )
            })?
            .clone();
        if !entry.encrypted {
            bail!(
                "managed local volume {:?} is not marked encrypted",
                request.volume.as_str()
            );
        }
        if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
            && enc.state != LocalVolumeState::Unlocked
        {
            bail!(
                "managed local volume {:?} is locked; unlock it before attaching",
                request.volume.as_str()
            );
        }
        let host_path = Path::new(&entry.host_path);
        if !host_path.is_absolute() {
            bail!("host path must be absolute, got {:?}", entry.host_path);
        }
        match &entry.kind {
            LocalVolumeKind::BlockImage { .. } if !host_path.is_file() => {
                bail!(
                    "managed block volume {:?} is not an existing file",
                    entry.host_path
                )
            }
            LocalVolumeKind::BlockImage { .. } => {
                ext4_view::Ext4::load_from_path(host_path).with_context(|| {
                    format!("managed block volume {:?} is not ext4", entry.host_path)
                })?;
            }
        }
        register_attachment(
            request,
            entry.host_path.clone(),
            entry.kind.clone(),
            VolumeMountSource::ManagedCatalog,
            None,
        )
    }

    fn detach(&self, owner: &str, guest_path: &str) -> Result<AttachmentRecord> {
        validate_vm_name(owner).with_context(|| format!("invalid VM name: {owner:?}"))?;
        let mut registry = VolumeMountRegistry::load(owner)?;
        let dropped = registry
            .remove(guest_path)
            .with_context(|| format!("VM {owner:?} has no volume mount at {guest_path:?}"))?;
        registry.save(owner)?;
        mvm_core::audit_emit!(VmVolumeRemove, vm: owner, "volume={} guest={}" ,
            dropped.volume_name, dropped.guest_path
        );
        Ok(attachment_record(owner, &dropped))
    }

    fn list_attachments(&self, owner: &str) -> Result<Vec<AttachmentRecord>> {
        validate_vm_name(owner).with_context(|| format!("invalid VM name: {owner:?}"))?;
        let registry = VolumeMountRegistry::load(owner)?;
        Ok(registry
            .iter()
            .map(|(_, entry)| attachment_record(owner, entry))
            .collect())
    }

    fn acquire_launch_lease(&self, request: &LaunchLeaseRequest) -> Result<LaunchPreparation> {
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        let registry = VolumeMountRegistry::load(&request.owner)?;
        if registry.is_empty() {
            enforce_profile_access(&request.explicit, request.profile)?;
            let intents = explicit_lease_intents(&request.owner, &request.explicit)?;
            lease::check_lease_conflicts(&intents)?;
            let lease = LaunchLease::acquire(&request.owner, intents)?;
            return Ok(LaunchPreparation {
                volumes: request.explicit.clone(),
                lease,
            });
        }

        let mut catalog = lifecycle::recover_local_volume_catalog()?;

        // Just-in-time unlock: decrypt locked managed volumes this launch
        // references, remembering them so the final lease release re-seals
        // them. Any later refusal in this resolution re-seals immediately.
        let mut jit_unlocked: Vec<String> = Vec::new();
        if request.unlock == UnlockPolicy::JustInTime {
            for (_, mount) in registry.iter() {
                let Some(entry) = catalog.get(&mount.volume_name) else {
                    continue;
                };
                if let LocalVolumeEncryption::MvmManaged(enc) = &entry.encryption
                    && enc.state == LocalVolumeState::Locked
                {
                    let name = entry.volume_name.clone();
                    lifecycle::unlock_volume_locked(&mut catalog, &name)
                        .with_context(|| format!("just-in-time unlock of volume {name:?}"))?;
                    jit_unlocked.push(name);
                }
            }
        }

        let resolution = (|| -> Result<LaunchPreparation> {
            let resolved = registry.resolve_for_launch(&catalog)?;

            let mut guest_paths = request
                .explicit
                .iter()
                .map(|volume| volume.guest.clone())
                .collect::<std::collections::BTreeSet<_>>();
            let mut volumes = request.explicit.clone();
            volumes.reserve(resolved.len());
            let mut intents = explicit_lease_intents(&request.owner, &request.explicit)?;
            let relock_by_name: BTreeMap<&str, ()> = jit_unlocked
                .iter()
                .map(|name| (name.as_str(), ()))
                .collect();
            for attachment in &resolved {
                let guest = attachment.guest_path.as_str().to_string();
                if !guest_paths.insert(guest.clone()) {
                    bail!(
                        "duplicate guest mount path {guest:?} between explicit and registered \
                         volumes"
                    );
                }
                if matches!(
                    attachment.source,
                    ResolvedVolumeSource::HostBackedCatalog | ResolvedVolumeSource::AdHocHost
                ) {
                    self.probe
                        .require_encrypted(&attachment.host_path)
                        .with_context(|| {
                            format!(
                                "registered volume {:?} no longer has encrypted host backing",
                                attachment.volume_name
                            )
                        })?;
                }
                let vm_volume = attachment.as_vm_volume();
                let runtime_volume = RuntimeVolume::from(&vm_volume);
                if matches!(attachment.kind, LocalVolumeKind::BlockImage { .. }) {
                    intents.push(LeaseIntent {
                        key: lease::lease_key(&attachment.host_path)?,
                        record: AttachmentLeaseRecord {
                            vm_name: request.owner.clone(),
                            volume_name: runtime_volume.guest.clone(),
                            read_only: runtime_volume.read_only,
                            acquired_at: mvm_core::util::time::utc_now(),
                            relock_volume: relock_by_name
                                .contains_key(attachment.volume_name.as_str())
                                .then(|| attachment.volume_name.as_str().to_string()),
                        },
                    });
                }
                volumes.push(runtime_volume);
            }
            enforce_profile_access(&volumes, request.profile)?;
            lease::check_lease_conflicts(&intents)?;
            let lease = LaunchLease::acquire(&request.owner, intents)?;
            Ok(LaunchPreparation { volumes, lease })
        })();

        match resolution {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                // Leak-free refusal: re-seal everything unlocked just in time
                // before surfacing the refusal.
                for name in &jit_unlocked {
                    if let Err(relock_error) = lifecycle::relock_if_unlocked(&mut catalog, name) {
                        tracing::error!(
                            volume = %name,
                            error = %relock_error,
                            "failed to re-seal a just-in-time unlocked volume after a refused \
                             launch"
                        );
                    }
                }
                Err(error)
            }
        }
    }

    fn release_owner_leases(&self, owner: &str) -> Result<ReleaseOutcome> {
        let _lock = lifecycle::acquire_volume_lifecycle_lock()?;
        lease::release_keys_for_owner(owner, None)
    }
}

/// Refuse any writable volume in the launch when the admitted profile does
/// not permit read-write attachments.
fn enforce_profile_access(
    volumes: &[RuntimeVolume],
    profile: super::dto::AdmittedProfile,
) -> Result<()> {
    if profile.permits_read_write() {
        return Ok(());
    }
    if let Some(volume) = volumes.iter().find(|volume| !volume.read_only) {
        bail!(
            "read-write attachment at guest path {:?} refused: the admitted profile does not \
             permit writable volumes (use a dev-tier profile)",
            volume.guest
        );
    }
    Ok(())
}

/// Lease intents for the caller-supplied explicit block-volume list.
fn explicit_lease_intents(owner: &str, explicit: &[RuntimeVolume]) -> Result<Vec<LeaseIntent>> {
    explicit
        .iter()
        .filter(|volume| volume.materialized_image.is_none())
        .map(|volume| {
            Ok(LeaseIntent {
                key: lease::lease_key(Path::new(&volume.host))?,
                record: AttachmentLeaseRecord {
                    vm_name: owner.to_string(),
                    volume_name: volume.guest.clone(),
                    read_only: volume.read_only,
                    acquired_at: mvm_core::util::time::utc_now(),
                    relock_volume: None,
                },
            })
        })
        .collect()
}

fn register_attachment(
    request: &AttachmentRequest,
    host_path: String,
    kind: LocalVolumeKind,
    source: VolumeMountSource,
    host_snapshot: Option<HostSnapshotSource>,
) -> Result<AttachmentRecord> {
    // Same policy check the guest agent runs; canonicalizes the guest path.
    let canonical_guest = validate_mount_path(&request.guest_path)
        .with_context(|| format!("guest path {:?} rejected by policy", request.guest_path))?;
    let mut registry = VolumeMountRegistry::load(&request.owner)?;
    let entry = VolumeMountEntry {
        volume_name: request.volume.as_str().to_string(),
        host_path,
        guest_path: canonical_guest,
        read_only: request.access.is_read_only(),
        kind,
        attached_at: mvm_core::util::time::utc_now(),
        source,
        host_snapshot,
    };
    registry.add(entry.clone())?;
    registry.save(&request.owner)?;
    mvm_core::audit_emit!(VmVolumeAdd, vm: &request.owner, "volume={} host={} guest={} ro={}" ,
        entry.volume_name, entry.host_path, entry.guest_path, entry.read_only
    );
    Ok(attachment_record(&request.owner, &entry))
}

fn attachment_record(owner: &str, entry: &VolumeMountEntry) -> AttachmentRecord {
    AttachmentRecord {
        owner: owner.to_string(),
        volume: entry.volume_name.clone(),
        guest_path: entry.guest_path.clone(),
        access: AccessMode::from_read_only(entry.read_only),
        host_path: entry.host_path.clone(),
        source: match entry.source {
            VolumeMountSource::AdHocHost => AttachmentSource::AdHocHost,
            VolumeMountSource::ManagedCatalog | VolumeMountSource::Legacy => {
                AttachmentSource::ManagedCatalog
            }
        },
        host_snapshot: entry
            .host_snapshot
            .as_ref()
            .map(|snapshot| HostSnapshotRecord {
                source_path: snapshot.source_path.clone(),
                fingerprint: snapshot.fingerprint.clone(),
            }),
        attached_at: entry.attached_at.clone(),
    }
}

fn validate_snapshot_source(source_dir: &Path, fingerprint: &str) -> Result<()> {
    if !source_dir.is_absolute() {
        bail!(
            "snapshot source path must be absolute, got {}",
            source_dir.display()
        );
    }
    if !source_dir.is_dir() {
        bail!(
            "snapshot source path {} is not an existing directory",
            source_dir.display()
        );
    }
    validate_snapshot_fingerprint(fingerprint)
}

fn validate_snapshot_fingerprint(fingerprint: &str) -> Result<()> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("host snapshot fingerprint must be 64 hexadecimal characters");
    }
    Ok(())
}

fn validate_snapshot_image(image: &Path) -> Result<()> {
    if !image.is_absolute() {
        bail!("image path must be absolute, got {}", image.display());
    }
    let metadata = std::fs::symlink_metadata(image)
        .with_context(|| format!("image path {} is not an existing file", image.display()))?;
    if !metadata.file_type().is_file() {
        bail!("image path {} is not an existing file", image.display());
    }
    ext4_view::Ext4::load_from_path(image)
        .with_context(|| format!("{} is not a valid ext4 image", image.display()))?;
    Ok(())
}

fn volume_record(
    entry: &LocalVolumeEntry,
    leases: &AttachmentLeaseCatalog,
) -> Result<VolumeRecord> {
    let (source, encryption, host_artifact) = match (&entry.kind, &entry.encryption) {
        (LocalVolumeKind::BlockImage { size_mib }, LocalVolumeEncryption::HostBacked) => (
            VolumeSourceKind::ManagedBlock {
                capacity_mib: *size_mib,
            },
            EncryptionState::HostBacked,
            Some(entry.host_path.clone()),
        ),
        (LocalVolumeKind::BlockImage { size_mib }, LocalVolumeEncryption::MvmManaged(enc)) => (
            VolumeSourceKind::ManagedBlock {
                capacity_mib: *size_mib,
            },
            managed_encryption_state(enc.state),
            (enc.state == LocalVolumeState::Unlocked).then(|| entry.host_path.clone()),
        ),
    };
    // Best-effort lease correlation: a host path whose parent no longer
    // exists cannot hold a live lease, so an unkeyable path reports detached.
    let attached_to = lease::lease_key(Path::new(&entry.host_path))
        .ok()
        .and_then(|key| leases.leases.get(&key).map(|lease| lease.vm_name.clone()));
    Ok(VolumeRecord {
        name: entry.volume_name.clone(),
        source,
        encryption,
        host_artifact,
        created_at: entry.created_at.clone(),
        attached_to,
    })
}

fn managed_encryption_state(state: LocalVolumeState) -> EncryptionState {
    match state {
        LocalVolumeState::Locked => EncryptionState::Locked,
        LocalVolumeState::Unlocked => EncryptionState::Unlocked,
        LocalVolumeState::Unlocking
        | LocalVolumeState::Locking
        | LocalVolumeState::Publishing
        | LocalVolumeState::Restoring => EncryptionState::Recovering,
    }
}

/// Default managed-volume root helper for callers that surface paths (the
/// CLI's `--root` default documentation).
#[must_use]
pub fn default_block_volume_root() -> PathBuf {
    lifecycle::default_mvm_volume_root()
}
