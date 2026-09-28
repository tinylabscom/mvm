//! Strict, secret-free DTOs for the local encrypted-volume service.
//!
//! Every type here is safe to serialize toward a presentation surface: no
//! wrapped key, no ciphertext bytes, no key-derivation material ever appears
//! in these shapes. Inbound types are `deny_unknown_fields` so an unexpected
//! field fails closed instead of being silently dropped.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use mvm_core::domain::volume::VolumeName;
use mvm_runtime::image::RuntimeVolume;
use serde::{Deserialize, Serialize};

use crate::profile::RunProfile;

/// How a guest sees an attachment: read-only (the default everywhere) or
/// read-write (an explicit opt-in gated on the admitted profile).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessMode {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl AccessMode {
    /// `true` when the guest must not write through this attachment.
    #[must_use]
    pub fn is_read_only(self) -> bool {
        matches!(self, AccessMode::ReadOnly)
    }

    /// Build from the registry's `read_only` boolean.
    #[must_use]
    pub fn from_read_only(read_only: bool) -> Self {
        if read_only {
            AccessMode::ReadOnly
        } else {
            AccessMode::ReadWrite
        }
    }
}

/// The machine profile a volume attachment is admitted under.
///
/// Whether the attachment may be read-write is the profile table's decision —
/// [`ProfileGrants::writable_disk_images`](crate::profile::ProfileGrants), the
/// same grant a `HOST.img:/GUEST:SIZE:rw` disk image is checked against. Every
/// managed volume reaches the guest as its own ext4 block image: a managed
/// block volume is one, and a registered host directory is snapshotted into a
/// private image copy before it is attached. So a guest writing to a managed
/// volume writes into that image, never into the host filesystem.
///
/// The default names no profile, and so does a name no profile answers to;
/// both refuse a writable attachment rather than guessing at a preset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmittedProfile(Option<RunProfile>);

impl AdmittedProfile {
    /// Admit under `profile`.
    #[must_use]
    pub const fn new(profile: RunProfile) -> Self {
        Self(Some(profile))
    }

    /// Admit under the profile a launch request or stored machine spec
    /// carries by name.
    #[must_use]
    pub fn from_profile_name(profile: &str) -> Self {
        Self(RunProfile::from_name(profile))
    }

    /// The admitted profile, when the name resolved to one.
    #[must_use]
    pub const fn profile(self) -> Option<RunProfile> {
        self.0
    }

    /// `true` when this profile may attach a volume read-write.
    #[must_use]
    pub fn permits_read_write(self) -> bool {
        self.0
            .is_some_and(|profile| profile.grants().writable_disk_images)
    }

    /// Refuse a read-write `subject` unless this profile permits it. Every
    /// writable-volume refusal is worded here, so registration and launch
    /// say the same thing.
    pub fn require_read_write(self, subject: &str) -> Result<()> {
        if self.permits_read_write() {
            return Ok(());
        }
        let granting = RunProfile::ALL
            .into_iter()
            .filter(|profile| profile.grants().writable_disk_images)
            .map(RunProfile::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        let admitted = match self.0 {
            Some(profile) => format!("profile {:?}", profile.as_str()),
            None => "no recognised profile".to_string(),
        };
        bail!(
            "{subject} refused: {admitted} does not permit writable volumes (a writable \
             managed volume is a disk image the guest writes into; profiles {granting} \
             grant it)"
        )
    }
}

impl From<RunProfile> for AdmittedProfile {
    fn from(profile: RunProfile) -> Self {
        Self::new(profile)
    }
}

/// The local artifact shape backing a volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum VolumeSourceKind {
    /// mvm-managed portable ext4 image, authenticated ciphertext while locked.
    ManagedBlock { capacity_mib: u32 },
    /// Managed catalog directory relying on encrypted host storage.
    ManagedDirectory,
    /// Operator-supplied host directory relying on encrypted host storage.
    AdHocHostDirectory,
}

/// Lifecycle position of a volume's encryption, collapsed to what a
/// presentation surface needs. Transitional catalog states surface as
/// [`EncryptionState::Recovering`]; the recovery pass drives them back to a
/// terminal state before any new lifecycle operation proceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionState {
    /// At-rest encryption comes from the host filesystem or block device.
    HostBacked,
    /// Sealed: only the authenticated ciphertext archive exists on disk.
    Locked,
    /// Explicitly unlocked: the plaintext attachment artifact is materialized.
    Unlocked,
    /// An interrupted lifecycle transition awaiting crash recovery.
    Recovering,
}

/// One managed local volume, described without any key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeRecord {
    /// Logical volume identity.
    pub name: String,
    /// Local artifact shape.
    pub source: VolumeSourceKind,
    /// Encryption lifecycle position.
    pub encryption: EncryptionState,
    /// Host path of the (plaintext) attachment artifact. Present only for
    /// host-backed volumes and unlocked managed volumes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_artifact: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Owner VM currently holding an attachment lease on this volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_to: Option<String>,
}

/// Request to create a managed encrypted block volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateBlockVolumeRequest {
    pub(crate) name: VolumeName,
    pub(crate) capacity_mib: u32,
    pub(crate) root: Option<PathBuf>,
}

impl CreateBlockVolumeRequest {
    /// Start building a request for `name`.
    pub fn builder(name: &str) -> Result<CreateBlockVolumeRequestBuilder> {
        let name =
            VolumeName::new(name).with_context(|| format!("invalid volume name {name:?}"))?;
        Ok(CreateBlockVolumeRequestBuilder {
            name,
            capacity_mib: None,
            root: None,
        })
    }

    /// Logical volume name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Requested ext4 capacity in MiB.
    #[must_use]
    pub fn capacity_mib(&self) -> u32 {
        self.capacity_mib
    }
}

/// Builder for [`CreateBlockVolumeRequest`].
#[derive(Debug, Clone)]
pub struct CreateBlockVolumeRequestBuilder {
    name: VolumeName,
    capacity_mib: Option<u32>,
    root: Option<PathBuf>,
}

impl CreateBlockVolumeRequestBuilder {
    /// Capacity of the new ext4 block volume, in MiB. Required, non-zero.
    #[must_use]
    pub fn capacity_mib(mut self, capacity_mib: u32) -> Self {
        self.capacity_mib = Some(capacity_mib);
        self
    }

    /// Root directory for the volume's encrypted state. Defaults to the
    /// managed volume root under the mvm home.
    #[must_use]
    pub fn root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Validate and build the request.
    pub fn build(self) -> Result<CreateBlockVolumeRequest> {
        let capacity_mib = self
            .capacity_mib
            .context("block volume capacity is required")?;
        if capacity_mib == 0 {
            bail!("volume capacity must be greater than zero");
        }
        if let Some(root) = &self.root
            && !root.is_absolute()
        {
            bail!(
                "managed volume root must be absolute, got {}",
                root.display()
            );
        }
        Ok(CreateBlockVolumeRequest {
            name: self.name,
            capacity_mib,
            root: self.root,
        })
    }
}

/// Request to register a managed volume as a typed attachment for a VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRequest {
    pub(crate) owner: String,
    pub(crate) volume: VolumeName,
    pub(crate) guest_path: String,
    pub(crate) access: AccessMode,
    pub(crate) profile: AdmittedProfile,
}

impl AttachmentRequest {
    /// Start building an attachment of `volume` into `owner`.
    pub fn builder(owner: &str, volume: &str) -> Result<AttachmentRequestBuilder> {
        mvm_core::naming::validate_vm_name(owner)
            .with_context(|| format!("invalid VM name {owner:?}"))?;
        let volume =
            VolumeName::new(volume).with_context(|| format!("invalid volume name {volume:?}"))?;
        Ok(AttachmentRequestBuilder {
            owner: owner.to_string(),
            volume,
            guest_path: None,
            access: AccessMode::ReadOnly,
            profile: AdmittedProfile::default(),
        })
    }
}

/// Builder for [`AttachmentRequest`]. Attachments default to read-only with no
/// admitted profile; a writable attachment must name a profile that grants
/// writable disk images.
#[derive(Debug, Clone)]
pub struct AttachmentRequestBuilder {
    owner: String,
    volume: VolumeName,
    guest_path: Option<String>,
    access: AccessMode,
    profile: AdmittedProfile,
}

impl AttachmentRequestBuilder {
    /// Guest mount point. Must fall under the mount allow-roots
    /// (`/mnt`, `/data`, `/work`); validated at build time.
    #[must_use]
    pub fn guest_path(mut self, guest_path: &str) -> Self {
        self.guest_path = Some(guest_path.to_string());
        self
    }

    /// Requested access mode (defaults to read-only).
    #[must_use]
    pub fn access(mut self, access: AccessMode) -> Self {
        self.access = access;
        self
    }

    /// Admitted profile of the workload (defaults to none, which refuses
    /// read-write).
    #[must_use]
    pub fn profile(mut self, profile: impl Into<AdmittedProfile>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Validate and build the request. Refuses guest paths outside the mount
    /// allow-roots, and read-write access under a profile that does not grant
    /// writable disk images.
    pub fn build(self) -> Result<AttachmentRequest> {
        let raw_guest = self
            .guest_path
            .context("attachment guest path is required")?;
        let guest_path = mvm_core::crypto::policy::validate_mount_path(&raw_guest)
            .with_context(|| format!("guest path {raw_guest:?} rejected by policy"))?;
        if !self.access.is_read_only() {
            self.profile.require_read_write(&format!(
                "read-write attachment of volume {:?}",
                self.volume.as_str()
            ))?;
        }
        Ok(AttachmentRequest {
            owner: self.owner,
            volume: self.volume,
            guest_path,
            access: self.access,
            profile: self.profile,
        })
    }
}

/// Origin of a registered attachment's host path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentSource {
    /// The path must keep matching an encrypted local-catalog entry.
    ManagedCatalog,
    /// Operator-supplied host directory; host encryption is rechecked
    /// immediately before every launch.
    AdHocHost,
}

/// Source identity retained for an ad-hoc host directory snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSnapshotRecord {
    pub source_path: String,
    pub fingerprint: String,
}

/// One registered attachment, described without any key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentRecord {
    /// Owner VM the attachment is registered for.
    pub owner: String,
    /// Logical volume identity.
    pub volume: String,
    /// Guest mount point.
    pub guest_path: String,
    /// Access mode presented to the guest.
    pub access: AccessMode,
    /// Host path backing the attachment.
    pub host_path: String,
    /// Origin of the host path.
    pub source: AttachmentSource,
    /// Present when `host_path` is a materialized image refreshed from a host
    /// directory at machine start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_snapshot: Option<HostSnapshotRecord>,
    /// RFC 3339 registration timestamp.
    pub attached_at: String,
}

/// When to decrypt a locked managed volume for a launch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnlockPolicy {
    /// Fail closed: a locked attachment refuses the launch. The operator
    /// unlocks explicitly and the volume stays unlocked after release.
    #[default]
    RequireUnlocked,
    /// Unlock just in time under the launch's lifecycle lock, and re-seal the
    /// volume automatically after its final lease release.
    JustInTime,
}

/// Request to resolve an owner's registered attachments and take exclusive
/// leases for a launch.
#[derive(Debug)]
pub struct LaunchLeaseRequest {
    pub(crate) owner: String,
    pub(crate) explicit: Vec<RuntimeVolume>,
    pub(crate) profile: AdmittedProfile,
    pub(crate) unlock: UnlockPolicy,
}

impl LaunchLeaseRequest {
    /// Start building a launch-lease request for `owner`.
    pub fn builder(owner: &str) -> Result<LaunchLeaseRequestBuilder> {
        mvm_core::naming::validate_vm_name(owner)
            .with_context(|| format!("invalid VM name {owner:?}"))?;
        Ok(LaunchLeaseRequestBuilder {
            owner: owner.to_string(),
            explicit: Vec::new(),
            profile: AdmittedProfile::default(),
            unlock: UnlockPolicy::RequireUnlocked,
        })
    }
}

/// Builder for [`LaunchLeaseRequest`].
#[derive(Debug)]
pub struct LaunchLeaseRequestBuilder {
    owner: String,
    explicit: Vec<RuntimeVolume>,
    profile: AdmittedProfile,
    unlock: UnlockPolicy,
}

impl LaunchLeaseRequestBuilder {
    /// Explicit (non-registered) volumes the launch already carries.
    #[must_use]
    pub fn explicit_volumes(mut self, explicit: Vec<RuntimeVolume>) -> Self {
        self.explicit = explicit;
        self
    }

    /// Admitted profile of the launch (defaults to none, which refuses
    /// writable attachments).
    #[must_use]
    pub fn profile(mut self, profile: impl Into<AdmittedProfile>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Unlock policy for locked managed volumes (defaults to fail-closed).
    #[must_use]
    pub fn unlock(mut self, unlock: UnlockPolicy) -> Self {
        self.unlock = unlock;
        self
    }

    /// Build the request.
    #[must_use]
    pub fn build(self) -> LaunchLeaseRequest {
        LaunchLeaseRequest {
            owner: self.owner,
            explicit: self.explicit,
            profile: self.profile,
            unlock: self.unlock,
        }
    }
}

/// Result of releasing an owner's attachment leases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseOutcome {
    /// Number of leases removed.
    pub released: usize,
    /// Managed volumes re-sealed because the service had unlocked them just
    /// in time for the launch.
    pub relocked: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mode_roundtrips_and_defaults_read_only() {
        assert_eq!(AccessMode::default(), AccessMode::ReadOnly);
        assert!(AccessMode::ReadOnly.is_read_only());
        assert!(!AccessMode::ReadWrite.is_read_only());
        assert_eq!(AccessMode::from_read_only(true), AccessMode::ReadOnly);
        assert_eq!(AccessMode::from_read_only(false), AccessMode::ReadWrite);
        let json = serde_json::to_string(&AccessMode::ReadWrite).unwrap();
        assert_eq!(json, "\"read-write\"");
        assert_eq!(
            serde_json::from_str::<AccessMode>(&json).unwrap(),
            AccessMode::ReadWrite
        );
    }

    /// The attachment gate reads the profile table's writable-disk grant:
    /// every profile that grants `writable_disk_images` for a `--mount` disk
    /// image grants a writable managed volume, and no other does.
    #[test]
    fn admitted_profile_follows_the_writable_disk_grant() {
        for profile in RunProfile::ALL {
            let admitted = AdmittedProfile::from_profile_name(profile.as_str());
            assert_eq!(admitted, AdmittedProfile::new(profile));
            assert_eq!(admitted.profile(), Some(profile));
            assert_eq!(
                admitted.permits_read_write(),
                profile.grants().writable_disk_images,
                "{}",
                profile.as_str()
            );
        }
        assert!(AdmittedProfile::new(RunProfile::Standard).permits_read_write());
        assert!(AdmittedProfile::new(RunProfile::Dev).permits_read_write());
        assert!(AdmittedProfile::new(RunProfile::Permissive).permits_read_write());
        assert!(!AdmittedProfile::new(RunProfile::Restrictive).permits_read_write());
    }

    /// No profile, and a name no profile answers to, refuse a writable
    /// attachment rather than falling back to a preset.
    #[test]
    fn an_unrecognised_or_missing_profile_refuses_read_write() {
        assert_eq!(AdmittedProfile::default().profile(), None);
        assert!(!AdmittedProfile::default().permits_read_write());
        for name in ["prod", "sealed", "dev-mode", ""] {
            let admitted = AdmittedProfile::from_profile_name(name);
            assert_eq!(admitted.profile(), None, "{name:?}");
            let message = admitted
                .require_read_write("attachment")
                .expect_err("an unknown profile grants nothing writable")
                .to_string();
            assert!(message.contains("no recognised profile"), "{message}");
        }
    }

    /// The refusal names the profile that refused and the profiles that
    /// grant a writable disk image, read off the table.
    #[test]
    fn the_read_write_refusal_names_the_granting_profiles() {
        let message = AdmittedProfile::new(RunProfile::Restrictive)
            .require_read_write("read-write attachment of volume \"work\"")
            .expect_err("restrictive grants no writable volume")
            .to_string();
        assert!(message.contains("does not permit writable"), "{message}");
        assert!(message.contains("profile \"restrictive\""), "{message}");
        assert!(message.contains("disk image"), "{message}");
        assert!(
            message.contains("profiles standard, dev, permissive grant it"),
            "{message}"
        );
        AdmittedProfile::new(RunProfile::Standard)
            .require_read_write("attachment")
            .expect("standard grants a writable disk image");
    }

    #[test]
    fn create_request_requires_nonzero_capacity_and_absolute_root() {
        let err = CreateBlockVolumeRequest::builder("work")
            .unwrap()
            .capacity_mib(0)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
        let err = CreateBlockVolumeRequest::builder("work")
            .unwrap()
            .capacity_mib(16)
            .root("relative/root")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("must be absolute"));
        let ok = CreateBlockVolumeRequest::builder("work")
            .unwrap()
            .capacity_mib(16)
            .build()
            .unwrap();
        assert_eq!(ok.name(), "work");
        assert_eq!(ok.capacity_mib(), 16);
    }

    #[test]
    fn create_request_rejects_invalid_volume_name() {
        assert!(CreateBlockVolumeRequest::builder("Not-Valid!").is_err());
    }

    #[test]
    fn attachment_request_defaults_read_only_and_validates_guest_path() {
        let req = AttachmentRequest::builder("vm-1", "work")
            .unwrap()
            .guest_path("/data/work")
            .build()
            .unwrap();
        assert_eq!(req.access, AccessMode::ReadOnly);
        assert_eq!(req.guest_path, "/data/work");

        let err = AttachmentRequest::builder("vm-1", "work")
            .unwrap()
            .guest_path("/etc/passwd")
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("rejected by policy"), "got: {err}");
    }

    #[test]
    fn attachment_request_refuses_read_write_without_a_granting_profile() {
        let writable = |profile: Option<RunProfile>| {
            let builder = AttachmentRequest::builder("vm-1", "work")
                .unwrap()
                .guest_path("/data/work")
                .access(AccessMode::ReadWrite);
            match profile {
                Some(profile) => builder.profile(profile).build(),
                None => builder.build(),
            }
        };
        for refused in [None, Some(RunProfile::Restrictive)] {
            let err = writable(refused).unwrap_err();
            assert!(
                err.to_string().contains("does not permit writable"),
                "{refused:?}: {err}"
            );
        }
        for granted in [
            RunProfile::Standard,
            RunProfile::Dev,
            RunProfile::Permissive,
        ] {
            let ok = writable(Some(granted)).unwrap();
            assert_eq!(ok.access, AccessMode::ReadWrite);
            assert_eq!(ok.profile, AdmittedProfile::new(granted));
        }
    }

    #[test]
    fn volume_record_serde_is_strict_and_roundtrips() {
        let record = VolumeRecord {
            name: "work".to_string(),
            source: VolumeSourceKind::ManagedBlock { capacity_mib: 16 },
            encryption: EncryptionState::Locked,
            host_artifact: None,
            created_at: "2026-08-02T00:00:00Z".to_string(),
            attached_to: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<VolumeRecord>(&json).unwrap(), record);

        let mut value = serde_json::to_value(&record).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("wrapped_key".to_string(), serde_json::json!("smuggled"));
        let err = serde_json::from_value::<VolumeRecord>(value).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn attachment_record_roundtrips_host_snapshot_and_defaults_it_for_legacy_json() {
        let record = AttachmentRecord {
            owner: "vm-1".to_string(),
            volume: "work".to_string(),
            guest_path: "/data/work".to_string(),
            access: AccessMode::ReadOnly,
            host_path: "/cache/work.ext4".to_string(),
            source: AttachmentSource::AdHocHost,
            host_snapshot: Some(HostSnapshotRecord {
                source_path: "/host/work".to_string(),
                fingerprint: "a".repeat(64),
            }),
            attached_at: "2026-09-03T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(
            serde_json::from_str::<AttachmentRecord>(&json).unwrap(),
            record
        );

        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy.as_object_mut().unwrap().remove("host_snapshot");
        assert_eq!(
            serde_json::from_value::<AttachmentRecord>(legacy)
                .unwrap()
                .host_snapshot,
            None
        );
    }

    #[test]
    fn launch_lease_request_defaults_fail_closed() {
        let request = LaunchLeaseRequest::builder("vm-1").unwrap().build();
        assert_eq!(request.profile, AdmittedProfile::default());
        assert!(!request.profile.permits_read_write());
        assert_eq!(request.unlock, UnlockPolicy::RequireUnlocked);
        assert!(request.explicit.is_empty());
    }
}
