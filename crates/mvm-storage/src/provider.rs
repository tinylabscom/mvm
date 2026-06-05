//! `StorageProvider` — host-side volume *lifecycle* (provision / attach /
//! detach; `snapshot` lands with plan 123 B3), distinct from the data-plane
//! [`VolumeBackend`](crate::VolumeBackend).
//!
//! `VolumeBackend` moves bytes in and out of a volume's namespace.
//! `StorageProvider` owns the volume as a *host* resource: it creates the
//! backing store, makes it attachable (a host path `VmBackend` virtio-fs /
//! virtio-blk-exports into a guest), and tears it down. The encrypted arm
//! (B2) and the content-addressed / snapshot arms (B3) implement this same
//! trait. mvmd's object-store / encrypted *data-plane* backends are a
//! separate layer and stay in mvmd (plan 45 §D5) — this trait does not
//! re-home them.

use std::path::{Path, PathBuf};

use mvm_core::volume::{VolumeError, VolumeName};

/// Declarative request to provision a volume. Grows per task: B2 adds an
/// encryption arm, B3 adds content-addressing / COW. B1 needs only identity.
#[derive(Debug, Clone)]
pub struct VolumeSpec {
    name: VolumeName,
}

impl VolumeSpec {
    pub fn new(name: VolumeName) -> Self {
        Self { name }
    }

    pub fn name(&self) -> &VolumeName {
        &self.name
    }
}

/// Persistent identity of a provisioned volume, stable across attach/detach
/// cycles. `backing` is the host path of the backing store — a directory for
/// [`LocalStorage`], a LUKS2 image for the encrypted arm (B2).
#[derive(Debug, Clone)]
pub struct VolumeHandle {
    name: VolumeName,
    backing: PathBuf,
}

impl VolumeHandle {
    pub fn name(&self) -> &VolumeName {
        &self.name
    }

    pub fn backing_path(&self) -> &Path {
        &self.backing
    }
}

/// A volume made usable. `host_path` is where bytes live *while attached* —
/// for [`LocalStorage`] that's the backing dir itself; for the encrypted arm
/// it's the decrypted mountpoint. Detach consumes this by value so a stale
/// path can't be used after teardown closes the mapper.
#[derive(Debug)]
pub struct AttachedVolume {
    name: VolumeName,
    host_path: PathBuf,
}

impl AttachedVolume {
    pub fn name(&self) -> &VolumeName {
        &self.name
    }

    /// Host path `VmBackend` exports into the guest (virtiofs for a dir).
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }
}

/// Host-side volume lifecycle. Sync on purpose: these are cold control-plane
/// ops (mkdir, `cryptsetup` open/close), not the hot data path that
/// [`VolumeBackend`](crate::VolumeBackend) serves.
pub trait StorageProvider: Send + Sync {
    /// Stable identifier for metrics / audit / error messages.
    fn kind(&self) -> &'static str;

    /// Create the backing store. Idempotent — provisioning an already-present
    /// volume returns its handle rather than failing.
    fn provision(&self, spec: &VolumeSpec) -> Result<VolumeHandle, VolumeError>;

    /// Make a provisioned volume usable, returning its live host path.
    fn attach(&self, handle: &VolumeHandle) -> Result<AttachedVolume, VolumeError>;

    /// Release an attachment. Consumes the `AttachedVolume` so the path it
    /// carries can't be used after teardown.
    fn detach(&self, attached: AttachedVolume) -> Result<(), VolumeError>;
}

/// Plain-directory `StorageProvider`. Each volume is a subdirectory under
/// `root`; attach hands back that directory (virtiofs exports it). No at-rest
/// encryption — that's the B2 encrypted arm.
pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl StorageProvider for LocalStorage {
    fn kind(&self) -> &'static str {
        "local"
    }

    fn provision(&self, spec: &VolumeSpec) -> Result<VolumeHandle, VolumeError> {
        let backing = self.root.join(spec.name().as_str());
        std::fs::create_dir_all(&backing)?;
        Ok(VolumeHandle {
            name: spec.name().clone(),
            backing,
        })
    }

    fn attach(&self, handle: &VolumeHandle) -> Result<AttachedVolume, VolumeError> {
        Ok(AttachedVolume {
            name: handle.name.clone(),
            host_path: handle.backing.clone(),
        })
    }

    fn detach(&self, _attached: AttachedVolume) -> Result<(), VolumeError> {
        // A local volume's backing dir is just a directory — nothing to
        // unmount. Dropping `attached` is the whole teardown. (The encrypted
        // arm closes its cryptsetup mapper here — B2.)
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_storage_provision_attach_roundtrip_detach() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(tmp.path());
        let spec = VolumeSpec::new(VolumeName::new("scratch").unwrap());

        let handle = storage.provision(&spec).unwrap();
        assert_eq!(handle.name().as_str(), "scratch");
        assert!(
            handle.backing_path().is_dir(),
            "provision must create the backing store"
        );

        let attached = storage.attach(&handle).unwrap();
        // Round-trip real bytes through the attached host path — proves the
        // volume is a genuine writable location, not just a returned struct.
        let file = attached.host_path().join("hello.txt");
        std::fs::write(&file, b"volume bytes").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"volume bytes");

        storage.detach(attached).unwrap();
        // Bytes survive detach for local (nothing was unmounted/torn down).
        assert_eq!(std::fs::read(&file).unwrap(), b"volume bytes");
    }
}
