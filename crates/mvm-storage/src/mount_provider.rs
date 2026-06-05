//! `MountProvider` — resolves a mount's *source* into something `VmBackend`
//! can attach. The share mechanism (virtiofs for a path, virtio-blk for a
//! device) stays `VmBackend`'s job; this layer only answers "where do the
//! bytes come from". External sources (S3, Hetzner Volume, NFS) register
//! under their `provider` string without a core-enum edit — the IR's
//! `MountSource::External` (plan 123 B4).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use mvm_core::volume::{VolumeError, VolumeName};
use mvm_sdk::ir::MountSource;

use crate::provider::{StorageProvider, VolumeSpec};

/// A resolved mount source `VmBackend` can attach into a guest. More variants
/// (`BlockDev`, `Fuse`) arrive with their producers — the LUKS block-volume
/// arm (B2 Linux follow-up) and a lazy-FUSE S3 source — so they're not
/// declared until something constructs them.
#[derive(Debug)]
pub enum Mountable {
    /// Host directory; `VmBackend` virtiofs-exports it.
    HostPath(PathBuf),
    /// Guest-side tmpfs of `size_mb`; there is no host source to attach.
    Tmpfs { size_mb: u32 },
}

/// Errors from mount-source resolution.
#[derive(Debug)]
pub enum MountError {
    /// No `MountProvider` is registered for this source's kind. An unknown
    /// external provider fails closed here — never a silent default.
    UnknownFsProvider { kind: String },
    /// A provider's underlying storage operation failed.
    Volume(VolumeError),
    /// A source was routed to a provider that doesn't handle it — a
    /// registration bug, not user input.
    MismatchedSource { provider: &'static str, got: String },
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFsProvider { kind } => {
                write!(f, "no MountProvider registered for source kind {kind:?}")
            }
            Self::Volume(e) => write!(f, "mount storage error: {e}"),
            Self::MismatchedSource { provider, got } => {
                write!(f, "provider {provider} cannot resolve a {got:?} source")
            }
        }
    }
}

impl std::error::Error for MountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Volume(e) => Some(e),
            _ => None,
        }
    }
}

impl From<VolumeError> for MountError {
    fn from(e: VolumeError) -> Self {
        Self::Volume(e)
    }
}

/// Resolves one kind of mount source.
pub trait MountProvider: Send + Sync {
    /// The `MountSource` discriminator this provider handles — `"host_path"`
    /// | `"volume"` | `"tmpfs"`, or an external `provider` string.
    fn kind(&self) -> &str;
    /// Resolve a source into an attachable [`Mountable`].
    fn resolve(&self, src: &MountSource) -> Result<Mountable, MountError>;
    /// Release a previously-resolved mountable (unmount / detach).
    fn release(&self, m: Mountable) -> Result<(), MountError>;
}

/// Discriminator string for a `MountSource`. External sources route by their
/// `provider` field, so a registered external provider is matched by name.
fn source_kind(src: &MountSource) -> &str {
    match src {
        MountSource::Volume { .. } => "volume",
        MountSource::HostPath { .. } => "host_path",
        MountSource::Tmpfs { .. } => "tmpfs",
        MountSource::External { provider, .. } => provider.as_str(),
    }
}

/// Routes each `MountSource` to its registered provider. An unregistered kind
/// fails with [`MountError::UnknownFsProvider`] — no silent default.
#[derive(Default)]
pub struct MountRegistry {
    providers: HashMap<String, Arc<dyn MountProvider>>,
}

impl MountRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider under its `kind()`. A later registration with the
    /// same kind replaces the earlier one.
    pub fn register(&mut self, provider: Arc<dyn MountProvider>) {
        self.providers.insert(provider.kind().to_string(), provider);
    }

    /// Resolve a source by routing to the provider for its kind.
    pub fn resolve(&self, src: &MountSource) -> Result<Mountable, MountError> {
        let kind = source_kind(src);
        match self.providers.get(kind) {
            Some(provider) => provider.resolve(src),
            None => Err(MountError::UnknownFsProvider {
                kind: kind.to_string(),
            }),
        }
    }
}

/// Host-path source: hands back the declared directory for virtiofs export.
pub struct HostPathFs;

impl MountProvider for HostPathFs {
    fn kind(&self) -> &str {
        "host_path"
    }

    fn resolve(&self, src: &MountSource) -> Result<Mountable, MountError> {
        match src {
            MountSource::HostPath { path } => Ok(Mountable::HostPath(PathBuf::from(path))),
            other => Err(MountError::MismatchedSource {
                provider: "host_path",
                got: source_kind(other).to_string(),
            }),
        }
    }

    fn release(&self, _m: Mountable) -> Result<(), MountError> {
        Ok(()) // a host path is borrowed, not mounted — nothing to release.
    }
}

/// Volume source: provisions + attaches through a [`StorageProvider`] and
/// returns its host path. A directory-backed volume (e.g. `LocalStorage`)
/// surfaces as `HostPath`; a block-backed one (the LUKS arm, deferred) will
/// surface as `BlockDev` once that producer exists.
pub struct VolumeFs {
    storage: Arc<dyn StorageProvider>,
}

impl VolumeFs {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self { storage }
    }
}

impl MountProvider for VolumeFs {
    fn kind(&self) -> &str {
        "volume"
    }

    fn resolve(&self, src: &MountSource) -> Result<Mountable, MountError> {
        match src {
            MountSource::Volume { name } => {
                let name = VolumeName::new(name)
                    .map_err(|e| MountError::Volume(VolumeError::InvalidPath(e.to_string())))?;
                let handle = self.storage.provision(&VolumeSpec::new(name))?;
                let attached = self.storage.attach(&handle)?;
                Ok(Mountable::HostPath(attached.host_path().to_path_buf()))
            }
            other => Err(MountError::MismatchedSource {
                provider: "volume",
                got: source_kind(other).to_string(),
            }),
        }
    }

    fn release(&self, _m: Mountable) -> Result<(), MountError> {
        // Detach is keyed off the StorageProvider handle, not the Mountable
        // path; the caller owning the handle drives detach. B4 keeps the
        // borrow model simple — richer release lands with the block arm.
        Ok(())
    }
}

/// Tmpfs source: no host bytes — the guest mounts a tmpfs of the given size.
pub struct TmpfsFs;

impl MountProvider for TmpfsFs {
    fn kind(&self) -> &str {
        "tmpfs"
    }

    fn resolve(&self, src: &MountSource) -> Result<Mountable, MountError> {
        match src {
            MountSource::Tmpfs { size_mb } => Ok(Mountable::Tmpfs { size_mb: *size_mb }),
            other => Err(MountError::MismatchedSource {
                provider: "tmpfs",
                got: source_kind(other).to_string(),
            }),
        }
    }

    fn release(&self, _m: Mountable) -> Result<(), MountError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalStorage;

    fn registry_with_builtins(root: &std::path::Path) -> MountRegistry {
        let mut reg = MountRegistry::new();
        reg.register(Arc::new(HostPathFs));
        reg.register(Arc::new(VolumeFs::new(Arc::new(LocalStorage::new(root)))));
        reg.register(Arc::new(TmpfsFs));
        reg
    }

    #[test]
    fn registry_resolves_host_path() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = registry_with_builtins(tmp.path());
        let src = MountSource::HostPath {
            path: "/srv/data".into(),
        };
        match reg.resolve(&src).unwrap() {
            Mountable::HostPath(p) => assert_eq!(p, PathBuf::from("/srv/data")),
            other => panic!("expected HostPath, got {other:?}"),
        }
    }

    #[test]
    fn registry_resolves_volume_via_storage_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = registry_with_builtins(tmp.path());
        let src = MountSource::Volume {
            name: "scratch".into(),
        };
        match reg.resolve(&src).unwrap() {
            // LocalStorage backs a volume as a directory under its root.
            Mountable::HostPath(p) => {
                assert!(p.is_dir(), "volume must resolve to an existing backing dir");
                assert!(p.starts_with(tmp.path()));
            }
            other => panic!("expected HostPath from LocalStorage, got {other:?}"),
        }
    }

    #[test]
    fn registry_rejects_unknown_external_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = registry_with_builtins(tmp.path());
        let src = MountSource::External {
            provider: "s3".into(),
            config: serde_json::json!({ "bucket": "b" }),
        };
        match reg.resolve(&src) {
            Err(MountError::UnknownFsProvider { kind }) => assert_eq!(kind, "s3"),
            other => panic!("expected UnknownFsProvider, got {other:?}"),
        }
    }

    #[test]
    fn mount_source_external_roundtrips_json() {
        let src = MountSource::External {
            provider: "s3".into(),
            config: serde_json::json!({ "bucket": "b", "prefix": "p/" }),
        };
        let json = serde_json::to_string(&src).unwrap();
        assert!(json.contains("\"kind\":\"external\""));
        let back: MountSource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }
}
