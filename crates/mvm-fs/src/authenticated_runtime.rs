//! Offline runtime attachments authenticated by the current image-set train.
//! This authority does not apply to independently published CLI runtime assets.

use std::path::{Path, PathBuf};

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ArtifactFormat, HostProtocolSupport, ImageLock, ImageSetManifest, ImageSetRole, MemberArtifact,
    MemberTarget, read_cached_image_set_root,
};
use mvm_core::packs::{PackRevocationChecker, Sha256Hex};
use mvm_core::vm_backend::{VmStartConfig, VmVolume};

use crate::release_archive::{INITRAMFS_MEMBERS, OVERLAY_MEMBERS, SIDECAR_MEMBERS};
use crate::runtime_archive_cache::{RuntimeArchiveError, file_identity, snapshot};

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedRuntimeError {
    #[error(
        "offline runtime publisher proof refused: {0}; prepare the accepted published image set before offline boot"
    )]
    Proof(String),
    #[error("offline runtime attachment refused: {0}")]
    Refused(String),
    #[error(transparent)]
    Archive(#[from] RuntimeArchiveError),
    #[error(transparent)]
    Extract(#[from] crate::release_archive::ReleaseArchiveError),
    #[error(transparent)]
    Overlay(#[from] crate::overlay::OverlayError),
    #[error(transparent)]
    Sidecar(#[from] crate::sdk_sidecar::SdkSidecarError),
    #[error(transparent)]
    Initramfs(#[from] crate::initramfs::InitramfsError),
    #[error("offline runtime attachment I/O: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, AuthenticatedRuntimeError>;

/// Explicit accepted authority and target. There is no downloader or developer
/// fallback, and a revocation checker is required even on a warm cache.
pub struct RuntimeAttachmentRequest<'a> {
    lock: &'a ImageLock,
    host: &'a HostProtocolSupport,
    revocations: &'a dyn PackRevocationChecker,
    arch: GuestArch,
    sidecar: Option<GuestLibc>,
    proof_cache: PathBuf,
    archive_cache: PathBuf,
}

impl<'a> RuntimeAttachmentRequest<'a> {
    pub fn new(
        lock: &'a ImageLock,
        host: &'a HostProtocolSupport,
        revocations: &'a dyn PackRevocationChecker,
        arch: GuestArch,
    ) -> Self {
        Self {
            lock,
            host,
            revocations,
            arch,
            sidecar: None,
            proof_cache: mvm_core::image_set::image_set_root_proof_cache(),
            archive_cache: crate::runtime_archive_cache::runtime_archive_cache(),
        }
    }

    pub fn with_sidecar(mut self, libc: GuestLibc) -> Self {
        self.sidecar = Some(libc);
        self
    }

    pub fn with_caches(mut self, proof_cache: PathBuf, archive_cache: PathBuf) -> Self {
        self.proof_cache = proof_cache;
        self.archive_cache = archive_cache;
        self
    }
}

#[derive(Debug)]
struct ExtractedMember {
    // Ownership keeps the exact materialized files alive through backend use.
    stage: tempfile::TempDir,
    role: ImageSetRole,
    artifact: MemberArtifact,
}

#[derive(Debug)]
struct AttachmentFile {
    path: PathBuf,
    sha256: Sha256Hex,
    size: u64,
}

impl AttachmentFile {
    fn from_extracted(path: PathBuf) -> Result<Self> {
        let (sha256, size) = file_identity(&path)?;
        Ok(Self { path, sha256, size })
    }

    fn verify(&self, selected: Option<&str>) -> Result<()> {
        if selected.map(Path::new) != Some(self.path.as_path())
            || file_identity(&self.path)? != (self.sha256.clone(), self.size)
        {
            return Err(AuthenticatedRuntimeError::Refused(
                "missing or substituted final runtime file".into(),
            ));
        }
        Ok(())
    }

    fn path_string(&self) -> Result<String> {
        self.path.to_str().map(str::to_owned).ok_or_else(|| {
            AuthenticatedRuntimeError::Refused("attachment path is not UTF-8".into())
        })
    }
}

/// Sealed evidence binding final attachments to authenticated source archives.
/// Keep this owner alive for the entire period the backend may open the paths.
/// No public constructor accepts caller hashes, extracted caches or versions.
#[derive(Debug)]
pub struct AuthenticatedRuntimeAttachments {
    root: Sha256Hex,
    arch: GuestArch,
    sources: Vec<ExtractedMember>,
    overlay: AttachmentFile,
    verity: AttachmentFile,
    roothash: String,
    version: String,
    initramfs: AttachmentFile,
    sidecar: Option<AttachmentFile>,
}

impl AuthenticatedRuntimeAttachments {
    pub fn open(request: &RuntimeAttachmentRequest<'_>) -> Result<Self> {
        if request.sidecar == Some(GuestLibc::Unknown) {
            return Err(AuthenticatedRuntimeError::Refused(
                "unknown SDK libc".into(),
            ));
        }
        let root = read_cached_image_set_root(
            &request.proof_cache,
            request.lock,
            request.host,
            Some(request.revocations),
        )
        .map_err(|error| AuthenticatedRuntimeError::Proof(format!("{error:#}")))?;
        Self::materialize(root.manifest(), root.manifest_sha256(), request)
    }

    fn materialize(
        manifest: &ImageSetManifest,
        root: &Sha256Hex,
        request: &RuntimeAttachmentRequest<'_>,
    ) -> Result<Self> {
        let overlay = extract_member(
            manifest,
            request,
            ImageSetRole::RuntimeOverlay,
            &OVERLAY_MEMBERS,
        )?;
        crate::overlay::verify_overlay_dir_integrity(overlay.stage.path())?;
        let resolved = crate::overlay::read_overlay_artifact_from_dir(
            overlay.stage.path(),
            &request.arch.to_string(),
        )?;
        crate::overlay::validate_overlay_payload(&resolved.overlay_ext4)?;
        let image = AttachmentFile::from_extracted(resolved.overlay_ext4)?;
        let verity = AttachmentFile::from_extracted(resolved.sidecar)?;
        let initramfs = extract_member(
            manifest,
            request,
            ImageSetRole::Initramfs,
            &INITRAMFS_MEMBERS,
        )?;
        let initrd = crate::initramfs::read_initramfs_artifact_from_dir(initramfs.stage.path())?;
        let expected_hash = std::fs::read_to_string(&initrd.hash_path)?;
        let expected_size = std::fs::read_to_string(&initrd.size_path)?;
        if crate::initramfs::gunzipped_sha256(&initrd.image_path)? != expected_hash.trim()
            || expected_size.trim().parse::<u64>().ok()
                != Some(std::fs::metadata(&initrd.image_path)?.len())
        {
            return Err(AuthenticatedRuntimeError::Refused(
                "initramfs hash or size mismatch".into(),
            ));
        }
        let initrd = AttachmentFile::from_extracted(initrd.image_path)?;
        let mut sources = vec![overlay, initramfs];
        let sidecar = if let Some(libc) = request.sidecar {
            let member = extract_member(
                manifest,
                request,
                ImageSetRole::SdkSidecar(libc),
                &SIDECAR_MEMBERS,
            )?;
            crate::sdk_sidecar::verify_sidecar_dir_integrity(member.stage.path())?;
            let path = member
                .stage
                .path()
                .join(crate::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE);
            crate::sdk_sidecar::validate_sidecar_payload(&path, libc)?;
            let file = AttachmentFile::from_extracted(path)?;
            sources.push(member);
            Some(file)
        } else {
            None
        };
        Ok(Self {
            root: root.clone(),
            arch: request.arch,
            sources,
            overlay: image,
            verity,
            roothash: resolved.roothash,
            version: resolved.version,
            initramfs: initrd,
            sidecar,
        })
    }

    pub fn root(&self) -> &Sha256Hex {
        &self.root
    }

    /// Signed source declarations for audit, not constructors or mutable state.
    pub fn sources(&self) -> impl Iterator<Item = (ImageSetRole, &MemberArtifact)> {
        self.sources
            .iter()
            .map(|source| (source.role, &source.artifact))
    }

    /// Populate only runtime fields. Image, plan and host policy admission are
    /// separate checks; call `verify_config` at the final backend boundary.
    pub fn attach(&self, config: &mut VmStartConfig) -> Result<()> {
        if config
            .volumes
            .iter()
            .any(|v| v.guest == mvm_core::plan::SDK_SIDECAR_GUEST_PATH)
        {
            return Err(AuthenticatedRuntimeError::Refused(
                "SDK attachment already present".into(),
            ));
        }
        config.runtime_overlay_path = Some(self.overlay.path_string()?);
        config.runtime_overlay_verity_path = Some(self.verity.path_string()?);
        config.runtime_overlay_roothash = Some(self.roothash.clone());
        config.runtime_overlay_version = Some(self.version.clone());
        config.initrd_path = Some(self.initramfs.path_string()?);
        if let Some(sidecar) = &self.sidecar {
            config.volumes.push(VmVolume {
                host: sidecar.path_string()?,
                guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
                read_only: true,
                ..Default::default()
            });
        }
        self.verify_config(config, &self.root, self.arch)
    }

    /// Rehash the exact final paths, and bind this evidence to the image gate's
    /// accepted root and architecture. The caller separately enforces whether
    /// the admitted plan requires a sidecar and which libc it requires.
    pub fn verify_config(
        &self,
        config: &VmStartConfig,
        accepted_root: &Sha256Hex,
        arch: GuestArch,
    ) -> Result<()> {
        if accepted_root != &self.root
            || arch != self.arch
            || config.runtime_overlay_roothash.as_deref() != Some(&self.roothash)
            || config.runtime_overlay_version.as_deref() != Some(&self.version)
        {
            return Err(AuthenticatedRuntimeError::Refused(
                "root, target, version or roothash mismatch".into(),
            ));
        }
        self.overlay
            .verify(config.runtime_overlay_path.as_deref())?;
        self.verity
            .verify(config.runtime_overlay_verity_path.as_deref())?;
        self.initramfs.verify(config.initrd_path.as_deref())?;
        let attached: Vec<_> = config
            .volumes
            .iter()
            .filter(|v| v.guest == mvm_core::plan::SDK_SIDECAR_GUEST_PATH)
            .collect();
        match (&self.sidecar, attached.as_slice()) {
            (None, []) => Ok(()),
            (Some(sidecar), [volume])
                if volume.read_only && !volume.encrypted && volume.materialized_image.is_none() =>
            {
                sidecar.verify(Some(&volume.host))
            }
            _ => Err(AuthenticatedRuntimeError::Refused(
                "missing, duplicate or substituted SDK attachment".into(),
            )),
        }
    }
}

fn extract_member(
    manifest: &ImageSetManifest,
    request: &RuntimeAttachmentRequest<'_>,
    role: ImageSetRole,
    expected: &[&str],
) -> Result<ExtractedMember> {
    let artifact = select_archive(manifest, role, request.arch)?.clone();
    let archive = snapshot(&request.archive_cache, &artifact)?;
    let stage = tempfile::tempdir()?;
    crate::release_archive::extract_release_archive(archive.path(), stage.path(), expected)?;
    Ok(ExtractedMember {
        stage,
        role,
        artifact,
    })
}

fn select_archive(
    manifest: &ImageSetManifest,
    role: ImageSetRole,
    arch: GuestArch,
) -> Result<&MemberArtifact> {
    let members: Vec<_> = manifest
        .members
        .iter()
        .filter(|member| {
            member.role == role
                && member.target == MemberTarget::Arch(arch)
                && member.build_mode.is_none()
        })
        .collect();
    let [member] = members.as_slice() else {
        return Err(AuthenticatedRuntimeError::Refused(format!(
            "expected one production {role}/{arch} member"
        )));
    };
    let [artifact] = member.artifacts.as_slice() else {
        return Err(AuthenticatedRuntimeError::Refused(format!(
            "expected one {role}/{arch} archive"
        )));
    };
    if artifact.format != ArtifactFormat::TarGz {
        return Err(AuthenticatedRuntimeError::Refused(format!(
            "expected tar.gz for {role}/{arch}"
        )));
    }
    Ok(artifact)
}

#[cfg(test)]
#[path = "authenticated_runtime_tests.rs"]
mod tests;
