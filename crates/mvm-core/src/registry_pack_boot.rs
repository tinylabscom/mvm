//! Authenticated built-pack boot contracts, shared by clients and host admission.
//!
//! A root proof authenticates member declarations, not files. Every config check
//! hashes the actual selected files against those declarations. This module does
//! not acquire artifacts or start a backend. The only revocation authority it
//! accepts for the base image set is the host's applied, authenticated
//! image-set list; the registry-pack feed is a different authority.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::arch::GuestArch;
use crate::image_set::{
    ArtifactFormat, BackendImageSupport, HostProtocolSupport, ImageSetManifest, MemberArtifact,
    WorkloadImageProfile, image_set_root_proof_cache, image_train_lock, read_cached_image_set_root,
    select_workload_image,
};
use crate::image_set_revocation::{ImageSetRevocationStore, VerifiedImageSetRevocations};
use crate::kernel_format::KernelFormat;
use crate::packs::{PackRevocationChecker, Sha256Hex};
use crate::plan::{AssetKind, ExecutionPlan};
use crate::protocol::vm_backend::{BackendKind, VmStartConfig};
use crate::registry_pack::{PackPin, RegistryPackImage};
use crate::registry_pack_image::{BuiltImagePlatform, BuiltPackImageDescriptor};

/// One freshly authenticated installed image and its accepted base declarations.
///
/// Not serializable: persist the pack pin, then reopen it for every start.
/// This is not a boot authorization; the host must check its final config too.
#[derive(Debug)]
pub struct BuiltPackBootContract {
    pin: PackPin,
    payload: PathBuf,
    image: BuiltPackImageDescriptor,
    base: ImageSetManifest,
}

impl BuiltPackBootContract {
    /// Reopen for admission under the host's applied image-set revocation list.
    ///
    /// Reads only prepared local state: the list and checkpoint under
    /// `MVM_HOME`, the retained root proof and the installed pack. A missing,
    /// stale, rolled-back or modified list refuses; it is never read as an
    /// empty list, and nothing here fetches a replacement.
    pub fn open_for_admission(pin: &PackPin, host: &HostProtocolSupport) -> Result<Self> {
        Self::open_with_store(
            pin,
            host,
            &ImageSetRevocationStore::in_mvm_home(),
            Utc::now(),
        )
    }

    fn open_with_store(
        pin: &PackPin,
        host: &HostProtocolSupport,
        store: &ImageSetRevocationStore,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let revocations = store
            .load(now)
            .context("built-pack admission requires the host's image-set revocation list")?;
        Self::open(pin, host, &revocations)
    }

    /// Reopen under current publisher, pin and mandatory pack-revocation policy,
    /// and check the base root against an image-set revocation list.
    ///
    /// The list type is the authenticated image-set feed, so neither the
    /// registry-pack feed nor an empty checker can stand in for it.
    pub fn open(
        pin: &PackPin,
        host: &HostProtocolSupport,
        image_revocations: &VerifiedImageSetRevocations,
    ) -> Result<Self> {
        use crate::registry_pack_store::{
            load_pack_lockfile, load_publisher_policy_or_official_default,
            open_installed_registry_pack,
        };
        let lock = load_pack_lockfile(&crate::config::pack_lockfile_path())?;
        let publisher = load_publisher_policy_or_official_default(
            &crate::config::registry_pack_publisher_policy_path(),
        )?;
        let (installed, verified) = open_installed_registry_pack(
            &crate::config::registry_pack_cache_dir(),
            &lock,
            &publisher.policy,
            pin.reference(),
        )?;
        ensure!(
            verified.manifest_sha256() == pin.manifest_sha256(),
            "installed built pack no longer matches the persisted pack pin"
        );
        let Some(RegistryPackImage::Built(image)) = &verified.manifest().image else {
            anyhow::bail!("the pinned registry pack is not a built image");
        };
        let accepted = &image_train_lock().image_set;
        image.validate_pin(pin.reference(), accepted)?;
        let root = read_cached_image_set_root(
            &image_set_root_proof_cache(),
            accepted,
            host,
            Some(image_revocations as &dyn PackRevocationChecker),
        )?;
        ensure!(
            root.manifest_sha256() == &image.base_set.manifest_sha256,
            "built pack and authenticated base root differ"
        );
        Ok(Self {
            pin: pin.clone(),
            payload: installed.payload_root(),
            image: image.as_ref().clone(),
            base: root.manifest().clone(),
        })
    }

    pub fn pin(&self) -> &PackPin {
        &self.pin
    }

    pub fn rootfs_path(&self) -> PathBuf {
        self.payload.join(self.image.assets.rootfs.name.as_str())
    }

    pub fn rootfs_sha256(&self) -> &Sha256Hex {
        &self.image.assets.rootfs.sha256
    }

    /// Resolve only the pack/base-owned image fields and verify the proposed
    /// kernel. The returned config uses the existing backend protocol, not a
    /// new source. It lacks authenticated runtime attachments and is not ready
    /// to boot; the caller must separately prepare and admit those attachments.
    pub fn image_config(
        &self,
        kernel: &Path,
        arch: GuestArch,
        backend: BackendKind,
    ) -> Result<VmStartConfig> {
        let roothash = read_roothash(
            &self.payload.join(self.image.assets.roothash.name.as_str()),
            &self.image.assets.roothash,
        )?;
        let config = VmStartConfig {
            rootfs_path: self.rootfs_path().display().to_string(),
            kernel_path: Some(kernel.display().to_string()),
            verity_path: Some(
                self.payload
                    .join(self.image.assets.verity.name.as_str())
                    .display()
                    .to_string(),
            ),
            roothash: Some(roothash.trim().to_owned()),
            revision_hash: self.rootfs_sha256().as_str().to_owned(),
            flake_ref: format!("pack:{}", self.pin.reference()),
            ..Default::default()
        };
        self.verify_artifacts(&config, arch, backend)?;
        Ok(config)
    }

    /// The production default-tenant kernel declaration, never a cached
    /// self-digest, developer override, or kernel for another profile.
    pub fn kernel(&self, arch: GuestArch, backend: BackendKind) -> Result<MemberArtifact> {
        ensure!(
            matches!(
                backend,
                BackendKind::Firecracker | BackendKind::Hvf | BackendKind::Qemu
            ),
            "built registry images require a supported Linux-direct backend"
        );
        let image_arch = match self.image.platform {
            BuiltImagePlatform::LinuxX86_64 => GuestArch::X86_64,
            BuiltImagePlatform::LinuxAarch64 => GuestArch::Aarch64,
        };
        ensure!(
            arch == image_arch,
            "built pack architecture does not match the boot architecture"
        );
        let support = BackendImageSupport::for_backend(backend)
            .context("backend cannot boot a built registry image")?;
        // The generic selector also serves dev images. Narrow its input to
        // production before selecting either half of this sealed pair.
        let mut production = self.base.clone();
        production
            .members
            .retain(|member| member.build_mode.is_none());
        let pair = select_workload_image(
            &production,
            WorkloadImageProfile::DefaultTenant,
            arch,
            &support,
        )?;
        let format = ArtifactFormat::Kernel(match arch {
            GuestArch::X86_64 => KernelFormat::Elf,
            GuestArch::Aarch64 => KernelFormat::Image,
        });
        let mut kernels = pair
            .kernel
            .artifacts
            .iter()
            .filter(|artifact| artifact.format == format);
        let kernel = kernels
            .next()
            .context("signed default-tenant member lacks the supported kernel format")?;
        ensure!(
            kernels.next().is_none(),
            "signed default-tenant kernel selection is ambiguous"
        );
        Ok(kernel.clone())
    }

    /// Bind caller-supplied pack, rootfs and kernel plan digests to the
    /// authenticated pack/base contracts. This does not authorize a full boot:
    /// runtime overlay, initramfs, SDK sidecar and other final admission gates
    /// are outside this method's verification scope.
    pub fn verify_plan(
        &self,
        plan: &ExecutionPlan,
        arch: GuestArch,
        backend: BackendKind,
    ) -> Result<()> {
        let kernel = self.kernel(arch, backend)?;
        ensure!(
            plan.asset_identities
                .iter()
                .any(|asset| asset.kind == AssetKind::RegistryPack
                    && asset.name == self.pin.reference().to_string()
                    && asset.digest == self.pin.manifest_sha256().as_str()),
            "built image plan does not bind its authenticated pack pin"
        );
        ensure!(
            plan.image.sha256 == self.image.assets.rootfs.sha256.as_str(),
            "built image plan rootfs differs from the authenticated descriptor"
        );
        ensure!(
            plan.environment
                .as_ref()
                .is_some_and(|environment| environment.kernel_sha256 == kernel.sha256.as_str()),
            "built image plan kernel differs from the signed default-tenant kernel"
        );
        Ok(())
    }

    /// Rehash the pack/base-owned rootfs, kernel, verity and sibling metadata
    /// supplied to the existing config. Path existence is never evidence of
    /// trust. This does not authenticate runtime overlay, initramfs or SDK
    /// sidecar attachments and must not replace final host admission.
    pub fn verify_image_config(
        &self,
        plan: &ExecutionPlan,
        config: &VmStartConfig,
        arch: GuestArch,
        backend: BackendKind,
    ) -> Result<()> {
        self.verify_plan(plan, arch, backend)?;
        self.verify_artifacts(config, arch, backend)
    }

    fn verify_artifacts(
        &self,
        config: &VmStartConfig,
        arch: GuestArch,
        backend: BackendKind,
    ) -> Result<()> {
        let kernel = self.kernel(arch, backend)?;
        check_file(
            Path::new(
                config
                    .kernel_path
                    .as_deref()
                    .context("built image requires its signed kernel")?,
            ),
            &kernel.sha256,
            kernel.size,
        )?;
        let rootfs = Path::new(&config.rootfs_path);
        check_asset(rootfs, &self.image.assets.rootfs)?;
        check_asset(
            Path::new(
                config
                    .verity_path
                    .as_deref()
                    .context("built image requires its verity sidecar")?,
            ),
            &self.image.assets.verity,
        )?;
        let directory = rootfs
            .parent()
            .context("built rootfs has no parent directory")?;
        check_asset(
            &directory.join("mvm-meta.json"),
            &self.image.assets.mvm_meta,
        )?;
        let roothash_path = directory.join("rootfs.roothash");
        let roothash = read_roothash(&roothash_path, &self.image.assets.roothash)?;
        let roothash = roothash.trim();
        Sha256Hex::new(roothash)?;
        ensure!(
            config.roothash.as_deref() == Some(roothash),
            "built image config roothash differs from the authenticated descriptor"
        );
        Ok(())
    }
}

fn check_asset(path: &Path, asset: &crate::registry_pack_image::BuiltImageAsset) -> Result<()> {
    check_file(path, &asset.sha256, asset.size)
}

fn read_roothash(
    path: &Path,
    asset: &crate::registry_pack_image::BuiltImageAsset,
) -> Result<String> {
    ensure!(asset.size <= 128, "oversized built image roothash");
    let mut bytes = Vec::new();
    let file = open_regular(path, asset.size)?;
    file.take(asset.size + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == asset.size && Sha256Hex::from_bytes(&bytes) == asset.sha256,
        "built image roothash differs from its signed digest"
    );
    Ok(String::from_utf8(bytes)?)
}

fn check_file(path: &Path, expected: &Sha256Hex, size: u64) -> Result<()> {
    let file = open_regular(path, size)?;
    let mut reader = file.take(size.checked_add(1).context("artifact size overflow")?);
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        hash.update(&buffer[..n]);
    }
    ensure!(
        count == size && hex::encode(hash.finalize()) == expected.as_str(),
        "built boot artifact {} differs from its signed digest",
        path.display()
    );
    Ok(())
}

fn open_regular(path: &Path, size: u64) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open built boot artifact {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == size,
        "built boot artifact {} has wrong type or size",
        path.display()
    );
    Ok(file)
}

#[cfg(test)]
#[path = "registry_pack_boot_tests.rs"]
mod tests;
