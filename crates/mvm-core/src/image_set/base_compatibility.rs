//! Verify a composable base descriptor against independently authenticated image-set bytes.
//!
//! The descriptor does not extend the image-set schema or grant itself authority.
//! Its unsigned form is usable only for local development.

use std::collections::HashSet;

use mvm_contract::guest_libc::GuestLibc;
use serde::Deserialize;
use thiserror::Error;

use super::{
    ArtifactFormat, ArtifactName, BaseImageContract, BootProtocol, ImageSetManifest, ImageSetRole,
    ImageSetVerification, LocalImageSetVerification, MemberTarget, VerifiedArtifact,
    WorkloadImageProfile, verify_image_set_artifacts, verify_local_image_set,
};
use crate::arch::GuestArch;
use crate::crypto::image_verify::verify_signed_payload_under_any_identity;
use crate::image_set_revocation::{
    ImageSetRevocationStoreError, VerifiedImageSetRevocations, load_image_set_revocations,
};
use crate::packs::{KeylessTrust, PackRevocationChecker, RevocationStatus, Sha256Hex};
#[cfg(feature = "host-state")]
use crate::registry_pack::application_component::ComponentRequirements;

const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const KERNEL_CAPABILITIES: [&str; 8] = [
    "virtio_vsock",
    "virtio_blk",
    "dm_verity",
    "pty",
    "namespaces",
    "cgroup_v2",
    "fuse",
    "overlayfs",
];

/// A versioned, syntactically checked declaration; this alone is not trust evidence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseCompatibility {
    schema: String,
    image_set_manifest_sha256: Sha256Hex,
    arch: GuestArch,
    profile: WorkloadImageProfile,
    kernel: ArtifactPin,
    composition_tar: ArtifactPin,
    base_image_contract: BaseImageContract,
    boot_protocol: BootProtocol,
    filesystem_abi: u32,
    kernel_version: String,
    libc_loaders: Vec<LibcLoader>,
    kernel_capabilities: Vec<String>,
}

/// An exact published artifact pin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPin {
    name: ArtifactName,
    sha256: Sha256Hex,
    size: u64,
}

/// A declared dynamic loader in the base filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibcLoader {
    libc: GuestLibc,
    path: String,
}

/// A separately signed descriptor tied to authenticated, revocation-checked member bytes.
#[derive(Debug)]
pub struct ProductionBaseCompatibility {
    descriptor: BaseCompatibility,
    descriptor_bytes: Vec<u8>,
    signature_bundle: Vec<u8>,
    kernel: VerifiedArtifact,
    composition_tar: VerifiedArtifact,
}

/// An unsigned descriptor tied to measured local member bytes, never production authority.
#[derive(Debug)]
pub struct DevelopmentBaseCompatibility {
    descriptor: BaseCompatibility,
    descriptor_bytes: Vec<u8>,
    kernel: VerifiedArtifact,
    composition_tar: VerifiedArtifact,
}

impl ProductionBaseCompatibility {
    /// The authenticated declaration.
    pub fn descriptor(&self) -> &BaseCompatibility {
        &self.descriptor
    }

    /// Exact descriptor bytes authenticated by the detached signature.
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    /// Original detached signature bundle, for a consumer retaining cache evidence.
    pub fn signature_bundle(&self) -> &[u8] {
        &self.signature_bundle
    }

    /// The two member files whose bytes were checked.
    pub fn artifacts(&self) -> (&VerifiedArtifact, &VerifiedArtifact) {
        (&self.kernel, &self.composition_tar)
    }

    /// Recheck the held signed bytes against a fresh consumer-held image-set source
    /// and the currently applied checkpointed revocation feed. Use the returned
    /// artifacts rather than paths from the earlier verification.
    ///
    /// # Errors
    /// Refuses a stale or missing feed, changed member bytes, or invalid signatures.
    pub fn reverify(
        &self,
        image_set: &ImageSetVerification<'_>,
    ) -> Result<Self, BaseCompatibilityError> {
        self.reverify_with(
            image_set,
            load_image_set_revocations,
            Checks {
                signature: verify_descriptor_signature,
                image_set: verify_image_set_artifacts,
            },
        )
    }

    fn reverify_with(
        &self,
        image_set: &ImageSetVerification<'_>,
        load: impl FnOnce() -> Result<VerifiedImageSetRevocations, ImageSetRevocationStoreError>,
        checks: Checks,
    ) -> Result<Self, BaseCompatibilityError> {
        let revocations = load()?;
        verify_production_with(
            &self.descriptor_bytes,
            &self.signature_bundle,
            image_set,
            self.descriptor.arch,
            self.descriptor.profile,
            &revocations,
            checks,
        )
    }

    /// Check app or runtime/tool requirements against the authenticated declaration.
    ///
    /// # Errors
    /// Refuses unknown, noncanonical or unsatisfied requirements.
    #[cfg(feature = "host-state")]
    pub fn check_component_requirements(
        &self,
        requirements: &ComponentRequirements,
        arch: GuestArch,
    ) -> Result<(), BaseCompatibilityError> {
        self.descriptor.check_requirements(requirements, arch)
    }
}

impl DevelopmentBaseCompatibility {
    /// The unsigned local declaration. Its kernel claims are not boot witnesses.
    pub fn descriptor(&self) -> &BaseCompatibility {
        &self.descriptor
    }

    /// Exact unsigned local descriptor bytes; never production evidence.
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    /// The two measured local member files.
    pub fn artifacts(&self) -> (&VerifiedArtifact, &VerifiedArtifact) {
        (&self.kernel, &self.composition_tar)
    }

    /// Recheck the held unsigned declaration against a fresh local checkout
    /// snapshot and measured member bytes. This remains Development evidence.
    ///
    /// # Errors
    /// Refuses a changed checkout, manifest, or selected member bytes.
    pub fn reverify(
        &self,
        image_set: &LocalImageSetVerification<'_>,
    ) -> Result<Self, BaseCompatibilityError> {
        verify_development_base_compatibility(
            &self.descriptor_bytes,
            image_set,
            self.descriptor.arch,
            self.descriptor.profile,
        )
    }

    /// Check requirements against measured local bytes and unsigned base claims.
    ///
    /// # Errors
    /// Refuses unknown, noncanonical or unsatisfied requirements; success remains Development.
    #[cfg(feature = "host-state")]
    pub fn check_component_requirements(
        &self,
        requirements: &ComponentRequirements,
        arch: GuestArch,
    ) -> Result<(), BaseCompatibilityError> {
        self.descriptor.check_requirements(requirements, arch)
    }
}

impl BaseCompatibility {
    /// Strictly parse the bounded v1 JSON and validate every declared value.
    ///
    /// # Errors
    /// Returns an error for malformed, unsupported or unbounded declarations.
    pub fn parse(bytes: &[u8]) -> Result<Self, BaseCompatibilityError> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(BaseCompatibilityError::Invalid(
                "descriptor too large".into(),
            ));
        }
        let descriptor: Self = serde_json::from_slice(bytes)
            .map_err(|e| BaseCompatibilityError::Invalid(e.to_string()))?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Claimed kernel version, in canonical major.minor.patch form.
    pub fn kernel_version(&self) -> &str {
        &self.kernel_version
    }

    /// Guest architecture bound to the selected member pair.
    pub fn arch(&self) -> GuestArch {
        self.arch
    }

    /// Generic workload profile bound to the selected member pair.
    pub fn profile(&self) -> WorkloadImageProfile {
        self.profile
    }

    /// Digest of the exact signed or locally measured image-set manifest.
    pub fn image_set_manifest_sha256(&self) -> &Sha256Hex {
        &self.image_set_manifest_sha256
    }

    /// Claimed loader paths; a signed descriptor is not a byte-level loader witness.
    pub fn libc_loaders(&self) -> &[LibcLoader] {
        &self.libc_loaders
    }

    /// Claimed kernel capabilities.
    pub fn kernel_capabilities(&self) -> &[String] {
        &self.kernel_capabilities
    }

    fn validate(&self) -> Result<(), BaseCompatibilityError> {
        let invalid = |reason: &str| BaseCompatibilityError::Invalid(reason.into());
        if self.schema != "base-compatibility/v1" {
            return Err(invalid("unsupported descriptor schema"));
        }
        if self.base_image_contract != BaseImageContract::LINUX_LAYER
            || self.boot_protocol != BootProtocol::LinuxDirect
            || self.filesystem_abi != 1
        {
            return Err(invalid("unsupported base, boot or filesystem ABI"));
        }
        if self.kernel.name == self.composition_tar.name
            || self.kernel.size == 0
            || self.composition_tar.size == 0
        {
            return Err(invalid("invalid artifact pins"));
        }
        if parse_kernel_version(&self.kernel_version).is_none_or(|version| version[0] == 0) {
            return Err(invalid(
                "kernel_version must be canonical major.minor.patch",
            ));
        }
        if self.libc_loaders.is_empty() || self.libc_loaders.len() > 2 {
            return Err(invalid("libc_loaders must contain one or two entries"));
        }
        let mut libcs = HashSet::new();
        for loader in &self.libc_loaders {
            if loader.libc == GuestLibc::Unknown || !libcs.insert(loader.libc.as_str()) {
                return Err(invalid("duplicate or unknown libc loader"));
            }
            let path = loader.path.as_str();
            if path.len() > 256
                || !path.starts_with('/')
                || path.contains("//")
                || path.split('/').skip(1).any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || !part.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+')
                        })
                })
            {
                return Err(invalid("invalid absolute libc loader path"));
            }
        }
        if self.kernel_capabilities.len() > KERNEL_CAPABILITIES.len() {
            return Err(invalid("too many kernel capabilities"));
        }
        let mut names = HashSet::new();
        for name in &self.kernel_capabilities {
            if !KERNEL_CAPABILITIES.contains(&name.as_str()) || !names.insert(name) {
                return Err(invalid("unsupported or duplicate kernel capability"));
            }
        }
        Ok(())
    }

    #[cfg(feature = "host-state")]
    fn check_requirements(
        &self,
        requirements: &ComponentRequirements,
        arch: GuestArch,
    ) -> Result<(), BaseCompatibilityError> {
        let mismatch = BaseCompatibilityError::Mismatch;
        if arch != self.arch {
            return Err(mismatch("guest architecture"));
        }
        if requirements.filesystem_abi != self.filesystem_abi {
            return Err(mismatch("filesystem ABI"));
        }
        let minimum = parse_kernel_version(&requirements.minimum_kernel)
            .ok_or(mismatch("invalid minimum kernel version"))?;
        let base = parse_kernel_version(&self.kernel_version)
            .ok_or(mismatch("invalid base kernel version"))?;
        if base < minimum {
            return Err(mismatch("minimum kernel version"));
        }
        match requirements.libc.as_str() {
            "static" if requirements.loader.is_none() => {}
            "musl" | "glibc" => {
                let loader = requirements
                    .loader
                    .as_deref()
                    .ok_or(mismatch("libc loader"))?;
                if !self
                    .libc_loaders
                    .iter()
                    .any(|entry| entry.libc.as_str() == requirements.libc && entry.path == loader)
                {
                    return Err(mismatch("libc loader"));
                }
            }
            _ => return Err(mismatch("unsupported libc or static loader")),
        }
        if requirements.required_capabilities.len() > KERNEL_CAPABILITIES.len() {
            return Err(mismatch("too many required kernel capabilities"));
        }
        let mut names = HashSet::new();
        for name in &requirements.required_capabilities {
            if !KERNEL_CAPABILITIES.contains(&name.as_str())
                || !names.insert(name)
                || !self.kernel_capabilities.contains(name)
            {
                return Err(mismatch("unsupported or missing kernel capability"));
            }
        }
        Ok(())
    }
}

fn parse_kernel_version(version: &str) -> Option<[u32; 3]> {
    let mut parts = version.split('.');
    let mut parsed = [0; 3];
    for slot in &mut parsed {
        let part = parts.next()?;
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(parsed)
}

impl LibcLoader {
    /// C library this loader serves.
    pub fn libc(&self) -> GuestLibc {
        self.libc
    }

    /// Absolute guest path declared by the descriptor.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Why a descriptor cannot authorize the selected base.
#[derive(Debug, Error)]
pub enum BaseCompatibilityError {
    #[error("invalid base compatibility descriptor: {0}")]
    Invalid(String),
    #[error("base descriptor signature invalid: {0}")]
    Signature(String),
    #[error("image-set verification failed: {0}")]
    ImageSet(#[from] super::ImageSetError),
    #[error("image-set revocations unavailable or stale: {0}")]
    Revocations(#[from] ImageSetRevocationStoreError),
    #[error("descriptor revoked: {0}")]
    Revoked(String),
    #[error("descriptor and selected image-set members disagree: {0}")]
    Mismatch(&'static str),
}

/// Verify separately signed descriptor bytes and signed, pinned selected image-set files.
///
/// Loads the applied revocation feed afresh; no supplied or host-claimed authority
/// can replace the lock's release identity or the persisted feed checkpoint.
///
/// # Errors
/// Refuses any signature, feed, lock, selection, syntax or byte mismatch.
pub fn verify_production_base_compatibility(
    bytes: &[u8],
    signature_bundle: &[u8],
    image_set: &ImageSetVerification<'_>,
    expected_arch: GuestArch,
    expected_profile: WorkloadImageProfile,
) -> Result<ProductionBaseCompatibility, BaseCompatibilityError> {
    let revocations = load_image_set_revocations()?;
    verify_production_with(
        bytes,
        signature_bundle,
        image_set,
        expected_arch,
        expected_profile,
        &revocations,
        Checks {
            signature: verify_descriptor_signature,
            image_set: verify_image_set_artifacts,
        },
    )
}

type SignatureCheck = fn(&[u8], &[u8], &KeylessTrust) -> Result<(), String>;
type SetCheck = fn(
    &ImageSetVerification<'_>,
    &[ArtifactName],
) -> Result<super::VerifiedSelectedArtifacts, super::ImageSetError>;

struct Checks {
    signature: SignatureCheck,
    image_set: SetCheck,
}

fn verify_production_with(
    bytes: &[u8],
    signature_bundle: &[u8],
    image_set: &ImageSetVerification<'_>,
    expected_arch: GuestArch,
    expected_profile: WorkloadImageProfile,
    revocations: &VerifiedImageSetRevocations,
    checks: Checks,
) -> Result<ProductionBaseCompatibility, BaseCompatibilityError> {
    if signature_bundle.len() > MAX_BUNDLE_BYTES {
        return Err(BaseCompatibilityError::Invalid(
            "signature bundle too large".into(),
        ));
    }
    let descriptor = BaseCompatibility::parse(bytes)?;
    if descriptor.arch != expected_arch || descriptor.profile != expected_profile {
        return Err(BaseCompatibilityError::Mismatch("architecture or profile"));
    }
    // The verifier accepts this trust only from the release lock, never from descriptor JSON.
    let trust = image_set.lock_trust();
    (checks.signature)(bytes, signature_bundle, &trust)
        .map_err(BaseCompatibilityError::Signature)?;
    let selected = [
        descriptor.kernel.name.clone(),
        descriptor.composition_tar.name.clone(),
    ];
    let checked = (checks.image_set)(&image_set.with_current_revocations(revocations), &selected)?;
    let signer = checked.signer_key_id;
    if let RevocationStatus::Revoked { reason } =
        revocations.status(&signer, &Sha256Hex::from_bytes(bytes))
    {
        return Err(BaseCompatibilityError::Revoked(reason));
    }
    let (kernel, tar) = bind(
        &descriptor,
        &checked.manifest,
        &checked.manifest_sha256,
        &checked.artifacts,
    )?;
    Ok(ProductionBaseCompatibility {
        descriptor,
        descriptor_bytes: bytes.to_vec(),
        signature_bundle: signature_bundle.to_vec(),
        kernel,
        composition_tar: tar,
    })
}

fn verify_descriptor_signature(
    bytes: &[u8],
    bundle: &[u8],
    trust: &KeylessTrust,
) -> Result<(), String> {
    let identities: Vec<&str> = trust
        .accepted_identities
        .iter()
        .map(String::as_str)
        .collect();
    verify_signed_payload_under_any_identity(bytes, bundle, &identities, &trust.issuer)
        .map_err(|e| e.to_string())
}

/// Verify unsigned local syntax and exact local image-set member bytes.
///
/// Never upgrades a locally built set or its descriptor to Production.
///
/// # Errors
/// Refuses malformed descriptor, stale local image set, or mismatched artifacts.
pub fn verify_development_base_compatibility(
    bytes: &[u8],
    image_set: &LocalImageSetVerification<'_>,
    expected_arch: GuestArch,
    expected_profile: WorkloadImageProfile,
) -> Result<DevelopmentBaseCompatibility, BaseCompatibilityError> {
    let descriptor = BaseCompatibility::parse(bytes)?;
    if descriptor.arch != expected_arch || descriptor.profile != expected_profile {
        return Err(BaseCompatibilityError::Mismatch("architecture or profile"));
    }
    let checked = verify_local_image_set(image_set)?;
    let (kernel, tar) = bind(
        &descriptor,
        &checked.manifest,
        &checked.manifest_sha256,
        &checked.artifacts,
    )?;
    Ok(DevelopmentBaseCompatibility {
        descriptor,
        descriptor_bytes: bytes.to_vec(),
        kernel,
        composition_tar: tar,
    })
}

fn bind(
    descriptor: &BaseCompatibility,
    manifest: &ImageSetManifest,
    root_sha: &Sha256Hex,
    artifacts: &[VerifiedArtifact],
) -> Result<(VerifiedArtifact, VerifiedArtifact), BaseCompatibilityError> {
    let mismatch = BaseCompatibilityError::Mismatch;
    if &descriptor.image_set_manifest_sha256 != root_sha {
        return Err(mismatch("image-set manifest digest"));
    }
    if manifest.schema_version != super::IMAGE_SET_SCHEMA_VERSION
        || manifest.compatibility.base_image_contract != Some(BaseImageContract::LINUX_LAYER)
    {
        return Err(mismatch("schema 3 Linux base contract required"));
    }
    let target = MemberTarget::Arch(descriptor.arch);
    let find = |role, pin: &ArtifactPin, format: fn(ArtifactFormat) -> bool| {
        let member = manifest
            .members
            .iter()
            .find(|member| {
                member.role == role
                    && member.target == target
                    && member.build_mode.is_none()
                    && member.artifacts.iter().any(|artifact| {
                        artifact.name == pin.name
                            && format(artifact.format)
                            && artifact.sha256 == pin.sha256
                            && artifact.size == pin.size
                    })
            })
            .ok_or(mismatch("selected member role, format or artifact pin"))?;
        if role == ImageSetRole::WorkloadKernel(descriptor.profile)
            && member.boot_protocol != Some(BootProtocol::LinuxDirect)
        {
            return Err(mismatch("kernel boot protocol"));
        }
        artifacts
            .iter()
            .find(|artifact| {
                artifact.name == pin.name
                    && artifact.role == role
                    && artifact.target == target
                    && artifact.sha256 == pin.sha256
                    && artifact.size == pin.size
            })
            .cloned()
            .ok_or(mismatch("selected artifact bytes"))
    };
    Ok((
        find(
            ImageSetRole::WorkloadKernel(descriptor.profile),
            &descriptor.kernel,
            |format| matches!(format, ArtifactFormat::Kernel(_)),
        )?,
        find(
            ImageSetRole::WorkloadRootfs(descriptor.profile),
            &descriptor.composition_tar,
            |format| format == ArtifactFormat::TarGz,
        )?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_set::MemberArtifact;
    use crate::kernel_format::KernelFormat;

    fn fixture() -> (
        BaseCompatibility,
        ImageSetManifest,
        Sha256Hex,
        Vec<VerifiedArtifact>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut manifest = super::super::tests::manifest();
        manifest.schema_version = super::super::IMAGE_SET_SCHEMA_VERSION;
        manifest.mvm_source_commit = None;
        manifest.compatibility.guest_agent_protocol = None;
        manifest.compatibility.base_image_contract = Some(BaseImageContract::LINUX_LAYER);
        manifest.compatibility.builder_boot_abi = Some(super::super::BuilderBootAbi::NO_MVM_BINARY);
        let arch = GuestArch::X86_64;
        let profile = WorkloadImageProfile::DefaultTenant;
        let target = MemberTarget::Arch(arch);
        let kernel_name = ArtifactName::new("kernel.elf").expect("kernel name");
        let tar_name = ArtifactName::new("base.tar.gz").expect("tar name");
        let kernel_bytes = b"kernel bytes";
        let tar_bytes = b"tar bytes";
        std::fs::write(dir.path().join(kernel_name.as_str()), kernel_bytes).expect("kernel");
        std::fs::write(dir.path().join(tar_name.as_str()), tar_bytes).expect("tar");
        let kernel_sha = Sha256Hex::from_bytes(kernel_bytes);
        let tar_sha = Sha256Hex::from_bytes(tar_bytes);
        let kernel = manifest
            .members
            .iter_mut()
            .find(|member| {
                member.role == ImageSetRole::WorkloadKernel(profile) && member.target == target
            })
            .expect("kernel member");
        kernel.artifacts = vec![MemberArtifact {
            name: kernel_name.clone(),
            format: ArtifactFormat::Kernel(KernelFormat::Elf),
            sha256: kernel_sha.clone(),
            size: kernel_bytes.len() as u64,
        }];
        let rootfs = manifest
            .members
            .iter_mut()
            .find(|member| {
                member.role == ImageSetRole::WorkloadRootfs(profile) && member.target == target
            })
            .expect("rootfs member");
        rootfs.artifacts.push(MemberArtifact {
            name: tar_name.clone(),
            format: ArtifactFormat::TarGz,
            sha256: tar_sha.clone(),
            size: tar_bytes.len() as u64,
        });
        let root_sha = Sha256Hex::from_bytes(&serde_json::to_vec(&manifest).expect("manifest"));
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "base-compatibility/v1",
            "image_set_manifest_sha256": root_sha,
            "arch": "x86_64",
            "profile": "default_tenant",
            "kernel": { "name": kernel_name, "sha256": kernel_sha, "size": kernel_bytes.len() },
            "composition_tar": { "name": tar_name, "sha256": tar_sha, "size": tar_bytes.len() },
            "base_image_contract": 1,
            "boot_protocol": "linux_direct",
            "filesystem_abi": 1,
            "kernel_version": "6.12.3",
            "libc_loaders": [{"libc": "musl", "path": "/lib/ld-musl-x86_64.so.1"}],
            "kernel_capabilities": ["virtio_vsock", "virtio_blk"]
        }))
        .expect("descriptor");
        let descriptor = BaseCompatibility::parse(&bytes).expect("descriptor parses");
        let artifacts = [
            (&descriptor.kernel, ImageSetRole::WorkloadKernel(profile)),
            (
                &descriptor.composition_tar,
                ImageSetRole::WorkloadRootfs(profile),
            ),
        ]
        .into_iter()
        .map(|(pin, role)| VerifiedArtifact {
            role,
            target,
            name: pin.name.clone(),
            path: dir.path().join(pin.name.as_str()),
            sha256: pin.sha256.clone(),
            size: pin.size,
        })
        .collect();
        (descriptor, manifest, root_sha, artifacts, dir)
    }

    #[test]
    fn rejects_unknown_and_malformed_wire_values() {
        let (good, _, _, _, _) = fixture();
        let value = serde_json::to_value(serde_json::json!({
            "schema": good.schema, "image_set_manifest_sha256": good.image_set_manifest_sha256,
            "arch": good.arch, "profile": good.profile,
            "kernel": {"name": good.kernel.name, "sha256": good.kernel.sha256, "size": good.kernel.size},
            "composition_tar": {"name": good.composition_tar.name, "sha256": good.composition_tar.sha256, "size": good.composition_tar.size},
            "base_image_contract": 1, "boot_protocol": "linux_direct", "filesystem_abi": 1,
            "kernel_version": "6.12.3",
            "libc_loaders": [{"libc": "musl", "path": "/lib/ld-musl-x86_64.so.1"}],
            "kernel_capabilities": ["virtio_vsock"]
        })).expect("json");
        for (field, bad) in [
            ("schema", serde_json::json!("base-compatibility/v2")),
            ("kernel_version", serde_json::json!("6.12")),
            ("kernel_version", serde_json::json!("06.12.3")),
            ("kernel_version", serde_json::json!("6.12.3-rc1")),
            ("base_image_contract", serde_json::json!(0)),
            ("filesystem_abi", serde_json::json!(2)),
            ("boot_protocol", serde_json::json!("uefi")),
            (
                "libc_loaders",
                serde_json::json!([{"libc":"glibc","path":"../ld.so"}]),
            ),
            (
                "libc_loaders",
                serde_json::json!([{"libc":"musl","path":"/lib/ld.so"},{"libc":"musl","path":"/lib/ld2.so"}]),
            ),
            ("kernel_capabilities", serde_json::json!(["guest_nic"])),
            (
                "kernel_capabilities",
                serde_json::json!(["virtio_blk", "virtio_blk"]),
            ),
            ("trust", serde_json::json!("production")),
        ] {
            let mut candidate = value.clone();
            candidate[field] = bad;
            assert!(
                BaseCompatibility::parse(&serde_json::to_vec(&candidate).expect("bytes")).is_err(),
                "{field}: {candidate}"
            );
        }
        assert!(BaseCompatibility::parse(&vec![b' '; MAX_DESCRIPTOR_BYTES + 1]).is_err());
    }

    #[test]
    fn binding_requires_exact_schema_profile_format_and_artifact_pins() {
        let (descriptor, mut manifest, root_sha, artifacts, _dir) = fixture();
        bind(&descriptor, &manifest, &root_sha, &artifacts).expect("valid exact binding");
        assert!(
            bind(
                &descriptor,
                &manifest,
                &Sha256Hex::from_bytes(b"other"),
                &artifacts
            )
            .is_err()
        );
        let mut tampered = artifacts.clone();
        tampered[0].sha256 = Sha256Hex::from_bytes(b"tampered");
        assert!(bind(&descriptor, &manifest, &root_sha, &tampered).is_err());
        let tar_index = manifest
            .members
            .iter()
            .position(|member| {
                member.role == ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant)
                    && member.target == MemberTarget::Arch(GuestArch::X86_64)
            })
            .expect("rootfs");
        manifest.members[tar_index]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.name == descriptor.composition_tar.name)
            .expect("tar")
            .format = ArtifactFormat::Ext4;
        assert!(bind(&descriptor, &manifest, &root_sha, &artifacts).is_err());
        manifest.members[tar_index]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.name == descriptor.composition_tar.name)
            .expect("tar")
            .format = ArtifactFormat::TarGz;
        manifest.schema_version = super::super::LEGACY_IMAGE_SET_SCHEMA_VERSION;
        manifest.compatibility.base_image_contract = None;
        assert!(bind(&descriptor, &manifest, &root_sha, &artifacts).is_err());
    }

    fn test_set_check(
        request: &ImageSetVerification<'_>,
        names: &[ArtifactName],
    ) -> Result<super::super::VerifiedSelectedArtifacts, super::super::ImageSetError> {
        super::super::verify::verify_checked_selected(request, names, |_, _, _| Ok(()))
    }

    fn test_signature(bytes: &[u8], bundle: &[u8], _: &KeylessTrust) -> Result<(), String> {
        if bundle == Sha256Hex::from_bytes(bytes).as_str().as_bytes() {
            Ok(())
        } else {
            Err("signature does not bind descriptor bytes".into())
        }
    }

    fn test_feed(revoked: Option<Sha256Hex>) -> VerifiedImageSetRevocations {
        use crate::crypto::image_verify::VerifiedSigner;
        use crate::pack_revocation::{PACK_REVOCATION_SCHEMA_VERSION, PackRevocationList};
        use crate::pack_trust::RevokedPack;
        use crate::release_trust::{RELEASE_OIDC_ISSUER, image_set_revocation_identity};
        use chrono::{TimeZone, Utc};

        let issued_at = Utc
            .with_ymd_and_hms(2026, 11, 1, 0, 0, 0)
            .single()
            .expect("date");
        let mut list = PackRevocationList {
            schema_version: PACK_REVOCATION_SCHEMA_VERSION,
            revocations: Vec::new(),
            issued_at,
            not_after: issued_at + chrono::Duration::days(20),
        };
        if let Some(sha) = revoked {
            let manifest = super::super::tests::manifest();
            let lock = super::super::tests::lock_for(&manifest);
            list.revocations.push(RevokedPack {
                key_id: crate::plan::bundle::key_id_from_identity(
                    &lock.signing_identity.certificate_identity(&lock.repository),
                ),
                pack_hash: Some(sha),
                reason: "withdrawn descriptor".into(),
            });
        }
        crate::image_set_revocation::verify_image_set_revocations_with(
            &serde_json::to_vec(&list).expect("list"),
            b"test",
            issued_at + chrono::Duration::days(1),
            None,
            |_, _| {
                Ok(VerifiedSigner {
                    identity: image_set_revocation_identity(1),
                    issuer: RELEASE_OIDC_ISSUER.into(),
                })
            },
        )
        .expect("fresh authenticated test feed")
    }

    #[test]
    fn production_checks_distinct_signature_selected_bytes_and_revocation() {
        let (descriptor, manifest, _, _, dir) = fixture();
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
        let lock = super::super::tests::lock_for(&manifest);
        let request =
            ImageSetVerification::new(&manifest_bytes, b"set signature", &lock, dir.path());
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": descriptor.schema,
            "image_set_manifest_sha256": descriptor.image_set_manifest_sha256,
            "arch": descriptor.arch,
            "profile": descriptor.profile,
            "kernel": {"name": descriptor.kernel.name, "sha256": descriptor.kernel.sha256, "size": descriptor.kernel.size},
            "composition_tar": {"name": descriptor.composition_tar.name, "sha256": descriptor.composition_tar.sha256, "size": descriptor.composition_tar.size},
            "base_image_contract": 1, "boot_protocol": "linux_direct", "filesystem_abi": 1,
            "kernel_version": descriptor.kernel_version,
            "libc_loaders": [{"libc":"musl","path":"/lib/ld-musl-x86_64.so.1"}],
            "kernel_capabilities": ["virtio_vsock", "virtio_blk"]
        }))
        .expect("descriptor");
        let signature = Sha256Hex::from_bytes(&bytes);
        let check = |feed: &VerifiedImageSetRevocations, bytes: &[u8], signature: &[u8]| {
            verify_production_with(
                bytes,
                signature,
                &request,
                GuestArch::X86_64,
                WorkloadImageProfile::DefaultTenant,
                feed,
                Checks {
                    signature: test_signature,
                    image_set: test_set_check,
                },
            )
        };
        let good = test_feed(None);
        let held = check(&good, &bytes, signature.as_str().as_bytes())
            .expect("test signer and set accepted");
        assert_eq!(held.descriptor_bytes(), bytes);
        assert_eq!(held.signature_bundle(), signature.as_str().as_bytes());
        let checks = || Checks {
            signature: test_signature,
            image_set: test_set_check,
        };
        let fresh = held
            .reverify_with(&request, || Ok(test_feed(None)), checks())
            .expect("held evidence reverifies with a current feed");
        assert_eq!(fresh.artifacts(), held.artifacts());
        assert!(matches!(
            held.reverify_with(
                &request,
                || Err(ImageSetRevocationStoreError::Missing),
                checks()
            ),
            Err(BaseCompatibilityError::Revocations(
                ImageSetRevocationStoreError::Missing
            ))
        ));
        assert!(matches!(
            held.reverify_with(
                &request,
                || Err(ImageSetRevocationStoreError::Verification(
                    crate::image_set_revocation::ImageSetRevocationError::Expired {
                        not_after: chrono::Utc::now() - chrono::Duration::seconds(1),
                        now: chrono::Utc::now(),
                    }
                )),
                checks()
            ),
            Err(BaseCompatibilityError::Revocations(
                ImageSetRevocationStoreError::Verification(
                    crate::image_set_revocation::ImageSetRevocationError::Expired { .. }
                )
            ))
        ));
        assert!(matches!(
            held.reverify_with(
                &request,
                || Ok(test_feed(Some(Sha256Hex::from_bytes(&bytes)))),
                checks()
            ),
            Err(BaseCompatibilityError::Revoked(_))
        ));
        let mut changed_bundle = held.signature_bundle.clone();
        changed_bundle.push(b'!');
        let mut changed_evidence = held;
        changed_evidence.signature_bundle = changed_bundle;
        assert!(matches!(
            changed_evidence.reverify_with(&request, || Ok(test_feed(None)), checks()),
            Err(BaseCompatibilityError::Signature(_))
        ));
        changed_evidence.signature_bundle = signature.as_str().as_bytes().to_vec();
        changed_evidence.descriptor_bytes.push(b' ');
        assert!(matches!(
            changed_evidence.reverify_with(&request, || Ok(test_feed(None)), checks()),
            Err(BaseCompatibilityError::Signature(_))
        ));
        let changed_set = ImageSetVerification::new(b"{}", b"set signature", &lock, dir.path());
        assert!(matches!(
            fresh.reverify_with(&changed_set, || Ok(test_feed(None)), checks()),
            Err(BaseCompatibilityError::ImageSet(_))
        ));
        assert!(matches!(
            check(&good, &bytes, b"wrong"),
            Err(BaseCompatibilityError::Signature(_))
        ));
        let mut altered = bytes.clone();
        let version_at = altered
            .windows(b"6.12.3".len())
            .position(|window| window == b"6.12.3")
            .expect("version in descriptor");
        altered[version_at + 5] = b'4';
        assert!(matches!(
            check(&good, &altered, signature.as_str().as_bytes()),
            Err(BaseCompatibilityError::Signature(_))
        ));
        let revoked = test_feed(Some(Sha256Hex::from_bytes(&bytes)));
        assert!(matches!(
            check(&revoked, &bytes, signature.as_str().as_bytes()),
            Err(BaseCompatibilityError::Revoked(_))
        ));
        std::fs::write(dir.path().join("kernel.elf"), b"tampered kernel").expect("tamper");
        assert!(matches!(
            fresh.reverify_with(&request, || Ok(test_feed(None)), checks()),
            Err(BaseCompatibilityError::ImageSet(_))
        ));
        assert!(matches!(
            check(&good, &bytes, signature.as_str().as_bytes()),
            Err(BaseCompatibilityError::ImageSet(_))
        ));
    }

    #[cfg(feature = "host-state")]
    #[test]
    fn component_requirements_compare_numeric_kernel_loader_abi_and_capabilities() {
        let (mut descriptor, _, _, artifacts, _dir) = fixture();
        descriptor.kernel_version = "6.10.0".into();
        let verified = ProductionBaseCompatibility {
            descriptor,
            descriptor_bytes: Vec::new(),
            signature_bundle: Vec::new(),
            kernel: artifacts[0].clone(),
            composition_tar: artifacts[1].clone(),
        };
        let mut requirements = ComponentRequirements {
            filesystem_abi: 1,
            libc: "musl".into(),
            loader: Some("/lib/ld-musl-x86_64.so.1".into()),
            minimum_kernel: "6.9.0".into(),
            required_capabilities: vec!["virtio_vsock".into()],
        };
        let check = |requirements: &ComponentRequirements, arch| {
            verified.check_component_requirements(requirements, arch)
        };
        check(&requirements, GuestArch::X86_64).expect("6.10 >= 6.9");
        requirements.libc = "static".into();
        requirements.loader = None;
        check(&requirements, GuestArch::X86_64).expect("static requires no loader");
        requirements.loader = Some("/lib/ld-musl-x86_64.so.1".into());
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.libc = "glibc".into();
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.libc = "musl".into();
        requirements.loader = Some("/lib/not-the-loader".into());
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.loader = Some("/lib/ld-musl-x86_64.so.1".into());
        requirements.minimum_kernel = "6.11.0".into();
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.minimum_kernel = "6.10.0-rc1".into();
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.minimum_kernel = "6.9.0".into();
        requirements.required_capabilities = vec!["dm_verity".into()];
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.required_capabilities = vec!["guest_nic".into()];
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.required_capabilities.clear();
        requirements.filesystem_abi = 2;
        assert!(check(&requirements, GuestArch::X86_64).is_err());
        requirements.filesystem_abi = 1;
        assert!(check(&requirements, GuestArch::Aarch64).is_err());
    }

    #[test]
    fn unsigned_local_candidate_stays_development_and_checks_measured_bytes() {
        let (descriptor, mut manifest, _, _, dir) = fixture();
        let current: super::super::LocalCheckouts = serde_json::from_value(serde_json::json!({
            "images": {"commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worktree": {"state": "clean"}}
        }))
        .expect("local checkout identity");
        manifest.producer = super::super::ImageSetProducer::LocalCheckouts(current.clone());
        manifest.revocation_channel = None;
        manifest.members.retain(|member| {
            member.target == MemberTarget::Arch(GuestArch::X86_64)
                && matches!(
                    member.role,
                    ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant)
                        | ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant)
                )
        });
        for member in &mut manifest.members {
            member.pack_hash = None;
            member.sbom = None;
            for artifact in &mut member.artifacts {
                if artifact.name != descriptor.kernel.name
                    && artifact.name != descriptor.composition_tar.name
                {
                    let bytes = artifact.name.as_str().as_bytes();
                    std::fs::write(dir.path().join(artifact.name.as_str()), bytes)
                        .expect("local artifact");
                    artifact.sha256 = Sha256Hex::from_bytes(bytes);
                    artifact.size = bytes.len() as u64;
                }
            }
        }
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
        let mut descriptor_value = serde_json::json!({
            "schema": "base-compatibility/v1",
            "image_set_manifest_sha256": Sha256Hex::from_bytes(&manifest_bytes),
            "arch": "x86_64", "profile": "default_tenant",
            "kernel": {"name": descriptor.kernel.name, "sha256": descriptor.kernel.sha256, "size": descriptor.kernel.size},
            "composition_tar": {"name": descriptor.composition_tar.name, "sha256": descriptor.composition_tar.sha256, "size": descriptor.composition_tar.size},
            "base_image_contract": 1, "boot_protocol": "linux_direct", "filesystem_abi": 1,
            "kernel_version": "6.12.3",
            "libc_loaders": [{"libc": "musl", "path": "/lib/ld-musl-x86_64.so.1"}],
            "kernel_capabilities": ["virtio_vsock"]
        });
        let bytes = serde_json::to_vec(&descriptor_value).expect("descriptor");
        let request = LocalImageSetVerification::new(
            &manifest_bytes,
            dir.path(),
            &current,
            GuestArch::X86_64,
        );
        let verified = verify_development_base_compatibility(
            &bytes,
            &request,
            GuestArch::X86_64,
            WorkloadImageProfile::DefaultTenant,
        )
        .expect("unsigned local descriptor remains development");
        assert_eq!(verified.descriptor_bytes(), bytes);
        assert_eq!(verified.artifacts().0.name, descriptor.kernel.name);
        verified.reverify(&request).expect("unchanged local source");
        let changed_checkout: super::super::LocalCheckouts =
            serde_json::from_value(serde_json::json!({
                "images": {"commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "worktree": {"state": "clean"}}
            }))
            .expect("changed checkout");
        let stale_request = LocalImageSetVerification::new(
            &manifest_bytes,
            dir.path(),
            &changed_checkout,
            GuestArch::X86_64,
        );
        assert!(matches!(
            verified.reverify(&stale_request),
            Err(BaseCompatibilityError::ImageSet(_))
        ));
        descriptor_value["image_set_manifest_sha256"] =
            serde_json::json!(Sha256Hex::from_bytes(b"other"));
        assert!(
            verify_development_base_compatibility(
                &serde_json::to_vec(&descriptor_value).expect("changed descriptor"),
                &request,
                GuestArch::X86_64,
                WorkloadImageProfile::DefaultTenant,
            )
            .is_err()
        );
        std::fs::write(dir.path().join("base.tar.gz"), b"changed").expect("tamper");
        assert!(matches!(
            verified.reverify(&request),
            Err(BaseCompatibilityError::ImageSet(_))
        ));
        assert!(
            verify_development_base_compatibility(
                &bytes,
                &request,
                GuestArch::X86_64,
                WorkloadImageProfile::DefaultTenant,
            )
            .is_err()
        );
    }
}
