//! Select the sealed local kernel and tar source bound by development proof.

use super::{
    ArtifactFormat, BackendImageSupport, BundleVerifyError, GuestArch, ImageSetManifest,
    ImageSetRole, LocalDevelopmentBaseProof, WorkloadImageProfile, select_workload_image,
    validate_structure,
};
use crate::image_set::{ImageSetMember, ImageSetProducer, MemberArtifact};

fn local_development_pair(
    image_set: &ImageSetManifest,
    arch: GuestArch,
    profile: WorkloadImageProfile,
) -> Result<(&ImageSetMember, &ImageSetMember), BundleVerifyError> {
    let refused = || {
        BundleVerifyError::ManifestParse(
            "local base has no unique compatible sealed kernel/rootfs/tar pair".into(),
        )
    };
    if image_set.schema_version != crate::image_set::IMAGE_SET_SCHEMA_VERSION
        || !matches!(image_set.producer, ImageSetProducer::LocalCheckouts(_))
    {
        return Err(refused());
    }
    validate_structure(image_set).map_err(|_| refused())?;
    let mut kernels = image_set.members.iter().filter(|member| {
        member.role == ImageSetRole::WorkloadKernel(profile)
            && member.target.admits(arch)
            && member.build_mode.is_none()
    });
    let kernel = kernels.next().ok_or_else(refused)?;
    if kernels.next().is_some() || kernel.artifacts.len() != 1 {
        return Err(refused());
    }
    let mut roots = image_set.members.iter().filter(|member| {
        member.role == ImageSetRole::WorkloadRootfs(profile)
            && member.target.admits(arch)
            && member.build_mode == kernel.build_mode
    });
    let rootfs = roots.next().ok_or_else(refused)?;
    if roots.next().is_some()
        || rootfs
            .artifacts
            .iter()
            .filter(|artifact| artifact.format == ArtifactFormat::TarGz)
            .count()
            != 1
    {
        return Err(refused());
    }
    let mut selected = image_set.clone();
    selected.members.retain(|member| {
        !matches!(
            member.role,
            ImageSetRole::WorkloadKernel(_) | ImageSetRole::WorkloadRootfs(_)
        ) || member == kernel
            || member == rootfs
    });
    select_workload_image(
        &selected,
        profile,
        arch,
        &BackendImageSupport::for_backend(crate::vm_backend::BackendKind::Qemu)
            .expect("QEMU supports portable workload boot"),
    )
    .map_err(|_| refused())?;
    Ok((kernel, rootfs))
}

/// Select the same sealed local kernel and tar source the bundle reader accepts.
/// These are declarations, not verified bytes or permission to boot.
pub fn select_local_development_source(
    image_set: &ImageSetManifest,
    arch: GuestArch,
    profile: WorkloadImageProfile,
) -> Result<(&MemberArtifact, &MemberArtifact), BundleVerifyError> {
    let (kernel, rootfs) = local_development_pair(image_set, arch, profile)?;
    let tar = rootfs
        .artifacts
        .iter()
        .find(|artifact| artifact.format == ArtifactFormat::TarGz)
        .expect("unique tar checked by local development pair");
    Ok((&kernel.artifacts[0], tar))
}

/// Find exactly one local kernel and same-profile rootfs whose tar matches the proof.
pub fn select_local_development_base<'a>(
    image_set: &'a ImageSetManifest,
    arch: GuestArch,
    kernel_sha256: &str,
    kernel_size: u64,
    proof: &LocalDevelopmentBaseProof,
) -> Result<(&'a ImageSetMember, &'a ImageSetMember), BundleVerifyError> {
    let refused = || {
        BundleVerifyError::ManifestParse(
            "local base does not bind one matching kernel/rootfs source pair".into(),
        )
    };
    let mut pairs = [
        WorkloadImageProfile::DefaultTenant,
        WorkloadImageProfile::RootlessTenant,
    ]
    .into_iter()
    .filter_map(|profile| {
        let (kernel, rootfs) = local_development_pair(image_set, arch, profile).ok()?;
        let selected_kernel = &kernel.artifacts[0];
        let tar = rootfs
            .artifacts
            .iter()
            .find(|artifact| artifact.format == ArtifactFormat::TarGz)
            .expect("unique tar checked by local development pair");
        (selected_kernel.sha256.as_str() == kernel_sha256
            && selected_kernel.size == kernel_size
            && tar.sha256.as_str() == proof.composition_tar_sha256
            && tar.size == proof.composition_tar_size)
            .then_some((kernel, rootfs))
    });
    let pair = pairs.next().ok_or_else(refused)?;
    if pairs.next().is_some() {
        return Err(refused());
    }
    Ok(pair)
}
