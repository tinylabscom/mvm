//! Artifact resolution for transient launch sources.

use super::ImageSource;
use anyhow::{Context, Result};

/// Kernel/rootfs/initrd + provenance resolved from `req.image`: either a
/// named template lookup (which also probes for a snapshot) or a pre-built
/// kernel/rootfs pair carried through as-is.
pub(super) struct ResolvedImage {
    pub(super) vmlinux: String,
    pub(super) initrd: Option<String>,
    pub(super) rootfs: String,
    pub(super) revision: String,
    pub(super) flake_ref: String,
    pub(super) profile: Option<String>,
    pub(super) snap_info: Option<mvm_core::template::SnapshotInfo>,
    pub(super) template_id: Option<String>,
}

/// Resolve image artifacts: either a named template or a pre-built pair. For
/// templates, also probe for a pre-built snapshot so the caller can skip the
/// cold-boot cost when the request turns out to be snapshot-eligible.
pub(super) fn resolve_image_artifacts(image: &ImageSource, backend: &str) -> Result<ResolvedImage> {
    match image {
        ImageSource::RegistryPack { pin } => {
            let image =
                mvm_client::launch::built_pack::resolve_built_pack_image(pin, backend, "standard")?;
            Ok(ResolvedImage {
                vmlinux: image
                    .kernel_path
                    .context("built pack has no verified kernel")?,
                initrd: None,
                rootfs: image.rootfs_path,
                revision: image.revision_hash,
                flake_ref: image.flake_ref,
                profile: Some("standard".to_owned()),
                snap_info: None,
                template_id: None,
            })
        }
        ImageSource::Template(name) => {
            let (spec, vmlinux, initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_boot(name)
                    .with_context(|| format!("Loading template '{name}'"))?;
            let snap_info =
                mvm_runtime::vm::template::lifecycle::template_snapshot_info_dispatched(name)
                    .ok()
                    .flatten();
            Ok(ResolvedImage {
                vmlinux,
                initrd,
                rootfs,
                revision: rev,
                flake_ref: spec.flake_ref.clone(),
                profile: Some(spec.profile.clone()),
                snap_info,
                template_id: Some(name.clone()),
            })
        }
        ImageSource::PinnedTemplate {
            slot_hash,
            revision_hash,
        } => {
            let (spec, vmlinux, initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_slot_revision(
                    slot_hash,
                    revision_hash,
                )
                .with_context(|| {
                    format!("Loading stored template revision {slot_hash}@{revision_hash}")
                })?;
            Ok(ResolvedImage {
                vmlinux,
                initrd,
                rootfs,
                revision: rev,
                flake_ref: spec.flake_ref,
                profile: Some(spec.profile),
                snap_info: None,
                template_id: Some(slot_hash.clone()),
            })
        }
        ImageSource::Prebuilt {
            kernel_path,
            rootfs_path,
            initrd_path,
            label,
            ..
        } => Ok(ResolvedImage {
            vmlinux: kernel_path.clone(),
            initrd: initrd_path.clone(),
            rootfs: rootfs_path.clone(),
            revision: String::new(),
            flake_ref: label.clone(),
            profile: None,
            snap_info: None,
            template_id: None,
        }),
        ImageSource::WasmModule { module_path, label } => Ok(ResolvedImage {
            vmlinux: String::new(),
            initrd: None,
            rootfs: module_path.clone(),
            revision: String::new(),
            flake_ref: label.clone(),
            profile: None,
            snap_info: None,
            template_id: None,
        }),
    }
}
