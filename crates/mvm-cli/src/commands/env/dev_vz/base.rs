use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(feature = "builder-vm")]
use super::DEV_BASE_PROVENANCE_FILE;

/// User-facing base-image reference accepted by `mvmctl dev up --base`.
///
/// The `id` is resolved by the existing template dispatcher, so it may be a
/// legacy template name, manifest slot hash, or installed bundle sha. A
/// revision pin (`name@revision`) is supported for template/slot bases only;
/// bundles are already content-addressed by their sha.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct DevBaseRef {
    pub(super) id: String,
    pub(super) revision: Option<String>,
}

impl DevBaseRef {
    pub(in crate::commands) fn parse(raw: &str) -> Result<Self> {
        let (id, revision) = match raw.split_once('@') {
            Some((id, revision)) => {
                if revision.is_empty() {
                    anyhow::bail!("dev base revision cannot be empty");
                }
                (id, Some(revision.to_string()))
            }
            None => (raw, None),
        };
        if id.is_empty() {
            anyhow::bail!("dev base id cannot be empty");
        }
        if !mvm_core::manifest::is_slot_hash_dirname(id) {
            mvm_core::naming::validate_template_name(id)
                .with_context(|| format!("invalid dev base template name: {id:?}"))?;
        }
        if let Some(rev) = revision.as_deref()
            && !is_safe_base_component(rev)
        {
            anyhow::bail!("invalid dev base revision: {rev:?}");
        }
        Ok(Self {
            id: id.to_string(),
            revision,
        })
    }
}

#[cfg(feature = "builder-vm")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedDevBaseImage {
    pub(super) id: String,
    pub(super) revision: String,
    pub(super) kernel_path: std::path::PathBuf,
    pub(super) rootfs_path: std::path::PathBuf,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct DevBaseProvenance {
    pub(super) schema_version: u8,
    pub(super) id: String,
    pub(super) revision: String,
    pub(super) rootfs_fingerprint: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub(in crate::commands) struct DevBaseStatusJson {
    pub id: String,
    pub revision: String,
    pub rootfs_fingerprint: String,
}

fn is_safe_base_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(feature = "builder-vm")]
pub(super) fn resolve_dev_base_image(base: &DevBaseRef) -> Result<ResolvedDevBaseImage> {
    match base.revision.as_deref() {
        Some(revision) => resolve_dev_base_pinned_revision(&base.id, revision),
        None => {
            let (_spec, kernel, _initrd, rootfs, revision) =
                mvm::vm::template::lifecycle::template_artifacts_dispatched(&base.id)
                    .with_context(|| format!("resolving dev base {:?}", base.id))?;
            Ok(ResolvedDevBaseImage {
                id: base.id.clone(),
                revision,
                kernel_path: std::path::PathBuf::from(kernel),
                rootfs_path: std::path::PathBuf::from(rootfs),
            })
        }
    }
}

#[cfg(feature = "builder-vm")]
fn resolve_dev_base_pinned_revision(id: &str, revision: &str) -> Result<ResolvedDevBaseImage> {
    let rev_dir = if mvm_core::manifest::is_slot_hash_dirname(id) {
        let slot_dir = std::path::PathBuf::from(mvm_core::manifest::slot_dir(id));
        if !slot_dir.exists() {
            anyhow::bail!(
                "dev base {id}@{revision} is not a built template slot; bundle bases are \
                 content-addressed, so omit @revision for installed bundle shas"
            );
        }
        mvm::vm::template::lifecycle::template_load_slot(id)
            .with_context(|| format!("loading dev base slot {id}"))?;
        std::path::PathBuf::from(mvm_core::manifest::slot_revision_dir(id, revision))
    } else {
        mvm::vm::template::lifecycle::template_load(id)
            .with_context(|| format!("loading dev base template {id:?}"))?;
        std::path::PathBuf::from(mvm_core::template::template_revision_dir(id, revision))
    };
    dev_base_artifacts_from_revision_dir(id, revision, &rev_dir)
}

#[cfg(feature = "builder-vm")]
pub(super) fn dev_base_artifacts_from_revision_dir(
    id: &str,
    revision: &str,
    rev_dir: &std::path::Path,
) -> Result<ResolvedDevBaseImage> {
    let kernel_path = rev_dir.join("vmlinux");
    if !kernel_path.is_file() {
        anyhow::bail!("dev base {id}@{revision} has no vmlinux artifact");
    }
    let rootfs_path = rev_dir.join("rootfs.ext4");
    if !rootfs_path.is_file() {
        anyhow::bail!("dev base {id}@{revision} has no rootfs artifact");
    }
    Ok(ResolvedDevBaseImage {
        id: id.to_string(),
        revision: revision.to_string(),
        kernel_path,
        rootfs_path,
    })
}

#[cfg(feature = "builder-vm")]
pub(super) fn dev_base_provenance_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join(DEV_BASE_PROVENANCE_FILE)
}

#[cfg(feature = "builder-vm")]
pub(super) fn write_dev_base_provenance(
    state_dir: &std::path::Path,
    base: &ResolvedDevBaseImage,
) -> Result<DevBaseProvenance> {
    let rootfs_fingerprint = mvm_core::crypto::image_verify::sha256_file_cached(&base.rootfs_path)
        .with_context(|| {
            format!(
                "fingerprinting pinned dev base rootfs {}",
                base.rootfs_path.display()
            )
        })?;
    let provenance = DevBaseProvenance {
        schema_version: 1,
        id: base.id.clone(),
        revision: base.revision.clone(),
        rootfs_fingerprint,
    };
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating dev VM state dir {}", state_dir.display()))?;
    let json = serde_json::to_vec_pretty(&provenance).context("serializing dev base provenance")?;
    std::fs::write(dev_base_provenance_path(state_dir), json)
        .with_context(|| format!("writing {}", dev_base_provenance_path(state_dir).display()))?;
    Ok(provenance)
}

#[cfg(feature = "builder-vm")]
pub(super) fn read_dev_base_provenance(state_dir: &std::path::Path) -> Option<DevBaseProvenance> {
    let path = dev_base_provenance_path(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not read dev base provenance");
            return None;
        }
    };
    match serde_json::from_slice::<DevBaseProvenance>(&bytes) {
        Ok(provenance) if provenance.schema_version == 1 => Some(provenance),
        Ok(provenance) => {
            tracing::warn!(
                schema_version = provenance.schema_version,
                path = %path.display(),
                "ignoring unsupported dev base provenance schema"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not parse dev base provenance");
            None
        }
    }
}

#[cfg(feature = "builder-vm")]
pub(super) fn remove_dev_base_provenance(state_dir: &std::path::Path) {
    let path = dev_base_provenance_path(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not remove dev base provenance")
        }
    }
}

#[cfg(not(feature = "builder-vm"))]
pub(super) fn read_dev_base_provenance(_state_dir: &std::path::Path) -> Option<DevBaseProvenance> {
    None
}
