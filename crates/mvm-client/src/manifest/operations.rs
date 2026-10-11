//! Mutations resolve current registry state; reports are never deletion authority.

use super::*;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RemoveRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub manifest_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RemoveReport {
    pub slot_hash: String,
    pub manifest_path: PathBuf,
    pub manifest_file_deleted: bool,
}

/// `orphans` explicitly selects the destructive mode. The library defaults to
/// preview; the CLI explicitly maps its existing `--dry-run` flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PruneRequest {
    #[serde(default)]
    pub orphans: bool,
    #[serde(default = "preview")]
    pub dry_run: bool,
}

fn preview() -> bool {
    true
}

impl Default for PruneRequest {
    fn default() -> Self {
        Self {
            orphans: false,
            dry_run: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PruneCandidate {
    pub slot_hash: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PruneReport {
    pub dry_run: bool,
    pub candidates: Vec<PruneCandidate>,
    pub removed_count: usize,
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ExportOciRequest {
    pub template: String,
    pub out: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExportOciReport {
    pub slot_hash: String,
    pub path: PathBuf,
    pub size_bytes: u64,
}

fn checked_slot(slot_hash: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        mvm_core::manifest::is_slot_hash_dirname(slot_hash),
        "invalid slot hash"
    );
    let path = PathBuf::from(mvm_core::manifest::slot_dir(slot_hash));
    let metadata = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "slot is not a real directory"
    );
    let parent = path
        .parent()
        .context("slot has no parent")?
        .canonicalize()?;
    anyhow::ensure!(
        path.canonicalize()?.parent() == Some(parent.as_path()),
        "slot escapes registry"
    );
    Ok(path)
}

fn check_identity(slot_hash: &str, persisted: &PersistedManifest) -> Result<()> {
    anyhow::ensure!(
        persisted.manifest_hash == slot_hash
            && mvm_core::manifest::key_for_manifest_identity(&persisted.manifest_path) == slot_hash,
        "slot records mismatched manifest identity"
    );
    Ok(())
}

/// Both stopped persistent machines and live backend state retain their
/// artifacts. A broken registry is not evidence that a slot is unreferenced.
fn retained_slot(slot_hash: &str) -> Result<bool> {
    for spec in mvm_runtime::machine::persist::list_machine_specs()? {
        if let Some(manifest) = spec.manifest {
            if manifest == slot_hash {
                return Ok(true);
            }
            if let Ok((_, key)) = resolve(Some(&manifest), "")
                && key == slot_hash
            {
                return Ok(true);
            }
            if Path::new(&manifest).is_absolute()
                && mvm_core::manifest::key_for_manifest_identity(&manifest) == slot_hash
            {
                return Ok(true);
            }
        }
    }
    let slot = PathBuf::from(mvm_core::manifest::slot_dir(slot_hash));
    let root = mvm_core::config::vm_state_dir("");
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        for name in ["rootfs.ref", "kernel.ref"] {
            let reference = match std::fs::read_to_string(entry.path().join(name)) {
                Ok(reference) => reference,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let path = Path::new(reference.trim());
            if path.starts_with(&slot)
                || path
                    .canonicalize()
                    .ok()
                    .zip(slot.canonicalize().ok())
                    .is_some_and(|(path, slot)| path.starts_with(slot))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub fn remove(request: &RemoveRequest) -> Result<RemoveReport> {
    let (manifest_path, slot_hash) = resolve(
        request.path.as_deref(),
        "No manifest found from cwd. Pass a path explicitly or `--force` if removing an orphaned slot by hash.",
    )?;
    let source_identity = std::fs::metadata(&manifest_path)?;
    if request.manifest_file {
        super::check_export_destination(&manifest_path)?;
    }
    let slot = PathBuf::from(mvm_core::manifest::slot_dir(&slot_hash));
    if std::fs::symlink_metadata(&slot).is_ok() {
        checked_slot(&slot_hash)?;
        if let Ok(persisted) = tmpl::template_load_slot(&slot_hash) {
            check_identity(&slot_hash, &persisted)?;
        }
        anyhow::ensure!(!retained_slot(&slot_hash)?, "slot is retained by a machine");
    }
    tmpl::template_delete_slot(&slot_hash, request.force)?;
    let manifest_file_deleted = request.manifest_file && manifest_path.exists();
    if manifest_file_deleted {
        let current = std::fs::symlink_metadata(&manifest_path)?;
        anyhow::ensure!(
            current.is_file()
                && current.dev() == source_identity.dev()
                && current.ino() == source_identity.ino(),
            "manifest file changed during slot removal"
        );
        std::fs::remove_file(&manifest_path).with_context(|| {
            format!("Failed to delete manifest file {}", manifest_path.display())
        })?;
    }
    mvm_core::audit_emit!(
        SlotRemove,
        vm: slot_hash.clone(),
        "manifest_path={} manifest_file_deleted={manifest_file_deleted}",
        manifest_path.display(),
    );
    Ok(RemoveReport {
        slot_hash,
        manifest_path,
        manifest_file_deleted,
    })
}

fn classify(slot_hash: &str) -> Result<Option<PruneCandidate>> {
    checked_slot(slot_hash)?;
    if retained_slot(slot_hash)? {
        return Ok(None);
    }
    let reason = match tmpl::template_load_slot(slot_hash) {
        Ok(persisted) => {
            check_identity(slot_hash, &persisted)?;
            if Path::new(&persisted.manifest_path).try_exists()? {
                return Ok(None);
            }
            format!("manifest gone: {}", persisted.manifest_path)
        }
        Err(error) => format!("unreadable manifest.json: {error}"),
    };
    Ok(Some(PruneCandidate {
        slot_hash: slot_hash.to_owned(),
        reason,
    }))
}

pub(super) fn candidate_unchanged(
    candidate: &PruneCandidate,
    before: &std::fs::Metadata,
) -> Result<bool> {
    if classify(&candidate.slot_hash)?.as_ref() != Some(candidate) {
        return Ok(false);
    }
    let current = std::fs::symlink_metadata(checked_slot(&candidate.slot_hash)?)?;
    Ok(current.dev() == before.dev() && current.ino() == before.ino())
}

pub fn prune(request: &PruneRequest) -> Result<PruneReport> {
    anyhow::ensure!(
        request.orphans,
        "no prune mode specified. Pass `--orphans` to remove slots whose manifest file is gone."
    );
    let mut report = PruneReport {
        dry_run: request.dry_run,
        candidates: Vec::new(),
        removed_count: 0,
        removed: Vec::new(),
    };
    for slot_hash in tmpl::template_list_slot_hashes()? {
        let Some(candidate) = classify(&slot_hash)? else {
            continue;
        };
        let path = checked_slot(&slot_hash)?;
        let before = std::fs::symlink_metadata(&path)?;
        report.candidates.push(candidate.clone());
        if request.dry_run {
            continue;
        }
        // Re-read classification and directory identity immediately before the
        // runtime delete; never apply the preview's stale classification.
        if !candidate_unchanged(&candidate, &before)? {
            continue;
        }
        match tmpl::template_delete_slot(&slot_hash, true) {
            Ok(()) => report.removed.push(slot_hash),
            Err(error) => {
                tracing::warn!(slot = %slot_hash, %error, "failed to remove orphaned slot")
            }
        }
    }
    report.removed_count = report.removed.len();
    if !request.dry_run {
        let count = report.removed_count;
        mvm_core::audit_emit!(SlotPrune, "source=manifest_prune count={count}");
    }
    Ok(report)
}

pub fn export_oci(request: &ExportOciRequest) -> Result<ExportOciReport> {
    let slot_hash = super::resolve_artifact_key(&request.template)?;
    let (_, _, _, rootfs_path, _) = tmpl::template_artifacts_dispatched(&slot_hash)
        .with_context(|| format!("resolving template artifacts for {:?}", request.template))?;
    let rev_dir = Path::new(&rootfs_path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent: {rootfs_path}"))?;
    let oci_src = rev_dir.join("image.tar.gz");
    if !oci_src.exists() {
        anyhow::bail!(
            "no OCI tarball at {} — this template wasn't built with the OCI output enabled. \
             Rebuild after wiring `dockerTools.streamLayeredImage` into the flake's mkGuest \
             call, or use `mvmctl bundle export` for a signed .mvmpkg instead.",
            oci_src.display()
        );
    }
    let oci_src = super::checked_artifact(&slot_hash, &oci_src)?;
    super::check_export_destination(&request.out)?;
    if let Some(parent) = request.out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let parent = request
        .out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let mut input = std::fs::File::open(&oci_src)?;
    let bytes = std::io::copy(&mut input, output.as_file_mut()).with_context(|| {
        format!(
            "copying OCI tarball {} -> {}",
            oci_src.display(),
            request.out.display()
        )
    })?;
    super::check_export_destination(&request.out)?;
    output.persist(&request.out)?;
    mvm_core::audit_emit!(ImageExportOci, "template={slot_hash},bytes={bytes}");
    Ok(ExportOciReport {
        slot_hash,
        path: request.out.clone(),
        size_bytes: bytes,
    })
}
