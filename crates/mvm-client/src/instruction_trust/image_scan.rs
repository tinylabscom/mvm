//! Inspect the materialized filesystem a persistent guest will mount.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use mvm_fs::tree_diff::{EntryInfo, EntryKind, Ext4Tree, TreeSource};

use super::is_sidecar_name;
use super::policy::EffectivePolicy;
use super::scan::{InstructionFile, RootKind};
use super::verify::{
    Failure, FileReport, MAX_INSTRUCTION_FILE_BYTES, MAX_INSTRUCTION_SIDECAR_BYTES, verify_bytes,
};

const MAX_IMAGE_ENTRIES: u64 = 500_000;

/// Scan the actual disk-image bytes attached to the guest, including sidecars.
pub(crate) fn scan_image(image: &Path, policy: &EffectivePolicy) -> Result<Vec<FileReport>> {
    let fs = Ext4Tree::open(image)
        .with_context(|| format!("opening mount image {}", image.display()))?;
    let entries = fs
        .entries(MAX_IMAGE_ENTRIES)
        .with_context(|| format!("enumerating mount image {}", image.display()))?;
    let mut reports = Vec::new();
    for (relative, info) in &entries {
        if info.kind == EntryKind::Directory
            || relative.split('/').any(|component| component == ".git")
            || relative.rsplit('/').next().is_some_and(is_sidecar_name)
            || !policy.includes(Path::new(relative))
        {
            continue;
        }
        let file = InstructionFile {
            root: image.to_path_buf(),
            root_kind: RootKind::Mount,
            relative: relative.clone(),
            path: image.join(relative),
        };
        let content = read_file(&fs, relative, info, MAX_INSTRUCTION_FILE_BYTES);
        reports.push(verify_bytes(file, content, policy, |sidecar| {
            read_sidecar(&fs, &entries, image, sidecar)
        }));
    }
    Ok(reports)
}

fn read_file(
    fs: &Ext4Tree,
    relative: &str,
    info: &EntryInfo,
    limit: u64,
) -> std::result::Result<Vec<u8>, String> {
    if info.kind != EntryKind::File {
        return Err("instruction path is not a regular file in the mounted image".to_string());
    }
    if info.size > limit {
        return Err(format!(
            "{} bytes exceeds the {limit}-byte limit",
            info.size
        ));
    }
    let bytes = fs
        .read_prefix(relative, limit)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != info.size {
        return Err("instruction file changed during the image read".to_string());
    }
    Ok(bytes)
}

fn read_sidecar(
    fs: &Ext4Tree,
    entries: &BTreeMap<String, EntryInfo>,
    image: &Path,
    path: &Path,
) -> Option<std::result::Result<Vec<u8>, Failure>> {
    let relative = path.strip_prefix(image).ok()?.to_str()?;
    let info = entries.get(relative)?;
    Some(
        read_file(fs, relative, info, MAX_INSTRUCTION_SIDECAR_BYTES).map_err(|detail| {
            Failure::Unreadable {
                detail: format!("reading signature beside {relative}: {detail}"),
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_image_is_not_a_clean_scan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = dir.path().join("invalid.ext4");
        std::fs::write(&image, b"not ext4").expect("write image");
        assert!(scan_image(&image, &EffectivePolicy::builtin()).is_err());
    }
}
