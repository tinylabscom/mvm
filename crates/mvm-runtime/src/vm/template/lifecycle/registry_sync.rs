//! Push/pull/verify a legacy name-keyed template's revision artifacts
//! against a [`TemplateRegistry`] (content-addressed remote object
//! store), plus the shared download-and-checksum-verify primitive
//! both the CLI and fleet agents build on.

use anyhow::{Context, Result};
use mvm_core::template::{template_current_symlink, template_dir, template_revision_dir};
use tracing::{instrument, warn};

use super::artifacts::{Checksums, current_revision_id, sha256_hex};
use super::require_local_template_fs;
use crate::vm::template::registry::TemplateRegistry;

/// Download a template revision's artifacts from the registry to a local directory.
///
/// Downloads all artifact files listed in `checksums.json`, verifies SHA-256
/// integrity, and writes them to `output_dir`. The directory must already exist.
///
/// This is the core download logic shared by [`template_pull()`] (writes to
/// template dir) and fleet agents (write to pool artifacts dir).
///
/// Returns the revision hash and the list of downloaded file names.
#[instrument(skip_all, fields(template_id))]
pub fn registry_download_revision(
    registry: &TemplateRegistry,
    template_id: &str,
    revision: Option<&str>,
    output_dir: &std::path::Path,
) -> Result<(String, Vec<String>)> {
    // Resolve revision from registry "current" pointer if not specified.
    let rev = match revision {
        Some(r) => r.to_string(),
        None => {
            let current = registry
                .get_text(&registry.key_current(template_id))?
                .trim()
                .to_string();
            if current.is_empty() {
                anyhow::bail!(
                    "Registry current revision is empty for template {}",
                    template_id
                );
            }
            current
        }
    };

    // Download checksums manifest.
    let sums_key = registry.key_revision_file(template_id, &rev, "checksums.json");
    let sums_bytes = registry.get_bytes(&sums_key)?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)
        .with_context(|| format!("Invalid checksums.json for {}/{}", template_id, rev))?;

    // Download each file and verify SHA-256.
    let mut downloaded_files = Vec::new();
    for (name, expected_hex) in &checksums.files {
        let key = registry.key_revision_file(template_id, &rev, name);
        let data = registry.get_bytes(&key)?;
        let file_path = output_dir.join(name);
        mvm_core::atomic_io::atomic_write(&file_path, &data)
            .with_context(|| format!("Failed to write {}", file_path.display()))?;
        let got = sha256_hex(&file_path)?;
        if &got != expected_hex {
            anyhow::bail!(
                "checksum mismatch for {} (expected {}, got {})",
                name,
                expected_hex,
                got
            );
        }
        downloaded_files.push(name.clone());
    }

    // Write checksums.json alongside the artifacts for offline verification.
    mvm_core::atomic_io::atomic_write(&output_dir.join("checksums.json"), &sums_bytes)
        .context("Failed to write checksums.json")?;

    Ok((rev, downloaded_files))
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_push(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;
    let registry = TemplateRegistry::from_env()?.context("Template registry not configured")?;
    registry.require_configured()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id(id)?,
    };

    let template_dir = template_dir(id);
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));

    let files = [
        (
            "template.json",
            std::path::PathBuf::from(format!("{}/template.json", template_dir)),
        ),
        ("revision.json", rev_dir.join("revision.json")),
        ("vmlinux", rev_dir.join("vmlinux")),
        ("rootfs.ext4", rev_dir.join("rootfs.ext4")),
        ("fc-base.json", rev_dir.join("fc-base.json")),
    ];

    // Compute checksums for integrity.
    let mut sums = std::collections::BTreeMap::new();
    for (name, path) in &files {
        let hex = sha256_hex(path)?;
        sums.insert(name.to_string(), hex);
    }
    let checksums = Checksums {
        schema_version: 1,
        template_id: id.to_string(),
        revision_hash: rev.clone(),
        files: sums,
    };
    let checksums_json = serde_json::to_vec_pretty(&checksums)?;
    // Store checksums locally alongside the revision so `template verify` works offline.
    mvm_core::atomic_io::atomic_write(&rev_dir.join("checksums.json"), &checksums_json)
        .with_context(|| {
            format!(
                "Failed to write checksums.json for template {} revision {}",
                id, rev
            )
        })?;

    // Upload revision objects first, then current pointer.
    for (name, path) in &files {
        let key = registry.key_revision_file(id, &rev, name);
        let data =
            std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
        registry.put_bytes(&key, data)?;
    }
    registry.put_bytes(
        &registry.key_revision_file(id, &rev, "checksums.json"),
        checksums_json,
    )?;
    registry.put_text(&registry.key_current(id), &format!("{}\n", rev))?;

    tracing::info!(template = %id, revision = %rev, "Pushed template revision to registry");
    Ok(())
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_pull(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;
    let registry = TemplateRegistry::from_env()?.context("Template registry not configured")?;
    registry.require_configured()?;

    let base_dir = std::path::PathBuf::from(template_dir(id));
    std::fs::create_dir_all(&base_dir)?;

    // Download to a temp dir, then move into place.
    let tmp_label = revision.unwrap_or("latest");
    let tmp_dir = base_dir.join(format!("tmp-pull-{}", tmp_label));
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir).ok();
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let (rev, _files) = match registry_download_revision(&registry, id, revision, &tmp_dir) {
        Ok(result) => result,
        Err(e) => {
            std::fs::remove_dir_all(&tmp_dir).ok();
            return Err(e);
        }
    };

    // Install into final revision dir.
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));
    std::fs::create_dir_all(rev_dir.parent().unwrap_or(&base_dir))?;
    if rev_dir.exists() {
        std::fs::remove_dir_all(&rev_dir).ok();
    }
    std::fs::rename(&tmp_dir, &rev_dir).with_context(|| {
        format!(
            "Failed to move {} to {}",
            tmp_dir.display(),
            rev_dir.display()
        )
    })?;

    // Update current symlink.
    let link = template_current_symlink(id);
    if let Err(e) = std::fs::remove_file(&link) {
        warn!("failed to remove old current symlink: {e}");
    }
    std::os::unix::fs::symlink(format!("revisions/{}", rev), &link)?;

    tracing::info!(template = %id, revision = %rev, "Pulled template revision from registry");
    Ok(())
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_verify(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id(id)?,
    };
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));
    let sums_path = rev_dir.join("checksums.json");
    let sums_bytes =
        std::fs::read(&sums_path).with_context(|| format!("Missing {}", sums_path.display()))?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)?;

    for (name, expected_hex) in &checksums.files {
        let p = rev_dir.join(name);
        let got = sha256_hex(&p)?;
        if &got != expected_hex {
            anyhow::bail!(
                "checksum mismatch for {} (expected {}, got {})",
                name,
                expected_hex,
                got
            );
        }
    }

    Ok(())
}
