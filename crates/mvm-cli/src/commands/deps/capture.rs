//! Import a dependency tree discovered in a development sandbox.
//!
//! The sandbox install itself remains a dev-only operation. This command owns
//! the host-side handoff: it copies captured content and fresh audit sidecars
//! into a scratch volume, reseals them, and atomically publishes the new hash
//! under the existing lockfile index entry.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Args as ClapArgs;
use serde::Serialize;
use std::path::{Path, PathBuf};

use mvm_sdk::compile::deps_audit::{
    FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, VolumeManifest,
    reseal_volume, verify_sealed_volume,
};

use super::audit::{copy_dir_recursive, refresh_index_pointer};

/// Arguments for importing a dependency tree captured from a development
/// sandbox. The sidecars must come from the same capture as the content.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Existing sealed dependency volume to replace.
    #[arg(value_name = "VOLUME_HASH")]
    pub volume_hash: String,

    /// Local directory containing the dependency tree captured from the sandbox.
    #[arg(long, value_name = "DIR")]
    pub content_dir: PathBuf,

    /// Fresh CycloneDX SBOM generated for the captured dependency tree.
    #[arg(long, value_name = "PATH")]
    pub sbom: PathBuf,

    /// Fetch log generated while installing the captured dependency tree.
    #[arg(long, value_name = "PATH")]
    pub fetch_log: PathBuf,

    /// Fresh CVE scan result generated for the captured dependency tree.
    #[arg(long, value_name = "PATH")]
    pub cve: PathBuf,

    /// Override the sealed dependency-volume cache root.
    #[arg(long)]
    pub cache_root: Option<PathBuf>,

    /// Emit a machine-readable JSON result on stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CaptureOutcome {
    prior_volume_hash: String,
    volume_hash: String,
    lockfile_hash: String,
    volume_dir: PathBuf,
}

pub(super) fn run(args: Args) -> Result<()> {
    let cache_root = mvm_build::app_deps::resolve_cache_root(args.cache_root.as_deref());
    let outcome = capture_volume(
        &cache_root,
        &args.volume_hash,
        &args.content_dir,
        &args.sbom,
        &args.fetch_log,
        &args.cve,
    )?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        eprintln!(
            "captured dependency volume {} -> {} (lockfile_hash {})",
            outcome.prior_volume_hash, outcome.volume_hash, outcome.lockfile_hash
        );
    }
    Ok(())
}

fn capture_volume(
    cache_root: &Path,
    prior_hash: &str,
    captured_content: &Path,
    sbom: &Path,
    fetch_log: &Path,
    cve: &Path,
) -> Result<CaptureOutcome> {
    validate_volume_hash(prior_hash)?;
    require_directory(captured_content, "captured content")?;
    require_file(sbom, "SBOM")?;
    require_file(fetch_log, "fetch log")?;
    require_file(cve, "CVE result")?;

    let prior_dir = cache_root.join(prior_hash);
    let computed = verify_sealed_volume(&prior_dir).with_context(|| {
        format!(
            "verifying dependency volume {}; capture refuses tampered input",
            prior_dir.display()
        )
    })?;
    if computed != prior_hash {
        bail!(
            "dependency volume directory {} disagrees with its sealed hash {}",
            prior_hash,
            computed
        );
    }
    let prior_manifest = read_manifest(&prior_dir)?;
    let lockfile_hash = prior_manifest
        .annotations
        .get("lockfile_hash")
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "dependency volume {} has no lockfile_hash annotation; captured dependencies must remain pinned",
                prior_hash
            )
        })?;
    validate_hash(&lockfile_hash, "lockfile")?;

    let scratch = scratch_dir(cache_root, prior_hash)?;
    let result = (|| {
        copy_dir_recursive(captured_content, &scratch.join(FILE_CONTENT_DIR))?;
        for (source, name) in [
            (sbom, FILE_SBOM),
            (fetch_log, FILE_FETCH_LOG),
            (cve, FILE_CVE),
        ] {
            std::fs::copy(source, scratch.join(name))
                .with_context(|| format!("copying captured {} into scratch volume", name))?;
        }

        let sealed = reseal_volume(
            &scratch.join(FILE_CONTENT_DIR),
            &scratch.join(FILE_SBOM),
            &scratch.join(FILE_FETCH_LOG),
            &scratch.join(FILE_CVE),
            prior_manifest.created_at,
            Utc::now().to_rfc3339(),
            prior_manifest.annotations,
        )?;
        std::fs::write(scratch.join(FILE_MANIFEST), &sealed.manifest_bytes)
            .context("writing captured dependency volume manifest")?;

        let new_dir = cache_root.join(&sealed.volume_hash);
        if new_dir.exists() {
            let existing = verify_sealed_volume(&new_dir).with_context(|| {
                format!("verifying existing captured volume {}", new_dir.display())
            })?;
            if existing != sealed.volume_hash {
                bail!(
                    "existing volume directory {} failed its own sealed-hash check",
                    new_dir.display()
                );
            }
            std::fs::remove_dir_all(&scratch)
                .with_context(|| format!("removing scratch volume {}", scratch.display()))?;
        } else {
            std::fs::rename(&scratch, &new_dir).with_context(|| {
                format!(
                    "publishing captured volume {} as {}",
                    scratch.display(),
                    new_dir.display()
                )
            })?;
        }

        refresh_index_pointer(cache_root, &lockfile_hash, &sealed.volume_hash)?;
        if new_dir != prior_dir {
            std::fs::remove_dir_all(&prior_dir)
                .with_context(|| format!("removing prior volume {}", prior_dir.display()))?;
        }
        Ok(CaptureOutcome {
            prior_volume_hash: prior_hash.to_string(),
            volume_hash: sealed.volume_hash,
            lockfile_hash,
            volume_dir: new_dir,
        })
    })();
    if result.is_err() && scratch.exists() {
        let _ = std::fs::remove_dir_all(&scratch);
    }
    result
}

fn read_manifest(volume_dir: &Path) -> Result<VolumeManifest> {
    let path = volume_dir.join(FILE_MANIFEST);
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn scratch_dir(cache_root: &Path, prior_hash: &str) -> Result<PathBuf> {
    let root = cache_root.join("in-progress");
    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    let scratch = root.join(format!("capture-{prior_hash}.{}", std::process::id()));
    if scratch.exists() {
        std::fs::remove_dir_all(&scratch)
            .with_context(|| format!("removing stale scratch {}", scratch.display()))?;
    }
    std::fs::create_dir_all(&scratch)
        .with_context(|| format!("creating scratch {}", scratch.display()))?;
    Ok(scratch)
}

fn validate_volume_hash(value: &str) -> Result<()> {
    validate_hash(value, "volume")
}

fn validate_hash(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} hash must be exactly 64 hexadecimal characters");
    }
    Ok(())
}

fn require_directory(path: &Path, label: &str) -> Result<()> {
    if !path.is_dir() {
        bail!("{} directory does not exist: {}", label, path.display());
    }
    Ok(())
}

fn require_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{} file does not exist: {}", label, path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_sdk::compile::deps_audit::seal_volume;
    use std::collections::BTreeMap;
    use std::fs;

    const LOCKFILE_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn seed_volume(root: &Path, lockfile_hash: Option<&str>) -> String {
        let volume = root.join("seed");
        let content = volume.join(FILE_CONTENT_DIR);
        fs::create_dir_all(&content).unwrap();
        fs::write(content.join("installed.txt"), b"old").unwrap();
        let sbom = volume.join(FILE_SBOM);
        let fetch = volume.join(FILE_FETCH_LOG);
        let cve = volume.join(FILE_CVE);
        fs::write(&sbom, b"old sbom").unwrap();
        fs::write(&fetch, b"old fetch\n").unwrap();
        fs::write(&cve, b"{\"results\":[]}").unwrap();
        let annotations = lockfile_hash
            .map(|hash| BTreeMap::from([("lockfile_hash".to_string(), hash.to_string())]))
            .unwrap_or_default();
        let sealed = seal_volume(
            &content,
            &sbom,
            &fetch,
            &cve,
            "2026-08-03T00:00:00Z",
            annotations,
        )
        .unwrap();
        fs::write(volume.join(FILE_MANIFEST), sealed.manifest_bytes).unwrap();
        let final_dir = root.join(&sealed.volume_hash);
        fs::rename(volume, &final_dir).unwrap();
        if let Some(lockfile_hash) = lockfile_hash {
            fs::create_dir_all(root.join("index")).unwrap();
            fs::write(root.join("index").join(lockfile_hash), &sealed.volume_hash).unwrap();
        }
        sealed.volume_hash
    }

    #[test]
    fn capture_reseals_content_and_refreshes_lockfile_index() {
        let tmp = tempfile::tempdir().unwrap();
        let old_hash = seed_volume(tmp.path(), Some(LOCKFILE_HASH));
        let captured = tmp.path().join("captured");
        fs::create_dir_all(&captured).unwrap();
        fs::write(captured.join("installed.txt"), b"new").unwrap();
        let sbom = tmp.path().join("sbom.json");
        let fetch = tmp.path().join("fetch.log");
        let cve = tmp.path().join("cve.json");
        fs::write(&sbom, b"new sbom").unwrap();
        fs::write(&fetch, b"new fetch\n").unwrap();
        fs::write(&cve, b"{\"results\":[]}").unwrap();

        let outcome =
            capture_volume(tmp.path(), &old_hash, &captured, &sbom, &fetch, &cve).unwrap();
        assert_ne!(outcome.prior_volume_hash, outcome.volume_hash);
        assert!(!tmp.path().join(&old_hash).exists());
        assert_eq!(
            fs::read_to_string(tmp.path().join("index").join(LOCKFILE_HASH)).unwrap(),
            outcome.volume_hash
        );
        assert_eq!(
            verify_sealed_volume(&outcome.volume_dir).unwrap(),
            outcome.volume_hash
        );
    }

    #[test]
    fn capture_refuses_unpinned_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let old_hash = seed_volume(tmp.path(), None);
        let captured = tmp.path().join("captured");
        fs::create_dir_all(&captured).unwrap();
        let sbom = tmp.path().join("sbom.json");
        let fetch = tmp.path().join("fetch.log");
        let cve = tmp.path().join("cve.json");
        fs::write(&sbom, b"sbom").unwrap();
        fs::write(&fetch, b"fetch\n").unwrap();
        fs::write(&cve, b"{}").unwrap();
        assert!(capture_volume(tmp.path(), &old_hash, &captured, &sbom, &fetch, &cve).is_err());
        assert!(tmp.path().join(&old_hash).exists());
    }

    #[test]
    fn capture_refuses_tampered_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let old_hash = seed_volume(tmp.path(), Some(LOCKFILE_HASH));
        fs::write(
            tmp.path()
                .join(&old_hash)
                .join(FILE_CONTENT_DIR)
                .join("installed.txt"),
            b"tampered",
        )
        .unwrap();
        let captured = tmp.path().join("captured");
        fs::create_dir_all(&captured).unwrap();
        let sbom = tmp.path().join("sbom.json");
        let fetch = tmp.path().join("fetch.log");
        let cve = tmp.path().join("cve.json");
        fs::write(&sbom, b"sbom").unwrap();
        fs::write(&fetch, b"fetch\n").unwrap();
        fs::write(&cve, b"{}").unwrap();
        assert!(capture_volume(tmp.path(), &old_hash, &captured, &sbom, &fetch, &cve).is_err());
    }
}
