//! Import a dependency tree discovered in a development sandbox.
//!
//! The sandbox install itself remains a dev-only operation. This command owns
//! the host-side handoff: it copies captured content and fresh audit sidecars
//! into a scratch volume, reseals them, and atomically publishes the new hash
//! under the existing lockfile index entry. When the original lockfile is
//! supplied, it can also emit the same dependency declaration shape consumed
//! by the workload IR.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::Args as ClapArgs;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use mvm_build::app_deps::{GateLevel, Language, derive_lockfile_hash};
use mvm_sdk::compile::deps_audit::{
    FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, VolumeManifest,
    reseal_volume, verify_sealed_volume,
};
use mvm_sdk::ir::{Dependencies, NodeTool, PythonTool};

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

    /// Write the captured dependency declaration as the canonical SDK/IR
    /// dependency object. The file is safe to commit alongside the workload.
    #[arg(long, value_name = "PATH", requires = "lockfile")]
    pub declaration: Option<PathBuf>,

    /// Lockfile whose bytes must match the sealed volume's recorded SHA-256.
    #[arg(long, value_name = "PATH", requires = "declaration")]
    pub lockfile: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands::deps) struct CaptureOutcome {
    pub prior_volume_hash: String,
    pub volume_hash: String,
    pub lockfile_hash: String,
    pub volume_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration: Option<PathBuf>,
}

/// Inputs for one atomic dependency-volume capture.
#[derive(Debug)]
pub(in crate::commands::deps) struct CaptureRequest<'a> {
    cache_root: &'a Path,
    prior_hash: &'a str,
    captured_content: &'a Path,
    sbom: &'a Path,
    fetch_log: &'a Path,
    cve: &'a Path,
    declaration_path: Option<&'a Path>,
    lockfile_path: Option<&'a Path>,
}

/// Builder for [`CaptureRequest`].
pub(in crate::commands::deps) struct CaptureRequestBuilder<'a> {
    cache_root: Option<&'a Path>,
    prior_hash: Option<&'a str>,
    captured_content: Option<&'a Path>,
    sbom: Option<&'a Path>,
    fetch_log: Option<&'a Path>,
    cve: Option<&'a Path>,
    declaration_path: Option<&'a Path>,
    lockfile_path: Option<&'a Path>,
}

impl<'a> CaptureRequest<'a> {
    /// Start building a capture request.
    pub(in crate::commands::deps) fn builder() -> CaptureRequestBuilder<'a> {
        CaptureRequestBuilder {
            cache_root: None,
            prior_hash: None,
            captured_content: None,
            sbom: None,
            fetch_log: None,
            cve: None,
            declaration_path: None,
            lockfile_path: None,
        }
    }
}

impl<'a> CaptureRequestBuilder<'a> {
    pub(in crate::commands::deps) fn cache_root(mut self, value: &'a Path) -> Self {
        self.cache_root = Some(value);
        self
    }

    pub(in crate::commands::deps) fn prior_hash(mut self, value: &'a str) -> Self {
        self.prior_hash = Some(value);
        self
    }

    pub(in crate::commands::deps) fn captured_content(mut self, value: &'a Path) -> Self {
        self.captured_content = Some(value);
        self
    }

    pub(in crate::commands::deps) fn sbom(mut self, value: &'a Path) -> Self {
        self.sbom = Some(value);
        self
    }

    pub(in crate::commands::deps) fn fetch_log(mut self, value: &'a Path) -> Self {
        self.fetch_log = Some(value);
        self
    }

    pub(in crate::commands::deps) fn cve(mut self, value: &'a Path) -> Self {
        self.cve = Some(value);
        self
    }

    pub(in crate::commands::deps) fn declaration_path(mut self, value: Option<&'a Path>) -> Self {
        self.declaration_path = value;
        self
    }

    pub(in crate::commands::deps) fn lockfile_path(mut self, value: Option<&'a Path>) -> Self {
        self.lockfile_path = value;
        self
    }

    pub(in crate::commands::deps) fn build(self) -> Result<CaptureRequest<'a>> {
        Ok(CaptureRequest {
            cache_root: self
                .cache_root
                .ok_or_else(|| anyhow::anyhow!("capture cache root is required"))?,
            prior_hash: self
                .prior_hash
                .ok_or_else(|| anyhow::anyhow!("capture prior volume hash is required"))?,
            captured_content: self
                .captured_content
                .ok_or_else(|| anyhow::anyhow!("captured content directory is required"))?,
            sbom: self
                .sbom
                .ok_or_else(|| anyhow::anyhow!("capture SBOM path is required"))?,
            fetch_log: self
                .fetch_log
                .ok_or_else(|| anyhow::anyhow!("capture fetch log path is required"))?,
            cve: self
                .cve
                .ok_or_else(|| anyhow::anyhow!("capture CVE path is required"))?,
            declaration_path: self.declaration_path,
            lockfile_path: self.lockfile_path,
        })
    }
}

pub(super) fn run(args: Args) -> Result<()> {
    let cache_root = mvm_build::app_deps::resolve_cache_root(args.cache_root.as_deref());
    let request = CaptureRequest::builder()
        .cache_root(&cache_root)
        .prior_hash(&args.volume_hash)
        .captured_content(&args.content_dir)
        .sbom(&args.sbom)
        .fetch_log(&args.fetch_log)
        .cve(&args.cve)
        .declaration_path(args.declaration.as_deref())
        .lockfile_path(args.lockfile.as_deref())
        .build()?;
    let outcome = capture_volume(request)?;
    mvm_core::audit_emit!(
        DepsAudit,
        "prior={},new={},lockfile_hash={}",
        outcome.prior_volume_hash,
        outcome.volume_hash,
        outcome.lockfile_hash,
    );
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

pub(in crate::commands::deps) fn capture_volume(
    request: CaptureRequest<'_>,
) -> Result<CaptureOutcome> {
    let CaptureRequest {
        cache_root,
        prior_hash,
        captured_content,
        sbom,
        fetch_log,
        cve,
        declaration_path,
        lockfile_path,
    } = request;
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
    let declaration = match (declaration_path, lockfile_path) {
        (Some(path), Some(lockfile)) => {
            validate_declaration_target(path, lockfile, cache_root)?;
            Some((path, build_declaration(&prior_manifest, lockfile)?))
        }
        (None, None) => None,
        _ => bail!("--declaration and --lockfile must be supplied together"),
    };

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
        if let Some((path, declaration)) = declaration {
            write_declaration(path, &declaration)?;
        }
        Ok(CaptureOutcome {
            prior_volume_hash: prior_hash.to_string(),
            volume_hash: sealed.volume_hash,
            lockfile_hash,
            volume_dir: new_dir,
            declaration: declaration_path.map(Path::to_path_buf),
        })
    })();
    if result.is_err() && scratch.exists() {
        let _ = std::fs::remove_dir_all(&scratch);
    }
    result
}

fn validate_declaration_target(
    declaration: &Path,
    lockfile: &Path,
    cache_root: &Path,
) -> Result<()> {
    let declaration_target = canonical_target(declaration)?;
    let lockfile_target = std::fs::canonicalize(lockfile)
        .with_context(|| format!("resolving lockfile {}", lockfile.display()))?;
    if declaration_target == lockfile_target {
        bail!(
            "declaration path {} must not overwrite the lockfile {}",
            declaration.display(),
            lockfile.display()
        );
    }

    let cache_target = std::fs::canonicalize(cache_root)
        .with_context(|| format!("resolving dependency cache {}", cache_root.display()))?;
    if declaration_target.starts_with(&cache_target) {
        bail!(
            "declaration path {} must be outside the dependency cache {}",
            declaration.display(),
            cache_root.display()
        );
    }
    Ok(())
}

fn canonical_target(path: &Path) -> Result<std::path::PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("declaration path must name a file"))?;
    Ok(std::fs::canonicalize(parent)
        .with_context(|| format!("resolving declaration parent {}", parent.display()))?
        .join(name))
}

fn build_declaration(manifest: &VolumeManifest, lockfile: &Path) -> Result<Dependencies> {
    require_file(lockfile, "lockfile")?;
    let expected_sha256 = annotation(&manifest.annotations, "lockfile_sha256")?;
    validate_hash(expected_sha256, "lockfile SHA-256")?;
    let actual_sha256 = sha256_file(lockfile)?;
    if actual_sha256 != expected_sha256 {
        bail!(
            "lockfile {} does not match sealed SHA-256: expected {}, got {}",
            lockfile.display(),
            expected_sha256,
            actual_sha256
        );
    }

    let language = parse_language(annotation(&manifest.annotations, "language")?)?;
    let gate = parse_gate(annotation(&manifest.annotations, "gate")?)?;
    let expected_lockfile_hash = derive_lockfile_hash(&actual_sha256, language, gate);
    let recorded_lockfile_hash = annotation(&manifest.annotations, "lockfile_hash")?;
    if expected_lockfile_hash != recorded_lockfile_hash {
        bail!(
            "lockfile {} does not match sealed lockfile hash: expected {}, got {}",
            lockfile.display(),
            recorded_lockfile_hash,
            expected_lockfile_hash
        );
    }

    let relative_path = annotation(&manifest.annotations, "lockfile_relative_path")?;
    let relative = Path::new(relative_path);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("sealed lockfile_relative_path must be relative and must not contain `..`");
    }

    match language {
        Language::Python => Ok(Dependencies::Python {
            lockfile: relative_path.to_string(),
            tool: python_tool(relative),
        }),
        Language::Node => Ok(Dependencies::Node {
            lockfile: relative_path.to_string(),
            tool: node_tool(relative),
        }),
    }
}

fn annotation<'a>(
    annotations: &'a std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str> {
    annotations
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("sealed volume has no {key} annotation"))
}

fn parse_language(value: &str) -> Result<Language> {
    match value {
        "python" => Ok(Language::Python),
        "node" => Ok(Language::Node),
        other => bail!("unsupported dependency language annotation `{other}`"),
    }
}

fn parse_gate(value: &str) -> Result<GateLevel> {
    match value {
        "dev" => Ok(GateLevel::Dev),
        "prod" => Ok(GateLevel::Prod),
        other => bail!("unsupported dependency gate annotation `{other}`"),
    }
}

fn python_tool(path: &Path) -> PythonTool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("requirements.txt") => PythonTool::PipTools,
        _ => PythonTool::Uv,
    }
}

fn node_tool(path: &Path) -> NodeTool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("package-lock.json") => NodeTool::Npm,
        Some("yarn.lock") => NodeTool::Yarn,
        _ => NodeTool::Pnpm,
    }
}

fn write_declaration(path: &Path, declaration: &Dependencies) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!(
            "declaration parent directory does not exist: {}",
            parent.display()
        );
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("declaration path must name a file"))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    if temporary.exists() {
        bail!(
            "temporary declaration path already exists: {}",
            temporary.display()
        );
    }
    let result = (|| {
        let mut bytes = serde_json::to_vec_pretty(declaration)?;
        bytes.push(b'\n');
        std::fs::write(&temporary, bytes)
            .with_context(|| format!("writing temporary declaration {}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("publishing dependency declaration {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
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
        let annotations = lockfile_hash
            .map(|hash| BTreeMap::from([("lockfile_hash".to_string(), hash.to_string())]))
            .unwrap_or_default();
        seed_volume_with_annotations(root, annotations)
    }

    fn seed_volume_with_annotations(root: &Path, annotations: BTreeMap<String, String>) -> String {
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
        let index_hash = annotations.get("lockfile_hash").cloned();
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
        if let Some(lockfile_hash) = index_hash {
            fs::create_dir_all(root.join("index")).unwrap();
            fs::write(root.join("index").join(lockfile_hash), &sealed.volume_hash).unwrap();
        }
        sealed.volume_hash
    }

    #[test]
    fn capture_request_builder_requires_core_inputs() {
        let error = CaptureRequest::builder()
            .build()
            .expect_err("an incomplete capture request must be rejected");
        assert!(error.to_string().contains("capture cache root is required"));
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

        let request = CaptureRequest::builder()
            .cache_root(tmp.path())
            .prior_hash(&old_hash)
            .captured_content(&captured)
            .sbom(&sbom)
            .fetch_log(&fetch)
            .cve(&cve)
            .build()
            .unwrap();
        let outcome = capture_volume(request).unwrap();
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
        let request = CaptureRequest::builder()
            .cache_root(tmp.path())
            .prior_hash(&old_hash)
            .captured_content(&captured)
            .sbom(&sbom)
            .fetch_log(&fetch)
            .cve(&cve)
            .build()
            .unwrap();
        assert!(capture_volume(request).is_err());
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
        let request = CaptureRequest::builder()
            .cache_root(tmp.path())
            .prior_hash(&old_hash)
            .captured_content(&captured)
            .sbom(&sbom)
            .fetch_log(&fetch)
            .cve(&cve)
            .build()
            .unwrap();
        assert!(capture_volume(request).is_err());
    }

    #[test]
    fn capture_emits_the_declared_dependency_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let lockfile = tmp.path().join("uv.lock");
        fs::write(&lockfile, "version = 1\n").unwrap();
        let lockfile_sha256 = sha256_file(&lockfile).unwrap();
        let lockfile_hash =
            derive_lockfile_hash(&lockfile_sha256, Language::Python, GateLevel::Dev);
        let old_hash = seed_volume_with_annotations(
            tmp.path(),
            BTreeMap::from([
                ("lockfile_hash".to_string(), lockfile_hash),
                ("lockfile_sha256".to_string(), lockfile_sha256),
                ("lockfile_relative_path".to_string(), "uv.lock".to_string()),
                ("language".to_string(), "python".to_string()),
                ("gate".to_string(), "dev".to_string()),
            ]),
        );
        let captured = tmp.path().join("captured");
        fs::create_dir_all(&captured).unwrap();
        fs::write(captured.join("installed.txt"), b"new").unwrap();
        let sbom = tmp.path().join("sbom.json");
        let fetch = tmp.path().join("fetch.log");
        let cve = tmp.path().join("cve.json");
        fs::write(&sbom, b"sbom").unwrap();
        fs::write(&fetch, b"fetch\n").unwrap();
        fs::write(&cve, b"{}").unwrap();
        let declaration_dir = tempfile::tempdir().unwrap();
        let declaration = declaration_dir.path().join("dependencies.json");

        let request = CaptureRequest::builder()
            .cache_root(tmp.path())
            .prior_hash(&old_hash)
            .captured_content(&captured)
            .sbom(&sbom)
            .fetch_log(&fetch)
            .cve(&cve)
            .declaration_path(Some(&declaration))
            .lockfile_path(Some(&lockfile))
            .build()
            .unwrap();
        let outcome = capture_volume(request).unwrap();

        assert_eq!(outcome.declaration, Some(declaration.clone()));
        let parsed: Dependencies = serde_json::from_slice(&fs::read(declaration).unwrap()).unwrap();
        assert_eq!(
            parsed,
            Dependencies::Python {
                lockfile: "uv.lock".to_string(),
                tool: PythonTool::Uv,
            }
        );
    }

    #[test]
    fn capture_refuses_a_lockfile_that_does_not_match_the_seal() {
        let tmp = tempfile::tempdir().unwrap();
        let lockfile = tmp.path().join("uv.lock");
        fs::write(&lockfile, "version = 1\n").unwrap();
        let lockfile_sha256 = sha256_file(&lockfile).unwrap();
        let lockfile_hash =
            derive_lockfile_hash(&lockfile_sha256, Language::Python, GateLevel::Dev);
        let old_hash = seed_volume_with_annotations(
            tmp.path(),
            BTreeMap::from([
                ("lockfile_hash".to_string(), lockfile_hash),
                ("lockfile_sha256".to_string(), lockfile_sha256),
                ("lockfile_relative_path".to_string(), "uv.lock".to_string()),
                ("language".to_string(), "python".to_string()),
                ("gate".to_string(), "dev".to_string()),
            ]),
        );
        fs::write(&lockfile, "tampered = true\n").unwrap();
        let captured = tmp.path().join("captured");
        fs::create_dir_all(&captured).unwrap();
        let sbom = tmp.path().join("sbom.json");
        let fetch = tmp.path().join("fetch.log");
        let cve = tmp.path().join("cve.json");
        fs::write(&sbom, b"sbom").unwrap();
        fs::write(&fetch, b"fetch\n").unwrap();
        fs::write(&cve, b"{}").unwrap();
        let declaration_dir = tempfile::tempdir().unwrap();
        let declaration = declaration_dir.path().join("dependencies.json");

        let request = CaptureRequest::builder()
            .cache_root(tmp.path())
            .prior_hash(&old_hash)
            .captured_content(&captured)
            .sbom(&sbom)
            .fetch_log(&fetch)
            .cve(&cve)
            .declaration_path(Some(&declaration))
            .lockfile_path(Some(&lockfile))
            .build()
            .unwrap();
        let error = capture_volume(request)
            .expect_err("capture must refuse an unmatching declaration lockfile");
        assert!(error.to_string().contains("does not match sealed SHA-256"));
        assert!(tmp.path().join(&old_hash).exists());
    }

    #[test]
    fn capture_refuses_declaration_inside_dependency_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let lockfile = tmp.path().join("uv.lock");
        fs::write(&lockfile, "version = 1\n").unwrap();
        let cache_root = tmp.path().join("cache");
        fs::create_dir_all(&cache_root).unwrap();
        let declaration = cache_root.join("dependencies.json");

        let error = validate_declaration_target(&declaration, &lockfile, &cache_root)
            .expect_err("declarations must not be written into the dependency cache");
        assert!(error.to_string().contains("outside the dependency cache"));
    }
}
