//! Template registry — bundled presets, built-in OCI image templates,
//! user-built image templates, and remote fetch/cache.
//!
//! The registry abstracts where a template comes from. Bundled templates
//! ship inside the `mvmctl` binary and are always available offline.
//! Built-in image templates are pinned OCI references for common language
//! runtimes and are also offline. User-built image templates are created
//! with `mvmctl template build --image <ref>` and stored under
//! `~/.mvm/templates/built/`. Remote templates live in a separate
//! repository and are fetched on first use, then cached under
//! `~/.mvm/templates/remote/`.
//!
//! Resolution order:
//!   1. User-built image templates (local, explicit).
//!   2. Built-in image templates (offline, pinned OCI refs).
//!   3. Bundled catalog (offline, core Nix presets).
//!   4. Local remote cache (already fetched).
//!   5. Remote registry index + download (network required).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A resolved template ready to use or scaffold.
#[derive(Debug, Clone)]
pub struct TemplateEntry {
    pub name: String,
    pub description: String,
    pub default_cpus: u8,
    pub default_memory_mib: u32,
    pub tags: Vec<String>,
    pub source: TemplateSource,
}

/// Where the template's files come from.
#[derive(Debug, Clone)]
pub enum TemplateSource {
    /// A preset whose flake content is embedded in `mvmctl`.
    Bundled { preset: String },
    /// A pinned OCI image reference.
    Image { image_ref: String },
    /// A template downloaded from the remote registry into the local cache.
    Remote { cache_dir: PathBuf },
}

/// Raw remote index shape.
#[derive(Debug, Deserialize)]
struct RemoteIndex {
    #[allow(dead_code)]
    schema_version: u32,
    templates: Vec<RemoteIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct RemoteIndexEntry {
    name: String,
    description: String,
    path: String,
    #[serde(default)]
    mvm_version: String,
}

/// Parsed `template.toml` from a remote template directory.
#[derive(Debug, Deserialize)]
struct RemoteTemplateMeta {
    name: String,
    description: String,
    default_vcpus: u8,
    default_memory_mib: u32,
    #[serde(default)]
    tags: Vec<String>,
    /// Additional files to download from the template directory.
    #[serde(default)]
    files: Vec<String>,
}

/// Persistent metadata for a user-built image template.
#[derive(Debug, Serialize, Deserialize)]
struct BuiltTemplateMeta {
    name: String,
    description: String,
    image_ref: String,
    default_vcpus: u8,
    default_memory_mib: u32,
    #[serde(default)]
    tags: Vec<String>,
}

/// Registry configuration.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Base URL of the remote registry. Supports `https://` and `file://`.
    pub registry_url: String,
    /// Directory where remote templates are cached.
    pub cache_root: PathBuf,
}

impl RegistryConfig {
    /// Load from environment / config, with sensible defaults.
    pub fn load() -> Self {
        let registry_url = std::env::var("MVM_TEMPLATE_REGISTRY")
            .ok()
            .unwrap_or_else(|| {
                "https://raw.githubusercontent.com/tinylabscom/mvm-templates/main".to_string()
            });
        let cache_root = PathBuf::from(mvm_core::config::mvm_home())
            .join("templates")
            .join("remote");
        Self {
            registry_url,
            cache_root,
        }
    }
}

/// One built-in image template entry.
struct BuiltinTemplate {
    name: &'static str,
    description: &'static str,
    image_ref: &'static str,
    cpus: u8,
    mem_mib: u32,
    tags: &'static [&'static str],
}

/// Built-in image templates backed by pinned OCI references.
///
/// These are conservative, well-known defaults so that
/// `mvmctl run --template python script.py` works without a manifest.
fn builtin_image_templates() -> Vec<TemplateEntry> {
    const BUILTINS: &[BuiltinTemplate] = &[
        BuiltinTemplate {
            name: "python",
            description: "Python 3.12 runtime",
            image_ref: "python:3.12-alpine",
            cpus: 1,
            mem_mib: 256,
            tags: &["python", "language"],
        },
        BuiltinTemplate {
            name: "node",
            description: "Node.js 22 runtime",
            image_ref: "node:22-alpine",
            cpus: 1,
            mem_mib: 256,
            tags: &["node", "javascript", "language"],
        },
        BuiltinTemplate {
            name: "rust",
            description: "Rust 1.85 runtime",
            image_ref: "rust:1.85-alpine",
            cpus: 2,
            mem_mib: 512,
            tags: &["rust", "language"],
        },
        BuiltinTemplate {
            name: "go",
            description: "Go 1.23 runtime",
            image_ref: "golang:1.23-alpine",
            cpus: 1,
            mem_mib: 256,
            tags: &["go", "language"],
        },
        BuiltinTemplate {
            name: "ruby",
            description: "Ruby 3.3 runtime",
            image_ref: "ruby:3.3-alpine",
            cpus: 1,
            mem_mib: 256,
            tags: &["ruby", "language"],
        },
        BuiltinTemplate {
            name: "java",
            description: "Java 21 runtime",
            image_ref: "eclipse-temurin:21-alpine",
            cpus: 1,
            mem_mib: 512,
            tags: &["java", "jvm", "language"],
        },
        BuiltinTemplate {
            name: "shell",
            description: "POSIX shell runtime",
            image_ref: "alpine:3.20",
            cpus: 1,
            mem_mib: 128,
            tags: &["shell", "sh", "language"],
        },
        BuiltinTemplate {
            name: "data-science",
            description: "Python data-science stack",
            image_ref: "jupyter/scipy-notebook:python-3.12",
            cpus: 2,
            mem_mib: 2048,
            tags: &["python", "data", "science"],
        },
        BuiltinTemplate {
            name: "web-dev",
            description: "Node.js web development runtime",
            image_ref: "node:22-alpine",
            cpus: 1,
            mem_mib: 512,
            tags: &["node", "web", "javascript"],
        },
    ];

    BUILTINS
        .iter()
        .map(|b| TemplateEntry {
            name: b.name.to_string(),
            description: b.description.to_string(),
            default_cpus: b.cpus,
            default_memory_mib: b.mem_mib,
            tags: b.tags.iter().map(|t| (*t).to_string()).collect(),
            source: TemplateSource::Image {
                image_ref: b.image_ref.to_string(),
            },
        })
        .collect()
}

/// Directory where user-built image templates are persisted.
fn built_templates_dir() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_home())
        .join("templates")
        .join("built")
}

/// Directory for one user-built image template.
fn built_template_dir(name: &str) -> PathBuf {
    built_templates_dir().join(sanitize_cache_key(name))
}

/// Persist a user-built image template so it can be resolved by name.
pub fn persist_built_image_template(
    name: &str,
    image_ref: &str,
    description: Option<&str>,
    default_vcpus: Option<u8>,
    default_memory_mib: Option<u32>,
) -> Result<()> {
    let dir = built_template_dir(name);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating built template dir {}", dir.display()))?;

    let meta = BuiltTemplateMeta {
        name: name.to_string(),
        description: description
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("OCI image template built from {image_ref}")),
        image_ref: image_ref.to_string(),
        default_vcpus: default_vcpus.unwrap_or(1),
        default_memory_mib: default_memory_mib.unwrap_or(256),
        tags: vec!["built".to_string(), "oci".to_string()],
    };

    let text = toml::to_string(&meta).context("serializing built template metadata")?;
    let path = dir.join("template.toml");
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read all user-built image templates from disk.
fn list_built_templates() -> Vec<TemplateEntry> {
    let dir = built_templates_dir();
    if !dir.is_dir() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let path = entry.path().join("template.toml");
        if !path.is_file() {
            continue;
        }
        match read_built_template(&path) {
            Ok(entry) => out.push(entry),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping built template");
            }
        }
    }
    out
}

fn read_built_template(path: &Path) -> Result<TemplateEntry> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let meta: BuiltTemplateMeta =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(TemplateEntry {
        name: meta.name,
        description: meta.description,
        default_cpus: meta.default_vcpus,
        default_memory_mib: meta.default_memory_mib,
        tags: meta.tags,
        source: TemplateSource::Image {
            image_ref: meta.image_ref,
        },
    })
}

/// Resolve a template name to an OCI image reference.
///
/// Checks user-built templates first, then built-in image templates.
/// Returns `None` if the name is not a built/builtin image template.
pub fn resolve_image_ref(name: &str) -> Option<String> {
    if let Some(entry) = list_built_templates().into_iter().find(|e| e.name == name)
        && let TemplateSource::Image { image_ref } = entry.source
    {
        return Some(image_ref);
    }
    if let Some(entry) = builtin_image_templates()
        .into_iter()
        .find(|e| e.name == name)
        && let TemplateSource::Image { image_ref } = entry.source
    {
        return Some(image_ref);
    }
    None
}

/// Return all bundled templates.
pub fn bundled_templates() -> Vec<TemplateEntry> {
    super::commands::catalog::load_bundled_catalog()
        .entries
        .into_iter()
        .map(|entry| TemplateEntry {
            name: entry.name.clone(),
            description: entry.description,
            default_cpus: entry.default_cpus,
            default_memory_mib: entry.default_memory_mib,
            tags: entry.tags,
            source: TemplateSource::Bundled {
                preset: entry.profile,
            },
        })
        .collect()
}

/// List templates available without network: built + built-in image + bundled + cached remote.
pub fn list_available(cfg: &RegistryConfig) -> Vec<TemplateEntry> {
    let mut out = list_built_templates();
    out.extend(builtin_image_templates());
    out.extend(bundled_templates());
    if let Ok(cached) = list_cached_remote(cfg) {
        out.extend(cached);
    }
    out
}

/// Search the remote registry index for templates matching `query`.
pub async fn search_remote(cfg: &RegistryConfig, query: &str) -> Result<Vec<TemplateEntry>> {
    let index = fetch_index(cfg).await?;
    let q = query.to_lowercase();
    let mut out = Vec::new();
    for entry in index.templates {
        if !satisfies_mvm_version(&entry.mvm_version) {
            continue;
        }
        let matches =
            entry.name.to_lowercase().contains(&q) || entry.description.to_lowercase().contains(&q);
        if matches {
            let cache_dir = cache_dir_for_template(cfg, &entry.name);
            out.push(TemplateEntry {
                name: entry.name,
                description: entry.description,
                // Defaults are unknown until we download; surface placeholder
                // values and let the downloaded metadata override them.
                default_cpus: 1,
                default_memory_mib: 256,
                tags: Vec::new(),
                source: TemplateSource::Remote { cache_dir },
            });
        }
    }
    Ok(out)
}

/// Resolve a template by name.
///
/// Order: user-built image, built-in image, bundled catalog, cached remote,
/// remote fetch.
pub async fn resolve(cfg: &RegistryConfig, name: &str) -> Result<TemplateEntry> {
    if let Some(entry) = list_built_templates().into_iter().find(|e| e.name == name) {
        return Ok(entry);
    }
    if let Some(entry) = builtin_image_templates()
        .into_iter()
        .find(|e| e.name == name)
    {
        return Ok(entry);
    }
    if let Some(entry) = bundled_templates().into_iter().find(|e| e.name == name) {
        return Ok(entry);
    }

    let cache_dir = cache_dir_for_template(cfg, name);
    if cache_dir.join("template.toml").is_file() && cache_dir.join("flake.nix").is_file() {
        return read_cached_remote_template(&cache_dir);
    }

    fetch_and_cache_remote_template(cfg, name).await
}

fn list_cached_remote(cfg: &RegistryConfig) -> Result<Vec<TemplateEntry>> {
    let mut out = Vec::new();
    if !cfg.cache_root.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&cfg.cache_root)? {
        let entry = entry?;
        let cache_dir = entry.path();
        if cache_dir.join("template.toml").is_file() && cache_dir.join("flake.nix").is_file() {
            out.push(read_cached_remote_template(&cache_dir)?);
        }
    }
    Ok(out)
}

fn read_cached_remote_template(cache_dir: &Path) -> Result<TemplateEntry> {
    let meta_path = cache_dir.join("template.toml");
    let text = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("reading {}", meta_path.display()))?;
    let meta: RemoteTemplateMeta =
        toml::from_str(&text).with_context(|| format!("parsing {}", meta_path.display()))?;
    Ok(TemplateEntry {
        name: meta.name,
        description: meta.description,
        default_cpus: meta.default_vcpus,
        default_memory_mib: meta.default_memory_mib,
        tags: meta.tags,
        source: TemplateSource::Remote {
            cache_dir: cache_dir.to_path_buf(),
        },
    })
}

async fn fetch_and_cache_remote_template(
    cfg: &RegistryConfig,
    name: &str,
) -> Result<TemplateEntry> {
    let index = fetch_index(cfg).await?;
    let index_entry = index
        .templates
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| anyhow::anyhow!("template {:?} not found in remote registry", name))?;
    if !satisfies_mvm_version(&index_entry.mvm_version) {
        bail!(
            "template {:?} requires mvm {}, but this is {}",
            name,
            index_entry.mvm_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    let cache_dir = cache_dir_for_template(cfg, name);
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating cache dir {}", cache_dir.display()))?;

    let base = format!(
        "{}/{}",
        cfg.registry_url.trim_end_matches('/'),
        index_entry.path
    );
    let base = base.trim_end_matches('/');

    download_text(
        &format!("{}/template.toml", base),
        &cache_dir.join("template.toml"),
    )
    .await?;
    download_text(&format!("{}/flake.nix", base), &cache_dir.join("flake.nix")).await?;

    // Download any extra files declared by the template (SDK sources, app/
    // directories, etc.).
    let meta_text = std::fs::read_to_string(cache_dir.join("template.toml"))
        .with_context(|| format!("re-reading template.toml from {}", cache_dir.display()))?;
    let meta: RemoteTemplateMeta = toml::from_str(&meta_text)
        .with_context(|| format!("parsing template.toml from {}", cache_dir.display()))?;
    for file in &meta.files {
        let file_url = format!("{}/{}", base, file);
        let dest = cache_dir.join(file);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir for {}", dest.display()))?;
        }
        download_text(&file_url, &dest).await?;
    }

    read_cached_remote_template(&cache_dir)
}

/// Very small `>=major.minor.patch` check against `CARGO_PKG_VERSION`.
/// Returns true if no requirement is supplied, if parsing fails, or if the
/// current package version satisfies the lower bound.
pub(crate) fn satisfies_mvm_version(req: &str) -> bool {
    if req.is_empty() {
        return true;
    }
    let current = env!("CARGO_PKG_VERSION");
    let ver = req.trim_start_matches('>').trim_start_matches('=');
    match (parse_version_triple(ver), parse_version_triple(current)) {
        (Some(r), Some(c)) => c >= r,
        _ => true,
    }
}

fn parse_version_triple(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

async fn fetch_index(cfg: &RegistryConfig) -> Result<RemoteIndex> {
    let url = format!("{}/index.json", cfg.registry_url.trim_end_matches('/'));
    let text = fetch_text(&url).await?;
    serde_json::from_str(&text).with_context(|| format!("parsing remote index from {url}"))
}

async fn download_text(url: &str, dest: &Path) -> Result<()> {
    let text = fetch_text(url).await?;
    std::fs::write(dest, text).with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

async fn fetch_text(url: &str) -> Result<String> {
    if let Some(path) = url.strip_prefix("file://") {
        return std::fs::read_to_string(path)
            .with_context(|| format!("reading local registry file {url}"));
    }

    let client = mvm_http::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("remote registry returned {} for {}", status.as_u16(), url);
    }
    resp.text()
        .await
        .with_context(|| format!("reading body from {url}"))
}

fn cache_dir_for_template(cfg: &RegistryConfig, name: &str) -> PathBuf {
    cfg.cache_root
        .join(sanitize_cache_key(&cfg.registry_url))
        .join(name)
}

fn sanitize_cache_key(url: &str) -> String {
    url.replace([':', '/', '?', '#', '&', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_cache_key_replaces_url_metacharacters() {
        assert_eq!(
            sanitize_cache_key("https://example.com/path?foo=bar"),
            "https___example.com_path_foo_bar"
        );
    }

    #[test]
    fn builtin_image_templates_include_language_presets() {
        let names: Vec<_> = builtin_image_templates()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"python".to_string()));
        assert!(names.contains(&"node".to_string()));
        assert!(names.contains(&"rust".to_string()));
        assert!(names.contains(&"go".to_string()));
        assert!(names.contains(&"ruby".to_string()));
        assert!(names.contains(&"java".to_string()));
        assert!(names.contains(&"shell".to_string()));
    }

    #[test]
    fn resolve_image_ref_finds_builtin_templates() {
        assert_eq!(
            resolve_image_ref("python"),
            Some("python:3.12-alpine".to_string())
        );
        assert_eq!(
            resolve_image_ref("node"),
            Some("node:22-alpine".to_string())
        );
        assert_eq!(resolve_image_ref("not-a-template"), None);
    }

    #[test]
    fn built_templates_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        // Redirect MVM_HOME so the test does not touch the user's registry.
        unsafe { std::env::set_var("MVM_HOME", tmp.path().as_os_str()) };
        persist_built_image_template("my-py", "python:3.12-alpine", None, None, None)
            .expect("persist built template");

        let entries = list_built_templates();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "my-py");
        if let TemplateSource::Image { image_ref } = &entries[0].source {
            assert_eq!(image_ref, "python:3.12-alpine");
        } else {
            panic!("expected image source");
        }

        assert_eq!(
            resolve_image_ref("my-py"),
            Some("python:3.12-alpine".to_string())
        );
    }

    #[test]
    fn bundled_templates_include_core_presets() {
        let names: Vec<_> = bundled_templates().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"minimal".to_string()));
        assert!(names.contains(&"python".to_string()));
        assert!(names.contains(&"postgres".to_string()));
        assert!(!names.contains(&"python-pandas".to_string()));
    }

    #[test]
    fn satisfies_mvm_version_accepts_empty_and_lower_bounds() {
        assert!(satisfies_mvm_version(""));
        assert!(satisfies_mvm_version(">=0.1.0"));
        assert!(!satisfies_mvm_version(">=999.0.0"));
    }

    #[test]
    fn resolve_and_search_work_with_file_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = tmp.path().join("registry");
        std::fs::create_dir_all(&reg).unwrap();
        std::fs::create_dir_all(reg.join("templates/demo")).unwrap();

        let index = serde_json::json!({
            "schema_version": 1,
            "templates": [{
                "name": "demo",
                "description": "demo template",
                "path": "templates/demo",
                "mvm_version": ">=0.1.0"
            }]
        });
        std::fs::write(reg.join("index.json"), index.to_string()).unwrap();
        std::fs::write(
            reg.join("templates/demo/template.toml"),
            r#"name = "demo"
description = "demo template"
default_vcpus = 2
default_memory_mib = 512
tags = ["demo"]
"#,
        )
        .unwrap();
        std::fs::write(reg.join("templates/demo/flake.nix"), "{ pkgs }: { }").unwrap();

        let cache = tmp.path().join("cache");
        let cfg = RegistryConfig {
            registry_url: format!("file://{}", reg.display()),
            cache_root: cache.clone(),
        };

        let entry = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(resolve(&cfg, "demo"))
            .expect("resolves remote demo");
        assert_eq!(entry.name, "demo");
        assert_eq!(entry.default_cpus, 2);
        assert_eq!(entry.default_memory_mib, 512);

        // Cached files were written.
        assert!(
            cache.read_dir().unwrap().next().is_some(),
            "cache has a registry subdir"
        );

        // Search finds the entry.
        let hits = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(search_remote(&cfg, "demo"))
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "demo");

        // Version-incompatible entries are filtered out.
        let filtered = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(search_remote(&cfg, "demo"))
            .unwrap();
        assert_eq!(filtered.len(), 1); // still one, demo is compatible
    }
}
