//! Registry client for signed product packs (PS-06).
//!
//! Fetches the pack index and pack payloads over HTTP(S) (or `file://` for
//! tests and air-gapped mirrors), then hands every byte to
//! `mvm_core::registry_pack` for verification and installation. Nothing here
//! trusts fetched content: paths from an unverified manifest are refused
//! before they are joined into URLs or staging paths, and the lock pin is
//! written only after signature, manifest, and payload all verify.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tempfile::TempDir;

use mvm_core::packs::pack_path_is_safe;
use mvm_core::registry_pack::{
    PackAdoption, PackReference, RegistryPackVerification, VerifiedRegistryPack,
    adopt_registry_pack, verify_registry_pack,
};
use mvm_core::registry_pack_store::{
    adopt_install_and_pin, load_pack_lockfile, load_publisher_policy_or_official_default,
};

/// Environment override for the pack registry base URL.
pub const PACK_REGISTRY_ENV: &str = "MVM_PACK_REGISTRY";
/// Default registry: the mvm-templates repository, same source the template
/// registry uses.
pub const DEFAULT_PACK_REGISTRY: &str =
    "https://raw.githubusercontent.com/tinylabscom/mvm-templates/main";

const PACK_INDEX_SCHEMA_VERSION: u32 = 1;
const PACKS_DIR: &str = "packs";
const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "manifest.sigstore.json";
const FILES_DIR: &str = "files";

/// Registry configuration: one base URL, overridable for tests and mirrors.
#[derive(Debug, Clone)]
pub struct PackRegistryConfig {
    pub registry_url: String,
}

impl PackRegistryConfig {
    pub fn load() -> Self {
        let registry_url = std::env::var(PACK_REGISTRY_ENV)
            .ok()
            .unwrap_or_else(|| DEFAULT_PACK_REGISTRY.to_string());
        Self { registry_url }
    }

    fn base(&self) -> String {
        self.registry_url.trim_end_matches('/').to_string()
    }
}

/// One pack in the registry index.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackIndexEntry {
    pub namespace: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub versions: Vec<String>,
}

impl PackIndexEntry {
    pub fn coordinate(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackIndexWire {
    schema_version: u32,
    packs: Vec<PackIndexEntry>,
}

/// Fetch and parse the pack index.
pub fn fetch_index(config: &PackRegistryConfig) -> Result<Vec<PackIndexEntry>> {
    let url = format!("{}/{PACKS_DIR}/index.json", config.base());
    let text = block_on(fetch_text(&url))?;
    let wire: PackIndexWire =
        serde_json::from_str(&text).with_context(|| format!("parsing pack index from {url}"))?;
    if wire.schema_version != PACK_INDEX_SCHEMA_VERSION {
        bail!(
            "pack index at {url} has schema version {}, expected {PACK_INDEX_SCHEMA_VERSION}",
            wire.schema_version
        );
    }
    Ok(wire.packs)
}

/// Filter index entries by an optional case-insensitive substring over
/// coordinate and description. No query lists everything.
pub fn search_index<'a>(
    index: &'a [PackIndexEntry],
    query: Option<&str>,
) -> Vec<&'a PackIndexEntry> {
    let Some(query) = query.map(str::to_lowercase) else {
        return index.iter().collect();
    };
    index
        .iter()
        .filter(|entry| {
            entry.coordinate().to_lowercase().contains(&query)
                || entry.description.to_lowercase().contains(&query)
        })
        .collect()
}

/// Pick the exact versioned reference to pull: the requested version must be
/// published, and an unversioned request takes the highest version.
pub fn resolve_version(entry: &PackIndexEntry, requested: &PackReference) -> Result<PackReference> {
    let versions = &entry.versions;
    if versions.is_empty() {
        bail!("pack {} publishes no versions", entry.coordinate());
    }
    let released = |spelling: &str| {
        mvm_core::release_version::ReleaseVersion::parse(
            spelling,
            mvm_core::release_version::VersionSyntax::Strict,
        )
    };
    let spelling = match requested.version() {
        Some(version) => {
            let spelling = version.to_string();
            if !versions.iter().any(|published| published == &spelling) {
                bail!(
                    "pack {} is not published at version {spelling} (published: {})",
                    entry.coordinate(),
                    versions.join(", ")
                );
            }
            spelling
        }
        None => versions
            .iter()
            .filter_map(|spelling| released(spelling).map(|version| (version, spelling)))
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, spelling)| spelling.clone())
            .expect("PackVersion already validated every published version as strict semver"),
    };
    format!("{}@{spelling}", entry.coordinate())
        .parse()
        .with_context(|| {
            format!(
                "registry listed an invalid version for {}",
                entry.coordinate()
            )
        })
}

fn pack_url(config: &PackRegistryConfig, reference: &PackReference, leaf: &str) -> String {
    let version = reference
        .version()
        .map(|version| version.to_string())
        .unwrap_or_default();
    format!(
        "{}/{PACKS_DIR}/{}/{}/{version}/{leaf}",
        config.base(),
        reference.namespace(),
        reference.name(),
    )
}

/// A downloaded pack awaiting verification: exact bytes in a staging dir that
/// lives until installation consumes it.
pub struct FetchedPack {
    pub reference: PackReference,
    pub manifest_bytes: Vec<u8>,
    pub signature_bundle: Vec<u8>,
    staged: TempDir,
}

impl FetchedPack {
    pub fn staged_path(&self) -> &Path {
        self.staged.path()
    }
}

/// The manifest paths declared by a pack, from an unverified manifest.
///
/// Paths are checked with the same rule the verifier applies before they are
/// joined into URLs or staging paths.
fn declared_paths(manifest_bytes: &[u8]) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct PathsOnly {
        files: Vec<PathEntry>,
    }
    #[derive(Deserialize)]
    struct PathEntry {
        path: String,
    }
    let manifest: PathsOnly = serde_json::from_slice(manifest_bytes)
        .context("parsing the pack manifest well enough to list its files")?;
    let mut paths = Vec::with_capacity(manifest.files.len());
    for file in manifest.files {
        if !pack_path_is_safe(&file.path) {
            bail!("pack manifest declares an unsafe file path {:?}", file.path);
        }
        paths.push(file.path);
    }
    Ok(paths)
}

/// Download a pack's manifest, signature bundle, and every declared payload
/// file into a fresh staging directory.
pub fn download_pack(
    config: &PackRegistryConfig,
    reference: &PackReference,
) -> Result<FetchedPack> {
    let manifest_url = pack_url(config, reference, MANIFEST_FILE);
    let manifest_bytes = block_on(fetch_bytes(&manifest_url))?;
    let signature_url = pack_url(config, reference, SIGNATURE_FILE);
    let signature_bundle = block_on(fetch_bytes(&signature_url))?;
    let staged = TempDir::new().context("creating a staging directory for the pack")?;
    for path in declared_paths(&manifest_bytes)? {
        let url = pack_url(config, reference, &format!("{FILES_DIR}/{path}"));
        let bytes = block_on(fetch_bytes(&url))?;
        let destination = staged.path().join(&path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&destination, bytes)
            .with_context(|| format!("writing {}", destination.display()))?;
    }
    Ok(FetchedPack {
        reference: reference.clone(),
        manifest_bytes,
        signature_bundle,
        staged,
    })
}

/// What `mvmctl pull` did, for the caller to render.
#[derive(Debug)]
pub struct PullSummary {
    pub reference: PackReference,
    pub manifest_sha256: String,
    pub files: usize,
    pub installed_root: PathBuf,
    pub refreshed: bool,
}

/// Fetch, verify, install, and pin one pack.
///
/// A pack whose coordinate is already pinned is re-verified lock-first
/// (digest drift refuses); a new pack is adopted signature-first. The pin is
/// written only after installation succeeds.
pub fn pull(reference_arg: &str) -> Result<PullSummary> {
    let requested: PackReference = reference_arg
        .parse()
        .with_context(|| format!("invalid pack reference {reference_arg:?}"))?;
    let config = PackRegistryConfig::load();
    let index = fetch_index(&config)?;
    let entry = index
        .iter()
        .find(|entry| entry.namespace == requested.namespace() && entry.name == requested.name())
        .with_context(|| {
            format!(
                "pack {}/{} is not in the registry index",
                requested.namespace(),
                requested.name()
            )
        })?;
    let reference = resolve_version(entry, &requested)?;
    let fetched = download_pack(&config, &reference)?;

    let policy_path = mvm_core::config::registry_pack_publisher_policy_path();
    let loaded = load_publisher_policy_or_official_default(&policy_path)?;
    if loaded.is_official_default() {
        crate::ui::info(&format!(
            "no publisher policy at {}; using the built-in official registry policy \
             (signed by {} in mvm-templates). Write that file to make your own trust \
             decision.",
            policy_path.display(),
            mvm_core::registry_pack::OFFICIAL_PACK_SIGNING_IDENTITY
        ));
    }
    let policy = loaded.policy;
    let lock_path = mvm_core::config::pack_lockfile_path();
    let lock = load_pack_lockfile(&lock_path)?;
    // Lock-first verification applies only when the resolved version is the
    // pinned one; a newer published version is adopted and replaces the pin
    // (that is what `pack registry update` relies on).
    let pinned = lock.pins().iter().any(|pin| pin.reference() == &reference);

    let verified: VerifiedRegistryPack = if pinned {
        let request = RegistryPackVerification::new(
            &reference,
            &fetched.manifest_bytes,
            &fetched.signature_bundle,
            &lock,
            &policy,
        );
        verify_registry_pack(&request)?
    } else {
        adopt_registry_pack(&PackAdoption {
            requested: &reference,
            manifest_bytes: &fetched.manifest_bytes,
            signature_bundle: &fetched.signature_bundle,
            publisher_policy: &policy,
        })?
    };

    let installed = if pinned {
        // The pin already exists; install reuses or repairs the cache entry.
        mvm_core::registry_pack::install_registry_pack(fetched.staged_path(), &verified)?
    } else {
        adopt_install_and_pin(
            &PackAdoption {
                requested: &reference,
                manifest_bytes: &fetched.manifest_bytes,
                signature_bundle: &fetched.signature_bundle,
                publisher_policy: &policy,
            },
            fetched.staged_path(),
            &mvm_core::config::registry_pack_cache_dir(),
            &lock_path,
        )?
    };
    let files = verified.manifest().files.len();
    Ok(PullSummary {
        reference: verified.manifest().reference.clone(),
        manifest_sha256: verified.manifest_sha256().as_str().to_string(),
        files,
        installed_root: installed.root().to_path_buf(),
        refreshed: pinned,
    })
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building a runtime for the pack registry fetch")
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    runtime()
        .expect("building a single-thread runtime for one registry fetch")
        .block_on(future)
}

async fn fetch_text(url: &str) -> Result<String> {
    let bytes = fetch_bytes(url).await?;
    String::from_utf8(bytes).with_context(|| format!("{url} is not UTF-8 text"))
}

async fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return std::fs::read(path).with_context(|| format!("reading local registry file {url}"));
    }
    let client = mvm_http::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("pack registry returned {} for {url}", status.as_u16());
    }
    response
        .bytes()
        .await
        .with_context(|| format!("reading body from {url}"))
        .map(|b| b.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(namespace: &str, name: &str, versions: &[&str]) -> PackIndexEntry {
        PackIndexEntry {
            namespace: namespace.to_string(),
            name: name.to_string(),
            description: format!("the {name} pack"),
            versions: versions.iter().map(|version| version.to_string()).collect(),
        }
    }

    #[test]
    fn search_filters_by_coordinate_and_description() {
        let index = vec![
            entry("runtime", "python", &["1.2.3"]),
            entry("agent", "claude", &["0.4.0"]),
        ];
        assert_eq!(search_index(&index, None).len(), 2);
        let hits = search_index(&index, Some("claude"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].coordinate(), "agent/claude");
        let hits = search_index(&index, Some("RUNTIME"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].coordinate(), "runtime/python");
        let hits = search_index(&index, Some("the"));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn resolve_version_takes_the_highest_published_version_when_unpinned() {
        let entry = entry("runtime", "python", &["1.2.3", "1.10.0", "1.2.10"]);
        let requested: PackReference = "runtime/python".parse().expect("reference");
        let resolved = resolve_version(&entry, &requested).expect("resolve");
        assert_eq!(resolved.to_string(), "runtime/python@1.10.0");
    }

    #[test]
    fn resolve_version_requires_the_requested_version_to_be_published() {
        let entry = entry("runtime", "python", &["1.2.3"]);
        let requested: PackReference = "runtime/python@9.9.9".parse().expect("reference");
        let error = resolve_version(&entry, &requested).expect_err("unpublished version");
        assert!(error.to_string().contains("not published at version 9.9.9"));
    }

    #[test]
    fn resolve_version_refuses_a_pack_with_no_versions() {
        let entry = entry("runtime", "python", &[]);
        let requested: PackReference = "runtime/python".parse().expect("reference");
        let error = resolve_version(&entry, &requested).expect_err("no versions");
        assert!(error.to_string().contains("publishes no versions"));
    }

    #[test]
    fn declared_paths_refuse_unsafe_manifest_paths() {
        let manifest = br#"{"files":[{"path":"pack/profile.toml"},{"path":"../escape.toml"}]}"#;
        let error = declared_paths(manifest).expect_err("unsafe path refuses");
        assert!(error.to_string().contains("unsafe file path"));
    }

    #[test]
    fn declared_paths_lists_safe_manifest_paths() {
        let manifest = br#"{"files":[{"path":"pack/profile.toml"},{"path":"pack/group.toml"}]}"#;
        let paths = declared_paths(manifest).expect("safe paths");
        assert_eq!(paths, vec!["pack/profile.toml", "pack/group.toml"]);
    }
}
