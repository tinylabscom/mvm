//! Untrusted catalog discovery and bounded metadata transport.
//!
//! Discovery does not authenticate, fetch application archives, install, pin
//! or launch anything. Publisher authentication remains a separate boundary.

use anyhow::{Context, Result, bail};
use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::{PackReference, local_input};
use serde::Deserialize;

pub const PACK_REGISTRY_ENV: &str = "MVM_PACK_REGISTRY";
pub const DEFAULT_PACK_REGISTRY: &str =
    "https://raw.githubusercontent.com/tinylabscom/mvm-packs/main";
const PACK_INDEX_SCHEMA_VERSION: u32 = 2;

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

    pub fn base(&self) -> String {
        self.registry_url.trim_end_matches('/').to_string()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackIndexEntry {
    pub namespace: String,
    pub name: String,
    pub description: String,
    pub versions: Vec<PackIndexVersion>,
}

/// A discovery digest is not signature evidence or namespace authority.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackIndexVersion {
    pub version: String,
    pub manifest_sha256: Sha256Hex,
    /// Aliases for this exact version (`latest`). Display and ordering hints
    /// only: a tag never selects a digest, the signed manifest does.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Guest architecture the version was built for, in `GuestArch` spelling.
    #[serde(default)]
    pub guest_arch: Option<String>,
    /// Size in bytes of the version's bundle archive, as advertised.
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

impl PackIndexVersion {
    /// Advertised guest platform, e.g. `linux/aarch64`; `None` for an index
    /// that predates the field.
    pub fn platform(&self) -> Option<String> {
        self.guest_arch.as_ref().map(|arch| format!("linux/{arch}"))
    }

    /// Whether the version can run on `host_arch`; an unadvertised
    /// architecture is not a mismatch.
    pub fn runs_on(&self, host_arch: &str) -> bool {
        self.guest_arch
            .as_deref()
            .is_none_or(|arch| arch == host_arch)
    }
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

pub fn fetch_index(config: &PackRegistryConfig) -> Result<Vec<PackIndexEntry>> {
    let url = format!("{}/index.json", config.base());
    let text = block_on(fetch_text(&url))?;
    parse_index(&text, &url)
}

fn parse_index(text: &str, url: &str) -> Result<Vec<PackIndexEntry>> {
    let wire: PackIndexWire =
        serde_json::from_str(text).with_context(|| format!("parsing pack index from {url}"))?;
    if wire.schema_version != PACK_INDEX_SCHEMA_VERSION {
        bail!(
            "pack index at {url} has schema version {}, expected {PACK_INDEX_SCHEMA_VERSION}",
            wire.schema_version
        );
    }
    let mut coordinates = std::collections::BTreeSet::new();
    for entry in &wire.packs {
        let coordinate = entry.coordinate();
        let reference: PackReference = coordinate.parse().context("invalid catalog coordinate")?;
        if reference.version().is_some()
            || reference.namespace() != entry.namespace
            || reference.name() != entry.name
            || !coordinates.insert(coordinate.clone())
        {
            bail!("duplicate or invalid catalog coordinate {coordinate}");
        }
        if entry.versions.is_empty() {
            bail!("pack {coordinate} publishes no versions");
        }
        let mut versions = std::collections::BTreeSet::new();
        let mut tags = std::collections::BTreeSet::new();
        for version in &entry.versions {
            let _: PackReference = format!("{coordinate}@{}", version.version)
                .parse()
                .context("invalid catalog version")?;
            if !versions.insert(&version.version) {
                bail!("duplicate catalog version {coordinate}@{}", version.version);
            }
            for tag in &version.tags {
                if !tags.insert(tag) {
                    bail!("catalog tag {tag:?} of {coordinate} names more than one version");
                }
            }
        }
    }
    Ok(wire.packs)
}

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

pub fn resolve_version(entry: &PackIndexEntry, requested: &PackReference) -> Result<PackReference> {
    resolve_matching(entry, requested, |_| true)
}

/// Like [`resolve_version`], but an unpinned request takes the highest version
/// that runs on `host_arch`. When none does it falls back to the highest
/// version overall so the caller can warn instead of failing to resolve.
pub fn resolve_version_for_arch(
    entry: &PackIndexEntry,
    requested: &PackReference,
    host_arch: &str,
) -> Result<PackReference> {
    resolve_matching(entry, requested, |version| version.runs_on(host_arch))
        .or_else(|_| resolve_version(entry, requested))
}

fn resolve_matching(
    entry: &PackIndexEntry,
    requested: &PackReference,
    eligible: impl Fn(&PackIndexVersion) -> bool,
) -> Result<PackReference> {
    if entry.namespace != requested.namespace() || entry.name != requested.name() {
        bail!("catalog coordinate does not match requested pack {requested}");
    }
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
            if !versions
                .iter()
                .any(|published| published.version == spelling)
            {
                bail!(
                    "pack {} is not published at version {spelling} (published: {})",
                    entry.coordinate(),
                    versions
                        .iter()
                        .map(|v| v.version.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            spelling
        }
        None => versions
            .iter()
            .filter(|published| eligible(published))
            .filter_map(|published| {
                released(&published.version).map(|version| (version, &published.version))
            })
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, spelling)| spelling.clone())
            .context("catalog contains no valid published versions")?,
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

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building a runtime for the pack registry fetch")
}

/// Synchronous bridge for synchronous registry callers. Safe to call from
/// inside a tokio runtime: the future then runs on a scoped helper thread with
/// its own runtime, because a runtime cannot be entered from within another.
pub fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    let run = || {
        runtime()
            .expect("building a single-thread runtime for one registry fetch")
            .block_on(future)
    };
    if tokio::runtime::Handle::try_current().is_err() {
        return run();
    }
    std::thread::scope(|scope| match scope.spawn(run).join() {
        Ok(output) => output,
        Err(panic) => std::panic::resume_unwind(panic),
    })
}

async fn fetch_text(url: &str) -> Result<String> {
    let bytes = fetch_bytes(url).await?;
    String::from_utf8(bytes).with_context(|| format!("{url} is not UTF-8 text"))
}

/// Read only catalog, descriptor or signature metadata, never a payload archive.
/// Local mirrors reuse the verifier's bounded regular-file handle checks.
///
/// `file://` mirrors are supported only on Unix. On non-Unix platforms the
/// canonical reader returns an `io::ErrorKind::Other` cause with the diagnostic
/// "safe local acquisition requires Unix input handles", including for a valid
/// regular file. Use an HTTPS registry there; no unchecked local file opener
/// is substituted when the safe reader is unavailable.
pub async fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return local_input::read_metadata(std::path::Path::new(path))
            .context("reading local pack registry metadata");
    }
    let client = mvm_http::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .max_response_bytes(local_input::MAX_METADATA_BYTES)
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

    fn catalog() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 2,
            "packs": [{
                "namespace": "runtime", "name": "python", "description": "Python policy",
                "versions": [{"version": "1.2.3", "manifest_sha256": "a".repeat(64)}]
            }]
        })
    }

    fn parse(value: &serde_json::Value) -> Result<Vec<PackIndexEntry>> {
        parse_index(&value.to_string(), "local test catalog")
    }

    #[tokio::test]
    async fn block_on_does_not_panic_inside_a_tokio_runtime() {
        assert_eq!(block_on(async { 7 }), 7);
    }

    #[test]
    fn catalog_resolution_binds_coordinates_and_exact_versions() {
        let index = parse(&catalog()).unwrap();
        let exact = "runtime/python@1.2.3".parse().unwrap();
        assert_eq!(resolve_version(&index[0], &exact).unwrap(), exact);
        assert!(resolve_version(&index[0], &"agent/python".parse().unwrap()).is_err());
        assert!(resolve_version(&index[0], &"runtime/python@9.0.0".parse().unwrap()).is_err());
    }

    #[test]
    fn latest_version_selection_is_semantic_not_lexical() {
        let mut value = catalog();
        value["packs"][0]["versions"] = serde_json::json!([
            {"version":"1.2.3", "manifest_sha256":"a".repeat(64)},
            {"version":"1.10.0", "manifest_sha256":"b".repeat(64)}
        ]);
        let index = parse(&value).unwrap();
        let latest = resolve_version(&index[0], &"runtime/python".parse().unwrap()).unwrap();
        assert_eq!(latest.to_string(), "runtime/python@1.10.0");
        assert_eq!(
            search_index(&index, Some("PYTHON"))[0].coordinate(),
            "runtime/python"
        );
    }

    #[test]
    fn catalog_refuses_legacy_shapes_duplicate_entries_and_unknown_fields() {
        let mut values = Vec::new();
        let mut value = catalog();
        value["schema_version"] = 1.into();
        values.push(value);
        let mut value = catalog();
        value["extra"] = true.into();
        values.push(value);
        let mut value = catalog();
        let duplicate = value["packs"][0].clone();
        value["packs"].as_array_mut().unwrap().push(duplicate);
        values.push(value);
        let mut value = catalog();
        let duplicate = value["packs"][0]["versions"][0].clone();
        value["packs"][0]["versions"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        values.push(value);
        let mut value = catalog();
        value["packs"][0]["versions"] = serde_json::json!([]);
        values.push(value);
        for value in values {
            assert!(parse(&value).is_err());
        }
        assert!(
            parse_index(
                r#"{"schema_version":2,"schema_version":2,"packs":[]}"#,
                "test"
            )
            .is_err()
        );
    }

    fn with_versions(versions: serde_json::Value) -> serde_json::Value {
        let mut value = catalog();
        value["packs"][0]["versions"] = versions;
        value
    }

    #[test]
    fn tags_platform_and_size_parse_and_old_entries_default() {
        let index = parse(&with_versions(serde_json::json!([
            {"version":"1.2.3", "manifest_sha256":"a".repeat(64)},
            {"version":"1.3.0", "manifest_sha256":"b".repeat(64),
             "tags":["latest"], "guest_arch":"aarch64", "size_bytes": 7}
        ])))
        .unwrap();
        let (old, new) = (&index[0].versions[0], &index[0].versions[1]);
        assert!(old.tags.is_empty() && old.platform().is_none() && old.size_bytes.is_none());
        assert!(old.runs_on("x86_64"));
        assert_eq!(new.tags, ["latest"]);
        assert_eq!(new.platform().as_deref(), Some("linux/aarch64"));
        assert_eq!((new.size_bytes, new.runs_on("x86_64")), (Some(7), false));
    }

    #[test]
    fn a_tag_naming_two_versions_is_refused() {
        let value = with_versions(serde_json::json!([
            {"version":"1.2.3", "manifest_sha256":"a".repeat(64), "tags":["latest"]},
            {"version":"1.3.0", "manifest_sha256":"b".repeat(64), "tags":["latest"]}
        ]));
        assert!(parse(&value).is_err());
    }

    #[test]
    fn unpinned_resolution_prefers_the_host_arch_and_ignores_tags() {
        let index = parse(&with_versions(serde_json::json!([
            {"version":"1.0.0", "manifest_sha256":"a".repeat(64), "guest_arch":"x86_64",
             "tags":["latest"]},
            {"version":"2.0.0", "manifest_sha256":"b".repeat(64), "guest_arch":"aarch64"}
        ])))
        .unwrap();
        let request = "runtime/python".parse().unwrap();
        let pick = |arch| resolve_version_for_arch(&index[0], &request, arch).unwrap();
        assert_eq!(pick("x86_64").to_string(), "runtime/python@1.0.0");
        assert_eq!(pick("aarch64").to_string(), "runtime/python@2.0.0");
        // No version runs here: still resolves so the caller can warn.
        assert_eq!(pick("riscv64").to_string(), "runtime/python@2.0.0");
        // The index tag does not override the semantic ordering.
        assert_eq!(
            resolve_version(&index[0], &request).unwrap().to_string(),
            "runtime/python@2.0.0"
        );
    }

    #[test]
    fn discovery_digests_are_canonical_lowercase_sha256() {
        for digest in ["", &"A".repeat(64), &"g".repeat(64), &"a".repeat(63)] {
            let mut value = catalog();
            value["packs"][0]["versions"][0]["manifest_sha256"] = digest.into();
            assert!(parse(&value).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_catalog_fetch_has_no_payload_or_install_side_effects() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("index.json"), catalog().to_string()).unwrap();
        let config = PackRegistryConfig {
            registry_url: format!("file://{}/", root.path().display()),
        };
        assert_eq!(fetch_index(&config).unwrap().len(), 1);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_accepts_limit_and_refuses_oversize() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("metadata");
        let size = usize::try_from(local_input::MAX_METADATA_BYTES).unwrap();
        std::fs::write(&path, vec![0; size]).unwrap();
        let url = format!("file://{}", path.display());
        assert_eq!(block_on(fetch_bytes(&url)).unwrap().len(), size);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(local_input::MAX_METADATA_BYTES + 1)
            .unwrap();
        assert!(block_on(fetch_bytes(&url)).is_err());
    }

    #[cfg(not(unix))]
    #[test]
    fn local_metadata_refuses_valid_regular_file_without_safe_platform_reader() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("metadata");
        std::fs::write(&path, b"valid regular metadata").unwrap();
        let error = block_on(fetch_bytes(&format!("file://{}", path.display()))).unwrap_err();
        let cause = error.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(cause.kind(), std::io::ErrorKind::Other);
        assert_eq!(
            cause.to_string(),
            "safe local acquisition requires Unix input handles"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_refuses_leaf_links_hardlinks_and_directories() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::write(&original, b"metadata").unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(block_on(fetch_bytes(&format!("file://{}", link.display()))).is_err());
        std::fs::hard_link(&original, root.path().join("alias")).unwrap();
        assert!(block_on(fetch_bytes(&format!("file://{}", original.display()))).is_err());
        assert!(block_on(fetch_bytes(&format!("file://{}", root.path().display()))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_refuses_socket_without_a_connection() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(block_on(fetch_bytes(&format!("file://{}", path.display()))).is_err());
    }
}
