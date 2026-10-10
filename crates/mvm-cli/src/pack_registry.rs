//! Registry client for signed product packs.
//!
//! Fetches the pack index and pack payloads over HTTP(S) (or `file://` for
//! tests and air-gapped mirrors), then hands every byte to
//! `mvm_core::registry_pack` for verification and installation. Nothing here
//! trusts fetched content: paths from an unverified manifest are refused
//! before they are joined into URLs or staging paths, and the lock pin is
//! written only after signature, manifest, and payload all verify.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tempfile::TempDir;

use mvm_client::policy_profiles::{PolicyRef, ProfileFile, builtin};
use mvm_core::registry_pack::{
    InstalledRegistryPack, PackAdoption, PackReference, RegistryPackImage,
    RegistryPackVerification, VerifiedRegistryPack, adopt_registry_pack, verify_registry_pack,
};
use mvm_core::registry_pack_store::{
    PackPolicyDocument, adopt_install_and_pin, check_registry_pack_revocations_if_configured,
    load_pack_lockfile, load_publisher_policy_or_official_default, read_pack_policy_document,
};

/// Environment override for the pack registry base URL.
pub const PACK_REGISTRY_ENV: &str = "MVM_PACK_REGISTRY";
/// Default registry: the mvm-packs repository, same source the template
/// registry uses.
pub const DEFAULT_PACK_REGISTRY: &str =
    "https://raw.githubusercontent.com/tinylabscom/mvm-packs/main";

const PACK_INDEX_SCHEMA_VERSION: u32 = 1;
const PACKS_DIR: &str = "packs";
const MANIFEST_FILE: &str = "manifest.json";
const SIGNATURE_FILE: &str = "manifest.sigstore.json";
const FILES_DIR: &str = "files";
const MAX_PACKS_PER_PULL: usize = 128;

#[derive(Debug, Clone, Copy)]
enum PolicyDependencyKind {
    Profile,
    Group,
}

impl PolicyDependencyKind {
    fn label(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Group => "group",
        }
    }
}

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

/// Download only trust metadata. Payload fetch waits for authentication.
pub fn download_pack(
    config: &PackRegistryConfig,
    reference: &PackReference,
) -> Result<FetchedPack> {
    let manifest_url = pack_url(config, reference, MANIFEST_FILE);
    let manifest_bytes = block_on(fetch_bytes(&manifest_url))?;
    let signature_url = pack_url(config, reference, SIGNATURE_FILE);
    let signature_bundle = block_on(fetch_bytes(&signature_url))?;
    let staged = TempDir::new().context("creating a staging directory for the pack")?;
    Ok(FetchedPack {
        reference: reference.clone(),
        manifest_bytes,
        signature_bundle,
        staged,
    })
}

fn download_payload(
    config: &PackRegistryConfig,
    verified: &VerifiedRegistryPack,
    destination: &Path,
) -> Result<()> {
    for file in verified.payload_files() {
        let release = !verified
            .manifest()
            .files
            .iter()
            .any(|entry| entry.path == file.path);
        let url = if release {
            let Some(RegistryPackImage::Built(image)) = &verified.manifest().image else {
                bail!("release asset without a built image descriptor");
            };
            format!(
                "https://github.com/{}/releases/download/{}/{}",
                image.release.repository.as_str(),
                image.release.tag,
                file.path
            )
        } else {
            pack_url(
                config,
                &verified.manifest().reference,
                &format!("{FILES_DIR}/{}", file.path),
            )
        };
        let target = destination.join(&file.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        download_payload_file(&url, &target, file.size, release)?;
    }
    Ok(())
}

fn allowed_release_url(url: &str) -> bool {
    mvm_http::Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.fragment().is_none()
            && matches!(
                url.host_str(),
                Some("github.com" | "release-assets.githubusercontent.com")
            )
    })
}

fn download_payload_file(url: &str, target: &Path, size: u64, release: bool) -> Result<()> {
    use std::io::Read;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    let mut source: Box<dyn Read> = if !release && let Some(path) = url.strip_prefix("file://") {
        Box::new(std::fs::File::open(path)?)
    } else {
        let client = mvm_http::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .max_response_bytes(size.saturating_add(1))
            .build()?;
        let mut current = url.to_string();
        let mut hops = 0;
        loop {
            if release && !allowed_release_url(&current) {
                bail!("built image release origin refused");
            }
            let response = client.get(&current).send()?;
            if release && response.status().is_redirection() {
                if hops >= 3 {
                    bail!("too many built image release redirects");
                }
                current = response
                    .headers()
                    .get("location")
                    .context("release redirect has no location")?
                    .to_str()?
                    .to_string();
                hops += 1;
                continue;
            }
            if !response.status().is_success() {
                bail!("pack asset download returned {}", response.status());
            }
            if response
                .content_length()
                .is_some_and(|length| length != size)
            {
                bail!("pack asset download size differs from signed declaration");
            }
            break Box::new(response) as Box<dyn Read>;
        }
    };
    let copied = std::io::copy(
        &mut source.by_ref().take(size.saturating_add(1)),
        &mut output,
    )?;
    if copied != size {
        bail!("pack asset download size differs from signed declaration");
    }
    Ok(())
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

/// Fetch, verify, install, and pin a pack and its signed profile dependencies.
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
    let mut seen = BTreeMap::new();
    let mut active = Vec::new();
    pull_with_dependencies(
        &config,
        &index,
        &requested,
        &mut seen,
        &mut active,
        &mut pull_one,
    )?
    .context("the requested pack was already visited before its pull")
}

fn register_dependency(
    seen: &mut BTreeMap<String, PackReference>,
    reference: &PackReference,
) -> Result<bool> {
    let coordinate = reference.coordinate_string();
    if let Some(prior) = seen.get(&coordinate) {
        if prior != reference {
            bail!("conflicting versions of pack {coordinate}: {prior} and {reference}");
        }
        return Ok(false);
    }
    if seen.len() >= MAX_PACKS_PER_PULL {
        bail!("too many packs in one pull (limit {MAX_PACKS_PER_PULL})");
    }
    seen.insert(coordinate, reference.clone());
    Ok(true)
}

fn profile_pack_dependencies(text: &str) -> Result<Vec<PackReference>> {
    let profile: ProfileFile = toml::from_str(text).context("parsing signed pack profile")?;
    let mut dependencies = Vec::new();
    for name in profile.extends.to_vec() {
        add_policy_dependency(&name, PolicyDependencyKind::Profile, &mut dependencies)?;
    }
    for name in profile.groups.include {
        add_policy_dependency(&name, PolicyDependencyKind::Group, &mut dependencies)?;
    }
    for block in profile.when {
        for name in block.include {
            add_policy_dependency(&name, PolicyDependencyKind::Group, &mut dependencies)?;
        }
    }
    Ok(dependencies)
}

fn add_policy_dependency(
    name: &str,
    kind: PolicyDependencyKind,
    dependencies: &mut Vec<PackReference>,
) -> Result<()> {
    let reference = PolicyRef::parse(name).map_err(|reason| {
        anyhow::anyhow!("invalid signed pack policy reference {name:?}: {reason}")
    })?;
    match reference {
        PolicyRef::Pack { .. } => {
            let pack: PackReference = name
                .parse()
                .with_context(|| format!("invalid pack reference {name:?}"))?;
            if !dependencies.contains(&pack) {
                dependencies.push(pack);
            }
        }
        PolicyRef::Name(local) => {
            let exists = match kind {
                PolicyDependencyKind::Profile => builtin::profile(&local).is_some(),
                PolicyDependencyKind::Group => builtin::group(&local).is_some(),
            };
            if !exists {
                bail!(
                    "{local:?} is not a built-in {}; signed packs cannot import local policy",
                    kind.label()
                );
            }
        }
        PolicyRef::Path(_) => {
            bail!("signed pack profile cannot follow a filesystem policy path: {name:?}")
        }
    }
    Ok(())
}

fn declared_pack_dependencies(
    installed: &InstalledRegistryPack,
    verified: &VerifiedRegistryPack,
) -> Result<Vec<PackReference>> {
    if !verified
        .manifest()
        .files
        .iter()
        .any(|file| file.path == PackPolicyDocument::Profile.file_name())
    {
        return Ok(Vec::new());
    }
    let (_, profile) = read_pack_policy_document(installed, verified, PackPolicyDocument::Profile)?;
    profile_pack_dependencies(&profile)
}

fn pull_with_dependencies<F>(
    config: &PackRegistryConfig,
    index: &[PackIndexEntry],
    requested: &PackReference,
    seen: &mut BTreeMap<String, PackReference>,
    active: &mut Vec<PackReference>,
    pull_pack: &mut F,
) -> Result<Option<PullSummary>>
where
    F: FnMut(&PackRegistryConfig, &PackReference) -> Result<(PullSummary, Vec<PackReference>)>,
{
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
    let reference = resolve_version(entry, requested)?;
    if !register_dependency(seen, &reference)? {
        if active.contains(&reference) {
            bail!("signed pack dependency cycle at {reference}");
        }
        return Ok(None);
    }
    active.push(reference.clone());
    let (summary, dependencies) = pull_pack(config, &reference)?;
    for dependency in dependencies {
        pull_with_dependencies(config, index, &dependency, seen, active, pull_pack)
            .with_context(|| format!("pulling dependency {dependency} of {}", summary.reference))?;
    }
    active.pop();
    Ok(Some(summary))
}

fn pull_one(
    config: &PackRegistryConfig,
    reference: &PackReference,
) -> Result<(PullSummary, Vec<PackReference>)> {
    let fetched = download_pack(config, reference)?;

    let policy_path = mvm_core::config::registry_pack_publisher_policy_path();
    let loaded = load_publisher_policy_or_official_default(&policy_path)?;
    if loaded.is_official_default() {
        crate::ui::info(&format!(
            "no publisher policy at {}; using built-in trust for agent/ and runtime/ \
             signed by {} (or the former identity until 2026-11-06 UTC). \
             Write that file to make your own trust decision.",
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
    let pinned = lock.pins().iter().any(|pin| pin.reference() == reference);

    let verified: VerifiedRegistryPack = if pinned {
        let request = RegistryPackVerification::new(
            reference,
            &fetched.manifest_bytes,
            &fetched.signature_bundle,
            &lock,
            &policy,
        );
        verify_registry_pack(&request)?
    } else {
        adopt_registry_pack(&PackAdoption {
            requested: reference,
            manifest_bytes: &fetched.manifest_bytes,
            signature_bundle: &fetched.signature_bundle,
            publisher_policy: &policy,
        })?
    };
    check_registry_pack_revocations_if_configured(&verified)?;
    with_built_image_verifier_preflight(verified.manifest().image.as_ref(), || {
        download_payload(config, &verified, fetched.staged_path())
    })?;

    let installed = if pinned {
        // The pin already exists; install reuses or repairs the cache entry.
        mvm_core::registry_pack::install_registry_pack(fetched.staged_path(), &verified)?
    } else {
        adopt_install_and_pin(
            &PackAdoption {
                requested: reference,
                manifest_bytes: &fetched.manifest_bytes,
                signature_bundle: &fetched.signature_bundle,
                publisher_policy: &policy,
            },
            fetched.staged_path(),
            &mvm_core::config::registry_pack_cache_dir(),
            &lock_path,
        )?
    };
    let files = verified.payload_files().len();
    let dependencies = declared_pack_dependencies(&installed, &verified)?;
    Ok((
        PullSummary {
            reference: verified.manifest().reference.clone(),
            manifest_sha256: verified.manifest_sha256().as_str().to_string(),
            files,
            installed_root: installed.root().to_path_buf(),
            refreshed: pinned,
        },
        dependencies,
    ))
}

fn with_built_image_verifier_preflight<T>(
    image: Option<&RegistryPackImage>,
    download_payload: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if matches!(image, Some(RegistryPackImage::Built(_))) {
        mvm_core::registry_pack::ensure_built_image_verifier_available()?;
    }
    download_payload()
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
    const MAX_METADATA_BYTES: u64 = 1024 * 1024;
    if let Some(path) = url.strip_prefix("file://") {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len())? > MAX_METADATA_BYTES {
            bail!("pack registry metadata exceeds 1 MiB");
        }
        return Ok(bytes);
    }
    let client = mvm_http::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .max_response_bytes(MAX_METADATA_BYTES)
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

    #[test]
    fn default_registry_points_to_the_official_packs_repository() {
        assert_eq!(
            DEFAULT_PACK_REGISTRY,
            "https://raw.githubusercontent.com/tinylabscom/mvm-packs/main"
        );
    }

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
    fn release_urls_refuse_origin_substitution_and_credentials() {
        for url in [
            "http://github.com/asset",
            "https://github.com.evil.test/asset",
            "https://user@github.com/asset",
            "https://github.com:8443/asset",
            "file:///tmp/asset",
            "https://evil.test/asset",
        ] {
            assert!(!allowed_release_url(url), "{url}");
        }
        assert!(allowed_release_url("https://github.com/asset"));
        assert!(allowed_release_url(
            "https://release-assets.githubusercontent.com/asset?sig=value"
        ));
    }

    #[test]
    fn payload_download_enforces_exact_size_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"abc").unwrap();
        let url = format!("file://{}", source.display());
        let target = dir.path().join("target");
        download_payload_file(&url, &target, 3, false).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"abc");
        assert!(download_payload_file(&url, &target, 3, false).is_err());
        for size in [0, 2, 4] {
            let target = dir.path().join(format!("size-{size}"));
            assert!(download_payload_file(&url, &target, size, false).is_err());
        }
    }

    #[test]
    fn metadata_fetch_does_not_fetch_unverified_payloads() {
        let registry = tempfile::tempdir().unwrap();
        let pack = registry.path().join("packs/runtime/python/1.0.0");
        std::fs::create_dir_all(&pack).unwrap();
        let manifest = br#"{"files":[{"path":"../escape"}]}"#;
        std::fs::write(pack.join(MANIFEST_FILE), manifest).unwrap();
        std::fs::write(pack.join(SIGNATURE_FILE), b"unsigned").unwrap();
        let config = PackRegistryConfig {
            registry_url: format!("file://{}", registry.path().display()),
        };
        let fetched = download_pack(&config, &"runtime/python@1.0.0".parse().unwrap()).unwrap();
        assert_eq!(fetched.manifest_bytes, manifest);
        assert_eq!(std::fs::read_dir(fetched.staged_path()).unwrap().count(), 0);
    }

    #[test]
    fn built_image_verifier_refusal_precedes_payload_download() {
        use mvm_core::image_set::{ArtifactName, ReleaseTag, RepositorySlug};
        use mvm_core::packs::Sha256Hex;
        use mvm_core::registry_pack_image::{
            BuiltImageAsset, BuiltImageAssets, BuiltImageBaseSet, BuiltImagePlatform,
            BuiltImageRelease, BuiltPackImageDescriptor,
        };

        let digest = Sha256Hex::from_bytes(b"test");
        let asset = |name: &str| BuiltImageAsset {
            name: ArtifactName::new(name).unwrap(),
            sha256: digest.clone(),
            size: 1,
        };
        let image = RegistryPackImage::Built(Box::new(BuiltPackImageDescriptor {
            schema_version: 2,
            platform: BuiltImagePlatform::LinuxX86_64,
            base_set: BuiltImageBaseSet {
                repository: RepositorySlug::new("tinylabscom/mvm-images").unwrap(),
                release_tag: ReleaseTag::new("image-set/v0.2.4").unwrap(),
                manifest_sha256: digest.clone(),
            },
            release: BuiltImageRelease {
                repository: RepositorySlug::new("tinylabscom/mvm-packs").unwrap(),
                tag: "pack-runtime-python-v1.0.0".to_string(),
            },
            assets: BuiltImageAssets {
                rootfs: asset("rootfs.ext4"),
                verity: asset("rootfs.verity"),
                roothash: asset("rootfs.roothash"),
                mvm_meta: asset("mvm-meta.json"),
                rootfs_signature_bundle: asset("rootfs.signature.json"),
                provenance_statement: asset("provenance.json"),
                provenance_signature_bundle: asset("provenance.signature.json"),
            },
        }));
        let mut payload_downloaded = false;

        let error = with_built_image_verifier_preflight(Some(&image), || {
            payload_downloaded = true;
            Ok(())
        })
        .expect_err("missing compatible verifier must refuse the pull");

        assert!(
            error
                .to_string()
                .contains("no trusted released image verifier compatible"),
            "expected the verifier-unavailable error, got {error:#}"
        );
        assert!(
            !payload_downloaded,
            "payload fetch must not run after refusal"
        );
    }

    #[test]
    fn streamed_http_download_refuses_truncation_oversize_and_redirects() {
        use std::io::{Read, Write};
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nab",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
            "HTTP/1.1 302 Found\r\nLocation: https://evil.test/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 4096);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let _ = stream.write_all(response.as_bytes());
            });
            let target = tempfile::tempdir().unwrap();
            assert!(
                download_payload_file(
                    &format!("http://{address}/file"),
                    &target.path().join("asset"),
                    3,
                    false,
                )
                .is_err()
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn pack_profile_dependencies_cover_parents_groups_and_conditional_groups() {
        let profile = "extends = [\"agent/base@1.0.0\", \"agent/base@1.0.0\"]\n\
            [groups]\ninclude = [\"runtime/python\", \"llm-apis\"]\n\
            [[when]]\ninclude = [\"runtime/node@2.0.0\"]\n";
        let dependencies = profile_pack_dependencies(profile).expect("dependencies");
        assert_eq!(
            dependencies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["agent/base@1.0.0", "runtime/python", "runtime/node@2.0.0"]
        );
    }

    #[test]
    fn pack_profile_dependencies_refuse_host_paths_and_invalid_versions() {
        let path = profile_pack_dependencies("extends = \"./owner.toml\"\n")
            .expect_err("host path forbidden");
        assert!(path.to_string().contains("filesystem policy path"));
        let version = profile_pack_dependencies("[groups]\ninclude = [\"runtime/python@bad\"]\n")
            .expect_err("invalid version forbidden");
        assert!(version.to_string().contains("invalid pack reference"));
        let unknown = profile_pack_dependencies("[groups]\ninclude = [\"missing-local-group\"]\n")
            .expect_err("unknown local group forbidden");
        assert!(unknown.to_string().contains("not a built-in group"));
    }

    #[test]
    fn dependency_registration_deduplicates_and_rejects_version_conflicts() {
        let mut seen = std::collections::BTreeMap::new();
        let one: PackReference = "runtime/python@1.0.0".parse().expect("reference");
        let same = one.clone();
        let other: PackReference = "runtime/python@2.0.0".parse().expect("reference");
        assert!(register_dependency(&mut seen, &one).expect("first"));
        assert!(!register_dependency(&mut seen, &same).expect("duplicate"));
        let conflict = register_dependency(&mut seen, &other).expect_err("conflict");
        assert!(conflict.to_string().contains("conflicting versions"));
    }

    #[test]
    fn dependency_registration_has_a_bounded_pack_count() {
        let mut seen = BTreeMap::new();
        for index in 0..MAX_PACKS_PER_PULL {
            let reference: PackReference = format!("runtime/p{index}@1.0.0")
                .parse()
                .expect("reference");
            assert!(register_dependency(&mut seen, &reference).expect("within bound"));
        }
        let extra: PackReference = "runtime/extra@1.0.0".parse().expect("reference");
        let error = register_dependency(&mut seen, &extra).expect_err("bound refuses");
        assert!(error.to_string().contains("too many packs"));
    }

    #[test]
    fn dependency_pull_refuses_a_cycle() {
        let index = vec![
            entry("agent", "root", &["1.0.0"]),
            entry("runtime", "node", &["2.0.0"]),
        ];
        let config = PackRegistryConfig {
            registry_url: "file:///unused".to_string(),
        };
        let root: PackReference = "agent/root".parse().expect("root");
        let mut seen = BTreeMap::new();
        let mut active = Vec::new();
        let mut visited = Vec::new();
        let mut pull = |_: &PackRegistryConfig, reference: &PackReference| {
            visited.push(reference.to_string());
            let dependencies = if reference.name() == "root" {
                vec!["runtime/node".parse().expect("dependency")]
            } else {
                vec!["agent/root".parse().expect("cycle")]
            };
            Ok((summary(reference), dependencies))
        };
        let error =
            pull_with_dependencies(&config, &index, &root, &mut seen, &mut active, &mut pull)
                .expect_err("cycle must refuse");
        assert!(format!("{error:#}").contains("dependency cycle"));
        assert_eq!(visited, ["agent/root@1.0.0", "runtime/node@2.0.0"]);
    }

    #[test]
    fn dependency_pull_deduplicates_a_diamond() {
        let index = vec![
            entry("agent", "root", &["1.0.0"]),
            entry("runtime", "node", &["1.0.0"]),
            entry("runtime", "python", &["1.0.0"]),
            entry("runtime", "shared", &["1.0.0"]),
        ];
        let config = PackRegistryConfig {
            registry_url: "file:///unused".to_string(),
        };
        let root: PackReference = "agent/root".parse().expect("root");
        let mut seen = BTreeMap::new();
        let mut active = Vec::new();
        let mut visited = Vec::new();
        let mut pull = |_: &PackRegistryConfig, reference: &PackReference| {
            visited.push(reference.to_string());
            let names: &[&str] = match reference.name() {
                "root" => &["runtime/node", "runtime/python"],
                "node" | "python" => &["runtime/shared"],
                "shared" => &[],
                _ => panic!("unexpected pack"),
            };
            let dependencies = names
                .iter()
                .map(|name| name.parse())
                .collect::<Result<Vec<_>, _>>()?;
            Ok((summary(reference), dependencies))
        };
        pull_with_dependencies(&config, &index, &root, &mut seen, &mut active, &mut pull)
            .expect("diamond succeeds");
        assert_eq!(visited.len(), 4);
        assert_eq!(
            visited
                .iter()
                .filter(|name| name.contains("shared"))
                .count(),
            1
        );
    }

    #[test]
    fn dependency_pull_refuses_conflicting_versions_before_the_second_fetch() {
        let index = vec![
            entry("agent", "root", &["1.0.0"]),
            entry("runtime", "node", &["1.0.0", "2.0.0"]),
        ];
        let config = PackRegistryConfig {
            registry_url: "file:///unused".to_string(),
        };
        let root: PackReference = "agent/root".parse().expect("root");
        let mut seen = BTreeMap::new();
        let mut active = Vec::new();
        let mut visited = Vec::new();
        let mut pull = |_: &PackRegistryConfig, reference: &PackReference| {
            visited.push(reference.to_string());
            let dependencies = if reference.name() == "root" {
                vec![
                    "runtime/node@1.0.0".parse().expect("first"),
                    "runtime/node@2.0.0".parse().expect("conflicting"),
                ]
            } else {
                Vec::new()
            };
            Ok((summary(reference), dependencies))
        };
        let error =
            pull_with_dependencies(&config, &index, &root, &mut seen, &mut active, &mut pull)
                .expect_err("conflict must refuse");
        assert!(format!("{error:#}").contains("conflicting versions"));
        assert_eq!(visited, ["agent/root@1.0.0", "runtime/node@1.0.0"]);
    }

    fn summary(reference: &PackReference) -> PullSummary {
        PullSummary {
            reference: reference.clone(),
            manifest_sha256: String::new(),
            files: 0,
            installed_root: PathBuf::new(),
            refreshed: false,
        }
    }
}
