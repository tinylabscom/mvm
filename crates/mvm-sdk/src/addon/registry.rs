//! Registry client for fetching addon artifacts.
//!
//! Two implementations live in this module:
//!
//! - [`LocalRegistry`]: a directory-backed registry useful for test
//!   harnesses and offline development. Reads pre-published artifacts
//!   from a fixed filesystem layout (see [`LocalRegistry`] docs).
//!   Verifies sha256 round-trip but does NOT verify sigstore signatures
//!   (the wire format is stored verbatim; signature checks land with
//!   the real registry client).
//! - [`HttpRegistry`]: stub. Real sigstore-keyless verification,
//!   Rekor inclusion-proof checks, and HTTP transport land in a
//!   follow-up patch.
//!
//! The [`Registry`] trait is shaped so the consumer-side compile
//! pipeline can mock it cleanly in compile-time error tests, and so a
//! `LocalRegistry` can stand in for `HttpRegistry` everywhere registry
//! resolution is needed.

use crate::addon::manifest::{self, AddonManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Resolved metadata about a single addon version, returned by
/// [`Registry::resolve`]. Lockfile entries are derived from this
/// shape plus the artifact bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedVersion {
    /// Canonical ref including version (e.g.
    /// `addons.mvm.io/postgres@16.1.0`).
    pub r#ref: String,
    /// Resolved SemVer version (matches the manifest's `[addon].version`).
    pub version: String,
    /// sha256 over the canonical-form artifact tarball bytes.
    pub sha256: String,
    /// sha256 over the canonical manifest bytes.
    pub exports_sha256: String,
    /// sha256 over the SBOM bytes.
    pub sbom_sha256: String,
    /// Rekor inclusion proof index.
    pub rekor_log_index: u64,
    /// Sigstore-keyless signature bundle (cert + sig).
    pub signature: String,
    /// Whether this version has been yanked. Yanked versions still
    /// resolve for already-locked consumers but are not picked up by
    /// `mvm addon update`.
    #[serde(default)]
    pub yanked: bool,
}

/// Registry client surface. Implementations: `HttpRegistry` (real),
/// `LocalRegistry` (directory-backed; used by test harnesses and by
/// hermetic `mvm compile`), and test fakes.
pub trait Registry {
    /// List addon names in the registry, optionally filtered to those
    /// containing `pattern` as a substring (case-insensitive).
    /// Returns names in deterministic order (lexicographic).
    fn names(&self, pattern: Option<&str>) -> Result<Vec<String>, RegistryError>;

    /// List all versions of `name` in the registry, newest first.
    fn versions(&self, name: &str) -> Result<Vec<ResolvedVersion>, RegistryError>;

    /// Resolve `name@requested` (a SemVer constraint or pinned
    /// version) to a single version. Returns `Err(NotFound)` when no
    /// version satisfies.
    fn resolve(&self, name: &str, requested: &str) -> Result<ResolvedVersion, RegistryError>;

    /// Fetch the canonical manifest bytes for a resolved version.
    /// The bytes are exactly what the signature covers.
    fn manifest(&self, version: &ResolvedVersion) -> Result<AddonManifest, RegistryError>;

    /// Fetch the canonical tarball bytes.
    fn tarball(&self, version: &ResolvedVersion) -> Result<Vec<u8>, RegistryError>;

    /// Fetch the SBOM bytes (SPDX, JSON or YAML).
    fn sbom(&self, version: &ResolvedVersion) -> Result<Vec<u8>, RegistryError>;
}

#[derive(Debug)]
pub enum RegistryError {
    /// No addon by that name in the configured namespace.
    NotFound {
        name: String,
        did_you_mean: Vec<String>,
    },
    /// Network / TLS / 5xx — registry temporarily unreachable. Maps
    /// to `E_ADDON_REGISTRY_UNREACHABLE`.
    Unreachable { name: String, detail: String },
    /// Registry refused the request (403 / authorization). Maps to
    /// `E_ADDON_TENANT_NAMESPACE_DENIED`.
    Denied { name: String, detail: String },
    /// Sigstore-keyless verification failed (cert chain, OIDC
    /// identity policy, or Rekor inclusion proof). Maps to
    /// `E_ADDON_SIGNATURE_INVALID`.
    SignatureInvalid { name: String, detail: String },
    /// Reserved-name / typosquat block. Maps to
    /// `E_ADDON_TYPOSQUAT_BLOCKED`.
    TyposquatBlocked {
        name: String,
        did_you_mean: Vec<String>,
    },
    /// I/O or parse error against fetched bytes.
    Malformed { name: String, detail: String },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { name, did_you_mean } => {
                write!(f, "addon {name:?} not found")?;
                if !did_you_mean.is_empty() {
                    write!(f, "; did you mean: {did_you_mean:?}")?;
                }
                Ok(())
            }
            Self::Unreachable { name, detail } => {
                write!(f, "registry unreachable while resolving {name:?}: {detail}")
            }
            Self::Denied { name, detail } => {
                write!(f, "registry denied access to {name:?}: {detail}")
            }
            Self::SignatureInvalid { name, detail } => {
                write!(f, "signature verification failed for {name:?}: {detail}")
            }
            Self::TyposquatBlocked { name, did_you_mean } => {
                write!(
                    f,
                    "registry refused {name:?} (typosquat block); did you mean: {did_you_mean:?}"
                )
            }
            Self::Malformed { name, detail } => {
                write!(f, "registry payload for {name:?} was malformed: {detail}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ────────────────────────────────────────────────────────────────────
// LocalRegistry — directory-backed
// ────────────────────────────────────────────────────────────────────

/// Directory-backed registry. Useful for test harnesses, offline
/// development, and as the v1 reference shape for the future
/// `HttpRegistry`.
///
/// Filesystem layout (rooted at `LocalRegistry::root`):
///
/// ```text
/// <root>/
///   <name>/
///     index.toml              # version list + per-version metadata
///     <version>/
///       manifest.toml         # canonical manifest bytes
///       artifact.tar.gz       # canonical artifact bytes
///       sbom.json             # SPDX SBOM bytes
///       signature.bundle      # sigstore-keyless cert + sig (placeholder
///                             # — wire-compatible with HttpRegistry once
///                             # sigstore verification lands)
/// ```
///
/// `index.toml` per-name shape:
///
/// ```toml
/// [[version]]
/// version = "16.1.0"
/// sha256 = "abc..."           # canonical artifact tarball
/// exports_sha256 = "789..."
/// sbom_sha256 = "..."
/// rekor_log_index = 12345678  # 0 when running offline
/// signature = "..."
/// published_at = "2026-04-15T12:00:00Z"
/// yanked = false
/// ```
///
/// `LocalRegistry` verifies sha256 round-trip on every read (returns
/// `Malformed` if the on-disk artifact's sha doesn't match the index).
/// Signatures are stored verbatim and returned as opaque blobs;
/// callers that need to verify must do so themselves until
/// sigstore-keyless wiring lands.
pub struct LocalRegistry {
    root: PathBuf,
}

impl LocalRegistry {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn name_dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn version_dir(&self, name: &str, version: &str) -> PathBuf {
        self.name_dir(name).join(version)
    }

    fn read_index(&self, name: &str) -> Result<LocalRegistryIndex, RegistryError> {
        let path = self.name_dir(name).join("index.toml");
        let body = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RegistryError::NotFound {
                    name: name.to_string(),
                    did_you_mean: self.suggest_similar_names(name),
                }
            } else {
                RegistryError::Unreachable {
                    name: name.to_string(),
                    detail: e.to_string(),
                }
            }
        })?;
        toml::from_str::<LocalRegistryIndex>(&body).map_err(|e| RegistryError::Malformed {
            name: name.to_string(),
            detail: format!("could not parse {}: {e}", path.display()),
        })
    }

    fn suggest_similar_names(&self, name: &str) -> Vec<String> {
        // Best-effort: scan immediate subdirectories of root for entries
        // whose name shares a >50% prefix with the requested name. Used
        // to populate `did_you_mean` hints without a Levenshtein dep.
        let Ok(read_dir) = std::fs::read_dir(&self.root) else {
            return vec![];
        };
        let prefix_len = name.len() / 2 + 1;
        let prefix = &name[..prefix_len.min(name.len())];
        let mut out = vec![];
        for entry in read_dir.flatten() {
            if let Some(s) = entry.file_name().to_str()
                && s != name
                && s.starts_with(prefix)
            {
                out.push(s.to_string());
            }
        }
        out.sort();
        out.truncate(3);
        out
    }
}

#[derive(Debug, Deserialize)]
struct LocalRegistryIndex {
    #[serde(rename = "version", default)]
    versions: Vec<LocalRegistryIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct LocalRegistryIndexEntry {
    version: String,
    sha256: String,
    exports_sha256: String,
    sbom_sha256: String,
    #[serde(default)]
    rekor_log_index: u64,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    yanked: bool,
}

impl Registry for LocalRegistry {
    fn names(&self, pattern: Option<&str>) -> Result<Vec<String>, RegistryError> {
        let read_dir = match std::fs::read_dir(&self.root) {
            Ok(d) => d,
            Err(e) => {
                return Err(RegistryError::Unreachable {
                    name: "<root>".to_string(),
                    detail: format!("could not read registry root {}: {e}", self.root.display()),
                });
            }
        };
        let needle = pattern.map(|s| s.to_ascii_lowercase());
        let mut out = Vec::new();
        for entry in read_dir.flatten() {
            // Only directories that contain an `index.toml` count as
            // published addons. Stray files / scratch dirs are
            // ignored — keeps the registry tolerant to ad-hoc
            // sidecar content.
            if !entry.path().is_dir() {
                continue;
            }
            if !entry.path().join("index.toml").is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Some(needle) = &needle
                && !name.to_ascii_lowercase().contains(needle.as_str())
            {
                continue;
            }
            out.push(name);
        }
        out.sort();
        Ok(out)
    }

    fn versions(&self, name: &str) -> Result<Vec<ResolvedVersion>, RegistryError> {
        let index = self.read_index(name)?;
        let mut out: Vec<ResolvedVersion> = index
            .versions
            .into_iter()
            .map(|e| ResolvedVersion {
                r#ref: format!("{}@{}", name, e.version),
                version: e.version,
                sha256: e.sha256,
                exports_sha256: e.exports_sha256,
                sbom_sha256: e.sbom_sha256,
                rekor_log_index: e.rekor_log_index,
                signature: e.signature,
                yanked: e.yanked,
            })
            .collect();
        // Sort by SemVer descending — newest first. Cheap lex sort
        // works for the well-formed cases this v1 stub handles; a
        // proper SemVer comparison lands when version constraints are
        // wired into `resolve`.
        out.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(out)
    }

    fn resolve(&self, name: &str, requested: &str) -> Result<ResolvedVersion, RegistryError> {
        let versions = self.versions(name)?;
        // v1 LocalRegistry: exact-match semantics. Pin a version, get
        // exactly that. SemVer constraint resolution (`^16`, `~16.1`)
        // lands with `mvm addon update`.
        versions
            .into_iter()
            .find(|v| !v.yanked && v.version == requested)
            .ok_or_else(|| RegistryError::NotFound {
                name: format!("{name}@{requested}"),
                did_you_mean: vec![],
            })
    }

    fn manifest(&self, version: &ResolvedVersion) -> Result<AddonManifest, RegistryError> {
        let (name, ver) = split_ref(&version.r#ref).ok_or_else(|| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: "ref does not parse as <name>@<version>".to_string(),
        })?;
        let path = self.version_dir(name, ver).join("manifest.toml");
        let body = std::fs::read_to_string(&path).map_err(|e| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: format!("could not read {}: {e}", path.display()),
        })?;
        // Round-trip sha guard: the on-disk manifest must hash to the
        // exports_sha256 the index recorded.
        let actual_sha = hex_sha256(body.as_bytes());
        if actual_sha != version.exports_sha256 {
            return Err(RegistryError::Malformed {
                name: version.r#ref.clone(),
                detail: format!(
                    "manifest sha mismatch: index says {:?}, on-disk is {actual_sha:?}",
                    version.exports_sha256
                ),
            });
        }
        manifest::parse(&body).map_err(|e| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: format!("manifest parse error: {e}"),
        })
    }

    fn tarball(&self, version: &ResolvedVersion) -> Result<Vec<u8>, RegistryError> {
        let (name, ver) = split_ref(&version.r#ref).ok_or_else(|| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: "ref does not parse as <name>@<version>".to_string(),
        })?;
        let path = self.version_dir(name, ver).join("artifact.tar.gz");
        let bytes = std::fs::read(&path).map_err(|e| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: format!("could not read {}: {e}", path.display()),
        })?;
        let actual_sha = hex_sha256(&bytes);
        if actual_sha != version.sha256 {
            return Err(RegistryError::Malformed {
                name: version.r#ref.clone(),
                detail: format!(
                    "artifact sha mismatch: index says {:?}, on-disk is {actual_sha:?}",
                    version.sha256
                ),
            });
        }
        Ok(bytes)
    }

    fn sbom(&self, version: &ResolvedVersion) -> Result<Vec<u8>, RegistryError> {
        let (name, ver) = split_ref(&version.r#ref).ok_or_else(|| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: "ref does not parse as <name>@<version>".to_string(),
        })?;
        let path = self.version_dir(name, ver).join("sbom.json");
        let bytes = std::fs::read(&path).map_err(|e| RegistryError::Malformed {
            name: version.r#ref.clone(),
            detail: format!("could not read {}: {e}", path.display()),
        })?;
        let actual_sha = hex_sha256(&bytes);
        if actual_sha != version.sbom_sha256 {
            return Err(RegistryError::Malformed {
                name: version.r#ref.clone(),
                detail: format!(
                    "sbom sha mismatch: index says {:?}, on-disk is {actual_sha:?}",
                    version.sbom_sha256
                ),
            });
        }
        Ok(bytes)
    }
}

fn split_ref(r: &str) -> Option<(&str, &str)> {
    let (name, version) = r.split_once('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ────────────────────────────────────────────────────────────────────
// HttpRegistry — stub
// ────────────────────────────────────────────────────────────────────

/// Stub HTTP registry. Returns `Unreachable` for every call; the real
/// implementation lands when sigstore-keyless verification is wired.
pub struct HttpRegistry {
    pub base_url: String,
}

impl HttpRegistry {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

impl Registry for HttpRegistry {
    fn names(&self, _pattern: Option<&str>) -> Result<Vec<String>, RegistryError> {
        Err(RegistryError::Unreachable {
            name: "<root>".to_string(),
            detail: format!(
                "HttpRegistry::names is not implemented yet ({}); sigstore-keyless verification + HTTP fetch land in a follow-up.",
                self.base_url
            ),
        })
    }

    fn versions(&self, name: &str) -> Result<Vec<ResolvedVersion>, RegistryError> {
        Err(RegistryError::Unreachable {
            name: name.to_string(),
            detail: format!(
                "HttpRegistry::versions is not implemented yet ({}); \
                 sigstore-keyless verification + HTTP fetch land in a \
                 follow-up patch.",
                self.base_url
            ),
        })
    }

    fn resolve(&self, name: &str, _requested: &str) -> Result<ResolvedVersion, RegistryError> {
        Err(RegistryError::Unreachable {
            name: name.to_string(),
            detail: format!(
                "HttpRegistry::resolve is not implemented yet ({}).",
                self.base_url
            ),
        })
    }

    fn manifest(&self, version: &ResolvedVersion) -> Result<AddonManifest, RegistryError> {
        Err(RegistryError::Unreachable {
            name: version.r#ref.clone(),
            detail: "HttpRegistry::manifest is not implemented yet.".to_string(),
        })
    }

    fn tarball(&self, version: &ResolvedVersion) -> Result<Vec<u8>, RegistryError> {
        Err(RegistryError::Unreachable {
            name: version.r#ref.clone(),
            detail: "HttpRegistry::tarball is not implemented yet.".to_string(),
        })
    }

    fn sbom(&self, version: &ResolvedVersion) -> Result<Vec<u8>, RegistryError> {
        Err(RegistryError::Unreachable {
            name: version.r#ref.clone(),
            detail: "HttpRegistry::sbom is not implemented yet.".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    fn write(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    /// Build a minimal LocalRegistry with one published version of an
    /// addon called `postgres@16.1.0`. Returns the canonical
    /// (sha-validated) `ResolvedVersion` so tests can assert on
    /// round-trip.
    fn seed_registry(root: &Path) -> ResolvedVersion {
        let manifest_body = br#"manifest_version = "0"

[addon]
name = "postgres"
version = "16.1.0"
description = "Postgres 16"
tier = "separate"

[[addon.exports]]
logical_name = "main"
protocol = "postgres"
default_port = 5432
env_var = "DATABASE_URL"
credentials = "generated"
credential_format = "scram-sha-256"
"#;
        let tarball_body = b"fake-tar-bytes-for-test";
        let sbom_body = br#"{"spdxVersion":"SPDX-2.3","name":"postgres-16.1.0"}"#;

        let manifest_sha = hex_sha256(manifest_body);
        let tarball_sha = hex_sha256(tarball_body);
        let sbom_sha = hex_sha256(sbom_body);

        let dir = root.join("postgres/16.1.0");
        write(&dir.join("manifest.toml"), manifest_body);
        write(&dir.join("artifact.tar.gz"), tarball_body);
        write(&dir.join("sbom.json"), sbom_body);
        write(&dir.join("signature.bundle"), b"fake-sig-bundle");

        let index = format!(
            r#"
[[version]]
version = "16.1.0"
sha256 = "{tarball_sha}"
exports_sha256 = "{manifest_sha}"
sbom_sha256 = "{sbom_sha}"
rekor_log_index = 0
signature = "fake-sig"
yanked = false
"#
        );
        write(&root.join("postgres/index.toml"), index.as_bytes());

        ResolvedVersion {
            r#ref: "postgres@16.1.0".to_string(),
            version: "16.1.0".to_string(),
            sha256: tarball_sha,
            exports_sha256: manifest_sha,
            sbom_sha256: sbom_sha,
            rekor_log_index: 0,
            signature: "fake-sig".to_string(),
            yanked: false,
        }
    }

    #[test]
    fn versions_returns_published_versions() {
        let tmp = tempdir().unwrap();
        let _expected = seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());

        let versions = reg.versions("postgres").expect("versions");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "16.1.0");
        assert_eq!(versions[0].r#ref, "postgres@16.1.0");
    }

    #[test]
    fn resolve_returns_exact_version() {
        let tmp = tempdir().unwrap();
        let expected = seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());

        let resolved = reg.resolve("postgres", "16.1.0").expect("resolve");
        assert_eq!(resolved.version, expected.version);
        assert_eq!(resolved.sha256, expected.sha256);
    }

    #[test]
    fn resolve_unknown_version_returns_not_found() {
        let tmp = tempdir().unwrap();
        seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());
        match reg.resolve("postgres", "99.0.0") {
            Err(RegistryError::NotFound { name, .. }) => {
                assert_eq!(name, "postgres@99.0.0");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn resolve_unknown_name_returns_not_found_with_did_you_mean() {
        let tmp = tempdir().unwrap();
        seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());
        match reg.resolve("postgress", "16.1.0") {
            Err(RegistryError::NotFound { name, did_you_mean }) => {
                assert_eq!(name, "postgress");
                assert!(
                    did_you_mean.contains(&"postgres".to_string()),
                    "expected `postgres` in did_you_mean: {did_you_mean:?}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn manifest_round_trips_against_index() {
        let tmp = tempdir().unwrap();
        let v = seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());
        let manifest = reg.manifest(&v).expect("manifest");
        assert_eq!(manifest.addon.name, "postgres");
        assert_eq!(manifest.addon.version, "16.1.0");
    }

    #[test]
    fn tarball_round_trips_against_index() {
        let tmp = tempdir().unwrap();
        let v = seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());
        let bytes = reg.tarball(&v).expect("tarball");
        assert_eq!(bytes, b"fake-tar-bytes-for-test");
    }

    #[test]
    fn tarball_sha_mismatch_returns_malformed() {
        let tmp = tempdir().unwrap();
        let mut v = seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());
        // Tamper with the resolved version so its sha doesn't match the
        // on-disk artifact (simulates registry corruption).
        v.sha256 = "0".repeat(64);
        match reg.tarball(&v) {
            Err(RegistryError::Malformed { .. }) => {}
            other => panic!("expected Malformed on sha mismatch, got {other:?}"),
        }
    }

    #[test]
    fn sbom_round_trips_against_index() {
        let tmp = tempdir().unwrap();
        let v = seed_registry(tmp.path());
        let reg = LocalRegistry::new(tmp.path());
        let bytes = reg.sbom(&v).expect("sbom");
        assert!(bytes.starts_with(b"{\"spdxVersion\""));
    }

    #[test]
    fn names_lists_published_addons_lexicographically() {
        let tmp = tempdir().unwrap();
        seed_registry(tmp.path());
        // Drop a non-addon dir to ensure we filter to entries with index.toml.
        std::fs::create_dir_all(tmp.path().join("scratch")).unwrap();
        // And a second addon.
        let postgres_alt = tmp.path().join("postgres-alt");
        std::fs::create_dir_all(&postgres_alt).unwrap();
        std::fs::write(
            postgres_alt.join("index.toml"),
            b"[[version]]\nversion=\"1.0.0\"\nsha256=\"a\"\nexports_sha256=\"b\"\nsbom_sha256=\"c\"\n",
        )
        .unwrap();

        let reg = LocalRegistry::new(tmp.path());
        let names = reg.names(None).expect("names");
        assert_eq!(
            names,
            vec!["postgres".to_string(), "postgres-alt".to_string()]
        );
    }

    #[test]
    fn names_filters_by_substring_case_insensitively() {
        let tmp = tempdir().unwrap();
        seed_registry(tmp.path());
        // Add another addon whose name doesn't contain "post".
        let redis = tmp.path().join("redis");
        std::fs::create_dir_all(&redis).unwrap();
        std::fs::write(
            redis.join("index.toml"),
            b"[[version]]\nversion=\"7.0.0\"\nsha256=\"a\"\nexports_sha256=\"b\"\nsbom_sha256=\"c\"\n",
        )
        .unwrap();

        let reg = LocalRegistry::new(tmp.path());
        // Substring match.
        let names = reg.names(Some("post")).unwrap();
        assert_eq!(names, vec!["postgres".to_string()]);
        // Case-insensitive.
        let names = reg.names(Some("POST")).unwrap();
        assert_eq!(names, vec!["postgres".to_string()]);
        // Not-found.
        let names = reg.names(Some("nope")).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn yanked_versions_are_skipped_by_resolve() {
        let tmp = tempdir().unwrap();
        seed_registry(tmp.path());
        // Hand-rewrite the index to yank 16.1.0.
        let yanked_index = std::fs::read_to_string(tmp.path().join("postgres/index.toml"))
            .unwrap()
            .replace("yanked = false", "yanked = true");
        std::fs::write(tmp.path().join("postgres/index.toml"), yanked_index).unwrap();
        let reg = LocalRegistry::new(tmp.path());
        match reg.resolve("postgres", "16.1.0") {
            Err(RegistryError::NotFound { .. }) => {}
            other => panic!("expected yanked version to be unresolvable, got {other:?}"),
        }
    }
}
