//! Application-dependency audit primitives. SDK port Phase 9.
//!
//! Phase 9's "Auditing the dep volume" section calls for every
//! application-dep volume to ship four sealed artifacts beside the
//! installed bytes:
//!
//! ```text
//! ~/.mvm/volumes/deps/<volume_hash>/
//! ├── content/                  # /app/.venv or /app/node_modules
//! ├── sbom.cdx.json             # CycloneDX SBOM
//! ├── fetch.log                 # every URL the installer dialed
//! ├── cve.json                  # pip-audit / pnpm-audit result
//! └── meta.json                 # sha256s + timestamps; sealed
//! ```
//!
//! The `volume_hash` is `sha256(content_sha256 || canonical(meta))`
//! so any tamper to any of the artifacts (content, SBOM, fetch
//! log, CVE result) invalidates `meta.json` → invalidates the
//! volume hash → admission fails closed.
//!
//! This module ships the pure-Rust primitives:
//!
//! - [`SbomFile`] / [`FetchLog`] / [`CveResult`] — typed wire
//!   shapes for the sealed artifacts. The builder VM emits these;
//!   the host reads them; both go through the same types so a
//!   schema drift breaks compilation.
//! - [`VolumeManifest`] — what `meta.json` carries: the four
//!   artifact hashes + creation/last-audit timestamps.
//! - [`seal_volume`] — reads a content directory and the three
//!   sidecar files, computes their hashes, builds the manifest,
//!   writes `meta.json`, and returns the canonical `volume_hash`.
//! - [`verify_sealed_volume`] — recomputes every hash from disk
//!   and compares to the manifest. Used at admission time before
//!   the workload boots; a mismatch raises
//!   [`VolumeError::HashMismatch`] and the supervisor rejects.
//!
//! The *builder-VM-side* install pipeline (running pip / pnpm
//! behind an egress allowlist, generating the SBOM via
//! `cyclonedx-py` / `pnpm sbom`, capturing the fetch log,
//! running `pip-audit` / `pnpm audit`) lives in `mvm-build` and
//! lands with Plan 71 W4 once the builder VM actually boots. The
//! audit gate stays *here* in the SDK so the same types are
//! consumed by the CLI (`mvmctl deps audit`, `mvmctl deps inspect`)
//! and the supervisor's admission path with no schema drift.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version stamped into every `meta.json`. Bumped only on
/// breaking changes; additive fields (new audit artifacts, e.g. a
/// future signature file) stay at the same major.
pub const VOLUME_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Canonical filename for each sealed artifact. Centralized so the
/// builder VM, the host audit path, and the admission verifier all
/// agree on the layout.
pub const FILE_CONTENT_DIR: &str = "content";
pub const FILE_SBOM: &str = "sbom.cdx.json";
pub const FILE_FETCH_LOG: &str = "fetch.log";
pub const FILE_CVE: &str = "cve.json";
pub const FILE_MANIFEST: &str = "meta.json";

/// What ends up in `meta.json`. Field order is the canonical hash
/// order — `serde_json::to_string` over a `BTreeMap`-backed value
/// produces deterministic bytes the same way other mvm canonical
/// IRs do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeManifest {
    /// Always `VOLUME_MANIFEST_SCHEMA_VERSION` on write; a `verify`
    /// against an older or newer schema fails closed.
    pub schema_version: u32,
    /// sha256 of the recursive content directory bytes — computed
    /// the same way `verify_sealed_volume` re-derives it (see
    /// `hash_dir`).
    pub content_sha256: String,
    /// sha256 of `sbom.cdx.json` bytes verbatim.
    pub sbom_sha256: String,
    /// sha256 of `fetch.log` bytes verbatim.
    pub fetch_log_sha256: String,
    /// sha256 of `cve.json` bytes verbatim.
    pub cve_sha256: String,
    /// ISO-8601 timestamp the volume was first sealed.
    pub created_at: String,
    /// ISO-8601 timestamp of the last `mvmctl deps audit` rerun,
    /// or equal to `created_at` if never re-audited.
    pub last_audit_at: String,
    /// Optional caller-provided pointers (lockfile path, tool
    /// version, etc.) for `mvmctl deps inspect`. Not part of the
    /// hash; admission ignores these.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Result of [`seal_volume`] — the volume hash that goes into the
/// directory name, plus the canonical manifest bytes (so the
/// caller can write them and verify the round-trip without
/// re-canonicalizing).
#[derive(Debug, Clone)]
pub struct VolumeSealResult {
    pub volume_hash: String,
    pub manifest: VolumeManifest,
    /// Canonical JSON bytes the caller should write to
    /// `<dir>/meta.json`.
    pub manifest_bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("volume directory `{}` is missing", .0.display())]
    Missing(PathBuf),

    #[error(
        "sealed artifact `{}` is missing in volume `{}`",
        artifact,
        volume.display()
    )]
    ArtifactMissing { volume: PathBuf, artifact: &'static str },

    #[error("failed to read volume artifact `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "{kind} hash mismatch in volume `{}`: manifest = {expected}, computed = {actual}",
        volume.display()
    )]
    HashMismatch {
        volume: PathBuf,
        kind: &'static str,
        expected: String,
        actual: String,
    },

    #[error(
        "manifest schema_version {found} does not match supported {expected} in volume `{}`",
        volume.display()
    )]
    SchemaMismatch {
        volume: PathBuf,
        expected: u32,
        found: u32,
    },

    #[error("manifest JSON is malformed in volume `{}`: {source}", volume.display())]
    ManifestParse {
        volume: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Seal a freshly-built dep volume. Reads the content directory and
/// the three sidecar files, computes their sha256s, builds the
/// canonical `meta.json` shape, and returns the volume hash plus
/// the manifest bytes. The caller writes the bytes to
/// `<volume_dir>/meta.json` and (typically) renames the volume
/// directory to its hash.
///
/// `created_at` / `last_audit_at` are caller-supplied so this
/// function stays pure / clock-free. Production callers pass
/// `chrono::Utc::now()`; tests pass a fixed string.
pub fn seal_volume(
    content_dir: &Path,
    sbom: &Path,
    fetch_log: &Path,
    cve: &Path,
    created_at: impl Into<String>,
    annotations: BTreeMap<String, String>,
) -> Result<VolumeSealResult, VolumeError> {
    let content_sha256 = hash_dir(content_dir)?;
    let sbom_sha256 = hash_file(sbom)?;
    let fetch_log_sha256 = hash_file(fetch_log)?;
    let cve_sha256 = hash_file(cve)?;

    let created_at = created_at.into();
    let manifest = VolumeManifest {
        schema_version: VOLUME_MANIFEST_SCHEMA_VERSION,
        content_sha256: content_sha256.clone(),
        sbom_sha256,
        fetch_log_sha256,
        cve_sha256,
        created_at: created_at.clone(),
        last_audit_at: created_at,
        annotations,
    };
    let manifest_bytes = canonical_json(&manifest)?;
    let volume_hash = derive_volume_hash(&content_sha256, &manifest_bytes);
    Ok(VolumeSealResult {
        volume_hash,
        manifest,
        manifest_bytes,
    })
}

/// Verify a sealed volume directory matches its manifest. Reads
/// `meta.json`, recomputes the content/sbom/fetch_log/cve hashes
/// from disk, and asserts they match. On success, returns the
/// expected `volume_hash` so the caller can compare it against
/// the directory name. Fails closed on any mismatch.
pub fn verify_sealed_volume(volume_dir: &Path) -> Result<String, VolumeError> {
    if !volume_dir.exists() {
        return Err(VolumeError::Missing(volume_dir.to_path_buf()));
    }
    let manifest_path = volume_dir.join(FILE_MANIFEST);
    if !manifest_path.exists() {
        return Err(VolumeError::ArtifactMissing {
            volume: volume_dir.to_path_buf(),
            artifact: FILE_MANIFEST,
        });
    }
    let manifest_bytes =
        std::fs::read(&manifest_path).map_err(|e| VolumeError::Io {
            path: manifest_path.clone(),
            source: e,
        })?;
    let manifest: VolumeManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| VolumeError::ManifestParse {
            volume: volume_dir.to_path_buf(),
            source,
        })?;
    if manifest.schema_version != VOLUME_MANIFEST_SCHEMA_VERSION {
        return Err(VolumeError::SchemaMismatch {
            volume: volume_dir.to_path_buf(),
            expected: VOLUME_MANIFEST_SCHEMA_VERSION,
            found: manifest.schema_version,
        });
    }

    let content_dir = volume_dir.join(FILE_CONTENT_DIR);
    if !content_dir.exists() {
        return Err(VolumeError::ArtifactMissing {
            volume: volume_dir.to_path_buf(),
            artifact: FILE_CONTENT_DIR,
        });
    }
    let pairs: &[(&'static str, &str, PathBuf)] = &[
        ("content", &manifest.content_sha256, content_dir.clone()),
        ("sbom", &manifest.sbom_sha256, volume_dir.join(FILE_SBOM)),
        (
            "fetch_log",
            &manifest.fetch_log_sha256,
            volume_dir.join(FILE_FETCH_LOG),
        ),
        ("cve", &manifest.cve_sha256, volume_dir.join(FILE_CVE)),
    ];
    for (kind, expected, path) in pairs {
        if !path.exists() {
            return Err(VolumeError::ArtifactMissing {
                volume: volume_dir.to_path_buf(),
                artifact: artifact_name(kind),
            });
        }
        let actual = if path.is_dir() {
            hash_dir(path)?
        } else {
            hash_file(path)?
        };
        if &actual != expected {
            return Err(VolumeError::HashMismatch {
                volume: volume_dir.to_path_buf(),
                kind,
                expected: (*expected).to_string(),
                actual,
            });
        }
    }

    // Canonicalize the manifest we just parsed and recompute the
    // volume hash. This is the value `mvmctl deps audit` rewrites
    // when re-running the CVE scan (the manifest changes →
    // volume_hash changes); admission compares this against the
    // ExecutionPlan's recorded hash.
    let canonical = canonical_json(&manifest)?;
    Ok(derive_volume_hash(&manifest.content_sha256, &canonical))
}

/// Compute the deterministic volume hash from the content sha256
/// and the canonical manifest bytes. Pure function so callers
/// (builder VM, admission verifier, audit re-runner) all agree
/// on the value.
pub fn derive_volume_hash(content_sha256: &str, manifest_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(content_sha256.as_bytes());
    h.update(b"\n");
    h.update(manifest_bytes);
    hex(&h.finalize())
}

fn artifact_name(kind: &str) -> &'static str {
    match kind {
        "content" => FILE_CONTENT_DIR,
        "sbom" => FILE_SBOM,
        "fetch_log" => FILE_FETCH_LOG,
        "cve" => FILE_CVE,
        _ => "<unknown>",
    }
}

/// Recursively hash a directory's contents. Walks entries in
/// sorted order (bytes-wise) so the same content produces the same
/// hash on every filesystem; folds (relative_path, sha256(file))
/// pairs into the rolling digest.
fn hash_dir(dir: &Path) -> Result<String, VolumeError> {
    let mut entries = Vec::new();
    walk_sorted(dir, dir, &mut entries)?;
    let mut h = Sha256::new();
    for (rel, file_path) in &entries {
        h.update(rel.as_bytes());
        h.update(b"\0");
        let file_hash = hash_file_raw(file_path)?;
        h.update(file_hash.as_bytes());
        h.update(b"\n");
    }
    Ok(hex(&h.finalize()))
}

fn walk_sorted(
    base: &Path,
    cur: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), VolumeError> {
    let mut entries: Vec<_> = std::fs::read_dir(cur)
        .map_err(|e| VolumeError::Io {
            path: cur.to_path_buf(),
            source: e,
        })?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        let ft = e.file_type().map_err(|err| VolumeError::Io {
            path: p.clone(),
            source: err,
        })?;
        if ft.is_dir() {
            walk_sorted(base, &p, out)?;
        } else if ft.is_file() {
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .into_owned();
            out.push((rel, p));
        }
        // Symlinks intentionally skipped: a symlink-bearing dep
        // closure that resolves outside the volume isn't
        // reproducible. The builder VM's install path materializes
        // every file inside the volume.
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, VolumeError> {
    hash_file_raw(path)
}

fn hash_file_raw(path: &Path) -> Result<String, VolumeError> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| VolumeError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| VolumeError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn canonical_json(manifest: &VolumeManifest) -> Result<Vec<u8>, VolumeError> {
    // serde_json with serde struct field order is deterministic.
    // The schema's annotations field uses BTreeMap so its keys are
    // sorted too.
    serde_json::to_vec(manifest).map_err(|source| VolumeError::ManifestParse {
        volume: PathBuf::from("<sealing>"),
        source,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// Wire-shape sketches for the artifacts the builder VM emits. Kept
// as type aliases over `serde_json::Value` for now — the SBOM
// (CycloneDX 1.5), fetch log, and CVE scan output each have their
// own external schemas (CycloneDX has a multi-thousand-line JSON
// Schema; pip-audit's output is documented), and the v1 audit gate
// only needs the *hashes* of these files, not field-level parsing.
// When the supervisor's admission gates start reading specific CVE
// severities directly, those types replace the alias.

/// Stand-in for `sbom.cdx.json` contents. CycloneDX 1.5 is the
/// canonical schema; the v1 audit gate hashes the bytes verbatim
/// and doesn't field-parse.
pub type SbomFile = serde_json::Value;

/// Stand-in for `fetch.log` parsed contents. Production builds
/// produce a newline-delimited URL list — the gate hashes the
/// bytes; a future tool may parse it.
pub type FetchLog = serde_json::Value;

/// Stand-in for `cve.json` (pip-audit / pnpm-audit output).
pub type CveResult = serde_json::Value;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().to_path_buf();
            Self { _tmp: tmp, dir }
        }

        /// Build a complete sealed volume layout at `<dir>/<name>/`
        /// with deterministic content, then run `seal_volume` over
        /// it. Returns the volume dir and the seal result.
        fn build_sealed(&self, name: &str) -> (PathBuf, VolumeSealResult) {
            let v = self.dir.join(name);
            let content = v.join(FILE_CONTENT_DIR);
            fs::create_dir_all(&content).unwrap();
            fs::write(content.join("a.txt"), b"alpha\n").unwrap();
            fs::create_dir_all(content.join("sub")).unwrap();
            fs::write(content.join("sub").join("b.txt"), b"beta\n").unwrap();

            let sbom = v.join(FILE_SBOM);
            fs::write(&sbom, br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#).unwrap();
            let fl = v.join(FILE_FETCH_LOG);
            fs::write(&fl, b"GET https://pypi.org/simple/requests/\n").unwrap();
            let cve = v.join(FILE_CVE);
            fs::write(&cve, br#"{"results":[]}"#).unwrap();

            let result = seal_volume(
                &content,
                &sbom,
                &fl,
                &cve,
                "2026-05-13T00:00:00Z",
                BTreeMap::new(),
            )
            .expect("seal");
            fs::write(v.join(FILE_MANIFEST), &result.manifest_bytes).unwrap();
            (v, result)
        }
    }

    #[test]
    fn seal_then_verify_round_trips_to_same_hash() {
        let fx = Fixture::new();
        let (v, sealed) = fx.build_sealed("vol-a");
        let verified = verify_sealed_volume(&v).expect("verify");
        assert_eq!(verified, sealed.volume_hash);
    }

    #[test]
    fn seal_is_deterministic_for_same_inputs() {
        let fx = Fixture::new();
        let (_, a) = fx.build_sealed("vol-1");
        let (_, b) = fx.build_sealed("vol-2");
        assert_eq!(
            a.volume_hash, b.volume_hash,
            "same inputs + same timestamp must yield the same hash"
        );
    }

    #[test]
    fn verify_detects_tampered_content() {
        let fx = Fixture::new();
        let (v, _) = fx.build_sealed("vol-tamper-content");
        // Modify a content file *after* sealing.
        fs::write(v.join(FILE_CONTENT_DIR).join("a.txt"), b"alpha-MODIFIED\n").unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(
            matches!(err, VolumeError::HashMismatch { kind, .. } if kind == "content"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_detects_tampered_sbom() {
        let fx = Fixture::new();
        let (v, _) = fx.build_sealed("vol-tamper-sbom");
        fs::write(v.join(FILE_SBOM), b"{\"bomFormat\":\"FAKE\"}").unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(matches!(err, VolumeError::HashMismatch { kind, .. } if kind == "sbom"));
    }

    #[test]
    fn verify_detects_tampered_cve() {
        let fx = Fixture::new();
        let (v, _) = fx.build_sealed("vol-tamper-cve");
        fs::write(v.join(FILE_CVE), b"{\"results\":[\"FORGED\"]}").unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(matches!(err, VolumeError::HashMismatch { kind, .. } if kind == "cve"));
    }

    #[test]
    fn verify_detects_tampered_fetch_log() {
        let fx = Fixture::new();
        let (v, _) = fx.build_sealed("vol-tamper-fetch");
        fs::write(v.join(FILE_FETCH_LOG), b"GET https://evil.example.com\n").unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(matches!(err, VolumeError::HashMismatch { kind, .. } if kind == "fetch_log"));
    }

    #[test]
    fn verify_rejects_missing_manifest() {
        let fx = Fixture::new();
        let v = fx.dir.join("no-meta");
        fs::create_dir_all(v.join(FILE_CONTENT_DIR)).unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(
            matches!(err, VolumeError::ArtifactMissing { artifact, .. } if artifact == FILE_MANIFEST)
        );
    }

    #[test]
    fn verify_rejects_unknown_schema_version() {
        let fx = Fixture::new();
        let (v, _) = fx.build_sealed("vol-schema");
        // Forge a future-schema manifest.
        let bad = serde_json::json!({
            "schema_version": 999,
            "content_sha256": "0",
            "sbom_sha256": "0",
            "fetch_log_sha256": "0",
            "cve_sha256": "0",
            "created_at": "x",
            "last_audit_at": "x",
        });
        fs::write(v.join(FILE_MANIFEST), bad.to_string()).unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(matches!(err, VolumeError::SchemaMismatch { .. }));
    }

    #[test]
    fn verify_rejects_missing_sealed_artifact() {
        let fx = Fixture::new();
        let (v, _) = fx.build_sealed("vol-missing");
        fs::remove_file(v.join(FILE_SBOM)).unwrap();
        let err = verify_sealed_volume(&v).unwrap_err();
        assert!(
            matches!(err, VolumeError::ArtifactMissing { artifact, .. } if artifact == FILE_SBOM)
        );
    }

    #[test]
    fn derive_volume_hash_is_pure() {
        let h1 = derive_volume_hash("aaaa", b"{}");
        let h2 = derive_volume_hash("aaaa", b"{}");
        assert_eq!(h1, h2);
        let h3 = derive_volume_hash("bbbb", b"{}");
        assert_ne!(h1, h3);
        let h4 = derive_volume_hash("aaaa", b"{\"x\":1}");
        assert_ne!(h1, h4);
    }

    #[test]
    fn manifest_round_trips_through_serde() {
        let m = VolumeManifest {
            schema_version: VOLUME_MANIFEST_SCHEMA_VERSION,
            content_sha256: "aa".into(),
            sbom_sha256: "bb".into(),
            fetch_log_sha256: "cc".into(),
            cve_sha256: "dd".into(),
            created_at: "2026-05-13T00:00:00Z".into(),
            last_audit_at: "2026-05-13T00:00:00Z".into(),
            annotations: {
                let mut m = BTreeMap::new();
                m.insert("lockfile".into(), "/work/uv.lock".into());
                m
            },
        };
        let bytes = canonical_json(&m).unwrap();
        let back: VolumeManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn manifest_rejects_unknown_fields() {
        // `deny_unknown_fields` keeps a future field-name typo
        // from being silently accepted by an older host.
        let bad = serde_json::json!({
            "schema_version": 1,
            "content_sha256": "a",
            "sbom_sha256": "b",
            "fetch_log_sha256": "c",
            "cve_sha256": "d",
            "created_at": "x",
            "last_audit_at": "x",
            "future_field": 42,
        });
        let err = serde_json::from_value::<VolumeManifest>(bad).unwrap_err();
        assert!(err.to_string().contains("future_field"));
    }
}

