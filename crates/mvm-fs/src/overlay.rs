//! Runtime-overlay cache resolution: pick the verity-sealed overlay artifact
//! set for one `(version, arch)` out of the local cache and validate it.
//!
//! Every microVM mvm boots — Nix-built rootfs and OCI-pulled rootfs alike —
//! attaches a second read-only virtio-blk device carrying the guest agent +
//! seccomp shim + runner + per-language SDK runtime libraries. This module is
//! the resolve half: given a cache root + an expected mvmctl version + an
//! arch directory name, it picks the right ext4 + verity sidecar + roothash
//! from the cache and returns paths the backend can attach. Building,
//! downloading, and installing overlay artifacts is acquisition policy and
//! lives in the build crate.
//!
//! ## Cache layout
//!
//! ```text
//! <cache_root>/
//!   runtime-overlay/
//!     <semver>/                # e.g. "0.14.0"
//!       <arch>/                # "aarch64" or "x86_64"
//!         overlay.ext4
//!         overlay.verity
//!         overlay.roothash     # text file, 64 lowercase hex chars + newline
//!         VERSION              # text file, semver of the producing mvmctl
//!         checksums-sha256.txt # sha256sum-format manifest over the four files
//! ```
//!
//! The installer additionally drops `SOURCE_FINGERPRINT` + `BUILD_EPOCH`
//! marker files next to the artifact for source-checkout freshness tracking;
//! the resolver ignores them, but [`RuntimeOverlayLayout`] names their paths
//! so producers and freshness checks agree on where they live.
//!
//! The `VERSION` file is what the resolver checks against the caller's
//! expected version. Mismatched versions are an admission-time error (the
//! agent's vsock protocol is versioned; a stale overlay paired with a newer
//! host would silently misbehave).
//!
//! Arch is passed as the cache directory-name segment (`"aarch64"` /
//! `"x86_64"`) rather than a typed enum so this crate stays free of
//! higher-layer type dependencies; callers with a typed arch convert via its
//! canonical `Display` form.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// File name of the per-artifact sha256sum-format checksum manifest.
pub const CHECKSUM_MANIFEST_FILE: &str = "checksums-sha256.txt";

/// Best-effort cache of a completed full integrity + payload validation.
///
/// The stamp is never accepted on its own: every canonical file and the
/// checksum manifest must retain the exact filesystem identity captured after
/// validation. A mismatch or unreadable stamp falls back to full validation.
const VALIDATION_STAMP_FILE: &str = ".validated-v1.json";
const VALIDATION_STAMP_SCHEMA_VERSION: u32 = 1;
const CANONICAL_OVERLAY_FILES: [&str; 4] = [
    "overlay.ext4",
    "overlay.verity",
    "overlay.roothash",
    "VERSION",
];

/// File name of the source-checkout fingerprint marker a local build drops
/// next to the artifact (freshness key for source-built overlays).
pub const LOCAL_SOURCE_FINGERPRINT_FILE: &str = "SOURCE_FINGERPRINT";

/// File name of the host-side build-epoch marker a local build drops next to
/// the artifact (invalidates source-built overlays across packaging changes).
pub const LOCAL_BUILD_EPOCH_FILE: &str = "BUILD_EPOCH";

/// Guest-absolute paths every overlay ext4 payload must carry. The overlay is
/// the single source of guest runtime binaries, so a missing entry means a
/// boot that silently strands the agent — fail at resolve time instead.
///
/// Public because every fixture that builds "a valid overlay" has to agree with
/// it, and each hand-written copy is one an added entry silently invalidates —
/// four of them existed, and adding `/forward-proxy` broke three.
pub const REQUIRED_OVERLAY_GUEST_PATHS: &[&str] = &[
    "/agent",
    "/netinit",
    "/seccomp-apply",
    "/runner",
    "/egress-client",
    // The whole of a secret-bearing workload's egress: that launch starts no
    // vsock egress client, so an overlay without this strands it as completely
    // as one without the agent.
    "/forward-proxy",
    "/addon-dns",
    "/exit-report",
    "/VERSION",
];

/// Failure resolving or validating a cached runtime-overlay artifact.
#[derive(Debug, Error)]
pub enum OverlayError {
    /// One of the files the cache layout requires (`overlay.ext4`,
    /// `overlay.verity`, `overlay.roothash`, `VERSION`, and — for cache
    /// resolution — `checksums-sha256.txt`) is missing under the expected
    /// path.
    #[error(
        "runtime overlay artifact incomplete at {artifact_dir:?}: \
         missing {missing:?} (mvmctl version {version}, arch {arch})"
    )]
    ArtifactIncomplete {
        /// Directory the artifact set was expected in.
        artifact_dir: PathBuf,
        /// The specific file that was absent.
        missing: PathBuf,
        /// Version label of the artifact (or `<unreadable>`).
        version: String,
        /// Arch directory-name segment of the artifact.
        arch: String,
    },

    /// The cache's `VERSION` file content doesn't match the version the
    /// caller expected. Always fail closed — a version mismatch means the
    /// overlay's agent protocol could disagree with the host's.
    #[error(
        "runtime overlay version mismatch: expected {expected:?}, \
         cache holds {found:?}"
    )]
    VersionMismatch {
        /// Version the resolver was configured to require.
        expected: String,
        /// Version the cached `VERSION` file actually holds.
        found: String,
    },

    /// The `overlay.roothash` text didn't parse as 64 lowercase hex chars
    /// (sha256). Always fail closed — a malformed roothash means the kernel
    /// cmdline can't be set correctly and the verity-init would panic at
    /// boot.
    #[error("runtime overlay roothash malformed: {reason}")]
    InvalidRoothash {
        /// Human-readable description of the malformation.
        reason: String,
    },

    /// The `VERSION` file is empty, non-UTF-8, or otherwise unreadable.
    #[error("runtime overlay VERSION file invalid: {reason}")]
    InvalidVersionFile {
        /// Human-readable description of the problem.
        reason: String,
    },

    /// The ext4 payload itself is missing a required runtime binary.
    #[error(
        "runtime overlay payload invalid at {overlay_ext4:?}: \
         missing required guest path {missing_path}"
    )]
    PayloadIncomplete {
        /// The overlay image that was inspected.
        overlay_ext4: PathBuf,
        /// The guest-absolute path that was absent.
        missing_path: String,
    },

    /// The ext4 payload could not be opened or inspected.
    #[error("runtime overlay payload invalid at {overlay_ext4:?}: {reason}")]
    PayloadUnreadable {
        /// The overlay image that was inspected.
        overlay_ext4: PathBuf,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The checksum manifest lacked an entry for one of the canonical
    /// runtime-overlay files. Always fail closed — both cached and freshly
    /// downloaded/extracted overlays must prove per-file integrity before
    /// attach/install.
    #[error(
        "runtime overlay checksum manifest at {manifest_path:?} did not \
         list an entry for {name}"
    )]
    ChecksumManifestMissing {
        /// The manifest that was consulted.
        manifest_path: PathBuf,
        /// Canonical file name the manifest failed to cover.
        name: String,
    },

    /// One of the runtime-overlay files drifted from the checksum recorded in
    /// the manifest. Refuse to attach/install the artifact.
    #[error(
        "runtime overlay integrity mismatch for {name}: expected sha256 \
         {expected}, computed {actual}"
    )]
    ChecksumManifestMismatch {
        /// Canonical file name that drifted.
        name: String,
        /// Digest the manifest committed to.
        expected: String,
        /// Digest computed from the on-disk bytes.
        actual: String,
    },

    /// Underlying io failure during a file read.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// File-system layout for one resolved overlay artifact. The resolver builds
/// this up before checking existence so callers can compute paths without
/// actually invoking the resolver (e.g. for testing or for telling a download
/// orchestrator where to land a fetched artifact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayLayout {
    /// Directory holding the whole artifact set.
    pub artifact_dir: PathBuf,
    /// The overlay ext4 image.
    pub overlay_ext4: PathBuf,
    /// The dm-verity hash-tree sidecar.
    pub sidecar: PathBuf,
    /// The roothash text file.
    pub roothash_file: PathBuf,
    /// The producing-mvmctl `VERSION` text file.
    pub version_file: PathBuf,
    /// The sha256sum-format checksum manifest over the four files above.
    pub checksum_manifest_file: PathBuf,
    /// Source-checkout fingerprint marker written by local builds.
    pub local_source_fingerprint_file: PathBuf,
    /// Host-side build-epoch marker written by local builds.
    pub local_build_epoch_file: PathBuf,
    /// Arch directory-name segment (`"aarch64"` / `"x86_64"`).
    pub arch: String,
    /// Version segment of the layout.
    pub version: String,
}

impl RuntimeOverlayLayout {
    /// Compute the canonical layout for `(version, arch)` under `cache_root`,
    /// where `arch` is the cache directory-name segment. Performs no I/O —
    /// pure path construction.
    pub fn under(cache_root: &Path, version: &str, arch: &str) -> Self {
        let artifact_dir = cache_root.join("runtime-overlay").join(version).join(arch);
        Self {
            overlay_ext4: artifact_dir.join("overlay.ext4"),
            sidecar: artifact_dir.join("overlay.verity"),
            roothash_file: artifact_dir.join("overlay.roothash"),
            version_file: artifact_dir.join("VERSION"),
            checksum_manifest_file: artifact_dir.join(CHECKSUM_MANIFEST_FILE),
            local_source_fingerprint_file: artifact_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE),
            local_build_epoch_file: artifact_dir.join(LOCAL_BUILD_EPOCH_FILE),
            artifact_dir,
            arch: arch.to_string(),
            version: version.to_string(),
        }
    }
}

/// Resolved overlay artifact, ready to hand to a microVM backend as the
/// second virtio-blk drive + sidecar + cmdline arg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayArtifact {
    /// The overlay ext4 image.
    pub overlay_ext4: PathBuf,
    /// The dm-verity hash-tree sidecar.
    pub sidecar: PathBuf,
    /// The roothash text file the `roothash` value was read from.
    pub roothash_file: PathBuf,
    /// Root hash as 64 lowercase hex chars (sha256). What the verity-init
    /// reads from the kernel cmdline as `mvm.runtime_roothash=<hex>`.
    pub roothash: String,
    /// Arch directory-name segment (`"aarch64"` / `"x86_64"`).
    pub arch: String,
    /// Version read from the artifact's `VERSION` file.
    pub version: String,
}

/// Release-side artifact names for one arch. Pure data — keeps naming checks
/// decoupled from the download network path that consumes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOverlayArtifactNames {
    /// The per-arch release tarball name.
    pub archive: String,
    /// The tarball's sha256 checksum sidecar name.
    pub archive_checksum: String,
}

impl RuntimeOverlayArtifactNames {
    /// Compute the per-arch release filenames a published release carries,
    /// with `arch` as the directory-name segment. The `runtime-overlay-`
    /// prefix and arch suffix scheme is what keeps aarch64 and x86_64 from
    /// colliding in the combined release-asset pool — they get renamed back
    /// to canonical names (`overlay.{ext4,verity,roothash}`, `VERSION`) when
    /// installed into the cache.
    pub fn for_arch(arch: &str) -> Self {
        Self {
            archive: format!("runtime-overlay-{arch}.tar.gz"),
            archive_checksum: format!("runtime-overlay-{arch}.tar.gz.sha256"),
        }
    }
}

/// Resolver for the runtime overlay cache. Stateless configuration: cache
/// root + expected mvmctl version. The `resolve` method does the actual
/// cache probe.
pub struct RuntimeOverlayResolver {
    cache_root: PathBuf,
    expected_version: String,
}

impl RuntimeOverlayResolver {
    /// Create a resolver against `cache_root` (typically `~/.mvm/cache/`)
    /// that expects overlays tagged with `expected_version` (typically the
    /// running binary's crate version).
    pub fn new(cache_root: PathBuf, expected_version: String) -> Self {
        Self {
            cache_root,
            expected_version,
        }
    }

    /// Cache root this resolver probes.
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// The mvmctl version cached overlays must match.
    pub fn expected_version(&self) -> &str {
        &self.expected_version
    }

    /// Compute the cache layout for `arch` (the cache directory-name
    /// segment) without doing any I/O. Useful for callers that need to know
    /// where an artifact *would* live (e.g. download orchestrators).
    pub fn layout(&self, arch: &str) -> RuntimeOverlayLayout {
        RuntimeOverlayLayout::under(&self.cache_root, &self.expected_version, arch)
    }

    /// Find the overlay artifact in cache. Validates:
    ///
    /// 1. All required files exist (the four canonical files plus the
    ///    checksum manifest).
    /// 2. `VERSION` file matches the resolver's expected version.
    /// 3. Every file matches its manifest checksum.
    /// 4. `overlay.roothash` parses as 64 lowercase hex chars.
    /// 5. The ext4 payload carries every required guest binary.
    ///
    /// Returns a [`RuntimeOverlayArtifact`] on success. Fails closed on
    /// every other path — no partial / degraded fallback: the agent must
    /// come from a trusted overlay or the verified-boot claim is silently
    /// weakened. This is a pure local cache read; populating the cache
    /// (build, download, or seeding from another cache) is the caller's
    /// concern.
    pub fn resolve(&self, arch: &str) -> Result<RuntimeOverlayArtifact, OverlayError> {
        let layout = self.layout(arch);
        for required in [
            &layout.overlay_ext4,
            &layout.sidecar,
            &layout.roothash_file,
            &layout.version_file,
            &layout.checksum_manifest_file,
        ] {
            check_exists(required, &layout.artifact_dir, &self.expected_version, arch)?;
        }

        let version = read_version_file(&layout.version_file)?;
        if version != self.expected_version {
            return Err(OverlayError::VersionMismatch {
                expected: self.expected_version.clone(),
                found: version,
            });
        }

        let validation_cached = validation_stamp_matches(&layout.artifact_dir);
        if !validation_cached {
            verify_overlay_dir_integrity(&layout.artifact_dir)?;
        }
        let roothash = read_roothash_file(&layout.roothash_file)?;
        if !validation_cached {
            validate_overlay_payload(&layout.overlay_ext4)?;
            write_validation_stamp(&layout.artifact_dir);
        }

        Ok(RuntimeOverlayArtifact {
            overlay_ext4: layout.overlay_ext4,
            sidecar: layout.sidecar,
            roothash_file: layout.roothash_file,
            roothash,
            arch: arch.to_string(),
            version,
        })
    }
}

/// Read and validate a built/downloaded overlay artifact from `dir`, where
/// the canonical four files live side-by-side (`overlay.ext4`,
/// `overlay.verity`, `overlay.roothash`, `VERSION`). `arch` is the cache
/// directory-name segment recorded on the returned artifact.
pub fn read_overlay_artifact_from_dir(
    dir: &Path,
    arch: &str,
) -> Result<RuntimeOverlayArtifact, OverlayError> {
    let overlay_ext4 = dir.join("overlay.ext4");
    let sidecar = dir.join("overlay.verity");
    let roothash_file = dir.join("overlay.roothash");
    let version_file = dir.join("VERSION");
    for required in [&overlay_ext4, &sidecar, &roothash_file, &version_file] {
        if !required.is_file() {
            return Err(OverlayError::ArtifactIncomplete {
                artifact_dir: dir.to_path_buf(),
                missing: required.clone(),
                version: read_version_file(&version_file)
                    .unwrap_or_else(|_| "<unreadable>".to_string()),
                arch: arch.to_string(),
            });
        }
    }
    let version = read_version_file(&version_file)?;
    let roothash = read_roothash_file(&roothash_file)?;
    Ok(RuntimeOverlayArtifact {
        overlay_ext4,
        sidecar,
        roothash_file,
        roothash,
        arch: arch.to_string(),
        version,
    })
}

/// Verify the four canonical overlay files in `dir` against the
/// [`CHECKSUM_MANIFEST_FILE`] manifest that sits alongside them. Used both
/// for cached artifacts (via [`RuntimeOverlayResolver::resolve`]) and for
/// freshly extracted download stages, so the two paths prove per-file
/// integrity identically.
pub fn verify_overlay_dir_integrity(dir: &Path) -> Result<(), OverlayError> {
    let manifest_path = dir.join(CHECKSUM_MANIFEST_FILE);
    let body = std::fs::read_to_string(&manifest_path)?;
    let expected = parse_checksums_manifest(&body);
    for name in CANONICAL_OVERLAY_FILES {
        let Some(expected_hash) = expected.get(name) else {
            return Err(OverlayError::ChecksumManifestMissing {
                manifest_path: manifest_path.clone(),
                name: name.to_string(),
            });
        };
        let actual = compute_file_sha256(&dir.join(name))?;
        if actual != *expected_hash {
            return Err(OverlayError::ChecksumManifestMismatch {
                name: name.to_string(),
                expected: expected_hash.clone(),
                actual,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationStamp {
    schema_version: u32,
    checksum_manifest_sha256: String,
    files: Vec<FileFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFingerprint {
    name: String,
    len: u64,
    modified_secs: u64,
    modified_nanos: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_dev: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_inode: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_ctime_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unix_ctime_nanos: Option<i64>,
}

fn validation_stamp_path(dir: &Path) -> PathBuf {
    dir.join(VALIDATION_STAMP_FILE)
}

/// Accept a prior validation only while every input retains the filesystem
/// identity it had after the full checksum and payload scan.
///
/// On Unix, device/inode/change-time make a same-size rewrite or atomic file
/// replacement invalidate the stamp even if an actor restores the mtime. The
/// manifest digest additionally makes editing its expected hashes visible.
/// This is a performance cache, not a new trust root: acquisition signature
/// verification and dm-verity remain the authenticity and guest-read
/// enforcement boundaries.
fn validation_stamp_matches(dir: &Path) -> bool {
    let body = match std::fs::read(validation_stamp_path(dir)) {
        Ok(body) => body,
        Err(_) => return false,
    };
    let stamp: ValidationStamp = match serde_json::from_slice(&body) {
        Ok(stamp) => stamp,
        Err(_) => return false,
    };
    if stamp.schema_version != VALIDATION_STAMP_SCHEMA_VERSION {
        return false;
    }
    let manifest_path = dir.join(CHECKSUM_MANIFEST_FILE);
    if compute_file_sha256(&manifest_path).ok().as_deref()
        != Some(stamp.checksum_manifest_sha256.as_str())
    {
        return false;
    }
    validation_fingerprints(dir).is_some_and(|fingerprints| fingerprints == stamp.files)
}

fn validation_fingerprints(dir: &Path) -> Option<Vec<FileFingerprint>> {
    CANONICAL_OVERLAY_FILES
        .into_iter()
        .chain(std::iter::once(CHECKSUM_MANIFEST_FILE))
        .map(|name| file_fingerprint(dir, name))
        .collect()
}

fn file_fingerprint(dir: &Path, name: &str) -> Option<FileFingerprint> {
    let metadata = std::fs::metadata(dir.join(name)).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    #[cfg(unix)]
    let (unix_dev, unix_inode, unix_ctime_secs, unix_ctime_nanos) = {
        use std::os::unix::fs::MetadataExt as _;
        (
            Some(metadata.dev()),
            Some(metadata.ino()),
            Some(metadata.ctime()),
            Some(metadata.ctime_nsec()),
        )
    };
    #[cfg(not(unix))]
    let (unix_dev, unix_inode, unix_ctime_secs, unix_ctime_nanos) = (None, None, None, None);
    Some(FileFingerprint {
        name: name.to_string(),
        len: metadata.len(),
        modified_secs: modified.as_secs(),
        modified_nanos: modified.subsec_nanos(),
        unix_dev,
        unix_inode,
        unix_ctime_secs,
        unix_ctime_nanos,
    })
}

/// Publish a reconstructible validation stamp without adding a durability
/// barrier to cache resolution. A crash can lose the stamp, in which case the
/// next resolve simply performs the full validation again.
fn write_validation_stamp(dir: &Path) {
    let Some(files) = validation_fingerprints(dir) else {
        return;
    };
    let Ok(checksum_manifest_sha256) = compute_file_sha256(&dir.join(CHECKSUM_MANIFEST_FILE))
    else {
        return;
    };
    let stamp = ValidationStamp {
        schema_version: VALIDATION_STAMP_SCHEMA_VERSION,
        checksum_manifest_sha256,
        files,
    };
    let Ok(body) = serde_json::to_vec_pretty(&stamp) else {
        return;
    };
    let path = validation_stamp_path(dir);
    let staged = dir.join(format!(
        ".{VALIDATION_STAMP_FILE}.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    ));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .and_then(|mut file| file.write_all(&body));
    if written.is_ok() {
        let _ = std::fs::rename(&staged, &path);
    }
    let _ = std::fs::remove_file(staged);
}

/// Read an `overlay.roothash` text file and validate it parses to 64
/// lowercase hex chars (sha256) — the value the verity-init consumes from
/// the kernel cmdline. Surrounding whitespace/newline is tolerated.
pub fn read_roothash_file(path: &Path) -> Result<String, OverlayError> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    validate_roothash(trimmed)?;
    Ok(trimmed.to_string())
}

/// Check the overlay ext4 payload carries every required guest binary at its
/// canonical absolute path. Fails closed when the image can't be opened.
pub fn validate_overlay_payload(overlay_ext4: &Path) -> Result<(), OverlayError> {
    let fs = ext4_view::Ext4::load_from_path(overlay_ext4).map_err(|e| {
        OverlayError::PayloadUnreadable {
            overlay_ext4: overlay_ext4.to_path_buf(),
            reason: format!("load ext4 image: {e}"),
        }
    })?;
    for required in REQUIRED_OVERLAY_GUEST_PATHS {
        let present = fs
            .exists(*required)
            .map_err(|e| OverlayError::PayloadUnreadable {
                overlay_ext4: overlay_ext4.to_path_buf(),
                reason: format!("lookup {required}: {e}"),
            })?;
        if !present {
            return Err(OverlayError::PayloadIncomplete {
                overlay_ext4: overlay_ext4.to_path_buf(),
                missing_path: (*required).to_string(),
            });
        }
    }
    Ok(())
}

/// Parse a `sha256sum`-format manifest (`<64-hex>  <name>`) into a
/// `name -> lowercase-hex-digest` map. Pure function so unit tests exercise
/// every corner (CRLF, leading `*` for binary mode, blank lines) without
/// touching disk or network.
pub fn parse_checksums_manifest(body: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in body.lines() {
        let mut iter = line.splitn(2, char::is_whitespace);
        let Some(hash) = iter.next() else { continue };
        let Some(rest) = iter.next() else { continue };
        let name = rest.trim().trim_start_matches('*').to_string();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            map.insert(name, hash.to_ascii_lowercase());
        }
    }
    map
}

/// Stream `path` through SHA-256, returning the lowercase hex digest.
pub fn compute_file_sha256(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn check_exists(
    path: &Path,
    artifact_dir: &Path,
    version: &str,
    arch: &str,
) -> Result<(), OverlayError> {
    if !path.is_file() {
        return Err(OverlayError::ArtifactIncomplete {
            artifact_dir: artifact_dir.to_path_buf(),
            missing: path.to_path_buf(),
            version: version.to_string(),
            arch: arch.to_string(),
        });
    }
    Ok(())
}

fn read_version_file(path: &Path) -> Result<String, OverlayError> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(OverlayError::InvalidVersionFile {
            reason: "VERSION file is empty".to_string(),
        });
    }
    if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(OverlayError::InvalidVersionFile {
            reason: format!("VERSION file contains internal whitespace: {trimmed:?}"),
        });
    }
    Ok(trimmed)
}

fn validate_roothash(s: &str) -> Result<(), OverlayError> {
    if s.len() != 64 {
        return Err(OverlayError::InvalidRoothash {
            reason: format!("expected 64 hex chars (sha256), got {} chars", s.len()),
        });
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OverlayError::InvalidRoothash {
            reason: format!("expected lowercase hex; got {s:?}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext4::Node;
    use tempfile::TempDir;

    const FAKE_ROOTHASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn write_manifest(artifact_dir: &Path) {
        let mut body = String::new();
        for name in [
            "overlay.ext4",
            "overlay.verity",
            "overlay.roothash",
            "VERSION",
        ] {
            let digest = compute_file_sha256(&artifact_dir.join(name)).unwrap();
            body.push_str(&format!("{digest}  {name}\n"));
        }
        std::fs::write(artifact_dir.join(CHECKSUM_MANIFEST_FILE), body).unwrap();
    }

    fn make_cache(version: &str, arch: &str, with_files: &[(&str, &[u8])]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let artifact_dir = tmp.path().join("runtime-overlay").join(version).join(arch);
        std::fs::create_dir_all(&artifact_dir).unwrap();
        for (name, contents) in with_files {
            std::fs::write(artifact_dir.join(name), contents).unwrap();
        }
        let have_all_canonical_files = [
            "overlay.ext4",
            "overlay.verity",
            "overlay.roothash",
            "VERSION",
        ]
        .iter()
        .all(|name| artifact_dir.join(name).is_file());
        if have_all_canonical_files {
            write_manifest(&artifact_dir);
        }
        tmp
    }

    fn complete_cache(version: &str, arch: &str) -> TempDir {
        make_cache(
            version,
            arch,
            &[
                ("overlay.ext4", &valid_overlay_ext4_bytes()),
                ("overlay.verity", b"verity-sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", format!("{version}\n").as_bytes()),
            ],
        )
    }

    /// A payload carrying every path the validator requires.
    ///
    /// Derived from `REQUIRED_OVERLAY_GUEST_PATHS` rather than listed again, so
    /// adding a required entry cannot leave the fixture describing a payload
    /// the validator would reject — which would fail every unrelated test at
    /// once and name none of them the cause.
    fn valid_overlay_ext4_bytes() -> Vec<u8> {
        overlay_ext4_bytes_without(&[])
    }

    /// The same payload with `omitted` left out, for the rejection tests.
    fn overlay_ext4_bytes_without(omitted: &[&str]) -> Vec<u8> {
        let nodes: Vec<Node> = REQUIRED_OVERLAY_GUEST_PATHS
            .iter()
            .filter(|path| !omitted.contains(*path))
            .map(|path| Node::File {
                path: (*path).into(),
                // `VERSION` is data the resolver reads back, not a binary.
                mode: if *path == "/VERSION" { 0o444 } else { 0o555 },
                data: if *path == "/VERSION" {
                    b"0.14.0\n".to_vec()
                } else {
                    path.trim_start_matches('/').as_bytes().to_vec()
                },
                xattrs: Vec::new(),
            })
            .collect();
        crate::ext4::build_image(nodes).expect("build valid overlay ext4 fixture")
    }

    #[test]
    fn layout_under_uses_canonical_directory_layout() {
        let root = Path::new("/cache");
        let layout = RuntimeOverlayLayout::under(root, "0.14.0", "aarch64");
        assert_eq!(
            layout.artifact_dir,
            PathBuf::from("/cache/runtime-overlay/0.14.0/aarch64")
        );
        assert_eq!(
            layout.overlay_ext4,
            PathBuf::from("/cache/runtime-overlay/0.14.0/aarch64/overlay.ext4")
        );
        assert_eq!(
            layout.sidecar,
            PathBuf::from("/cache/runtime-overlay/0.14.0/aarch64/overlay.verity")
        );
        assert_eq!(
            layout.roothash_file,
            PathBuf::from("/cache/runtime-overlay/0.14.0/aarch64/overlay.roothash")
        );
        assert_eq!(
            layout.version_file,
            PathBuf::from("/cache/runtime-overlay/0.14.0/aarch64/VERSION")
        );
        assert_eq!(
            layout.checksum_manifest_file,
            PathBuf::from("/cache/runtime-overlay/0.14.0/aarch64/checksums-sha256.txt")
        );
        assert_eq!(layout.arch, "aarch64");
        assert_eq!(layout.version, "0.14.0");
    }

    #[test]
    fn resolver_exposes_its_configuration() {
        let resolver = RuntimeOverlayResolver::new(PathBuf::from("/cache"), "0.14.0".to_string());
        assert_eq!(resolver.cache_root(), Path::new("/cache"));
        assert_eq!(resolver.expected_version(), "0.14.0");
    }

    #[test]
    fn resolve_returns_artifact_when_all_files_present_and_version_matches() {
        let cache = complete_cache("0.14.0", "aarch64");
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let artifact = resolver.resolve("aarch64").expect("resolve");

        assert_eq!(artifact.version, "0.14.0");
        assert_eq!(artifact.arch, "aarch64");
        assert_eq!(artifact.roothash, FAKE_ROOTHASH);
        assert!(artifact.overlay_ext4.ends_with("overlay.ext4"));
        assert!(artifact.sidecar.ends_with("overlay.verity"));
        assert!(artifact.roothash_file.ends_with("overlay.roothash"));
    }

    #[test]
    fn successful_full_validation_publishes_a_reconstructible_stamp() {
        let cache = complete_cache("0.14.0", "aarch64");
        let artifact_dir = cache.path().join("runtime-overlay/0.14.0/aarch64");
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());

        resolver
            .resolve("aarch64")
            .expect("first resolve validates");

        let stamp_path = validation_stamp_path(&artifact_dir);
        let stamp: ValidationStamp = serde_json::from_slice(
            &std::fs::read(&stamp_path).expect("validation stamp was published"),
        )
        .expect("validation stamp parses");
        assert_eq!(stamp.schema_version, VALIDATION_STAMP_SCHEMA_VERSION);
        assert_eq!(stamp.files.len(), CANONICAL_OVERLAY_FILES.len() + 1);
        assert!(validation_stamp_matches(&artifact_dir));
    }

    #[test]
    fn same_size_overlay_rewrite_invalidates_stamp_and_fails_closed() {
        let cache = complete_cache("0.14.0", "aarch64");
        let artifact_dir = cache.path().join("runtime-overlay/0.14.0/aarch64");
        let overlay = artifact_dir.join("overlay.ext4");
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        resolver
            .resolve("aarch64")
            .expect("first resolve validates");
        let mut bytes = std::fs::read(&overlay).expect("read overlay fixture");
        let last = bytes.last_mut().expect("overlay fixture is non-empty");
        *last ^= 0xff;
        std::fs::write(&overlay, bytes).expect("rewrite overlay at the same length");

        assert!(!validation_stamp_matches(&artifact_dir));
        let err = resolver
            .resolve("aarch64")
            .expect_err("changed bytes must force full validation and fail");
        assert!(
            matches!(
                err,
                OverlayError::ChecksumManifestMismatch { ref name, .. }
                    if name == "overlay.ext4"
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn corrupt_validation_stamp_falls_back_to_full_validation_and_repairs_it() {
        let cache = complete_cache("0.14.0", "aarch64");
        let artifact_dir = cache.path().join("runtime-overlay/0.14.0/aarch64");
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        resolver
            .resolve("aarch64")
            .expect("first resolve validates");
        std::fs::write(validation_stamp_path(&artifact_dir), b"not-json")
            .expect("corrupt validation stamp");

        resolver
            .resolve("aarch64")
            .expect("corrupt cache metadata cannot reject a valid artifact");

        assert!(validation_stamp_matches(&artifact_dir));
    }

    #[test]
    fn resolve_fails_when_overlay_ext4_missing() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::ArtifactIncomplete { missing, .. } => {
                assert!(missing.ends_with("overlay.ext4"), "missing={missing:?}");
            }
            other => panic!("expected ArtifactIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn resolve_fails_when_checksum_manifest_missing() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", &valid_overlay_ext4_bytes()),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        std::fs::remove_file(
            cache
                .path()
                .join("runtime-overlay/0.14.0/aarch64")
                .join(CHECKSUM_MANIFEST_FILE),
        )
        .unwrap();
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::ArtifactIncomplete { missing, .. } => {
                assert!(
                    missing.ends_with(CHECKSUM_MANIFEST_FILE),
                    "missing={missing:?}"
                );
            }
            other => panic!("expected ArtifactIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn resolve_fails_when_sidecar_missing() {
        let cache = make_cache(
            "0.14.0",
            "x86_64",
            &[
                ("overlay.ext4", b"ext4"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("x86_64").unwrap_err();
        assert!(
            matches!(err, OverlayError::ArtifactIncomplete { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_fails_when_version_file_disagrees() {
        // The artifact lives at the EXPECTED version's path
        // (`0.14.0/<arch>/`), but the VERSION file *inside* it says
        // `0.13.99` — the case where someone manually hand-edited the file
        // or a release-pipeline bug shipped the wrong VERSION content
        // alongside otherwise-valid bytes. Fail closed.
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", b"ext4"),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.13.99\n"),
            ],
        );
        let resolver =
            RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".to_string());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::VersionMismatch { expected, found } => {
                assert_eq!(expected, "0.14.0");
                assert_eq!(found, "0.13.99");
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn resolve_fails_when_directory_path_for_expected_version_missing() {
        // The other half of the version-mismatch story: the cache only
        // contains a `0.13.99/` directory, the resolver expects `0.14.0/`.
        // Surfaces as `ArtifactIncomplete` (the *expected* artifact_dir
        // doesn't exist), not `VersionMismatch`. Distinct from the
        // VERSION-file disagreement above.
        let cache = complete_cache("0.13.99", "aarch64");
        let resolver =
            RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".to_string());
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(
            matches!(err, OverlayError::ArtifactIncomplete { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_fails_on_malformed_roothash_wrong_length() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", b"ext4"),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", b"abc\n"),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(
            matches!(err, OverlayError::InvalidRoothash { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_fails_on_malformed_roothash_uppercase() {
        let upper = "0123456789ABCDEF".repeat(4);
        assert_eq!(upper.len(), 64);
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", b"ext4"),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{upper}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(
            matches!(err, OverlayError::InvalidRoothash { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_fails_on_empty_version_file() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", b"ext4"),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b""),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(
            matches!(err, OverlayError::InvalidVersionFile { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_fails_on_whitespace_inside_version_file() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", b"ext4"),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14 0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        assert!(
            matches!(err, OverlayError::InvalidVersionFile { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn resolve_tolerates_roothash_without_trailing_newline() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", &valid_overlay_ext4_bytes()),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", FAKE_ROOTHASH.as_bytes()),
                ("VERSION", b"0.14.0"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let artifact = resolver.resolve("aarch64").expect("resolve");
        assert_eq!(artifact.roothash, FAKE_ROOTHASH);
    }

    #[test]
    fn resolve_rejects_overlay_payload_missing_egress_client() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                (
                    "overlay.ext4",
                    &overlay_ext4_bytes_without(&["/egress-client"]),
                ),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::PayloadIncomplete { missing_path, .. } => {
                assert_eq!(missing_path, "/egress-client");
            }
            other => panic!("expected PayloadIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejects_overlay_payload_missing_addon_dns() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                ("overlay.ext4", &overlay_ext4_bytes_without(&["/addon-dns"])),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::PayloadIncomplete { missing_path, .. } => {
                assert_eq!(missing_path, "/addon-dns");
            }
            other => panic!("expected PayloadIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejects_overlay_payload_missing_exit_report() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                (
                    "overlay.ext4",
                    &overlay_ext4_bytes_without(&["/exit-report"]),
                ),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::PayloadIncomplete { missing_path, .. } => {
                assert_eq!(missing_path, "/exit-report");
            }
            other => panic!("expected PayloadIncomplete, got {other:?}"),
        }
    }

    /// A secret-bearing workload starts no vsock egress client, so this is the
    /// whole of its egress: an overlay without it strands that workload as
    /// completely as one without the agent, and must be refused at resolve
    /// time rather than at its first request.
    #[test]
    fn resolve_rejects_overlay_payload_missing_forward_proxy() {
        let cache = make_cache(
            "0.14.0",
            "aarch64",
            &[
                (
                    "overlay.ext4",
                    &overlay_ext4_bytes_without(&["/forward-proxy"]),
                ),
                ("overlay.verity", b"sidecar"),
                ("overlay.roothash", format!("{FAKE_ROOTHASH}\n").as_bytes()),
                ("VERSION", b"0.14.0\n"),
            ],
        );
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        match resolver.resolve("aarch64").unwrap_err() {
            OverlayError::PayloadIncomplete { missing_path, .. } => {
                assert_eq!(missing_path, "/forward-proxy");
            }
            other => panic!("expected PayloadIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejects_cache_when_overlay_bytes_drift_from_checksum_manifest() {
        let cache = complete_cache("0.14.0", "aarch64");
        let artifact_dir = cache.path().join("runtime-overlay/0.14.0/aarch64");
        std::fs::write(artifact_dir.join("overlay.ext4"), b"tampered-overlay-bytes").unwrap();

        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::ChecksumManifestMismatch { name, .. } => {
                assert_eq!(name, "overlay.ext4");
            }
            other => panic!("expected ChecksumManifestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn resolve_rejects_cache_when_checksum_manifest_entry_missing() {
        let cache = complete_cache("0.14.0", "aarch64");
        let artifact_dir = cache.path().join("runtime-overlay/0.14.0/aarch64");
        let ext4_hash = compute_file_sha256(&artifact_dir.join("overlay.ext4")).unwrap();
        let sidecar_hash = compute_file_sha256(&artifact_dir.join("overlay.verity")).unwrap();
        std::fs::write(
            artifact_dir.join(CHECKSUM_MANIFEST_FILE),
            format!("{ext4_hash}  overlay.ext4\n{sidecar_hash}  overlay.verity\n"),
        )
        .unwrap();

        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let err = resolver.resolve("aarch64").unwrap_err();
        match err {
            OverlayError::ChecksumManifestMissing { name, .. } => {
                assert_eq!(name, "overlay.roothash");
            }
            other => panic!("expected ChecksumManifestMissing, got {other:?}"),
        }
    }

    #[test]
    fn layout_via_resolver_matches_under_helper() {
        let resolver = RuntimeOverlayResolver::new(PathBuf::from("/cache"), "0.14.0".to_string());
        let direct = RuntimeOverlayLayout::under(Path::new("/cache"), "0.14.0", "aarch64");
        let via_resolver = resolver.layout("aarch64");
        assert_eq!(direct, via_resolver);
    }

    #[test]
    fn resolve_works_for_x86_64_arch_too() {
        let cache = complete_cache("0.14.0", "x86_64");
        let resolver = RuntimeOverlayResolver::new(cache.path().to_path_buf(), "0.14.0".into());
        let artifact = resolver.resolve("x86_64").expect("resolve");
        assert_eq!(artifact.arch, "x86_64");
        assert!(artifact.overlay_ext4.to_string_lossy().contains("x86_64"));
    }

    /// Per-arch release filenames must match the names the release pipeline
    /// stages. A drift here is silently catastrophic: the host would 404 on
    /// every overlay fetch. Asserting the exact strings keeps both sides
    /// honest.
    #[test]
    fn artifact_names_match_release_naming_aarch64() {
        let names = RuntimeOverlayArtifactNames::for_arch("aarch64");
        assert_eq!(names.archive, "runtime-overlay-aarch64.tar.gz");
        assert_eq!(
            names.archive_checksum,
            "runtime-overlay-aarch64.tar.gz.sha256"
        );
    }

    #[test]
    fn artifact_names_match_release_naming_x86_64() {
        let names = RuntimeOverlayArtifactNames::for_arch("x86_64");
        assert_eq!(names.archive, "runtime-overlay-x86_64.tar.gz");
        assert_eq!(
            names.archive_checksum,
            "runtime-overlay-x86_64.tar.gz.sha256"
        );
    }

    #[test]
    fn parse_checksums_manifest_accepts_sha256sum_canonical() {
        let body = "\
0000000000000000000000000000000000000000000000000000000000000001  runtime-overlay-aarch64.tar.gz
0000000000000000000000000000000000000000000000000000000000000002  runtime-overlay-aarch64.tar.gz.sha256
";
        let map = parse_checksums_manifest(body);
        assert_eq!(
            map.get("runtime-overlay-aarch64.tar.gz").unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            map.get("runtime-overlay-aarch64.tar.gz.sha256").unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000002"
        );
    }

    #[test]
    fn parse_checksums_manifest_strips_binary_mode_star() {
        // `sha256sum -b` emits `<hash> *<file>` for binary mode. Both modes
        // must parse identically.
        let body = "0000000000000000000000000000000000000000000000000000000000000003 *runtime-overlay-x86_64.tar.gz";
        let map = parse_checksums_manifest(body);
        assert_eq!(
            map.get("runtime-overlay-x86_64.tar.gz").unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000003"
        );
    }

    #[test]
    fn parse_checksums_manifest_lowercases_hash() {
        // Upstream `sha256sum` always emits lowercase; some third-party
        // tools emit upper. Normalize so the lookup matches.
        let body = "ABCDEF0000000000000000000000000000000000000000000000000000000000  foo.ext4";
        let map = parse_checksums_manifest(body);
        assert_eq!(
            map.get("foo.ext4").unwrap(),
            "abcdef0000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn parse_checksums_manifest_skips_garbage_lines() {
        let body = "\
# comment line
not-a-hash  foo.ext4

0000000000000000000000000000000000000000000000000000000000000004  ok.ext4
short  bar.ext4
";
        let map = parse_checksums_manifest(body);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("ok.ext4"));
    }

    #[test]
    fn validate_roothash_accepts_canonical() {
        validate_roothash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("64 lowercase hex chars must validate");
    }

    #[test]
    fn validate_roothash_rejects_wrong_length() {
        let err = validate_roothash("abc").unwrap_err();
        assert!(
            matches!(err, OverlayError::InvalidRoothash { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn validate_roothash_rejects_uppercase() {
        let err =
            validate_roothash("ABCDEF0000000000000000000000000000000000000000000000000000000000")
                .unwrap_err();
        assert!(
            matches!(err, OverlayError::InvalidRoothash { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn read_roothash_file_trims_surrounding_whitespace() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("overlay.roothash");
        std::fs::write(&path, format!("{FAKE_ROOTHASH}\n")).unwrap();
        assert_eq!(read_roothash_file(&path).unwrap(), FAKE_ROOTHASH);
    }

    #[test]
    fn read_overlay_artifact_from_dir_reads_canonical_four_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("overlay.ext4"), valid_overlay_ext4_bytes()).unwrap();
        std::fs::write(tmp.path().join("overlay.verity"), b"verity").unwrap();
        std::fs::write(
            tmp.path().join("overlay.roothash"),
            format!("{FAKE_ROOTHASH}\n"),
        )
        .unwrap();
        std::fs::write(tmp.path().join("VERSION"), b"0.14.0\n").unwrap();

        let artifact = read_overlay_artifact_from_dir(tmp.path(), "aarch64").expect("read");
        assert_eq!(artifact.version, "0.14.0");
        assert_eq!(artifact.arch, "aarch64");
        assert_eq!(artifact.roothash, FAKE_ROOTHASH);
    }

    #[test]
    fn read_overlay_artifact_from_dir_fails_on_missing_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("overlay.ext4"), b"ext4").unwrap();
        let err = read_overlay_artifact_from_dir(tmp.path(), "aarch64").unwrap_err();
        assert!(
            matches!(err, OverlayError::ArtifactIncomplete { .. }),
            "{err:?}"
        );
    }
}
