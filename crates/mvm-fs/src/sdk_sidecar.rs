//! Resolver for the optional SDK sidecar image.
//!
//! The sidecar carries the glibc host-services cdylib the language SDKs
//! `dlopen`, plus the loader closure that cdylib needs. It is deliberately not
//! part of the base rootfs or the static-musl runtime overlay, so a workload
//! that never calls a host service never pays for the glibc closure.
//!
//! Layout mirrors the runtime overlay's cache, and the integrity discipline is
//! the same one: the artifact directory carries a `sha256sum`-format manifest
//! over every canonical file, a `VERSION` that must match the running binary,
//! and an ext4 payload whose required in-image path is proven present before an
//! attachment is offered. Every failure path returns `Err`; there is no
//! degraded attach, because a workload that was admitted to call a host service
//! and then finds no cdylib fails in-guest with an error it cannot act on.
//!
//! Verification reuses [`crate::overlay`]'s manifest parser and digest helper
//! rather than growing a second copy.

use mvm_contract::guest_libc::GuestLibc;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::overlay::{CHECKSUM_MANIFEST_FILE, compute_file_sha256, parse_checksums_manifest};

/// Cache subdirectory every sidecar artifact lives under.
pub const SDK_SIDECAR_CACHE_DIR: &str = "sdk-sidecar";

/// The sidecar's ext4 image file name inside its artifact directory.
pub const SDK_SIDECAR_IMAGE_FILE: &str = "sdk.ext4";

/// The producing-mvmctl version marker file name.
pub const SDK_SIDECAR_VERSION_FILE: &str = "VERSION";

/// Canonical files the manifest must cover, in verification order.
const MANIFEST_COVERED_FILES: [&str; 2] = [SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE];

/// In-image absolute paths the sidecar payload must carry. Kept in sync with
/// the guest lookup path the language SDKs default to
/// (`mvm_contract::plan::sdk_sidecar::SDK_SIDECAR_LIB_PATH`, mounted under
/// `SDK_SIDECAR_GUEST_PATH`); the unit test below pins them together.
const REQUIRED_SIDECAR_IMAGE_PATHS: &[&str] = &["/lib/libmvm_host_services.so"];

/// Failure resolving or validating a cached SDK-sidecar artifact.
///
/// Every variant names the artifact and the reason without echoing file
/// contents, so the message is safe to surface to an operator verbatim.
#[derive(Debug, Error)]
pub enum SdkSidecarError {
    /// A file the cache layout requires is absent.
    #[error(
        "SDK sidecar artifact incomplete at {artifact_dir:?}: missing {missing:?} \
         (mvmctl version {version}, arch {arch})"
    )]
    ArtifactIncomplete {
        /// Directory the artifact set was expected in.
        artifact_dir: PathBuf,
        /// The specific file that was absent.
        missing: PathBuf,
        /// Version the resolver required.
        version: String,
        /// Arch directory-name segment.
        arch: String,
    },

    /// The cached `VERSION` disagrees with the version the caller requires. A
    /// sidecar built by a different mvmctl may export a different C ABI than
    /// the SDKs in the matching runtime overlay expect, so this fails closed.
    #[error("SDK sidecar version mismatch: expected {expected:?}, cache holds {found:?}")]
    VersionMismatch {
        /// Version the resolver was configured to require.
        expected: String,
        /// Version the cached `VERSION` file holds.
        found: String,
    },

    /// The `VERSION` file is empty, non-UTF-8, or carries internal whitespace.
    #[error("SDK sidecar VERSION file invalid: {reason}")]
    InvalidVersionFile {
        /// Human-readable description of the problem.
        reason: String,
    },

    /// The manifest did not cover one of the canonical files.
    #[error("SDK sidecar checksum manifest at {manifest_path:?} did not list an entry for {name}")]
    ChecksumManifestMissing {
        /// The manifest that was consulted.
        manifest_path: PathBuf,
        /// Canonical file name the manifest failed to cover.
        name: String,
    },

    /// A canonical file drifted from the digest the manifest committed to.
    #[error(
        "SDK sidecar integrity mismatch for {name}: expected sha256 {expected}, computed {actual}"
    )]
    ChecksumManifestMismatch {
        /// Canonical file name that drifted.
        name: String,
        /// Digest the manifest committed to.
        expected: String,
        /// Digest computed from the on-disk bytes.
        actual: String,
    },

    /// The ext4 payload is missing a path the SDK needs.
    #[error("SDK sidecar payload invalid at {image:?}: missing required guest path {missing_path}")]
    PayloadIncomplete {
        /// The image that was inspected.
        image: PathBuf,
        /// The in-image absolute path that was absent.
        missing_path: String,
    },

    /// The ext4 payload could not be opened or inspected.
    #[error("SDK sidecar payload invalid at {image:?}: {reason}")]
    PayloadUnreadable {
        /// The image that was inspected.
        image: PathBuf,
        /// Human-readable description of the failure.
        reason: String,
    },

    /// Underlying io failure during a file read.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Filesystem layout for one sidecar artifact. Pure path construction — no I/O
/// — so a download orchestrator or a test can compute where an artifact would
/// live without invoking the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkSidecarLayout {
    /// Directory holding the whole artifact set.
    pub artifact_dir: PathBuf,
    /// The sidecar ext4 image.
    pub image: PathBuf,
    /// The producing-mvmctl `VERSION` text file.
    pub version_file: PathBuf,
    /// The `sha256sum`-format manifest over the files above.
    pub checksum_manifest_file: PathBuf,
    /// Arch directory-name segment (`"aarch64"` / `"x86_64"`).
    pub arch: String,
    /// Version segment of the layout.
    pub version: String,
    /// The libc the cached cdylib is built against.
    pub libc: GuestLibc,
}

impl SdkSidecarLayout {
    /// Compute the canonical layout for `(version, arch, libc)` under
    /// `cache_root`.
    ///
    /// The libc is a path segment rather than a field on one shared directory
    /// because the two variants are different artifacts, not two encodings of
    /// one: they carry different objects and different bundled libraries, and
    /// they verify against different manifests. Keying the directory on it is
    /// what stops the resolver handing back a sidecar the guest cannot
    /// `dlopen` — a failure that otherwise surfaces inside the guest as a
    /// relocation error naming a symbol the operator never asked for.
    #[must_use]
    pub fn under(cache_root: &Path, version: &str, arch: &str, libc: GuestLibc) -> Self {
        let artifact_dir = cache_root
            .join(SDK_SIDECAR_CACHE_DIR)
            .join(version)
            .join(arch)
            .join(libc.as_str());
        Self {
            image: artifact_dir.join(SDK_SIDECAR_IMAGE_FILE),
            version_file: artifact_dir.join(SDK_SIDECAR_VERSION_FILE),
            checksum_manifest_file: artifact_dir.join(CHECKSUM_MANIFEST_FILE),
            artifact_dir,
            arch: arch.to_string(),
            version: version.to_string(),
            libc,
        }
    }
}

/// Recover the libc a cached sidecar image was filed under.
///
/// [`SdkSidecarLayout::under`] writes the libc as the last directory segment,
/// and this reads it back. The pair is what lets a consumer holding only the
/// attached volume's path — admission, which sees a launch config rather than
/// the resolver that built it — say which variant it is looking at without a
/// second source of truth to drift from. A round-trip test pins them together.
///
/// Anything that is not one of the two written names is [`GuestLibc::Unknown`],
/// which every caller treats as "cannot say" rather than as a default.
impl SdkSidecarLayout {
    /// The libc segment of `image`, a path shaped like the one
    /// [`SdkSidecarLayout::under`] produces.
    #[must_use]
    pub fn libc_of_image_path(image: &Path) -> GuestLibc {
        let Some(segment) = image.parent().and_then(|d| d.file_name()) else {
            return GuestLibc::Unknown;
        };
        match segment.to_str() {
            Some(s) if s == GuestLibc::Glibc.as_str() => GuestLibc::Glibc,
            Some(s) if s == GuestLibc::Musl.as_str() => GuestLibc::Musl,
            _ => GuestLibc::Unknown,
        }
    }
}

/// A resolved, verified sidecar artifact ready to attach read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkSidecarArtifact {
    /// The sidecar ext4 image to attach.
    pub image: PathBuf,
    /// Lowercase-hex sha256 of `image`, as verified against the manifest. The
    /// launch path records this so an audit reader can tell which sidecar bytes
    /// a workload booted with.
    pub image_sha256: String,
    /// Arch directory-name segment.
    pub arch: String,
    /// Version read from the artifact's `VERSION` file.
    pub version: String,
    /// The libc this artifact's cdylib is built against.
    pub libc: GuestLibc,
}

/// Resolver for the sidecar cache: cache root plus the version cached artifacts
/// must match. Stateless configuration; [`Self::resolve`] does the probe.
#[derive(Debug, Clone)]
pub struct SdkSidecarResolver {
    cache_root: PathBuf,
    expected_version: String,
}

impl SdkSidecarResolver {
    /// Create a resolver against `cache_root` (typically `~/.mvm/cache/`) that
    /// requires sidecars tagged `expected_version` (typically the running
    /// binary's crate version).
    #[must_use]
    pub fn new(cache_root: PathBuf, expected_version: String) -> Self {
        Self {
            cache_root,
            expected_version,
        }
    }

    /// Cache root this resolver probes.
    #[must_use]
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// The mvmctl version cached sidecars must match.
    #[must_use]
    pub fn expected_version(&self) -> &str {
        &self.expected_version
    }

    /// Compute the cache layout for `(arch, libc)` without doing any I/O.
    #[must_use]
    pub fn layout(&self, arch: &str, libc: GuestLibc) -> SdkSidecarLayout {
        SdkSidecarLayout::under(&self.cache_root, &self.expected_version, arch, libc)
    }

    /// Find and verify the sidecar artifact in cache.
    ///
    /// Validates, in order: every required file exists; `VERSION` matches the
    /// expected version; every canonical file matches its manifest digest; the
    /// ext4 payload carries the cdylib the SDKs load. Fails closed on every
    /// other path — there is no partial or degraded attachment.
    pub fn resolve(
        &self,
        arch: &str,
        libc: GuestLibc,
    ) -> Result<SdkSidecarArtifact, SdkSidecarError> {
        let layout = self.layout(arch, libc);
        for required in [
            &layout.image,
            &layout.version_file,
            &layout.checksum_manifest_file,
        ] {
            if !required.is_file() {
                return Err(SdkSidecarError::ArtifactIncomplete {
                    artifact_dir: layout.artifact_dir.clone(),
                    missing: required.clone(),
                    version: self.expected_version.clone(),
                    arch: arch.to_string(),
                });
            }
        }

        let version = read_version_file(&layout.version_file)?;
        if version != self.expected_version {
            return Err(SdkSidecarError::VersionMismatch {
                expected: self.expected_version.clone(),
                found: version,
            });
        }

        let digests = verify_sidecar_dir_integrity(&layout.artifact_dir)?;
        validate_sidecar_payload(&layout.image)?;

        let image_sha256 = digests
            .into_iter()
            .find_map(|(name, digest)| (name == SDK_SIDECAR_IMAGE_FILE).then_some(digest))
            .ok_or_else(|| SdkSidecarError::ChecksumManifestMissing {
                manifest_path: layout.checksum_manifest_file.clone(),
                name: SDK_SIDECAR_IMAGE_FILE.to_string(),
            })?;

        Ok(SdkSidecarArtifact {
            image: layout.image,
            image_sha256,
            arch: arch.to_string(),
            version,
            libc,
        })
    }
}

/// Verify every canonical sidecar file in `dir` against the manifest beside
/// them, returning the verified `(name, digest)` pairs so a caller can record
/// the image digest without re-hashing.
pub fn verify_sidecar_dir_integrity(dir: &Path) -> Result<Vec<(String, String)>, SdkSidecarError> {
    let manifest_path = dir.join(CHECKSUM_MANIFEST_FILE);
    let body = std::fs::read_to_string(&manifest_path)?;
    let expected = parse_checksums_manifest(&body);
    let mut verified = Vec::with_capacity(MANIFEST_COVERED_FILES.len());
    for name in MANIFEST_COVERED_FILES {
        let Some(expected_hash) = expected.get(name) else {
            return Err(SdkSidecarError::ChecksumManifestMissing {
                manifest_path: manifest_path.clone(),
                name: name.to_string(),
            });
        };
        let actual = compute_file_sha256(&dir.join(name))?;
        if actual != *expected_hash {
            return Err(SdkSidecarError::ChecksumManifestMismatch {
                name: name.to_string(),
                expected: expected_hash.clone(),
                actual,
            });
        }
        verified.push((name.to_string(), actual));
    }
    Ok(verified)
}

/// Prove the sidecar ext4 payload carries every path the SDKs load from it.
/// Fails closed when the image can't be opened.
pub fn validate_sidecar_payload(image: &Path) -> Result<(), SdkSidecarError> {
    let fs =
        ext4_view::Ext4::load_from_path(image).map_err(|e| SdkSidecarError::PayloadUnreadable {
            image: image.to_path_buf(),
            reason: format!("load ext4 image: {e}"),
        })?;
    for required in REQUIRED_SIDECAR_IMAGE_PATHS {
        let present = fs
            .exists(*required)
            .map_err(|e| SdkSidecarError::PayloadUnreadable {
                image: image.to_path_buf(),
                reason: format!("lookup {required}: {e}"),
            })?;
        if !present {
            return Err(SdkSidecarError::PayloadIncomplete {
                image: image.to_path_buf(),
                missing_path: (*required).to_string(),
            });
        }
    }
    Ok(())
}

fn read_version_file(path: &Path) -> Result<String, SdkSidecarError> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(SdkSidecarError::InvalidVersionFile {
            reason: "VERSION file is empty".to_string(),
        });
    }
    if trimmed.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(SdkSidecarError::InvalidVersionFile {
            reason: format!("VERSION file contains internal whitespace: {trimmed:?}"),
        });
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ext4 image carrying `/lib/libmvm_host_services.so`, built with
    /// the in-repo pure-Rust writer so the fixture needs no `mkfs`.
    fn sidecar_image_bytes(with_lib: bool) -> Vec<u8> {
        use crate::ext4::Node;
        let payload = if with_lib {
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: b"\x7fELF-stub".to_vec(),
                xattrs: Vec::new(),
            }
        } else {
            Node::File {
                path: "/lib/README".into(),
                mode: 0o444,
                data: b"no cdylib here".to_vec(),
                xattrs: Vec::new(),
            }
        };
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
            },
            payload,
        ];
        crate::ext4::build_image(nodes).expect("build sidecar ext4 fixture")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    struct Fixture {
        _root: tempfile::TempDir,
        cache: PathBuf,
        version: String,
        arch: String,
    }

    impl Fixture {
        fn seed(version: &str, with_lib: bool, tamper_image: bool) -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let cache = root.path().join("cache");
            let arch = "aarch64".to_string();
            let layout = SdkSidecarLayout::under(&cache, version, &arch, GuestLibc::Musl);
            std::fs::create_dir_all(&layout.artifact_dir).expect("mkdir artifact dir");

            let image = sidecar_image_bytes(with_lib);
            let image_digest = sha256_hex(&image);
            let version_bytes = format!("{version}\n");
            let version_digest = sha256_hex(version_bytes.as_bytes());

            // The manifest is written over the pristine bytes; a tampered image
            // is written afterwards so the digest no longer matches.
            std::fs::write(&layout.image, &image).expect("write image");
            std::fs::write(&layout.version_file, &version_bytes).expect("write VERSION");
            std::fs::write(
                &layout.checksum_manifest_file,
                format!(
                    "{image_digest}  {SDK_SIDECAR_IMAGE_FILE}\n\
                     {version_digest}  {SDK_SIDECAR_VERSION_FILE}\n"
                ),
            )
            .expect("write manifest");
            if tamper_image {
                let mut tampered = image.clone();
                let last = tampered.len() - 1;
                tampered[last] ^= 0xff;
                std::fs::write(&layout.image, &tampered).expect("write tampered image");
            }

            Self {
                _root: root,
                cache,
                version: version.to_string(),
                arch,
            }
        }

        fn resolver(&self, expected_version: &str) -> SdkSidecarResolver {
            SdkSidecarResolver::new(self.cache.clone(), expected_version.to_string())
        }
    }

    #[test]
    fn layout_is_pure_path_construction() {
        let layout =
            SdkSidecarLayout::under(Path::new("/cache"), "9.9.9", "x86_64", GuestLibc::Musl);
        assert_eq!(
            layout.artifact_dir,
            Path::new("/cache/sdk-sidecar/9.9.9/x86_64/musl")
        );
        assert_eq!(layout.image.file_name().unwrap(), SDK_SIDECAR_IMAGE_FILE);
        assert_eq!(
            layout.checksum_manifest_file.file_name().unwrap(),
            CHECKSUM_MANIFEST_FILE
        );
        assert_eq!(layout.version, "9.9.9");
        assert_eq!(layout.arch, "x86_64");
        assert_eq!(layout.libc, GuestLibc::Musl);
    }

    /// The layout writes the libc into the path and `libc_of_image_path` reads
    /// it back. They are two halves of one encoding, so a change to either
    /// without the other has to fail here rather than in admission, where the
    /// symptom would be a correctly-built sidecar refused as `Unknown`.
    #[test]
    fn the_libc_segment_round_trips_through_the_image_path() {
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            let layout = SdkSidecarLayout::under(Path::new("/cache"), "9.9.9", "x86_64", libc);
            assert_eq!(SdkSidecarLayout::libc_of_image_path(&layout.image), libc);
        }
    }

    /// A path that is not one this layout wrote reads as `Unknown`, never as a
    /// guess. Admission refuses `Unknown`, so guessing here would turn a
    /// missing answer into a wrong one.
    #[test]
    fn a_foreign_path_reads_as_unknown() {
        for p in [
            "/somewhere/sdk.ext4",
            "/cache/sdk-sidecar/9.9.9/x86_64/sdk.ext4",
            "sdk.ext4",
        ] {
            assert_eq!(
                SdkSidecarLayout::libc_of_image_path(Path::new(p)),
                GuestLibc::Unknown,
                "{p}"
            );
        }
    }

    /// The two variants carry different objects and verify against different
    /// manifests, so they must not land in one directory. If they shared it,
    /// whichever was built last would answer for both and a guest would be
    /// handed a cdylib it cannot `dlopen` — the failure this key exists to
    /// prevent, surfacing inside the guest instead of here.
    #[test]
    fn the_two_libc_variants_do_not_share_a_directory() {
        let glibc =
            SdkSidecarLayout::under(Path::new("/cache"), "9.9.9", "x86_64", GuestLibc::Glibc);
        let musl = SdkSidecarLayout::under(Path::new("/cache"), "9.9.9", "x86_64", GuestLibc::Musl);

        assert_ne!(glibc.artifact_dir, musl.artifact_dir);
        assert_ne!(glibc.image, musl.image);
        assert_ne!(glibc.checksum_manifest_file, musl.checksum_manifest_file);
    }

    #[test]
    fn resolve_returns_the_verified_artifact() {
        let f = Fixture::seed("1.2.3", true, false);
        let artifact = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect("a complete, matching artifact resolves");
        assert_eq!(artifact.version, "1.2.3");
        assert_eq!(artifact.arch, "aarch64");
        assert_eq!(artifact.image_sha256.len(), 64);
        assert!(artifact.image.is_file());
    }

    #[test]
    fn a_cold_cache_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let err = SdkSidecarResolver::new(root.path().join("cache"), "1.2.3".to_string())
            .resolve("aarch64", GuestLibc::Musl)
            .expect_err("an empty cache must not resolve");
        assert!(
            matches!(err, SdkSidecarError::ArtifactIncomplete { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_missing_manifest_fails_closed() {
        let f = Fixture::seed("1.2.3", true, false);
        let layout = f.resolver(&f.version).layout(&f.arch, GuestLibc::Musl);
        std::fs::remove_file(&layout.checksum_manifest_file).unwrap();
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("no manifest must not resolve");
        assert!(
            matches!(err, SdkSidecarError::ArtifactIncomplete { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_tampered_image_fails_closed() {
        let f = Fixture::seed("1.2.3", true, true);
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("a byte-flipped image must not resolve");
        match err {
            SdkSidecarError::ChecksumManifestMismatch { name, .. } => {
                assert_eq!(name, SDK_SIDECAR_IMAGE_FILE);
            }
            other => panic!("expected a manifest mismatch, got {other}"),
        }
    }

    /// The cache is version-keyed, so asking for a version that was never
    /// populated finds nothing at all rather than silently reusing another
    /// build's sidecar.
    #[test]
    fn a_different_requested_version_finds_no_artifact() {
        let f = Fixture::seed("1.2.3", true, false);
        let err = f
            .resolver("9.9.9")
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("a differently-versioned sidecar must not resolve");
        assert!(
            matches!(err, SdkSidecarError::ArtifactIncomplete { .. }),
            "{err}"
        );
    }

    /// A cache entry whose `VERSION` disagrees with the directory it sits in is
    /// incompatible — a sidecar from another build may export a different C ABI
    /// than the SDKs in the matching runtime overlay call.
    #[test]
    fn an_incompatible_version_marker_fails_closed() {
        let f = Fixture::seed("1.2.3", true, false);
        let layout = f.resolver(&f.version).layout(&f.arch, GuestLibc::Musl);
        let drifted = "0.0.1\n";
        std::fs::write(&layout.version_file, drifted).unwrap();
        // Re-stamp the manifest so integrity passes and the version gate is
        // what actually refuses the artifact.
        let image = std::fs::read(&layout.image).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(&image),
                sha256_hex(drifted.as_bytes()),
            ),
        )
        .unwrap();
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("a drifted VERSION must not resolve");
        match err {
            SdkSidecarError::VersionMismatch { expected, found } => {
                assert_eq!(expected, "1.2.3");
                assert_eq!(found, "0.0.1");
            }
            other => panic!("expected a version mismatch, got {other}"),
        }
    }

    #[test]
    fn a_payload_without_the_cdylib_fails_closed() {
        let f = Fixture::seed("1.2.3", false, false);
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("a sidecar with no cdylib must not resolve");
        match err {
            SdkSidecarError::PayloadIncomplete { missing_path, .. } => {
                assert_eq!(missing_path, "/lib/libmvm_host_services.so");
            }
            other => panic!("expected an incomplete payload, got {other}"),
        }
    }

    #[test]
    fn a_non_ext4_payload_fails_closed() {
        let f = Fixture::seed("1.2.3", true, false);
        let layout = f.resolver(&f.version).layout(&f.arch, GuestLibc::Musl);
        let garbage = b"not an ext4 image".to_vec();
        std::fs::write(&layout.image, &garbage).unwrap();
        std::fs::write(
            &layout.checksum_manifest_file,
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(&garbage),
                sha256_hex(format!("{}\n", f.version).as_bytes()),
            ),
        )
        .unwrap();
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("an unreadable payload must not resolve");
        assert!(
            matches!(err, SdkSidecarError::PayloadUnreadable { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_empty_version_file_fails_closed() {
        let f = Fixture::seed("1.2.3", true, false);
        let layout = f.resolver(&f.version).layout(&f.arch, GuestLibc::Musl);
        std::fs::write(&layout.version_file, b"   \n").unwrap();
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .expect_err("a blank VERSION must not resolve");
        assert!(
            matches!(err, SdkSidecarError::InvalidVersionFile { .. }),
            "{err}"
        );
    }

    #[test]
    fn required_image_paths_match_the_protocol_guest_contract() {
        assert!(
            REQUIRED_SIDECAR_IMAGE_PATHS
                .contains(&mvm_contract::plan::sdk_sidecar::SDK_SIDECAR_LIB_PATH),
            "the resolver must prove the exact path the SDKs load"
        );
    }

    #[test]
    fn error_messages_carry_no_file_contents() {
        let f = Fixture::seed("1.2.3", true, true);
        let err = f
            .resolver(&f.version)
            .resolve(&f.arch, GuestLibc::Musl)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("SDK sidecar"), "{rendered}");
        assert!(!rendered.contains("ELF"), "{rendered}");
    }
}
