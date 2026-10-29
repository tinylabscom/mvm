//! One verified guest-bins tree shared by runtime-overlay, initramfs and SDK
//! assembly. A source checkout builds the archive once, then all consumers
//! read its digest-named extraction rather than starting separate guest builds.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use sha2::{Digest, Sha256};
use tar::EntryType;

use crate::guest_agent_build::{self, Freshness, GuestAgentBuildError};
use crate::guest_bins::{
    self, GPU_SHIM_CDYLIBS, GUEST_BINS_MANIFEST_FILE, GuestBinsBuild, GuestBinsError,
    GuestBinsManifest, GuestBinsMember, HOST_SERVICES_CDYLIB,
};
use crate::process_memo::ProcessMemo;

/// A complete guest runtime extracted under a single archive digest.
#[derive(Debug, Clone)]
pub struct GuestRuntime {
    pub root: PathBuf,
    pub digest: String,
    pub manifest: GuestBinsManifest,
    /// Untrusted inputs for a later independent release verification, not a
    /// verified identity. Source and layout-only cache reads carry no proof.
    pub release_proof: Option<evidence::RuntimeReleaseProof>,
}

mod declaration_cache;
pub mod evidence;
pub mod source;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// Canonical SHA-256 spelling used by archive and assembly identities.
pub fn is_archive_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, thiserror::Error)]
pub enum GuestRuntimeError {
    #[error("guest runtime release: {0}")]
    Release(#[from] crate::runtime_overlay::RuntimeOverlayError),
    #[error("guest runtime archive: {0}")]
    Archive(#[from] GuestBinsError),
    #[error("guest runtime source: {0}")]
    Source(#[from] GuestAgentBuildError),
    #[error("guest runtime member: {0}")]
    Member(#[from] guest_bins::MemberError),
    #[error("guest runtime io: {0}")]
    Io(#[from] std::io::Error),
    #[error("guest runtime cache: {0}")]
    Cache(String),
    #[error("guest runtime archive version {actual:?} differs from requested {expected:?}")]
    Version { expected: String, actual: String },
    #[error("guest runtime archive is missing required member {0}")]
    MissingRequired(String),
    #[error("guest runtime archive includes an SDK member absent from this source checkout: {0}")]
    UnexpectedSourceSdkMember(String),
    #[error("guest runtime archive includes another architecture's member {0}")]
    ForeignArchitecture(String),
    #[error("guest runtime tree member {member} has sha256 {actual}, expected {expected}")]
    TreeDigest {
        member: String,
        expected: String,
        actual: String,
    },
}

/// Reject a self-consistent but incomplete archive before any artifact can be
/// assembled from it. A one-architecture runtime must not mix foreign ELF
/// members into its tree.
pub fn validate_guest_runtime_manifest(
    manifest: &GuestBinsManifest,
    version: &str,
    arch: GuestArch,
) -> Result<(), GuestRuntimeError> {
    validate_manifest(manifest, version, arch, ArchiveScope::HostArch)
}

/// Which architectures an archive may carry members for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveScope {
    /// A source build: the host architecture alone.
    HostArch,
    /// A CLI release's guest runtime: every architecture the release ships,
    /// of which the host's must be complete.
    Release,
}

/// Check a release-shaped tree's host layout without granting release authority.
/// Signed evidence additionally requires schema 2 and both assembly declarations.
pub fn validate_release_guest_runtime_layout(
    manifest: &GuestBinsManifest,
    version: &str,
    arch: GuestArch,
) -> Result<(), GuestRuntimeError> {
    validate_manifest(manifest, version, arch, ArchiveScope::Release)
}

fn validate_manifest(
    manifest: &GuestBinsManifest,
    version: &str,
    arch: GuestArch,
    scope: ArchiveScope,
) -> Result<(), GuestRuntimeError> {
    if manifest.version != version {
        return Err(GuestRuntimeError::Version {
            expected: version.to_string(),
            actual: manifest.version.clone(),
        });
    }
    let present: BTreeSet<&str> = manifest.files.keys().map(String::as_str).collect();
    let mut required = BTreeSet::new();
    for name in guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS
        .into_iter()
        .chain(guest_agent_build::RUNTIME_OVERLAY_ADDON_BINS)
        .chain(["mvm-oci-entrypoint", "mvm-setpriv"])
    {
        required.insert(GuestBinsMember::executable(arch, name)?.path());
    }
    required.insert(GuestBinsMember::InitramfsAgent { arch }.path());
    for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
        for cdylib in [HOST_SERVICES_CDYLIB].into_iter().chain(GPU_SHIM_CDYLIBS) {
            required.insert(GuestBinsMember::shared_object(arch, libc, cdylib.soname)?.path());
        }
    }
    required.insert("sdk-py/mvm/__init__.py".to_string());
    if let Some(missing) = required
        .iter()
        .find(|name| !present.contains(name.as_str()))
    {
        return Err(GuestRuntimeError::MissingRequired(missing.clone()));
    }
    for member in present {
        match GuestBinsMember::parse(member)? {
            GuestBinsMember::Executable { arch: found, .. }
            | GuestBinsMember::InitramfsAgent { arch: found }
            | GuestBinsMember::SharedObject { arch: found, .. }
                if found != arch && scope == ArchiveScope::HostArch =>
            {
                return Err(GuestRuntimeError::ForeignArchitecture(member.to_string()));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Release payloads contain both architectures; source payloads remain strictly
/// single-architecture. Never admit an overlay-only archive as a release runtime.
pub fn validate_release_guest_runtime_manifest(
    manifest: &GuestBinsManifest,
    version: &str,
) -> Result<(), GuestRuntimeError> {
    if manifest.schema_version != guest_bins::GUEST_BINS_MANIFEST_SCHEMA {
        return Err(GuestBinsError::UnsupportedSchema {
            found: manifest.schema_version,
        }
        .into());
    }
    for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
        validate_manifest(manifest, version, arch, ArchiveScope::Release)?;
    }
    for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
        manifest
            .assemblies
            .get(&arch)
            .ok_or_else(|| GuestRuntimeError::MissingRequired(format!("assembly for {arch}")))?
            .validate(arch)?;
    }
    Ok(())
}

/// Verify a packaged or downloaded complete guest-bins archive and install it
/// into the shared digest cache. Signature verification is mandatory, including
/// when legacy image download escape-hatch environment variables are set.
pub fn install_signed_guest_runtime_archive(
    cache_root: &Path,
    archive: &Path,
    checksum: &Path,
    bundle: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let verified = evidence::verify_release_archive(archive, checksum, bundle, version, arch)?;
    let base = cache_root.join("guest-runtime").join("v1");
    fs::create_dir_all(&base)?;
    let _lock = guest_agent_build::acquire_guest_build_lock(&base, "guest runtime")?;
    let stage = stage_archive(&base, verified.archive_path())?;
    let mut runtime = promote_staged_archive(
        &base,
        stage,
        verified.manifest().clone(),
        verified.archive_sha256().to_string(),
        arch,
        ArchiveScope::Release,
    )?;
    runtime.release_proof = Some(evidence::RuntimeReleaseProof {
        archive: archive.canonicalize()?,
        checksum: checksum.canonicalize()?,
        signature_bundle: bundle.canonicalize()?,
        archive_sha256: verified.archive_sha256().to_string(),
        version: version.to_string(),
        arch,
    });
    Ok(runtime)
}

/// Acquire the CLI-version-locked runtime. A packaged archive takes precedence;
/// any verification failure is terminal, never a reason to try another source.
/// Cached release triplets are reverified on every use, including offline use.
pub fn resolve_or_download_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let executable = std::env::current_exe()?.canonicalize()?;
    resolve_release_guest_runtime(
        cache_root,
        version,
        arch,
        &packaged_runtime_locations(&executable)?,
        &format!("https://github.com/tinylabscom/mvm/releases/download/v{version}"),
        false,
    )
}

/// Acquire all four signed release files for portable packaging. Unlike the
/// ordinary resolver, an authenticated legacy triplet may need network access
/// to obtain its standalone checksum signature. Invalid evidence never falls
/// back. Locate the checksum signature with [`evidence::checksum_bundle_path`].
pub fn resolve_or_download_guest_runtime_quartet(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let executable = std::env::current_exe()?.canonicalize()?;
    resolve_release_guest_runtime(
        cache_root,
        version,
        arch,
        &packaged_runtime_locations(&executable)?,
        &format!("https://github.com/tinylabscom/mvm/releases/download/v{version}"),
        true,
    )
}

/// Authenticate only an existing release triplet. This probe never downloads,
/// extracts, or builds; a partial selected triplet is an error, not a miss.
pub fn cached_runtime_release_proof(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<Option<evidence::RuntimeReleaseProof>, GuestRuntimeError> {
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return Err(GuestRuntimeError::Cache("invalid release version".into()));
    }
    let executable = std::env::current_exe()?.canonicalize()?;
    let mut locations = packaged_runtime_locations(&executable)?;
    let cached = cache_root.join("guest-runtime/releases").join(version);
    locations.push(cached.clone());
    let asset = guest_bins::guest_bins_archive_name(version);
    for directory in locations {
        let archive = directory.join(&asset);
        let checksum = directory.join(format!("{asset}.sha256"));
        let signature_bundle = directory.join(format!("{asset}.bundle"));
        let mut present = false;
        let checksum_bundle = evidence::checksum_bundle_path(&checksum);
        for path in [&archive, &checksum, &signature_bundle, &checksum_bundle] {
            match fs::symlink_metadata(path) {
                Ok(_) => present = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !present && directory == cached {
            match fs::symlink_metadata(&directory) {
                Ok(_) => present = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if present {
            let verified = evidence::verify_release_archive(
                &archive,
                &checksum,
                &signature_bundle,
                version,
                arch,
            )?;
            return Ok(Some(evidence::RuntimeReleaseProof {
                archive: archive.canonicalize()?,
                checksum: checksum.canonicalize()?,
                signature_bundle: signature_bundle.canonicalize()?,
                archive_sha256: verified.archive_sha256().to_string(),
                version: version.to_owned(),
                arch,
            }));
        }
    }
    Ok(None)
}

fn packaged_runtime_locations(executable: &Path) -> Result<Vec<PathBuf>, GuestRuntimeError> {
    let directory = executable.parent().ok_or_else(|| {
        GuestRuntimeError::Cache("executable has no parent directory".to_string())
    })?;
    let mut locations = vec![directory.join("guest-runtime")];
    // System packages keep public binaries in prefix/bin and private data in
    // prefix/lib/mvmctl. Versioned and Nix installations resolve their public
    // symlink first and use the runtime beside the real executable.
    if directory.file_name().is_some_and(|name| name == "bin")
        && let Some(prefix) = directory.parent()
    {
        locations.push(prefix.join("lib/mvmctl/guest-runtime"));
    }
    Ok(locations)
}

fn resolve_release_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    packaged: &[PathBuf],
    release_url: &str,
    require_quartet: bool,
) -> Result<GuestRuntime, GuestRuntimeError> {
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return Err(GuestRuntimeError::Cache(
            "invalid release version".to_string(),
        ));
    }
    let asset = guest_bins::guest_bins_archive_name(version);
    let install = |dir: &Path| {
        install_signed_guest_runtime_archive(
            cache_root,
            &dir.join(&asset),
            &dir.join(format!("{asset}.sha256")),
            &dir.join(format!("{asset}.bundle")),
            version,
            arch,
        )
    };
    let mut legacy_package = None;
    'packaged: for directory in packaged {
        for name in [
            asset.clone(),
            format!("{asset}.sha256"),
            format!("{asset}.bundle"),
            format!("{asset}.sha256.bundle"),
        ] {
            match fs::symlink_metadata(directory.join(name)) {
                Ok(_) => {
                    let runtime = install(directory)?;
                    if !require_quartet
                        || evidence::checksum_bundle_present(
                            &directory.join(format!("{asset}.sha256.bundle")),
                        )?
                    {
                        return Ok(runtime);
                    }
                    // The selected legacy package is authenticated, but cannot
                    // supply portable evidence. Do not modify a package prefix.
                    let mut files = Vec::new();
                    for name in [
                        asset.clone(),
                        format!("{asset}.sha256"),
                        format!("{asset}.bundle"),
                    ] {
                        let bytes = fs::read(directory.join(&name))?;
                        if name == asset && hex::encode(Sha256::digest(&bytes)) != runtime.digest {
                            return Err(GuestRuntimeError::Cache(
                                "selected packaged archive changed during acquisition".into(),
                            ));
                        }
                        files.push((name, bytes));
                    }
                    legacy_package = Some(files);
                    break 'packaged;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    let releases = cache_root.join("guest-runtime").join("releases");
    fs::create_dir_all(&releases)?;
    let _lock = guest_agent_build::acquire_guest_build_lock(&releases, "guest runtime release")?;
    let destination = releases.join(version);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            if let Some(files) = &legacy_package {
                for (name, bytes) in files {
                    if *bytes != fs::read(destination.join(name))? {
                        return Err(GuestRuntimeError::Cache(
                            "cached release differs from selected packaged runtime".into(),
                        ));
                    }
                }
            }
            let runtime = install(&destination)?;
            let bundle_name = format!("{asset}.sha256.bundle");
            let bundle = destination.join(&bundle_name);
            if require_quartet && !evidence::checksum_bundle_present(&bundle)? {
                let stage = tempfile::Builder::new()
                    .prefix(".checksum-")
                    .tempdir_in(&releases)?;
                let downloaded = stage.path().join(&bundle_name);
                crate::runtime_overlay::curl_download(
                    &format!("{release_url}/{bundle_name}"),
                    &downloaded,
                )?;
                evidence::verify_checksum_signature(
                    &fs::read(destination.join(format!("{asset}.sha256")))?,
                    &downloaded,
                    version,
                )?;
                fs::rename(downloaded, bundle)?;
                return install(&destination);
            }
            return Ok(runtime);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let stage = tempfile::Builder::new()
        .prefix(".download-")
        .tempdir_in(&releases)?;
    for name in [
        asset.clone(),
        format!("{asset}.sha256"),
        format!("{asset}.bundle"),
        format!("{asset}.sha256.bundle"),
    ] {
        let target = stage.path().join(&name);
        if let Some(bytes) = legacy_package
            .as_ref()
            .and_then(|files| files.iter().find(|(file, _)| file == &name))
            .map(|(_, bytes)| bytes)
        {
            fs::write(target, bytes)?;
        } else {
            crate::runtime_overlay::curl_download(&format!("{release_url}/{name}"), &target)?;
        }
    }
    let runtime = install(stage.path())?;
    promote_release_download(stage, &destination, runtime)
}

fn promote_release_download(
    stage: tempfile::TempDir,
    destination: &Path,
    mut runtime: GuestRuntime,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let proof = runtime.release_proof.as_mut().ok_or_else(|| {
        GuestRuntimeError::Cache("downloaded runtime has no release verification inputs".into())
    })?;
    let asset = guest_bins::guest_bins_archive_name(&proof.version);
    fs::metadata(stage.path().join(format!("{asset}.sha256.bundle")))?;
    fs::rename(stage.path(), destination)?;
    // The download staging directory no longer exists. Preserve the exact
    // digest/version/architecture pin, but carry the durable quartet paths.
    proof.archive = destination.join(&asset).canonicalize()?;
    proof.checksum = destination.join(format!("{asset}.sha256")).canonicalize()?;
    proof.signature_bundle = destination.join(format!("{asset}.bundle")).canonicalize()?;
    Ok(runtime)
}

/// Build guest-bins only on a source-fingerprint miss, and return a verified
/// extraction shared by all three host-side assemblers.
pub fn resolve_or_build_source_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<GuestRuntime, GuestRuntimeError> {
    if let Some(runtime) = seed_source_guest_runtime(
        cache_root,
        &crate::cache_install::default_cache_root(),
        version,
        arch,
        workspace_root,
    )? {
        return Ok(runtime);
    }
    let base = cache_root.join("guest-runtime").join("v1");
    fs::create_dir_all(&base)?;
    let _lock = guest_agent_build::acquire_guest_build_lock(&base, "guest runtime")?;
    let fingerprint = source_fingerprint(version, arch, workspace_root)?;
    let pointer = base.join("sources").join(&fingerprint);
    if pointer.exists() {
        let digest = fs::read_to_string(&pointer)?;
        return load_cached_source(&base, digest.trim(), version, arch, workspace_root);
    }
    let build_dir = tempfile::Builder::new()
        .prefix(".build-")
        .tempdir_in(&base)?;
    let written = guest_bins::build_guest_bins(&GuestBinsBuild {
        workspace_root: workspace_root.to_path_buf(),
        cache_root: cache_root.to_path_buf(),
        version: version.to_string(),
        arches: vec![arch],
        out_dir: build_dir.path().to_path_buf(),
    })?;
    if source_fingerprint_with(version, arch, workspace_root, Freshness::Rewalk)? != fingerprint {
        return Err(GuestRuntimeError::Cache(
            "source changed while guest runtime was building".to_string(),
        ));
    }
    let runtime = install_archive(&base, &written.archive, version, arch)?;
    validate_source_sdk_members(&runtime.manifest, workspace_root)?;
    fs::create_dir_all(base.join("sources"))?;
    mvm_core::util::atomic_io::atomic_write(&pointer, format!("{}\n", runtime.digest).as_bytes())
        .map_err(|error| GuestRuntimeError::Cache(error.to_string()))?;
    Ok(runtime)
}

/// Copy a matching source runtime into an independent cache without compiling.
///
/// Both roots must be trusted local caches. The exact source/version/architecture
/// pointer selects the donor; archive, member digests, member set and modes are
/// verified before admission. Only the archive is copied (never hardlinked), and
/// the destination pointer is published last. A corrupt cache is an error, not
/// permission to rebuild over evidence of tampering.
pub fn seed_source_guest_runtime(
    cache_root: &Path,
    seed_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<Option<GuestRuntime>, GuestRuntimeError> {
    if let Some(runtime) = cached_source_guest_runtime(cache_root, version, arch, workspace_root)? {
        return Ok(Some(runtime));
    }
    if cache_root == seed_root {
        return Ok(None);
    }
    let fingerprint = source_fingerprint(version, arch, workspace_root)?;
    let Some(source) = cached_source_guest_runtime(seed_root, version, arch, workspace_root)?
    else {
        return Ok(None);
    };
    let base = cache_root.join("guest-runtime").join("v1");
    fs::create_dir_all(&base)?;
    let _lock = guest_agent_build::acquire_guest_build_lock(&base, "guest runtime")?;
    if let Some(runtime) = cached_source_guest_runtime(cache_root, version, arch, workspace_root)? {
        return Ok(Some(runtime));
    }
    let archive = seed_root
        .join("guest-runtime/v1/objects")
        .join(&source.digest)
        .join("archive.tar.gz");
    let runtime = install_archive(&base, &archive, version, arch)?;
    if runtime.digest != source.digest {
        return Err(GuestRuntimeError::Cache(
            "seed archive changed while guest runtime was copying".to_string(),
        ));
    }
    validate_source_sdk_members(&runtime.manifest, workspace_root)?;
    if source_fingerprint_with(version, arch, workspace_root, Freshness::Rewalk)? != fingerprint {
        return Err(GuestRuntimeError::Cache(
            "source changed while guest runtime was copying".to_string(),
        ));
    }
    fs::create_dir_all(base.join("sources"))?;
    mvm_core::util::atomic_io::atomic_write(
        &base.join("sources").join(fingerprint),
        format!("{}\n", runtime.digest).as_bytes(),
    )
    .map_err(|error| GuestRuntimeError::Cache(error.to_string()))?;
    Ok(Some(runtime))
}

/// Find the already-built runtime for this source tree without compiling it.
/// A corrupt pointer or object is an error, not a cache miss that might hide
/// evidence of tampering.
#[tracing::instrument(skip_all)]
pub fn cached_source_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<Option<GuestRuntime>, GuestRuntimeError> {
    let base = cache_root.join("guest-runtime").join("v1");
    if !base.join("sources").is_dir() {
        return Ok(None);
    }
    let fingerprint = source_fingerprint(version, arch, workspace_root)?;
    let pointer = base.join("sources").join(fingerprint);
    match fs::read_to_string(pointer) {
        Ok(digest) => {
            load_cached_source(&base, digest.trim(), version, arch, workspace_root).map(Some)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The digest of the archive this source tree's runtime is cached under, read
/// from its pointer alone: nothing is hashed, extracted or verified. For
/// diagnostics, and for provenance decisions that consume nothing the archive
/// holds, such as whether an artifact built from some runtime is still the one
/// this tree builds; both must stay cheap, and the launch path makes the
/// second on every run. Verifying the object would prove nothing there: the
/// pointer is what maps a tree to an archive, and
/// [`cached_source_guest_runtime`] trusts it the same way before checking the
/// object against it. Anything that uses the runtime's bytes goes through
/// [`cached_source_guest_runtime`], which verifies the object.
pub fn source_guest_runtime_digest(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<Option<String>, GuestRuntimeError> {
    let sources = cache_root.join("guest-runtime").join("v1").join("sources");
    if !sources.is_dir() {
        return Ok(None);
    }
    let fingerprint = source_fingerprint(version, arch, workspace_root)?;
    match fs::read_to_string(sources.join(fingerprint)) {
        Ok(digest) => {
            let digest = digest.trim();
            if !is_archive_digest(digest) {
                return Err(GuestRuntimeError::Cache(
                    "invalid archive digest pointer".to_string(),
                ));
            }
            Ok(Some(digest.to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Install a CLI release's guest runtime into the same digest-keyed object
/// store a source build uses, and return its verified extraction.
///
/// `archive` must already be authenticated: a release binary gets it from
/// [`crate::guest_bins::release::acquire_release_guest_runtime`], which holds
/// it to its digest and release signature, or adopts the copy an installer
/// authenticated the same way. Here it is copied into the store and held to
/// its own manifest again, and the host architecture's members must be
/// complete. A copy already in the store is reverified rather than trusted. A
/// failure is an error, never a reason to use another source.
pub fn install_release_guest_runtime(
    cache_root: &Path,
    archive: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let base = cache_root.join("guest-runtime").join("v1");
    fs::create_dir_all(&base)?;
    let _lock = guest_agent_build::acquire_guest_build_lock(&base, "guest runtime")?;
    install_archive_scoped(&base, archive, version, arch, ArchiveScope::Release)
}

/// Validated source SDK member sets, keyed by `(archive digest, workspace root)`.
/// `validate_source_sdk_members` walks the Python SDK source tree on every call;
/// memoizing the result avoids re-walking it on each of the three lookups a
/// single source-checkout launch makes.
static VALIDATED_SOURCE_SDK: ProcessMemo<(String, PathBuf), ()> = ProcessMemo::new();

fn load_cached_source(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let runtime = load_cached(base, digest, version, arch)?;
    VALIDATED_SOURCE_SDK
        .get_or_try_insert((digest.to_string(), workspace_root.to_path_buf()), || {
            validate_source_sdk_members(&runtime.manifest, workspace_root)
        })?;
    Ok(runtime)
}

/// A source-built archive must carry the complete Python package from that
/// checkout, even when its manifest and tarball agree with each other.
fn validate_source_sdk_members(
    manifest: &GuestBinsManifest,
    workspace_root: &Path,
) -> Result<(), GuestRuntimeError> {
    let expected: BTreeSet<String> = guest_bins::python_sdk::python_sdk_members(workspace_root)?
        .into_iter()
        .map(|(member, _)| member.path())
        .collect();
    let actual: BTreeSet<&str> = manifest
        .files
        .keys()
        .map(String::as_str)
        .filter(|member| member.starts_with("sdk-py/"))
        .collect();
    if let Some(missing) = expected
        .iter()
        .find(|member| !actual.contains(member.as_str()))
    {
        return Err(GuestRuntimeError::MissingRequired(missing.clone()));
    }
    if let Some(extra) = actual.iter().find(|member| !expected.contains(**member)) {
        return Err(GuestRuntimeError::UnexpectedSourceSdkMember(
            (*extra).to_string(),
        ));
    }
    Ok(())
}

/// [`source_fingerprint`] answers, by workspace root, version and architecture.
static SOURCE_FINGERPRINTS: ProcessMemo<(PathBuf, String, GuestArch), String> = ProcessMemo::new();

/// The key a source checkout's runtime is cached under. Memoized for the
/// process: a source-checkout launch asks this from its preparation check, its
/// runtime identity and its initramfs eviction, and each answer used to walk
/// the guest sources again.
fn source_fingerprint(
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<String, GuestRuntimeError> {
    source_fingerprint_with(version, arch, workspace_root, Freshness::Memoized)
}

/// [`source_fingerprint`], or a new walk of every input when `freshness` asks
/// for one — what a build uses to notice the tree changing under it.
fn source_fingerprint_with(
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
    freshness: Freshness,
) -> Result<String, GuestRuntimeError> {
    let compute = || compute_source_fingerprint(version, arch, workspace_root, freshness);
    match freshness {
        Freshness::Memoized => SOURCE_FINGERPRINTS.get_or_try_insert(
            (workspace_root.to_path_buf(), version.to_string(), arch),
            || {
                crate::source_stamp::stamped_fingerprint(
                    &crate::source_stamp::Fingerprint {
                        kind: &format!("guest-runtime-source\0{version}\0{arch}"),
                        roots: &crate::source_stamp::guest_fingerprint_roots(),
                    },
                    workspace_root,
                    compute,
                )
            },
        ),
        Freshness::Rewalk => compute(),
    }
}

/// Files of this recipe whose bytes [`compute_source_fingerprint`] folds in.
pub(crate) const RUNTIME_SOURCE_FILES: &[&str] = &[
    "crates/mvm-build/src/guest_bins/mod.rs",
    "crates/mvm-build/src/guest_bins/member.rs",
    "crates/mvm-build/src/guest_bins/python_sdk.rs",
    "crates/mvm-build/src/guest_runtime.rs",
];

fn compute_source_fingerprint(
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
    freshness: Freshness,
) -> Result<String, GuestRuntimeError> {
    let mut hash = Sha256::new();
    hash.update(b"mvm-guest-runtime-source-v1\0");
    for value in [
        version.to_string(),
        arch.to_string(),
        guest_agent_build::guest_source_fingerprint_with(workspace_root, freshness)?,
        guest_agent_build::sdk_cdylib_source_fingerprint_with(workspace_root, freshness)?,
        guest_bins::extras::extras_source_fingerprint_with(workspace_root, freshness)?,
    ] {
        hash.update(value.as_bytes());
        hash.update(b"\0");
    }
    for relative in RUNTIME_SOURCE_FILES {
        hash.update(relative.as_bytes());
        hash.update(b"\0");
        hash.update(fs::read(workspace_root.join(relative))?);
        hash.update(b"\0");
    }
    for (member, path) in guest_bins::python_sdk::python_sdk_members(workspace_root)? {
        hash.update(member.path().as_bytes());
        hash.update(b"\0");
        hash.update(fs::read(path)?);
        hash.update(b"\0");
    }
    Ok(hex::encode(hash.finalize()))
}

fn install_archive(
    base: &Path,
    archive: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    install_archive_scoped(base, archive, version, arch, ArchiveScope::HostArch)
}

fn install_archive_scoped(
    base: &Path,
    archive: &Path,
    version: &str,
    arch: GuestArch,
    scope: ArchiveScope,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let stage = stage_archive(base, archive)?;
    let snapshot = stage.path().join("archive.tar.gz");
    let digest = file_digest(&snapshot)?;
    let manifest = guest_bins::verify_guest_bins_archive(&snapshot)?;
    validate_manifest(&manifest, version, arch, scope)?;
    promote_staged_archive(base, stage, manifest, digest, arch, scope)
}

fn stage_archive(base: &Path, archive: &Path) -> Result<tempfile::TempDir, GuestRuntimeError> {
    let objects = base.join("objects");
    fs::create_dir_all(&objects)?;
    let stage = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&objects)?;
    let snapshot = stage.path().join("archive.tar.gz");
    fs::copy(archive, &snapshot)?;
    Ok(stage)
}

fn promote_staged_archive(
    base: &Path,
    stage: tempfile::TempDir,
    manifest: GuestBinsManifest,
    digest: String,
    arch: GuestArch,
    scope: ArchiveScope,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let snapshot = stage.path().join("archive.tar.gz");
    let destination = base.join("objects").join(&digest);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return load_cached_scoped(
                base,
                &digest,
                &manifest.version,
                arch,
                scope,
                std::time::SystemTime::now(),
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let tree = stage.path().join("tree");
    fs::create_dir(&tree)?;
    extract_verified(&snapshot, &tree, &manifest)?;
    verify_tree(&tree, &manifest)?;
    fs::rename(stage.path(), &destination)?;
    Ok(GuestRuntime {
        root: destination.join("tree"),
        digest,
        manifest,
        release_proof: None,
    })
}

/// Objects this process has fully verified, by object directory, with the
/// filesystem state they were verified in.
static VERIFIED_OBJECTS: ProcessMemo<PathBuf, (ObjectStamp, GuestRuntime)> = ProcessMemo::new();

fn load_cached(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    load_cached_at(base, digest, version, arch, std::time::SystemTime::now())
}

/// Load a cached object, verifying it in full at most once per process.
///
/// Full verification hashes the 30-odd MB archive, decompresses it, and hashes
/// every extracted member. A source-checkout launch reaches this from three
/// call sites, and paying it three times was most of a warm claim's startup.
///
/// A repeat is answered from the memo only when the object's filesystem state
/// is exactly what it was verified in — every entry's inode, size, mode, mtime
/// and ctime — and only when every one of those timestamps was already settled
/// at least [`OBJECT_SETTLE`] before verification began. File timestamps
/// advance on a coarse clock, so an edit made in the same tick as the stamp
/// could otherwise leave it unchanged; an object written that recently is
/// verified in full every time instead.
///
/// Each launch is its own process, so the same reuse also crosses processes:
/// a completed full verification is recorded under a digest of the object's
/// stamp and the verifying executable, and a later process that finds the
/// object in exactly that state, run by the same executable, reuses it.
fn load_cached_at(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
    now: std::time::SystemTime,
) -> Result<GuestRuntime, GuestRuntimeError> {
    load_cached_scoped(base, digest, version, arch, ArchiveScope::HostArch, now)
}

fn load_cached_scoped(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
    scope: ArchiveScope,
    now: std::time::SystemTime,
) -> Result<GuestRuntime, GuestRuntimeError> {
    if !is_archive_digest(digest) {
        return Err(GuestRuntimeError::Cache(
            "invalid archive digest pointer".to_string(),
        ));
    }
    let object = base.join("objects").join(digest);
    let stamp = settled_stamp(&object, now);
    if let Some(stamp) = &stamp
        && let Some((verified_in, runtime)) = VERIFIED_OBJECTS.get(&object)
        && verified_in == *stamp
        && runtime.digest == digest
    {
        validate_manifest(&runtime.manifest, version, arch, scope)?;
        return Ok(runtime);
    }
    if let Some(stamp) = &stamp
        && verified_earlier(base, digest, stamp)
    {
        let runtime = previously_verified_object(&object, digest)?;
        validate_manifest(&runtime.manifest, version, arch, scope)?;
        VERIFIED_OBJECTS.insert(object, (stamp.clone(), runtime.clone()));
        return Ok(runtime);
    }
    let runtime = verify_cached_object(&object, digest, version, arch, scope)?;
    if let Some(stamp) = stamp {
        record_verification(base, digest, &stamp);
        VERIFIED_OBJECTS.insert(object, (stamp, runtime.clone()));
    }
    Ok(runtime)
}

#[cfg(test)]
thread_local! {
    static FULL_OBJECT_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The filesystem state of one cached object: every entry under it, keyed by
/// relative path.
#[cfg(unix)]
type ObjectStamp = std::collections::BTreeMap<PathBuf, crate::source_stamp::EntryStamp>;
/// No platform without an inode change time can vouch for a reuse, so there
/// is never a stamp there and every load verifies in full.
#[cfg(not(unix))]
type ObjectStamp = std::convert::Infallible;

/// The object's stamp, or `None` when it cannot vouch for a later reuse: an
/// entry changed within [`crate::source_stamp::SETTLE`] of `now`, or the
/// object could not be walked.
#[cfg(unix)]
fn settled_stamp(object: &Path, now: std::time::SystemTime) -> Option<ObjectStamp> {
    let mut entries = ObjectStamp::new();
    collect_entry_stamps(object, object, &mut entries).ok()?;
    let horizon = crate::source_stamp::settle_horizon(now)?;
    entries
        .values()
        .all(|entry| entry.settled_before(horizon))
        .then_some(entries)
}

#[cfg(not(unix))]
fn settled_stamp(_object: &Path, _now: std::time::SystemTime) -> Option<ObjectStamp> {
    None
}

#[cfg(unix)]
fn collect_entry_stamps(
    root: &Path,
    path: &Path,
    entries: &mut ObjectStamp,
) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
    entries.insert(
        relative.to_path_buf(),
        crate::source_stamp::EntryStamp::of(&metadata),
    );
    if metadata.file_type().is_dir() {
        for entry in fs::read_dir(path)? {
            collect_entry_stamps(root, &entry?.path(), entries)?;
        }
    }
    Ok(())
}

/// Where completed full verifications are recorded, beside — never inside —
/// the objects they cover, so recording one does not change its stamp.
fn verification_records(base: &Path) -> PathBuf {
    base.join("verified")
}

/// What verifying the object named `digest` in the state `stamp` describes,
/// by the executable now running, digests to.
#[cfg(unix)]
fn verification_key(digest: &str, stamp: &ObjectStamp) -> Option<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"mvm-guest-runtime-verified-v1\0");
    crate::source_stamp::executable_stamp()?.fold(&mut hasher);
    hasher.update(digest.as_bytes());
    hasher.update(b"\0");
    for (relative, entry) in stamp {
        hasher.update(relative.as_os_str().as_encoded_bytes());
        hasher.update(b"\0");
        entry.fold(&mut hasher);
    }
    Some(hex::encode(hasher.finalize()))
}

#[cfg(not(unix))]
fn verification_key(_digest: &str, stamp: &ObjectStamp) -> Option<String> {
    match *stamp {}
}

/// Whether an earlier process verified this object in full in exactly the
/// state it is in now.
fn verified_earlier(base: &Path, digest: &str, stamp: &ObjectStamp) -> bool {
    verification_key(digest, stamp).is_some_and(|key| {
        crate::source_stamp::read_record(&verification_records(base), "verified-object", &key)
            .as_deref()
            == Some(digest)
    })
}

fn record_verification(base: &Path, digest: &str, stamp: &ObjectStamp) {
    if let Some(key) = verification_key(digest, stamp) {
        crate::source_stamp::write_record(
            &verification_records(base),
            "verified-object",
            &key,
            digest,
        );
    }
}

/// The runtime an earlier full verification admitted, read back from the
/// extracted tree whose every entry is unchanged since. That verification
/// already held the tree's manifest equal to the archive's.
fn previously_verified_object(
    object: &Path,
    digest: &str,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let tree = object.join("tree");
    let manifest: GuestBinsManifest =
        serde_json::from_slice(&fs::read(tree.join(GUEST_BINS_MANIFEST_FILE))?)
            .map_err(GuestBinsError::from)?;
    Ok(GuestRuntime {
        root: tree,
        digest: digest.to_string(),
        manifest,
        release_proof: None,
    })
}

/// Verify a cached object in full: its layout, the archive against the
/// digest that names it, the archive's own manifest, and every extracted
/// member against that manifest.
fn verify_cached_object(
    object: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
    scope: ArchiveScope,
) -> Result<GuestRuntime, GuestRuntimeError> {
    #[cfg(test)]
    FULL_OBJECT_VERIFICATIONS.with(|count| count.set(count.get() + 1));
    let object = object.to_path_buf();
    for dir in [&object, &object.join("tree")] {
        if !fs::symlink_metadata(dir)?.file_type().is_dir() {
            return Err(GuestRuntimeError::Cache(format!(
                "cached runtime directory {} is not a directory",
                dir.display()
            )));
        }
    }
    let archive = object.join("archive.tar.gz");
    if !fs::symlink_metadata(&archive)?.file_type().is_file() {
        return Err(GuestRuntimeError::Cache(format!(
            "cached runtime archive {} is not a regular file",
            archive.display()
        )));
    }
    let actual = file_digest(&archive)?;
    if actual != digest {
        return Err(GuestRuntimeError::Cache(format!(
            "cached archive digest mismatch: expected {digest}, found {actual}"
        )));
    }
    let manifest = guest_bins::verify_guest_bins_archive(&archive)?;
    validate_manifest(&manifest, version, arch, scope)?;
    let tree = object.join("tree");
    verify_tree(&tree, &manifest)?;
    Ok(GuestRuntime {
        root: tree,
        digest: digest.to_string(),
        manifest,
        release_proof: None,
    })
}

fn extract_verified(
    archive_path: &Path,
    tree: &Path,
    manifest: &GuestBinsManifest,
) -> Result<(), GuestRuntimeError> {
    let archive = File::open(archive_path)?;
    let mut archive = tar::Archive::new(GzDecoder::new(archive));
    let mut seen = BTreeSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != EntryType::Regular {
            return Err(GuestRuntimeError::Cache(
                "non-regular archive entry".to_string(),
            ));
        }
        let path = entry.path()?.into_owned();
        let member = path
            .to_str()
            .ok_or_else(|| GuestRuntimeError::Cache("non-UTF-8 archive entry name".to_string()))?;
        if member != GUEST_BINS_MANIFEST_FILE {
            GuestBinsMember::parse(member)?;
        }
        if !seen.insert(member.to_string()) {
            return Err(GuestRuntimeError::Cache(format!(
                "duplicate member {member}"
            )));
        }
        if member != GUEST_BINS_MANIFEST_FILE && !manifest.files.contains_key(member) {
            return Err(GuestRuntimeError::Cache(format!(
                "unlisted member {member}"
            )));
        }
        let target = tree.join(member);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        out.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if member == GUEST_BINS_MANIFEST_FILE {
                0o644
            } else {
                GuestBinsMember::parse(member)?.mode()
            };
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn verify_tree(tree: &Path, manifest: &GuestBinsManifest) -> Result<(), GuestRuntimeError> {
    if !fs::symlink_metadata(tree)?.file_type().is_dir() {
        return Err(GuestRuntimeError::Cache(
            "cached guest runtime tree is not a directory".to_string(),
        ));
    }
    let mut actual_members = BTreeSet::new();
    collect_tree_members(tree, tree, &mut actual_members)?;
    let mut expected_members: BTreeSet<String> = manifest.files.keys().cloned().collect();
    expected_members.insert(GUEST_BINS_MANIFEST_FILE.to_string());
    if actual_members != expected_members {
        return Err(GuestRuntimeError::Cache(format!(
            "cached tree member set differs from archive manifest: missing {:?}, extra {:?}",
            expected_members
                .difference(&actual_members)
                .collect::<Vec<_>>(),
            actual_members
                .difference(&expected_members)
                .collect::<Vec<_>>()
        )));
    }
    let tree_manifest: GuestBinsManifest =
        serde_json::from_slice(&fs::read(tree.join(GUEST_BINS_MANIFEST_FILE))?)
            .map_err(GuestBinsError::from)?;
    if &tree_manifest != manifest {
        return Err(GuestRuntimeError::Cache(
            "cached tree manifest differs from archive manifest".to_string(),
        ));
    }
    for (member, expected) in &manifest.files {
        let path = tree.join(member);
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(GuestRuntimeError::Cache(format!(
                "cached member {member} is not a regular file"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let actual = fs::symlink_metadata(&path)?.permissions().mode() & 0o7777;
            let expected = GuestBinsMember::parse(member)?.mode();
            if actual != expected {
                return Err(GuestRuntimeError::Cache(format!(
                    "cached member {member} has mode {actual:o}, expected {expected:o}"
                )));
            }
        }
        let actual = file_digest(&path)?;
        if actual != *expected {
            return Err(GuestRuntimeError::TreeDigest {
                member: member.clone(),
                expected: expected.clone(),
                actual,
            });
        }
    }
    Ok(())
}

fn collect_tree_members(
    root: &Path,
    dir: &Path,
    members: &mut BTreeSet<String>,
) -> Result<(), GuestRuntimeError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let kind = fs::symlink_metadata(&path)?.file_type();
        if kind.is_dir() {
            collect_tree_members(root, &path, members)?;
        } else if kind.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| {
                GuestRuntimeError::Cache(format!("cached tree path is outside its root: {error}"))
            })?;
            let relative = relative.to_str().ok_or_else(|| {
                GuestRuntimeError::Cache("cached tree has non-UTF-8 member".to_string())
            })?;
            members.insert(relative.replace(std::path::MAIN_SEPARATOR, "/"));
        } else {
            return Err(GuestRuntimeError::Cache(format!(
                "cached tree has non-regular entry {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, GuestRuntimeError> {
    let mut reader = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hex::encode(hash.finalize()))
}

/// A CLI release's guest runtime as `release.yml` publishes it: every member
/// for both architectures, executables as static ELFs of their architecture
/// (the OCI guest set is validated as such), written as one archive the way
/// [`crate::guest_bins::GuestBinsArtifact`] lays it out.
#[cfg(any(test, feature = "test-support"))]
pub mod release_fixture {
    use super::*;
    use mvm_core::image_set::{GitCommit, WorktreeState};

    /// Every member a release carries for `arch`, with its bytes.
    fn members(arch: GuestArch) -> Vec<(GuestBinsMember, Vec<u8>)> {
        let mut members = Vec::new();
        for name in guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS
            .into_iter()
            .chain(guest_agent_build::RUNTIME_OVERLAY_ADDON_BINS)
            .chain(["mvm-oci-entrypoint", "mvm-setpriv"])
        {
            members.push((
                GuestBinsMember::executable(arch, name).unwrap(),
                guest_agent_build::fake_static_elf(arch, name.as_bytes()),
            ));
        }
        members.push((
            GuestBinsMember::InitramfsAgent { arch },
            guest_agent_build::fake_static_elf(arch, b"initramfs-agent"),
        ));
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            for cdylib in [HOST_SERVICES_CDYLIB].into_iter().chain(GPU_SHIM_CDYLIBS) {
                members.push((
                    GuestBinsMember::shared_object(arch, libc, cdylib.soname).unwrap(),
                    mvm_fs::elf::test_fixture::shared_object(&[
                        "libgcc_s.so.1",
                        libc.libc_soname().unwrap(),
                    ]),
                ));
            }
        }
        members
    }

    /// Write `version`'s release archive into `dir` and return its path.
    pub fn write_release_archive(dir: &Path, version: &str) -> PathBuf {
        write_release_archive_tampering(dir, version, None)
    }

    /// [`write_release_archive`], with the bytes of `tampered` changed after
    /// the manifest recorded their digest.
    pub fn write_release_archive_tampering(
        dir: &Path,
        version: &str,
        tampered: Option<&str>,
    ) -> PathBuf {
        let mut entries: Vec<(String, u32, Vec<u8>)> = Vec::new();
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            for (member, bytes) in members(arch) {
                entries.push((member.path(), member.mode(), bytes));
            }
        }
        entries.push(("sdk-py/mvm/__init__.py".to_string(), 0o644, Vec::new()));
        let manifest = GuestBinsManifest {
            schema_version: guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
            version: version.to_string(),
            guest_source_fingerprint: "a".repeat(64),
            sdk_cdylib_source_fingerprint: "b".repeat(64),
            source: crate::image_source::RepoIdentity {
                commit: GitCommit::new("c".repeat(40)).unwrap(),
                worktree: WorktreeState::Clean,
            },
            files: entries
                .iter()
                .map(|(path, _, bytes)| (path.clone(), hex::encode(Sha256::digest(bytes))))
                .collect(),
            assemblies: Default::default(),
        };
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(guest_bins::guest_bins_archive_name(version));
        let gz = flate2::GzBuilder::new()
            .mtime(0)
            .write(File::create(&path).unwrap(), flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);
        let mut append = |name: &str, mode: u32, bytes: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_entry_type(EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            tar.append(&header, bytes).unwrap();
        };
        append(
            GUEST_BINS_MANIFEST_FILE,
            0o644,
            &serde_json::to_vec(&manifest).unwrap(),
        );
        for (name, mode, bytes) in &mut entries {
            if tampered == Some(name.as_str()) {
                bytes.push(b'!');
            }
            append(name, *mode, bytes);
        }
        tar.into_inner().unwrap().finish().unwrap();
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::image_set::{GitCommit, WorktreeState};

    #[test]
    fn cached_release_proof_probe_is_read_only_and_refuses_partial_triplets() {
        let cache = tempfile::tempdir().unwrap();
        let version = "0.0.0-local-proof-probe";
        assert!(
            cached_runtime_release_proof(cache.path(), version, GuestArch::host())
                .unwrap()
                .is_none()
        );
        assert!(!cache.path().join("guest-runtime").exists());
        assert!(
            cached_runtime_release_proof(cache.path(), "../escape", GuestArch::host()).is_err()
        );
        let directory = cache.path().join("guest-runtime/releases").join(version);
        fs::create_dir_all(&directory).unwrap();
        assert!(cached_runtime_release_proof(cache.path(), version, GuestArch::host()).is_err());
        fs::write(
            directory.join(guest_bins::guest_bins_archive_name(version)),
            b"not signed",
        )
        .unwrap();
        assert!(cached_runtime_release_proof(cache.path(), version, GuestArch::host()).is_err());
        assert!(!cache.path().join("guest-runtime/v1").exists());
    }

    fn fixture_manifest(arch: GuestArch) -> GuestBinsManifest {
        let mut files = std::collections::BTreeMap::new();
        for name in guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS
            .into_iter()
            .chain(guest_agent_build::RUNTIME_OVERLAY_ADDON_BINS)
            .chain(["mvm-oci-entrypoint", "mvm-setpriv"])
        {
            files.insert(
                GuestBinsMember::executable(arch, name).unwrap().path(),
                hex::encode(Sha256::digest(b"fixture")),
            );
        }
        files.insert(
            GuestBinsMember::InitramfsAgent { arch }.path(),
            hex::encode(Sha256::digest(b"fixture")),
        );
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            for cdylib in [HOST_SERVICES_CDYLIB].into_iter().chain(GPU_SHIM_CDYLIBS) {
                files.insert(
                    GuestBinsMember::shared_object(arch, libc, cdylib.soname)
                        .unwrap()
                        .path(),
                    hex::encode(Sha256::digest(b"fixture")),
                );
            }
        }
        files.insert(
            "sdk-py/mvm/__init__.py".to_string(),
            hex::encode(Sha256::digest(b"fixture")),
        );
        GuestBinsManifest {
            schema_version: guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
            version: "1.2.3".to_string(),
            guest_source_fingerprint: "a".repeat(64),
            sdk_cdylib_source_fingerprint: "b".repeat(64),
            source: crate::image_source::RepoIdentity {
                commit: GitCommit::new("c".repeat(40)).unwrap(),
                worktree: WorktreeState::Clean,
            },
            files,
            assemblies: Default::default(),
        }
    }

    fn fixture_manifest_with_source_sdk(
        arch: GuestArch,
        workspace_root: &Path,
    ) -> GuestBinsManifest {
        let mut manifest = fixture_manifest(arch);
        for (member, _) in guest_bins::python_sdk::python_sdk_members(workspace_root).unwrap() {
            manifest
                .files
                .insert(member.path(), hex::encode(Sha256::digest(b"fixture")));
        }
        manifest
    }

    fn append(tar: &mut tar::Builder<flate2::write::GzEncoder<File>>, name: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_entry_type(EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, bytes).unwrap();
    }

    fn archive(dir: &Path, manifest: &GuestBinsManifest) -> PathBuf {
        let path = dir.join("fixture.tar.gz");
        let file = File::create(&path).unwrap();
        let gz = flate2::GzBuilder::new()
            .mtime(0)
            .write(file, flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);
        append(
            &mut tar,
            GUEST_BINS_MANIFEST_FILE,
            &serde_json::to_vec(manifest).unwrap(),
        );
        for member in manifest.files.keys() {
            append(&mut tar, member, b"fixture");
        }
        tar.into_inner().unwrap().finish().unwrap();
        path
    }

    #[test]
    fn complete_archive_is_extracted_and_reused_under_one_digest() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let first = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        assert_eq!(first.manifest, manifest);
        assert!(first.release_proof.is_none());
        assert_eq!(
            fs::read(first.root.join("sdk-py/mvm/__init__.py")).unwrap(),
            b"fixture"
        );
        let second = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.root, second.root);
        assert!(second.release_proof.is_none());
    }

    #[test]
    fn download_proof_paths_survive_staging_promotion_and_cache_reads_do_not_invent_proof() {
        let cache = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir_in(cache.path()).unwrap();
        let stage_path = stage.path().to_path_buf();
        let asset = guest_bins::guest_bins_archive_name("1.2.3");
        let archive_path = stage.path().join(&asset);
        fs::rename(archive(stage.path(), &release_manifest()), &archive_path).unwrap();
        let checksum = stage.path().join(format!("{asset}.sha256"));
        let bundle = stage.path().join(format!("{asset}.bundle"));
        let checksum_bundle = stage.path().join(format!("{asset}.sha256.bundle"));
        let digest = file_digest(&archive_path).unwrap();
        fs::write(&checksum, format!("{digest}  {asset}\n")).unwrap();
        fs::write(&bundle, b"unsigned test bundle").unwrap();
        fs::write(&checksum_bundle, b"unsigned checksum test bundle").unwrap();
        let objects = cache.path().join("objects-cache");
        let mut runtime = install_archive_scoped(
            &objects,
            &archive_path,
            "1.2.3",
            GuestArch::X86_64,
            ArchiveScope::Release,
        )
        .unwrap();
        assert!(
            runtime.release_proof.is_none(),
            "layout checks do not authenticate a release"
        );
        // This tests the locator handoff, not a successful signature. The proof
        // remains untrusted and must still fail the independent boundary check.
        runtime.release_proof = Some(evidence::RuntimeReleaseProof {
            archive: archive_path,
            checksum,
            signature_bundle: bundle,
            archive_sha256: digest.clone(),
            version: "1.2.3".into(),
            arch: GuestArch::X86_64,
        });
        let destination = cache.path().join("release");
        let runtime = promote_release_download(stage, &destination, runtime).unwrap();
        assert!(!stage_path.exists());
        let proof = runtime.release_proof.unwrap();
        let checksum_bundle = evidence::checksum_bundle_path(&proof.checksum);
        for path in [
            &proof.archive,
            &proof.checksum,
            &proof.signature_bundle,
            &checksum_bundle,
        ] {
            assert!(path.is_absolute());
            assert_eq!(path.parent().unwrap(), destination.canonicalize().unwrap());
            assert!(path.is_file());
        }
        assert_eq!(proof.archive_sha256, digest);
        assert_eq!(proof.version, "1.2.3");
        assert_eq!(proof.arch, GuestArch::X86_64);
        assert!(
            evidence::verify_runtime_release_proof(&proof, "1.2.3", GuestArch::X86_64).is_err()
        );
        let cached = load_cached_scoped(
            &objects,
            &digest,
            "1.2.3",
            GuestArch::X86_64,
            ArchiveScope::Release,
            std::time::SystemTime::now(),
        )
        .unwrap();
        assert!(cached.release_proof.is_none());
    }

    fn release_manifest() -> GuestBinsManifest {
        let mut manifest = fixture_manifest(GuestArch::Aarch64);
        manifest
            .files
            .extend(fixture_manifest(GuestArch::X86_64).files);
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            manifest.assemblies.insert(
                arch,
                guest_bins::assembly::RuntimeAssembly {
                    assembly_format: guest_bins::assembly::RUNTIME_ASSEMBLY_FORMAT,
                    arch,
                    protocol_version: mvm_agentd::vsock::PROTOCOL_VERSION,
                    min_supported_protocol_version:
                        mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
                    overlay_sha256: "a".repeat(64),
                    overlay_verity_sha256: "b".repeat(64),
                    overlay_roothash: "c".repeat(64),
                    initramfs_sha256: "d".repeat(64),
                },
            );
        }
        manifest
    }

    #[test]
    fn release_requires_supported_arch_bound_protocol_declarations() {
        let manifest = release_manifest();
        let mut missing = manifest.clone();
        missing.assemblies.clear();
        assert!(validate_release_guest_runtime_manifest(&missing, "1.2.3").is_err());
        for change in 0..4 {
            let mut invalid = manifest.clone();
            let declaration = invalid.assemblies.get_mut(&GuestArch::X86_64).unwrap();
            match change {
                0 => declaration.arch = GuestArch::Aarch64,
                1 => declaration.assembly_format += 1,
                2 => declaration.protocol_version = 0,
                3 => declaration.min_supported_protocol_version = declaration.protocol_version + 1,
                _ => unreachable!(),
            }
            assert!(validate_release_guest_runtime_manifest(&invalid, "1.2.3").is_err());
        }
        // Unsigned, single-architecture development artifacts remain usable.
        validate_guest_runtime_manifest(
            &fixture_manifest(GuestArch::X86_64),
            "1.2.3",
            GuestArch::X86_64,
        )
        .unwrap();
    }

    #[test]
    fn legacy_source_archive_is_readable_but_never_release_evidence() {
        let mut legacy = fixture_manifest(GuestArch::X86_64);
        legacy.schema_version = 1;
        let mut json = serde_json::to_value(&legacy).unwrap();
        json.as_object_mut().unwrap().remove("assemblies");
        let legacy: GuestBinsManifest = serde_json::from_value(json).unwrap();
        assert!(legacy.assemblies.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let input = archive(dir.path(), &legacy);
        let runtime = install_archive(
            &dir.path().join("source-cache"),
            &input,
            "1.2.3",
            GuestArch::X86_64,
        )
        .unwrap();
        assert_eq!(runtime.manifest.schema_version, 1);

        // This mandatory validation also runs after signature verification and
        // before any VerifiedRuntimeManifest is constructed. Even a signed
        // legacy archive with both architectures and declarations is refused.
        let mut signed_legacy_shape = release_manifest();
        signed_legacy_shape.schema_version = 1;
        assert!(matches!(
            validate_release_guest_runtime_manifest(&signed_legacy_shape, "1.2.3"),
            Err(GuestRuntimeError::Archive(
                GuestBinsError::UnsupportedSchema { found: 1 }
            ))
        ));
    }

    #[test]
    fn release_requires_both_architectures_and_exact_version() {
        let manifest = release_manifest();
        validate_release_guest_runtime_manifest(&manifest, "1.2.3").unwrap();
        assert!(matches!(
            validate_release_guest_runtime_manifest(&manifest, "1.2.4"),
            Err(GuestRuntimeError::Version { .. })
        ));
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            assert!(matches!(
                validate_release_guest_runtime_manifest(&fixture_manifest(arch), "1.2.3"),
                Err(GuestRuntimeError::MissingRequired(_))
            ));
            assert!(matches!(
                validate_guest_runtime_manifest(&manifest, "1.2.3", arch),
                Err(GuestRuntimeError::ForeignArchitecture(_))
            ));
        }
    }

    #[test]
    fn both_architectures_share_one_digest_and_tampering_is_terminal() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = release_manifest();
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let first = install_archive_scoped(
            &base,
            &input,
            "1.2.3",
            GuestArch::Aarch64,
            ArchiveScope::Release,
        )
        .unwrap();
        let second = install_archive_scoped(
            &base,
            &input,
            "1.2.3",
            GuestArch::X86_64,
            ArchiveScope::Release,
        )
        .unwrap();
        assert_eq!(first.root, second.root);
        assert_eq!(first.digest, file_digest(&input).unwrap());
        fs::write(first.root.join("x86_64/bin/mvm-setpriv"), b"tampered").unwrap();
        assert!(matches!(
            install_archive_scoped(
                &base,
                &input,
                "1.2.3",
                GuestArch::Aarch64,
                ArchiveScope::Release
            ),
            Err(GuestRuntimeError::TreeDigest { .. })
        ));
    }

    fn unsigned_release(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        fs::create_dir_all(dir).unwrap();
        let input = archive(dir, &release_manifest());
        let asset = guest_bins::guest_bins_archive_name("1.2.3");
        let archive = dir.join(&asset);
        fs::rename(input, &archive).unwrap();
        let checksum = dir.join(format!("{asset}.sha256"));
        fs::write(
            &checksum,
            format!("{}  {asset}\n", file_digest(&archive).unwrap()),
        )
        .unwrap();
        let bundle = dir.join(format!("{asset}.bundle"));
        fs::write(&bundle, b"invalid signature bundle").unwrap();
        (archive, checksum, bundle)
    }

    #[test]
    fn digest_mismatch_is_refused_before_signature_or_cache_admission() {
        let temp = tempfile::tempdir().unwrap();
        let (archive, checksum, bundle) = unsigned_release(&temp.path().join("payload"));
        fs::write(&archive, b"tampered").unwrap();
        fs::remove_file(&bundle).unwrap();
        let cache = temp.path().join("cache");
        let error = install_signed_guest_runtime_archive(
            &cache,
            &archive,
            &checksum,
            &bundle,
            "1.2.3",
            GuestArch::Aarch64,
        )
        .unwrap_err();
        assert!(error.to_string().contains("checksum"));
        assert!(!cache.exists());
    }

    #[test]
    fn package_locations_follow_the_real_executable_and_standard_prefix() {
        assert_eq!(
            packaged_runtime_locations(Path::new("/usr/bin/mvmctl")).unwrap(),
            [
                PathBuf::from("/usr/bin/guest-runtime"),
                PathBuf::from("/usr/lib/mvmctl/guest-runtime"),
            ]
        );
        assert_eq!(
            packaged_runtime_locations(Path::new("/nix/store/mvm/lib/mvmctl/mvmctl")).unwrap(),
            [PathBuf::from("/nix/store/mvm/lib/mvmctl/guest-runtime")]
        );
    }

    #[test]
    fn a_system_package_is_verified_in_place_instead_of_downloaded() {
        let temp = tempfile::tempdir().unwrap();
        unsigned_release(&temp.path().join("lib/mvmctl/guest-runtime"));
        let cache = temp.path().join("cache");
        let error = resolve_release_guest_runtime(
            &cache,
            "1.2.3",
            GuestArch::Aarch64,
            &packaged_runtime_locations(&temp.path().join("bin/mvmctl")).unwrap(),
            "file:///nonexistent/no-fallback",
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GuestRuntimeError::Release(
                crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
            )
        ));
        assert!(!cache.exists());
    }

    #[test]
    fn packaged_verification_failure_never_falls_back_to_download() {
        let temp = tempfile::tempdir().unwrap();
        let packaged = temp.path().join("packaged");
        unsigned_release(&packaged);
        let cache = temp.path().join("cache");
        let error = resolve_release_guest_runtime(
            &cache,
            "1.2.3",
            GuestArch::Aarch64,
            &[packaged, temp.path().join("other-package-location")],
            "file:///nonexistent/no-fallback",
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GuestRuntimeError::Release(
                crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
            )
        ));
        assert!(!cache.exists());
    }

    #[test]
    fn incomplete_packaged_triplet_is_an_error_not_a_download_miss() {
        let temp = tempfile::tempdir().unwrap();
        let packaged = temp.path().join("packaged");
        let (archive, _, _) = unsigned_release(&packaged);
        fs::remove_file(archive).unwrap();
        let cache = temp.path().join("cache");
        let error = resolve_release_guest_runtime(
            &cache,
            "1.2.3",
            GuestArch::Aarch64,
            &[packaged],
            "file:///nonexistent/no-fallback",
            false,
        )
        .unwrap_err();
        assert!(matches!(error, GuestRuntimeError::Io(_)));
        assert!(!cache.exists());
    }

    #[test]
    fn cached_release_is_reverified_instead_of_trusting_its_location() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join("cache");
        unsigned_release(&cache.join("guest-runtime/releases/1.2.3"));
        let error = resolve_release_guest_runtime(
            &cache,
            "1.2.3",
            GuestArch::X86_64,
            &[temp.path().join("absent")],
            "file:///nonexistent/no-fallback",
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GuestRuntimeError::Release(
                crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
            )
        ));
        assert!(!cache.join("guest-runtime/v1/objects").exists());
    }

    #[test]
    fn unsigned_download_is_not_promoted_to_the_release_cache() {
        let temp = tempfile::tempdir().unwrap();
        let release = temp.path().join("release");
        unsigned_release(&release);
        fs::write(
            release.join(format!(
                "{}.sha256.bundle",
                guest_bins::guest_bins_archive_name("1.2.3")
            )),
            b"unsigned checksum test bundle",
        )
        .unwrap();
        let cache = temp.path().join("cache");
        let error = resolve_release_guest_runtime(
            &cache,
            "1.2.3",
            GuestArch::X86_64,
            &[temp.path().join("absent")],
            &format!("file://{}", release.display()),
            false,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            GuestRuntimeError::Release(
                crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
            )
        ));
        assert!(!cache.join("guest-runtime/releases/1.2.3").exists());
        assert!(!cache.join("guest-runtime/v1/objects").exists());
    }

    #[test]
    fn checksum_proof_missing_or_tampered_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("checksum.bundle");
        assert!(!evidence::checksum_bundle_present(&bundle).unwrap());
        assert!(matches!(
            evidence::verify_checksum_signature(b"checksum", &bundle, "1.2.3"),
            Err(GuestRuntimeError::Io(_))
        ));
        fs::write(&bundle, b"tampered checksum signature").unwrap();
        assert!(evidence::checksum_bundle_present(&bundle).unwrap());
        assert!(matches!(
            evidence::verify_checksum_signature(b"checksum", &bundle, "1.2.3"),
            Err(GuestRuntimeError::Release(
                crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
            ))
        ));
    }

    #[test]
    fn present_invalid_checksum_proof_never_triggers_download() {
        let temp = tempfile::tempdir().unwrap();
        let packaged = temp.path().join("packaged");
        let (_, checksum, _) = unsigned_release(&packaged);
        fs::write(evidence::checksum_bundle_path(&checksum), b"tampered").unwrap();
        for require_quartet in [false, true] {
            let cache = temp.path().join("cache");
            let error = resolve_release_guest_runtime(
                &cache,
                "1.2.3",
                GuestArch::Aarch64,
                std::slice::from_ref(&packaged),
                "file:///nonexistent/no-fallback",
                require_quartet,
            )
            .unwrap_err();
            assert!(matches!(
                error,
                GuestRuntimeError::Release(
                    crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
                )
            ));
            assert!(error.to_string().contains(".sha256"));
            assert!(!cache.exists());
        }
    }

    #[test]
    fn new_download_requires_checksum_proof_before_promotion() {
        let temp = tempfile::tempdir().unwrap();
        let release = temp.path().join("release");
        unsigned_release(&release);
        let cache = temp.path().join("cache");
        assert!(
            resolve_release_guest_runtime(
                &cache,
                "1.2.3",
                GuestArch::X86_64,
                &[],
                &format!("file://{}", release.display()),
                true,
            )
            .is_err()
        );
        let releases = cache.join("guest-runtime/releases");
        assert!(!releases.join("1.2.3").exists());
        assert!(!cache.join("guest-runtime/v1/objects").exists());
        assert!(fs::read_dir(releases).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".download-")
        }));
    }

    #[test]
    fn self_consistent_archive_missing_required_member_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut manifest = fixture_manifest(GuestArch::X86_64);
        manifest.files.remove("x86_64/bin/mvm-setpriv");
        let input = archive(temp.path(), &manifest);
        assert!(matches!(
            install_archive(&temp.path().join("cache"), &input, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::MissingRequired(member)) if member == "x86_64/bin/mvm-setpriv"
        ));
    }

    #[test]
    fn source_runtime_rejects_an_incomplete_or_extra_python_sdk() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let arch = GuestArch::X86_64;
        let mut manifest = fixture_manifest_with_source_sdk(arch, &workspace);
        manifest.files.remove("sdk-py/mvm/host.py");
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", arch).unwrap();
        assert!(matches!(
            validate_source_sdk_members(&runtime.manifest, &workspace),
            Err(GuestRuntimeError::MissingRequired(member)) if member == "sdk-py/mvm/host.py"
        ));
        assert!(matches!(
            load_cached_source(&base, &runtime.digest, "1.2.3", arch, &workspace),
            Err(GuestRuntimeError::MissingRequired(member)) if member == "sdk-py/mvm/host.py"
        ));

        let mut complete = fixture_manifest_with_source_sdk(arch, &workspace);
        complete.files.insert(
            "sdk-py/mvm/stale.py".to_string(),
            hex::encode(Sha256::digest(b"fixture")),
        );
        assert!(matches!(
            validate_source_sdk_members(&complete, &workspace),
            Err(GuestRuntimeError::UnexpectedSourceSdkMember(member))
                if member == "sdk-py/mvm/stale.py"
        ));
    }

    #[test]
    fn wrong_version_and_foreign_architecture_are_refused() {
        let mut manifest = fixture_manifest(GuestArch::X86_64);
        assert!(matches!(
            validate_guest_runtime_manifest(&manifest, "4.5.6", GuestArch::X86_64),
            Err(GuestRuntimeError::Version { .. })
        ));
        manifest.files.insert(
            "aarch64/bin/mvm-ping".to_string(),
            hex::encode(Sha256::digest(b"fixture")),
        );
        assert!(matches!(
            validate_guest_runtime_manifest(&manifest, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::ForeignArchitecture(member)) if member == "aarch64/bin/mvm-ping"
        ));
    }

    #[test]
    fn tampered_or_extra_cached_tree_member_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        fs::write(runtime.root.join("x86_64/bin/mvm-ping"), b"tampered").unwrap();
        assert!(matches!(
            load_cached(&base, &runtime.digest, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::TreeDigest { .. })
        ));
        fs::write(runtime.root.join("x86_64/bin/mvm-ping"), b"fixture").unwrap();
        fs::write(runtime.root.join("sdk-py/mvm/extra.py"), b"extra").unwrap();
        assert!(matches!(
            load_cached(&base, &runtime.digest, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::Cache(_))
        ));
    }

    #[test]
    fn interrupted_staging_directory_does_not_count_as_cached_object() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        fs::create_dir_all(base.join("objects/.staging-interrupted/tree")).unwrap();
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        assert!(runtime.root.join("x86_64/bin/mvm-ping").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_cached_tree_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        let target = runtime.root.join("sdk-py/mvm/__init__.py");
        fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &target).unwrap();
        assert!(matches!(
            load_cached(&base, &runtime.digest, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::Cache(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cached_tree_root_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        let moved = runtime.root.with_file_name("tree-moved");
        fs::rename(&runtime.root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &runtime.root).unwrap();
        assert!(matches!(
            load_cached(&base, &runtime.digest, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::Cache(_))
        ));
    }

    #[test]
    fn damaged_archive_is_refused_before_promotion() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        fs::write(&input, b"not a guest archive").unwrap();
        let base = temp.path().join("cache");
        assert!(install_archive(&base, &input, "1.2.3", GuestArch::X86_64).is_err());
        assert_eq!(fs::read_dir(base.join("objects")).unwrap().count(), 0);
    }

    #[test]
    fn stale_source_pointer_does_not_resolve_as_a_warm_hit() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let arch = GuestArch::X86_64;
        let manifest = fixture_manifest_with_source_sdk(arch, &workspace);
        let input = archive(temp.path(), &manifest);
        let cache_root = temp.path().join("cache");
        let base = cache_root.join("guest-runtime/v1");
        let runtime = install_archive(&base, &input, "1.2.3", arch).unwrap();
        let fingerprint = source_fingerprint("1.2.3", arch, &workspace).unwrap();
        fs::create_dir_all(base.join("sources")).unwrap();
        fs::write(base.join("sources").join(fingerprint), &runtime.digest).unwrap();
        assert!(
            cached_source_guest_runtime(&cache_root, "1.2.3", arch, &workspace)
                .unwrap()
                .is_some()
        );
        assert!(
            cached_source_guest_runtime(&cache_root, "1.2.4", arch, &workspace)
                .unwrap()
                .is_none()
        );
    }

    fn full_object_verifications() -> usize {
        FULL_OBJECT_VERIFICATIONS.with(std::cell::Cell::get)
    }

    #[test]
    fn a_settled_object_is_verified_in_full_once_until_it_changes() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        // As a launch long after the object was written sees it.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);

        let before = full_object_verifications();
        for _ in 0..3 {
            let loaded =
                load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, later).unwrap();
            assert_eq!(loaded.digest, runtime.digest);
            assert_eq!(loaded.manifest, runtime.manifest);
        }
        let expected = if cfg!(unix) { 1 } else { 3 };
        assert_eq!(full_object_verifications() - before, expected);

        assert!(
            matches!(
                load_cached_at(&base, &runtime.digest, "4.5.6", GuestArch::X86_64, later),
                Err(GuestRuntimeError::Version { .. })
            ),
            "a reused verification still answers to the requested version"
        );
        fs::write(runtime.root.join("x86_64/bin/mvm-ping"), b"tampered!").unwrap();
        assert!(
            matches!(
                load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, later),
                Err(GuestRuntimeError::TreeDigest { .. })
            ),
            "a member changed after verification is verified again, and refused"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_later_process_reuses_a_recorded_verification_until_the_object_changes() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let object = base.join("objects").join(&runtime.digest);
        // Each load below stands for a separate launch: nothing carries over
        // in this process's memory between them.
        let load_as_a_new_process = || {
            VERIFIED_OBJECTS.remove(&object);
            load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, later)
        };

        let before = full_object_verifications();
        for _ in 0..3 {
            let loaded = load_as_a_new_process().unwrap();
            assert_eq!(loaded.digest, runtime.digest);
            assert_eq!(loaded.manifest, runtime.manifest);
            assert_eq!(loaded.root, runtime.root);
            assert!(loaded.release_proof.is_none());
        }
        assert_eq!(
            full_object_verifications() - before,
            1,
            "only the first launch verifies in full"
        );
        assert!(
            matches!(
                {
                    VERIFIED_OBJECTS.remove(&object);
                    load_cached_at(&base, &runtime.digest, "4.5.6", GuestArch::X86_64, later)
                },
                Err(GuestRuntimeError::Version { .. })
            ),
            "a recorded verification still answers to the requested version"
        );

        // Same length as the original member, so only the content and the
        // entry's timestamps move.
        let member = runtime.root.join("x86_64/bin/mvm-ping");
        let before_edit = crate::source_stamp::EntryStamp::of(&fs::metadata(&member).unwrap());
        let len = before_edit.len as usize;
        fs::write(&member, vec![b'!'; len]).unwrap();
        // Change the stamp deterministically even if the write shares a filesystem clock tick.
        File::options()
            .write(true)
            .open(&member)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        let after_edit = crate::source_stamp::EntryStamp::of(&fs::metadata(&member).unwrap());
        assert_eq!(after_edit.len, before_edit.len);
        assert_eq!(after_edit.ino, before_edit.ino);
        assert_eq!(after_edit.mode, before_edit.mode);
        assert_ne!(after_edit.mtime, before_edit.mtime);
        assert_ne!(after_edit, before_edit);
        let before_verification = full_object_verifications();
        let observed = load_as_a_new_process();
        assert!(
            matches!(&observed, Err(GuestRuntimeError::TreeDigest { .. })),
            "a member changed after the recorded verification is verified again, and refused: \
             observed={observed:?}, before={before_edit:?}, after={after_edit:?}"
        );
        assert_eq!(full_object_verifications() - before_verification, 1);
    }

    #[test]
    #[cfg(unix)]
    fn a_recent_same_length_mutation_is_verified_despite_seeded_caches() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        let object = base.join("objects").join(&runtime.digest);
        let member = runtime.root.join("x86_64/bin/mvm-ping");
        // Hold a captured non-future clock fixed to test the settling boundary, not clock speed.
        let now = std::time::SystemTime::now();
        let set_mtime = || {
            File::options()
                .write(true)
                .open(&member)
                .unwrap()
                .set_modified(now)
                .unwrap();
        };
        set_mtime();
        let later = now + std::time::Duration::from_secs(3600);
        load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, later).unwrap();
        let recorded_stamp = settled_stamp(&object, later).unwrap();
        assert_eq!(
            VERIFIED_OBJECTS.get(&object).expect("seeded memo").0,
            recorded_stamp
        );
        assert!(verified_earlier(&base, &runtime.digest, &recorded_stamp));

        let before_edit = crate::source_stamp::EntryStamp::of(&fs::metadata(&member).unwrap());
        fs::write(&member, vec![b'!'; before_edit.len as usize]).unwrap();
        set_mtime();
        let after_edit = crate::source_stamp::EntryStamp::of(&fs::metadata(&member).unwrap());
        assert_eq!(after_edit.len, before_edit.len);
        assert_eq!(after_edit.ino, before_edit.ino);
        assert_eq!(after_edit.mode, before_edit.mode);
        assert_eq!(after_edit.mtime, before_edit.mtime);
        // ctime may advance or share a tick; either way this state is too recent to reuse.
        assert!(settled_stamp(&object, now).is_none());

        for clear_memo in [false, true] {
            if clear_memo {
                VERIFIED_OBJECTS.remove(&object);
            }
            assert_eq!(VERIFIED_OBJECTS.get(&object).is_none(), clear_memo);
            assert!(verified_earlier(&base, &runtime.digest, &recorded_stamp));
            let before_verification = full_object_verifications();
            let observed = load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, now);
            assert!(
                matches!(&observed, Err(GuestRuntimeError::TreeDigest { .. })),
                "a recent mutation must be verified and refused even with cached verification: \
                 clear_memo={clear_memo}, observed={observed:?}, \
                 before={before_edit:?}, after={after_edit:?}"
            );
            assert_eq!(full_object_verifications() - before_verification, 1);
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_verification_record_for_another_state_is_not_reused() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let object = base.join("objects").join(&runtime.digest);
        load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, later).unwrap();

        // Swap a member for a different file: its inode changes even though
        // its path does not.
        let member = runtime.root.join("x86_64/bin/mvm-ping");
        let replacement = runtime.root.join("replacement");
        fs::write(&replacement, b"other").unwrap();
        fs::rename(&replacement, &member).unwrap();
        VERIFIED_OBJECTS.remove(&object);
        let before = full_object_verifications();
        assert!(load_cached_at(&base, &runtime.digest, "1.2.3", GuestArch::X86_64, later).is_err());
        assert_eq!(full_object_verifications() - before, 1);
    }

    #[test]
    fn a_freshly_written_object_is_verified_in_full_every_time() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = fixture_manifest(GuestArch::X86_64);
        let input = archive(temp.path(), &manifest);
        let base = temp.path().join("cache");
        let runtime = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();

        let before = full_object_verifications();
        for _ in 0..2 {
            load_cached(&base, &runtime.digest, "1.2.3", GuestArch::X86_64).unwrap();
        }
        assert_eq!(
            full_object_verifications() - before,
            2,
            "an object whose timestamps may not have advanced past an edit is never reused"
        );
    }

    #[test]
    fn repeated_source_lookups_walk_the_guest_sources_once() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let cache_root = temp.path().join("cache");
        source_cache_fixture(&cache_root, &workspace);

        let walks = guest_agent_build::source_input_walks_on_this_thread();
        // Preparation check, runtime identity and initramfs eviction: the
        // three lookups one source-checkout launch makes.
        for _ in 0..3 {
            assert!(
                cached_source_guest_runtime(&cache_root, "1.2.3", GuestArch::X86_64, &workspace)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            guest_agent_build::source_input_walks_on_this_thread(),
            walks,
            "a lookup after the first answers from the memo"
        );

        let memoized = source_fingerprint("1.2.3", GuestArch::X86_64, &workspace).unwrap();
        let rewalked =
            source_fingerprint_with("1.2.3", GuestArch::X86_64, &workspace, Freshness::Rewalk)
                .unwrap();
        assert_eq!(memoized, rewalked);
        assert!(
            guest_agent_build::source_input_walks_on_this_thread() >= walks + 3,
            "a rewalk reads the guest, cdylib and extras inputs again"
        );
    }

    fn source_cache_fixture(cache: &Path, workspace: &Path) -> GuestRuntime {
        test_support::write_source_cache_fixture(cache, workspace, "1.2.3", GuestArch::X86_64)
            .unwrap()
    }

    #[test]
    fn checked_source_runtime_binds_legacy_bytes_and_refuses_substitution() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        env.set(
            crate::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV,
            &workspace,
        );
        env.set("MVM_ALLOW_UNSIGNED_RUNTIME", "1");
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let mut manifest = fixture_manifest_with_source_sdk(arch, &workspace);
        manifest.schema_version = 1;
        let input = archive(cache.path(), &manifest);
        let base = cache.path().join("guest-runtime/v1");
        let runtime = install_archive(&base, &input, "1.2.3", arch).unwrap();
        fs::create_dir_all(base.join("sources")).unwrap();
        let pointer = base
            .join("sources")
            .join(source_fingerprint("1.2.3", arch, &workspace).unwrap());
        fs::write(&pointer, &runtime.digest).unwrap();
        let cold_started = std::time::Instant::now();
        let checked = source::check_source_runtime(cache.path(), "1.2.3", arch);
        if !crate::artifact_acquisition::compiled_channel().permits_automatic_builds() {
            assert!(
                checked
                    .unwrap_err()
                    .to_string()
                    .contains("compiled release channel")
            );
            return;
        }
        let checked = checked.unwrap();
        let cold_elapsed = cold_started.elapsed();
        assert_eq!(checked.archive_sha256(), runtime.digest);
        assert!(checked.declaration(GuestArch::Aarch64).is_err());
        let assembled = tempfile::tempdir().unwrap();
        let overlay = crate::runtime_overlay::build_runtime_overlay_from_guest_runtime(
            assembled.path(),
            "1.2.3",
            arch,
            &runtime,
        )
        .unwrap();
        let initramfs = crate::initramfs::build_initramfs_from_guest_runtime(
            assembled.path(),
            "1.2.3",
            arch,
            &runtime,
        )
        .unwrap();
        let selection = evidence::RuntimeArtifactSelection {
            arch,
            overlay: &overlay.overlay_ext4,
            overlay_verity: &overlay.sidecar,
            overlay_roothash: &overlay.roothash,
            initramfs: &initramfs.image_path,
            minimum_protocol: mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION,
            host_protocol: mvm_agentd::vsock::PROTOCOL_VERSION,
        };
        let parent = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let snapshot = checked
            .snapshot_artifacts_in(&selection, parent.path())
            .unwrap();
        for path in [
            selection.overlay,
            selection.overlay_verity,
            selection.initramfs,
        ] {
            let original = fs::read(path).unwrap();
            fs::write(path, b"substituted").unwrap();
            assert!(checked.snapshot_artifacts(&selection).is_err());
            fs::write(path, original).unwrap();
        }
        let persisted = snapshot.persist().unwrap();
        assert_eq!(
            file_digest(&persisted.overlay_path()).unwrap(),
            checked.declaration(arch).unwrap().overlay_sha256
        );
        assert!(source::check_source_runtime(cache.path(), "9.9.9", arch).is_err());
        assert!(source::check_source_runtime(cache.path(), "1.2.3", GuestArch::Aarch64).is_err());
        // Warm hits still validate archive bytes; memoized derivation is not
        // authority to adopt a corrupted object.
        let warm_started = std::time::Instant::now();
        source::check_source_runtime(cache.path(), "1.2.3", arch).unwrap();
        eprintln!(
            "synthetic source cache: cold {:?}, warm {:?}; fixture bytes, not production launch timing",
            cold_elapsed,
            warm_started.elapsed()
        );
        fs::write(
            base.join("objects")
                .join(&runtime.digest)
                .join("archive.tar.gz"),
            b"bad",
        )
        .unwrap();
        assert!(source::check_source_runtime(cache.path(), "1.2.3", arch).is_err());
        fs::remove_file(pointer).unwrap();
        assert!(source::check_source_runtime(cache.path(), "1.2.3", arch).is_err());
    }

    #[test]
    fn checked_source_runtime_rejects_forged_schema_two_declaration() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        env.set(
            crate::image_source::GUEST_RUNTIME_SOURCE_ROOT_ENV,
            &workspace,
        );
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let mut manifest = fixture_manifest_with_source_sdk(arch, &workspace);
        manifest
            .assemblies
            .insert(arch, release_manifest().assemblies[&arch].clone());
        let input = archive(cache.path(), &manifest);
        let base = cache.path().join("guest-runtime/v1");
        let runtime = install_archive(&base, &input, "1.2.3", arch).unwrap();
        fs::create_dir_all(base.join("sources")).unwrap();
        fs::write(
            base.join("sources")
                .join(source_fingerprint("1.2.3", arch, &workspace).unwrap()),
            runtime.digest,
        )
        .unwrap();
        let error = source::check_source_runtime(cache.path(), "1.2.3", arch).unwrap_err();
        if crate::artifact_acquisition::compiled_channel().permits_automatic_builds() {
            assert!(
                error.to_string().contains("differs from archive members"),
                "{error}"
            );
        } else {
            assert!(
                error.to_string().contains("compiled release channel"),
                "{error}"
            );
        }
    }

    #[test]
    fn the_source_digest_is_read_from_the_pointer_without_touching_the_object() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let cache = temp.path().join("cache");
        assert_eq!(
            source_guest_runtime_digest(&cache, "1.2.3", GuestArch::X86_64, &workspace).unwrap(),
            None
        );
        let runtime = source_cache_fixture(&cache, &workspace);
        // The object is gone; the pointer alone answers.
        fs::remove_dir_all(runtime.root.parent().unwrap()).unwrap();
        assert_eq!(
            source_guest_runtime_digest(&cache, "1.2.3", GuestArch::X86_64, &workspace).unwrap(),
            Some(runtime.digest.clone())
        );
        assert_eq!(
            source_guest_runtime_digest(&cache, "1.2.4", GuestArch::X86_64, &workspace).unwrap(),
            None
        );
        let pointer = cache
            .join("guest-runtime/v1/sources")
            .join(source_fingerprint("1.2.3", GuestArch::X86_64, &workspace).unwrap());
        fs::write(pointer, "../outside").unwrap();
        assert!(
            source_guest_runtime_digest(&cache, "1.2.3", GuestArch::X86_64, &workspace).is_err()
        );
    }

    #[test]
    fn source_seed_copies_verified_objects_without_sharing_mutable_state() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        let original = source_cache_fixture(&source, &workspace);
        let seeded =
            seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                .unwrap()
                .unwrap();
        assert_eq!(original.digest, seeded.digest);
        assert!(seeded.root.starts_with(&target));
        assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
        assert!(
            cached_source_guest_runtime(&target, "1.2.3", GuestArch::X86_64, &workspace)
                .unwrap()
                .is_some()
        );
        fs::write(seeded.root.join("sdk-py/mvm/__init__.py"), b"changed").unwrap();
        assert!(
            cached_source_guest_runtime(&source, "1.2.3", GuestArch::X86_64, &workspace)
                .unwrap()
                .is_some()
        );
        assert!(
            seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                .is_err(),
            "a corrupt destination must not be silently repaired"
        );
    }

    #[test]
    fn source_seed_requires_an_exact_source_version_and_arch_pointer() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        source_cache_fixture(&source, &workspace);
        for (version, arch) in [("1.2.4", GuestArch::X86_64), ("1.2.3", GuestArch::Aarch64)] {
            assert!(
                seed_source_guest_runtime(&target, &source, version, arch, &workspace)
                    .unwrap()
                    .is_none()
            );
        }
        let base = source.join("guest-runtime/v1");
        fs::remove_dir_all(base.join("sources")).unwrap();
        fs::create_dir(base.join("sources")).unwrap();
        fs::write(base.join("sources").join("0".repeat(64)), "a".repeat(64)).unwrap();
        assert!(
            seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                .unwrap()
                .is_none()
        );
        assert!(!target.join("guest-runtime/v1/sources").exists());
    }

    #[test]
    fn source_seed_distinguishes_absent_cache_from_malformed_or_dangling_pointer() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        assert!(
            seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                .unwrap()
                .is_none()
        );
        let pointers = source.join("guest-runtime/v1/sources");
        fs::create_dir_all(&pointers).unwrap();
        let pointer =
            pointers.join(source_fingerprint("1.2.3", GuestArch::X86_64, &workspace).unwrap());
        for digest in [
            "".to_string(),
            "../outside".to_string(),
            "z".repeat(64),
            "a".repeat(64),
        ] {
            fs::write(&pointer, digest).unwrap();
            assert!(
                seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                    .is_err()
            );
            assert!(!target.exists());
        }
    }

    #[test]
    fn source_resolver_seeds_default_cache_without_a_guest_build() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let temp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(temp.path());
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let source = crate::cache_install::default_cache_root();
        let target = temp.path().join("isolated/cache");
        let original = source_cache_fixture(&source, &workspace);
        let runtime =
            resolve_or_build_source_guest_runtime(&target, "1.2.3", GuestArch::X86_64, &workspace)
                .unwrap();
        assert_eq!(original.digest, runtime.digest);
        assert!(runtime.root.starts_with(&target));
        assert!(!guest_agent_build::guest_build_target_dir(&target, &workspace).exists());
    }

    #[test]
    fn source_seed_refuses_corrupt_donors_before_publishing_a_pointer() {
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        for member in ["tree/sdk-py/mvm/__init__.py", "archive.tar.gz"] {
            let fixture = tempfile::tempdir_in(temp.path()).unwrap();
            let source = fixture.path().join("source");
            let target = fixture.path().join("target");
            let runtime = source_cache_fixture(&source, &workspace);
            fs::write(runtime.root.parent().unwrap().join(member), b"tampered").unwrap();
            assert!(
                seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                    .is_err()
            );
            assert!(!target.join("guest-runtime/v1/sources").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_seed_refuses_wrong_executable_modes() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let workspace =
            guest_agent_build::source_workspace_from(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        let runtime = source_cache_fixture(&source, &workspace);
        let member = GuestBinsMember::executable(
            GuestArch::X86_64,
            guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS[0],
        )
        .unwrap();
        fs::set_permissions(
            runtime.root.join(member.path()),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            seed_source_guest_runtime(&target, &source, "1.2.3", GuestArch::X86_64, &workspace)
                .is_err()
        );
        assert!(!target.join("guest-runtime/v1/sources").exists());
    }

    #[test]
    fn a_release_runtime_carries_both_architectures_and_needs_the_hosts_complete() {
        let mut release = fixture_manifest(GuestArch::X86_64);
        release
            .files
            .extend(fixture_manifest(GuestArch::Aarch64).files);
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            validate_release_guest_runtime_layout(&release, "1.2.3", arch).unwrap();
            assert!(
                matches!(
                    validate_guest_runtime_manifest(&release, "1.2.3", arch),
                    Err(GuestRuntimeError::ForeignArchitecture(_))
                ),
                "a source build stays single-architecture"
            );
        }
        assert!(matches!(
            validate_release_guest_runtime_layout(&release, "1.2.4", GuestArch::X86_64),
            Err(GuestRuntimeError::Version { .. })
        ));
        // The host's members must be whole even when the other architecture's
        // are: an assembled overlay would otherwise miss a binary.
        let mut incomplete = release.clone();
        incomplete.files.remove("x86_64/bin/mvm-setpriv");
        assert!(matches!(
            validate_release_guest_runtime_layout(&incomplete, "1.2.3", GuestArch::X86_64),
            Err(GuestRuntimeError::MissingRequired(member)) if member == "x86_64/bin/mvm-setpriv"
        ));
        validate_release_guest_runtime_layout(&incomplete, "1.2.3", GuestArch::Aarch64).unwrap();
    }

    #[test]
    fn a_release_runtime_installs_under_its_archive_digest_and_is_reverified() {
        let temp = tempfile::tempdir().unwrap();
        let archive = release_fixture::write_release_archive(temp.path(), "1.2.3");
        let cache = temp.path().join("cache");
        let runtime =
            install_release_guest_runtime(&cache, &archive, "1.2.3", GuestArch::X86_64).unwrap();
        assert_eq!(runtime.digest, file_digest(&archive).unwrap());
        assert!(
            runtime
                .root
                .starts_with(cache.join("guest-runtime/v1/objects"))
        );
        assert!(runtime.root.join("aarch64/bin/mvm-guest-agent").is_file());

        // Repeats go straight to the store: the build lock is fail-fast under
        // test, and a sibling test's subprocess can inherit it briefly.
        let base = cache.join("guest-runtime/v1");
        let install = |version| {
            install_archive_scoped(
                &base,
                &archive,
                version,
                GuestArch::X86_64,
                ArchiveScope::Release,
            )
        };
        // The same bytes reuse the object; a member changed in place since is
        // refused rather than assembled from.
        assert_eq!(install("1.2.3").unwrap().root, runtime.root);
        fs::write(
            runtime.root.join("x86_64/bin/mvm-guest-agent"),
            b"tampered!",
        )
        .unwrap();
        let refused = install("1.2.3");
        assert!(
            matches!(
                &refused,
                Err(GuestRuntimeError::TreeDigest { member, .. })
                    if member == "x86_64/bin/mvm-guest-agent"
            ),
            "{refused:?}"
        );
        // Another version's archive is not this binary's runtime.
        let other = install("1.2.4");
        assert!(
            matches!(&other, Err(GuestRuntimeError::Version { .. })),
            "{other:?}"
        );
    }
}
