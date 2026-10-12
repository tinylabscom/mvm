//! One verified guest-bins tree shared by runtime-overlay, initramfs and SDK
//! assembly. A source checkout builds the archive once. Installed clients use
//! the complete, both-architecture guest-bins archive signed by their exact CLI
//! release tag, preferring the triplet next to the real executable under
//! `guest-runtime/`, then the system prefix's `lib/mvmctl/guest-runtime/`,
//! over the release download. All consumers share its
//! digest-named extraction. Verification errors never trigger source fallback.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use sha2::{Digest, Sha256};
use tar::EntryType;

use crate::guest_agent_build::{self, GuestAgentBuildError};
use crate::guest_bins::{
    self, GPU_SHIM_CDYLIBS, GUEST_BINS_MANIFEST_FILE, GuestBinsBuild, GuestBinsError,
    GuestBinsManifest, GuestBinsMember, HOST_SERVICES_CDYLIB,
};

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
    validate_runtime_manifest(manifest, version, arch, false)
}

fn validate_runtime_manifest(
    manifest: &GuestBinsManifest,
    version: &str,
    arch: GuestArch,
    release: bool,
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
                if found != arch && !release =>
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
        validate_runtime_manifest(manifest, version, arch, true)?;
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
        true,
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
    if source_fingerprint(version, arch, workspace_root)? != fingerprint {
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
    if source_fingerprint(version, arch, workspace_root)? != fingerprint {
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

fn load_cached_source(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let runtime = load_cached(base, digest, version, arch)?;
    validate_source_sdk_members(&runtime.manifest, workspace_root)?;
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

fn source_fingerprint(
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<String, GuestRuntimeError> {
    let mut hash = Sha256::new();
    hash.update(b"mvm-guest-runtime-source-v1\0");
    for value in [
        version.to_string(),
        arch.to_string(),
        guest_agent_build::guest_source_fingerprint(workspace_root)?,
        guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)?,
        guest_bins::extras::extras_source_fingerprint(workspace_root)?,
    ] {
        hash.update(value.as_bytes());
        hash.update(b"\0");
    }
    for relative in [
        "crates/mvm-build/src/guest_bins/mod.rs",
        "crates/mvm-build/src/guest_bins/member.rs",
        "crates/mvm-build/src/guest_bins/python_sdk.rs",
        "crates/mvm-build/src/guest_runtime.rs",
    ] {
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
    install_archive_with_layout(base, archive, version, arch, false)
}

fn install_archive_with_layout(
    base: &Path,
    archive: &Path,
    version: &str,
    arch: GuestArch,
    release: bool,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let stage = stage_archive(base, archive)?;
    let snapshot = stage.path().join("archive.tar.gz");
    let digest = file_digest(&snapshot)?;
    let manifest = guest_bins::verify_guest_bins_archive(&snapshot)?;
    validate_archive_layout(&manifest, version, arch, release)?;
    promote_staged_archive(base, stage, manifest, digest, arch, release)
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
    release: bool,
) -> Result<GuestRuntime, GuestRuntimeError> {
    let snapshot = stage.path().join("archive.tar.gz");
    let destination = base.join("objects").join(&digest);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return load_cached_with_layout(base, &digest, &manifest.version, arch, release),
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

fn load_cached(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, GuestRuntimeError> {
    load_cached_with_layout(base, digest, version, arch, false)
}

fn validate_archive_layout(
    manifest: &GuestBinsManifest,
    version: &str,
    arch: GuestArch,
    release: bool,
) -> Result<(), GuestRuntimeError> {
    if release {
        validate_release_guest_runtime_manifest(manifest, version)
    } else {
        validate_guest_runtime_manifest(manifest, version, arch)
    }
}

fn load_cached_with_layout(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
    release: bool,
) -> Result<GuestRuntime, GuestRuntimeError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GuestRuntimeError::Cache(
            "invalid archive digest pointer".to_string(),
        ));
    }
    let object = base.join("objects").join(digest);
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
    validate_archive_layout(&manifest, version, arch, release)?;
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
        let mut runtime =
            install_archive_with_layout(&objects, &archive_path, "1.2.3", GuestArch::X86_64, true)
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
        let cached =
            load_cached_with_layout(&objects, &digest, "1.2.3", GuestArch::X86_64, true).unwrap();
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
        let first =
            install_archive_with_layout(&base, &input, "1.2.3", GuestArch::Aarch64, true).unwrap();
        let second =
            install_archive_with_layout(&base, &input, "1.2.3", GuestArch::X86_64, true).unwrap();
        assert_eq!(first.root, second.root);
        assert_eq!(first.digest, file_digest(&input).unwrap());
        fs::write(first.root.join("x86_64/bin/mvm-setpriv"), b"tampered").unwrap();
        assert!(matches!(
            install_archive_with_layout(&base, &input, "1.2.3", GuestArch::Aarch64, true),
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
}
