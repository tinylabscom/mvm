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
}

#[derive(Debug, thiserror::Error)]
pub enum GuestRuntimeError {
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
                if found != arch =>
            {
                return Err(GuestRuntimeError::ForeignArchitecture(member.to_string()));
            }
            _ => {}
        }
    }
    Ok(())
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
/// diagnostics that must stay cheap. Anything that uses the runtime goes
/// through [`cached_source_guest_runtime`], which verifies the object.
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

/// Whether `value` has the shape of an archive digest: 64 hex characters.
pub fn is_archive_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
            compute,
        ),
        Freshness::Rewalk => compute(),
    }
}

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
    let objects = base.join("objects");
    fs::create_dir_all(&objects)?;
    let stage = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&objects)?;
    let snapshot = stage.path().join("archive.tar.gz");
    fs::copy(archive, &snapshot)?;
    let digest = file_digest(&snapshot)?;
    let manifest = guest_bins::verify_guest_bins_archive(&snapshot)?;
    validate_guest_runtime_manifest(&manifest, version, arch)?;
    let destination = objects.join(&digest);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return load_cached(base, &digest, version, arch),
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
fn load_cached_at(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
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
        validate_guest_runtime_manifest(&runtime.manifest, version, arch)?;
        return Ok(runtime);
    }
    let runtime = verify_cached_object(&object, digest, version, arch)?;
    if let Some(stamp) = stamp {
        VERIFIED_OBJECTS.insert(object, (stamp, runtime.clone()));
    }
    Ok(runtime)
}

#[cfg(test)]
thread_local! {
    static FULL_OBJECT_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How long an object's timestamps must have been still before its
/// verification may be reused. Comfortably above any filesystem's timestamp
/// granularity.
#[cfg(unix)]
const OBJECT_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// The filesystem state of one cached object: every entry under it, keyed by
/// relative path.
#[cfg(unix)]
type ObjectStamp = std::collections::BTreeMap<PathBuf, EntryStamp>;
/// No platform without an inode change time can vouch for a reuse, so there
/// is never a stamp there and every load verifies in full.
#[cfg(not(unix))]
type ObjectStamp = std::convert::Infallible;

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryStamp {
    dev: u64,
    ino: u64,
    mode: u32,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

/// The object's stamp, or `None` when it cannot vouch for a later reuse: an
/// entry changed within [`OBJECT_SETTLE`] of `now`, or the object could not be
/// walked.
#[cfg(unix)]
fn settled_stamp(object: &Path, now: std::time::SystemTime) -> Option<ObjectStamp> {
    let mut entries = ObjectStamp::new();
    collect_entry_stamps(object, object, &mut entries).ok()?;
    let horizon = now
        .checked_sub(OBJECT_SETTLE)?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let horizon = (
        i64::try_from(horizon.as_secs()).ok()?,
        i64::from(horizon.subsec_nanos()),
    );
    entries
        .values()
        .all(|entry| entry.mtime < horizon && entry.ctime < horizon)
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
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
    entries.insert(
        relative.to_path_buf(),
        EntryStamp {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        },
    );
    if metadata.file_type().is_dir() {
        for entry in fs::read_dir(path)? {
            collect_entry_stamps(root, &entry?.path(), entries)?;
        }
    }
    Ok(())
}

/// Verify a cached object in full: its layout, the archive against the
/// digest that names it, the archive's own manifest, and every extracted
/// member against that manifest.
fn verify_cached_object(
    object: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
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
    validate_guest_runtime_manifest(&manifest, version, arch)?;
    let tree = object.join("tree");
    verify_tree(&tree, &manifest)?;
    Ok(GuestRuntime {
        root: tree,
        digest: digest.to_string(),
        manifest,
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
        assert_eq!(
            fs::read(first.root.join("sdk-py/mvm/__init__.py")).unwrap(),
            b"fixture"
        );
        let second = install_archive(&base, &input, "1.2.3", GuestArch::X86_64).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.root, second.root);
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
        let arch = GuestArch::X86_64;
        fs::create_dir_all(cache).unwrap();
        let input = archive(cache, &fixture_manifest_with_source_sdk(arch, workspace));
        let base = cache.join("guest-runtime/v1");
        let runtime = install_archive(&base, &input, "1.2.3", arch).unwrap();
        fs::create_dir_all(base.join("sources")).unwrap();
        fs::write(
            base.join("sources")
                .join(source_fingerprint("1.2.3", arch, workspace).unwrap()),
            &runtime.digest,
        )
        .unwrap();
        runtime
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
}
