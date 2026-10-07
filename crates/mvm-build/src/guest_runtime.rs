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
    let base = cache_root.join("guest-runtime").join("v1");
    fs::create_dir_all(&base)?;
    let _lock = guest_agent_build::acquire_guest_build_lock(&base, "guest runtime")?;
    let fingerprint = source_fingerprint(version, arch, workspace_root)?;
    let pointer = base.join("sources").join(&fingerprint);
    if pointer.exists() {
        let digest = fs::read_to_string(&pointer)?;
        return load_cached(&base, digest.trim(), version, arch);
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
    fs::create_dir_all(base.join("sources"))?;
    mvm_core::util::atomic_io::atomic_write(&pointer, format!("{}\n", runtime.digest).as_bytes())
        .map_err(|error| GuestRuntimeError::Cache(error.to_string()))?;
    Ok(runtime)
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
        Ok(digest) => load_cached(&base, digest.trim(), version, arch).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
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

fn load_cached(
    base: &Path,
    digest: &str,
    version: &str,
    arch: GuestArch,
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
        let manifest = fixture_manifest(arch);
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
}
