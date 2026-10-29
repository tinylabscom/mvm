//! Authentication of runtime declarations and privately owned artifact snapshots.
//!
//! A verified snapshot is not proof of execution. A launcher must retain its
//! ownership through all backend reads, bind its paths and verity root to the
//! actual boot, and retain a durable generation for detached supervisors.

use super::GuestRuntimeError;
use crate::guest_bins::{GuestBinsManifest, assembly::RuntimeAssembly};
use mvm_core::arch::GuestArch;
pub use mvm_core::protocol::runtime_release::RuntimeReleaseProof;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Authenticated declarations plus ownership of the exact signed archive bytes.
/// Private fields and no Deserialize implementation prevent caller-minted trust.
#[derive(Debug)]
pub struct VerifiedRuntimeManifest {
    archive: tempfile::NamedTempFile,
    checksum: Vec<u8>,
    signature: Vec<u8>,
    checksum_signature: Option<Vec<u8>>,
    version: String,
    digest: String,
    manifest: GuestBinsManifest,
    arch: GuestArch,
}

impl VerifiedRuntimeManifest {
    pub(super) fn archive_path(&self) -> &Path {
        self.archive.path()
    }

    pub(super) fn manifest(&self) -> &GuestBinsManifest {
        &self.manifest
    }

    pub fn archive_sha256(&self) -> &str {
        &self.digest
    }

    /// Retain only the evidence bytes consumed by the successful verifier.
    pub fn retain_release_proof_in(
        &self,
        proof: &RuntimeReleaseProof,
        generation: &Path,
    ) -> Result<RuntimeReleaseProof, GuestRuntimeError> {
        if proof.archive_sha256 != self.digest
            || proof.arch != self.arch
            || proof.version != self.version
        {
            return Err(GuestRuntimeError::Cache(
                "runtime proof identity changed".into(),
            ));
        }
        let mut retained = proof.clone();
        retained.archive = generation.join("archive");
        retained.checksum = generation.join("checksum");
        retained.signature_bundle = generation.join("archive.signature");
        snapshot_file(self.archive.path(), &retained.archive, &self.digest)?;
        for (path, bytes) in [
            (&retained.checksum, self.checksum.as_slice()),
            (&retained.signature_bundle, self.signature.as_slice()),
        ] {
            write_evidence(path, bytes)?;
        }
        if let Some(bytes) = &self.checksum_signature {
            write_evidence(&checksum_bundle_path(&retained.checksum), bytes)?;
        }
        Ok(retained)
    }

    /// Authenticate selected bytes without creating a snapshot or cache entry.
    pub fn verify_selected_artifacts(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
    ) -> Result<(), GuestRuntimeError> {
        let declaration = self.declaration(selection.arch)?;
        validate_selection(declaration, selection)?;
        for (path, expected) in [
            (selection.overlay, &declaration.overlay_sha256),
            (selection.overlay_verity, &declaration.overlay_verity_sha256),
            (selection.initramfs, &declaration.initramfs_sha256),
        ] {
            hash_artifact(path, expected, &mut std::io::sink())?;
        }
        Ok(())
    }

    pub fn declaration(&self, arch: GuestArch) -> Result<&RuntimeAssembly, GuestRuntimeError> {
        if arch != self.arch {
            return Err(GuestRuntimeError::Cache(
                "runtime evidence architecture mismatch".into(),
            ));
        }
        self.manifest
            .assemblies
            .get(&arch)
            .ok_or_else(|| GuestRuntimeError::MissingRequired(format!("assembly for {arch}")))
    }

    /// Copies and hashes the same read stream into private snapshots. Original
    /// paths are never returned as authenticated artifact paths.
    pub fn snapshot_artifacts(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
    ) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
        self.snapshot_artifacts_at(selection, None)
    }

    /// Creates a fresh generation under a caller-owned private parent. The
    /// parent must already exist; no cache or prior generation is reused.
    pub fn snapshot_artifacts_in(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
        private_parent: &Path,
    ) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
        self.snapshot_artifacts_at(selection, Some(private_parent))
    }

    fn snapshot_artifacts_at(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
        private_parent: Option<&Path>,
    ) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
        snapshot_declared_artifacts(
            &self.digest,
            self.declaration(selection.arch)?,
            selection,
            private_parent,
        )
    }
}

/// Shared byte ownership mechanism; the caller supplies already checked
/// declarations, with release authentication or explicit developer trust.
#[tracing::instrument(skip_all)]
pub(super) fn snapshot_declared_artifacts(
    digest: &str,
    declaration: &RuntimeAssembly,
    selection: &RuntimeArtifactSelection<'_>,
    private_parent: Option<&Path>,
) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
    if let Some(parent) = private_parent {
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(GuestRuntimeError::Cache(
                "runtime snapshot parent must be a non-symlink directory".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if parent_metadata.permissions().mode() & 0o077 != 0 {
                return Err(GuestRuntimeError::Cache(
                    "runtime snapshot parent must not grant group or other access".into(),
                ));
            }
        }
    }
    validate_selection(declaration, selection)?;
    let mut builder = tempfile::Builder::new();
    builder.prefix("runtime-");
    let directory = match private_parent {
        Some(parent) => builder.tempdir_in(parent)?,
        None => builder.tempdir()?,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let overlay = directory.path().join("overlay.ext4");
    let verity = directory.path().join("overlay.verity");
    let initramfs = directory.path().join("initramfs.cpio.gz");
    for (source, destination, expected) in [
        (selection.overlay, &overlay, &declaration.overlay_sha256),
        (
            selection.overlay_verity,
            &verity,
            &declaration.overlay_verity_sha256,
        ),
        (
            selection.initramfs,
            &initramfs,
            &declaration.initramfs_sha256,
        ),
    ] {
        snapshot_file(source, destination, expected)?;
    }
    Ok(VerifiedRuntimeArtifacts {
        directory,
        archive_sha256: digest.to_owned(),
        declaration: declaration.clone(),
    })
}

fn validate_selection(
    declaration: &RuntimeAssembly,
    selection: &RuntimeArtifactSelection<'_>,
) -> Result<(), GuestRuntimeError> {
    declaration.validate(selection.arch)?;
    if declaration.protocol_version < selection.minimum_protocol
        || declaration.min_supported_protocol_version > selection.host_protocol
        || selection.overlay_roothash != declaration.overlay_roothash
    {
        return Err(GuestRuntimeError::Cache(
            "selected runtime protocol or overlay root does not match its checked declaration"
                .into(),
        ));
    }
    Ok(())
}

/// Selected boot artifacts, not cache labels or claimed verification flags.
#[derive(Debug)]
pub struct RuntimeArtifactSelection<'a> {
    pub arch: GuestArch,
    pub overlay: &'a Path,
    pub overlay_verity: &'a Path,
    pub overlay_roothash: &'a str,
    pub initramfs: &'a Path,
    pub minimum_protocol: u32,
    pub host_protocol: u32,
}

/// Owns copied bytes matching a checked declaration. Authentication depends on
/// the issuing release/source evidence, not this shared byte owner. Not yet a boot
/// capability: dropping this owner removes its files, so detached launch must
/// transfer ownership to a durable, generation-scoped lifecycle before use.
#[derive(Debug)]
pub struct VerifiedRuntimeArtifacts {
    directory: tempfile::TempDir,
    archive_sha256: String,
    declaration: RuntimeAssembly,
}

impl VerifiedRuntimeArtifacts {
    pub fn directory_path(&self) -> &Path {
        self.directory.path()
    }

    pub fn overlay_path(&self) -> PathBuf {
        self.directory.path().join("overlay.ext4")
    }

    pub fn overlay_verity_path(&self) -> PathBuf {
        self.directory.path().join("overlay.verity")
    }

    pub fn initramfs_path(&self) -> PathBuf {
        self.directory.path().join("initramfs.cpio.gz")
    }

    pub fn declaration(&self) -> &RuntimeAssembly {
        &self.declaration
    }

    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    /// Transfer deletion responsibility to the launch lifecycle, without moving
    /// or recopying any artifact. Failure keeps RAII cleanup in force.
    pub fn persist(self) -> Result<PersistedRuntimeArtifacts, GuestRuntimeError> {
        for path in [
            self.overlay_path(),
            self.overlay_verity_path(),
            self.initramfs_path(),
        ] {
            std::fs::File::open(path)?.sync_all()?;
        }
        std::fs::File::open(self.directory.path())?.sync_all()?;
        if let Some(parent) = self.directory.path().parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(PersistedRuntimeArtifacts {
            directory: self.directory.keep(),
            archive_sha256: self.archive_sha256,
            declaration: self.declaration,
        })
    }
}

/// Durable verified generation with no automatic deletion. This does not prove
/// execution or grant permission to delete: the lifecycle must bind these paths
/// to its supervisor generation and prove termination before cleanup.
#[derive(Debug)]
pub struct PersistedRuntimeArtifacts {
    directory: PathBuf,
    archive_sha256: String,
    declaration: RuntimeAssembly,
}

impl PersistedRuntimeArtifacts {
    pub fn directory_path(&self) -> &Path {
        &self.directory
    }

    pub fn overlay_path(&self) -> PathBuf {
        self.directory.join("overlay.ext4")
    }

    pub fn overlay_verity_path(&self) -> PathBuf {
        self.directory.join("overlay.verity")
    }

    pub fn initramfs_path(&self) -> PathBuf {
        self.directory.join("initramfs.cpio.gz")
    }

    pub fn declaration(&self) -> &RuntimeAssembly {
        &self.declaration
    }

    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }
}

pub fn verify_runtime_release_proof(
    proof: &RuntimeReleaseProof,
    expected_version: &str,
    expected_arch: GuestArch,
) -> Result<VerifiedRuntimeManifest, GuestRuntimeError> {
    if proof.arch != expected_arch
        || proof.version != expected_version
        || !super::is_archive_digest(&proof.archive_sha256)
    {
        return Err(GuestRuntimeError::Cache(
            "runtime proof does not match the selected version and guest architecture".into(),
        ));
    }
    let verified = verify_release_archive(
        &proof.archive,
        &proof.checksum,
        &proof.signature_bundle,
        expected_version,
        expected_arch,
    )?;
    if verified.digest != proof.archive_sha256 {
        return Err(GuestRuntimeError::Cache(
            "runtime proof archive digest changed".into(),
        ));
    }
    verified
        .declaration(expected_arch)?
        .validate(expected_arch)?;
    Ok(verified)
}

pub(super) fn verify_release_archive(
    archive: &Path,
    checksum: &Path,
    bundle: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<VerifiedRuntimeManifest, GuestRuntimeError> {
    let asset = crate::guest_bins::guest_bins_archive_name(version);
    let bytes = std::fs::read(archive)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let checksum_bytes = std::fs::read(checksum)?;
    let checksum_bundle = checksum_bundle_path(checksum);
    // Legacy offline packages carry only the archive signature, which already
    // authenticates its bytes. A present standalone checksum signature must
    // still verify; portable acquisition separately requires that fourth file.
    let checksum_signature = if checksum_bundle_present(&checksum_bundle)? {
        let signature = std::fs::read(&checksum_bundle)?;
        verify_checksum_signature_bytes(&checksum_bytes, &signature, version)?;
        Some(signature)
    } else {
        None
    };
    let checksums = mvm_fs::overlay::parse_checksums_manifest(
        std::str::from_utf8(&checksum_bytes)
            .map_err(|error| GuestRuntimeError::Cache(error.to_string()))?,
    );
    if checksums.get(&asset) != Some(&digest) {
        return Err(GuestRuntimeError::Cache(format!(
            "guest runtime checksum missing or mismatched for {asset}"
        )));
    }
    let signature = std::fs::read(bundle)?;
    crate::release_signature::verify_release_archive_bytes(
        &bytes,
        &signature,
        &asset,
        &mvm_core::release_trust::accepted_release_identities(version),
        mvm_core::release_trust::RELEASE_OIDC_ISSUER,
    )?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    snapshot.write_all(&bytes)?;
    snapshot.flush()?;
    let manifest = crate::guest_bins::verify_guest_bins_archive(snapshot.path())?;
    super::validate_release_guest_runtime_manifest(&manifest, version)?;
    Ok(VerifiedRuntimeManifest {
        archive: snapshot,
        checksum: checksum_bytes,
        signature,
        checksum_signature,
        version: version.to_owned(),
        digest,
        manifest,
        arch,
    })
}

/// Locate a checksum's signature by appending `.bundle` to its complete path.
/// Portable packages may rename checksum files; replacing the extension would
/// silently select a different sibling for names other than `.sha256`.
pub fn checksum_bundle_path(checksum: &Path) -> PathBuf {
    let mut path = checksum.as_os_str().to_os_string();
    path.push(".bundle");
    PathBuf::from(path)
}

pub(super) fn checksum_bundle_present(path: &Path) -> Result<bool, GuestRuntimeError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn verify_checksum_signature(
    checksum_bytes: &[u8],
    bundle: &Path,
    version: &str,
) -> Result<(), GuestRuntimeError> {
    verify_checksum_signature_bytes(checksum_bytes, &std::fs::read(bundle)?, version)
}

fn verify_checksum_signature_bytes(
    checksum_bytes: &[u8],
    bundle: &[u8],
    version: &str,
) -> Result<(), GuestRuntimeError> {
    crate::release_signature::verify_release_archive_bytes(
        checksum_bytes,
        bundle,
        &format!(
            "{}.sha256",
            crate::guest_bins::guest_bins_archive_name(version)
        ),
        &mvm_core::release_trust::accepted_release_identities(version),
        mvm_core::release_trust::RELEASE_OIDC_ISSUER,
    )?;
    Ok(())
}

fn snapshot_file(
    source: &Path,
    destination: &Path,
    expected: &str,
) -> Result<(), GuestRuntimeError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    hash_artifact(source, expected, &mut output)?;
    output.flush()?;
    let mut permissions = output.metadata()?.permissions();
    permissions.set_readonly(true);
    output.set_permissions(permissions)?;
    output.sync_all()?;
    Ok(())
}

fn write_evidence(path: &Path, bytes: &[u8]) -> Result<(), GuestRuntimeError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    let mut permissions = output.metadata()?.permissions();
    permissions.set_readonly(true);
    output.set_permissions(permissions)?;
    output.sync_all()?;
    Ok(())
}

fn hash_artifact(
    source: &Path,
    expected: &str,
    output: &mut impl Write,
) -> Result<(), GuestRuntimeError> {
    let mut input_options = std::fs::OpenOptions::new();
    input_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        input_options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut input = input_options.open(source)?;
    if !input.metadata()?.is_file() {
        return Err(GuestRuntimeError::Cache(
            "runtime artifact is not a regular file".into(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > 1024 * 1024 * 1024 {
            return Err(GuestRuntimeError::Cache(
                "runtime artifact exceeds size limit".into(),
            ));
        }
        hasher.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    output.flush()?;
    if hex::encode(hasher.finalize()) != expected {
        return Err(GuestRuntimeError::Cache(
            "runtime artifact differs from signed assembly".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn checksum_signature_path_appends_without_replacing_extensions() {
        for name in ["runtime.tar.gz.sha256", "proof.txt", "checksum"] {
            assert_eq!(
                checksum_bundle_path(Path::new(name)),
                PathBuf::from(format!("{name}.bundle")),
            );
        }
    }

    #[test]
    fn renamed_checksum_cannot_hide_an_invalid_present_signature() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive");
        let checksum = dir.path().join("proof.txt");
        let bytes = b"archive bytes";
        std::fs::write(&archive, bytes).unwrap();
        std::fs::write(
            &checksum,
            format!(
                "{}  {}\n",
                hex::encode(Sha256::digest(bytes)),
                crate::guest_bins::guest_bins_archive_name("1.2.3")
            ),
        )
        .unwrap();
        std::fs::write(checksum_bundle_path(&checksum), b"invalid signature").unwrap();
        let error = verify_release_archive(
            &archive,
            &checksum,
            &dir.path().join("absent-archive.bundle"),
            "1.2.3",
            GuestArch::X86_64,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                GuestRuntimeError::Release(
                    crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
                )
            ),
            "present checksum signature must be checked before reading the archive bundle: {error}"
        );
    }

    fn fixture() -> (tempfile::TempDir, VerifiedRuntimeManifest) {
        let dir = tempfile::tempdir().unwrap();
        for name in ["overlay", "verity", "initramfs"] {
            std::fs::write(dir.path().join(name), name).unwrap();
        }
        let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let declaration = RuntimeAssembly {
            assembly_format: crate::guest_bins::assembly::RUNTIME_ASSEMBLY_FORMAT,
            arch: GuestArch::X86_64,
            protocol_version: 2,
            min_supported_protocol_version: 2,
            overlay_sha256: digest(b"overlay"),
            overlay_verity_sha256: digest(b"verity"),
            overlay_roothash: "a".repeat(64),
            initramfs_sha256: digest(b"initramfs"),
        };
        let verified = VerifiedRuntimeManifest {
            archive: tempfile::NamedTempFile::new().unwrap(),
            checksum: Vec::new(),
            signature: Vec::new(),
            checksum_signature: None,
            version: "fixture".into(),
            digest: "d".repeat(64),
            arch: GuestArch::X86_64,
            manifest: GuestBinsManifest {
                schema_version: crate::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
                version: "1.2.3".into(),
                guest_source_fingerprint: "a".repeat(64),
                sdk_cdylib_source_fingerprint: "b".repeat(64),
                source: crate::image_source::RepoIdentity {
                    commit: mvm_core::image_set::GitCommit::new("c".repeat(40)).unwrap(),
                    worktree: mvm_core::image_set::WorktreeState::Clean,
                },
                files: BTreeMap::new(),
                assemblies: BTreeMap::from([(GuestArch::X86_64, declaration)]),
            },
        };
        (dir, verified)
    }

    fn selection<'a>(paths: &'a [PathBuf; 3], root: &'a str) -> RuntimeArtifactSelection<'a> {
        RuntimeArtifactSelection {
            arch: GuestArch::X86_64,
            overlay: &paths[0],
            overlay_verity: &paths[1],
            initramfs: &paths[2],
            overlay_roothash: root,
            minimum_protocol: 2,
            host_protocol: 2,
        }
    }

    #[test]
    fn selected_artifact_verification_is_snapshot_free_and_checks_every_byte() {
        let (dir, verified) = fixture();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        verified
            .verify_selected_artifacts(&selection(&paths, &root))
            .unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
        for path in &paths {
            let original = std::fs::read(path).unwrap();
            std::fs::write(path, b"substituted").unwrap();
            assert!(
                verified
                    .verify_selected_artifacts(&selection(&paths, &root))
                    .is_err()
            );
            std::fs::write(path, original).unwrap();
        }
        let wrong_root = "b".repeat(64);
        assert!(
            verified
                .verify_selected_artifacts(&selection(&paths, &wrong_root))
                .is_err()
        );
        let mut selected = selection(&paths, &root);
        selected.minimum_protocol = 3;
        assert!(verified.verify_selected_artifacts(&selected).is_err());
        selected.minimum_protocol = 2;
        selected.host_protocol = 1;
        assert!(verified.verify_selected_artifacts(&selected).is_err());
        selected.host_protocol = 2;
        selected.arch = GuestArch::Aarch64;
        assert!(verified.verify_selected_artifacts(&selected).is_err());
    }

    #[test]
    fn snapshots_own_the_verified_bytes_not_mutable_cache_paths() {
        let (dir, verified) = fixture();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        let snapshot = verified
            .snapshot_artifacts(&selection(&paths, &root))
            .unwrap();
        for path in &paths {
            std::fs::write(path, b"replacement").unwrap();
        }
        assert_eq!(std::fs::read(snapshot.overlay_path()).unwrap(), b"overlay");
        assert_eq!(
            std::fs::read(snapshot.overlay_verity_path()).unwrap(),
            b"verity"
        );
        assert_eq!(
            std::fs::read(snapshot.initramfs_path()).unwrap(),
            b"initramfs"
        );
        assert_eq!(snapshot.archive_sha256(), verified.archive_sha256());
        let owned_path = snapshot.overlay_path();
        drop(snapshot);
        assert!(!owned_path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn private_generations_are_unique_and_persist_without_moving_or_deleting() {
        let (dir, verified) = fixture();
        let parent = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        let selected = selection(&paths, &root);
        let first = verified
            .snapshot_artifacts_in(&selected, parent.path())
            .unwrap();
        let second = verified
            .snapshot_artifacts_in(&selected, parent.path())
            .unwrap();
        assert_eq!(first.directory_path().parent(), Some(parent.path()));
        assert_ne!(first.directory_path(), second.directory_path());
        let first_path = first.directory_path().to_path_buf();
        let second_path = second.directory_path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            let inode = std::fs::metadata(first.overlay_path()).unwrap().ino();
            let persisted = first.persist().unwrap();
            assert_eq!(persisted.directory_path(), first_path);
            assert_eq!(
                std::fs::metadata(persisted.overlay_path()).unwrap().ino(),
                inode
            );
            assert_eq!(persisted.archive_sha256(), verified.archive_sha256());
            assert_eq!(
                persisted.declaration(),
                verified.declaration(GuestArch::X86_64).unwrap()
            );
            assert_eq!(
                std::fs::read(persisted.overlay_verity_path()).unwrap(),
                b"verity"
            );
            assert_eq!(
                std::fs::read(persisted.initramfs_path()).unwrap(),
                b"initramfs"
            );
            drop(persisted);
            assert!(
                first_path.exists(),
                "persisted generation has no deleting Drop"
            );
        }
        drop(second);
        assert!(
            !second_path.exists(),
            "unpersisted generation retains RAII cleanup"
        );
    }

    #[test]
    #[cfg(unix)]
    fn failed_persistence_cleans_only_its_own_unpublished_generation() {
        let (dir, verified) = fixture();
        let parent = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        let selected = selection(&paths, &root);
        let snapshot = verified
            .snapshot_artifacts_in(&selected, parent.path())
            .unwrap();
        let generation = snapshot.directory_path().to_path_buf();
        std::fs::remove_file(snapshot.initramfs_path()).unwrap();
        assert!(snapshot.persist().is_err());
        assert!(!generation.exists());
        assert!(parent.path().is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn generation_parent_cannot_be_a_symlink() {
        let (dir, verified) = fixture();
        let parent = tempfile::tempdir().unwrap();
        let link = dir.path().join("linked-parent");
        std::os::unix::fs::symlink(parent.path(), &link).unwrap();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        assert!(
            verified
                .snapshot_artifacts_in(&selection(&paths, &root), &link)
                .is_err()
        );
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn generation_parent_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, verified) = fixture();
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        assert!(
            verified
                .snapshot_artifacts_in(&selection(&paths, &root), parent.path())
                .is_err()
        );
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }

    #[test]
    fn changed_or_missing_artifacts_wrong_arch_protocol_and_root_are_refused() {
        for index in 0..3 {
            let (dir, verified) = fixture();
            let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
            let root = "a".repeat(64);
            std::fs::write(&paths[index], b"replacement").unwrap();
            assert!(
                verified
                    .snapshot_artifacts(&selection(&paths, &root))
                    .is_err()
            );
            std::fs::remove_file(&paths[index]).unwrap();
            assert!(
                verified
                    .snapshot_artifacts(&selection(&paths, &root))
                    .is_err()
            );
        }
        let (dir, verified) = fixture();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        let mut selected = selection(&paths, &root);
        selected.arch = GuestArch::Aarch64;
        assert!(verified.snapshot_artifacts(&selected).is_err());
        selected.arch = GuestArch::X86_64;
        selected.minimum_protocol = 3;
        assert!(verified.snapshot_artifacts(&selected).is_err());
        selected.minimum_protocol = 2;
        selected.host_protocol = 1;
        assert!(verified.snapshot_artifacts(&selected).is_err());
        selected.host_protocol = 2;
        let wrong_root = "b".repeat(64);
        selected.overlay_roothash = &wrong_root;
        assert!(verified.snapshot_artifacts(&selected).is_err());
    }

    #[test]
    fn deserialized_proof_is_not_authority_and_does_not_accept_verified_flag() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive");
        std::fs::write(&archive, b"unsigned").unwrap();
        let digest = hex::encode(Sha256::digest(b"unsigned"));
        let checksum = dir.path().join("checksum");
        std::fs::write(
            &checksum,
            format!("{digest}  mvm-guest-bins-v1.2.3.tar.gz\n"),
        )
        .unwrap();
        let bundle = dir.path().join("bundle");
        std::fs::write(&bundle, b"{}").unwrap();
        let proof = RuntimeReleaseProof {
            archive,
            checksum,
            signature_bundle: bundle,
            archive_sha256: digest,
            version: "1.2.3".into(),
            arch: GuestArch::X86_64,
        };
        let mut json = serde_json::to_value(&proof).unwrap();
        let decoded: RuntimeReleaseProof = serde_json::from_value(json.clone()).unwrap();
        assert!(verify_runtime_release_proof(&decoded, "1.2.3", GuestArch::X86_64).is_err());
        assert!(verify_runtime_release_proof(&decoded, "1.2.3", GuestArch::Aarch64).is_err());
        assert!(verify_runtime_release_proof(&decoded, "1.2.4", GuestArch::X86_64).is_err());
        json["verified"] = true.into();
        assert!(serde_json::from_value::<RuntimeReleaseProof>(json).is_err());
    }

    #[test]
    #[ignore = "manual copy/hash timing; not a prepared-launch benchmark"]
    fn artifact_snapshot_hash_budget() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let bytes = vec![0x5a; 128 * 1024 * 1024];
        let digest = hex::encode(Sha256::digest(&bytes));
        std::fs::write(&source, bytes).unwrap();
        let started = std::time::Instant::now();
        snapshot_file(&source, &dir.path().join("snapshot"), &digest).unwrap();
        eprintln!("128 MiB copy+SHA256: {:?}", started.elapsed());
    }
}
