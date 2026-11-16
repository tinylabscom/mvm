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
#[derive(Debug, Clone)]
pub struct VerifiedRuntimeManifest {
    archive: std::sync::Arc<tempfile::NamedTempFile>,
    checksum: Vec<u8>,
    signature: Vec<u8>,
    checksum_signature: Option<Vec<u8>>,
    version: String,
    digest: String,
    manifest: GuestBinsManifest,
    arch: GuestArch,
    signer: mvm_core::crypto::image_verify::VerifiedSigner,
}

/// Launch-owned authentication of a release proof and its exact archive snapshot.
///
/// This value cannot be reconstructed from a serialized proof. Keep it alive until
/// the launch lifecycle retains the verified archive in its durable generation.
#[derive(Debug)]
pub struct VerifiedReleaseRuntime {
    proof: RuntimeReleaseProof,
    manifest: VerifiedRuntimeManifest,
}

impl VerifiedReleaseRuntime {
    pub(super) fn from_verified(
        proof: RuntimeReleaseProof,
        manifest: VerifiedRuntimeManifest,
    ) -> Self {
        Self { proof, manifest }
    }

    pub fn proof(&self) -> &RuntimeReleaseProof {
        &self.proof
    }

    pub fn manifest(&self) -> &VerifiedRuntimeManifest {
        &self.manifest
    }

    /// Verified archive signer identity and issuer required by the verifier.
    pub fn signer(&self) -> &mvm_core::crypto::image_verify::VerifiedSigner {
        self.manifest.signer()
    }
}

/// Authenticate a path-based proof and retain the checked archive for this launch.
pub fn verify_release_runtime(
    proof: RuntimeReleaseProof,
    expected_version: &str,
    expected_arch: GuestArch,
) -> Result<VerifiedReleaseRuntime, GuestRuntimeError> {
    let manifest = verify_runtime_release_proof(&proof, expected_version, expected_arch)?;
    Ok(VerifiedReleaseRuntime { proof, manifest })
}

impl VerifiedRuntimeManifest {
    pub fn signer(&self) -> &mvm_core::crypto::image_verify::VerifiedSigner {
        &self.signer
    }

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
    #[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
pub(super) fn verify_release_archive(
    archive: &Path,
    checksum: &Path,
    bundle: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<VerifiedRuntimeManifest, GuestRuntimeError> {
    let asset = crate::guest_bins::guest_bins_archive_name(version);
    let (bytes, digest) = read_and_digest_archive(archive)?;
    let checksum_bytes = std::fs::read(checksum)?;
    let checksum_bundle = checksum_bundle_path(checksum);
    // The archive's signature is read here, once, and these are the bytes the
    // verification below uses, so what is remembered is exactly what was
    // checked. An unreadable bundle skips the memo and fails where it always
    // did, after a present checksum signature has been held to its own check.
    let signature_bytes = std::fs::read(bundle).ok();
    let checksum_signature_bytes = std::fs::read(&checksum_bundle).ok();
    let key = signature_bytes.as_ref().map(|signature| {
        launch_scope::Key::new(
            &digest,
            &checksum_bytes,
            checksum_signature_bytes.as_deref(),
            signature.clone(),
            version,
            arch,
        )
    });
    if let Some(shared) = key.as_ref().and_then(launch_scope::recall) {
        return Ok(shared);
    }
    #[cfg(test)]
    RELEASE_ARCHIVE_VERIFICATIONS.with(|calls| calls.set(calls.get() + 1));
    // Legacy offline packages carry only the archive signature, which already
    // authenticates its bytes. A present standalone checksum signature must
    // still verify; portable acquisition separately requires that fourth file.
    let checksum_signature = if checksum_bundle_present(&checksum_bundle)? {
        let signature = match checksum_signature_bytes {
            Some(signature) => signature,
            None => std::fs::read(&checksum_bundle)?,
        };
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
    let signature = match signature_bytes {
        Some(signature) => signature,
        None => std::fs::read(bundle)?,
    };
    let signer = crate::release_signature::verify_release_archive_bytes_with_signer(
        &bytes,
        &signature,
        &asset,
        &mvm_core::release_trust::accepted_release_identities(version),
        mvm_core::release_trust::RELEASE_OIDC_ISSUER,
    )?;
    let snapshot = write_archive_snapshot(&bytes)?;
    let manifest = crate::guest_bins::verify_guest_bins_archive(snapshot.path())?;
    super::validate_release_guest_runtime_manifest(&manifest, version)?;
    let verified = VerifiedRuntimeManifest {
        archive: std::sync::Arc::new(snapshot),
        checksum: checksum_bytes,
        signature,
        checksum_signature,
        version: version.to_owned(),
        digest,
        manifest,
        arch,
        signer,
    };
    if let Some(key) = key {
        launch_scope::remember(key, &verified);
    }
    Ok(verified)
}

#[cfg(test)]
thread_local! {
    static RELEASE_ARCHIVE_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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

#[tracing::instrument(skip_all)]
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

/// Read the archive once and digest the bytes that were read.
#[tracing::instrument(skip_all)]
fn read_and_digest_archive(archive: &Path) -> Result<(Vec<u8>, String), GuestRuntimeError> {
    let bytes = std::fs::read(archive)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, digest))
}

/// Write the authenticated bytes to a private temporary file, the copy the
/// member check and any later retention read from.
#[tracing::instrument(skip_all)]
fn write_archive_snapshot(bytes: &[u8]) -> Result<tempfile::NamedTempFile, GuestRuntimeError> {
    let mut snapshot = tempfile::NamedTempFile::new()?;
    snapshot.write_all(bytes)?;
    snapshot.flush()?;
    Ok(snapshot)
}

/// The durability barrier for one snapshot, apart from the copy so its cost
/// is measured on its own. On macOS this empties the drive cache.
#[tracing::instrument(skip_all)]
fn sync_snapshot(output: &std::fs::File) -> std::io::Result<()> {
    output.sync_all()
}

#[tracing::instrument(skip_all, fields(artifact = snapshot_name(destination)))]
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
    sync_snapshot(&output)?;
    Ok(())
}

/// The snapshot's own file name: a fixed artifact name, never a caller path.
fn snapshot_name(destination: &Path) -> &str {
    destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unnamed")
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

    #[test]
    fn the_archive_digest_is_of_the_bytes_that_were_read() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive");
        std::fs::write(&archive, b"archive bytes").unwrap();
        let (bytes, digest) = read_and_digest_archive(&archive).unwrap();
        assert_eq!(bytes, b"archive bytes");
        assert_eq!(digest, hex::encode(Sha256::digest(b"archive bytes")));
        assert!(read_and_digest_archive(&dir.path().join("absent")).is_err());
    }

    #[test]
    fn the_archive_snapshot_holds_exactly_the_given_bytes() {
        let snapshot = write_archive_snapshot(b"verified bytes").unwrap();
        assert_eq!(std::fs::read(snapshot.path()).unwrap(), b"verified bytes");
    }

    #[test]
    fn a_snapshot_is_named_by_its_file_and_never_by_its_directory() {
        assert_eq!(
            snapshot_name(Path::new("/private/vm/runtime-1/overlay.ext4")),
            "overlay.ext4"
        );
        assert_eq!(snapshot_name(Path::new("/")), "unnamed");
    }

    #[test]
    fn syncing_a_snapshot_succeeds_on_an_open_file() {
        let file = tempfile::tempfile().unwrap();
        sync_snapshot(&file).unwrap();
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
            archive: std::sync::Arc::new(tempfile::NamedTempFile::new().unwrap()),
            checksum: Vec::new(),
            signature: Vec::new(),
            checksum_signature: None,
            version: "fixture".into(),
            digest: "d".repeat(64),
            arch: GuestArch::X86_64,
            signer: mvm_core::crypto::image_verify::VerifiedSigner {
                identity: "unsigned test fixture".into(),
                issuer: "unsigned test fixture".into(),
            },
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
    fn launch_handle_keeps_verified_archive_bytes_after_cache_refresh() {
        let (dir, mut verified) = fixture();
        (&*verified.archive).write_all(b"verified archive").unwrap();
        (&*verified.archive).flush().unwrap();
        verified.digest = hex::encode(Sha256::digest(b"verified archive"));
        let archive = dir.path().join("archive");
        std::fs::write(&archive, b"verified archive").unwrap();
        let proof = RuntimeReleaseProof {
            archive: archive.clone(),
            checksum: dir.path().join("checksum"),
            signature_bundle: dir.path().join("signature"),
            archive_sha256: verified.archive_sha256().to_owned(),
            version: "fixture".into(),
            arch: GuestArch::X86_64,
        };
        let launch = VerifiedReleaseRuntime::from_verified(proof, verified);
        std::fs::write(&archive, b"concurrent cache refresh").unwrap();
        assert_eq!(
            std::fs::read(launch.manifest().archive_path()).unwrap(),
            b"verified archive"
        );
        assert_eq!(launch.proof().archive, archive);
        assert_eq!(
            launch
                .manifest()
                .declaration(GuestArch::X86_64)
                .unwrap()
                .overlay_roothash,
            "a".repeat(64)
        );
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    #[ignore = "requires MVM_SIGNED_RUNTIME_FIXTURE_DIR with the published v0.28.0-rc.2 quartet"]
    fn signed_release_verification_is_once_per_launch_and_refuses_tampering() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("MVM_SIGNED_RUNTIME_FIXTURE_DIR")
                .expect("set MVM_SIGNED_RUNTIME_FIXTURE_DIR to the published release quartet"),
        );
        let asset = "mvm-guest-bins-v0.28.0-rc.2.tar.gz";
        let proof = RuntimeReleaseProof {
            archive: directory.join(asset),
            checksum: directory.join(format!("{asset}.sha256")),
            signature_bundle: directory.join(format!("{asset}.bundle")),
            archive_sha256: "8a36fae9e7444f92b3beaa1ed7d78c68003ea2f8d2d72320361cfa906a829921"
                .into(),
            version: "0.28.0-rc.2".into(),
            arch: GuestArch::host(),
        };
        let before = RELEASE_ARCHIVE_VERIFICATIONS.with(std::cell::Cell::get);
        for launch in 1..=2 {
            let runtime = verify_release_runtime(proof.clone(), &proof.version, proof.arch)
                .expect("signed release");
            assert_eq!(runtime.manifest().archive_sha256(), proof.archive_sha256);
            for _ in 0..5 {
                runtime
                    .manifest()
                    .declaration(proof.arch)
                    .expect("same authenticated declaration");
            }
            assert_eq!(
                RELEASE_ARCHIVE_VERIFICATIONS.with(std::cell::Cell::get) - before,
                launch,
                "one archive and signature verification per launch"
            );
        }

        let scope = LaunchProofScope::begin();
        let before = RELEASE_ARCHIVE_VERIFICATIONS.with(std::cell::Cell::get);
        for _ in 0..7 {
            verify_release_runtime(proof.clone(), &proof.version, proof.arch)
                .expect("signed release inside one launch scope");
        }
        assert_eq!(
            RELEASE_ARCHIVE_VERIFICATIONS.with(std::cell::Cell::get) - before,
            1,
            "seven asks inside one launch scope verify once"
        );
        drop(scope);

        let scratch = tempfile::tempdir().expect("tampered archive directory");
        let mut edited = std::fs::read(&proof.archive).expect("published archive");
        edited[0] ^= 1;
        let tampered_archive = scratch.path().join(asset);
        std::fs::write(&tampered_archive, edited).expect("write tampered archive");
        let tampered = RuntimeReleaseProof {
            archive: tampered_archive,
            ..proof
        };
        let error = verify_release_runtime(tampered, "0.28.0-rc.2", GuestArch::host())
            .expect_err("a modified archive must not become a launch handle");
        assert!(error.to_string().contains("checksum"));
    }

    #[test]
    fn a_launch_scope_shares_one_verification_among_steps_that_read_the_same_bytes() {
        let (_dir, verified) = fixture();
        let key = |archive: &str, version: &str| {
            launch_scope::Key::new(
                archive,
                b"sums",
                Some(b"sums-sig"),
                b"sig".to_vec(),
                version,
                GuestArch::X86_64,
            )
        };
        // No scope: nothing is remembered, so every step verifies in full.
        launch_scope::remember(key("a", "1"), &verified);
        assert!(launch_scope::recall(&key("a", "1")).is_none());

        let scope = LaunchProofScope::begin();
        launch_scope::remember(key("a", "1"), &verified);
        assert!(launch_scope::recall(&key("a", "1")).is_some());
        // One byte of anything the verification read is a different question.
        assert!(launch_scope::recall(&key("b", "1")).is_none());
        assert!(launch_scope::recall(&key("a", "2")).is_none());
        let other_signature = launch_scope::Key::new(
            "a",
            b"sums",
            Some(b"sums-sig"),
            b"sig2".to_vec(),
            "1",
            GuestArch::X86_64,
        );
        assert!(launch_scope::recall(&other_signature).is_none());
        let other_arch = launch_scope::Key::new(
            "a",
            b"sums",
            Some(b"sums-sig"),
            b"sig".to_vec(),
            "1",
            GuestArch::Aarch64,
        );
        assert!(launch_scope::recall(&other_arch).is_none());

        // A scope begun inside another is inert and closes nothing.
        drop(LaunchProofScope::begin());
        assert!(launch_scope::recall(&key("a", "1")).is_some());

        // The next launch starts with nothing remembered.
        drop(scope);
        assert!(launch_scope::recall(&key("a", "1")).is_none());
        let _next = LaunchProofScope::begin();
        assert!(launch_scope::recall(&key("a", "1")).is_none());
    }

    #[test]
    fn a_launch_scope_does_not_reach_another_thread() {
        let (_dir, verified) = fixture();
        let key = launch_scope::Key::new("a", b"s", None, b"g".to_vec(), "1", GuestArch::X86_64);
        let _scope = LaunchProofScope::begin();
        launch_scope::remember(key, &verified);
        std::thread::spawn(|| {
            let key =
                launch_scope::Key::new("a", b"s", None, b"g".to_vec(), "1", GuestArch::X86_64);
            assert!(launch_scope::recall(&key).is_none());
        })
        .join()
        .unwrap();
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

pub use launch_scope::LaunchProofScope;

/// What one launch shares between the steps that each ask whether the signed
/// runtime release is authentic.
///
/// A launch asks that question several times (admission, overlay, initramfs,
/// dispatch, lifecycle bind), and each ask re-reads and re-verifies the whole
/// archive. Within one launch scope a successful verification is remembered
/// under the content of everything it consumed, so the next ask over the same
/// bytes returns the same result instead of repeating the work. Nothing here
/// outlives the scope, nothing is written to disk, a failure is never
/// remembered, and a call whose archive, checksum, signature, version or
/// architecture differs by a single byte finds no entry and verifies in full.
mod launch_scope {
    use super::{GuestArch, VerifiedRuntimeManifest};
    use std::cell::RefCell;

    /// Everything a verification read, by content.
    #[derive(PartialEq, Eq)]
    pub(super) struct Key {
        archive_digest: String,
        checksum: Vec<u8>,
        checksum_signature: Option<Vec<u8>>,
        signature: Vec<u8>,
        version: String,
        arch: GuestArch,
    }

    impl Key {
        pub(super) fn new(
            archive_digest: &str,
            checksum: &[u8],
            checksum_signature: Option<&[u8]>,
            signature: Vec<u8>,
            version: &str,
            arch: GuestArch,
        ) -> Self {
            Self {
                archive_digest: archive_digest.to_owned(),
                checksum: checksum.to_vec(),
                checksum_signature: checksum_signature.map(<[u8]>::to_vec),
                signature,
                version: version.to_owned(),
                arch,
            }
        }
    }

    thread_local! {
        static SCOPE: RefCell<Option<Vec<(Key, VerifiedRuntimeManifest)>>> =
            const { RefCell::new(None) };
    }

    /// Open while one launch runs on this thread. Not `Send`: the memory it
    /// guards is the thread's, so it cannot be carried to another thread or
    /// held across a task that may move. A launch step on a thread with no
    /// scope simply verifies in full.
    #[must_use = "the scope ends when this is dropped"]
    pub struct LaunchProofScope {
        owner: bool,
        _not_send: std::marker::PhantomData<*const ()>,
    }

    impl LaunchProofScope {
        /// Begin a launch's scope. Inside an already open scope this is inert
        /// and ends nothing, so a launch that starts another launch's steps
        /// never extends or closes its caller's.
        pub fn begin() -> Self {
            let owner = SCOPE.with(|scope| {
                let mut scope = scope.borrow_mut();
                if scope.is_some() {
                    false
                } else {
                    *scope = Some(Vec::new());
                    true
                }
            });
            Self {
                owner,
                _not_send: std::marker::PhantomData,
            }
        }
    }

    impl Drop for LaunchProofScope {
        fn drop(&mut self) {
            if self.owner {
                SCOPE.with(|scope| *scope.borrow_mut() = None);
            }
        }
    }

    pub(super) fn recall(key: &Key) -> Option<VerifiedRuntimeManifest> {
        SCOPE.with(|scope| {
            scope
                .borrow()
                .as_ref()?
                .iter()
                .find(|(seen, _)| seen == key)
                .map(|(_, verified)| verified.clone())
        })
    }

    pub(super) fn remember(key: Key, verified: &VerifiedRuntimeManifest) {
        SCOPE.with(|scope| {
            if let Some(entries) = scope.borrow_mut().as_mut() {
                entries.push((key, verified.clone()));
            }
        });
    }
}
