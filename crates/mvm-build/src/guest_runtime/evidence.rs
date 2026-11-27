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
///
/// Holding one means the archive's digest matched the signed checksum, its
/// signatures verified, and its first entry is a valid release manifest. It
/// does not mean the archive's members were compared with that manifest.
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

/// Synthetic authenticated release state for cross-crate launch-boundary tests.
#[cfg(feature = "test-support")]
pub struct VerifiedReleaseRuntimeFixture {
    pub release: std::sync::Arc<VerifiedReleaseRuntime>,
    pub overlay: PathBuf,
    pub overlay_verity: PathBuf,
    pub initramfs: PathBuf,
    pub overlay_roothash: String,
}

/// Build internally authenticated runtime evidence without weakening production constructors.
#[cfg(feature = "test-support")]
pub fn verified_release_runtime_fixture(
    root: &Path,
    arch: GuestArch,
    minimum_protocol: u32,
    host_protocol: u32,
) -> VerifiedReleaseRuntimeFixture {
    use mvm_core::image_set::{GitCommit, WorktreeState};

    std::fs::create_dir_all(root).expect("create verified runtime fixture directory");
    let overlay = root.join("overlay.ext4");
    let overlay_verity = root.join("overlay.verity");
    let initramfs = root.join("initramfs");
    std::fs::write(&overlay, b"overlay").expect("write verified runtime overlay");
    std::fs::write(&overlay_verity, b"verity").expect("write verified runtime verity");
    std::fs::write(&initramfs, b"initramfs").expect("write verified runtime initramfs");
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let overlay_roothash = "a".repeat(64);
    let declaration = RuntimeAssembly {
        assembly_format: crate::guest_bins::assembly::RUNTIME_ASSEMBLY_FORMAT,
        arch,
        protocol_version: host_protocol,
        min_supported_protocol_version: minimum_protocol,
        overlay_sha256: digest(b"overlay"),
        overlay_verity_sha256: digest(b"verity"),
        overlay_roothash: overlay_roothash.clone(),
        initramfs_sha256: digest(b"initramfs"),
    };
    let archive = root.join("guest-runtime.tar.gz");
    std::fs::write(&archive, b"verified archive").expect("write verified runtime archive");
    let archive_sha256 = digest(b"verified archive");
    let proof = RuntimeReleaseProof {
        archive,
        checksum: root.join("guest-runtime.sha256"),
        signature_bundle: root.join("guest-runtime.bundle"),
        archive_sha256: archive_sha256.clone(),
        version: "verified-runtime-fixture".into(),
        arch,
    };
    let mut snapshot = tempfile::NamedTempFile::new().expect("create verified archive snapshot");
    snapshot
        .write_all(b"verified archive")
        .expect("write verified archive snapshot");
    let manifest = VerifiedRuntimeManifest {
        archive: std::sync::Arc::new(snapshot),
        checksum: Vec::new(),
        signature: Vec::new(),
        checksum_signature: None,
        version: proof.version.clone(),
        digest: archive_sha256,
        manifest: GuestBinsManifest {
            schema_version: crate::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
            version: proof.version.clone(),
            guest_source_fingerprint: "b".repeat(64),
            sdk_cdylib_source_fingerprint: "c".repeat(64),
            source: crate::image_source::RepoIdentity {
                commit: GitCommit::new("d".repeat(40)).expect("valid fixture commit"),
                worktree: WorktreeState::Clean,
            },
            files: std::collections::BTreeMap::new(),
            assemblies: std::collections::BTreeMap::from([(arch, declaration)]),
        },
        arch,
        signer: mvm_core::crypto::image_verify::VerifiedSigner {
            identity: "verified runtime fixture".into(),
            issuer: "verified runtime fixture".into(),
        },
    };
    VerifiedReleaseRuntimeFixture {
        release: std::sync::Arc::new(VerifiedReleaseRuntime::from_verified(proof, manifest)),
        overlay,
        overlay_verity,
        initramfs,
        overlay_roothash,
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
    /// With `shared`, the archive is linked from that content store when an
    /// intact copy is already there, as in [`Self::snapshot_artifacts_shared_in`].
    #[tracing::instrument(skip_all)]
    pub fn retain_release_proof_in(
        &self,
        proof: &RuntimeReleaseProof,
        generation: &Path,
        shared: Option<&Path>,
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
        snapshot_file(self.archive.path(), &retained.archive, &self.digest, shared)?;
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

    /// [`Self::snapshot_artifacts_in`], sharing bytes through the content store
    /// `shared`: an artifact already there under its digest is linked into the
    /// generation and re-hashed in place instead of copied, and a fresh copy is
    /// published there for the next generation. The generation layout and its
    /// verification are unchanged; only the inodes are shared.
    pub fn snapshot_artifacts_shared_in(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
        private_parent: &Path,
        shared: &Path,
    ) -> Result<VerifiedRuntimeArtifacts, GuestRuntimeError> {
        snapshot_declared_artifacts(
            &self.digest,
            self.declaration(selection.arch)?,
            selection,
            Some(private_parent),
            Some(shared),
        )
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
            None,
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
    shared: Option<&Path>,
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
        snapshot_file(source, destination, expected, shared)?;
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

/// Owns a generation of artifact files matching a checked declaration: fresh
/// copies, or hard links to an intact shared copy that was re-hashed when
/// linked. Authentication depends on
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
    /// or recopying any artifact. Nothing is synced: the lifecycle makes the
    /// files and the directory entries naming them durable before anything
    /// relies on them surviving a host crash.
    pub fn keep(self) -> PersistedRuntimeArtifacts {
        PersistedRuntimeArtifacts {
            directory: self.directory.keep(),
            archive_sha256: self.archive_sha256,
            declaration: self.declaration,
        }
    }
}

/// Verified generation with no automatic deletion. This does not prove
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
    let identities = mvm_core::release_trust::accepted_release_identities(version);
    verify_release_archive_signed_by(
        archive,
        checksum,
        bundle,
        version,
        arch,
        &|payload, signature, asset| {
            crate::release_signature::verify_release_archive_bytes_with_signer(
                payload,
                signature,
                asset,
                &identities,
                mvm_core::release_trust::RELEASE_OIDC_ISSUER,
            )
        },
    )
}

/// Whether `signature` is the release's signature over `payload`, the bytes
/// published as `asset`, and who signed it.
pub(super) type SignatureCheck<'a> = dyn Fn(
        &[u8],
        &[u8],
        &str,
    ) -> Result<
        mvm_core::crypto::image_verify::VerifiedSigner,
        crate::runtime_overlay::RuntimeOverlayError,
    > + 'a;

/// [`verify_release_archive`] with the signature check as a parameter. The
/// one production caller passes the release verifier; nothing outside this
/// module's parent can name this function, so no other crate can supply a
/// check of its own.
pub(super) fn verify_release_archive_signed_by(
    archive: &Path,
    checksum: &Path,
    bundle: &Path,
    version: &str,
    arch: GuestArch,
    signed_by: &SignatureCheck<'_>,
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
        tracing::info_span!("verify_checksum_signature_bytes")
            .in_scope(|| signed_by(&checksum_bytes, &signature, &format!("{asset}.sha256")))?;
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
    let signer = signed_by(&bytes, &signature, &asset)?;
    let snapshot = write_archive_snapshot(&bytes)?;
    let manifest = read_authenticated_manifest(&bytes, version)?;
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

/// What authenticated archive bytes declare, read from their first entry.
///
/// `bytes` must be the buffer that was digested against the signed checksum
/// and checked against the archive signature: the manifest is parsed from
/// that memory, never from a path, so what is read is what was authenticated.
/// Members are not decompressed or hashed here. Whether they agree with the
/// manifest is a property of the signed bytes, established before signing and
/// again where an archive is acquired or installed; the digest and signatures
/// are what tie this archive to those verdicts.
pub(super) fn read_authenticated_manifest(
    bytes: &[u8],
    version: &str,
) -> Result<GuestBinsManifest, GuestRuntimeError> {
    let manifest = crate::guest_bins::read_release_manifest(bytes)?;
    super::validate_release_guest_runtime_manifest(&manifest, version)?;
    Ok(manifest)
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

/// Write the authenticated bytes to a private temporary file, the copy an
/// installation's member check and any later retention read from.
#[tracing::instrument(skip_all)]
fn write_archive_snapshot(bytes: &[u8]) -> Result<tempfile::NamedTempFile, GuestRuntimeError> {
    let mut snapshot = tempfile::NamedTempFile::new()?;
    snapshot.write_all(bytes)?;
    snapshot.flush()?;
    Ok(snapshot)
}

/// The durability barrier for one snapshot, apart from the copy so its cost
/// is measured on its own. On macOS this empties the drive cache. Production
/// snapshots submit their data instead and rely on the launch's one final
/// full flush; this remains as the direct unit for that contract.
#[cfg(test)]
#[tracing::instrument(skip_all)]
fn sync_snapshot(output: &std::fs::File) -> std::io::Result<()> {
    output.sync_all()
}

#[tracing::instrument(skip_all, fields(artifact = snapshot_name(destination)))]
fn snapshot_file(
    source: &Path,
    destination: &Path,
    expected: &str,
    shared: Option<&Path>,
) -> Result<(), GuestRuntimeError> {
    let blob = shared.map(|store| store.join(expected));
    if let Some(blob) = &blob
        && std::fs::symlink_metadata(blob).is_ok()
    {
        // The selection is still checked against its declaration: a changed
        // source refuses the launch even when an intact copy is on hand.
        hash_artifact(source, expected, &mut std::io::sink())?;
        if link_shared_copy(blob, destination, expected)? {
            return Ok(());
        }
    }
    copy_snapshot_file(source, destination, expected)?;
    if let Some(blob) = &blob {
        publish_shared_copy(destination, blob);
    }
    Ok(())
}

/// Make the fresh, verified `copy` the shared copy at `blob`, replacing one that
/// was missing, changed or mis-permissioned so later launches link again
/// instead of copying forever. The new name is linked beside the blob and
/// renamed over it, so a reader sees the old file or the new one, never a
/// partial one. Best effort: failing only costs the next launch a copy.
fn publish_shared_copy(copy: &Path, blob: &Path) {
    static PUBLISHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let (Some(store), Some(name)) = (blob.parent(), blob.file_name()) else {
        return;
    };
    let staged = store.join(format!(
        ".{}.{}.{}",
        name.to_string_lossy(),
        std::process::id(),
        PUBLISHED.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    if std::fs::hard_link(copy, &staged).is_err() {
        return;
    }
    if std::fs::rename(&staged, blob).is_err() {
        let _ = std::fs::remove_file(&staged);
        return;
    }
    // The bytes are flushed with the generation that owns `copy`; this makes
    // the new directory entry durable too.
    let _ = std::fs::File::open(store).and_then(|directory| directory.sync_all());
}

/// Link `blob` into place as `destination` and check the linked inode, which is
/// what a backend will read. A missing, mis-permissioned or changed blob is not
/// an error: the link is removed and the caller copies from the source.
fn link_shared_copy(
    blob: &Path,
    destination: &Path,
    expected: &str,
) -> Result<bool, GuestRuntimeError> {
    if std::fs::hard_link(blob, destination).is_err() {
        return Ok(false);
    }
    let intact = read_only_regular_file(destination)
        && hash_artifact(destination, expected, &mut std::io::sink()).is_ok();
    if !intact {
        std::fs::remove_file(destination)?;
    }
    Ok(intact)
}

/// The shape a retained artifact must keep: a regular file of ours, mode 0400.
fn read_only_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && mvm_core::private_fs::require_current_owner(&metadata).is_ok()
            && mvm_core::private_fs::mode_bits(path, &metadata).is_ok_and(|mode| mode == 0o400)
    })
}

fn copy_snapshot_file(
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
    // Submitted, not flushed: the launch's retention record is synced after
    // every snapshot file and that one full flush covers them, where a flush
    // per file cost ~8-18 ms each on macOS.
    mvm_core::util::atomic_io::submit_file_data(&output)
        .map_err(|error| GuestRuntimeError::Cache(format!("{error:#}")))?;
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
    #[ignore = "requires MVM_SIGNED_RUNTIME_FIXTURE_DIR holding one signed release quartet this build accepts"]
    fn signed_release_verification_is_once_per_launch_and_refuses_tampering() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("MVM_SIGNED_RUNTIME_FIXTURE_DIR")
                .expect("set MVM_SIGNED_RUNTIME_FIXTURE_DIR to a signed release quartet"),
        );
        // The quartet names its own version and digest, so the test follows
        // whichever release the current member contract still accepts.
        let asset = std::fs::read_dir(&directory)
            .expect("fixture directory")
            .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
            .find(|name| name.starts_with("mvm-guest-bins-v") && name.ends_with(".tar.gz"))
            .expect("a guest runtime archive in the fixture directory");
        let asset = asset.as_str();
        let version = asset
            .trim_start_matches("mvm-guest-bins-v")
            .trim_end_matches(".tar.gz");
        let checksum = directory.join(format!("{asset}.sha256"));
        let proof = RuntimeReleaseProof {
            archive: directory.join(asset),
            signature_bundle: directory.join(format!("{asset}.bundle")),
            archive_sha256: std::fs::read_to_string(&checksum)
                .expect("checksum file")
                .split_whitespace()
                .next()
                .expect("a digest in the checksum file")
                .to_owned(),
            checksum,
            version: version.to_owned(),
            arch: GuestArch::host(),
        };
        let before = RELEASE_ARCHIVE_VERIFICATIONS.with(std::cell::Cell::get);
        let walks = crate::guest_bins::MEMBER_WALKS.with(std::cell::Cell::get);
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
        assert_eq!(
            crate::guest_bins::MEMBER_WALKS.with(std::cell::Cell::get),
            walks,
            "a launch authenticates the archive and reads its manifest without walking members"
        );
        let published =
            crate::guest_bins::release::check_release_archive(&proof.archive, &proof.version)
                .expect("the published archive passes the member walk");
        assert_eq!(
            verify_release_runtime(proof.clone(), &proof.version, proof.arch)
                .expect("signed release")
                .manifest()
                .manifest(),
            &published,
            "the manifest a launch reads is the one the member walk admits"
        );

        // The same signed bytes offered as another tag's runtime: the bundle is
        // genuine, and its signer is not that tag's release workflow.
        let other = tempfile::tempdir().expect("foreign tag directory");
        let foreign = "mvm-guest-bins-v0.0.0-foreign.tar.gz";
        std::fs::copy(&proof.archive, other.path().join(foreign)).expect("copy archive");
        std::fs::copy(
            &proof.signature_bundle,
            other.path().join(format!("{foreign}.bundle")),
        )
        .expect("copy bundle");
        std::fs::write(
            other.path().join(format!("{foreign}.sha256")),
            format!("{}  {foreign}\n", proof.archive_sha256),
        )
        .expect("write checksum");
        let error = verify_release_archive(
            &other.path().join(foreign),
            &other.path().join(format!("{foreign}.sha256")),
            &other.path().join(format!("{foreign}.bundle")),
            "0.0.0-foreign",
            proof.arch,
        )
        .expect_err("another tag's signer must not authenticate this runtime");
        assert!(
            matches!(
                error,
                GuestRuntimeError::Release(
                    crate::runtime_overlay::RuntimeOverlayError::SignatureInvalid { .. }
                )
            ),
            "{error}"
        );

        let scratch = tempfile::tempdir().expect("tampered archive directory");
        let mut edited = std::fs::read(&proof.archive).expect("published archive");
        edited[0] ^= 1;
        let tampered_archive = scratch.path().join(asset);
        std::fs::write(&tampered_archive, edited).expect("write tampered archive");
        let tampered = RuntimeReleaseProof {
            archive: tampered_archive,
            ..proof
        };
        let error = verify_release_runtime(tampered, version, GuestArch::host())
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
            let persisted = first.keep();
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
    fn generations_share_artifact_bytes_and_never_link_a_changed_copy() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (dir, verified) = fixture();
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let shared = parent.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let paths = ["overlay", "verity", "initramfs"].map(|name| dir.path().join(name));
        let root = "a".repeat(64);
        let selected = selection(&paths, &root);
        let snapshot = || {
            verified
                .snapshot_artifacts_shared_in(&selected, parent.path(), &shared)
                .unwrap()
        };
        let first = snapshot();
        let second = snapshot();
        assert_ne!(first.directory_path(), second.directory_path());
        let inode = |path: PathBuf| std::fs::metadata(path).unwrap().ino();
        assert_eq!(inode(first.overlay_path()), inode(second.overlay_path()));
        assert_eq!(
            inode(first.initramfs_path()),
            inode(second.initramfs_path())
        );
        assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 3);

        // A changed selection is refused even with an intact shared copy.
        let original = std::fs::read(&paths[0]).unwrap();
        std::fs::write(&paths[0], b"replacement").unwrap();
        assert!(
            verified
                .snapshot_artifacts_shared_in(&selected, parent.path(), &shared)
                .is_err()
        );
        std::fs::write(&paths[0], original).unwrap();

        // A shared copy whose bytes changed is never handed to a generation.
        let declaration = verified.declaration(GuestArch::X86_64).unwrap();
        let blob = shared.join(&declaration.overlay_sha256);
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&blob, b"tampered").unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o400)).unwrap();
        let third = snapshot();
        assert_eq!(std::fs::read(third.overlay_path()).unwrap(), b"overlay");
        // ...and the fresh copy repairs the shared one, which the next launch
        // links again.
        assert_eq!(std::fs::read(&blob).unwrap(), b"overlay");
        assert_eq!(inode(third.overlay_path()), inode(blob.clone()));
        let after_repair = snapshot();
        assert_eq!(inode(after_repair.overlay_path()), inode(blob.clone()));

        // Nor is one that lost its read-only private mode.
        let initramfs_blob = shared.join(&declaration.initramfs_sha256);
        std::fs::set_permissions(&initramfs_blob, std::fs::Permissions::from_mode(0o644)).unwrap();
        let fourth = snapshot();
        assert_eq!(
            std::fs::metadata(fourth.initramfs_path()).unwrap().mode() & 0o777,
            0o400
        );
        assert_eq!(
            std::fs::metadata(&initramfs_blob).unwrap().mode() & 0o777,
            0o400,
            "the repaired shared copy is read-only again"
        );
        assert_eq!(inode(snapshot().initramfs_path()), inode(initramfs_blob));
        // No staging names are left in the store.
        assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 3);
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
        snapshot_file(&source, &dir.path().join("snapshot"), &digest, None).unwrap();
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
