//! Streaming bundle I/O: sealing, verifying, and installing a `.mvmpkg`
//! without holding an artifact in memory.
//!
//! An artifact's bytes pass through a fixed-size copy buffer on their way
//! between the archive and their destination — a staging file on install, a
//! discarding sink on verify — and are hashed on the way. Memory use is
//! bounded by that buffer and the manifest, not by the size of the rootfs.
//! Only the embedded image-set manifests, which verification has to parse,
//! are read whole, and they are capped at [`MAX_IMAGE_SET_MANIFEST_BYTES`].

use std::collections::BTreeMap;
#[cfg(feature = "host-state")]
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(feature = "host-state")]
use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256};

use super::{BundleArtifact, BundleManifest, BundleVerifyError};
#[cfg(feature = "host-state")]
use super::{
    BundleInstallError, BundleMember, BundleRegistry, BundleSizeBudget, ImageSetSource,
    InstalledBundle, KeyId, MANIFEST_FILENAME, ManifestSigner, SIGNATURE_FILENAME, TrustStore,
    VerifiedEmbeddedImageSet, canonical_manifest_bytes, declarations, ensure_safe_path,
    install_embedded_image_set_cache, key_id_from_pubkey, verify_embedded_image_sets,
    verify_signed_manifest,
};

/// Read `manifest.json` and `manifest.sig` out of an archive, stopping as soon
/// as both are found. A bundle writes them first, so a multi-GiB archive is
/// read only as far as its first two entries.
#[cfg(feature = "host-state")]
pub(super) fn read_manifest_entries(
    archive: impl Read,
) -> Result<(Vec<u8>, Vec<u8>), BundleVerifyError> {
    let (manifest, signature) = read_manifest_entries_inner(archive, true)?;
    let missing = |name: &str| BundleVerifyError::ManifestParse(format!("{name} missing"));
    Ok((
        manifest,
        signature.ok_or_else(|| missing(SIGNATURE_FILENAME))?,
    ))
}

/// Read only the manifest for denial-only classification. A missing signature
/// is left to the mandatory verification path, which reports that failure.
#[cfg(feature = "host-state")]
pub(super) fn read_manifest_entry(archive: impl Read) -> Result<Vec<u8>, BundleVerifyError> {
    read_manifest_entries_inner(archive, false).map(|(manifest, _)| manifest)
}

#[cfg(feature = "host-state")]
fn read_manifest_entries_inner(
    archive: impl Read,
    require_signature: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>), BundleVerifyError> {
    let tar_error = |e: std::io::Error| BundleVerifyError::ManifestParse(format!("tar read: {e}"));
    let mut manifest = None;
    let mut signature = None;
    let mut budget = declarations::BundleSizeBudget::default();
    for entry in tar::Archive::new(archive).entries().map_err(tar_error)? {
        let mut entry = entry.map_err(tar_error)?;
        let path = entry
            .path()
            .map_err(tar_error)?
            .to_string_lossy()
            .into_owned();
        let slot = match path.as_str() {
            MANIFEST_FILENAME => &mut manifest,
            SIGNATURE_FILENAME => &mut signature,
            _ => continue,
        };
        budget.admit(&path, entry.size())?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(tar_error)?;
        *slot = Some(bytes);
        if manifest.is_some() && (signature.is_some() || !require_signature) {
            break;
        }
    }
    let missing = |name: &str| BundleVerifyError::ManifestParse(format!("{name} missing"));
    Ok((
        manifest.ok_or_else(|| missing(MANIFEST_FILENAME))?,
        signature,
    ))
}

/// Largest embedded image-set manifest verification will read. The manifest
/// is JSON naming a handful of artifacts; anything near this size is not one.
pub const MAX_IMAGE_SET_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Keep cooperating bundle removal excluded through a caller's reference commit.
#[cfg(feature = "host-state")]
pub(crate) struct BundleInstallLease {
    pub(crate) bundle: InstalledBundle,
    _lease: File,
}

/// Where verified artifact bytes can be read back from, by archive-relative
/// path: memory for a bundle verified from bytes, a staging directory for one
/// verified from a file.
#[cfg(feature = "host-state")]
pub(super) trait ArtifactSource {
    fn reader(&self, bundle_path: &str) -> io::Result<Box<dyn Read + '_>>;

    /// Copy one artifact to `destination`, streaming.
    fn copy_to(&self, bundle_path: &str, destination: &Path) -> io::Result<()> {
        let mut reader = self.reader(bundle_path)?;
        let mut file = File::create(destination)?;
        io::copy(&mut reader, &mut file)?;
        file.sync_all()
    }

    /// Read an embedded image-set manifest, refusing one over
    /// [`MAX_IMAGE_SET_MANIFEST_BYTES`].
    fn read_image_set_manifest(&self, bundle_path: &str) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.reader(bundle_path)
            .and_then(|reader| {
                reader
                    .take(MAX_IMAGE_SET_MANIFEST_BYTES + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|error| format!("reading {bundle_path}: {error}"))?;
        if bytes.len() as u64 > MAX_IMAGE_SET_MANIFEST_BYTES {
            return Err(format!(
                "{bundle_path} is over the {MAX_IMAGE_SET_MANIFEST_BYTES}-byte image-set manifest limit"
            ));
        }
        Ok(bytes)
    }
}

/// Artifacts held in memory, keyed by archive-relative path.
#[cfg(feature = "host-state")]
pub(super) struct InMemoryArtifacts<'a>(pub &'a BTreeMap<String, Vec<u8>>);

#[cfg(feature = "host-state")]
impl ArtifactSource for InMemoryArtifacts<'_> {
    fn reader(&self, bundle_path: &str) -> io::Result<Box<dyn Read + '_>> {
        self.0
            .get(bundle_path)
            .map(|bytes| Box::new(bytes.as_slice()) as Box<dyn Read>)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, bundle_path.to_string()))
    }
}

/// Artifacts extracted under a directory at their archive-relative paths.
#[cfg(feature = "host-state")]
pub(super) struct StagedArtifacts<'a>(pub &'a Path);

#[cfg(feature = "host-state")]
impl ArtifactSource for StagedArtifacts<'_> {
    fn reader(&self, bundle_path: &str) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(File::open(self.0.join(bundle_path))?))
    }
}

/// A writer that hashes and counts what passes through it.
pub(crate) struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    pub(crate) fn finish(self) -> (u64, String) {
        (self.written, hex::encode(self.hasher.finalize()))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Compare an artifact's measured size and digest with its declaration.
pub(super) fn check_artifact_digest(
    artifact: &BundleArtifact,
    actual_size: u64,
    actual_sha256: String,
) -> Result<(), BundleVerifyError> {
    if actual_size != artifact.size_bytes {
        return Err(BundleVerifyError::ArtifactSizeMismatch {
            name: artifact.name.clone(),
            declared: artifact.size_bytes,
            actual: actual_size,
        });
    }
    if actual_sha256 != artifact.sha256 {
        return Err(BundleVerifyError::ArtifactSha256Mismatch {
            name: artifact.name.clone(),
            declared: artifact.sha256.clone(),
            actual: actual_sha256,
        });
    }
    Ok(())
}

/// Where [`stream_artifacts`] sends each declared artifact.
#[cfg(feature = "host-state")]
enum Destination<'a> {
    /// Hash and discard.
    Discard,
    /// Hash and keep in memory, under the image-set manifest cap.
    Capture,
    /// Hash and write to this file.
    File(&'a Path),
}

/// Walk an archive once, hashing every declared artifact into the
/// destination `route` picks for it and checking it against the manifest.
/// Returns the bytes of the artifacts routed to [`Destination::Capture`].
///
/// Entries the manifest does not declare are skipped, as the in-memory
/// verifier skips them; a declared artifact that appears twice or never is
/// refused.
#[cfg(feature = "host-state")]
fn stream_artifacts<'p>(
    archive: impl Read,
    manifest: &BundleManifest,
    mut route: impl FnMut(&BundleArtifact) -> Destination<'p>,
) -> Result<BTreeMap<String, Vec<u8>>, BundleVerifyError> {
    let tar_error = |e: io::Error| BundleVerifyError::ManifestParse(format!("tar read: {e}"));
    let declared: BTreeMap<&str, &BundleArtifact> = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect();
    for path in declared.keys() {
        ensure_safe_path(path)?;
    }
    let mut seen = BTreeSet::new();
    let mut captured = BTreeMap::new();
    let mut budget = BundleSizeBudget::default();
    for entry in tar::Archive::new(archive).entries().map_err(tar_error)? {
        let mut entry = entry.map_err(tar_error)?;
        let path = entry
            .path()
            .map_err(tar_error)?
            .to_string_lossy()
            .into_owned();
        ensure_safe_path(&path)?;
        budget.admit(&path, entry.size())?;
        let Some(artifact) = declared.get(path.as_str()) else {
            continue;
        };
        if entry.size() != artifact.size_bytes {
            return Err(BundleVerifyError::ArtifactSizeMismatch {
                name: artifact.name.clone(),
                declared: artifact.size_bytes,
                actual: entry.size(),
            });
        }
        if !seen.insert(path.clone()) {
            return Err(BundleVerifyError::ManifestParse(format!(
                "archive carries {path} more than once"
            )));
        }
        let (size, sha256) = match route(artifact) {
            Destination::Discard => {
                let mut sink = HashingWriter::new(io::sink());
                io::copy(&mut entry, &mut sink).map_err(tar_error)?;
                sink.finish()
            }
            Destination::Capture => {
                if entry.size() > MAX_IMAGE_SET_MANIFEST_BYTES {
                    return Err(BundleVerifyError::ImageSetManifestParse {
                        name: artifact.name.clone(),
                        reason: format!(
                            "{} bytes is over the {MAX_IMAGE_SET_MANIFEST_BYTES}-byte limit",
                            entry.size()
                        ),
                    });
                }
                let mut sink = HashingWriter::new(Vec::new());
                io::copy(&mut entry, &mut sink).map_err(tar_error)?;
                let bytes = std::mem::take(&mut sink.inner);
                let measured = sink.finish();
                captured.insert(path.clone(), bytes);
                measured
            }
            Destination::File(target) => {
                let staged = |e: io::Error| {
                    BundleVerifyError::ManifestParse(format!("staging {}: {e}", target.display()))
                };
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(staged)?;
                }
                let mut sink = HashingWriter::new(File::create(target).map_err(staged)?);
                io::copy(&mut entry, &mut sink).map_err(tar_error)?;
                sink.inner.sync_all().map_err(staged)?;
                sink.finish()
            }
        };
        check_artifact_digest(artifact, size, sha256)?;
    }
    if let Some(missing) = manifest
        .artifacts
        .iter()
        .find(|artifact| !seen.contains(&artifact.path))
    {
        return Err(BundleVerifyError::ArtifactMissing {
            name: missing.name.clone(),
        });
    }
    Ok(captured)
}

/// The archive paths of every embedded image-set manifest a bundle declares.
#[cfg(feature = "host-state")]
fn image_set_manifest_paths(manifest: &BundleManifest) -> BTreeSet<String> {
    manifest
        .members
        .iter()
        .filter_map(|member| match member {
            BundleMember::EmbeddedImageSet { manifest_artifact }
            | BundleMember::EmbeddedBootAssets { manifest_artifact } => {
                manifest.find_by_name(manifest_artifact)
            }
            BundleMember::EmbeddedCliBootAssets(runtime) => {
                manifest.find_by_name(&runtime.manifest_artifact)
            }
            BundleMember::CanonicalLinuxProof(proof) => {
                manifest.find_by_name(&proof.manifest_artifact)
            }
            _ => None,
        })
        .map(|artifact| artifact.path.clone())
        .collect()
}

/// A bundle archive on disk that passed every check
/// [`super::read_and_verify_bundle`] makes, verified without loading it.
#[derive(Debug)]
#[cfg(feature = "host-state")]
pub struct VerifiedBundleFile {
    pub manifest: BundleManifest,
    pub key_id: KeyId,
    /// SHA-256 of the whole archive file.
    pub bundle_sha256: String,
    pub embedded_image_sets: Vec<VerifiedEmbeddedImageSet>,
    pub boot_assets: Option<super::VerifiedBootAssets>,
    manifest_signature: [u8; 64],
}

#[cfg(feature = "host-state")]
impl VerifiedBundleFile {
    /// Internal bounded selection over an independently positioned owned file.
    /// The application facade supplies only its identity-safe retained snapshot.
    pub(crate) fn read_small_verified_member(
        &self,
        mut archive: File,
        name: &str,
        maximum: u64,
    ) -> Result<Vec<u8>, BundleVerifyError> {
        use std::io::{Seek, SeekFrom};
        let invalid = |reason: &str| BundleVerifyError::ManifestParse(reason.to_owned());
        let mut matches = self
            .manifest
            .artifacts
            .iter()
            .filter(|member| member.name == name);
        let member = matches
            .next()
            .ok_or_else(|| BundleVerifyError::ArtifactMissing {
                name: name.to_owned(),
            })?;
        if matches.next().is_some()
            || self
                .manifest
                .artifacts
                .iter()
                .filter(|other| other.path == member.path)
                .count()
                != 1
        {
            return Err(invalid("selected signed member is ambiguous"));
        }
        if member.size_bytes > maximum || member.size_bytes > MAX_IMAGE_SET_MANIFEST_BYTES {
            return Err(invalid("selected signed member exceeds its capture bound"));
        }
        let metadata = archive
            .metadata()
            .map_err(|error| invalid(&format!("snapshot metadata: {error}")))?;
        if !metadata.is_file() || metadata.len() > super::MAX_BUNDLE_TOTAL_BYTES + 64 * 1024 * 1024
        {
            return Err(invalid("snapshot is not a bounded regular archive"));
        }
        archive
            .seek(SeekFrom::Start(0))
            .map_err(|error| invalid(&format!("snapshot rewind: {error}")))?;
        let mut digest = HashingWriter::new(io::sink());
        io::copy(
            &mut Read::by_ref(&mut archive).take(metadata.len() + 1),
            &mut digest,
        )
        .map_err(|error| invalid(&format!("snapshot hash: {error}")))?;
        let (size, hash) = digest.finish();
        if size != metadata.len() || hash != self.bundle_sha256 {
            return Err(invalid(
                "retained snapshot differs from its original archive pin",
            ));
        }
        archive
            .seek(SeekFrom::Start(0))
            .map_err(|error| invalid(&format!("snapshot rewind: {error}")))?;
        let mut captured = stream_artifacts(archive, &self.manifest, |artifact| {
            if artifact.path == member.path {
                Destination::Capture
            } else {
                Destination::Discard
            }
        })?;
        captured
            .remove(&member.path)
            .ok_or_else(|| BundleVerifyError::ArtifactMissing {
                name: name.to_owned(),
            })
    }

    /// The original archive, signature and publisher identity for independent
    /// plan admission. This is a pin, not permission to skip re-verification.
    pub fn plan_artifact(&self) -> super::PlanArtifact {
        super::PlanArtifact::new(
            self.bundle_sha256.clone(),
            &self.manifest_signature,
            self.key_id.clone(),
        )
    }
}

/// Owns only the selected kernel/proof files from one pinned private archive
/// snapshot. This is application-envelope integrity, not canonical Linux
/// authority or permission to start a VM.
#[derive(Debug)]
pub struct CapturedCanonicalLinuxInputs {
    _archive: File,
    directory_path: PathBuf,
    directory_guard: std::sync::Mutex<Option<tempfile::TempDir>>,
    manifest: BundleManifest,
    pin: super::PlanArtifact,
    proof: super::CanonicalLinuxProof,
    kernel: BundleArtifact,
    selected: BTreeMap<String, PathBuf>,
}

impl CapturedCanonicalLinuxInputs {
    /// Resource location only, not execution or cleanup authority.
    pub fn generation_dir(&self) -> &Path {
        &self.directory_path
    }

    /// One-way retention before a native reader can exist.
    pub fn retain_generation(&self) -> Result<()> {
        if let Some(directory) = self
            .directory_guard
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel generation guard poisoned"))?
            .take()
        {
            let retained = directory.keep();
            anyhow::ensure!(
                retained == self.directory_path,
                "kernel generation retention changed its identity"
            );
        }
        Ok(())
    }
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }
    pub fn pin(&self) -> &super::PlanArtifact {
        &self.pin
    }
    pub fn proof(&self) -> &super::CanonicalLinuxProof {
        &self.proof
    }
    pub fn kernel(&self) -> &BundleArtifact {
        &self.kernel
    }

    /// Reopen a retained regular file without following a link and verify the
    /// actual stream against its signed inventory. No ambient path is returned.
    pub fn open_artifact(&self, name: &str) -> Result<File> {
        use std::io::{Seek, SeekFrom};
        let path = self
            .selected
            .get(name)
            .context("artifact was not retained")?;
        let declaration = self
            .manifest
            .find_by_name(name)
            .context("artifact declaration missing")?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() == declaration.size_bytes,
            "retained artifact is not regular or has changed size"
        );
        let mut digest = HashingWriter::new(io::sink());
        io::copy(
            &mut Read::by_ref(&mut file).take(declaration.size_bytes + 1),
            &mut digest,
        )?;
        let (size, hash) = digest.finish();
        check_artifact_digest(declaration, size, hash)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

/// Snapshot a pinned archive with bounded streaming I/O, then retain only the
/// canonical-proof inputs. Re-verification runs on our private snapshot, not
/// multiple independently mutable reads of the caller's path.
///
/// The caller must still apply the canonical Linux lock/signature/revocation
/// verifier and bind the selected kernel to an admitted native operation.
#[cfg(feature = "host-state")]
pub fn capture_canonical_linux_inputs(
    archive: &Path,
    pin: &super::PlanArtifact,
    trust: &dyn TrustStore,
) -> Result<CapturedCanonicalLinuxInputs> {
    use std::io::{Seek, SeekFrom};
    anyhow::ensure!(
        cfg!(unix),
        "canonical Linux proof capture is unsupported on this platform"
    );
    const MAX_RAW_ARCHIVE: u64 = super::MAX_BUNDLE_TOTAL_BYTES + 64 * 1024 * 1024;
    const MAX_KERNEL: u64 = 256 * 1024 * 1024;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut input = options.open(archive)?;
    let metadata = input.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= MAX_RAW_ARCHIVE,
        "bundle archive is not regular or exceeds the capture bound"
    );
    // An authenticated metadata preflight can refuse an oversized selected
    // kernel before copying a multi-GiB workload archive. It is not authority
    // for the later snapshot: that exact snapshot is independently verified.
    let (head, signature) = read_manifest_entries(input.try_clone()?)?;
    let (head, key) = verify_signed_manifest(&head, &signature, trust)?;
    let pinned_signature = pin.signature_bytes().context("invalid pinned signature")?;
    anyhow::ensure!(
        key == pin.key_id && signature.as_slice() == pinned_signature.as_slice(),
        "archive preflight publisher or signature differs from its pin"
    );
    anyhow::ensure!(
        head.members
            .iter()
            .any(|member| matches!(member, BundleMember::CanonicalLinuxProof(_))),
        "canonical Linux proof is required"
    );
    let preflight_kernel = head
        .find_by_role(&super::ArtifactRole::Kernel)
        .context("kernel missing")?;
    anyhow::ensure!(
        preflight_kernel.size_bytes > 0 && preflight_kernel.size_bytes <= MAX_KERNEL,
        "selected kernel exceeds the capture bound"
    );
    input.seek(SeekFrom::Start(0))?;
    let parent = crate::config::mvm_home_strict()?.join("canonical-kernel-generations");
    crate::config::create_private_dir(&parent)?;
    anyhow::ensure!(
        !std::fs::symlink_metadata(&parent)?.file_type().is_symlink(),
        "canonical kernel generation parent cannot be a symlink"
    );
    let directory = tempfile::Builder::new()
        .prefix("kernel-")
        .tempdir_in(&parent)?;
    crate::config::create_private_dir(directory.path())?;
    let snapshot_path = directory.path().join("archive.mvmpkg");
    let mut snapshot = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&snapshot_path)?;
    let mut writer = HashingWriter::new(&mut snapshot);
    io::copy(&mut input.take(MAX_RAW_ARCHIVE + 1), &mut writer)?;
    let (size, digest) = writer.finish();
    anyhow::ensure!(
        size <= MAX_RAW_ARCHIVE && digest == pin.bundle_sha256,
        "captured archive differs from its exact pin or exceeds the capture bound"
    );
    snapshot.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot_path, std::fs::Permissions::from_mode(0o400))?;
    }
    let verified = verify_bundle_file(&snapshot_path, trust)?;
    anyhow::ensure!(
        &verified.plan_artifact() == pin,
        "captured archive publisher or signature pin differs"
    );
    let proof = verified
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::CanonicalLinuxProof(proof) => Some(proof.clone()),
            _ => None,
        })
        .context("canonical Linux proof is required")?;
    let kernel = verified
        .manifest
        .find_by_role(&super::ArtifactRole::Kernel)
        .context("selected kernel is missing")?
        .clone();
    anyhow::ensure!(
        kernel.size_bytes > 0 && kernel.size_bytes <= MAX_KERNEL,
        "selected kernel exceeds the capture bound"
    );
    let mut selected = BTreeMap::new();
    for (index, name) in [
        &kernel.name,
        &proof.manifest_artifact,
        &proof.signature_bundle_artifact,
        &proof.revocation_document_artifact,
        &proof.revocation_signature_bundle_artifact,
    ]
    .into_iter()
    .enumerate()
    {
        anyhow::ensure!(
            verified
                .manifest
                .artifacts
                .iter()
                .filter(|a| a.name == *name)
                .count()
                == 1,
            "selected artifact declaration is missing or ambiguous"
        );
        anyhow::ensure!(
            selected
                .insert(
                    name.clone(),
                    directory.path().join(format!("member-{index}"))
                )
                .is_none(),
            "selected canonical inputs alias"
        );
    }
    stream_artifacts(
        open_archive(&snapshot_path)?,
        &verified.manifest,
        |artifact| {
            selected
                .get(&artifact.name)
                .map_or(Destination::Discard, |path| Destination::File(path))
        },
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in selected.values() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
        }
    }
    Ok(CapturedCanonicalLinuxInputs {
        _archive: snapshot,
        directory_path: directory.path().to_owned(),
        directory_guard: std::sync::Mutex::new(Some(directory)),
        manifest: verified.manifest,
        pin: pin.clone(),
        proof,
        kernel,
        selected,
    })
}

#[cfg(feature = "host-state")]
fn open_archive(path: &Path) -> Result<File, BundleVerifyError> {
    File::open(path).map_err(|e| {
        BundleVerifyError::ManifestParse(format!("opening bundle archive {}: {e}", path.display()))
    })
}

#[cfg(feature = "host-state")]
fn archive_sha256(path: &Path) -> Result<String, BundleVerifyError> {
    crate::crypto::image_verify::sha256_reader(open_archive(path)?).map_err(|e| {
        BundleVerifyError::ManifestParse(format!("hashing bundle archive {}: {e}", path.display()))
    })
}

/// Verify the manifest at the head of the archive at `path`.
#[cfg(feature = "host-state")]
fn verify_head(
    path: &Path,
    trust_store: &dyn TrustStore,
) -> Result<(BundleManifest, KeyId, Vec<u8>, Vec<u8>), BundleVerifyError> {
    let (manifest_bytes, sig_bytes) = read_manifest_entries(open_archive(path)?)?;
    let (manifest, key_id) = verify_signed_manifest(&manifest_bytes, &sig_bytes, trust_store)?;
    Ok((manifest, key_id, manifest_bytes, sig_bytes))
}

/// Verify the `.mvmpkg` at `path` the way [`super::read_and_verify_bundle`]
/// verifies bytes — signature, declarations, every artifact's size and
/// digest, embedded image sets — reading each artifact once through a fixed
/// buffer.
#[cfg(feature = "host-state")]
pub fn verify_bundle_file(
    path: &Path,
    trust_store: &dyn TrustStore,
) -> Result<VerifiedBundleFile, BundleVerifyError> {
    let (manifest, key_id, _, signature) = verify_head(path, trust_store)?;
    let manifest_signature = signature.try_into().map_err(|_| {
        BundleVerifyError::ManifestParse("verified manifest signature has invalid length".into())
    })?;
    let capture = image_set_manifest_paths(&manifest);
    let captured = stream_artifacts(open_archive(path)?, &manifest, |artifact| {
        if capture.contains(&artifact.path) {
            Destination::Capture
        } else {
            Destination::Discard
        }
    })?;
    let embedded_image_sets = verify_embedded_image_sets(&manifest, &InMemoryArtifacts(&captured))?;
    let boot_assets = super::verify_boot_assets(&manifest, &InMemoryArtifacts(&captured))?;
    Ok(VerifiedBundleFile {
        bundle_sha256: archive_sha256(path)?,
        manifest,
        key_id,
        embedded_image_sets,
        boot_assets,
        manifest_signature,
    })
}

#[cfg(feature = "host-state")]
impl BundleRegistry {
    /// Install the `.mvmpkg` at `archive`, streaming.
    ///
    /// Each artifact is hashed on its way into `<sha>.partial/` and refused
    /// on the first mismatch; the directory is renamed to `<sha>/` only once
    /// every artifact and every embedded image set has verified. The archive
    /// itself is copied to `<sha>.mvmpkg` for the admit-time resolver.
    ///
    /// Without `force`, a bundle already installed under the same sha256 is
    /// verified in full and then refused as `AlreadyInstalled`, so a caller
    /// that reuses the existing install still knows these bytes verified.
    pub fn install_file(
        &self,
        archive: &Path,
        trust: &dyn TrustStore,
        force: bool,
    ) -> Result<InstalledBundle, BundleInstallError> {
        self.install_leased_file(archive, trust, force)
            .map(|installed| installed.bundle)
    }

    pub(crate) fn install_leased_file(
        &self,
        archive: &Path,
        trust: &dyn TrustStore,
        force: bool,
    ) -> Result<BundleInstallLease, BundleInstallError> {
        let sha = archive_sha256(archive).map_err(BundleInstallError::Verify)?;
        let io_error = |reason: String| BundleInstallError::Io {
            bundle_sha256: sha.clone(),
            reason,
        };
        let (manifest, _, manifest_bytes, sig_bytes) =
            verify_head(archive, trust).map_err(BundleInstallError::Verify)?;
        let lease = self.lock_entry(&sha).map_err(io_error)?;
        let install_dir = self.install_dir(&sha);
        if install_dir.exists() && !force {
            verify_bundle_file(archive, trust).map_err(BundleInstallError::Verify)?;
            return Err(BundleInstallError::AlreadyInstalled {
                bundle_sha256: sha.clone(),
            });
        }
        let staging = self.root.join(format!("{sha}.partial"));
        if staging.exists() {
            std::fs::remove_dir_all(&staging).map_err(|e| {
                io_error(format!(
                    "removing stale staging at {}: {e}",
                    staging.display()
                ))
            })?;
        }
        std::fs::create_dir_all(&staging)
            .map_err(|e| io_error(format!("creating staging dir {}: {e}", staging.display())))?;
        let staged = stage(
            archive,
            &manifest,
            &staging,
            [
                (MANIFEST_FILENAME, manifest_bytes.as_slice()),
                (SIGNATURE_FILENAME, sig_bytes.as_slice()),
            ],
        )
        .map_err(|error| match error {
            StageError::Verify(error) => BundleInstallError::Verify(error),
            StageError::Io(reason) => io_error(reason),
        });
        let embedded = match staged {
            Ok(embedded) => embedded,
            Err(error) => {
                // Best effort: a refused archive leaves nothing behind.
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        install_embedded_image_set_cache(
            &ImageSetSource {
                manifest: &manifest,
                embedded: &embedded,
                artifacts: &StagedArtifacts(&staging),
            },
            &self.embedded_image_set_cache_root(),
            &sha,
        )?;

        sync_staging(&staging, &manifest).map_err(io_error)?;
        publish_install_with(&staging, &install_dir, exchange_directories).map_err(|e| {
            io_error(format!(
                "promoting staging {} → install {}: {e}",
                staging.display(),
                install_dir.display()
            ))
        })?;
        crate::private_fs::sync_managed_directory_chain(&self.root, &self.root)
            .map_err(|error| io_error(error.to_string()))?;
        // After an exchange, staging holds only the obsolete generation.
        // Interrupted cleanup cannot damage the newly published directory.
        if std::fs::symlink_metadata(&staging).is_ok() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        self.persist_archive(archive, &sha).map_err(io_error)?;

        Ok(BundleInstallLease {
            bundle: InstalledBundle {
                sha256: sha,
                root: install_dir,
                manifest,
            },
            _lease: lease,
        })
    }

    /// Fill the embedded image-set cache from the archive at `archive`,
    /// without installing the workload bundle. `bundle fetch` uses this:
    /// the image-set artifacts are re-hashed into a scratch directory as they
    /// are copied, then published to the cache.
    pub fn cache_embedded_image_sets_from_file(
        &self,
        archive: &Path,
        verified: &VerifiedBundleFile,
    ) -> Result<(), BundleInstallError> {
        if verified.embedded_image_sets.is_empty() {
            return Ok(());
        }
        let io_error = |reason: String| BundleInstallError::Io {
            bundle_sha256: verified.bundle_sha256.clone(),
            reason,
        };
        let scratch = tempfile::tempdir()
            .map_err(|e| io_error(format!("creating image-set scratch directory: {e}")))?;
        let mut wanted = image_set_manifest_paths(&verified.manifest);
        wanted.extend(
            verified
                .embedded_image_sets
                .iter()
                .flat_map(|set| set.artifact_paths.values().cloned()),
        );
        let targets: BTreeMap<String, PathBuf> = wanted
            .into_iter()
            .map(|path| {
                let target = scratch.path().join(&path);
                (path, target)
            })
            .collect();
        stream_artifacts(
            open_archive(archive).map_err(BundleInstallError::Verify)?,
            &verified.manifest,
            |artifact| match targets.get(&artifact.path) {
                Some(target) => Destination::File(target),
                None => Destination::Discard,
            },
        )
        .map_err(BundleInstallError::Verify)?;
        install_embedded_image_set_cache(
            &ImageSetSource {
                manifest: &verified.manifest,
                embedded: &verified.embedded_image_sets,
                artifacts: &StagedArtifacts(scratch.path()),
            },
            &self.embedded_image_set_cache_root(),
            &verified.bundle_sha256,
        )
    }

    /// Create the registry root, owner-only.
    fn create_root(&self) -> Result<(), String> {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.root) {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("bundle registry root must be a real directory".to_string());
            }
            crate::private_fs::require_current_owner(&metadata)
                .map_err(|error| error.to_string())?;
        }
        crate::config::create_private_dir(&self.root).map_err(|error| error.to_string())
    }

    /// Every installer and remover shares one stable content-addressed lease.
    pub(super) fn lock_entry(&self, sha: &str) -> Result<File, String> {
        if sha.len() != 64
            || !sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("bundle address must be canonical SHA-256".to_string());
        }
        self.create_root()?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(self.root.join(format!(".{sha}.lock")))
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() {
            return Err("bundle lease must be a regular file".to_string());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err("bundle lease cannot have multiple links".to_string());
            }
        }
        crate::private_fs::require_current_owner(&metadata).map_err(|error| error.to_string())?;
        file.lock().map_err(|error| error.to_string())?;
        Ok(file)
    }

    /// Copy the archive to `<sha>.mvmpkg`, atomically.
    fn persist_archive(&self, archive: &Path, sha: &str) -> Result<(), String> {
        let destination = self.archive_path(sha);
        let mut tmp = tempfile::NamedTempFile::new_in(&self.root)
            .map_err(|e| format!("creating archive tempfile: {e}"))?;
        let mut source = File::open(archive)
            .map_err(|e| format!("reopening archive {}: {e}", archive.display()))?;
        io::copy(&mut source, tmp.as_file_mut())
            .map_err(|e| format!("copying archive bytes: {e}"))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| format!("syncing archive: {e}"))?;
        tmp.persist(&destination).map_err(|e| {
            format!(
                "persisting archive {} → {}: {e}",
                e.file.path().display(),
                destination.display()
            )
        })?;
        Ok(())
    }
}

#[cfg(feature = "host-state")]
fn sync_staging(staging: &Path, manifest: &BundleManifest) -> Result<(), String> {
    let sync = || -> io::Result<()> {
        for name in [MANIFEST_FILENAME, SIGNATURE_FILENAME] {
            File::open(staging.join(name))?.sync_all()?;
        }
        let mut directories = BTreeSet::new();
        for artifact in &manifest.artifacts {
            let path = staging.join(&artifact.path);
            for parent in path
                .ancestors()
                .skip(1)
                .take_while(|parent| parent.starts_with(staging))
            {
                directories.insert(parent.to_path_buf());
            }
        }
        for directory in directories.iter().rev() {
            File::open(directory)?.sync_all()?;
        }
        File::open(staging)?.sync_all()
    };
    sync().map_err(|error| format!("syncing bundle staging: {error}"))
}

#[cfg(feature = "host-state")]
fn publish_install_with(
    staging: &Path,
    destination: &Path,
    exchange: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    match std::fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            exchange(staging, destination)
        }
        Ok(_) => Err(io::Error::other(
            "existing bundle install is not a real directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::rename(staging, destination)
        }
        Err(error) => Err(error),
    }
}

#[cfg(feature = "host-state")]
fn exchange_directories(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .map_err(Into::into)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, destination);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(feature = "host-state")]
enum StageError {
    Verify(BundleVerifyError),
    Io(String),
}

/// Extract and verify every artifact into `staging`, write the manifest and
/// signature beside them, and verify the embedded image sets.
#[cfg(feature = "host-state")]
fn stage(
    archive: &Path,
    manifest: &BundleManifest,
    staging: &Path,
    head: [(&str, &[u8]); 2],
) -> Result<Vec<VerifiedEmbeddedImageSet>, StageError> {
    let targets: BTreeMap<String, PathBuf> = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.clone(), staging.join(&artifact.path)))
        .collect();
    stream_artifacts(
        open_archive(archive).map_err(StageError::Verify)?,
        manifest,
        |artifact| match targets.get(&artifact.path) {
            Some(target) => Destination::File(target),
            None => Destination::Discard,
        },
    )
    .map_err(StageError::Verify)?;
    let embedded = verify_embedded_image_sets(manifest, &StagedArtifacts(staging))
        .map_err(StageError::Verify)?;
    super::verify_boot_assets(manifest, &StagedArtifacts(staging)).map_err(StageError::Verify)?;
    for (name, bytes) in head {
        std::fs::write(staging.join(name), bytes).map_err(|e| {
            StageError::Io(format!("writing {name} into {}: {e}", staging.display()))
        })?;
    }
    Ok(embedded)
}

/// The bytes of one artifact being sealed into a bundle.
#[derive(Debug, Clone)]
#[cfg(feature = "host-state")]
pub enum BundlePayload {
    /// Bytes already in memory.
    Bytes(Vec<u8>),
    /// A file read as it is written into the archive.
    File(PathBuf),
}

#[cfg(feature = "host-state")]
impl BundlePayload {
    fn len(&self) -> io::Result<u64> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.len() as u64),
            Self::File(path) => Ok(std::fs::metadata(path)?.len()),
        }
    }

    fn reader(&self) -> io::Result<Box<dyn Read + '_>> {
        match self {
            Self::Bytes(bytes) => Ok(Box::new(bytes.as_slice())),
            Self::File(path) => Ok(Box::new(File::open(path)?)),
        }
    }
}

/// A reader that hashes and counts what is read through it.
#[cfg(feature = "host-state")]
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    read: u64,
}

#[cfg(feature = "host-state")]
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.read += n as u64;
        Ok(n)
    }
}

/// Seal `manifest` and the artifacts it declares into a `.mvmpkg` written to
/// `out`, streaming each artifact from its payload.
///
/// The manifest is validated and signed before a byte is written, and the
/// signature is checked against the signer's own key. Each artifact is hashed
/// as it is copied into the archive and compared with its declaration, so a
/// file that changed between hashing and sealing fails the write rather than
/// producing a bundle that installs nowhere. A caller writing to a file
/// should write to a temporary path and rename it on success.
#[cfg(feature = "host-state")]
pub fn write_bundle_to(
    manifest: &BundleManifest,
    signer: &dyn ManifestSigner,
    mut artifacts: Vec<(String, BundlePayload)>,
    out: impl Write,
) -> Result<()> {
    let verifying_key = signer.verifying_key();
    let derived = key_id_from_pubkey(&verifying_key);
    declarations::validate_declarations(manifest).context("refusing to seal the bundle")?;
    anyhow::ensure!(
        manifest.key_id == derived,
        "manifest key_id ({}) does not match signing key derivation ({})",
        manifest.key_id.0,
        derived.0
    );
    let mut declared = Vec::with_capacity(artifacts.len());
    for (path, payload) in &artifacts {
        ensure_safe_path(path).context("artifact path validation")?;
        let artifact = manifest
            .artifacts
            .iter()
            .find(|a| a.path == *path)
            .with_context(|| {
                format!("archive contains {path:?} not declared in manifest.artifacts")
            })?;
        let size = payload
            .len()
            .with_context(|| format!("reading artifact {}", artifact.name))?;
        anyhow::ensure!(
            artifact.size_bytes == size,
            "artifact {} size mismatch at write time: manifest {}, actual {}",
            artifact.name,
            artifact.size_bytes,
            size,
        );
        // Bytes in memory can be checked before anything is signed; a file is
        // checked as it streams into the archive below.
        if let BundlePayload::Bytes(bytes) = payload {
            let actual = super::sha256_hex(bytes);
            anyhow::ensure!(
                artifact.sha256 == actual,
                "artifact {} sha256 mismatch at write time: manifest {}, actual {}",
                artifact.name,
                artifact.sha256,
                actual,
            );
        }
        declared.push(artifact);
    }

    let manifest_bytes = canonical_manifest_bytes(manifest)?;
    let sig_bytes = signer
        .sign_manifest(&manifest_bytes)
        .context("signing the bundle manifest")?;
    verifying_key
        .verify(&manifest_bytes, &Signature::from_bytes(&sig_bytes))
        .map_err(|e| {
            anyhow::anyhow!(
                "the signer returned a signature that does not verify under its own key {}: {e}",
                derived.0
            )
        })?;

    let mut tar = tar::Builder::new(out);
    // manifest.json first so a reader finds it — and stops — at the head.
    append_entry(
        &mut tar,
        MANIFEST_FILENAME,
        manifest_bytes.len() as u64,
        manifest_bytes.as_slice(),
    )?;
    append_entry(
        &mut tar,
        SIGNATURE_FILENAME,
        sig_bytes.len() as u64,
        sig_bytes.as_slice(),
    )?;

    // Artifacts in path order — deterministic output.
    artifacts.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (path, payload) in &artifacts {
        let artifact = declared
            .iter()
            .find(|a| a.path == *path)
            .context("declared artifact disappeared")?;
        let mut reader = HashingReader {
            inner: payload
                .reader()
                .with_context(|| format!("opening artifact {}", artifact.name))?
                .take(artifact.size_bytes),
            hasher: Sha256::new(),
            read: 0,
        };
        append_entry(&mut tar, path, artifact.size_bytes, &mut reader)?;
        let actual = hex::encode(reader.hasher.finalize());
        anyhow::ensure!(
            reader.read == artifact.size_bytes && actual == artifact.sha256,
            "artifact {} changed while it was being sealed: manifest {} ({} bytes), read {} ({} bytes)",
            artifact.name,
            artifact.sha256,
            artifact.size_bytes,
            actual,
            reader.read,
        );
    }
    tar.into_inner()
        .and_then(|mut out| out.flush())
        .context("finalise tar archive")?;
    Ok(())
}

#[cfg(feature = "host-state")]
fn append_entry<W: Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    size: u64,
    data: impl Read,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, data)
        .with_context(|| format!("write tar entry {path:?}"))
}

#[cfg(all(test, feature = "host-state"))]
mod tests {
    use super::*;
    use crate::plan::bundle::{
        ArtifactRole, BUNDLE_SCHEMA_VERSION, read_and_verify_bundle, sha256_hex,
    };
    use ed25519_dalek::{SigningKey, VerifyingKey};

    struct OneKey(VerifyingKey);

    impl TrustStore for OneKey {
        fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
            (*key_id == key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11; 32])
    }

    fn artifact(name: &str, role: ArtifactRole, bytes: &[u8]) -> BundleArtifact {
        BundleArtifact {
            name: name.to_string(),
            role,
            path: format!("artifacts/{name}"),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }
    }

    fn manifest(artifacts: Vec<BundleArtifact>) -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "stream-test".to_string(),
            key_id: key_id_from_pubkey(&key().verifying_key()),
            arch: "x86_64".to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            labels: Default::default(),
            artifacts,
            members: Vec::new(),
            verity: None,
            resources: None,
        }
    }

    /// A kernel + rootfs bundle sealed from files into `dir/app.mvmpkg`.
    fn sealed_from_files(dir: &Path) -> PathBuf {
        let (kernel, rootfs) = (b"kernel bytes".as_slice(), b"rootfs bytes".as_slice());
        std::fs::write(dir.join("vmlinux"), kernel).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        let manifest = manifest(vec![
            artifact("vmlinux", ArtifactRole::Kernel, kernel),
            artifact("rootfs.ext4", ArtifactRole::Rootfs, rootfs),
        ]);
        let out = dir.join("app.mvmpkg");
        write_bundle_to(
            &manifest,
            &key(),
            vec![
                (
                    "artifacts/vmlinux".to_string(),
                    BundlePayload::File(dir.join("vmlinux")),
                ),
                (
                    "artifacts/rootfs.ext4".to_string(),
                    BundlePayload::File(dir.join("rootfs.ext4")),
                ),
            ],
            File::create(&out).unwrap(),
        )
        .expect("seal from files");
        out
    }

    fn trust() -> OneKey {
        OneKey(key().verifying_key())
    }

    #[test]
    fn a_bundle_sealed_from_files_matches_one_sealed_from_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = sealed_from_files(dir.path());
        let from_files = std::fs::read(&path).unwrap();
        let from_bytes = crate::plan::bundle::write_bundle(
            &read_and_verify_bundle(&from_files, &trust())
                .unwrap()
                .manifest,
            &key(),
            vec![
                ("artifacts/vmlinux".to_string(), b"kernel bytes".to_vec()),
                (
                    "artifacts/rootfs.ext4".to_string(),
                    b"rootfs bytes".to_vec(),
                ),
            ],
        )
        .unwrap();
        assert_eq!(from_files, from_bytes);
    }

    #[test]
    fn a_file_verifies_like_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = sealed_from_files(dir.path());
        let bytes = std::fs::read(&path).unwrap();

        let streamed = verify_bundle_file(&path, &trust()).expect("streamed verify");
        let in_memory = read_and_verify_bundle(&bytes, &trust()).expect("in-memory verify");

        assert_eq!(streamed.manifest, in_memory.manifest);
        assert_eq!(streamed.key_id, in_memory.key_id);
        assert_eq!(streamed.bundle_sha256, sha256_hex(&bytes));
    }

    fn flip(path: &Path, needle: &[u8], replacement: &[u8]) {
        let mut bytes = std::fs::read(path).unwrap();
        let at = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("needle in archive");
        bytes[at..at + needle.len()].copy_from_slice(replacement);
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn failed_replacement_preserves_the_previously_committed_generation() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("installed");
        let staging = directory.path().join("staging");
        std::fs::create_dir(&current).unwrap();
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(current.join("rootfs"), b"committed").unwrap();
        std::fs::write(staging.join("rootfs"), b"replacement").unwrap();
        let fail = |_: &Path, _: &Path| Err(io::Error::other("injected exchange failure"));
        assert!(publish_install_with(&staging, &current, fail).is_err());
        assert_eq!(std::fs::read(current.join("rootfs")).unwrap(), b"committed");
        assert_eq!(
            std::fs::read(staging.join("rootfs")).unwrap(),
            b"replacement"
        );
        publish_install_with(&staging, &current, exchange_directories).unwrap();
        assert_eq!(
            std::fs::read(current.join("rootfs")).unwrap(),
            b"replacement"
        );
        assert_eq!(std::fs::read(staging.join("rootfs")).unwrap(), b"committed");
    }

    #[test]
    fn a_tampered_artifact_is_refused_when_streamed() {
        let dir = tempfile::tempdir().unwrap();
        let path = sealed_from_files(dir.path());
        flip(&path, b"rootfs bytes", b"rootfs BYTES");

        assert!(matches!(
            verify_bundle_file(&path, &trust()),
            Err(BundleVerifyError::ArtifactSha256Mismatch { .. })
        ));
        let registry = BundleRegistry::new(dir.path().join("registry"));
        assert!(matches!(
            registry.install_file(&path, &trust(), false),
            Err(BundleInstallError::Verify(
                BundleVerifyError::ArtifactSha256Mismatch { .. }
            ))
        ));
        let lease_path = registry
            .root()
            .join(format!(".{}.lock", archive_sha256(&path).unwrap()));
        let leftovers: Vec<_> = std::fs::read_dir(registry.root())
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|path| path != &lease_path)
                    .collect()
            })
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "refused install left {leftovers:?}");
    }

    #[test]
    fn install_file_extracts_every_artifact_and_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = sealed_from_files(dir.path());
        let registry = BundleRegistry::new(dir.path().join("registry"));

        let installed = registry
            .install_file(&path, &trust(), false)
            .expect("install");

        assert_eq!(
            std::fs::read(installed.root.join("artifacts/rootfs.ext4")).unwrap(),
            b"rootfs bytes"
        );
        assert_eq!(
            std::fs::read(registry.archive_path(&installed.sha256)).unwrap(),
            std::fs::read(&path).unwrap()
        );
        assert!(
            registry
                .verified_manifest(&installed.sha256, &trust())
                .unwrap()
                .is_some()
        );
    }

    /// The installed directory carries the manifest and signature exactly as
    /// signed, so the install can be re-verified from the directory alone.
    #[test]
    fn install_file_writes_the_manifest_and_signature_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let path = sealed_from_files(dir.path());
        let registry = BundleRegistry::new(dir.path().join("registry"));
        let installed = registry.install_file(&path, &trust(), false).unwrap();

        let manifest = std::fs::read(installed.root.join(MANIFEST_FILENAME)).unwrap();
        let signature = std::fs::read(installed.root.join(SIGNATURE_FILENAME)).unwrap();
        let (head_manifest, head_signature) =
            read_manifest_entries(File::open(&path).unwrap()).unwrap();
        assert_eq!(manifest, head_manifest);
        assert_eq!(signature, head_signature);
        verify_signed_manifest(&manifest, &signature, &trust()).expect("installed head verifies");
    }

    #[test]
    fn a_second_install_verifies_then_refuses_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = sealed_from_files(dir.path());
        let registry = BundleRegistry::new(dir.path().join("registry"));
        registry.install_file(&path, &trust(), false).unwrap();

        assert!(matches!(
            registry.install_file(&path, &trust(), false),
            Err(BundleInstallError::AlreadyInstalled { .. })
        ));
        registry
            .install_file(&path, &trust(), true)
            .expect("force replaces");
        let untrusted = OneKey(SigningKey::from_bytes(&[12; 32]).verifying_key());
        assert!(
            matches!(
                registry.install_file(&path, &untrusted, false),
                Err(BundleInstallError::Verify(
                    BundleVerifyError::UnknownKey { .. }
                ))
            ),
            "an existing install must not excuse an archive that fails verification"
        );
    }

    #[test]
    fn a_file_that_changes_while_sealed_fails_the_write() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vmlinux"), b"kernel bytes").unwrap();
        // Declared from different bytes of the same length.
        let manifest = manifest(vec![artifact(
            "vmlinux",
            ArtifactRole::Kernel,
            b"KERNEL BYTES",
        )]);
        let err = write_bundle_to(
            &manifest,
            &key(),
            vec![(
                "artifacts/vmlinux".to_string(),
                BundlePayload::File(dir.path().join("vmlinux")),
            )],
            io::sink(),
        )
        .expect_err("digest drift");
        assert!(
            format!("{err:#}").contains("changed while it was being sealed"),
            "{err:#}"
        );
    }

    #[test]
    fn an_artifact_missing_from_the_archive_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let declared = manifest(vec![artifact("vmlinux", ArtifactRole::Kernel, b"k")]);
        let manifest_bytes = canonical_manifest_bytes(&declared).unwrap();
        let sig = ed25519_dalek::Signer::sign(&key(), &manifest_bytes).to_bytes();
        let mut tar = tar::Builder::new(Vec::new());
        append_entry(
            &mut tar,
            MANIFEST_FILENAME,
            manifest_bytes.len() as u64,
            manifest_bytes.as_slice(),
        )
        .unwrap();
        append_entry(&mut tar, SIGNATURE_FILENAME, 64, sig.as_slice()).unwrap();
        let path = dir.path().join("short.mvmpkg");
        std::fs::write(&path, tar.into_inner().unwrap()).unwrap();

        assert!(matches!(
            verify_bundle_file(&path, &trust()),
            Err(BundleVerifyError::ArtifactMissing { .. })
        ));
    }
}
