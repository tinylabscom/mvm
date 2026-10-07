//! Streaming bundle I/O: sealing, verifying, and installing a `.mvmpkg`
//! without holding an artifact in memory.
//!
//! An artifact's bytes pass through a fixed-size copy buffer on their way
//! between the archive and their destination — a staging file on install, a
//! discarding sink on verify — and are hashed on the way. Memory use is
//! bounded by that buffer and the manifest, not by the size of the rootfs.
//! Only the embedded image-set manifests, which verification has to parse,
//! are read whole, and they are capped at [`MAX_IMAGE_SET_MANIFEST_BYTES`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256};

use super::{
    BundleArtifact, BundleInstallError, BundleManifest, BundleMember, BundleRegistry,
    BundleSizeBudget, BundleVerifyError, ImageSetSource, InstalledBundle, KeyId, MANIFEST_FILENAME,
    ManifestSigner, SIGNATURE_FILENAME, TrustStore, VerifiedEmbeddedImageSet,
    canonical_manifest_bytes, declarations, ensure_safe_path, install_embedded_image_set_cache,
    key_id_from_pubkey, read_manifest_entries, verify_embedded_image_sets, verify_signed_manifest,
};

/// Largest embedded image-set manifest verification will read. The manifest
/// is JSON naming a handful of artifacts; anything near this size is not one.
pub const MAX_IMAGE_SET_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Where verified artifact bytes can be read back from, by archive-relative
/// path: memory for a bundle verified from bytes, a staging directory for one
/// verified from a file.
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
pub(super) struct InMemoryArtifacts<'a>(pub &'a BTreeMap<String, Vec<u8>>);

impl ArtifactSource for InMemoryArtifacts<'_> {
    fn reader(&self, bundle_path: &str) -> io::Result<Box<dyn Read + '_>> {
        self.0
            .get(bundle_path)
            .map(|bytes| Box::new(bytes.as_slice()) as Box<dyn Read>)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, bundle_path.to_string()))
    }
}

/// Artifacts extracted under a directory at their archive-relative paths.
pub(super) struct StagedArtifacts<'a>(pub &'a Path);

impl ArtifactSource for StagedArtifacts<'_> {
    fn reader(&self, bundle_path: &str) -> io::Result<Box<dyn Read + '_>> {
        Ok(Box::new(File::open(self.0.join(bundle_path))?))
    }
}

/// A writer that hashes and counts what passes through it.
struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn finish(self) -> (u64, String) {
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
fn image_set_manifest_paths(manifest: &BundleManifest) -> BTreeSet<String> {
    manifest
        .members
        .iter()
        .filter_map(|member| match member {
            BundleMember::EmbeddedImageSet { manifest_artifact } => {
                manifest.find_by_name(manifest_artifact)
            }
            _ => None,
        })
        .map(|artifact| artifact.path.clone())
        .collect()
}

/// A bundle archive on disk that passed every check
/// [`super::read_and_verify_bundle`] makes, verified without loading it.
#[derive(Debug)]
pub struct VerifiedBundleFile {
    pub manifest: BundleManifest,
    pub key_id: KeyId,
    /// SHA-256 of the whole archive file.
    pub bundle_sha256: String,
    pub embedded_image_sets: Vec<VerifiedEmbeddedImageSet>,
}

fn open_archive(path: &Path) -> Result<File, BundleVerifyError> {
    File::open(path).map_err(|e| {
        BundleVerifyError::ManifestParse(format!("opening bundle archive {}: {e}", path.display()))
    })
}

fn archive_sha256(path: &Path) -> Result<String, BundleVerifyError> {
    crate::crypto::image_verify::sha256_reader(open_archive(path)?).map_err(|e| {
        BundleVerifyError::ManifestParse(format!("hashing bundle archive {}: {e}", path.display()))
    })
}

/// Verify the manifest at the head of the archive at `path`.
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
pub fn verify_bundle_file(
    path: &Path,
    trust_store: &dyn TrustStore,
) -> Result<VerifiedBundleFile, BundleVerifyError> {
    let (manifest, key_id, _, _) = verify_head(path, trust_store)?;
    let capture = image_set_manifest_paths(&manifest);
    let captured = stream_artifacts(open_archive(path)?, &manifest, |artifact| {
        if capture.contains(&artifact.path) {
            Destination::Capture
        } else {
            Destination::Discard
        }
    })?;
    let embedded_image_sets = verify_embedded_image_sets(&manifest, &InMemoryArtifacts(&captured))?;
    Ok(VerifiedBundleFile {
        bundle_sha256: archive_sha256(path)?,
        manifest,
        key_id,
        embedded_image_sets,
    })
}

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
        let sha = archive_sha256(archive).map_err(BundleInstallError::Verify)?;
        let io_error = |reason: String| BundleInstallError::Io {
            bundle_sha256: sha.clone(),
            reason,
        };
        let install_dir = self.install_dir(&sha);
        if install_dir.exists() && !force {
            verify_bundle_file(archive, trust).map_err(BundleInstallError::Verify)?;
            return Err(BundleInstallError::AlreadyInstalled {
                bundle_sha256: sha.clone(),
            });
        }
        let (manifest, _, manifest_bytes, sig_bytes) =
            verify_head(archive, trust).map_err(BundleInstallError::Verify)?;

        self.create_root().map_err(io_error)?;
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

        if install_dir.exists() {
            std::fs::remove_dir_all(&install_dir).map_err(|e| {
                io_error(format!(
                    "removing existing install at {}: {e}",
                    install_dir.display()
                ))
            })?;
        }
        std::fs::rename(&staging, &install_dir).map_err(|e| {
            io_error(format!(
                "promoting staging {} → install {}: {e}",
                staging.display(),
                install_dir.display()
            ))
        })?;
        self.persist_archive(archive, &sha).map_err(io_error)?;

        Ok(InstalledBundle {
            sha256: sha,
            root: install_dir,
            manifest,
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
        std::fs::create_dir_all(&self.root)
            .map_err(|e| format!("creating registry root {}: {e}", self.root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("restricting registry root {}: {e}", self.root.display()))?;
        }
        Ok(())
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

enum StageError {
    Verify(BundleVerifyError),
    Io(String),
}

/// Extract and verify every artifact into `staging`, write the manifest and
/// signature beside them, and verify the embedded image sets.
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
    for (name, bytes) in head {
        std::fs::write(staging.join(name), bytes).map_err(|e| {
            StageError::Io(format!("writing {name} into {}: {e}", staging.display()))
        })?;
    }
    Ok(embedded)
}

/// The bytes of one artifact being sealed into a bundle.
#[derive(Debug, Clone)]
pub enum BundlePayload {
    /// Bytes already in memory.
    Bytes(Vec<u8>),
    /// A file read as it is written into the archive.
    File(PathBuf),
}

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
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    read: u64,
}

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

#[cfg(test)]
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
        let leftovers: Vec<_> = std::fs::read_dir(registry.root())
            .map(|entries| entries.filter_map(Result::ok).map(|e| e.path()).collect())
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
