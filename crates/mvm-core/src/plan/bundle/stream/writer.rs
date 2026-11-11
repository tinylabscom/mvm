//! Stream artifact payloads into a signed bundle archive.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256};

use super::super::{
    BundleManifest, MANIFEST_FILENAME, ManifestSigner, SIGNATURE_FILENAME,
    canonical_manifest_bytes, declarations, ensure_safe_path, key_id_from_pubkey,
};

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
            let actual = super::super::sha256_hex(bytes);
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

pub(super) fn append_entry<W: Write>(
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
