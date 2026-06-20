//! Portable signed `.mvm` artifacts.
//!
//! A `.mvm` file is a gzip-compressed tarball wrapping a sealed-prod
//! microVM image. It contains:
//!
//! ```text
//!   manifest.json                       ← signed envelope (this module)
//!   kernel/vmlinux
//!   rootfs/rootfs.ext4
//!   rootfs/rootfs.verity                (optional; required for sealed-prod)
//!   rootfs/roothash                     (optional; required for sealed-prod)
//!   initrd/verity-initrd.cpio.gz        (optional)
//!   cmdline.txt
//!   signatures/manifest.ed25519         ← 64-byte Ed25519 signature
//! ```
//!
//! The signature covers a deterministic byte representation of the
//! manifest (serde_json `to_vec` with `BTreeMap`-shaped fields → stable
//! ordering). The manifest itself embeds SHA-256 hashes of every other
//! file in the archive, so verifying the manifest signature transitively
//! verifies the whole archive contents.
//!
//! **Why not OCI.** OCI is the registry-distribution format; this is
//! the internal-sealed unit. `.mvm` remains the signed boundary and
//! optionally wraps in OCI for transport. Keeping the verification path
//! single ensures sealed-prod policies aren't split between two
//! formats.
//!
//! **Fail-closed properties** (artifact extraction is an attack
//! surface):
//! - Tar path-traversal entries (`../`, absolute paths) are rejected
//!   pre-extraction.
//! - Symlinks and hardlinks are rejected outright — the archive is
//!   regular files only.
//! - Special files (devices, fifos, sockets) are rejected.
//! - Each declared file is bounded by `MAX_ENTRY_BYTES`; the total
//!   uncompressed size by `MAX_ARCHIVE_BYTES`. Decompression bombs
//!   fail with `ArtifactError::SizeCap` before exhausting disk.
//! - Unknown manifest format versions are rejected (no permissive
//!   inference).
//! - `SealedProd`-declared artifacts that omit verity sidecars are
//!   rejected at verification time.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use mvm_core::arch::GuestArch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, Header};

// ============================================================================
// Public surface
// ============================================================================

/// Current `.mvm` manifest format. A future format bump is a breaking
/// change — old readers MUST refuse the new version, new readers MUST
/// refuse unknown versions: unknown artifact format versions fail
/// closed.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Hard cap on a single file inside the archive (2 GiB). Matches the
/// per-layer cap used by `oci_to_rootfs` for the same decompression-
/// bomb reason.
pub const MAX_ENTRY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Hard cap on the total uncompressed bytes consumed during verify
/// extraction (4 GiB). Any legitimate sealed image fits comfortably;
/// a malicious manifest pointing at a >4 GiB blob is refused before
/// it can fill the host disk.
pub const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Filename of the signed manifest inside the tar.
pub const MANIFEST_FILENAME: &str = "manifest.json";

/// Filename of the detached Ed25519 signature inside the tar.
pub const SIGNATURE_FILENAME: &str = "signatures/manifest.ed25519";

/// Profile a `.mvm` artifact declares for the guest agent it
/// boots into. Mirrors `mvm_core::security::AgentProfile`'s
/// wire-stable kebab-case shape so callers can re-export the
/// same enum across the boundary without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactProfile {
    SealedProd,
    Dev,
    Builder,
}

/// Per-file hash + size record. Filenames are the in-archive paths;
/// `size_bytes` matches what `tar` reports on `Entry::size()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
}

/// Security posture the artifact declares. `SealedProd` requires
/// verity sidecars to be present and listed in `files`; verify
/// refuses sealed-prod artifacts that omit them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityPosture {
    pub profile: ArtifactProfile,
    /// `true` when the rootfs is dm-verity-protected and the
    /// kernel cmdline carries a `roothash=` parameter.
    pub verity_protected: bool,
    /// `true` when the agent enforces `require_auth = true` on the
    /// vsock control socket.
    pub requires_auth: bool,
    /// `true` when the image config permits runtime volume mounts.
    /// `false` for the v1 SealedProd default (boot-declared volumes
    /// only).
    pub allows_volumes: bool,
    /// `true` when the image config permits outbound egress beyond
    /// the host firewall's deny-by-default.
    pub allows_egress: bool,
}

/// `.mvm` manifest. Serialized to `manifest.json` inside the
/// archive; the detached signature at `signatures/manifest.ed25519`
/// covers `to_signing_bytes()`.
///
/// `BTreeMap` for the file index gives deterministic JSON ordering
/// so re-serialisation produces byte-identical output — necessary
/// for signature verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Always `MANIFEST_FORMAT_VERSION` for the current shape.
    /// Unknown values are refused.
    pub format_version: u32,
    /// Producer's `CARGO_PKG_VERSION`. Surfaced in error messages;
    /// not load-bearing for verify (we don't pin host-vs-artifact
    /// versions).
    pub mvm_version: String,
    /// Guest CPU architecture. Serializes as `"aarch64"` / `"x86_64"`
    /// (snake_case). Mismatched arch fails at boot, not at verify.
    pub target_arch: GuestArch,
    /// SHA-256 hashes of every file in the archive, keyed by
    /// in-archive path. `BTreeMap` for deterministic ordering.
    pub files: BTreeMap<String, FileEntry>,
    /// Pointer back to the build provenance — the mvm tenant +
    /// build invocation that produced this artifact. Free-form
    /// today; reserved for attestation linkage.
    pub build_provenance: Option<String>,
    /// Security claims the producer makes about this artifact.
    pub security: SecurityPosture,
}

impl Manifest {
    /// Deterministic byte representation used by both signer and
    /// verifier. `serde_json::to_vec` is canonical here because
    /// `BTreeMap` gives ordered keys and we control every field
    /// shape (no `serde(flatten)`, no untagged enums).
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        serde_json::to_vec(self).map_err(ArtifactError::from)
    }
}

/// Inputs to `pack`. Filenames inside the archive are derived from
/// the field — for example, `kernel` always ends up at `kernel/vmlinux`.
/// Optional sidecars (`verity`, `roothash`, `initrd`) are skipped
/// when `None`; SealedProd verifies them in.
#[derive(Debug, Clone)]
pub struct PackInputs<'a> {
    pub kernel: &'a Path,
    pub rootfs: &'a Path,
    pub cmdline: &'a Path,
    pub verity: Option<&'a Path>,
    pub roothash: Option<&'a Path>,
    pub initrd: Option<&'a Path>,
    pub target_arch: GuestArch,
    pub build_provenance: Option<String>,
    pub security: SecurityPosture,
}

/// Sign-and-pack a `.mvm` artifact at `out_path`.
pub fn pack(
    inputs: &PackInputs<'_>,
    signing_key: &SigningKey,
    out_path: &Path,
) -> Result<(), ArtifactError> {
    // 1. Resolve every input. Each `Option<&Path>` either contributes
    //    a `(archive_path, host_path)` pair or is skipped.
    let mut planned: Vec<(String, &Path)> = vec![
        ("kernel/vmlinux".to_string(), inputs.kernel),
        ("rootfs/rootfs.ext4".to_string(), inputs.rootfs),
        ("cmdline.txt".to_string(), inputs.cmdline),
    ];
    if let Some(p) = inputs.verity {
        planned.push(("rootfs/rootfs.verity".to_string(), p));
    }
    if let Some(p) = inputs.roothash {
        planned.push(("rootfs/roothash".to_string(), p));
    }
    if let Some(p) = inputs.initrd {
        planned.push(("initrd/verity-initrd.cpio.gz".to_string(), p));
    }

    if inputs.security.profile == ArtifactProfile::SealedProd
        && (inputs.verity.is_none() || inputs.roothash.is_none())
    {
        return Err(ArtifactError::SealedProdMissingVerity);
    }

    // 2. Stream-hash each input file. We keep the byte content in
    //    memory only long enough to feed it into the tar writer
    //    below; for sealed prod artifacts the rootfs can be large
    //    (hundreds of MB), so reading once + writing once matters.
    //    The `files` map is built ahead of the tar so the manifest
    //    can be serialised + signed before any payload bytes go in.
    let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
    let mut total_bytes: u64 = 0;
    for (archive_path, host_path) in &planned {
        let (sha, size) = hash_file(host_path)?;
        if size > MAX_ENTRY_BYTES {
            return Err(ArtifactError::EntryTooLarge {
                path: archive_path.clone(),
                size,
            });
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_ARCHIVE_BYTES {
            return Err(ArtifactError::SizeCap);
        }
        files.insert(
            archive_path.clone(),
            FileEntry {
                path: archive_path.clone(),
                sha256_hex: sha,
                size_bytes: size,
            },
        );
    }

    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        mvm_version: env!("CARGO_PKG_VERSION").to_string(),
        target_arch: inputs.target_arch,
        files,
        build_provenance: inputs.build_provenance.clone(),
        security: inputs.security.clone(),
    };
    let manifest_bytes = manifest.to_signing_bytes()?;
    let signature: Signature = signing_key.sign(&manifest_bytes);

    // 3. Write tar.gz with manifest first, signature second, then
    //    every input file. The "manifest first" ordering means a
    //    streaming verifier can read manifest + signature + reject
    //    bad signatures before extracting a single payload byte.
    let file = File::create(out_path).with_context(|| format!("create {}", out_path.display()))?;
    let gz = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(gz);
    tar.mode(tar::HeaderMode::Deterministic);

    append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes)?;
    append_bytes(&mut tar, SIGNATURE_FILENAME, &signature.to_bytes())?;
    for (archive_path, host_path) in &planned {
        let bytes = fs::read(host_path).with_context(|| format!("read {}", host_path.display()))?;
        append_bytes(&mut tar, archive_path, &bytes)?;
    }
    tar.finish().context("finalize tar")?;
    Ok(())
}

/// Inspect a `.mvm` artifact's manifest **without** verifying the
/// signature. Useful for debugging ("what's in this file?") and for
/// tools that don't have the producer's verifying key yet — e.g.
/// a registry that wants to surface a `.mvm`'s file listing
/// before the operator decides whether to trust the producer.
///
/// The returned manifest is parsed but its signature is NOT
/// checked, payloads are NOT re-hashed, and SealedProd verity
/// requirements are NOT enforced. Callers that need any of those
/// must use [`verify`] instead. Format-version mismatch IS
/// rejected — even an inspection should refuse a wire shape it
/// can't safely parse.
pub fn inspect_unverified(path: &Path) -> Result<Manifest, ArtifactError> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let gz = GzDecoder::new(f);
    let mut archive = Archive::new(gz);
    let (manifest_bytes, _signature_bytes) = read_manifest_and_signature(&mut archive)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(ArtifactError::from)?;
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        return Err(ArtifactError::UnknownFormatVersion {
            got: manifest.format_version,
            expected: MANIFEST_FORMAT_VERSION,
        });
    }
    Ok(manifest)
}

/// Verify an existing `.mvm` artifact without extracting payload
/// bytes to disk. Returns the parsed `Manifest` on success.
pub fn verify(path: &Path, verifying_key: &VerifyingKey) -> Result<Manifest, ArtifactError> {
    // First pass: read manifest + signature. The archive layout
    // guarantees these are the first two entries, but we walk the
    // whole tar to find them so a re-ordered tar (e.g. produced by
    // a non-mvm packer) still verifies — at the cost of one extra
    // streaming pass.
    let manifest_bytes;
    let signature_bytes;
    {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let gz = GzDecoder::new(f);
        let mut archive = Archive::new(gz);
        let (m, s) = read_manifest_and_signature(&mut archive)?;
        manifest_bytes = m;
        signature_bytes = s;
    }

    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(ArtifactError::from)?;
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        return Err(ArtifactError::UnknownFormatVersion {
            got: manifest.format_version,
            expected: MANIFEST_FORMAT_VERSION,
        });
    }

    // Re-serialise the parsed manifest and compare against the on-
    // wire bytes; this catches a malicious packer that emits a JSON
    // shape we accept on read but whose re-serialisation differs.
    // `BTreeMap` + `deny_unknown_fields` already make the path
    // narrow; this is belt-and-suspenders.
    let canonical = manifest.to_signing_bytes()?;
    if canonical != manifest_bytes {
        return Err(ArtifactError::ManifestNotCanonical);
    }

    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| ArtifactError::BadSignatureBytes)?;
    verifying_key
        .verify(&manifest_bytes, &signature)
        .map_err(|_| ArtifactError::SignatureMismatch)?;

    // SealedProd posture requires verity sidecars to be present
    // AND listed in the manifest. Either omission is a refusal.
    if manifest.security.profile == ArtifactProfile::SealedProd {
        let need = ["rootfs/rootfs.verity", "rootfs/roothash"];
        for p in need {
            if !manifest.files.contains_key(p) {
                return Err(ArtifactError::SealedProdMissingVerity);
            }
        }
    }

    // Second pass: verify each payload file's SHA-256 against the
    // manifest. Streaming hash avoids holding the whole rootfs in
    // memory; size cap fires before exhausting disk on a manifest
    // that lies about its declared size.
    {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let gz = GzDecoder::new(f);
        let mut archive = Archive::new(gz);
        let mut total_bytes: u64 = 0;
        let mut hashed: BTreeMap<String, String> = BTreeMap::new();
        for entry in archive.entries().context("iterate archive")? {
            let entry = entry.context("read tar entry")?;
            validate_entry_meta(&entry)?;
            let path_str = entry_path_string(&entry)?;
            if path_str == MANIFEST_FILENAME || path_str == SIGNATURE_FILENAME {
                continue;
            }
            let declared =
                manifest
                    .files
                    .get(&path_str)
                    .ok_or_else(|| ArtifactError::UnexpectedFile {
                        path: path_str.clone(),
                    })?;
            if declared.size_bytes != entry.size() {
                return Err(ArtifactError::SizeMismatch {
                    path: path_str,
                    declared: declared.size_bytes,
                    actual: entry.size(),
                });
            }
            total_bytes = total_bytes.saturating_add(entry.size());
            if total_bytes > MAX_ARCHIVE_BYTES {
                return Err(ArtifactError::SizeCap);
            }
            let sha = stream_hash(entry)?;
            if sha != declared.sha256_hex {
                return Err(ArtifactError::HashMismatch {
                    path: path_str,
                    declared: declared.sha256_hex.clone(),
                    actual: sha,
                });
            }
            hashed.insert(path_str, declared.sha256_hex.clone());
        }
        // Every manifest entry must have been seen exactly once.
        // A missing file is a refusal — sealed-prod must not boot
        // a half-archive.
        for declared in manifest.files.keys() {
            if !hashed.contains_key(declared) {
                return Err(ArtifactError::MissingFile {
                    path: declared.clone(),
                });
            }
        }
    }

    Ok(manifest)
}

/// Verify a `.mvm` artifact and extract its payload files into `dest`.
///
/// Extraction happens *only after* full verification (signature, hashes,
/// format version, sealed-prod verity, size caps). Only files declared in
/// the verified manifest are written, each through the same
/// `entry_path_string` safety check `verify` uses (absolute paths and
/// non-normal components like `..` are rejected), so a tampered or
/// traversal-laden archive never lands a byte under `dest`. Returns the
/// verified `Manifest`. Missing parent directories under `dest` are created.
pub fn extract(
    path: &Path,
    verifying_key: &VerifyingKey,
    dest: &Path,
) -> Result<Manifest, ArtifactError> {
    // Full verification first: refuses tampered / wrong-key / unknown-version
    // / sealed-prod-missing-verity / oversize / traversal artifacts before a
    // single payload byte is written.
    let manifest = verify(path, verifying_key)?;

    // Write pass: re-read the archive and emit only manifest-listed files,
    // re-checking path safety per entry (defense in depth — `verify` already
    // ran the same check).
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let gz = GzDecoder::new(f);
    let mut archive = Archive::new(gz);
    for entry in archive.entries().context("iterate archive")? {
        let mut entry = entry.context("read tar entry")?;
        validate_entry_meta(&entry)?;
        let path_str = entry_path_string(&entry)?;
        if path_str == MANIFEST_FILENAME || path_str == SIGNATURE_FILENAME {
            continue;
        }
        if !manifest.files.contains_key(&path_str) {
            return Err(ArtifactError::UnexpectedFile { path: path_str });
        }
        let out = dest.join(&path_str);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let mut writer = File::create(&out).with_context(|| format!("create {}", out.display()))?;
        std::io::copy(&mut entry, &mut writer)
            .with_context(|| format!("write {}", out.display()))?;
    }
    Ok(manifest)
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("manifest format version {got} not supported (expected {expected})")]
    UnknownFormatVersion { got: u32, expected: u32 },
    #[error("sealed-prod artifact missing verity sidecars (rootfs.verity / roothash)")]
    SealedProdMissingVerity,
    #[error("manifest signature did not verify")]
    SignatureMismatch,
    #[error("manifest signature bytes are not a valid Ed25519 signature")]
    BadSignatureBytes,
    #[error("manifest JSON not in canonical form (re-serialise mismatch)")]
    ManifestNotCanonical,
    #[error("file {path} not declared in manifest")]
    UnexpectedFile { path: String },
    #[error("file {path} declared in manifest is missing from archive")]
    MissingFile { path: String },
    #[error("file {path} size mismatch: declared {declared}, actual {actual}")]
    SizeMismatch {
        path: String,
        declared: u64,
        actual: u64,
    },
    #[error("file {path} hash mismatch: declared {declared}, actual {actual}")]
    HashMismatch {
        path: String,
        declared: String,
        actual: String,
    },
    #[error("entry {path} exceeds per-entry size cap")]
    EntryTooLarge { path: String, size: u64 },
    #[error("archive exceeds total uncompressed size cap")]
    SizeCap,
    #[error("path-traversal entry rejected: {0}")]
    PathTraversal(String),
    #[error("non-regular file entry rejected: {0}")]
    NonRegularEntry(String),
    #[error("manifest absent from archive")]
    ManifestAbsent,
    #[error("signature absent from archive")]
    SignatureAbsent,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

// ============================================================================
// Helpers
// ============================================================================

fn append_bytes<W: Write>(
    tar: &mut Builder<W>,
    archive_path: &str,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let mut header = Header::new_gnu();
    header
        .set_path(archive_path)
        .map_err(|e| ArtifactError::Other(anyhow::anyhow!("set path {archive_path}: {e}")))?;
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    tar.append(&header, bytes)
        .with_context(|| format!("write tar entry {archive_path}"))?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<(String, u64), ArtifactError> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).context("read input")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let digest = hasher.finalize();
    Ok((hex_lower(&digest), total))
}

fn stream_hash<R: Read>(mut entry: R) -> Result<String, ArtifactError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = entry.read(&mut buf).context("read tar entry body")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0xf));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}

fn read_manifest_and_signature<R: Read>(
    archive: &mut Archive<R>,
) -> Result<(Vec<u8>, Vec<u8>), ArtifactError> {
    let mut manifest: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for entry in archive.entries().context("iterate archive")? {
        let mut entry = entry.context("read tar entry")?;
        validate_entry_meta(&entry)?;
        let path = entry_path_string(&entry)?;
        if path == MANIFEST_FILENAME {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf).context("read manifest body")?;
            manifest = Some(buf);
        } else if path == SIGNATURE_FILENAME {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf).context("read signature body")?;
            signature = Some(buf);
        }
        if manifest.is_some() && signature.is_some() {
            break;
        }
    }
    let manifest = manifest.ok_or(ArtifactError::ManifestAbsent)?;
    let signature = signature.ok_or(ArtifactError::SignatureAbsent)?;
    Ok((manifest, signature))
}

/// Reject anything that isn't a regular file with a tar-traversal-
/// safe path. Artifact extraction is an attack surface; this function
/// gates each of the specific risks.
fn validate_entry_meta<R: Read>(entry: &tar::Entry<'_, R>) -> Result<(), ArtifactError> {
    let kind = entry.header().entry_type();
    if kind != EntryType::Regular && kind != EntryType::Continuous {
        let p = entry
            .path()
            .ok()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unreadable>".to_string());
        return Err(ArtifactError::NonRegularEntry(format!(
            "{p}: kind={:?}",
            kind
        )));
    }
    Ok(())
}

/// Read an entry's path as a String, rejecting traversal components.
/// Refuses absolute paths, `..` segments, embedded NULs, and
/// non-UTF-8 paths.
fn entry_path_string<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, ArtifactError> {
    let path = entry
        .path()
        .map_err(|e| ArtifactError::PathTraversal(format!("read path: {e}")))?;
    let path: PathBuf = path.into_owned();
    if path.is_absolute() {
        return Err(ArtifactError::PathTraversal(format!(
            "absolute path: {}",
            path.display()
        )));
    }
    for c in path.components() {
        match c {
            Component::Normal(_) => {}
            _ => {
                return Err(ArtifactError::PathTraversal(format!(
                    "non-normal component in {}",
                    path.display()
                )));
            }
        }
    }
    path.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| ArtifactError::PathTraversal(format!("non-UTF8 path: {}", path.display())))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::io::Cursor;

    fn test_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn write_fixture(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    fn dev_inputs<'a>(kernel: &'a Path, rootfs: &'a Path, cmdline: &'a Path) -> PackInputs<'a> {
        PackInputs {
            kernel,
            rootfs,
            cmdline,
            verity: None,
            roothash: None,
            initrd: None,
            target_arch: GuestArch::Aarch64,
            build_provenance: Some("test".to_string()),
            security: SecurityPosture {
                profile: ArtifactProfile::Dev,
                verity_protected: false,
                requires_auth: false,
                allows_volumes: true,
                allows_egress: true,
            },
        }
    }

    fn sealed_inputs<'a>(
        kernel: &'a Path,
        rootfs: &'a Path,
        cmdline: &'a Path,
        verity: &'a Path,
        roothash: &'a Path,
    ) -> PackInputs<'a> {
        PackInputs {
            kernel,
            rootfs,
            cmdline,
            verity: Some(verity),
            roothash: Some(roothash),
            initrd: None,
            target_arch: GuestArch::Aarch64,
            build_provenance: Some("test".to_string()),
            security: SecurityPosture {
                profile: ArtifactProfile::SealedProd,
                verity_protected: true,
                requires_auth: true,
                allows_volumes: false,
                allows_egress: false,
            },
        }
    }

    #[test]
    fn pack_then_verify_dev_artifact_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"kernel bytes");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"rootfs bytes");
        let c = write_fixture(dir.path(), "cmdline.txt", b"console=hvc0 root=/dev/vda");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();

        let mf = verify(&out, &key.verifying_key()).unwrap();
        assert_eq!(mf.format_version, MANIFEST_FORMAT_VERSION);
        assert_eq!(mf.target_arch, GuestArch::Aarch64);
        assert_eq!(mf.security.profile, ArtifactProfile::Dev);
        assert!(mf.files.contains_key("kernel/vmlinux"));
        assert!(mf.files.contains_key("rootfs/rootfs.ext4"));
        assert!(mf.files.contains_key("cmdline.txt"));
    }

    #[test]
    fn extract_writes_verified_payload_to_dest() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"kernel bytes");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"rootfs bytes");
        let c = write_fixture(dir.path(), "cmdline.txt", b"console=hvc0");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();

        let dest = dir.path().join("extracted");
        let mf = extract(&out, &key.verifying_key(), &dest).unwrap();

        assert_eq!(mf.target_arch, GuestArch::Aarch64);
        assert_eq!(
            fs::read(dest.join("kernel/vmlinux")).unwrap(),
            b"kernel bytes"
        );
        assert_eq!(
            fs::read(dest.join("rootfs/rootfs.ext4")).unwrap(),
            b"rootfs bytes"
        );
        assert_eq!(fs::read(dest.join("cmdline.txt")).unwrap(), b"console=hvc0");
    }

    #[test]
    fn extract_writes_nothing_when_verification_fails() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"kernel bytes");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"rootfs bytes");
        let c = write_fixture(dir.path(), "cmdline.txt", b"console=hvc0");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();

        // A different key fails the signature check; extraction must abort
        // before writing any payload — a portable artifact is never a bypass.
        let wrong_key = test_keypair();
        let dest = dir.path().join("extracted");
        let err = extract(&out, &wrong_key.verifying_key(), &dest).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureMismatch));
        assert!(
            !dest.join("kernel/vmlinux").exists(),
            "no payload may land on disk when verification fails"
        );
    }

    #[test]
    fn pack_then_verify_sealed_artifact_roundtrips_with_verity() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"roothash=abc root=/dev/vda");
        let v = write_fixture(dir.path(), "rootfs.verity", b"v");
        let h = write_fixture(dir.path(), "roothash", b"deadbeef");
        let key = test_keypair();
        let out = dir.path().join("sealed.mvm");
        pack(&sealed_inputs(&k, &r, &c, &v, &h), &key, &out).unwrap();
        let mf = verify(&out, &key.verifying_key()).unwrap();
        assert_eq!(mf.security.profile, ArtifactProfile::SealedProd);
        assert!(mf.security.verity_protected);
    }

    #[test]
    fn pack_refuses_sealed_prod_without_verity_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let key = test_keypair();
        let out = dir.path().join("nope.mvm");
        // SealedProd posture but no verity/roothash supplied.
        let bad = PackInputs {
            kernel: &k,
            rootfs: &r,
            cmdline: &c,
            verity: None,
            roothash: None,
            initrd: None,
            target_arch: GuestArch::Aarch64,
            build_provenance: None,
            security: SecurityPosture {
                profile: ArtifactProfile::SealedProd,
                verity_protected: true,
                requires_auth: true,
                allows_volumes: false,
                allows_egress: false,
            },
        };
        let err = pack(&bad, &key, &out).unwrap_err();
        assert!(matches!(err, ArtifactError::SealedProdMissingVerity));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let producer = test_keypair();
        let attacker = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &producer, &out).unwrap();
        // Attacker's verifying key — same signature shape, wrong
        // public key. Verify must refuse rather than silently
        // accepting.
        let err = verify(&out, &attacker.verifying_key()).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_tampered_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"original rootfs");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();

        // Tamper: open the .mvm, swap a byte in the rootfs payload,
        // and re-pack with a fresh tar that keeps the original
        // manifest + signature. The simulation here writes a brand-
        // new archive with mutated rootfs bytes while pretending
        // the manifest is unchanged.
        tamper_payload(&out, "rootfs/rootfs.ext4", b"corrupted rootfs!");
        let err = verify(&out, &key.verifying_key()).unwrap_err();
        // The tampered rootfs has a different size + hash; either
        // a SizeMismatch or HashMismatch is acceptable — both
        // signal "the file changed after sign".
        assert!(
            matches!(
                err,
                ArtifactError::HashMismatch { .. } | ArtifactError::SizeMismatch { .. }
            ),
            "expected hash or size mismatch, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_unknown_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();

        // Re-pack the tar with a bumped format_version. The
        // signature was over the original manifest, so this will
        // also fail signature verify — but the format-version
        // check fires FIRST so the error is the right one.
        rewrite_manifest_version(&out, 999);
        let err = verify(&out, &key.verifying_key()).unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::UnknownFormatVersion { got: 999, .. }
        ));
    }

    #[test]
    fn verify_rejects_archive_missing_signature() {
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();

        // Re-pack the tar with the signature entry stripped.
        rebuild_archive_without(&out, &[SIGNATURE_FILENAME]);
        let err = verify(&out, &key.verifying_key()).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureAbsent), "got {err:?}");
    }

    #[test]
    fn inspect_unverified_returns_manifest_without_signature_check() {
        // Two-different-keys scenario: producer signs the artifact,
        // an inspector with the wrong key (or NO key at all) must
        // still be able to read the manifest. This is the load-
        // bearing distinction from `verify`.
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let producer = test_keypair();
        let attacker = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &producer, &out).unwrap();

        // Inspect with no key — manifest reads cleanly.
        let mf = inspect_unverified(&out).unwrap();
        assert_eq!(mf.format_version, MANIFEST_FORMAT_VERSION);
        assert_eq!(mf.security.profile, ArtifactProfile::Dev);
        assert!(mf.files.contains_key("kernel/vmlinux"));

        // `verify` with the wrong key on the same file must still
        // refuse — inspect's permissiveness doesn't bleed into
        // verify's trust check.
        let err = verify(&out, &attacker.verifying_key()).unwrap_err();
        assert!(matches!(err, ArtifactError::SignatureMismatch));
    }

    #[test]
    fn inspect_unverified_rejects_unknown_format_version() {
        // Even an inspection must refuse a wire shape it can't
        // safely parse — otherwise a future format-2 file would
        // half-deserialise into a format-1 struct.
        let dir = tempfile::tempdir().unwrap();
        let k = write_fixture(dir.path(), "vmlinux", b"k");
        let r = write_fixture(dir.path(), "rootfs.ext4", b"r");
        let c = write_fixture(dir.path(), "cmdline.txt", b"c");
        let key = test_keypair();
        let out = dir.path().join("out.mvm");
        pack(&dev_inputs(&k, &r, &c), &key, &out).unwrap();
        rewrite_manifest_version(&out, 999);

        let err = inspect_unverified(&out).unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::UnknownFormatVersion { got: 999, .. }
        ));
    }

    #[test]
    fn inspect_unverified_does_not_enforce_sealed_prod_verity() {
        // `verify` refuses a SealedProd artifact missing verity
        // sidecars; `inspect` is the diagnostic surface, so it
        // must show the bad manifest contents instead of
        // refusing — operators need to SEE what's wrong.
        // We can't pack such an artifact via `pack` (which
        // refuses), so build one by hand the same way the
        // path-traversal test does.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("bad-sealed.mvm");
        let key = test_keypair();
        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            mvm_version: "test".to_string(),
            target_arch: GuestArch::Aarch64,
            files: BTreeMap::new(),
            build_provenance: None,
            security: SecurityPosture {
                profile: ArtifactProfile::SealedProd,
                verity_protected: true,
                requires_auth: true,
                allows_volumes: false,
                allows_egress: false,
            },
        };
        let manifest_bytes = manifest.to_signing_bytes().unwrap();
        let sig = key.sign(&manifest_bytes);

        let buf = Vec::new();
        let gz = GzEncoder::new(buf, Compression::default());
        let mut tar = Builder::new(gz);
        tar.mode(tar::HeaderMode::Deterministic);
        append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
        append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
        tar.finish().unwrap();
        let gz_done = tar.into_inner().unwrap();
        let bytes = gz_done.finish().unwrap();
        fs::write(&out, bytes).unwrap();

        // Inspect surfaces the (broken) sealed-prod manifest.
        let mf = inspect_unverified(&out).unwrap();
        assert_eq!(mf.security.profile, ArtifactProfile::SealedProd);

        // Verify refuses (signature is fine, but the SealedProd
        // verity gate fires).
        let err = verify(&out, &key.verifying_key()).unwrap_err();
        assert!(matches!(err, ArtifactError::SealedProdMissingVerity));
    }

    #[test]
    fn verify_rejects_path_traversal_in_archive() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("malicious.mvm");
        // Build a tarball whose manifest claims to ship a normal
        // file but whose contents include a `../` traversal entry.
        // The verifier walks the archive entries before trusting
        // any payload, so the traversal entry fires the gate.
        let key = test_keypair();
        let mut manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            mvm_version: "test".to_string(),
            target_arch: GuestArch::Aarch64,
            files: BTreeMap::new(),
            build_provenance: None,
            security: SecurityPosture {
                profile: ArtifactProfile::Dev,
                verity_protected: false,
                requires_auth: false,
                allows_volumes: true,
                allows_egress: true,
            },
        };
        manifest.files.insert(
            "../escape".to_string(),
            FileEntry {
                path: "../escape".to_string(),
                sha256_hex: "a".repeat(64),
                size_bytes: 1,
            },
        );
        let manifest_bytes = manifest.to_signing_bytes().unwrap();
        let sig = key.sign(&manifest_bytes);

        let buf = Vec::new();
        let gz = GzEncoder::new(buf, Compression::default());
        let mut tar = Builder::new(gz);
        tar.mode(tar::HeaderMode::Deterministic);
        append_bytes(&mut tar, MANIFEST_FILENAME, &manifest_bytes).unwrap();
        append_bytes(&mut tar, SIGNATURE_FILENAME, &sig.to_bytes()).unwrap();
        // Mimic a malicious entry — by manipulating the tar Header
        // directly we get an entry whose path looks like `../escape`.
        let body = b"x";
        let mut header = Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(EntryType::Regular);
        header.set_path("../escape").expect_err(
            "tar refuses to encode absolute or traversal paths; use the override below",
        );
        // The tar crate refuses to encode `..` via `set_path`, so we
        // instead inject a synthetic entry that doesn't go through the
        // path normalizer. This exercises the verifier's defensive
        // path check against archives produced by hostile non-mvm
        // packers.
        let synthetic = synthetic_traversal_archive(&manifest_bytes, &sig.to_bytes());
        fs::write(&out, &synthetic).unwrap();
        let err = verify(&out, &key.verifying_key()).unwrap_err();
        assert!(
            matches!(err, ArtifactError::PathTraversal(_)),
            "got {err:?}"
        );
    }

    // ── Helpers used only by tests ────────────────────────────────

    /// Rebuild the gzipped tar at `path` with every entry except
    /// those whose archive path is in `drop`. Manifest + signature
    /// + payloads are preserved otherwise.
    fn rebuild_archive_without(path: &Path, drop: &[&str]) {
        let bytes = fs::read(path).unwrap();
        let gz = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz);

        let buf = Vec::new();
        let gz_out = GzEncoder::new(buf, Compression::default());
        let mut out = Builder::new(gz_out);
        out.mode(tar::HeaderMode::Deterministic);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let p = e.path().unwrap().to_string_lossy().to_string();
            if drop.contains(&p.as_str()) {
                continue;
            }
            let mut body = Vec::with_capacity(e.size() as usize);
            e.read_to_end(&mut body).unwrap();
            let mut h = Header::new_gnu();
            h.set_path(&p).unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_entry_type(EntryType::Regular);
            h.set_cksum();
            out.append(&h, body.as_slice()).unwrap();
        }
        out.finish().unwrap();
        let inner = out.into_inner().unwrap();
        let final_bytes = inner.finish().unwrap();
        fs::write(path, final_bytes).unwrap();
    }

    /// Rewrite the manifest entry in the archive at `path` with
    /// `format_version` set to `new_version`. Manifest signature is
    /// untouched, so verify is expected to fail — but the failure
    /// must be on the version check, not on signature.
    fn rewrite_manifest_version(path: &Path, new_version: u32) {
        let bytes = fs::read(path).unwrap();
        let gz = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz);

        let buf = Vec::new();
        let gz_out = GzEncoder::new(buf, Compression::default());
        let mut out = Builder::new(gz_out);
        out.mode(tar::HeaderMode::Deterministic);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let p = e.path().unwrap().to_string_lossy().to_string();
            let mut body = Vec::with_capacity(e.size() as usize);
            e.read_to_end(&mut body).unwrap();
            if p == MANIFEST_FILENAME {
                let mut m: Manifest = serde_json::from_slice(&body).unwrap();
                m.format_version = new_version;
                body = serde_json::to_vec(&m).unwrap();
            }
            let mut h = Header::new_gnu();
            h.set_path(&p).unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_entry_type(EntryType::Regular);
            h.set_cksum();
            out.append(&h, body.as_slice()).unwrap();
        }
        out.finish().unwrap();
        let inner = out.into_inner().unwrap();
        let final_bytes = inner.finish().unwrap();
        fs::write(path, final_bytes).unwrap();
    }

    /// Replace the bytes of `entry_path` inside the archive at `path`
    /// with `new_body`. Manifest + signature untouched — verify is
    /// expected to fail on size or hash mismatch.
    fn tamper_payload(path: &Path, entry_path: &str, new_body: &[u8]) {
        let bytes = fs::read(path).unwrap();
        let gz = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz);

        let buf = Vec::new();
        let gz_out = GzEncoder::new(buf, Compression::default());
        let mut out = Builder::new(gz_out);
        out.mode(tar::HeaderMode::Deterministic);
        for entry in archive.entries().unwrap() {
            let mut e = entry.unwrap();
            let p = e.path().unwrap().to_string_lossy().to_string();
            let mut body = Vec::with_capacity(e.size() as usize);
            e.read_to_end(&mut body).unwrap();
            if p == entry_path {
                body = new_body.to_vec();
            }
            let mut h = Header::new_gnu();
            h.set_path(&p).unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_entry_type(EntryType::Regular);
            h.set_cksum();
            out.append(&h, body.as_slice()).unwrap();
        }
        out.finish().unwrap();
        let inner = out.into_inner().unwrap();
        let final_bytes = inner.finish().unwrap();
        fs::write(path, final_bytes).unwrap();
    }

    /// Hand-build a gzipped tar whose entries include a
    /// path-traversal `../escape` regular-file entry. The `tar`
    /// crate's `set_path` refuses to encode `..` for us, so we
    /// build the tar by hand using the lower-level header API and
    /// manually constructing the path slot.
    fn synthetic_traversal_archive(manifest_bytes: &[u8], sig_bytes: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let gz = GzEncoder::new(&mut buf, Compression::default());
        let mut tar = Builder::new(gz);
        tar.mode(tar::HeaderMode::Deterministic);
        // Manifest + signature
        let mut h = Header::new_gnu();
        h.set_path(MANIFEST_FILENAME).unwrap();
        h.set_size(manifest_bytes.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_entry_type(EntryType::Regular);
        h.set_cksum();
        tar.append(&h, manifest_bytes).unwrap();
        let mut h2 = Header::new_gnu();
        h2.set_path(SIGNATURE_FILENAME).unwrap();
        h2.set_size(sig_bytes.len() as u64);
        h2.set_mode(0o644);
        h2.set_mtime(0);
        h2.set_entry_type(EntryType::Regular);
        h2.set_cksum();
        tar.append(&h2, sig_bytes).unwrap();

        // Synthesize a traversal entry by writing the GNU header
        // bytes directly. We bypass tar's encoder safety by using
        // append_data on a header whose `path` slot we set with the
        // raw bytes of "../escape".
        let mut bad = Header::new_gnu();
        // `set_path` would refuse `..` — instead set the long-name
        // GNU extension to point at the traversal. The tar crate
        // tolerates writing such headers; the verifier rejects them.
        bad.set_size(1);
        bad.set_mode(0o644);
        bad.set_mtime(0);
        bad.set_entry_type(EntryType::Regular);
        // Write the path bytes directly into the header name slot.
        let name_bytes = b"../escape";
        let name_field = bad.as_old_mut().name.as_mut_slice();
        name_field[..name_bytes.len()].copy_from_slice(name_bytes);
        bad.set_cksum();
        tar.append(&bad, &b"x"[..]).unwrap();

        tar.finish().unwrap();
        drop(tar);
        buf
    }

    /// Wire-compat: `GuestArch` must serialize as the bare arch string
    /// (`"aarch64"` / `"x86_64"`), not `"aarch64-linux"`. Any
    /// previously-persisted JSON that held `"aarch64"` still round-trips
    /// correctly after this migration — the serde representation is
    /// unchanged (was already `"aarch64"` via snake_case).
    #[test]
    fn target_arch_serde_wire_compat() {
        let j = serde_json::to_string(&GuestArch::Aarch64).unwrap();
        assert_eq!(j, "\"aarch64\"", "wire format must be bare arch string");
        let back: GuestArch = serde_json::from_str(&j).unwrap();
        assert_eq!(back, GuestArch::Aarch64);

        let j2 = serde_json::to_string(&GuestArch::X86_64).unwrap();
        assert_eq!(j2, "\"x86_64\"");
        let back2: GuestArch = serde_json::from_str(&j2).unwrap();
        assert_eq!(back2, GuestArch::X86_64);
    }
}
