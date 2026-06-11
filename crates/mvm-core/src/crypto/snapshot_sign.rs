//! Content-addressed, Ed25519-signed snapshots.
//!
//! [`snapshot_hmac`](crate::crypto::snapshot_hmac) gives a snapshot a
//! host-local HMAC tag: that is *integrity* (the bytes didn't change) but
//! not *authentication* — anyone holding the symmetric HMAC key can forge
//! a fresh-looking envelope. Snapshots are instead treated like signed
//! bundles (claim 9): content-addressed (sha256 over the bytes) and
//! Ed25519-signed, so only the holder of the host's private key can vouch
//! for a snapshot and a single flipped byte breaks the content-address.
//!
//! This is an **additive** layer. It writes a separate `snapshot.sig`
//! sidecar next to `integrity.json`, leaving the HMAC path untouched (kept
//! as cheap local integrity). The Ed25519 signature is the authentication
//! gate at resume admit.
//!
//! ## Signing identity
//!
//! Snapshots are signed by the **host attestation identity**
//! ([`crate::crypto::attestation::identity`]) — the host's "I am this host"
//! key — resolved via [`host_snapshot_identity`]. Two reasons over a
//! dedicated key:
//!
//! 1. It is the identity a control plane already enrols and trusts. When
//!    mvmd verifies a worker's snapshot it pins that worker's *attestation*
//!    pubkey — no new per-host snapshot key to distribute.
//! 2. It is *not* the plan host-signer, which lives behind the claim-8
//!    subprocess moat (so a guest RCE can't forge plans). Snapshot sealing
//!    runs host-side in `mvm-backend`, outside that moat; reusing the plan
//!    key there would pull it into a process the moat keeps it out of. The
//!    attestation identity is loaded in-process by design and carries no
//!    such constraint.
//!
//! ## mvmd extensibility
//!
//! The substrate is key-source-agnostic: [`sign`] takes any `SigningKey`
//! and [`verify_signature`] takes a **set** of trusted signer pubkeys —
//! mvmd passes the enrolled worker identities, a standalone host passes its
//! own. The sidecar records the signer's pubkey so a verifier can identify
//! which enrolled key vouched for a given snapshot.

use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::attestation::identity::IdentityKey;
use crate::crypto::snapshot_hmac::SnapshotFiles;

/// Raw Ed25519 public key length.
const KEY_BYTES: usize = 32;
/// Ed25519 signature length.
const SIG_BYTES: usize = 64;

/// Filename of the signature sidecar written next to the snapshot.
pub const SIGNATURE_FILENAME: &str = "snapshot.sig";

/// The host identity that signs snapshots: the attestation identity,
/// resolved under the mvm **data dir** (`<data_dir>/attestation`) rather
/// than the attestation module's `$HOME`-based default. This honours
/// `MVM_DATA_DIR` isolation (so tests and parallel sessions don't share or
/// pollute the real `~/.mvm/attestation`) while coinciding with the
/// canonical `~/.mvm/attestation` in the default layout.
///
/// mvmd does not call this — it verifies a *worker's* snapshot by pinning
/// that worker's enrolled attestation pubkey via [`verify_signature`]'s
/// `trusted_signers`. This loader is the local host's own signing identity.
pub fn host_snapshot_identity() -> Result<IdentityKey> {
    let dir = PathBuf::from(crate::config::mvm_data_dir()).join("attestation");
    crate::crypto::attestation::identity::load_or_init_at(&dir)
}

/// Signature sidecar: the snapshot's content-address + an Ed25519 signature
/// over `(sha256 ‖ epoch)`, plus the signer's public key (pinned at verify
/// against the trusted set — a self-described pubkey proves nothing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSignature {
    /// sha256-hex content-address over the length-prefixed snapshot files.
    pub sha256: String,
    /// The epoch bound into the signed message — replay defence carried
    /// into the signature, not only the HMAC.
    pub epoch: u64,
    /// Ed25519 signature (hex) over `sha256_bytes ‖ be_u64(epoch)`.
    pub signature: String,
    /// Signer's Ed25519 public key (hex).
    pub pubkey: String,
}

/// Reasons signature verification fails.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotSigError {
    #[error("signature sidecar {} missing or unreadable: {detail}", path.display())]
    Missing { path: PathBuf, detail: String },
    #[error("signature sidecar {} could not be parsed: {detail}", path.display())]
    Parse { path: PathBuf, detail: String },
    #[error("I/O hashing snapshot files: {0}")]
    Io(String),
    #[error("snapshot content-address mismatch — a byte changed since signing")]
    ContentHashMismatch,
    #[error("signed epoch {got} != expected {expected}")]
    EpochMismatch { got: u64, expected: u64 },
    #[error("snapshot signed by an untrusted key (signer pubkey not in the trusted set)")]
    SignerMismatch,
    #[error("Ed25519 signature does not verify")]
    SignatureInvalid,
    #[error("malformed hex in signature sidecar field '{field}'")]
    BadHex { field: &'static str },
}

/// sha256 over the length-prefixed snapshot files. Same splice-defence idea
/// as [`snapshot_hmac::compute_tag`](crate::crypto::snapshot_hmac::compute_tag)
/// — length prefixes stop a chosen-prefix move between `vmstate` and `mem` —
/// but a plain digest; the authentication comes from the Ed25519 signature
/// over this hash. Streams the files so a multi-GB `mem.bin` isn't buffered.
pub fn compute_content_hash(files: &SnapshotFiles) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_file_lenprefixed(&mut hasher, &files.vmstate)?;
    hash_file_lenprefixed(&mut hasher, &files.mem)?;
    Ok(hasher.finalize().into())
}

fn hash_file_lenprefixed(hasher: &mut Sha256, path: &Path) -> std::io::Result<()> {
    let f = File::open(path)?;
    let len = f.metadata()?.len();
    hasher.update(len.to_be_bytes());
    let mut reader = BufReader::with_capacity(64 * 1024, f);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(())
}

/// The message that gets signed: the 32-byte content hash followed by the
/// big-endian epoch. Binding the epoch into the signature means a captured
/// older signed snapshot can't be re-presented at a higher epoch.
fn signed_message(content_hash: &[u8; 32], epoch: u64) -> [u8; 40] {
    let mut msg = [0u8; 40];
    msg[..32].copy_from_slice(content_hash);
    msg[32..].copy_from_slice(&epoch.to_be_bytes());
    msg
}

/// Sign a snapshot: compute its content-address, sign `(sha256 ‖ epoch)`
/// under `signing_key`, and write `snapshot.sig` atomically (mode 0600).
pub fn sign(
    snap_dir: &Path,
    files: &SnapshotFiles,
    epoch: u64,
    signing_key: &SigningKey,
) -> Result<SnapshotSignature> {
    let content_hash = compute_content_hash(files)
        .with_context(|| format!("hashing snapshot files in {}", snap_dir.display()))?;
    let sig = signing_key.sign(&signed_message(&content_hash, epoch));
    let sidecar = SnapshotSignature {
        sha256: hex_encode(&content_hash),
        epoch,
        signature: hex_encode(&sig.to_bytes()),
        pubkey: hex_encode(signing_key.verifying_key().as_bytes()),
    };
    write_sig_atomic(snap_dir, &sidecar)?;
    Ok(sidecar)
}

/// Verify `snapshot.sig`: the recorded signer pubkey must be in
/// `trusted_signers`, the epoch must match, the on-disk files must rehash
/// to the recorded content-address, and the Ed25519 signature must verify.
/// The authentication gate at resume admit.
///
/// `trusted_signers` is a set so the same routine serves a standalone host
/// (its own identity) and mvmd (the enrolled worker identities).
pub fn verify_signature(
    snap_dir: &Path,
    files: &SnapshotFiles,
    expected_epoch: u64,
    trusted_signers: &[VerifyingKey],
) -> std::result::Result<SnapshotSignature, SnapshotSigError> {
    let path = snap_dir.join(SIGNATURE_FILENAME);
    let raw = std::fs::read(&path).map_err(|e| SnapshotSigError::Missing {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    let sidecar: SnapshotSignature =
        serde_json::from_slice(&raw).map_err(|e| SnapshotSigError::Parse {
            path: path.clone(),
            detail: e.to_string(),
        })?;

    // Pin the signer first — a self-described pubkey proves nothing.
    let signer = decode_pubkey(&sidecar.pubkey)?;
    if !trusted_signers
        .iter()
        .any(|k| k.to_bytes() == signer.to_bytes())
    {
        return Err(SnapshotSigError::SignerMismatch);
    }
    if sidecar.epoch != expected_epoch {
        return Err(SnapshotSigError::EpochMismatch {
            got: sidecar.epoch,
            expected: expected_epoch,
        });
    }

    let actual = compute_content_hash(files).map_err(|e| SnapshotSigError::Io(e.to_string()))?;
    let claimed = decode_hash(&sidecar.sha256)?;
    if actual != claimed {
        return Err(SnapshotSigError::ContentHashMismatch);
    }

    let sig = decode_signature(&sidecar.signature)?;
    signer
        .verify(&signed_message(&actual, expected_epoch), &sig)
        .map_err(|_| SnapshotSigError::SignatureInvalid)?;
    Ok(sidecar)
}

fn write_sig_atomic(snap_dir: &Path, sidecar: &SnapshotSignature) -> Result<()> {
    let json = serde_json::to_vec_pretty(sidecar).context("serialize signature sidecar")?;
    let final_path = snap_dir.join(SIGNATURE_FILENAME);
    let tmp_path = snap_dir.join(format!("{SIGNATURE_FILENAME}.tmp"));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("open {} for write", tmp_path.display()))?;
        f.write_all(&json)
            .with_context(|| format!("write {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("rename {} → {}", tmp_path.display(), final_path.display()))?;
    Ok(())
}

fn decode_pubkey(hex: &str) -> std::result::Result<VerifyingKey, SnapshotSigError> {
    let bytes = hex_decode(hex).ok_or(SnapshotSigError::BadHex { field: "pubkey" })?;
    let arr: [u8; KEY_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| SnapshotSigError::BadHex { field: "pubkey" })?;
    VerifyingKey::from_bytes(&arr).map_err(|_| SnapshotSigError::BadHex { field: "pubkey" })
}

fn decode_hash(hex: &str) -> std::result::Result<[u8; 32], SnapshotSigError> {
    let bytes = hex_decode(hex).ok_or(SnapshotSigError::BadHex { field: "sha256" })?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SnapshotSigError::BadHex { field: "sha256" })
}

fn decode_signature(hex: &str) -> std::result::Result<Signature, SnapshotSigError> {
    let bytes = hex_decode(hex).ok_or(SnapshotSigError::BadHex { field: "signature" })?;
    let arr: [u8; SIG_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| SnapshotSigError::BadHex { field: "signature" })?;
    Ok(Signature::from_bytes(&arr))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_snap(dir: &Path) -> SnapshotFiles {
        std::fs::write(dir.join("vmstate.bin"), b"vmstate-bytes-here").unwrap();
        std::fs::write(dir.join("mem.bin"), b"memory-image-bytes").unwrap();
        SnapshotFiles {
            vmstate: dir.join("vmstate.bin"),
            mem: dir.join("mem.bin"),
        }
    }

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let signer = key();

        let sealed = sign(tmp.path(), &files, 4, &signer).unwrap();
        let verified = verify_signature(tmp.path(), &files, 4, &[signer.verifying_key()]).unwrap();
        assert_eq!(sealed, verified);
    }

    #[test]
    fn flipped_byte_breaks_content_address() {
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let signer = key();
        sign(tmp.path(), &files, 1, &signer).unwrap();

        let mut bytes = std::fs::read(&files.mem).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&files.mem, &bytes).unwrap();

        let err = verify_signature(tmp.path(), &files, 1, &[signer.verifying_key()]).unwrap_err();
        assert!(matches!(err, SnapshotSigError::ContentHashMismatch));
    }

    #[test]
    fn untrusted_signer_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let signer = key();
        sign(tmp.path(), &files, 1, &signer).unwrap();

        let attacker = key();
        let err = verify_signature(tmp.path(), &files, 1, &[attacker.verifying_key()]).unwrap_err();
        assert!(matches!(err, SnapshotSigError::SignerMismatch));
    }

    #[test]
    fn trusted_set_accepts_any_member() {
        // mvmd shape: several enrolled signers, the snapshot signed by one.
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let a = key();
        let b = key();
        sign(tmp.path(), &files, 2, &b).unwrap();
        let trusted = [a.verifying_key(), b.verifying_key()];
        assert!(verify_signature(tmp.path(), &files, 2, &trusted).is_ok());
    }

    #[test]
    fn epoch_mismatch_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let signer = key();
        sign(tmp.path(), &files, 3, &signer).unwrap();
        let err = verify_signature(tmp.path(), &files, 5, &[signer.verifying_key()]).unwrap_err();
        assert!(matches!(
            err,
            SnapshotSigError::EpochMismatch {
                got: 3,
                expected: 5
            }
        ));
    }

    #[test]
    fn tampered_signature_field_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let signer = key();
        sign(tmp.path(), &files, 1, &signer).unwrap();

        // Flip a byte inside the stored signature hex but keep it valid hex
        // of the right length, so it parses but fails Ed25519 verification.
        let sig_path = tmp.path().join(SIGNATURE_FILENAME);
        let mut v: SnapshotSignature =
            serde_json::from_slice(&std::fs::read(&sig_path).unwrap()).unwrap();
        let mut sig_bytes = hex_decode(&v.signature).unwrap();
        sig_bytes[0] ^= 0x01;
        v.signature = hex_encode(&sig_bytes);
        std::fs::write(&sig_path, serde_json::to_vec(&v).unwrap()).unwrap();

        let err = verify_signature(tmp.path(), &files, 1, &[signer.verifying_key()]).unwrap_err();
        assert!(matches!(err, SnapshotSigError::SignatureInvalid));
    }

    #[test]
    fn missing_sidecar_reports_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let files = make_snap(tmp.path());
        let signer = key();
        let err = verify_signature(tmp.path(), &files, 1, &[signer.verifying_key()]).unwrap_err();
        assert!(matches!(err, SnapshotSigError::Missing { .. }));
    }

    #[test]
    fn host_snapshot_identity_is_stable_under_data_dir() {
        // Pin MVM_DATA_DIR to a tempdir; the identity loads from
        // <data_dir>/attestation and is stable across calls.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("attestation");
        let id1 = crate::crypto::attestation::identity::load_or_init_at(&dir).unwrap();
        let id2 = crate::crypto::attestation::identity::load_or_init_at(&dir).unwrap();
        assert_eq!(id1.verifying.to_bytes(), id2.verifying.to_bytes());

        // A snapshot signed by it round-trips through verify.
        let files = make_snap(tmp.path());
        sign(tmp.path(), &files, 1, &id1.signing).unwrap();
        assert!(verify_signature(tmp.path(), &files, 1, &[id1.verifying_key()]).is_ok());
    }
}
