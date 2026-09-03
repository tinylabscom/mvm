//! Verity-sealed in-artifact provenance mark.
//!
//! At seal time (before the dm-verity hash is computed) the builder writes
//! two files into the rootfs being sealed:
//!
//! - `/mvm/provenance.json` — a canonical-JSON document naming the image
//!   identity, the signing builder, and the tool that sealed it.
//! - `/mvm/provenance.sig` — a detached Ed25519 signature over the
//!   JCS-canonical mark bytes, hex-encoded.
//!
//! Because the mark lands inside the image *before* verity formatting, the
//! kernel's dm-verity check covers it: a tampered mark changes the rootfs
//! bytes, breaks the roothash, and the guest refuses to boot. The signature
//! additionally binds the mark to a builder key at read time, so a mark can
//! be verified offline against an embedded public key and then matched to a
//! local trust anchor (`~/.mvm/keys/host-signer.pub`).
//!
//! Identity convention: `builder_id` is `mvm:builder:ed25519:sha256:<hex>`
//! where `<hex>` is the SHA-256 of the raw 32-byte Ed25519 verifying key —
//! the same fingerprint [`verify_mark`] recomputes from the embedded key, so
//! a mark that lies about its builder fails verification.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Wire schema of `/mvm/provenance.json`.
pub const PROVENANCE_MARK_SCHEMA: &str = "mvm.provenance-mark/v1";

/// In-rootfs path of the mark (relative to the unpacked tree root).
pub const MARK_PATH: &str = "mvm/provenance.json";

/// In-rootfs path of the detached mark signature.
pub const MARK_SIG_PATH: &str = "mvm/provenance.sig";

/// Ed25519 signature byte length.
const SIGNATURE_BYTES: usize = 64;

/// Inputs needed to write a provenance mark into a rootfs tree.
///
/// Built with [`SealEvidence::builder`]; the seal timestamp defaults to
/// "now" so ordinary callers only supply a signer and optionally the image
/// identity being sealed.
#[derive(Debug, Clone)]
pub struct SealEvidence<'a> {
    signer: &'a SigningKey,
    image_ref: Option<&'a str>,
    image_digest: Option<&'a str>,
    created: String,
}

impl<'a> SealEvidence<'a> {
    /// Builder entry point. `signer` is the builder identity key — the
    /// host signer conventionally (`mvmctl artifact pack` signs with the
    /// same key, so one trust anchor covers both artifact forms).
    pub fn builder(signer: &'a SigningKey) -> SealEvidenceBuilder<'a> {
        SealEvidenceBuilder {
            signer,
            image_ref: None,
            image_digest: None,
            created: None,
        }
    }

    /// The signing key — the statement/sidecar emitters reuse it.
    pub fn signer(&self) -> &'a SigningKey {
        self.signer
    }

    /// Canonical registry reference, when supplied.
    pub fn image_ref(&self) -> Option<&'a str> {
        self.image_ref
    }

    /// Resolved manifest digest, when supplied.
    pub fn image_digest(&self) -> Option<&'a str> {
        self.image_digest
    }

    fn mark(&self) -> ProvenanceMark {
        let verifying = self.signer.verifying_key();
        ProvenanceMark {
            schema: PROVENANCE_MARK_SCHEMA.to_string(),
            image_ref: self.image_ref.map(str::to_string),
            image_digest: self.image_digest.map(str::to_string),
            builder_id: builder_id(&verifying),
            signer_public_key: hex::encode(verifying.to_bytes()),
            tool: "mvmctl".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            created: self.created.clone(),
        }
    }
}

/// Builder for [`SealEvidence`].
#[derive(Debug, Clone)]
pub struct SealEvidenceBuilder<'a> {
    signer: &'a SigningKey,
    image_ref: Option<&'a str>,
    image_digest: Option<&'a str>,
    created: Option<String>,
}

impl<'a> SealEvidenceBuilder<'a> {
    /// Canonical registry reference of the image being sealed
    /// (e.g. `docker.io/library/nginx:1.27`).
    pub fn with_image_ref(mut self, image_ref: &'a str) -> Self {
        self.image_ref = Some(image_ref);
        self
    }

    /// Resolved manifest digest of the image being sealed
    /// (e.g. `sha256:…`), when the caller resolved one.
    pub fn with_image_digest(mut self, image_digest: &'a str) -> Self {
        self.image_digest = Some(image_digest);
        self
    }

    /// Seal timestamp, RFC 3339. Defaults to the current wall clock.
    pub fn with_created(mut self, created: impl Into<String>) -> Self {
        self.created = Some(created.into());
        self
    }

    pub fn build(self) -> SealEvidence<'a> {
        SealEvidence {
            signer: self.signer,
            image_ref: self.image_ref,
            image_digest: self.image_digest,
            created: self.created.unwrap_or_else(now_rfc3339),
        }
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// The `/mvm/provenance.json` document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceMark {
    /// Wire schema; readers refuse anything else.
    pub schema: String,
    /// Canonical registry reference of the sealed image, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
    /// Resolved manifest digest (`sha256:…`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    /// Builder identity fingerprint — `mvm:builder:ed25519:sha256:<hex>`.
    pub builder_id: String,
    /// Raw 32-byte Ed25519 verifying key, hex-encoded. Embedded so the
    /// mark is self-verifying; trust is decided by matching the
    /// recomputed fingerprint against a local anchor.
    pub signer_public_key: String,
    /// Tool that wrote the mark.
    pub tool: String,
    /// Version of the writing tool.
    pub tool_version: String,
    /// Seal timestamp, RFC 3339.
    pub created: String,
}

/// The parsed, signature-verified mark plus the recomputed builder
/// fingerprint — everything a reader needs to decide trust.
#[derive(Debug, Clone)]
pub struct VerifiedMark {
    /// The mark document.
    pub mark: ProvenanceMark,
    /// `mvm:builder:ed25519:sha256:<hex>` recomputed from the embedded
    /// key. Matches `mark.builder_id` by construction of verification.
    pub builder_fingerprint: String,
}

/// Compute the builder-id fingerprint for a verifying key.
pub fn builder_id(key: &VerifyingKey) -> String {
    format!("mvm:builder:ed25519:sha256:{}", key_fingerprint(key))
}

/// SHA-256 of the raw 32-byte Ed25519 verifying key, hex-encoded.
pub fn key_fingerprint(key: &VerifyingKey) -> String {
    let digest: [u8; 32] = sha2::Sha256::digest(key.to_bytes()).into();
    hex::encode(digest)
}

/// JCS-canonical bytes of a serializable value.
pub(crate) fn jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).context("JCS-canonical encode")
}

/// Write the mark and its detached signature into `tree_root` (the
/// unpacked rootfs tree, before ext4 materialization/verity hashing).
pub fn write_mark(tree_root: &Path, evidence: &SealEvidence<'_>) -> Result<()> {
    let mark = evidence.mark();
    let mark_bytes = jcs_bytes(&mark)?;
    let signature = evidence.signer.sign(&mark_bytes);
    let mark_dir = tree_root.join("mvm");
    std::fs::create_dir_all(&mark_dir).with_context(|| format!("create {}", mark_dir.display()))?;
    std::fs::write(mark_dir.join("provenance.json"), &mark_bytes)
        .context("write /mvm/provenance.json")?;
    std::fs::write(
        mark_dir.join("provenance.sig"),
        format!("{}\n", hex::encode(signature.to_bytes())),
    )
    .context("write /mvm/provenance.sig")?;
    tracing::info!(
        builder_id = %mark.builder_id,
        image_ref = ?mark.image_ref,
        "provenance mark written into sealed rootfs"
    );
    Ok(())
}

/// Verify a mark document + detached hex signature.
///
/// Re-canonicalizes the parsed document with JCS (so whitespace or key
/// order changes between write and read cannot desync the signed bytes),
/// verifies the Ed25519 signature against the embedded public key, and
/// checks the embedded key matches the claimed `builder_id`. Trust
/// against a local anchor is the caller's decision.
pub fn verify_mark(mark_json: &[u8], signature_hex: &str) -> Result<VerifiedMark> {
    let mark: ProvenanceMark =
        serde_json::from_slice(mark_json).context("parse provenance mark")?;
    if mark.schema != PROVENANCE_MARK_SCHEMA {
        anyhow::bail!(
            "unsupported provenance mark schema {:?}; want {PROVENANCE_MARK_SCHEMA}",
            mark.schema
        );
    }
    let key_bytes: [u8; 32] = hex::decode(&mark.signer_public_key)
        .context("decode embedded signer_public_key hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer_public_key is not 32 bytes"))?;
    let verifying = VerifyingKey::from_bytes(&key_bytes).context("parse embedded public key")?;
    let signature_bytes: [u8; SIGNATURE_BYTES] = hex::decode(signature_hex.trim())
        .context("decode provenance signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("provenance signature is not {SIGNATURE_BYTES} bytes"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    let canonical = jcs_bytes(&mark)?;
    verifying
        .verify(&canonical, &signature)
        .context("provenance mark signature invalid")?;
    let fingerprint = key_fingerprint(&verifying);
    if mark.builder_id != builder_id(&verifying) {
        anyhow::bail!(
            "mark builder_id {} does not match embedded key fingerprint {}",
            mark.builder_id,
            fingerprint
        );
    }
    Ok(VerifiedMark {
        mark,
        builder_fingerprint: fingerprint,
    })
}

/// Read the provenance mark out of a sealed ext4 image using host
/// `debugfs` (offline, no mount). Returns `Ok(None)` when the image has
/// no mark. `debugfs` is a Linux/e2fsprogs tool; on other hosts this
/// returns an error naming the limitation — roothash verification via
/// [`mvm_fs::ext4::verity::root_hash`] remains available everywhere.
pub fn read_mark_from_ext4(image: &Path) -> Result<Option<VerifiedMark>> {
    let debugfs = locate_debugfs().context(
        "debugfs (e2fsprogs) not found; reading an in-rootfs mark needs a Linux host or the builder VM",
    )?;
    let Some(mark_json) = debugfs_cat(&debugfs, image, "/mvm/provenance.json")? else {
        return Ok(None);
    };
    let Some(signature_hex) = debugfs_cat(&debugfs, image, "/mvm/provenance.sig")? else {
        anyhow::bail!("image has /mvm/provenance.json but no /mvm/provenance.sig");
    };
    verify_mark(mark_json.as_bytes(), &signature_hex).map(Some)
}

fn locate_debugfs() -> Option<std::path::PathBuf> {
    for candidate in [
        "/usr/sbin/debugfs",
        "/sbin/debugfs",
        "/usr/bin/debugfs",
        "/bin/debugfs",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    which::which("debugfs").ok()
}

/// `debugfs -R "cat <guest_path>" <image>`; `Ok(None)` when the guest
/// path is absent from the image.
fn debugfs_cat(debugfs: &Path, image: &Path, guest_path: &str) -> Result<Option<String>> {
    let output = std::process::Command::new(debugfs)
        .args(["-R", &format!("cat {guest_path}")])
        .arg(image)
        .output()
        .with_context(|| format!("spawn debugfs for {guest_path}"))?;
    if output.status.success() {
        return Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not found") {
        return Ok(None);
    }
    anyhow::bail!("debugfs cat {guest_path} failed: {stderr}");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    fn evidence(key: &SigningKey) -> SealEvidence<'_> {
        SealEvidence::builder(key)
            .with_image_ref("docker.io/library/nginx:1.27")
            .with_image_digest("sha256:abc123")
            .with_created("2026-09-02T00:00:00Z")
            .build()
    }

    #[test]
    fn mark_roundtrips_through_write_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        write_mark(dir.path(), &evidence(&key)).unwrap();

        let mark_json = std::fs::read(dir.path().join("mvm/provenance.json")).unwrap();
        let sig = std::fs::read_to_string(dir.path().join("mvm/provenance.sig")).unwrap();
        let verified = verify_mark(&mark_json, &sig).expect("mark verifies");

        assert_eq!(verified.mark.schema, PROVENANCE_MARK_SCHEMA);
        assert_eq!(
            verified.mark.image_ref.as_deref(),
            Some("docker.io/library/nginx:1.27")
        );
        assert_eq!(verified.mark.image_digest.as_deref(), Some("sha256:abc123"));
        assert_eq!(verified.mark.builder_id, builder_id(&key.verifying_key()));
        assert_eq!(
            verified.builder_fingerprint,
            key_fingerprint(&key.verifying_key())
        );
    }

    #[test]
    fn whitespace_and_key_order_changes_do_not_break_verification() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        write_mark(dir.path(), &evidence(&key)).unwrap();
        let mark: ProvenanceMark =
            serde_json::from_slice(&std::fs::read(dir.path().join("mvm/provenance.json")).unwrap())
                .unwrap();
        // Re-serialize in a different shape: pretty, different key order.
        let mut value = serde_json::to_value(&mark).unwrap();
        let obj = value.as_object_mut().unwrap();
        let created = obj.remove("created").unwrap();
        obj.insert("created".to_string(), created);
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        let sig = std::fs::read_to_string(dir.path().join("mvm/provenance.sig")).unwrap();
        verify_mark(pretty.as_bytes(), &sig)
            .expect("JCS re-canonicalization covers reserialization");
    }

    #[test]
    fn tampered_mark_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        write_mark(dir.path(), &evidence(&key)).unwrap();
        let sig = std::fs::read_to_string(dir.path().join("mvm/provenance.sig")).unwrap();
        let tampered = br#"{"schema":"mvm.provenance-mark/v1","tool":"mvmctl","tool_version":"0.18.0","created":"2026-09-02T00:00:00Z","builder_id":"x","signer_public_key":"y","image_ref":"evil"}"#;
        assert!(verify_mark(tampered, &sig).is_err());
    }

    #[test]
    fn mark_signed_by_another_key_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let key = test_key();
        write_mark(dir.path(), &evidence(&key)).unwrap();
        let mark_json = std::fs::read(dir.path().join("mvm/provenance.json")).unwrap();
        let other = SigningKey::from_bytes(&[7; 32]);
        let mark: ProvenanceMark = serde_json::from_slice(&mark_json).unwrap();
        let forged = serde_json::to_vec(&ProvenanceMark {
            signer_public_key: hex::encode(other.verifying_key().to_bytes()),
            builder_id: builder_id(&other.verifying_key()),
            ..mark
        })
        .unwrap();
        let sig = std::fs::read_to_string(dir.path().join("mvm/provenance.sig")).unwrap();
        assert!(verify_mark(&forged, &sig).is_err());
    }

    #[test]
    fn unknown_schema_is_refused() {
        let err = verify_mark(
            br#"{"schema":"mvm.provenance-mark/v2","tool":"t","tool_version":"1","created":"c","builder_id":"b","signer_public_key":"00"}"#,
            "00",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported provenance mark schema")
        );
    }

    #[test]
    fn missing_optional_identity_fields_roundtrip() {
        let key = test_key();
        let mark = SealEvidence::builder(&key)
            .with_created("2026-09-02T00:00:00Z")
            .build()
            .mark();
        let json = serde_json::to_value(&mark).unwrap();
        assert!(json.get("image_ref").is_none());
        assert!(json.get("image_digest").is_none());
        let back: ProvenanceMark = serde_json::from_value(json).unwrap();
        assert_eq!(back, mark);
    }

    #[test]
    fn mark_rejects_unknown_fields() {
        let key = test_key();
        let mark = evidence(&key).mark();
        let mut value = serde_json::to_value(&mark).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), serde_json::json!(1));
        assert!(serde_json::from_value::<ProvenanceMark>(value).is_err());
    }
}
