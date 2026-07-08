//! On-disk trust config for attested packs.
//!
//! The verifier in `packs` looks a signing pubkey up out of band — never inside
//! the pack — and asks a revocation checker whether a signer or a specific pack
//! is still good. This module is the operator-supplied answer to both: a strict
//! JSON file listing the publishers we trust (their ed25519 pubkeys and the
//! channels they may publish to) and any revocations. It implements
//! `PackTrustStore` + `PackRevocationChecker` directly, so the host loads one
//! file and hands the same value to `verify_pack_at` as both trust store and
//! revocation checker.

use std::collections::BTreeSet;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::packs::{PackRevocationChecker, PackTrustStore, RevocationStatus, Sha256Hex};
use crate::plan::bundle::KeyId;

/// Trusted publishers plus revocations. Absence of this file means "trust
/// nothing" — the inert, fail-closed default (`load_pack_trust_config` returns
/// `Ok(None)`), which leaves the attested path unable to verify any pack. That
/// same inert state is `Default` (no publishers, no revocations): a verifier
/// holding it trusts no key and allows no channel, so the caller falls through.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackTrustConfig {
    pub publishers: Vec<TrustedPublisher>,
    #[serde(default)]
    pub revocations: Vec<RevokedPack>,
    /// Enterprise mirror base URL for pack + revocation downloads. When set,
    /// downloads target `<mirror>/<asset>` instead of the default release host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
    /// How pack artifacts may be acquired. Governs whether a network fetch is
    /// allowed at all and from where.
    #[serde(default)]
    pub fetch_mode: PackFetchMode,
}

/// Operator policy for how attested pack artifacts may be acquired. Read
/// alongside `PackTrustConfig::mirror` by [`resolve_pack_download_base`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PackFetchMode {
    /// Download from the mirror if configured, else the default release host.
    #[default]
    Online,
    /// Never download; use only already-cached, promoted packs.
    OfflinePinned,
    /// Download only from the configured mirror; never the default host.
    MirrorOnly,
    /// Never download a pack; always build locally in the builder VM.
    LocalRebuildRequired,
}

/// One publisher's verifying key and the channels it may publish to. The pubkey
/// is the raw 32-byte ed25519 verifying key, base64-encoded; its `KeyId` is
/// derived (never stored) so it can't drift from the key it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPublisher {
    pub pubkey_base64: String,
    pub channels: Vec<String>,
}

/// A revocation entry. With no `pack_hash` it revokes the whole key; with a
/// `pack_hash` it revokes exactly that pack under that key and leaves the
/// signer's other packs trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedPack {
    pub key_id: KeyId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_hash: Option<Sha256Hex>,
    pub reason: String,
}

impl PackTrustConfig {
    /// Union of every publisher's channels — the set a caller feeds into
    /// `LocalPackPolicy.allowed_channels`.
    pub fn allowed_channels(&self) -> BTreeSet<String> {
        self.publishers
            .iter()
            .flat_map(|publisher| publisher.channels.iter().cloned())
            .collect()
    }
}

/// Decode a publisher's base64 pubkey into a verifying key. Rejected at load so
/// a typo removing a legitimate publisher fails loudly rather than silently.
fn decode_pubkey(encoded: &str) -> Result<VerifyingKey, PackTrustError> {
    let bytes = B64
        .decode(encoded)
        .map_err(|reason| PackTrustError::MalformedPubkey(reason.to_string()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        PackTrustError::MalformedPubkey(format!("expected 32 pubkey bytes, got {}", bytes.len()))
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|reason| PackTrustError::MalformedPubkey(reason.to_string()))
}

/// Load and validate the trust config. A missing file is the inert default
/// (`Ok(None)`); a present file is parsed strictly and every publisher pubkey is
/// decoded eagerly so a malformed key is caught here, not at verify time.
pub fn load_pack_trust_config(path: &Path) -> Result<Option<PackTrustConfig>, PackTrustError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(PackTrustError::Io(error.to_string())),
    };
    let config: PackTrustConfig = serde_json::from_slice(&bytes)?;
    for publisher in &config.publishers {
        decode_pubkey(&publisher.pubkey_base64)?;
    }
    Ok(Some(config))
}

impl PackTrustStore for PackTrustConfig {
    fn verifying_key(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        self.publishers.iter().find_map(|publisher| {
            // Skip malformed keys defensively; `load_pack_trust_config` already
            // rejects them, so this only matters for hand-built configs.
            let vk = decode_pubkey(&publisher.pubkey_base64).ok()?;
            (KeyId::from_pubkey(&vk) == *key_id).then_some(vk)
        })
    }
}

impl PackRevocationChecker for PackTrustConfig {
    fn status(&self, key_id: &KeyId, pack_hash: &Sha256Hex) -> RevocationStatus {
        revocation_status(&self.revocations, key_id, pack_hash)
    }
}

/// Shared revocation-list scan: an entry whose `key_id` matches and whose
/// `pack_hash` is unset (whole-key) or equal to `pack_hash` (pinned) revokes.
/// Factored out so `pack_revocation::PackRevocationList` — the fetched,
/// project-signed counterpart to this operator-owned config — can reuse the
/// exact same matching rule instead of drifting a second copy.
pub(crate) fn revocation_status(
    revocations: &[RevokedPack],
    key_id: &KeyId,
    pack_hash: &Sha256Hex,
) -> RevocationStatus {
    for entry in revocations {
        if &entry.key_id != key_id {
            continue;
        }
        // A pinned pack_hash revokes only that pack; an unpinned entry
        // revokes the whole key.
        let matches = match &entry.pack_hash {
            Some(pinned) => pinned == pack_hash,
            None => true,
        };
        if matches {
            return RevocationStatus::Revoked {
                reason: entry.reason.clone(),
            };
        }
    }
    RevocationStatus::Good
}

/// Resolve the base URL a pack/revocation download should target, or `None`
/// when the policy forbids a network fetch (the caller then uses the local
/// cache or the builder VM). `default_base` is the project's release host.
/// Errors only when the policy REQUIRES a mirror that is not configured —
/// a misconfiguration that must fail loudly, not silently fall back to the
/// default host.
pub fn resolve_pack_download_base(
    config: &PackTrustConfig,
    default_base: &str,
) -> Result<Option<String>, PackTrustError> {
    match config.fetch_mode {
        PackFetchMode::Online => Ok(Some(
            config
                .mirror
                .clone()
                .unwrap_or_else(|| default_base.to_string()),
        )),
        PackFetchMode::MirrorOnly => config
            .mirror
            .clone()
            .map(Some)
            .ok_or(PackTrustError::MirrorRequired),
        PackFetchMode::OfflinePinned | PackFetchMode::LocalRebuildRequired => Ok(None),
    }
}

#[derive(Debug, Error)]
pub enum PackTrustError {
    #[error("trust config could not be read: {0}")]
    Io(String),
    #[error("trust config is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("trusted publisher pubkey is malformed: {0}")]
    MalformedPubkey(String),
    #[error("fetch_mode=mirror_only requires a configured mirror")]
    MirrorRequired,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;
    use crate::arch::GuestArch;
    use crate::packs::{
        HostCapability, LocalPackPolicy, PackBackend, PackBuilder, PackKind, PackManifest,
        PackMetadata, PackOutputHashes, PackProvenanceMeta, PackTrustMeta, PackVerifyError,
        PolicyCompatibility, ReproducibilityStatus, SbomReference, SignatureValidity,
        verify_pack_at,
    };

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey_base64(key: &SigningKey) -> String {
        B64.encode(key.verifying_key().to_bytes())
    }

    fn publisher(key: &SigningKey, channels: &[&str]) -> TrustedPublisher {
        TrustedPublisher {
            pubkey_base64: pubkey_base64(key),
            channels: channels.iter().map(|c| c.to_string()).collect(),
        }
    }

    fn sample_config() -> PackTrustConfig {
        PackTrustConfig {
            publishers: vec![
                publisher(&signing_key(1), &["stable", "beta"]),
                publisher(&signing_key(2), &["stable"]),
            ],
            revocations: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn config_roundtrips_without_revocations() {
        let config = sample_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let recovered: PackTrustConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, config);
    }

    #[test]
    fn config_roundtrips_with_revocations() {
        let mut config = sample_config();
        config.revocations = vec![
            RevokedPack {
                key_id: KeyId::from_pubkey(&signing_key(1).verifying_key()),
                pack_hash: None,
                reason: "key compromised".to_string(),
            },
            RevokedPack {
                key_id: KeyId::from_pubkey(&signing_key(2).verifying_key()),
                pack_hash: Some(Sha256Hex::from_bytes(b"bad-pack")),
                reason: "bad build".to_string(),
            },
        ];
        let json = serde_json::to_string(&config).expect("serialize");
        let recovered: PackTrustConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, config);
    }

    #[test]
    fn config_roundtrips_with_mirror_and_each_fetch_mode() {
        for fetch_mode in [
            PackFetchMode::Online,
            PackFetchMode::OfflinePinned,
            PackFetchMode::MirrorOnly,
            PackFetchMode::LocalRebuildRequired,
        ] {
            let mut config = sample_config();
            config.mirror = Some("https://mirror.example.test/packs".to_string());
            config.fetch_mode = fetch_mode;
            let json = serde_json::to_string(&config).expect("serialize");
            let recovered: PackTrustConfig = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(recovered, config, "fetch_mode {fetch_mode:?} roundtrips");
        }
    }

    #[test]
    fn mirror_and_fetch_mode_default_when_omitted() {
        let json = serde_json::to_string(&sample_config().publishers).expect("serialize");
        let raw = format!(r#"{{"publishers": {json}, "revocations": []}}"#);
        let config: PackTrustConfig = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(config.mirror, None);
        assert_eq!(config.fetch_mode, PackFetchMode::Online);
    }

    #[test]
    fn absent_file_is_inert_default() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("missing.json");
        assert_eq!(load_pack_trust_config(&path).expect("load"), None);
    }

    #[test]
    fn present_valid_file_loads() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("trust.json");
        fs::write(&path, serde_json::to_vec(&sample_config()).expect("json")).expect("write");
        let loaded = load_pack_trust_config(&path).expect("load").expect("some");
        assert_eq!(loaded, sample_config());
    }

    #[test]
    fn malformed_json_is_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("trust.json");
        fs::write(&path, b"{ not json ").expect("write");
        assert!(matches!(
            load_pack_trust_config(&path),
            Err(PackTrustError::Parse(_))
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("trust.json");
        fs::write(&path, br#"{"publishers": [], "surprise": true}"#).expect("write");
        let err = load_pack_trust_config(&path).expect_err("unknown field rejected");
        assert!(err.to_string().contains("surprise"), "got: {err}");
    }

    #[test]
    fn malformed_pubkey_rejected_at_load() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("trust.json");
        // Valid base64 but only 3 bytes — not a 32-byte ed25519 key.
        let config = PackTrustConfig {
            publishers: vec![TrustedPublisher {
                pubkey_base64: B64.encode([1u8, 2, 3]),
                channels: vec!["stable".to_string()],
            }],
            revocations: vec![],
            ..Default::default()
        };
        fs::write(&path, serde_json::to_vec(&config).expect("json")).expect("write");
        assert!(matches!(
            load_pack_trust_config(&path),
            Err(PackTrustError::MalformedPubkey(_))
        ));
    }

    #[test]
    fn non_base64_pubkey_rejected_at_load() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("trust.json");
        let config = PackTrustConfig {
            publishers: vec![TrustedPublisher {
                pubkey_base64: "!!! not base64 !!!".to_string(),
                channels: vec!["stable".to_string()],
            }],
            revocations: vec![],
            ..Default::default()
        };
        fs::write(&path, serde_json::to_vec(&config).expect("json")).expect("write");
        assert!(matches!(
            load_pack_trust_config(&path),
            Err(PackTrustError::MalformedPubkey(_))
        ));
    }

    #[test]
    fn verifying_key_returns_publisher_key() {
        let config = sample_config();
        let key = signing_key(1);
        let key_id = KeyId::from_pubkey(&key.verifying_key());
        assert_eq!(
            config.verifying_key(&key_id),
            Some(key.verifying_key()),
            "known publisher key is returned"
        );
    }

    #[test]
    fn verifying_key_returns_none_for_unknown_key() {
        let config = sample_config();
        let unknown = KeyId::from_pubkey(&signing_key(99).verifying_key());
        assert_eq!(config.verifying_key(&unknown), None);
    }

    #[test]
    fn allowed_channels_dedupes_union() {
        let config = sample_config();
        assert_eq!(
            config.allowed_channels(),
            BTreeSet::from(["stable".to_string(), "beta".to_string()])
        );
    }

    #[test]
    fn whole_key_revocation_covers_any_pack_hash() {
        let key_id = KeyId::from_pubkey(&signing_key(1).verifying_key());
        let config = PackTrustConfig {
            publishers: vec![publisher(&signing_key(1), &["stable"])],
            revocations: vec![RevokedPack {
                key_id: key_id.clone(),
                pack_hash: None,
                reason: "key compromised".to_string(),
            }],
            ..Default::default()
        };
        assert!(matches!(
            config.status(&key_id, &Sha256Hex::from_bytes(b"anything")),
            RevocationStatus::Revoked { .. }
        ));
        assert!(matches!(
            config.status(&key_id, &Sha256Hex::from_bytes(b"else")),
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn pack_pinned_revocation_matches_only_that_pack() {
        let key_id = KeyId::from_pubkey(&signing_key(1).verifying_key());
        let bad = Sha256Hex::from_bytes(b"bad-pack");
        let good = Sha256Hex::from_bytes(b"good-pack");
        let config = PackTrustConfig {
            publishers: vec![publisher(&signing_key(1), &["stable"])],
            revocations: vec![RevokedPack {
                key_id: key_id.clone(),
                pack_hash: Some(bad.clone()),
                reason: "bad build".to_string(),
            }],
            ..Default::default()
        };
        assert!(matches!(
            config.status(&key_id, &bad),
            RevocationStatus::Revoked { .. }
        ));
        assert_eq!(config.status(&key_id, &good), RevocationStatus::Good);
    }

    #[test]
    fn no_revocation_entry_is_good() {
        let config = sample_config();
        let key_id = KeyId::from_pubkey(&signing_key(1).verifying_key());
        assert_eq!(
            config.status(&key_id, &Sha256Hex::from_bytes(b"pack")),
            RevocationStatus::Good
        );
    }

    fn utc(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0)
            .single()
            .expect("valid timestamp")
    }

    /// Mint a signed Builder pack under `dir`, compatible with the hvf backend
    /// and the "stable" channel, signed by `key`.
    fn mint_pack(dir: &TempDir, key: &SigningKey) -> PackManifest {
        fs::write(dir.path().join("kernel"), b"builder-kernel").expect("write kernel");
        fs::write(dir.path().join("builder.img"), b"builder-image").expect("write builder");
        let metadata = PackMetadata {
            kind: PackKind::Builder,
            target_arch: GuestArch::host(),
            backend_compatibility: vec![PackBackend::Hvf, PackBackend::Libkrun],
            required_host_capabilities: vec![HostCapability("vsock".to_string())],
            policy_compatibility: PolicyCompatibility {
                policy_hash: Sha256Hex::from_bytes(b"policy"),
                local_rebuild_required: false,
                allowed_channels: vec!["stable".to_string()],
            },
            inputs: crate::packs::PackInputs {
                flake_locks: Vec::new(),
                derivations: Vec::new(),
                nar_hashes: Vec::new(),
                oci_images: Vec::new(),
                setup_commands: Vec::new(),
                source_revisions: Vec::new(),
                toolchain_versions: std::collections::BTreeMap::new(),
            },
            provenance: PackProvenanceMeta {
                builder_identity: "ci-builder".to_string(),
                build_environment_identity: "github-actions".to_string(),
                build_timestamp: utc(2026, 6, 23),
                reproducibility: ReproducibilityStatus::Reproduced,
                sbom: SbomReference {
                    uri: "https://example.test/sbom.spdx.json".to_string(),
                    sha256: Sha256Hex::from_bytes(b"sbom"),
                },
            },
            trust: PackTrustMeta {
                expires_at: utc(2026, 12, 31),
                revocation_channel: "https://example.test/revocations.json".to_string(),
                channel_identity: "stable".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
            signature: SignatureValidity {
                signed_at: utc(2026, 6, 24),
                expires_at: utc(2026, 12, 31),
            },
        };
        PackBuilder::new(dir.path(), metadata, key)
            .files(["kernel", "builder.img"])
            .output_hashes(PackOutputHashes {
                kernel_hash: Some(Sha256Hex::from_bytes(b"builder-kernel")),
                builder_image_hash: Some(Sha256Hex::from_bytes(b"builder-image")),
                ..Default::default()
            })
            .build()
            .expect("produce pack")
    }

    fn policy_for(channels: &[&str]) -> LocalPackPolicy {
        LocalPackPolicy {
            host_arch: GuestArch::host(),
            backend: PackBackend::Hvf,
            host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
            policy_hash: Sha256Hex::from_bytes(b"policy"),
            allowed_channels: channels.iter().map(|c| c.to_string()).collect(),
            now: utc(2026, 6, 24),
        }
    }

    #[test]
    fn pack_signed_by_trusted_publisher_verifies_against_config() {
        let dir = TempDir::new().expect("tempdir");
        let key = signing_key(11);
        let manifest = mint_pack(&dir, &key);
        let config = PackTrustConfig {
            publishers: vec![publisher(&key, &["stable"])],
            revocations: vec![],
            ..Default::default()
        };
        let policy = policy_for(&["stable"]);
        // The config is fed as BOTH trust store and revocation checker.
        let verified =
            verify_pack_at(&manifest, dir.path(), &policy, &config, &config).expect("verifies");
        assert_eq!(verified.file_count, 2);
        assert_eq!(
            verified.signer_key_id,
            KeyId::from_pubkey(&key.verifying_key())
        );
    }

    #[test]
    fn pack_from_absent_publisher_is_rejected() {
        let dir = TempDir::new().expect("tempdir");
        let key = signing_key(11);
        let manifest = mint_pack(&dir, &key);
        // Config trusts a different publisher, so the signer's key is unknown.
        let config = PackTrustConfig {
            publishers: vec![publisher(&signing_key(22), &["stable"])],
            revocations: vec![],
            ..Default::default()
        };
        let policy = policy_for(&["stable"]);
        let err = verify_pack_at(&manifest, dir.path(), &policy, &config, &config)
            .expect_err("unknown signer rejected");
        assert!(matches!(err, PackVerifyError::UnknownSigningKey { .. }));
    }

    #[test]
    fn pack_on_disallowed_channel_is_rejected() {
        let dir = TempDir::new().expect("tempdir");
        let key = signing_key(11);
        let manifest = mint_pack(&dir, &key);
        let config = PackTrustConfig {
            publishers: vec![publisher(&key, &["stable"])],
            revocations: vec![],
            ..Default::default()
        };
        // Policy allows only "beta"; the pack publishes to "stable".
        let policy = policy_for(&["beta"]);
        let err = verify_pack_at(&manifest, dir.path(), &policy, &config, &config)
            .expect_err("disallowed channel rejected");
        assert!(matches!(err, PackVerifyError::ChannelNotAllowed(_)));
    }

    #[test]
    fn revoked_signer_in_config_rejects_pack() {
        let dir = TempDir::new().expect("tempdir");
        let key = signing_key(11);
        let manifest = mint_pack(&dir, &key);
        let config = PackTrustConfig {
            publishers: vec![publisher(&key, &["stable"])],
            revocations: vec![RevokedPack {
                key_id: KeyId::from_pubkey(&key.verifying_key()),
                pack_hash: None,
                reason: "key compromised".to_string(),
            }],
            ..Default::default()
        };
        let policy = policy_for(&["stable"]);
        let err = verify_pack_at(&manifest, dir.path(), &policy, &config, &config)
            .expect_err("revoked signer rejected");
        assert!(matches!(err, PackVerifyError::Revoked { .. }));
    }

    const DEFAULT_BASE: &str = "https://github.com/tinylabscom/mvm/releases/download/v0.0.0";
    const MIRROR_BASE: &str = "https://mirror.example.test/packs";

    fn config_with(mirror: Option<&str>, fetch_mode: PackFetchMode) -> PackTrustConfig {
        PackTrustConfig {
            mirror: mirror.map(str::to_string),
            fetch_mode,
            ..Default::default()
        }
    }

    #[test]
    fn resolve_online_uses_default_base_without_mirror() {
        let config = config_with(None, PackFetchMode::Online);
        assert_eq!(
            resolve_pack_download_base(&config, DEFAULT_BASE).expect("resolves"),
            Some(DEFAULT_BASE.to_string())
        );
    }

    #[test]
    fn resolve_online_prefers_mirror_when_set() {
        let config = config_with(Some(MIRROR_BASE), PackFetchMode::Online);
        assert_eq!(
            resolve_pack_download_base(&config, DEFAULT_BASE).expect("resolves"),
            Some(MIRROR_BASE.to_string())
        );
    }

    #[test]
    fn resolve_mirror_only_uses_mirror_when_set() {
        let config = config_with(Some(MIRROR_BASE), PackFetchMode::MirrorOnly);
        assert_eq!(
            resolve_pack_download_base(&config, DEFAULT_BASE).expect("resolves"),
            Some(MIRROR_BASE.to_string())
        );
    }

    #[test]
    fn resolve_mirror_only_errs_without_mirror() {
        let config = config_with(None, PackFetchMode::MirrorOnly);
        assert!(matches!(
            resolve_pack_download_base(&config, DEFAULT_BASE),
            Err(PackTrustError::MirrorRequired)
        ));
    }

    #[test]
    fn resolve_offline_pinned_forbids_fetch_regardless_of_mirror() {
        for mirror in [None, Some(MIRROR_BASE)] {
            let config = config_with(mirror, PackFetchMode::OfflinePinned);
            assert_eq!(
                resolve_pack_download_base(&config, DEFAULT_BASE).expect("resolves"),
                None
            );
        }
    }

    #[test]
    fn resolve_local_rebuild_required_forbids_fetch_regardless_of_mirror() {
        for mirror in [None, Some(MIRROR_BASE)] {
            let config = config_with(mirror, PackFetchMode::LocalRebuildRequired);
            assert_eq!(
                resolve_pack_download_base(&config, DEFAULT_BASE).expect("resolves"),
                None
            );
        }
    }
}
