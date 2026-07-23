//! Semantic content identity for the Workload IR.
//!
//! A [`SemanticAddress`] is `sha256(JCS(workload_ir))` rendered as
//! `sha256:<64-hex>` — the UOR-ADDR JSON realization (RFC 8785 JSON
//! Canonicalization Scheme + SHA-256). Two [`mvm_protocol::ir::Workload`]
//! documents that mean the same thing get the same address regardless of
//! JSON key order, whitespace, or which SDK language emitted them.
//!
//! This module reuses `serde_jcs` (already a `mvm-core` dependency — the same
//! canonicalizer that signs [`crate::protocol::broker_control::ControlRequest`])
//! rather than `mvm_protocol::ir::ir_hash`. `ir_hash` canonicalizes with an
//! in-crate, `no_std`-only JSON writer documented to sidestep full JCS number
//! handling; it exists to fingerprint IR for launch plans and audit records,
//! an internal use that has never needed cross-implementation conformance.
//! `SemanticAddress` exists specifically to match the external UOR-ADDR
//! realization byte-for-byte, so it goes through the dedicated JCS crate.
//!
//! Caveat on the canonical form: `serde_jcs` 0.1.0 orders object keys by their
//! UTF-8 byte value, not the UTF-16 code-unit order true RFC 8785 mandates. The
//! two coincide for every code point up to U+FFFF but diverge for astral-plane
//! (>U+FFFF) keys, so an address computed here can differ from one a strictly
//! conformant implementation would produce for a workload carrying such keys.
//! The `canonicalizer_equivalence` test module documents and pins this
//! divergence class; cross-implementation conformance vectors are a tracked
//! follow-up.
//!
//! # What this is not
//!
//! A semantic address authenticates nothing, proves no provenance, is not
//! confidential, and is not fresh. It **never** enters and must never be
//! confused with an exact-byte identity (OCI manifest/layer digests, `.mvm`
//! archive-entry SHA-256, kernel/rootfs/initrd/verity bytes, dm-verity
//! roothash — see [`crate::packs::Sha256Hex`] / [`crate::packs::OciDigest`]),
//! a trust/authorization artifact (signatures, plan admission, key ids — see
//! `mvm_protocol::plan::bundle::KeyId`), or an ephemeral/replay identifier
//! (VM/op/session ids, plan nonces — see `mvm_protocol::plan::types::Nonce`).
//! `SemanticAddress` is a distinct type with no `From`/`Into`/`Deref` to or
//! from any of those — passing one where an exact-byte digest, key id, or
//! nonce is expected does not compile.

use mvm_protocol::ir::{VersionError, Workload, validate_schema_version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Semantic content identity of a [`Workload`] IR document:
/// `sha256(JCS(ir))` rendered `sha256:<64 lowercase hex>`.
///
/// This is a **semantic** identity — it says two workload declarations mean
/// the same thing. It is not an exact-byte digest, not a signature, and not
/// a runtime/replay id; see the module docs for the full boundary. Construct
/// one from a validated [`Workload`] via [`semantic_address`], or parse a
/// previously computed value with [`SemanticAddress::parse`] /
/// [`str::parse`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SemanticAddress(String);

impl SemanticAddress {
    /// The fixed hash-axis prefix every semantic address carries.
    pub const PREFIX: &'static str = "sha256:";

    /// Validates and wraps a `sha256:<64 lowercase hex>` string. Rejects any
    /// other prefix, wrong length, or non-lowercase-hex content. Shares the
    /// shape check with every other prefixed content-address newtype so none
    /// can drift.
    pub fn parse(value: impl Into<String>) -> Result<Self, SemanticAddressParseError> {
        use crate::digest_shape::Sha256PrefixedShape;
        let value = value.into();
        match crate::digest_shape::validate_sha256_prefixed(&value) {
            Sha256PrefixedShape::Ok => Ok(Self(value)),
            Sha256PrefixedShape::MissingPrefix => {
                Err(SemanticAddressParseError::MissingPrefix(value))
            }
            Sha256PrefixedShape::WrongLength { len } => {
                Err(SemanticAddressParseError::WrongLength { len })
            }
            Sha256PrefixedShape::NonHex { ch } => Err(SemanticAddressParseError::NonHex { ch }),
        }
    }

    /// The `sha256:<64-hex>` string view.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for SemanticAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for SemanticAddress {
    type Err = SemanticAddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for SemanticAddress {
    type Error = SemanticAddressParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<SemanticAddress> for String {
    fn from(addr: SemanticAddress) -> Self {
        addr.0
    }
}

/// [`SemanticAddress::parse`] / [`SemanticAddress::from_str`] failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SemanticAddressParseError {
    /// The value did not start with `sha256:`.
    #[error("semantic address must start with \"sha256:\", got {0:?}")]
    MissingPrefix(String),
    /// The hex portion (after the prefix) was not exactly 64 characters.
    #[error("semantic address hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    /// The hex portion contained a non-lowercase-hex character.
    #[error("semantic address hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

/// [`semantic_address`] failure.
#[derive(Debug, thiserror::Error)]
pub enum SemanticAddressError {
    /// The IR declares a schema version this host does not recognize. A
    /// semantic address is only meaningful at a known, validated schema
    /// version, so addressing fails closed rather than hashing an
    /// unrecognized shape.
    #[error("workload schema version is not supported: {0}")]
    UnsupportedSchemaVersion(#[from] VersionError),
    /// The IR could not be serialized to its JCS canonical byte form.
    #[error("failed to canonicalize workload IR: {0}")]
    Canonicalize(#[from] serde_json::Error),
}

/// Computes the [`SemanticAddress`] of `workload`: validates its declared
/// schema version (failing closed on anything unrecognized), then hashes
/// its RFC 8785 JSON-canonical form with SHA-256.
///
/// Pure and side-effect-free — the same `workload` value always produces the
/// same address, independent of how it was originally deserialized
/// (whitespace, key order).
pub fn semantic_address(workload: &Workload) -> Result<SemanticAddress, SemanticAddressError> {
    validate_schema_version(&workload.schema_version)?;
    let bytes = serde_jcs::to_vec(workload)?;
    let digest = Sha256::digest(&bytes);
    Ok(SemanticAddress(format!(
        "{}{}",
        SemanticAddress::PREFIX,
        hex::encode(digest)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_protocol::ir::{App, Entrypoint, Image, Resources, Source};

    fn sample_workload() -> Workload {
        Workload {
            schema_version: "0.1".to_string(),
            id: "hello".to_string(),
            apps: vec![App {
                name: "hello".to_string(),
                source: Source::LocalPath {
                    path: ".".to_string(),
                    include: vec!["**".to_string()],
                    exclude: vec![],
                },
                image: Image::NixPackages {
                    packages: vec!["python312".to_string()],
                },
                entrypoints: vec![Entrypoint::Command {
                    command: vec!["python".to_string(), "-m".to_string(), "hello".to_string()],
                    working_dir: "/app".to_string(),
                    env: Default::default(),
                }],
                env: Default::default(),
                mounts: vec![],
                network: None,
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: None,
                threat_tier: Default::default(),
                addons: vec![],
                hooks: Default::default(),
                files: vec![],
                health_check: None,
            }],
            volumes: vec![],
            extensions: Default::default(),
        }
    }

    #[test]
    fn deterministic_across_repeated_calls() {
        let w = sample_workload();
        let a = semantic_address(&w).expect("valid IR");
        let b = semantic_address(&w).expect("valid IR");
        assert_eq!(a, b);
    }

    #[test]
    fn format_invariant_across_json_whitespace_and_reparse() {
        let w = sample_workload();
        let compact = serde_json::to_string(&w).expect("serialize compact");
        let pretty = serde_json::to_string_pretty(&w).expect("serialize pretty");
        assert_ne!(
            compact, pretty,
            "fixture must actually exercise two encodings"
        );

        let from_compact: Workload = serde_json::from_str(&compact).expect("deserialize compact");
        let from_pretty: Workload = serde_json::from_str(&pretty).expect("deserialize pretty");

        let addr_compact = semantic_address(&from_compact).expect("valid IR");
        let addr_pretty = semantic_address(&from_pretty).expect("valid IR");
        assert_eq!(addr_compact, addr_pretty);
    }

    #[test]
    fn distinct_for_meaningfully_different_ir() {
        let a = sample_workload();
        let mut b = sample_workload();
        b.id = "goodbye".to_string();

        let addr_a = semantic_address(&a).expect("valid IR");
        let addr_b = semantic_address(&b).expect("valid IR");
        assert_ne!(addr_a, addr_b);
    }

    #[test]
    fn unsupported_schema_version_fails_closed() {
        let mut w = sample_workload();
        w.schema_version = "1.0".to_string();

        let err = semantic_address(&w).expect_err("unsupported major must be rejected");
        assert!(matches!(
            err,
            SemanticAddressError::UnsupportedSchemaVersion(VersionError::UnsupportedMajor {
                found: 1,
                supported: 0,
            })
        ));
    }

    #[test]
    fn parse_accepts_well_formed_address() {
        let s = format!("sha256:{}", "a".repeat(64));
        let addr = SemanticAddress::parse(s.clone()).expect("well-formed");
        assert_eq!(addr.as_str(), s);
        assert_eq!(addr.to_string(), s);
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let bad = format!("md5:{}", "a".repeat(64));
        let err = SemanticAddress::parse(bad.clone()).unwrap_err();
        assert_eq!(err, SemanticAddressParseError::MissingPrefix(bad));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let bad = format!("sha256:{}", "a".repeat(63));
        let err = SemanticAddress::parse(bad).unwrap_err();
        assert_eq!(err, SemanticAddressParseError::WrongLength { len: 63 });
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        let bad = format!("sha256:{}", "A".repeat(64));
        let err = SemanticAddress::parse(bad).unwrap_err();
        assert_eq!(err, SemanticAddressParseError::NonHex { ch: 'A' });
    }

    #[test]
    fn parse_rejects_non_hex_char() {
        let bad = format!("sha256:{}", "g".repeat(64));
        let err = SemanticAddress::parse(bad).unwrap_err();
        assert_eq!(err, SemanticAddressParseError::NonHex { ch: 'g' });
    }

    #[test]
    fn from_str_matches_parse() {
        let s = format!("sha256:{}", "b".repeat(64));
        let via_from_str: SemanticAddress = s.parse().expect("well-formed");
        let via_parse = SemanticAddress::parse(s).expect("well-formed");
        assert_eq!(via_from_str, via_parse);
    }

    #[test]
    fn serde_round_trips() {
        let addr = semantic_address(&sample_workload()).expect("valid IR");
        let json = serde_json::to_string(&addr).expect("serialize");
        assert_eq!(json, format!("{:?}", addr.as_str()));
        let back: SemanticAddress = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, back);
    }

    #[test]
    fn serde_rejects_malformed_string() {
        let bad = "\"not-a-semantic-address\"";
        let err = serde_json::from_str::<SemanticAddress>(bad).unwrap_err();
        assert!(err.to_string().contains("semantic address"));
    }

    /// Both `SemanticAddress` and [`crate::packs::OciDigest`] use the exact
    /// same string shape (`sha256:<64-hex>`) — which is precisely why the
    /// boundary between them has to be a type-system property, not a
    /// string-shape check. A `sha256:...` string parses as either type on
    /// its own; there is no `From`/`TryFrom`/`Deref` from `SemanticAddress`
    /// to `OciDigest` (or `Sha256Hex`, `KeyId`, `Nonce`) or back, so a value
    /// of one type cannot be handed to code expecting the other without an
    /// explicit, separate re-parse of the underlying string that names both
    /// types at the call site — exactly the compile-time separation the
    /// design requires.
    #[test]
    fn semantic_address_shape_overlaps_oci_digest_but_types_never_convert() {
        let addr = semantic_address(&sample_workload()).expect("valid IR");

        // Same shape, independently re-validated — not a type conversion.
        let reparsed_as_oci_digest = crate::packs::OciDigest::new(addr.as_str().to_string());
        assert!(
            reparsed_as_oci_digest.is_ok(),
            "documents the shape overlap this test guards against"
        );

        // `Sha256Hex` has no `sha256:` prefix in its wire shape, so the same
        // string is rejected there — a second, independent illustration that
        // these are unrelated types with coincidentally similar cousins.
        let reparsed_as_sha256_hex = crate::packs::Sha256Hex::new(addr.as_str().to_string());
        assert!(reparsed_as_sha256_hex.is_err());
    }

    /// Golden/pinned value for a fixed IR fixture. The realization is JCS
    /// (RFC 8785) + SHA-256, matching the UOR-ADDR JSON realization; this
    /// pin should be cross-checked against UOR-ADDR's published conformance
    /// vectors and the TS/Python SDK output once that access is available —
    /// that interop check is a follow-up, not part of this pilot.
    #[test]
    fn golden_address_for_fixed_ir_fixture() {
        let addr = semantic_address(&sample_workload()).expect("valid IR");
        assert_eq!(
            addr.as_str(),
            "sha256:bf6f9f61571d7c5080144d83b681eb6718d76ab30ab80f61a715c50ac85b6ab3"
        );
    }
}
