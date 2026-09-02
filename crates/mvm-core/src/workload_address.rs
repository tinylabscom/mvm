//! Canonical content address for the Workload IR.
//!
//! A [`WorkloadAddress`] is `sha256(JCS(NFC(workload_ir)))` rendered as
//! `sha256:<64-hex>` — the UOR-ADDR JSON realization (RFC 8785 JSON
//! Canonicalization Scheme + Unicode NFC + SHA-256). Two [`mvm_contract::ir::Workload`]
//! documents that deserialize to the same IR value get the same address
//! regardless of JSON object-key order, whitespace, or which SDK language
//! emitted them. Array order remains significant, as required by JSON and JCS.
//!
//! This module reuses `serde_jcs` (already a `mvm-core` dependency — the same
//! canonicalizer that signs [`crate::protocol::broker_control::ControlRequest`])
//! rather than `mvm_contract::ir::ir_hash`. `ir_hash` canonicalizes with an
//! in-crate, `no_std`-only JSON writer documented to sidestep full JCS number
//! handling; it exists to fingerprint IR for launch plans and audit records,
//! an internal use that has never needed cross-implementation conformance.
//! `WorkloadAddress` exists specifically to match the external UOR-ADDR JSON
//! realization byte-for-byte, so it normalizes JSON strings and object keys to
//! Unicode NFC before sending the value through the dedicated JCS crate.
//!
//! Caveat on the canonical form: `serde_jcs` 0.1.0 orders object keys by their
//! UTF-8 byte value, not the UTF-16 code-unit order true RFC 8785 mandates. The
//! two coincide for every code point up to U+FFFF but diverge for astral-plane
//! (>U+FFFF) keys, so an address computed here can differ from one a strictly
//! conformant implementation would produce for a workload carrying such keys.
//! The `canonicalizer_equivalence` test module documents and pins this
//! divergence class. The published UOR-ADDR JSON baseline is pinned separately
//! by the 12-fixture conformance test below.
//!
//! # What this is not
//!
//! A workload address authenticates nothing, proves no provenance, is not
//! confidential, and is not fresh. It **never** enters and must never be
//! confused with an exact-byte identity (OCI manifest/layer digests, `.mvm`
//! archive-entry SHA-256, kernel/rootfs/initrd/verity bytes, dm-verity
//! roothash — see [`crate::packs::Sha256Hex`] / [`crate::packs::OciDigest`]),
//! a trust/authorization artifact (signatures, plan admission, key ids — see
//! `mvm_contract::plan::bundle::KeyId`), or an ephemeral/replay identifier
//! (VM/op/session ids, plan nonces — see `mvm_contract::plan::types::Nonce`).
//! `WorkloadAddress` is a distinct type with no `From`/`Into`/`Deref` to or
//! from any of those — passing one where an exact-byte digest, key id, or
//! nonce is expected does not compile.
//!
//! That taxonomy separates *what* is identified. [`crate::at_rest`] adds the
//! orthogonal axis: given exact bytes, *which* bytes — the plaintext a protocol
//! names (σ) or the representation on disk (κ). They coincide only under the
//! identity transform, and mvm already has cases where they do not: an OCI
//! layer is `tar+gzip`, so the verified layer digest is κ while `diff_id` is σ,
//! and a sealed transcript records the digest of its ciphertext.

use mvm_contract::ir::{VersionError, Workload, validate_schema_version};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Canonical content address of a [`Workload`] IR document:
/// `sha256(JCS(NFC(ir)))` rendered `sha256:<64 lowercase hex>`.
///
/// Two declarations that deserialize to the same IR value have the same
/// address even when their JSON whitespace or object-key order differs.
/// Array order remains significant. This is not an exact-byte digest, a
/// signature, or a runtime/replay id; see the module docs for the full
/// boundary. Construct one from a schema-version-checked [`Workload`] via
/// [`workload_address`], or parse a
/// previously computed value with [`WorkloadAddress::parse`] /
/// [`str::parse`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkloadAddress(String);

impl WorkloadAddress {
    /// The fixed hash-axis prefix every workload address carries.
    pub const PREFIX: &'static str = "sha256:";

    /// Validates and wraps a `sha256:<64 lowercase hex>` string. Rejects any
    /// other prefix, wrong length, or non-lowercase-hex content. Shares the
    /// shape check with every other prefixed content-address newtype so none
    /// can drift.
    pub fn parse(value: impl Into<String>) -> Result<Self, WorkloadAddressParseError> {
        use crate::digest_shape::Sha256PrefixedShape;
        let value = value.into();
        match crate::digest_shape::validate_sha256_prefixed(&value) {
            Sha256PrefixedShape::Ok => Ok(Self(value)),
            Sha256PrefixedShape::MissingPrefix => {
                Err(WorkloadAddressParseError::MissingPrefix(value))
            }
            Sha256PrefixedShape::WrongLength { len } => {
                Err(WorkloadAddressParseError::WrongLength { len })
            }
            Sha256PrefixedShape::NonHex { ch } => Err(WorkloadAddressParseError::NonHex { ch }),
        }
    }

    /// The `sha256:<64-hex>` string view.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for WorkloadAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::str::FromStr for WorkloadAddress {
    type Err = WorkloadAddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for WorkloadAddress {
    type Error = WorkloadAddressParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<WorkloadAddress> for String {
    fn from(addr: WorkloadAddress) -> Self {
        addr.0
    }
}

/// [`WorkloadAddress::parse`] / [`WorkloadAddress::from_str`] failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkloadAddressParseError {
    /// The value did not start with `sha256:`.
    #[error("workload address must start with \"sha256:\", got {0:?}")]
    MissingPrefix(String),
    /// The hex portion (after the prefix) was not exactly 64 characters.
    #[error("workload address hex must be exactly 64 chars, got {len}")]
    WrongLength { len: usize },
    /// The hex portion contained a non-lowercase-hex character.
    #[error("workload address hex must be lowercase 0-9a-f, found {ch:?}")]
    NonHex { ch: char },
}

/// [`workload_address`] failure.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadAddressError {
    /// The IR declares a schema version this host does not recognize. A
    /// workload address is only meaningful at a known schema
    /// version, so addressing fails closed rather than hashing an
    /// unrecognized shape.
    #[error("workload schema version is not supported: {0}")]
    UnsupportedSchemaVersion(#[from] VersionError),
    /// The IR could not be serialized to its JCS canonical byte form.
    #[error("failed to canonicalize workload IR: {0}")]
    Canonicalize(#[from] serde_json::Error),
}

/// Computes the [`WorkloadAddress`] of `workload`: validates its declared
/// schema version (failing closed on anything unrecognized), normalizes JSON
/// strings and object keys to Unicode NFC, then hashes its RFC 8785
/// JSON-canonical form with SHA-256.
///
/// Pure and side-effect-free — the same `workload` value always produces the
/// same address, independent of how it was originally deserialized
/// (whitespace, key order).
pub fn workload_address(workload: &Workload) -> Result<WorkloadAddress, WorkloadAddressError> {
    validate_schema_version(&workload.schema_version)?;
    workload_address_json(serde_json::to_value(workload)?)
}

fn workload_address_json(value: Value) -> Result<WorkloadAddress, WorkloadAddressError> {
    let normalized = normalize_json(value);
    let bytes = serde_jcs::to_vec(&normalized)?;
    let digest = Sha256::digest(&bytes);
    Ok(WorkloadAddress(format!(
        "{}{}",
        WorkloadAddress::PREFIX,
        hex::encode(digest)
    )))
}

fn normalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_json).collect()),
        Value::Object(entries) => Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.nfc().collect(), normalize_json(value)))
                .collect(),
        ),
        Value::String(value) => Value::String(value.nfc().collect()),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::ir::{App, Entrypoint, Image, Resources, Source};

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
        let a = workload_address(&w).expect("valid IR");
        let b = workload_address(&w).expect("valid IR");
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

        let addr_compact = workload_address(&from_compact).expect("valid IR");
        let addr_pretty = workload_address(&from_pretty).expect("valid IR");
        assert_eq!(addr_compact, addr_pretty);
    }

    #[test]
    fn distinct_for_meaningfully_different_ir() {
        let a = sample_workload();
        let mut b = sample_workload();
        b.id = "goodbye".to_string();

        let addr_a = workload_address(&a).expect("valid IR");
        let addr_b = workload_address(&b).expect("valid IR");
        assert_ne!(addr_a, addr_b);
    }

    #[test]
    fn unsupported_schema_version_fails_closed() {
        let mut w = sample_workload();
        w.schema_version = "1.0".to_string();

        let err = workload_address(&w).expect_err("unsupported major must be rejected");
        assert!(matches!(
            err,
            WorkloadAddressError::UnsupportedSchemaVersion(VersionError::UnsupportedMajor {
                found: 1,
                supported: 0,
            })
        ));
    }

    #[test]
    fn parse_accepts_well_formed_address() {
        let s = format!("sha256:{}", "a".repeat(64));
        let addr = WorkloadAddress::parse(s.clone()).expect("well-formed");
        assert_eq!(addr.as_str(), s);
        assert_eq!(addr.to_string(), s);
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let bad = format!("md5:{}", "a".repeat(64));
        let err = WorkloadAddress::parse(bad.clone()).unwrap_err();
        assert_eq!(err, WorkloadAddressParseError::MissingPrefix(bad));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let bad = format!("sha256:{}", "a".repeat(63));
        let err = WorkloadAddress::parse(bad).unwrap_err();
        assert_eq!(err, WorkloadAddressParseError::WrongLength { len: 63 });
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        let bad = format!("sha256:{}", "A".repeat(64));
        let err = WorkloadAddress::parse(bad).unwrap_err();
        assert_eq!(err, WorkloadAddressParseError::NonHex { ch: 'A' });
    }

    #[test]
    fn parse_rejects_non_hex_char() {
        let bad = format!("sha256:{}", "g".repeat(64));
        let err = WorkloadAddress::parse(bad).unwrap_err();
        assert_eq!(err, WorkloadAddressParseError::NonHex { ch: 'g' });
    }

    #[test]
    fn from_str_matches_parse() {
        let s = format!("sha256:{}", "b".repeat(64));
        let via_from_str: WorkloadAddress = s.parse().expect("well-formed");
        let via_parse = WorkloadAddress::parse(s).expect("well-formed");
        assert_eq!(via_from_str, via_parse);
    }

    #[test]
    fn serde_round_trips() {
        let addr = workload_address(&sample_workload()).expect("valid IR");
        let json = serde_json::to_string(&addr).expect("serialize");
        assert_eq!(json, format!("{:?}", addr.as_str()));
        let back: WorkloadAddress = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, back);
    }

    #[test]
    fn serde_rejects_malformed_string() {
        let bad = "\"not-a-workload-address\"";
        let err = serde_json::from_str::<WorkloadAddress>(bad).unwrap_err();
        assert!(err.to_string().contains("workload address"));
    }

    /// Both `WorkloadAddress` and [`crate::packs::OciDigest`] use the exact
    /// same string shape (`sha256:<64-hex>`) — which is precisely why the
    /// boundary between them has to be a type-system property, not a
    /// string-shape check. A `sha256:...` string parses as either type on
    /// its own; there is no `From`/`TryFrom`/`Deref` from `WorkloadAddress`
    /// to `OciDigest` (or `Sha256Hex`, `KeyId`, `Nonce`) or back, so a value
    /// of one type cannot be handed to code expecting the other without an
    /// explicit, separate re-parse of the underlying string that names both
    /// types at the call site — exactly the compile-time separation the
    /// design requires.
    #[test]
    fn workload_address_shape_overlaps_oci_digest_but_types_never_convert() {
        let addr = workload_address(&sample_workload()).expect("valid IR");

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
    /// (RFC 8785) + Unicode NFC normalization + SHA-256, matching the
    /// UOR-ADDR JSON realization. The independent published UOR-ADDR vectors
    /// are covered by [`matches_published_uor_addr_json_fixtures`].
    #[test]
    fn golden_address_for_fixed_ir_fixture() {
        let addr = workload_address(&sample_workload()).expect("valid IR");
        assert_eq!(
            addr.as_str(),
            "sha256:bf6f9f61571d7c5080144d83b681eb6718d76ab30ab80f61a715c50ac85b6ab3"
        );
    }

    struct UorFixture {
        name: &'static str,
        raw_json: &'static str,
        expected_address: &'static str,
    }

    // These are the 12 JSON byte-identity fixtures published by UOR-ADDR's
    // conformance test at commit 165b51e3e2113ee5d032730cde709335d4fe9b60.
    const UOR_ADDR_FIXTURES: &[UorFixture] = &[
        UorFixture {
            name: "simple_object",
            raw_json: r#"{"foo": "bar"}"#,
            expected_address: "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b",
        },
        UorFixture {
            name: "empty_object",
            raw_json: "{}",
            expected_address: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        },
        UorFixture {
            name: "empty_array",
            raw_json: "[]",
            expected_address: "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        },
        UorFixture {
            name: "key_sort_test",
            raw_json: r#"{"b": 1, "a": 2}"#,
            expected_address: "sha256:d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
        },
        UorFixture {
            name: "unicode_muller",
            raw_json: r#"{"name": "Müller"}"#,
            expected_address: "sha256:5e92260d138e28f7118a40c3c44be922d4569a39f9f1de676ca334cf19c3a37c",
        },
        UorFixture {
            name: "unicode_sao_paulo",
            raw_json: r#"{"city": "São Paulo"}"#,
            expected_address: "sha256:0906524dcbec3bdb6aa4d7c22ed65d671ba32177b10823b6f256546280aa526b",
        },
        UorFixture {
            name: "unicode_cafe_composed",
            raw_json: r#"{"name": "café"}"#,
            expected_address: "sha256:645fa443126a8954fc6d871912b8fc67bc2ee8feae417efe55546251962ca74d",
        },
        UorFixture {
            name: "unicode_cafe_decomposed",
            raw_json: "{\"name\": \"cafe\u{0301}\"}",
            expected_address: "sha256:645fa443126a8954fc6d871912b8fc67bc2ee8feae417efe55546251962ca74d",
        },
        UorFixture {
            name: "mixed_types",
            raw_json: r#"{"int": 42, "bool": true, "null_val": null}"#,
            expected_address: "sha256:0966918f3851b97071b0e04d2576a2a86a197e71072b07061c8bfdaa6b6a5d2c",
        },
        UorFixture {
            name: "nested",
            raw_json: r#"{"nested": {"deep": {"value": "found"}}}"#,
            expected_address: "sha256:b18dce7d3cbf2ac3b908ad75c8420c4a42077192df69dffdbf786755724eff1d",
        },
        UorFixture {
            name: "string_array",
            raw_json: r#"["a", "b", "c"]"#,
            expected_address: "sha256:fa1844c2988ad15ab7b49e0ece09684500fad94df916859fb9a43ff85f5bb477",
        },
        UorFixture {
            name: "number_array",
            raw_json: "[1, 2, 3]",
            expected_address: "sha256:a615eeaee21de5179de080de8c3052c8da901138406ba71c38c032845f7d54f4",
        },
    ];

    #[test]
    fn matches_published_uor_addr_json_fixtures() {
        let mut failures = Vec::new();
        for fixture in UOR_ADDR_FIXTURES {
            let value: Value = serde_json::from_str(fixture.raw_json)
                .unwrap_or_else(|error| panic!("{} is invalid JSON: {error}", fixture.name));
            let actual = workload_address_json(value)
                .unwrap_or_else(|error| panic!("{} could not be addressed: {error}", fixture.name));
            if actual.as_str() != fixture.expected_address {
                failures.push(format!(
                    "{}: expected {}, got {}",
                    fixture.name,
                    fixture.expected_address,
                    actual.as_str()
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "UOR-ADDR vector mismatches:\n{}",
            failures.join("\n")
        );
    }
}
