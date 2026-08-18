//! Bounded identifiers and digests shared by the assurance contract.
//!
//! The shapes here are fixed by the counterparty that consumes them: an
//! identifier is at most 160 bytes of `[A-Za-z0-9._-]` and a digest is
//! `sha256:` followed by exactly 64 lowercase-or-uppercase hex digits. They are
//! newtypes rather than `String` because every one of these values is copied
//! into an audit record and compared for equality against a value that came
//! from a different process; a loose string would let a caller smuggle a
//! newline, a path separator, or a look-alike into that comparison.

use alloc::string::String;
use core::fmt;

use serde::{Deserialize, Serialize};

/// Longest identifier accepted on the assurance wire.
pub const MAX_ASSURANCE_ID_BYTES: usize = 160;
/// Exact hex-digit count in a `sha256:` digest.
const SHA256_HEX_DIGITS: usize = 64;

/// A bounded, audit-safe identifier.
///
/// Unlike the agent-session identifiers this contract sits beside, uppercase is
/// legal: the finding and rule identifiers minted upstream look like
/// `SCOUT-RCE-001`, and lowercasing them here would silently break the join
/// back to the source finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct AssuranceId(String);

impl AssuranceId {
    /// Parse an identifier accepted on the assurance wire.
    pub fn parse(raw: impl Into<String>) -> Result<Self, AssuranceIdError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(AssuranceIdError::Empty);
        }
        if raw.len() > MAX_ASSURANCE_ID_BYTES {
            return Err(AssuranceIdError::TooLong);
        }
        if !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(AssuranceIdError::IllegalCharacter);
        }
        Ok(Self(raw))
    }

    /// Borrow the canonical wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AssuranceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for AssuranceId {
    type Error = AssuranceIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<AssuranceId> for String {
    fn from(value: AssuranceId) -> Self {
        value.0
    }
}

/// Why an identifier is not acceptable on the assurance wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum AssuranceIdError {
    #[error("assurance identifier is empty")]
    Empty,
    #[error("assurance identifier exceeds the wire length limit")]
    TooLong,
    #[error("assurance identifier contains an illegal character")]
    IllegalCharacter,
}

/// A `sha256:<64 hex>` digest.
///
/// Stored in its wire form rather than as `[u8; 32]` so that a digest which
/// round-trips through this contract is byte-identical to the one the
/// counterparty computed, including its hex case. Equality is over those exact
/// bytes, which is what the identity checks downstream depend on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parse a `sha256:`-prefixed hex digest.
    pub fn parse(raw: impl Into<String>) -> Result<Self, DigestError> {
        let raw = raw.into();
        let Some(hex) = raw.strip_prefix("sha256:") else {
            return Err(DigestError::MissingPrefix);
        };
        if hex.len() != SHA256_HEX_DIGITS {
            return Err(DigestError::WrongLength);
        }
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DigestError::NotHex);
        }
        Ok(Self(raw))
    }

    /// Render raw digest bytes in the canonical wire form.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut out = String::from("sha256:");
        for byte in bytes {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Self(out)
    }

    /// Borrow the canonical wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

/// Why a digest is not acceptable on the assurance wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum DigestError {
    #[error("digest is not sha256:-prefixed")]
    MissingPrefix,
    #[error("digest does not carry exactly 64 hex digits")]
    WrongLength,
    #[error("digest contains a non-hex character")]
    NotHex,
}

/// An opaque reference to evidence held elsewhere.
///
/// The point of the type is what it refuses to be: a host path, a socket name,
/// or a blob of log text. It carries a scheme-qualified pointer such as
/// `mvm:audit:<id>` that the holder of the corresponding store can resolve,
/// and nothing a reader could act on without that store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EvidenceRef(String);

/// Longest evidence reference accepted on the assurance wire.
pub const MAX_EVIDENCE_REF_BYTES: usize = 256;

impl EvidenceRef {
    /// Parse a `scheme:`-qualified evidence reference.
    pub fn parse(raw: impl Into<String>) -> Result<Self, EvidenceRefError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(EvidenceRefError::Empty);
        }
        if raw.len() > MAX_EVIDENCE_REF_BYTES {
            return Err(EvidenceRefError::TooLong);
        }
        if !raw.contains(':') {
            return Err(EvidenceRefError::MissingScheme);
        }
        // A reference is embedded in JSON and in audit entries; anything that
        // could terminate a field or read as a filesystem path is refused.
        if raw.bytes().any(|byte| {
            byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b'"' | b'\'' | b' ')
        }) {
            return Err(EvidenceRefError::IllegalCharacter);
        }
        Ok(Self(raw))
    }

    /// Borrow the canonical wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EvidenceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for EvidenceRef {
    type Error = EvidenceRefError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<EvidenceRef> for String {
    fn from(value: EvidenceRef) -> Self {
        value.0
    }
}

/// Why an evidence reference is not acceptable on the assurance wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum EvidenceRefError {
    #[error("evidence reference is empty")]
    Empty,
    #[error("evidence reference exceeds the wire length limit")]
    TooLong,
    #[error("evidence reference has no scheme")]
    MissingScheme,
    #[error("evidence reference contains an illegal character")]
    IllegalCharacter,
}

impl AssuranceIdError {
    /// Stable label for audit and error text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong => "too_long",
            Self::IllegalCharacter => "illegal_character",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn identifier_accepts_the_upstream_finding_shape() {
        for raw in [
            "SCOUT-RCE-001",
            "mvm-campaign-1",
            "trial-abc.def_9",
            "scout-run-0",
        ] {
            assert!(AssuranceId::parse(raw).is_ok(), "{raw} should parse");
        }
    }

    #[test]
    fn identifier_refuses_separators_control_bytes_and_overlong_input() {
        assert_eq!(AssuranceId::parse(""), Err(AssuranceIdError::Empty));
        assert_eq!(
            AssuranceId::parse("a/b"),
            Err(AssuranceIdError::IllegalCharacter)
        );
        assert_eq!(
            AssuranceId::parse("a b"),
            Err(AssuranceIdError::IllegalCharacter)
        );
        assert_eq!(
            AssuranceId::parse("a\nb"),
            Err(AssuranceIdError::IllegalCharacter)
        );
        let overlong = "a".repeat(MAX_ASSURANCE_ID_BYTES + 1);
        assert_eq!(AssuranceId::parse(overlong), Err(AssuranceIdError::TooLong));
        // Exactly at the bound is legal, so the check is `>` and not `>=`.
        assert!(AssuranceId::parse("a".repeat(MAX_ASSURANCE_ID_BYTES)).is_ok());
    }

    #[test]
    fn digest_round_trips_and_refuses_malformed_input() {
        let hex = "b".repeat(SHA256_HEX_DIGITS);
        let digest = Sha256Digest::parse(alloc::format!("sha256:{hex}")).expect("digest");
        assert_eq!(digest.as_str(), alloc::format!("sha256:{hex}"));

        assert_eq!(
            Sha256Digest::parse(hex.clone()),
            Err(DigestError::MissingPrefix)
        );
        assert_eq!(
            Sha256Digest::parse("sha256:abc"),
            Err(DigestError::WrongLength)
        );
        assert_eq!(
            Sha256Digest::parse(alloc::format!("sha256:{}", "z".repeat(SHA256_HEX_DIGITS))),
            Err(DigestError::NotHex)
        );
    }

    #[test]
    fn digest_from_bytes_matches_the_parsed_form() {
        let digest = Sha256Digest::from_bytes(&[0xab; 32]);
        assert_eq!(
            digest,
            Sha256Digest::parse(alloc::format!("sha256:{}", "ab".repeat(32))).expect("digest")
        );
    }

    #[test]
    fn evidence_ref_requires_a_scheme_and_refuses_paths() {
        assert!(EvidenceRef::parse("mvm:audit:entry-1").is_ok());
        assert_eq!(
            EvidenceRef::parse("no-scheme"),
            Err(EvidenceRefError::MissingScheme)
        );
        assert_eq!(
            EvidenceRef::parse("file:/etc/passwd"),
            Err(EvidenceRefError::IllegalCharacter)
        );
        assert_eq!(
            EvidenceRef::parse("mvm:audit:a b"),
            Err(EvidenceRefError::IllegalCharacter)
        );
    }

    #[test]
    fn serde_rejects_an_illegal_identifier_rather_than_accepting_it() {
        let error = serde_json::from_str::<AssuranceId>("\"bad/id\"").unwrap_err();
        assert!(error.to_string().contains("illegal character"), "{error}");
    }
}
