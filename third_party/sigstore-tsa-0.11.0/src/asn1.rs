//! ASN.1 types for RFC 3161 Time-Stamp Protocol
//!
//! This module defines the ASN.1 structures used in the Time-Stamp Protocol
//! as specified in RFC 3161.

use const_oid::ObjectIdentifier;
use der::{
    asn1::{BitString, GeneralizedTime, Int, OctetString, Uint},
    Decode, Encode, Sequence,
};
use rand::Rng;
use sigstore_types::HashAlgorithm;
use x509_cert::{ext::pkix::name::GeneralName, ext::Extensions};

/// OID for SHA-256: 2.16.840.1.101.3.4.2.1
pub const OID_SHA256: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_256;

/// OID for SHA-384: 2.16.840.1.101.3.4.2.2
pub const OID_SHA384: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_384;

/// OID for SHA-512: 2.16.840.1.101.3.4.2.3
pub const OID_SHA512: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_512;

/// OID for id-ct-TSTInfo: 1.2.840.113549.1.9.16.1.4
pub const OID_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Generates a random nonce for RFC 3161 timestamp requests.
///
/// Uses `der::asn1::Uint` to guarantee correct minimal positive DER INTEGER
/// encoding. Raw random bytes are passed through `Uint::new` which strips
/// leading zeros and adds sign-bit padding as required by DER.
pub fn generate_nonce() -> Int {
    let nonce: u64 = rand::rng().random();
    let uint = Uint::new(&nonce.to_be_bytes()).expect("valid uint from random u64");
    Int::from(uint)
}

/// Algorithm identifier with optional parameters
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    /// Algorithm OID
    pub algorithm: ObjectIdentifier,
    /// Optional parameters (usually NULL for hash algorithms)
    #[asn1(optional = "true")]
    pub parameters: Option<der::Any>,
}

impl AlgorithmIdentifier {
    /// Create a SHA-256 algorithm identifier
    pub fn sha256() -> Self {
        Self {
            algorithm: OID_SHA256,
            parameters: None,
        }
    }

    /// Create a SHA-384 algorithm identifier
    pub fn sha384() -> Self {
        Self {
            algorithm: OID_SHA384,
            parameters: None,
        }
    }

    /// Create a SHA-512 algorithm identifier
    pub fn sha512() -> Self {
        Self {
            algorithm: OID_SHA512,
            parameters: None,
        }
    }

    /// Try to convert to a HashAlgorithm enum
    pub fn to_hash_algorithm(&self) -> Option<HashAlgorithm> {
        match self.algorithm {
            OID_SHA256 => Some(HashAlgorithm::Sha2256),
            OID_SHA384 => Some(HashAlgorithm::Sha2384),
            OID_SHA512 => Some(HashAlgorithm::Sha2512),
            _ => None,
        }
    }
}

impl From<HashAlgorithm> for AlgorithmIdentifier {
    fn from(algo: HashAlgorithm) -> Self {
        match algo {
            HashAlgorithm::Sha2256 => Self::sha256(),
            HashAlgorithm::Sha2384 => Self::sha384(),
            HashAlgorithm::Sha2512 => Self::sha512(),
        }
    }
}

/// Message imprint containing hash algorithm and hashed message (ASN.1/DER format).
///
/// RFC 3161 Section 2.4.1
///
/// Note: This is different from `sigstore_types::MessageImprint` which is the
/// JSON/serde representation used in bundles.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Asn1MessageImprint {
    /// Hash algorithm used
    pub hash_algorithm: AlgorithmIdentifier,
    /// Hashed message
    pub hashed_message: OctetString,
}

impl Asn1MessageImprint {
    /// Create a new message imprint
    pub fn new(algorithm: AlgorithmIdentifier, digest: Vec<u8>) -> Self {
        Self {
            hash_algorithm: algorithm,
            hashed_message: OctetString::new(digest).expect("valid octet string"),
        }
    }
}

/// Time-stamp request
/// RFC 3161 Section 2.4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampReq {
    /// Version (must be 1)
    pub version: u8,
    /// Message imprint to be timestamped
    pub message_imprint: Asn1MessageImprint,
    /// Optional policy OID
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    /// Optional nonce
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    /// Whether to include certificates in response
    #[asn1(default = "default_false")]
    pub cert_req: bool,
    // Extensions omitted for simplicity
}

fn default_false() -> bool {
    false
}

impl TimeStampReq {
    /// Create a new timestamp request with an automatically generated nonce
    pub fn new(message_imprint: Asn1MessageImprint) -> Self {
        Self {
            version: 1,
            message_imprint,
            req_policy: None,
            nonce: Some(generate_nonce()),
            cert_req: true,
        }
    }

    /// Create a new timestamp request without a nonce (not recommended)
    pub fn new_without_nonce(message_imprint: Asn1MessageImprint) -> Self {
        Self {
            version: 1,
            message_imprint,
            req_policy: None,
            nonce: None,
            cert_req: true,
        }
    }

    /// Set the nonce manually (overrides auto-generated nonce).
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        let uint = Uint::new(&nonce.to_be_bytes()).expect("valid unsigned integer");
        self.nonce = Some(Int::from(uint));
        self
    }

    /// Set whether to request certificates
    pub fn with_cert_req(mut self, cert_req: bool) -> Self {
        self.cert_req = cert_req;
        self
    }

    /// Encode to DER
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        Encode::to_der(self)
    }
}

/// PKI status values
/// RFC 3161 Section 2.4.2
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PkiStatus {
    /// Granted
    Granted = 0,
    /// Granted with modifications
    GrantedWithMods = 1,
    /// Rejection
    Rejection = 2,
    /// Waiting
    Waiting = 3,
    /// Revocation warning
    RevocationWarning = 4,
    /// Revocation notification
    RevocationNotification = 5,
}

impl TryFrom<u8> for PkiStatus {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PkiStatus::Granted),
            1 => Ok(PkiStatus::GrantedWithMods),
            2 => Ok(PkiStatus::Rejection),
            3 => Ok(PkiStatus::Waiting),
            4 => Ok(PkiStatus::RevocationWarning),
            5 => Ok(PkiStatus::RevocationNotification),
            _ => Err(()),
        }
    }
}

/// PKI status info
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    /// Status value
    pub status: u8,
    /// Optional failure info
    #[asn1(optional = "true")]
    pub fail_info: Option<BitString>,
}

impl PkiStatusInfo {
    /// Check if the status indicates success
    pub fn is_success(&self) -> bool {
        self.status == PkiStatus::Granted as u8 || self.status == PkiStatus::GrantedWithMods as u8
    }

    /// Get the status as an enum
    pub fn status_enum(&self) -> Option<PkiStatus> {
        PkiStatus::try_from(self.status).ok()
    }
}

/// Accuracy of the timestamp
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    /// Seconds
    #[asn1(optional = "true")]
    pub seconds: Option<u64>,
    /// Milliseconds (1-999)
    #[asn1(context_specific = "0", optional = "true")]
    pub millis: Option<u16>,
    /// Microseconds (1-999)
    #[asn1(context_specific = "1", optional = "true")]
    pub micros: Option<u16>,
}

/// TSTInfo - the actual timestamp token info
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    /// Version (must be 1)
    pub version: u8,
    /// Policy OID
    pub policy: ObjectIdentifier,
    /// Message imprint
    pub message_imprint: Asn1MessageImprint,
    /// Serial number
    pub serial_number: Int,
    /// Generation time
    pub gen_time: GeneralizedTime,
    /// Accuracy
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    /// Ordering
    #[asn1(default = "default_false")]
    pub ordering: bool,
    /// Nonce
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    /// TSA name
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub tsa: Option<GeneralName>,
    /// Extensions
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    pub extensions: Option<Extensions>,
}

impl TstInfo {
    /// Decode from DER bytes
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }
}

/// Time-stamp response
/// RFC 3161 Section 2.4.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    /// Status information
    pub status: PkiStatusInfo,
    /// Time-stamp token (CMS ContentInfo)
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<der::Any>,
}

impl TimeStampResp {
    /// Decode from DER bytes
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        Self::from_der(bytes)
    }

    /// Check if the response indicates success
    pub fn is_success(&self) -> bool {
        self.status.is_success() && self.time_stamp_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_imprint_encode() {
        let digest = vec![0u8; 32]; // SHA-256 produces 32 bytes
        let imprint = Asn1MessageImprint::new(AlgorithmIdentifier::sha256(), digest);
        let der = Encode::to_der(&imprint).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_timestamp_req_encode() {
        let digest = vec![0u8; 32];
        let imprint = Asn1MessageImprint::new(AlgorithmIdentifier::sha256(), digest);
        let req = TimeStampReq::new(imprint);
        let der = req.to_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_timestamp_req_has_nonce() {
        let digest = vec![0u8; 32];
        let imprint = Asn1MessageImprint::new(AlgorithmIdentifier::sha256(), digest);
        let req = TimeStampReq::new(imprint);

        // Verify that the request has a nonce
        assert!(
            req.nonce.is_some(),
            "Nonce should be automatically generated"
        );
    }

    #[test]
    fn test_generate_nonce_roundtrips_as_canonical_der() {
        // Encode → decode round-trip. The der crate's Int decoder calls
        // `validate_canonical` internally, which rejects non-minimal
        // encodings (e.g. 0x00 0x35 — the same check Go's encoding/asn1
        // performs). If our nonce encoding is ever non-minimal, the
        // decode step will fail with a non-canonical error.
        for _ in 0..1000 {
            let nonce = generate_nonce();
            let encoded = Encode::to_der(&nonce).expect("DER encoding must succeed");
            let decoded = Int::from_der(&encoded);
            assert!(
                decoded.is_ok(),
                "nonce failed canonical DER round-trip: {:02x?} → {:?}",
                encoded,
                decoded.err()
            );
        }
    }

    #[test]
    fn test_uint_produces_canonical_der_for_problematic_patterns() {
        // These are the exact byte patterns that caused HTTP 400 with the
        // old code. Encode via Uint→Int, then decode to trigger
        // validate_canonical.

        let cases: &[&[u8]] = &[
            &[0x00, 0x35],             // leading zero unnecessary (0x35 high bit clear)
            &[0x00, 0xFF],             // leading zero IS needed (0xFF high bit set)
            &[0x00, 0x00, 0x42],       // two leading zeros, both unnecessary
            &[0x00, 0x00, 0x00, 0x01], // many leading zeros
        ];

        for input in cases {
            let uint = Uint::new(input).unwrap();
            let int = Int::from(uint);
            let encoded = Encode::to_der(&int).unwrap();
            let decoded = Int::from_der(&encoded);
            assert!(
                decoded.is_ok(),
                "input {:02x?} produced non-canonical DER: {:02x?} → {:?}",
                input,
                encoded,
                decoded.err()
            );
        }
    }

    #[test]
    fn test_pki_status() {
        assert!(PkiStatus::try_from(0).is_ok());
        assert!(PkiStatus::try_from(5).is_ok());
        assert!(PkiStatus::try_from(6).is_err());
    }
}
