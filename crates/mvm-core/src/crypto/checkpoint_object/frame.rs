//! Byte layout of a version 1 checkpoint object, and its keyless parser.
//!
//! ```text
//! offset  size  field
//! 0       4     magic "MVCO"
//! 4       1     format version (1)
//! 5       1     object kind (1 = chunk, 2 = index)
//! 6       2     reserved, must be zero
//! 8       1     key-domain length n (1..=255)
//! 9       n     key domain, UTF-8 (`host` or `tenant:<name>`)
//! 9+n     32    object reference
//! 41+n    8     plaintext length, big-endian
//! 49+n    60    wrapped data key (nonce ‖ key ‖ tag)
//! 109+n   rest  payload (nonce ‖ ciphertext ‖ tag), exactly plaintext length + 28
//! ```
//!
//! Every byte from offset 0 through the plaintext length is the object's
//! binding header. It is authenticated as associated data by both the payload
//! and the wrapped data key, so none of it can change without both failing.
//! Nothing is variable-length except the domain, whose length is a single
//! byte, and the payload, whose length the header fixes. The parser therefore
//! knows the exact frame size before it looks at any ciphertext and never
//! allocates.

use sha2::{Digest as _, Sha256};

use super::{CheckpointObjectError, ObjectKind, ObjectRef, REFERENCE_LEN};
use crate::crypto::aead::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};

/// Leading bytes of every checkpoint object.
pub const MAGIC: [u8; 4] = *b"MVCO";
/// The only format version this build writes or reads.
pub const FORMAT_VERSION: u8 = 1;
/// Longest key-domain string a frame can carry.
pub const MAX_DOMAIN_LEN: usize = u8::MAX as usize;
/// Size of the wrapped data key: an AEAD frame around one AES-256 key.
pub const WRAPPED_KEY_LEN: usize = NONCE_SIZE + KEY_SIZE + TAG_SIZE;
/// What the payload adds to the plaintext: one nonce and one tag.
pub const PAYLOAD_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;

const FIXED_PREFIX_LEN: usize = 9;
const PLAINTEXT_LEN_BYTES: usize = 8;
const FINGERPRINT_LABEL: &[u8] = b"mvm.checkpoint-object.fingerprint.v1\0";

/// Identity of an object's sealed payload bytes: SHA-256 over the payload
/// frame. Rewrapping keeps it unchanged because it never touches the payload,
/// and the wrapped data key authenticates it, so a key cannot be moved onto
/// another payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadFingerprint([u8; 32]);

impl PayloadFingerprint {
    pub(super) fn of(payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_LABEL);
        hasher.update(payload);
        Self(hasher.finalize().into())
    }

    /// The raw digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A structurally valid checkpoint object, borrowed from its bytes.
///
/// Parsing checks layout, version, kind, reserved bits, size bounds and exact
/// length. It proves nothing about authenticity: that needs the keys, and
/// happens in [`super::open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectFrame<'a> {
    kind: ObjectKind,
    domain: &'a str,
    reference: ObjectRef,
    plaintext_len: u64,
    header: &'a [u8],
    wrapped_key: &'a [u8],
    payload: &'a [u8],
}

impl<'a> ObjectFrame<'a> {
    /// Parse `bytes` as a version 1 object. Refuses anything that is not
    /// exactly one well-formed frame.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CheckpointObjectError> {
        let fixed = take(bytes, 0, FIXED_PREFIX_LEN)?;
        if fixed[..4] != MAGIC {
            return Err(CheckpointObjectError::BadMagic);
        }
        if fixed[4] != FORMAT_VERSION {
            return Err(CheckpointObjectError::UnsupportedVersion(fixed[4]));
        }
        let kind = ObjectKind::from_wire(fixed[5])?;
        if fixed[6..8] != [0, 0] {
            return Err(CheckpointObjectError::ReservedBitsSet);
        }
        let domain_len = usize::from(fixed[8]);
        if domain_len == 0 {
            return Err(CheckpointObjectError::EmptyDomain);
        }
        let domain = take(bytes, FIXED_PREFIX_LEN, domain_len)?;
        let domain =
            std::str::from_utf8(domain).map_err(|_| CheckpointObjectError::DomainNotUtf8)?;

        let reference_at = FIXED_PREFIX_LEN + domain_len;
        let reference = take(bytes, reference_at, REFERENCE_LEN)?;
        let reference = ObjectRef::from_bytes(reference.try_into().expect("taken exact length"));

        let len_at = reference_at + REFERENCE_LEN;
        let len_bytes = take(bytes, len_at, PLAINTEXT_LEN_BYTES)?;
        let plaintext_len = u64::from_be_bytes(len_bytes.try_into().expect("taken exact length"));
        kind.check_len(plaintext_len)?;

        let header_len = len_at + PLAINTEXT_LEN_BYTES;
        // Bounded by the kind check above, so this cannot overflow.
        let payload_len =
            usize::try_from(plaintext_len).expect("bounded by kind") + PAYLOAD_OVERHEAD;
        let expected = header_len + WRAPPED_KEY_LEN + payload_len;
        if bytes.len() != expected {
            return Err(CheckpointObjectError::LengthMismatch {
                expected,
                got: bytes.len(),
            });
        }
        Ok(Self {
            kind,
            domain,
            reference,
            plaintext_len,
            header: &bytes[..header_len],
            wrapped_key: &bytes[header_len..header_len + WRAPPED_KEY_LEN],
            payload: &bytes[header_len + WRAPPED_KEY_LEN..],
        })
    }

    /// What the object holds.
    #[must_use]
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// The key domain the object claims, unverified until opened.
    #[must_use]
    pub fn domain(&self) -> &'a str {
        self.domain
    }

    /// The object reference the object claims, unverified until opened.
    #[must_use]
    pub fn reference(&self) -> ObjectRef {
        self.reference
    }

    /// Plaintext length the header declares.
    #[must_use]
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// Fingerprint of the sealed payload bytes.
    #[must_use]
    pub fn fingerprint(&self) -> PayloadFingerprint {
        PayloadFingerprint::of(self.payload)
    }

    pub(super) fn header(&self) -> &'a [u8] {
        self.header
    }

    pub(super) fn wrapped_key(&self) -> &'a [u8] {
        self.wrapped_key
    }

    pub(super) fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// The fields a binding header is built from.
pub(super) struct Binding<'a> {
    pub kind: ObjectKind,
    pub domain: &'a str,
    pub reference: ObjectRef,
    pub plaintext_len: u64,
}

impl Binding<'_> {
    /// Encode the binding header. The caller has already bounded the domain.
    pub(super) fn encode(&self) -> Vec<u8> {
        let domain_len = u8::try_from(self.domain.len()).expect("domain length checked by caller");
        let mut out = Vec::with_capacity(
            FIXED_PREFIX_LEN + self.domain.len() + REFERENCE_LEN + PLAINTEXT_LEN_BYTES,
        );
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.kind.to_wire());
        out.extend_from_slice(&[0, 0]);
        out.push(domain_len);
        out.extend_from_slice(self.domain.as_bytes());
        out.extend_from_slice(self.reference.as_bytes());
        out.extend_from_slice(&self.plaintext_len.to_be_bytes());
        out
    }
}

fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8], CheckpointObjectError> {
    at.checked_add(len)
        .and_then(|end| bytes.get(at..end))
        .ok_or(CheckpointObjectError::Truncated { got: bytes.len() })
}
