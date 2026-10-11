//! Authenticated, encrypted envelopes for checkpoint objects.
//!
//! A checkpoint object is one chunk of captured state, or one index naming
//! chunks. Each is sealed on its own:
//!
//! * a fresh random data key encrypts the payload through
//!   [`aead::seal`], with the object's binding header as associated
//!   data — format version, kind, key domain, object reference and plaintext
//!   length;
//! * the domain's wrapping key wraps that data key, authenticating the same
//!   header plus the payload's [`PayloadFingerprint`], so a wrapped key opens
//!   only for the payload and context it was made for;
//! * the object reference is an HMAC of the plaintext under the domain's
//!   reference key. Equal plaintext in one domain gets one reference, so a
//!   store can deduplicate inside a domain; two domains hold different keys and
//!   never share a reference, and a reference reveals nothing comparable about
//!   the plaintext to anyone without that key.
//!
//! Key custody belongs to the caller. This module takes a [`DomainKeys`] and
//! never stores, derives or fetches a key. The caller also supplies what it
//! expects to open ([`ObjectExpectation`]); those expectations must come from
//! metadata the caller has already authenticated, because the frame's own
//! claims are checked against them, not trusted.
//!
//! [`rewrap`] moves an object to a new wrapping key without touching the
//! payload, so its fingerprint stays the same. The data key does not change,
//! so rewrapping is rotation, not revocation: anyone who held the old wrapping
//! key and any copy of the object can still recover the data key, and that key
//! still decrypts the rewrapped payload. When the old wrapping key may be
//! compromised, re-seal instead — [`open`] then [`seal`] — which draws a new
//! data key and produces a new payload.
//!
//! The wrapping key draws a random 96-bit nonce for every seal and rewrap, so
//! a wrapping key must be rotated well before it has wrapped 2^32 data keys.
//!
//! Replaying an object is harmless by construction: a reference names exactly
//! one plaintext in a domain, so a replayed object under the same reference
//! carries the same bytes. Freshness of which objects a checkpoint uses is
//! the job of the authenticated index that names them.

mod frame;

#[cfg(test)]
mod tests;

use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

use super::aead;
use super::constant_time::constant_time_eq;
use crate::checkpoint::CheckpointKeyDomain;

use frame::Binding;
pub use frame::{
    FORMAT_VERSION, MAGIC, MAX_DOMAIN_LEN, ObjectFrame, PAYLOAD_OVERHEAD, PayloadFingerprint,
    WRAPPED_KEY_LEN,
};

/// Size of an [`ObjectRef`] and of a [`ReferenceKey`].
pub const REFERENCE_LEN: usize = 32;
/// Largest chunk plaintext an object may carry.
pub const MAX_CHUNK_LEN: u64 = 4 * 1024 * 1024;
/// Largest index plaintext an object may carry.
pub const MAX_INDEX_LEN: u64 = 16 * 1024 * 1024;

const REFERENCE_LABEL: &[u8] = b"mvm.checkpoint-object.reference.v1\0";
const PAYLOAD_LABEL: &[u8] = b"mvm.checkpoint-object.payload.v1\0";
const WRAP_LABEL: &[u8] = b"mvm.checkpoint-object.wrap.v1\0";

/// What a checkpoint object holds. Part of the authenticated binding, so an
/// index cannot be opened as a chunk or the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// A fixed-size slice of captured content.
    Chunk,
    /// A list of the chunks that make up one piece of content.
    Index,
}

impl ObjectKind {
    /// Largest plaintext an object of this kind may carry.
    #[must_use]
    pub fn max_plaintext_len(self) -> u64 {
        match self {
            ObjectKind::Chunk => MAX_CHUNK_LEN,
            ObjectKind::Index => MAX_INDEX_LEN,
        }
    }

    fn check_len(self, len: u64) -> Result<(), CheckpointObjectError> {
        let max = self.max_plaintext_len();
        if len > max {
            return Err(CheckpointObjectError::TooLarge {
                kind: self,
                len,
                max,
            });
        }
        Ok(())
    }

    fn to_wire(self) -> u8 {
        match self {
            ObjectKind::Chunk => 1,
            ObjectKind::Index => 2,
        }
    }

    fn from_wire(byte: u8) -> Result<Self, CheckpointObjectError> {
        match byte {
            1 => Ok(ObjectKind::Chunk),
            2 => Ok(ObjectKind::Index),
            other => Err(CheckpointObjectError::UnknownKind(other)),
        }
    }
}

/// Keyed identity of an object's plaintext within one key domain.
///
/// Rendered as 64 lowercase hex characters, which is also its serde form, so
/// an index can name objects and a store can use it as a file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectRef([u8; REFERENCE_LEN]);

impl ObjectRef {
    /// Wrap raw reference bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; REFERENCE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw reference bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; REFERENCE_LEN] {
        &self.0
    }
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl std::str::FromStr for ObjectRef {
    type Err = CheckpointObjectError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = s.len() == REFERENCE_LEN * 2
            && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid {
            return Err(CheckpointObjectError::InvalidReference);
        }
        let mut out = [0u8; REFERENCE_LEN];
        hex::decode_to_slice(s, &mut out).map_err(|_| CheckpointObjectError::InvalidReference)?;
        Ok(Self(out))
    }
}

impl serde::Serialize for ObjectRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ObjectRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// HMAC key a domain computes [`ObjectRef`]s under. Separate from the
/// wrapping key so one key is never used for two primitives.
pub struct ReferenceKey([u8; REFERENCE_LEN]);

impl ReferenceKey {
    /// Wrap an owned key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; REFERENCE_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh key from the OS CSPRNG.
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; REFERENCE_LEN];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl Drop for ReferenceKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The keys of one checkpoint key domain, supplied by whoever holds custody.
///
/// Holding the domain beside its keys means an object is always sealed and
/// opened under the domain the keys belong to; there is no argument through
/// which another domain's name could be paired with them.
pub struct DomainKeys {
    domain: CheckpointKeyDomain,
    wrapping: aead::Key,
    reference: ReferenceKey,
}

impl DomainKeys {
    /// Bundle a domain with its keys. Refuses a domain too long to frame.
    pub fn new(
        domain: CheckpointKeyDomain,
        wrapping: aead::Key,
        reference: ReferenceKey,
    ) -> Result<Self, CheckpointObjectError> {
        if wrapping.same_bytes_as(&reference.0) {
            return Err(CheckpointObjectError::SharedKeyMaterial);
        }
        if domain.as_str().len() > MAX_DOMAIN_LEN {
            return Err(CheckpointObjectError::DomainTooLong {
                len: domain.as_str().len(),
            });
        }
        Ok(Self {
            domain,
            wrapping,
            reference,
        })
    }

    /// The domain these keys belong to.
    #[must_use]
    pub fn domain(&self) -> &CheckpointKeyDomain {
        &self.domain
    }

    /// The reference `plaintext` would be sealed under as a `kind` object in
    /// this domain. Lets a store find an existing object before sealing.
    pub fn reference_for(
        &self,
        kind: ObjectKind,
        plaintext: &[u8],
    ) -> Result<ObjectRef, CheckpointObjectError> {
        let len = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
        kind.check_len(len)?;
        Ok(self.compute_reference(kind, plaintext))
    }

    fn compute_reference(&self, kind: ObjectKind, plaintext: &[u8]) -> ObjectRef {
        let domain = self.domain.as_str().as_bytes();
        let domain_len = u8::try_from(domain.len()).expect("bounded in DomainKeys::new");
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.reference.0)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(REFERENCE_LABEL);
        mac.update(&[domain_len]);
        mac.update(domain);
        mac.update(&[kind.to_wire()]);
        mac.update(&(plaintext.len() as u64).to_be_bytes());
        mac.update(plaintext);
        ObjectRef(mac.finalize().into_bytes().into())
    }
}

/// A sealed object and the reference a store files it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedObject {
    /// The object's keyed reference, also carried in its header.
    pub reference: ObjectRef,
    /// The complete frame.
    pub bytes: Vec<u8>,
}

/// What the caller expects an object to be, taken from metadata it has
/// already authenticated. [`open`] and [`rewrap`] refuse a frame that claims
/// anything else, before any key is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectExpectation {
    kind: ObjectKind,
    reference: ObjectRef,
    plaintext_len: Option<u64>,
}

impl ObjectExpectation {
    /// Expect a `kind` object filed under `reference`.
    #[must_use]
    pub fn new(kind: ObjectKind, reference: ObjectRef) -> Self {
        Self {
            kind,
            reference,
            plaintext_len: None,
        }
    }

    /// Also require this exact plaintext length.
    #[must_use]
    pub fn plaintext_len(mut self, len: u64) -> Self {
        self.plaintext_len = Some(len);
        self
    }

    fn check(
        &self,
        keys: &DomainKeys,
        frame: &ObjectFrame<'_>,
    ) -> Result<(), CheckpointObjectError> {
        let mismatch = |field| Err(CheckpointObjectError::ContextMismatch(field));
        if frame.domain() != keys.domain.as_str() {
            return mismatch(ContextField::Domain);
        }
        if frame.kind() != self.kind {
            return mismatch(ContextField::Kind);
        }
        if frame.reference() != self.reference {
            return mismatch(ContextField::Reference);
        }
        if self
            .plaintext_len
            .is_some_and(|len| len != frame.plaintext_len())
        {
            return mismatch(ContextField::PlaintextLen);
        }
        Ok(())
    }
}

/// Which expected property a frame contradicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextField {
    Domain,
    Kind,
    Reference,
    PlaintextLen,
}

/// Every way sealing, parsing, opening or rewrapping can refuse.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckpointObjectError {
    #[error("checkpoint object truncated at {got} bytes")]
    Truncated { got: usize },
    #[error("not a checkpoint object: bad magic")]
    BadMagic,
    #[error("unsupported checkpoint object format version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown checkpoint object kind {0}")]
    UnknownKind(u8),
    #[error("checkpoint object has reserved header bits set")]
    ReservedBitsSet,
    #[error("checkpoint object names an empty key domain")]
    EmptyDomain,
    #[error("checkpoint object key domain is not UTF-8")]
    DomainNotUtf8,
    #[error("checkpoint key domain is {len} bytes; at most {MAX_DOMAIN_LEN} fit an object")]
    DomainTooLong { len: usize },
    #[error("{kind:?} plaintext of {len} bytes exceeds the {max}-byte bound")]
    TooLarge {
        kind: ObjectKind,
        len: u64,
        max: u64,
    },
    #[error("checkpoint object is {got} bytes; its header requires exactly {expected}")]
    LengthMismatch { expected: usize, got: usize },
    #[error("checkpoint object does not match the expected {0:?}")]
    ContextMismatch(ContextField),
    #[error("checkpoint object data key did not authenticate: wrong key or tampered object")]
    WrappedKeyAuth,
    #[error("checkpoint object payload did not authenticate")]
    PayloadAuth,
    #[error("checkpoint object plaintext does not match its reference")]
    ReferenceMismatch,
    #[error("a checkpoint domain's wrapping and reference keys must differ")]
    SharedKeyMaterial,
    #[error("checkpoint object reference must be 64 lowercase hexadecimal characters")]
    InvalidReference,
}

/// Seal `plaintext` as a `kind` object in the keys' domain.
pub fn seal(
    keys: &DomainKeys,
    kind: ObjectKind,
    plaintext: &[u8],
) -> Result<SealedObject, CheckpointObjectError> {
    let reference = keys.reference_for(kind, plaintext)?;
    let header = Binding {
        kind,
        domain: keys.domain.as_str(),
        reference,
        plaintext_len: plaintext.len() as u64,
    }
    .encode();
    let data_key = aead::Key::random();
    let payload = aead::seal(&data_key, plaintext, &payload_aad(&header));
    let fingerprint = PayloadFingerprint::of(&payload);
    let wrapped = data_key.wrap_under(&keys.wrapping, &wrap_aad(&header, &fingerprint));
    Ok(SealedObject {
        reference,
        bytes: assemble(&header, &wrapped, &payload),
    })
}

/// Open an object, returning its plaintext only if the frame matches
/// `expected`, both AEAD layers authenticate under `keys`, and the plaintext
/// hashes to the reference it was filed under.
pub fn open(
    keys: &DomainKeys,
    expected: &ObjectExpectation,
    bytes: &[u8],
) -> Result<Vec<u8>, CheckpointObjectError> {
    let frame = ObjectFrame::parse(bytes)?;
    expected.check(keys, &frame)?;
    let data_key = unwrap_data_key(&keys.wrapping, &frame)?;
    let mut plaintext = zeroize::Zeroizing::new(
        aead::open(&data_key, frame.payload(), &payload_aad(frame.header()))
            .map_err(|_| CheckpointObjectError::PayloadAuth)?,
    );
    let recomputed = keys.compute_reference(frame.kind(), &plaintext);
    if !constant_time_eq(recomputed.as_bytes(), frame.reference().as_bytes()) {
        return Err(CheckpointObjectError::ReferenceMismatch);
    }
    // Released only once verified; a refused plaintext is zeroized on drop.
    Ok(std::mem::take(&mut *plaintext))
}

/// Re-wrap an object's data key under `new_wrapping`, keeping the header and
/// payload bytes — and so the payload fingerprint — exactly as they were.
///
/// The payload is not decrypted and the data key is unchanged, so this is
/// rotation, not revocation (see the module docs): copies wrapped under the
/// old key still open under it, and the old key still yields the data key
/// that decrypts this payload. Refuses a new wrapping key equal to the
/// domain's reference key.
pub fn rewrap(
    keys: &DomainKeys,
    new_wrapping: &aead::Key,
    expected: &ObjectExpectation,
    bytes: &[u8],
) -> Result<Vec<u8>, CheckpointObjectError> {
    if new_wrapping.same_bytes_as(&keys.reference.0) {
        return Err(CheckpointObjectError::SharedKeyMaterial);
    }
    let frame = ObjectFrame::parse(bytes)?;
    expected.check(keys, &frame)?;
    let data_key = unwrap_data_key(&keys.wrapping, &frame)?;
    let wrapped = data_key.wrap_under(
        new_wrapping,
        &wrap_aad(frame.header(), &frame.fingerprint()),
    );
    Ok(assemble(frame.header(), &wrapped, frame.payload()))
}

fn unwrap_data_key(
    wrapping: &aead::Key,
    frame: &ObjectFrame<'_>,
) -> Result<aead::Key, CheckpointObjectError> {
    aead::Key::unwrap_under(
        wrapping,
        frame.wrapped_key(),
        &wrap_aad(frame.header(), &frame.fingerprint()),
    )
    .map_err(|_| CheckpointObjectError::WrappedKeyAuth)
}

fn payload_aad(header: &[u8]) -> Vec<u8> {
    [PAYLOAD_LABEL, header].concat()
}

fn wrap_aad(header: &[u8], fingerprint: &PayloadFingerprint) -> Vec<u8> {
    [WRAP_LABEL, header, fingerprint.as_bytes()].concat()
}

fn assemble(header: &[u8], wrapped: &[u8], payload: &[u8]) -> Vec<u8> {
    debug_assert_eq!(wrapped.len(), WRAPPED_KEY_LEN);
    let mut out = Vec::with_capacity(header.len() + wrapped.len() + payload.len());
    out.extend_from_slice(header);
    out.extend_from_slice(wrapped);
    out.extend_from_slice(payload);
    out
}
