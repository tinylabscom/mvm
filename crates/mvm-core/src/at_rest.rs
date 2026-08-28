//! σ and κ: the digest a protocol names content by, and the address the bytes
//! are actually stored under.
//!
//! Any transform applied at rest separates the two. This is the general case,
//! not an encryption special case, and the precedents are unanimous: a git
//! object id has never hashed the bytes on disk in any implementation (loose
//! objects are deflated, packed objects delta-encoded against a base), and ZFS
//! compresses and encrypts beneath a checksum carried in the parent block
//! pointer.
//!
//! Both already occur here. An OCI layer is `tar+gzip`: the digest fetch
//! verifies is over the compressed bytes — κ — while the config's `diff_id` is
//! the uncompressed digest — σ. A sealed transcript stores ciphertext, so a
//! [`crate::transcript::ChunkRecord`]'s digest is κ, and σ is deliberately
//! absent because a plaintext digest on a third-party-verifiable chain is a
//! confirmation oracle.
//!
//! # Why they are separate types
//!
//! Under the identity transform the two are numerically equal, and that is
//! exactly when confusing them is easy and harmless — right up until the first
//! transform lands, at which point every place that picked the wrong one is a
//! silent bug. Keeping them disjoint costs a newtype now and cannot be
//! retrofitted cheaply later, because by then the wrong choices are already
//! serialized into published artifacts.
//!
//! This extends the identity taxonomy documented on
//! [`crate::workload_address`] rather than starting a new one. That taxonomy
//! separates *what* is being identified — semantic content, exact bytes, trust,
//! ephemeral. This axis is orthogonal: given exact bytes, *which* bytes —
//! the plaintext a protocol names, or the representation on disk.
//!
//! # What this does not do
//!
//! Neither type authenticates anything. κ says what the stored bytes are, never
//! whether they may be served or run; that stays with the signed execution
//! plan. A digest is integrity, never authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::packs::{PackManifestError, Sha256Hex};

/// σ — the digest a protocol names content by, computed over **plaintext**.
///
/// The ETag, the content-digest header, an OCI `diff_id`. It is what a peer
/// asks for; it is not necessarily what is on disk.
///
/// Deliberately has no conversion to or from [`StorageAddress`]. Passing one
/// where the other is expected does not compile:
///
/// ```compile_fail
/// use mvm_core::at_rest::{ProtocolDigest, StorageAddress};
/// use mvm_core::packs::Sha256Hex;
/// let sigma = ProtocolDigest::new(Sha256Hex::from_bytes(b"x"));
/// // `.into()` rather than a bare binding: a plain `let kappa: StorageAddress
/// // = sigma;` never compiles whatever impls exist, since Rust has no
/// // implicit coercion — so it would pass this test vacuously and prove
/// // nothing. This line compiles exactly when a `From` bridge exists, which
/// // is the invariant being asserted.
/// let _kappa: StorageAddress = sigma.into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolDigest(Sha256Hex);

/// κ — the address the bytes are stored under, computed over the **bytes at
/// rest**.
///
/// It derives the storage path, it is the verification target on read, and it
/// is the unit of transfer between stores.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StorageAddress(Sha256Hex);

impl ProtocolDigest {
    pub fn new(digest: Sha256Hex) -> Self {
        Self(digest)
    }

    /// Parse from a hex string. Rejects anything that is not 64 lowercase hex
    /// characters, which is what keeps a non-collision-resistant digest out:
    /// MD5 is 32, CRC32C is 8, CRC64 is 16. Those are legitimate
    /// *attestations* and are disqualified as *addresses*.
    pub fn parse(value: impl Into<String>) -> Result<Self, PackManifestError> {
        Sha256Hex::new(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl StorageAddress {
    pub fn new(digest: Sha256Hex) -> Self {
        Self(digest)
    }

    /// See [`ProtocolDigest::parse`] — the same width check, for the same
    /// reason.
    pub fn parse(value: impl Into<String>) -> Result<Self, PackManifestError> {
        Sha256Hex::new(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// How the stored representation is cut into units before transforms apply.
///
/// Framing is the outer layer and transforms apply per frame. That ordering is
/// what keeps ranged reads possible: sealing an object whole turns a ten-byte
/// range request against a ten-gigabyte object into a whole-object operation,
/// which removes the capability rather than slowing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Framing {
    /// One frame covering the whole object.
    Whole,
    /// Fixed-size frames, the last possibly short.
    Fixed { frame_size: u32 },
    /// Frames enumerated by a manifest, itself stored and addressed. The
    /// manifest is named by κ, never σ — it is a stored object.
    Chunked { manifest: StorageAddress },
}

/// A transform applied to one frame.
///
/// An open enumeration rather than an `encrypted: bool`, because the boolean
/// costs a format migration per transform family that arrives after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FrameTransform {
    /// Stored as-is. σ and κ coincide numerically.
    Identity,
    /// Authenticated encryption.
    Aead,
    /// DEFLATE-family compression.
    Deflate,
    /// Encoded as a delta against another stored object.
    Delta { base: StorageAddress },
    /// Erasure-coded into `k` data and `m` parity shards.
    Erasure { k: u8, m: u8 },
}

/// Whether a reader can map a plaintext offset onto a stored offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SeekMap {
    /// Derivable from the framing alone (fixed frames, size-preserving
    /// transforms).
    Implicit,
    /// Carried explicitly as cumulative stored offsets, one per frame.
    Explicit { cumulative: Vec<u64> },
    /// Not seekable; reads start at the beginning.
    Absent,
}

/// How the bytes at rest were produced from the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformDescriptor {
    pub framing: Framing,
    /// Applied in order, per frame.
    pub per_frame: Vec<FrameTransform>,
    pub seek_map: SeekMap,
}

impl TransformDescriptor {
    /// The identity transform: stored exactly as presented.
    pub fn identity() -> Self {
        Self {
            framing: Framing::Whole,
            per_frame: vec![FrameTransform::Identity],
            seek_map: SeekMap::Implicit,
        }
    }

    /// Whether every frame is stored as-is, which is the only case where σ and
    /// κ are numerically equal.
    pub fn is_identity(&self) -> bool {
        matches!(self.framing, Framing::Whole)
            && self
                .per_frame
                .iter()
                .all(|t| matches!(t, FrameTransform::Identity))
    }
}

/// One stored object: its address, the transform that produced it, and every
/// protocol digest that names it.
///
/// **σ is a set.** One stored object is reachable by more than one protocol
/// digest — that is what a dual-hash transition needs, and what multi-axis
/// registration provides. Modelling σ as a single value forecloses both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBinding {
    storage: StorageAddress,
    protocol: BTreeSet<ProtocolDigest>,
    transform: TransformDescriptor,
}

impl AddressBinding {
    pub fn new(storage: StorageAddress, transform: TransformDescriptor) -> Self {
        Self {
            storage,
            protocol: BTreeSet::new(),
            transform,
        }
    }

    /// The identity-transform case: the same bytes are both the plaintext and
    /// the representation, so the one digest is both σ and κ — as two values of
    /// two types, which is the entire point.
    pub fn identity(digest: Sha256Hex) -> Self {
        let mut binding = Self::new(
            StorageAddress::new(digest.clone()),
            TransformDescriptor::identity(),
        );
        binding.add_protocol_digest(ProtocolDigest::new(digest));
        binding
    }

    pub fn add_protocol_digest(&mut self, sigma: ProtocolDigest) -> bool {
        self.protocol.insert(sigma)
    }

    pub fn storage_address(&self) -> &StorageAddress {
        &self.storage
    }

    pub fn protocol_digests(&self) -> impl Iterator<Item = &ProtocolDigest> {
        self.protocol.iter()
    }

    pub fn transform(&self) -> &TransformDescriptor {
        &self.transform
    }

    /// Whether `sigma` is one of the protocol digests naming this object.
    pub fn is_named_by(&self, sigma: &ProtocolDigest) -> bool {
        self.protocol.contains(sigma)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(b: &[u8]) -> Sha256Hex {
        Sha256Hex::from_bytes(b)
    }

    #[test]
    fn identity_transform_makes_the_two_numerically_equal() {
        let d = digest(b"payload");
        let binding = AddressBinding::identity(d.clone());
        assert!(binding.transform().is_identity());
        assert_eq!(binding.storage_address().as_str(), d.as_str());
        let sigma: Vec<&str> = binding.protocol_digests().map(|s| s.as_str()).collect();
        assert_eq!(sigma, vec![d.as_str()], "σ equals κ under identity");
    }

    #[test]
    fn sigma_is_a_set_so_one_object_can_be_named_twice() {
        // A dual-hash transition: the same stored object reachable by the
        // digest a new protocol names it by and the one the old protocol did.
        let mut binding = AddressBinding::new(
            StorageAddress::new(digest(b"stored")),
            TransformDescriptor::identity(),
        );
        let old = ProtocolDigest::new(digest(b"named-one-way"));
        let new = ProtocolDigest::new(digest(b"named-another-way"));
        assert!(binding.add_protocol_digest(old.clone()));
        assert!(binding.add_protocol_digest(new.clone()));
        assert!(!binding.add_protocol_digest(old.clone()), "set, not list");

        assert_eq!(binding.protocol_digests().count(), 2);
        assert!(binding.is_named_by(&old));
        assert!(binding.is_named_by(&new));
    }

    #[test]
    fn a_transform_separates_the_two() {
        let plaintext = digest(b"the plaintext");
        let ciphertext = digest(b"the ciphertext at rest");
        let mut binding = AddressBinding::new(
            StorageAddress::new(ciphertext.clone()),
            TransformDescriptor {
                framing: Framing::Fixed { frame_size: 4096 },
                per_frame: vec![FrameTransform::Deflate, FrameTransform::Aead],
                seek_map: SeekMap::Explicit {
                    cumulative: vec![0, 4096],
                },
            },
        );
        binding.add_protocol_digest(ProtocolDigest::new(plaintext.clone()));

        assert!(!binding.transform().is_identity());
        assert_ne!(binding.storage_address().as_str(), plaintext.as_str());
        assert_eq!(binding.storage_address().as_str(), ciphertext.as_str());
    }

    #[test]
    fn a_non_collision_resistant_digest_cannot_become_an_address() {
        // MD5 is 32 hex chars, CRC32C is 8, CRC64 is 16. Each is a legitimate
        // attestation and disqualified as an address; the width check is what
        // keeps them out without needing review to catch it.
        for bad in [
            "d41d8cd98f00b204e9800998ecf8427e", // MD5
            "00000000",                         // CRC32C
            "0000000000000000",                 // CRC64
            "",
            &"g".repeat(64), // right width, not hex
        ] {
            assert!(
                ProtocolDigest::parse(bad).is_err(),
                "σ accepted {bad:?}, which is not a SHA-256"
            );
            assert!(
                StorageAddress::parse(bad).is_err(),
                "κ accepted {bad:?}, which is not a SHA-256"
            );
        }
    }

    #[test]
    fn a_chunked_manifest_is_named_by_kappa_not_sigma() {
        // The manifest is itself a stored object, so it is addressed the way
        // stored objects are. That this is enforced by the type rather than by
        // convention is the point.
        let manifest = StorageAddress::new(digest(b"chunk manifest"));
        let framing = Framing::Chunked {
            manifest: manifest.clone(),
        };
        match framing {
            Framing::Chunked { manifest: m } => assert_eq!(m, manifest),
            other => panic!("unexpected framing: {other:?}"),
        }
    }

    #[test]
    fn descriptor_round_trips_through_serde() {
        let d = TransformDescriptor {
            framing: Framing::Chunked {
                manifest: StorageAddress::new(digest(b"m")),
            },
            per_frame: vec![
                FrameTransform::Delta {
                    base: StorageAddress::new(digest(b"base")),
                },
                FrameTransform::Erasure { k: 4, m: 2 },
            ],
            seek_map: SeekMap::Absent,
        };
        let json = serde_json::to_string(&d).expect("serializable");
        let back: TransformDescriptor = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(d, back);
    }

    #[test]
    fn identity_descriptor_is_the_only_one_reported_identity() {
        assert!(TransformDescriptor::identity().is_identity());
        let compressed = TransformDescriptor {
            framing: Framing::Whole,
            per_frame: vec![FrameTransform::Deflate],
            seek_map: SeekMap::Absent,
        };
        assert!(!compressed.is_identity());
        // Framing alone is enough to make it non-identity: a chunked object is
        // not stored as one blob even when every frame is untransformed.
        let chunked = TransformDescriptor {
            framing: Framing::Fixed { frame_size: 64 },
            per_frame: vec![FrameTransform::Identity],
            seek_map: SeekMap::Implicit,
        };
        assert!(!chunked.is_identity());
    }
}
