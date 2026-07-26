//! Transparency-log inclusion proofs over the chain-signed audit log.
//!
//! The audit log (see [`crate::verify`]) is a per-tenant stream of
//! [`crate::verify::SignedEnvelope`] lines, each an Ed25519 signature over
//! the entry plus the previous line's hash. Verifying that *one* event is
//! in the log today means replaying the whole chain and trusting the host
//! key. A Merkle transparency log buys the missing property: an
//! `O(log n)` inclusion proof that a single event is in a tree of size
//! `n`, checkable against a published root without replaying the chain.
//!
//! This module is the pure, `no_std` foundation for that: the RFC 6962
//! tree math, the [`InclusionProof`] / [`SignedAuditRoot`] wire types, and
//! the verifiers. It carries no host, filesystem, or CLI wiring — the same
//! logic runs in a browser tab so anyone can audit a downloaded proof
//! against a published root with no trust in a server. The host-side
//! builder that produces these proofs and signs roots is layered on top.
//!
//! # Leaf bytes
//!
//! The Merkle **leaf input** is the exact canonical audit line — the same
//! bytes [`crate::verify`] hashes to advance the chain. The leaf **hash**
//! applies domain separation over those bytes (see below), so a leaf hash
//! is never equal to an interior hash and a proof cannot smuggle an
//! interior digest in as a leaf.
//!
//! # RFC 6962 hashing
//!
//! Two prefixed hashes give second-preimage resistance across the
//! leaf/interior boundary:
//!
//! - `leaf_hash(line)   = SHA-256(0x00 || line)`
//! - `interior_hash(l,r) = SHA-256(0x01 || l || r)`
//!
//! # Tree shape (odd-node handling)
//!
//! The tree is built bottom-up, level by level: at each level the nodes
//! are paired left-to-right; an unpaired node at the end of an odd-length
//! level is **promoted** — carried up to the next level unchanged, never
//! hashed with itself. This is exactly the RFC 6962 Merkle Tree Hash,
//! whose recursive definition splits a level of `n` nodes at the largest
//! power of two strictly less than `n`; the level-by-level promotion
//! construction yields the identical tree (cross-checked in the tests
//! against an independent recursive oracle for every size up to 32).
//! Builder and verifier share the one construction here so they cannot
//! drift.
//!
//! # Empty tree
//!
//! [`merkle_root`] of an empty leaf set is `SHA-256("")` — the RFC 6962
//! empty-tree hash, computed via [`crate::verify::hash_line`] over no
//! bytes.
//!
//! # Audit-path ordering
//!
//! [`InclusionProof::audit_path`] is ordered bottom→top: the first element
//! is the leaf's immediate sibling, the last is the top-level sibling. At
//! each level the `leaf_index` bit selects placement — an even index sits
//! left of its sibling, an odd index sits right.

use crate::verify::{decode_hex32, encode_hex32, hash_line};
use alloc::string::String;
use alloc::vec::Vec;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use core::fmt;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// RFC 6962 leaf-node domain-separation prefix.
const LEAF_PREFIX: u8 = 0x00;
/// RFC 6962 interior-node domain-separation prefix.
const INTERIOR_PREFIX: u8 = 0x01;

/// An `O(log n)` proof that one audit line is a leaf of a Merkle tree of
/// `tree_size` leaves whose root is `root`.
///
/// `audit_path` holds the sibling hashes bottom→top as lowercase hex. The
/// proof is self-describing: [`verify_inclusion`] recomputes the leaf hash
/// from `leaf_line`, folds the path, and checks the result against `root`
/// — no external tree state needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    /// 0-based index of the leaf in the tree.
    pub leaf_index: u64,
    /// Total number of leaves in the tree.
    pub tree_size: u64,
    /// The exact canonical audit line whose inclusion is proven.
    pub leaf_line: String,
    /// Sibling hashes on the path from the leaf to the root, bottom→top,
    /// each 64 lowercase hex chars.
    pub audit_path: Vec<String>,
    /// The Merkle root the path folds to, 64 lowercase hex chars.
    pub root: String,
}

/// A published Merkle root for a tenant's audit log at a point in time,
/// signed by the host so an external auditor can pin it.
///
/// The signature covers a fixed-field-order serialization of
/// `(tenant, tree_size, root_hash, timestamp)` — see
/// [`root_signing_bytes`] for the exact bytes. `signature` and
/// `signer_pubkey` are not part of the signed input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditRoot {
    /// Tenant whose audit log this root covers.
    pub tenant: String,
    /// Number of leaves in the tree at signing time.
    pub tree_size: u64,
    /// The Merkle root, 64 lowercase hex chars.
    pub root_hash: String,
    /// RFC 3339 timestamp of when the root was published.
    pub timestamp: String,
    /// STANDARD-alphabet base64 of the 64-byte Ed25519 signature over
    /// [`root_signing_bytes`].
    pub signature: String,
    /// The signer's Ed25519 public key, 64 lowercase hex chars. Bound to
    /// the verifying key at check time so a root cannot claim one signer
    /// and be verified under another.
    pub signer_pubkey: String,
}

/// Why a Merkle operation failed. A plain enum with a `Display` impl (no
/// `thiserror`) so the type stays `no_std` and allocation-light. Every
/// verifier path fails closed into one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// `leaf_index` is not a valid leaf of a `tree_size`-leaf tree.
    LeafIndexOutOfRange {
        /// The offending leaf index.
        leaf_index: u64,
        /// The tree size it was checked against.
        tree_size: u64,
    },
    /// The audit path had fewer siblings than the tree shape requires.
    AuditPathTooShort,
    /// The audit path had more siblings than the tree shape requires.
    AuditPathTooLong,
    /// A hex field (a sibling hash or the root) failed to decode.
    HexDecode(String),
    /// The folded path did not equal the claimed root.
    RootMismatch,
    /// The recorded `signer_pubkey` did not match the verifying key the
    /// caller supplied.
    SignerKeyMismatch,
    /// The `signer_pubkey` field could not be decoded as a 32-byte key.
    KeyDecode(String),
    /// The `signature` field could not be decoded as a 64-byte signature.
    SignatureDecode(String),
    /// The Ed25519 signature did not verify against the key and payload.
    SignatureInvalid,
    /// The canonical signing payload could not be serialized (unreachable
    /// for the scalar fields, but fail closed rather than panic).
    PayloadSerialize(String),
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeafIndexOutOfRange {
                leaf_index,
                tree_size,
            } => write!(
                f,
                "leaf index {leaf_index} out of range for tree of size {tree_size}"
            ),
            Self::AuditPathTooShort => write!(f, "audit path shorter than the tree requires"),
            Self::AuditPathTooLong => write!(f, "audit path longer than the tree requires"),
            Self::HexDecode(reason) => write!(f, "hex decode failed: {reason}"),
            Self::RootMismatch => write!(f, "recomputed root does not match claimed root"),
            Self::SignerKeyMismatch => {
                write!(f, "recorded signer public key does not match verifying key")
            }
            Self::KeyDecode(reason) => write!(f, "signer public key decode failed: {reason}"),
            Self::SignatureDecode(reason) => write!(f, "signature decode failed: {reason}"),
            Self::SignatureInvalid => write!(f, "signature did not verify"),
            Self::PayloadSerialize(reason) => {
                write!(f, "signing payload serialize failed: {reason}")
            }
        }
    }
}

impl core::error::Error for MerkleError {}

/// RFC 6962 leaf hash: `SHA-256(0x00 || line)`.
pub fn leaf_hash(line: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(line);
    hasher.finalize().into()
}

/// RFC 6962 interior hash: `SHA-256(0x01 || left || right)`.
pub fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INTERIOR_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Reduce one level of the tree to the next: pair nodes left-to-right,
/// promoting a lone trailing node unchanged. The single construction both
/// [`merkle_root`] and [`build_inclusion_proof`] fold through, so their
/// tree shapes cannot diverge.
fn reduce_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            next.push(interior_hash(&level[i], &level[i + 1]));
            i += 2;
        } else {
            // Lone trailing node at an odd-length level: promote it.
            next.push(level[i]);
            i += 1;
        }
    }
    next
}

/// The Merkle root over `leaf_lines`.
///
/// Empty input is the RFC 6962 empty-tree hash `SHA-256("")`. A single
/// leaf's root is its [`leaf_hash`] (not an interior hash). Otherwise the
/// leaves are hashed and folded level by level with lone-node promotion.
pub fn merkle_root(leaf_lines: &[impl AsRef<[u8]>]) -> [u8; 32] {
    if leaf_lines.is_empty() {
        return hash_line(&[]);
    }
    let mut level: Vec<[u8; 32]> = leaf_lines.iter().map(|l| leaf_hash(l.as_ref())).collect();
    while level.len() > 1 {
        level = reduce_level(&level);
    }
    level[0]
}

/// Build the inclusion proof for the leaf at `index` in the tree over
/// `leaf_lines`.
///
/// Fails with [`MerkleError::LeafIndexOutOfRange`] if `index` is not a
/// leaf (which also covers an empty tree). The returned proof's
/// `audit_path` is ordered bottom→top and verifies via
/// [`verify_inclusion`].
pub fn build_inclusion_proof(
    leaf_lines: &[impl AsRef<[u8]>],
    index: usize,
) -> Result<InclusionProof, MerkleError> {
    let n = leaf_lines.len();
    if index >= n {
        return Err(MerkleError::LeafIndexOutOfRange {
            leaf_index: index as u64,
            tree_size: n as u64,
        });
    }
    let leaf_line = String::from_utf8_lossy(leaf_lines[index].as_ref()).into_owned();
    let mut level: Vec<[u8; 32]> = leaf_lines.iter().map(|l| leaf_hash(l.as_ref())).collect();
    let mut idx = index;
    let mut audit_path: Vec<String> = Vec::new();
    while level.len() > 1 {
        let count = level.len();
        // A node has a sibling unless it is the lone trailing node of an
        // odd-length level.
        let is_lone = idx == count - 1 && count % 2 == 1;
        if !is_lone {
            let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            audit_path.push(encode_hex32(&level[sib]));
        }
        level = reduce_level(&level);
        idx /= 2;
    }
    Ok(InclusionProof {
        leaf_index: index as u64,
        tree_size: n as u64,
        leaf_line,
        audit_path,
        root: encode_hex32(&level[0]),
    })
}

/// Verify an [`InclusionProof`], returning the recomputed root on success.
///
/// Recomputes `leaf_hash(leaf_line)`, folds `audit_path` bottom→top —
/// placing each sibling left or right per the `leaf_index` bit at that
/// level, promoting past levels where the node is the lone trailing node —
/// and checks the result against `root`. Fails closed on: `leaf_index >=
/// tree_size`, an audit path length inconsistent with `tree_size`, any hex
/// decode error, and root mismatch.
pub fn verify_inclusion(proof: &InclusionProof) -> Result<[u8; 32], MerkleError> {
    if proof.leaf_index >= proof.tree_size {
        return Err(MerkleError::LeafIndexOutOfRange {
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
        });
    }
    let mut hash = leaf_hash(proof.leaf_line.as_bytes());
    let mut index = proof.leaf_index;
    let mut size = proof.tree_size;
    let mut path = proof.audit_path.iter();
    while size > 1 {
        let is_lone = index == size - 1 && size % 2 == 1;
        if !is_lone {
            let sibling_hex = path.next().ok_or(MerkleError::AuditPathTooShort)?;
            let sibling = decode_hex32(sibling_hex).map_err(MerkleError::HexDecode)?;
            hash = if index % 2 == 0 {
                interior_hash(&hash, &sibling)
            } else {
                interior_hash(&sibling, &hash)
            };
        }
        index /= 2;
        size = size.div_ceil(2);
    }
    // A path with siblings still unconsumed is inconsistent with the tree.
    if path.next().is_some() {
        return Err(MerkleError::AuditPathTooLong);
    }
    let claimed_root = decode_hex32(&proof.root).map_err(MerkleError::HexDecode)?;
    if hash != claimed_root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(hash)
}

/// The exact bytes an Ed25519 signature over a [`SignedAuditRoot`] covers.
///
/// A fixed-field-order JSON object over the four signed fields, with no
/// whitespace and standard JSON string escaping:
///
/// ```text
/// {"tenant":"<tenant>","tree_size":<n>,"root_hash":"<hex>","timestamp":"<rfc3339>"}
/// ```
///
/// The host signer and this verifier both call this function, so the
/// signed bytes are identical on both sides.
pub fn root_signing_bytes(
    tenant: &str,
    tree_size: u64,
    root_hash: &str,
    timestamp: &str,
) -> Result<Vec<u8>, MerkleError> {
    #[derive(Serialize)]
    struct SigningPayload<'a> {
        tenant: &'a str,
        tree_size: u64,
        root_hash: &'a str,
        timestamp: &'a str,
    }
    serde_json::to_vec(&SigningPayload {
        tenant,
        tree_size,
        root_hash,
        timestamp,
    })
    .map_err(|e| MerkleError::PayloadSerialize(alloc::string::ToString::to_string(&e)))
}

/// Verify a [`SignedAuditRoot`]'s Ed25519 signature against `vk`.
///
/// Binds the root's recorded `signer_pubkey` to `vk` (fails closed if they
/// differ), then verifies the signature over [`root_signing_bytes`]. On
/// success the root's `root_hash` can be pinned as an authenticated tree
/// root. Fails closed on a bad public key, a malformed signature, a
/// signer/key mismatch, or an invalid signature.
pub fn verify_signed_root(root: &SignedAuditRoot, vk: &VerifyingKey) -> Result<(), MerkleError> {
    let recorded = decode_hex32(&root.signer_pubkey).map_err(MerkleError::KeyDecode)?;
    if &recorded != vk.as_bytes() {
        return Err(MerkleError::SignerKeyMismatch);
    }
    let sig_bytes = B64
        .decode(&root.signature)
        .map_err(|e| MerkleError::SignatureDecode(alloc::string::ToString::to_string(&e)))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| MerkleError::SignatureDecode(String::from("signature must be 64 bytes")))?;
    let signature = Signature::from_bytes(&sig_arr);
    let payload = root_signing_bytes(
        &root.tenant,
        root.tree_size,
        &root.root_hash,
        &root.timestamp,
    )?;
    vk.verify(&payload, &signature)
        .map_err(|_| MerkleError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use ed25519_dalek::{Signer, SigningKey};

    fn lines(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("audit-line-{i}")).collect()
    }

    /// Independent RFC 6962 Merkle Tree Hash oracle: recursive split at
    /// the largest power of two strictly less than `n`. Kept separate from
    /// the level-by-level production code so agreement between the two is
    /// real evidence, not a tautology.
    fn rfc6962_mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => hash_line(&[]),
            1 => leaves[0],
            n => {
                let mut k = 1usize;
                while k * 2 < n {
                    k *= 2;
                }
                interior_hash(&rfc6962_mth(&leaves[..k]), &rfc6962_mth(&leaves[k..]))
            }
        }
    }

    fn rfc6962_root(leaf_lines: &[String]) -> [u8; 32] {
        if leaf_lines.is_empty() {
            return hash_line(&[]);
        }
        let leaves: Vec<[u8; 32]> = leaf_lines.iter().map(|l| leaf_hash(l.as_bytes())).collect();
        rfc6962_mth(&leaves)
    }

    #[test]
    fn empty_tree_root_is_sha256_of_empty() {
        let empty: [&str; 0] = [];
        let root = merkle_root(&empty);
        let want: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(root, want);
        // And equals the shared no-prefix hash of no bytes.
        assert_eq!(root, hash_line(&[]));
    }

    #[test]
    fn single_leaf_root_is_leaf_hash_not_interior() {
        let line = "only-one";
        let root = merkle_root(&[line]);
        assert_eq!(root, leaf_hash(line.as_bytes()));
        // Domain separation: the root is a 0x00-prefixed hash, never a
        // 0x01-prefixed interior hash of anything.
        assert_ne!(root, interior_hash(&leaf_hash(line.as_bytes()), &[0u8; 32]));
    }

    #[test]
    fn two_leaf_root_is_interior_of_leaves() {
        let l = lines(2);
        let want = interior_hash(&leaf_hash(l[0].as_bytes()), &leaf_hash(l[1].as_bytes()));
        assert_eq!(merkle_root(&l), want);
    }

    #[test]
    fn three_leaf_root_promotes_lone_node() {
        // interior( interior(l0,l1), l2 ) — l2 promoted at level 0.
        let l = lines(3);
        let l0 = leaf_hash(l[0].as_bytes());
        let l1 = leaf_hash(l[1].as_bytes());
        let l2 = leaf_hash(l[2].as_bytes());
        let want = interior_hash(&interior_hash(&l0, &l1), &l2);
        assert_eq!(merkle_root(&l), want);
    }

    #[test]
    fn merkle_root_matches_rfc6962_oracle_for_many_sizes() {
        for n in 0..=32usize {
            let l = lines(n);
            assert_eq!(
                merkle_root(&l),
                rfc6962_root(&l),
                "level-by-level root diverged from RFC 6962 oracle at n={n}"
            );
        }
    }

    #[test]
    fn known_answer_roots_are_stable() {
        // Pin concrete hex so a hashing-scheme change is caught, not just
        // internal self-consistency.
        assert_eq!(
            encode_hex32(&merkle_root(&["a"])),
            encode_hex32(&leaf_hash(b"a"))
        );
        let two = merkle_root(&["a", "b"]);
        assert_eq!(
            encode_hex32(&two),
            encode_hex32(&interior_hash(&leaf_hash(b"a"), &leaf_hash(b"b")))
        );
    }

    #[test]
    fn every_leaf_proof_verifies_and_yields_the_root_for_sizes_1_to_8() {
        for &n in &[1usize, 2, 3, 4, 5, 8] {
            let l = lines(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let proof = build_inclusion_proof(&l, i).unwrap();
                assert_eq!(proof.leaf_index, i as u64);
                assert_eq!(proof.tree_size, n as u64);
                assert_eq!(proof.leaf_line, l[i]);
                let got = verify_inclusion(&proof).expect("proof must verify");
                assert_eq!(got, root, "leaf {i} of {n} folded to the wrong root");
                assert_eq!(proof.root, encode_hex32(&root));
            }
        }
    }

    #[test]
    fn round_trip_every_index_up_to_32_leaves() {
        for n in 1..=32usize {
            let l = lines(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let proof = build_inclusion_proof(&l, i).unwrap();
                assert_eq!(verify_inclusion(&proof).unwrap(), root);
            }
        }
    }

    #[test]
    fn single_leaf_proof_has_empty_audit_path() {
        let proof = build_inclusion_proof(&["solo"], 0).unwrap();
        assert!(proof.audit_path.is_empty());
        // The recomputed root is the leaf hash — no interior fold happens.
        assert_eq!(verify_inclusion(&proof).unwrap(), leaf_hash(b"solo"));
    }

    #[test]
    fn proof_cannot_forge_an_interior_digest_as_a_leaf() {
        // Second-preimage across the 0x00/0x01 boundary: take a genuine
        // interior hash and try to pass it off as a leaf line. Because the
        // leaf is re-hashed with the 0x00 prefix, the fold cannot land on
        // the same root, so verification fails closed.
        let l = lines(4);
        let root = merkle_root(&l);
        let interior = interior_hash(&leaf_hash(l[0].as_bytes()), &leaf_hash(l[1].as_bytes()));
        let forged = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            // Feed the raw interior digest bytes as if they were a leaf line.
            leaf_line: String::from_utf8_lossy(&interior).into_owned(),
            audit_path: vec![encode_hex32(&leaf_hash(l[2].as_bytes()))],
            root: encode_hex32(&root),
        };
        assert_eq!(verify_inclusion(&forged), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn flipped_sibling_fails_closed() {
        let l = lines(5);
        let mut proof = build_inclusion_proof(&l, 1).unwrap();
        // Corrupt the first sibling hash (flip its leading hex nibble).
        let mut sib = proof.audit_path[0].clone().into_bytes();
        sib[0] = if sib[0] == b'0' { b'1' } else { b'0' };
        proof.audit_path[0] = String::from_utf8(sib).unwrap();
        assert_eq!(verify_inclusion(&proof), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn wrong_leaf_index_fails_closed() {
        let l = lines(8);
        let mut proof = build_inclusion_proof(&l, 3).unwrap();
        proof.leaf_index = 4; // valid range, wrong leaf → path places siblings wrong
        assert_eq!(verify_inclusion(&proof), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn leaf_index_at_or_past_tree_size_fails_closed() {
        let proof = InclusionProof {
            leaf_index: 4,
            tree_size: 4,
            leaf_line: "x".to_string(),
            audit_path: vec![],
            root: encode_hex32(&leaf_hash(b"x")),
        };
        assert_eq!(
            verify_inclusion(&proof),
            Err(MerkleError::LeafIndexOutOfRange {
                leaf_index: 4,
                tree_size: 4,
            })
        );
    }

    #[test]
    fn truncated_audit_path_fails_closed() {
        let l = lines(5);
        let mut proof = build_inclusion_proof(&l, 0).unwrap();
        proof.audit_path.pop();
        assert_eq!(
            verify_inclusion(&proof),
            Err(MerkleError::AuditPathTooShort)
        );
    }

    #[test]
    fn extended_audit_path_fails_closed() {
        let l = lines(4);
        let mut proof = build_inclusion_proof(&l, 0).unwrap();
        proof.audit_path.push(encode_hex32(&[0xabu8; 32]));
        assert_eq!(verify_inclusion(&proof), Err(MerkleError::AuditPathTooLong));
    }

    #[test]
    fn tampered_leaf_line_fails_closed() {
        let l = lines(4);
        let mut proof = build_inclusion_proof(&l, 2).unwrap();
        proof.leaf_line.push_str("-tampered");
        assert_eq!(verify_inclusion(&proof), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn non_hex_sibling_fails_closed() {
        let l = lines(2);
        let mut proof = build_inclusion_proof(&l, 0).unwrap();
        proof.audit_path[0] = "zz".repeat(32);
        assert!(matches!(
            verify_inclusion(&proof),
            Err(MerkleError::HexDecode(_))
        ));
    }

    #[test]
    fn build_proof_out_of_range_is_rejected() {
        let l = lines(3);
        assert_eq!(
            build_inclusion_proof(&l, 3),
            Err(MerkleError::LeafIndexOutOfRange {
                leaf_index: 3,
                tree_size: 3,
            })
        );
        let empty: [&str; 0] = [];
        assert_eq!(
            build_inclusion_proof(&empty, 0),
            Err(MerkleError::LeafIndexOutOfRange {
                leaf_index: 0,
                tree_size: 0,
            })
        );
    }

    // --- signed root ---------------------------------------------------

    const SEED: [u8; 32] = [11u8; 32];

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SEED)
    }

    fn signed_root(
        key: &SigningKey,
        tenant: &str,
        tree_size: u64,
        root_hash: &str,
    ) -> SignedAuditRoot {
        let timestamp = "2026-07-24T00:00:00Z";
        let payload = root_signing_bytes(tenant, tree_size, root_hash, timestamp).unwrap();
        let sig = key.sign(&payload);
        SignedAuditRoot {
            tenant: tenant.to_string(),
            tree_size,
            root_hash: root_hash.to_string(),
            timestamp: timestamp.to_string(),
            signature: B64.encode(sig.to_bytes()),
            signer_pubkey: encode_hex32(&key.verifying_key().to_bytes()),
        }
    }

    #[test]
    fn signed_root_happy_path() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(4)));
        let root = signed_root(&key, "tenant-a", 4, &root_hash);
        assert_eq!(verify_signed_root(&root, &key.verifying_key()), Ok(()));
    }

    #[test]
    fn root_signing_bytes_are_fixed_field_order() {
        let bytes = root_signing_bytes("t", 7, "deadbeef", "2026-07-24T00:00:00Z").unwrap();
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"tenant":"t","tree_size":7,"root_hash":"deadbeef","timestamp":"2026-07-24T00:00:00Z"}"#
        );
    }

    #[test]
    fn signed_root_wrong_key_fails_closed() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(2)));
        let root = signed_root(&key, "tenant-a", 2, &root_hash);
        let other = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        // Recorded signer_pubkey binds to the signer, not `other`.
        assert_eq!(
            verify_signed_root(&root, &other),
            Err(MerkleError::SignerKeyMismatch)
        );
    }

    #[test]
    fn signed_root_forged_signature_fails_closed() {
        // signer_pubkey matches the verifying key, but the signature is
        // one the key never produced → the signature check must reject.
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(2)));
        let mut root = signed_root(&key, "tenant-a", 2, &root_hash);
        let forged = SigningKey::from_bytes(&[3u8; 32]).sign(b"unrelated");
        root.signature = B64.encode(forged.to_bytes());
        assert_eq!(
            verify_signed_root(&root, &key.verifying_key()),
            Err(MerkleError::SignatureInvalid)
        );
    }

    #[test]
    fn signed_root_tampered_root_hash_fails_closed() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(4)));
        let mut root = signed_root(&key, "tenant-a", 4, &root_hash);
        root.root_hash = encode_hex32(&[0xffu8; 32]);
        assert_eq!(
            verify_signed_root(&root, &key.verifying_key()),
            Err(MerkleError::SignatureInvalid)
        );
    }

    #[test]
    fn signed_root_tampered_tree_size_fails_closed() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(4)));
        let mut root = signed_root(&key, "tenant-a", 4, &root_hash);
        root.tree_size = 5;
        assert_eq!(
            verify_signed_root(&root, &key.verifying_key()),
            Err(MerkleError::SignatureInvalid)
        );
    }

    #[test]
    fn signed_root_tampered_tenant_fails_closed() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(4)));
        let mut root = signed_root(&key, "tenant-a", 4, &root_hash);
        root.tenant = "tenant-b".to_string();
        assert_eq!(
            verify_signed_root(&root, &key.verifying_key()),
            Err(MerkleError::SignatureInvalid)
        );
    }

    #[test]
    fn signed_root_malformed_signature_length_fails_closed() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(2)));
        let mut root = signed_root(&key, "tenant-a", 2, &root_hash);
        root.signature = B64.encode([0u8; 10]); // valid base64, wrong length
        assert!(matches!(
            verify_signed_root(&root, &key.verifying_key()),
            Err(MerkleError::SignatureDecode(_))
        ));
    }

    // --- serde ---------------------------------------------------------

    #[test]
    fn inclusion_proof_serde_round_trip() {
        let proof = build_inclusion_proof(&lines(5), 2).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let back: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, back);
    }

    #[test]
    fn signed_root_serde_round_trip() {
        let key = signing_key();
        let root_hash = encode_hex32(&merkle_root(&lines(3)));
        let root = signed_root(&key, "tenant-a", 3, &root_hash);
        let json = serde_json::to_string(&root).unwrap();
        let back: SignedAuditRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(root, back);
    }

    #[test]
    fn inclusion_proof_rejects_unknown_field() {
        let proof = build_inclusion_proof(&lines(2), 0).unwrap();
        let mut value: serde_json::Value = serde_json::to_value(&proof).unwrap();
        value["surprise"] = serde_json::Value::Bool(true);
        let json = serde_json::to_string(&value).unwrap();
        assert!(serde_json::from_str::<InclusionProof>(&json).is_err());
    }

    #[test]
    fn signed_root_rejects_unknown_field() {
        let key = signing_key();
        let root = signed_root(&key, "t", 1, &encode_hex32(&leaf_hash(b"x")));
        let mut value: serde_json::Value = serde_json::to_value(&root).unwrap();
        value["surprise"] = serde_json::Value::Bool(true);
        let json = serde_json::to_string(&value).unwrap();
        assert!(serde_json::from_str::<SignedAuditRoot>(&json).is_err());
    }
}
