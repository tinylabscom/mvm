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
//!
//! # Consistency proofs, and what they do not buy
//!
//! [`build_consistency_proof`] / [`verify_consistency`] implement the RFC
//! 6962 consistency proof: an `O(log n)` witness that the tree of `m`
//! leaves is a **prefix** of the tree of `n` leaves — that the log was only
//! appended to, never rewritten, between the two.
//!
//! Read the following three limits before treating this as a defence
//! against a log being shortened.
//!
//! **1. A consistency proof on its own detects nothing.** It relates two
//! roots the caller already holds. If the only place either root has ever
//! been stored is the host that produced the log, a host that rewrites the
//! log re-signs a matching root and every proof it emits is internally
//! perfect. This code is what makes an *off-host* witness meaningful; it is
//! not itself a witness. Without somewhere the host cannot rewrite a root,
//! and something that compares successive roots, this adds capability, not
//! a guarantee.
//!
//! **2. A host-signed root stored on the host is zero tamper-evidence
//! against that host.** [`SignedAuditRoot`] is signed by the host signer at
//! `~/.mvm/keys/host-signer.ed25519` and published beside the log it
//! attests — same directory, same machine. Against a malicious host —
//! explicitly out of project scope — that signature proves nothing the
//! host did not already control. Against accident, and against a *later*
//! compromise that did not also capture the earlier root, it is worth
//! having, and that is the whole of its value.
//!
//! **3. Even with an off-host witness the property is DETECTION, never
//! prevention, and only back to the last witnessed root.** Entries appended
//! and then deleted *between* two witness points leave no trace in either
//! root, so no consistency proof can speak about them. The detection window
//! is exactly the witnessing interval.
//!
//! Tail truncation of the audit log is undetectable today, and nothing in
//! this module changes that.

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
///
/// # Security: this proof is only half of a membership check
///
/// A successful [`verify_inclusion`] proves *only* that the proof is
/// internally consistent with its **own embedded `root`** — a fully
/// fabricated proof (invent leaves, compute their root, embed it)
/// self-verifies. To prove membership in a **real published log**, a caller
/// MUST additionally:
///
/// 1. obtain the log's [`SignedAuditRoot`];
/// 2. [`verify_signed_root`] it against the trusted host `VerifyingKey`; and
/// 3. check `proof.root == root.root_hash` **and**
///    `proof.tree_size == root.tree_size`.
///
/// Only then does a verified proof attest membership in the authenticated
/// tree. Binding the proof to a signed root is the entire security property.
///
/// # Framing responsibility
///
/// `audit_path` is attacker-controlled once deserialized from untrusted
/// bytes (e.g. in a browser). The fold in [`verify_inclusion`] consumes
/// only the deterministic per-level sibling count, so a padded path is
/// rejected with no per-element work amplification — but the transport /
/// framing layer that deserializes this struct is still responsible for
/// bounding the `Vec` length before allocation (a sane log has an
/// `audit_path` no longer than `ceil(log2(tree_size))`).
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
    /// A leaf's bytes are not valid UTF-8 and so cannot be carried in the
    /// proof's `String` `leaf_line`. The tree is hashed from raw bytes, so
    /// building a proof fails loud here rather than lossily transcoding a
    /// leaf that would then never re-verify.
    LeafNotUtf8,
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
    /// A consistency proof was asked for from an empty tree. RFC 6962
    /// defines the proof only for `0 < m`, and the empty tree's root
    /// (`SHA-256("")`) is not a node of any larger tree, so there is
    /// nothing to relate.
    ConsistencyOldSizeZero,
    /// The tree claimed to be the prefix is **larger** than the tree it is
    /// claimed to be a prefix of. A log cannot shrink by appending, so this
    /// is the shape a shortened log takes when checked against a root that
    /// was witnessed when it was longer.
    ConsistencyShrunk {
        /// Leaf count of the earlier (claimed-prefix) tree.
        old_size: u64,
        /// Leaf count of the later tree, which is smaller.
        new_size: u64,
    },
    /// `new_size` exceeds the number of leaves supplied to the builder.
    NewSizeExceedsLeaves {
        /// The requested tree size.
        new_size: u64,
        /// How many leaves were actually supplied.
        leaves: u64,
    },
    /// The consistency path had fewer nodes than the two tree shapes
    /// require.
    ConsistencyPathTooShort,
    /// The consistency path had more nodes than the two tree shapes
    /// require.
    ConsistencyPathTooLong,
    /// The path folded to something other than the claimed **earlier**
    /// root: the later tree does not contain the earlier tree as a prefix.
    /// At equal sizes this means the two roots disagree over the same leaf
    /// count — the log's existing entries changed.
    OldRootMismatch,
    /// The path folded to something other than the claimed **later** root.
    NewRootMismatch,
    /// A consistency proof did not bind to the pair of [`SignedAuditRoot`]s
    /// it was checked against. The payload names the field that differed.
    RootBindingMismatch(&'static str),
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
            Self::LeafNotUtf8 => write!(f, "leaf bytes are not valid UTF-8"),
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
            Self::ConsistencyOldSizeZero => {
                write!(f, "consistency proof is undefined from an empty tree")
            }
            Self::ConsistencyShrunk { old_size, new_size } => write!(
                f,
                "tree shrank from {old_size} to {new_size} leaves; an appended log cannot shrink"
            ),
            Self::NewSizeExceedsLeaves { new_size, leaves } => write!(
                f,
                "requested tree size {new_size} exceeds the {leaves} leaves supplied"
            ),
            Self::ConsistencyPathTooShort => {
                write!(f, "consistency path shorter than the trees require")
            }
            Self::ConsistencyPathTooLong => {
                write!(f, "consistency path longer than the trees require")
            }
            Self::OldRootMismatch => write!(
                f,
                "recomputed earlier root does not match the claimed earlier root"
            ),
            Self::NewRootMismatch => write!(
                f,
                "recomputed later root does not match the claimed later root"
            ),
            Self::RootBindingMismatch(field) => {
                write!(
                    f,
                    "consistency proof does not bind to the signed roots: {field}"
                )
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
    let level: Vec<[u8; 32]> = leaf_lines.iter().map(|l| leaf_hash(l.as_ref())).collect();
    merkle_root_of_leaf_hashes(&level)
}

/// The Merkle root over leaves that have already been hashed.
///
/// [`merkle_root`] is this preceded by one [`leaf_hash`] per line. Splitting
/// them lets a caller that holds the leaf hashes fold them without the lines:
/// hashing the leaves is proportional to the log's bytes, folding them is
/// proportional to its entries, and only the first has to be paid again when
/// nothing about a prefix has changed.
///
/// Same tree as [`merkle_root`] over the same leaves — the empty case included,
/// which is why it is stated here rather than left to the caller.
#[must_use]
pub fn merkle_root_of_leaf_hashes(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    if leaf_hashes.is_empty() {
        return hash_line(&[]);
    }
    let mut level = leaf_hashes.to_vec();
    while level.len() > 1 {
        level = reduce_level(&level);
    }
    level[0]
}

/// Build the inclusion proof for the leaf at `index` in the tree over
/// `leaf_lines`.
///
/// Fails with [`MerkleError::LeafIndexOutOfRange`] if `index` is not a
/// leaf (which also covers an empty tree), or [`MerkleError::LeafNotUtf8`]
/// if the target leaf's bytes are not valid UTF-8 — the proof carries the
/// leaf as a `String`, and the tree is hashed from raw bytes, so a lossy
/// transcode would yield a proof that could never re-verify. Real canonical
/// audit lines are always valid UTF-8. The returned proof's `audit_path`
/// is ordered bottom→top and verifies via [`verify_inclusion`].
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
    let leaf_line = String::from_utf8(leaf_lines[index].as_ref().to_vec())
        .map_err(|_| MerkleError::LeafNotUtf8)?;
    let level: Vec<[u8; 32]> = leaf_lines.iter().map(|l| leaf_hash(l.as_ref())).collect();
    Ok(InclusionProof {
        leaf_index: index as u64,
        tree_size: n as u64,
        leaf_line,
        audit_path: sibling_path(level, index),
        root: encode_hex32(&merkle_root(leaf_lines)),
    })
}

/// Sibling hashes on the path from `index` at `level` up to the tree root,
/// bottom→top, skipping the levels where the node is the lone trailing node
/// and so has no sibling.
///
/// `level` may be any level of the tree, not just the leaves — the
/// consistency builder enters part-way up. Folding to the root is the same
/// [`reduce_level`] both proof kinds share, so an inclusion path and a
/// consistency path can never disagree about the tree's shape.
fn sibling_path(mut level: Vec<[u8; 32]>, mut index: usize) -> Vec<String> {
    let mut path = Vec::new();
    while level.len() > 1 {
        let count = level.len();
        // A node has a sibling unless it is the lone trailing node of an
        // odd-length level.
        let is_lone = index == count - 1 && count % 2 == 1;
        if !is_lone {
            let sibling = if index % 2 == 0 { index + 1 } else { index - 1 };
            path.push(encode_hex32(&level[sibling]));
        }
        level = reduce_level(&level);
        index /= 2;
    }
    path
}

/// Verify an [`InclusionProof`], returning the recomputed root on success.
///
/// Recomputes `leaf_hash(leaf_line)`, folds `audit_path` bottom→top —
/// placing each sibling left or right per the `leaf_index` bit at that
/// level, promoting past levels where the node is the lone trailing node —
/// and checks the result against `root`. Fails closed on: `leaf_index >=
/// tree_size`, an audit path length inconsistent with `tree_size`, any hex
/// decode error, and root mismatch.
///
/// An `Ok` result attests **only** that the proof folds to its own embedded
/// `proof.root`; it does not by itself prove membership in a real log. The
/// caller must bind `proof.root` / `proof.tree_size` to a
/// [`verify_signed_root`]-checked [`SignedAuditRoot`] — see the
/// [`InclusionProof`] "Security" note.
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

/// An `O(log n)` proof that the tree of `old_size` leaves is a **prefix**
/// of the tree of `new_size` leaves — i.e. that the log was only appended
/// to between the two.
///
/// `path` holds the nodes bottom→top as lowercase hex, per RFC 6962
/// §2.1.2. The proof is self-describing: [`verify_consistency`]
/// reconstructs both roots from `path` and checks them against `old_root`
/// and `new_root`.
///
/// # Security: an unbound consistency proof is worth nothing
///
/// Exactly as for [`InclusionProof`], a successful [`verify_consistency`]
/// attests only that the proof is internally consistent with its **own
/// embedded roots**. Anyone can invent two trees, compute both roots, and
/// emit a self-verifying proof. The proof means something only when
/// `old_root` is a root some party recorded *earlier and elsewhere* — see
/// [`verify_consistency_against_roots`], and the module-level note on why
/// "elsewhere" cannot be the host that wrote the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyProof {
    /// Leaf count of the earlier tree, claimed to be a prefix.
    pub old_size: u64,
    /// Leaf count of the later tree.
    pub new_size: u64,
    /// The earlier tree's Merkle root, 64 lowercase hex chars.
    pub old_root: String,
    /// The later tree's Merkle root, 64 lowercase hex chars.
    pub new_root: String,
    /// RFC 6962 consistency-proof nodes, bottom→top, each 64 lowercase hex
    /// chars. Empty when `old_size == new_size`.
    pub path: Vec<String>,
}

/// The level and index of the largest perfect subtree ending exactly at
/// leaf `size - 1` — the node a consistency proof for `size` is anchored
/// at.
///
/// The subtree spans `[size - 2^level, size)`. `index == 0` exactly when
/// `size` is a power of two, in which case that node **is** the tree's own
/// root and a prover therefore never has to send it.
fn consistency_anchor(size: u64) -> (u32, u64) {
    let level = size.trailing_zeros();
    (level, (size - 1) >> level)
}

/// Node count at `level` in a tree of `leaves` leaves — the same div-ceil
/// ladder [`reduce_level`] walks, so builder and verifier agree on where a
/// level ends and therefore on which nodes are lone.
fn level_width(leaves: u64, level: u32) -> u64 {
    (0..level).fold(leaves, |width, _| width.div_ceil(2))
}

/// Build the RFC 6962 consistency proof from the tree of `old_size` leaves
/// to the tree of `new_size` leaves, both taken from the front of
/// `leaf_lines`.
///
/// Requires `0 < old_size <= new_size <= leaf_lines.len()`. `old_size ==
/// new_size` yields an empty path and two equal roots.
///
/// Fails closed with [`MerkleError::ConsistencyOldSizeZero`] (RFC 6962
/// defines the proof only for a non-empty prefix),
/// [`MerkleError::ConsistencyShrunk`] (the prefix is bigger than the tree
/// it is claimed to be a prefix of — what a shortened log looks like), or
/// [`MerkleError::NewSizeExceedsLeaves`].
///
/// Unlike [`build_inclusion_proof`] this carries no leaf bytes, so leaves
/// need not be valid UTF-8.
pub fn build_consistency_proof(
    leaf_lines: &[impl AsRef<[u8]>],
    old_size: usize,
    new_size: usize,
) -> Result<ConsistencyProof, MerkleError> {
    if new_size > leaf_lines.len() {
        return Err(MerkleError::NewSizeExceedsLeaves {
            new_size: new_size as u64,
            leaves: leaf_lines.len() as u64,
        });
    }
    if old_size == 0 {
        return Err(MerkleError::ConsistencyOldSizeZero);
    }
    if old_size > new_size {
        return Err(MerkleError::ConsistencyShrunk {
            old_size: old_size as u64,
            new_size: new_size as u64,
        });
    }
    let mut path = Vec::new();
    if old_size < new_size {
        let (level, index) = consistency_anchor(old_size as u64);
        // Climb to the anchor's level, then walk to the root exactly as an
        // inclusion path does.
        let mut nodes: Vec<[u8; 32]> = leaf_lines[..new_size]
            .iter()
            .map(|l| leaf_hash(l.as_ref()))
            .collect();
        for _ in 0..level {
            nodes = reduce_level(&nodes);
        }
        let index = index as usize;
        if index != 0 {
            // `old_size` is not a power of two, so the anchor is not the
            // earlier root; the verifier cannot derive it and needs it sent.
            path.push(encode_hex32(&nodes[index]));
        }
        path.extend(sibling_path(nodes, index));
    }
    Ok(ConsistencyProof {
        old_size: old_size as u64,
        new_size: new_size as u64,
        old_root: encode_hex32(&merkle_root(&leaf_lines[..old_size])),
        new_root: encode_hex32(&merkle_root(&leaf_lines[..new_size])),
        path,
    })
}

/// Verify a [`ConsistencyProof`], reconstructing both roots from `path`.
///
/// Both accumulators start at the anchor node ([`consistency_anchor`]) —
/// the first path element, or `old_root` itself when `old_size` is a power
/// of two and the anchor therefore *is* that root. Walking up, a sibling on
/// the **left** lies inside the earlier tree and folds into both
/// accumulators; a sibling on the **right** covers leaves the earlier tree
/// did not have and folds into the later accumulator only. What survives is
/// the earlier root reconstructed out of nodes of the later tree, which is
/// precisely the prefix claim.
///
/// Fails closed on `old_size == 0`, `old_size > new_size` (a log that
/// shrank), a path length inconsistent with the two tree shapes, any hex
/// decode error, and either root mismatching.
///
/// An `Ok` result attests **only** that the proof folds to its own embedded
/// roots. It is not evidence about a real log until `old_root` is bound to
/// a root recorded earlier and off-host — see
/// [`verify_consistency_against_roots`] and the module-level note.
pub fn verify_consistency(proof: &ConsistencyProof) -> Result<(), MerkleError> {
    if proof.old_size == 0 {
        return Err(MerkleError::ConsistencyOldSizeZero);
    }
    if proof.old_size > proof.new_size {
        return Err(MerkleError::ConsistencyShrunk {
            old_size: proof.old_size,
            new_size: proof.new_size,
        });
    }
    let old_root = decode_hex32(&proof.old_root).map_err(MerkleError::HexDecode)?;
    let new_root = decode_hex32(&proof.new_root).map_err(MerkleError::HexDecode)?;
    let mut path = proof.path.iter();

    if proof.old_size == proof.new_size {
        // Same tree: nothing to fold, and nothing legitimate to send.
        if path.next().is_some() {
            return Err(MerkleError::ConsistencyPathTooLong);
        }
        if old_root != new_root {
            return Err(MerkleError::OldRootMismatch);
        }
        return Ok(());
    }

    let (level, mut index) = consistency_anchor(proof.old_size);
    let anchor = if index == 0 {
        old_root
    } else {
        let hex = path.next().ok_or(MerkleError::ConsistencyPathTooShort)?;
        decode_hex32(hex).map_err(MerkleError::HexDecode)?
    };
    let mut old_hash = anchor;
    let mut new_hash = anchor;
    let mut width = level_width(proof.new_size, level);
    while width > 1 {
        let is_lone = index == width - 1 && width % 2 == 1;
        if !is_lone {
            let hex = path.next().ok_or(MerkleError::ConsistencyPathTooShort)?;
            let sibling = decode_hex32(hex).map_err(MerkleError::HexDecode)?;
            if index % 2 == 1 {
                old_hash = interior_hash(&sibling, &old_hash);
                new_hash = interior_hash(&sibling, &new_hash);
            } else {
                new_hash = interior_hash(&new_hash, &sibling);
            }
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    if path.next().is_some() {
        return Err(MerkleError::ConsistencyPathTooLong);
    }
    if old_hash != old_root {
        return Err(MerkleError::OldRootMismatch);
    }
    if new_hash != new_root {
        return Err(MerkleError::NewRootMismatch);
    }
    Ok(())
}

/// Verify a [`ConsistencyProof`] **bound to two [`SignedAuditRoot`]s** —
/// the composition that actually says something about a log.
///
/// Checks both roots describe the same tenant, that the proof's sizes and
/// root hashes are exactly the signed ones, and only then folds the path.
/// The caller MUST have already run [`verify_signed_root`] on both roots
/// under the trusted key; this function deliberately does not, so that key
/// handling stays in one place.
///
/// This is still detection, not prevention, and it detects only back to
/// whenever `old` was recorded. If `old` was read from the same host that
/// produced `new`, it detects nothing at all — that host can reissue both.
/// The module-level note spells out why.
pub fn verify_consistency_against_roots(
    proof: &ConsistencyProof,
    old: &SignedAuditRoot,
    new: &SignedAuditRoot,
) -> Result<(), MerkleError> {
    if old.tenant != new.tenant {
        return Err(MerkleError::RootBindingMismatch("tenant"));
    }
    if proof.old_size != old.tree_size {
        return Err(MerkleError::RootBindingMismatch("old_size"));
    }
    if proof.new_size != new.tree_size {
        return Err(MerkleError::RootBindingMismatch("new_size"));
    }
    // Compare decoded bytes, not the hex strings, so a case or formatting
    // difference is not mistaken for a tampered root.
    let bind = |proof_hex: &str, root_hex: &str, field| -> Result<(), MerkleError> {
        let a = decode_hex32(proof_hex).map_err(MerkleError::HexDecode)?;
        let b = decode_hex32(root_hex).map_err(MerkleError::HexDecode)?;
        if a == b {
            Ok(())
        } else {
            Err(MerkleError::RootBindingMismatch(field))
        }
    };
    bind(&proof.old_root, &old.root_hash, "old_root")?;
    bind(&proof.new_root, &new.root_hash, "new_root")?;
    verify_consistency(proof)
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

/// Why [`verify_membership`] refused.
///
/// Each arm names one of the four checks, so a refusal says which half of the
/// membership property failed rather than just that verification failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// The signed root did not verify under the trusted key.
    #[error("signed-root verification failed: {0}")]
    RootSignature(MerkleError),
    /// The root is genuinely signed, but for a different tenant.
    #[error("tenant binding failed: signed root is for '{signed}', expected '{expected}'")]
    TenantMismatch {
        /// Tenant the signed root names.
        signed: String,
        /// Tenant the caller intended.
        expected: String,
    },
    /// The proof is not internally consistent.
    #[error("inclusion-proof verification failed: {0}")]
    Inclusion(MerkleError),
    /// The proof folds to a root other than the signed one.
    #[error("root binding failed: proof root {proof} is not the signed root {signed}")]
    RootBinding {
        /// Root the proof folds to.
        proof: String,
        /// Root the host signed.
        signed: String,
    },
    /// The proof's tree size disagrees with the signed root's.
    #[error("tree-size binding failed: proof says {proof}, signed root says {signed}")]
    TreeSizeBinding {
        /// Tree size the proof carries.
        proof: u64,
        /// Tree size the signed root carries.
        signed: u64,
    },
}

/// The full membership check: a verified proof, plus the binding that makes it
/// attest membership in a real published log rather than in its own arithmetic.
///
/// [`verify_inclusion`] alone checks a proof against the root the proof itself
/// carries, so a wholly fabricated proof self-verifies. The binding steps here
/// are what close that: the root has to be one the host signed, for the tenant
/// the caller meant, and the proof has to fold to *that* root at *that* tree
/// size.
///
/// Ordered and fail-closed, so the first failure names the check that failed.
pub fn verify_membership(
    proof: &InclusionProof,
    root: &SignedAuditRoot,
    vk: &VerifyingKey,
    expected_tenant: &str,
) -> Result<(), MembershipError> {
    verify_signed_root(root, vk).map_err(MembershipError::RootSignature)?;
    if root.tenant != expected_tenant {
        return Err(MembershipError::TenantMismatch {
            signed: root.tenant.clone(),
            expected: String::from(expected_tenant),
        });
    }
    verify_inclusion(proof).map_err(MembershipError::Inclusion)?;
    if proof.root != root.root_hash {
        return Err(MembershipError::RootBinding {
            proof: proof.root.clone(),
            signed: root.root_hash.clone(),
        });
    }
    if proof.tree_size != root.tree_size {
        return Err(MembershipError::TreeSizeBinding {
            proof: proof.tree_size,
            signed: root.tree_size,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    /// The split must be a refactor, not a second tree. Anything that folds
    /// cached leaf hashes has to land on the byte-identical root the line-based
    /// path produces, or a cached prefix would silently describe a different
    /// log than the one the signed root committed to.
    #[test]
    fn folding_leaf_hashes_gives_the_same_root_as_folding_lines() {
        for n in 0..40usize {
            let lines: Vec<alloc::string::String> =
                (0..n).map(|i| alloc::format!("line-{i}")).collect();
            let hashes: Vec<[u8; 32]> = lines.iter().map(|l| leaf_hash(l.as_bytes())).collect();
            assert_eq!(
                merkle_root(&lines),
                merkle_root_of_leaf_hashes(&hashes),
                "tree of {n} leaves disagrees between the two entry points"
            );
        }
    }

    #[test]
    fn an_empty_leaf_hash_set_is_the_empty_tree() {
        let no_lines: [&[u8]; 0] = [];
        assert_eq!(merkle_root_of_leaf_hashes(&[]), merkle_root(&no_lines));
    }
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
    fn interior_digest_cannot_masquerade_as_a_leaf() {
        // Domain separation across the 0x00 / 0x01 boundary, exercised with
        // RAW bytes (no UTF-8 transcoding). In a real 4-leaf tree the root
        // is interior(left, right), where `left` is itself the interior
        // digest of leaves 0 and 1. An attacker who learns `left` cannot
        // present it as a *leaf* and reach the same root: a leaf is hashed
        // with the 0x00 tag, an interior node with 0x01, so leaf_hash(left)
        // is not the interior digest it came from.
        let real: [&[u8]; 4] = [b"l0", b"l1", b"l2", b"l3"];
        let real_root = merkle_root(&real);
        let left = interior_hash(&leaf_hash(b"l0"), &leaf_hash(b"l1"));
        let right = interior_hash(&leaf_hash(b"l2"), &leaf_hash(b"l3"));

        // The tag alone defeats the second preimage.
        assert_ne!(leaf_hash(&left), left);
        assert_ne!(leaf_hash(&left), right);

        // Feed the raw 32-byte interior digest in as a leaf via the
        // raw-bytes `merkle_root` API. Because it is re-hashed with the leaf
        // tag, the 2-node tree over [left, right] has a DIFFERENT root than
        // the real 4-leaf tree — the interior digest cannot fold to the
        // real root.
        let forged: [&[u8]; 2] = [&left, &right];
        let forged_root = merkle_root(&forged);
        assert_ne!(
            forged_root, real_root,
            "an interior digest presented as a leaf must not fold to the real root"
        );
        // And it is exactly the leaf-tagged re-hash, confirming the 0x00
        // prefix was applied rather than the digest being spliced in raw.
        assert_eq!(
            forged_root,
            interior_hash(&leaf_hash(&left), &leaf_hash(&right))
        );
    }

    #[test]
    fn build_proof_rejects_non_utf8_leaf() {
        // A leaf whose bytes are not valid UTF-8: build must fail loud
        // rather than lossily transcode into a proof that can never verify.
        let good_bytes = b"ok-leaf";
        let bad_bytes = [0xffu8, 0xfe, 0x00, 0x80];
        let leaves: [&[u8]; 2] = [good_bytes, &bad_bytes];
        assert_eq!(
            build_inclusion_proof(&leaves, 1),
            Err(MerkleError::LeafNotUtf8)
        );
        // The valid-UTF-8 leaf at index 0 still builds a verifying proof.
        let proof = build_inclusion_proof(&leaves, 0).unwrap();
        assert_eq!(verify_inclusion(&proof).unwrap(), merkle_root(&leaves));
    }

    #[test]
    fn non_ascii_utf8_leaf_round_trips() {
        // Real audit lines carry UTF-8 label values; a non-ASCII leaf must
        // build a proof and verify to the right root, byte-exact.
        let l = vec![
            r#"{"event":"plan.admitted","label":"café"}"#.to_string(),
            r#"{"event":"plan.launched","label":"你好"}"#.to_string(),
            r#"{"event":"plan.failed","label":"Ωmega"}"#.to_string(),
        ];
        let root = merkle_root(&l);
        for (i, line) in l.iter().enumerate() {
            let proof = build_inclusion_proof(&l, i).unwrap();
            // Byte-exact: no transcoding of the multibyte leaf.
            assert_eq!(&proof.leaf_line, line);
            assert_eq!(verify_inclusion(&proof).unwrap(), root);
        }
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

    // --- consistency proofs ---------------------------------------------

    /// Independent RFC 6962 §2.1.2 `SUBPROOF` oracle, transcribed from the
    /// recursive definition. Structurally unrelated to the level-by-level
    /// builder — it recurses on a split at the largest power of two, where
    /// the builder folds levels and promotes lone nodes — so agreement
    /// between them is evidence, not a tautology. Same discipline as
    /// [`rfc6962_mth`], which pins the tree shape the whole algorithm
    /// assumes (see `merkle_root_matches_rfc6962_oracle_for_many_sizes`).
    fn rfc6962_subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if m == n {
            return if b {
                Vec::new()
            } else {
                vec![rfc6962_mth(leaves)]
            };
        }
        let mut k = 1usize;
        while k * 2 < n {
            k *= 2;
        }
        if m <= k {
            let mut out = rfc6962_subproof(m, &leaves[..k], b);
            out.push(rfc6962_mth(&leaves[k..]));
            out
        } else {
            let mut out = rfc6962_subproof(m - k, &leaves[k..], false);
            out.push(rfc6962_mth(&leaves[..k]));
            out
        }
    }

    /// `PROOF(m, D[n]) = SUBPROOF(m, D[n], true)`, as hex.
    fn rfc6962_consistency(leaf_lines: &[String], m: usize, n: usize) -> Vec<String> {
        let leaves: Vec<[u8; 32]> = leaf_lines[..n]
            .iter()
            .map(|l| leaf_hash(l.as_bytes()))
            .collect();
        rfc6962_subproof(m, &leaves, true)
            .iter()
            .map(encode_hex32)
            .collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn consistency_path_matches_rfc6962_oracle_for_every_pair() {
        // Every (m, n) with 1 <= m <= n <= 33 — past the 32 boundary so a
        // power-of-two special case cannot hide at the edge of the range.
        for n in 1..=33usize {
            let l = lines(n);
            for m in 1..=n {
                let proof = build_consistency_proof(&l, m, n).unwrap();
                assert_eq!(
                    proof.path,
                    rfc6962_consistency(&l, m, n),
                    "consistency path diverged from the RFC 6962 oracle at m={m}, n={n}"
                );
                assert_eq!(proof.old_root, encode_hex32(&rfc6962_root(&l[..m])));
                assert_eq!(proof.new_root, encode_hex32(&rfc6962_root(&l[..n])));
            }
        }
    }

    #[test]
    fn every_consistency_proof_round_trips() {
        for n in 1..=33usize {
            let l = lines(n);
            for m in 1..=n {
                let proof = build_consistency_proof(&l, m, n).unwrap();
                assert_eq!(
                    verify_consistency(&proof),
                    Ok(()),
                    "m={m}, n={n} failed to verify"
                );
            }
        }
    }

    /// The eight leaves of the Certificate Transparency reference tree, as
    /// published in `transparency-dev/merkle`'s `testdata`. Hex-encoded
    /// byte strings, not text — leaf 0 is the empty string.
    fn ct_reference_leaves() -> Vec<Vec<u8>> {
        [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ]
        .iter()
        .map(|h| unhex(h))
        .collect()
    }

    #[test]
    fn known_answer_consistency_vectors_from_the_ct_reference_tree() {
        // Known answers from an INDEPENDENT implementation — the CT
        // reference tree's published consistency vectors
        // (transparency-dev/merkle, testdata/consistency/*), converted from
        // base64 to hex. These are not this implementation's own output
        // pasted back: agreement means our tree, our hashing scheme, and our
        // proof shape all match the reference log, and any drift in any of
        // the three turns this red.
        let leaves = ct_reference_leaves();
        let cases: &[(usize, usize, &str, &str, &[&str])] = &[
            (
                1,
                1,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                &[],
            ),
            (
                1,
                8,
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
                &[
                    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
                ],
            ),
            (
                6,
                8,
                "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
                "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
                &[
                    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
            (
                2,
                5,
                "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
                "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
                &[
                    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                ],
            ),
            (
                6,
                7,
                "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
                "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
                &[
                    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                    "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
                    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
                ],
            ),
        ];
        for &(m, n, root1, root2, path) in cases {
            let proof = build_consistency_proof(&leaves, m, n).unwrap();
            // Our roots equal the reference log's published roots...
            assert_eq!(proof.old_root, root1, "root1 drifted at m={m}, n={n}");
            assert_eq!(proof.new_root, root2, "root2 drifted at m={m}, n={n}");
            // ...and so does every node of the proof, in order.
            assert_eq!(proof.path, path, "proof drifted at m={m}, n={n}");
            assert_eq!(verify_consistency(&proof), Ok(()));
        }
    }

    #[test]
    fn a_truncated_log_fails_consistency_against_its_own_earlier_root() {
        // The failure mode, executable rather than described.
        //
        // Scope note, because this test is the one most likely to be
        // misread: it demonstrates that the MATH refuses a truncated log
        // checked against a root witnessed when the log was longer. It does
        // NOT demonstrate host-level detection. Nothing here keeps the
        // witnessed root out of reach of the host that wrote the log, so on
        // a real host today the attacker holding `witnessed` simply reissues
        // it. That gap is the off-host witness, and it is not this module.
        let full = lines(12);
        let witnessed = encode_hex32(&merkle_root(&full)); // recorded at size 12

        // The host deletes the three newest lines.
        let truncated = &full[..9];

        // There is no proof to offer at all: the log is now shorter than the
        // root a witness already holds, and appending cannot shrink a tree.
        assert_eq!(
            build_consistency_proof(truncated, 12, truncated.len()),
            Err(MerkleError::ConsistencyShrunk {
                old_size: 12,
                new_size: 9,
            })
        );

        // So the host rewrites instead: keep the first nine, substitute the
        // three it deleted, and keep appending past the witnessed size. The
        // log is now LONGER than when it was witnessed, so no size check can
        // catch it.
        let mut rewritten: Vec<String> = full[..9].to_vec();
        for i in 9..15 {
            rewritten.push(format!("rewritten-line-{i}"));
        }
        let mut forged = build_consistency_proof(&rewritten, 12, 15).unwrap();
        assert_ne!(
            forged.old_root, witnessed,
            "the rewritten prefix must not reproduce the witnessed root"
        );
        // The host claims the witnessed root as its size-12 prefix.
        forged.old_root = witnessed.clone();
        assert_eq!(
            verify_consistency(&forged),
            Err(MerkleError::OldRootMismatch),
            "a rewritten prefix must not verify against the witnessed root"
        );

        // Control: had the host only appended, the same 12 -> 15 proof
        // verifies against the same witnessed root. The test above fails for
        // the truncation, not because 12 -> 15 proofs never verify.
        let mut appended: Vec<String> = full.clone();
        for i in 12..15 {
            appended.push(format!("audit-line-{i}"));
        }
        let honest = build_consistency_proof(&appended, 12, 15).unwrap();
        assert_eq!(honest.old_root, witnessed);
        assert_eq!(verify_consistency(&honest), Ok(()));
    }

    #[test]
    fn a_log_that_shrank_is_refused_by_both_builder_and_verifier() {
        let l = lines(4);
        assert_eq!(
            build_consistency_proof(&l, 4, 3),
            Err(MerkleError::ConsistencyShrunk {
                old_size: 4,
                new_size: 3,
            })
        );
        let mut proof = build_consistency_proof(&l, 2, 4).unwrap();
        proof.old_size = 5;
        assert_eq!(
            verify_consistency(&proof),
            Err(MerkleError::ConsistencyShrunk {
                old_size: 5,
                new_size: 4,
            })
        );
    }

    #[test]
    fn equal_sizes_yield_an_empty_proof_and_reject_a_changed_root() {
        let l = lines(6);
        let proof = build_consistency_proof(&l, 6, 6).unwrap();
        assert!(proof.path.is_empty());
        assert_eq!(proof.old_root, proof.new_root);
        assert_eq!(verify_consistency(&proof), Ok(()));

        // Same leaf count, different root: existing entries were edited.
        let mut edited = proof.clone();
        edited.new_root = encode_hex32(&merkle_root(&lines(5)));
        assert_eq!(
            verify_consistency(&edited),
            Err(MerkleError::OldRootMismatch)
        );

        // And nothing legitimate can be sent for an equal-size claim.
        let mut padded = proof.clone();
        padded.path.push(encode_hex32(&[0xabu8; 32]));
        assert_eq!(
            verify_consistency(&padded),
            Err(MerkleError::ConsistencyPathTooLong)
        );
    }

    #[test]
    fn empty_prefix_is_refused_by_both_builder_and_verifier() {
        let l = lines(4);
        assert_eq!(
            build_consistency_proof(&l, 0, 4),
            Err(MerkleError::ConsistencyOldSizeZero)
        );
        let mut proof = build_consistency_proof(&l, 1, 4).unwrap();
        proof.old_size = 0;
        assert_eq!(
            verify_consistency(&proof),
            Err(MerkleError::ConsistencyOldSizeZero)
        );
    }

    #[test]
    fn new_size_past_the_supplied_leaves_is_refused() {
        let l = lines(3);
        assert_eq!(
            build_consistency_proof(&l, 2, 4),
            Err(MerkleError::NewSizeExceedsLeaves {
                new_size: 4,
                leaves: 3,
            })
        );
    }

    #[test]
    fn consistency_proof_carries_no_leaf_bytes_so_non_utf8_leaves_are_fine() {
        // Unlike an inclusion proof, nothing here embeds a leaf, so a leaf
        // that is not valid UTF-8 must not block a proof.
        let leaves: [&[u8]; 4] = [b"ok", &[0xffu8, 0xfe], b"also-ok", &[0x80u8]];
        let proof = build_consistency_proof(&leaves, 2, 4).unwrap();
        assert_eq!(verify_consistency(&proof), Ok(()));
        assert_eq!(proof.new_root, encode_hex32(&merkle_root(&leaves)));
    }

    #[test]
    fn flipped_consistency_node_fails_closed() {
        let l = lines(9);
        let mut proof = build_consistency_proof(&l, 6, 9).unwrap();
        let mut node = proof.path[0].clone().into_bytes();
        node[0] = if node[0] == b'0' { b'1' } else { b'0' };
        proof.path[0] = String::from_utf8(node).unwrap();
        // The anchor is shared by both folds, so corrupting it breaks the
        // earlier root first.
        assert_eq!(
            verify_consistency(&proof),
            Err(MerkleError::OldRootMismatch)
        );
    }

    #[test]
    fn tampered_new_root_fails_closed_on_the_later_root() {
        let l = lines(7);
        let mut proof = build_consistency_proof(&l, 3, 7).unwrap();
        proof.new_root = encode_hex32(&[0xffu8; 32]);
        assert_eq!(
            verify_consistency(&proof),
            Err(MerkleError::NewRootMismatch)
        );
    }

    #[test]
    fn truncated_and_extended_consistency_paths_fail_closed() {
        let l = lines(7);
        let mut short = build_consistency_proof(&l, 3, 7).unwrap();
        short.path.pop();
        assert_eq!(
            verify_consistency(&short),
            Err(MerkleError::ConsistencyPathTooShort)
        );

        let mut long = build_consistency_proof(&l, 3, 7).unwrap();
        long.path.push(encode_hex32(&[0xabu8; 32]));
        assert_eq!(
            verify_consistency(&long),
            Err(MerkleError::ConsistencyPathTooLong)
        );
    }

    #[test]
    fn power_of_two_prefix_does_not_send_its_own_root() {
        // When `old_size` is a power of two the anchor IS the earlier root,
        // so the prover omits it and the verifier seeds from `old_root`.
        // A proof for a non-power-of-two prefix at the same tree size
        // carries exactly one more node.
        let l = lines(7);
        let pow2 = build_consistency_proof(&l, 4, 7).unwrap();
        assert_eq!(pow2.path, rfc6962_consistency(&l, 4, 7));
        assert_eq!(verify_consistency(&pow2), Ok(()));

        // Seeding from `old_root` means a wrong `old_root` must surface on
        // the LATER root, since the earlier fold is then trivially self-
        // consistent. Fail closed either way.
        let mut swapped = pow2.clone();
        swapped.old_root = encode_hex32(&merkle_root(&l[..2]));
        assert_eq!(
            verify_consistency(&swapped),
            Err(MerkleError::NewRootMismatch)
        );
    }

    #[test]
    fn non_hex_consistency_node_fails_closed() {
        let l = lines(5);
        let mut proof = build_consistency_proof(&l, 3, 5).unwrap();
        proof.path[0] = "zz".repeat(32);
        assert!(matches!(
            verify_consistency(&proof),
            Err(MerkleError::HexDecode(_))
        ));
    }

    #[test]
    fn consistency_proof_serde_round_trip_and_unknown_field() {
        let proof = build_consistency_proof(&lines(9), 5, 9).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert_eq!(
            serde_json::from_str::<ConsistencyProof>(&json).unwrap(),
            proof
        );

        let mut value: serde_json::Value = serde_json::to_value(&proof).unwrap();
        value["surprise"] = serde_json::Value::Bool(true);
        let json = serde_json::to_string(&value).unwrap();
        assert!(serde_json::from_str::<ConsistencyProof>(&json).is_err());
    }

    #[test]
    fn binding_to_signed_roots_rejects_every_mismatch() {
        let key = signing_key();
        let l = lines(9);
        let proof = build_consistency_proof(&l, 5, 9).unwrap();
        let old = signed_root(&key, "tenant-a", 5, &proof.old_root);
        let new = signed_root(&key, "tenant-a", 9, &proof.new_root);
        assert_eq!(verify_consistency_against_roots(&proof, &old, &new), Ok(()));

        // A root signed for a different tenant is not this log's root.
        let other_tenant = signed_root(&key, "tenant-b", 9, &proof.new_root);
        assert_eq!(
            verify_consistency_against_roots(&proof, &old, &other_tenant),
            Err(MerkleError::RootBindingMismatch("tenant"))
        );

        // Sizes must be exactly the signed ones...
        let wrong_size = signed_root(&key, "tenant-a", 4, &proof.old_root);
        assert_eq!(
            verify_consistency_against_roots(&proof, &wrong_size, &new),
            Err(MerkleError::RootBindingMismatch("old_size"))
        );
        let wrong_new_size = signed_root(&key, "tenant-a", 10, &proof.new_root);
        assert_eq!(
            verify_consistency_against_roots(&proof, &old, &wrong_new_size),
            Err(MerkleError::RootBindingMismatch("new_size"))
        );

        // ...and so must the hashes. A self-consistent proof over roots
        // nobody signed is exactly the forgery the binding exists to stop.
        let unrelated = signed_root(&key, "tenant-a", 5, &encode_hex32(&[0x11u8; 32]));
        assert_eq!(
            verify_consistency_against_roots(&proof, &unrelated, &new),
            Err(MerkleError::RootBindingMismatch("old_root"))
        );
        let unrelated_new = signed_root(&key, "tenant-a", 9, &encode_hex32(&[0x22u8; 32]));
        assert_eq!(
            verify_consistency_against_roots(&proof, &old, &unrelated_new),
            Err(MerkleError::RootBindingMismatch("new_root"))
        );
    }

    #[test]
    fn binding_does_not_verify_signatures_itself() {
        // The binding helper is deliberately signature-blind: a root whose
        // signature is garbage still binds, because checking it is
        // `verify_signed_root`'s job and the caller's responsibility. This
        // pins that split so nobody later assumes binding implies signed.
        let key = signing_key();
        let l = lines(4);
        let proof = build_consistency_proof(&l, 2, 4).unwrap();
        let old = signed_root(&key, "t", 2, &proof.old_root);
        let mut new = signed_root(&key, "t", 4, &proof.new_root);
        new.signature = B64.encode([0u8; 64]);
        assert_eq!(verify_consistency_against_roots(&proof, &old, &new), Ok(()));
        assert_eq!(
            verify_signed_root(&new, &key.verifying_key()),
            Err(MerkleError::SignatureInvalid)
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

    #[test]
    fn membership_rejects_a_self_consistent_proof_over_an_unsigned_root() {
        let key = signing_key();
        let l = lines(8);
        let root_hash = encode_hex32(&merkle_root(&l));
        let signed = signed_root(&key, "local", 8, &root_hash);
        // A proof over a different leaf set folds to its own root perfectly
        // well; that root is simply not the one the host signed.
        let other = lines(4);
        let proof = build_inclusion_proof(&other, 1).expect("proof over the other tree");
        let err = verify_membership(&proof, &signed, &key.verifying_key(), "local")
            .expect_err("a proof over a different tree must not pass");
        assert!(
            matches!(err, MembershipError::RootBinding { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn membership_rejects_a_genuinely_signed_root_for_another_tenant() {
        let key = signing_key();
        let l = lines(8);
        let root_hash = encode_hex32(&merkle_root(&l));
        let signed = signed_root(&key, "other-tenant", 8, &root_hash);
        let proof = build_inclusion_proof(&l, 3).expect("proof");
        let err = verify_membership(&proof, &signed, &key.verifying_key(), "local")
            .expect_err("a root for another tenant is not evidence for this one");
        assert!(
            matches!(err, MembershipError::TenantMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn membership_accepts_a_proof_bound_to_its_own_signed_root() {
        let key = signing_key();
        let l = lines(8);
        let root_hash = encode_hex32(&merkle_root(&l));
        let signed = signed_root(&key, "local", 8, &root_hash);
        let proof = build_inclusion_proof(&l, 3).expect("proof");
        verify_membership(&proof, &signed, &key.verifying_key(), "local").expect("membership");
    }
}
