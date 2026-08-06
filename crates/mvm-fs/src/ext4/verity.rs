//! Pure-Rust dm-verity (version 1, SHA-256) Merkle **root hash**.
//!
//! Replaces the `veritysetup format` shell-out: given the rootfs image bytes,
//! the salt, and the block sizes, compute the same 32-byte root hash
//! `veritysetup` prints as `Root hash:`. That hash is dm-verity's integrity
//! anchor (claim 3) and mvm's content-addressed image identifier — so it is
//! deterministic by construction (a pure function of data + salt + block sizes).
//!
//! The CI `ext4-real-mount` lane cross-checks this against real `veritysetup` on
//! the same image, byte-for-byte on the hex.
//!
//! Version 1 hashing: each block digest is `SHA-256(salt ‖ block)` (salt
//! prepended). Leaves are the data-block digests; each level's digests are
//! packed 32 bytes each into hash blocks (zero-padded), and each hash block is
//! hashed to form the level above, until one block remains — the root hash is
//! that final block's digest.

use rayon::prelude::*;
use sha2::{Digest, Sha256};

const DIGEST_SIZE: usize = 32;

/// Compute the dm-verity v1 SHA-256 root hash of `data`.
///
/// `data.len()` should be a multiple of `data_block_size` (a rootfs image is);
/// a short final block is zero-padded, matching `veritysetup`.
pub fn root_hash(
    data: &[u8],
    salt: &[u8],
    data_block_size: usize,
    hash_block_size: usize,
) -> [u8; DIGEST_SIZE] {
    // Level 0 (leaves): digest of each data block.
    let n_data_blocks = data.len().div_ceil(data_block_size).max(1);
    let mut level: Vec<[u8; DIGEST_SIZE]> = (0..n_data_blocks)
        .into_par_iter()
        .map(|i| {
            let start = i * data_block_size;
            let end = (start + data_block_size).min(data.len());
            let mut block = vec![0u8; data_block_size];
            if start < data.len() {
                block[..end - start].copy_from_slice(&data[start..end]);
            }
            hash_block(salt, &block)
        })
        .collect();

    let hashes_per_block = hash_block_size / DIGEST_SIZE;
    loop {
        let n_blocks = level.len().div_ceil(hashes_per_block).max(1);
        if n_blocks == 1 {
            // This level fits one hash block — its digest is the root hash.
            return hash_block(salt, &pack(&level, 0, hash_block_size));
        }
        // Otherwise, hash each packed block to form the level above.
        level = (0..n_blocks)
            .into_par_iter()
            .map(|b| hash_block(salt, &pack(&level, b * hashes_per_block, hash_block_size)))
            .collect();
    }
}

/// A verity root hash plus the hash-tree bytes (no-superblock layout) that
/// dm-verity / `veritysetup open` consumes as the hash device.
pub struct VerityOutput {
    pub root_hash: [u8; DIGEST_SIZE],
    /// The hash tree, levels concatenated **top-first** (level L-1 down to
    /// level 0) — the layout `veritysetup format --no-superblock` writes and the
    /// kernel dm-verity target reads.
    pub hash_tree: Vec<u8>,
}

/// Compute the dm-verity v1 SHA-256 root hash **and** emit the full hash tree
/// (no-superblock). Byte-for-byte equal to `veritysetup format --no-superblock`
/// for the same `(data, salt, block sizes)`, which the CI lane asserts.
pub fn format(
    data: &[u8],
    salt: &[u8],
    data_block_size: usize,
    hash_block_size: usize,
) -> VerityOutput {
    let hashes_per_block = hash_block_size / DIGEST_SIZE;

    // Level 0 (leaves): one digest per data block.
    let n_data_blocks = data.len().div_ceil(data_block_size).max(1);
    let mut cur: Vec<[u8; DIGEST_SIZE]> = (0..n_data_blocks)
        .into_par_iter()
        .map(|i| {
            let start = i * data_block_size;
            let end = (start + data_block_size).min(data.len());
            let mut block = vec![0u8; data_block_size];
            if start < data.len() {
                block[..end - start].copy_from_slice(&data[start..end]);
            }
            hash_block(salt, &block)
        })
        .collect();

    // Build each level's *block bytes* bottom-up: level 0 first in `levels`.
    let mut levels: Vec<Vec<u8>> = Vec::new();
    loop {
        let n_blocks = cur.len().div_ceil(hashes_per_block).max(1);
        let mut level_bytes = vec![0u8; n_blocks * hash_block_size];
        for (j, digest) in cur.iter().enumerate() {
            let blk = j / hashes_per_block;
            let idx = j % hashes_per_block;
            let off = blk * hash_block_size + idx * DIGEST_SIZE;
            level_bytes[off..off + DIGEST_SIZE].copy_from_slice(digest);
        }
        levels.push(level_bytes);
        if n_blocks == 1 {
            break;
        }
        // Next level up: hash each block of this level.
        let this = levels.last().expect("just pushed");
        cur = (0..n_blocks)
            .into_par_iter()
            .map(|b| hash_block(salt, &this[b * hash_block_size..(b + 1) * hash_block_size]))
            .collect();
    }

    // Root hash = digest of the single top-level block.
    let top = levels.last().expect("at least one level");
    let root_hash = hash_block(salt, top);

    // Tree file: top level first, leaves last.
    let mut hash_tree = Vec::with_capacity(levels.iter().map(Vec::len).sum());
    for level in levels.iter().rev() {
        hash_tree.extend_from_slice(level);
    }

    VerityOutput {
        root_hash,
        hash_tree,
    }
}

/// Pack up to `hash_block_size / 32` digests starting at `from` into a single
/// zero-padded hash block.
fn pack(digests: &[[u8; DIGEST_SIZE]], from: usize, hash_block_size: usize) -> Vec<u8> {
    let hashes_per_block = hash_block_size / DIGEST_SIZE;
    let mut block = vec![0u8; hash_block_size];
    for j in 0..hashes_per_block {
        match digests.get(from + j) {
            Some(d) => block[j * DIGEST_SIZE..(j + 1) * DIGEST_SIZE].copy_from_slice(d),
            None => break,
        }
    }
    block
}

fn hash_block(salt: &[u8], block: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(block);
    h.finalize().into()
}

/// Lowercase-hex of a digest (the form `veritysetup` prints and mvm's
/// `rootfs.roothash` stores).
pub fn to_hex(digest: &[u8; DIGEST_SIZE]) -> String {
    let mut s = String::with_capacity(DIGEST_SIZE * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_hash_is_deterministic() {
        let data = vec![0xABu8; 4096 * 5];
        let salt = [0u8; 32];
        let a = root_hash(&data, &salt, 4096, 4096);
        let b = root_hash(&data, &salt, 4096, 4096);
        assert_eq!(a, b);
        assert_eq!(to_hex(&a).len(), 64);
    }

    #[test]
    fn single_data_block_matches_hand_computation() {
        // One 4096-byte data block of zeros, zero salt. The tree is a single
        // leaf that fits one hash block, so root = H(salt ‖ pack([H(salt ‖ block)])).
        let data = vec![0u8; 4096];
        let salt = [0u8; 32];
        let leaf = hash_block(&salt, &vec![0u8; 4096]);
        let mut hash_block_bytes = vec![0u8; 4096];
        hash_block_bytes[..32].copy_from_slice(&leaf);
        let expected = hash_block(&salt, &hash_block_bytes);
        assert_eq!(root_hash(&data, &salt, 4096, 4096), expected);
    }

    #[test]
    fn format_agrees_with_root_hash_and_emits_whole_blocks() {
        // 200 data blocks → 2 leaf hash blocks → a 2-level tree.
        let data = vec![0x5Au8; 4096 * 200];
        let salt = [0u8; 32];
        let out = format(&data, &salt, 4096, 4096);
        assert_eq!(out.root_hash, root_hash(&data, &salt, 4096, 4096));
        assert!(!out.hash_tree.is_empty());
        assert_eq!(out.hash_tree.len() % 4096, 0, "tree is whole hash blocks");
    }

    #[test]
    fn distinct_data_changes_the_root() {
        let salt = [0u8; 32];
        let a = root_hash(&vec![0u8; 4096 * 3], &salt, 4096, 4096);
        let b = root_hash(&vec![1u8; 4096 * 3], &salt, 4096, 4096);
        assert_ne!(a, b);
    }
}
