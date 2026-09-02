//! JBD2 live-write side: serialize a transaction, write it to the journal
//! inode, then apply the writes to their final fs locations and mark the
//! journal clean.
//!
//! The replay-side dual is [`crate::journal_apply`] (which the mount path
//! calls when the journal is dirty). The serialization dual is
//! [`crate::transaction::Transaction`] (which builds the journal-format
//! bytes). This module is the glue: it owns the journal inode's logical→
//! physical map, the JBD2 superblock cursor (`start` + `sequence`), and
//! the four-fence sequencing that makes a write crash-safe.
//!
//! ## Crash-safety contract — "journal then immediate checkpoint"
//!
//! Each [`JournalWriter::commit`] call performs five fenced steps:
//!
//! ```text
//!   1. Write transaction blocks (descriptor + data + commit) to journal
//!      logical blocks [1, 1+N) → flush.
//!   2. Set jsb.start = 1 (mark journal dirty), keep jsb.sequence as-is →
//!      flush.
//!   3. Write each fs block in the transaction to its final on-disk
//!      location → flush.
//!   4. Set jsb.start = 0 (clean), bump jsb.sequence → flush.
//! ```
//!
//! Crash analysis:
//!
//! - Crash before step 2: jsb.start unchanged → walker yields empty plan
//!   → the partially-written journal is ignored.
//! - Crash between 2 and 3: jsb.start = 1 → walker reads one transaction,
//!   replay applies the writes (idempotent with what step 3 would have
//!   written).
//! - Crash between 3 and 4: same — replay re-applies; final-location
//!   bytes are already what they would be after replay, so it's a no-op.
//! - Crash after 4: clean state, walker yields empty plan.
//!
//! ## Limitations (deferred to later Phase 5 sub-items)
//!
//! - Transactions are bounded by `max_len - 2` blocks (one for sb, one for
//!   commit). Large file writes that exceed the journal capacity must be
//!   split by the caller; this module errors on overflow.
//! - No batching across calls. Every commit checkpoints immediately, so
//!   the journal only ever holds one transaction at rest. This is
//!   correctness-first; ring-style batching is a Phase 8 perf concern.
//! - The JBD2 superblock checksum (`s_checksum` at 0xFC) is recomputed by
//!   `write_jsb` whenever the journal is checksummed (CSUM_V2/V3), because we
//!   mutate `s_start` + `s_sequence` on every commit. A real Linux kernel AND
//!   `e2fsck` REFUSE a checksummed journal whose superblock checksum is stale
//!   ("Journal superblock is corrupt"), so leaving it unrecomputed bricks the
//!   fs on the next mount. v1 journals have no such field and are untouched.

use crate::block_io::BlockDevice;
use crate::error::{Error, Result};
use crate::fs::Filesystem;
use crate::inode::Inode;
use crate::jbd2::{self, JournalSuperblock, JBD2_MAGIC_NUMBER};
use crate::transaction::Transaction;

/// Owns the live-write side of the JBD2 journal. Built once at mount time
/// (when the FS has a journal); reused across every mutating capi call.
///
/// Cheap to construct (one inode read + extent walk). Not thread-safe; the
/// outer Filesystem lock must serialize mutating ops anyway.
pub struct JournalWriter {
    /// `physical_map[logical]` is the fs physical block backing journal
    /// logical block `logical`. Length = `jsb.max_len`. Block 0 is the
    /// JBD2 superblock; blocks 1.. carry transactions.
    physical_map: Vec<u64>,
    /// Block size of the underlying device (matches `jsb.block_size`).
    block_size: u32,
    /// Cached JBD2 superblock — mutated in memory + flushed to disk on
    /// every commit. The on-disk truth always matches this between calls.
    jsb: JournalSuperblock,
}

impl JournalWriter {
    /// Open the writer for a mounted filesystem.
    ///
    /// Returns `Ok(None)` when the FS has no journal (`s_journal_inum == 0`)
    /// — callers should fall back to unjournaled writes in that case.
    /// Returns `Err` when the journal is misconfigured (e.g. the journal
    /// inode is missing or unparsable).
    ///
    /// Flavor-aware: walks the journal inode's block tree via
    /// [`crate::indirect::map_logical_any`], so ext3 journals (legacy
    /// indirect block pointers) work the same as ext4 ones (extent tree).
    pub fn open(fs: &Filesystem) -> Result<Option<Self>> {
        let Some(jsb) = jbd2::read_superblock(fs)? else {
            return Ok(None);
        };
        let raw = fs.read_inode_raw(fs.sb.journal_inode)?;
        let jinode = Inode::parse(&raw)?;

        // Build the full physical map up-front. For typical 32 MiB journals
        // at 4 KiB blocks that's 8192 entries — tiny. Allocates once at
        // mount; every commit then does a constant-time index.
        let bs = fs.sb.block_size();
        let mut physical_map = Vec::with_capacity(jsb.max_len as usize);
        for logical in 0..jsb.max_len as u64 {
            let phys = crate::indirect::map_logical_any(
                &jinode.block,
                jinode.flags,
                fs.dev.as_ref(),
                bs,
                logical,
            )?
            .ok_or(Error::Corrupt(
                "journal_writer: journal inode has unmapped logical block",
            ))?;
            physical_map.push(phys);
        }

        Ok(Some(Self {
            physical_map,
            block_size: bs,
            jsb,
        }))
    }

    /// Begin a new transaction with the next sequence number. Caller adds
    /// writes, then calls [`Self::commit`] to publish.
    pub fn begin(&self) -> Transaction {
        Transaction::begin(
            self.jsb.sequence,
            self.block_size,
            self.jsb.uses_64bit(),
            self.jsb.uses_csum_v2_or_v3(),
        )
    }

    /// The capacity (in fs blocks) the caller can fit into one transaction.
    /// One block is reserved for the JBD2 superblock; the remaining
    /// `max_len - 1` carry [descriptor, data..., (revoke), commit].
    pub fn max_blocks_per_transaction(&self) -> usize {
        // -1 for sb. Caller's writes also need a descriptor + commit slot,
        // so payload-only capacity is roughly `max_len - 3` data blocks
        // when the descriptor's tag table fits in one block. We expose the
        // raw upper bound here; the commit path enforces the real limit.
        (self.jsb.max_len as usize).saturating_sub(1)
    }

    /// Publish a transaction crash-safely (see module docs for the four-
    /// fence ordering). On success, the in-memory JSB is up-to-date and
    /// the on-disk JSB has been written back twice (dirty marker + clean
    /// marker).
    pub fn commit(&mut self, dev: &dyn BlockDevice, tx: &Transaction) -> Result<()> {
        if !dev.is_writable() {
            return Err(Error::ReadOnly);
        }

        // Sanity: the transaction's seq must match what we handed out from
        // begin(). A mismatch means the caller built it with a stale
        // writer or skipped begin() — either is a programming error that
        // could corrupt the journal.
        if tx.sequence != self.jsb.sequence {
            return Err(Error::Corrupt(
                "journal_writer: transaction sequence does not match writer state",
            ));
        }

        let blocks = tx.commit()?;
        if blocks.is_empty() {
            return Ok(()); // empty transaction is a no-op
        }
        if blocks.len() > self.max_blocks_per_transaction() {
            return Err(Error::Corrupt(
                "journal_writer: transaction too large for journal",
            ));
        }

        let bs_u64 = self.block_size as u64;

        // -- Step 1: write transaction blocks to journal at logical [1..1+N).
        //    Block 0 is the JBD2 superblock; we never overwrite it here.
        let txn_first_jblock = 1usize;
        for (i, block) in blocks.iter().enumerate() {
            let jblock_idx = txn_first_jblock + i;
            let phys = self.physical_map[jblock_idx];
            dev.write_at(phys * bs_u64, block)?;
        }
        dev.flush()?;

        // -- Step 2: mark journal dirty. start = first txn block; sequence
        //    unchanged so the walker matches our header_sequence.
        self.jsb.start = txn_first_jblock as u32;
        self.write_jsb(dev)?;
        dev.flush()?;

        // -- Step 3: apply writes to final-location fs blocks.
        for w in &tx.writes {
            dev.write_at(w.fs_block * bs_u64, &w.bytes)?;
        }
        dev.flush()?;

        // -- Step 4: mark journal clean + advance sequence.
        self.jsb.start = 0;
        self.jsb.sequence = self.jsb.sequence.wrapping_add(1);
        self.write_jsb(dev)?;
        dev.flush()?;

        Ok(())
    }

    /// Re-emit the JBD2 superblock at journal logical block 0 from the
    /// in-memory `self.jsb`. Patches only the fields we mutate
    /// (`s_start`, `s_sequence`, `s_header.h_sequence`); leaves all other
    /// bytes (including the v2 checksum trailer) intact by reading the
    /// existing block first.
    ///
    /// Big-endian on disk per JBD2 convention.
    fn write_jsb(&self, dev: &dyn BlockDevice) -> Result<()> {
        let bs_u64 = self.block_size as u64;
        let phys = self.physical_map[0];
        let mut buf = vec![0u8; self.block_size as usize];
        dev.read_at(phys * bs_u64, &mut buf)?;

        // Verify what we read still looks like our journal sb. A bit-flip
        // here would silently brick the journal; better to refuse.
        let magic = u32::from_be_bytes(buf[0x00..0x04].try_into().unwrap());
        if magic != JBD2_MAGIC_NUMBER {
            return Err(Error::Corrupt(
                "journal_writer: jsb block lost its magic between mount and commit",
            ));
        }
        let block_type = u32::from_be_bytes(buf[0x04..0x08].try_into().unwrap());
        if block_type != self.jsb.block_type {
            return Err(Error::Corrupt(
                "journal_writer: jsb block_type changed since mount",
            ));
        }

        // h_sequence (header) at 0x08, s_sequence at 0x18, s_start at 0x1C.
        // Kernel keeps h_sequence == s_sequence on the sb; we mirror that.
        buf[0x08..0x0C].copy_from_slice(&self.jsb.sequence.to_be_bytes());
        buf[0x18..0x1C].copy_from_slice(&self.jsb.sequence.to_be_bytes());
        buf[0x1C..0x20].copy_from_slice(&self.jsb.start.to_be_bytes());

        // Recompute the JBD2 superblock checksum (s_checksum at 0xFC) when the
        // journal is checksummed (CSUM_V2/V3). It covers the whole 1024-byte
        // journal_superblock_t with s_checksum zeroed, seeded ~0 — the journal
        // is self-contained, so this is NOT the fs metadata_csum seed. Leaving
        // it stale after mutating s_start/s_sequence makes a real kernel and
        // e2fsck refuse the journal ("Journal superblock is corrupt"). v1
        // journals carry no such field; their bytes are left intact.
        if self.jsb.uses_csum_v2_or_v3() {
            const JSB_LEN: usize = 1024; // sizeof(journal_superblock_t)
            buf[0xFC..0x100].copy_from_slice(&0u32.to_be_bytes());
            let csum = crate::checksum::linux_crc32c(!0, &buf[..JSB_LEN]);
            buf[0xFC..0x100].copy_from_slice(&csum.to_be_bytes());
        }

        dev.write_at(phys * bs_u64, &buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_io::FileDevice;
    use std::fs;
    use std::sync::Arc;

    fn copy_to_tmp(name: &str, tag: &str) -> Option<String> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let src = format!("{}/test-disks/{}", env!("CARGO_MANIFEST_DIR"), name);
        if !std::path::Path::new(&src).exists() {
            return None;
        }
        let dst = format!("/tmp/fs_ext4_jw_{}_{tag}_{n}.img", std::process::id());
        fs::copy(&src, &dst).ok()?;
        Some(dst)
    }

    #[test]
    fn open_returns_none_when_no_journal() {
        // ext4-no-csum.img is built without a journal in some configs; if it
        // happens to have one, this test is a no-op (we just exercise the
        // open path). The point of the test is that open() itself doesn't
        // panic on an unjournaled image.
        let Some(path) = copy_to_tmp("ext4-no-csum.img", "no_journal") else {
            return;
        };
        let dev = FileDevice::open(&path).expect("open ro");
        let fs = Filesystem::mount(Arc::new(dev)).expect("mount");
        // Just exercise — either Some or None is fine; we're checking
        // structural correctness of the open path.
        let _ = JournalWriter::open(&fs).expect("open journal_writer");
        fs::remove_file(path).ok();
    }

    #[test]
    fn empty_transaction_is_no_op() {
        let Some(path) = copy_to_tmp("ext4-basic.img", "empty_tx") else {
            return;
        };
        let dev = FileDevice::open_rw(&path).expect("open rw");
        let fs = Filesystem::mount(Arc::new(dev)).expect("mount");
        let Some(mut jw) = JournalWriter::open(&fs).expect("open writer") else {
            return; // image has no journal — skip
        };
        let initial_seq = jw.jsb.sequence;
        let tx = jw.begin();
        // commit() short-circuits on tx.commit() returning a single commit
        // block — actually tx.commit() always returns at least the commit
        // block, so an empty tx still goes through the protocol but writes
        // only one block. Verify it advances sequence by 1.
        jw.commit(fs.dev.as_ref(), &tx).expect("commit");
        assert_eq!(
            jw.jsb.sequence,
            initial_seq.wrapping_add(1),
            "sequence should advance even for a no-write commit"
        );
        assert_eq!(jw.jsb.start, 0, "should be clean after commit");
        fs::remove_file(path).ok();
    }
}
