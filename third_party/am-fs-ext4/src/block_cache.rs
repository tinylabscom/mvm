//! Buffer cache wrapping a `BlockDevice`.
//!
//! `CachedDevice` is the single source of truth for block contents
//! within a mount session. Mirrors Linux's buffer-cache role for
//! journaled filesystems: reads are served from the cache, writes
//! update the cache, and the cache holds journaled-but-not-yet-
//! checkpointed bytes so that subsequent reads see them before the
//! data area on disk catches up.
//!
//! Design:
//! - **LRU clean entries** — `entries` holds blocks read from disk
//!   or written through `write_at`. LRU-evictable; the disk has the
//!   same bytes so eviction is safe.
//! - **Pinned entries** — `pinned` holds blocks whose bytes only
//!   exist in this map and the journal log on disk; the data area on
//!   disk still has the pre-commit content. Pinned entries are
//!   NEVER evicted, since evicting them would lose the only
//!   in-memory copy and the next allocator scan would re-read stale
//!   bytes from disk. `Filesystem::commit_block_buffer` populates
//!   `pinned` after a successful journal commit; the
//!   `Filesystem::replay_journal_if_dirty` hook calls `unpin_all`
//!   when the journal has been checkpointed.
//! - **Write-through update** — `write_at` UPDATES the cache (not
//!   invalidates) and forwards to the inner device. This keeps the
//!   cache consistent with disk for direct writes (e.g.
//!   `write_inode_raw`) and means a read-after-write is satisfied
//!   from the cache without bouncing to disk.
//! - **Block-aligned reads only.** Multi-block reads bypass the
//!   cache and pass through.
//! - **Crash safety unchanged.** Pinned bytes are also persisted in
//!   the journal log (the caller invoked `populate_cache` after a
//!   journal commit); on crash, replay applies them. Clean LRU
//!   entries match disk by construction.
//! - **No external LRU crate** — hand-rolled to avoid pulling in
//!   GPL/LGPL deps and to keep the cache logic auditable.

use crate::block_io::BlockDevice;
use crate::error::Result;
use std::collections::HashMap;
use std::sync::Mutex;

/// Inner cache state held under a Mutex on `CachedDevice`.
///
/// Two maps:
/// - `entries`: clean blocks (LRU-evictable; disk has the same bytes).
/// - `pinned`: blocks whose bytes only exist here and in the journal
///   log on disk. NEVER evicted until `unpin_all`.
///
/// Read order: `pinned` → `entries` → inner device.
/// Write through `write_at`: updates `entries` only; pinned stays.
/// Populate via `populate`: inserts into `pinned`.
struct CacheState {
    capacity: usize,
    entries: HashMap<u64, (Vec<u8>, u64)>,
    pinned: HashMap<u64, Vec<u8>>,
    next_seq: u64,
    hits: u64,
    misses: u64,
}

impl CacheState {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity.min(1024)),
            pinned: HashMap::new(),
            next_seq: 0,
            hits: 0,
            misses: 0,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = s.wrapping_add(1);
        s
    }

    /// Look up `block`. Pinned wins over LRU. On miss: None.
    fn get(&mut self, block: u64) -> Option<Vec<u8>> {
        if let Some(bytes) = self.pinned.get(&block) {
            self.hits += 1;
            return Some(bytes.clone());
        }
        let seq = self.next_seq();
        if let Some(slot) = self.entries.get_mut(&block) {
            slot.1 = seq;
            self.hits += 1;
            Some(slot.0.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    /// Insert/update a clean LRU entry. Evicts the LRU victim if full.
    /// Pinned entries are never considered for eviction.
    fn put(&mut self, block: u64, bytes: Vec<u8>) {
        // If the block is already pinned, replace its pinned bytes
        // (a journaled write superseded by a direct write — unlikely
        // in practice but kept consistent).
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.pinned.entry(block) {
            e.insert(bytes);
            return;
        }
        if self.entries.len() >= self.capacity {
            if let Some((&victim, _)) = self.entries.iter().min_by_key(|(_, (_, seq))| *seq) {
                self.entries.remove(&victim);
            }
        }
        let seq = self.next_seq();
        self.entries.insert(block, (bytes, seq));
    }

    /// Stash a block whose bytes live only here and in the journal
    /// log. Will not be evicted until `unpin_all`. If the block was
    /// in the LRU, the LRU entry is dropped — pinned takes priority.
    fn pin(&mut self, block: u64, bytes: Vec<u8>) {
        self.entries.remove(&block);
        self.pinned.insert(block, bytes);
    }

    /// Move all pinned entries into the LRU (now safe to evict).
    fn unpin_all(&mut self) {
        // Drain pinned. Each entry becomes an LRU candidate;
        // capacity-bound eviction kicks in if the LRU was already full.
        let drained: Vec<(u64, Vec<u8>)> = self.pinned.drain().collect();
        for (block, bytes) in drained {
            if self.entries.len() >= self.capacity {
                if let Some((&victim, _)) = self.entries.iter().min_by_key(|(_, (_, seq))| *seq) {
                    self.entries.remove(&victim);
                }
            }
            let seq = self.next_seq();
            self.entries.insert(block, (bytes, seq));
        }
    }
}

/// LRU-cached BlockDevice. Pass-through for is_writable + size_bytes;
/// caches block-aligned reads, invalidates on writes.
pub struct CachedDevice {
    inner: std::sync::Arc<dyn BlockDevice>,
    block_size: u32,
    state: Mutex<CacheState>,
}

impl CachedDevice {
    /// Wrap `inner` with an LRU of `capacity` blocks. Pick `capacity`
    /// based on workload: 64 blocks (256 KiB at 4 KiB) is a reasonable
    /// default for general use; bigger directory walks benefit from 256+.
    pub fn new(inner: std::sync::Arc<dyn BlockDevice>, block_size: u32, capacity: usize) -> Self {
        Self {
            inner,
            block_size,
            state: Mutex::new(CacheState::new(capacity.max(1))),
        }
    }

    /// Snapshot (hits, misses) — useful for benchmarks and tests.
    pub fn stats(&self) -> (u64, u64) {
        let s = self.state.lock().expect("cache mutex poisoned");
        (s.hits, s.misses)
    }
}

impl BlockDevice for CachedDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let bs = self.block_size as u64;
        let block = offset / bs;
        let off_in_block = (offset % bs) as usize;
        let len = buf.len();

        // Block-aligned single-block read: cache fast path.
        if off_in_block + len <= bs as usize {
            // Try the cache first.
            {
                let mut state = self.state.lock().expect("cache mutex poisoned");
                if let Some(blk) = state.get(block) {
                    buf.copy_from_slice(&blk[off_in_block..off_in_block + len]);
                    return Ok(());
                }
            }
            // Miss: read the whole block from the inner device, then cache.
            let mut blk = vec![0u8; bs as usize];
            self.inner.read_at(block * bs, &mut blk)?;
            buf.copy_from_slice(&blk[off_in_block..off_in_block + len]);
            let mut state = self.state.lock().expect("cache mutex poisoned");
            state.put(block, blk);
            return Ok(());
        }

        // Multi-block read (rare): bypass the cache, pass through.
        self.inner.read_at(offset, buf)
    }

    fn size_bytes(&self) -> u64 {
        self.inner.size_bytes()
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let bs = self.block_size as u64;
        // Forward to disk first; if the inner write fails, the cache
        // still reflects whatever was there before — no partial update.
        self.inner.write_at(offset, buf)?;

        // Single-block, block-aligned writes update the cache directly
        // (write-through). Multi-block / unaligned writes fall through
        // to invalidation since we don't have the full block image
        // for each affected block.
        let off_in_block = (offset % bs) as usize;
        let len = buf.len();
        if off_in_block == 0 && len == bs as usize {
            let block = offset / bs;
            let mut state = self.state.lock().expect("cache mutex poisoned");
            state.put(block, buf.to_vec());
            return Ok(());
        }

        // Unaligned / multi-block write. Two layers to handle:
        //
        // - PINNED blocks hold post-commit-pre-checkpoint journaled
        //   bytes that don't yet exist on disk. We MUST NOT
        //   invalidate them — the on-disk data area still has the
        //   pre-commit version, so dropping the pinned image would
        //   make the next read serve stale bytes for the unwritten
        //   portion. Instead, overlay the new sub-block bytes onto
        //   the pinned image so reads see (journaled bytes for the
        //   unwritten portion + new bytes for the written portion).
        //
        // - LRU entries (clean, not pinned) can be dropped: we just
        //   wrote to disk above, so the disk holds the merged truth
        //   (old bytes for unwritten portion + new bytes for written
        //   portion). The next read fetches that merged image.
        //
        // The only sub-block write site in the crate today is
        // `write_inode_raw` (writes a single inode at its offset
        // within a 4 KiB inode-table block); other direct writes
        // (`set_block_run_used`, BGD blocks, indirect blocks) are
        // full-block-aligned and take the fast path above.
        let first_block = offset / bs;
        let last_block = (offset + buf.len() as u64).saturating_sub(1) / bs;
        let buf_end_byte = offset + buf.len() as u64;
        let mut state = self.state.lock().expect("cache mutex poisoned");
        for b in first_block..=last_block {
            let block_start = b * bs;
            let block_end = block_start + bs;
            let write_start = offset.max(block_start);
            let write_end = buf_end_byte.min(block_end);
            let in_block_off = (write_start - block_start) as usize;
            let in_block_end = (write_end - block_start) as usize;
            let buf_start = (write_start - offset) as usize;
            let buf_end = (write_end - offset) as usize;

            if let Some(img) = state.pinned.get_mut(&b) {
                img[in_block_off..in_block_end].copy_from_slice(&buf[buf_start..buf_end]);
            }
            state.entries.remove(&b);
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn is_writable(&self) -> bool {
        self.inner.is_writable()
    }

    fn populate_cache(&self, block: u64, bytes: Vec<u8>) {
        let mut state = self.state.lock().expect("cache mutex poisoned");
        state.pin(block, bytes);
    }

    fn unpin_all(&self) {
        let mut state = self.state.lock().expect("cache mutex poisoned");
        state.unpin_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Counts every read/write so we can prove the cache eliminates them.
    struct CountingDevice {
        bytes: Mutex<Vec<u8>>,
        reads: std::sync::atomic::AtomicU64,
        writes: std::sync::atomic::AtomicU64,
        writable: bool,
    }

    impl CountingDevice {
        fn new(size: usize, writable: bool) -> Arc<Self> {
            Arc::new(Self {
                bytes: Mutex::new(vec![0u8; size]),
                reads: std::sync::atomic::AtomicU64::new(0),
                writes: std::sync::atomic::AtomicU64::new(0),
                writable,
            })
        }
        fn reads(&self) -> u64 {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn writes(&self) -> u64 {
            self.writes.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl BlockDevice for CountingDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let b = self.bytes.lock().unwrap();
            let off = offset as usize;
            buf.copy_from_slice(&b[off..off + buf.len()]);
            Ok(())
        }
        fn size_bytes(&self) -> u64 {
            self.bytes.lock().unwrap().len() as u64
        }
        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut b = self.bytes.lock().unwrap();
            let off = offset as usize;
            b[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn is_writable(&self) -> bool {
            self.writable
        }
    }

    #[test]
    fn second_read_of_same_block_is_a_cache_hit() {
        let inner = CountingDevice::new(4096 * 16, false);
        let cached = CachedDevice::new(inner.clone(), 4096, 8);
        let mut buf = vec![0u8; 100];
        cached.read_at(0, &mut buf).unwrap();
        cached.read_at(0, &mut buf).unwrap();
        cached.read_at(50, &mut buf).unwrap(); // still in same block 0
        assert_eq!(inner.reads(), 1, "cache should serve all 3 from one read");
        let (hits, misses) = cached.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 1);
    }

    #[test]
    fn unaligned_write_merges_into_pinned_block() {
        // Pinned blocks hold post-commit-pre-checkpoint journaled
        // bytes that don't yet exist on disk. A sub-block write must
        // NOT invalidate the pinned image — that would let later
        // reads serve stale data-area bytes for the untouched portion.
        // The cache must overlay the new sub-block bytes onto the
        // pinned image, preserving everything else.
        let inner = CountingDevice::new(4096 * 16, true);
        let cached = CachedDevice::new(inner.clone(), 4096, 8);
        // Pin block 5 with a synthetic post-commit image. Disk
        // (CountingDevice) still holds zeros — the pre-commit version.
        let mut journaled = vec![0u8; 4096];
        journaled[0] = 0xAA;
        journaled[3000] = 0xBB;
        cached.populate_cache(5, journaled);
        // Sub-block direct write touching bytes 100..200 of block 5.
        cached.write_at(5 * 4096 + 100, &[0xCCu8; 100]).unwrap();
        // Read back the full block via the cache.
        let mut buf = vec![0u8; 4096];
        for i in 0..4096 {
            cached
                .read_at(5 * 4096 + i as u64, &mut buf[i..i + 1])
                .unwrap();
        }
        assert_eq!(buf[0], 0xAA, "pinned journaled byte 0 must survive");
        assert_eq!(buf[100], 0xCC, "new sub-block bytes must be visible");
        assert_eq!(buf[199], 0xCC);
        assert_eq!(buf[200], 0x00, "untouched portion stays at journaled value");
        assert_eq!(
            buf[3000], 0xBB,
            "pinned bytes outside the write window survive"
        );
    }

    #[test]
    fn unaligned_write_invalidates_cache_entry() {
        // Partial-block writes don't have a full block image to
        // update the cache with, so we drop the affected entries and
        // the next read pays the cost of a fresh disk read.
        let inner = CountingDevice::new(4096 * 16, true);
        let cached = CachedDevice::new(inner.clone(), 4096, 8);
        let mut buf = vec![0u8; 100];
        cached.read_at(0, &mut buf).unwrap();
        cached.write_at(0, &[42u8; 100]).unwrap(); // unaligned: 100 < 4096
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(inner.reads(), 2);
        assert_eq!(buf[0], 42, "post-write read should see the new bytes");
    }

    #[test]
    fn aligned_write_updates_cache_entry() {
        // Full-block, block-aligned writes go straight into the cache
        // (write-through). The next read is served from cache without
        // touching the inner device — read-after-write coherence with
        // zero extra device reads.
        let inner = CountingDevice::new(4096 * 16, true);
        let cached = CachedDevice::new(inner.clone(), 4096, 8);
        // Prime the cache with a read.
        let mut buf = vec![0u8; 100];
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(inner.reads(), 1);
        // Full-block write — cache should hold the new bytes.
        let new_block = vec![0xCDu8; 4096];
        cached.write_at(0, &new_block).unwrap();
        // Read back: served from cache, no additional device read.
        let mut readback = vec![0u8; 100];
        cached.read_at(0, &mut readback).unwrap();
        assert_eq!(inner.reads(), 1, "aligned write-through skips disk read");
        assert_eq!(readback[0], 0xCD);
        // Verify the inner device also got the bytes.
        let mut from_disk = vec![0u8; 100];
        inner.read_at(0, &mut from_disk).unwrap();
        assert_eq!(from_disk[0], 0xCD);
    }

    #[test]
    fn populate_cache_pins_entry_against_lru() {
        // Pinned entries hold journaled-but-not-checkpointed bytes —
        // they're the only in-memory copy, so eviction would lose
        // data. Verify they survive even when the LRU is hammered.
        let inner = CountingDevice::new(4096 * 16, false);
        let cached = CachedDevice::new(inner.clone(), 4096, 2); // tiny capacity
                                                                // Pin block 7 with synthetic journaled bytes.
        cached.populate_cache(7, vec![0xAAu8; 4096]);
        // Saturate the LRU with reads of other blocks.
        let mut throwaway = vec![0u8; 8];
        for blk in 0..5u64 {
            cached.read_at(blk * 4096, &mut throwaway).unwrap();
        }
        // Block 7 must still be served from the pin, NOT from disk
        // (which has zeros).
        let mut buf = vec![0u8; 8];
        cached.read_at(7 * 4096, &mut buf).unwrap();
        assert_eq!(buf, vec![0xAA; 8],
                   "pinned entry must survive LRU pressure — otherwise journaled writes vanish before checkpoint");
    }

    #[test]
    fn unpin_all_lets_pinned_entries_evict_normally() {
        // After journal replay, pinned bytes are also on disk —
        // unpin_all moves them into the LRU where they can be evicted
        // under normal pressure, freeing memory.
        let inner = CountingDevice::new(4096 * 16, false);
        let cached = CachedDevice::new(inner.clone(), 4096, 1); // capacity=1
        cached.populate_cache(3, vec![0xBBu8; 4096]);
        cached.unpin_all();
        // Now read another block — block 3 should be evicted under
        // capacity pressure.
        let mut throwaway = vec![0u8; 8];
        cached.read_at(0, &mut throwaway).unwrap();
        // Re-read block 3 — should miss (evicted), serve from disk
        // (which is zeros — `unpin_all` is purely an in-memory
        // re-classification, the cache still hands out the pinned
        // bytes that are STILL there until eviction picks them).
        // Actually since capacity=1 and we just read block 0, block 3
        // got evicted; the next read of block 3 misses the cache and
        // hits the inner device. Inner has zeros (no journal replay
        // really happened here — this test only exercises the
        // pin/unpin state machine).
        let mut buf3 = vec![0u8; 8];
        cached.read_at(3 * 4096, &mut buf3).unwrap();
        assert_eq!(
            buf3,
            vec![0; 8],
            "after unpin + LRU eviction, the inner device's bytes win"
        );
    }

    #[test]
    fn multi_block_read_bypasses_cache() {
        let inner = CountingDevice::new(4096 * 16, false);
        let cached = CachedDevice::new(inner.clone(), 4096, 8);
        let mut buf = vec![0u8; 8000]; // spans blocks 0 + 1
        cached.read_at(0, &mut buf).unwrap();
        // Cache wasn't populated → second multi-block read goes to disk again.
        cached.read_at(0, &mut buf).unwrap();
        assert_eq!(inner.reads(), 2);
        let (hits, misses) = cached.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 0, "multi-block reads bypass entirely");
    }

    #[test]
    fn lru_evicts_oldest_when_capacity_exceeded() {
        let inner = CountingDevice::new(4096 * 16, false);
        let cached = CachedDevice::new(inner.clone(), 4096, 2); // capacity=2
        let mut buf = vec![0u8; 8];
        // Read blocks 0, 1, 2 — block 0 should be evicted.
        for blk in 0..3u64 {
            cached.read_at(blk * 4096, &mut buf).unwrap();
        }
        // Re-read block 0 → should miss (evicted).
        cached.read_at(0, &mut buf).unwrap();
        // Re-read block 2 → should hit (most recent).
        cached.read_at(2 * 4096, &mut buf).unwrap();
        let (hits, misses) = cached.stats();
        assert_eq!(misses, 4, "blocks 0,1,2 + re-read of 0 (evicted)");
        assert_eq!(hits, 1, "re-read of 2 still cached");
    }

    #[test]
    fn lru_keeps_recently_touched_block_alive() {
        // With capacity=2, reading [0, 1, 0, 2] keeps block 0 alive
        // because it was touched between 1 and 2 — block 1 should be
        // the eviction victim, not 0.
        let inner = CountingDevice::new(4096 * 16, false);
        let cached = CachedDevice::new(inner.clone(), 4096, 2);
        let mut buf = vec![0u8; 8];
        cached.read_at(0, &mut buf).unwrap(); // miss → cache
        cached.read_at(4096, &mut buf).unwrap(); // miss → cache
        cached.read_at(0, &mut buf).unwrap(); // hit, bumps recency
        cached.read_at(2 * 4096, &mut buf).unwrap(); // miss → evicts block 1
        cached.read_at(0, &mut buf).unwrap(); // hit (still cached)
        let (hits, misses) = cached.stats();
        assert_eq!(hits, 2);
        assert_eq!(misses, 3);
        // Verify block 1 was the eviction victim, not 0.
        cached.read_at(4096, &mut buf).unwrap(); // should miss
        let (_, m_after) = cached.stats();
        assert_eq!(m_after, 4, "block 1 was evicted, re-read is a miss");
    }
}
