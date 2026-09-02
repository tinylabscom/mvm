//! Abstract block-device I/O.
//!
//! The driver doesn't care if blocks come from a file, raw device, or a
//! callback into Swift — it just needs `read_at(offset, buf) -> Result<()>`.
//!
//! `write_at` is an optional trait method: it defaults to returning
//! `Error::Corrupt("read-only device")` so every existing read-only caller
//! keeps working. `FileDevice` and the callback-with-writer device override
//! it when the underlying resource allows writes.

use crate::error::{Error, Result};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

/// Random-access block device. Reads required; writes optional.
pub trait BlockDevice: Send + Sync {
    /// Read exactly `buf.len()` bytes starting at `offset` (bytes from start of device).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Total device size in bytes (for bounds-checking).
    fn size_bytes(&self) -> u64;

    /// Write exactly `buf.len()` bytes at `offset`. Default: returns an error
    /// for read-only devices. Writable devices override this.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<()> {
        Err(Error::Corrupt(
            "block device is read-only (no write_at impl)",
        ))
    }

    /// Flush any pending writes to stable storage. Default: no-op for
    /// read-only devices; writable devices should implement fsync semantics.
    fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Reports whether `write_at` is likely to succeed. Used by the mount
    /// path to decide whether journal replay is possible.
    fn is_writable(&self) -> bool {
        false
    }

    /// Buffer-cache hook: stash `bytes` for `block` so a subsequent
    /// `read_at` returns those bytes instead of reading from physical
    /// storage. Used by `commit_block_buffer` to make journaled
    /// metadata visible to readers before the journal is checkpointed
    /// back to the data area on disk.
    ///
    /// Pinned entries inserted via `populate_cache` MUST NOT be evicted
    /// — they're the only place those bytes exist until `unpin_all`
    /// runs (typically after journal replay). Devices without a cache
    /// (raw `FileDevice`, etc.) implement this as a no-op and the
    /// caller's bytes simply have no in-memory shadow; that's safe
    /// because un-cached devices imply no separate journal log either.
    fn populate_cache(&self, _block: u64, _bytes: Vec<u8>) {}

    /// Buffer-cache hook: tell the device the journal has been
    /// checkpointed, so any blocks pinned via `populate_cache` are now
    /// consistent with disk and can be evicted under normal LRU
    /// pressure. No-op for un-cached devices.
    fn unpin_all(&self) {}
}

/// File-backed device — used for disk images and `/dev/diskN`.
pub struct FileDevice {
    file: Mutex<File>,
    size: u64,
    writable: bool,
}

impl FileDevice {
    /// Open read-only. Matches pre-existing behaviour.
    pub fn open(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            size,
            writable: false,
        })
    }

    /// Open read-write. Prefer this when the caller needs to journal-replay
    /// or apply Phase 4 mutations. Falls back to an error if the path is
    /// not writable.
    pub fn open_rw(path: &str) -> Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            size,
            writable: true,
        })
    }

    /// Open read-write if possible; otherwise fall back to read-only. Useful
    /// for the mount path so read-only images on e.g. a locked volume still
    /// mount, just without replay.
    pub fn open_best_effort(path: &str) -> Result<Self> {
        match Self::open_rw(path) {
            Ok(d) => Ok(d),
            Err(_) => Self::open(path),
        }
    }
}

impl BlockDevice for FileDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(buf)?;
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(Error::Corrupt("FileDevice opened read-only"));
        }
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(buf)?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        if !self.writable {
            return Ok(());
        }
        let mut f = self.file.lock().unwrap();
        f.flush()?;
        f.sync_data()?;
        Ok(())
    }

    fn is_writable(&self) -> bool {
        self.writable
    }
}

/// Read callback: fill `buf` starting at byte `offset`.
pub type ReadCb = Box<dyn Fn(u64, &mut [u8]) -> std::io::Result<()> + Send + Sync>;
/// Write callback: write `buf` starting at byte `offset`.
pub type WriteCb = Box<dyn Fn(u64, &[u8]) -> std::io::Result<()> + Send + Sync>;
/// Flush callback.
pub type FlushCb = Box<dyn Fn() -> std::io::Result<()> + Send + Sync>;

/// Callback-backed device — used when the host process owns the fd
/// (e.g. FSBlockDeviceResource via the C bridge). Optional write callback;
/// set to `None` for read-only.
pub struct CallbackDevice {
    pub size: u64,
    pub read: ReadCb,
    pub write: Option<WriteCb>,
    pub flush: Option<FlushCb>,
}

impl BlockDevice for CallbackDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (self.read)(offset, buf)?;
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.size
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        match &self.write {
            Some(f) => {
                f(offset, buf)?;
                Ok(())
            }
            None => Err(Error::Corrupt("CallbackDevice has no write callback")),
        }
    }

    fn flush(&self) -> Result<()> {
        match &self.flush {
            Some(f) => {
                f()?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn is_writable(&self) -> bool {
        self.write.is_some()
    }
}

// ---------------------------------------------------------------------------
// CachingDevice — small LRU block cache decorator
// ---------------------------------------------------------------------------

/// LRU read cache wrapping another `BlockDevice`.
///
/// Caches only reads whose `offset` is a multiple of `block_size` AND whose
/// `buf.len() == block_size`. Every other read bypasses the cache and goes
/// straight to the inner device — the common hot paths (`fs.read_block`,
/// `extent::lookup` child-block reads, bitmap reads) all satisfy that
/// constraint, while `file_io::read`'s arbitrary-offset reads don't need
/// caching (the OS page cache handles them when backed by `FileDevice`).
///
/// Writes invalidate any cached block whose range overlaps. The cache is
/// held under a single `Mutex` — fine for fs-driver workloads, which are
/// metadata-heavy rather than contention-bound.
pub struct CachingDevice {
    inner: Arc<dyn BlockDevice>,
    block_size: u64,
    state: Mutex<CacheState>,
}

struct CacheState {
    /// Fixed-capacity LRU; head is most-recently used.
    entries: VecDeque<(u64, Arc<Vec<u8>>)>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl CachingDevice {
    /// Wrap `inner`, caching at most `capacity` blocks of size `block_size`.
    pub fn new(inner: Arc<dyn BlockDevice>, block_size: u64, capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            inner,
            block_size,
            state: Mutex::new(CacheState {
                entries: VecDeque::with_capacity(capacity),
                capacity,
                hits: 0,
                misses: 0,
            }),
        })
    }

    /// Returns `(hits, misses)` — useful for tests and telemetry.
    pub fn stats(&self) -> (u64, u64) {
        let s = self.state.lock().unwrap();
        (s.hits, s.misses)
    }

    /// Drop every cached block. Callers should invoke this after any
    /// operation that mutates the underlying device outside this wrapper.
    pub fn invalidate_all(&self) {
        let mut s = self.state.lock().unwrap();
        s.entries.clear();
    }

    fn invalidate_range(state: &mut CacheState, start: u64, end: u64, block_size: u64) {
        state.entries.retain(|(off, _)| {
            let block_end = off.saturating_add(block_size);
            *off >= end || block_end <= start
        });
    }
}

impl BlockDevice for CachingDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        // Only cache exact block-aligned, block-sized reads.
        let cacheable =
            buf.len() as u64 == self.block_size && offset.is_multiple_of(self.block_size);
        if !cacheable {
            return self.inner.read_at(offset, buf);
        }

        // Probe the cache.
        {
            let mut s = self.state.lock().unwrap();
            if let Some(pos) = s.entries.iter().position(|(o, _)| *o == offset) {
                // Hit — move to front, copy out.
                let entry = s.entries.remove(pos).unwrap();
                buf.copy_from_slice(&entry.1);
                s.entries.push_front(entry);
                s.hits += 1;
                return Ok(());
            }
            s.misses += 1;
        }

        // Miss — read underlying, then insert (evicting LRU).
        self.inner.read_at(offset, buf)?;
        let data = Arc::new(buf.to_vec());
        let mut s = self.state.lock().unwrap();
        if s.entries.len() >= s.capacity {
            s.entries.pop_back();
        }
        s.entries.push_front((offset, data));
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.inner.size_bytes()
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let end = offset.saturating_add(buf.len() as u64);
        {
            let mut s = self.state.lock().unwrap();
            let bs = self.block_size;
            Self::invalidate_range(&mut s, offset, end, bs);
        }
        self.inner.write_at(offset, buf)
    }

    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    fn is_writable(&self) -> bool {
        self.inner.is_writable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_image(bytes: &[u8]) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/fs_ext4_block_io_test_{}_{n}.img", std::process::id());
        let mut f = File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[test]
    fn file_device_ro_write_rejected() {
        let path = tmp_image(&[0u8; 4096]);
        let dev = FileDevice::open(&path).unwrap();
        assert!(!dev.is_writable());
        let err = dev.write_at(0, &[1u8; 16]).unwrap_err();
        match err {
            Error::Corrupt(msg) => assert!(msg.contains("read-only")),
            _ => panic!(),
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn file_device_rw_round_trip() {
        let path = tmp_image(&[0u8; 4096]);
        let dev = FileDevice::open_rw(&path).unwrap();
        assert!(dev.is_writable());
        dev.write_at(100, &[0xAB, 0xCD, 0xEF]).unwrap();
        dev.flush().unwrap();
        let mut buf = [0u8; 3];
        dev.read_at(100, &mut buf).unwrap();
        assert_eq!(buf, [0xAB, 0xCD, 0xEF]);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn best_effort_falls_back_to_ro() {
        // Create a file without write permission.
        let path = tmp_image(&[0u8; 4096]);
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&path, perm).unwrap();

        let dev = FileDevice::open_best_effort(&path).unwrap();
        assert!(
            !dev.is_writable(),
            "read-only file should not report writable"
        );
        // Cleanup: restore writability so remove_file succeeds.
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&path, perm).unwrap();
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn callback_device_without_writer_rejects_writes() {
        let dev = CallbackDevice {
            size: 4096,
            read: Box::new(|_, buf| {
                buf.fill(0);
                Ok(())
            }),
            write: None,
            flush: None,
        };
        assert!(!dev.is_writable());
        assert!(dev.write_at(0, &[0u8; 4]).is_err());
    }

    // -----------------------------------------------------------------------
    // CachingDevice
    // -----------------------------------------------------------------------

    /// Instrumented inner device — counts `read_at`/`write_at` calls and
    /// backs reads with a deterministic pattern (byte = (offset % 251) + i%7).
    struct CountingDev {
        size: u64,
        read_calls: Mutex<u64>,
        write_calls: Mutex<u64>,
        bytes: Mutex<Vec<u8>>,
    }
    impl CountingDev {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                size: bytes.len() as u64,
                read_calls: Mutex::new(0),
                write_calls: Mutex::new(0),
                bytes: Mutex::new(bytes),
            }
        }
    }
    impl BlockDevice for CountingDev {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            *self.read_calls.lock().unwrap() += 1;
            let b = self.bytes.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            buf.copy_from_slice(&b[start..end]);
            Ok(())
        }
        fn size_bytes(&self) -> u64 {
            self.size
        }
        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
            *self.write_calls.lock().unwrap() += 1;
            let mut b = self.bytes.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            b[start..end].copy_from_slice(buf);
            Ok(())
        }
        fn is_writable(&self) -> bool {
            true
        }
    }

    #[test]
    fn caching_device_caches_repeated_reads() {
        let bytes = (0u8..=255u8).cycle().take(64 * 1024).collect::<Vec<_>>();
        let inner: Arc<CountingDev> = Arc::new(CountingDev::new(bytes.clone()));
        let inner_trait: Arc<dyn BlockDevice> = inner.clone();
        let dev = CachingDevice::new(inner_trait, 4096, 4);

        let mut buf = vec![0u8; 4096];
        dev.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, &bytes[0..4096]);
        dev.read_at(0, &mut buf).unwrap();
        dev.read_at(0, &mut buf).unwrap();

        assert_eq!(
            *inner.read_calls.lock().unwrap(),
            1,
            "cache should absorb repeats"
        );
        let (hits, misses) = dev.stats();
        assert_eq!((hits, misses), (2, 1));
    }

    #[test]
    fn caching_device_bypasses_non_aligned_reads() {
        let bytes = vec![0x5A; 8192];
        let inner: Arc<CountingDev> = Arc::new(CountingDev::new(bytes));
        let inner_trait: Arc<dyn BlockDevice> = inner.clone();
        let dev = CachingDevice::new(inner_trait, 4096, 2);

        let mut buf = vec![0u8; 100];
        dev.read_at(123, &mut buf).unwrap();
        dev.read_at(123, &mut buf).unwrap();

        assert_eq!(*inner.read_calls.lock().unwrap(), 2);
        let (hits, misses) = dev.stats();
        assert_eq!((hits, misses), (0, 0));
    }

    #[test]
    fn caching_device_evicts_lru() {
        let bytes = vec![0u8; 64 * 1024];
        let inner: Arc<CountingDev> = Arc::new(CountingDev::new(bytes));
        let inner_trait: Arc<dyn BlockDevice> = inner.clone();
        let dev = CachingDevice::new(inner_trait, 4096, 2);

        let mut buf = vec![0u8; 4096];
        dev.read_at(0, &mut buf).unwrap();
        dev.read_at(4096, &mut buf).unwrap();
        dev.read_at(8192, &mut buf).unwrap(); // evicts offset=0
        dev.read_at(0, &mut buf).unwrap(); // miss — must re-read

        assert_eq!(*inner.read_calls.lock().unwrap(), 4);
    }

    #[test]
    fn caching_device_invalidates_on_write() {
        let bytes = vec![0u8; 8192];
        let inner: Arc<CountingDev> = Arc::new(CountingDev::new(bytes));
        let inner_trait: Arc<dyn BlockDevice> = inner.clone();
        let dev = CachingDevice::new(inner_trait, 4096, 4);

        let mut buf = vec![0u8; 4096];
        dev.read_at(0, &mut buf).unwrap(); // miss
        dev.write_at(0, &[0xABu8; 4096]).unwrap(); // invalidates
        dev.read_at(0, &mut buf).unwrap(); // miss again
        assert_eq!(buf[0], 0xAB);

        let (hits, misses) = dev.stats();
        assert_eq!(hits, 0);
        assert_eq!(misses, 2);
    }

    #[test]
    fn caching_device_write_invalidates_overlapping_but_not_distant() {
        let bytes = vec![0u8; 16 * 1024];
        let inner: Arc<CountingDev> = Arc::new(CountingDev::new(bytes));
        let inner_trait: Arc<dyn BlockDevice> = inner.clone();
        let dev = CachingDevice::new(inner_trait, 4096, 4);

        let mut buf = vec![0u8; 4096];
        dev.read_at(0, &mut buf).unwrap();
        dev.read_at(4096, &mut buf).unwrap();
        dev.read_at(8192, &mut buf).unwrap();
        dev.read_at(12288, &mut buf).unwrap();
        assert_eq!(*inner.read_calls.lock().unwrap(), 4);

        // Write into block 1 only — blocks 0, 2, 3 should stay cached.
        dev.write_at(4096, &[0x11u8; 4096]).unwrap();

        dev.read_at(0, &mut buf).unwrap(); // hit
        dev.read_at(8192, &mut buf).unwrap(); // hit
        dev.read_at(12288, &mut buf).unwrap(); // hit
        dev.read_at(4096, &mut buf).unwrap(); // miss (was invalidated)

        assert_eq!(*inner.read_calls.lock().unwrap(), 5);
    }
}
