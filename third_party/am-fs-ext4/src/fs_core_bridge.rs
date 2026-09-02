//! Bidirectional bridge between ext4's local [`BlockDevice`] trait and the
//! shared [`fs_core::BlockDevice`] trait.
//!
//! Two directions:
//!
//! 1. **Outbound** — ext4's [`FileDevice`] / [`CallbackDevice`] also
//!    implement [`fs_core::BlockDevice`], so anything that takes a
//!    `&dyn fs_core::BlockDevice` (a partition probe, a slice adapter)
//!    can drive an ext4-flavoured device directly.
//!
//! 2. **Inbound** — [`CoreDevice<T>`] wraps any `fs_core::BlockDevice` and
//!    presents it as ext4's local `BlockDevice`, with the journal-cache
//!    hooks (`populate_cache` / `unpin_all`) defaulting to no-ops. This is
//!    how an external image reader (a [`Qcow2Reader`][qcow]), or a
//!    partition slice, is fed into ext4's mount path.
//!
//! Strictly additive — does not touch the existing [`BlockDevice`] trait
//! or any of its implementors. Risk-bounded: removing `pub mod
//! fs_core_bridge;` from `lib.rs` reverts the entire change.
//!
//! [qcow]: https://crates.io/crates/am-img-qcow2

use crate::block_io::{BlockDevice, CallbackDevice, FileDevice};
use crate::error::Error;

/// Lift an ext4 error into the unified `fs_core::Error` shape so trait
/// methods can return the framework's error type. Lossy on variants
/// without a direct counterpart — those flatten to `Custom(String)`.
///
/// `Error::OutOfBounds` deliberately flattens to `Custom` rather than
/// `fs_core::Error::OutOfBounds { offset, len, size }`: ext4's error type
/// doesn't carry the offset/len/size context, so synthesising zeros here
/// would silently mislead consumers pattern-matching on those fields.
fn ext4_to_fs_core_error(e: Error) -> fs_core::Error {
    match e {
        Error::Io(io) => fs_core::Error::Io(io),
        Error::ReadOnly => fs_core::Error::ReadOnly,
        other => fs_core::Error::Custom(format!("{other:?}")),
    }
}

/// Drop a `fs_core::Error` back into ext4's error type for the inbound
/// adapter path. `Custom` and `OutOfBounds` flatten to a synthetic
/// `io::Error` so ext4's existing `From<io::Error>` lifts them naturally.
fn fs_core_to_ext4_error(e: fs_core::Error) -> Error {
    match e {
        fs_core::Error::Io(io) => Error::Io(io),
        fs_core::Error::ReadOnly => Error::ReadOnly,
        fs_core::Error::OutOfBounds { .. } => Error::OutOfBounds,
        fs_core::Error::ShortRead { offset, want, got } => Error::Io(std::io::Error::other(
            format!("short read at {offset}: wanted {want} got {got}"),
        )),
        fs_core::Error::Custom(s) => Error::Io(std::io::Error::other(s)),
    }
}

// ---------------------------------------------------------------------------
// Outbound: ext4's adapters also satisfy fs_core::BlockDevice.
// ---------------------------------------------------------------------------

impl fs_core::BlockRead for FileDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        BlockDevice::read_at(self, offset, buf).map_err(ext4_to_fs_core_error)
    }
    fn size_bytes(&self) -> u64 {
        BlockDevice::size_bytes(self)
    }
}

impl fs_core::BlockDevice for FileDevice {
    fn write_at(&self, offset: u64, buf: &[u8]) -> fs_core::Result<()> {
        // Short-circuit on the writable bit so RO devices surface
        // `fs_core::Error::ReadOnly` consistently. The inner write_at
        // would otherwise return `Error::Corrupt("FileDevice opened
        // read-only")`, which our error map flattens to `Custom`,
        // breaking the `is_writable()` / `write_at` contract.
        if !BlockDevice::is_writable(self) {
            return Err(fs_core::Error::ReadOnly);
        }
        BlockDevice::write_at(self, offset, buf).map_err(ext4_to_fs_core_error)
    }
    fn flush(&self) -> fs_core::Result<()> {
        BlockDevice::flush(self).map_err(ext4_to_fs_core_error)
    }
    fn is_writable(&self) -> bool {
        BlockDevice::is_writable(self)
    }
}

impl fs_core::BlockRead for CallbackDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
        BlockDevice::read_at(self, offset, buf).map_err(ext4_to_fs_core_error)
    }
    fn size_bytes(&self) -> u64 {
        BlockDevice::size_bytes(self)
    }
}

impl fs_core::BlockDevice for CallbackDevice {
    fn write_at(&self, offset: u64, buf: &[u8]) -> fs_core::Result<()> {
        // Same RO short-circuit as the FileDevice impl above — without
        // it, callback devices configured with `write: None` surface
        // their `Error::Corrupt("CallbackDevice has no write
        // callback")` as `fs_core::Error::Custom`, which breaks
        // `is_writable()` / `write_at` consistency.
        if !BlockDevice::is_writable(self) {
            return Err(fs_core::Error::ReadOnly);
        }
        BlockDevice::write_at(self, offset, buf).map_err(ext4_to_fs_core_error)
    }
    fn flush(&self) -> fs_core::Result<()> {
        BlockDevice::flush(self).map_err(ext4_to_fs_core_error)
    }
    fn is_writable(&self) -> bool {
        BlockDevice::is_writable(self)
    }
}

// ---------------------------------------------------------------------------
// Inbound: any fs_core::BlockDevice can drive ext4 via this wrapper.
// ---------------------------------------------------------------------------

/// Wraps any [`fs_core::BlockDevice`] and presents it as an ext4
/// [`BlockDevice`]. Journal-cache hooks default to no-ops (the underlying
/// device has no notion of "pinned" pages), which is the same as ext4's
/// behaviour against a raw `FileDevice` — safe because un-cached devices
/// imply no separate journal log either.
pub struct CoreDevice<T: fs_core::BlockDevice> {
    inner: T,
}

impl<T: fs_core::BlockDevice> CoreDevice<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped device, e.g. for diagnostics.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Consume the wrapper and return the inner device.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: fs_core::BlockDevice> BlockDevice for CoreDevice<T> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> crate::error::Result<()> {
        fs_core::BlockRead::read_at(&self.inner, offset, buf).map_err(fs_core_to_ext4_error)
    }
    fn size_bytes(&self) -> u64 {
        fs_core::BlockRead::size_bytes(&self.inner)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> crate::error::Result<()> {
        fs_core::BlockDevice::write_at(&self.inner, offset, buf).map_err(fs_core_to_ext4_error)
    }
    fn flush(&self) -> crate::error::Result<()> {
        fs_core::BlockDevice::flush(&self.inner).map_err(fs_core_to_ext4_error)
    }
    fn is_writable(&self) -> bool {
        fs_core::BlockDevice::is_writable(&self.inner)
    }
    // populate_cache / unpin_all use the trait's default no-op impls — see
    // module-level docs for why that's safe for un-journaled inbound devices.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Trivial in-memory `fs_core::BlockDevice` for testing the inbound
    /// adapter without dragging in a real qcow2 fixture.
    struct InMemoryFsCore(Mutex<Vec<u8>>);

    impl fs_core::BlockRead for InMemoryFsCore {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_core::Result<()> {
            let b = self.0.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            if end > b.len() {
                return Err(fs_core::Error::ShortRead {
                    offset,
                    want: buf.len(),
                    got: b.len().saturating_sub(start),
                });
            }
            buf.copy_from_slice(&b[start..end]);
            Ok(())
        }
        fn size_bytes(&self) -> u64 {
            self.0.lock().unwrap().len() as u64
        }
    }

    impl fs_core::BlockDevice for InMemoryFsCore {
        fn write_at(&self, offset: u64, buf: &[u8]) -> fs_core::Result<()> {
            let mut b = self.0.lock().unwrap();
            let start = offset as usize;
            let end = start + buf.len();
            // Honest BlockDevice impl: out-of-range writes return
            // `fs_core::Error::OutOfBounds` rather than panicking from
            // a slice copy_from_slice. Without this guard, future
            // tests that exercise the error path would panic instead.
            if end > b.len() {
                return Err(fs_core::Error::OutOfBounds {
                    offset,
                    len: buf.len() as u64,
                    size: b.len() as u64,
                });
            }
            b[start..end].copy_from_slice(buf);
            Ok(())
        }
        fn is_writable(&self) -> bool {
            true
        }
    }

    #[test]
    fn core_device_round_trip() {
        let mem = InMemoryFsCore(Mutex::new(vec![0u8; 4096]));
        let dev = CoreDevice::new(mem);
        assert_eq!(BlockDevice::size_bytes(&dev), 4096);

        // Inbound write-then-read through the ext4 trait.
        BlockDevice::write_at(&dev, 100, &[0x11, 0x22, 0x33, 0x44]).unwrap();
        let mut buf = [0u8; 4];
        BlockDevice::read_at(&dev, 100, &mut buf).unwrap();
        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn core_device_propagates_short_read_as_oob() {
        let mem = InMemoryFsCore(Mutex::new(vec![0u8; 64]));
        let dev = CoreDevice::new(mem);
        let mut buf = [0u8; 16];
        // Read past the end -> fs_core::Error::ShortRead -> ext4::Error::Io
        // (we surface short reads as io errors, not OutOfBounds, because
        // the offset/len/size context is lost in translation).
        let err = BlockDevice::read_at(&dev, 60, &mut buf).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got: {err:?}");
    }
}
