//! Backend-agnostic virtio-fs DAX mapper seam.
//!
//! A `DaxMapper` is supplied by the concrete VMM backend to map host file
//! ranges directly into a guest-accessible DAX window. The virtio-fs FUSE
//! server uses it to handle `FUSE_SETUPMAPPING` and `FUSE_REMOVEMAPPING`
//! without knowing the details of guest physical memory layout or the host
//! hypervisor API.

use std::path::Path;

/// Maps host file ranges into a guest DAX window.
///
/// All offsets and lengths must be aligned to [`DaxMapper::alignment`]. The
/// FUSE server validates alignment and window bounds before calling into the
/// mapper; implementations may assume that the arguments respect those
/// invariants.
pub trait DaxMapper {
    /// Map `len` bytes of `path` starting at `file_offset` into the DAX window
    /// at `window_offset` bytes from the start of the window.
    ///
    /// `writable` indicates that the guest may write through the mapping. For a
    /// read-only root device the server generally passes `false`, but the
    /// mapper must still honour the flag.
    ///
    /// On failure returns a FUSE error value (negated `errno`, e.g. `-EIO`).
    fn map(
        &mut self,
        path: &Path,
        file_offset: u64,
        window_offset: u64,
        len: u64,
        writable: bool,
    ) -> Result<(), i32>;

    /// Remove a previously established mapping covering `window_offset..+len`.
    ///
    /// On failure returns a FUSE error value (negated `errno`).
    fn unmap(&mut self, window_offset: u64, len: u64) -> Result<(), i32>;

    /// Inclusive base and size of the DAX window in guest physical address
    /// space. The FUSE server uses this to reject out-of-bounds requests.
    fn window(&self) -> (u64, u64);

    /// Alignment required for file offsets, window offsets, and lengths.
    fn alignment(&self) -> u64;
}
