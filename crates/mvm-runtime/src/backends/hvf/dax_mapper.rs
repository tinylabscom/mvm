//! HVF-backed virtio-fs DAX mapper.
//!
//! Maps host file ranges into a guest physical DAX window with
//! `mmap(2)` + `hv_vm_map(2)`. The window lives below guest RAM so it is never
//! described as normal memory to the kernel; the FUSE server validates
//! alignment and bounds before invoking the mapper.

use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr::NonNull;

use mvm_vmm::dax::DaxMapper;

use super::guest_ram::HVF_PAGE_SIZE;
use super::sys::{HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, HV_SUCCESS};
use super::sys::{hv_vm_map, hv_vm_unmap};

/// Guest physical base of the virtio-fs DAX window. Placed above the default
/// RAM region (which starts at 0x8000_0000) so the kernel can hot-add it as
/// device memory without colliding with normal guest RAM.
pub(crate) const DAX_WINDOW_BASE: u64 = 0x1_0000_0000;

/// Size of the DAX window. 256 MiB is enough for the builder rootfs working set
/// while leaving the low 2 GiB address map mostly free.
pub(crate) const DAX_WINDOW_SIZE: u64 = 256 * 1024 * 1024;

const FUSE_EIO: i32 = -5;
const FUSE_EINVAL: i32 = -22;

/// One active host mapping backing a guest DAX range.
struct Mapping {
    host: NonNull<c_void>,
    len: usize,
}

pub(crate) struct HvfDaxMapper {
    active: HashMap<u64, Mapping>,
}

impl HvfDaxMapper {
    pub(crate) fn new() -> Self {
        Self {
            active: HashMap::new(),
        }
    }
}

impl DaxMapper for HvfDaxMapper {
    fn map(
        &mut self,
        path: &Path,
        file_offset: u64,
        window_offset: u64,
        len: u64,
        writable: bool,
    ) -> Result<(), i32> {
        let align = HVF_PAGE_SIZE as u64;
        if !window_offset.is_multiple_of(align)
            || !file_offset.is_multiple_of(align)
            || !len.is_multiple_of(align)
            || len == 0
        {
            return Err(FUSE_EINVAL);
        }
        let (_, win_size) = self.window();
        let Some(end) = window_offset.checked_add(len) else {
            return Err(FUSE_EINVAL);
        };
        if end > win_size {
            return Err(FUSE_EINVAL);
        }
        let mapped_len = len as usize;

        let file = File::open(path).map_err(|_| FUSE_EIO)?;
        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        // SAFETY: `mmap` with a private file mapping; the returned pointer is
        // page-aligned and the mapping length is page-rounded by the caller.
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped_len,
                prot,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                file_offset as i64,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(FUSE_EIO);
        }

        let flags = if writable {
            HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC
        } else {
            HV_MEMORY_READ | HV_MEMORY_EXEC
        };
        let gpa = DAX_WINDOW_BASE + window_offset;
        // SAFETY: FFI to HVF to install the host mapping at the guest IPA.
        let rc = unsafe { hv_vm_map(host, gpa, mapped_len, flags) };
        if rc != HV_SUCCESS {
            // SAFETY: undo the host mmap on failure so we do not leak it.
            unsafe {
                libc::munmap(host, mapped_len);
            }
            return Err(FUSE_EIO);
        }

        let host = NonNull::new(host).ok_or(FUSE_EIO)?;
        self.active.insert(
            window_offset,
            Mapping {
                host,
                len: mapped_len,
            },
        );
        Ok(())
    }

    fn unmap(&mut self, window_offset: u64, len: u64) -> Result<(), i32> {
        let align = HVF_PAGE_SIZE as u64;
        if !window_offset.is_multiple_of(align) || !len.is_multiple_of(align) || len == 0 {
            return Err(FUSE_EINVAL);
        }
        let (_, win_size) = self.window();
        let Some(end) = window_offset.checked_add(len) else {
            return Err(FUSE_EINVAL);
        };
        if end > win_size {
            return Err(FUSE_EINVAL);
        }
        let len = len as usize;
        let mapping = self.active.remove(&window_offset).ok_or(FUSE_EINVAL)?;
        if mapping.len != len {
            // Put it back: the kernel must unmap exactly what it mapped.
            self.active.insert(window_offset, mapping);
            return Err(FUSE_EINVAL);
        }

        let gpa = DAX_WINDOW_BASE + window_offset;
        // SAFETY: FFI to remove the guest mapping, then release the host mmap.
        // The pointer/length came from a successful mmap in `map`.
        unsafe {
            hv_vm_unmap(gpa, len);
            libc::munmap(mapping.host.as_ptr(), len);
        }
        Ok(())
    }

    fn window(&self) -> (u64, u64) {
        (DAX_WINDOW_BASE, DAX_WINDOW_SIZE)
    }

    fn alignment(&self) -> u64 {
        HVF_PAGE_SIZE as u64
    }
}

impl Drop for HvfDaxMapper {
    fn drop(&mut self) {
        for (offset, mapping) in self.active.drain() {
            // SAFETY: same pointer/length contract as `unmap`.
            unsafe {
                hv_vm_unmap(offset, mapping.len);
                libc::munmap(mapping.host.as_ptr(), mapping.len);
            }
        }
    }
}

impl Default for HvfDaxMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_alignment_are_page_sized() {
        let m = HvfDaxMapper::new();
        assert_eq!(m.alignment(), HVF_PAGE_SIZE as u64);
        assert_eq!(m.window().1, DAX_WINDOW_SIZE);
    }

    #[test]
    fn rejects_unaligned_setup() {
        let mut m = HvfDaxMapper::new();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        // Cannot actually map without a live VM, but alignment is checked
        // before any HVF call.
        assert_eq!(
            m.map(&p, 1, DAX_WINDOW_BASE, HVF_PAGE_SIZE as u64, false),
            Err(FUSE_EINVAL)
        );
        assert_eq!(
            m.map(&p, 0, DAX_WINDOW_BASE + 1, HVF_PAGE_SIZE as u64, false),
            Err(FUSE_EINVAL)
        );
        assert_eq!(
            m.map(&p, 0, DAX_WINDOW_BASE, HVF_PAGE_SIZE as u64 - 1, false),
            Err(FUSE_EINVAL)
        );
    }
}
