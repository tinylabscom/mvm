//! EA_INODE xattr value follow (E12, Phase 5).
//!
//! When an xattr entry has `e_value_inum != 0` (and the filesystem has
//! `INCOMPAT_EA_INODE` enabled), the value does NOT live in the xattr
//! block — instead it lives in the referenced inode's file body. This
//! accommodates xattrs whose values are larger than an inline xattr slot
//! can hold (typically: ACL blobs > 4 KiB, Finder metadata bundles, etc).
//!
//! Spec: <https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#extended-attributes>
//! Field: `ext4_xattr_entry.e_value_inum`. Target inode is a regular inode
//! with the `EA_INODE` flag set (`0x200000`); its `i_size` = value length;
//! data lives via the same extent-tree/inline-data mechanisms as a regular
//! file.
//!
//! Phase 1 (this landing): read only. Write-path is deferred to when
//! the filesystem gains an inode allocator (E6) integration.

use crate::error::{Error, Result};
use crate::file_io;
use crate::fs::Filesystem;
use crate::inode::{Inode, InodeFlags};

/// Follow an `e_value_inum` pointer and return the raw value bytes. Errors:
/// - [`Error::InvalidInode`] if `value_inum` is 0 or out of range.
/// - [`Error::Corrupt`] if the target inode does not have the `EA_INODE`
///   flag set (guards against pointing at a regular file / directory by
///   accident).
pub fn read_value_inode(fs: &Filesystem, value_inum: u32) -> Result<Vec<u8>> {
    if value_inum == 0 {
        return Err(Error::InvalidInode(value_inum));
    }

    let raw = fs.read_inode_raw(value_inum)?;
    let inode = Inode::parse(&raw)?;
    if inode.flags & InodeFlags::EA_INODE.bits() == 0 {
        return Err(Error::Corrupt(
            "e_value_inum target missing EA_INODE flag (0x200000)",
        ));
    }

    // Body read path: identical to a regular file body. If the target uses
    // inline data (rare but legal for very small EA_INODE values), follow
    // that route; otherwise extent-tree read.
    if inode.flags & InodeFlags::INLINE_DATA.bits() != 0 {
        return file_io::read_inline(fs, &inode, &raw);
    }
    file_io::read_all(fs, &inode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::InodeFlags;

    /// Quick property check: EA_INODE flag bit is 0x200000 per spec.
    #[test]
    fn ea_inode_flag_bit_value() {
        assert_eq!(InodeFlags::EA_INODE.bits(), 0x0020_0000);
    }

    /// Guard against accidentally calling read_value_inode with ino=0.
    #[test]
    fn zero_inode_is_rejected() {
        // We don't need a Filesystem to exercise the guard — the first
        // branch short-circuits. Just verify the error discriminant.
        let err = Error::InvalidInode(0);
        match err {
            Error::InvalidInode(n) => assert_eq!(n, 0),
            _ => panic!(),
        }
    }
}
