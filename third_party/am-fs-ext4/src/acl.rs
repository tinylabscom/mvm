//! POSIX ACL decoder for ext4's compact on-disk ACL format.
//!
//! ext4 stores ACLs in xattrs under `system.posix_acl_access` and
//! `system.posix_acl_default`. The value is NOT the generic POSIX ACL xattr
//! format — the kernel packs it into a compact ext4-specific layout (version 1)
//! when storing and expands back to POSIX format on getxattr. When we read the
//! xattr value directly from disk we see the compact form.
//!
//! Reference: `fs/ext4/acl.h` in the Linux kernel.
//!
//! Layout:
//!   u32 a_version = 0x0001 (EXT4_ACL_VERSION)
//!   Then entries back-to-back:
//!     struct ext4_acl_entry_short { u16 e_tag; u16 e_perm; }          (4 bytes)
//!     struct ext4_acl_entry       { u16 e_tag; u16 e_perm; u32 e_id; } (8 bytes)
//!
//! Short form (no e_id) is used for USER_OBJ, GROUP_OBJ, MASK, OTHER.
//! Full form (with e_id) is used for USER and GROUP entries.

use crate::block_io::BlockDevice;
use crate::error::{Error, Result};
use crate::inode::Inode;
use crate::xattr;

pub const EXT4_ACL_VERSION: u32 = 0x0001;

/// Which ACL we're reading. ext4 stores access ACL under
/// `system.posix_acl_access`; the default ACL (inherited by new children in
/// a directory) is under `system.posix_acl_default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclKind {
    Access,
    Default,
}

impl AclKind {
    pub fn xattr_name(self) -> &'static str {
        match self {
            AclKind::Access => "system.posix_acl_access",
            AclKind::Default => "system.posix_acl_default",
        }
    }
}

/// POSIX ACL entry tag. Values match `<linux/posix_acl.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AclTag {
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

impl AclTag {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0x01 => Some(AclTag::UserObj),
            0x02 => Some(AclTag::User),
            0x04 => Some(AclTag::GroupObj),
            0x08 => Some(AclTag::Group),
            0x10 => Some(AclTag::Mask),
            0x20 => Some(AclTag::Other),
            _ => None,
        }
    }

    /// True when this tag's entry carries an id (USER or GROUP).
    pub fn has_id(self) -> bool {
        matches!(self, AclTag::User | AclTag::Group)
    }
}

pub const ACL_READ: u16 = 4;
pub const ACL_WRITE: u16 = 2;
pub const ACL_EXECUTE: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    pub tag: AclTag,
    /// Permission bits: bit 0=execute, bit 1=write, bit 2=read.
    pub perm: u16,
    /// uid for `User`, gid for `Group`, otherwise `None`.
    pub id: Option<u32>,
}

/// Parse an ext4 compact ACL xattr value into a list of entries.
pub fn decode(buf: &[u8]) -> Result<Vec<AclEntry>> {
    if buf.len() < 4 {
        return Err(Error::Corrupt("acl too short for version header"));
    }
    let version = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if version != EXT4_ACL_VERSION {
        return Err(Error::Corrupt("acl version mismatch"));
    }

    let mut entries = Vec::new();
    let mut pos = 4;
    while pos < buf.len() {
        if pos + 4 > buf.len() {
            return Err(Error::Corrupt("acl entry truncated"));
        }
        let e_tag = u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap());
        let e_perm = u16::from_le_bytes(buf[pos + 2..pos + 4].try_into().unwrap());
        let tag = AclTag::from_u16(e_tag).ok_or(Error::Corrupt("acl entry has unknown tag"))?;

        let (id, size) = if tag.has_id() {
            if pos + 8 > buf.len() {
                return Err(Error::Corrupt("acl full entry truncated"));
            }
            let e_id = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap());
            (Some(e_id), 8)
        } else {
            (None, 4)
        };

        entries.push(AclEntry {
            tag,
            perm: e_perm,
            id,
        });
        pos += size;
    }
    Ok(entries)
}

/// Read the ACL attached to an inode via xattr lookup + decode.
///
/// Returns `Ok(None)` when the xattr is absent (inode has no ACL of that kind);
/// `Ok(Some(entries))` when present. Errors propagate from the xattr layer or
/// from decoding an ill-formed ACL value.
pub fn read(
    dev: &dyn BlockDevice,
    inode: &Inode,
    inode_raw: &[u8],
    inode_size: u16,
    block_size: u32,
    kind: AclKind,
) -> Result<Option<Vec<AclEntry>>> {
    let value = xattr::get(
        dev,
        inode,
        inode_raw,
        inode_size,
        block_size,
        kind.xattr_name(),
    )?;
    match value {
        Some(bytes) => Ok(Some(decode(&bytes)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    fn le16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }

    /// Build a minimal valid ACL blob in ext4 compact format.
    fn build(entries: &[(u16, u16, Option<u32>)]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&le32(EXT4_ACL_VERSION));
        for (tag, perm, id) in entries {
            v.extend_from_slice(&le16(*tag));
            v.extend_from_slice(&le16(*perm));
            if let Some(id) = id {
                v.extend_from_slice(&le32(*id));
            }
        }
        v
    }

    #[test]
    fn decodes_minimal_acl() {
        // Standard mode-mapped acl: USER_OBJ(rwx), GROUP_OBJ(r-x), OTHER(r--)
        let buf = build(&[(0x01, 7, None), (0x04, 5, None), (0x20, 4, None)]);
        let entries = decode(&buf).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            AclEntry {
                tag: AclTag::UserObj,
                perm: 7,
                id: None
            }
        );
        assert_eq!(
            entries[1],
            AclEntry {
                tag: AclTag::GroupObj,
                perm: 5,
                id: None
            }
        );
        assert_eq!(
            entries[2],
            AclEntry {
                tag: AclTag::Other,
                perm: 4,
                id: None
            }
        );
    }

    #[test]
    fn decodes_named_user_and_group() {
        let buf = build(&[
            (0x01, 7, None),       // USER_OBJ rwx
            (0x02, 6, Some(1000)), // named USER uid=1000 rw-
            (0x04, 5, None),       // GROUP_OBJ r-x
            (0x08, 4, Some(2000)), // named GROUP gid=2000 r--
            (0x10, 7, None),       // MASK rwx
            (0x20, 0, None),       // OTHER ---
        ]);
        let entries = decode(&buf).unwrap();
        assert_eq!(entries.len(), 6);
        assert_eq!(
            entries[1],
            AclEntry {
                tag: AclTag::User,
                perm: 6,
                id: Some(1000)
            }
        );
        assert_eq!(
            entries[3],
            AclEntry {
                tag: AclTag::Group,
                perm: 4,
                id: Some(2000)
            }
        );
        assert_eq!(
            entries[4],
            AclEntry {
                tag: AclTag::Mask,
                perm: 7,
                id: None
            }
        );
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = build(&[(0x01, 7, None)]);
        buf[0] = 0x02; // bump version
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn rejects_unknown_tag() {
        let buf = build(&[(0x99, 7, None)]);
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn rejects_truncated_full_entry() {
        // USER entry needs 8 bytes but only 4 provided after version
        let mut v = Vec::new();
        v.extend_from_slice(&le32(EXT4_ACL_VERSION));
        v.extend_from_slice(&le16(0x02)); // USER
        v.extend_from_slice(&le16(7));
        // missing 4-byte id
        assert!(decode(&v).is_err());
    }

    #[test]
    fn xattr_names_correct() {
        assert_eq!(AclKind::Access.xattr_name(), "system.posix_acl_access");
        assert_eq!(AclKind::Default.xattr_name(), "system.posix_acl_default");
    }

    #[test]
    fn tag_has_id_matches_spec() {
        assert!(AclTag::User.has_id());
        assert!(AclTag::Group.has_id());
        assert!(!AclTag::UserObj.has_id());
        assert!(!AclTag::GroupObj.has_id());
        assert!(!AclTag::Mask.has_id());
        assert!(!AclTag::Other.has_id());
    }
}
