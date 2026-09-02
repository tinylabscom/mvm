//! ext4 feature flags — COMPAT, INCOMPAT, RO_COMPAT.
//!
//! Spec source: kernel.org/doc/html/latest/filesystems/ext4/super.html

use bitflags::bitflags;

bitflags! {
    /// COMPAT features — safe to ignore if unknown.
    #[derive(Debug, Clone, Copy)]
    pub struct Compat: u32 {
        const DIR_PREALLOC      = 0x0001;
        const IMAGIC_INODES     = 0x0002;
        const HAS_JOURNAL       = 0x0004;
        const EXT_ATTR          = 0x0008;
        const RESIZE_INODE      = 0x0010;
        const DIR_INDEX         = 0x0020;  // HTree
        const LAZY_BG           = 0x0040;
        const SPARSE_SUPER2     = 0x0200;
        const FAST_COMMIT       = 0x0400;
        const ORPHAN_FILE       = 0x1000;
    }

    /// INCOMPAT features — kernel MUST understand or refuse to mount.
    #[derive(Debug, Clone, Copy)]
    pub struct Incompat: u32 {
        const COMPRESSION       = 0x00001;
        const FILETYPE          = 0x00002;
        const RECOVER           = 0x00004;
        const JOURNAL_DEV       = 0x00008;
        const META_BG           = 0x00010;
        const EXTENTS           = 0x00040;
        const BIT64             = 0x00080;
        const MMP               = 0x00100;
        const FLEX_BG           = 0x00200;
        const EA_INODE          = 0x00400;
        const DIRDATA           = 0x01000;
        const CSUM_SEED         = 0x02000;
        const LARGEDIR          = 0x04000;
        const INLINE_DATA       = 0x08000;
        const ENCRYPT           = 0x10000;
        const CASEFOLD          = 0x20000;
    }

    /// RO_COMPAT features — must mount read-only if unknown.
    #[derive(Debug, Clone, Copy)]
    pub struct RoCompat: u32 {
        const SPARSE_SUPER      = 0x0001;
        const LARGE_FILE        = 0x0002;
        const BTREE_DIR         = 0x0004;
        const HUGE_FILE         = 0x0008;
        const GDT_CSUM          = 0x0010;
        const DIR_NLINK         = 0x0020;
        const EXTRA_ISIZE       = 0x0040;
        const HAS_SNAPSHOT      = 0x0080;
        const QUOTA             = 0x0100;
        const BIGALLOC          = 0x0200;
        const METADATA_CSUM     = 0x0400;
        const REPLICA           = 0x0800;
        const READONLY          = 0x1000;
        const PROJECT           = 0x2000;
        const VERITY            = 0x8000;
        const ORPHAN_PRESENT    = 0x10000;
    }
}

/// INCOMPAT bits we know how to handle (Phase 1 read-only goal).
/// Anything else in feature_incompat means refuse-to-mount.
pub const SUPPORTED_INCOMPAT: u32 = Incompat::FILETYPE.bits()
    | Incompat::EXTENTS.bits()
    | Incompat::BIT64.bits()
    | Incompat::FLEX_BG.bits()
    | Incompat::CSUM_SEED.bits()
    // The features below are tolerated for read-only mount even if not fully implemented:
    | Incompat::RECOVER.bits()      // we'll skip journal replay for now (warn)
    | Incompat::MMP.bits()          // ignore for read-only
    | Incompat::INLINE_DATA.bits()  // we'll handle the flag, even if data overflow uses xattr later
    | Incompat::LARGEDIR.bits()
    | Incompat::EA_INODE.bits()
    | Incompat::CASEFOLD.bits();

/// RO_COMPAT bits we tolerate (since we mount read-only anyway).
pub const SUPPORTED_RO_COMPAT: u32 = RoCompat::SPARSE_SUPER.bits()
    | RoCompat::LARGE_FILE.bits()
    | RoCompat::HUGE_FILE.bits()
    | RoCompat::GDT_CSUM.bits()
    | RoCompat::DIR_NLINK.bits()
    | RoCompat::EXTRA_ISIZE.bits()
    | RoCompat::QUOTA.bits()
    | RoCompat::METADATA_CSUM.bits()
    | RoCompat::PROJECT.bits()
    | RoCompat::ORPHAN_PRESENT.bits()
    | RoCompat::BIGALLOC.bits()  // tolerated; cluster math may need updates
    ;

/// Filesystem dialect — derived from the on-disk feature flags at mount time.
/// Drives runtime behaviour where ext2 / ext3 / ext4 differ:
///
/// - inode block-mapping scheme (extent tree vs legacy direct/indirect)
/// - presence of a journal (replay path runs only for `Ext3`/`Ext4`)
/// - which features new inodes opt into when the driver creates them
///
/// The classification mirrors what the Linux kernel's single `ext4` driver
/// uses internally — there is no separate ext2 driver in this crate, just
/// runtime dispatch keyed on this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsFlavor {
    /// No EXTENTS, no HAS_JOURNAL.
    Ext2,
    /// No EXTENTS, HAS_JOURNAL set (jbd2-style log on a hidden journal inode).
    Ext3,
    /// EXTENTS set (with or without a journal — modern ext4 typically has one).
    Ext4,
}

impl FsFlavor {
    /// Derive flavor from the parsed superblock's COMPAT/INCOMPAT bits.
    pub fn detect(feature_compat: u32, feature_incompat: u32) -> Self {
        let has_extents = (feature_incompat & Incompat::EXTENTS.bits()) != 0;
        let has_journal = (feature_compat & Compat::HAS_JOURNAL.bits()) != 0;
        match (has_extents, has_journal) {
            (true, _) => FsFlavor::Ext4,
            (false, true) => FsFlavor::Ext3,
            (false, false) => FsFlavor::Ext2,
        }
    }

    /// True when the driver should allocate new inodes with `EXT4_EXTENTS_FL`
    /// set (so file contents are tracked by an extent tree). False for ext2/3,
    /// which use the legacy direct/indirect block-pointer scheme.
    pub fn uses_extents(&self) -> bool {
        matches!(self, FsFlavor::Ext4)
    }

    /// True when this volume has a journal that must be replayed (or honoured
    /// on writes). Ext2 has none.
    pub fn has_journal(&self) -> bool {
        matches!(self, FsFlavor::Ext3 | FsFlavor::Ext4)
    }

    pub fn name(&self) -> &'static str {
        match self {
            FsFlavor::Ext2 => "ext2",
            FsFlavor::Ext3 => "ext3",
            FsFlavor::Ext4 => "ext4",
        }
    }

    /// Returns `(inode_size, desc_size, csum_enabled, dir_csum_tail)` tuple.
    pub(crate) fn geometry(&self) -> (u16, u16, bool, usize) {
        let csum_enabled = matches!(self, FsFlavor::Ext4);
        let inode_size: u16 = if csum_enabled { 256 } else { 128 };
        let desc_size: u16 = if csum_enabled { 64 } else { 32 };
        let dir_csum_tail: usize = if csum_enabled { 12 } else { 0 };
        (inode_size, desc_size, csum_enabled, dir_csum_tail)
    }
}

/// Check whether the filesystem can be mounted read-only.
/// Returns Err with the unsupported bits if not.
pub fn check_mountable(feature_incompat: u32, _feature_ro_compat: u32) -> crate::error::Result<()> {
    let unsupported_incompat = feature_incompat & !SUPPORTED_INCOMPAT;
    if unsupported_incompat != 0 {
        return Err(crate::error::Error::UnsupportedIncompat(
            unsupported_incompat,
        ));
    }
    // RO_COMPAT bits are all OK for read-only mount even if unknown,
    // per the spec's compatibility model. We log them but don't fail.
    Ok(())
}
