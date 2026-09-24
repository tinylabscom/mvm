//! Read-only inspection of an ext4 image's journal state.
//!
//! A workload disk is attached to the guest read-only, and the image behind it
//! is shared and content-addressed: it was hashed when the launch was admitted,
//! and every later launch that names it expects the same bytes. So neither side
//! may replay a dirty journal. The guest cannot — ext4 refuses to mount a
//! filesystem that needs recovery from a read-only device — and the host must
//! not, because replaying rewrites bytes the admitted plan already recorded.
//!
//! What remains is to tell the two cases apart before boot, from the primary
//! superblock alone. This module reads it and never opens the image for write.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::EXT4_MAGIC;

/// Byte offset of the primary superblock in an ext4 image.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// Bytes of the superblock this probe needs: through `s_feature_incompat`.
const SUPERBLOCK_PREFIX_LEN: usize = 0x64;
/// `s_magic` offset within the superblock.
const MAGIC_OFFSET: usize = 0x38;
/// `s_feature_incompat` offset within the superblock.
const FEATURE_INCOMPAT_OFFSET: usize = 0x60;
/// `EXT4_FEATURE_INCOMPAT_RECOVER`: the journal holds transactions that have
/// not yet been written to their home locations.
const INCOMPAT_RECOVER: u32 = 0x4;

/// What an image's primary superblock says about its journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalState {
    /// No ext4 superblock: another filesystem, or not a filesystem at all.
    NotExt4,
    /// Mountable as-is from a read-only device: no journal, or an empty one.
    Clean,
    /// The journal must be replayed before the filesystem is consistent, which
    /// needs write access to the device.
    NeedsRecovery,
}

/// Decode the journal state from the superblock bytes, where `superblock`
/// starts at the superblock itself (image offset 1024).
pub fn journal_state_of_superblock(superblock: &[u8]) -> JournalState {
    let Some(prefix) = superblock.get(..SUPERBLOCK_PREFIX_LEN) else {
        return JournalState::NotExt4;
    };
    let magic = u16::from_le_bytes([prefix[MAGIC_OFFSET], prefix[MAGIC_OFFSET + 1]]);
    if magic != EXT4_MAGIC {
        return JournalState::NotExt4;
    }
    let incompat = u32::from_le_bytes([
        prefix[FEATURE_INCOMPAT_OFFSET],
        prefix[FEATURE_INCOMPAT_OFFSET + 1],
        prefix[FEATURE_INCOMPAT_OFFSET + 2],
        prefix[FEATURE_INCOMPAT_OFFSET + 3],
    ]);
    if incompat & INCOMPAT_RECOVER != 0 {
        JournalState::NeedsRecovery
    } else {
        JournalState::Clean
    }
}

/// Read the journal state of the ext4 image at `path` without writing to it.
///
/// An image too short to hold a superblock is [`JournalState::NotExt4`]; only a
/// failure to open or read the file is an error.
pub fn read_journal_state(path: &Path) -> io::Result<JournalState> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))?;
    let mut superblock = Vec::with_capacity(SUPERBLOCK_PREFIX_LEN);
    file.take(SUPERBLOCK_PREFIX_LEN as u64)
        .read_to_end(&mut superblock)?;
    Ok(journal_state_of_superblock(&superblock))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock(magic: u16, incompat: u32) -> Vec<u8> {
        let mut sb = vec![0u8; SUPERBLOCK_PREFIX_LEN];
        sb[MAGIC_OFFSET..MAGIC_OFFSET + 2].copy_from_slice(&magic.to_le_bytes());
        sb[FEATURE_INCOMPAT_OFFSET..FEATURE_INCOMPAT_OFFSET + 4]
            .copy_from_slice(&incompat.to_le_bytes());
        sb
    }

    fn formatted_image(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("rootfs.ext4");
        let mut image = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let size = 8 * 1024 * 1024;
        image.set_len(size).unwrap();
        crate::ext4::mkfs::format_empty_ext4(&mut image, size).unwrap();
        path
    }

    fn set_incompat_bits(path: &Path, bits: u32) {
        let mut bytes = std::fs::read(path).unwrap();
        let at = SUPERBLOCK_OFFSET as usize + FEATURE_INCOMPAT_OFFSET;
        let current = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        bytes[at..at + 4].copy_from_slice(&(current | bits).to_le_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn a_superblock_with_the_recover_flag_needs_recovery() {
        // Other incompat bits (filetype, extents) ride alongside RECOVER.
        let sb = superblock(EXT4_MAGIC, 0x2 | 0x40 | INCOMPAT_RECOVER);
        assert_eq!(
            journal_state_of_superblock(&sb),
            JournalState::NeedsRecovery
        );
    }

    #[test]
    fn a_superblock_without_the_recover_flag_is_clean() {
        let sb = superblock(EXT4_MAGIC, 0x2 | 0x40);
        assert_eq!(journal_state_of_superblock(&sb), JournalState::Clean);
    }

    #[test]
    fn a_wrong_magic_or_a_short_buffer_is_not_ext4() {
        assert_eq!(
            journal_state_of_superblock(&superblock(0x1234, INCOMPAT_RECOVER)),
            JournalState::NotExt4
        );
        let short = &superblock(EXT4_MAGIC, 0)[..FEATURE_INCOMPAT_OFFSET];
        assert_eq!(journal_state_of_superblock(short), JournalState::NotExt4);
        assert_eq!(journal_state_of_superblock(&[]), JournalState::NotExt4);
    }

    #[test]
    fn a_freshly_formatted_image_reads_clean_and_a_flagged_one_needs_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = formatted_image(dir.path());
        assert_eq!(read_journal_state(&path).unwrap(), JournalState::Clean);

        set_incompat_bits(&path, INCOMPAT_RECOVER);
        assert_eq!(
            read_journal_state(&path).unwrap(),
            JournalState::NeedsRecovery
        );
    }

    #[test]
    fn reading_the_state_leaves_the_image_bytes_and_mtime_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = formatted_image(dir.path());
        let before = std::fs::read(&path).unwrap();
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();

        read_journal_state(&path).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    }

    #[test]
    fn a_file_shorter_than_a_superblock_is_not_ext4_and_a_missing_one_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let tiny = dir.path().join("tiny.img");
        std::fs::write(&tiny, b"rootfs").unwrap();
        assert_eq!(read_journal_state(&tiny).unwrap(), JournalState::NotExt4);

        let missing = dir.path().join("absent.img");
        assert_eq!(
            read_journal_state(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
